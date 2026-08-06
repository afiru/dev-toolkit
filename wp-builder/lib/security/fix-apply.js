import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline/promises';
import {
    lintPhpBytes,
    sha256,
    takeSecurityFileSnapshot
} from './fix-plan.js';
import {
    metadataCanReplace,
    metadataSnapshotsMatch,
    WINDOWS_APPLY_UNSUPPORTED_CODE,
    WINDOWS_APPLY_UNSUPPORTED_MESSAGE
} from './metadata.js';
import {
    LinuxRollbackError,
    assertLinuxFinalSnapshot,
    assertLinuxRollbackPathAvailable,
    cleanupLinuxRollbackBeforeRename,
    createLinuxRollbackBackup,
    fsyncLinuxDirectory,
    linuxRollbackPath,
    revalidateLinuxTransaction,
    removeLinuxRollbackBackup,
    rollbackLinuxTarget
} from './linux-rollback.js';

export class SecurityApplyError extends Error {
    constructor(message, exitCode = 1, code = 'SECURITY_APPLY_ERROR') {
        super(message);
        this.name = 'SecurityApplyError';
        this.exitCode = exitCode;
        this.code = code;
    }
}

function snapshotsMatch(expected, current) {
    return (
        expected.state === current.state &&
        expected.state === 'present' &&
        expected.normalFile === current.normalFile &&
        expected.symlink === current.symlink &&
        expected.size === current.size &&
        expected.hash === current.hash &&
        metadataSnapshotsMatch(expected.metadata, current.metadata)
    );
}

function assertSnapshotCurrent(plan, takeSnapshot = takeSecurityFileSnapshot) {
    const current = takeSnapshot(plan.targetPath);
    if (!snapshotsMatch(plan.snapshot, current)) throw new SecurityApplyError(
        `Security target changed after preview: ${plan.targetPath}`,
        4,
        'STALE_FILE'
    );
}

async function confirmApply(input, output, plan) {
    const prompt = readline.createInterface({ input, output });
    try {
        const answer = await prompt.question(
            `Apply ${plan.replacements.length} Security Fix replacement(s) to ${plan.targetPath}? [y/N] `
        );
        return /^(y|yes)$/i.test(answer.trim());
    } finally {
        prompt.close();
    }
}

async function removeTemporaryFile(fileSystem, filePath) {
    if (!filePath) return;
    try {
        await fileSystem.rm(filePath, { force: true });
    } catch (error) {
        console.warn(`[WARNING] Could not remove Security Fix temporary file: ${filePath}`);
        console.warn(`  ${error.message}`);
    }
}

function asAtomicError(error, action) {
    if (error instanceof SecurityApplyError) return error;
    return new SecurityApplyError(
        `Security Fix ${action} failed: ${error.message}`,
        6,
        'ATOMIC_WRITE_FAILED'
    );
}

function asSecurityApplyError(error) {
    if (error instanceof SecurityApplyError) return error;
    if (error instanceof LinuxRollbackError) {
        const result = new SecurityApplyError(error.message, error.exitCode, error.code);
        result.details = error.details;
        return result;
    }
    return error;
}

export async function applySecurityFixPlan(plan, options = {}) {
    const {
        assumeYes = false,
        isTTY = false,
        input = process.stdin,
        output = process.stderr,
        phpCommand = 'php',
        fileSystem = fs,
        takeSnapshot = takeSecurityFileSnapshot
    } = options;

    if (plan?.snapshot?.metadata?.platform === 'win32') throw new SecurityApplyError(
        WINDOWS_APPLY_UNSUPPORTED_MESSAGE,
        2,
        WINDOWS_APPLY_UNSUPPORTED_CODE
    );

    if (!plan.canApply) throw new SecurityApplyError(
        'This Security Fix Plan is blocked. No files were changed.',
        2,
        'PLAN_BLOCKED'
    );
    const linuxRollbackEnabled = plan.snapshot.metadata?.platform === 'linux';
    const rollbackPath = linuxRollbackEnabled ? linuxRollbackPath(plan.targetPath) : null;
    if (linuxRollbackEnabled) {
        try {
            await assertLinuxRollbackPathAvailable(fileSystem, rollbackPath);
        } catch (error) {
            throw asSecurityApplyError(error);
        }
    }
    if (!plan.hasChanges) return { status: 'no_changes' };

    if (!assumeYes) {
        if (!isTTY) throw new SecurityApplyError(
            'Non-interactive apply requires --yes.',
            1,
            'CONFIRMATION_REQUIRED'
        );
        const confirmed = await confirmApply(input, output, plan);
        if (!confirmed) return { status: 'cancelled' };
    }

    const nonce = crypto.randomBytes(8).toString('hex');
    const directory = path.dirname(plan.targetPath);
    const tempPath = path.join(directory, `.${path.basename(plan.targetPath)}.${process.pid}.${nonce}.security-fix.tmp`);
    const lockPath = `${plan.targetPath}.security-fix.lock`;
    let lockHandle;
    let tempHandle;
    let ownsLock = false;
    let rollbackCreated = false;

    try {
        try {
            lockHandle = await fileSystem.open(lockPath, 'wx');
            ownsLock = true;
            await lockHandle.writeFile(`${process.pid}\n`, 'utf8');
            await lockHandle.sync();
        } catch (error) {
            if (error.code === 'EEXIST') throw new SecurityApplyError(
                `Security target is locked: ${lockPath}`,
                5,
                'LOCKED'
            );
            throw new SecurityApplyError(
                `Could not acquire Security Fix lock: ${error.message}`,
                1,
                'LOCK_IO_ERROR'
            );
        }

        assertSnapshotCurrent(plan, takeSnapshot);
        if (linuxRollbackEnabled) {
            try {
                await assertLinuxRollbackPathAvailable(fileSystem, rollbackPath);
            } catch (error) {
                throw asSecurityApplyError(error);
            }
        }

        try {
            tempHandle = await fileSystem.open(tempPath, 'wx');
            await tempHandle.writeFile(plan.desiredBytes);
            if (plan.snapshot.metadata.platform !== 'win32') {
                await tempHandle.chmod(plan.snapshot.metadata.stat.mode & 0o777);
            }
            await tempHandle.sync();
            await tempHandle.close();
            tempHandle = null;
        } catch (error) {
            throw asAtomicError(error, 'temporary write');
        }

        let tempBytes;
        try {
            tempBytes = await fileSystem.readFile(tempPath);
        } catch (error) {
            throw asAtomicError(error, 'temporary read');
        }
        if (sha256(tempBytes) !== plan.desiredHash) throw new SecurityApplyError(
            'Temporary Security Fix file failed hash validation.',
            6,
            'TEMP_HASH_MISMATCH'
        );

        const tempSnapshot = takeSecurityFileSnapshot(tempPath);
        if (!metadataCanReplace(plan.snapshot.metadata, tempSnapshot.metadata)) throw new SecurityApplyError(
            'Temporary Security Fix file cannot reproduce the target metadata safely.',
            2,
            'METADATA_UNSAFE'
        );

        const tempLint = lintPhpBytes(null, {
            phpCommand,
            filePath: tempPath
        });
        if (!tempLint.available) throw new SecurityApplyError(
            'PHP runtime became unavailable before apply.',
            2,
            'PHP_LINT_UNAVAILABLE'
        );
        if (!tempLint.passed) throw new SecurityApplyError(
            `Temporary Security Fix file failed PHP lint.\n${tempLint.output}`,
            2,
            'PHP_LINT_FAILED'
        );

        // First post-temp stale check.
        assertSnapshotCurrent(plan, takeSnapshot);
        // Immediate pre-rename stale check. Keep this separate so the safety contract is explicit.
        assertSnapshotCurrent(plan, takeSnapshot);

        if (linuxRollbackEnabled) {
            try {
                await createLinuxRollbackBackup({
                    fileSystem,
                    targetPath: plan.targetPath,
                    rollbackPath,
                    originalSnapshot: plan.snapshot,
                    takeSnapshot
                });
                rollbackCreated = true;
                // Keep this as a separate immediate check. nlink === 2 is the
                // expected transaction state after our own hard-link backup.
                await revalidateLinuxTransaction({
                    targetPath: plan.targetPath,
                    rollbackPath,
                    originalSnapshot: plan.snapshot,
                    takeSnapshot
                });
            } catch (error) {
                if (rollbackCreated) {
                    try {
                        await cleanupLinuxRollbackBeforeRename({
                            fileSystem,
                            targetPath: plan.targetPath,
                            rollbackPath,
                            directoryPath: directory,
                            originalSnapshot: plan.snapshot,
                            takeSnapshot
                        });
                        rollbackCreated = false;
                    } catch (cleanupError) {
                        throw asSecurityApplyError(cleanupError);
                    }
                }
                throw asSecurityApplyError(error);
            }
        }

        try {
            await fileSystem.rename(tempPath, plan.targetPath);
        } catch (error) {
            if (linuxRollbackEnabled && rollbackCreated) {
                try {
                    await cleanupLinuxRollbackBeforeRename({
                        fileSystem,
                        targetPath: plan.targetPath,
                        rollbackPath,
                        directoryPath: directory,
                        originalSnapshot: plan.snapshot,
                        takeSnapshot
                    });
                    rollbackCreated = false;
                } catch (cleanupError) {
                    throw asSecurityApplyError(cleanupError);
                }
            }
            throw asAtomicError(error, 'atomic replace');
        }

        if (linuxRollbackEnabled) {
            let finalFailure = null;
            try {
                await fsyncLinuxDirectory(fileSystem, directory);
                const finalSnapshot = takeSnapshot(plan.targetPath);
                assertLinuxFinalSnapshot(
                    plan.snapshot,
                    tempSnapshot,
                    finalSnapshot,
                    plan.desiredHash,
                    plan.desiredBytes.length
                );
            } catch (error) {
                finalFailure = error;
            }

            if (finalFailure) {
                try {
                    await rollbackLinuxTarget({
                        fileSystem,
                        targetPath: plan.targetPath,
                        rollbackPath,
                        directoryPath: directory,
                        originalSnapshot: plan.snapshot,
                        takeSnapshot
                    });
                    rollbackCreated = false;
                } catch (rollbackError) {
                    throw asSecurityApplyError(rollbackError);
                }
                throw new SecurityApplyError(
                    `Security Fix final validation failed and the original file was restored: ${finalFailure.message}`,
                    6,
                    'FINAL_VALIDATION_FAILED_ROLLED_BACK'
                );
            }

            try {
                await removeLinuxRollbackBackup({
                    fileSystem,
                    rollbackPath,
                    directoryPath: directory
                });
                rollbackCreated = false;
            } catch (error) {
                throw asSecurityApplyError(error);
            }
        } else {
            // Preserve the existing Windows apply and final-validation semantics.
            let finalBytes;
            try {
                finalBytes = await fileSystem.readFile(plan.targetPath);
            } catch (error) {
                throw asAtomicError(error, 'final validation read');
            }
            if (sha256(finalBytes) !== plan.desiredHash) throw new SecurityApplyError(
                'Applied Security Fix file failed final hash validation.',
                6,
                'FINAL_HASH_MISMATCH'
            );
        }
        return {
            status: 'applied',
            path: plan.targetPath,
            hash: plan.desiredHash
        };
    } finally {
        if (tempHandle) await tempHandle.close().catch(() => {});
        await removeTemporaryFile(fileSystem, tempPath);
        if (lockHandle) await lockHandle.close().catch(() => {});
        if (ownsLock) await removeTemporaryFile(fileSystem, lockPath);
    }
}
