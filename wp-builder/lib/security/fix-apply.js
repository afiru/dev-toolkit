import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline/promises';
import {
    lintPhpBytes,
    sha256,
    takeSecurityFileSnapshot
} from './fix-plan.js';

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
        expected.hash === current.hash
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

    if (!plan.canApply) throw new SecurityApplyError(
        'This Security Fix Plan is blocked. No files were changed.',
        2,
        'PLAN_BLOCKED'
    );
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

        try {
            tempHandle = await fileSystem.open(tempPath, 'wx');
            await tempHandle.writeFile(plan.desiredBytes);
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

        try {
            await fileSystem.rename(tempPath, plan.targetPath);
        } catch (error) {
            throw asAtomicError(error, 'atomic replace');
        }

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
