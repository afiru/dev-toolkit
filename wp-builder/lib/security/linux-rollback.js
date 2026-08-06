import path from 'node:path';

export const LINUX_ROLLBACK_SUFFIX = '.security-fix.rollback';

export class LinuxRollbackError extends Error {
    constructor(message, exitCode = 6, code = 'LINUX_ROLLBACK_ERROR', details = {}) {
        super(message);
        this.name = 'LinuxRollbackError';
        this.exitCode = exitCode;
        this.code = code;
        this.details = details;
    }
}

export function linuxRollbackPath(targetPath) {
    return `${targetPath}${LINUX_ROLLBACK_SUFFIX}`;
}

function isPresentNormalFile(snapshot) {
    return snapshot?.state === 'present' &&
        snapshot.normalFile === true &&
        snapshot.symlink === false;
}

function hasSafeMetadata(snapshot) {
    return (snapshot?.metadata?.capability?.blockingReasons?.length ?? 0) === 0;
}

function sameSecurityMetadata(expected, current) {
    return expected?.metadata?.platform === current?.metadata?.platform &&
        expected?.metadata?.stat?.mode === current?.metadata?.stat?.mode &&
        expected?.metadata?.stat?.uid === current?.metadata?.stat?.uid &&
        expected?.metadata?.stat?.gid === current?.metadata?.stat?.gid &&
        expected?.metadata?.securityFingerprint === current?.metadata?.securityFingerprint &&
        hasSafeMetadata(current);
}

function sameOriginalInode(original, current, expectedLinks) {
    return isPresentNormalFile(current) &&
        current.size === original.size &&
        current.hash === original.hash &&
        current.metadata?.identity?.dev === original.metadata?.identity?.dev &&
        current.metadata?.identity?.ino === original.metadata?.identity?.ino &&
        current.metadata?.identity?.nlink === expectedLinks &&
        sameSecurityMetadata(original, current);
}

async function pathExists(fileSystem, filePath) {
    try {
        await fileSystem.lstat(filePath);
        return true;
    } catch (error) {
        if (error.code === 'ENOENT') return false;
        throw error;
    }
}

export async function assertLinuxRollbackPathAvailable(fileSystem, rollbackPath) {
    let exists;
    try {
        exists = await pathExists(fileSystem, rollbackPath);
    } catch (error) {
        throw new LinuxRollbackError(
            `Could not inspect Security Fix recovery artifact: ${rollbackPath}`,
            6,
            'RECOVERY_INSPECTION_FAILED'
        );
    }
    if (exists) throw new LinuxRollbackError(
        `Security Fix recovery is required before another apply: ${rollbackPath}`,
        2,
        'RECOVERY_REQUIRED',
        { rollbackPath }
    );
}

export async function fsyncLinuxDirectory(fileSystem, directoryPath) {
    let handle;
    try {
        handle = await fileSystem.open(directoryPath, 'r');
        await handle.sync();
    } catch (error) {
        throw new LinuxRollbackError(
            `Security Fix directory fsync failed: ${directoryPath}`,
            6,
            'DIRECTORY_FSYNC_FAILED'
        );
    } finally {
        if (handle) await handle.close().catch(() => {});
    }
}

export function assertLinuxTransactionSnapshot(original, target, backup) {
    if (!sameOriginalInode(original, target, 2) ||
        !sameOriginalInode(original, backup, 2) ||
        target.metadata.identity.dev !== backup.metadata.identity.dev ||
        target.metadata.identity.ino !== backup.metadata.identity.ino) {
        throw new LinuxRollbackError(
            'Security Fix rollback transaction changed before atomic replace.',
            4,
            'STALE_FILE'
        );
    }
}

function isSafeRollbackEntry(original, target, backup) {
    const targetLinks = target?.metadata?.identity?.nlink;
    return isPresentNormalFile(target) &&
        isPresentNormalFile(backup) &&
        target.size === original.size &&
        backup.size === original.size &&
        target.hash === original.hash &&
        backup.hash === original.hash &&
        target.metadata?.identity?.dev === original.metadata?.identity?.dev &&
        target.metadata?.identity?.ino === original.metadata?.identity?.ino &&
        backup.metadata?.identity?.dev === original.metadata?.identity?.dev &&
        backup.metadata?.identity?.ino === original.metadata?.identity?.ino &&
        targetLinks >= 2 &&
        backup.metadata?.identity?.nlink === targetLinks &&
        sameSecurityMetadata(original, target) &&
        sameSecurityMetadata(original, backup);
}

export async function cleanupLinuxRollbackBeforeRename({
    fileSystem,
    targetPath,
    rollbackPath,
    directoryPath,
    originalSnapshot,
    takeSnapshot
}) {
    const target = takeSnapshot(targetPath);
    const backup = takeSnapshot(rollbackPath);
    if (!isSafeRollbackEntry(originalSnapshot, target, backup)) throw new LinuxRollbackError(
        `Security Fix recovery is required: ${rollbackPath}`,
        6,
        'ROLLBACK_FAILED_RECOVERY_REQUIRED',
        {
            rollbackPath,
            targetPath,
            originalHash: originalSnapshot.hash,
            currentHash: target?.hash ?? null
        }
    );
    await fileSystem.unlink(rollbackPath);
    await fsyncLinuxDirectory(fileSystem, directoryPath);
}

export function assertLinuxFinalSnapshot(original, temporary, finalSnapshot, desiredHash, desiredSize) {
    if (!isPresentNormalFile(finalSnapshot) ||
        finalSnapshot.size !== desiredSize ||
        finalSnapshot.hash !== desiredHash ||
        finalSnapshot.metadata?.identity?.dev !== temporary.metadata?.identity?.dev ||
        finalSnapshot.metadata?.identity?.ino !== temporary.metadata?.identity?.ino ||
        finalSnapshot.metadata?.identity?.nlink !== 1 ||
        !sameSecurityMetadata(temporary, finalSnapshot) ||
        original.metadata?.stat?.mode !== finalSnapshot.metadata?.stat?.mode ||
        original.metadata?.stat?.uid !== finalSnapshot.metadata?.stat?.uid ||
        original.metadata?.stat?.gid !== finalSnapshot.metadata?.stat?.gid ||
        original.metadata?.replacementFingerprint !== finalSnapshot.metadata?.replacementFingerprint) {
        throw new LinuxRollbackError(
            'Applied Security Fix file failed final validation.',
            6,
            'FINAL_VALIDATION_FAILED'
        );
    }
}

export function assertLinuxRestoredSnapshot(original, restored) {
    if (!sameOriginalInode(original, restored, 1)) throw new LinuxRollbackError(
        'Security Fix rollback could not verify the restored original file.',
        6,
        'ROLLBACK_VALIDATION_FAILED'
    );
}

export async function createLinuxRollbackBackup({
    fileSystem,
    targetPath,
    rollbackPath,
    originalSnapshot,
    takeSnapshot
}) {
    await assertLinuxRollbackPathAvailable(fileSystem, rollbackPath);
    let linked = false;
    try {
        await fileSystem.link(targetPath, rollbackPath);
        linked = true;
    } catch (error) {
        if (error.code === 'EEXIST') throw new LinuxRollbackError(
            `Security Fix recovery is required before another apply: ${rollbackPath}`,
            2,
            'RECOVERY_REQUIRED',
            { rollbackPath }
        );
        throw new LinuxRollbackError(
            `Could not create Security Fix rollback backup: ${error.message}`,
            6,
            'ROLLBACK_BACKUP_FAILED'
        );
    }

    const directory = path.dirname(targetPath);
    try {
        await fsyncLinuxDirectory(fileSystem, directory);
        const targetSnapshot = takeSnapshot(targetPath);
        const backupSnapshot = takeSnapshot(rollbackPath);
        assertLinuxTransactionSnapshot(originalSnapshot, targetSnapshot, backupSnapshot);
        return { targetSnapshot, backupSnapshot };
    } catch (error) {
        if (linked) {
            try {
                await cleanupLinuxRollbackBeforeRename({
                    fileSystem,
                    targetPath,
                    rollbackPath,
                    directoryPath: directory,
                    originalSnapshot,
                    takeSnapshot
                });
            } catch (cleanupError) {
                throw cleanupError;
            }
        }
        throw error;
    }
}

export async function revalidateLinuxTransaction({
    targetPath,
    rollbackPath,
    originalSnapshot,
    takeSnapshot
}) {
    const targetSnapshot = takeSnapshot(targetPath);
    const backupSnapshot = takeSnapshot(rollbackPath);
    assertLinuxTransactionSnapshot(originalSnapshot, targetSnapshot, backupSnapshot);
    return { targetSnapshot, backupSnapshot };
}

export async function removeLinuxRollbackBackup({ fileSystem, rollbackPath, directoryPath }) {
    try {
        await fileSystem.unlink(rollbackPath);
    } catch (error) {
        throw new LinuxRollbackError(
            `Could not remove Security Fix rollback backup: ${rollbackPath}`,
            6,
            'RECOVERY_REQUIRED',
            { rollbackPath }
        );
    }
    await fsyncLinuxDirectory(fileSystem, directoryPath);
}

export async function rollbackLinuxTarget({
    fileSystem,
    targetPath,
    rollbackPath,
    directoryPath,
    originalSnapshot,
    takeSnapshot
}) {
    try {
        await fileSystem.rename(rollbackPath, targetPath);
        await fsyncLinuxDirectory(fileSystem, directoryPath);
        const restored = takeSnapshot(targetPath);
        assertLinuxRestoredSnapshot(originalSnapshot, restored);
        return restored;
    } catch (error) {
        // rename() consumes the rollback name on success. If validation then fails,
        // recreate the recovery link only when target still names the original inode.
        try {
            const current = takeSnapshot(targetPath);
            if (sameOriginalInode(originalSnapshot, current, 1) && !(await pathExists(fileSystem, rollbackPath))) {
                await fileSystem.link(targetPath, rollbackPath);
                await fsyncLinuxDirectory(fileSystem, directoryPath);
            }
        } catch {
            // Preserve the original failure. Recovery state is reported to the caller.
        }
        const current = takeSnapshot(targetPath);
        throw new LinuxRollbackError(
            `Security Fix rollback failed; recovery artifact must be preserved: ${rollbackPath}`,
            6,
            'ROLLBACK_FAILED_RECOVERY_REQUIRED',
            {
                rollbackPath,
                targetPath,
                originalHash: originalSnapshot.hash,
                currentHash: current?.hash ?? null
            }
        );
    }
}
