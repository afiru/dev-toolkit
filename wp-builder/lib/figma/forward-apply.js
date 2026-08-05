import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline/promises';
import {
    sha256
} from './sync-plan.js';
import {
    takeForwardFileSnapshot
} from './forward-plan.js';

export class FigmaForwardApplyError extends Error {
    constructor(message, exitCode = 1, code = 'FORWARD_APPLY_ERROR') {
        super(message);
        this.name = 'FigmaForwardApplyError';
        this.exitCode = exitCode;
        this.code = code;
    }
}

function snapshotsMatch(expected, current) {
    if (expected.state !== current.state) return false;
    if (expected.state === 'missing') return true;
    if (expected.state !== 'present') return false;
    return expected.hash === current.hash;
}

function assertPlanSnapshotsCurrent(plan) {
    const currentIndex = takeForwardFileSnapshot(plan.indexPath);
    const currentTarget = takeForwardFileSnapshot(plan.targetPath);
    if (!snapshotsMatch(plan.indexSnapshot, currentIndex)) {
        throw new FigmaForwardApplyError(
            `Component index changed after preview: ${plan.indexPath}`,
            4,
            'STALE_COMPONENT_INDEX'
        );
    }
    if (!snapshotsMatch(plan.targetSnapshot, currentTarget)) {
        throw new FigmaForwardApplyError(
            `Figma managed target changed after preview: ${plan.targetPath}`,
            4,
            'STALE_FIGMA_TARGET'
        );
    }
}

async function confirmApply(input, output) {
    const prompt = readline.createInterface({
        input,
        output
    });
    try {
        const answer = await prompt.question('Apply this Forward Plan to _Component.scss? [y/N] ');
        return /^(y|yes)$/i.test(answer.trim());
    } finally {
        prompt.close();
    }
}

async function removeTemporaryFile(filePath) {
    if (!filePath) return;
    try {
        await fs.rm(filePath, {
            force: true
        });
    } catch (error) {
        console.warn(`[WARNING] Could not remove temporary Forward Plan file: ${filePath}`);
        console.warn(`  ${error.message}`);
    }
}

async function writeLock(handle) {
    await handle.writeFile(`${process.pid}\n`, 'utf8');
    await handle.sync();
}

export async function applyFigmaForwardPlan(plan, options = {}) {
    const {
        assumeYes = false,
        isTTY = false,
        input = process.stdin,
        output = process.stderr
    } = options;

    if (!plan.canApply) {
        throw new FigmaForwardApplyError(
            'This Forward Plan is blocked. No files were changed.',
            plan.blockingExitCode || 1,
            'FORWARD_PLAN_BLOCKED'
        );
    }
    if (!plan.hasChanges) return {
        status: 'no_changes'
    };

    if (!assumeYes) {
        if (!isTTY) throw new FigmaForwardApplyError(
            'Non-interactive apply requires --yes.',
            1,
            'CONFIRMATION_REQUIRED'
        );
        const confirmed = await confirmApply(input, output);
        if (!confirmed) return {
            status: 'cancelled'
        };
    }

    const nonce = crypto.randomBytes(8).toString('hex');
    const tempPath = path.join(
        path.dirname(plan.indexPath),
        `.${path.basename(plan.indexPath)}.${process.pid}.${nonce}.tmp`
    );
    const targetLockPath = `${plan.targetPath}.lock`;
    const indexLockPath = `${plan.indexPath}.lock`;
    let targetLockHandle;
    let indexLockHandle;
    let tempHandle;
    let ownsTargetLock = false;
    let ownsIndexLock = false;

    try {
        try {
            targetLockHandle = await fs.open(targetLockPath, 'wx');
            ownsTargetLock = true;
            await writeLock(targetLockHandle);
        } catch (error) {
            if (error.code === 'EEXIST') throw new FigmaForwardApplyError(
                `Figma target is locked: ${targetLockPath}`,
                1,
                'TARGET_LOCKED'
            );
            throw error;
        }

        try {
            indexLockHandle = await fs.open(indexLockPath, 'wx');
            ownsIndexLock = true;
            await writeLock(indexLockHandle);
        } catch (error) {
            if (error.code === 'EEXIST') throw new FigmaForwardApplyError(
                `Component index is locked: ${indexLockPath}`,
                1,
                'INDEX_LOCKED'
            );
            throw error;
        }

        assertPlanSnapshotsCurrent(plan);

        tempHandle = await fs.open(tempPath, 'wx');
        await tempHandle.writeFile(plan.desiredContent, 'utf8');
        await tempHandle.sync();
        await tempHandle.close();
        tempHandle = null;

        const tempBytes = await fs.readFile(tempPath);
        if (sha256(tempBytes) !== plan.desiredHash) throw new FigmaForwardApplyError(
            'Temporary Component index failed hash validation.',
            1,
            'TEMP_VALIDATION_FAILED'
        );

        assertPlanSnapshotsCurrent(plan);
        await fs.rename(tempPath, plan.indexPath);

        const finalBytes = await fs.readFile(plan.indexPath);
        if (sha256(finalBytes) !== plan.desiredHash) throw new FigmaForwardApplyError(
            'Applied Component index failed final hash validation.',
            1,
            'FINAL_VALIDATION_FAILED'
        );

        return {
            status: 'applied',
            path: plan.indexPath,
            hash: plan.desiredHash
        };
    } finally {
        if (tempHandle) await tempHandle.close().catch(() => {});
        await removeTemporaryFile(tempPath);
        if (indexLockHandle) await indexLockHandle.close().catch(() => {});
        if (ownsIndexLock) await removeTemporaryFile(indexLockPath);
        if (targetLockHandle) await targetLockHandle.close().catch(() => {});
        if (ownsTargetLock) await removeTemporaryFile(targetLockPath);
    }
}
