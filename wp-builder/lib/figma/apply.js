import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline/promises';
import {
    sha256,
    takeFileSnapshot
} from './sync-plan.js';

export class FigmaApplyError extends Error {
    constructor(message, exitCode = 1, code = 'APPLY_ERROR') {
        super(message);
        this.name = 'FigmaApplyError';
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
    const currentTarget = takeFileSnapshot(plan.targetPath, {
        rejectSymlink: true
    });
    const currentColor = takeFileSnapshot(plan.colorPath);
    if (!snapshotsMatch(plan.targetSnapshot, currentTarget)) {
        throw new FigmaApplyError(
            `Figma generated target changed after preview: ${plan.targetPath}`,
            4,
            'STALE_TARGET'
        );
    }
    if (!snapshotsMatch(plan.colorSnapshot, currentColor)) {
        throw new FigmaApplyError(
            `Legacy color ownership file changed after preview: ${plan.colorPath}`,
            4,
            'STALE_COLOR_FILE'
        );
    }
}

async function confirmApply(input, output) {
    const prompt = readline.createInterface({
        input,
        output
    });
    try {
        const answer = await prompt.question('Apply this Figma plan? [y/N] ');
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
        console.warn(`[WARNING] Could not remove temporary file: ${filePath}`);
        console.warn(`  ${error.message}`);
    }
}

export async function applyFigmaSyncPlan(plan, options = {}) {
    const {
        assumeYes = false,
        isTTY = false,
        input = process.stdin,
        output = process.stderr
    } = options;

    if (!plan.canApply) {
        throw new FigmaApplyError(
            'This Figma plan is blocked by conflicts or an unmanaged target.',
            plan.hasUnsafeTarget ? 5 : 2,
            plan.hasUnsafeTarget ? 'UNMANAGED_TARGET' : 'CONFLICT'
        );
    }
    if (!plan.hasChanges) return {
        status: 'no_changes'
    };

    if (!assumeYes) {
        if (!isTTY) throw new FigmaApplyError(
            'Non-interactive apply requires --yes.',
            1,
            'CONFIRMATION_REQUIRED'
        );
        const confirmed = await confirmApply(input, output);
        if (!confirmed) return {
            status: 'cancelled'
        };
    }

    const targetDirectory = path.dirname(plan.targetPath);
    await fs.mkdir(targetDirectory, {
        recursive: true
    });

    const nonce = crypto.randomBytes(8).toString('hex');
    const tempPath = path.join(targetDirectory, `.${path.basename(plan.targetPath)}.${process.pid}.${nonce}.tmp`);
    const lockPath = `${plan.targetPath}.lock`;
    let lockHandle;
    let ownsLock = false;
    let tempHandle;

    try {
        try {
            lockHandle = await fs.open(lockPath, 'wx');
            ownsLock = true;
            await lockHandle.writeFile(`${process.pid}\n`, 'utf8');
            await lockHandle.sync();
        } catch (error) {
            if (error.code === 'EEXIST') throw new FigmaApplyError(
                `Another Figma apply may be running: ${lockPath}`,
                1,
                'LOCKED'
            );
            throw error;
        }

        assertPlanSnapshotsCurrent(plan);

        tempHandle = await fs.open(tempPath, 'wx');
        await tempHandle.writeFile(plan.content, 'utf8');
        await tempHandle.sync();
        await tempHandle.close();
        tempHandle = null;

        const tempBytes = await fs.readFile(tempPath);
        if (sha256(tempBytes) !== plan.contentHash) throw new FigmaApplyError(
            'Temporary Figma generated file failed hash validation.',
            1,
            'TEMP_VALIDATION_FAILED'
        );

        // Recheck after writing the temp file to minimize the preview/apply race.
        assertPlanSnapshotsCurrent(plan);
        await fs.rename(tempPath, plan.targetPath);

        const finalBytes = await fs.readFile(plan.targetPath);
        if (sha256(finalBytes) !== plan.contentHash) throw new FigmaApplyError(
            'Applied Figma generated file failed final hash validation.',
            1,
            'FINAL_VALIDATION_FAILED'
        );

        return {
            status: 'applied',
            path: plan.targetPath,
            hash: plan.contentHash
        };
    } finally {
        if (tempHandle) await tempHandle.close().catch(() => {});
        await removeTemporaryFile(tempPath);
        if (lockHandle) await lockHandle.close().catch(() => {});
        if (ownsLock) await removeTemporaryFile(lockPath);
    }
}
