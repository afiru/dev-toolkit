import fs from 'node:fs';
import path from 'node:path';
import { getBundledWindowsInspectorPath } from '../../lib/security/windows-native-inspector.js';

function isInside(parent, target) {
    const relative = path.relative(parent, target);
    return relative === '' || (
        relative !== '..' &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative)
    );
}

export function resolveWindowsNativeInspectorTestPath(
    env = process.env,
    variableName = 'WPB_TEST_WINDOWS_INSPECTOR_PATH'
) {
    const configuredPath = env[variableName];
    if (!configuredPath) return getBundledWindowsInspectorPath();
    if (!path.isAbsolute(configuredPath)) {
        throw new Error(`${variableName} must be an absolute path.`);
    }

    const runnerTemp = env.RUNNER_TEMP;
    if (!runnerTemp || !path.isAbsolute(runnerTemp)) {
        throw new Error('RUNNER_TEMP must be an absolute path when the test helper override is used.');
    }

    const helperStat = fs.lstatSync(configuredPath);
    if (!helperStat.isFile() || helperStat.isSymbolicLink()) {
        throw new Error(`${variableName} must identify a regular, non-symlink file.`);
    }

    const realRunnerTemp = fs.realpathSync.native(runnerTemp);
    const realHelperPath = fs.realpathSync.native(configuredPath);
    if (!isInside(realRunnerTemp, realHelperPath)) {
        throw new Error(`${variableName} must be inside RUNNER_TEMP.`);
    }
    return realHelperPath;
}
