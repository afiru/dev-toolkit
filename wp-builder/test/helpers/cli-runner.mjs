import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { assertTempTarget } from './temp-workspace.mjs';

const cliPath = fileURLToPath(new URL('../../bin/cli.mjs', import.meta.url));

export function runCli(cwd, args, options = {}) {
    assertTempTarget(cwd, cwd);
    return spawnSync(process.execPath, [cliPath, ...args], {
        cwd,
        encoding: 'utf8',
        env: options.env,
        input: options.input,
        windowsHide: true
    });
}
