import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const SECURITY_TEST_SUITES = Object.freeze([
    Object.freeze({ name: 'npm test', args: ['test'] }),
    Object.freeze({ name: 'test:security:required', args: ['run', 'test:security:required'] }),
    Object.freeze({ name: 'test:security:metadata', args: ['run', 'test:security:metadata'] })
]);

function runNpm(suite) {
    if (!process.env.npm_execpath) {
        return {
            status: null,
            error: new Error('npm_execpath is unavailable; run this helper through npm.')
        };
    }
    return spawnSync(process.execPath, [process.env.npm_execpath, ...suite.args], {
        cwd: process.cwd(),
        env: process.env,
        stdio: 'inherit',
        windowsHide: true
    });
}

export function runSecurityTestSuites({ runCommand = runNpm, log = console.log, logError = console.error } = {}) {
    let failed = false;

    for (const suite of SECURITY_TEST_SUITES) {
        const result = runCommand(suite);
        const status = result.status ?? 'spawn-error';
        log(`[security-suite] ${suite.name}: ${status}`);
        if (result.error) logError(`[security-suite] ${suite.name}: ${result.error.message}`);
        if (result.error || result.status !== 0) {
            failed = true;
        }
    }

    return failed ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    process.exitCode = runSecurityTestSuites();
}
