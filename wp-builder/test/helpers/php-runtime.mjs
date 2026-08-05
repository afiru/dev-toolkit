import { spawnSync } from 'node:child_process';

let cached;

export function inspectPhpRuntime() {
    if (cached) return cached;
    const version = spawnSync('php', ['--version'], { encoding: 'utf8', windowsHide: true });
    if (version.error?.code === 'ENOENT' || version.status !== 0) {
        cached = {
            available: false,
            reason: 'PHP CLI is unavailable.',
            version: null,
            tokenizer: false
        };
        return cached;
    }
    const tokenizer = spawnSync('php', ['-r', "exit(extension_loaded('tokenizer') ? 0 : 2);"], {
        encoding: 'utf8',
        windowsHide: true
    });
    cached = {
        available: tokenizer.status === 0,
        reason: tokenizer.status === 0 ? null : 'PHP tokenizer extension is unavailable.',
        version: version.stdout.split(/\r?\n/)[0],
        tokenizer: tokenizer.status === 0
    };
    return cached;
}

export function phpIntegrationTestOptions() {
    const runtime = inspectPhpRuntime();
    return runtime.available ? {} : { skip: runtime.reason };
}
