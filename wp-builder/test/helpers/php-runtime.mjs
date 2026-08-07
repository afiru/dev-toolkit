import { spawnSync } from 'node:child_process';

let cached;
let linuxMetadataCached;

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
    const match = version.stdout.match(/^PHP\s+(\d+)\.(\d+)\.(\d+)/m);
    cached = {
        available: tokenizer.status === 0,
        reason: tokenizer.status === 0 ? null : 'PHP tokenizer extension is unavailable.',
        version: version.stdout.split(/\r?\n/)[0],
        phpVersion: match?.[0]?.replace(/^PHP\s+/, '') ?? null,
        phpMajor: match ? Number(match[1]) : null,
        phpMinor: match ? Number(match[2]) : null,
        tokenizer: tokenizer.status === 0
    };
    return cached;
}

export function assertExpectedPhpMinor(assert, runtime = inspectPhpRuntime()) {
    assert.equal(runtime.available, true, runtime.reason);
    const expected = process.env.WPB_EXPECTED_PHP_MINOR;
    if (!expected) return;
    assert.match(expected, /^\d+\.\d+$/, 'WPB_EXPECTED_PHP_MINOR must use major.minor format.');
    assert.equal(
        `${runtime.phpMajor}.${runtime.phpMinor}`,
        expected,
        `Expected PHP ${expected}, received ${runtime.phpVersion ?? runtime.version}.`
    );
}

export function expectedPhpRuntimeGate(runtime) {
    if (runtime.phpMajor < 8) {
        return {
            status: 'PHP_VERSION_UNSUPPORTED',
            applyEligible: false,
            blockingCode: 'PHP_VERSION_UNSUPPORTED'
        };
    }
    if (runtime.phpMajor === 8 && runtime.phpMinor <= 1) {
        return {
            status: 'LEGACY_COMPATIBILITY',
            applyEligible: false,
            blockingCode: 'PHP_VERSION_LEGACY_COMPATIBILITY'
        };
    }
    if (runtime.phpMajor === 8 && runtime.phpMinor <= 4) {
        return {
            status: 'VERIFIED_APPLY_CANDIDATE',
            applyEligible: true,
            blockingCode: null
        };
    }
    return {
        status: 'PHP_VERSION_UNVERIFIED',
        applyEligible: false,
        blockingCode: 'PHP_VERSION_UNVERIFIED'
    };
}

export function phpIntegrationTestOptions() {
    const runtime = inspectPhpRuntime();
    return runtime.available ? {} : { skip: runtime.reason };
}

export function inspectLinuxMetadataRuntime() {
    if (process.platform !== 'linux') return {
        available: false,
        reason: 'Linux-only metadata integration test.'
    };
    if (linuxMetadataCached) return linuxMetadataCached;
    for (const command of ['getfacl', 'getfattr']) {
        const result = spawnSync(command, ['--version'], {
            encoding: 'utf8',
            env: { ...process.env, LC_ALL: 'C', LANG: 'C' },
            windowsHide: true
        });
        if (result.error?.code === 'ENOENT' || result.status !== 0) {
            linuxMetadataCached = {
                available: false,
                reason: `Linux metadata integration requires ${command}.`
            };
            return linuxMetadataCached;
        }
    }
    linuxMetadataCached = { available: true, reason: null };
    return linuxMetadataCached;
}

export function securityFixIntegrationTestOptions() {
    const php = inspectPhpRuntime();
    if (!php.available) return { skip: php.reason };
    if (process.platform === 'win32') return {};
    if (process.platform === 'linux') {
        const metadata = inspectLinuxMetadataRuntime();
        return metadata.available ? {} : { skip: metadata.reason };
    }
    return { skip: `Security Fix apply metadata is unsupported on ${process.platform}.` };
}
