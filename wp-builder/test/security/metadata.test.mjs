import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { applySecurityFixPlan } from '../../lib/security/fix-apply.js';
import {
    buildSecurityFixPlan,
    takeSecurityFileSnapshot
} from '../../lib/security/fix-plan.js';
import {
    createWindowsPowerShellEnvironment,
    inspectSecurityMetadata
} from '../../lib/security/metadata.js';
import {
    phpIntegrationTestOptions,
    securityFixIntegrationTestOptions
} from '../helpers/php-runtime.mjs';
import {
    assertNoSecurityArtifacts,
    assertTempTarget,
    createTempWorkspace,
    writeTempFile
} from '../helpers/temp-workspace.mjs';

const source = Buffer.from("<p><?= SCF::get('title') ?></p>\n");

function powershell(script) {
    return spawnSync('powershell.exe', ['-NoProfile', '-Command', script], {
        encoding: 'utf8',
        windowsHide: true
    });
}

function psQuote(value) {
    return `'${value.replaceAll("'", "''")}'`;
}

function windowsAcl(file) {
    const result = powershell(`(Get-Acl -LiteralPath ${psQuote(file)}).Sddl`);
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
}

const windowsPhpOptions = process.platform === 'win32'
    ? phpIntegrationTestOptions()
    : { skip: 'Windows-only metadata test.' };
const linuxMetadataPhpOptions = process.platform === 'linux'
    ? securityFixIntegrationTestOptions()
    : { skip: 'Linux-only metadata test.' };

function blockingCodes(plan) {
    return plan.blockingReasons.map(reason => reason.code);
}

test('Windows PowerShell child environment removes only PSModulePath case-insensitively', async t => {
    for (const key of ['PSModulePath', 'PSMODULEPATH', 'psmodulepath', 'PsMoDuLePaTh']) {
        await t.test(key, () => {
            const sourceEnvironment = {
                PATH: 'C:\\Windows\\System32',
                SystemRoot: 'C:\\Windows',
                TEMP: 'C:\\Temp',
                TMP: 'C:\\Temp',
                USERPROFILE: 'C:\\Users\\fixture',
                WinPSModulePath: 'C:\\WindowsPowerShell\\Modules',
                [key]: 'C:\\Program Files\\PowerShell\\7\\Modules'
            };
            const originalEnvironment = { ...sourceEnvironment };
            const childEnvironment = createWindowsPowerShellEnvironment(
                sourceEnvironment,
                'C:\\fixture\\case.php'
            );

            assert.deepEqual(sourceEnvironment, originalEnvironment);
            assert.equal(
                Object.keys(childEnvironment).some(name => name.toLowerCase() === 'psmodulepath'),
                false
            );
            assert.equal(childEnvironment.PATH, sourceEnvironment.PATH);
            assert.equal(childEnvironment.SystemRoot, sourceEnvironment.SystemRoot);
            assert.equal(childEnvironment.TEMP, sourceEnvironment.TEMP);
            assert.equal(childEnvironment.TMP, sourceEnvironment.TMP);
            assert.equal(childEnvironment.USERPROFILE, sourceEnvironment.USERPROFILE);
            assert.equal(childEnvironment.WinPSModulePath, sourceEnvironment.WinPSModulePath);
            assert.equal(childEnvironment.WPB_SECURITY_METADATA_TARGET, 'C:\\fixture\\case.php');
        });
    }

    await t.test('PSModulePath absent', () => {
        const sourceEnvironment = {
            PATH: 'C:\\Windows\\System32',
            WinPSModulePath: 'C:\\WindowsPowerShell\\Modules'
        };
        const childEnvironment = createWindowsPowerShellEnvironment(
            sourceEnvironment,
            'C:\\fixture\\case.php'
        );
        assert.deepEqual(sourceEnvironment, {
            PATH: 'C:\\Windows\\System32',
            WinPSModulePath: 'C:\\WindowsPowerShell\\Modules'
        });
        assert.equal(childEnvironment.PATH, sourceEnvironment.PATH);
        assert.equal(childEnvironment.WinPSModulePath, sourceEnvironment.WinPSModulePath);
        assert.equal(
            Object.keys(childEnvironment).some(name => name.toLowerCase() === 'psmodulepath'),
            false
        );
        assert.equal(childEnvironment.WPB_SECURITY_METADATA_TARGET, 'C:\\fixture\\case.php');
    });
});

test('Windows metadata inspection passes a sanitized copy to powershell.exe', () => {
    const originalEnvironment = { ...process.env };
    let spawnCall;
    const windowsResponse = {
        readonly: false,
        attributes: 128,
        aclProtected: false,
        explicitAccessRuleCount: 0,
        ownerSid: 'S-1-5-21-fixture',
        groupSid: 'S-1-5-21-fixture',
        currentSid: 'S-1-5-21-fixture',
        daclSddl: 'fixture',
        daclOnlySddl: 'fixture',
        daclState: 'present',
        daclRevision: 2,
        streams: []
    };
    const metadata = inspectSecurityMetadata('C:\\fixture\\case.php', {
        dev: 1,
        ino: 2,
        nlink: 1,
        mode: 0,
        uid: 0,
        gid: 0
    }, {
        platform: 'win32',
        spawnSync(command, args, options) {
            spawnCall = { command, args, options };
            return {
                status: 0,
                stdout: JSON.stringify(windowsResponse),
                stderr: ''
            };
        },
        nativeInspector: () => ({
            status: 'unavailable',
            inspected: false,
            code: 'WINDOWS_NATIVE_INSPECTOR_UNAVAILABLE',
            message: 'fixture'
        })
    });

    assert.equal(spawnCall.command, 'powershell.exe');
    assert.equal(
        Object.keys(spawnCall.options.env).some(key => key.toLowerCase() === 'psmodulepath'),
        false
    );
    for (const key of ['PATH', 'SystemRoot', 'TEMP', 'TMP', 'USERPROFILE', 'WinPSModulePath']) {
        if (Object.hasOwn(process.env, key)) {
            assert.equal(spawnCall.options.env[key], process.env[key]);
        }
    }
    assert.equal(spawnCall.options.env.WPB_SECURITY_METADATA_TARGET, 'C:\\fixture\\case.php');
    assert.deepEqual({ ...process.env }, originalEnvironment);
    assert.equal(metadata.capability.inspectable, true);
    assert.equal(metadata.nativeShadow.compared, false);
});

test('Windows protected explicit ACL is blocked before rename', windowsPhpOptions, async t => {
    const root = createTempWorkspace(t, 'metadata-acl');
    const file = writeTempFile(root, 'case.php', source);
    const setup = spawnSync('icacls.exe', [file, '/inheritance:d'], { encoding: 'utf8', windowsHide: true });
    assert.equal(setup.status, 0, setup.stderr);
    const before = windowsAcl(file);
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    assertTempTarget(root, plan.targetPath);
    assert.equal(plan.canApply, false);
    assert.ok(blockingCodes(plan).includes('WINDOWS_SPECIAL_ACL'));
    await assert.rejects(
        () => applySecurityFixPlan(plan, { assumeYes: true }),
        error => error.exitCode === 2 && error.code === 'PLAN_BLOCKED'
    );
    assert.equal(windowsAcl(file), before);
    assert.deepEqual(fs.readFileSync(file), source);
    assertNoSecurityArtifacts(root);
});

test('Windows read-only target is blocked at Plan time', windowsPhpOptions, async t => {
    const root = createTempWorkspace(t, 'metadata-readonly');
    const file = writeTempFile(root, 'case.php', source);
    const setReadOnly = powershell(`(Get-Item -LiteralPath ${psQuote(file)} -Force).IsReadOnly = $true`);
    assert.equal(setReadOnly.status, 0, setReadOnly.stderr);
    try {
        const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
        assertTempTarget(root, plan.targetPath);
        assert.equal(plan.canApply, false);
        assert.ok(blockingCodes(plan).includes('READ_ONLY_TARGET'));
        await assert.rejects(
            () => applySecurityFixPlan(plan, { assumeYes: true }),
            error => error.exitCode === 2 && error.code === 'PLAN_BLOCKED'
        );
        assert.deepEqual(fs.readFileSync(file), source);
        assertNoSecurityArtifacts(root);
    } finally {
        powershell(`(Get-Item -LiteralPath ${psQuote(file)} -Force).IsReadOnly = $false`);
    }
});

test('Windows alternate data stream is blocked before rename', windowsPhpOptions, async t => {
    const root = createTempWorkspace(t, 'metadata-ads');
    const file = writeTempFile(root, 'case.php', source);
    fs.writeFileSync(`${file}:wpb-metadata-test`, 'metadata');
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    assert.equal(plan.canApply, false);
    assert.ok(blockingCodes(plan).includes('WINDOWS_ADS_UNSUPPORTED'));
    await assert.rejects(
        () => applySecurityFixPlan(plan, { assumeYes: true }),
        error => error.exitCode === 2 && error.code === 'PLAN_BLOCKED'
    );
    assert.deepEqual(fs.readFileSync(file), source);
    assert.equal(fs.readFileSync(`${file}:wpb-metadata-test`, 'utf8'), 'metadata');
    assertNoSecurityArtifacts(root);
});

test('hard-linked target is blocked before rename', phpIntegrationTestOptions(), async t => {
    const root = createTempWorkspace(t, 'metadata-hardlink');
    const file = writeTempFile(root, 'case.php', source);
    const linked = `${file}.linked.php`;
    fs.linkSync(file, linked);
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    assert.equal(plan.snapshot.metadata.identity.nlink, 2);
    assert.equal(plan.canApply, false);
    assert.ok(blockingCodes(plan).includes('HARD_LINK_TARGET'));
    await assert.rejects(
        () => applySecurityFixPlan(plan, { assumeYes: true }),
        error => error.exitCode === 2 && error.code === 'PLAN_BLOCKED'
    );
    assert.deepEqual(fs.readFileSync(file), source);
    assert.deepEqual(fs.readFileSync(linked), source);
    assertNoSecurityArtifacts(root);
});

test('unavailable Windows metadata inspection fails closed', windowsPhpOptions, t => {
    const root = createTempWorkspace(t, 'metadata-unavailable');
    const file = writeTempFile(root, 'case.php', source);
    const plan = buildSecurityFixPlan({
        workspaceRoot: root,
        file,
        metadataOptions: {
            spawnSync: () => ({
                error: Object.assign(new Error('injected inspector failure'), { code: 'ENOENT' }),
                status: null,
                stdout: '',
                stderr: ''
            })
        }
    });
    assert.equal(plan.canApply, false);
    assert.ok(blockingCodes(plan).includes('UNSUPPORTED_WINDOWS_METADATA'));
    assert.deepEqual(fs.readFileSync(file), source);
    assertNoSecurityArtifacts(root);
});

test('file identity change with identical bytes is stale', securityFixIntegrationTestOptions(), async t => {
    const root = createTempWorkspace(t, 'metadata-identity-stale');
    const file = writeTempFile(root, 'case.php', source);
    const replacement = writeTempFile(root, 'replacement.php', source);
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    assert.equal(plan.canApply, true);
    fs.renameSync(replacement, file);
    await assert.rejects(
        () => applySecurityFixPlan(plan, { assumeYes: true }),
        error => error.exitCode === 4 && error.code === 'STALE_FILE'
    );
    assert.deepEqual(fs.readFileSync(file), source);
    assertNoSecurityArtifacts(root);
});

test('metadata change after preview is stale and preserves the original', securityFixIntegrationTestOptions(), async t => {
    const root = createTempWorkspace(t, 'metadata-stale');
    const file = writeTempFile(root, 'case.php', source);
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    assert.equal(plan.canApply, true);
    if (process.platform === 'win32') {
        const changed = powershell(`(Get-Item -LiteralPath ${psQuote(file)} -Force).IsReadOnly = $true`);
        assert.equal(changed.status, 0, changed.stderr);
    } else {
        fs.chmodSync(file, 0o400);
    }
    try {
        await assert.rejects(
            () => applySecurityFixPlan(plan, { assumeYes: true }),
            error => error.exitCode === 4 && error.code === 'STALE_FILE'
        );
        assert.deepEqual(fs.readFileSync(file), source);
        assertNoSecurityArtifacts(root);
    } finally {
        if (process.platform === 'win32') {
            powershell(`(Get-Item -LiteralPath ${psQuote(file)} -Force).IsReadOnly = $false`);
        } else {
            fs.chmodSync(file, 0o600);
        }
    }
});

test('metadata change after temp validation stops before rename and cleans artifacts', securityFixIntegrationTestOptions(), async t => {
    const root = createTempWorkspace(t, 'metadata-stale-after-temp');
    const file = writeTempFile(root, 'case.php', source);
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    let checks = 0;
    const takeSnapshot = target => {
        checks += 1;
        if (checks === 2) {
            if (process.platform === 'win32') {
                const changed = powershell(`(Get-Item -LiteralPath ${psQuote(target)} -Force).IsReadOnly = $true`);
                assert.equal(changed.status, 0, changed.stderr);
            } else {
                fs.chmodSync(target, 0o400);
            }
        }
        return takeSecurityFileSnapshot(target);
    };
    try {
        await assert.rejects(
            () => applySecurityFixPlan(plan, { assumeYes: true, takeSnapshot }),
            error => error.exitCode === 4 && error.code === 'STALE_FILE'
        );
        assert.deepEqual(fs.readFileSync(file), source);
        assertNoSecurityArtifacts(root);
    } finally {
        if (process.platform === 'win32') {
            powershell(`(Get-Item -LiteralPath ${psQuote(file)} -Force).IsReadOnly = $false`);
        } else {
            fs.chmodSync(file, 0o600);
        }
    }
});

test('Linux mode matrix survives atomic replacement across umask', linuxMetadataPhpOptions, async t => {
    for (const mode of [0o600, 0o640, 0o644, 0o750]) {
        await t.test(mode.toString(8), async st => {
            const root = createTempWorkspace(st, `metadata-linux-mode-${mode.toString(8)}`);
            const file = writeTempFile(root, 'case.php', source);
            fs.chmodSync(file, mode);
            const previousUmask = process.umask(0o077);
            try {
                const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
                assertTempTarget(root, plan.targetPath);
                await applySecurityFixPlan(plan, { assumeYes: true });
                assert.equal(fs.statSync(file).mode & 0o777, mode);
                assertNoSecurityArtifacts(root);
            } finally {
                process.umask(previousUmask);
            }
        });
    }
});

function runLinuxMetadataCommand(command, args) {
    return spawnSync(command, args, {
        encoding: 'utf8',
        env: { ...process.env, LC_ALL: 'C', LANG: 'C' },
        windowsHide: true
    });
}

test('Linux real ACL/xattr fixtures block and preserve originals', linuxMetadataPhpOptions, async t => {
    await t.test('additional POSIX ACL', async st => {
        const root = createTempWorkspace(st, 'metadata-linux-acl');
        const file = writeTempFile(root, 'case.php', source);
        const setup = runLinuxMetadataCommand('setfacl', ['-m', 'u:12345:r--', '--', file]);
        if (setup.error?.code === 'ENOENT') return st.skip('setfacl is unavailable for ACL fixture setup.');
        assert.equal(setup.status, 0, setup.stderr);
        const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
        assert.equal(plan.canApply, false);
        assert.ok(blockingCodes(plan).includes('POSIX_ACL_PRESENT'));
        await assert.rejects(
            () => applySecurityFixPlan(plan, { assumeYes: true }),
            error => error.exitCode === 2 && error.code === 'PLAN_BLOCKED'
        );
        assert.deepEqual(fs.readFileSync(file), source);
        assertNoSecurityArtifacts(root);
    });

    await t.test('user xattr', async st => {
        const root = createTempWorkspace(st, 'metadata-linux-xattr');
        const file = writeTempFile(root, 'case.php', source);
        const setup = runLinuxMetadataCommand('setfattr', ['-n', 'user.wpb-test', '-v', 'value', '--', file]);
        if (setup.error?.code === 'ENOENT') return st.skip('setfattr is unavailable for xattr fixture setup.');
        assert.equal(setup.status, 0, setup.stderr);
        const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
        assert.equal(plan.canApply, false);
        assert.ok(blockingCodes(plan).includes('POSIX_XATTR_PRESENT'));
        assert.deepEqual(fs.readFileSync(file), source);
        assertNoSecurityArtifacts(root);
    });

    await t.test('security xattr when permitted', st => {
        const root = createTempWorkspace(st, 'metadata-linux-security-xattr');
        const file = writeTempFile(root, 'case.php', source);
        const setup = runLinuxMetadataCommand('setfattr', ['-n', 'security.wpb-test', '-v', 'value', '--', file]);
        if (setup.error?.code === 'ENOENT' || setup.status !== 0) {
            return st.skip('Current Linux environment cannot create a security.* xattr fixture.');
        }
        const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
        assert.equal(plan.canApply, false);
        assert.ok(blockingCodes(plan).includes('POSIX_SECURITY_XATTR_PRESENT'));
        assert.deepEqual(fs.readFileSync(file), source);
        assertNoSecurityArtifacts(root);
    });
});

test('Linux ACL/xattr changes after Plan are stale and clean artifacts', linuxMetadataPhpOptions, async t => {
    for (const fixture of [
        ['ACL', 'setfacl', file => ['-m', 'u:12345:r--', '--', file]],
        ['xattr', 'setfattr', file => ['-n', 'user.wpb-stale', '-v', 'value', '--', file]]
    ]) {
        const [name, command, args] = fixture;
        await t.test(name, async st => {
            const root = createTempWorkspace(st, `metadata-linux-stale-${name.toLowerCase()}`);
            const file = writeTempFile(root, 'case.php', source);
            const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
            assert.equal(plan.canApply, true);
            const setup = runLinuxMetadataCommand(command, args(file));
            if (setup.error?.code === 'ENOENT') return st.skip(`${command} is unavailable for fixture setup.`);
            assert.equal(setup.status, 0, setup.stderr);
            await assert.rejects(
                () => applySecurityFixPlan(plan, { assumeYes: true }),
                error => error.exitCode === 4 && error.code === 'STALE_FILE'
            );
            assert.deepEqual(fs.readFileSync(file), source);
            assertNoSecurityArtifacts(root);
        });
    }
});
