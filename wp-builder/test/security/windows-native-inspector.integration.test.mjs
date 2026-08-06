import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
    inspectWindowsNative
} from '../../lib/security/windows-native-inspector.js';
import { validateWindowsHelperTrust } from '../../lib/security/windows-helper-trust.js';
import {
    createTempWorkspace,
    writeTempFile
} from '../helpers/temp-workspace.mjs';
import { resolveWindowsNativeInspectorTestPath } from '../helpers/windows-native-inspector-path.mjs';

const helperPath = resolveWindowsNativeInspectorTestPath();
const experimentalHelperPath = resolveWindowsNativeInspectorTestPath(
    process.env,
    'WPB_TEST_WINDOWS_REPLACE_INSPECTOR_PATH'
);
const integrationOptions = process.platform !== 'win32'
    ? { skip: 'Windows-only native inspector integration fixture.' }
    : !fs.existsSync(helperPath)
        ? { skip: `Native inspector binary is not built: ${helperPath}` }
        : {};
const experimentalIntegrationOptions = process.env.WPB_RUN_WINDOWS_REPLACE_CHARACTERIZATION !== '1'
    ? { skip: 'Experimental ReplaceFileW characterization is not enabled.' }
    : process.platform !== 'win32'
        ? { skip: 'Windows-only experimental ReplaceFileW characterization.' }
        : !fs.existsSync(experimentalHelperPath)
            ? { skip: `Experimental native helper binary is not built: ${experimentalHelperPath}` }
            : {};

test('test-only helper override canonicalizes a regular file inside RUNNER_TEMP', t => {
    const runnerTemp = createTempWorkspace(t, 'windows-helper-path');
    const helper = writeTempFile(runnerTemp, 'bin/helper.exe', 'fixture');
    assert.equal(resolveWindowsNativeInspectorTestPath({
        WPB_TEST_WINDOWS_INSPECTOR_PATH: helper,
        RUNNER_TEMP: runnerTemp
    }), fs.realpathSync.native(helper));
});

test('test-only helper override accepts canonical long paths', t => {
    const runnerTemp = createTempWorkspace(t, 'windows-helper-long-path');
    const helper = writeTempFile(runnerTemp, 'bin/helper.exe', 'fixture');
    const realRunnerTemp = fs.realpathSync.native(runnerTemp);
    const realHelper = fs.realpathSync.native(helper);
    assert.equal(resolveWindowsNativeInspectorTestPath({
        WPB_TEST_WINDOWS_INSPECTOR_PATH: realHelper,
        RUNNER_TEMP: realRunnerTemp
    }), realHelper);
});

test('test-only helper override accepts Windows path case aliases', {
    skip: process.platform === 'win32' ? false : 'Windows paths are case-insensitive.'
}, t => {
    const runnerTemp = createTempWorkspace(t, 'windows-helper-path-case');
    const helper = writeTempFile(runnerTemp, 'bin/helper.exe', 'fixture');
    assert.equal(resolveWindowsNativeInspectorTestPath({
        WPB_TEST_WINDOWS_INSPECTOR_PATH: helper.toUpperCase(),
        RUNNER_TEMP: runnerTemp.toUpperCase()
    }), fs.realpathSync.native(helper));
});

test('test-only helper override rejects paths outside RUNNER_TEMP', t => {
    const root = createTempWorkspace(t, 'windows-helper-outside');
    const runnerTemp = path.join(root, 'runner-temp');
    fs.mkdirSync(runnerTemp);
    const helper = writeTempFile(root, 'outside/helper.exe', 'fixture');
    assert.throws(() => resolveWindowsNativeInspectorTestPath({
        WPB_TEST_WINDOWS_INSPECTOR_PATH: helper,
        RUNNER_TEMP: runnerTemp
    }), /inside RUNNER_TEMP/);
});

test('test-only helper override rejects a sibling prefix path', t => {
    const root = createTempWorkspace(t, 'windows-helper-prefix');
    const runnerTemp = path.join(root, 'runner');
    fs.mkdirSync(runnerTemp);
    const helper = writeTempFile(root, 'runner-sibling/helper.exe', 'fixture');
    assert.throws(() => resolveWindowsNativeInspectorTestPath({
        WPB_TEST_WINDOWS_INSPECTOR_PATH: helper,
        RUNNER_TEMP: runnerTemp
    }), /inside RUNNER_TEMP/);
});

test('test-only helper override rejects a symlink helper file', t => {
    const runnerTemp = createTempWorkspace(t, 'windows-helper-symlink');
    const target = writeTempFile(runnerTemp, 'bin/target.exe', 'fixture');
    const helper = path.join(runnerTemp, 'bin/helper.exe');
    try {
        fs.symlinkSync(target, helper, 'file');
    } catch (error) {
        if (process.platform === 'win32' && error.code === 'EPERM') {
            t.skip('Symlink creation requires Windows Developer Mode or privilege.');
            return;
        }
        throw error;
    }
    assert.throws(() => resolveWindowsNativeInspectorTestPath({
        WPB_TEST_WINDOWS_INSPECTOR_PATH: helper,
        RUNNER_TEMP: runnerTemp
    }), /regular, non-symlink file/);
});

test('test-only helper override rejects a directory reparse escape', t => {
    const root = createTempWorkspace(t, 'windows-helper-reparse');
    const runnerTemp = path.join(root, 'runner');
    const outside = path.join(root, 'outside');
    const linkedDirectory = path.join(runnerTemp, 'linked');
    fs.mkdirSync(runnerTemp);
    fs.mkdirSync(outside);
    const target = writeTempFile(outside, 'helper.exe', 'fixture');
    try {
        fs.symlinkSync(outside, linkedDirectory, process.platform === 'win32' ? 'junction' : 'dir');
    } catch (error) {
        if (process.platform === 'win32' && error.code === 'EPERM') {
            t.skip('Junction creation is unavailable in this environment.');
            return;
        }
        throw error;
    }
    assert.throws(() => resolveWindowsNativeInspectorTestPath({
        WPB_TEST_WINDOWS_INSPECTOR_PATH: path.join(linkedDirectory, path.basename(target)),
        RUNNER_TEMP: runnerTemp
    }), /inside RUNNER_TEMP/);
});

test('test-only helper override rejects relative paths', () => {
    assert.throws(() => resolveWindowsNativeInspectorTestPath({
        WPB_TEST_WINDOWS_INSPECTOR_PATH: 'helper.exe',
        RUNNER_TEMP: 'runner-temp'
    }), /absolute path/);
});

function inspect(file) {
    const result = inspectWindowsNative(file, { helperPath });
    assert.equal(result.status, 'inspected', result.message);
    return result.response;
}

function inspectRaw(file, requestId = 'raw-leak-check') {
    const result = spawnSync(helperPath, [], {
        input: JSON.stringify({
            schemaVersion: 1,
            operation: 'inspect',
            requestId,
            target: { path: path.resolve(file) }
        }),
        encoding: 'utf8',
        windowsHide: true
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    const output = result.stdout.trim();
    const response = JSON.parse(output);
    assert.equal(Array.isArray(response), false);
    assert.equal(typeof response, 'object');
    assert.equal(response.capabilities.completeForReplace, false);
    assert.equal(output.includes(path.resolve(file)), false);
    assert.doesNotMatch(output, /S-\d+(?:-\d+){1,}/);
    assert.doesNotMatch(output, /(?:^|[,{\s])(?:O|G|D|S):(?:AI|AR|P|\()/);
    return { response, output };
}

function runRawRequest(request, env = process.env, executable = helperPath) {
    const result = spawnSync(executable, [], {
        input: JSON.stringify(request),
        encoding: 'utf8',
        windowsHide: true,
        env
    });
    assert.equal(result.stderr, '');
    return { status: result.status, response: JSON.parse(result.stdout.trim()) };
}

const validationBooleanFields = [
    'contentHashMatches',
    'sizeMatches',
    'volumeMatches',
    'identityMatches',
    'ownerMatches',
    'groupMatches',
    'daclMatches',
    'daclPresentMatches',
    'daclNullMatches',
    'protectedAclMatches',
    'daclAutoInheritedMatches',
    'daclAutoInheritRequiredMatches',
    'daclRevisionMatches',
    'aceCountMatches',
    'explicitAceCountMatches',
    'inheritedAceCountMatches',
    'aceOrderDigestMatches',
    'semanticAceSetDigestMatches',
    'accessMaskDigestMatches',
    'inheritanceFlagsDigestMatches',
    'trusteeDigestMatches',
    'aceSemanticsCompleteMatches',
    'adsMatches',
    'attributesMatch',
    'readonlyAttributeMatches',
    'hiddenAttributeMatches',
    'systemAttributeMatches',
    'archiveAttributeMatches',
    'temporaryAttributeMatches',
    'sparseAttributeMatches',
    'compressedAttributeMatches',
    'encryptedAttributeMatches',
    'otherAttributesMatch',
    'linkCountMatches',
    'regularFileMatches',
    'reparseStateMatches',
    'metadataFingerprintMatches'
];

const validationCountFields = [
    'actualAceCount',
    'expectedAceCount',
    'actualExplicitAceCount',
    'expectedExplicitAceCount',
    'actualInheritedAceCount',
    'expectedInheritedAceCount'
];

function reportSafeValidation(fixture, response) {
    assert.ok(Array.isArray(response.validation), `${fixture}: validation diagnostics are missing`);
    for (const item of response.validation) {
        assert.deepEqual(Object.keys(item).sort(), ['stage', 'subject', ...validationBooleanFields, ...validationCountFields].sort());
        assert.match(item.stage, /^post-(?:replace|rollback)$/);
        assert.match(item.subject, /^(?:target|backup)$/);
        for (const field of validationBooleanFields) assert.equal(typeof item[field], 'boolean', `${fixture}: ${field}`);
        for (const field of validationCountFields) {
            assert.equal(Number.isSafeInteger(item[field]), true, `${fixture}: ${field}`);
            assert.ok(item[field] >= 0, `${fixture}: ${field}`);
        }
    }
    const sanitized = JSON.stringify(response.validation);
    assert.doesNotMatch(sanitized, /S-\d+(?:-\d+){1,}/);
    assert.doesNotMatch(sanitized, /(?:^|[,\{\s])(?:O|G|D|S):(?:AI|AR|P|\()/);
    assert.doesNotMatch(sanitized, /[A-Za-z]:\\/);
    console.log(`WPB_VALIDATION ${fixture} ${sanitized}`);
}

function assertKnownInheritedDaclLimitation(fixture, result) {
    reportSafeValidation(fixture, result.response);
    assert.equal(result.status, 2, JSON.stringify(result.response));
    assert.equal(result.response.error.code, 'WINDOWS_RECOVERY_REQUIRED');
    const forwardTarget = result.response.validation.find(item => (
        item.stage === 'post-replace' && item.subject === 'target'
    ));
    const backup = result.response.validation.find(item => (
        item.stage === 'post-replace' && item.subject === 'backup'
    ));
    const rollbackTarget = result.response.validation.find(item => (
        item.stage === 'post-rollback' && item.subject === 'target'
    ));
    for (const item of [forwardTarget, rollbackTarget]) {
        assert.ok(item, `${fixture}: inherited DACL target diagnostic is missing`);
        assert.equal(item.daclAutoInheritedMatches, false);
        assert.equal(item.daclMatches, false);
        assert.equal(item.metadataFingerprintMatches, false);
        for (const field of [
            'daclPresentMatches',
            'daclNullMatches',
            'protectedAclMatches',
            'daclAutoInheritRequiredMatches',
            'daclRevisionMatches',
            'aceCountMatches',
            'explicitAceCountMatches',
            'inheritedAceCountMatches',
            'aceOrderDigestMatches',
            'semanticAceSetDigestMatches',
            'accessMaskDigestMatches',
            'inheritanceFlagsDigestMatches',
            'trusteeDigestMatches',
            'aceSemanticsCompleteMatches'
        ]) assert.equal(item[field], true, `${fixture}: ${field}`);
    }
    assert.ok(backup, `${fixture}: exact recovery backup diagnostic is missing`);
    for (const field of validationBooleanFields) {
        assert.equal(backup[field], true, `${fixture}: backup ${field}`);
    }
}

function replaceEndpoint(file, response = inspect(file)) {
    return {
        path: path.resolve(file),
        expected: {
            contentSha256: `sha256:${createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`,
            size: String(fs.statSync(file).size),
            identity: response.file.identity,
            metadataFingerprint: response.metadataFingerprint
        }
    };
}

function replaceRequest(target, replacement, backup, requestId = 'replace-fixture') {
    return {
        schemaVersion: 2,
        operation: 'replace',
        requestId,
        target: replaceEndpoint(target),
        replacement: replaceEndpoint(replacement),
        backup: { path: path.resolve(backup) }
    };
}

test('built helper trust manifest is valid for inspect and ineligible for replace', {
    skip: process.platform !== 'win32'
        ? 'Windows-only helper trust integration fixture.'
        : !process.env.WPB_TEST_WINDOWS_INSPECTOR_MANIFEST_PATH
            ? 'Built helper manifest path is unavailable.'
            : false
}, () => {
    const result = validateWindowsHelperTrust({
        helperPath,
        expectedBundledPath: helperPath,
        manifestPath: process.env.WPB_TEST_WINDOWS_INSPECTOR_MANIFEST_PATH,
        expectedSourceRevision: process.env.GITHUB_SHA,
        platform: 'win32',
        architecture: 'x64'
    });
    assert.equal(result.trustedForInspection, true, JSON.stringify(result.trustReasons));
    assert.equal(result.trustedForReplace, false);
    assert.ok(result.replaceBlockingReasons.some(reason => reason.code === 'WINDOWS_HELPER_REPLACE_INCOMPLETE'));
});

test('release helper accepts protocol v2 inspect and rejects replace requests', integrationOptions, () => {
    const root = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP ?? os.tmpdir(), 'wpb-protocol-v2-'));
    const file = path.join(root, 'case.php');
    fs.writeFileSync(file, '<?php echo 1; ?>');
    try {
        const inspectResult = runRawRequest({
            schemaVersion: 2,
            operation: 'inspect',
            requestId: 'protocol-v2-inspect',
            target: { path: path.resolve(file) }
        });
        assert.equal(inspectResult.status, 0);
        assert.equal(inspectResult.response.schemaVersion, 2);
        assert.equal(inspectResult.response.ok, true);
        assert.equal(inspectResult.response.capabilities.completeForReplace, false);

        const replaceResult = runRawRequest({
            schemaVersion: 2,
            operation: 'replace',
            requestId: 'protocol-v2-replace',
            target: { path: path.resolve(file) }
        });
        assert.equal(replaceResult.status, 2);
        assert.equal(replaceResult.response.ok, false);
        assert.equal(replaceResult.response.operation, 'replace');
        assert.equal(replaceResult.response.error.code, 'OPERATION_UNSUPPORTED');

        const unsupported = runRawRequest({
            schemaVersion: 2,
            operation: 'delete',
            requestId: 'protocol-v2-unsupported',
            target: { path: path.resolve(file) }
        });
        assert.equal(unsupported.status, 2);
        assert.equal(unsupported.response.error.code, 'OPERATION_UNSUPPORTED');
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

function powershell(script) {
    return spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
        encoding: 'utf8',
        windowsHide: true
    });
}

function psQuote(value) {
    return `'${value.replaceAll("'", "''")}'`;
}

test('Windows native inspector real filesystem fixtures', integrationOptions, async t => {
    const root = createTempWorkspace(t, 'windows-native-inspector');

    await t.test('normal NTFS, Unicode and option-like paths are deterministic', () => {
        const file = writeTempFile(root, '-日本語-case.php', '<?php echo 1; ?>');
        const first = inspect(file);
        const second = inspect(file);
        assert.equal(first.filesystem.type, 'NTFS');
        assert.equal(first.file.normalFile, true);
        assert.equal(first.metadataFingerprint, second.metadataFingerprint);
        assert.equal(first.capabilities.completeForReplace, false);
        inspectRaw(file);
    });

    await t.test('readonly metadata change changes the fingerprint', () => {
        const file = writeTempFile(root, 'readonly.php', '<?php echo 1; ?>');
        const before = inspect(file);
        const setup = powershell(`(Get-Item -LiteralPath ${psQuote(file)} -Force).IsReadOnly = $true`);
        assert.equal(setup.status, 0, setup.stderr);
        try {
            const after = inspect(file);
            assert.equal(after.file.readonly, true);
            assert.notEqual(after.metadataFingerprint, before.metadataFingerprint);
        } finally {
            powershell(`(Get-Item -LiteralPath ${psQuote(file)} -Force).IsReadOnly = $false`);
        }
    });

    await t.test('inherited ACL is inspected', () => {
        const file = writeTempFile(root, 'inherited-acl.php', '<?php echo 1; ?>');
        const response = inspect(file);
        assert.equal(response.security.daclProtected, false);
        assert.match(response.security.daclFingerprint, /^sha256:[0-9a-f]{64}$/);
    });

    await t.test('protected explicit ACL is visible to the helper', () => {
        const file = writeTempFile(root, 'protected-acl.php', '<?php echo 1; ?>');
        const setup = spawnSync('icacls.exe', [file, '/inheritance:d'], { encoding: 'utf8', windowsHide: true });
        assert.equal(setup.status, 0, setup.stderr);
        const response = inspect(file);
        assert.equal(response.security.daclProtected, true);
        assert.ok(response.compatibility.explicitAccessRuleCount > 0);
        assert.ok(response.blockingReasons.some(reason => reason.code === 'WINDOWS_SPECIAL_ACL'));
    });

    await t.test('ADS is hashed without exposing its name or content', () => {
        const file = writeTempFile(root, 'ads.php', '<?php echo 1; ?>');
        const secretName = 'wpb-secret-stream';
        const secretContent = 'wpb-secret-content';
        fs.writeFileSync(`${file}:${secretName}`, secretContent);
        const response = inspect(file);
        assert.equal(response.streams.count, 1);
        assert.match(response.streams.digest, /^sha256:[0-9a-f]{64}$/);
        const serialized = JSON.stringify(response);
        assert.equal(serialized.includes(secretName), false);
        assert.equal(serialized.includes(secretContent), false);
        const raw = inspectRaw(file, 'ads-leak-check').output;
        assert.equal(raw.includes(secretName), false);
        assert.equal(raw.includes(secretContent), false);
    });

    await t.test('hard link reports linkCount greater than one', () => {
        const file = writeTempFile(root, 'hardlink.php', '<?php echo 1; ?>');
        fs.linkSync(file, path.join(root, 'hardlink-copy.php'));
        assert.ok(BigInt(inspect(file).file.linkCount) > 1n);
    });

    await t.test('symbolic link is a reparse point', t => {
        const target = writeTempFile(root, 'symlink-target.php', '<?php echo 1; ?>');
        const link = path.join(root, 'symlink.php');
        try {
            fs.symlinkSync(target, link, 'file');
        } catch (error) {
            if (error.code === 'EPERM') return t.skip('Symlink creation requires Windows Developer Mode or privilege.');
            throw error;
        }
        const response = inspect(link);
        assert.equal(response.file.reparsePoint, true);
        assert.ok(response.blockingReasons.some(reason => reason.code === 'REPARSE_POINT_UNSUPPORTED'));
    });

    await t.test('junction is a reparse point', t => {
        const directory = path.join(root, 'junction-target');
        const junction = path.join(root, 'junction');
        fs.mkdirSync(directory);
        try {
            fs.symlinkSync(directory, junction, 'junction');
        } catch (error) {
            if (error.code === 'EPERM') return t.skip('Junction creation is unavailable in this environment.');
            throw error;
        }
        const response = inspect(junction);
        assert.equal(response.file.reparsePoint, true);
    });

    await t.test('access denied is machine-readable when the fixture can be created', t => {
        const file = writeTempFile(root, 'access-denied.php', '<?php echo 1; ?>');
        const identity = powershell('[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value');
        assert.equal(identity.status, 0, identity.stderr);
        const sid = identity.stdout.trim();
        const setup = spawnSync('icacls.exe', [file, '/deny', `*${sid}:(R)`], { encoding: 'utf8', windowsHide: true });
        if (setup.status !== 0) return t.skip(`Could not create access-denied fixture: ${setup.stderr.trim()}`);
        try {
            const result = inspectWindowsNative(file, { helperPath });
            assert.equal(result.status, 'failed');
            assert.equal(result.code, 'ACCESS_DENIED');
        } finally {
            spawnSync('icacls.exe', [file, '/remove:d', `*${sid}`], { encoding: 'utf8', windowsHide: true });
            spawnSync('icacls.exe', [file, '/reset'], { encoding: 'utf8', windowsHide: true });
        }
    });
});

test('Experimental ReplaceFileW characterization', experimentalIntegrationOptions, async t => {
    const root = createTempWorkspace(t, 'windows-native-replace');
    const files = name => ({
        target: writeTempFile(root, `${name}-target.php`, `original-${name}`),
        replacement: writeTempFile(root, `${name}-replacement.php`, `desired-${name}`),
        backup: path.join(root, `${name}-rollback.wpb`)
    });
    const runReplace = (fixture, options = {}) => {
        const request = options.request ?? replaceRequest(
            fixture.target,
            fixture.replacement,
            fixture.backup,
            options.requestId
        );
        return runRawRequest(request, options.env ?? process.env, experimentalHelperPath);
    };

    await t.test('normal inherited DACL remains unsupported after restore and rollback', () => {
        const fixture = files('normal');
        const original = fs.readFileSync(fixture.target);
        const result = runReplace(fixture);
        assertKnownInheritedDaclLimitation('normal-replace', result);
        assert.deepEqual(fs.readFileSync(fixture.target), original);
        assert.equal(fs.existsSync(fixture.backup), false);
        assert.equal(fs.existsSync(fixture.replacement), true);
    });

    await t.test('inherited ACL ACE semantics restore but control state remains unsupported', () => {
        const fixture = files('inherited');
        const before = inspect(fixture.target);
        assert.equal(before.security.daclProtected, false);
        const result = runReplace(fixture);
        assertKnownInheritedDaclLimitation('inherited-acl', result);
    });

    await t.test('protected explicit ACL is preserved', () => {
        const fixture = files('protected');
        const setup = spawnSync('icacls.exe', [fixture.target, '/inheritance:d'], { encoding: 'utf8', windowsHide: true });
        assert.equal(setup.status, 0, setup.stderr);
        const before = inspect(fixture.target);
        assert.equal(before.security.daclProtected, true);
        const result = runReplace(fixture);
        reportSafeValidation('protected-explicit-acl', result.response);
        assert.equal(result.status, 0, JSON.stringify(result.response));
        const after = inspect(fixture.target);
        assert.equal(after.security.daclFingerprint, before.security.daclFingerprint);
        assert.equal(after.security.daclProtected, true);
    });

    await t.test('an Administrators-owned target is validated by fingerprint, not an owner allowlist', t => {
        const fixture = files('administrators-owner');
        const setup = spawnSync('icacls.exe', [fixture.target, '/setowner', '*S-1-5-32-544'], {
            encoding: 'utf8',
            windowsHide: true
        });
        if (setup.status !== 0) return t.skip('The runner account cannot create an Administrators-owned fixture.');
        const before = inspect(fixture.target);
        const result = runReplace(fixture);
        assertKnownInheritedDaclLimitation('administrators-owner', result);
        assert.equal(inspect(fixture.target).security.ownerFingerprint, before.security.ownerFingerprint);
    });

    await t.test('ADS inventory and content digest are preserved', () => {
        const fixture = files('ads');
        fs.writeFileSync(`${fixture.target}:wpb-phase-b`, 'sensitive-stream-value');
        const before = inspect(fixture.target);
        const result = runReplace(fixture);
        assertKnownInheritedDaclLimitation('ads', result);
        assert.ok(result.response.validation.every(item => item.adsMatches));
        const after = inspect(fixture.target);
        assert.equal(after.streams.count, 1);
        assert.equal(after.streams.digest, before.streams.digest);
        assert.equal(after.streams.inventoryDigest, before.streams.inventoryDigest);
    });

    await t.test('hidden attribute is explicitly restored after replace', () => {
        const fixture = files('hidden');
        const setup = powershell(`(Get-Item -LiteralPath ${psQuote(fixture.target)} -Force).Attributes = ((Get-Item -LiteralPath ${psQuote(fixture.target)} -Force).Attributes -bor [IO.FileAttributes]::Hidden)`);
        assert.equal(setup.status, 0, setup.stderr);
        const before = inspect(fixture.target);
        const result = runReplace(fixture);
        assertKnownInheritedDaclLimitation('hidden-attribute', result);
        assert.ok(result.response.validation.every(item => item.attributesMatch));
        assert.equal(inspect(fixture.target).file.attributes, before.file.attributes);
        assert.equal(powershell(`if ((Get-Item -LiteralPath ${psQuote(fixture.target)} -Force).Attributes -band [IO.FileAttributes]::Hidden) { exit 0 } else { exit 1 }`).status, 0);
    });

    await t.test('readonly target either preserves metadata or fails without changing content', () => {
        const fixture = files('readonly-replace');
        const setup = powershell(`(Get-Item -LiteralPath ${psQuote(fixture.target)} -Force).IsReadOnly = $true`);
        assert.equal(setup.status, 0, setup.stderr);
        const original = fs.readFileSync(fixture.target);
        try {
            const result = runReplace(fixture);
            if (result.status === 0) {
                assert.equal(inspect(fixture.target).file.readonly, true);
            } else {
                assert.ok([
                    'WINDOWS_REPLACE_FAILED',
                    'WINDOWS_RECOVERY_REQUIRED'
                ].includes(result.response.error.code));
                if (result.response.validation) reportSafeValidation('readonly-replace', result.response);
                assert.deepEqual(fs.readFileSync(fixture.target), original);
            }
        } finally {
            if (fs.existsSync(fixture.target)) powershell(`(Get-Item -LiteralPath ${psQuote(fixture.target)} -Force).IsReadOnly = $false`);
            if (fs.existsSync(fixture.backup)) powershell(`(Get-Item -LiteralPath ${psQuote(fixture.backup)} -Force).IsReadOnly = $false`);
        }
    });

    await t.test('stale content hash blocks before ReplaceFileW', () => {
        const fixture = files('stale-hash');
        const request = replaceRequest(fixture.target, fixture.replacement, fixture.backup);
        fs.appendFileSync(fixture.target, '-changed');
        const result = runReplace(fixture, { request });
        assert.equal(result.status, 2);
        assert.equal(result.response.error.code, 'STALE_FILE');
        assert.equal(fs.existsSync(fixture.backup), false);
    });

    await t.test('stale identity blocks before ReplaceFileW', () => {
        const fixture = files('stale-identity');
        const request = replaceRequest(fixture.target, fixture.replacement, fixture.backup);
        fs.unlinkSync(fixture.target);
        fs.writeFileSync(fixture.target, 'original-stale-identity');
        const result = runReplace(fixture, { request });
        assert.equal(result.status, 2);
        assert.equal(result.response.error.code, 'STALE_FILE');
    });

    await t.test('stale ACL blocks before ReplaceFileW', () => {
        const fixture = files('stale-acl');
        const request = replaceRequest(fixture.target, fixture.replacement, fixture.backup);
        const setup = spawnSync('icacls.exe', [fixture.target, '/inheritance:d'], { encoding: 'utf8', windowsHide: true });
        assert.equal(setup.status, 0, setup.stderr);
        const result = runReplace(fixture, { request });
        assert.equal(result.status, 2);
        assert.equal(result.response.error.code, 'STALE_FILE');
    });

    await t.test('stale ADS blocks before ReplaceFileW', () => {
        const fixture = files('stale-ads');
        const request = replaceRequest(fixture.target, fixture.replacement, fixture.backup);
        fs.writeFileSync(`${fixture.target}:late-stream`, 'late');
        const result = runReplace(fixture, { request });
        assert.equal(result.status, 2);
        assert.equal(result.response.error.code, 'STALE_FILE');
    });

    await t.test('replacement mismatch blocks before ReplaceFileW', () => {
        const fixture = files('replacement-mismatch');
        const request = replaceRequest(fixture.target, fixture.replacement, fixture.backup);
        fs.appendFileSync(fixture.replacement, '-changed');
        const result = runReplace(fixture, { request });
        assert.equal(result.status, 2);
        assert.equal(result.response.error.code, 'STALE_FILE');
        assert.match(fs.readFileSync(fixture.target, 'utf8'), /^original-/);
    });

    await t.test('hard-link target is blocked', () => {
        const fixture = files('hardlink-replace');
        fs.linkSync(fixture.target, path.join(root, 'hardlink-replace-copy.php'));
        const result = runReplace(fixture);
        assert.equal(result.status, 2);
        assert.equal(result.response.error.code, 'HARD_LINK_TARGET');
        assert.equal(fs.existsSync(fixture.backup), false);
    });

    await t.test('reparse target is blocked when symlink creation is available', t => {
        const realTarget = writeTempFile(root, 'reparse-real.php', 'original-reparse');
        const replacement = writeTempFile(root, 'reparse-replacement.php', 'desired-reparse');
        const target = path.join(root, 'reparse-link.php');
        try {
            fs.symlinkSync(realTarget, target, 'file');
        } catch (error) {
            if (error.code === 'EPERM') return t.skip('Symlink creation requires Windows Developer Mode or privilege.');
            throw error;
        }
        const fixture = { target, replacement, backup: path.join(root, 'reparse-backup.wpb') };
        const result = runReplace(fixture);
        assert.equal(result.status, 2);
        assert.equal(result.response.error.code, 'REPARSE_POINT_UNSUPPORTED');
    });

    await t.test('final hash mismatch triggers validated rollback', () => {
        const fixture = files('rollback-hash');
        const original = fs.readFileSync(fixture.target);
        const originalIdentity = inspect(fixture.target).file.identity;
        const result = runReplace(fixture, {
            env: { ...process.env, WPB_TEST_WINDOWS_REPLACE_FAULT: 'final-hash-mismatch' }
        });
        assertKnownInheritedDaclLimitation('rollback-after-hash-fault', result);
        assert.deepEqual(fs.readFileSync(fixture.target), original);
        assert.deepEqual(inspect(fixture.target).file.identity, originalIdentity);
        assert.equal(fs.existsSync(fixture.backup), false);
        assert.equal(fs.existsSync(fixture.replacement), true);
    });

    await t.test('final metadata mismatch triggers validated rollback', () => {
        const fixture = files('rollback-metadata');
        const before = inspect(fixture.target);
        const result = runReplace(fixture, {
            env: { ...process.env, WPB_TEST_WINDOWS_REPLACE_FAULT: 'final-metadata-mismatch' }
        });
        assertKnownInheritedDaclLimitation('rollback-after-metadata-fault', result);
        const after = inspect(fixture.target);
        assert.notEqual(after.metadataFingerprint, before.metadataFingerprint);
        const rollbackDiagnostic = result.response.validation.find(item => item.stage === 'post-rollback');
        assert.equal(rollbackDiagnostic.attributesMatch, true);
    });

    await t.test('DACL restoration failure rolls back only after complete metadata restoration', () => {
        const fixture = files('dacl-restore-failure');
        const before = inspect(fixture.target);
        const original = fs.readFileSync(fixture.target);
        const result = runReplace(fixture, {
            env: { ...process.env, WPB_TEST_WINDOWS_REPLACE_FAULT: 'dacl-restoration-failure' }
        });
        assertKnownInheritedDaclLimitation('dacl-restoration-failure', result);
        assert.deepEqual(fs.readFileSync(fixture.target), original);
        assert.notEqual(inspect(fixture.target).metadataFingerprint, before.metadataFingerprint);
    });

    await t.test('attribute restoration failure rolls back only after complete metadata restoration', () => {
        const fixture = files('attribute-restore-failure');
        const before = inspect(fixture.target);
        const original = fs.readFileSync(fixture.target);
        const result = runReplace(fixture, {
            env: { ...process.env, WPB_TEST_WINDOWS_REPLACE_FAULT: 'attribute-restoration-failure' }
        });
        assertKnownInheritedDaclLimitation('attribute-restoration-failure', result);
        assert.deepEqual(fs.readFileSync(fixture.target), original);
        assert.notEqual(inspect(fixture.target).metadataFingerprint, before.metadataFingerprint);
    });

    await t.test('rollback restoration failure remains recovery-required', () => {
        const fixture = files('rollback-restore-failure');
        const result = runReplace(fixture, {
            env: { ...process.env, WPB_TEST_WINDOWS_REPLACE_FAULT: 'rollback-restoration-failure' }
        });
        reportSafeValidation('rollback-restoration-failure', result.response);
        assert.equal(result.status, 2);
        assert.equal(result.response.error.code, 'WINDOWS_RECOVERY_REQUIRED');
        assert.equal(result.response.error.phase, 'rollback-security-restore');
        assert.equal(fs.existsSync(fixture.replacement), true);
    });

    await t.test('unverifiable backup produces recovery-required without destructive fallback', () => {
        const fixture = files('rollback-failure');
        const original = fs.readFileSync(fixture.target);
        const result = runReplace(fixture, {
            env: { ...process.env, WPB_TEST_WINDOWS_REPLACE_FAULT: 'rollback-failure' }
        });
        assert.equal(result.status, 2);
        assert.equal(result.response.error.code, 'WINDOWS_RECOVERY_REQUIRED');
        assert.equal(fs.existsSync(fixture.backup), true);
        assert.deepEqual(fs.readFileSync(fixture.backup), original);
    });

    await t.test('replace responses do not leak paths or security metadata', () => {
        const fixture = files('leak');
        const result = spawnSync(experimentalHelperPath, [], {
            input: JSON.stringify(replaceRequest(fixture.target, fixture.replacement, fixture.backup)),
            encoding: 'utf8',
            windowsHide: true
        });
        assert.equal(result.status, 2, result.stdout);
        assert.equal(result.stderr, '');
        assert.equal(result.stdout.includes(root), false);
        assert.doesNotMatch(result.stdout, /S-\d+(?:-\d+){1,}/);
        assert.doesNotMatch(result.stdout, /(?:^|[,\{\s])(?:O|G|D|S):(?:AI|AR|P|\()/);
        const response = JSON.parse(result.stdout);
        assert.equal(response.error.code, 'WINDOWS_RECOVERY_REQUIRED');
        reportSafeValidation('raw-leak', response);
    });
});
