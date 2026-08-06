import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import {
    inspectWindowsNative
} from '../../lib/security/windows-native-inspector.js';
import {
    createTempWorkspace,
    writeTempFile
} from '../helpers/temp-workspace.mjs';
import { resolveWindowsNativeInspectorTestPath } from '../helpers/windows-native-inspector-path.mjs';

const helperPath = resolveWindowsNativeInspectorTestPath();
const integrationOptions = process.platform !== 'win32'
    ? { skip: 'Windows-only native inspector integration fixture.' }
    : !fs.existsSync(helperPath)
        ? { skip: `Native inspector binary is not built: ${helperPath}` }
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
