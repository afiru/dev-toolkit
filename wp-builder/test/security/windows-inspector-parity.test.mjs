import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { takeSecurityFileSnapshot } from '../../lib/security/fix-plan.js';
import {
    createTempWorkspace,
    writeTempFile
} from '../helpers/temp-workspace.mjs';
import { resolveWindowsNativeInspectorTestPath } from '../helpers/windows-native-inspector-path.mjs';

const helperPath = resolveWindowsNativeInspectorTestPath();
const parityOptions = process.platform !== 'win32'
    ? { skip: 'Windows-only PowerShell/native parity fixture.' }
    : !fs.existsSync(helperPath)
        ? { skip: `Native inspector binary is not built: ${helperPath}` }
        : {};

function snapshot(file) {
    // GitHub-hosted Windows runners may expose os.tmpdir() through an 8.3 alias.
    // Inspect the canonical target so PowerShell and the native helper receive
    // the same long-path representation.
    const canonicalFile = fs.realpathSync.native(file);
    return takeSecurityFileSnapshot(canonicalFile, {
        metadata: { nativeInspectorOptions: { helperPath } }
    });
}

function assertParity(file) {
    const result = snapshot(file);
    assert.equal(result.state, 'present', result.reason);
    assert.equal(result.metadata.capability.inspectable, true, JSON.stringify({
        blockingReasons: result.metadata.capability.blockingReasons
    }));
    assert.ok(result.metadata.nativeShadow, 'Native shadow result is missing.');
    assert.equal(result.metadata.nativeShadow.native?.inspected, true, JSON.stringify({
        native: result.metadata.nativeShadow.native
    }));
    assert.equal(result.metadata.nativeShadow.compared, true);
    assert.equal(result.metadata.nativeShadow.matching, true, JSON.stringify({
        differences: result.metadata.nativeShadow.differences
    }));
    assert.equal(result.metadata.nativeShadow.diagnostic, null);
    return result;
}

function run(command, args) {
    const result = spawnSync(command, args, { encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, 0, result.stderr);
}

test('PowerShell and native inspector shared fields match', parityOptions, async t => {
    const root = createTempWorkspace(t, 'windows-inspector-parity');

    await t.test('normal inherited ACL', () => {
        assertParity(writeTempFile(root, 'inherited.php', '<?php echo 1; ?>'));
    });

    await t.test('readonly and attributes', () => {
        const file = writeTempFile(root, 'readonly.php', '<?php echo 1; ?>');
        run('powershell.exe', [
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            `(Get-Item -LiteralPath '${file.replaceAll("'", "''")}' -Force).IsReadOnly = $true`
        ]);
        try {
            const result = assertParity(file);
            assert.equal(result.metadata.windows.readonly, true);
        } finally {
            run('powershell.exe', [
                '-NoProfile',
                '-NonInteractive',
                '-Command',
                `(Get-Item -LiteralPath '${file.replaceAll("'", "''")}' -Force).IsReadOnly = $false`
            ]);
        }
    });

    await t.test('protected explicit ACL and explicit ACE count', () => {
        const file = writeTempFile(root, 'protected.php', '<?php echo 1; ?>');
        run('icacls.exe', [file, '/inheritance:d']);
        try {
            const result = assertParity(file);
            assert.equal(result.metadata.windows.aclProtected, true);
            assert.ok(result.metadata.windows.explicitAccessRuleCount > 0);
        } finally {
            run('icacls.exe', [file, '/reset']);
        }
    });

    await t.test('ADS count and inventory digest', () => {
        const file = writeTempFile(root, 'ads.php', '<?php echo 1; ?>');
        fs.writeFileSync(`${file}:wpb-parity-stream`, 'secret');
        const result = assertParity(file);
        assert.equal(result.metadata.windows.streams.length, 1);
    });
});
