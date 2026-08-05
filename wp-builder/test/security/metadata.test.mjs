import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { applySecurityFixPlan } from '../../lib/security/fix-apply.js';
import { buildSecurityFixPlan } from '../../lib/security/fix-plan.js';
import { phpIntegrationTestOptions } from '../helpers/php-runtime.mjs';
import { assertTempTarget, createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

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
const posixPhpOptions = process.platform === 'win32'
    ? { skip: 'POSIX-only metadata test.' }
    : phpIntegrationTestOptions();

test('KEEP BLOCKER: Windows explicit ACL must survive atomic replacement', {
    ...windowsPhpOptions,
    todo: 'Current Security Fix apply replaces the explicit ACL with inherited directory ACLs.'
}, async t => {
    const root = createTempWorkspace(t, 'metadata-acl');
    const file = writeTempFile(root, 'case.php', source);
    const setup = spawnSync('icacls.exe', [file, '/inheritance:d'], { encoding: 'utf8', windowsHide: true });
    assert.equal(setup.status, 0, setup.stderr);
    const before = windowsAcl(file);
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    assertTempTarget(root, plan.targetPath);
    await applySecurityFixPlan(plan, { assumeYes: true });
    assert.equal(windowsAcl(file), before);
});

test('Windows read-only target fails safely and preserves the original', windowsPhpOptions, async t => {
    const root = createTempWorkspace(t, 'metadata-readonly');
    const file = writeTempFile(root, 'case.php', source);
    const setReadOnly = powershell(`(Get-Item -LiteralPath ${psQuote(file)} -Force).IsReadOnly = $true`);
    assert.equal(setReadOnly.status, 0, setReadOnly.stderr);
    try {
        const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
        assertTempTarget(root, plan.targetPath);
        await assert.rejects(
            () => applySecurityFixPlan(plan, { assumeYes: true }),
            error => error.exitCode === 6 && error.code === 'ATOMIC_WRITE_FAILED'
        );
        assert.deepEqual(fs.readFileSync(file), source);
    } finally {
        powershell(`(Get-Item -LiteralPath ${psQuote(file)} -Force).IsReadOnly = $false`);
    }
});

test('KEEP BLOCKER: POSIX mode must survive atomic replacement', {
    ...posixPhpOptions,
    todo: 'Current Security Fix apply does not copy the original mode to its temporary file.'
}, async t => {
    const root = createTempWorkspace(t, 'metadata-posix-mode');
    const file = writeTempFile(root, 'case.php', source);
    fs.chmodSync(file, 0o600);
    const before = fs.statSync(file).mode & 0o777;
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    assertTempTarget(root, plan.targetPath);
    await applySecurityFixPlan(plan, { assumeYes: true });
    assert.equal(fs.statSync(file).mode & 0o777, before);
});
