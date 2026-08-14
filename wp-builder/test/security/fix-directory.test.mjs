import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {
    buildSecurityFixDirectoryPlan,
    openSecurityFixDirectoryDiffs,
    renderSecurityFixDirectoryPreview
} from '../../lib/security/fix-directory.js';
import { sha256 } from '../helpers/hash.mjs';
import { securityFixIntegrationTestOptions } from '../helpers/php-runtime.mjs';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

test('Security Fix directory recursively scans PHP only and preserves sources', securityFixIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-directory');
    const auto = writeTempFile(root, 'include/layouts/auto.php', "<p><?= SCF::get('title') ?></p>\n");
    const diagnostic = writeTempFile(root, 'include/common/diagnostic.php', "<?php $value = SCF::get('body');\n");
    writeTempFile(root, 'include/layouts/ignored.txt', "<?= SCF::get('ignored') ?>\n");
    const before = new Map([
        [auto, sha256(fs.readFileSync(auto))],
        [diagnostic, sha256(fs.readFileSync(diagnostic))]
    ]);

    const plan = buildSecurityFixDirectoryPlan({ workspaceRoot: root, directory: 'include' });
    assert.equal(plan.counts.filesScanned, 2);
    assert.equal(plan.counts.autoFixable, 1);
    assert.equal(plan.counts.diagnosticOnly, 1);
    assert.deepEqual(
        plan.plans.map(item => path.relative(root, item.targetPath).replace(/\\/g, '/')),
        ['include/common/diagnostic.php', 'include/layouts/auto.php']
    );
    before.forEach((hash, file) => assert.equal(sha256(fs.readFileSync(file)), hash));

    const output = [];
    renderSecurityFixDirectoryPreview(plan, {
        out(message) { output.push(message); },
        error() {}
    });
    assert.match(output.join('\n'), /AUTO_FIXABLE:[\s\S]*include\/layouts\/auto\.php:1/);
    assert.match(output.join('\n'), /DIAGNOSTIC_ONLY:[\s\S]*include\/common\/diagnostic\.php:1/);
    assert.match(output.join('\n'), /2 files scanned/);
});

test('Security Fix directory lint failure blocks diff opening', securityFixIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-directory-lint');
    writeTempFile(root, 'include/case.php', "<?= SCF::get('title') ?>\n");
    const plan = buildSecurityFixDirectoryPlan({
        workspaceRoot: root,
        directory: 'include',
        lintPhpCommand: 'wpb-php-command-that-does-not-exist'
    });
    assert.equal(plan.canOpenDiffs, false);
    assert.ok(plan.blockingDiagnostics.some(item => item.code === 'PHP_LINT_UNAVAILABLE'));
    let opened = false;
    const result = openSecurityFixDirectoryDiffs(plan, {
        openDiff() {
            opened = true;
        },
        out() {},
        error() {}
    });
    assert.equal(result.status, 'blocked');
    assert.equal(opened, false);
});

test('Security Fix directory opens candidates sequentially with VS Code wait mode', () => {
    const calls = [];
    const directoryPlan = {
        canOpenDiffs: true,
        plans: [
            { targetPath: 'auto.php', counts: { autoFixable: 1, diagnosticOnly: 0 } },
            { targetPath: 'diagnostic.php', counts: { autoFixable: 0, diagnosticOnly: 1 } }
        ]
    };
    const result = openSecurityFixDirectoryDiffs(directoryPlan, {
        openDiff(plan, options) {
            calls.push({ targetPath: plan.targetPath, waitForClose: options.waitForClose });
            return { status: 'opened' };
        },
        out() {},
        error() {}
    });
    assert.equal(result.status, 'opened-sequentially');
    assert.deepEqual(calls, [
        { targetPath: 'auto.php', waitForClose: true },
        { targetPath: 'diagnostic.php', waitForClose: true }
    ]);
});

test('Security Fix directory rejects a symlink or junction entry', t => {
    const root = createTempWorkspace(t, 'fix-directory-symlink');
    const include = path.join(root, 'include');
    const outside = path.join(root, 'outside');
    fs.mkdirSync(include, { recursive: true });
    fs.mkdirSync(outside, { recursive: true });
    writeTempFile(root, 'outside/case.php', "<?= SCF::get('title') ?>\n");
    try {
        fs.symlinkSync(outside, path.join(include, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
    } catch (error) {
        if (error.code === 'EPERM' || error.code === 'EACCES') {
            t.skip(`Symlink creation unavailable: ${error.code}`);
            return;
        }
        throw error;
    }

    assert.throws(
        () => buildSecurityFixDirectoryPlan({ workspaceRoot: root, directory: 'include' }),
        error => error.code === 'DIRECTORY_ENTRY_SYMLINK_UNSUPPORTED' && error.exitCode === 2
    );
});

test('Security Fix directory rejects paths outside the workspace', t => {
    const root = createTempWorkspace(t, 'fix-directory-outside');
    assert.throws(
        () => buildSecurityFixDirectoryPlan({ workspaceRoot: root, directory: '..' }),
        error => error.code === 'DIRECTORY_OUTSIDE_WORKSPACE' && error.exitCode === 2
    );
});
