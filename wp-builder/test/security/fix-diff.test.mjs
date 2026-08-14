import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {
    openSecurityFixDiff,
    resolveCodeInvocation,
    securityFixPreviewBlockingReasons
} from '../../lib/security/fix-diff.js';
import { sha256 } from '../helpers/hash.mjs';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

function autoFixPlan(file, desiredBytes) {
    return {
        targetPath: file,
        desiredBytes,
        hasChanges: true,
        lint: { available: true, passed: true },
        counts: { autoFixable: 1 },
        findings: []
    };
}

test('preview ignores apply-only metadata blockers but retains analysis and hard-link blockers', () => {
    const ownerReason = {
        code: 'WINDOWS_OWNER_UNSUPPORTED',
        message: 'Owner cannot be preserved by automatic apply.'
    };
    const plan = {
        snapshot: {
            metadata: {
                capability: { blockingReasons: [ownerReason] }
            }
        },
        blockingReasons: [
            ownerReason,
            { code: 'HARD_LINK_TARGET', message: 'Hard link target.' },
            { code: 'PHP_LINT_FAILED', message: 'Lint failed.' }
        ]
    };

    assert.deepEqual(
        securityFixPreviewBlockingReasons(plan).map(reason => reason.code),
        ['HARD_LINK_TARGET', 'PHP_LINT_FAILED']
    );
});

test('Security Fix diff creates a linted preview without changing the source', t => {
    const root = createTempWorkspace(t, 'fix-diff-auto');
    const file = writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\r\n");
    const before = sha256(fs.readFileSync(file));
    const calls = [];
    const desiredBytes = Buffer.from("<p><?= esc_html(SCF::get('title')) ?></p>\r\n");

    const result = openSecurityFixDiff(autoFixPlan(file, desiredBytes), {
        tempDirectory: root,
        codeCommand: 'code-test',
        spawn(command, args) {
            calls.push({ command, args });
            return { status: 0 };
        },
        out() {},
        error() {}
    });

    assert.equal(result.status, 'preview-created');
    assert.equal(result.opened, true);
    assert.ok(result.previewPath.startsWith(`${root}${path.sep}`));
    assert.deepEqual(fs.readFileSync(result.previewPath), desiredBytes);
    assert.equal(sha256(fs.readFileSync(file)), before);
    assert.deepEqual(calls, [{ command: 'code-test', args: ['--diff', file, result.previewPath] }]);
});

test('diagnostic-only Security Fix diff creates no preview and opens the source location', t => {
    const root = createTempWorkspace(t, 'fix-diff-diagnostic');
    const file = writeTempFile(root, 'case.php', "<?php $value = SCF::get('title');\n");
    const beforeEntries = fs.readdirSync(root);
    const output = [];
    const calls = [];
    const result = openSecurityFixDiff({
        targetPath: file,
        desiredBytes: fs.readFileSync(file),
        hasChanges: false,
        lint: { available: true, passed: true },
        counts: { autoFixable: 0 },
        findings: [{
            autoFixable: false,
            ruleId: 'WPB-SCF-UNESCAPED',
            location: { startLine: 1, startColumn: 16 }
        }]
    }, {
        tempDirectory: root,
        codeCommand: 'code-test',
        spawn(command, args) {
            calls.push({ command, args });
            return { status: 0 };
        },
        out(message) { output.push(message); },
        error() {}
    });

    assert.equal(result.status, 'no-auto-fixable');
    assert.equal(result.previewPath, null);
    assert.deepEqual(fs.readdirSync(root), beforeEntries);
    assert.match(output.join('\n'), /No auto-fixable Security Fix candidates/);
    assert.match(output.join('\n'), /case\.php:1:16/);
    assert.deepEqual(calls, [{ command: 'code-test', args: ['--goto', `${file}:1:16`] }]);
});

test('lint failure creates no diff preview', t => {
    const root = createTempWorkspace(t, 'fix-diff-lint');
    const file = writeTempFile(root, 'case.php', "<?php echo SCF::get('title');\n");
    const beforeEntries = fs.readdirSync(root);
    let spawned = false;
    const messages = [];
    const plan = autoFixPlan(file, Buffer.from("<?php echo esc_html(SCF::get('title'));\n"));
    plan.lint = { available: true, passed: false };

    const result = openSecurityFixDiff(plan, {
        tempDirectory: root,
        spawn() {
            spawned = true;
            return { status: 0 };
        },
        out() {},
        error(message) { messages.push(message); }
    });

    assert.equal(result.status, 'lint-blocked');
    assert.equal(result.previewPath, null);
    assert.equal(spawned, false);
    assert.deepEqual(fs.readdirSync(root), beforeEntries);
    assert.match(messages.join('\n'), /PHP lint did not pass/);
});

test('missing VS Code CLI keeps the preview available without crashing', t => {
    const root = createTempWorkspace(t, 'fix-diff-no-code');
    const file = writeTempFile(root, 'case.php', "<?= SCF::get('title') ?>\n");
    const messages = [];
    const result = openSecurityFixDiff(
        autoFixPlan(file, Buffer.from("<?= esc_html(SCF::get('title')) ?>\n")),
        {
            tempDirectory: root,
            codeCommand: 'missing-code',
            spawn() {
                return { status: null, error: Object.assign(new Error('not found'), { code: 'ENOENT' }) };
            },
            out() {},
            error(message) { messages.push(message); }
        }
    );

    assert.equal(result.status, 'preview-created');
    assert.equal(result.opened, false);
    assert.ok(fs.existsSync(result.previewPath));
    assert.match(messages.join('\n'), /code --diff/);
});

test('Windows VS Code command wrapper resolves to Code.exe plus versioned cli.js without a shell', {
    skip: process.platform === 'win32' ? false : 'Windows-specific VS Code CLI wrapper.'
}, t => {
    const root = createTempWorkspace(t, 'fix-diff-code-wrapper');
    const bin = path.join(root, 'bin');
    const cliPath = path.join(root, 'revision', 'resources', 'app', 'out', 'cli.js');
    fs.mkdirSync(path.dirname(cliPath), { recursive: true });
    fs.mkdirSync(bin, { recursive: true });
    const executable = writeTempFile(root, 'Code.exe', 'stub');
    fs.writeFileSync(cliPath, 'stub');
    const commandFile = path.join(bin, 'code.cmd');
    fs.writeFileSync(
        commandFile,
        '@echo off\r\nset ELECTRON_RUN_AS_NODE=1\r\n"%~dp0..\\Code.exe" "%~dp0..\\revision\\resources\\app\\out\\cli.js" %*\r\n'
    );

    const invocation = resolveCodeInvocation(() => ({ status: 0, stdout: `${commandFile}\r\n` }));
    assert.equal(invocation.command, executable);
    assert.deepEqual(invocation.argsPrefix, [cliPath]);
    assert.equal(invocation.env.ELECTRON_RUN_AS_NODE, '1');
});
