import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { runCli } from '../helpers/cli-runner.mjs';
import { sha256 } from '../helpers/hash.mjs';
import { securityFixIntegrationTestOptions } from '../helpers/php-runtime.mjs';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

test('security:fix CLI preview and option contract', securityFixIntegrationTestOptions(), async t => {
    await t.test('preview is read-only', st => {
        const root = createTempWorkspace(st, 'cli-preview');
        const file = writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\n");
        const before = sha256(fs.readFileSync(file));
        const result = runCli(root, ['security:fix', '--file', 'case.php']);
        assert.equal(result.status, 0);
        assert.match(result.stdout, /Security Fix Preview/);
        assert.match(result.stdout, /No files changed\./);
        if (process.platform === 'win32') {
            assert.match(result.stderr, /WINDOWS_APPLY_UNSUPPORTED_STRICT_METADATA/);
        }
        assert.equal(sha256(fs.readFileSync(file)), before);
    });

    await t.test('directory preview recursively summarizes PHP files without writing', st => {
        const root = createTempWorkspace(st, 'cli-directory-preview');
        const auto = writeTempFile(root, 'include/layouts/auto.php', "<p><?= SCF::get('title') ?></p>\n");
        const diagnostic = writeTempFile(root, 'include/common/diagnostic.php', "<?php $value = SCF::get('body');\n");
        writeTempFile(root, 'include/layouts/ignored.txt', "<?= SCF::get('ignored') ?>\n");
        const before = new Map([
            [auto, sha256(fs.readFileSync(auto))],
            [diagnostic, sha256(fs.readFileSync(diagnostic))]
        ]);

        const result = runCli(root, ['security:fix', '--dir', 'include']);
        assert.equal(result.status, 0);
        assert.match(result.stdout, /Security Fix Directory Preview/);
        assert.match(result.stdout, /2 files scanned/);
        assert.match(result.stdout, /1 auto-fixable/);
        assert.match(result.stdout, /1 diagnostic-only/);
        before.forEach((hash, file) => assert.equal(sha256(fs.readFileSync(file)), hash));
    });

    await t.test('directory apply remains unsupported without writing', st => {
        const root = createTempWorkspace(st, 'cli-directory-apply');
        const file = writeTempFile(root, 'include/case.php', "<p><?= SCF::get('title') ?></p>\n");
        const before = sha256(fs.readFileSync(file));
        const result = runCli(root, ['security:fix', '--dir', 'include', '--apply', '--yes']);
        assert.equal(result.status, 1);
        assert.match(result.stderr, /Directory apply is unsupported/);
        assert.equal(sha256(fs.readFileSync(file)), before);
    });

    await t.test('directory edit keeps one-file fallback commands when the extension is unavailable', st => {
        const root = createTempWorkspace(st, 'cli-directory-edit');
        const file = writeTempFile(root, 'include/case.php', "<p><?= SCF::get('title') ?></p>\n");
        const before = sha256(fs.readFileSync(file));
        const fakeBin = path.join(root, 'fake-vscode', 'bin');
        fs.mkdirSync(fakeBin, { recursive: true });
        if (process.platform === 'win32') {
            writeTempFile(root, 'fake-vscode/Code.exe', 'not-an-executable');
            writeTempFile(root, 'fake-vscode/revision/resources/app/out/cli.js', 'stub');
            writeTempFile(
                root,
                'fake-vscode/bin/code.cmd',
                '@echo off\r\nset ELECTRON_RUN_AS_NODE=1\r\n"%~dp0..\\Code.exe" "%~dp0..\\revision\\resources\\app\\out\\cli.js" %*\r\n'
            );
        } else {
            const command = writeTempFile(root, 'fake-vscode/bin/code', '#!/bin/sh\nexit 1\n');
            fs.chmodSync(command, 0o700);
        }
        const pathKey = Object.keys(process.env).find(key => key.toLowerCase() === 'path') ?? 'PATH';
        const childEnvironment = { ...process.env };
        childEnvironment[pathKey] = `${fakeBin}${path.delimiter}${process.env[pathKey] ?? ''}`;
        const result = runCli(root, ['security:fix', '--dir', 'include', '--edit'], {
            env: childEnvironment
        });
        assert.equal(result.status, 1);
        assert.match(result.stdout, /Security Fix edit candidates \(run one at a time\)/);
        assert.match(result.stdout, /security:fix --file "include\/case\.php" --edit/);
        assert.match(result.stderr, /extension wp-builder\.security-fix-edit is unavailable/);
        assert.equal(sha256(fs.readFileSync(file)), before);
    });

    await t.test('--edit conflicts with --apply and --diff', st => {
        const root = createTempWorkspace(st, 'cli-edit-conflict');
        const file = writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\n");
        const before = sha256(fs.readFileSync(file));
        const withApply = runCli(root, ['security:fix', '--file', 'case.php', '--edit', '--apply']);
        const withDiff = runCli(root, ['security:fix', '--file', 'case.php', '--edit', '--diff']);
        assert.equal(withApply.status, 1);
        assert.equal(withDiff.status, 1);
        assert.match(withApply.stderr, /--edit cannot be combined/);
        assert.match(withDiff.stderr, /--edit cannot be combined/);
        assert.equal(sha256(fs.readFileSync(file)), before);
    });

    await t.test('single-file edit option is exposed without changing a file', st => {
        const root = createTempWorkspace(st, 'cli-file-edit');
        const file = writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\n");
        const before = sha256(fs.readFileSync(file));
        const result = runCli(root, ['security:fix', '--help']);
        assert.equal(result.status, 0);
        assert.match(result.stdout, /--edit/);
        assert.equal(sha256(fs.readFileSync(file)), before);
    });

    await t.test('--apply --yes applies one file', st => {
        const root = createTempWorkspace(st, 'cli-apply');
        const file = writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\n");
        const before = sha256(fs.readFileSync(file));
        const result = runCli(root, ['security:fix', '--file', 'case.php', '--apply', '--yes']);
        if (process.platform === 'win32') {
            assert.equal(result.status, 2);
            assert.match(result.stderr, /WINDOWS_APPLY_UNSUPPORTED_STRICT_METADATA/);
            assert.match(result.stderr, /Windows apply is unsupported/);
            assert.equal(sha256(fs.readFileSync(file)), before);
        } else {
            assert.equal(result.status, 0);
            assert.match(fs.readFileSync(file, 'utf8'), /esc_html\(SCF::get/);
        }
    });

    await t.test('--yes without --apply fails without writing', st => {
        const root = createTempWorkspace(st, 'cli-yes-only');
        const file = writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\n");
        const before = sha256(fs.readFileSync(file));
        const result = runCli(root, ['security:fix', '--file', 'case.php', '--yes']);
        assert.equal(result.status, 1);
        assert.equal(sha256(fs.readFileSync(file)), before);
    });

    await t.test('non-TTY --apply requires --yes', st => {
        const root = createTempWorkspace(st, 'cli-non-tty');
        const file = writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\n");
        const before = sha256(fs.readFileSync(file));
        const result = runCli(root, ['security:fix', '--file', 'case.php', '--apply']);
        assert.equal(result.status, process.platform === 'win32' ? 2 : 1);
        if (process.platform === 'win32') {
            assert.match(result.stderr, /WINDOWS_APPLY_UNSUPPORTED_STRICT_METADATA/);
        }
        assert.equal(sha256(fs.readFileSync(file)), before);
    });

    await t.test('--all remains unsupported', st => {
        const root = createTempWorkspace(st, 'cli-all');
        writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\n");
        const result = runCli(root, ['security:fix', '--file', 'case.php', '--all']);
        assert.equal(result.status, 1);
    });
});
