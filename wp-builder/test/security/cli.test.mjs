import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { runCli } from '../helpers/cli-runner.mjs';
import { sha256 } from '../helpers/hash.mjs';
import { phpIntegrationTestOptions } from '../helpers/php-runtime.mjs';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

test('security:fix CLI preview and option contract', phpIntegrationTestOptions(), async t => {
    await t.test('preview is read-only', st => {
        const root = createTempWorkspace(st, 'cli-preview');
        const file = writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\n");
        const before = sha256(fs.readFileSync(file));
        const result = runCli(root, ['security:fix', '--file', 'case.php']);
        assert.equal(result.status, 0);
        assert.match(result.stdout, /Security Fix Preview/);
        assert.match(result.stdout, /No files changed\./);
        assert.equal(sha256(fs.readFileSync(file)), before);
    });

    await t.test('--apply --yes applies one file', st => {
        const root = createTempWorkspace(st, 'cli-apply');
        const file = writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\n");
        const result = runCli(root, ['security:fix', '--file', 'case.php', '--apply', '--yes']);
        assert.equal(result.status, 0);
        assert.match(fs.readFileSync(file, 'utf8'), /esc_html\(SCF::get/);
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
        assert.equal(result.status, 1);
        assert.equal(sha256(fs.readFileSync(file)), before);
    });

    await t.test('--all remains unsupported', st => {
        const root = createTempWorkspace(st, 'cli-all');
        writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\n");
        const result = runCli(root, ['security:fix', '--file', 'case.php', '--all']);
        assert.equal(result.status, 1);
    });
});
