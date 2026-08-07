import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { runCli } from '../helpers/cli-runner.mjs';
import { sha256 } from '../helpers/hash.mjs';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

test('legacy security remains read-only and reports WARNING / NOTICE', t => {
    const root = createTempWorkspace(t, 'legacy-security-read');
    const file = writeTempFile(
        root,
        'case.php',
        "<?php\necho SCF::get('title');\n$value = SCF::get('body');\n"
    );
    const before = sha256(fs.readFileSync(file));
    const result = runCli(root, ['security']);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /\[WARNING\]/);
    assert.match(result.stdout, /\[NOTICE\]/);
    assert.equal(sha256(fs.readFileSync(file)), before);
});

test('legacy security --fix characterization: unsafe comment and qualified-class rewrites remain observable', t => {
    const root = createTempWorkspace(t, 'legacy-security-fix');
    const comment = writeTempFile(root, 'comment.php', "<?php\n// SCF::get('title');\n");
    const qualified = writeTempFile(root, 'qualified.php', "<p><?= Vendor\\SCF::get('title') ?></p>\n");
    const result = runCli(root, ['security', '--fix']);
    assert.equal(result.status, 0);
    assert.match(
        result.stderr,
        /\[DEPRECATED\] Legacy "security --fix" is a DISABLE_CANDIDATE\. Use "security:fix --file <path>" instead\./
    );
    assert.match(fs.readFileSync(comment, 'utf8'), /\/\/ esc_html\(SCF::get/);
    assert.match(fs.readFileSync(qualified, 'utf8'), /Vendor\\esc_html\(SCF::get/);
});
