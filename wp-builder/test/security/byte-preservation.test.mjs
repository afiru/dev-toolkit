import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { buildSecurityFixPlan } from '../../lib/security/fix-plan.js';
import { securityFixIntegrationTestOptions } from '../helpers/php-runtime.mjs';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

const bom = Buffer.from([0xef, 0xbb, 0xbf]);
const cases = [
    ['LF', Buffer.from("<p><?= SCF::get('field') ?></p>\n<div>x</div>\n"), 'LF', false, true],
    ['CRLF', Buffer.from("<p><?= SCF::get('field') ?></p>\r\n<div>x</div>\r\n"), 'CRLF', false, true],
    ['mixed newline', Buffer.from("<p><?= SCF::get('field') ?></p>\r\n<div>x</div>\n"), 'MIXED', false, true],
    ['UTF-8 BOM', Buffer.concat([bom, Buffer.from("<p><?= SCF::get('field') ?></p>\n")]), 'LF', true, true],
    ['no trailing newline', Buffer.from("<p><?= SCF::get('field') ?></p>"), 'LF', false, false],
    ['multibyte', Buffer.from("<p>日本語 <?= SCF::get('field') ?> 終了</p>\n"), 'LF', false, true]
];

test('Security Fix Plan preserves bytes outside replacement ranges', securityFixIntegrationTestOptions(), async t => {
    for (const [name, input, newline, hasBom, trailing] of cases) {
        await t.test(name, () => {
            const root = createTempWorkspace(t, 'bytes');
            const file = writeTempFile(root, 'case.php', input);
            const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
            assert.equal(plan.replacements.length, 1);
            assert.equal(plan.newline.style, newline);
            assert.equal(plan.newline.trailing, trailing);
            assert.equal(plan.encoding.bom, hasBom);
            assert.deepEqual(plan.originalBytes, input);
            assert.deepEqual(fs.readFileSync(file), input, 'Plan generation must not write the source file.');

            const replacement = plan.replacements[0];
            const replacementBytes = Buffer.from(replacement.replacementText, 'utf8');
            assert.deepEqual(
                plan.desiredBytes.subarray(0, replacement.startByte),
                input.subarray(0, replacement.startByte)
            );
            assert.deepEqual(
                plan.desiredBytes.subarray(replacement.startByte + replacementBytes.length),
                input.subarray(replacement.endByte)
            );
            if (hasBom) assert.deepEqual(plan.desiredBytes.subarray(0, 3), bom);
        });
    }
});
