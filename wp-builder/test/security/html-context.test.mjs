import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { buildSecurityFixPlan } from '../../lib/security/fix-plan.js';
import { phpIntegrationTestOptions } from '../helpers/php-runtime.mjs';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

const cases = [
    ['HTML text', "<p><?= SCF::get('field') ?></p>\n", true, 'HTML_TEXT', 'esc_html'],
    ['normal attribute', "<div title=\"<?= SCF::get('field') ?>\"></div>\n", true, 'HTML_ATTRIBUTE', 'esc_attr'],
    ['href URL attribute', "<a href=\"<?= SCF::get('field') ?>\">x</a>\n", true, 'URL_ATTRIBUTE', 'esc_url'],
    ['src URL attribute', "<img src=\"<?= SCF::get('field') ?>\">\n", true, 'URL_ATTRIBUTE', 'esc_url'],
    ['textarea', "<textarea><?= SCF::get('field') ?></textarea>\n", true, 'TEXTAREA', 'esc_textarea'],
    ['srcset', "<img srcset=\"<?= SCF::get('field') ?>\">\n", false, 'SRCSET_ATTRIBUTE', null],
    ['script', "<script><?= SCF::get('field') ?></script>\n", false, 'SCRIPT', null],
    ['style', "<style><?= SCF::get('field') ?></style>\n", false, 'STYLE', null],
    ['data attribute', "<div data-value=\"<?= SCF::get('field') ?>\"></div>\n", false, 'UNSAFE_ATTRIBUTE', null],
    ['event handler', "<button onclick=\"<?= SCF::get('field') ?>\">x</button>\n", false, 'UNSAFE_ATTRIBUTE', null],
    ['malformed HTML', "<div title=<?= SCF::get('field') ?>></div>\n", false, 'CONTEXT_UNKNOWN', null],
    ['unclosed quote', "<div title=\"<?= SCF::get('field') ?></div>\n", false, 'CONTEXT_UNKNOWN', null],
    ['HTML comment', "<!-- <?= SCF::get('field') ?> -->\n", false, 'CONTEXT_UNKNOWN', null]
];

test('HTML context matrix', phpIntegrationTestOptions(), async t => {
    for (const [name, source, autoFixable, context, escape] of cases) {
        await t.test(name, () => {
            const root = createTempWorkspace(t, 'html-context');
            const file = writeTempFile(root, 'case.php', source);
            const before = fs.readFileSync(file);
            const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
            assert.equal(plan.findings.length, 1);
            assert.equal(plan.findings[0].autoFixable, autoFixable);
            assert.equal(plan.findings[0].outputContext.kind, context);
            assert.equal(plan.findings[0].proposedEscape, escape);
            assert.deepEqual(fs.readFileSync(file), before);
        });
    }
});

test('KEEP BLOCKER: multiple PHP islands in one attribute must be diagnostic-only', {
    ...phpIntegrationTestOptions(),
    todo: 'The current HTML context analyzer treats the second island as AUTO_FIXABLE.'
}, t => {
    const root = createTempWorkspace(t, 'html-islands');
    const file = writeTempFile(root, 'case.php', "<div title=\"<?= other() ?><?= SCF::get('field') ?>\"></div>\n");
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    assert.equal(plan.findings[0].autoFixable, false);
});
