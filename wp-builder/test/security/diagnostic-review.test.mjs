import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeSecurityFile } from '../../lib/security/analyzer.js';
import { securityFixIntegrationTestOptions } from '../helpers/php-runtime.mjs';

const cases = [
    ['multiline HTML text', "<p><?= SCF::get(\n    'title'\n) ?></p>\n", 'WPB-SCF-EXPRESSION-COMPLEX', 'CANDIDATES', 'HIGH'],
    ['multiline unknown context', "<script><?= SCF::get(\n    'title'\n) ?></script>\n", 'WPB-SCF-EXPRESSION-COMPLEX', 'MANUAL_ONLY', null],
    ['dynamic field HTML text', "<p><?= SCF::get($field) ?></p>\n", 'WPB-SCF-ARGUMENT-UNSUPPORTED', 'CANDIDATES', 'MEDIUM'],
    ['dynamic field URL', "<a href=\"<?= SCF::get($field) ?>\">x</a>\n", 'WPB-SCF-ARGUMENT-UNSUPPORTED', 'CANDIDATES', 'MEDIUM'],
    ['array field argument', "<p><?= SCF::get([$field]) ?></p>\n", 'WPB-SCF-ARGUMENT-UNSUPPORTED', 'MANUAL_ONLY', null],
    ['computed field argument', "<p><?= SCF::get(resolve_field()) ?></p>\n", 'WPB-SCF-ARGUMENT-UNSUPPORTED', 'MANUAL_ONLY', null],
    ['dynamic field unknown context', "<script><?= SCF::get($field) ?></script>\n", 'WPB-SCF-ARGUMENT-UNSUPPORTED', 'MANUAL_ONLY', null],
    ['compatible existing escape', "<p><?= esc_html(SCF::get('title')) ?></p>\n", 'WPB-SCF-ALREADY-ESCAPED', 'NO_CHANGE', null],
    ['mismatched existing escape', "<a href=\"<?= esc_html(SCF::get('url')) ?>\">x</a>\n", 'WPB-SCF-ALREADY-ESCAPED', 'CANDIDATES', 'HIGH'],
    ['kses intent unknown', "<p><?= wp_kses_post(SCF::get('body')) ?></p>\n", 'WPB-SCF-ALREADY-ESCAPED', 'MANUAL_ONLY', null],
    ['single definition and sink', "<?php $value = SCF::get('title'); ?>\n<p><?= $value ?></p>\n", 'WPB-SCF-INDIRECT-USAGE', 'CANDIDATES', 'MEDIUM'],
    ['reassignment', "<?php $value = SCF::get('title'); $value = other(); ?>\n<p><?= $value ?></p>\n", 'WPB-SCF-INDIRECT-USAGE', 'MANUAL_ONLY', null],
    ['branch', "<?php $value = SCF::get('title'); if ($ok) { echo 'x'; } ?>\n<p><?= $value ?></p>\n", 'WPB-SCF-INDIRECT-USAGE', 'MANUAL_ONLY', null],
    ['loop', "<?php $value = SCF::get('title'); foreach ($items as $item) { echo $item; } ?>\n<p><?= $value ?></p>\n", 'WPB-SCF-INDIRECT-USAGE', 'MANUAL_ONLY', null],
    ['return', "<?php function value() { $value = SCF::get('title'); return $value; } ?>\n", 'WPB-SCF-INDIRECT-USAGE', 'MANUAL_ONLY', null],
    ['unknown function argument', "<?php $value = SCF::get('title'); consume($value); ?>\n", 'WPB-SCF-INDIRECT-USAGE', 'MANUAL_ONLY', null],
    ['reference', "<?php $value = SCF::get('title'); $reference =& $value; ?>\n", 'WPB-SCF-INDIRECT-USAGE', 'MANUAL_ONLY', null],
    ['variable variable', "<?php $value = SCF::get('title'); ?>\n<p><?= $$value ?></p>\n", 'WPB-SCF-INDIRECT-USAGE', 'MANUAL_ONLY', null],
    ['unresolved class', "<?php namespace Project; ?>\n<p><?= SCF::get('title') ?></p>\n", 'WPB-SCF-CLASS-AMBIGUOUS', 'MANUAL_ONLY', null],
    ['context unknown', "<script><?= SCF::get('title') ?></script>\n", 'WPB-SCF-CONTEXT-UNKNOWN', 'MANUAL_ONLY', null],
    ['parse unsafe', "<?php if ( ?>\n", 'WPB-SCF-PARSE-UNSAFE', 'MANUAL_ONLY', null]
];

test('DIAGNOSTIC_ONLY Phase D1 classification matrix is conservative and source preserving', securityFixIntegrationTestOptions(), async t => {
    for (const [name, source, ruleId, disposition, confidence] of cases) {
        await t.test(name, () => {
            const bytes = Buffer.from(source);
            const before = Buffer.from(bytes);
            const analysis = analyzeSecurityFile({ filePath: `${name}.php`, bytes });
            assert.equal(analysis.findings.length, 1);
            const finding = analysis.findings[0];
            assert.equal(finding.ruleId, ruleId);
            assert.equal(finding.autoFixable, false);
            assert.equal(finding.reviewDisposition, disposition);
            assert.deepEqual(bytes, before);

            if (disposition === 'CANDIDATES') {
                assert.equal(finding.reviewCandidates.length, 1);
                const candidate = finding.reviewCandidates[0];
                assert.equal(candidate.schemaVersion, 1);
                assert.equal(candidate.findingId, finding.id);
                assert.equal(candidate.confidence, confidence);
                assert.equal(candidate.lint.available, true);
                assert.equal(candidate.lint.passed, true);
                assert.equal(candidate.lint.exitCode, 0);
                assert.match(candidate.desiredSha256, /^[a-f0-9]{64}$/);
                assert.ok(candidate.edits.every(edit => /^[a-f0-9]{64}$/.test(edit.originalSha256)));
                assert.equal('command' in candidate, false);
            } else {
                assert.deepEqual(finding.reviewCandidates, []);
            }
        });
    }
});

test('AUTO_FIXABLE findings remain outside the diagnostic review contract', securityFixIntegrationTestOptions(), () => {
    const source = "<p><?= SCF::get('title') ?></p>\n";
    const finding = analyzeSecurityFile({ filePath: 'auto.php', bytes: Buffer.from(source) }).findings[0];
    assert.equal(finding.autoFixable, true);
    assert.equal(finding.proposedEscape, 'esc_html');
    assert.equal('reviewDisposition' in finding, false);
    assert.equal('reviewCandidates' in finding, false);
});
