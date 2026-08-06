import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { analyzeSecurityFile } from '../../../lib/security/analyzer.js';
import { loadSecurityFixture } from '../../helpers/fixture-loader.mjs';
import { sha256 } from '../../helpers/hash.mjs';
import { assertExpectedPhpMinor, inspectPhpRuntime } from '../../helpers/php-runtime.mjs';
import { createTempWorkspace, writeTempFile } from '../../helpers/temp-workspace.mjs';

const cases = [
    ['global-scf.php', 1, 'WPB-SCF-UNESCAPED-OUTPUT', 'WARNING', true, 'esc_html', 'HTML_TEXT'],
    ['fully-qualified-scf.php', 1, 'WPB-SCF-UNESCAPED-OUTPUT', 'WARNING', true, 'esc_html', 'HTML_TEXT'],
    ['vendor-scf.php', 0],
    ['my-scf.php', 0],
    ['namespaced-scf.php', 1, 'WPB-SCF-CLASS-AMBIGUOUS', 'WARNING', false, null, 'HTML_TEXT'],
    ['use-scf.php', 1, 'WPB-SCF-CLASS-AMBIGUOUS', 'WARNING', false, null, 'HTML_TEXT'],
    ['use-alias.php', 0],
    ['vendor-import.php', 1, 'WPB-SCF-CLASS-AMBIGUOUS', 'WARNING', false, null, 'HTML_TEXT'],
    ['namespace-block.php', 1, 'WPB-SCF-CLASS-AMBIGUOUS', 'NOTICE', false, null, 'INDIRECT_OR_COMPLEX'],
    ['echo.php', 1, 'WPB-SCF-UNESCAPED-OUTPUT', 'WARNING', true, 'esc_html', 'HTML_TEXT'],
    ['multiline.php', 1, 'WPB-SCF-EXPRESSION-COMPLEX', 'WARNING', false, null, 'HTML_TEXT'],
    ['multiline-escaped.php', 1, 'WPB-SCF-ALREADY-ESCAPED', 'INFO', false, null, 'INDIRECT_OR_COMPLEX'],
    ['multiple-calls.php', 2, 'WPB-SCF-INDIRECT-USAGE', 'NOTICE', false, null, 'INDIRECT_OR_COMPLEX'],
    ['assignment.php', 1, 'WPB-SCF-INDIRECT-USAGE', 'NOTICE', false, null, 'INDIRECT_OR_COMPLEX'],
    ['return.php', 1, 'WPB-SCF-INDIRECT-USAGE', 'NOTICE', false, null, 'INDIRECT_OR_COMPLEX'],
    ['argument.php', 1, 'WPB-SCF-INDIRECT-USAGE', 'NOTICE', false, null, 'INDIRECT_OR_COMPLEX'],
    ['dynamic-field.php', 1, 'WPB-SCF-ARGUMENT-UNSUPPORTED', 'WARNING', false, null, 'HTML_TEXT'],
    ['already-escaped.php', 1, 'WPB-SCF-ALREADY-ESCAPED', 'INFO', false, null, 'INDIRECT_OR_COMPLEX']
];

test('Analyzer contract is common across the PHP matrix', async t => {
    assertExpectedPhpMinor(assert, inspectPhpRuntime());
    for (const [fixture, count, ruleId, severity, autoFixable, proposedEscape, context] of cases) {
        await t.test(fixture, () => {
            const root = createTempWorkspace(t, 'php-matrix-analyzer');
            const bytes = loadSecurityFixture(`analyzer/${fixture}`);
            const filePath = writeTempFile(root, path.join('fixture', fixture), bytes);
            const before = sha256(fs.readFileSync(filePath));
            const analysis = analyzeSecurityFile({ filePath, bytes });
            assert.equal(analysis.canAnalyze, true);
            assert.equal(analysis.findings.length, count);
            for (const finding of analysis.findings) {
                assert.equal(finding.ruleId, ruleId);
                assert.equal(finding.severity, severity);
                assert.equal(finding.autoFixable, autoFixable);
                assert.equal(finding.proposedEscape, proposedEscape);
                assert.equal(finding.outputContext.kind, context);
                assert.ok(finding.range.startByte >= 0);
                assert.ok(finding.range.endByte > finding.range.startByte);
                assert.ok(finding.location.startLine >= 1);
                assert.ok(finding.location.startColumn >= 1);
                assert.equal(
                    bytes.subarray(finding.range.startByte, finding.range.endByte).toString('utf8'),
                    finding.exactSourceExpression
                );
            }
            assert.equal(sha256(fs.readFileSync(filePath)), before);
        });
    }
});
