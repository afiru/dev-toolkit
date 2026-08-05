import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { analyzeSecurityFile } from '../../lib/security/analyzer.js';
import { loadSecurityFixture } from '../helpers/fixture-loader.mjs';
import { sha256 } from '../helpers/hash.mjs';
import { phpIntegrationTestOptions } from '../helpers/php-runtime.mjs';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

const cases = [
    ['line-comment.php', 0, null, false, null],
    ['block-comment.php', 0, null, false, null],
    ['php-string.php', 0, null, false, null],
    ['heredoc.php', 0, null, false, null],
    ['nowdoc.php', 0, null, false, null],
    ['outside-html.php', 0, null, false, null],
    ['global-scf.php', 1, 'WPB-SCF-UNESCAPED-OUTPUT', true, 'esc_html'],
    ['fully-qualified-scf.php', 1, 'WPB-SCF-UNESCAPED-OUTPUT', true, 'esc_html'],
    ['vendor-scf.php', 0, null, false, null],
    ['my-scf.php', 0, null, false, null],
    ['namespaced-scf.php', 1, 'WPB-SCF-CLASS-AMBIGUOUS', false, null],
    ['multiline.php', 1, 'WPB-SCF-EXPRESSION-COMPLEX', false, null],
    ['multiline-escaped.php', 1, 'WPB-SCF-ALREADY-ESCAPED', false, null],
    ['multiple-calls.php', 2, 'WPB-SCF-INDIRECT-USAGE', false, null],
    ['assignment.php', 1, 'WPB-SCF-INDIRECT-USAGE', false, null],
    ['return.php', 1, 'WPB-SCF-INDIRECT-USAGE', false, null],
    ['argument.php', 1, 'WPB-SCF-INDIRECT-USAGE', false, null],
    ['dynamic-field.php', 1, 'WPB-SCF-ARGUMENT-UNSUPPORTED', false, null],
    ['already-escaped.php', 1, 'WPB-SCF-ALREADY-ESCAPED', false, null]
];

test('Security Analyzer fixture matrix', phpIntegrationTestOptions(), async t => {
    for (const [fixture, count, ruleId, autoFixable, proposedEscape] of cases) {
        await t.test(fixture, () => {
            const root = createTempWorkspace(t, 'analyzer');
            const bytes = loadSecurityFixture(`analyzer/${fixture}`);
            const filePath = writeTempFile(root, path.join('fixture', fixture), bytes);
            const beforeHash = sha256(fs.readFileSync(filePath));
            const analysis = analyzeSecurityFile({ filePath, bytes: fs.readFileSync(filePath) });

            assert.equal(analysis.canAnalyze, true);
            assert.equal(analysis.findings.length, count);
            if (ruleId) assert.deepEqual([...new Set(analysis.findings.map(item => item.ruleId))], [ruleId]);
            assert.equal(analysis.findings.filter(item => item.autoFixable).length, autoFixable ? count : 0);
            if (proposedEscape) assert.ok(analysis.findings.every(item => item.proposedEscape === proposedEscape));

            analysis.findings.forEach(finding => {
                assert.ok(finding.range.startByte >= 0);
                assert.ok(finding.range.endByte > finding.range.startByte);
                assert.ok(finding.location.startLine >= 1);
                assert.ok(finding.location.startColumn >= 1);
                assert.equal(
                    bytes.subarray(finding.range.startByte, finding.range.endByte).toString('utf8'),
                    finding.exactSourceExpression
                );
            });
            assert.equal(sha256(fs.readFileSync(filePath)), beforeHash, 'Analyzer must not modify its source file.');
        });
    }
});
