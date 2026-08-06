import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { analyzeSecurityFile, runPhpTokenizer } from '../../../lib/security/analyzer.js';
import { buildSecurityFixPlan } from '../../../lib/security/fix-plan.js';
import { loadSecurityFixture } from '../../helpers/fixture-loader.mjs';
import { assertExpectedPhpMinor, inspectPhpRuntime } from '../../helpers/php-runtime.mjs';
import { createTempWorkspace, writeTempFile } from '../../helpers/temp-workspace.mjs';

const fixtures = [
    [1, "<?php enum Status { case Draft; } ?>\n<p><?= SCF::get('title') ?></p>\n"],
    [2, "<?php readonly class Record { public string $value; } ?>\n<p><?= SCF::get('title') ?></p>\n"],
    [3, "<?php class Constants { public const string NAME = 'x'; } ?>\n<p><?= SCF::get('title') ?></p>\n"],
    [4, "<?php class Hooked { public string $name { get => 'x'; } } ?>\n<p><?= SCF::get('title') ?></p>\n"]
];

test('TOKEN_PARSE follows PHP syntax introduction versions', async t => {
    const runtime = inspectPhpRuntime();
    assertExpectedPhpMinor(assert, runtime);
    for (const [introducedMinor, source] of fixtures) {
        await t.test(`PHP 8.${introducedMinor} syntax`, () => {
            const bytes = Buffer.from(source);
            const tokenized = runPhpTokenizer(bytes);
            const shouldParse = runtime.phpMajor > 8 || (runtime.phpMajor === 8 && runtime.phpMinor >= introducedMinor);
            assert.equal(tokenized.ok, shouldParse);
            if (!shouldParse) {
                assert.equal(tokenized.errorCode, 'WPB-SCF-PARSE-UNSAFE');
                const root = createTempWorkspace(t, `php-8-${introducedMinor}-syntax`);
                const file = writeTempFile(root, path.join('fixture', 'case.php'), bytes);
                const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
                assert.equal(plan.canApply, false);
                assert.ok(plan.blockingReasons.some(reason => reason.code === 'WPB-SCF-PARSE-UNSAFE'));
                return;
            }
            const analysis = analyzeSecurityFile({ filePath: 'fixture.php', bytes });
            assert.equal(analysis.canAnalyze, true);
            assert.equal(analysis.findings.length, 1);
            assert.equal(analysis.findings[0].ruleId, 'WPB-SCF-UNESCAPED-OUTPUT');
        });
    }
});

test('invalid PHP remains parse-unsafe without fallback', () => {
    const bytes = loadSecurityFixture('analyzer/parse-error.php');
    const result = runPhpTokenizer(bytes);
    assert.equal(result.ok, false);
    assert.equal(result.errorCode, 'WPB-SCF-PARSE-UNSAFE');
    assert.equal(result.runtime.phpVersion, inspectPhpRuntime().phpVersion);
    assert.ok(Number.isInteger(result.line));
});
