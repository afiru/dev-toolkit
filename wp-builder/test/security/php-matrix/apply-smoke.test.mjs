import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { applySecurityFixPlan } from '../../../lib/security/fix-apply.js';
import { buildSecurityFixPlan } from '../../../lib/security/fix-plan.js';
import { assertExpectedPhpMinor, inspectPhpRuntime } from '../../helpers/php-runtime.mjs';
import {
    assertNoSecurityArtifacts,
    createTempWorkspace,
    writeTempFile
} from '../../helpers/temp-workspace.mjs';

test('eligible PHP matrix runtime completes one apply smoke', {
    skip: ['win32', 'linux'].includes(process.platform) ? false : `Apply smoke is unsupported on ${process.platform}.`
}, async t => {
    const runtime = inspectPhpRuntime();
    assertExpectedPhpMinor(assert, runtime);
    const root = createTempWorkspace(t, 'php-matrix-apply');
    const file = writeTempFile(root, 'case.php', Buffer.from("<p><?= SCF::get('title') ?></p>\n"));
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });

    if (runtime.phpMajor === 8 && runtime.phpMinor <= 1) {
        assert.equal(plan.canApply, false);
        assert.ok(plan.blockingReasons.some(reason => reason.code === 'PHP_VERSION_LEGACY_COMPATIBILITY'));
        return;
    }

    assert.equal(plan.tokenizer.runtime.gate.status, 'VERIFIED_APPLY_CANDIDATE');
    assert.equal(plan.lint.passed, true, plan.lint.output);
    assert.equal(plan.canApply, true, JSON.stringify(plan.blockingReasons));
    const result = await applySecurityFixPlan(plan, { assumeYes: true });
    assert.equal(result.status, 'applied');
    assert.deepEqual(fs.readFileSync(file), plan.desiredBytes);
    assertNoSecurityArtifacts(root);
});
