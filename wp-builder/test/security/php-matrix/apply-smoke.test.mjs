import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { applySecurityFixPlan } from '../../../lib/security/fix-apply.js';
import { buildSecurityFixPlan } from '../../../lib/security/fix-plan.js';
import {
    assertExpectedPhpMinor,
    expectedPhpRuntimeGate,
    inspectPhpRuntime
} from '../../helpers/php-runtime.mjs';
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
    const expectedRuntimeGate = expectedPhpRuntimeGate(runtime);
    const root = createTempWorkspace(t, 'php-matrix-apply');
    const file = writeTempFile(root, 'case.php', Buffer.from("<p><?= SCF::get('title') ?></p>\n"));
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });

    assert.equal(plan.tokenizer.runtime.gate.status, expectedRuntimeGate.status);
    if (!expectedRuntimeGate.applyEligible) {
        assert.equal(plan.canApply, false);
        assert.ok(plan.blockingReasons.some(reason => reason.code === expectedRuntimeGate.blockingCode));
        assert.deepEqual(fs.readFileSync(file), plan.originalBytes);
        assertNoSecurityArtifacts(root);
        return;
    }

    assert.equal(plan.lint.passed, true, plan.lint.output);
    if (process.platform === 'win32') {
        assert.equal(plan.canApply, false);
        assert.ok(plan.blockingReasons.some(
            reason => reason.code === 'WINDOWS_APPLY_UNSUPPORTED_STRICT_METADATA'
        ));
        await assert.rejects(
            () => applySecurityFixPlan({ ...plan, canApply: true }, { assumeYes: true }),
            error => (
                error.exitCode === 2 &&
                error.code === 'WINDOWS_APPLY_UNSUPPORTED_STRICT_METADATA'
            )
        );
        assert.deepEqual(fs.readFileSync(file), plan.originalBytes);
        assertNoSecurityArtifacts(root);
        return;
    }
    assert.equal(plan.canApply, true, JSON.stringify(plan.blockingReasons));
    const result = await applySecurityFixPlan(plan, { assumeYes: true });
    assert.equal(result.status, 'applied');
    assert.deepEqual(fs.readFileSync(file), plan.desiredBytes);
    assertNoSecurityArtifacts(root);
});
