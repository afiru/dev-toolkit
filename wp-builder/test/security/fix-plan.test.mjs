import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { buildSecurityFixPlan, sha256 } from '../../lib/security/fix-plan.js';
import { renderSecurityFixPreview } from '../../lib/security/fix-preview.js';
import { phpIntegrationTestOptions } from '../helpers/php-runtime.mjs';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

test('Security Fix Plan contains immutable source and preview data without writing', phpIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-plan');
    const input = Buffer.from("<p><?= SCF::get('title') ?></p>\n");
    const file = writeTempFile(root, 'case.php', input);
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });

    assert.equal(plan.snapshot.state, 'present');
    assert.equal(plan.snapshot.normalFile, true);
    assert.equal(plan.snapshot.symlink, false);
    assert.equal(plan.snapshot.size, input.length);
    assert.equal(plan.snapshot.hash, sha256(input));
    assert.deepEqual(plan.originalBytes, input);
    assert.notDeepEqual(plan.desiredBytes, input);
    assert.equal(plan.desiredHash, sha256(plan.desiredBytes));
    assert.equal(plan.replacements.length, 1);
    assert.match(plan.replacements[0].replacementText, /^esc_html\(/);
    assert.match(plan.diff, /^--- a\/case\.php/m);
    assert.match(plan.diff, /^\+\+\+ b\/case\.php/m);
    assert.equal(plan.lint.available, true);
    assert.equal(plan.lint.passed, true);
    assert.equal(plan.canApply, true);

    const output = [];
    const errors = [];
    renderSecurityFixPreview(plan, {
        out: line => output.push(line),
        error: line => errors.push(line)
    });
    assert.ok(output.includes('No files changed.'));
    assert.ok(output.some(line => String(line).includes('AUTO_FIXABLE')));
    assert.ok(output.some(line => String(line).includes('unified diff:')));
    assert.deepEqual(errors, []);
    assert.deepEqual(fs.readFileSync(file), input);
});
