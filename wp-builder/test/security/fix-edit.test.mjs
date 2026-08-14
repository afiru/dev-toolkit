import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {
    createSecurityFixEditReviewPayload,
    createSecurityFixEditPayload,
    openSecurityFixEdit,
    openSecurityFixEditReview,
    SECURITY_FIX_EDIT_EXTENSION_ID,
    SECURITY_FIX_EDIT_REVIEW_ACK_KIND
} from '../../lib/security/fix-edit.js';
import { buildSecurityFixDirectoryPlan } from '../../lib/security/fix-directory.js';
import { buildSecurityFixPlan } from '../../lib/security/fix-plan.js';
import { securityFixIntegrationTestOptions } from '../helpers/php-runtime.mjs';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

test('AUTO_FIXABLE plan creates a bounded edit payload with original identity', securityFixIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-edit-payload');
    const file = writeTempFile(root, 'case.php', "<p><?= SCF::get('title') ?></p>\r\n");
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    const payload = createSecurityFixEditPayload(plan, { workspaceRoot: root });

    assert.equal(payload.schemaVersion, 1);
    assert.equal(payload.file, file);
    assert.equal(payload.originalSha256, plan.snapshot.hash);
    assert.equal(payload.originalSize, plan.snapshot.size);
    assert.equal(payload.edits.length, 1);
    assert.equal(payload.edits[0].findingId, plan.replacements[0].findingId);
    assert.equal(payload.edits[0].startByte, plan.replacements[0].startByte);
    assert.equal(payload.edits[0].endByte, plan.replacements[0].endByte);
    assert.equal(payload.edits[0].originalSha256, plan.replacements[0].originalHash);
    assert.match(payload.edits[0].replacement, /^esc_html\(/);
});

test('DIAGNOSTIC_ONLY plan creates no edit payload', securityFixIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-edit-diagnostic');
    const file = writeTempFile(root, 'case.php', "<?php $value = SCF::get('body');\n");
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    assert.equal(plan.counts.autoFixable, 0);
    assert.equal(createSecurityFixEditPayload(plan, { workspaceRoot: root }), null);
});

test('lint failure and workspace escape create no edit payload', securityFixIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-edit-blocked');
    const otherRoot = createTempWorkspace(t, 'fix-edit-other-root');
    const file = writeTempFile(root, 'case.php', "<?= SCF::get('title') ?>\n");
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    const lintFailed = { ...plan, lint: { available: true, passed: false } };
    assert.throws(
        () => createSecurityFixEditPayload(lintFailed, { workspaceRoot: root }),
        error => error.code === 'SECURITY_EDIT_LINT_REQUIRED'
    );
    assert.throws(
        () => createSecurityFixEditPayload(plan, { workspaceRoot: otherRoot }),
        error => error.code === 'SECURITY_EDIT_OUTSIDE_WORKSPACE'
    );
});

test('symlink edit target is rejected', securityFixIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-edit-symlink');
    const file = writeTempFile(root, 'case.php', "<?= SCF::get('title') ?>\n");
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    const link = path.join(root, 'linked.php');
    try {
        fs.symlinkSync(file, link, 'file');
    } catch (error) {
        if (error.code === 'EPERM' || error.code === 'EACCES') {
            t.skip(`Symlink creation unavailable: ${error.code}`);
            return;
        }
        throw error;
    }
    assert.throws(
        () => createSecurityFixEditPayload({ ...plan, targetPath: link }, { workspaceRoot: root }),
        error => error.code === 'SECURITY_EDIT_UNSAFE_TARGET'
    );
});

test('junction in the edit target path is rejected', securityFixIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-edit-junction');
    const realDirectory = path.join(root, 'real');
    fs.mkdirSync(realDirectory, { recursive: true });
    const file = writeTempFile(root, 'real/case.php', "<?= SCF::get('title') ?>\n");
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    const junction = path.join(root, 'linked');
    try {
        fs.symlinkSync(realDirectory, junction, process.platform === 'win32' ? 'junction' : 'dir');
    } catch (error) {
        if (error.code === 'EPERM' || error.code === 'EACCES') {
            t.skip(`Junction creation unavailable: ${error.code}`);
            return;
        }
        throw error;
    }
    assert.throws(
        () => createSecurityFixEditPayload(
            { ...plan, targetPath: path.join(junction, 'case.php') },
            { workspaceRoot: root }
        ),
        error => error.code === 'SECURITY_EDIT_UNSAFE_TARGET'
    );
});

test('installed extension receives a fixed-schema temp JSON request', securityFixIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-edit-launch');
    const file = writeTempFile(root, 'case.php', "<?= SCF::get('title') ?>\n");
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    const calls = [];
    const result = openSecurityFixEdit(plan, {
        workspaceRoot: root,
        tempDirectory: root,
        codeCommand: 'code-test',
        spawn(command, args) {
            calls.push({ command, args });
            if (args[0] === '--list-extensions') return { status: 0, stdout: `${SECURITY_FIX_EDIT_EXTENSION_ID}\n` };
            return { status: 0, stdout: '' };
        },
        out() {},
        error() {}
    });

    assert.equal(result.status, 'request-sent');
    assert.ok(fs.existsSync(result.payloadPath));
    const stored = JSON.parse(fs.readFileSync(result.payloadPath, 'utf8'));
    assert.equal(stored.originalSha256, plan.snapshot.hash);
    assert.equal(calls.length, 2);
    assert.equal(calls[1].args[0], '--open-url');
    assert.match(calls[1].args[1], /^vscode:\/\/wp-builder\.security-fix-edit\/edit\?payload=/);
});

test('directory review payload is stable, groups findings by file, and keeps diagnostics non-editing', securityFixIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-edit-review-payload');
    writeTempFile(root, 'include/z.php', "<p><?= SCF::get('one') ?> <?= SCF::get('two') ?></p>\n");
    writeTempFile(root, 'include/a.php', "<p><?= SCF::get('title') ?></p>\n");
    writeTempFile(root, 'include/diagnostic.php', "<?php $value = SCF::get('body');\n");
    const directoryPlan = buildSecurityFixDirectoryPlan({ workspaceRoot: root, directory: 'include' });
    const payload = createSecurityFixEditReviewPayload(directoryPlan);

    assert.equal(payload.kind, 'wp-builder-security-fix-edit-review');
    assert.match(payload.ackToken, /^[a-f0-9]{64}$/);
    assert.deepEqual(payload.items.map(item => item.relativePath), ['include/a.php', 'include/z.php']);
    assert.equal(payload.items[1].edits.length, 2);
    assert.equal(payload.items[0].desiredSha256, directoryPlan.plans.find(plan => plan.relativePath === 'include/a.php').desiredHash);
    assert.equal(payload.diagnostics.length, 1);
    assert.equal(payload.diagnostics[0].file, 'include/diagnostic.php');
    assert.equal('edits' in payload.diagnostics[0], false);
});

test('diagnostic-only directory review uses a separate fixed candidate queue', securityFixIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-edit-diagnostic-review-payload');
    const file = writeTempFile(root, 'include/dynamic.php', '<p><?= SCF::get($field) ?></p>\n');
    const before = fs.readFileSync(file);
    const directoryPlan = buildSecurityFixDirectoryPlan({ workspaceRoot: root, directory: 'include' });
    const payload = createSecurityFixEditReviewPayload(directoryPlan);

    assert.equal(payload.items.length, 0);
    assert.equal(payload.diagnostics.length, 1);
    const diagnostic = payload.diagnostics[0];
    assert.equal(diagnostic.reviewDisposition, 'CANDIDATES');
    assert.equal(diagnostic.candidates.length, 1);
    assert.equal(diagnostic.candidates[0].lint.passed, true);
    assert.equal(diagnostic.candidates[0].findingId, diagnostic.findingId);
    assert.equal(diagnostic.source.file, file);
    assert.equal(diagnostic.source.originalSha256, directoryPlan.plans[0].snapshot.hash);
    assert.deepEqual(fs.readFileSync(file), before);
});

test('installed extension receives one directory review request', securityFixIntegrationTestOptions(), t => {
    const root = createTempWorkspace(t, 'fix-edit-review-launch');
    writeTempFile(root, 'include/case.php', "<?= SCF::get('title') ?>\n");
    const directoryPlan = buildSecurityFixDirectoryPlan({ workspaceRoot: root, directory: 'include' });
    const calls = [];
    const output = [];
    let stored;
    let requestRoot;
    const result = openSecurityFixEditReview(directoryPlan, {
        tempDirectory: root,
        codeCommand: 'code-test',
        spawn(command, args) {
            calls.push({ command, args });
            if (args[0] === '--list-extensions') return { status: 0, stdout: `${SECURITY_FIX_EDIT_EXTENSION_ID}\n` };
            const uri = new URL(args.at(-1));
            const payloadPath = new URLSearchParams(uri.searchParams).get('payload');
            requestRoot = path.dirname(payloadPath);
            stored = JSON.parse(fs.readFileSync(payloadPath, 'utf8'));
            fs.writeFileSync(path.join(requestRoot, 'edit-ack.json'), JSON.stringify({
                schemaVersion: 1,
                kind: SECURITY_FIX_EDIT_REVIEW_ACK_KIND,
                sessionId: stored.sessionId,
                ackToken: stored.ackToken,
                status: 'session-started',
                code: null
            }));
            return { status: 0, stdout: '' };
        },
        out(message) { output.push(message); },
        error() {}
    });

    assert.equal(result.status, 'session-started');
    assert.equal(stored.kind, 'wp-builder-security-fix-edit-review');
    assert.equal(stored.items.length, 1);
    assert.equal(calls.length, 2);
    assert.deepEqual(calls[1].args.slice(0, 2), ['--reuse-window', '--open-url']);
    assert.match(calls[1].args[2], /^vscode:\/\/wp-builder\.security-fix-edit\/edit\?payload=/);
    assert.match(output.join('\n'), /Review started in VS Code/);
    assert.doesNotMatch(output.join('\n'), /No editor was modified/);
    assert.equal(fs.existsSync(requestRoot), false);
});

test('directory review acknowledgement failures are fail-closed and cleaned', securityFixIntegrationTestOptions(), async t => {
    const root = createTempWorkspace(t, 'fix-edit-review-ack');
    writeTempFile(root, 'include/case.php', "<?= SCF::get('title') ?>\n");
    const directoryPlan = buildSecurityFixDirectoryPlan({ workspaceRoot: root, directory: 'include' });

    const run = (ackFactory, overrides = {}) => {
        const errors = [];
        let requestRoot;
        const result = openSecurityFixEditReview(directoryPlan, {
            tempDirectory: root,
            codeCommand: 'code-test',
            ackTimeoutMs: 0,
            spawn(_command, args) {
                if (args[0] === '--list-extensions') return { status: 0, stdout: `${SECURITY_FIX_EDIT_EXTENSION_ID}\n` };
                const uri = new URL(args.at(-1));
                const payloadPath = new URLSearchParams(uri.searchParams).get('payload');
                requestRoot = path.dirname(payloadPath);
                const payload = JSON.parse(fs.readFileSync(payloadPath, 'utf8'));
                const ack = ackFactory?.(payload);
                if (ack) fs.writeFileSync(path.join(requestRoot, 'edit-ack.json'), JSON.stringify(ack));
                return { status: 0, stdout: '' };
            },
            out() {},
            error(message) { errors.push(message); },
            ...overrides
        });
        assert.equal(fs.existsSync(requestRoot), false);
        return { result, errors };
    };
    const ackFor = (payload, values) => ({
        schemaVersion: 1,
        kind: SECURITY_FIX_EDIT_REVIEW_ACK_KIND,
        sessionId: payload.sessionId,
        ackToken: payload.ackToken,
        status: 'rejected',
        code: 'TARGET_EDITOR_DIRTY',
        ...values
    });

    await t.test('TARGET_EDITOR_DIRTY', () => {
        const { result, errors } = run(payload => ackFor(payload));
        assert.equal(result.status, 'ack-rejected');
        assert.equal(result.code, 'TARGET_EDITOR_DIRTY');
        assert.doesNotMatch(errors.join('\n'), /REVIEW_SESSION_ALREADY_ACTIVE/);
        assert.match(errors.join('\n'), /Close, save, or discard/);
    });
    await t.test('REVIEW_SESSION_ALREADY_ACTIVE', () => {
        const { result, errors } = run(payload => ackFor(payload, {
            code: 'REVIEW_SESSION_ALREADY_ACTIVE'
        }));
        assert.equal(result.status, 'ack-rejected');
        assert.equal(result.code, 'REVIEW_SESSION_ALREADY_ACTIVE');
        assert.doesNotMatch(errors.join('\n'), /TARGET_EDITOR_DIRTY/);
        assert.match(errors.join('\n'), /Security Fix Review is already active/);
        assert.match(errors.join('\n'), /Finish or cancel the current review/);
    });
    await t.test('timeout', () => {
        const { result, errors } = run(() => null);
        assert.equal(result.status, 'ack-timeout');
        assert.match(errors.join('\n'), /ACK_TIMEOUT/);
    });
    await t.test('stale token', () => {
        const { result, errors } = run(payload => ackFor(payload, { ackToken: '0'.repeat(64) }));
        assert.equal(result.status, 'ack-stale');
        assert.match(errors.join('\n'), /STALE_ACK/);
    });
    await t.test('invalid schema', () => {
        const { result, errors } = run(() => ({ schemaVersion: 99 }));
        assert.equal(result.status, 'ack-invalid');
        assert.match(errors.join('\n'), /INVALID_ACK_SCHEMA/);
    });
});
