import { spawnSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { launchCode, resolveCodeInvocation } from './fix-diff.js';
import { sha256 } from './fix-plan.js';

export const SECURITY_FIX_EDIT_EXTENSION_ID = 'wp-builder.security-fix-edit';
export const SECURITY_FIX_EDIT_SCHEMA_VERSION = 1;
export const SECURITY_FIX_EDIT_REVIEW_KIND = 'wp-builder-security-fix-edit-review';
export const SECURITY_FIX_EDIT_REVIEW_ACK_KIND = 'wp-builder-security-fix-edit-review-ack';

function isInside(parent, target) {
    const relative = path.relative(path.resolve(parent), path.resolve(target));
    return relative === '' || (
        relative !== '..' &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative)
    );
}

function editError(code, message, exitCode = 2) {
    const error = new Error(message);
    error.code = code;
    error.exitCode = exitCode;
    return error;
}

function assertNoSymlinkPath(root, file) {
    let current = root;
    const relative = path.relative(root, file);
    for (const segment of relative.split(path.sep).filter(Boolean)) {
        current = path.join(current, segment);
        if (fs.lstatSync(current).isSymbolicLink()) {
            throw editError('SECURITY_EDIT_UNSAFE_TARGET', 'Security Fix edit path contains a symbolic link or junction.');
        }
    }
}

function assertCurrentIdentity(plan, stat, bytes) {
    const expected = plan.snapshot?.metadata?.identity;
    if (!expected ||
        stat.dev !== expected.dev ||
        stat.ino !== expected.ino ||
        stat.nlink !== expected.nlink ||
        stat.size !== plan.snapshot.size ||
        sha256(bytes) !== plan.snapshot.hash) {
        throw editError(
            'SECURITY_EDIT_STALE_FILE',
            'Security Fix edit cancelled: the file changed after preview. Run security:fix again.',
            4
        );
    }
}

export function createSecurityFixEditPayload(plan, { workspaceRoot }) {
    if ((plan.counts?.autoFixable ?? 0) === 0 || !plan.hasChanges) return null;
    if (!plan.lint?.available || !plan.lint.passed) {
        throw editError('SECURITY_EDIT_LINT_REQUIRED', 'Security Fix edit requires a successful PHP lint result.');
    }

    const root = path.resolve(workspaceRoot);
    const file = path.resolve(plan.targetPath);
    if (!isInside(root, file)) {
        throw editError('SECURITY_EDIT_OUTSIDE_WORKSPACE', 'Security Fix edit target must be inside the workspace.');
    }
    assertNoSymlinkPath(root, file);

    const stat = fs.lstatSync(file);
    if (stat.isSymbolicLink() || !stat.isFile()) {
        throw editError('SECURITY_EDIT_UNSAFE_TARGET', 'Security Fix edit target must be a normal non-symlink file.');
    }
    const exactStat = fs.lstatSync(file, { bigint: true });
    const currentBytes = fs.readFileSync(file);
    const confirmedExactStat = fs.lstatSync(file, { bigint: true });
    if (exactStat.dev !== confirmedExactStat.dev ||
        exactStat.ino !== confirmedExactStat.ino ||
        exactStat.nlink !== confirmedExactStat.nlink ||
        exactStat.size !== confirmedExactStat.size) {
        throw editError('SECURITY_EDIT_STALE_FILE', 'Security Fix edit cancelled: the file changed during verification.', 4);
    }
    assertCurrentIdentity(plan, stat, currentBytes);

    const findings = new Map(plan.findings.map(finding => [finding.id, finding]));
    const edits = plan.replacements
        .map(replacement => {
            const finding = findings.get(replacement.findingId);
            if (!finding?.autoFixable) {
                throw editError('SECURITY_EDIT_INVALID_REPLACEMENT', 'Edit payload contains a non-auto-fixable replacement.');
            }
            return {
                findingId: replacement.findingId,
                startByte: replacement.startByte,
                endByte: replacement.endByte,
                originalSha256: replacement.originalHash,
                replacement: replacement.replacementText,
                location: {
                    line: finding.location.startLine,
                    column: finding.location.startColumn
                }
            };
        })
        .sort((left, right) => left.startByte - right.startByte);
    if (edits.length === 0) {
        throw editError('SECURITY_EDIT_NO_REPLACEMENTS', 'Security Fix edit has no verified replacements.');
    }

    return {
        schemaVersion: SECURITY_FIX_EDIT_SCHEMA_VERSION,
        kind: 'wp-builder-security-fix-edit',
        workspaceRoot: root,
        file,
        originalSha256: plan.snapshot.hash,
        desiredSha256: plan.desiredHash,
        originalSize: plan.snapshot.size,
        originalIdentity: {
            dev: exactStat.dev.toString(),
            ino: exactStat.ino.toString(),
            nlink: exactStat.nlink.toString()
        },
        encoding: {
            charset: plan.encoding.charset,
            bom: plan.encoding.bom
        },
        edits
    };
}

function compareReviewItems(left, right) {
    const byPath = left.relativePath.localeCompare(right.relativePath, 'en');
    if (byPath !== 0) return byPath;
    const byLine = left.firstLocation.line - right.firstLocation.line;
    return byLine !== 0 ? byLine : left.firstLocation.column - right.firstLocation.column;
}

function diagnosticSourceForPlan(plan, workspaceRoot) {
    const root = path.resolve(workspaceRoot);
    const file = path.resolve(plan.targetPath);
    if (!isInside(root, file)) {
        throw editError('SECURITY_EDIT_OUTSIDE_WORKSPACE', 'Security Fix diagnostic target must be inside the workspace.');
    }
    assertNoSymlinkPath(root, file);
    const before = fs.lstatSync(file, { bigint: true });
    const bytes = fs.readFileSync(file);
    const after = fs.lstatSync(file, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() ||
        before.dev !== after.dev || before.ino !== after.ino || before.nlink !== after.nlink || before.size !== after.size ||
        sha256(bytes) !== plan.snapshot.hash) {
        throw editError('SECURITY_EDIT_STALE_FILE', 'Security Fix diagnostic review source changed after preview.', 4);
    }
    return {
        workspaceRoot: root,
        file,
        originalSha256: plan.snapshot.hash,
        originalSize: plan.snapshot.size,
        originalIdentity: {
            dev: before.dev.toString(),
            ino: before.ino.toString(),
            nlink: before.nlink.toString()
        },
        encoding: {
            charset: plan.encoding.charset,
            bom: plan.encoding.bom
        }
    };
}

export function createSecurityFixEditReviewPayload(directoryPlan) {
    const items = directoryPlan.plans
        .filter(plan => (plan.counts?.autoFixable ?? 0) > 0)
        .map(plan => {
            const payload = createSecurityFixEditPayload(plan, {
                workspaceRoot: directoryPlan.workspaceRoot
            });
            const firstFinding = plan.findings
                .filter(finding => finding.autoFixable)
                .sort((left, right) =>
                    left.location.startLine - right.location.startLine ||
                    left.location.startColumn - right.location.startColumn
                )[0];
            return {
                ...payload,
                relativePath: path.relative(directoryPlan.workspaceRoot, plan.targetPath).replace(/\\/g, '/'),
                firstLocation: {
                    line: firstFinding.location.startLine,
                    column: firstFinding.location.startColumn
                }
            };
        })
        .sort(compareReviewItems);
    const diagnostics = directoryPlan.plans.flatMap(plan => plan.findings
        .filter(finding => !finding.autoFixable)
        .map(finding => {
            const reviewDisposition = finding.reviewDisposition ?? 'MANUAL_ONLY';
            const candidates = reviewDisposition === 'CANDIDATES'
                ? finding.reviewCandidates ?? []
                : [];
            return {
                file: path.relative(directoryPlan.workspaceRoot, plan.targetPath).replace(/\\/g, '/'),
                line: finding.location.startLine,
                column: finding.location.startColumn,
                findingId: finding.id,
                ruleId: finding.ruleId,
                reviewDisposition,
                reason: finding.reviewReason ?? finding.reason,
                source: candidates.length > 0
                    ? diagnosticSourceForPlan(plan, directoryPlan.workspaceRoot)
                    : null,
                candidates
            };
        }))
        .sort((left, right) =>
            left.file.localeCompare(right.file, 'en') ||
            left.line - right.line ||
            left.column - right.column
        );
    if (items.length === 0 && diagnostics.length === 0) return null;

    return {
        schemaVersion: SECURITY_FIX_EDIT_SCHEMA_VERSION,
        kind: SECURITY_FIX_EDIT_REVIEW_KIND,
        sessionId: randomUUID(),
        ackToken: randomBytes(32).toString('hex'),
        workspaceRoot: path.resolve(directoryPlan.workspaceRoot),
        items,
        diagnostics
    };
}

function sleep(milliseconds) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

export function waitForSecurityFixEditReviewAck(ackPath, payload, options = {}) {
    const timeoutMs = options.ackTimeoutMs ?? 5000;
    const pause = options.sleep ?? sleep;
    const deadline = Date.now() + timeoutMs;
    while (!fs.existsSync(ackPath)) {
        if (Date.now() >= deadline) return { status: 'ack-timeout' };
        pause(Math.min(50, Math.max(1, deadline - Date.now())));
    }

    let stat;
    let ack;
    try {
        stat = fs.lstatSync(ackPath);
        if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 4096) return { status: 'ack-invalid' };
        ack = JSON.parse(fs.readFileSync(ackPath, 'utf8'));
    } catch {
        return { status: 'ack-invalid' };
    }
    if (!ack || ack.schemaVersion !== 1 || ack.kind !== SECURITY_FIX_EDIT_REVIEW_ACK_KIND ||
        !['session-started', 'rejected'].includes(ack.status) ||
        (ack.status === 'session-started' && ack.code !== null) ||
        (ack.status === 'rejected' && !/^[A-Z][A-Z0-9_]{2,63}$/.test(ack.code ?? ''))) {
        return { status: 'ack-invalid' };
    }
    if (ack.sessionId !== payload.sessionId || ack.ackToken !== payload.ackToken) {
        return { status: 'ack-stale' };
    }
    return ack.status === 'session-started'
        ? { status: 'session-started', code: null }
        : { status: 'ack-rejected', code: ack.code };
}

function extensionAvailable(invocation, spawn) {
    const result = spawn(invocation.command, [...invocation.argsPrefix, '--list-extensions'], {
        encoding: 'utf8',
        env: { ...process.env, ...invocation.env },
        timeout: 5000,
        windowsHide: true
    });
    if (result.error || result.status !== 0) return false;
    return String(result.stdout ?? '')
        .split(/\r?\n/)
        .some(item => item.trim().toLowerCase() === SECURITY_FIX_EDIT_EXTENSION_ID);
}

function openSecurityFixPayload(payload, options = {}) {
    const {
        out = console.log,
        error = console.error,
        spawn = spawnSync,
        tempDirectory = os.tmpdir()
    } = options;
    const invocation = options.codeCommand ? {
        command: options.codeCommand,
        argsPrefix: options.codeArgsPrefix ?? [],
        env: options.codeEnv ?? {}
    } : resolveCodeInvocation(spawn);
    if (!invocation || !extensionAvailable(invocation, spawn)) {
        error(`VS Code extension ${SECURITY_FIX_EDIT_EXTENSION_ID} is unavailable. No edit was applied.`);
        return { status: 'extension-unavailable', opened: false, payloadPath: null };
    }

    const tempRoot = fs.mkdtempSync(path.join(tempDirectory, 'wp-builder-security-edit-'));
    const payloadPath = path.join(tempRoot, 'edit-request.json');
    fs.writeFileSync(payloadPath, `${JSON.stringify(payload)}\n`, { flag: 'wx', mode: 0o600 });
    const uri = `vscode://${SECURITY_FIX_EDIT_EXTENSION_ID}/edit?payload=${encodeURIComponent(payloadPath)}`;
    const launchArguments = payload.kind === SECURITY_FIX_EDIT_REVIEW_KIND
        ? ['--reuse-window', '--open-url', uri]
        : ['--open-url', uri];
    const launch = launchCode(launchArguments, {
        ...options,
        codeCommand: invocation.command,
        codeArgsPrefix: invocation.argsPrefix,
        codeEnv: invocation.env,
        spawn
    });
    if (!launch.opened) {
        fs.rmSync(tempRoot, { recursive: true, force: true });
        error('VS Code could not open the Security Fix edit request. No edit was applied.');
        return { status: 'launch-failed', payloadPath: null, ...launch };
    }

    if (payload.kind !== SECURITY_FIX_EDIT_REVIEW_KIND) {
        out('Security Fix edit request sent to VS Code. Review the dirty editor and press Ctrl+S only if approved.');
        return { status: 'request-sent', payloadPath, ...launch };
    }

    const ackPath = path.join(tempRoot, 'edit-ack.json');
    let ack;
    try {
        ack = waitForSecurityFixEditReviewAck(ackPath, payload, options);
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
    if (ack.status === 'session-started') {
        out('Security Fix Edit Review started in VS Code. Only one file will be dirty at a time.');
        return { status: 'session-started', payloadPath: null, ...launch };
    }
    if (ack.status === 'ack-rejected' && ack.code === 'REVIEW_SESSION_ALREADY_ACTIVE') {
        error('Security Fix Edit Review was not started.');
        error('[REVIEW_SESSION_ALREADY_ACTIVE]');
        error('Security Fix Review is already active.');
        error('Finish or cancel the current review before starting another review.');
    } else if (ack.status === 'ack-rejected' && ack.code === 'TARGET_EDITOR_DIRTY') {
        error('Security Fix Edit Review was not started.');
        error('[TARGET_EDITOR_DIRTY]');
        error('Close, save, or discard the existing dirty editor and run the command again.');
    } else if (ack.status === 'ack-rejected') {
        error(`Security Fix Edit Review was not started. [${ack.code}]`);
    } else if (ack.status === 'ack-timeout') {
        error('Security Fix Edit Review was not started. [ACK_TIMEOUT]');
    } else if (ack.status === 'ack-stale') {
        error('Security Fix Edit Review was not started. [STALE_ACK]');
    } else {
        error('Security Fix Edit Review was not started. [INVALID_ACK_SCHEMA]');
    }
    return { ...ack, opened: false, payloadPath: null };
}

export function openSecurityFixEdit(plan, options = {}) {
    const payload = createSecurityFixEditPayload(plan, { workspaceRoot: options.workspaceRoot });
    if (!payload) return { status: 'no-auto-fixable', opened: false, payloadPath: null };
    return openSecurityFixPayload(payload, options);
}

export function openSecurityFixEditReview(directoryPlan, options = {}) {
    const payload = createSecurityFixEditReviewPayload(directoryPlan);
    if (!payload) return { status: 'no-review-items', opened: false, payloadPath: null };
    return openSecurityFixPayload(payload, options);
}
