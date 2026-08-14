'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
    diagnosticEditablePayload,
    prepareEdits,
    renderCandidateText,
    sha256,
    validateIncomingPayload,
    validateDiagnosticCandidatePayload,
    validatePayload,
    validateReviewPayload
} = require('./edit-core.cjs');
const {
    COMMANDS: REVIEW_COMMANDS,
    SecurityFixReviewUi,
    validateReviewCommandArguments
} = require('./review-ui.cjs');

const SKIP_COMMAND = 'wp-builder.securityFixEdit.skip';
const CANCEL_COMMAND = 'wp-builder.securityFixEdit.cancel';
const REVIEW_ACK_KIND = 'wp-builder-security-fix-edit-review-ack';
const CANDIDATE_DOCUMENT_SCHEME = 'wp-builder-security-fix-candidate';
const SAFE_REVIEW_REJECTION_CODES = new Set([
    'AUTO_SAVE_ENABLED',
    'DOCUMENT_DIRTY',
    'OUTSIDE_WORKSPACE',
    'REVIEW_SESSION_ALREADY_ACTIVE',
    'STALE_FILE',
    'TARGET_EDITOR_DIRTY',
    'UNSAFE_TARGET'
]);
const MANUAL_REVIEW_EXPLANATIONS = Object.freeze({
    'WPB-SCF-INDIRECT-USAGE': {
        reason: 'SCF::get() の値が間接的に使用されているため、最終的な出力先を安全に特定できません。',
        check: '値が最終的にどこへ出力されるか確認し、その文脈に適した処理を手動で判断してください。'
    },
    'WPB-SCF-CONTEXT-UNKNOWN': {
        reason: 'この値がHTML本文・URL・属性値など、どの文脈へ出力されるか安全に特定できません。',
        check: '実際の出力先を確認してください。誤ったエスケープを避けるため自動修正は行いません。'
    },
    'WPB-SCF-ARGUMENT-UNSUPPORTED': {
        reason: 'SCF::get() の引数が現在の安全な自動解析対象外です。',
        check: '取得している値と、その値の出力先を確認してください。'
    },
    'WPB-SCF-PARSE-UNSAFE': {
        reason: 'コードを安全に解析できないため、自動修正候補を作成できません。',
        check: '対象コードの構文や周辺処理を手動で確認してください。'
    },
    'WPB-SCF-CLASS-AMBIGUOUS': {
        reason: 'SCFとして検出した呼び出しのクラス判定を安全に確定できません。',
        check: '対象の呼び出しが意図したSCF処理か確認してください。'
    }
});
const MANUAL_REVIEW_FALLBACK_REASON =
    'この箇所は安全な自動修正方法を確定できないため、手動確認が必要です。';
const MANUAL_REVIEW_FALLBACK_CHECK = '対象箇所の処理内容と実際の出力先を手動で確認してください。';
let activeReviewSession = null;
let reviewOutputChannel = null;
let reviewUi = null;
const candidateDocuments = new Map();

function isInside(parent, target) {
    const relative = path.relative(path.resolve(parent), path.resolve(target));
    return relative === '' || (
        relative !== '..' &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative)
    );
}

function samePath(left, right) {
    if (!left || !right) return false;
    const normalizedLeft = path.resolve(left);
    const normalizedRight = path.resolve(right);
    return process.platform === 'win32'
        ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
        : normalizedLeft === normalizedRight;
}

function requestRootFor(payloadPath) {
    if (!path.isAbsolute(payloadPath) || path.basename(payloadPath) !== 'edit-request.json') return null;
    const requestRoot = path.dirname(payloadPath);
    if (path.dirname(requestRoot) !== path.resolve(os.tmpdir()) ||
        !path.basename(requestRoot).startsWith('wp-builder-security-edit-')) return null;
    return requestRoot;
}

function reviewError(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
}

function reviewRejectionCode(error) {
    return SAFE_REVIEW_REJECTION_CODES.has(error?.code) ? error.code : 'REVIEW_START_FAILED';
}

function assertReviewSessionAvailable(session) {
    if (session) {
        throw reviewError(
            'REVIEW_SESSION_ALREADY_ACTIVE',
            'Security Fix：すでにレビューが進行中です。\n現在のレビューを終了してから、もう一度実行してください。'
        );
    }
}

function showReviewRequestError(vscode, error) {
    const message = error?.code === 'REVIEW_SESSION_ALREADY_ACTIVE'
        ? error.message
        : `Security Fix edit cancelled: ${error.message}`;
    return vscode.window.showErrorMessage(message);
}

function safeManualReviewReason(value) {
    if (typeof value !== 'string') return null;
    const reason = value.trim();
    if (reason.length === 0 || reason.length > 500 ||
        /[\r\n<>$={}\[\]`"'\\/]/u.test(reason) ||
        /\b(?:token|password|secret|\.env)\b/iu.test(reason) ||
        /[A-Za-z]:/u.test(reason)) return null;
    return reason;
}

function manualReviewMessage(item) {
    const explanation = MANUAL_REVIEW_EXPLANATIONS[item.ruleId];
    const reason = explanation?.reason ?? safeManualReviewReason(item.reason) ?? MANUAL_REVIEW_FALLBACK_REASON;
    const check = explanation?.check ?? MANUAL_REVIEW_FALLBACK_CHECK;
    return `Security Fix：手動確認が必要です。\n\n${item.ruleId}\n\n理由：\n${reason}\n\n確認：\n${check}`;
}

function writeReviewAck(payloadPath, payload, status, code = null) {
    const requestRoot = requestRootFor(payloadPath);
    if (!requestRoot || payload?.kind !== 'wp-builder-security-fix-edit-review') {
        throw new Error('Security Fix Edit Review cannot write an acknowledgement for this request.');
    }
    const ackPath = path.join(requestRoot, 'edit-ack.json');
    const temporaryPath = path.join(requestRoot, 'edit-ack.tmp');
    const ack = {
        schemaVersion: 1,
        kind: REVIEW_ACK_KIND,
        sessionId: payload.sessionId,
        ackToken: payload.ackToken,
        status,
        code
    };
    fs.writeFileSync(temporaryPath, `${JSON.stringify(ack)}\n`, { flag: 'wx', mode: 0o600 });
    fs.renameSync(temporaryPath, ackPath);
}

function readPayload(payloadPath) {
    if (!requestRootFor(payloadPath) || !isInside(os.tmpdir(), payloadPath)) {
        throw new Error('Security Fix edit request must be a file inside the OS temp directory.');
    }
    const stat = fs.lstatSync(payloadPath);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 1024 * 1024) {
        throw new Error('Security Fix edit request is not a safe regular JSON file.');
    }
    return validateIncomingPayload(JSON.parse(fs.readFileSync(payloadPath, 'utf8')));
}

function assertSafeTargetPath(workspaceRoot, file) {
    let current = path.resolve(workspaceRoot);
    if (fs.lstatSync(current).isSymbolicLink()) {
        throw new Error('Security Fix edit workspace root cannot be a symbolic link or junction.');
    }
    const relative = path.relative(current, path.resolve(file));
    for (const segment of relative.split(path.sep).filter(Boolean)) {
        current = path.join(current, segment);
        if (fs.lstatSync(current).isSymbolicLink()) {
            throw new Error('Security Fix edit path contains a symbolic link or junction.');
        }
    }
}

function assertAutoSaveDisabled(vscode, uri) {
    const configuration = vscode.workspace.getConfiguration?.('files', uri);
    const autoSave = configuration?.get?.('autoSave');
    if (autoSave !== 'off') {
        throw reviewError('AUTO_SAVE_ENABLED', 'Security Fix Edit Review requires files.autoSave to be off. No editor was changed.');
    }
}

function documentForFile(vscode, file) {
    return (vscode.workspace.textDocuments ?? []).find(document => samePath(document.uri?.fsPath, file));
}

function tabUri(tab) {
    return tab?.input?.uri ?? tab?.input?.modified ?? null;
}

function isFileTabOpen(vscode, file) {
    const groups = vscode.window.tabGroups?.all;
    if (!Array.isArray(groups)) return null;
    return groups.some(group => (group.tabs ?? []).some(tab => samePath(tabUri(tab)?.fsPath, file)));
}

async function applyPayloadToEditor(vscode, payload) {
    if (payload?.kind === 'wp-builder-security-fix-diagnostic-candidate') {
        validateDiagnosticCandidatePayload(payload);
    } else {
        validatePayload(payload);
    }
    assertSafeTargetPath(payload.workspaceRoot, payload.file);
    const targetUri = vscode.Uri.file(payload.file);
    if (!vscode.workspace.getWorkspaceFolder(targetUri)) {
        throw reviewError('OUTSIDE_WORKSPACE', 'Security Fix edit target is not inside an open VS Code workspace.');
    }
    assertAutoSaveDisabled(vscode, targetUri);
    const document = await vscode.workspace.openTextDocument(targetUri);
    const editor = await vscode.window.showTextDocument(document, { preview: false });
    const prepareCurrentEdits = () => {
        const stat = fs.lstatSync(payload.file, { bigint: true });
        const currentBytes = fs.readFileSync(payload.file);
        return prepareEdits({
            payload,
            currentBytes,
            currentIdentity: {
                dev: stat.dev.toString(),
                ino: stat.ino.toString(),
                nlink: stat.nlink.toString(),
                isFile: stat.isFile(),
                isSymbolicLink: stat.isSymbolicLink()
            },
            documentText: document.getText(),
            documentIsDirty: document.isDirty
        });
    };
    prepareCurrentEdits();
    const edits = prepareCurrentEdits();

    const workspaceEdit = new vscode.WorkspaceEdit();
    edits.forEach(edit => {
        workspaceEdit.replace(
            document.uri,
            new vscode.Range(document.positionAt(edit.startOffset), document.positionAt(edit.endOffset)),
            edit.replacement
        );
    });
    const applied = await vscode.workspace.applyEdit(workspaceEdit);
    if (!applied || !document.isDirty) throw new Error('Security Fix edit could not create an unsaved editor change.');

    const first = edits[0];
    const firstPosition = document.positionAt(first.startOffset);
    editor.selection = new vscode.Selection(firstPosition, firstPosition);
    editor.revealRange(new vscode.Range(firstPosition, firstPosition));
    return { applied: true, dirty: document.isDirty, editCount: edits.length, document, editor };
}

function documentBytes(document, encoding) {
    const content = Buffer.from(document.getText(), 'utf8');
    return encoding?.bom ? Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), content]) : content;
}

function currentFileState(file) {
    const stat = fs.lstatSync(file, { bigint: true });
    return {
        bytes: fs.readFileSync(file),
        identity: {
            dev: stat.dev.toString(),
            ino: stat.ino.toString(),
            nlink: stat.nlink.toString(),
            isFile: stat.isFile(),
            isSymbolicLink: stat.isSymbolicLink()
        }
    };
}

async function showDiagnosticCandidateDiff(vscode, item, candidate) {
    const payload = diagnosticEditablePayload(item.source, candidate);
    validateDiagnosticCandidatePayload(payload);
    assertSafeTargetPath(payload.workspaceRoot, payload.file);
    const targetUri = vscode.Uri.file(payload.file);
    if (!vscode.workspace.getWorkspaceFolder(targetUri)) {
        throw reviewError('OUTSIDE_WORKSPACE', 'Security Fix diagnostic target is not inside an open VS Code workspace.');
    }
    assertAutoSaveDisabled(vscode, targetUri);
    const document = await vscode.workspace.openTextDocument(targetUri);
    const current = currentFileState(payload.file);
    const candidateText = renderCandidateText({
        payload,
        currentBytes: current.bytes,
        currentIdentity: current.identity,
        documentText: document.getText(),
        documentIsDirty: document.isDirty
    });
    const candidateUri = vscode.Uri.parse(
        `${CANDIDATE_DOCUMENT_SCHEME}:/${encodeURIComponent(candidate.candidateId)}.php`
    );
    candidateDocuments.set(candidateUri.toString(), candidateText);
    await vscode.commands.executeCommand(
        'vscode.diff',
        targetUri,
        candidateUri,
        `Security Fix: current ↔ ${candidate.label}`,
        { preview: true }
    );
    return { payload, candidateUri };
}

async function gotoDiagnostic(vscode, workspaceRoot, item, onPrepared) {
    const file = path.resolve(workspaceRoot, item.file);
    assertSafeTargetPath(workspaceRoot, file);
    const uri = vscode.Uri.file(file);
    if (!vscode.workspace.getWorkspaceFolder(uri)) {
        throw reviewError('OUTSIDE_WORKSPACE', 'Security Fix diagnostic target is outside an open workspace.');
    }
    const document = await vscode.workspace.openTextDocument(uri);
    const position = new vscode.Position(item.line - 1, item.column - 1);
    const range = new vscode.Range(position, position);
    await onPrepared({ document, range });
    const editor = await vscode.window.showTextDocument(document, { preview: false });
    editor.selection = new vscode.Selection(position, position);
    editor.revealRange(range);
    return { document, editor, range };
}

class SecurityFixEditReviewSession {
    constructor(vscode, payload, options = {}) {
        this.vscode = vscode;
        this.payload = validateReviewPayload(payload);
        this.applyItem = options.applyItem ?? applyPayloadToEditor;
        this.applyDiagnosticCandidate = options.applyDiagnosticCandidate ?? applyPayloadToEditor;
        this.showCandidateDiff = options.showCandidateDiff ?? showDiagnosticCandidateDiff;
        this.gotoDiagnostic = options.gotoDiagnostic ?? gotoDiagnostic;
        this.readFile = options.readFile ?? fs.readFileSync;
        this.onFinish = options.onFinish ?? (() => {});
        this.outputChannel = options.outputChannel ?? null;
        this.reviewUi = options.reviewUi ?? new SecurityFixReviewUi(vscode);
        this.ownsReviewUi = !options.reviewUi;
        this.status = 'created';
        this.currentIndex = 0;
        this.currentDocument = null;
        this.savedCount = 0;
        this.skippedCount = 0;
        this.diagnosticIndex = 0;
        this.noChangeCount = 0;
        this.manualOnlyCount = 0;
        this.candidateReviewedCount = 0;
        this.disposables = [];
        this.controls = [];
        this.skipControl = null;
        this.failure = null;
        this.currentDiagnostic = null;
    }

    snapshot() {
        return {
            sessionId: this.payload.sessionId,
            status: this.status,
            currentIndex: this.currentIndex,
            savedCount: this.savedCount,
            skippedCount: this.skippedCount,
            diagnosticIndex: this.diagnosticIndex,
            diagnosticCount: this.payload.diagnostics.length
        };
    }

    async start() {
        if (this.status !== 'created') throw new Error('Security Fix Edit Review session has already started.');
        for (const item of this.payload.items) {
            const uri = this.vscode.Uri.file(item.file);
            if (!this.vscode.workspace.getWorkspaceFolder(uri)) {
                throw reviewError('OUTSIDE_WORKSPACE', 'Security Fix edit target is not inside an open VS Code workspace.');
            }
            assertAutoSaveDisabled(this.vscode, uri);
            if (documentForFile(this.vscode, item.file)?.isDirty) {
                throw reviewError('TARGET_EDITOR_DIRTY', 'Security Fix Edit Review cannot start while a target editor is already dirty.');
            }
        }
        for (const diagnostic of this.payload.diagnostics) {
            if (diagnostic.reviewDisposition !== 'CANDIDATES') continue;
            const uri = this.vscode.Uri.file(diagnostic.source.file);
            if (!this.vscode.workspace.getWorkspaceFolder(uri)) {
                throw reviewError('OUTSIDE_WORKSPACE', 'Security Fix diagnostic target is not inside an open VS Code workspace.');
            }
            assertAutoSaveDisabled(this.vscode, uri);
            if (documentForFile(this.vscode, diagnostic.source.file)?.isDirty) {
                throw reviewError('TARGET_EDITOR_DIRTY', 'Security Fix Edit Review cannot start while a diagnostic target is dirty.');
            }
        }
        this.status = 'active';
        this.installListeners();
        this.installControls();
        await this.openCurrent();
        return this.snapshot();
    }

    installListeners() {
        this.disposables.push(
            this.vscode.workspace.onDidSaveTextDocument(document => {
                void this.handleSave(document);
            }),
            this.vscode.workspace.onDidCloseTextDocument(document => {
                void this.handleClose(document);
            }),
            this.vscode.window.tabGroups.onDidChangeTabs(() => {
                if (this.status === 'awaiting-discard') void this.tryCompleteSkip();
            })
        );
    }

    installControls() {
        if (typeof this.vscode.window.createStatusBarItem !== 'function') return;
        const alignment = this.vscode.StatusBarAlignment?.Left;
        const skip = this.vscode.window.createStatusBarItem(alignment, 101);
        skip.text = '$(debug-step-over) Security Fix：今回はスキップ';
        skip.tooltip = 'Explicitly skip the current Security Fix review item';
        skip.command = SKIP_COMMAND;
        if (this.payload.items.length > 0) skip.show();
        this.skipControl = skip;
        const cancel = this.vscode.window.createStatusBarItem(alignment, 100);
        cancel.text = '$(close) Security Fix レビューを終了';
        cancel.tooltip = 'Cancel review without saving, reverting, or closing the current editor';
        cancel.command = CANCEL_COMMAND;
        cancel.show();
        this.controls.push(skip, cancel);
    }

    async openCurrent() {
        if (this.currentIndex >= this.payload.items.length) {
            if (this.payload.diagnostics.length === 0) {
                this.complete();
                return;
            }
            this.status = 'diagnostic-active';
            this.skipControl?.hide?.();
            await this.reviewNextDiagnostic();
            return;
        }
        const dirtyReviewDocument = this.payload.items
            .map(item => documentForFile(this.vscode, item.file))
            .find(document => document?.isDirty);
        if (dirtyReviewDocument) {
            this.block(new Error('Security Fix Edit Review stopped because another review target is dirty.'));
            return;
        }

        const item = this.payload.items[this.currentIndex];
        try {
            const result = await this.applyItem(this.vscode, item);
            this.currentDocument = result.document;
            this.status = 'active';
            this.vscode.window.showInformationMessage(
                `[${this.currentIndex + 1}/${this.payload.items.length}] ${item.relativePath}: ` +
                'review the unsaved candidate. Press Ctrl+S to save, or use Skip / Cancel Review.'
            );
        } catch (error) {
            this.block(error);
        }
    }

    async handleSave(document) {
        if (this.status !== 'active' || !this.currentDocument ||
            !samePath(document.uri?.fsPath, this.currentDocument.uri?.fsPath)) return false;
        const item = this.payload.items[this.currentIndex];
        if (document.isDirty || sha256(this.readFile(item.file)) !== item.desiredSha256) {
            this.block(new Error('Security Fix Edit Review stopped: saved content does not match the verified candidate.'));
            return false;
        }
        this.savedCount += 1;
        this.currentIndex += 1;
        this.currentDocument = null;
        this.status = 'transitioning';
        await this.openCurrent();
        return true;
    }

    async reviewNextDiagnostic() {
        if (this.status !== 'diagnostic-active') return false;
        if (this.diagnosticIndex >= this.payload.diagnostics.length) {
            this.complete();
            return true;
        }
        const item = this.payload.diagnostics[this.diagnosticIndex];
        try {
            if (item.reviewDisposition === 'NO_CHANGE') {
                this.outputChannel?.appendLine?.(
                    `${item.file}:${item.line}:${item.column} ${item.ruleId} (${item.findingId}) - NO_CHANGE: ${item.reason}`
                );
                this.noChangeCount += 1;
                this.diagnosticIndex += 1;
                return this.reviewNextDiagnostic();
            }
            await this.gotoDiagnostic(this.vscode, this.payload.workspaceRoot, item, location => {
                this.currentDiagnostic = item;
                this.reviewUi.setCurrent({
                    sessionId: this.payload.sessionId,
                    item,
                    uri: location.document.uri,
                    languageId: location.document.languageId,
                    range: location.range
                });
            });
            return true;
        } catch (error) {
            this.block(error);
            return false;
        }
    }

    async handleDiagnosticCommand(action, rawArguments) {
        try {
            const args = validateReviewCommandArguments(rawArguments, action);
            const item = this.currentDiagnostic;
            if (this.status !== 'diagnostic-active' || !item ||
                args.sessionId !== this.payload.sessionId || args.findingId !== item.findingId) {
                throw reviewError('STALE_FILE', 'Security Fix review command is stale or belongs to another session.');
            }
            if (action === 'cancel') {
                this.cancel();
                return true;
            }
            if (action === 'showReason') {
                if (item.reviewDisposition === 'MANUAL_ONLY') {
                    await this.vscode.window.showInformationMessage(manualReviewMessage(item), { modal: true });
                } else {
                    await this.vscode.window.showInformationMessage(`${item.ruleId}: ${item.reason}`);
                }
                return true;
            }
            if (action === 'skip') {
                if (item.reviewDisposition === 'MANUAL_ONLY') this.manualOnlyCount += 1;
                else this.candidateReviewedCount += 1;
                this.diagnosticIndex += 1;
                this.currentDiagnostic = null;
                this.reviewUi.clear();
                return this.reviewNextDiagnostic();
            }
            if (item.reviewDisposition !== 'CANDIDATES') {
                throw new Error('Manual-only diagnostics cannot be compared or applied.');
            }
            const candidate = await this.selectDiagnosticCandidate(item, args.candidateId, action);
            if (!candidate) return false;
            if (action === 'compare') {
                await this.showCandidateDiff(this.vscode, item, candidate);
                return true;
            }
            const candidatePayload = diagnosticEditablePayload(item.source, candidate);
            validateDiagnosticCandidatePayload(candidatePayload);
            const diskBefore = sha256(this.readFile(candidatePayload.file));
            const result = await this.applyDiagnosticCandidate(this.vscode, candidatePayload);
            if (!result?.dirty || !result.document?.isDirty ||
                sha256(documentBytes(result.document, candidatePayload.encoding)) !== candidatePayload.desiredSha256) {
                throw new Error('Security Fix diagnostic candidate did not create the exact verified unsaved content.');
            }
            if (sha256(this.readFile(candidatePayload.file)) !== diskBefore) {
                throw new Error('Security Fix diagnostic candidate unexpectedly changed the file on disk.');
            }
            this.candidateReviewedCount += 1;
            this.status = 'diagnostic-applied';
            this.currentDiagnostic = null;
            this.dispose();
            this.vscode.window.showInformationMessage(
                'Security Fix：修正候補を未保存で適用しました。内容を確認し、問題なければ Ctrl + S で保存してください。'
            );
            this.onFinish(this);
            return true;
        } catch (error) {
            this.block(error);
            return false;
        }
    }

    async selectDiagnosticCandidate(item, candidateId, action) {
        if (candidateId !== null) {
            const candidate = item.candidates.find(entry => entry.candidateId === candidateId);
            if (!candidate) throw reviewError('STALE_FILE', 'Security Fix candidate identifier is stale.');
            return candidate;
        }
        if (item.candidates.length === 1) return item.candidates[0];
        const selection = await this.vscode.window.showQuickPick(
            item.candidates.map(candidate => ({
                label: candidate.label,
                description: `${candidate.confidence} confidence${candidate.recommended ? ' - recommended' : ''}`,
                detail: candidate.reason,
                candidateId: candidate.candidateId
            })),
            {
                title: `${action === 'apply' ? 'Apply' : 'Compare'} Security Fix candidate`,
                placeHolder: 'Choose one candidate. The command will revalidate it before use.',
                ignoreFocusOut: true
            }
        );
        return selection
            ? item.candidates.find(candidate => candidate.candidateId === selection.candidateId) ?? null
            : null;
    }

    async requestSkip() {
        if (!['active', 'awaiting-discard'].includes(this.status) || !this.currentDocument) return false;
        this.status = 'awaiting-discard';
        this.vscode.window.showWarningMessage(
            'Skip requested. Close the current tab and choose Don\'t Save. The extension will not save, revert, or close it.'
        );
        return this.tryCompleteSkip();
    }

    async handleClose(document) {
        if (!this.currentDocument || !samePath(document.uri?.fsPath, this.currentDocument.uri?.fsPath)) return false;
        if (this.status !== 'awaiting-discard') {
            this.vscode.window.showWarningMessage(
                'The review tab closed, but it was not marked skipped. Use Skip to continue or Cancel Review.'
            );
            return false;
        }
        return this.tryCompleteSkip();
    }

    async tryCompleteSkip() {
        if (this.status !== 'awaiting-discard' || !this.currentDocument) return false;
        const item = this.payload.items[this.currentIndex];
        const openTab = isFileTabOpen(this.vscode, item.file);
        if (openTab === null) {
            this.block(new Error('Security Fix Edit Review cannot verify that the skipped tab closed.'));
            return false;
        }
        const dirtyDocument = documentForFile(this.vscode, item.file);
        if (openTab || dirtyDocument?.isDirty) return false;
        if (sha256(this.readFile(item.file)) !== item.originalSha256) {
            this.block(new Error('Security Fix Edit Review cannot skip because the original file changed.'));
            return false;
        }
        this.skippedCount += 1;
        this.currentIndex += 1;
        this.currentDocument = null;
        this.status = 'transitioning';
        await this.openCurrent();
        return true;
    }

    cancel(options = {}) {
        if (['cancelled', 'completed', 'blocked'].includes(this.status)) return;
        this.status = 'cancelled';
        this.dispose();
        if (!options.silent) {
            this.vscode.window.showInformationMessage(
                'Security Fix レビューを終了しました。現在のエディターは保存、破棄、または閉じられていません。'
            );
        }
        this.onFinish(this);
    }

    complete() {
        this.status = 'completed';
        this.dispose();
        if (this.payload.diagnostics.length > 0 && this.outputChannel) {
            this.outputChannel.clear();
            this.outputChannel.appendLine('Diagnostic review summary:');
            this.outputChannel.appendLine('');
            for (const item of this.payload.diagnostics) {
                this.outputChannel.appendLine(`${item.file}:${item.line}:${item.column}`);
                this.outputChannel.appendLine(`${item.ruleId} (${item.findingId}) — ${item.reviewDisposition}`);
                this.outputChannel.appendLine('');
            }
            this.outputChannel.show(true);
        }
        this.vscode.window.showInformationMessage(
            'Security Fix：レビューが完了しました。\n確認対象はすべて処理されました。'
        );
        this.onFinish(this);
    }

    block(error) {
        this.failure = error;
        this.status = 'blocked';
        this.dispose();
        this.vscode.window.showErrorMessage(`Security Fix Edit Review stopped: ${error.message}`);
        this.onFinish(this);
    }

    dispose() {
        candidateDocuments.clear();
        this.currentDiagnostic = null;
        if (this.ownsReviewUi) this.reviewUi?.dispose?.();
        else this.reviewUi?.clear?.();
        for (const disposable of [...this.disposables, ...this.controls]) {
            try { disposable?.dispose?.(); } catch {}
        }
        this.disposables = [];
        this.controls = [];
        this.skipControl = null;
    }
}

function activate(context) {
    const vscode = require('vscode');
    reviewOutputChannel = vscode.window.createOutputChannel('WP Builder Security Fix Review');
    reviewUi = new SecurityFixReviewUi(vscode, { outputChannel: reviewOutputChannel });
    const reviewCommand = action => vscode.commands.registerCommand(REVIEW_COMMANDS[action], args =>
        activeReviewSession?.handleDiagnosticCommand(action, args)
    );
    context.subscriptions.push(
        reviewOutputChannel,
        reviewUi,
        vscode.languages.registerCodeLensProvider({ scheme: 'file', language: 'php' }, reviewUi),
        vscode.languages.registerCodeActionsProvider(
            { scheme: 'file', language: 'php' },
            reviewUi,
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        ),
        reviewCommand('compare'),
        reviewCommand('apply'),
        reviewCommand('skip'),
        reviewCommand('cancel'),
        reviewCommand('showReason'),
        vscode.workspace.registerTextDocumentContentProvider(CANDIDATE_DOCUMENT_SCHEME, {
            provideTextDocumentContent(uri) {
                return candidateDocuments.get(uri.toString()) ?? '';
            }
        }),
        vscode.commands.registerCommand(SKIP_COMMAND, () => activeReviewSession?.requestSkip()),
        vscode.commands.registerCommand(CANCEL_COMMAND, () => activeReviewSession?.cancel()),
        vscode.window.registerUriHandler({
            async handleUri(uri) {
                const payloadPath = new URLSearchParams(uri.query).get('payload');
                const cleanupRoot = payloadPath ? requestRootFor(payloadPath) : null;
                let payload = null;
                let reviewRequest = false;
                let ackWritten = false;
                if (!payloadPath) {
                    vscode.window.showErrorMessage('Security Fix edit request is missing its payload path.');
                    return;
                }
                try {
                    payload = readPayload(payloadPath);
                    reviewRequest = payload.kind === 'wp-builder-security-fix-edit-review';
                    assertReviewSessionAvailable(activeReviewSession);
                    if (reviewRequest) {
                        const session = new SecurityFixEditReviewSession(vscode, payload, {
                            outputChannel: reviewOutputChannel,
                            reviewUi,
                            onFinish(finished) {
                                if (activeReviewSession === finished) activeReviewSession = null;
                            }
                        });
                        activeReviewSession = session;
                        try {
                            const snapshot = await session.start();
                            if (!['active', 'diagnostic-active'].includes(snapshot.status)) {
                                throw session.failure ?? reviewError('REVIEW_START_FAILED', 'Security Fix Edit Review did not start.');
                            }
                            writeReviewAck(payloadPath, payload, 'session-started');
                            ackWritten = true;
                        } catch (error) {
                            activeReviewSession = null;
                            session.dispose();
                            throw error;
                        }
                    } else {
                        await applyPayloadToEditor(vscode, payload);
                        vscode.window.showInformationMessage(
                            'Security Fix candidate applied to an unsaved editor. Review it and press Ctrl+S only if approved.'
                        );
                    }
                } catch (error) {
                    if (reviewRequest && payload && !ackWritten) {
                        try {
                            writeReviewAck(payloadPath, payload, 'rejected', reviewRejectionCode(error));
                            ackWritten = true;
                        } catch {
                            // The CLI will fail closed on acknowledgement timeout.
                        }
                    }
                    showReviewRequestError(vscode, error);
                } finally {
                    if (cleanupRoot && !reviewRequest) {
                        try {
                            fs.rmSync(cleanupRoot, { recursive: true, force: true });
                        } catch {
                            // The OS temp directory can clean an inaccessible request later.
                        }
                    }
                }
            }
        })
    );
}

function deactivate() {
    activeReviewSession?.cancel({ silent: true });
    activeReviewSession = null;
    reviewOutputChannel = null;
    reviewUi?.dispose?.();
    reviewUi = null;
    candidateDocuments.clear();
}

module.exports = {
    CANCEL_COMMAND,
    SKIP_COMMAND,
    SecurityFixEditReviewSession,
    activate,
    applyPayloadToEditor,
    assertReviewSessionAvailable,
    assertAutoSaveDisabled,
    deactivate,
    documentBytes,
    manualReviewMessage,
    readPayload,
    requestRootFor,
    showReviewRequestError,
    showDiagnosticCandidateDiff,
    writeReviewAck
};
