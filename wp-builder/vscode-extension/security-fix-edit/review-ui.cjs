'use strict';

const path = require('node:path');

const COMMANDS = Object.freeze({
    compare: 'wp-builder.securityFixReview.compare',
    apply: 'wp-builder.securityFixReview.apply',
    skip: 'wp-builder.securityFixReview.skip',
    cancel: 'wp-builder.securityFixReview.cancel',
    showReason: 'wp-builder.securityFixReview.showReason'
});

const ACTIONS = new Set(Object.keys(COMMANDS));

function samePath(left, right) {
    if (!left || !right) return false;
    const a = path.resolve(left);
    const b = path.resolve(right);
    return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function validateReviewCommandArguments(value, expectedAction = null) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error('Security Fix review command arguments are invalid.');
    }
    const keys = Object.keys(value).sort();
    if (keys.join(',') !== 'action,candidateId,findingId,sessionId') {
        throw new Error('Security Fix review command arguments contain unsupported fields.');
    }
    if (typeof value.sessionId !== 'string' || typeof value.findingId !== 'string' ||
        (value.candidateId !== null && typeof value.candidateId !== 'string') ||
        !ACTIONS.has(value.action) || (expectedAction && value.action !== expectedAction)) {
        throw new Error('Security Fix review command identifiers are invalid.');
    }
    return value;
}

function commandArguments(sessionId, findingId, candidateId, action) {
    return [{ sessionId, findingId, candidateId, action }];
}

class SecurityFixReviewUi {
    constructor(vscode, options = {}) {
        this.vscode = vscode;
        this.outputChannel = options.outputChannel ?? null;
        this.current = null;
        this.emitter = typeof vscode.EventEmitter === 'function' ? new vscode.EventEmitter() : null;
        this.onDidChangeCodeLenses = this.emitter?.event;
        this.diagnostics = vscode.languages?.createDiagnosticCollection?.('wp-builder-security-fix-review') ?? null;
        this.decoration = vscode.window.createTextEditorDecorationType?.({
            isWholeLine: true,
            backgroundColor: new vscode.ThemeColor('editor.wordHighlightBackground')
        }) ?? null;
    }

    setCurrent(current) {
        this.clearVisuals();
        this.current = current;
        this.log([
            '[Security Fix Review UI]',
            'event: set-current',
            `findingId: ${current.item.findingId}`,
            `disposition: ${current.item.reviewDisposition}`,
            `candidateCount: ${current.item.candidates.length}`,
            `languageId: ${current.languageId ?? 'unknown'}`,
            `uriMatchKey: ${current.item.file ?? 'unavailable'}`
        ]);
        const diagnostic = this.createDiagnostic(current);
        if (diagnostic && this.diagnostics) this.diagnostics.set(current.uri, [diagnostic]);
        this.decorate(current);
        this.emitter?.fire?.();
    }

    clear() {
        this.clearVisuals();
        this.current = null;
        this.emitter?.fire?.();
    }

    clearVisuals() {
        this.diagnostics?.clear?.();
        if (this.decoration) {
            for (const editor of this.vscode.window.visibleTextEditors ?? []) {
                editor.setDecorations?.(this.decoration, []);
            }
        }
    }

    createDiagnostic(current) {
        if (typeof this.vscode.Diagnostic !== 'function') return null;
        const diagnostic = new this.vscode.Diagnostic(
            current.range,
            current.item.reviewDisposition === 'MANUAL_ONLY'
                ? `Manual review only: ${current.item.reason}`
                : `Security Fix candidate review: ${current.item.reason}`,
            this.vscode.DiagnosticSeverity?.Information
        );
        diagnostic.source = 'WP Builder Security Fix';
        diagnostic.code = current.item.ruleId;
        return diagnostic;
    }

    decorate(current) {
        if (!this.decoration) return;
        const editor = (this.vscode.window.visibleTextEditors ?? [])
            .find(candidate => samePath(candidate.document?.uri?.fsPath, current.uri.fsPath));
        editor?.setDecorations?.(this.decoration, [current.range]);
    }

    provideCodeLenses(document) {
        const current = this.current;
        const uriMatchesCurrent = Boolean(current && samePath(document.uri?.fsPath, current.uri.fsPath));
        if (!current || !uriMatchesCurrent) {
            this.logCodeLensResult(document, current, uriMatchesCurrent, 0);
            if (current?.item.reviewDisposition === 'CANDIDATES') {
                this.logWarning(uriMatchesCurrent ? 'UNKNOWN' : 'URI_MISMATCH');
            }
            return [];
        }
        const item = current.item;
        const candidate = item.candidates.length === 1 ? item.candidates[0] : null;
        const status = item.reviewDisposition === 'MANUAL_ONLY'
            ? `Security Fix：手動確認が必要 · ${item.ruleId}`
            : candidate
                ? `Security Fix：修正候補あり · ${candidate.confidence}`
                : `Security Fix：修正候補 ${item.candidates.length}件`;
        const lenses = [this.lens(current.range, status, 'showReason', null)];
        if (item.reviewDisposition === 'CANDIDATES') {
            lenses.push(
                this.lens(current.range, candidate ? '【修正前後を比較】' : '【修正前後を比較…】', 'compare', candidate?.candidateId ?? null),
                this.lens(
                    current.range,
                    candidate ? '【修正を適用する】' : '【修正を適用する…】',
                    'apply',
                    candidate?.candidateId ?? null
                )
            );
        } else {
            lenses.push(this.lens(current.range, '【理由を確認】', 'showReason', null));
        }
        lenses.push(
            this.lens(current.range, '【今回はスキップ】', 'skip', null),
            this.lens(current.range, '【レビューを終了】', 'cancel', null)
        );
        this.logCodeLensResult(document, current, uriMatchesCurrent, lenses.length);
        if (item.reviewDisposition === 'CANDIDATES' && lenses.length === 0) this.logWarning('UNKNOWN');
        return lenses;
    }

    logCodeLensResult(document, current, uriMatchesCurrent, lensCount) {
        this.log([
            '[Security Fix Review UI]',
            'event: provide-code-lenses',
            `hasCurrent: ${Boolean(current)}`,
            `languageId: ${document.languageId ?? 'unknown'}`,
            `uriMatchesCurrent: ${uriMatchesCurrent}`,
            `lensCount: ${lensCount}`
        ]);
    }

    logWarning(reason) {
        this.log([
            '[Security Fix Review UI WARNING]',
            'CANDIDATES produced zero CodeLens items.',
            `reason: ${reason}`
        ]);
    }

    log(lines) {
        if (!this.outputChannel?.appendLine) return;
        for (const line of lines) this.outputChannel.appendLine(line);
        this.outputChannel.appendLine('');
    }

    provideCodeActions(document, range) {
        const current = this.current;
        if (!current || !samePath(document.uri?.fsPath, current.uri.fsPath) || !current.range.intersection?.(range)) return [];
        return this.provideCodeLenses(document).slice(1).map(lens => {
            if (typeof this.vscode.CodeAction !== 'function') return { title: lens.command.title, command: lens.command };
            const action = new this.vscode.CodeAction(lens.command.title, this.vscode.CodeActionKind?.QuickFix);
            action.command = { command: lens.command.command, title: lens.command.title, arguments: lens.command.arguments };
            action.isPreferred = false;
            return action;
        });
    }

    lens(range, title, action, candidateId) {
        const args = commandArguments(
            this.current.sessionId,
            this.current.item.findingId,
            candidateId,
            action
        );
        const command = { title, command: COMMANDS[action], arguments: args };
        return typeof this.vscode.CodeLens === 'function' ? new this.vscode.CodeLens(range, command) : { range, command };
    }

    dispose() {
        this.clear();
        this.diagnostics?.dispose?.();
        this.decoration?.dispose?.();
        this.emitter?.dispose?.();
    }
}

module.exports = {
    COMMANDS,
    SecurityFixReviewUi,
    validateReviewCommandArguments
};
