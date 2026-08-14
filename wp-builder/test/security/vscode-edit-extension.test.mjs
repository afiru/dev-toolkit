import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

const require = createRequire(import.meta.url);
const {
    diagnosticEditablePayload,
    prepareEdits,
    sha256,
    validateDiagnosticCandidate,
    validatePayload,
    validateReviewPayload
} = require(
    '../../vscode-extension/security-fix-edit/edit-core.cjs'
);
const {
    applyPayloadToEditor,
    assertReviewSessionAvailable,
    manualReviewMessage,
    SecurityFixEditReviewSession,
    showDiagnosticCandidateDiff,
    showReviewRequestError
} = require(
    '../../vscode-extension/security-fix-edit/extension.cjs'
);
const { requestRootFor, writeReviewAck } = require('../../vscode-extension/security-fix-edit/extension.cjs');
const {
    COMMANDS,
    SecurityFixReviewUi,
    validateReviewCommandArguments
} = require('../../vscode-extension/security-fix-edit/review-ui.cjs');

function payloadFor(file, bytes, stat, overrides = {}) {
    return {
        schemaVersion: 1,
        kind: 'wp-builder-security-fix-edit',
        workspaceRoot: path.dirname(file),
        file,
        originalSha256: sha256(bytes),
        originalSize: bytes.length,
        originalIdentity: {
            dev: stat.dev.toString(),
            ino: stat.ino.toString(),
            nlink: stat.nlink.toString()
        },
        encoding: { charset: 'utf-8', bom: false },
        edits: [{
            findingId: 'finding-1',
            startByte: 1,
            endByte: 2,
            originalSha256: sha256(bytes.subarray(1, 2)),
            replacement: 'B',
            location: { line: 1, column: 2 }
        }],
        ...overrides
    };
}

test('extension core allows hash-matched clean documents and rejects stale content', t => {
    const root = createTempWorkspace(t, 'vscode-edit-core');
    const file = writeTempFile(root, 'case.php', 'abc');
    const bytes = fs.readFileSync(file);
    const stat = fs.lstatSync(file, { bigint: true });
    const payload = payloadFor(file, bytes, stat);
    const identity = {
        dev: stat.dev.toString(),
        ino: stat.ino.toString(),
        nlink: stat.nlink.toString(),
        isFile: true,
        isSymbolicLink: false
    };

    const edits = prepareEdits({
        payload,
        currentBytes: bytes,
        currentIdentity: identity,
        documentText: 'abc',
        documentIsDirty: false
    });
    assert.deepEqual(edits.map(edit => [edit.startOffset, edit.endOffset, edit.replacement]), [[1, 2, 'B']]);
    assert.throws(
        () => prepareEdits({
            payload,
            currentBytes: Buffer.from('axc'),
            currentIdentity: identity,
            documentText: 'axc',
            documentIsDirty: false
        }),
        error => error.code === 'STALE_FILE'
    );
});

test('extension core rejects invalid schema, diagnostic-only payload, dirty editor, and workspace escape', t => {
    const root = createTempWorkspace(t, 'vscode-edit-reject');
    const file = writeTempFile(root, 'case.php', 'abc');
    const bytes = fs.readFileSync(file);
    const stat = fs.lstatSync(file, { bigint: true });
    const payload = payloadFor(file, bytes, stat);

    assert.throws(() => validatePayload({ ...payload, schemaVersion: 2 }), error => error.code === 'INVALID_SCHEMA');
    assert.throws(() => validatePayload({ ...payload, edits: [] }), error => error.code === 'INVALID_EDITS');
    assert.throws(
        () => validatePayload({ ...payload, workspaceRoot: path.join(root, 'other') }),
        error => error.code === 'OUTSIDE_WORKSPACE'
    );
    assert.throws(
        () => prepareEdits({
            payload,
            currentBytes: bytes,
            currentIdentity: {
                dev: stat.dev.toString(),
                ino: stat.ino.toString(),
                nlink: stat.nlink.toString(),
                isFile: true,
                isSymbolicLink: false
            },
            documentText: 'abc',
            documentIsDirty: true
        }),
        error => error.code === 'DOCUMENT_DIRTY'
    );
});

test('extension cleanup accepts only owned request directories in OS temp', () => {
    const ownedRoot = path.join(
        path.resolve(os.tmpdir()),
        'wp-builder-security-edit-example'
    );
    assert.equal(requestRootFor(path.join(ownedRoot, 'edit-request.json')), ownedRoot);
    assert.equal(requestRootFor(path.join(path.dirname(ownedRoot), 'unowned', 'edit-request.json')), null);
    assert.equal(requestRootFor(path.join(ownedRoot, 'other.json')), null);
});

test('extension writes a fixed-schema directory review acknowledgement atomically', t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-builder-security-edit-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const payloadPath = path.join(root, 'edit-request.json');
    fs.writeFileSync(payloadPath, '{}');
    const payload = {
        kind: 'wp-builder-security-fix-edit-review',
        sessionId: '00000000-0000-4000-8000-000000000001',
        ackToken: 'a'.repeat(64)
    };

    writeReviewAck(payloadPath, payload, 'session-started');
    const ack = JSON.parse(fs.readFileSync(path.join(root, 'edit-ack.json'), 'utf8'));
    assert.deepEqual(ack, {
        schemaVersion: 1,
        kind: 'wp-builder-security-fix-edit-review-ack',
        sessionId: payload.sessionId,
        ackToken: payload.ackToken,
        status: 'session-started',
        code: null
    });
    assert.equal(fs.existsSync(path.join(root, 'edit-ack.tmp')), false);
});

test('duplicate directory review is rejected without changing the active session', async () => {
    const activeSession = {
        status: 'diagnostic-active',
        currentDiagnostic: { findingId: 'finding-current' },
        diagnosticIndex: 3,
        currentDocument: {
            isDirty: true,
            save() { saveCalls += 1; },
            close() { closeCalls += 1; },
            revert() { revertCalls += 1; }
        }
    };
    const currentDiagnostic = activeSession.currentDiagnostic;
    const currentDocument = activeSession.currentDocument;
    let workspaceEditCalls = 0;
    let saveCalls = 0;
    let closeCalls = 0;
    let revertCalls = 0;
    let notification = null;

    let rejection;
    try {
        assertReviewSessionAvailable(activeSession);
    } catch (error) {
        rejection = error;
    }

    assert.equal(rejection.code, 'REVIEW_SESSION_ALREADY_ACTIVE');
    assert.notEqual(rejection.code, 'TARGET_EDITOR_DIRTY');
    await showReviewRequestError({
        window: {
            showErrorMessage(message) {
                notification = message;
            }
        },
        workspace: {
            applyEdit() { workspaceEditCalls += 1; }
        }
    }, rejection);

    assert.equal(notification,
        'Security Fix：すでにレビューが進行中です。\n現在のレビューを終了してから、もう一度実行してください。');
    assert.doesNotMatch(notification, /レビューが完了しました/);
    assert.equal(activeSession.status, 'diagnostic-active');
    assert.equal(activeSession.currentDiagnostic, currentDiagnostic);
    assert.equal(activeSession.diagnosticIndex, 3);
    assert.equal(activeSession.currentDocument, currentDocument);
    assert.equal(activeSession.currentDocument.isDirty, true);
    assert.equal(workspaceEditCalls, 0);
    assert.equal(saveCalls, 0);
    assert.equal(closeCalls, 0);
    assert.equal(revertCalls, 0);
});

test('extension applies WorkspaceEdit without calling document.save', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-apply');
    const file = writeTempFile(root, 'case.php', 'abc');
    const bytes = fs.readFileSync(file);
    const stat = fs.lstatSync(file, { bigint: true });
    const payload = payloadFor(file, bytes, stat);
    let saveCalls = 0;
    const document = {
        uri: { fsPath: file },
        isDirty: false,
        getText: () => 'abc',
        positionAt: offset => offset,
        async save() {
            saveCalls += 1;
            return true;
        }
    };
    const appliedEdits = [];
    class WorkspaceEdit {
        replace(uri, range, replacement) {
            appliedEdits.push({ uri, range, replacement });
        }
    }
    class Range {
        constructor(start, end) {
            this.start = start;
            this.end = end;
        }
    }
    class Selection extends Range {}
    const vscode = {
        Uri: { file: filePath => ({ fsPath: filePath }) },
        WorkspaceEdit,
        Range,
        Selection,
        workspace: {
            getWorkspaceFolder() { return { uri: { fsPath: root } }; },
            getConfiguration() { return { get() { return 'off'; } }; },
            async openTextDocument() { return document; },
            async applyEdit() {
                document.isDirty = true;
                return true;
            }
        },
        window: {
            async showTextDocument() {
                return { selection: null, revealRange() {} };
            }
        }
    };

    const result = await applyPayloadToEditor(vscode, payload);
    assert.equal(result.applied, true);
    assert.equal(document.isDirty, true);
    assert.equal(saveCalls, 0);
    assert.deepEqual(appliedEdits.map(edit => [edit.range.start, edit.range.end, edit.replacement]), [[1, 2, 'B']]);
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
});

test('extension refuses Auto Save before applying an edit', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-autosave');
    const file = writeTempFile(root, 'case.php', 'abc');
    const bytes = fs.readFileSync(file);
    const stat = fs.lstatSync(file, { bigint: true });
    const payload = payloadFor(file, bytes, stat);
    let opened = false;
    const vscode = {
        Uri: { file: filePath => ({ fsPath: filePath }) },
        workspace: {
            getWorkspaceFolder() { return { uri: { fsPath: root } }; },
            getConfiguration() { return { get() { return 'afterDelay'; } }; },
            async openTextDocument() { opened = true; }
        }
    };

    await assert.rejects(applyPayloadToEditor(vscode, payload), /files\.autoSave to be off/);
    assert.equal(opened, false);
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
});

test('extension rejects a target outside every open VS Code workspace', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-no-workspace');
    const file = writeTempFile(root, 'case.php', 'abc');
    const bytes = fs.readFileSync(file);
    const stat = fs.lstatSync(file, { bigint: true });
    const payload = payloadFor(file, bytes, stat);
    const vscode = {
        Uri: { file: filePath => ({ fsPath: filePath }) },
        workspace: {
            getWorkspaceFolder() { return undefined; }
        }
    };

    await assert.rejects(
        applyPayloadToEditor(vscode, payload),
        /not inside an open VS Code workspace/
    );
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
});

function reviewPayload(root, files, diagnostics = []) {
    return {
        schemaVersion: 1,
        kind: 'wp-builder-security-fix-edit-review',
        sessionId: '00000000-0000-4000-8000-000000000001',
        ackToken: 'a'.repeat(64),
        workspaceRoot: root,
        items: files.map(({ file, original, desired }, index) => {
            const bytes = Buffer.from(original);
            const stat = fs.lstatSync(file, { bigint: true });
            return {
                ...payloadFor(file, bytes, stat, {
                    desiredSha256: sha256(Buffer.from(desired)),
                    edits: [{
                        findingId: `finding-${index + 1}`,
                        startByte: 1,
                        endByte: 2,
                        originalSha256: sha256(bytes.subarray(1, 2)),
                        replacement: desired[1],
                        location: { line: 1, column: 2 }
                    }]
                }),
                relativePath: path.basename(file),
                firstLocation: { line: 1, column: 2 }
            };
        }),
        diagnostics
    };
}

function diagnosticReviewItem(root, file, original, replacement, disposition = 'CANDIDATES') {
    const bytes = Buffer.from(original);
    const stat = fs.lstatSync(file, { bigint: true });
    const startByte = original.indexOf('b');
    const desired = `${original.slice(0, startByte)}${replacement}${original.slice(startByte + 1)}`;
    const candidate = {
        schemaVersion: 1,
        candidateId: 'finding-1-candidate-01',
        findingId: 'finding-1',
        label: 'Candidate escape',
        confidence: 'MEDIUM',
        recommended: true,
        reason: 'Known direct output context.',
        edits: [{
            startByte,
            endByte: startByte + 1,
            originalSha256: sha256(bytes.subarray(startByte, startByte + 1)),
            replacement
        }],
        desiredSha256: sha256(Buffer.from(desired)),
        lint: { available: true, passed: true, exitCode: 0 }
    };
    return {
        file: path.basename(file),
        line: 1,
        column: 2,
        findingId: 'finding-1',
        ruleId: 'WPB-SCF-ARGUMENT-UNSUPPORTED',
        reviewDisposition: disposition,
        reason: 'Known direct output context.',
        source: disposition === 'CANDIDATES' ? {
            workspaceRoot: root,
            file,
            originalSha256: sha256(bytes),
            originalSize: bytes.length,
            originalIdentity: {
                dev: stat.dev.toString(),
                ino: stat.ino.toString(),
                nlink: stat.nlink.toString()
            },
            encoding: { charset: 'utf-8', bom: false }
        } : null,
        candidates: disposition === 'CANDIDATES' ? [candidate] : []
    };
}

function reviewVscode(root, documents, tabs, autoSave = 'off') {
    const disposable = () => ({ dispose() {} });
    const statusBarItems = [];
    const informationMessages = [];
    const informationMessageCalls = [];
    class Position {
        constructor(line, character) { this.line = line; this.character = character; }
    }
    class Range {
        constructor(start, end) { this.start = start; this.end = end; }
        intersection() { return this; }
    }
    const vscode = {
        Uri: { file: filePath => ({ fsPath: filePath, toString: () => `file:${filePath}` }) },
        Position,
        Range,
        Selection: class Selection extends Range {},
        StatusBarAlignment: { Left: 1 },
        workspace: {
            textDocuments: documents,
            getWorkspaceFolder() { return { uri: { fsPath: root } }; },
            getConfiguration() { return { get() { return autoSave; } }; },
            async openTextDocument(uri) {
                let document = documents.find(entry => entry.uri?.fsPath === uri.fsPath);
                if (!document) {
                    document = {
                        uri,
                        languageId: 'php',
                        isDirty: false,
                        getText: () => fs.readFileSync(uri.fsPath, 'utf8'),
                        positionAt(offset) { return new Position(0, offset); }
                    };
                    documents.push(document);
                }
                return document;
            },
            onDidSaveTextDocument() { return disposable(); },
            onDidCloseTextDocument() { return disposable(); }
        },
        window: {
            tabGroups: {
                all: [{ tabs }],
                onDidChangeTabs() { return disposable(); }
            },
            createStatusBarItem() {
                const item = {
                    visible: false,
                    show() { this.visible = true; },
                    hide() { this.visible = false; },
                    dispose() { this.visible = false; }
                };
                statusBarItems.push(item);
                return item;
            },
            async showTextDocument(document) {
                return { document, selection: null, revealRange() {} };
            },
            showInformationMessage(message, ...args) {
                informationMessages.push(message);
                informationMessageCalls.push({ message, args });
            },
            showWarningMessage() {},
            showErrorMessage() {}
        }
    };
    vscode.__statusBarItems = statusBarItems;
    vscode.__informationMessages = informationMessages;
    vscode.__informationMessageCalls = informationMessageCalls;
    return vscode;
}

test('status bar Skip is visible for AUTO_FIXABLE and hidden after transition to DIAGNOSTIC', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-status-phase');
    const autoFile = writeTempFile(root, 'auto.php', 'abc');
    const diagnosticFile = writeTempFile(root, 'diagnostic.php', 'abc');
    const diagnostic = diagnosticReviewItem(root, diagnosticFile, 'abc', 'B', 'MANUAL_ONLY');
    const payload = reviewPayload(root, [{ file: autoFile, original: 'abc', desired: 'aBc' }], [diagnostic]);
    const documents = [];
    const tabs = [];
    const vscode = reviewVscode(root, documents, tabs);
    const session = new SecurityFixEditReviewSession(vscode, payload, {
        reviewUi: { setCurrent() {}, clear() {} },
        async applyItem(_vscode, item) {
            const document = { uri: { fsPath: item.file }, isDirty: true };
            documents.push(document);
            tabs.push({ input: { uri: document.uri } });
            return { document };
        }
    });

    await session.start();
    const statusSkip = vscode.__statusBarItems.find(item => item.text?.includes('Security Fix：今回はスキップ'));
    const statusCancel = vscode.__statusBarItems.find(item => item.text?.includes('Security Fix レビューを終了'));
    assert.equal(statusSkip.visible, true);
    assert.equal(statusCancel.visible, true);

    fs.writeFileSync(autoFile, 'aBc');
    documents[0].isDirty = false;
    await session.handleSave(documents[0]);
    assert.equal(session.status, 'diagnostic-active');
    assert.equal(statusSkip.visible, false);
    assert.equal(statusCancel.visible, true);
    session.cancel();
    assert.equal(statusCancel.visible, false);
});

test('diagnostic-only review never shows status bar Skip and keeps global Cancel visible', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-status-diagnostic');
    const file = writeTempFile(root, 'manual.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B', 'MANUAL_ONLY');
    const vscode = reviewVscode(root, [], []);
    const session = new SecurityFixEditReviewSession(vscode, reviewPayload(root, [], [item]), {
        reviewUi: { setCurrent() {}, clear() {} }
    });

    await session.start();
    const statusSkip = vscode.__statusBarItems.find(entry => entry.text?.includes('Security Fix：今回はスキップ'));
    const statusCancel = vscode.__statusBarItems.find(entry => entry.text?.includes('Security Fix レビューを終了'));
    assert.equal(statusSkip.visible, false);
    assert.equal(statusCancel.visible, true);
    session.cancel();
});

test('diagnostic current is installed before showTextDocument requests the final CANDIDATES CodeLens', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-diagnostic-timing');
    const file = writeTempFile(root, '099_test.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    const vscode = reviewVscode(root, [], []);
    const reviewUi = new SecurityFixReviewUi(vscode);
    const events = [];
    const originalSetCurrent = reviewUi.setCurrent.bind(reviewUi);
    reviewUi.setCurrent = current => {
        events.push('set-current');
        originalSetCurrent(current);
    };
    let observedCurrent = false;
    let lensCount = 0;
    vscode.window.showTextDocument = async document => {
        events.push('show-text-document');
        observedCurrent = reviewUi.current !== null;
        lensCount = reviewUi.provideCodeLenses(document).length;
        return { document, selection: null, revealRange() {} };
    };
    const session = new SecurityFixEditReviewSession(
        vscode,
        reviewPayload(root, [], [item]),
        { reviewUi }
    );

    await session.start();

    assert.deepEqual(events, ['set-current', 'show-text-document']);
    assert.equal(observedCurrent, true);
    assert.equal(lensCount, 5);
    assert.equal(session.status, 'diagnostic-active');
    assert.equal(session.diagnosticIndex, 0);
    assert.equal(session.currentDiagnostic, item);
    assert.equal(reviewUi.current.item, item);
    session.cancel();
});

test('diagnostic showTextDocument failure clears prepared current state and blocks', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-diagnostic-show-failure');
    const file = writeTempFile(root, '099_test.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    const vscode = reviewVscode(root, [], []);
    const reviewUi = new SecurityFixReviewUi(vscode);
    vscode.window.showTextDocument = async () => {
        throw new Error('show failed');
    };
    const session = new SecurityFixEditReviewSession(
        vscode,
        reviewPayload(root, [], [item]),
        { reviewUi }
    );

    await session.start();

    assert.equal(session.status, 'blocked');
    assert.equal(session.currentDiagnostic, null);
    assert.equal(reviewUi.current, null);
    assert.match(session.failure.message, /show failed/);
});

test('directory review saves by event plus desired hash and keeps only one review document dirty', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-review-save');
    const firstFile = writeTempFile(root, 'a.php', 'abc');
    const secondFile = writeTempFile(root, 'b.php', 'def');
    const documents = [];
    const tabs = [];
    const payload = reviewPayload(root, [
        { file: firstFile, original: 'abc', desired: 'aBc' },
        { file: secondFile, original: 'def', desired: 'dEf' }
    ]);
    const vscode = reviewVscode(root, documents, tabs);
    let saveCalls = 0;
    const applyItem = async (_vscode, item) => {
        const document = {
            uri: { fsPath: item.file },
            isDirty: true,
            async save() { saveCalls += 1; }
        };
        documents.push(document);
        tabs.splice(0, tabs.length, { input: { uri: document.uri } });
        return { document };
    };
    const session = new SecurityFixEditReviewSession(vscode, payload, { applyItem });

    await session.start();
    assert.equal(documents.filter(document => document.isDirty).length, 1);
    fs.writeFileSync(firstFile, 'aBc');
    documents[0].isDirty = false;
    assert.equal(await session.handleSave(documents[0]), true);
    assert.equal(session.savedCount, 1);
    assert.equal(documents.filter(document => document.isDirty).length, 1);

    fs.writeFileSync(secondFile, 'dEf');
    documents[1].isDirty = false;
    assert.equal(await session.handleSave(documents[1]), true);
    assert.equal(session.status, 'completed');
    assert.equal(session.savedCount, 2);
    assert.equal(saveCalls, 0);
});

test('directory review does not infer skip from close and requires explicit skip plus unchanged disk and closed tab', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-review-skip');
    const firstFile = writeTempFile(root, 'a.php', 'abc');
    const secondFile = writeTempFile(root, 'b.php', 'def');
    const documents = [];
    const tabs = [];
    const payload = reviewPayload(root, [
        { file: firstFile, original: 'abc', desired: 'aBc' },
        { file: secondFile, original: 'def', desired: 'dEf' }
    ]);
    const vscode = reviewVscode(root, documents, tabs);
    const applyItem = async (_vscode, item) => {
        const document = { uri: { fsPath: item.file }, isDirty: true };
        documents.push(document);
        tabs.splice(0, tabs.length, { input: { uri: document.uri } });
        return { document };
    };
    const session = new SecurityFixEditReviewSession(vscode, payload, { applyItem });

    await session.start();
    assert.equal(await session.handleClose(documents[0]), false);
    assert.equal(session.currentIndex, 0);
    assert.equal(await session.requestSkip(), false);
    documents[0].isDirty = false;
    documents.splice(0, 1);
    assert.equal(await session.tryCompleteSkip(), false);
    assert.equal(session.currentIndex, 0);
    tabs.splice(0, tabs.length);
    assert.equal(await session.tryCompleteSkip(), true);
    assert.equal(session.skippedCount, 1);
    assert.equal(session.currentIndex, 1);
    assert.equal(documents.filter(document => document.isDirty).length, 1);
});

test('directory review blocks when a save event does not match the desired SHA-256', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-review-save-mismatch');
    const file = writeTempFile(root, 'a.php', 'abc');
    const payload = reviewPayload(root, [{ file, original: 'abc', desired: 'aBc' }]);
    const documents = [];
    const tabs = [];
    const session = new SecurityFixEditReviewSession(reviewVscode(root, documents, tabs), payload, {
        async applyItem(_vscode, item) {
            const document = { uri: { fsPath: item.file }, isDirty: true };
            documents.push(document);
            tabs.push({ input: { uri: document.uri } });
            return { document };
        }
    });

    await session.start();
    fs.writeFileSync(file, 'user-change');
    documents[0].isDirty = false;
    assert.equal(await session.handleSave(documents[0]), false);
    assert.equal(session.status, 'blocked');
    assert.equal(session.savedCount, 0);
});

test('directory review rejects Auto Save and cancel leaves the current dirty buffer untouched', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-review-cancel');
    const file = writeTempFile(root, 'a.php', 'abc');
    const payload = reviewPayload(root, [{ file, original: 'abc', desired: 'aBc' }]);
    let applied = false;
    const autoSaveSession = new SecurityFixEditReviewSession(
        reviewVscode(root, [], [], 'afterDelay'),
        payload,
        { applyItem: async () => { applied = true; } }
    );
    await assert.rejects(autoSaveSession.start(), /files\.autoSave to be off/);
    assert.equal(applied, false);

    const documents = [];
    const tabs = [];
    const document = { uri: { fsPath: file }, isDirty: true, saveCalls: 0, closeCalls: 0, revertCalls: 0 };
    const session = new SecurityFixEditReviewSession(reviewVscode(root, documents, tabs), payload, {
        async applyItem() {
            documents.push(document);
            tabs.push({ input: { uri: document.uri } });
            return { document };
        }
    });
    await session.start();
    session.cancel();
    assert.equal(session.status, 'cancelled');
    assert.equal(document.isDirty, true);
    assert.equal(document.saveCalls, 0);
    assert.equal(document.closeCalls, 0);
    assert.equal(document.revertCalls, 0);
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
});

test('directory review rejects an existing dirty target with TARGET_EDITOR_DIRTY', async t => {
    const root = createTempWorkspace(t, 'vscode-edit-review-dirty');
    const file = writeTempFile(root, 'a.php', 'abc');
    const documents = [{ uri: { fsPath: file }, isDirty: true }];
    const tabs = [];
    const payload = reviewPayload(root, [{ file, original: 'abc', desired: 'aBc' }]);
    const session = new SecurityFixEditReviewSession(reviewVscode(root, documents, tabs), payload);

    await assert.rejects(
        session.start(),
        error => error.code === 'TARGET_EDITOR_DIRTY'
    );
    assert.equal(session.status, 'created');
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
});

test('directory review schema rejects invalid or duplicate items', t => {
    const root = createTempWorkspace(t, 'vscode-edit-review-schema');
    const file = writeTempFile(root, 'a.php', 'abc');
    const payload = reviewPayload(root, [{ file, original: 'abc', desired: 'aBc' }]);
    assert.throws(
        () => validateReviewPayload({ ...payload, items: [...payload.items, payload.items[0]] }),
        error => error.code === 'INVALID_SESSION'
    );
    assert.throws(
        () => validateReviewPayload({ ...payload, diagnostics: [{ file: '../outside.php' }] }),
        error => error.code === 'INVALID_SESSION'
    );
});

test('diagnostic candidate schema rejects arbitrary fields and overlapping edits', t => {
    const root = createTempWorkspace(t, 'vscode-diagnostic-schema');
    const file = writeTempFile(root, 'case.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    const candidate = item.candidates[0];
    assert.throws(
        () => validateDiagnosticCandidate({ ...candidate, command: 'anything' }),
        error => error.code === 'INVALID_CANDIDATE'
    );

    const overlappingCandidate = {
        ...candidate,
        edits: [candidate.edits[0], { ...candidate.edits[0], startByte: 1, endByte: 3 }]
    };
    assert.throws(
        () => validateDiagnosticCandidate(overlappingCandidate),
        error => error.code === 'INVALID_CANDIDATE'
    );
    const review = reviewPayload(root, [], [{ ...item, command: 'anything' }]);
    assert.throws(() => validateReviewPayload(review), error => error.code === 'INVALID_SESSION');
});

test('diagnostic candidate rejects stale source before preview or apply', t => {
    const root = createTempWorkspace(t, 'vscode-diagnostic-stale');
    const file = writeTempFile(root, 'case.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    const payload = diagnosticEditablePayload(item.source, item.candidates[0]);
    const stat = fs.lstatSync(file, { bigint: true });
    assert.throws(
        () => prepareEdits({
            payload,
            currentBytes: Buffer.from('axc'),
            currentIdentity: {
                dev: stat.dev.toString(), ino: stat.ino.toString(), nlink: stat.nlink.toString(),
                isFile: true, isSymbolicLink: false
            },
            documentText: 'axc',
            documentIsDirty: false
        }),
        error => error.code === 'STALE_FILE'
    );
});

test('diagnostic CodeLens Compare opens comparison without editing', async t => {
    const root = createTempWorkspace(t, 'vscode-diagnostic-preview');
    const file = writeTempFile(root, 'case.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    const payload = reviewPayload(root, [], [item]);
    const vscode = reviewVscode(root, [], []);
    let diffCount = 0;
    let applyCount = 0;
    const reviewUi = { current: null, setCurrent(value) { this.current = value; }, clear() {} };
    const session = new SecurityFixEditReviewSession(vscode, payload, {
        reviewUi,
        async showCandidateDiff(_vscode, diagnostic, candidate) {
            diffCount += 1;
            return { payload: diagnosticEditablePayload(diagnostic.source, candidate) };
        },
        async applyDiagnosticCandidate() {
            applyCount += 1;
            return { dirty: true };
        }
    });

    await session.start();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(reviewUi.current.item.findingId, item.findingId);
    await session.handleDiagnosticCommand('compare', {
        sessionId: payload.sessionId,
        findingId: item.findingId,
        candidateId: item.candidates[0].candidateId,
        action: 'compare'
    });
    assert.equal(diffCount, 1);
    assert.equal(applyCount, 0);
    assert.equal(session.status, 'diagnostic-active');
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
});

test('diagnostic comparison uses a virtual document and does not call WorkspaceEdit', async t => {
    const root = createTempWorkspace(t, 'vscode-diagnostic-virtual-diff');
    const file = writeTempFile(root, 'case.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    const commands = [];
    let applyCount = 0;
    const document = { uri: { fsPath: file }, isDirty: false, getText: () => 'abc' };
    const vscode = {
        Uri: {
            file: filePath => ({ fsPath: filePath, toString: () => `file:${filePath}` }),
            parse: value => ({ toString: () => value })
        },
        workspace: {
            getWorkspaceFolder() { return { uri: { fsPath: root } }; },
            getConfiguration() { return { get() { return 'off'; } }; },
            async openTextDocument() { return document; },
            async applyEdit() { applyCount += 1; return true; }
        },
        commands: {
            async executeCommand(...args) { commands.push(args); }
        }
    };

    const result = await showDiagnosticCandidateDiff(vscode, item, item.candidates[0]);
    assert.equal(result.payload.kind, 'wp-builder-security-fix-diagnostic-candidate');
    assert.equal(commands.length, 1);
    assert.equal(commands[0][0], 'vscode.diff');
    assert.match(commands[0][2].toString(), /^wp-builder-security-fix-candidate:/);
    assert.equal(applyCount, 0);
    assert.equal(document.isDirty, false);
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
});

test('diagnostic CodeLens Apply becomes dirty only after independent explicit apply', async t => {
    const root = createTempWorkspace(t, 'vscode-diagnostic-apply');
    const file = writeTempFile(root, 'case.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    const payload = reviewPayload(root, [], [item]);
    const vscode = reviewVscode(root, [], []);
    const reviewUi = { setCurrent() {}, clear() {} };
    let appliedPayload = null;
    const session = new SecurityFixEditReviewSession(vscode, payload, {
        reviewUi,
        async applyDiagnosticCandidate(_vscode, candidatePayload) {
            appliedPayload = candidatePayload;
            return {
                dirty: true,
                document: { isDirty: true, getText: () => 'aBc' }
            };
        }
    });

    await session.start();
    await new Promise(resolve => setImmediate(resolve));
    await session.handleDiagnosticCommand('apply', {
        sessionId: payload.sessionId,
        findingId: item.findingId,
        candidateId: item.candidates[0].candidateId,
        action: 'apply'
    });
    assert.equal(appliedPayload.kind, 'wp-builder-security-fix-diagnostic-candidate');
    assert.equal(session.status, 'diagnostic-applied');
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
    assert.ok(vscode.__informationMessages.includes(
        'Security Fix：修正候補を未保存で適用しました。内容を確認し、問題なければ Ctrl + S で保存してください。'
    ));
    assert.equal(vscode.__informationMessages.some(message => message.includes('レビューが完了しました')), false);
});

test('NO_CHANGE diagnostic advances without WorkspaceEdit', async t => {
    const root = createTempWorkspace(t, 'vscode-diagnostic-no-change');
    const file = writeTempFile(root, 'case.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B', 'NO_CHANGE');
    const payload = reviewPayload(root, [], [item]);
    const vscode = reviewVscode(root, [], []);
    vscode.window.showInformationMessage = async () => 'Continue';
    let applyCount = 0;
    const session = new SecurityFixEditReviewSession(vscode, payload, {
        async applyDiagnosticCandidate() { applyCount += 1; }
    });

    await session.start();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(session.status, 'completed');
    assert.equal(session.noChangeCount, 1);
    assert.equal(applyCount, 0);
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
});

function codeLensVscode() {
    class EventEmitter {
        constructor() { this.event = () => ({ dispose() {} }); this.fireCount = 0; }
        fire() { this.fireCount += 1; }
        dispose() {}
    }
    class CodeLens {
        constructor(range, command) { this.range = range; this.command = command; }
    }
    class CodeAction {
        constructor(title, kind) { this.title = title; this.kind = kind; }
    }
    return {
        EventEmitter,
        CodeLens,
        CodeAction,
        CodeActionKind: { QuickFix: 'quickfix' },
        window: { visibleTextEditors: [] }
    };
}

test('CodeLens exposes only the current finding and command arguments contain identifiers only', t => {
    const vscode = codeLensVscode();
    const ui = new SecurityFixReviewUi(vscode);
    const item = {
        findingId: 'finding-1',
        ruleId: 'WPB-SCF-ARGUMENT-UNSUPPORTED',
        reviewDisposition: 'CANDIDATES',
        reason: 'Review required.',
        candidates: [{ candidateId: 'candidate-1', label: 'esc_html()', confidence: 'MEDIUM', recommended: true }]
    };
    const range = { intersection() { return this; } };
    ui.setCurrent({ sessionId: 'session-1', item, uri: { fsPath: 'C:\\work\\a.php' }, range });

    const lenses = ui.provideCodeLenses({ uri: { fsPath: 'C:\\work\\a.php' } });
    assert.deepEqual(lenses.map(lens => lens.command.title), [
        'Security Fix：修正候補あり · MEDIUM',
        '【修正前後を比較】', '【修正を適用する】', '【今回はスキップ】', '【レビューを終了】'
    ]);
    assert.ok(lenses.every(lens => lens.range === range));
    assert.ok(ui.emitter.fireCount >= 1);
    for (const lens of lenses) {
        const [args] = lens.command.arguments;
        assert.deepEqual(Object.keys(args).sort(), ['action', 'candidateId', 'findingId', 'sessionId']);
        assert.equal('file' in args, false);
        assert.equal('edits' in args, false);
    }
    assert.deepEqual(COMMANDS, {
        compare: 'wp-builder.securityFixReview.compare',
        apply: 'wp-builder.securityFixReview.apply',
        skip: 'wp-builder.securityFixReview.skip',
        cancel: 'wp-builder.securityFixReview.cancel',
        showReason: 'wp-builder.securityFixReview.showReason'
    });
    assert.deepEqual(ui.provideCodeLenses({ uri: { fsPath: 'C:\\work\\b.php' } }), []);

    const actions = ui.provideCodeActions({ uri: { fsPath: 'C:\\work\\a.php' } }, range);
    assert.ok(actions.length > 0);
    assert.ok(actions.every(action => action.edit === undefined && action.command));
    ui.dispose();
});

test('CodeLens diagnostics log only safe CANDIDATES and MANUAL_ONLY state', t => {
    const vscode = codeLensVscode();
    const lines = [];
    const ui = new SecurityFixReviewUi(vscode, {
        outputChannel: { appendLine(line) { lines.push(line); } }
    });
    const range = { intersection() { return this; } };
    const candidateItem = {
        file: 'include/099_test.php',
        findingId: 'finding-1',
        ruleId: 'WPB-SCF-ARGUMENT-UNSUPPORTED',
        reviewDisposition: 'CANDIDATES',
        reason: 'RAW_SOURCE_MARKER',
        candidates: [{
            candidateId: 'candidate-1',
            label: 'esc_html()',
            confidence: 'MEDIUM',
            recommended: true,
            replacement: 'RAW_REPLACEMENT_MARKER'
        }]
    };
    ui.setCurrent({
        sessionId: 'session-1',
        item: candidateItem,
        uri: { fsPath: 'C:\\private\\workspace\\include\\099_test.php' },
        languageId: 'php',
        range
    });
    const matching = ui.provideCodeLenses({
        uri: { fsPath: 'C:\\private\\workspace\\include\\099_test.php' },
        languageId: 'php'
    });
    assert.equal(matching.length, 5);
    ui.provideCodeLenses({
        uri: { fsPath: 'C:\\private\\workspace\\include\\other.php' },
        languageId: 'php'
    });
    ui.setCurrent({
        sessionId: 'session-1',
        item: {
            file: 'include/manual.php',
            findingId: 'finding-2',
            ruleId: 'WPB-SCF-CONTEXT-UNKNOWN',
            reviewDisposition: 'MANUAL_ONLY',
            reason: 'Manual review.',
            candidates: []
        },
        uri: { fsPath: 'C:\\private\\workspace\\include\\manual.php' },
        languageId: 'php',
        range
    });

    const log = lines.join('\n');
    assert.match(log, /event: set-current/);
    assert.match(log, /disposition: CANDIDATES/);
    assert.match(log, /candidateCount: 1/);
    assert.match(log, /uriMatchKey: include\/099_test\.php/);
    assert.match(log, /event: provide-code-lenses/);
    assert.match(log, /hasCurrent: true/);
    assert.match(log, /uriMatchesCurrent: true/);
    assert.match(log, /uriMatchesCurrent: false/);
    assert.match(log, /lensCount: 5/);
    assert.match(log, /reason: URI_MISMATCH/);
    assert.match(log, /disposition: MANUAL_ONLY/);
    assert.doesNotMatch(log, /RAW_SOURCE_MARKER|RAW_REPLACEMENT_MARKER/);
    assert.doesNotMatch(log, /C:\\private\\workspace/i);
    ui.dispose();
});

test('MANUAL_ONLY CodeLens has no Compare or Apply and NO_CHANGE is not presented', t => {
    const vscode = codeLensVscode();
    const ui = new SecurityFixReviewUi(vscode);
    const range = { intersection() { return this; } };
    ui.setCurrent({
        sessionId: 'session-1',
        item: {
            findingId: 'finding-1', ruleId: 'WPB-SCF-CONTEXT-UNKNOWN',
            reviewDisposition: 'MANUAL_ONLY', reason: 'Context is unknown.', candidates: []
        },
        uri: { fsPath: 'C:\\work\\a.php' },
        range
    });
    const titles = ui.provideCodeLenses({ uri: { fsPath: 'C:\\work\\a.php' } })
        .map(lens => lens.command.title);
    assert.equal(titles.includes('【修正前後を比較】'), false);
    assert.equal(titles.includes('【修正を適用する】'), false);
    assert.deepEqual(titles, [
        'Security Fix：手動確認が必要 · WPB-SCF-CONTEXT-UNKNOWN',
        '【理由を確認】', '【今回はスキップ】', '【レビューを終了】'
    ]);
    ui.clear();
    assert.deepEqual(ui.provideCodeLenses({ uri: { fsPath: 'C:\\work\\a.php' } }), []);
});

test('review command schema rejects payload data and stale command identifiers', async t => {
    assert.throws(() => validateReviewCommandArguments({
        sessionId: 'session', findingId: 'finding', candidateId: null, action: 'skip', file: 'x.php'
    }), /unsupported fields/);

    const root = createTempWorkspace(t, 'vscode-review-stale-command');
    const file = writeTempFile(root, 'case.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    const payload = reviewPayload(root, [], [item]);
    const session = new SecurityFixEditReviewSession(reviewVscode(root, [], []), payload, {
        reviewUi: { setCurrent() {}, clear() {} }
    });
    await session.start();
    assert.equal(await session.handleDiagnosticCommand('skip', {
        sessionId: 'another-session', findingId: item.findingId, candidateId: null, action: 'skip'
    }), false);
    assert.equal(session.status, 'blocked');
    assert.match(session.failure.message, /stale|another session/);
});

test('multiple candidates use QuickPick only after Compare or Apply is selected', async t => {
    const root = createTempWorkspace(t, 'vscode-review-multiple');
    const file = writeTempFile(root, 'case.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    item.candidates.push({
        ...item.candidates[0],
        candidateId: 'finding-1-candidate-02',
        label: 'Second candidate',
        recommended: false
    });
    const payload = reviewPayload(root, [], [item]);
    const vscode = reviewVscode(root, [], []);
    let quickPickCount = 0;
    vscode.window.showQuickPick = async choices => {
        quickPickCount += 1;
        return choices[1];
    };
    let comparedCandidate = null;
    const session = new SecurityFixEditReviewSession(vscode, payload, {
        reviewUi: { setCurrent() {}, clear() {} },
        async showCandidateDiff(_vscode, _item, candidate) { comparedCandidate = candidate; }
    });
    await session.start();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(quickPickCount, 0);
    await session.handleDiagnosticCommand('compare', {
        sessionId: payload.sessionId, findingId: item.findingId, candidateId: null, action: 'compare'
    });
    assert.equal(quickPickCount, 1);
    assert.equal(comparedCandidate.candidateId, 'finding-1-candidate-02');
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
});

test('Compare revalidates stale source and fails closed without WorkspaceEdit', async t => {
    const root = createTempWorkspace(t, 'vscode-review-compare-stale');
    const file = writeTempFile(root, 'case.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    const payload = reviewPayload(root, [], [item]);
    const vscode = reviewVscode(root, [], []);
    vscode.Uri.parse = value => ({ toString: () => value });
    vscode.commands = { async executeCommand() { throw new Error('diff must not open'); } };
    const session = new SecurityFixEditReviewSession(vscode, payload, {
        reviewUi: { setCurrent() {}, clear() {} }
    });
    await session.start();
    fs.writeFileSync(file, 'axc');
    assert.equal(await session.handleDiagnosticCommand('compare', {
        sessionId: payload.sessionId,
        findingId: item.findingId,
        candidateId: item.candidates[0].candidateId,
        action: 'compare'
    }), false);
    assert.equal(session.status, 'blocked');
    assert.equal(session.failure.code, 'STALE_FILE');
});

test('Apply independently revalidates stale source before WorkspaceEdit', async t => {
    const root = createTempWorkspace(t, 'vscode-review-apply-stale');
    const file = writeTempFile(root, 'case.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    const payload = reviewPayload(root, [], [item]);
    const vscode = reviewVscode(root, [], []);
    let workspaceEditCount = 0;
    vscode.WorkspaceEdit = class WorkspaceEdit {
        replace() { workspaceEditCount += 1; }
    };
    vscode.workspace.applyEdit = async () => { workspaceEditCount += 1; return true; };
    let compareCount = 0;
    const session = new SecurityFixEditReviewSession(vscode, payload, {
        reviewUi: { setCurrent() {}, clear() {} },
        async showCandidateDiff() { compareCount += 1; }
    });
    await session.start();
    assert.equal(await session.handleDiagnosticCommand('compare', {
        sessionId: payload.sessionId,
        findingId: item.findingId,
        candidateId: item.candidates[0].candidateId,
        action: 'compare'
    }), true);
    assert.equal(compareCount, 1);
    fs.writeFileSync(file, 'axc');
    assert.equal(await session.handleDiagnosticCommand('apply', {
        sessionId: payload.sessionId,
        findingId: item.findingId,
        candidateId: item.candidates[0].candidateId,
        action: 'apply'
    }), false);
    assert.equal(session.status, 'blocked');
    assert.equal(session.failure.code, 'STALE_FILE');
    assert.equal(workspaceEditCount, 0);
});

test('NO_CHANGE writes an output entry and advances without review UI', async t => {
    const root = createTempWorkspace(t, 'vscode-review-no-change-output');
    const file = writeTempFile(root, 'case.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B', 'NO_CHANGE');
    const payload = reviewPayload(root, [], [item]);
    const lines = [];
    let setCurrentCount = 0;
    const session = new SecurityFixEditReviewSession(reviewVscode(root, [], []), payload, {
        reviewUi: { setCurrent() { setCurrentCount += 1; }, clear() {} },
        outputChannel: {
            appendLine(line) { lines.push(line); },
            clear() {},
            show() {}
        }
    });
    await session.start();
    assert.equal(session.status, 'completed');
    assert.equal(setCurrentCount, 0);
    assert.ok(lines.some(line => line.includes('NO_CHANGE') && line.includes(item.findingId)));
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
});

test('diagnostic Skip advances without editing and Cancel clears review UI without touching disk', async t => {
    const root = createTempWorkspace(t, 'vscode-review-skip-cancel');
    const firstFile = writeTempFile(root, 'first.php', 'abc');
    const secondFile = writeTempFile(root, 'second.php', 'abc');
    const first = diagnosticReviewItem(root, firstFile, 'abc', 'B', 'MANUAL_ONLY');
    const second = diagnosticReviewItem(root, secondFile, 'abc', 'B');
    second.findingId = 'finding-2';
    second.candidates[0].findingId = 'finding-2';
    second.candidates[0].candidateId = 'finding-2-candidate-01';
    const payload = reviewPayload(root, [], [first, second]);
    let clearCount = 0;
    const ui = { setCurrent() {}, clear() { clearCount += 1; } };
    const session = new SecurityFixEditReviewSession(reviewVscode(root, [], []), payload, { reviewUi: ui });
    await session.start();
    await new Promise(resolve => setImmediate(resolve));
    await session.handleDiagnosticCommand('skip', {
        sessionId: payload.sessionId, findingId: first.findingId, candidateId: null, action: 'skip'
    });
    assert.equal(session.diagnosticIndex, 1);
    session.cancel();
    assert.equal(session.status, 'cancelled');
    assert.ok(session.vscode.__informationMessages.includes(
        'Security Fix レビューを終了しました。現在のエディターは保存、破棄、または閉じられていません。'
    ));
    assert.equal(session.vscode.__informationMessages.some(message => message.includes('レビューが完了しました')), false);
    assert.ok(clearCount >= 2);
    assert.equal(fs.readFileSync(firstFile, 'utf8'), 'abc');
    assert.equal(fs.readFileSync(secondFile, 'utf8'), 'abc');
});

test('last MANUAL_ONLY Skip shows completion once after existing cleanup', async t => {
    const root = createTempWorkspace(t, 'vscode-review-complete');
    const file = writeTempFile(root, 'last.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B', 'MANUAL_ONLY');
    const payload = reviewPayload(root, [], [item]);
    const vscode = reviewVscode(root, [], []);
    let clearCount = 0;
    const reviewUi = {
        current: null,
        setCurrent(current) { this.current = current; },
        clear() { this.current = null; clearCount += 1; }
    };
    const session = new SecurityFixEditReviewSession(vscode, payload, { reviewUi });

    await session.start();
    const cancelControl = vscode.__statusBarItems.find(entry => entry.text?.includes('Security Fix レビューを終了'));
    assert.equal(session.status, 'diagnostic-active');
    assert.equal(session.diagnosticIndex, 0);
    assert.equal(session.currentDiagnostic, item);
    assert.equal(cancelControl.visible, true);
    assert.equal(vscode.__informationMessages.some(message => message.includes('レビューが完了しました')), false);

    assert.equal(await session.handleDiagnosticCommand('skip', {
        sessionId: payload.sessionId,
        findingId: item.findingId,
        candidateId: null,
        action: 'skip'
    }), true);

    assert.equal(session.status, 'completed');
    assert.equal(session.currentDiagnostic, null);
    assert.equal(reviewUi.current, null);
    assert.equal(cancelControl.visible, false);
    assert.ok(clearCount >= 2);
    assert.equal(vscode.__informationMessages.filter(
        message => message === 'Security Fix：レビューが完了しました。\n確認対象はすべて処理されました。'
    ).length, 1);
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
});

test('MANUAL_ONLY reason command shows safe Japanese guidance and preserves the current finding', async t => {
    const cases = [
        ['WPB-SCF-INDIRECT-USAGE', 'SCF::get() の値が間接的に使用されているため、最終的な出力先を安全に特定できません。'],
        ['WPB-SCF-CONTEXT-UNKNOWN', 'この値がHTML本文・URL・属性値など、どの文脈へ出力されるか安全に特定できません。'],
        ['WPB-SCF-ARGUMENT-UNSUPPORTED', 'SCF::get() の引数が現在の安全な自動解析対象外です。'],
        ['WPB-SCF-PARSE-UNSAFE', 'コードを安全に解析できないため、自動修正候補を作成できません。'],
        ['WPB-SCF-CLASS-AMBIGUOUS', 'SCFとして検出した呼び出しのクラス判定を安全に確定できません。']
    ];

    for (const [ruleId, expectedReason] of cases) {
        await t.test(ruleId, async t => {
            const root = createTempWorkspace(t, `vscode-review-reason-${ruleId.toLowerCase()}`);
            const file = writeTempFile(root, 'case.php', 'abc');
            const item = diagnosticReviewItem(root, file, 'abc', 'B', 'MANUAL_ONLY');
            item.ruleId = ruleId;
            const payload = reviewPayload(root, [], [item]);
            const vscode = reviewVscode(root, [], []);
            const session = new SecurityFixEditReviewSession(vscode, payload, {
                reviewUi: { setCurrent() {}, clear() {} }
            });
            await session.start();

            assert.equal(await session.handleDiagnosticCommand('showReason', {
                sessionId: payload.sessionId,
                findingId: item.findingId,
                candidateId: null,
                action: 'showReason'
            }), true);

            const message = vscode.__informationMessages.at(-1);
            assert.match(message, /^Security Fix：手動確認が必要です。/);
            assert.match(message, new RegExp(ruleId));
            assert.ok(message.includes(`理由：\n${expectedReason}`));
            assert.match(message, /確認：\n.+/s);
            assert.equal(session.diagnosticIndex, 0);
            assert.equal(session.currentDiagnostic, item);
            assert.equal(session.status, 'diagnostic-active');
            assert.deepEqual(vscode.__informationMessageCalls.at(-1).args, [{ modal: true }]);
            session.cancel({ silent: true });
        });
    }
});

test('MANUAL_ONLY unknown rule uses only safe reason or fixed fallback without leaking source or path', () => {
    const safe = manualReviewMessage({
        ruleId: 'WPB-SCF-FUTURE-RULE',
        reason: 'The analyzer could not prove a safe automatic change.'
    });
    assert.match(safe, /The analyzer could not prove a safe automatic change\./);

    const absolutePath = 'C:\\private\\project\\case.php';
    const rawSource = '<?php echo $secret; ?>';
    const unsafe = manualReviewMessage({
        ruleId: 'WPB-SCF-FUTURE-RULE',
        reason: `${absolutePath} ${rawSource}`
    });
    assert.match(unsafe, /この箇所は安全な自動修正方法を確定できないため、手動確認が必要です。/);
    assert.doesNotMatch(unsafe, /C:\\private|<\?php|\$secret/);
});

test('CANDIDATES CodeLens Skip completes the item and refreshes without editing', async t => {
    const root = createTempWorkspace(t, 'vscode-review-candidate-skip');
    const file = writeTempFile(root, 'candidate.php', 'abc');
    const item = diagnosticReviewItem(root, file, 'abc', 'B');
    const payload = reviewPayload(root, [], [item]);
    let setCount = 0;
    let clearCount = 0;
    const session = new SecurityFixEditReviewSession(reviewVscode(root, [], []), payload, {
        reviewUi: {
            setCurrent() { setCount += 1; },
            clear() { clearCount += 1; }
        }
    });

    await session.start();
    assert.equal(await session.handleDiagnosticCommand('skip', {
        sessionId: payload.sessionId,
        findingId: item.findingId,
        candidateId: null,
        action: 'skip'
    }), true);
    assert.equal(session.status, 'completed');
    assert.equal(session.candidateReviewedCount, 1);
    assert.equal(setCount, 1);
    assert.ok(clearCount >= 2);
    assert.equal(fs.readFileSync(file, 'utf8'), 'abc');
    assert.ok(session.vscode.__informationMessages.some(message =>
        message === 'Security Fix：レビューが完了しました。\n確認対象はすべて処理されました。'
    ));
});
