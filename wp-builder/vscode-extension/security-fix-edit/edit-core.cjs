'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const { TextDecoder } = require('node:util');

function fail(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
}

function isInside(parent, target) {
    const relative = path.relative(path.resolve(parent), path.resolve(target));
    return relative === '' || (
        relative !== '..' &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative)
    );
}

function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

function validInteger(value) {
    return Number.isSafeInteger(value) && value >= 0;
}

function validIdentityPart(value) {
    return typeof value === 'string' && /^\d+$/.test(value);
}

function hasOnlyKeys(value, allowed) {
    return value && typeof value === 'object' &&
        Object.keys(value).every(key => allowed.has(key));
}

function validatePayload(payload) {
    if (!payload || payload.schemaVersion !== 1 || payload.kind !== 'wp-builder-security-fix-edit') {
        throw fail('INVALID_SCHEMA', 'Unsupported Security Fix edit payload schema.');
    }
    if (!path.isAbsolute(payload.workspaceRoot) || !path.isAbsolute(payload.file) ||
        !isInside(payload.workspaceRoot, payload.file)) {
        throw fail('OUTSIDE_WORKSPACE', 'Security Fix edit target is outside the workspace.');
    }
    if (!/^[a-f0-9]{64}$/.test(payload.originalSha256) || !validInteger(payload.originalSize)) {
        throw fail('INVALID_IDENTITY', 'Security Fix edit payload identity is invalid.');
    }
    if (payload.desiredSha256 !== undefined && !/^[a-f0-9]{64}$/.test(payload.desiredSha256)) {
        throw fail('INVALID_IDENTITY', 'Security Fix edit payload desired hash is invalid.');
    }
    if (!payload.originalIdentity ||
        !validIdentityPart(payload.originalIdentity.dev) ||
        !validIdentityPart(payload.originalIdentity.ino) ||
        !validIdentityPart(payload.originalIdentity.nlink)) {
        throw fail('INVALID_IDENTITY', 'Security Fix edit payload file identity is invalid.');
    }
    if (payload.encoding?.charset !== 'utf-8' || typeof payload.encoding.bom !== 'boolean') {
        throw fail('UNSUPPORTED_ENCODING', 'Security Fix edit supports UTF-8 and UTF-8 BOM only.');
    }
    if (!Array.isArray(payload.edits) || payload.edits.length === 0) {
        throw fail('INVALID_EDITS', 'Security Fix edit payload has no edits.');
    }
    payload.edits.forEach(edit => {
        if (typeof edit.findingId !== 'string' ||
            !validInteger(edit.startByte) ||
            !validInteger(edit.endByte) ||
            edit.endByte <= edit.startByte ||
            !/^[a-f0-9]{64}$/.test(edit.originalSha256) ||
            typeof edit.replacement !== 'string') {
            throw fail('INVALID_EDITS', 'Security Fix edit payload contains an invalid edit.');
        }
    });
    return payload;
}

function validRelativePath(value) {
    if (typeof value !== 'string' || value.length === 0 || value.includes('\\')) return false;
    const normalized = path.posix.normalize(value);
    return normalized === value && normalized !== '..' && !normalized.startsWith('../') && !path.posix.isAbsolute(value);
}

function validateDiagnosticCandidate(candidate) {
    const candidateKeys = new Set([
        'schemaVersion', 'candidateId', 'findingId', 'label', 'confidence',
        'recommended', 'reason', 'edits', 'desiredSha256', 'lint'
    ]);
    const editKeys = new Set(['startByte', 'endByte', 'originalSha256', 'replacement']);
    if (!hasOnlyKeys(candidate, candidateKeys) || candidate.schemaVersion !== 1 ||
        typeof candidate.candidateId !== 'string' || candidate.candidateId.length > 128 ||
        typeof candidate.findingId !== 'string' || candidate.findingId.length > 128 ||
        typeof candidate.label !== 'string' || candidate.label.length === 0 || candidate.label.length > 256 ||
        !['HIGH', 'MEDIUM', 'LOW'].includes(candidate.confidence) ||
        typeof candidate.recommended !== 'boolean' ||
        typeof candidate.reason !== 'string' || candidate.reason.length === 0 || candidate.reason.length > 2000 ||
        !/^[a-f0-9]{64}$/.test(candidate.desiredSha256 ?? '') ||
        !hasOnlyKeys(candidate.lint, new Set(['available', 'passed', 'exitCode'])) ||
        candidate.lint.available !== true || candidate.lint.passed !== true ||
        !(candidate.lint.exitCode === 0)) {
        throw fail('INVALID_CANDIDATE', 'Security Fix diagnostic candidate schema is invalid.');
    }
    if (!Array.isArray(candidate.edits) || candidate.edits.length === 0 || candidate.edits.length > 100) {
        throw fail('INVALID_CANDIDATE', 'Security Fix diagnostic candidate must contain bounded edits.');
    }
    let previousEnd = -1;
    [...candidate.edits].sort((left, right) => left.startByte - right.startByte).forEach(edit => {
        if (!hasOnlyKeys(edit, editKeys) ||
            !validInteger(edit.startByte) || !validInteger(edit.endByte) || edit.endByte <= edit.startByte ||
            edit.startByte < previousEnd ||
            !/^[a-f0-9]{64}$/.test(edit.originalSha256 ?? '') || typeof edit.replacement !== 'string') {
            throw fail('INVALID_CANDIDATE', 'Security Fix diagnostic candidate contains an invalid edit.');
        }
        previousEnd = edit.endByte;
    });
    return candidate;
}

function diagnosticEditablePayload(source, candidate) {
    return {
        schemaVersion: 1,
        kind: 'wp-builder-security-fix-diagnostic-candidate',
        ...source,
        desiredSha256: candidate.desiredSha256,
        edits: candidate.edits.map(edit => ({
            findingId: candidate.findingId,
            ...edit
        })),
        candidateId: candidate.candidateId
    };
}

function validateDiagnosticCandidatePayload(payload) {
    if (!payload || payload.schemaVersion !== 1 || payload.kind !== 'wp-builder-security-fix-diagnostic-candidate' ||
        typeof payload.candidateId !== 'string') {
        throw fail('INVALID_SCHEMA', 'Unsupported Security Fix diagnostic candidate payload schema.');
    }
    validatePayload({ ...payload, kind: 'wp-builder-security-fix-edit' });
    return payload;
}

function validateReviewPayload(payload) {
    if (!payload || payload.schemaVersion !== 1 || payload.kind !== 'wp-builder-security-fix-edit-review') {
        throw fail('INVALID_SCHEMA', 'Unsupported Security Fix edit review payload schema.');
    }
    if (typeof payload.sessionId !== 'string' ||
        !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(payload.sessionId) ||
        typeof payload.ackToken !== 'string' || !/^[a-f0-9]{64}$/.test(payload.ackToken) ||
        !path.isAbsolute(payload.workspaceRoot)) {
        throw fail('INVALID_SESSION', 'Security Fix edit review session identity is invalid.');
    }
    if (!Array.isArray(payload.items) || payload.items.length > 1000) {
        throw fail('INVALID_SESSION', 'Security Fix edit review file items are invalid.');
    }
    const seen = new Set();
    payload.items.forEach(item => {
        validatePayload(item);
        if (path.relative(path.resolve(payload.workspaceRoot), path.resolve(item.workspaceRoot)) !== '' ||
            !validRelativePath(item.relativePath) ||
            !item.firstLocation ||
            !validInteger(item.firstLocation.line) || item.firstLocation.line < 1 ||
            !validInteger(item.firstLocation.column) || item.firstLocation.column < 1 ||
            !/^[a-f0-9]{64}$/.test(item.desiredSha256 ?? '')) {
            throw fail('INVALID_SESSION', 'Security Fix edit review contains an invalid file item.');
        }
        const key = process.platform === 'win32' ? item.file.toLowerCase() : item.file;
        if (seen.has(key)) throw fail('INVALID_SESSION', 'Security Fix edit review contains a duplicate file.');
        seen.add(key);
    });
    if (!Array.isArray(payload.diagnostics) || payload.diagnostics.length > 5000 ||
        payload.items.length + payload.diagnostics.length === 0) {
        throw fail('INVALID_SESSION', 'Security Fix edit review diagnostics are invalid.');
    }
    payload.diagnostics.forEach(item => {
        if (!hasOnlyKeys(item, new Set([
            'file', 'line', 'column', 'findingId', 'ruleId', 'reviewDisposition',
            'reason', 'source', 'candidates'
        ])) || !validRelativePath(item.file) ||
            !validInteger(item.line) || item.line < 1 ||
            !validInteger(item.column) || item.column < 1 ||
            typeof item.findingId !== 'string' || typeof item.ruleId !== 'string' ||
            !['CANDIDATES', 'MANUAL_ONLY', 'NO_CHANGE'].includes(item.reviewDisposition) ||
            typeof item.reason !== 'string' || item.reason.length === 0 || item.reason.length > 2000 ||
            !Array.isArray(item.candidates)) {
            throw fail('INVALID_SESSION', 'Security Fix edit review contains an invalid diagnostic.');
        }
        if (item.reviewDisposition === 'CANDIDATES') {
            if (!hasOnlyKeys(item.source, new Set([
                'workspaceRoot', 'file', 'originalSha256', 'originalSize', 'originalIdentity', 'encoding'
            ])) || item.candidates.length === 0 || item.candidates.length > 10) {
                throw fail('INVALID_SESSION', 'Security Fix candidate review source is invalid.');
            }
            item.candidates.forEach(candidate => {
                validateDiagnosticCandidate(candidate);
                if (candidate.findingId !== item.findingId) {
                    throw fail('INVALID_SESSION', 'Security Fix candidate finding identity is invalid.');
                }
                validateDiagnosticCandidatePayload(diagnosticEditablePayload(item.source, candidate));
            });
            const expectedFile = path.resolve(payload.workspaceRoot, item.file);
            const sourceFile = path.resolve(item.source.file);
            const sameFile = process.platform === 'win32'
                ? expectedFile.toLowerCase() === sourceFile.toLowerCase()
                : expectedFile === sourceFile;
            if (!sameFile || path.resolve(item.source.workspaceRoot) !== path.resolve(payload.workspaceRoot)) {
                throw fail('INVALID_SESSION', 'Security Fix candidate source is outside the review workspace.');
            }
        } else if (item.source !== null || item.candidates.length !== 0) {
            throw fail('INVALID_SESSION', 'Non-candidate diagnostics cannot contain edit payloads.');
        }
    });
    return payload;
}

function validateIncomingPayload(payload) {
    return payload?.kind === 'wp-builder-security-fix-edit-review'
        ? validateReviewPayload(payload)
        : validatePayload(payload);
}

function decodeUtf8(bytes) {
    try {
        return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
        throw fail('UNSUPPORTED_ENCODING', 'Security Fix edit source is not valid UTF-8.');
    }
}

function prepareEdits({ payload, currentBytes, currentIdentity, documentText, documentIsDirty }) {
    if (payload?.kind === 'wp-builder-security-fix-diagnostic-candidate') {
        validateDiagnosticCandidatePayload(payload);
    } else {
        validatePayload(payload);
    }
    if (documentIsDirty) throw fail('DOCUMENT_DIRTY', 'Security Fix edit cancelled: the editor already has unsaved changes.');
    if (currentIdentity.isSymbolicLink || !currentIdentity.isFile ||
        currentIdentity.dev !== payload.originalIdentity.dev ||
        currentIdentity.ino !== payload.originalIdentity.ino ||
        currentIdentity.nlink !== payload.originalIdentity.nlink ||
        currentBytes.length !== payload.originalSize ||
        sha256(currentBytes) !== payload.originalSha256) {
        throw fail('STALE_FILE', 'Security Fix edit cancelled: the file changed after preview. Run security:fix again.');
    }

    const hasBom = currentBytes.length >= 3 &&
        currentBytes[0] === 0xef && currentBytes[1] === 0xbb && currentBytes[2] === 0xbf;
    if (hasBom !== payload.encoding.bom) {
        throw fail('STALE_FILE', 'Security Fix edit cancelled: the file encoding changed after preview.');
    }
    const bomLength = hasBom ? 3 : 0;
    const sourceText = decodeUtf8(currentBytes.subarray(bomLength));
    if (sourceText !== documentText) {
        throw fail('DOCUMENT_MISMATCH', 'Security Fix edit cancelled: the open document differs from the preview source.');
    }

    let previousEnd = bomLength;
    return [...payload.edits]
        .sort((left, right) => left.startByte - right.startByte)
        .map(edit => {
            if (edit.startByte < previousEnd || edit.endByte > currentBytes.length || edit.startByte < bomLength) {
                throw fail('INVALID_EDITS', 'Security Fix edit ranges overlap or exceed the source.');
            }
            if (sha256(currentBytes.subarray(edit.startByte, edit.endByte)) !== edit.originalSha256) {
                throw fail('STALE_RANGE', 'Security Fix edit cancelled: a target range changed after preview.');
            }
            const startOffset = decodeUtf8(currentBytes.subarray(bomLength, edit.startByte)).length;
            const endOffset = decodeUtf8(currentBytes.subarray(bomLength, edit.endByte)).length;
            previousEnd = edit.endByte;
            return { ...edit, startOffset, endOffset };
        });
}

function renderCandidateText({ payload, currentBytes, currentIdentity, documentText, documentIsDirty }) {
    const edits = prepareEdits({ payload, currentBytes, currentIdentity, documentText, documentIsDirty });
    let desiredText = documentText;
    for (const edit of [...edits].sort((left, right) => right.startOffset - left.startOffset)) {
        desiredText = `${desiredText.slice(0, edit.startOffset)}${edit.replacement}${desiredText.slice(edit.endOffset)}`;
    }
    const prefix = payload.encoding.bom ? Buffer.from([0xef, 0xbb, 0xbf]) : Buffer.alloc(0);
    if (sha256(Buffer.concat([prefix, Buffer.from(desiredText, 'utf8')])) !== payload.desiredSha256) {
        throw fail('DESIRED_HASH_MISMATCH', 'Security Fix diagnostic candidate does not match its desired hash.');
    }
    return desiredText;
}

module.exports = {
    diagnosticEditablePayload,
    prepareEdits,
    renderCandidateText,
    sha256,
    validateDiagnosticCandidate,
    validateDiagnosticCandidatePayload,
    validateIncomingPayload,
    validatePayload,
    validateReviewPayload
};
