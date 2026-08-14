import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { normalizePhpRuntimeContract } from './php-runtime-contract.js';

const TOKENIZER_PATH = fileURLToPath(new URL('./php-tokenizer.php', import.meta.url));
const ESCAPE_FUNCTIONS = new Set([
    'esc_html',
    'esc_attr',
    'esc_url',
    'esc_textarea',
    'wp_kses_post'
]);
const URL_ATTRIBUTES = new Set(['href', 'src', 'action', 'formaction', 'poster', 'cite']);
const IGNORED_TOKEN_TYPES = new Set(['T_WHITESPACE', 'T_COMMENT', 'T_DOC_COMMENT']);
const REVIEW_DISPOSITIONS = Object.freeze({
    CANDIDATES: 'CANDIDATES',
    MANUAL_ONLY: 'MANUAL_ONLY',
    NO_CHANGE: 'NO_CHANGE'
});
const INDIRECT_CONTROL_FLOW_TOKENS = new Set([
    'T_IF', 'T_ELSEIF', 'T_ELSE', 'T_SWITCH', 'T_CASE', 'T_DEFAULT',
    'T_FOR', 'T_FOREACH', 'T_WHILE', 'T_DO', 'T_FUNCTION', 'T_FN',
    'T_TRY', 'T_CATCH', 'T_FINALLY', 'T_MATCH', 'T_GOTO', 'T_GLOBAL',
    'T_RETURN', 'T_YIELD', 'T_YIELD_FROM'
]);

function isIgnoredToken(token) {
    return IGNORED_TOKEN_TYPES.has(token?.type);
}

function previousSignificant(tokens, index) {
    for (let cursor = index - 1; cursor >= 0; cursor -= 1) {
        if (!isIgnoredToken(tokens[cursor])) return cursor;
    }
    return -1;
}

function nextSignificant(tokens, index) {
    for (let cursor = index + 1; cursor < tokens.length; cursor += 1) {
        if (!isIgnoredToken(tokens[cursor])) return cursor;
    }
    return -1;
}

function buildDelimiterPairs(tokens) {
    const stack = [];
    const pairs = new Map();
    const opening = new Map([['(', ')'], ['[', ']'], ['{', '}']]);
    const closing = new Map([[')', '('], [']', '['], ['}', '{']]);

    tokens.forEach((token, index) => {
        if (opening.has(token.text)) {
            stack.push({ index, text: token.text });
            return;
        }
        if (!closing.has(token.text)) return;
        const current = stack.pop();
        if (!current || current.text !== closing.get(token.text)) return;
        pairs.set(current.index, index);
    });
    return pairs;
}

function normalizeFunctionName(text) {
    return text.startsWith('\\') ? text.slice(1) : text;
}

function isInsideEscape(tokens, pairs, callStartIndex, callEndIndex) {
    for (const [openIndex, closeIndex] of pairs.entries()) {
        if (openIndex >= callStartIndex || closeIndex <= callEndIndex) continue;
        const functionIndex = previousSignificant(tokens, openIndex);
        if (functionIndex < 0) continue;
        if (ESCAPE_FUNCTIONS.has(normalizeFunctionName(tokens[functionIndex].text))) return true;
    }
    return false;
}

function decodeStaticField(tokenText) {
    return tokenText.slice(1, -1);
}

function locationForRange(bytes, startByte, endByte) {
    const prefix = bytes.subarray(0, startByte).toString('utf8');
    const source = bytes.subarray(startByte, endByte).toString('utf8');
    const prefixLines = prefix.split('\n');
    const sourceLines = source.split('\n');
    const startLine = prefixLines.length;
    const startColumn = [...prefixLines.at(-1)].length + 1;
    return {
        startLine,
        startColumn,
        endLine: startLine + sourceLines.length - 1,
        endColumn: sourceLines.length === 1
            ? startColumn + [...source].length
            : [...sourceLines.at(-1)].length + 1
    };
}

function stripCompleteHtmlComments(value) {
    return value.replace(/<!--[\s\S]*?-->/g, '');
}

function hasUnclosedHtmlComment(value) {
    return value.lastIndexOf('<!--') > value.lastIndexOf('-->');
}

function currentRawElement(html) {
    const clean = stripCompleteHtmlComments(html);
    const pattern = /<(\/?)\s*(textarea|script|style)\b[^>]*>/gi;
    let current = null;
    let match;
    while ((match = pattern.exec(clean)) !== null) {
        current = match[1] ? null : match[2].toLowerCase();
    }
    return current;
}

function inlineHtmlBefore(tokens, openIndex) {
    return tokens
        .slice(0, openIndex)
        .filter(token => token.type === 'T_INLINE_HTML')
        .map(token => token.text)
        .join('');
}

function inlineHtmlAfter(tokens, closeIndex) {
    for (let index = closeIndex + 1; index < tokens.length; index += 1) {
        if (tokens[index].type === 'T_INLINE_HTML') return tokens[index].text;
        if (!isIgnoredToken(tokens[index])) break;
    }
    return '';
}

function hasEarlierPhpIslandInQuotedAttribute(tokens, openIndex, attributeName, quote) {
    let attributeStartIndex = -1;
    for (let index = openIndex - 1; index >= 0; index -= 1) {
        if (tokens[index].type !== 'T_INLINE_HTML') continue;
        const clean = stripCompleteHtmlComments(tokens[index].text);
        const attribute = clean.match(/(?:^|\s)([A-Za-z_:][A-Za-z0-9_:.-]*)\s*=\s*(["'])$/);
        if (attribute?.[1].toLowerCase() === attributeName && attribute[2] === quote) {
            attributeStartIndex = index;
            break;
        }
    }

    // The combined HTML looked like a quoted attribute, but its opening boundary
    // could not be tied to one inline-HTML token. Fail closed instead of guessing.
    if (attributeStartIndex === -1) return true;
    return tokens
        .slice(attributeStartIndex + 1, openIndex)
        .some(token => token.type === 'T_OPEN_TAG' || token.type === 'T_OPEN_TAG_WITH_ECHO');
}

function determineHtmlContext(tokens, openIndex, closeIndex) {
    const before = inlineHtmlBefore(tokens, openIndex);
    const after = inlineHtmlAfter(tokens, closeIndex);
    if (hasUnclosedHtmlComment(before)) return {
        kind: 'CONTEXT_UNKNOWN',
        confidence: 'LOW',
        reason: 'The PHP output is inside or adjacent to an unclosed HTML comment.'
    };

    const rawElement = currentRawElement(before);
    if (rawElement === 'script' || rawElement === 'style') return {
        kind: rawElement.toUpperCase(),
        confidence: 'HIGH',
        reason: `${rawElement} output is diagnostic-only.`
    };
    if (rawElement === 'textarea') return {
        kind: 'TEXTAREA',
        confidence: 'HIGH',
        proposedEscape: 'esc_textarea',
        reason: 'Direct output in textarea content.'
    };

    const clean = stripCompleteHtmlComments(before);
    const lastOpen = clean.lastIndexOf('<');
    const lastClose = clean.lastIndexOf('>');
    if (lastOpen > lastClose) {
        const tagTail = clean.slice(lastOpen);
        const attribute = tagTail.match(/(?:^|\s)([A-Za-z_:][A-Za-z0-9_:.-]*)\s*=\s*(["'])$/);
        if (!attribute || !after.startsWith(attribute[2])) return {
            kind: 'CONTEXT_UNKNOWN',
            confidence: 'LOW',
            reason: 'The PHP output is in a tag context that cannot be resolved safely.'
        };

        const attributeName = attribute[1].toLowerCase();
        if (hasEarlierPhpIslandInQuotedAttribute(tokens, openIndex, attributeName, attribute[2])) return {
            kind: 'MULTIPLE_PHP_ISLAND_ATTRIBUTE',
            confidence: 'HIGH',
            attributeName,
            reason: `Attribute ${attributeName} is composed from multiple PHP islands.`
        };
        if (attributeName === 'srcset') return {
            kind: 'SRCSET_ATTRIBUTE',
            confidence: 'HIGH',
            attributeName,
            reason: 'srcset requires dedicated URL-list handling.'
        };
        if (
            attributeName.startsWith('data-') ||
            attributeName === 'style' ||
            attributeName === 'srcdoc' ||
            attributeName.startsWith('on')
        ) return {
            kind: 'UNSAFE_ATTRIBUTE',
            confidence: 'HIGH',
            attributeName,
            reason: `Attribute ${attributeName} is not eligible for automatic escaping.`
        };
        if (URL_ATTRIBUTES.has(attributeName)) return {
            kind: 'URL_ATTRIBUTE',
            confidence: 'HIGH',
            attributeName,
            proposedEscape: 'esc_url',
            reason: `Direct output in quoted URL attribute ${attributeName}.`
        };
        return {
            kind: 'HTML_ATTRIBUTE',
            confidence: 'HIGH',
            attributeName,
            proposedEscape: 'esc_attr',
            reason: `Direct output in quoted attribute ${attributeName}.`
        };
    }

    return {
        kind: 'HTML_TEXT',
        confidence: 'HIGH',
        proposedEscape: 'esc_html',
        reason: 'Direct output in HTML text context.'
    };
}

function findPhpIsland(tokens, callStartIndex, callEndIndex) {
    let openIndex = callStartIndex;
    while (openIndex >= 0 && !['T_OPEN_TAG', 'T_OPEN_TAG_WITH_ECHO'].includes(tokens[openIndex].type)) {
        if (tokens[openIndex].type === 'T_CLOSE_TAG') return null;
        openIndex -= 1;
    }
    let closeIndex = callEndIndex;
    while (closeIndex < tokens.length && tokens[closeIndex].type !== 'T_CLOSE_TAG') {
        if (closeIndex !== callEndIndex && ['T_OPEN_TAG', 'T_OPEN_TAG_WITH_ECHO'].includes(tokens[closeIndex].type)) return null;
        closeIndex += 1;
    }
    if (openIndex < 0 || closeIndex >= tokens.length) return null;
    return { openIndex, closeIndex };
}

function hasComments(tokens, startIndex, endIndex) {
    return tokens.slice(startIndex, endIndex + 1).some(token => ['T_COMMENT', 'T_DOC_COMMENT'].includes(token.type));
}

function classifyDirectOutput(tokens, callStartIndex, callEndIndex) {
    const island = findPhpIsland(tokens, callStartIndex, callEndIndex);
    if (!island || hasComments(tokens, island.openIndex, island.closeIndex)) return {
        direct: false,
        kind: 'INDIRECT_OR_COMPLEX',
        island
    };

    const before = previousSignificant(tokens, callStartIndex);
    let after = nextSignificant(tokens, callEndIndex);
    if (tokens[after]?.text === ';') after = nextSignificant(tokens, after);

    if (
        tokens[island.openIndex].type === 'T_OPEN_TAG_WITH_ECHO' &&
        before === island.openIndex &&
        after === island.closeIndex
    ) return { direct: true, kind: 'SHORT_ECHO', island };

    const beforeEcho = previousSignificant(tokens, before);
    if (
        tokens[before]?.type === 'T_ECHO' &&
        beforeEcho === island.openIndex &&
        after === island.closeIndex
    ) return { direct: true, kind: 'ECHO', island };

    return { direct: false, kind: 'INDIRECT_OR_COMPLEX', island };
}

function diagnosticReason(tokens, callStartIndex, callEndIndex) {
    const before = previousSignificant(tokens, callStartIndex);
    const nearbyStart = Math.max(0, callStartIndex - 12);
    const nearbyEnd = Math.min(tokens.length, callEndIndex + 12);
    const nearby = tokens.slice(nearbyStart, nearbyEnd);
    if (nearby.some(token => token.type === 'T_PRINT')) return 'print output is diagnostic-only in the initial implementation.';
    if (nearby.some(token => token.type === 'T_RETURN')) return 'return context is diagnostic-only.';
    if (nearby.some(token => token.type === 'T_ECHO')) return 'echo contains multiple or complex expressions.';
    if (tokens[before]?.text === '=') return 'assignment context is diagnostic-only.';
    if (nearby.some(token => ['?', '??', '.', ','].includes(token.text))) return 'complex expression is diagnostic-only.';
    return 'The SCF call is not an eligible standalone direct-output expression.';
}

function sha256(value) {
    return createHash('sha256').update(value).digest('hex');
}

function manualReview(reason) {
    return {
        reviewDisposition: REVIEW_DISPOSITIONS.MANUAL_ONLY,
        reviewReason: reason,
        reviewCandidates: []
    };
}

function candidateReview({ label, confidence, reason, edits }) {
    return {
        reviewDisposition: REVIEW_DISPOSITIONS.CANDIDATES,
        reviewReason: reason,
        reviewCandidates: [{ label, confidence, recommended: true, reason, edits }]
    };
}

function directEscapeWrapper(tokens, pairs, callStartIndex, callEndIndex) {
    let match = null;
    for (const [openIndex, closeIndex] of pairs.entries()) {
        if (openIndex >= callStartIndex || closeIndex <= callEndIndex || tokens[openIndex]?.text !== '(') continue;
        const functionIndex = previousSignificant(tokens, openIndex);
        if (functionIndex < 0) continue;
        const functionName = normalizeFunctionName(tokens[functionIndex].text).toLowerCase();
        if (!ESCAPE_FUNCTIONS.has(functionName) ||
            nextSignificant(tokens, openIndex) !== callStartIndex ||
            previousSignificant(tokens, closeIndex) !== callEndIndex) continue;
        if (!match || closeIndex - openIndex < match.closeIndex - match.openIndex) {
            match = { openIndex, closeIndex, functionIndex, functionName };
        }
    }
    if (!match) return null;
    const directOutput = classifyDirectOutput(tokens, match.functionIndex, match.closeIndex);
    if (!directOutput.direct) return { ...match, direct: false, outputContext: null };
    return {
        ...match,
        direct: true,
        outputContext: determineHtmlContext(tokens, directOutput.island.openIndex, directOutput.island.closeIndex)
    };
}

function initialDiagnosticReview({
    finding,
    tokens,
    pairs,
    classIndex,
    closeParenIndex,
    significantArguments,
    directOutput
}) {
    if (finding.ruleId === 'WPB-SCF-EXPRESSION-COMPLEX') {
        if (!directOutput.direct || !finding.outputContext.proposedEscape) {
            return manualReview('A multiline expression requires manual review because its output context is not safely known.');
        }
        const replacement = `${finding.outputContext.proposedEscape}(${finding.exactSourceExpression})`;
        return candidateReview({
            label: `Wrap with ${finding.outputContext.proposedEscape}()`,
            confidence: 'HIGH',
            reason: `The complete direct-output expression can be wrapped for ${finding.outputContext.kind}.`,
            edits: [{ ...finding.range, replacement }]
        });
    }

    if (finding.ruleId === 'WPB-SCF-ARGUMENT-UNSUPPORTED') {
        const reviewableDynamicArgument = significantArguments.length === 1 &&
            significantArguments[0].type === 'T_VARIABLE';
        if (!directOutput.direct || !finding.outputContext.proposedEscape || !reviewableDynamicArgument) {
            return manualReview('The SCF argument or output context cannot be reduced to a safe scalar review candidate.');
        }
        const replacement = `${finding.outputContext.proposedEscape}(${finding.exactSourceExpression})`;
        return candidateReview({
            label: `Review ${finding.outputContext.proposedEscape}() wrapper`,
            confidence: 'MEDIUM',
            reason: 'The direct-output context is known; confirm that the dynamic SCF field resolves to a scalar value.',
            edits: [{ ...finding.range, replacement }]
        });
    }

    if (finding.ruleId === 'WPB-SCF-ALREADY-ESCAPED') {
        const wrapper = directEscapeWrapper(tokens, pairs, classIndex, closeParenIndex);
        if (!wrapper?.direct || !wrapper.outputContext?.proposedEscape || wrapper.functionName === 'wp_kses_post') {
            return manualReview('The existing escape wrapper cannot be proven to be a complete context-compatible direct output.');
        }
        if (wrapper.functionName === wrapper.outputContext.proposedEscape) {
            return {
                reviewDisposition: REVIEW_DISPOSITIONS.NO_CHANGE,
                reviewReason: `The direct ${wrapper.outputContext.kind} output already uses ${wrapper.functionName}().`,
                reviewCandidates: []
            };
        }
        const functionToken = tokens[wrapper.functionIndex];
        const replacement = functionToken.text.startsWith('\\')
            ? `\\${wrapper.outputContext.proposedEscape}`
            : wrapper.outputContext.proposedEscape;
        return candidateReview({
            label: `Replace ${wrapper.functionName}() with ${wrapper.outputContext.proposedEscape}()`,
            confidence: 'HIGH',
            reason: `The existing wrapper does not match the proven ${wrapper.outputContext.kind} context.`,
            edits: [{ startByte: functionToken.startByte, endByte: functionToken.endByte, replacement }]
        });
    }

    return manualReview(finding.reason);
}

function isVariableVariable(tokens, index) {
    const before = previousSignificant(tokens, index);
    return tokens[before]?.text === '$' || tokens[before]?.type === 'T_DOLLAR_OPEN_CURLY_BRACES';
}

function indirectDiagnosticReview({ finding, tokens, classIndex, closeParenIndex }) {
    const assignmentOperatorIndex = previousSignificant(tokens, classIndex);
    const variableIndex = previousSignificant(tokens, assignmentOperatorIndex);
    const statementEndIndex = nextSignificant(tokens, closeParenIndex);
    if (tokens[assignmentOperatorIndex]?.text !== '=' ||
        tokens[variableIndex]?.type !== 'T_VARIABLE' ||
        tokens[statementEndIndex]?.text !== ';' ||
        nextSignificant(tokens, variableIndex) !== assignmentOperatorIndex ||
        isVariableVariable(tokens, variableIndex)) {
        return manualReview('Phase D1 only follows a simple single-variable assignment.');
    }

    const boundaryIndex = previousSignificant(tokens, variableIndex);
    if (boundaryIndex >= 0 &&
        ![';', '{'].includes(tokens[boundaryIndex].text) &&
        !['T_OPEN_TAG', 'T_OPEN_TAG_WITH_ECHO'].includes(tokens[boundaryIndex].type)) {
        return manualReview('The SCF assignment is not a standalone straight-line statement.');
    }

    const variableName = tokens[variableIndex].text;
    const occurrences = tokens
        .map((token, index) => ({ token, index }))
        .filter(item => item.token.type === 'T_VARIABLE' && item.token.text === variableName);
    if (occurrences.length !== 2 || occurrences[0].index !== variableIndex) {
        return manualReview('The assigned variable does not have exactly one definition and one later use.');
    }
    const sinkIndex = occurrences[1].index;
    if (sinkIndex <= statementEndIndex || isVariableVariable(tokens, sinkIndex)) {
        return manualReview('The assigned variable use cannot be proven to be a later direct sink.');
    }

    const intervening = tokens.slice(statementEndIndex + 1, sinkIndex);
    if (intervening.some(token =>
        INDIRECT_CONTROL_FLOW_TOKENS.has(token.type) ||
        ['{', '}', '&'].includes(token.text) ||
        (token.type === 'T_STRING' && token.text.toLowerCase() === 'extract')
    )) {
        return manualReview('Control flow, scope changes, references, or dynamic symbol extraction prevent strict tracking.');
    }

    const sinkOutput = classifyDirectOutput(tokens, sinkIndex, sinkIndex);
    if (!sinkOutput.direct) {
        return manualReview('The only tracked variable use is not a standalone direct-output sink.');
    }
    const outputContext = determineHtmlContext(tokens, sinkOutput.island.openIndex, sinkOutput.island.closeIndex);
    if (!outputContext.proposedEscape) {
        return manualReview('The tracked direct-output sink does not have a supported HTML context.');
    }
    const variableToken = tokens[sinkIndex];
    return candidateReview({
        label: `Escape ${variableName} at its only output sink`,
        confidence: 'MEDIUM',
        reason: `A single straight-line definition reaches one ${outputContext.kind} sink with no other observed use.`,
        edits: [{
            startByte: variableToken.startByte,
            endByte: variableToken.endByte,
            replacement: `${outputContext.proposedEscape}(${variableName})`
        }]
    });
}

function applyCandidateEdits(bytes, edits) {
    let desired = Buffer.from(bytes);
    for (const edit of [...edits].sort((left, right) => right.startByte - left.startByte)) {
        desired = Buffer.concat([
            desired.subarray(0, edit.startByte),
            Buffer.from(edit.replacement, 'utf8'),
            desired.subarray(edit.endByte)
        ]);
    }
    return desired;
}

function finalizeDiagnosticReview(finding, bytes, phpCommand) {
    if (finding.reviewDisposition !== REVIEW_DISPOSITIONS.CANDIDATES) return finding;
    const candidates = [];
    for (let index = 0; index < finding.reviewCandidates.length; index += 1) {
        const draft = finding.reviewCandidates[index];
        const edits = [...draft.edits].sort((left, right) => left.startByte - right.startByte);
        const invalid = edits.some((edit, editIndex) =>
            !Number.isSafeInteger(edit.startByte) || !Number.isSafeInteger(edit.endByte) ||
            edit.startByte < 0 || edit.endByte <= edit.startByte || edit.endByte > bytes.length ||
            (editIndex > 0 && edit.startByte < edits[editIndex - 1].endByte)
        );
        if (invalid) continue;
        const desired = applyCandidateEdits(bytes, edits);
        const lintResult = spawnSync(phpCommand ?? 'php', ['-l'], {
            input: desired,
            encoding: 'utf8',
            maxBuffer: 16 * 1024 * 1024,
            windowsHide: true
        });
        const lint = {
            available: lintResult.error?.code !== 'ENOENT',
            passed: !lintResult.error && lintResult.status === 0,
            exitCode: lintResult.error ? null : lintResult.status
        };
        if (!lint.available || !lint.passed) continue;
        candidates.push({
            schemaVersion: 1,
            candidateId: `${finding.id}-candidate-${String(index + 1).padStart(2, '0')}`,
            findingId: finding.id,
            label: draft.label,
            confidence: draft.confidence,
            recommended: draft.recommended,
            reason: draft.reason,
            edits: edits.map(edit => ({
                startByte: edit.startByte,
                endByte: edit.endByte,
                originalSha256: sha256(bytes.subarray(edit.startByte, edit.endByte)),
                replacement: edit.replacement
            })),
            desiredSha256: sha256(desired),
            lint
        });
    }
    if (candidates.length === 0) return {
        ...finding,
        reviewDisposition: REVIEW_DISPOSITIONS.MANUAL_ONLY,
        reviewReason: 'No candidate passed fixed-range validation and PHP lint.',
        reviewCandidates: []
    };
    return { ...finding, reviewCandidates: candidates, reviewSourceSha256: sha256(bytes) };
}

function parseTokenizerOutput(result) {
    if (result.error?.code === 'ENOENT') return {
        ok: false,
        unavailable: true,
        errorCode: 'PHP_TOKENIZER_UNAVAILABLE',
        runtime: null,
        message: 'PHP runtime is unavailable.'
    };
    let parsed;
    try {
        parsed = JSON.parse(result.stdout || '{}');
    } catch {
        return {
            ok: false,
            unavailable: false,
            errorCode: 'PHP_TOKENIZER_CONTRACT_UNSAFE',
            runtime: null,
            message: result.stderr || 'PHP tokenizer returned invalid output.'
        };
    }

    const contract = normalizePhpRuntimeContract(parsed.runtime);
    if (!contract.ok) return {
        ok: false,
        unavailable: false,
        errorCode: contract.code,
        runtime: contract.runtime,
        message: contract.message
    };

    if (!parsed.ok) return {
        ok: false,
        unavailable: parsed.error?.code === 'PHP_TOKENIZER_UNAVAILABLE',
        errorCode: parsed.error?.code ?? 'WPB-SCF-PARSE-UNSAFE',
        runtime: contract.runtime,
        message: parsed.error?.message || 'PHP tokenizer rejected the file.',
        line: parsed.error?.line ?? null
    };
    return {
        ...parsed,
        runtime: contract.runtime
    };
}

export function runPhpTokenizer(bytes, options = {}) {
    const result = spawnSync(options.phpCommand ?? 'php', [options.tokenizerPath ?? TOKENIZER_PATH], {
        input: bytes,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true
    });
    return parseTokenizerOutput(result);
}

function makeParseUnsafeFinding(filePath, bytes, tokenizerResult) {
    const runtimeNote = tokenizerResult.errorCode === 'WPB-SCF-PARSE-UNSAFE' && tokenizerResult.runtime?.phpVersion
        ? ` Runtime PHP ${tokenizerResult.runtime.phpVersion}; the file may use syntax introduced by a newer PHP version.`
        : '';
    return {
        id: 'finding-0001',
        file: filePath,
        range: { startByte: 0, endByte: 0 },
        location: {
            startLine: tokenizerResult.line ?? 1,
            startColumn: 1,
            endLine: tokenizerResult.line ?? 1,
            endColumn: 1
        },
        ruleId: 'WPB-SCF-PARSE-UNSAFE',
        severity: 'ERROR',
        scf: null,
        exactSourceExpression: '',
        outputContext: { kind: 'PARSE_UNSAFE', confidence: 'LOW' },
        proposedEscape: null,
        confidence: 'LOW',
        autoFixable: false,
        reviewDisposition: REVIEW_DISPOSITIONS.MANUAL_ONLY,
        reviewReason: 'Parsing must succeed before any diagnostic candidate can be generated.',
        reviewCandidates: [],
        reason: `${tokenizerResult.message}${runtimeNote}`,
        replacement: null
    };
}

export function analyzeSecurityFile({ filePath, bytes, phpCommand, tokenizerPath, candidateLintPhpCommand } = {}) {
    const tokenizer = runPhpTokenizer(bytes, { phpCommand, tokenizerPath });
    if (!tokenizer.ok) return {
        tokenizer: {
            available: !tokenizer.unavailable,
            ok: false,
            error: tokenizer.message,
            errorCode: tokenizer.errorCode,
            runtime: tokenizer.runtime
        },
        findings: [makeParseUnsafeFinding(filePath, bytes, tokenizer)],
        canAnalyze: false
    };

    const tokens = tokenizer.tokens;
    const delimiterPairs = buildDelimiterPairs(tokens);
    const hasNamespace = tokens.some(token => token.type === 'T_NAMESPACE');
    const findings = [];
    const findingInternals = [];

    for (let classIndex = 0; classIndex < tokens.length; classIndex += 1) {
        const classToken = tokens[classIndex];
        const isGlobalScf = classToken.type === 'T_NAME_FULLY_QUALIFIED' && classToken.text === '\\SCF';
        const isUnqualifiedScf = classToken.type === 'T_STRING' && classToken.text === 'SCF';
        if (!isGlobalScf && !isUnqualifiedScf) continue;

        const doubleColonIndex = nextSignificant(tokens, classIndex);
        const methodIndex = nextSignificant(tokens, doubleColonIndex);
        const openParenIndex = nextSignificant(tokens, methodIndex);
        if (
            tokens[doubleColonIndex]?.text !== '::' ||
            tokens[methodIndex]?.type !== 'T_STRING' ||
            tokens[methodIndex]?.text !== 'get' ||
            tokens[openParenIndex]?.text !== '('
        ) continue;

        const closeParenIndex = delimiterPairs.get(openParenIndex);
        if (closeParenIndex === undefined) continue;
        const startByte = classToken.startByte;
        const endByte = tokens[closeParenIndex].endByte;
        const exactSourceExpression = bytes.subarray(startByte, endByte).toString('utf8');
        const significantArguments = tokens
            .slice(openParenIndex + 1, closeParenIndex)
            .filter(token => !isIgnoredToken(token));
        const staticArgument = significantArguments.length === 1 && significantArguments[0].type === 'T_CONSTANT_ENCAPSED_STRING';
        const field = staticArgument ? decodeStaticField(significantArguments[0].text) : null;
        const multiline = /\r|\n/.test(exactSourceExpression);
        const escaped = isInsideEscape(tokens, delimiterPairs, classIndex, closeParenIndex);
        const directOutput = classifyDirectOutput(tokens, classIndex, closeParenIndex);
        const ambiguousClass = isUnqualifiedScf && hasNamespace;
        let outputContext = {
            kind: directOutput.kind,
            confidence: directOutput.direct ? 'HIGH' : 'LOW'
        };
        if (directOutput.direct) {
            outputContext = determineHtmlContext(
                tokens,
                directOutput.island.openIndex,
                directOutput.island.closeIndex
            );
        }

        let ruleId = 'WPB-SCF-UNESCAPED-OUTPUT';
        let severity = directOutput.direct ? 'WARNING' : 'NOTICE';
        let confidence = 'HIGH';
        let autoFixable = false;
        let reason;

        if (ambiguousClass) {
            ruleId = 'WPB-SCF-CLASS-AMBIGUOUS';
            confidence = 'LOW';
            reason = 'Unqualified SCF inside a namespaced file cannot be resolved safely.';
        } else if (escaped) {
            ruleId = 'WPB-SCF-ALREADY-ESCAPED';
            severity = 'INFO';
            reason = 'The SCF call is already inside a recognized escape function.';
        } else if (!staticArgument) {
            ruleId = 'WPB-SCF-ARGUMENT-UNSUPPORTED';
            confidence = 'LOW';
            reason = 'SCF::get() must have exactly one static quoted-string argument.';
        } else if (multiline) {
            ruleId = 'WPB-SCF-EXPRESSION-COMPLEX';
            reason = 'Multiline SCF calls are diagnostic-only in the initial implementation.';
        } else if (!directOutput.direct) {
            ruleId = 'WPB-SCF-INDIRECT-USAGE';
            confidence = 'MEDIUM';
            reason = diagnosticReason(tokens, classIndex, closeParenIndex);
        } else if (!outputContext.proposedEscape) {
            ruleId = 'WPB-SCF-CONTEXT-UNKNOWN';
            confidence = outputContext.confidence;
            reason = outputContext.reason;
        } else {
            autoFixable = true;
            reason = outputContext.reason;
        }

        const proposedEscape = autoFixable ? outputContext.proposedEscape : null;
        const replacementText = proposedEscape ? `${proposedEscape}(${exactSourceExpression})` : null;
        const finding = {
            id: `finding-${String(findings.length + 1).padStart(4, '0')}`,
            file: filePath,
            range: { startByte, endByte },
            location: locationForRange(bytes, startByte, endByte),
            ruleId,
            severity,
            scf: {
                classForm: classToken.text,
                method: 'get',
                field,
                exactExpression: exactSourceExpression
            },
            exactSourceExpression,
            outputContext,
            proposedEscape,
            confidence,
            autoFixable,
            reason,
            replacement: replacementText ? {
                startByte,
                endByte,
                replacementText
            } : null
        };
        if (!autoFixable) {
            Object.assign(finding, initialDiagnosticReview({
                finding,
                tokens,
                pairs: delimiterPairs,
                classIndex,
                closeParenIndex,
                significantArguments,
                directOutput
            }));
        }
        findings.push(finding);
        findingInternals.push({ classIndex, closeParenIndex });
        classIndex = closeParenIndex;
    }

    for (let index = 0; index < findings.length; index += 1) {
        if (findings[index].ruleId === 'WPB-SCF-INDIRECT-USAGE') {
            Object.assign(findings[index], indirectDiagnosticReview({
                finding: findings[index],
                tokens,
                ...findingInternals[index]
            }));
        }
        if (!findings[index].autoFixable) {
            findings[index] = finalizeDiagnosticReview(
                findings[index],
                bytes,
                candidateLintPhpCommand ?? phpCommand
            );
        }
    }

    return {
        tokenizer: {
            available: true,
            ok: true,
            error: null,
            errorCode: null,
            runtime: tokenizer.runtime
        },
        findings,
        canAnalyze: true
    };
}

export const securityAnalyzerInternals = Object.freeze({
    tokenizerPath: path.resolve(TOKENIZER_PATH),
    urlAttributes: URL_ATTRIBUTES,
    reviewDispositions: REVIEW_DISPOSITIONS
});
