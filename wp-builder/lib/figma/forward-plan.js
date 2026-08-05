import fs from 'node:fs';
import path from 'node:path';
import {
    TextDecoder
} from 'node:util';
import {
    FIGMA_GENERATOR_SCHEMA,
    FIGMA_MAGIC_HEADER,
    FIGMA_REQUIRED_FORWARD,
    createUnifiedDiff,
    sha256
} from './sync-plan.js';

const SECTION_COMMENTS = new Set([
    '/* --- Text Colors --- */',
    '/* --- Background Colors --- */',
    '/* --- Border Radius --- */'
]);

function freezeDeep(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    Object.freeze(value);
    Object.values(value).forEach(freezeDeep);
    return value;
}

export function takeForwardFileSnapshot(filePath) {
    let stat;
    try {
        stat = fs.lstatSync(filePath);
    } catch (error) {
        if (error.code === 'ENOENT') return freezeDeep({
            path: filePath,
            state: 'missing',
            hash: null,
            content: '',
            reason: null
        });
        return freezeDeep({
            path: filePath,
            state: 'unreadable',
            hash: null,
            content: '',
            reason: error.message
        });
    }

    if (stat.isSymbolicLink() || !stat.isFile()) return freezeDeep({
        path: filePath,
        state: 'unsafe',
        hash: null,
        content: '',
        reason: stat.isSymbolicLink() ? 'symbolic links are not supported' : 'path is not a regular file'
    });

    let bytes;
    try {
        bytes = fs.readFileSync(filePath);
        new TextDecoder('utf-8', {
            fatal: true
        }).decode(bytes);
    } catch (error) {
        return freezeDeep({
            path: filePath,
            state: 'unreadable',
            hash: null,
            content: '',
            reason: error.message
        });
    }

    return freezeDeep({
        path: filePath,
        state: 'present',
        hash: sha256(bytes),
        content: bytes.toString('utf8'),
        reason: null
    });
}

function resolveScssModuleTarget(currentFile, specifier) {
    const withoutExtension = specifier.replace(/\.scss$/, '');
    const parsed = path.posix.parse(withoutExtension.replace(/\\/g, '/'));
    const partialName = parsed.base.startsWith('_') ? parsed.base : `_${parsed.base}`;
    const targetPosix = path.posix.join(parsed.dir, `${partialName}.scss`);

    return path.resolve(path.dirname(currentFile), ...targetPosix.split('/'));
}

function readQuotedString(source, start) {
    const quote = source[start];
    let value = '';
    for (let index = start + 1; index < source.length; index += 1) {
        const current = source[index];
        if (current === '\\') {
            if (index + 1 >= source.length) return {
                unsafe: true,
                reason: 'unterminated escape sequence in a quoted string'
            };
            // Sass supports richer escapes than this tool can canonicalize safely.
            return {
                unsafe: true,
                reason: 'escaped module URLs cannot be compared safely'
            };
        }
        if (current === quote) return {
            unsafe: false,
            value,
            end: index + 1
        };
        if (current === '\r' || current === '\n') return {
            unsafe: true,
            reason: 'unterminated quoted string'
        };
        value += current;
    }
    return {
        unsafe: true,
        reason: 'unterminated quoted string'
    };
}

function skipDirectiveTrivia(source, start) {
    let index = start;
    while (index < source.length) {
        if (/\s/.test(source[index])) {
            index += 1;
            continue;
        }
        if (source.startsWith('//', index)) {
            const newline = source.indexOf('\n', index + 2);
            index = newline === -1 ? source.length : newline + 1;
            continue;
        }
        if (source.startsWith('/*', index)) {
            const end = source.indexOf('*/', index + 2);
            if (end === -1) return {
                unsafe: true,
                reason: 'unterminated block comment'
            };
            index = end + 2;
            continue;
        }
        break;
    }
    return {
        unsafe: false,
        index
    };
}

function parseForwardSpecifier(statement) {
    const directiveEnd = '@forward'.length;
    const trivia = skipDirectiveTrivia(statement, directiveEnd);
    if (trivia.unsafe) return trivia;
    const quote = statement[trivia.index];
    if (quote !== '"' && quote !== "'") return {
        unsafe: true,
        reason: '@forward does not use a supported quoted module URL'
    };
    return readQuotedString(statement, trivia.index);
}

function scanTopLevelStatements(source) {
    const statements = [];
    const braceStack = [];
    let parentheses = 0;
    let brackets = 0;
    let statementStart = null;
    let index = 0;

    const unsafe = reason => ({
        unsafe: true,
        reason,
        statements: []
    });

    const completeStatement = end => {
        const text = source.slice(statementStart, end);
        const type = /^@forward\b/.test(text) ? 'forward' : /^@use\b/.test(text) ? 'use' : 'other';
        statements.push({
            start: statementStart,
            end,
            text,
            type
        });
        statementStart = null;
    };

    while (index < source.length) {
        const current = source[index];

        if (source.startsWith('//', index)) {
            const newline = source.indexOf('\n', index + 2);
            index = newline === -1 ? source.length : newline;
            continue;
        }
        if (source.startsWith('/*', index)) {
            const end = source.indexOf('*/', index + 2);
            if (end === -1) return unsafe('unterminated block comment');
            index = end + 2;
            continue;
        }
        if (current === '"' || current === "'") {
            if (statementStart === null) statementStart = index;
            const quote = current;
            index += 1;
            let closed = false;
            while (index < source.length) {
                if (source[index] === '\\') {
                    if (index + 1 >= source.length) return unsafe('unterminated escape sequence in a quoted string');
                    index += 2;
                    continue;
                }
                if (source[index] === quote) {
                    index += 1;
                    closed = true;
                    break;
                }
                if (source[index] === '\r' || source[index] === '\n') return unsafe('unterminated quoted string');
                index += 1;
            }
            if (!closed) return unsafe('unterminated quoted string');
            continue;
        }

        if (statementStart === null && (/\s/.test(current) || current === '\uFEFF')) {
            index += 1;
            continue;
        }
        if (statementStart === null) statementStart = index;

        if (current === '(') parentheses += 1;
        else if (current === ')') {
            parentheses -= 1;
            if (parentheses < 0) return unsafe('unmatched closing parenthesis');
        } else if (current === '[') brackets += 1;
        else if (current === ']') {
            brackets -= 1;
            if (brackets < 0) return unsafe('unmatched closing bracket');
        } else if (current === '{') {
            braceStack.push(index > 0 && source[index - 1] === '#' ? 'interpolation' : 'block');
        } else if (current === '}') {
            if (braceStack.length === 0) return unsafe('unmatched closing brace');
            const closedBrace = braceStack.pop();
            if (
                closedBrace === 'block' &&
                braceStack.length === 0 &&
                parentheses === 0 &&
                brackets === 0
            ) completeStatement(index + 1);
        } else if (
            current === ';' &&
            braceStack.length === 0 &&
            parentheses === 0 &&
            brackets === 0
        ) completeStatement(index + 1);

        index += 1;
    }

    if (braceStack.length > 0) return unsafe('unterminated brace block');
    if (parentheses !== 0) return unsafe('unterminated parenthesized expression');
    if (brackets !== 0) return unsafe('unterminated bracket expression');
    if (statementStart !== null) return unsafe('unterminated top-level statement');

    return {
        unsafe: false,
        reason: null,
        statements
    };
}

function chooseNearbyEol(source, offset) {
    const prefixMatches = [...source.slice(0, offset).matchAll(/\r\n|\n/g)];
    if (prefixMatches.length > 0) return prefixMatches.at(-1)[0];
    const suffixMatch = source.slice(offset).match(/\r\n|\n/);
    return suffixMatch ? suffixMatch[0] : '\n';
}

function insertCanonicalForward(source, offset, options = {}) {
    const {
        preserveFollowingTrivia = false
    } = options;
    const eol = chooseNearbyEol(source, offset);
    if (source.length === 0) return `${FIGMA_REQUIRED_FORWARD}${eol}`;

    const prefix = source.slice(0, offset);
    const suffix = source.slice(offset);
    const prefixEndsWithEol = /(?:\r\n|\n)$/.test(prefix);
    const suffixStartsWithEol = /^(?:\r\n|\n)/.test(suffix);
    const sourceEndsWithEol = /(?:\r\n|\n)$/.test(source);
    const prefixIsOnlyBom = prefix === '\uFEFF';
    const leading = prefix.length > 0 && !prefixIsOnlyBom && !prefixEndsWithEol ? eol : '';
    let trailing = '';
    if (preserveFollowingTrivia) trailing = eol;
    else if (suffix.length > 0 && !suffixStartsWithEol) trailing = eol;
    else if (suffix.length === 0 && sourceEndsWithEol) trailing = eol;

    return `${prefix}${leading}${FIGMA_REQUIRED_FORWARD}${trailing}${suffix}`;
}

function findStatementLineStart(source, statementStart) {
    const previousNewline = source.lastIndexOf('\n', statementStart - 1);
    const lineStart = previousNewline === -1 ? 0 : previousNewline + 1;
    const indentationStart = lineStart === 0 && source[0] === '\uFEFF' ? 1 : lineStart;
    return /^[ \t]*$/.test(source.slice(indentationStart, statementStart)) ? indentationStart : statementStart;
}

function findOffsetAfterStatementLine(source, statementEnd) {
    let index = statementEnd;
    while (index < source.length) {
        if (source.startsWith('//', index)) {
            const newline = source.indexOf('\n', index + 2);
            return newline === -1 ? {
                offset: source.length,
                passedLineEnding: false
            } : {
                offset: newline + 1,
                passedLineEnding: true
            };
        }
        if (source.startsWith('/*', index)) {
            const end = source.indexOf('*/', index + 2);
            if (end === -1) return {
                offset: statementEnd,
                passedLineEnding: false
            };
            index = end + 2;
            continue;
        }
        if (source.startsWith('\r\n', index)) return {
            offset: index + 2,
            passedLineEnding: true
        };
        if (source[index] === '\n') return {
            offset: index + 1,
            passedLineEnding: true
        };
        if (source[index] === ' ' || source[index] === '\t' || source[index] === '\r') {
            index += 1;
            continue;
        }
        break;
    }
    return {
        offset: index,
        passedLineEnding: false
    };
}

function analyzeComponentIndex(source, indexPath, targetPath) {
    const scan = scanTopLevelStatements(source);
    if (scan.unsafe) return {
        unsafe: true,
        reason: scan.reason
    };

    const forwardStatements = scan.statements.filter(statement => statement.type === 'forward');
    const matches = [];
    for (const statement of forwardStatements) {
        const parsed = parseForwardSpecifier(statement.text);
        if (parsed.unsafe) return {
            unsafe: true,
            reason: parsed.reason
        };
        if (resolveScssModuleTarget(indexPath, parsed.value) === targetPath) matches.push(parsed.value);
    }

    if (matches.length > 0) return {
        unsafe: false,
        publicationStatus: matches.length === 1 ? 'FORWARD_PRESENT' : 'FORWARD_DUPLICATE',
        matchedSpecifiers: matches,
        desiredContent: source,
        insertionOffset: null
    };

    const lastForward = forwardStatements.at(-1);
    let insertionOffset;
    let preserveFollowingTrivia = false;
    if (lastForward) {
        const afterStatement = findOffsetAfterStatementLine(source, lastForward.end);
        insertionOffset = afterStatement.offset;
        preserveFollowingTrivia = afterStatement.passedLineEnding;
    } else {
        const firstUse = scan.statements.find(statement => statement.type === 'use');
        const firstRelevantStatement = firstUse ?? scan.statements[0];
        insertionOffset = firstRelevantStatement ?
            findStatementLineStart(source, firstRelevantStatement.start) : source.length;
    }

    return {
        unsafe: false,
        publicationStatus: 'FORWARD_MISSING',
        matchedSpecifiers: [],
        desiredContent: insertCanonicalForward(source, insertionOffset, {
            preserveFollowingTrivia
        }),
        insertionOffset
    };
}

function validateManagedTarget(content) {
    const lines = content.replace(/\r\n/g, '\n').split('\n');
    if (lines[0] !== FIGMA_MAGIC_HEADER) return 'missing wp-builder Figma generated magic header';
    const closingIndex = lines.indexOf(' */');
    if (closingIndex === -1) return 'invalid wp-builder Figma generated header';

    const metadata = {};
    for (const line of lines.slice(1, closingIndex)) {
        const match = line.match(/^ \* ([a-z-]+): (.*)$/);
        if (!match) return 'invalid wp-builder Figma generated metadata';
        metadata[match[1]] = match[2];
    }
    if (metadata['do-not-edit'] !== 'true') return 'missing do-not-edit: true';
    if (!metadata['figma-file-key']) return 'missing Figma file key metadata';
    if (!metadata['figma-node-id']) return 'missing Figma node ID metadata';
    if (metadata['generator-schema'] !== String(FIGMA_GENERATOR_SCHEMA)) {
        return `unsupported generator schema: ${metadata['generator-schema'] ?? 'missing'}`;
    }
    if (!metadata['generator-version']) return 'missing generator version metadata';

    const selectors = new Set();
    for (const rawLine of lines.slice(closingIndex + 1)) {
        const line = rawLine.trim();
        if (!line || SECTION_COMMENTS.has(line)) continue;
        const rule = line.match(/^(\.(?:cl|bg|rd)_[A-Za-z0-9_-]+)\s*\{[^{}]*\}$/);
        if (!rule) return `invalid generated rule: ${line}`;
        if (selectors.has(rule[1])) return `duplicate generated selector: ${rule[1]}`;
        selectors.add(rule[1]);
    }
    return null;
}

function addFinding(findings, code, message, exitCode, blocking = true) {
    findings.push({
        code,
        message,
        exitCode,
        blocking
    });
}

export function buildFigmaForwardPlan({
    projectType,
    scssRoot
}) {
    const indexPath = path.resolve(scssRoot, 'Component', '_Component.scss');
    const targetPath = path.resolve(scssRoot, 'Component', '_figma-generated.scss');
    const indexSnapshot = takeForwardFileSnapshot(indexPath);
    const targetSnapshot = takeForwardFileSnapshot(targetPath);
    const findings = [];
    let publicationStatus;
    let targetStatus;
    let matchedSpecifiers = [];
    let desiredContent = indexSnapshot.content;
    let insertionOffset = null;

    if (indexSnapshot.state === 'missing') {
        publicationStatus = 'COMPONENT_INDEX_MISSING';
        addFinding(findings, publicationStatus, '_Component.scss does not exist and will not be created automatically.', 5);
    } else if (indexSnapshot.state === 'unreadable') {
        publicationStatus = 'COMPONENT_INDEX_UNREADABLE';
        addFinding(findings, publicationStatus, indexSnapshot.reason, 1);
    } else if (indexSnapshot.state === 'unsafe') {
        publicationStatus = 'COMPONENT_INDEX_UNSAFE';
        addFinding(findings, publicationStatus, indexSnapshot.reason, 5);
    } else {
        const analysis = analyzeComponentIndex(indexSnapshot.content, indexPath, targetPath);
        if (analysis.unsafe) {
            publicationStatus = 'COMPONENT_INDEX_PARSE_UNSAFE';
            addFinding(findings, publicationStatus, analysis.reason, 5);
        } else {
            publicationStatus = analysis.publicationStatus;
            matchedSpecifiers = analysis.matchedSpecifiers;
            desiredContent = analysis.desiredContent;
            insertionOffset = analysis.insertionOffset;
            if (publicationStatus === 'FORWARD_DUPLICATE') {
                addFinding(findings, publicationStatus, 'Multiple @forward rules resolve to the Figma managed target. No rules were removed.', 2);
            }
        }
    }

    if (targetSnapshot.state === 'missing') {
        targetStatus = 'TARGET_MISSING';
        addFinding(
            findings,
            targetStatus,
            'Run "wp-builder figma:sync --page <id> --apply" before publishing the generated module.',
            2
        );
    } else if (targetSnapshot.state === 'unreadable') {
        targetStatus = 'TARGET_UNREADABLE';
        addFinding(findings, targetStatus, targetSnapshot.reason, 1);
    } else if (targetSnapshot.state === 'unsafe') {
        targetStatus = 'TARGET_UNMANAGED';
        addFinding(findings, targetStatus, targetSnapshot.reason, 5);
    } else {
        const validationError = validateManagedTarget(targetSnapshot.content);
        if (validationError) {
            targetStatus = 'TARGET_UNMANAGED';
            addFinding(findings, targetStatus, validationError, 5);
        } else {
            targetStatus = 'TARGET_MANAGED';
        }
    }

    addFinding(
        findings,
        'UPSTREAM_USAGE_UNVERIFIED',
        'This tool cannot verify that _Component.scss is loaded by the project top-level SCSS entrypoint.',
        0,
        false
    );

    const hasChanges = publicationStatus === 'FORWARD_MISSING' && desiredContent !== indexSnapshot.content;
    const diff = hasChanges ? createUnifiedDiff(
        indexSnapshot.content,
        desiredContent,
        'scss/Component/_Component.scss',
        false
    ) : '';
    const blockingFindings = findings.filter(finding => finding.blocking);
    const canApply = blockingFindings.length === 0;

    return freezeDeep({
        kind: 'figma-forward',
        projectType,
        indexPath,
        targetPath,
        requiredForward: FIGMA_REQUIRED_FORWARD,
        publicationStatus,
        targetStatus,
        matchedSpecifiers,
        findings,
        indexSnapshot,
        targetSnapshot,
        insertionOffset,
        currentContent: indexSnapshot.content,
        desiredContent,
        desiredHash: sha256(Buffer.from(desiredContent, 'utf8')),
        diff,
        hasChanges,
        canApply,
        blockingExitCode: blockingFindings.reduce((code, finding) => Math.max(code, finding.exitCode), 0)
    });
}
