import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
    parseNodeToScss
} from './generator.js';

export const FIGMA_GENERATOR_SCHEMA = 1;
export const FIGMA_MAGIC_HEADER = '/* wp-builder:figma-generated';
export const FIGMA_REQUIRED_FORWARD = '@forward "figma-generated";';

const packageJson = JSON.parse(fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
const FIGMA_GENERATOR_VERSION = packageJson.version;
const SECTION_COMMENTS = new Set([
    '/* --- Text Colors --- */',
    '/* --- Background Colors --- */',
    '/* --- Border Radius --- */'
]);
const CATEGORY_ORDER = new Map([
    ['cl', 0],
    ['bg', 1],
    ['rd', 2]
]);

export class FigmaPlanError extends Error {
    constructor(message, exitCode = 1) {
        super(message);
        this.name = 'FigmaPlanError';
        this.exitCode = exitCode;
    }
}

export function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

function freezeDeep(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    Object.freeze(value);
    Object.values(value).forEach(freezeDeep);
    return value;
}

export function takeFileSnapshot(filePath, options = {}) {
    const {
        rejectSymlink = false
    } = options;

    let stat;
    try {
        stat = fs.lstatSync(filePath);
    } catch (error) {
        if (error.code === 'ENOENT') return freezeDeep({
            path: filePath,
            state: 'missing',
            hash: null,
            content: ''
        });
        throw error;
    }

    if (rejectSymlink && stat.isSymbolicLink()) return freezeDeep({
        path: filePath,
        state: 'unsafe',
        reason: 'symbolic links are not valid Figma generated targets',
        hash: null,
        content: ''
    });

    if (!stat.isFile() && !stat.isSymbolicLink()) return freezeDeep({
        path: filePath,
        state: 'unsafe',
        reason: 'target is not a regular file',
        hash: null,
        content: ''
    });

    const bytes = fs.readFileSync(filePath);
    return freezeDeep({
        path: filePath,
        state: 'present',
        hash: sha256(bytes),
        content: bytes.toString('utf8')
    });
}

function normalizeDeclaration(value) {
    return value.replace(/\s+/g, ' ').trim();
}

function comparableOwnedDeclaration(selector, declaration) {
    const selectorMatch = selector.match(/^\.(cl|bg)_([0-9a-fA-F]{6})$/);
    if (!selectorMatch) return normalizeDeclaration(declaration);
    const declarationMatch = declaration.match(/^\s*(color|background-color)\s*:\s*#([0-9a-fA-F]{6})\s*;?\s*$/);
    if (!declarationMatch) return null;
    const expectedProperty = selectorMatch[1] === 'cl' ? 'color' : 'background-color';
    if (declarationMatch[1] !== expectedProperty) return null;
    return `${expectedProperty}: #${declarationMatch[2].toUpperCase()};`;
}

function parseRuleLine(line) {
    const match = line.trim().match(/^(\.(cl|bg|rd)_[A-Za-z0-9_-]+)\s*\{([^{}]*)\}$/);
    if (!match) return null;
    return {
        selector: match[1],
        category: match[2],
        declaration: normalizeDeclaration(match[3]),
        line: line.trim()
    };
}

function compareSelectors(left, right) {
    const categoryDifference = CATEGORY_ORDER.get(left.category) - CATEGORY_ORDER.get(right.category);
    if (categoryDifference !== 0) return categoryDifference;
    return left.selector < right.selector ? -1 : left.selector > right.selector ? 1 : 0;
}

function findTargetNode(figmaFile, nodeId) {
    const findNode = (nodes) => {
        for (const node of nodes) {
            if (node.id === nodeId) return node;
            if (node.children) {
                const found = findNode(node.children);
                if (found) return found;
            }
        }
        return null;
    };

    let targetNode = null;
    for (const page of figmaFile?.document?.children ?? []) {
        const found = findNode(page.children ?? []);
        if (found) targetNode = found;
    }
    return targetNode;
}

function collectGeneratedRules(targetNode) {
    const rules = new Map();
    const diagnostics = [];

    const scan = (nodes) => {
        nodes.forEach(node => {
            const code = parseNodeToScss(node);
            if (code) code.split('\n').forEach(rawLine => {
                const line = rawLine.trim();
                if (!line) return;
                const parsed = parseRuleLine(line);
                if (!parsed) {
                    diagnostics.push({
                        level: 'CONFLICT_UNKNOWN',
                        selector: null,
                        message: `Generated SCSS could not be parsed safely: ${line}`
                    });
                    return;
                }

                const current = rules.get(parsed.selector);
                if (!current) {
                    rules.set(parsed.selector, {
                        ...parsed,
                        declarations: [parsed.declaration]
                    });
                    return;
                }
                if (!current.declarations.includes(parsed.declaration)) current.declarations.push(parsed.declaration);
            });
            if (node.children) scan(node.children);
        });
    };

    scan([targetNode]);
    for (const rule of rules.values()) {
        if (rule.declarations.length > 1) diagnostics.push({
            level: 'CONFLICT',
            selector: rule.selector,
            message: 'Figma generated multiple declarations for the same selector.'
        });
    }

    return {
        rules,
        diagnostics
    };
}

function stripScssComments(content) {
    return content
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/\/\/.*$/gm, '');
}

function resolveScssModuleTarget(currentFile, specifier) {
    const withoutExtension = specifier.replace(/\.scss$/, '');
    const parsed = path.posix.parse(withoutExtension.replace(/\\/g, '/'));
    const partialName = parsed.base.startsWith('_') ? parsed.base : `_${parsed.base}`;
    const targetPosix = path.posix.join(parsed.dir, `${partialName}.scss`);

    return path.resolve(path.dirname(currentFile), ...targetPosix.split('/'));
}

function inspectPublication(scssRoot, targetPath) {
    const indexPath = path.join(scssRoot, 'Component', '_Component.scss');
    const publication = {
        status: 'COMPONENT_INDEX_MISSING',
        indexPath,
        targetPath,
        requiredForward: FIGMA_REQUIRED_FORWARD,
        matchedSpecifiers: [],
        error: null
    };

    try {
        fs.lstatSync(indexPath);
    } catch (error) {
        if (error.code === 'ENOENT') return publication;
        return {
            ...publication,
            status: 'COMPONENT_INDEX_UNREADABLE',
            error: error.message
        };
    }

    let content;
    try {
        content = fs.readFileSync(indexPath, 'utf8');
    } catch (error) {
        return {
            ...publication,
            status: 'COMPONENT_INDEX_UNREADABLE',
            error: error.message
        };
    }

    const matches = [];
    const source = stripScssComments(content);
    const forwardPattern = /@forward\s+(['"])([^'"]+)\1/g;
    let match;
    while ((match = forwardPattern.exec(source)) !== null) {
        if (resolveScssModuleTarget(indexPath, match[2]) === path.resolve(targetPath)) matches.push(match[2]);
    }

    return {
        ...publication,
        status: matches.length === 0 ? 'FORWARD_MISSING' : matches.length === 1 ? 'FORWARD_PRESENT' : 'FORWARD_DUPLICATE',
        matchedSpecifiers: matches
    };
}

function readRuleBlock(content, openBraceIndex) {
    let depth = 0;
    let nested = false;
    for (let index = openBraceIndex; index < content.length; index += 1) {
        if (content[index] === '{') {
            depth += 1;
            if (depth > 1) nested = true;
        } else if (content[index] === '}') {
            depth -= 1;
            if (depth === 0) return {
                body: content.slice(openBraceIndex + 1, index),
                nested,
                endIndex: index
            };
        }
    }
    return null;
}

function indexLegacyRules(content) {
    const source = stripScssComments(content);
    const rules = new Map();
    const selectorPattern = /\.(cl|bg|rd)_[A-Za-z0-9_-]+\s*\{/g;
    let match;
    while ((match = selectorPattern.exec(source)) !== null) {
        const selector = match[0].slice(0, match[0].lastIndexOf('{')).trim();
        const openBraceIndex = source.indexOf('{', match.index);
        const block = readRuleBlock(source, openBraceIndex);
        const definitions = rules.get(selector) ?? [];
        if (!block || block.nested) {
            definitions.push(null);
        } else {
            definitions.push(normalizeDeclaration(block.body));
            selectorPattern.lastIndex = block.endIndex + 1;
        }
        rules.set(selector, definitions);
    }
    return rules;
}

function parseManagedHeader(content) {
    const lines = content.replace(/\r\n/g, '\n').split('\n');
    if (lines[0] !== FIGMA_MAGIC_HEADER) return null;
    const closingIndex = lines.indexOf(' */');
    if (closingIndex === -1) return null;

    const metadata = {};
    for (const line of lines.slice(1, closingIndex)) {
        const match = line.match(/^ \* ([a-z-]+): (.*)$/);
        if (!match) return null;
        metadata[match[1]] = match[2];
    }
    return {
        metadata,
        closingIndex
    };
}

function parseManagedRules(content, header) {
    const rules = new Map();
    const lines = content.replace(/\r\n/g, '\n').split('\n').slice(header.closingIndex + 1);
    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line || SECTION_COMMENTS.has(line)) continue;
        const parsed = parseRuleLine(line);
        if (!parsed || rules.has(parsed.selector)) return null;
        rules.set(parsed.selector, parsed);
    }
    return rules;
}

function buildManagedHeader(fileKey, nodeId) {
    for (const [name, value] of Object.entries({
            'Figma file key': fileKey,
            'node ID': nodeId
        })) {
        if (typeof value !== 'string' || value.length === 0 || /[\r\n]/.test(value)) {
            throw new FigmaPlanError(`${name} is missing or invalid.`);
        }
    }

    return `${FIGMA_MAGIC_HEADER}\n` +
        ' * do-not-edit: true\n' +
        ` * figma-file-key: ${fileKey}\n` +
        ` * figma-node-id: ${nodeId}\n` +
        ` * generator-schema: ${FIGMA_GENERATOR_SCHEMA}\n` +
        ` * generator-version: ${FIGMA_GENERATOR_VERSION}\n` +
        ' */';
}

function renderManagedContent(fileKey, nodeId, rules) {
    const sorted = [...rules].sort(compareSelectors);
    const sections = [{
        category: 'cl',
        title: '/* --- Text Colors --- */'
    }, {
        category: 'bg',
        title: '/* --- Background Colors --- */'
    }, {
        category: 'rd',
        title: '/* --- Border Radius --- */'
    }];
    const lines = [buildManagedHeader(fileKey, nodeId), ''];

    sections.forEach((section, index) => {
        lines.push(section.title);
        sorted.filter(rule => rule.category === section.category).forEach(rule => lines.push(rule.line));
        if (index < sections.length - 1) lines.push('');
    });
    return `${lines.join('\n')}\n`;
}

function contentLines(content) {
    if (!content) return [];
    const lines = content.replace(/\r\n/g, '\n').split('\n');
    if (lines.at(-1) === '') lines.pop();
    return lines;
}

export function createUnifiedDiff(oldContent, newContent, relativePath, isNewFile) {
    if (oldContent === newContent) return '';
    const oldLines = contentLines(oldContent);
    const newLines = contentLines(newContent);
    let prefix = 0;
    while (prefix < oldLines.length && prefix < newLines.length && oldLines[prefix] === newLines[prefix]) prefix += 1;
    let suffix = 0;
    while (
        suffix < oldLines.length - prefix &&
        suffix < newLines.length - prefix &&
        oldLines[oldLines.length - 1 - suffix] === newLines[newLines.length - 1 - suffix]
    ) suffix += 1;

    const context = 3;
    const oldStart = Math.max(0, prefix - context);
    const newStart = Math.max(0, prefix - context);
    const oldChangedEnd = oldLines.length - suffix;
    const newChangedEnd = newLines.length - suffix;
    const oldEnd = Math.min(oldLines.length, oldChangedEnd + context);
    const newEnd = Math.min(newLines.length, newChangedEnd + context);
    const oldCount = oldEnd - oldStart;
    const newCount = newEnd - newStart;
    const oldLabel = isNewFile ? '/dev/null' : `a/${relativePath}`;
    const newLabel = `b/${relativePath}`;
    const oldLineNumber = oldCount === 0 ? 0 : oldStart + 1;
    const newLineNumber = newCount === 0 ? 0 : newStart + 1;
    const output = [oldLabel === '/dev/null' ? '--- /dev/null' : `--- ${oldLabel}`, `+++ ${newLabel}`];
    output.push(`@@ -${oldLineNumber},${oldCount} +${newLineNumber},${newCount} @@`);

    oldLines.slice(oldStart, prefix).forEach(line => output.push(` ${line}`));
    oldLines.slice(prefix, oldChangedEnd).forEach(line => output.push(`-${line}`));
    newLines.slice(prefix, newChangedEnd).forEach(line => output.push(`+${line}`));
    newLines.slice(newChangedEnd, newEnd).forEach(line => output.push(` ${line}`));
    return output.join('\n');
}

function addBlockingDiagnostic(diagnostics, message) {
    diagnostics.push({
        level: 'UNMANAGED_TARGET',
        selector: null,
        message
    });
}

export function buildFigmaSyncPlan({
    figmaFile,
    fileKey,
    nodeId,
    projectType,
    scssRoot
}) {
    const targetNode = findTargetNode(figmaFile, nodeId);
    if (!targetNode) throw new FigmaPlanError(`Figma node ID ${nodeId} was not found.`);

    const targetPath = path.join(scssRoot, 'Component', '_figma-generated.scss');
    const colorPath = path.join(scssRoot, 'Component', '_colorS.scss');
    const publication = inspectPublication(scssRoot, targetPath);
    const targetSnapshot = takeFileSnapshot(targetPath, {
        rejectSymlink: true
    });
    const colorSnapshot = takeFileSnapshot(colorPath);
    const diagnostics = [];
    const generated = collectGeneratedRules(targetNode);
    diagnostics.push(...generated.diagnostics);

    let currentRules = new Map();
    let managedHeader = null;
    if (targetSnapshot.state === 'unsafe') {
        addBlockingDiagnostic(diagnostics, targetSnapshot.reason);
    } else if (targetSnapshot.state === 'present') {
        managedHeader = parseManagedHeader(targetSnapshot.content);
        if (!managedHeader) {
            addBlockingDiagnostic(diagnostics, 'Existing target does not contain a valid wp-builder Figma generated header.');
        } else if (managedHeader.metadata['do-not-edit'] !== 'true') {
            addBlockingDiagnostic(diagnostics, 'Existing target is missing do-not-edit: true.');
        } else if (managedHeader.metadata['generator-schema'] !== String(FIGMA_GENERATOR_SCHEMA)) {
            addBlockingDiagnostic(diagnostics, `Unsupported generator schema: ${managedHeader.metadata['generator-schema'] ?? 'missing'}`);
        } else if (managedHeader.metadata['figma-file-key'] !== fileKey || managedHeader.metadata['figma-node-id'] !== nodeId) {
            addBlockingDiagnostic(diagnostics, 'Existing target belongs to a different Figma file key or node ID.');
        } else {
            const parsedRules = parseManagedRules(targetSnapshot.content, managedHeader);
            if (!parsedRules) addBlockingDiagnostic(diagnostics, 'Existing managed target contains invalid or duplicate generated rules.');
            else currentRules = parsedRules;
        }
    }
    if (colorSnapshot.state === 'unsafe') addBlockingDiagnostic(diagnostics, colorSnapshot.reason);

    const legacyRules = colorSnapshot.state === 'present' ? indexLegacyRules(colorSnapshot.content) : new Map();
    const eligibleRules = [];
    const rows = [];
    const existingOwnershipConflicts = new Set();

    for (const current of currentRules.values()) {
        const legacyDefinitions = legacyRules.get(current.selector);
        if (!legacyDefinitions) continue;
        existingOwnershipConflicts.add(current.selector);
        diagnostics.push({
            level: legacyDefinitions.some(value => value === null) ? 'CONFLICT_UNKNOWN' : 'CONFLICT',
            selector: current.selector,
            message: 'Selector is already owned by both legacy _colorS.scss and the Figma generated target.'
        });
    }

    for (const rule of generated.rules.values()) {
        if (rule.declarations.length > 1) {
            rows.push({
                selector: rule.selector,
                line: rule.line,
                status: 'CONFLICT'
            });
            continue;
        }

        const legacyDefinitions = legacyRules.get(rule.selector);
        if (legacyDefinitions) {
            const currentGeneratedRule = currentRules.get(rule.selector);
            if (currentGeneratedRule) {
                rows.push({
                    selector: rule.selector,
                    line: rule.line,
                    status: 'CONFLICT'
                });
            } else if (legacyDefinitions.some(value => value === null)) {
                diagnostics.push({
                    level: 'CONFLICT_UNKNOWN',
                    selector: rule.selector,
                    message: 'Legacy declaration is too complex to compare safely.'
                });
                rows.push({
                    selector: rule.selector,
                    line: rule.line,
                    status: 'CONFLICT_UNKNOWN'
                });
            } else {
                const generatedComparable = comparableOwnedDeclaration(rule.selector, rule.declaration);
                const legacyComparable = legacyDefinitions.map(value => comparableOwnedDeclaration(rule.selector, value));
                if (generatedComparable === null || legacyComparable.some(value => value === null)) {
                    diagnostics.push({
                        level: 'CONFLICT_UNKNOWN',
                        selector: rule.selector,
                        message: 'Legacy declaration is too complex to compare safely.'
                    });
                    rows.push({
                        selector: rule.selector,
                        line: rule.line,
                        status: 'CONFLICT_UNKNOWN'
                    });
                } else if (legacyComparable.every(value => value === generatedComparable)) {
                    rows.push({
                        selector: rule.selector,
                        line: rule.line,
                        status: 'OWNED_SAME'
                    });
                } else {
                    diagnostics.push({
                        level: 'CONFLICT',
                        selector: rule.selector,
                        message: 'Figma declaration differs from the legacy _colorS.scss declaration.'
                    });
                    rows.push({
                        selector: rule.selector,
                        line: rule.line,
                        status: 'CONFLICT'
                    });
                }
            }
            continue;
        }

        eligibleRules.push(rule);
        const current = currentRules.get(rule.selector);
        rows.push({
            selector: rule.selector,
            line: rule.line,
            status: !current ? 'ADD' : current.declaration === rule.declaration ? 'UNCHANGED' : 'CHANGE'
        });
    }

    for (const current of currentRules.values()) {
        if (!generated.rules.has(current.selector)) rows.push({
            selector: current.selector,
            line: current.line,
            status: existingOwnershipConflicts.has(current.selector) ? 'CONFLICT' : 'REMOVE'
        });
    }

    const desiredContent = renderManagedContent(fileKey, nodeId, eligibleRules);
    const shouldCreateInitialFile = targetSnapshot.state !== 'missing' || eligibleRules.length > 0;
    const hasChanges = shouldCreateInitialFile && targetSnapshot.content !== desiredContent;
    const relativePath = 'scss/Component/_figma-generated.scss';
    const diff = hasChanges ? createUnifiedDiff(targetSnapshot.content, desiredContent, relativePath, targetSnapshot.state === 'missing') : '';
    const hasConflict = diagnostics.some(item => item.level === 'CONFLICT' || item.level === 'CONFLICT_UNKNOWN');
    const hasUnsafeTarget = diagnostics.some(item => item.level === 'UNMANAGED_TARGET');
    const counts = rows.reduce((result, row) => {
        result[row.status] = (result[row.status] ?? 0) + 1;
        return result;
    }, {});

    return freezeDeep({
        source: {
            fileKey,
            nodeId,
            nodeName: targetNode.name ?? 'unknown',
            nodeType: targetNode.type ?? 'unknown'
        },
        projectType,
        targetPath,
        colorPath,
        publication,
        targetSnapshot,
        colorSnapshot,
        rows,
        diagnostics,
        counts,
        content: desiredContent,
        contentHash: sha256(Buffer.from(desiredContent, 'utf8')),
        diff,
        hasChanges,
        hasConflict,
        hasUnsafeTarget,
        canApply: !hasConflict && !hasUnsafeTarget
    });
}
