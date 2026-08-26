import fs from 'node:fs';
import path from 'node:path';
import {
    toPosixPath,
    ensureFile
} from '../utils/fs-helper.js';
import {
    ensureTemplateFiles
} from './generator.js';
import {
    getProjectContext
} from './project-context.js';

const {
    scssRoot
} = getProjectContext();
const colorSPath = path.join(scssRoot, 'Component', '_colorS.scss');
const figmaGeneratedPath = path.resolve(scssRoot, 'Component', '_figma-generated.scss');
const phpP = [/get_template_part\s*\(\s*(['"])([^'"]+)\1/g, /include_once\s*\(\s*(['"])([^'"]+)\1\s*\)/g];

function parseComparableColorDeclaration(body) {
    const match = body.match(/^\s*(color|background-color)\s*:\s*#([0-9a-fA-F]{6})\s*;?\s*$/);
    if (!match) return null;
    return {
        property: match[1],
        hex: match[2].toUpperCase()
    };
}

function readRuleBlock(content, openBraceIndex) {
    let depth = 0;
    let hasNestedBlock = false;
    for (let i = openBraceIndex; i < content.length; i += 1) {
        if (content[i] === '{') {
            depth += 1;
            if (depth > 1) hasNestedBlock = true;
        } else if (content[i] === '}') {
            depth -= 1;
            if (depth === 0) return {
                body: content.slice(openBraceIndex + 1, i),
                hasNestedBlock,
                endIndex: i
            };
        }
    }
    return null;
}

function readFigmaOwnedSelectors() {
    if (!fs.existsSync(figmaGeneratedPath)) return new Map();

    let content;
    try {
        content = fs.readFileSync(figmaGeneratedPath, 'utf8');
    } catch (error) {
        console.error(`[ERROR] Unable to read Figma ownership file: ${figmaGeneratedPath}`);
        console.error(`  ${error.message}`);
        return null;
    }

    const withoutComments = content
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/\/\/.*$/gm, '');
    const rules = new Map();
    const selectorPattern = /\.(cl|bg)_([0-9a-fA-F]{6})\s*\{/g;
    let match;
    while ((match = selectorPattern.exec(withoutComments)) !== null) {
        const selector = `${match[1]}_${match[2]}`;
        const openBraceIndex = withoutComments.indexOf('{', match.index);
        const block = readRuleBlock(withoutComments, openBraceIndex);
        const definitions = rules.get(selector) ?? [];

        if (!block || block.hasNestedBlock) {
            definitions.push(null);
        } else {
            definitions.push(parseComparableColorDeclaration(block.body));
            selectorPattern.lastIndex = block.endIndex + 1;
        }
        rules.set(selector, definitions);
    }

    return rules;
}

function expectedColorDeclaration(type, hex) {
    return {
        property: type === 'cl' ? 'color' : 'background-color',
        hex: hex.toUpperCase()
    };
}

function compareOwnedDeclaration(definitions, expected) {
    if (definitions.some(definition => definition === null)) return 'unknown';
    return definitions.every(definition =>
        definition.property === expected.property && definition.hex === expected.hex
    ) ? 'same' : 'different';
}

function reportColorOwnershipConflict(level, sourceFile, sourceSelector, outputSelector, expected, details) {
    console.error(`[${level}] Color selector ownership conflict: .${sourceSelector}`);
    console.error(`  usage: ${sourceFile}`);
    console.error(`  scanner output: .${outputSelector} { ${expected.property}: #${expected.hex}; }`);
    console.error(`  owner: figma (${figmaGeneratedPath})`);
    console.error(`  ${details}`);
    console.error('  action: _colorS.scss was not changed for this selector');
}

function normalizeForwardTarget(currentFile, specifier) {
    const withoutExtension = specifier.replace(/\.scss$/, '');
    const parsed = path.posix.parse(toPosixPath(withoutExtension));
    const partialName = parsed.base.startsWith('_') ? parsed.base : `_${parsed.base}`;
    const targetPosix = path.posix.join(parsed.dir, `${partialName}.scss`);

    return path.resolve(path.dirname(currentFile), ...targetPosix.split('/'));
}

function stripScssComments(source) {
    return source
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/\/\/.*$/gm, '');
}

function hasActiveFigmaManagedForward(currentFile, source) {
    const activeSource = stripScssComments(source);
    const forwardPattern = /@forward\s+(['"])([^'"]+)\1/g;
    let match;
    while ((match = forwardPattern.exec(activeSource)) !== null) {
        if (normalizeForwardTarget(currentFile, match[2]) === figmaGeneratedPath) return true;
    }
    return false;
}

function reportMissingFigmaManagedTarget(sourceFile) {
    console.warn('[MISSING_MANAGED_TARGET] Managed SCSS target is missing.');
    console.warn(`  source: ${sourceFile}`);
    console.warn(`  target: ${figmaGeneratedPath}`);
    console.warn('  owner: figma');
    console.warn('  action: run "wp-builder figma:sync --page <id>" to preview,');
    console.warn('          then use "--apply" after review');
}

export function scanPhpFile(f) {
    const src = fs.readFileSync(f, 'utf8');
    phpP.forEach(reg => {
        let m;
        while ((m = reg.exec(src)) !== null) ensureTemplateFiles(m[2]);
    });
}

export function scanScssFile(f) {
    const src = fs.readFileSync(f, 'utf8');
    const hasActiveManagedForward = hasActiveFigmaManagedForward(f, src);
    let reportedMissingManagedTarget = false;
    const reg = /@forward\s+(['"])([^'"]+)\1/g;
    let m;
    while ((m = reg.exec(src)) !== null) {
        const target = normalizeForwardTarget(f, m[2]);
        if (target === figmaGeneratedPath) {
            if (
                hasActiveManagedForward &&
                !reportedMissingManagedTarget &&
                !fs.existsSync(figmaGeneratedPath)
            ) {
                reportMissingFigmaManagedTarget(f);
                reportedMissingManagedTarget = true;
            }
            continue;
        }
        ensureFile(target, '');
    }
}

export function scanColorUtilities(f) {
    if (path.resolve(f) === figmaGeneratedPath) return;

    const figmaOwnedSelectors = readFigmaOwnedSelectors();
    // The ownership file exists but could not be read. Fail closed rather than
    // generating a potentially conflicting selector in _colorS.scss.
    if (figmaOwnedSelectors === null) return;

    const src = fs.readFileSync(f, 'utf8');
    const found = new Map();
    let m;
    const reg = /\b(cl|bg)_([0-9a-fA-F]{6})\b/g;
    while ((m = reg.exec(src)) !== null) {
        const sourceSelector = `${m[1]}_${m[2]}`;
        found.set(sourceSelector, {
            type: m[1],
            hex: m[2],
            sourceSelector,
            outputSelector: `${m[1]}_${m[2].toUpperCase()}`
        });
    }
    if (found.size === 0) return;

    const cur = fs.existsSync(colorSPath) ? fs.readFileSync(colorSPath, 'utf8') : '';
    const plannedOutputs = new Map();

    for (const value of found.values()) {
        const expected = expectedColorDeclaration(value.type, value.hex);
        const sourceDefinitions = figmaOwnedSelectors.get(value.sourceSelector);
        const outputDefinitions = value.outputSelector === value.sourceSelector ?
            sourceDefinitions : figmaOwnedSelectors.get(value.outputSelector);

        if (sourceDefinitions && outputDefinitions && value.sourceSelector !== value.outputSelector) {
            reportColorOwnershipConflict(
                'CONFLICT',
                f,
                value.sourceSelector,
                value.outputSelector,
                expected,
                'both sourceSelector and outputSelector are owned by Figma'
            );
            continue;
        }

        const ownedDefinitions = sourceDefinitions ?? outputDefinitions;
        if (ownedDefinitions) {
            const comparison = compareOwnedDeclaration(ownedDefinitions, expected);
            if (comparison === 'different') {
                reportColorOwnershipConflict(
                    'CONFLICT',
                    f,
                    value.sourceSelector,
                    value.outputSelector,
                    expected,
                    'the Figma declaration differs from the scanner declaration'
                );
            } else if (comparison === 'unknown') {
                reportColorOwnershipConflict(
                    'CONFLICT_UNKNOWN',
                    f,
                    value.sourceSelector,
                    value.outputSelector,
                    expected,
                    'the Figma declaration is too complex to compare safely'
                );
            }
            continue;
        }

        plannedOutputs.set(value.outputSelector, value);
    }

    let add = '';
    for (const [selector, value] of plannedOutputs)
        if (!cur.includes(`.${selector}`)) add += `.${selector} { ${value.type === 'cl' ? 'color' : 'background-color'}: #${value.hex}; }\n\n`;
    if (add) {
        fs.mkdirSync(path.dirname(colorSPath), {
            recursive: true
        });
        fs.appendFileSync(colorSPath, add);
    }
}
