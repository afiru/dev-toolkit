#!/usr/bin/env node

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
  watch
} from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const wpThemeRoot = path.join(root, 'public', 'wp-content', 'themes', 'WebPTemplatebyMarcat');
const projectRoot = existsSync(wpThemeRoot) ? wpThemeRoot : root;
const mode = process.argv.includes('--watch') ? 'watch' : 'scan';
const ignoredDirs = new Set(['.git', '.vscode', 'node_modules', 'vendor', 'work', 'outputs']);

const phpTemplatePartPattern = /get_template_part\s*\(\s*(['"])([^'"]+)\1/g;
const phpIncludeOncePattern = /include_once\s*\(\s*(['"])([^'"]+)\1\s*\)/g;
const scssForwardPattern = /@forward\s+(['"])([^'"]+)\1/g;
const colorUtilityPattern = /\b(cl|bg)_([0-9a-fA-F]{6})\b/g;
const securityScanMode = process.argv.includes('--security-scan');
const escapedScfPattern = /(esc_html|esc_url|esc_attr|wp_kses_post|esc_textarea)\s*\([^)]*SCF::get\s*\(/;
const scfGetPattern = /SCF::get\s*\(\s*(['"])([^'"]+)\1\s*\)/g;
const colorSPath = path.join(projectRoot, 'scss', 'Component', '_colorS.scss');

function toPosixPath(value) {
  return value.replace(/\\/g, '/');
}

function walkFiles(dir, extensions, files = []) {
  if (!existsSync(dir)) {
    return files;
  }

  for (const entry of readdirSync(dir, {
      withFileTypes: true
    })) {
    if (entry.isDirectory()) {
      if (!ignoredDirs.has(entry.name)) {
        walkFiles(path.join(dir, entry.name), extensions, files);
      }
      continue;
    }

    if (entry.isFile() && extensions.has(path.extname(entry.name))) {
      files.push(path.join(dir, entry.name));
    }
  }

  return files;
}

function ensureFile(filePath, contents) {
  if (existsSync(filePath)) {
    return false;
  }

  mkdirSync(path.dirname(filePath), {
    recursive: true
  });
  writeFileSync(filePath, contents, 'utf8');
  console.log(`created ${toPosixPath(path.relative(root, filePath))}`);
  return true;
}

function phpStub(templatePart) {
  const name = path.basename(templatePart);
  return `<?php
/**
 * Template part: ${name}
 */
?>
`;
}

function scssStub(name) {
  return `/* ==========================================================================
   use＆nameSpace
   ========================================================================== */
@use "../../Functions/mixin" as mi;

/* ==========================================================================
   LAYOUT
   ========================================================================== */

.${name} {
}
`;
}

function normalizeTemplatePath(templatePart) {
  return toPosixPath(templatePart)
    .replace(/\.php$/, '')
    .replace(/^\/+/, '');
}

function isManagedTemplate(templatePart) {
  return (
    templatePart.startsWith('include/layouts/') ||
    templatePart.startsWith('include/common/')
  );
}

function buildScssPathFromTemplatePart(templatePart) {
  const normalized = normalizeTemplatePath(templatePart);
  const prefix = 'include/layouts/';

  if (!normalized.startsWith(prefix)) {
    return null;
  }

  const parts = normalized.slice(prefix.length).split('/').filter(Boolean);
  if (parts.length < 2) {
    return null;
  }

  const fileName = parts.pop();
  return path.join(projectRoot, 'scss', 'Layout', ...parts, `_${fileName}.scss`);
}

function ensureScssForwardIndex(scssPath) {
  const dir = path.dirname(scssPath);
  const dirName = path.basename(dir);
  const indexPath = path.join(dir, `_${dirName}.scss`);
  const partialName = path.basename(scssPath, '.scss');
  const forwardLine = `@forward "${partialName}";`;

  if (!existsSync(indexPath)) {
    mkdirSync(dir, {
      recursive: true
    });
    writeFileSync(indexPath, `${forwardLine}\n`, 'utf8');
    console.log(`created ${toPosixPath(path.relative(root, indexPath))}`);
    return;
  }

  const current = readFileSync(indexPath, 'utf8');

  if (current.includes(forwardLine) || current.includes(`@forward '${partialName}';`)) {
    return;
  }

  const prefix = current.trim().length > 0 ? `${current.replace(/\s*$/, '')}\n` : '';
  writeFileSync(indexPath, `${prefix}${forwardLine}\n`, 'utf8');
  console.log(`updated ${toPosixPath(path.relative(root, indexPath))}`);
}

function ensureTemplateFiles(templatePart) {
  const normalized = normalizeTemplatePath(templatePart);

  if (!isManagedTemplate(normalized)) {
    return;
  }

  const phpPath = path.join(projectRoot, ...normalized.split('/')) + '.php';
  const scssPath = buildScssPathFromTemplatePart(normalized);

  ensureFile(phpPath, phpStub(normalized));

  if (scssPath) {
    const className = path.basename(normalized);
    ensureFile(scssPath, scssStub(className));
    ensureScssForwardIndex(scssPath);
  }
}

function scanPhpFile(filePath) {
  const source = readFileSync(filePath, 'utf8');
  let match;

  while ((match = phpTemplatePartPattern.exec(source)) !== null) {
    ensureTemplateFiles(match[2]);
  }

  while ((match = phpIncludeOncePattern.exec(source)) !== null) {
    ensureTemplateFiles(match[2]);
  }
}

function normalizeForwardTarget(currentFile, specifier) {
  const withoutExtension = specifier.replace(/\.scss$/, '');
  const parsed = path.posix.parse(toPosixPath(withoutExtension));
  const partialName = parsed.base.startsWith('_') ? parsed.base : `_${parsed.base}`;
  const targetPosix = path.posix.join(parsed.dir, `${partialName}.scss`);

  return path.resolve(path.dirname(currentFile), ...targetPosix.split('/'));
}

function scanScssFile(filePath) {
  const source = readFileSync(filePath, 'utf8');
  let match;

  while ((match = scssForwardPattern.exec(source)) !== null) {
    const targetPath = normalizeForwardTarget(filePath, match[2]);
    const partialName = path.basename(targetPath, '.scss').replace(/^_/, '');
    ensureFile(targetPath, scssStub(partialName));
  }
}

function scanColorUtilities(filePath) {
  const source = readFileSync(filePath, 'utf8');
  const found = new Map();
  let match;

  while ((match = colorUtilityPattern.exec(source)) !== null) {
    const type = match[1];
    const hex = match[2].toUpperCase();
    const className = `${type}_${hex}`;
    found.set(className, {
      type,
      hex
    });
  }

  if (found.size === 0) {
    return;
  }

  const current = existsSync(colorSPath) ? readFileSync(colorSPath, 'utf8') : '';
  const additions = [];

  for (const [className, value] of found) {
    if (current.includes(`.${className}`)) {
      continue;
    }

    if (value.type === 'cl') {
      additions.push(`.${className} {
  color: #${value.hex};
}`);
    }

    if (value.type === 'bg') {
      additions.push(`.${className} {
  background-color: #${value.hex};
}`);
    }
  }

  if (additions.length === 0) {
    return;
  }

  mkdirSync(path.dirname(colorSPath), {
    recursive: true
  });
  const prefix = current.trim().length > 0 ? `${current.replace(/\s*$/, '')}\n\n` : '';
  writeFileSync(colorSPath, `${prefix}${additions.join('\n\n')}\n`, 'utf8');

  console.log(`updated ${toPosixPath(path.relative(root, colorSPath))}`);
}

function guessEscapeFunction(fieldName, line) {
  const name = fieldName.toLowerCase();

  if (/(url|link|href|src|image|img|file|pdf|movie|video)/.test(name)) {
    return 'esc_url';
  }

  if (/(alt|aria|label|placeholder|title_attr|data_|id|class)/.test(name) || /=["'][^"']*SCF::get/.test(line)) {
    return 'esc_attr';
  }

  if (/(body|content|html|wysiwyg|editor|detail|description|lead|text_area)/.test(name)) {
    return 'wp_kses_post';
  }

  return 'esc_html';
}

function isDirectOutputLine(line) {
  return /(<\?=|echo\s+)/.test(line);
}

function isAssignmentLine(line) {
  return /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*\s*=/.test(line);
}

function scanScfSecurityFile(filePath) {
  const source = readFileSync(filePath, 'utf8');
  const lines = source.split(/\r?\n/);
  const results = [];

  lines.forEach((line, index) => {
    if (!line.includes('SCF::get(')) {
      return;
    }

    if (escapedScfPattern.test(line)) {
      return;
    }

    let match;
    scfGetPattern.lastIndex = 0;

    while ((match = scfGetPattern.exec(line)) !== null) {
      const fieldName = match[2];
      const escapeFunction = guessEscapeFunction(fieldName, line);
      const level = isDirectOutputLine(line) && !isAssignmentLine(line) ? 'warning' : 'notice';

      results.push({
        level,
        line: index + 1,
        fieldName,
        escapeFunction,
        code: line.trim()
      });
    }
  });

  return results;
}

function runSecurityScan() {
  const phpFiles = walkFiles(root, new Set(['.php']));
  let warningCount = 0;
  let noticeCount = 0;

  for (const file of phpFiles) {
    const results = scanScfSecurityFile(file);

    for (const result of results) {
      if (result.level === 'warning') {
        warningCount += 1;
        console.log(`security warning: ${toPosixPath(path.relative(root, file))}:${result.line}`);
        console.log(`  direct output should be wrapped with ${result.escapeFunction}()`);
      } else {
        noticeCount += 1;
        console.log(`security notice: ${toPosixPath(path.relative(root, file))}:${result.line}`);
        console.log(`  assignment detected. Confirm output is escaped with ${result.escapeFunction}()`);
      }

      console.log(`  SCF::get('${result.fieldName}')`);
      console.log(`  ${result.code}`);
    }
  }

  console.log(`security scan complete: ${warningCount} warning(s), ${noticeCount} notice(s), ${phpFiles.length} PHP files`);
}

function scanWorkspace() {
  const phpFiles = walkFiles(root, new Set(['.php']));
  const scssFiles = walkFiles(root, new Set(['.scss']));
  const codeFiles = walkFiles(root, new Set(['.php', '.html', '.js', '.jsx', '.ts', '.tsx', '.scss']));

  for (const file of phpFiles) {
    scanPhpFile(file);
  }

  for (const file of scssFiles) {
    scanScssFile(file);
  }

  for (const file of codeFiles) {
    scanColorUtilities(file);
  }

  const projectMode = projectRoot === wpThemeRoot ? 'wordpress' : 'static';
  console.log(`scan complete: ${phpFiles.length} PHP files, ${scssFiles.length} SCSS files, mode: ${projectMode}`);
}

function watchWorkspace() {
  scanWorkspace();
  console.log('watching workspace for PHP and SCSS changes...');

  watch(root, {
    recursive: true
  }, (_eventType, filename) => {
    if (!filename) {
      return;
    }

    const relativePath = toPosixPath(filename);
    const firstSegment = relativePath.split('/')[0];
    if (ignoredDirs.has(firstSegment)) {
      return;
    }

    const fullPath = path.join(root, filename);
    if (!existsSync(fullPath) || !statSync(fullPath).isFile()) {
      return;
    }

    const extension = path.extname(fullPath);
    if (extension === '.php') {
      scanPhpFile(fullPath);
    }

    if (extension === '.scss') {
      scanScssFile(fullPath);
    }

    if (['.php', '.html', '.js', '.jsx', '.ts', '.tsx', '.scss'].includes(extension)) {
      scanColorUtilities(fullPath);
    }
  });
}

if (securityScanMode) {
  runSecurityScan();
} else if (mode === 'watch') {
  watchWorkspace();
} else {
  scanWorkspace();
}