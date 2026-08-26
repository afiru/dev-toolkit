import fs from 'node:fs';
import path from 'node:path';
import {
    toPosixPath
} from '../utils/fs-helper.js';
import {
    getProjectContext
} from './project-context.js';

const {
    projectRoot,
    scssRoot
} = getProjectContext();

function scssStub() {
    return `/* ==========================================================================
   use＆nameSpace
   ========================================================================== */
@use "../../Functions/mixin" as mi;

/* ==========================================================================
   LAYOUT
   ========================================================================== */
`;
}

function stripScssComments(source) {
    return source
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/\/\/.*$/gm, '');
}

function hasActiveUse(source, specifier) {
    const activeSource = stripScssComments(source);
    const usePattern = /^\s*@use\s+(['"])([^'"]+)\1(?:\s+[^;]+)?\s*;/gm;
    let match;
    while ((match = usePattern.exec(activeSource)) !== null) {
        if (match[2] === specifier) return true;
    }
    return false;
}

function ensureCommonLayoutUse(layoutParts) {
    if (layoutParts.length === 0) return;

    const indexName = layoutParts.at(-1);
    const specifier = `Layout/${layoutParts.join('/')}/${indexName}`;
    const line = `@use "${specifier}";`;
    const commonPath = path.join(scssRoot, 'common.scss');
    const current = fs.existsSync(commonPath) ? fs.readFileSync(commonPath, 'utf8') : '';

    if (hasActiveUse(current, specifier)) return;

    fs.mkdirSync(path.dirname(commonPath), { recursive: true });
    const separator = current.length > 0 && !current.endsWith('\n') ? '\n' : '';
    fs.appendFileSync(commonPath, `${separator}${line}\n`, 'utf8');
    console.log(`Updated Common: ${commonPath}`);
}

export function ensureTemplateFiles(templatePart) {
    const norm = toPosixPath(templatePart).replace(/\.php$/, '').replace(/^\/+/, '');
    const isLayout = norm.startsWith('include/layouts/');
    const isCommon = norm.startsWith('include/common/');
    if (!isLayout && !isCommon) return;

    // 1. PHPファイルの作成
    const phpP = path.join(projectRoot, norm + '.php');
    if (!fs.existsSync(phpP)) {
        fs.mkdirSync(path.dirname(phpP), {
            recursive: true
        });
        fs.writeFileSync(phpP, `<?php\n/**\n * Template part: ${path.basename(norm)}\n */\n?>\n`, 'utf8');
        console.log(`Created PHP: ${phpP}`);
    }

    // include/common/ is PHP-only, matching the legacy workspace builder.
    if (isCommon) return;

    // 2. SCSSファイルの作成 (インデックス計算を安全な方法に変更)
    const relativePath = norm.replace('include/layouts/', '');
    const parts = relativePath.split('/').filter(Boolean);
    const fileName = parts.pop(); // ファイル名を取得

    // レイアウトディレクトリ配下のパス構築
    const scssP = path.join(scssRoot, 'Layout', ...parts, `_${fileName}.scss`);

    if (!fs.existsSync(scssP)) {
        fs.mkdirSync(path.dirname(scssP), {
            recursive: true
        });
        fs.writeFileSync(scssP, scssStub(), 'utf8');
        console.log(`Created SCSS: ${scssP}`);
    }

    // 3. Forward管理
    const dir = path.dirname(scssP);
    const idx = path.join(dir, `_${path.basename(dir)}.scss`);
    const line = `@forward "${fileName}";`;

    if (!fs.existsSync(idx) || !fs.readFileSync(idx, 'utf8').includes(line)) {
        fs.appendFileSync(idx, `${line}\n`);
        console.log(`Updated Index: ${idx}`);
    }

    // 4. common.scssへLayout indexを登録
    ensureCommonLayoutUse(parts);
}
