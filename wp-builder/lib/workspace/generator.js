import fs from 'node:fs';
import path from 'node:path';
import {
    toPosixPath
} from '../utils/fs-helper.js';

const root = process.cwd();
const wpThemeRoot = path.join(root, 'public', 'wp-content', 'themes', 'WebPTemplatebyMarcat');
const projectRoot = fs.existsSync(wpThemeRoot) ? wpThemeRoot : root;

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

export function ensureTemplateFiles(templatePart) {
    const norm = toPosixPath(templatePart).replace(/\.php$/, '').replace(/^\/+/, '');
    if (!norm.startsWith('include/layouts/')) return;

    // 1. PHPファイルの作成
    const phpP = path.join(projectRoot, norm + '.php');
    if (!fs.existsSync(phpP)) {
        fs.mkdirSync(path.dirname(phpP), {
            recursive: true
        });
        fs.writeFileSync(phpP, `<?php\n/**\n * Template part: ${path.basename(norm)}\n */\n?>\n`, 'utf8');
        console.log(`Created PHP: ${phpP}`);
    }

    // 2. SCSSファイルの作成 (インデックス計算を安全な方法に変更)
    const relativePath = norm.replace('include/layouts/', '');
    const parts = relativePath.split('/').filter(Boolean);
    const fileName = parts.pop(); // ファイル名を取得

    // レイアウトディレクトリ配下のパス構築
    const scssP = path.join(projectRoot, 'scss', 'Layout', ...parts, `_${fileName}.scss`);

    if (!fs.existsSync(scssP)) {
        fs.mkdirSync(path.dirname(scssP), {
            recursive: true
        });
        fs.writeFileSync(scssP, scssStub(fileName), 'utf8');
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
}