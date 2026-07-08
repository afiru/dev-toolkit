import fs from 'node:fs';
import path from 'node:path';
import {
    walkFiles,
    toPosixPath
} from '../utils/fs-helper.js';

const root = process.cwd();
// 大文字小文字を無視(i)し、scf::get を広く拾う
const scfP = /scf::get\s*\(\s*(['"])([^'"]+)\1\s*\)/gi;
const escP = /(esc_html|esc_url|esc_attr|wp_kses_post|esc_textarea)\s*\([^)]*scf::get\s*\(/i;

function guess(f, line) {
    const n = f.toLowerCase();
    // iframe や map を含む場合、より強力なサニタイズを促す関数を割り当て
    if (/(iframe|map|youtube|video|movie)/.test(n)) return 'wp_kses_post';

    if (/(url|link|href|src|image|img|file|pdf|movie|video)/.test(n)) return 'esc_url';
    if (/(alt|aria|label|placeholder|title_attr|data_|id|class)/.test(n) || /=["'][^"']*scf::get/i.test(line)) return 'esc_attr';
    if (/(body|content|cnt|txt|html|wysiwyg|editor|detail|description|lead|text_area)/.test(n)) return 'wp_kses_post';
    return 'esc_html';
}

export function runSecurityScan(options = {
    fix: false
}) {
    const files = walkFiles(root, new Set(['.php']));
    console.log(`[DEBUG] Found ${files.length} PHP files to scan.`);

    files.forEach(file => {
        const src = fs.readFileSync(file, 'utf8');
        const lines = src.split(/\r?\n/);

        // そもそもファイルの中に scf::get が存在するかチェック
        if (!/scf::get/i.test(src)) return;

        console.log(`[DEBUG] Scanning file: ${toPosixPath(path.relative(root, file))}`);

        const newLines = lines.map((line, i) => {
            if (!/scf::get/i.test(line) || escP.test(line)) return line;

            return line.replace(scfP, (match, q, field) => {
                const func = guess(field, line);
                console.log(`[FOUND] Line ${i+1}: ${field} -> needs ${func}()`);
                return options.fix ? `${func}(${match})` : match;
            });
        });

        if (options.fix && src !== newLines.join('\n')) {
            fs.writeFileSync(file, newLines.join('\n'), 'utf8');
            console.log(`[FIXED] ${toPosixPath(path.relative(root, file))}`);
        }
    });
}