import fs from 'node:fs';
import path from 'node:path';
import {
    toPosixPath,
    ensureFile
} from '../utils/fs-helper.js';
import {
    ensureTemplateFiles
} from './generator.js';

const colorSPath = path.join(process.cwd(), 'scss', 'Component', '_colorS.scss');
const phpP = [/get_template_part\s*\(\s*(['"])([^'"]+)\1/g, /include_once\s*\(\s*(['"])([^'"]+)\1\s*\)/g];

export function scanPhpFile(f) {
    const src = fs.readFileSync(f, 'utf8');
    phpP.forEach(reg => {
        let m;
        while ((m = reg.exec(src)) !== null) ensureTemplateFiles(m[2]);
    });
}

export function scanScssFile(f) {
    const src = fs.readFileSync(f, 'utf8');
    const reg = /@forward\s+(['"])([^'"]+)\1/g;
    let m;
    while ((m = reg.exec(src)) !== null) {
        const target = path.resolve(path.dirname(f), m[2].replace(/\.scss$/, '').replace(/([^\\/]+)$/, '_$1') + '.scss');
        ensureFile(target, `.${path.basename(target, '.scss').slice(1)} {\n}\n`);
    }
}

export function scanColorUtilities(f) {
    const src = fs.readFileSync(f, 'utf8');
    const found = new Map();
    let m;
    const reg = /\b(cl|bg)_([0-9a-fA-F]{6})\b/g;
    while ((m = reg.exec(src)) !== null) found.set(`${m[1]}_${m[2].toUpperCase()}`, {
        type: m[1],
        hex: m[2]
    });
    if (found.size === 0) return;
    const cur = fs.existsSync(colorSPath) ? fs.readFileSync(colorSPath, 'utf8') : '';
    let add = '';
    for (const [cls, v] of found)
        if (!cur.includes(`.${cls}`)) add += `.${cls} { ${v.type === 'cl' ? 'color' : 'background-color'}: #${v.hex}; }\n\n`;
    if (add) fs.appendFileSync(colorSPath, add);
}