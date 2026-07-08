import fs from 'node:fs';
import path from 'node:path';
export function toPosixPath(v) {
    return v.replace(/\\/g, '/');
}
export function walkFiles(dir, exts, files = []) {
    if (!fs.existsSync(dir)) return files;
    for (const e of fs.readdirSync(dir, {
            withFileTypes: true
        })) {
        if (e.isDirectory()) {
            if (!['.git', '.vscode', 'node_modules', 'vendor', 'work', 'outputs'].includes(e.name)) walkFiles(path.join(dir, e.name), exts, files);
            continue;
        }
        if (e.isFile() && exts.has(path.extname(e.name))) files.push(path.join(dir, e.name));
    }
    return files;
}
export function ensureFile(p, c) {
    if (fs.existsSync(p)) return false;
    fs.mkdirSync(path.dirname(p), {
        recursive: true
    });
    fs.writeFileSync(p, c, 'utf8');
    return true;
}