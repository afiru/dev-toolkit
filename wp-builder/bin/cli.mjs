#!/usr/bin/env node

import {
    Command
} from 'commander';
import fs from 'node:fs';
import path from 'node:path';
import {
    scanPhpFile,
    scanScssFile,
    scanColorUtilities
} from '../lib/workspace/scanner.js';
import {
    runSecurityScan
} from '../lib/security/scanner.js';
import {
    walkFiles
} from '../lib/utils/fs-helper.js';
import {
    compressImages
} from '../lib/image/compressor.js';

const program = new Command();
program.name('wp-builder').version('1.0.0');

program.command('watch').action(() => {
    console.log('Watching workspace for changes...');
    fs.watch(process.cwd(), {
        recursive: true
    }, (_, filename) => {
        if (!filename) return;
        const fullPath = path.join(process.cwd(), filename);

        try {
            if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) return;

            // PHP/SCSS系
            if (filename.endsWith('.php')) scanPhpFile(fullPath);
            if (filename.endsWith('.scss')) scanScssFile(fullPath);
            scanColorUtilities(fullPath);

            // ★画像圧縮系を追加 (imgフォルダーが含まれる場合のみ実行)
            if (filename.includes('img') && /\.(png|jpg|jpeg)$/i.test(filename)) {
                compressSingleImage(fullPath);
            }
        } catch (err) {
            /* エラー時は無視 */
        }
    });
});

program.command('security').option('--fix').action((opt) => runSecurityScan(opt));
program.action(() => {
    walkFiles(process.cwd(), new Set(['.php'])).forEach(scanPhpFile);
    walkFiles(process.cwd(), new Set(['.scss'])).forEach(scanScssFile);
    console.log('Full scan complete.');
});

program
    .command('optimize') // image:optimize から optimize に短縮して試す
    .description('Compress all images in current directory')
    .action(() => {
        console.log('Running image optimizer...');
        compressImages(process.cwd());
    });

console.log('Arguments:', process.argv); // ★追加: どんな引数で認識されているか表示
program.parse(process.argv);

program.parse(process.argv);