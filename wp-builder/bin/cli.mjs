#!/usr/bin/env node

import {
    Command
} from 'commander';
import fs from 'node:fs';
import path from 'node:path';
import axios from 'axios';
import 'dotenv/config';
import dotenv from 'dotenv'; // これを追記
// ★ここに必ずこれが必要です！
import {
    formatScss
} from '../lib/utils/formatter.js';

// 強制的に指定した場所の .env を読み込む
dotenv.config({
    path: 'D:\\dev-toolkit\\wp-builder\\.env'
});

import {
    scanPhpFile,
    scanScssFile,
    scanColorUtilities
} from '../lib/workspace/scanner.js';
import {
    runSecurityScan
} from '../lib/security/scanner.js';
import {
    compressImages,
    compressSingleImage
} from '../lib/image/compressor.js';
import {
    parseNodeToScss
} from '../lib/figma/generator.js';
import {
    walkFiles
} from '../lib/utils/fs-helper.js';

const program = new Command();
program.name('wp-builder').version('1.0.0');

// 1. 監視・自動化モード
program.command('watch').action(() => {
    console.log('Watching workspace for changes...');
    fs.watch(process.cwd(), {
        recursive: true
    }, (_, filename) => {
        if (!filename) return;
        const fullPath = path.join(process.cwd(), filename);
        if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) return;

        if (filename.endsWith('.php')) scanPhpFile(fullPath);
        if (filename.endsWith('.scss')) scanScssFile(fullPath);
        scanColorUtilities(fullPath);

        if (filename.includes('img') && /\.(png|jpg|jpeg)$/i.test(filename)) {
            compressSingleImage(fullPath);
        }
    });
});

// 2. セキュリティスキャン
program.command('security').option('--fix').action((opt) => runSecurityScan(opt));

// 3. 画像最適化 (一括変換)
program.command('image:optimize').action(() => {
    compressImages(process.cwd());
});

// 4. Figma同期 (デザイン数値からSCSS生成)
program
    .command('figma:sync')
    .description('Sync styles from Figma')
    .option('-f, --file <key>', 'Figma File Key (optional, defaults to .env)')
    .requiredOption('-p, --page <id>', 'Page/Node ID to sync')
    .action(async (options) => {
        const fileKey = options.file || process.env.FIGMA_FILE_KEY;
        const url = `https://api.figma.com/v1/files/${fileKey}`;
        const filePath = './scss/Component/_colorS.scss';

        try {
            const res = await axios.get(url, {
                headers: {
                    'X-Figma-Token': process.env.FIGMA_TOKEN
                }
            });

            // 1. 既存データの読み込み
            const generatedClasses = new Set();
            if (fs.existsSync(filePath)) {
                const existingContent = fs.readFileSync(filePath, 'utf-8');
                existingContent.split('\n').forEach(line => {
                    if (line.trim()) generatedClasses.add(line);
                });
            }

            // 2. ターゲットノード検索
            let targetNode = null;
            const findNode = (nodes) => {
                for (const node of nodes) {
                    if (node.id === options.page) return node;
                    if (node.children) {
                        const found = findNode(node.children);
                        if (found) return found;
                    }
                }
                return null;
            };

            res.data.document.children.forEach(page => {
                const found = findNode(page.children || []);
                if (found) targetNode = found;
            });

            if (!targetNode) {
                console.error(`❌ ノード ID ${options.page} が見つかりませんでした。`);
                return;
            }

            // 3. スキャン
            const scan = (nodes) => {
                nodes.forEach(node => {
                    const code = parseNodeToScss(node);
                    if (code) code.split('\n').forEach(line => {
                        if (line.trim()) generatedClasses.add(line);
                    });
                    if (node.children) scan(node.children);
                });
            };
            scan([targetNode]);

            // 4. 保存と整形
            fs.writeFileSync(filePath, Array.from(generatedClasses).join('\n'));
            formatScss(filePath); // ここで呼び出し！

            console.log(`✅ ${targetNode.name} (${options.page}) を同期し、整形しました！`);
        } catch (err) {
            console.error('❌ Sync failed:', err.message);
        }
    });

// デフォルト (全スキャン)
program.action(() => {
    walkFiles(process.cwd(), new Set(['.php'])).forEach(scanPhpFile);
    walkFiles(process.cwd(), new Set(['.scss'])).forEach(scanScssFile);
    console.log('Full scan complete.');
});

program.parse(process.argv);