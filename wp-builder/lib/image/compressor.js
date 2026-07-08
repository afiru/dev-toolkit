import fs from 'node:fs';
import {
    exec
} from 'node:child_process';
import path from 'node:path';
import {
    walkFiles
} from '../utils/fs-helper.js';

const cwebpPath = 'D:\\dev-toolkit\\libwebp-1.6.0-windows-x64\\bin\\cwebp.exe';

export function compressImages(inputDir) {
    console.log(`--- Starting WebP Compression in: ${inputDir} ---`);

    // 検索対象の拡張子を確認
    const files = walkFiles(inputDir, new Set(['.png', '.jpg', '.jpeg']));
    console.log(`--- Found ${files.length} images to process ---`);

    if (files.length === 0) {
        console.log("No images found. Please check your directory path.");
    }

    files.forEach(file => {
        const outputFile = file.replace(/\.(png|jpg|jpeg)$/i, '.webp');

        if (fs.existsSync(outputFile)) {
            return;
        }

        console.log(`Processing: ${path.basename(file)}...`);
        const cmd = `"${cwebpPath}" -q 80 "${file}" -o "${outputFile}"`;

        exec(cmd, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error compressing ${file}: ${error.message}`);
                return;
            }
            console.log(`Converted: ${path.basename(file)}`);
        });
    });
}