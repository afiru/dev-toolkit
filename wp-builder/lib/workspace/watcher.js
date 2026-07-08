import fs from 'node:fs';
import {
    scanWorkspace
} from './scanner.js';

export function startWatcher() {
    scanWorkspace();
    console.log('Watching workspace...');
    fs.watch(process.cwd(), {
        recursive: true
    }, () => scanWorkspace());
}