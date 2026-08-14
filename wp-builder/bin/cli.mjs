#!/usr/bin/env node

import {
    Command
} from 'commander';
import fs from 'node:fs';
import path from 'node:path';
import 'dotenv/config';
import dotenv from 'dotenv'; // これを追記
// ★ここに必ずこれが必要です！
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
    buildSecurityFixPlan
} from '../lib/security/fix-plan.js';
import {
    renderSecurityFixPreview
} from '../lib/security/fix-preview.js';
import {
    openSecurityFixDiff,
    securityFixPreviewBlockingReasons
} from '../lib/security/fix-diff.js';
import {
    buildSecurityFixDirectoryPlan,
    openSecurityFixDirectoryDiffs,
    renderSecurityFixDirectoryEditSelection,
    renderSecurityFixDirectoryPreview
} from '../lib/security/fix-directory.js';
import {
    openSecurityFixEdit,
    openSecurityFixEditReview
} from '../lib/security/fix-edit.js';
import {
    applySecurityFixPlan
} from '../lib/security/fix-apply.js';
import {
    compressImages,
    compressSingleImage
} from '../lib/image/compressor.js';
import {
    fetchFigmaFile
} from '../lib/figma/client.js';
import {
    buildFigmaSyncPlan
} from '../lib/figma/sync-plan.js';
import {
    renderFigmaSyncPreview
} from '../lib/figma/preview.js';
import {
    applyFigmaSyncPlan
} from '../lib/figma/apply.js';
import {
    buildFigmaForwardPlan
} from '../lib/figma/forward-plan.js';
import {
    renderFigmaForwardPreview
} from '../lib/figma/forward-preview.js';
import {
    applyFigmaForwardPlan
} from '../lib/figma/forward-apply.js';
import {
    walkFiles
} from '../lib/utils/fs-helper.js';
import {
    getProjectContext
} from '../lib/workspace/project-context.js';

const {
    workspaceRoot,
    projectType,
    scssRoot
} = getProjectContext();
const ignoredWatchDirs = new Set(['.git', '.vscode', 'node_modules', 'vendor', 'work', 'outputs']);
const colorScanExtensions = new Set(['.php', '.html', '.js', '.jsx', '.ts', '.tsx', '.scss']);
const legacyCommands = new Map([
    ['--scan', {
        args: [],
        replacement: 'wp-builder'
    }],
    ['--watch', {
        args: ['watch'],
        replacement: 'wp-builder watch'
    }],
    ['--security-scan', {
        args: ['security'],
        replacement: 'wp-builder security'
    }]
]);

function resolveLegacyArgs(argv) {
    const userArgs = argv.slice(2);
    const legacyFlags = userArgs.filter(arg => legacyCommands.has(arg));

    if (legacyFlags.length === 0) return argv;

    if (legacyFlags.length !== 1 || userArgs.length !== 1) {
        console.error('[ERROR] Legacy flags must be used alone: --scan, --watch, or --security-scan.');
        console.error('Use the new CLI form explicitly: "wp-builder", "wp-builder watch", or "wp-builder security".');
        process.exitCode = 1;
        return null;
    }

    const legacyFlag = legacyFlags[0];
    const command = legacyCommands.get(legacyFlag);
    console.warn(`[DEPRECATED] ${legacyFlag} is deprecated. Use "${command.replacement}" instead.`);
    return [...argv.slice(0, 2), ...command.args];
}

function runFullScan() {
    const phpFiles = walkFiles(workspaceRoot, new Set(['.php']));
    phpFiles.forEach(scanPhpFile);

    const scssFiles = walkFiles(workspaceRoot, new Set(['.scss']));
    scssFiles.forEach(scanScssFile);

    walkFiles(workspaceRoot, colorScanExtensions).forEach(scanColorUtilities);
    console.log(`scan complete: ${phpFiles.length} PHP files, ${scssFiles.length} SCSS files, mode: ${projectType}`);
}

const program = new Command();
program.name('wp-builder').version('1.0.0');

// 1. 監視・自動化モード
program.command('watch').action(() => {
    runFullScan();
    console.log('Watching workspace for changes...');
    fs.watch(workspaceRoot, {
        recursive: true
    }, (_, filename) => {
        if (!filename) return;
        const relativePath = filename.replace(/\\/g, '/');
        const firstSegment = relativePath.split('/')[0];
        if (ignoredWatchDirs.has(firstSegment)) return;

        const fullPath = path.join(workspaceRoot, filename);
        if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) return;

        const extension = path.extname(fullPath);
        if (extension === '.php') scanPhpFile(fullPath);
        if (extension === '.scss') scanScssFile(fullPath);
        if (colorScanExtensions.has(extension)) scanColorUtilities(fullPath);

        if (filename.includes('img') && /\.(png|jpg|jpeg)$/i.test(filename)) {
            compressSingleImage(fullPath);
        }
    });
});

// 2. セキュリティスキャン
program.command('security').option('--fix').action((opt) => runSecurityScan(opt));

program
    .command('security:fix')
    .description('Preview safe Security Fix Plans or apply one file')
    .option('--file <path>', 'One PHP file inside the current workspace')
    .option('--dir <path>', 'Recursively preview PHP files inside one workspace directory')
    .option('--diff', 'Open the linted Security Fix candidate in a read-only VS Code diff')
    .option('--edit', 'Apply verified candidates to a dirty VS Code editor without saving')
    .option('--apply', 'Apply the previewed Security Fix Plan')
    .option('--yes', 'Skip interactive confirmation (requires --apply)')
    .addHelpText('after', `
Support:
  Preview / Plan: supported on Windows, Linux, macOS, and other POSIX platforms.
  Windows apply: unsupported (WINDOWS_APPLY_UNSUPPORTED_STRICT_METADATA).
    Strict metadata preservation cannot be guaranteed.
  Linux apply: KEEP_CANDIDATE; conditional and fail-closed for unsupported metadata.
  Legacy "security --fix": DISABLE_CANDIDATE; migrate to "security:fix --file <path>".
`)
    .action(async (options) => {
        if (Boolean(options.file) === Boolean(options.dir)) {
            console.error('[ERROR] Specify exactly one of --file or --dir.');
            process.exitCode = 1;
            return;
        }
        if (options.dir && options.apply) {
            console.error('[ERROR] Directory apply is unsupported. Use --dir for preview or --dir --diff.');
            process.exitCode = 1;
            return;
        }
        if (options.edit && (options.apply || options.diff)) {
            console.error('[ERROR] --edit cannot be combined with --apply or --diff.');
            process.exitCode = 1;
            return;
        }
        if (options.diff && options.apply) {
            console.error('[ERROR] --diff cannot be combined with --apply.');
            process.exitCode = 1;
            return;
        }
        if (options.yes && !options.apply) {
            console.error('[ERROR] --yes requires --apply.');
            process.exitCode = 1;
            return;
        }

        const isTTY = Boolean(process.stdin.isTTY && process.stdout.isTTY);

        try {
            if (options.dir) {
                const directoryPlan = buildSecurityFixDirectoryPlan({
                    workspaceRoot,
                    directory: options.dir
                });
                renderSecurityFixDirectoryPreview(directoryPlan);
                if (!directoryPlan.canOpenDiffs) {
                    process.exitCode = 2;
                    return;
                }
                if (options.diff) openSecurityFixDirectoryDiffs(directoryPlan);
                if (options.edit) {
                    const result = openSecurityFixEditReview(directoryPlan);
                    if (result.status !== 'session-started') {
                        renderSecurityFixDirectoryEditSelection(directoryPlan);
                        process.exitCode = 1;
                    }
                }
                return;
            }

            const plan = buildSecurityFixPlan({
                workspaceRoot,
                file: options.file
            });
            renderSecurityFixPreview(plan, {
                applyRequested: options.apply
            });

            if (options.diff) {
                const diffBlockingReasons = securityFixPreviewBlockingReasons(plan);
                if (diffBlockingReasons.length > 0) {
                    console.error('Security Fix diff is blocked by the diagnostics above.');
                    process.exitCode = 2;
                    return;
                }
                const result = openSecurityFixDiff(plan);
                if (result.status === 'lint-blocked') process.exitCode = 2;
                return;
            }

            if (options.edit) {
                const editBlockingReasons = securityFixPreviewBlockingReasons(plan);
                if (editBlockingReasons.length > 0) {
                    console.error('Security Fix edit is blocked by the diagnostics above.');
                    process.exitCode = 2;
                    return;
                }
                if (plan.counts.autoFixable === 0) {
                    openSecurityFixDiff(plan);
                    return;
                }
                const result = openSecurityFixEdit(plan, { workspaceRoot });
                if (result.status !== 'request-sent') process.exitCode = 1;
                return;
            }

            if (!plan.canApply) {
                const windowsApplyUnsupported = plan.blockingReasons.some(
                    reason => reason.code === 'WINDOWS_APPLY_UNSUPPORTED_STRICT_METADATA'
                );
                if (!options.apply && windowsApplyUnsupported) return;
                console.error('Security Fix apply is blocked by the diagnostics above.');
                process.exitCode = 2;
                return;
            }
            if (!options.apply) return;
            if (!options.yes && !isTTY) {
                console.error('[ERROR] Non-interactive apply requires --yes.');
                process.exitCode = 1;
                return;
            }
            if (!plan.hasChanges) {
                console.log('No Security Fix changes to apply.');
                return;
            }

            const result = await applySecurityFixPlan(plan, {
                assumeYes: options.yes,
                isTTY,
                input: process.stdin,
                output: process.stderr
            });
            if (result.status === 'cancelled') {
                console.log('Security Fix apply cancelled. No files changed.');
                process.exitCode = 3;
            } else if (result.status === 'applied') {
                console.log(`Security Fix apply complete: ${result.path}`);
            }
        } catch (error) {
            console.error('Security Fix failed:', error.message);
            process.exitCode = error.exitCode ?? 1;
        }
    });

// 3. 画像最適化 (一括変換)
program.command('image:optimize').action(() => {
    compressImages(workspaceRoot);
});

// 4. Figma同期 (デザイン数値からSCSS生成)
program
    .command('figma:sync')
    .description('Preview Figma styles and apply them only with explicit approval')
    .option('-f, --file <key>', 'Figma File Key (optional, defaults to .env)')
    .requiredOption('-p, --page <id>', 'Page/Node ID to sync')
    .option('--apply', 'Apply the previewed SyncPlan to the managed generated file')
    .option('--yes', 'Skip interactive confirmation (requires --apply)')
    .action(async (options) => {
        if (options.yes && !options.apply) {
            console.error('[ERROR] --yes requires --apply.');
            process.exitCode = 1;
            return;
        }

        const isTTY = Boolean(process.stdin.isTTY && process.stdout.isTTY);
        if (options.apply && !options.yes && !isTTY) {
            console.error('[ERROR] Non-interactive apply requires --yes.');
            process.exitCode = 1;
            return;
        }

        const fileKey = options.file || process.env.FIGMA_FILE_KEY;
        if (!fileKey) {
            console.error('[ERROR] A Figma file key is required via --file or FIGMA_FILE_KEY.');
            process.exitCode = 1;
            return;
        }
        if (!process.env.FIGMA_TOKEN) {
            console.error('[ERROR] FIGMA_TOKEN is required.');
            process.exitCode = 1;
            return;
        }

        try {
            const figmaFile = await fetchFigmaFile(fileKey, process.env.FIGMA_TOKEN);
            const plan = buildFigmaSyncPlan({
                figmaFile,
                fileKey,
                nodeId: options.page,
                projectType,
                scssRoot
            });
            renderFigmaSyncPreview(plan, {
                applyRequested: options.apply
            });

            if (plan.hasUnsafeTarget) {
                console.error('Apply is blocked because the target is unmanaged or unsafe.');
                process.exitCode = 5;
                return;
            }
            if (plan.hasConflict) {
                console.error('Apply is blocked because the SyncPlan contains conflicts.');
                process.exitCode = 2;
                return;
            }
            if (!options.apply) return;
            if (!plan.hasChanges) {
                console.log('No changes to apply.');
                return;
            }

            const result = await applyFigmaSyncPlan(plan, {
                assumeYes: options.yes,
                isTTY,
                input: process.stdin,
                output: process.stderr
            });
            if (result.status === 'cancelled') {
                console.log('Figma apply cancelled. No files changed.');
                process.exitCode = 3;
            } else if (result.status === 'applied') {
                console.log(`Figma apply complete: ${result.path}`);
            }
        } catch (err) {
            console.error('❌ Sync failed:', err.message);
            process.exitCode = err.exitCode ?? 1;
        }
    });

// デフォルト (全スキャン)
program
    .command('figma:forward')
    .description('Preview or apply the Figma @forward entry in _Component.scss')
    .option('--apply', 'Apply the previewed Forward Plan to _Component.scss')
    .option('--yes', 'Skip interactive confirmation (requires --apply)')
    .action(async (options) => {
        if (options.yes && !options.apply) {
            console.error('[ERROR] --yes requires --apply.');
            process.exitCode = 1;
            return;
        }

        const isTTY = Boolean(process.stdin.isTTY && process.stdout.isTTY);
        if (options.apply && !options.yes && !isTTY) {
            console.error('[ERROR] Non-interactive apply requires --yes.');
            process.exitCode = 1;
            return;
        }

        try {
            const plan = buildFigmaForwardPlan({
                projectType,
                scssRoot
            });
            renderFigmaForwardPreview(plan, {
                applyRequested: options.apply
            });

            if (!plan.canApply) {
                console.error('Forward apply is blocked by the findings above.');
                process.exitCode = plan.blockingExitCode || 1;
                return;
            }
            if (!options.apply) return;
            if (!plan.hasChanges) {
                console.log('No forward changes to apply.');
                return;
            }

            const result = await applyFigmaForwardPlan(plan, {
                assumeYes: options.yes,
                isTTY,
                input: process.stdin,
                output: process.stderr
            });
            if (result.status === 'cancelled') {
                console.log('Forward apply cancelled. No files changed.');
                process.exitCode = 3;
            } else if (result.status === 'applied') {
                console.log(`Forward apply complete: ${result.path}`);
            }
        } catch (error) {
            console.error('Forward apply failed:', error.message);
            process.exitCode = error.exitCode ?? 1;
        }
    });

program.action(() => {
    runFullScan();
});

const resolvedArgs = resolveLegacyArgs(process.argv);
if (resolvedArgs) await program.parseAsync(resolvedArgs);
