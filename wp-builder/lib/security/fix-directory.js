import fs from 'node:fs';
import path from 'node:path';
import {
    openSecurityFixDiff,
    securityFixPreviewBlockingReasons
} from './fix-diff.js';
import { buildSecurityFixPlan } from './fix-plan.js';

function isInside(parent, target) {
    const relative = path.relative(path.resolve(parent), path.resolve(target));
    return relative === '' || (
        relative !== '..' &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative)
    );
}

function directoryError(code, message) {
    const error = new Error(message);
    error.code = code;
    error.exitCode = 2;
    return error;
}

function resolveDirectory(workspaceRoot, directory) {
    const root = path.resolve(workspaceRoot);
    const target = path.resolve(root, directory);
    if (!isInside(root, target)) {
        throw directoryError('DIRECTORY_OUTSIDE_WORKSPACE', 'Security Fix directory must be inside the current workspace.');
    }

    let stat;
    try {
        stat = fs.lstatSync(target);
    } catch (error) {
        if (error.code === 'ENOENT') throw directoryError('DIRECTORY_MISSING', 'Security Fix directory does not exist.');
        throw directoryError('DIRECTORY_UNREADABLE', `Cannot inspect Security Fix directory: ${error.message}`);
    }
    if (stat.isSymbolicLink()) {
        throw directoryError('DIRECTORY_SYMLINK_UNSUPPORTED', 'Security Fix directory cannot be a symbolic link or junction.');
    }
    if (!stat.isDirectory()) {
        throw directoryError('DIRECTORY_NOT_DIRECTORY', 'Security Fix --dir target must be a directory.');
    }

    const relative = path.relative(root, target);
    let current = root;
    for (const segment of relative.split(path.sep).filter(Boolean)) {
        current = path.join(current, segment);
        if (fs.lstatSync(current).isSymbolicLink()) {
            throw directoryError(
                'DIRECTORY_SYMLINK_UNSUPPORTED',
                `Security Fix directory path contains a symbolic link or junction: ${path.relative(root, current)}`
            );
        }
    }
    return { root, target };
}

function collectPhpFiles(workspaceRoot, directory) {
    const { root, target } = resolveDirectory(workspaceRoot, directory);
    const files = [];

    const walk = current => {
        const entries = fs.readdirSync(current, { withFileTypes: true })
            .sort((left, right) => left.name.localeCompare(right.name));
        for (const entry of entries) {
            const entryPath = path.join(current, entry.name);
            const stat = fs.lstatSync(entryPath);
            if (stat.isSymbolicLink()) {
                throw directoryError(
                    'DIRECTORY_ENTRY_SYMLINK_UNSUPPORTED',
                    `Security Fix directory contains a symbolic link or junction: ${path.relative(root, entryPath)}`
                );
            }
            if (stat.isDirectory()) {
                walk(entryPath);
                continue;
            }
            if (stat.isFile()) {
                if (path.extname(entry.name).toLowerCase() === '.php') files.push(entryPath);
                continue;
            }
            throw directoryError(
                'DIRECTORY_ENTRY_UNSAFE',
                `Security Fix directory contains an unsupported filesystem entry: ${path.relative(root, entryPath)}`
            );
        }
    };

    walk(target);
    return { root, target, files };
}

export function buildSecurityFixDirectoryPlan({
    workspaceRoot,
    directory,
    planBuilder = buildSecurityFixPlan,
    ...planOptions
}) {
    const scan = collectPhpFiles(workspaceRoot, directory);
    const plans = scan.files.map(file => planBuilder({
        workspaceRoot: scan.root,
        file,
        ...planOptions
    }));
    const autoFixable = plans.reduce((total, plan) => total + plan.counts.autoFixable, 0);
    const diagnosticOnly = plans.reduce((total, plan) => total + plan.counts.diagnosticOnly, 0);
    const blockingDiagnostics = plans.flatMap(plan => plan.blockingReasons.map(reason => ({
        file: plan.targetPath,
        ...reason
    })));
    const diffBlockingDiagnostics = plans.flatMap(plan =>
        securityFixPreviewBlockingReasons(plan).map(reason => ({
            file: plan.targetPath,
            ...reason
        }))
    );

    return {
        schemaVersion: 1,
        workspaceRoot: scan.root,
        directoryPath: scan.target,
        plans,
        counts: {
            filesScanned: plans.length,
            autoFixable,
            diagnosticOnly
        },
        blockingDiagnostics,
        canOpenDiffs: diffBlockingDiagnostics.length === 0
    };
}

function findingRows(directoryPlan, predicate) {
    return directoryPlan.plans.flatMap(plan => plan.findings
        .filter(predicate)
        .map(finding => ({
            file: path.relative(directoryPlan.workspaceRoot, plan.targetPath).replace(/\\/g, '/'),
            line: finding.location.startLine,
            column: finding.location.startColumn,
            ruleId: finding.ruleId
        })));
}

export function renderSecurityFixDirectoryPreview(directoryPlan, options = {}) {
    const { out = console.log, error = console.error } = options;
    const autoRows = findingRows(directoryPlan, finding => finding.autoFixable);
    const diagnosticRows = findingRows(directoryPlan, finding => !finding.autoFixable);

    out('Security Fix Directory Preview');
    out(`directory: ${directoryPlan.directoryPath}`);
    out('');
    out('AUTO_FIXABLE:');
    if (autoRows.length === 0) out('  (none)');
    autoRows.forEach(row => out(`- ${row.file}:${row.line}:${row.column} [${row.ruleId}]`));
    out('');
    out('DIAGNOSTIC_ONLY:');
    if (diagnosticRows.length === 0) out('  (none)');
    diagnosticRows.forEach(row => out(`- ${row.file}:${row.line}:${row.column} [${row.ruleId}]`));

    if (directoryPlan.blockingDiagnostics.length > 0) {
        error('blocking diagnostics:');
        directoryPlan.blockingDiagnostics.forEach(item => {
            const relative = path.relative(directoryPlan.workspaceRoot, item.file).replace(/\\/g, '/');
            error(`  ${relative} [${item.code}] ${item.message}`);
        });
    }

    out('');
    out('summary:');
    out(`  ${directoryPlan.counts.filesScanned} files scanned`);
    out(`  ${directoryPlan.counts.autoFixable} auto-fixable`);
    out(`  ${directoryPlan.counts.diagnosticOnly} diagnostic-only`);
    out('No files changed.');
}

export function openSecurityFixDirectoryDiffs(directoryPlan, options = {}) {
    const {
        out = console.log,
        error = console.error,
        openDiff = openSecurityFixDiff
    } = options;
    if (!directoryPlan.canOpenDiffs) {
        error('Security Fix directory diff is blocked by the diagnostics above.');
        return { status: 'blocked', results: [] };
    }

    const candidates = directoryPlan.plans.filter(
        plan => plan.counts.autoFixable > 0 || plan.counts.diagnosticOnly > 0
    );
    if (candidates.length === 0) {
        out('No Security Fix diff or diagnostic locations to open.');
        return { status: 'no-candidates', results: [] };
    }

    out('Opening VS Code previews sequentially. Close each view before the next opens.');
    const results = candidates.map(plan => openDiff(plan, {
        ...options,
        openDiff: undefined,
        waitForClose: true
    }));
    return { status: 'opened-sequentially', results };
}

export function renderSecurityFixDirectoryEditSelection(directoryPlan, options = {}) {
    const { out = console.log } = options;
    const candidates = directoryPlan.plans.filter(plan => plan.counts.autoFixable > 0);
    if (candidates.length === 0) {
        out('No auto-fixable files are available for VS Code edit. Manual review is required for diagnostics above.');
        return { status: 'no-auto-fixable', candidates: [] };
    }

    out('Security Fix edit candidates (run one at a time):');
    candidates.forEach((plan, index) => {
        const relative = path.relative(directoryPlan.workspaceRoot, plan.targetPath).replace(/\\/g, '/');
        out(`  ${index + 1}. ${relative} (${plan.counts.autoFixable} auto-fixable)`);
        out(`     wp-builder security:fix --file "${relative}" --edit`);
    });
    out('No editor was modified by the directory command. Choose one command above after review.');
    return { status: 'selection-required', candidates };
}
