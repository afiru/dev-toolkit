import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function regularFile(filePath) {
    try {
        const stat = fs.lstatSync(filePath);
        return stat.isFile() && !stat.isSymbolicLink();
    } catch {
        return false;
    }
}

function invocationFromWindowsCommand(candidate) {
    if (/\.exe$/i.test(candidate) && regularFile(candidate)) {
        const commandFile = path.join(path.dirname(candidate), 'bin', 'code.cmd');
        if (regularFile(commandFile)) return invocationFromWindowsCommand(commandFile);
        return null;
    }
    if (!/\.cmd$/i.test(candidate) || !regularFile(candidate)) return null;

    const content = fs.readFileSync(candidate, 'utf8');
    const match = content.match(
        /"%~dp0\.\.\\Code\.exe"\s+"%~dp0\.\.\\([^"\r\n]*resources\\app\\out\\cli\.js)"/i
    );
    if (!match) return null;
    const installRoot = path.resolve(path.dirname(candidate), '..');
    const command = path.join(installRoot, 'Code.exe');
    const cliPath = path.resolve(installRoot, ...match[1].split('\\'));
    if (!regularFile(command) || !regularFile(cliPath)) return null;
    return {
        command,
        argsPrefix: [cliPath],
        env: { ELECTRON_RUN_AS_NODE: '1' }
    };
}

function resolveWindowsCodeInvocation(spawn = spawnSync) {
    const result = spawn('where.exe', ['code'], {
        encoding: 'utf8',
        timeout: 3000,
        windowsHide: true
    });
    const discovered = result.error || result.status !== 0 ? [] : String(result.stdout ?? '')
        .split(/\r?\n/)
        .map(item => item.trim())
        .filter(Boolean);
    const candidates = [
        ...discovered,
        process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Programs', 'Microsoft VS Code', 'Code.exe'),
        process.env.ProgramFiles && path.join(process.env.ProgramFiles, 'Microsoft VS Code', 'Code.exe'),
        process.env['ProgramFiles(x86)'] && path.join(process.env['ProgramFiles(x86)'], 'Microsoft VS Code', 'Code.exe')
    ].filter(Boolean);
    for (const candidate of candidates) {
        const invocation = invocationFromWindowsCommand(candidate);
        if (invocation) return invocation;
    }
    return null;
}

export function resolveCodeInvocation(spawn = spawnSync) {
    return process.platform === 'win32'
        ? resolveWindowsCodeInvocation(spawn)
        : { command: 'code', argsPrefix: [], env: {} };
}

export function resolveCodeExecutable(spawn = spawnSync) {
    return resolveCodeInvocation(spawn)?.command ?? null;
}

export function launchCode(args, options) {
    const {
        spawn = spawnSync,
        waitForClose = false
    } = options;
    const invocation = options.codeCommand ? {
        command: options.codeCommand,
        argsPrefix: options.codeArgsPrefix ?? [],
        env: options.codeEnv ?? {}
    } : resolveCodeInvocation(spawn);
    if (!invocation) return { opened: false, reason: 'not-found' };

    const codeArgs = waitForClose ? ['--wait', ...args] : args;
    const result = spawn(invocation.command, [...invocation.argsPrefix, ...codeArgs], {
        encoding: 'utf8',
        env: { ...process.env, ...invocation.env },
        ...(waitForClose ? {} : { timeout: options.timeoutMs ?? 10000 }),
        windowsHide: true
    });
    if (result.error?.code === 'ENOENT' || result.error?.code === 'EINVAL') {
        return { opened: false, reason: 'not-found' };
    }
    if (result.error || result.status !== 0) {
        return {
            opened: false,
            reason: 'launch-failed',
            exitCode: result.status,
            error: result.error?.message ?? null
        };
    }
    return { opened: true, reason: null };
}

function diagnosticLocations(plan) {
    return plan.findings
        .filter(finding => !finding.autoFixable)
        .map(finding => ({
            line: finding.location.startLine,
            column: finding.location.startColumn,
            ruleId: finding.ruleId
        }));
}

export function securityFixPreviewBlockingReasons(plan) {
    const metadataReasons = new Set(
        (plan.snapshot?.metadata?.capability?.blockingReasons ?? [])
            .map(reason => `${reason.code}\0${reason.message ?? ''}`)
    );
    return (plan.blockingReasons ?? []).filter(
        reason => !metadataReasons.has(`${reason.code}\0${reason.message ?? ''}`)
    );
}

export function openSecurityFixDiff(plan, options = {}) {
    const {
        out = console.log,
        error = console.error,
        tempDirectory = os.tmpdir()
    } = options;
    const autoFixable = plan.counts?.autoFixable ?? 0;

    if (autoFixable === 0 || !plan.hasChanges) {
        const locations = diagnosticLocations(plan);
        out('No auto-fixable Security Fix candidates.');
        locations.forEach(location => {
            out(`  ${plan.targetPath}:${location.line}:${location.column} [${location.ruleId}]`);
        });
        if (locations.length === 0) return { status: 'no-auto-fixable', opened: false, previewPath: null };

        const first = locations[0];
        const launch = launchCode([
            '--goto',
            `${plan.targetPath}:${first.line}:${first.column}`
        ], options);
        if (!launch.opened) error('VS Code CLI "code" is unavailable; open the diagnostic location shown above manually.');
        return { status: 'no-auto-fixable', previewPath: null, ...launch };
    }

    if (!plan.lint?.available || !plan.lint.passed) {
        error('Security Fix diff is blocked because PHP lint did not pass. No preview file was created.');
        return { status: 'lint-blocked', opened: false, previewPath: null };
    }

    const tempRoot = fs.mkdtempSync(path.join(tempDirectory, 'wp-builder-security-fix-'));
    const extension = path.extname(plan.targetPath) || '.php';
    const baseName = path.basename(plan.targetPath, path.extname(plan.targetPath));
    const previewPath = path.join(tempRoot, `${baseName}.security-fix-preview${extension}`);
    fs.writeFileSync(previewPath, plan.desiredBytes, { flag: 'wx', mode: 0o600 });
    out(`Security Fix diff preview: ${previewPath}`);

    const launch = launchCode(['--diff', plan.targetPath, previewPath], options);
    if (!launch.opened) {
        error(`VS Code CLI "code" is unavailable; run code --diff "${plan.targetPath}" "${previewPath}" manually.`);
    }
    return { status: 'preview-created', previewPath, ...launch };
}
