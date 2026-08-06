import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

export const WINDOWS_HELPER_MANIFEST_SCHEMA_VERSION = 1;
export const WINDOWS_HELPER_NAME = 'wpb-windows-inspector';
export const WINDOWS_HELPER_VERSION = '0.2.0';
export const WINDOWS_HELPER_ADAPTER = 'windows-native-inspector-v1';
export const WINDOWS_HELPER_PRODUCTION_ARCHITECTURE = 'x64';
export const WINDOWS_HELPER_INSPECTION_PROTOCOL = 1;

function reason(code, message) {
    return { code, message };
}

function sameWindowsPath(left, right) {
    return left.localeCompare(right, 'en', { sensitivity: 'accent' }) === 0;
}

function sha256File(filePath, fileSystem) {
    return crypto.createHash('sha256').update(fileSystem.readFileSync(filePath)).digest('hex');
}

function windowsPowerShellEnvironment(sourceEnvironment, targetPath) {
    const childEnvironment = { ...sourceEnvironment, WPB_WINDOWS_HELPER_TRUST_TARGET: targetPath };
    for (const key of Object.keys(childEnvironment)) {
        if (key.toLowerCase() === 'psmodulepath') delete childEnvironment[key];
    }
    return childEnvironment;
}

function inspectWindowsReparsePoint(filePath, options) {
    if (options.platform !== 'win32') return false;
    const spawn = options.spawnSync ?? spawnSync;
    const script = String.raw`
$ErrorActionPreference = 'Stop'
$target = [Environment]::GetEnvironmentVariable('WPB_WINDOWS_HELPER_TRUST_TARGET')
$item = Get-Item -LiteralPath $target -Force
[bool](($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) | ConvertTo-Json -Compress
`;
    const result = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
        encoding: 'utf8',
        windowsHide: true,
        env: windowsPowerShellEnvironment(options.environment ?? process.env, filePath),
        maxBuffer: 64 * 1024
    });
    if (result.error || result.status !== 0) throw new Error('Helper reparse-point inspection failed.');
    const value = JSON.parse(result.stdout.trim());
    if (typeof value !== 'boolean') throw new Error('Helper reparse-point inspection returned invalid data.');
    return value;
}

function inspectRegularFile(filePath, label, options, reasons) {
    const fileSystem = options.fileSystem ?? fs;
    if (!path.isAbsolute(filePath)) {
        reasons.push(reason(`WINDOWS_HELPER_${label}_PATH_INVALID`, `${label} path must be absolute.`));
        return null;
    }
    let stat;
    try {
        stat = fileSystem.lstatSync(filePath);
    } catch {
        reasons.push(reason(`WINDOWS_HELPER_${label}_UNAVAILABLE`, `${label} is unavailable.`));
        return null;
    }
    if (!stat.isFile() || stat.isSymbolicLink()) {
        reasons.push(reason(`WINDOWS_HELPER_${label}_PATH_UNSAFE`, `${label} must be a regular, non-symlink file.`));
        return null;
    }
    try {
        const isReparsePoint = (options.inspectReparsePoint ?? inspectWindowsReparsePoint)(filePath, options);
        if (isReparsePoint) {
            reasons.push(reason(`WINDOWS_HELPER_${label}_PATH_UNSAFE`, `${label} must not be a reparse point.`));
            return null;
        }
    } catch {
        reasons.push(reason(`WINDOWS_HELPER_${label}_PATH_UNVERIFIED`, `${label} reparse-point state could not be verified.`));
        return null;
    }
    try {
        return { stat, realPath: fileSystem.realpathSync.native(filePath) };
    } catch {
        reasons.push(reason(`WINDOWS_HELPER_${label}_PATH_UNVERIFIED`, `${label} canonical path could not be verified.`));
        return null;
    }
}

function readManifest(manifestPath, options, reasons) {
    const inspected = inspectRegularFile(manifestPath, 'MANIFEST', options, reasons);
    if (!inspected) return null;
    try {
        const manifest = JSON.parse((options.fileSystem ?? fs).readFileSync(manifestPath, 'utf8'));
        if (!manifest || Array.isArray(manifest) || typeof manifest !== 'object') throw new Error('invalid manifest');
        return manifest;
    } catch {
        reasons.push(reason('WINDOWS_HELPER_MANIFEST_INVALID', 'Helper manifest is not valid JSON.'));
        return null;
    }
}

export function validateWindowsHelperTrust(options = {}) {
    const helperPath = options.helperPath;
    const manifestPath = options.manifestPath;
    const expectedBundledPath = options.expectedBundledPath;
    const platform = options.platform ?? process.platform;
    const architecture = options.architecture ?? process.arch;
    const fileSystem = options.fileSystem ?? fs;
    const trustReasons = [];
    const replaceBlockingReasons = [];

    if (!helperPath || !manifestPath || !expectedBundledPath) {
        trustReasons.push(reason('WINDOWS_HELPER_TRUST_INPUT_INVALID', 'Helper, manifest, and bundled paths are required.'));
    }
    const helper = helperPath
        ? inspectRegularFile(helperPath, 'BINARY', { ...options, platform }, trustReasons)
        : null;
    let expectedRealPath = null;
    if (expectedBundledPath && !path.isAbsolute(expectedBundledPath)) {
        trustReasons.push(reason('WINDOWS_HELPER_BUNDLED_PATH_INVALID', 'Bundled helper path must be absolute.'));
    } else if (expectedBundledPath) {
        try {
            expectedRealPath = fileSystem.realpathSync.native(expectedBundledPath);
        } catch {
            trustReasons.push(reason('WINDOWS_HELPER_BUNDLED_PATH_UNVERIFIED', 'Bundled helper path could not be verified.'));
        }
    }
    if (helper?.realPath && expectedRealPath && !sameWindowsPath(helper.realPath, expectedRealPath)) {
        trustReasons.push(reason('WINDOWS_HELPER_PATH_MISMATCH', 'Helper is not the expected bundled binary.'));
    }

    const manifest = manifestPath
        ? readManifest(manifestPath, { ...options, platform }, trustReasons)
        : null;
    if (manifest) {
        const requireEqual = (condition, code, message) => {
            if (!condition) trustReasons.push(reason(code, message));
        };
        requireEqual(manifest.manifestSchemaVersion === WINDOWS_HELPER_MANIFEST_SCHEMA_VERSION,
            'WINDOWS_HELPER_MANIFEST_SCHEMA_UNSUPPORTED', 'Helper manifest schema is unsupported.');
        requireEqual(typeof manifest.sourceRevision === 'string' && /^[0-9a-f]{40}$/i.test(manifest.sourceRevision),
            'WINDOWS_HELPER_MANIFEST_INVALID', 'Helper source revision is invalid.');
        requireEqual(typeof manifest.completeForReplace === 'boolean' && typeof manifest.signed === 'boolean',
            'WINDOWS_HELPER_MANIFEST_INVALID', 'Helper capability or signing state is invalid.');
        requireEqual(manifest.helperName === WINDOWS_HELPER_NAME,
            'WINDOWS_HELPER_NAME_MISMATCH', 'Helper name does not match.');
        requireEqual(manifest.helperVersion === (options.expectedHelperVersion ?? WINDOWS_HELPER_VERSION),
            'WINDOWS_HELPER_VERSION_MISMATCH', 'Helper version does not match.');
        requireEqual(manifest.adapter === (options.expectedAdapter ?? WINDOWS_HELPER_ADAPTER),
            'WINDOWS_HELPER_ADAPTER_MISMATCH', 'Helper adapter does not match.');
        requireEqual(manifest.platform === 'win32' && platform === 'win32',
            'WINDOWS_HELPER_PLATFORM_MISMATCH', 'Helper is not a Windows binary.');
        requireEqual(manifest.architecture === WINDOWS_HELPER_PRODUCTION_ARCHITECTURE && architecture === WINDOWS_HELPER_PRODUCTION_ARCHITECTURE,
            'WINDOWS_HELPER_ARCHITECTURE_MISMATCH', 'Only the verified x64 helper is eligible.');
        requireEqual(Array.isArray(manifest.protocolSchemaVersions) && manifest.protocolSchemaVersions.length > 0 &&
            manifest.protocolSchemaVersions.every(version => version === 1 || version === 2) &&
            manifest.protocolSchemaVersions.includes(options.requiredProtocol ?? WINDOWS_HELPER_INSPECTION_PROTOCOL),
        'WINDOWS_HELPER_PROTOCOL_MISMATCH', 'Helper does not advertise the required protocol.');
        requireEqual(manifest.toolchain?.windowsSdkBuildSelectionVerified === true,
            'WINDOWS_HELPER_BUILD_UNVERIFIED', 'The Windows SDK build selection is not verified.');
        if (options.expectedSourceRevision !== undefined) requireEqual(
            manifest.sourceRevision === options.expectedSourceRevision,
            'WINDOWS_HELPER_SOURCE_REVISION_MISMATCH',
            'Helper source revision does not match.'
        );
        if (helper) {
            requireEqual(Number.isInteger(manifest.artifact?.size) && manifest.artifact.size > 0 && manifest.artifact.size === helper.stat.size,
                'WINDOWS_HELPER_SIZE_MISMATCH', 'Helper size does not match its manifest.');
            requireEqual(typeof manifest.artifact?.sha256 === 'string' && /^[0-9a-f]{64}$/.test(manifest.artifact.sha256) &&
                manifest.artifact.sha256 === sha256File(helperPath, fileSystem),
                'WINDOWS_HELPER_HASH_MISMATCH', 'Helper SHA-256 does not match its manifest.');
        }
        if (manifest.completeForReplace !== true) replaceBlockingReasons.push(reason(
            'WINDOWS_HELPER_REPLACE_INCOMPLETE',
            'Inspection-only helper reports completeForReplace=false.'
        ));
        if (manifest.signed !== true) replaceBlockingReasons.push(reason(
            'WINDOWS_HELPER_UNSIGNED',
            'Unsigned helper is not eligible for replace authority.'
        ));
    }

    return {
        trustedForInspection: trustReasons.length === 0,
        trustedForReplace: trustReasons.length === 0 && replaceBlockingReasons.length === 0,
        platformScope: 'win32',
        architectureScope: WINDOWS_HELPER_PRODUCTION_ARCHITECTURE,
        manifest,
        trustReasons,
        replaceBlockingReasons
    };
}
