import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

export const WINDOWS_INSPECTOR_SCHEMA_VERSION = 1;
export const WINDOWS_INSPECTOR_HELPER_VERSION = '0.1.0';
export const WINDOWS_INSPECTOR_MAX_OUTPUT = 1024 * 1024;
export const WINDOWS_INSPECTOR_TIMEOUT_MS = 5000;

const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(moduleDirectory, '..', '..');

function taggedDigest(tag, bytes) {
    return `sha256:${crypto.createHash('sha256')
        .update(Buffer.from(`${tag}\0`, 'utf8'))
        .update(bytes)
        .digest('hex')}`;
}

export function fingerprintWindowsSid(sid) {
    return taggedDigest('wpb-sid-v1', Buffer.from(String(sid), 'utf8'));
}

export function fingerprintWindowsDacl({ state, protected: protectedDacl, revision, sddl }) {
    const canonical = [
        `state=${state}`,
        `protected=${protectedDacl ? 'true' : 'false'}`,
        `revision=${revision}`,
        `sddl=${sddl ?? ''}`
    ].join('\0');
    return taggedDigest('wpb-dacl-v1', Buffer.from(canonical, 'utf8'));
}

function uint64Le(value) {
    const result = Buffer.alloc(8);
    result.writeBigUInt64LE(BigInt(value));
    return result;
}

function uint32Le(value) {
    const result = Buffer.alloc(4);
    result.writeUInt32LE(value);
    return result;
}

export function fingerprintWindowsStreams(streams) {
    const normalized = streams.map(stream => ({
        name: String(stream.name),
        length: String(stream.length),
        contentSha256: String(stream.contentSha256).toLowerCase()
    })).sort((left, right) => Buffer.compare(
        Buffer.from(left.name, 'utf8'),
        Buffer.from(right.name, 'utf8')
    ));
    const chunks = [Buffer.from('wpb-ads-v1\0', 'utf8')];
    for (const stream of normalized) {
        const name = Buffer.from(stream.name, 'utf8');
        const hash = Buffer.from(stream.contentSha256, 'hex');
        if (hash.length !== 32) throw new Error('Invalid ADS content SHA-256.');
        chunks.push(uint32Le(name.length), name, uint64Le(stream.length), hash);
    }
    return `sha256:${crypto.createHash('sha256').update(Buffer.concat(chunks)).digest('hex')}`;
}

export function fingerprintWindowsStreamInventory(streams) {
    const normalized = streams.map(stream => ({
        name: String(stream.name),
        length: String(stream.length)
    })).sort((left, right) => Buffer.compare(
        Buffer.from(left.name, 'utf8'),
        Buffer.from(right.name, 'utf8')
    ));
    const chunks = [Buffer.from('wpb-ads-inventory-v1\0', 'utf8')];
    for (const stream of normalized) {
        const name = Buffer.from(stream.name, 'utf8');
        chunks.push(uint32Le(name.length), name, uint64Le(stream.length));
    }
    return `sha256:${crypto.createHash('sha256').update(Buffer.concat(chunks)).digest('hex')}`;
}

export function getBundledWindowsInspectorPath(options = {}) {
    const architecture = options.architecture ?? process.arch;
    return path.join(
        options.repositoryRoot ?? repositoryRoot,
        'native',
        'windows-inspector',
        'bin',
        `win32-${architecture}`,
        'wpb-windows-inspector.exe'
    );
}

function unavailable(code, message, helperPath) {
    return {
        status: 'unavailable',
        inspected: false,
        helperPath,
        code,
        message
    };
}

function failed(code, message, helperPath, response = null) {
    return {
        status: 'failed',
        inspected: false,
        helperPath,
        code,
        message,
        response
    };
}

function containsRawMetadata(value, parentKey = '') {
    if (!value || typeof value !== 'object') return false;
    for (const [key, child] of Object.entries(value)) {
        const normalized = key.toLowerCase();
        if (
            normalized === 'sddl' ||
            normalized.endsWith('sid') ||
            normalized === 'streamname' ||
            normalized === 'adsname' ||
            normalized === 'adscontent' ||
            normalized === 'rawmetadata' ||
            normalized === 'rawsecuritydescriptor'
        ) return true;
        if (containsRawMetadata(child, key || parentKey)) return true;
    }
    return false;
}

function validateSuccessResponse(response, requestId) {
    if (response.schemaVersion !== WINDOWS_INSPECTOR_SCHEMA_VERSION) {
        return 'Helper response schemaVersion is unsupported.';
    }
    if (response.requestId !== requestId) return 'Helper response requestId does not match.';
    if (response.operation !== 'inspect') return 'Helper response operation is invalid.';
    if (response.ok !== true) return null;
    if (typeof response.helperVersion !== 'string' || response.helperVersion.length === 0) {
        return 'Helper response helperVersion is missing.';
    }
    if (response.adapter !== 'windows-native-inspector-v1') {
        return 'Helper response adapter is unsupported.';
    }
    if (response.capabilities?.completeForReplace !== false) {
        return 'Inspection-only helper must report completeForReplace=false.';
    }
    if (typeof response.file?.size !== 'string' || typeof response.file?.linkCount !== 'string') {
        return 'Helper response must encode size and linkCount as decimal strings.';
    }
    if (containsRawMetadata(response)) return 'Helper response contains forbidden raw metadata.';
    return null;
}

export function inspectWindowsNative(targetPath, options = {}) {
    const helperPath = options.helperPath ?? getBundledWindowsInspectorPath(options);
    const existsSync = options.existsSync ?? fs.existsSync;
    const statSync = options.statSync ?? fs.statSync;
    if (!existsSync(helperPath)) return unavailable(
        'WINDOWS_NATIVE_INSPECTOR_UNAVAILABLE',
        'Bundled Windows native inspector is not installed.',
        helperPath
    );
    try {
        if (!statSync(helperPath).isFile()) return unavailable(
            'WINDOWS_NATIVE_INSPECTOR_INVALID',
            'Bundled Windows native inspector path is not a regular file.',
            helperPath
        );
    } catch (error) {
        return unavailable(
            'WINDOWS_NATIVE_INSPECTOR_UNAVAILABLE',
            `Bundled Windows native inspector could not be checked: ${error.message}`,
            helperPath
        );
    }

    const requestId = options.requestId ?? crypto.randomUUID();
    const request = {
        schemaVersion: WINDOWS_INSPECTOR_SCHEMA_VERSION,
        operation: 'inspect',
        requestId,
        target: { path: path.resolve(targetPath) }
    };
    const spawn = options.spawnSync ?? spawnSync;
    const result = spawn(helperPath, [], {
        input: JSON.stringify(request),
        encoding: 'utf8',
        windowsHide: true,
        timeout: options.timeoutMs ?? WINDOWS_INSPECTOR_TIMEOUT_MS,
        maxBuffer: options.maxOutputBytes ?? WINDOWS_INSPECTOR_MAX_OUTPUT,
        env: options.env ?? process.env
    });
    if (result.error?.code === 'ETIMEDOUT') return failed(
        'WINDOWS_NATIVE_INSPECTOR_TIMEOUT',
        'Windows native inspector timed out.',
        helperPath
    );
    if (result.error) return failed(
        'WINDOWS_NATIVE_INSPECTOR_EXEC_FAILED',
        `Windows native inspector could not be executed: ${result.error.message}`,
        helperPath
    );
    const stdout = result.stdout ?? '';
    const maxOutputBytes = options.maxOutputBytes ?? WINDOWS_INSPECTOR_MAX_OUTPUT;
    if (Buffer.byteLength(stdout, 'utf8') > maxOutputBytes) return failed(
        'WINDOWS_NATIVE_INSPECTOR_OUTPUT_TOO_LARGE',
        'Windows native inspector output exceeded the configured limit.',
        helperPath
    );
    let response;
    try {
        response = JSON.parse(stdout);
    } catch {
        return failed(
            'WINDOWS_NATIVE_INSPECTOR_MALFORMED_RESPONSE',
            'Windows native inspector returned malformed JSON.',
            helperPath
        );
    }
    if (!response || Array.isArray(response) || typeof response !== 'object') return failed(
        'WINDOWS_NATIVE_INSPECTOR_MALFORMED_RESPONSE',
        'Windows native inspector response must be one JSON object.',
        helperPath
    );
    const validationError = validateSuccessResponse(response, requestId);
    if (validationError) return failed(
        'WINDOWS_NATIVE_INSPECTOR_PROTOCOL_ERROR',
        validationError,
        helperPath
    );
    if (result.status !== 0 || response.ok !== true) return failed(
        response.error?.code ?? 'WINDOWS_NATIVE_INSPECTOR_FAILED',
        'Windows native inspection did not complete successfully.',
        helperPath,
        response
    );
    return {
        status: 'inspected',
        inspected: true,
        helperPath,
        response
    };
}
