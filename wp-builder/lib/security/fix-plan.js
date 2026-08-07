import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { analyzeSecurityFile } from './analyzer.js';
import {
    inspectSecurityMetadata,
    metadataBlockingReasons
} from './metadata.js';
import { phpRuntimeBlockingReason } from './php-runtime-contract.js';

export class SecurityPlanError extends Error {
    constructor(message, exitCode = 1, code = 'SECURITY_PLAN_ERROR') {
        super(message);
        this.name = 'SecurityPlanError';
        this.exitCode = exitCode;
        this.code = code;
    }
}

export function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

function isWithinRoot(root, target) {
    const relative = path.relative(root, target);
    return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

export function resolveSecurityTarget(workspaceRoot, requestedPath) {
    if (!requestedPath) throw new SecurityPlanError('--file is required.', 1, 'FILE_REQUIRED');
    const targetPath = path.resolve(workspaceRoot, requestedPath);
    if (!isWithinRoot(path.resolve(workspaceRoot), targetPath)) throw new SecurityPlanError(
        `Security target must be inside the workspace: ${targetPath}`,
        1,
        'OUTSIDE_WORKSPACE'
    );
    if (path.extname(targetPath).toLowerCase() !== '.php') throw new SecurityPlanError(
        `Security target must be a PHP file: ${targetPath}`,
        1,
        'NOT_PHP_FILE'
    );
    return targetPath;
}

function linuxStatsMatch(left, right) {
    return left.dev === right.dev &&
        left.ino === right.ino &&
        left.nlink === right.nlink &&
        left.mode === right.mode &&
        left.uid === right.uid &&
        left.gid === right.gid &&
        left.size === right.size &&
        left.mtimeMs === right.mtimeMs &&
        left.ctimeMs === right.ctimeMs;
}

function readLinuxDescriptor(fileDescriptor, size) {
    const bytes = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
        const count = fs.readSync(fileDescriptor, bytes, offset, size - offset, offset);
        if (count === 0) throw new Error('Linux target changed while its content was being read.');
        offset += count;
    }
    return bytes;
}

function addLinuxInspectionBlock(metadata, code, message) {
    return {
        ...metadata,
        posix: {
            ...metadata.posix,
            binding: {
                ...metadata.posix?.binding,
                identityVerified: false,
                stablePasses: 2
            }
        },
        capability: {
            ...metadata.capability,
            reproducible: false,
            blockingReasons: [
                ...(metadata.capability?.blockingReasons ?? []),
                { code, message }
            ]
        }
    };
}

function takeLinuxSecurityFileSnapshot(filePath, options) {
    const flags = fs.constants.O_RDONLY |
        (fs.constants.O_NOFOLLOW ?? 0) |
        (fs.constants.O_NONBLOCK ?? 0);
    let fileDescriptor;
    try {
        fileDescriptor = fs.openSync(filePath, flags);
        const beforeRead = fs.fstatSync(fileDescriptor);
        if (!beforeRead.isFile()) return {
            state: 'unsafe',
            normalFile: false,
            symlink: false,
            size: beforeRead.size,
            hash: null,
            bytes: null,
            reason: 'Security target is not a normal file.'
        };

        const bytes = readLinuxDescriptor(fileDescriptor, beforeRead.size);
        const afterRead = fs.fstatSync(fileDescriptor);
        const confirmBytes = readLinuxDescriptor(fileDescriptor, afterRead.size);
        const afterConfirmRead = fs.fstatSync(fileDescriptor);
        if (!linuxStatsMatch(beforeRead, afterRead) ||
            !linuxStatsMatch(afterRead, afterConfirmRead) ||
            !bytes.equals(confirmBytes)) {
            return {
                state: 'unsafe',
                normalFile: false,
                symlink: false,
                size: afterConfirmRead.size,
                hash: null,
                bytes: null,
                reason: 'Linux target changed while its descriptor-bound snapshot was being read.'
            };
        }

        const metadataOptions = {
            ...(options.metadata ?? {}),
            linuxFileDescriptor: fileDescriptor,
            linuxFileSystemType: typeof fs.statfsSync === 'function'
            ? fs.statfsSync(`/proc/self/fd/${fileDescriptor}`).type
            : null
        };
        const firstMetadata = inspectSecurityMetadata(filePath, afterConfirmRead, metadataOptions);
        const afterFirstInspection = fs.fstatSync(fileDescriptor);
        const secondMetadata = firstMetadata.capability?.inspectable
            ? inspectSecurityMetadata(filePath, afterFirstInspection, metadataOptions)
            : firstMetadata;
        const afterSecondInspection = fs.fstatSync(fileDescriptor);
        const finalPathStat = fs.lstatSync(filePath);
        if (finalPathStat.isSymbolicLink() ||
            !finalPathStat.isFile() ||
            !linuxStatsMatch(afterConfirmRead, afterFirstInspection) ||
            !linuxStatsMatch(afterFirstInspection, afterSecondInspection) ||
            finalPathStat.dev !== afterSecondInspection.dev ||
            finalPathStat.ino !== afterSecondInspection.ino ||
            finalPathStat.nlink !== afterSecondInspection.nlink) {
            return {
                state: 'unsafe',
                normalFile: false,
                symlink: finalPathStat.isSymbolicLink(),
                size: afterSecondInspection.size,
                hash: null,
                bytes: null,
                reason: 'Linux target identity changed during descriptor-bound metadata inspection.'
            };
        }

        const metadataStable = firstMetadata.securityFingerprint === secondMetadata.securityFingerprint &&
            firstMetadata.posix?.inspectionFingerprint === secondMetadata.posix?.inspectionFingerprint;
        const metadata = metadataStable
            ? {
                ...secondMetadata,
                posix: {
                    ...secondMetadata.posix,
                    binding: {
                        ...secondMetadata.posix?.binding,
                        identityVerified: true,
                        stablePasses: firstMetadata.capability?.inspectable ? 2 : 1
                    }
                }
            }
            : addLinuxInspectionBlock(
                secondMetadata,
                'POSIX_METADATA_CHANGED_DURING_INSPECTION',
                'Linux ACL or xattr metadata changed during descriptor-bound inspection.'
            );
        return {
            state: 'present',
            normalFile: true,
            symlink: false,
            size: bytes.length,
            hash: sha256(bytes),
            bytes,
            metadata,
            reason: null
        };
    } catch (error) {
        if (error.code === 'ENOENT') return {
            state: 'missing',
            normalFile: false,
            symlink: false,
            size: 0,
            hash: null,
            bytes: null,
            reason: 'Security target does not exist.'
        };
        if (error.code === 'ELOOP') {
            const stat = fs.lstatSync(filePath);
            return {
                state: 'unsafe',
                normalFile: false,
                symlink: true,
                size: stat.size,
                hash: null,
                bytes: null,
                reason: 'Symbolic links are not eligible for Security Fix apply.'
            };
        }
        return {
            state: 'unsafe',
            normalFile: false,
            symlink: false,
            size: 0,
            hash: null,
            bytes: null,
            reason: error.message
        };
    } finally {
        if (fileDescriptor !== undefined) fs.closeSync(fileDescriptor);
    }
}

export function takeSecurityFileSnapshot(filePath, options = {}) {
    if ((options.metadata?.platform ?? process.platform) === 'linux') {
        return takeLinuxSecurityFileSnapshot(filePath, options);
    }
    try {
        const stat = fs.lstatSync(filePath);
        if (stat.isSymbolicLink()) return {
            state: 'unsafe',
            normalFile: false,
            symlink: true,
            size: stat.size,
            hash: null,
            bytes: null,
            reason: 'Symbolic links are not eligible for Security Fix apply.'
        };
        if (!stat.isFile()) return {
            state: 'unsafe',
            normalFile: false,
            symlink: false,
            size: stat.size,
            hash: null,
            bytes: null,
            reason: 'Security target is not a normal file.'
        };
        const bytes = fs.readFileSync(filePath);
        const metadata = inspectSecurityMetadata(filePath, stat, options.metadata ?? {});
        return {
            state: 'present',
            normalFile: true,
            symlink: false,
            size: bytes.length,
            hash: sha256(bytes),
            bytes,
            metadata,
            reason: null
        };
    } catch (error) {
        if (error.code === 'ENOENT') return {
            state: 'missing',
            normalFile: false,
            symlink: false,
            size: 0,
            hash: null,
            bytes: null,
            reason: 'Security target does not exist.'
        };
        return {
            state: 'unsafe',
            normalFile: false,
            symlink: false,
            size: 0,
            hash: null,
            bytes: null,
            reason: error.message
        };
    }
}

function inspectEncoding(bytes) {
    const hasUtf8Bom = bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
    const hasUnsupportedBom = (
        (bytes[0] === 0xff && bytes[1] === 0xfe) ||
        (bytes[0] === 0xfe && bytes[1] === 0xff) ||
        (bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0xfe && bytes[3] === 0xff) ||
        (bytes[0] === 0xff && bytes[1] === 0xfe && bytes[2] === 0x00 && bytes[3] === 0x00)
    );
    const decoded = bytes.toString('utf8');
    const validUtf8 = Buffer.from(decoded, 'utf8').equals(bytes);
    return {
        supported: validUtf8 && !hasUnsupportedBom,
        charset: validUtf8 && !hasUnsupportedBom ? 'utf-8' : 'unsupported',
        bom: hasUtf8Bom,
        reason: validUtf8 && !hasUnsupportedBom ? null : 'Only UTF-8 and UTF-8 with BOM are supported.'
    };
}

function detectNewline(bytes) {
    const text = bytes.toString('utf8');
    const crlf = (text.match(/\r\n/g) ?? []).length;
    const lf = (text.match(/(?<!\r)\n/g) ?? []).length;
    return {
        style: crlf > 0 && lf > 0 ? 'MIXED' : crlf > 0 ? 'CRLF' : 'LF',
        mixed: crlf > 0 && lf > 0,
        trailing: /(?:\r\n|\n)$/.test(text)
    };
}

function applyReplacements(originalBytes, replacements) {
    let desired = Buffer.from(originalBytes);
    const descending = [...replacements].sort((left, right) => right.startByte - left.startByte);
    for (const replacement of descending) {
        desired = Buffer.concat([
            desired.subarray(0, replacement.startByte),
            Buffer.from(replacement.replacementText, 'utf8'),
            desired.subarray(replacement.endByte)
        ]);
    }
    return desired;
}

function findOverlaps(replacements) {
    const ordered = [...replacements].sort((left, right) => left.startByte - right.startByte);
    const overlaps = [];
    for (let index = 1; index < ordered.length; index += 1) {
        if (ordered[index].startByte < ordered[index - 1].endByte) {
            overlaps.push([ordered[index - 1], ordered[index]]);
        }
    }
    return overlaps;
}

export function lintPhpBytes(bytes, options = {}) {
    const command = options.phpCommand ?? 'php';
    const args = options.filePath ? ['-l', options.filePath] : ['-l'];
    const result = spawnSync(command, args, {
        input: options.filePath ? undefined : bytes,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true
    });
    if (result.error?.code === 'ENOENT') return {
        available: false,
        passed: false,
        exitCode: null,
        output: 'PHP runtime is unavailable.'
    };
    return {
        available: true,
        passed: result.status === 0,
        exitCode: result.status,
        output: [result.stdout, result.stderr].filter(Boolean).join('\n').trim()
    };
}

function contentLines(bytes) {
    if (!bytes || bytes.length === 0) return [];
    const lines = bytes.toString('utf8').replace(/\r\n/g, '\n').split('\n');
    if (lines.at(-1) === '') lines.pop();
    return lines;
}

export function createSecurityUnifiedDiff(originalBytes, desiredBytes, relativePath) {
    if (originalBytes.equals(desiredBytes)) return '';
    const oldLines = contentLines(originalBytes);
    const newLines = contentLines(desiredBytes);
    let prefix = 0;
    while (prefix < oldLines.length && prefix < newLines.length && oldLines[prefix] === newLines[prefix]) prefix += 1;
    let suffix = 0;
    while (
        suffix < oldLines.length - prefix &&
        suffix < newLines.length - prefix &&
        oldLines[oldLines.length - 1 - suffix] === newLines[newLines.length - 1 - suffix]
    ) suffix += 1;

    const context = 3;
    const oldStart = Math.max(0, prefix - context);
    const newStart = Math.max(0, prefix - context);
    const oldChangedEnd = oldLines.length - suffix;
    const newChangedEnd = newLines.length - suffix;
    const oldEnd = Math.min(oldLines.length, oldChangedEnd + context);
    const newEnd = Math.min(newLines.length, newChangedEnd + context);
    const oldCount = oldEnd - oldStart;
    const newCount = newEnd - newStart;
    const output = [`--- a/${relativePath}`, `+++ b/${relativePath}`];
    output.push(`@@ -${oldCount === 0 ? 0 : oldStart + 1},${oldCount} +${newCount === 0 ? 0 : newStart + 1},${newCount} @@`);
    oldLines.slice(oldStart, prefix).forEach(line => output.push(` ${line}`));
    oldLines.slice(prefix, oldChangedEnd).forEach(line => output.push(`-${line}`));
    newLines.slice(prefix, newChangedEnd).forEach(line => output.push(`+${line}`));
    newLines.slice(newChangedEnd, newEnd).forEach(line => output.push(` ${line}`));
    return output.join('\n');
}

function blockedPlan({ targetPath, workspaceRoot, snapshot, reason, code }) {
    return {
        schemaVersion: 1,
        targetPath,
        relativePath: path.relative(workspaceRoot, targetPath).replace(/\\/g, '/'),
        snapshot,
        encoding: null,
        newline: null,
        findings: [],
        replacements: [],
        originalBytes: snapshot.bytes,
        desiredBytes: snapshot.bytes,
        desiredHash: snapshot.hash,
        diff: '',
        lint: { available: true, passed: false, exitCode: null, output: 'Not run.' },
        hasChanges: false,
        counts: { findings: 0, autoFixable: 0, diagnosticOnly: 0 },
        blockingReasons: [{ code, message: reason }],
        canApply: false
    };
}

export function buildSecurityFixPlan({
    workspaceRoot,
    file,
    phpCommand = 'php',
    tokenizerPhpCommand = phpCommand,
    lintPhpCommand = phpCommand,
    tokenizerPath,
    metadataOptions
}) {
    const targetPath = resolveSecurityTarget(workspaceRoot, file);
    const snapshot = takeSecurityFileSnapshot(targetPath, { metadata: metadataOptions });
    if (snapshot.state !== 'present') return blockedPlan({
        targetPath,
        workspaceRoot,
        snapshot,
        reason: snapshot.reason,
        code: snapshot.state === 'missing' ? 'TARGET_MISSING' : 'TARGET_UNSAFE'
    });

    const encoding = inspectEncoding(snapshot.bytes);
    if (!encoding.supported) return blockedPlan({
        targetPath,
        workspaceRoot,
        snapshot,
        reason: encoding.reason,
        code: 'UNSUPPORTED_ENCODING'
    });

    const analysis = analyzeSecurityFile({
        filePath: targetPath,
        bytes: snapshot.bytes,
        phpCommand: tokenizerPhpCommand,
        tokenizerPath
    });
    const replacements = analysis.findings
        .filter(finding => finding.autoFixable && finding.replacement)
        .map(finding => ({
            ...finding.replacement,
            findingId: finding.id,
            originalHash: sha256(snapshot.bytes.subarray(finding.range.startByte, finding.range.endByte))
        }));
    const overlaps = findOverlaps(replacements);
    const blockingReasons = [];
    blockingReasons.push(...metadataBlockingReasons(snapshot.metadata));
    const runtimeBlocking = phpRuntimeBlockingReason(analysis.tokenizer.runtime);
    if (runtimeBlocking) blockingReasons.push(runtimeBlocking);
    if (!analysis.canAnalyze) {
        const code = analysis.tokenizer.errorCode ?? (
            analysis.tokenizer.available ? 'WPB-SCF-PARSE-UNSAFE' : 'PHP_TOKENIZER_UNAVAILABLE'
        );
        if (!blockingReasons.some(reason => reason.code === code)) blockingReasons.push({
            code,
            message: analysis.tokenizer.error
        });
    }
    if (overlaps.length > 0) blockingReasons.push({
        code: 'OVERLAPPING_RANGES',
        message: 'Auto-fix replacement ranges overlap.'
    });

    const desiredBytes = overlaps.length === 0
        ? applyReplacements(snapshot.bytes, replacements)
        : Buffer.from(snapshot.bytes);
    const lint = analysis.canAnalyze
        ? lintPhpBytes(desiredBytes, { phpCommand: lintPhpCommand })
        : { available: true, passed: false, exitCode: null, output: 'Not run because PHP parsing failed.' };
    if (!lint.available) blockingReasons.push({
        code: 'PHP_LINT_UNAVAILABLE',
        message: lint.output
    });
    else if (!lint.passed) blockingReasons.push({
        code: 'PHP_LINT_FAILED',
        message: lint.output
    });

    const relativePath = path.relative(workspaceRoot, targetPath).replace(/\\/g, '/');
    const autoFixable = analysis.findings.filter(finding => finding.autoFixable).length;
    return {
        schemaVersion: 1,
        targetPath,
        relativePath,
        snapshot,
        encoding,
        newline: detectNewline(snapshot.bytes),
        tokenizer: analysis.tokenizer,
        findings: analysis.findings,
        replacements,
        originalBytes: snapshot.bytes,
        desiredBytes,
        desiredHash: sha256(desiredBytes),
        diff: createSecurityUnifiedDiff(snapshot.bytes, desiredBytes, relativePath),
        lint,
        hasChanges: !snapshot.bytes.equals(desiredBytes),
        counts: {
            findings: analysis.findings.length,
            autoFixable,
            diagnosticOnly: analysis.findings.length - autoFixable
        },
        blockingReasons,
        canApply: blockingReasons.length === 0
    };
}
