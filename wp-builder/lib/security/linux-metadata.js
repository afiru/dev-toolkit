import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

export const LINUX_METADATA_ADAPTER = 'linux-tools-v1';

function digest(value) {
    return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function reason(code, message) {
    return { code, message };
}

function runInspector(command, args, filePath, spawn) {
    const result = spawn(command, [...args, '--', filePath], {
        encoding: 'utf8',
        windowsHide: true,
        env: {
            ...process.env,
            LC_ALL: 'C',
            LANG: 'C'
        },
        timeout: 5000,
        maxBuffer: 4 * 1024 * 1024
    });
    if (result.error?.code === 'ENOENT') return {
        ok: false,
        unavailable: true,
        detail: `${command} is unavailable.`
    };
    if (result.error || result.status !== 0) return {
        ok: false,
        unavailable: false,
        detail: `${command} inspection failed: ${result.error?.message ?? result.stderr?.trim() ?? `exit ${result.status}`}`
    };
    return { ok: true, stdout: result.stdout };
}

function modePermissions(mode) {
    const render = bits => [4, 2, 1]
        .map((mask, index) => bits & mask ? 'rwx'[index] : '-')
        .join('');
    return {
        user: render((mode >> 6) & 7),
        group: render((mode >> 3) & 7),
        other: render(mode & 7)
    };
}

export function parseGetfaclOutput(output, mode) {
    if (typeof output !== 'string' || output.includes('\0')) throw new Error('getfacl returned invalid text.');
    const lines = output.split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean)
        .filter(line => !line.startsWith('#'));
    if (lines.length === 0) throw new Error('getfacl returned no ACL entries.');

    const entries = lines.map(line => {
        const normalized = line.replace(/\s+#effective:[rwx-]{3}$/, '');
        const match = normalized.match(/^(default:)?(user|group|mask|other):([^:]*):([rwx-]{3})$/);
        if (!match) throw new Error('getfacl returned an unsupported ACL entry.');
        return {
            normalized,
            defaultEntry: Boolean(match[1]),
            tag: match[2],
            qualifier: match[3],
            permissions: match[4]
        };
    });
    const base = entries.filter(entry => (
        !entry.defaultEntry &&
        entry.qualifier === '' &&
        ['user', 'group', 'other'].includes(entry.tag)
    ));
    if (base.length !== 3 || new Set(base.map(entry => entry.tag)).size !== 3) {
        throw new Error('getfacl did not return exactly one base user/group/other entry.');
    }
    const expected = modePermissions(mode);
    for (const entry of base) {
        if (entry.permissions !== expected[entry.tag]) throw new Error('ACL base entries do not match the file mode.');
    }
    const additional = entries.filter(entry => !base.includes(entry));
    return {
        inspected: true,
        present: additional.length > 0,
        entryCount: entries.length,
        digest: digest(entries.map(entry => entry.normalized))
    };
}

export function parseGetfattrOutput(output) {
    if (typeof output !== 'string' || output.includes('\0')) throw new Error('getfattr returned invalid text.');
    const entries = [];
    const seen = new Set();
    for (const rawLine of output.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line) continue;
        if (line.startsWith('# file: ')) continue;
        const separator = line.indexOf('=');
        if (separator <= 0) throw new Error('getfattr returned malformed output.');
        const name = line.slice(0, separator);
        const value = line.slice(separator + 1);
        if (!/^[A-Za-z0-9_-]+\.[^=\s]+$/.test(name) || !/^0x(?:[0-9A-Fa-f]{2})*$/.test(value)) {
            throw new Error('getfattr returned an unsupported attribute encoding.');
        }
        if (seen.has(name)) throw new Error('getfattr returned a duplicate attribute name.');
        seen.add(name);
        entries.push({ name, value: value.toLowerCase() });
    }
    entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    const securitySensitive = entries.some(entry => (
        entry.name.startsWith('security.') ||
        entry.name.startsWith('trusted.') ||
        entry.name.startsWith('system.posix_acl_')
    ));
    return {
        inspected: true,
        present: entries.length > 0,
        count: entries.length,
        digest: digest(entries),
        securitySensitive
    };
}

function unavailableResult(detail) {
    return {
        readonly: null,
        posix: {
            adapter: LINUX_METADATA_ADAPTER,
            acl: { inspected: false, present: null, entryCount: null, digest: null },
            xattrs: { inspected: false, present: null, count: null, digest: null },
            securityMetadata: { present: null },
            inspectionFingerprint: null
        },
        securityFingerprint: null,
        replacementFingerprint: null,
        capability: {
            inspectable: false,
            reproducible: false,
            blockingReasons: [reason('POSIX_METADATA_INSPECTOR_UNAVAILABLE', detail)]
        }
    };
}

function failedResult(detail) {
    return {
        readonly: null,
        posix: {
            adapter: LINUX_METADATA_ADAPTER,
            acl: { inspected: false, present: null, entryCount: null, digest: null },
            xattrs: { inspected: false, present: null, count: null, digest: null },
            securityMetadata: { present: null },
            inspectionFingerprint: null
        },
        securityFingerprint: null,
        replacementFingerprint: null,
        capability: {
            inspectable: false,
            reproducible: false,
            blockingReasons: [reason('POSIX_METADATA_INSPECTION_FAILED', detail)]
        }
    };
}

export function inspectLinuxMetadata(filePath, stat, options = {}) {
    const spawn = options.spawnSync ?? spawnSync;
    const aclResult = runInspector('getfacl', [
        '--numeric',
        '--omit-header',
        '--absolute-names'
    ], filePath, spawn);
    if (!aclResult.ok) return aclResult.unavailable
        ? unavailableResult(aclResult.detail)
        : failedResult(aclResult.detail);

    const xattrResult = runInspector('getfattr', [
        '--dump',
        '--match=-',
        '--encoding=hex',
        '--absolute-names'
    ], filePath, spawn);
    if (!xattrResult.ok) return xattrResult.unavailable
        ? unavailableResult(xattrResult.detail)
        : failedResult(xattrResult.detail);

    let acl;
    let xattrs;
    try {
        acl = parseGetfaclOutput(aclResult.stdout, stat.mode);
        xattrs = parseGetfattrOutput(xattrResult.stdout);
    } catch (error) {
        return failedResult(error.message);
    }

    const readonly = (stat.mode & 0o222) === 0;
    const reasons = [];
    if (readonly) reasons.push(reason('READ_ONLY_TARGET', 'Read-only files are not eligible for Security Fix apply.'));
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) reasons.push(reason(
        'POSIX_OWNER_UNSUPPORTED',
        'The POSIX file owner cannot be reproduced by the current process.'
    ));
    if (typeof process.getgid === 'function' && stat.gid !== process.getgid()) reasons.push(reason(
        'POSIX_GROUP_UNSUPPORTED',
        'The POSIX file group cannot be reproduced by the current process.'
    ));
    if ((stat.mode & 0o7000) !== 0) reasons.push(reason(
        'POSIX_SPECIAL_MODE_UNSUPPORTED',
        'Files with setuid, setgid, or sticky mode bits are not eligible for Security Fix apply.'
    ));
    if (acl.present) reasons.push(reason(
        'POSIX_ACL_PRESENT',
        'Files with additional POSIX ACL entries are not eligible until ACL preservation is supported.'
    ));
    if (xattrs.present) reasons.push(reason(
        'POSIX_XATTR_PRESENT',
        'Files with extended attributes are not eligible until xattr preservation is supported.'
    ));
    if (xattrs.securitySensitive) reasons.push(reason(
        'POSIX_SECURITY_XATTR_PRESENT',
        'Security-sensitive extended metadata is present and cannot be preserved safely.'
    ));

    const posix = {
        adapter: LINUX_METADATA_ADAPTER,
        acl,
        xattrs: {
            inspected: xattrs.inspected,
            present: xattrs.present,
            count: xattrs.count,
            digest: xattrs.digest
        },
        securityMetadata: { present: xattrs.securitySensitive }
    };
    posix.inspectionFingerprint = digest({
        adapter: posix.adapter,
        aclDigest: acl.digest,
        xattrDigest: xattrs.digest,
        securityMetadataPresent: posix.securityMetadata.present,
        inspected: acl.inspected && xattrs.inspected
    });
    const securityState = {
        adapter: posix.adapter,
        mode: stat.mode,
        uid: stat.uid,
        gid: stat.gid,
        readonly,
        inspectionFingerprint: posix.inspectionFingerprint,
        inspectable: true
    };
    const fingerprint = digest(securityState);
    return {
        readonly,
        posix,
        securityFingerprint: fingerprint,
        replacementFingerprint: fingerprint,
        capability: {
            inspectable: true,
            reproducible: reasons.length === 0,
            blockingReasons: reasons
        }
    };
}

export function unsupportedPosixMetadata(platform) {
    return {
        readonly: null,
        posix: {
            adapter: `${platform}-unsupported`,
            acl: { inspected: false, present: null, entryCount: null, digest: null },
            xattrs: { inspected: false, present: null, count: null, digest: null },
            securityMetadata: { present: null },
            inspectionFingerprint: null
        },
        securityFingerprint: null,
        replacementFingerprint: null,
        capability: {
            inspectable: false,
            reproducible: false,
            blockingReasons: [reason(
                'POSIX_METADATA_UNSUPPORTED_PLATFORM',
                `Security Fix apply is not supported on ${platform} until a dedicated metadata inspector is available.`
            )]
        }
    };
}
