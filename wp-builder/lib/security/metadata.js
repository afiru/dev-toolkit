import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
    inspectLinuxMetadata,
    unsupportedPosixMetadata
} from './linux-metadata.js';
import {
    fingerprintWindowsDacl,
    fingerprintWindowsSid,
    fingerprintWindowsStreamInventory,
    inspectWindowsNative
} from './windows-native-inspector.js';

function digest(value) {
    return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function blockingReason(code, message) {
    return { code, message };
}

const WINDOWS_INSPECTION_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$target = [Environment]::GetEnvironmentVariable('WPB_SECURITY_METADATA_TARGET')
$item = Get-Item -LiteralPath $target -Force
$acl = Get-Acl -LiteralPath $target
$ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
$groupSid = $acl.GetGroup([System.Security.Principal.SecurityIdentifier]).Value
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor
    [System.Security.AccessControl.AccessControlSections]::Group -bor
    [System.Security.AccessControl.AccessControlSections]::Access
$sddl = $acl.GetSecurityDescriptorSddlForm($sections)
$daclOnlySddl = $acl.GetSecurityDescriptorSddlForm(
    [System.Security.AccessControl.AccessControlSections]::Access
)
$rawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
    $acl.GetSecurityDescriptorBinaryForm(),
    0
)
$daclPresent = (($rawDescriptor.ControlFlags -band
    [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -ne 0)
$daclState = if (-not $daclPresent) {
    'missing'
} elseif ($null -eq $rawDescriptor.DiscretionaryAcl) {
    'null'
} elseif ($rawDescriptor.DiscretionaryAcl.Count -eq 0) {
    'empty'
} else {
    'present'
}
$daclRevision = if ($null -eq $rawDescriptor.DiscretionaryAcl) {
    0
} else {
    [int]$rawDescriptor.DiscretionaryAcl.Revision
}
$explicitRules = @($acl.Access | Where-Object { -not $_.IsInherited })
$streams = @(Get-Item -LiteralPath $target -Stream * -ErrorAction Stop |
    Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne '::$DATA' } |
    ForEach-Object { [ordered]@{ name = [string]$_.Stream; length = [int64]$_.Length } })
[ordered]@{
    readonly = [bool](($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0)
    attributes = [int64]$item.Attributes
    aclProtected = [bool]$acl.AreAccessRulesProtected
    explicitAccessRuleCount = [int]$explicitRules.Count
    ownerSid = [string]$ownerSid
    groupSid = [string]$groupSid
    currentSid = [string]$currentSid
    daclSddl = [string]$sddl
    daclOnlySddl = [string]$daclOnlySddl
    daclState = [string]$daclState
    daclRevision = [int]$daclRevision
    streams = $streams
} | ConvertTo-Json -Compress -Depth 5
`;

function compareWindowsInspectors(windows, nativeInspection) {
    if (nativeInspection.status !== 'inspected') return {
        status: nativeInspection.status,
        compared: false,
        matching: null,
        differences: [],
        diagnostic: null,
        native: nativeInspection
    };
    const response = nativeInspection.response;
    const streamFingerprint = fingerprintWindowsStreamInventory(windows.streams);
    const expected = {
        readonly: windows.readonly,
        attributes: Number(windows.attributes),
        daclFingerprint: fingerprintWindowsDacl({
            state: windows.daclState,
            protected: windows.aclProtected,
            revision: windows.daclRevision,
            sddl: windows.daclOnlySddl
        }),
        daclProtected: windows.aclProtected,
        ownerFingerprint: fingerprintWindowsSid(windows.ownerSid),
        groupFingerprint: fingerprintWindowsSid(windows.groupSid),
        streamCount: windows.streams.length,
        streamDigest: streamFingerprint,
        explicitAccessRuleCount: windows.explicitAccessRuleCount
    };
    const actual = {
        readonly: response.file?.readonly,
        attributes: Number.parseInt(response.file?.attributes, 16),
        daclFingerprint: response.security?.daclFingerprint,
        daclProtected: response.security?.daclProtected,
        ownerFingerprint: response.security?.ownerFingerprint,
        groupFingerprint: response.security?.groupFingerprint,
        streamCount: response.streams?.count,
        streamDigest: response.streams?.inventoryDigest,
        explicitAccessRuleCount: response.compatibility?.explicitAccessRuleCount
    };
    const differences = Object.keys(expected).filter(key => expected[key] !== actual[key]);
    return {
        status: 'compared',
        compared: true,
        matching: differences.length === 0,
        differences,
        diagnostic: differences.length === 0 ? null : {
            code: 'WINDOWS_INSPECTOR_PARITY_MISMATCH',
            message: 'PowerShell and native Windows metadata inspectors returned different shared metadata.',
            fields: differences
        },
        native: nativeInspection
    };
}

function inspectWindows(filePath, spawn = spawnSync, options = {}) {
    const result = spawn('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        WINDOWS_INSPECTION_SCRIPT
    ], {
        encoding: 'utf8',
        windowsHide: true,
        env: {
            ...process.env,
            WPB_SECURITY_METADATA_TARGET: filePath
        },
        maxBuffer: 4 * 1024 * 1024
    });
    if (result.error || result.status !== 0) return {
        readonly: null,
        windows: null,
        capability: {
            inspectable: false,
            reproducible: false,
            blockingReasons: [blockingReason(
                'UNSUPPORTED_WINDOWS_METADATA',
                `Windows metadata could not be inspected safely: ${result.error?.message ?? result.stderr?.trim() ?? 'unknown error'}`
            )]
        }
    };

    let windows;
    try {
        windows = JSON.parse(result.stdout.trim());
    } catch (error) {
        return {
            readonly: null,
            windows: null,
            capability: {
                inspectable: false,
                reproducible: false,
                blockingReasons: [blockingReason(
                    'UNSUPPORTED_WINDOWS_METADATA',
                    `Windows metadata inspection returned invalid data: ${error.message}`
                )]
            }
        };
    }

    windows.streams = Array.isArray(windows.streams)
        ? windows.streams
        : windows.streams ? [windows.streams] : [];
    let nativeInspection;
    try {
        nativeInspection = (options.nativeInspector ?? inspectWindowsNative)(
            filePath,
            options.nativeInspectorOptions ?? {}
        );
    } catch {
        nativeInspection = {
            status: 'failed',
            inspected: false,
            code: 'WINDOWS_NATIVE_INSPECTOR_FAILED',
            message: 'Windows native shadow inspection failed.'
        };
    }
    const nativeShadow = compareWindowsInspectors(windows, nativeInspection);
    const reasons = [];
    const READ_ONLY_ATTRIBUTE = 0x1;
    const ARCHIVE_ATTRIBUTE = 0x20;
    const NORMAL_ATTRIBUTE = 0x80;
    const unsupportedAttributes = windows.attributes & ~(
        READ_ONLY_ATTRIBUTE |
        ARCHIVE_ATTRIBUTE |
        NORMAL_ATTRIBUTE
    );
    if (windows.readonly) reasons.push(blockingReason(
        'READ_ONLY_TARGET',
        'Read-only files are not eligible for Security Fix apply.'
    ));
    if (windows.aclProtected || windows.explicitAccessRuleCount > 0) reasons.push(blockingReason(
        'WINDOWS_SPECIAL_ACL',
        'Files with protected or explicit Windows ACLs are not eligible until ACL-preserving replace is supported.'
    ));
    if (windows.ownerSid !== windows.currentSid) reasons.push(blockingReason(
        'WINDOWS_OWNER_UNSUPPORTED',
        'The Windows file owner cannot be guaranteed by the current rename-based apply.'
    ));
    if (windows.streams.length > 0) reasons.push(blockingReason(
        'WINDOWS_ADS_UNSUPPORTED',
        'Files with alternate data streams are not eligible until stream-preserving replace is supported.'
    ));
    if (unsupportedAttributes !== 0) reasons.push(blockingReason(
        'WINDOWS_ATTRIBUTES_UNSUPPORTED',
        'The file has Windows attributes that the current rename-based apply cannot reproduce safely.'
    ));

    const securityState = {
        readonly: windows.readonly,
        attributes: windows.attributes,
        aclProtected: windows.aclProtected,
        explicitAccessRuleCount: windows.explicitAccessRuleCount,
        ownerSid: windows.ownerSid,
        groupSid: windows.groupSid,
        daclSddl: windows.daclSddl,
        streams: windows.streams
    };
    return {
        readonly: windows.readonly,
        windows,
        nativeShadow,
        securityFingerprint: digest(securityState),
        replacementFingerprint: digest({
            readonly: windows.readonly,
            aclProtected: windows.aclProtected,
            explicitAccessRuleCount: windows.explicitAccessRuleCount,
            ownerSid: windows.ownerSid,
            groupSid: windows.groupSid,
            daclSddl: windows.daclSddl,
            streams: windows.streams
        }),
        capability: {
            inspectable: true,
            reproducible: reasons.length === 0,
            blockingReasons: reasons
        }
    };
}

export function inspectSecurityMetadata(filePath, stat, options = {}) {
    const platform = options.platform ?? process.platform;
    const base = {
        platform,
        identity: {
            dev: stat.dev,
            ino: stat.ino,
            nlink: stat.nlink
        },
        stat: {
            mode: stat.mode,
            uid: stat.uid,
            gid: stat.gid
        }
    };
    if (platform === 'win32') {
        const inspection = inspectWindows(filePath, options.spawnSync ?? spawnSync, options);
        return { ...base, ...inspection };
    }

    if (platform === 'linux') return {
        ...base,
        ...inspectLinuxMetadata(filePath, stat, options)
    };
    return {
        ...base,
        ...unsupportedPosixMetadata(platform)
    };
}

export function metadataBlockingReasons(metadata) {
    const reasons = [...(metadata?.capability?.blockingReasons ?? [])];
    if ((metadata?.identity?.nlink ?? 0) > 1) reasons.unshift(blockingReason(
        'HARD_LINK_TARGET',
        'Hard-linked files are not eligible for Security Fix apply.'
    ));
    return reasons;
}

export function metadataSnapshotsMatch(expected, current) {
    return (
        expected?.platform === current?.platform &&
        expected?.identity?.dev === current?.identity?.dev &&
        expected?.identity?.ino === current?.identity?.ino &&
        expected?.identity?.nlink === current?.identity?.nlink &&
        expected?.securityFingerprint === current?.securityFingerprint &&
        (current?.capability?.blockingReasons?.length ?? 0) === 0
    );
}

export function metadataCanReplace(expected, replacement) {
    if (!expected || !replacement) return false;
    if ((replacement.capability?.blockingReasons?.length ?? 0) > 0) return false;
    if (expected.platform === 'win32') {
        return expected.replacementFingerprint === replacement.replacementFingerprint;
    }
    return (
        (expected.stat.mode & 0o777) === (replacement.stat.mode & 0o777) &&
        expected.stat.uid === replacement.stat.uid &&
        expected.stat.gid === replacement.stat.gid &&
        expected.posix?.inspectionFingerprint === replacement.posix?.inspectionFingerprint
    );
}
