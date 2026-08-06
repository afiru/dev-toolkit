import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
    fingerprintWindowsDacl,
    fingerprintWindowsSid,
    fingerprintWindowsStreamInventory,
    fingerprintWindowsStreams,
    inspectWindowsNative
} from '../../lib/security/windows-native-inspector.js';
import {
    inspectSecurityMetadata,
    metadataBlockingReasons
} from '../../lib/security/metadata.js';

function responseFor(request, overrides = {}) {
    return {
        schemaVersion: 1,
        helperVersion: '0.1.0',
        requestId: request.requestId,
        ok: true,
        operation: 'inspect',
        adapter: 'windows-native-inspector-v1',
        architecture: 'x64',
        filesystem: {
            type: 'NTFS',
            remote: false,
            driveType: 'FIXED',
            volumeSerial: '00000001',
            volumeFingerprint: 'sha256:volume'
        },
        file: {
            normalFile: true,
            reparsePoint: false,
            reparseTag: null,
            identity: { volumeSerial: '0000000000000001', fileId: '00'.repeat(16) },
            linkCount: '1',
            size: '1',
            attributes: '00000020',
            readonly: false
        },
        security: {
            daclFingerprint: 'sha256:dacl',
            daclProtected: false,
            ownerFingerprint: 'sha256:owner',
            groupFingerprint: 'sha256:group'
        },
        streams: {
            count: 0,
            digest: fingerprintWindowsStreams([]),
            inventoryDigest: fingerprintWindowsStreamInventory([])
        },
        compression: { compressed: false, format: '0000' },
        encryption: { encrypted: false },
        capabilities: {
            completeForReplace: false,
            localNtfsCandidate: true,
            saclInspected: false,
            extendedAttributesInspected: true,
            securityResourceAttributesInspected: false
        },
        compatibility: { explicitAccessRuleCount: 0 },
        metadataFingerprint: 'sha256:metadata',
        blockingReasons: [],
        ...overrides
    };
}

function runWithResponse(makeResponse, options = {}) {
    return inspectWindowsNative('C:\\fixture\\case.php', {
        helperPath: 'C:\\fixture\\wpb-windows-inspector.exe',
        existsSync: () => true,
        statSync: () => ({ isFile: () => true }),
        maxOutputBytes: options.maxOutputBytes,
        spawnSync: (_command, _args, spawnOptions) => {
            const request = JSON.parse(spawnOptions.input);
            const generated = makeResponse(request);
            return {
                status: generated.status ?? 0,
                stdout: typeof generated.stdout === 'string'
                    ? generated.stdout
                    : JSON.stringify(generated.response ?? generated),
                stderr: generated.stderr ?? '',
                error: generated.spawnError
            };
        }
    });
}

test('Windows native inspector accepts a valid protocol v1 response', () => {
    const result = runWithResponse(request => {
        assert.equal(request.schemaVersion, 1);
        assert.equal(request.operation, 'inspect');
        return responseFor(request);
    });
    assert.equal(result.status, 'inspected');
    assert.equal(result.response.capabilities.completeForReplace, false);
});

test('protocol v1 and inspection-only v2 schemas remain distinct and valid JSON', () => {
    const testDirectory = path.dirname(fileURLToPath(import.meta.url));
    const protocolDirectory = path.resolve(testDirectory, '..', '..', 'native', 'windows-inspector');
    const v1 = JSON.parse(fs.readFileSync(path.join(protocolDirectory, 'protocol-schema-v1.json'), 'utf8'));
    const v2 = JSON.parse(fs.readFileSync(path.join(protocolDirectory, 'protocol-schema-v2.json'), 'utf8'));
    assert.equal(v1.oneOf[0].properties.schemaVersion.const, 1);
    assert.equal(v2.oneOf[0].properties.schemaVersion.const, 2);
    assert.equal(v1.oneOf[0].properties.operation.const, 'inspect');
    assert.equal(v2.oneOf[0].properties.operation.const, 'inspect');
    assert.doesNotMatch(JSON.stringify(v2), /ReplaceFileW|lpReplacedFileName/);
});

test('Windows native inspector rejects schema mismatch', () => {
    const result = runWithResponse(request => responseFor(request, { schemaVersion: 2 }));
    assert.equal(result.status, 'failed');
    assert.equal(result.code, 'WINDOWS_NATIVE_INSPECTOR_PROTOCOL_ERROR');
});

test('Windows native inspector rejects malformed JSON', () => {
    const result = runWithResponse(() => ({ stdout: '{invalid' }));
    assert.equal(result.code, 'WINDOWS_NATIVE_INSPECTOR_MALFORMED_RESPONSE');
});

test('Windows native inspector reports timeout without retrying', () => {
    const result = runWithResponse(() => ({
        status: null,
        stdout: '',
        spawnError: Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' })
    }));
    assert.equal(result.code, 'WINDOWS_NATIVE_INSPECTOR_TIMEOUT');
});

test('Windows native inspector missing helper is unavailable, not inspected', () => {
    const result = inspectWindowsNative('C:\\fixture\\case.php', {
        helperPath: 'C:\\missing\\wpb-windows-inspector.exe',
        existsSync: () => false
    });
    assert.equal(result.status, 'unavailable');
    assert.equal(result.inspected, false);
    assert.equal(result.code, 'WINDOWS_NATIVE_INSPECTOR_UNAVAILABLE');
});

test('Windows native inspector rejects wrong requestId', () => {
    const result = runWithResponse(request => responseFor(request, { requestId: 'wrong' }));
    assert.equal(result.code, 'WINDOWS_NATIVE_INSPECTOR_PROTOCOL_ERROR');
});

test('Windows native inspector rejects raw security metadata', () => {
    const result = runWithResponse(request => responseFor(request, {
        security: {
            daclFingerprint: 'sha256:dacl',
            daclProtected: false,
            ownerFingerprint: 'sha256:owner',
            groupFingerprint: 'sha256:group',
            ownerSid: 'S-1-5-18'
        }
    }));
    assert.equal(result.code, 'WINDOWS_NATIVE_INSPECTOR_PROTOCOL_ERROR');
    assert.match(result.message, /raw metadata/i);
});

test('Windows native inspector rejects oversized output', () => {
    const result = runWithResponse(() => ({ stdout: 'x'.repeat(129) }), { maxOutputBytes: 128 });
    assert.equal(result.code, 'WINDOWS_NATIVE_INSPECTOR_OUTPUT_TOO_LARGE');
});

for (const code of ['ACCESS_DENIED', 'UNSUPPORTED_FILESYSTEM']) {
    test(`Windows native inspector preserves ${code} diagnostic`, () => {
        const result = runWithResponse(request => ({
            schemaVersion: 1,
            helperVersion: '0.1.0',
            requestId: request.requestId,
            ok: false,
            operation: 'inspect',
            error: { code, windowsError: 5, phase: 'fixture', retryable: false }
        }));
        assert.equal(result.status, 'failed');
        assert.equal(result.code, code);
    });
}

test('PowerShell remains authoritative when shadow parity differs', () => {
    const ownerSid = 'S-1-5-21-1000';
    const groupSid = 'S-1-5-21-513';
    const dacl = {
        state: 'empty',
        protected: false,
        revision: 2,
        sddl: 'D:'
    };
    const powershell = {
        readonly: false,
        attributes: 32,
        aclProtected: false,
        explicitAccessRuleCount: 0,
        ownerSid,
        groupSid,
        currentSid: ownerSid,
        daclSddl: `O:${ownerSid}G:${groupSid}D:`,
        daclOnlySddl: 'D:',
        daclState: 'empty',
        daclRevision: 2,
        streams: []
    };
    const nativeResponse = responseFor({ requestId: 'shadow' }, {
        requestId: 'shadow',
        file: {
            normalFile: true,
            reparsePoint: false,
            reparseTag: null,
            identity: { volumeSerial: '1', fileId: '00'.repeat(16) },
            linkCount: '1',
            size: '1',
            attributes: '00000020',
            readonly: true
        },
        security: {
            daclFingerprint: fingerprintWindowsDacl(dacl),
            daclProtected: false,
            ownerFingerprint: fingerprintWindowsSid(ownerSid),
            groupFingerprint: fingerprintWindowsSid(groupSid)
        }
    });
    const metadata = inspectSecurityMetadata('C:\\fixture\\case.php', {
        dev: 1,
        ino: 2,
        nlink: 1,
        mode: 0o100644,
        uid: 0,
        gid: 0
    }, {
        platform: 'win32',
        spawnSync: () => ({ status: 0, stdout: JSON.stringify(powershell), stderr: '' }),
        nativeInspector: () => ({ status: 'inspected', inspected: true, response: nativeResponse })
    });
    assert.equal(metadata.nativeShadow.matching, false);
    assert.deepEqual(metadata.nativeShadow.differences, ['readonly']);
    assert.equal(metadata.nativeShadow.diagnostic.code, 'WINDOWS_INSPECTOR_PARITY_MISMATCH');
    assert.deepEqual(metadataBlockingReasons(metadata), []);
});
