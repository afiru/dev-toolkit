import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { validateWindowsHelperTrust } from '../../lib/security/windows-helper-trust.js';
import { createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

const revision = 'a'.repeat(40);

test('checked-in helper manifest schema requires the Phase A trust fields', () => {
    const testDirectory = path.dirname(fileURLToPath(import.meta.url));
    const schemaPath = path.resolve(testDirectory, '..', '..', 'native', 'windows-inspector', 'helper-manifest-schema-v1.json');
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
    assert.ok(schema.required.includes('platform'));
    assert.equal(schema.properties.platform.const, 'win32');
    assert.equal(schema.properties.architecture.const, 'x64');
    assert.equal(schema.properties.toolchain.properties.windowsSdkBuildSelectionVerified.const, true);
});

function sha256(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
}

function fixture(t, overrides = {}) {
    const root = createTempWorkspace(t, 'windows-helper-trust');
    const helperBytes = Buffer.from('inspection-only helper fixture');
    const helperPath = writeTempFile(root, 'bin/wpb-windows-inspector.exe', helperBytes);
    const manifest = {
        manifestSchemaVersion: 1,
        helperName: 'wpb-windows-inspector',
        helperVersion: '0.1.0',
        protocolSchemaVersions: [1, 2],
        adapter: 'windows-native-inspector-v1',
        platform: 'win32',
        architecture: 'x64',
        sourceRevision: revision,
        completeForReplace: false,
        artifact: { sha256: sha256(helperBytes), size: helperBytes.length },
        runner: { image: 'fixture', version: 'fixture' },
        toolchain: {
            windowsSdkVersion: '10.0.26100.0',
            windowsSdkVersionSource: 'msbuild-resolved-property',
            windowsSdkBuildSelectionVerified: true
        },
        securityFlags: ['/GS', '/guard:cf'],
        signed: false,
        ...overrides
    };
    const manifestPath = writeTempFile(root, 'wpb-windows-inspector.manifest.json', JSON.stringify(manifest));
    return { helperPath, manifestPath, manifest };
}

function validate(paths, overrides = {}) {
    return validateWindowsHelperTrust({
        ...paths,
        expectedBundledPath: paths.helperPath,
        expectedSourceRevision: revision,
        platform: 'win32',
        architecture: 'x64',
        inspectReparsePoint: () => false,
        ...overrides
    });
}

test('valid inspection-only manifest is trusted for inspect but never replace', t => {
    const result = validate(fixture(t));
    assert.equal(result.trustedForInspection, true);
    assert.equal(result.trustedForReplace, false);
    assert.deepEqual(result.trustReasons, []);
    assert.deepEqual(result.replaceBlockingReasons.map(item => item.code), [
        'WINDOWS_HELPER_REPLACE_INCOMPLETE',
        'WINDOWS_HELPER_UNSIGNED'
    ]);
    assert.equal(result.architectureScope, 'x64');
});

for (const [name, mutate, code] of [
    ['hash mismatch', manifest => { manifest.artifact.sha256 = '0'.repeat(64); }, 'WINDOWS_HELPER_HASH_MISMATCH'],
    ['size mismatch', manifest => { manifest.artifact.size += 1; }, 'WINDOWS_HELPER_SIZE_MISMATCH'],
    ['architecture mismatch', manifest => { manifest.architecture = 'arm64'; }, 'WINDOWS_HELPER_ARCHITECTURE_MISMATCH'],
    ['adapter mismatch', manifest => { manifest.adapter = 'windows-native-inspector-v2'; }, 'WINDOWS_HELPER_ADAPTER_MISMATCH'],
    ['protocol mismatch', manifest => { manifest.protocolSchemaVersions = [2]; }, 'WINDOWS_HELPER_PROTOCOL_MISMATCH'],
    ['manifest schema mismatch', manifest => { manifest.manifestSchemaVersion = 2; }, 'WINDOWS_HELPER_MANIFEST_SCHEMA_UNSUPPORTED'],
    ['platform mismatch', manifest => { manifest.platform = 'linux'; }, 'WINDOWS_HELPER_PLATFORM_MISMATCH'],
    ['SDK selection unverified', manifest => { manifest.toolchain.windowsSdkBuildSelectionVerified = false; }, 'WINDOWS_HELPER_BUILD_UNVERIFIED']
]) {
    test(`helper trust rejects ${name}`, t => {
        const paths = fixture(t);
        mutate(paths.manifest);
        fs.writeFileSync(paths.manifestPath, JSON.stringify(paths.manifest));
        const result = validate(paths);
        assert.equal(result.trustedForInspection, false);
        assert.ok(result.trustReasons.some(item => item.code === code));
    });
}

test('helper trust rejects a non-bundled binary path', t => {
    const paths = fixture(t);
    const otherPath = writeTempFile(path.dirname(paths.helperPath), 'other.exe', 'other');
    const result = validate(paths, { expectedBundledPath: otherPath });
    assert.equal(result.trustedForInspection, false);
    assert.ok(result.trustReasons.some(item => item.code === 'WINDOWS_HELPER_PATH_MISMATCH'));
});

test('helper trust rejects a reparse-point result without executing the helper', t => {
    const paths = fixture(t);
    const result = validate(paths, { inspectReparsePoint: () => true });
    assert.equal(result.trustedForInspection, false);
    assert.ok(result.trustReasons.some(item => item.code === 'WINDOWS_HELPER_BINARY_PATH_UNSAFE'));
});
