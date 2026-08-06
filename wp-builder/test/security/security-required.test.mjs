import assert from 'node:assert/strict';
import test from 'node:test';
import {
    inspectLinuxMetadataRuntime,
    inspectPhpRuntime
} from '../helpers/php-runtime.mjs';

test('Security KEEP gate requires PHP CLI with tokenizer', () => {
    const runtime = inspectPhpRuntime();
    assert.equal(runtime.available, true, runtime.reason);
    assert.equal(runtime.tokenizer, true, runtime.reason);
});

test('Linux Security KEEP gate requires getfacl and getfattr', {
    skip: process.platform === 'linux' ? false : 'Linux-only KEEP gate.'
}, () => {
    const runtime = inspectLinuxMetadataRuntime();
    assert.equal(runtime.available, true, runtime.reason);
});

await import('./security.test.mjs');
