import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runCli } from '../helpers/cli-runner.mjs';
import { createTempWorkspace } from '../helpers/temp-workspace.mjs';

const readmePath = fileURLToPath(new URL('../../../README.md', import.meta.url));

test('security:fix command help states platform apply support without changing behavior', t => {
    const root = createTempWorkspace(t, 'support-help');
    const result = runCli(root, ['security:fix', '--help']);

    assert.equal(result.status, 0);
    assert.match(result.stdout, /Preview \/ Plan: supported/);
    assert.match(result.stdout, /Windows apply: unsupported/);
    assert.match(result.stdout, /WINDOWS_APPLY_UNSUPPORTED_STRICT_METADATA/);
    assert.match(result.stdout, /Linux apply: KEEP_CANDIDATE/);
    assert.match(result.stdout, /Legacy "security --fix": DISABLE_CANDIDATE/);
    assert.match(result.stdout, /security:fix --file <path>/);
});

test('root README records the supported platform and PHP boundaries', () => {
    const readme = fs.readFileSync(readmePath, 'utf8');

    assert.match(readme, /Windows x64 \| Apply \| UNSUPPORTED/);
    assert.match(readme, /Windows x64 \| PowerShell metadata inspection \| KEEP/);
    assert.match(readme, /Windows x64 \| Native shadow inspection \| KEEP_CANDIDATE/);
    assert.match(readme, /Linux \| Apply \| KEEP_CANDIDATE/);
    assert.match(readme, /macOS \/ other POSIX \| Apply \| UNSUPPORTED/);
    assert.match(readme, /PHP 7\.x \| UNSUPPORTED/);
    assert.match(readme, /PHP 8\.0–8\.1 \| `LEGACY_COMPATIBILITY`/);
    assert.match(readme, /PHP 8\.2–8\.3 \| verified candidate/);
    assert.match(readme, /PHP 8\.4 \| contract上のcandidate/);
    assert.match(readme, /PHP 8\.5\+ \| `PHP_VERSION_UNVERIFIED`/);
    assert.match(readme, /tokenizer unavailable \| `PHP_TOKENIZER_UNAVAILABLE`/);
    assert.match(readme, /completeForReplace=false/);
    assert.match(readme, /EXPERIMENTAL \/ NOT FOR PRODUCTION/);
    assert.match(readme, /旧`security --fix`は`DISABLE_CANDIDATE`/);
    assert.match(readme, /`security:fix --file <path>`へ移行/);
});
