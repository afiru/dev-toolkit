import assert from 'node:assert/strict';
import test from 'node:test';
import { buildSecurityFixPlan } from '../../../lib/security/fix-plan.js';
import {
    PHP_TOKENIZER_HELPER_SCHEMA_VERSION,
    classifyPhpRuntime,
    normalizePhpRuntimeContract,
    phpRuntimeBlockingReason
} from '../../../lib/security/php-runtime-contract.js';
import { assertExpectedPhpMinor, inspectPhpRuntime } from '../../helpers/php-runtime.mjs';
import { createTempWorkspace, writeTempFile } from '../../helpers/temp-workspace.mjs';

function runtime(phpMajor, phpMinor, overrides = {}) {
    return {
        phpVersion: `${phpMajor}.${phpMinor}.0`,
        phpVersionId: phpMajor * 10000 + phpMinor * 100,
        phpMajor,
        phpMinor,
        tokenizerAvailable: true,
        helperSchemaVersion: PHP_TOKENIZER_HELPER_SCHEMA_VERSION,
        ...overrides
    };
}

test('PHP runtime version gate contract', async t => {
    const cases = [
        [runtime(7, 4), 'PHP_VERSION_UNSUPPORTED', false],
        [runtime(8, 0), 'LEGACY_COMPATIBILITY', false],
        [runtime(8, 1), 'LEGACY_COMPATIBILITY', false],
        [runtime(8, 2), 'VERIFIED_APPLY_CANDIDATE', true],
        [runtime(8, 3), 'VERIFIED_APPLY_CANDIDATE', true],
        [runtime(8, 4), 'VERIFIED_APPLY_CANDIDATE', true],
        [runtime(8, 5), 'PHP_VERSION_UNVERIFIED', false],
        [runtime(9, 0), 'PHP_VERSION_UNVERIFIED', false],
        [runtime(8, 2, { tokenizerAvailable: false }), 'PHP_TOKENIZER_UNAVAILABLE', false]
    ];

    for (const [input, status, applyEligible] of cases) {
        await t.test(`${input.phpVersion} => ${status}`, () => {
            const gate = classifyPhpRuntime(input);
            assert.equal(gate.status, status);
            assert.equal(gate.applyEligible, applyEligible);
        });
    }
});

test('runtime contract rejects missing or changed helper schemas', () => {
    assert.equal(normalizePhpRuntimeContract(null).code, 'PHP_TOKENIZER_CONTRACT_UNSAFE');
    assert.equal(
        normalizePhpRuntimeContract(runtime(8, 2, { helperSchemaVersion: 999 })).code,
        'PHP_TOKENIZER_HELPER_SCHEMA_UNSUPPORTED'
    );
    const normalized = normalizePhpRuntimeContract(runtime(8, 2, { tokenizerAvailable: false }));
    assert.equal(normalized.ok, true);
    assert.equal(phpRuntimeBlockingReason(normalized.runtime).code, 'PHP_TOKENIZER_UNAVAILABLE');
});

test('matrix runtime matches WPB_EXPECTED_PHP_MINOR when provided', () => {
    assertExpectedPhpMinor(assert, inspectPhpRuntime());
});

function writeFakeTokenizer(root, payload) {
    const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
    return writeTempFile(root, 'fake-tokenizer.php', Buffer.from(`<?php echo base64_decode('${encoded}');`));
}

test('Security Fix Plan applies runtime and tokenizer gates from the helper contract', async t => {
    const cases = [
        [runtime(7, 4), true, 'PHP_VERSION_UNSUPPORTED'],
        [runtime(8, 0), true, 'PHP_VERSION_LEGACY_COMPATIBILITY'],
        [runtime(8, 5), true, 'PHP_VERSION_UNVERIFIED'],
        [runtime(8, 2, { tokenizerAvailable: false }), false, 'PHP_TOKENIZER_UNAVAILABLE']
    ];

    for (const [phpRuntime, ok, expectedCode] of cases) {
        await t.test(expectedCode, () => {
            const root = createTempWorkspace(t, 'runtime-gate-plan');
            const file = writeTempFile(root, 'case.php', Buffer.from('<?php echo 1;\n'));
            const tokenizerPath = writeFakeTokenizer(root, ok ? {
                ok: true,
                runtime: phpRuntime,
                tokens: []
            } : {
                ok: false,
                runtime: phpRuntime,
                error: {
                    code: 'PHP_TOKENIZER_UNAVAILABLE',
                    message: 'PHP tokenizer extension is unavailable.',
                    line: null
                }
            });
            const plan = buildSecurityFixPlan({ workspaceRoot: root, file, tokenizerPath });
            assert.equal(plan.canApply, false);
            assert.ok(plan.blockingReasons.some(reason => reason.code === expectedCode));
        });
    }
});
