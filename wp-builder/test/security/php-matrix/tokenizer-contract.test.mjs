import assert from 'node:assert/strict';
import test from 'node:test';
import { runPhpTokenizer } from '../../../lib/security/analyzer.js';
import { PHP_TOKENIZER_HELPER_SCHEMA_VERSION } from '../../../lib/security/php-runtime-contract.js';
import { assertExpectedPhpMinor, inspectPhpRuntime } from '../../helpers/php-runtime.mjs';

const source = Buffer.from(
    "<p><?= SCF::get('title') ?></p>\n" +
    "<?php echo \\SCF::get('url'); Vendor\\SCF::get('ignored'); ?>\n" +
    "<p>日本語</p>\n"
);

function findToken(tokens, type, text) {
    const token = tokens.find(item => item.type === type && item.text === text);
    assert.ok(token, `Expected ${type} token ${JSON.stringify(text)}.`);
    return token;
}

test('PHP tokenizer byte and SCF token contract', () => {
    assertExpectedPhpMinor(assert, inspectPhpRuntime());
    const result = runPhpTokenizer(source);
    assert.equal(result.ok, true, result.message);
    assert.equal(result.runtime.helperSchemaVersion, PHP_TOKENIZER_HELPER_SCHEMA_VERSION);
    assert.equal(result.runtime.tokenizerAvailable, true);

    let previousEnd = 0;
    for (const token of result.tokens) {
        assert.equal(token.startByte, previousEnd);
        assert.ok(token.endByte >= token.startByte);
        assert.ok(Number.isInteger(token.line) && token.line >= 1);
        assert.deepEqual(source.subarray(token.startByte, token.endByte), Buffer.from(token.text, 'utf8'));
        previousEnd = token.endByte;
    }
    assert.equal(previousEnd, source.length);
    assert.deepEqual(Buffer.concat(result.tokens.map(token => Buffer.from(token.text, 'utf8'))), source);

    findToken(result.tokens, 'T_OPEN_TAG_WITH_ECHO', '<?=',);
    findToken(result.tokens, 'T_STRING', 'SCF');
    findToken(result.tokens, 'T_NAME_FULLY_QUALIFIED', '\\SCF');
    findToken(result.tokens, 'T_NAME_QUALIFIED', 'Vendor\\SCF');
    findToken(result.tokens, 'T_ECHO', 'echo');
    findToken(result.tokens, 'T_STRING', 'get');
    findToken(result.tokens, 'T_CONSTANT_ENCAPSED_STRING', "'title'");
});
