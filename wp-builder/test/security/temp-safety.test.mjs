import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { assertTempTarget, createTempWorkspace, writeTempFile } from '../helpers/temp-workspace.mjs';

test('test helpers reject targets outside the OS temp workspace', t => {
    const root = createTempWorkspace(t, 'safety-assertion');
    const inside = writeTempFile(root, 'inside.php', '<?php\n');
    assert.doesNotThrow(() => assertTempTarget(root, inside));

    const repositoryPackage = fileURLToPath(new URL('../../package.json', import.meta.url));
    assert.throws(() => assertTempTarget(root, repositoryPackage), /outside the test workspace/);
    assert.throws(
        () => writeTempFile(root, path.join('..', 'outside.php'), '<?php\n'),
        /outside the test workspace/
    );
});
