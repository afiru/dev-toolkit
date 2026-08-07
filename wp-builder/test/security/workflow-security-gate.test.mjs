import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
    runSecurityTestSuites,
    SECURITY_TEST_SUITES
} from '../helpers/run-security-test-suites.mjs';

const linuxWorkflowPath = fileURLToPath(new URL('../../../.github/workflows/linux-security.yml', import.meta.url));

function runWithStatuses(statuses) {
    const calls = [];
    const exitCode = runSecurityTestSuites({
        log() {},
        logError() {},
        runCommand(suite) {
            calls.push(suite.name);
            return { status: statuses[calls.length - 1], error: null };
        }
    });
    assert.deepEqual(calls, SECURITY_TEST_SUITES.map(suite => suite.name));
    return exitCode;
}

test('workflow security gate succeeds only when every suite succeeds', async t => {
    const cases = [
        ['all pass', [0, 0, 0], 0],
        ['first fails', [1, 0, 0], 1],
        ['middle fails', [0, 1, 0], 1],
        ['last fails', [0, 0, 1], 1]
    ];

    for (const [name, statuses, expected] of cases) {
        await t.test(name, () => {
            assert.equal(runWithStatuses(statuses), expected);
        });
    }
});

test('permanent Linux gate uses real PHP minors and real metadata tools without Docker', () => {
    const workflow = fs.readFileSync(linuxWorkflowPath, 'utf8');
    assert.match(workflow, /runs-on: ubuntu-24\.04/);
    assert.match(workflow, /php: \["8\.2", "8\.3", "8\.4"\]/);
    assert.match(workflow, /shivammathur\/setup-php@[0-9a-f]{40}/);
    assert.match(workflow, /sudo apt-get install -y --no-install-recommends acl attr/);
    assert.match(workflow, /npm run test:security:php-current/);
    assert.match(workflow, /npm run test:security:ci/);
    assert.match(workflow, /findmnt -T/);
    assert.doesNotMatch(workflow, /\bdocker\b/i);
});
