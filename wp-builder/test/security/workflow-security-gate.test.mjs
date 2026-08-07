import assert from 'node:assert/strict';
import test from 'node:test';
import {
    runSecurityTestSuites,
    SECURITY_TEST_SUITES
} from '../helpers/run-security-test-suites.mjs';

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
