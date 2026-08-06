import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as fsPromises from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { applySecurityFixPlan } from '../../lib/security/fix-apply.js';
import { buildSecurityFixPlan, takeSecurityFileSnapshot } from '../../lib/security/fix-plan.js';
import { linuxRollbackPath } from '../../lib/security/linux-rollback.js';
import { securityFixIntegrationTestOptions } from '../helpers/php-runtime.mjs';
import {
    assertNoSecurityArtifacts,
    createTempWorkspace,
    writeTempFile
} from '../helpers/temp-workspace.mjs';

const linuxOptions = process.platform === 'linux'
    ? securityFixIntegrationTestOptions()
    : { skip: 'Linux-only rollback integration test.' };
const source = Buffer.from("<p><?= SCF::get('title') ?></p>\n");

function createPlan(t, label) {
    const root = createTempWorkspace(t, label);
    const file = writeTempFile(root, 'case.php', source);
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    assert.equal(plan.canApply, true, JSON.stringify(plan.blockingReasons));
    return { root, file, plan, rollbackPath: linuxRollbackPath(file) };
}

async function expectError(action, exitCode, code) {
    await assert.rejects(action, error => {
        assert.equal(error.exitCode, exitCode);
        assert.equal(error.code, code);
        return true;
    });
}

function assertOriginalRestored(fixture) {
    const restored = takeSecurityFileSnapshot(fixture.file);
    assert.equal(restored.hash, fixture.plan.snapshot.hash);
    assert.equal(restored.metadata.identity.dev, fixture.plan.snapshot.metadata.identity.dev);
    assert.equal(restored.metadata.identity.ino, fixture.plan.snapshot.metadata.identity.ino);
    assert.equal(restored.metadata.identity.nlink, 1);
    assert.equal(restored.metadata.stat.mode, fixture.plan.snapshot.metadata.stat.mode);
    assert.equal(restored.metadata.stat.uid, fixture.plan.snapshot.metadata.stat.uid);
    assert.equal(restored.metadata.stat.gid, fixture.plan.snapshot.metadata.stat.gid);
    assert.equal(restored.metadata.securityFingerprint, fixture.plan.snapshot.metadata.securityFingerprint);
    assert.deepEqual(fs.readFileSync(fixture.file), source);
    assert.equal(fs.existsSync(fixture.rollbackPath), false);
    assertNoSecurityArtifacts(fixture.root);
}

function finalFaultFileSystem(fixture, mutateFinal, options = {}) {
    const state = {
        desiredRenamed: false,
        rollingBack: false,
        backupCreated: false,
        backupRemoved: false
    };
    const fileSystem = {
        ...fsPromises,
        link: async (existingPath, newPath) => {
            const result = await fsPromises.link(existingPath, newPath);
            if (newPath === fixture.rollbackPath) state.backupCreated = true;
            return result;
        },
        unlink: async target => {
            const result = await fsPromises.unlink(target);
            if (target === fixture.rollbackPath) state.backupRemoved = true;
            return result;
        },
        rename: async (oldPath, newPath) => {
            if (oldPath === fixture.rollbackPath) {
                state.rollingBack = true;
                if (options.rollbackFailure) {
                    const error = new Error('injected rollback failure');
                    error.code = 'EIO';
                    throw error;
                }
            }
            const result = await fsPromises.rename(oldPath, newPath);
            if (newPath === fixture.file && oldPath.includes('.security-fix.tmp')) state.desiredRenamed = true;
            return result;
        }
    };
    const takeSnapshot = target => {
        const snapshot = takeSecurityFileSnapshot(target);
        if (target === fixture.file && state.desiredRenamed && !state.rollingBack) {
            return mutateFinal(structuredClone(snapshot));
        }
        return snapshot;
    };
    return { fileSystem, takeSnapshot, state };
}

test('Linux rollback successful apply creates and removes its hard-link backup', linuxOptions, async t => {
    const fixture = createPlan(t, 'linux-rollback-success');
    const fault = finalFaultFileSystem(fixture, snapshot => snapshot);
    const result = await applySecurityFixPlan(fixture.plan, {
        assumeYes: true,
        fileSystem: fault.fileSystem,
        takeSnapshot: fault.takeSnapshot
    });
    assert.equal(result.status, 'applied');
    assert.equal(fault.state.backupCreated, true);
    assert.equal(fault.state.backupRemoved, true);
    assert.deepEqual(fs.readFileSync(fixture.file), fixture.plan.desiredBytes);
    assert.equal(fs.existsSync(fixture.rollbackPath), false);
    assertNoSecurityArtifacts(fixture.root);
});

test('Linux final-validation failures restore original inode and metadata', linuxOptions, async t => {
    const cases = [
        ['hash', snapshot => ({ ...snapshot, hash: '0'.repeat(64) })],
        ['normal file', snapshot => ({ ...snapshot, state: 'unsafe', normalFile: false })],
        ['mode', snapshot => {
            snapshot.metadata.stat.mode ^= 0o020;
            return snapshot;
        }],
        ['uid/gid', snapshot => {
            snapshot.metadata.stat.uid += 1;
            snapshot.metadata.stat.gid += 1;
            return snapshot;
        }],
        ['ACL/xattr fingerprint', snapshot => {
            snapshot.metadata.replacementFingerprint = 'changed';
            return snapshot;
        }],
        ['inspector failure', snapshot => {
            snapshot.metadata.capability.inspectable = false;
            snapshot.metadata.capability.reproducible = false;
            snapshot.metadata.capability.blockingReasons = [{ code: 'INJECTED_INSPECTOR_FAILURE' }];
            return snapshot;
        }]
    ];
    for (const [name, mutate] of cases) {
        await t.test(name, async st => {
            const fixture = createPlan(st, `linux-rollback-final-${name.replace(/\W+/g, '-')}`);
            const fault = finalFaultFileSystem(fixture, mutate);
            await expectError(
                () => applySecurityFixPlan(fixture.plan, {
                    assumeYes: true,
                    fileSystem: fault.fileSystem,
                    takeSnapshot: fault.takeSnapshot
                }),
                6,
                'FINAL_VALIDATION_FAILED_ROLLED_BACK'
            );
            assert.equal(fault.state.backupCreated, true);
            assertOriginalRestored(fixture);
        });
    }
});

test('Existing Linux rollback artifact blocks before rename and is preserved', linuxOptions, async t => {
    const fixture = createPlan(t, 'linux-rollback-collision');
    const recovery = Buffer.from('existing recovery artifact');
    fs.writeFileSync(fixture.rollbackPath, recovery, { flag: 'wx' });
    try {
        await expectError(
            () => applySecurityFixPlan(fixture.plan, { assumeYes: true }),
            2,
            'RECOVERY_REQUIRED'
        );
        assert.deepEqual(fs.readFileSync(fixture.file), source);
        assert.deepEqual(fs.readFileSync(fixture.rollbackPath), recovery);
    } finally {
        fs.rmSync(fixture.rollbackPath, { force: true });
    }
    assertNoSecurityArtifacts(fixture.root);
});

test('External hard link after backup is stale and removes only owned backup', linuxOptions, async t => {
    const fixture = createPlan(t, 'linux-rollback-extra-link');
    const externalLink = path.join(fixture.root, 'external.php');
    const fileSystem = {
        ...fsPromises,
        link: async (existingPath, newPath) => {
            await fsPromises.link(existingPath, newPath);
            if (newPath === fixture.rollbackPath) await fsPromises.link(existingPath, externalLink);
        }
    };
    try {
        await expectError(
            () => applySecurityFixPlan(fixture.plan, { assumeYes: true, fileSystem }),
            4,
            'STALE_FILE'
        );
        assert.deepEqual(fs.readFileSync(fixture.file), source);
        assert.deepEqual(fs.readFileSync(externalLink), source);
        assert.equal(fs.existsSync(fixture.rollbackPath), false);
    } finally {
        fs.rmSync(externalLink, { force: true });
    }
    assertNoSecurityArtifacts(fixture.root);
});

test('Linux rollback failure retains recovery artifact and original inode', linuxOptions, async t => {
    const fixture = createPlan(t, 'linux-rollback-failure');
    const fault = finalFaultFileSystem(
        fixture,
        snapshot => ({ ...snapshot, hash: 'f'.repeat(64) }),
        { rollbackFailure: true }
    );
    try {
        await expectError(
            () => applySecurityFixPlan(fixture.plan, {
                assumeYes: true,
                fileSystem: fault.fileSystem,
                takeSnapshot: fault.takeSnapshot
            }),
            6,
            'ROLLBACK_FAILED_RECOVERY_REQUIRED'
        );
        assert.equal(fs.existsSync(fixture.rollbackPath), true);
        const recovery = takeSecurityFileSnapshot(fixture.rollbackPath);
        assert.equal(recovery.hash, fixture.plan.snapshot.hash);
        assert.equal(recovery.metadata.identity.ino, fixture.plan.snapshot.metadata.identity.ino);
        assert.equal(fs.existsSync(`${fixture.file}.security-fix.lock`), false);
    } finally {
        fs.rmSync(fixture.rollbackPath, { force: true });
    }
    assertNoSecurityArtifacts(fixture.root);
});

test('Linux directory fsync failure stops before rename and cleans owned artifacts', linuxOptions, async t => {
    const fixture = createPlan(t, 'linux-rollback-directory-fsync');
    let failed = false;
    const fileSystem = {
        ...fsPromises,
        open: async (target, flags, ...args) => {
            if (!failed && target === fixture.root && flags === 'r') {
                failed = true;
                const error = new Error('injected directory fsync failure');
                error.code = 'EIO';
                throw error;
            }
            return fsPromises.open(target, flags, ...args);
        }
    };
    await expectError(
        () => applySecurityFixPlan(fixture.plan, { assumeYes: true, fileSystem }),
        6,
        'DIRECTORY_FSYNC_FAILED'
    );
    assert.deepEqual(fs.readFileSync(fixture.file), source);
    assert.equal(fs.existsSync(fixture.rollbackPath), false);
    assertNoSecurityArtifacts(fixture.root);
});
