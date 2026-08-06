import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as fsPromises from 'node:fs/promises';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { applySecurityFixPlan } from '../../lib/security/fix-apply.js';
import { buildSecurityFixPlan, takeSecurityFileSnapshot } from '../../lib/security/fix-plan.js';
import { securityFixIntegrationTestOptions } from '../helpers/php-runtime.mjs';
import {
    assertNoSecurityArtifacts,
    assertTempTarget,
    createTempWorkspace,
    writeTempFile
} from '../helpers/temp-workspace.mjs';

const source = Buffer.from("<p><?= SCF::get('title') ?></p>\n");

function createPlan(t, label, content = source) {
    const root = createTempWorkspace(t, label);
    const file = writeTempFile(root, 'case.php', content);
    const plan = buildSecurityFixPlan({ workspaceRoot: root, file });
    assertTempTarget(root, plan.targetPath);
    return { root, file, plan, original: Buffer.from(content) };
}

async function expectApplyError(action, exitCode, code) {
    await assert.rejects(action, error => {
        assert.equal(error.exitCode, exitCode);
        assert.equal(error.code, code);
        return true;
    });
}

const applySafetyOptions = process.platform === 'win32'
    ? { skip: 'Windows apply is unsupported by the strict metadata contract.' }
    : securityFixIntegrationTestOptions();

test('Windows applier guard rejects a forged apply-capable Plan before artifacts exist', async t => {
    const fixture = createPlan(t, 'apply-windows-guard');
    const before = fs.readFileSync(fixture.file);
    const beforeStat = fs.statSync(fixture.file);
    const beforeSnapshot = takeSecurityFileSnapshot(fixture.file);
    const forgedPlan = {
        ...fixture.plan,
        canApply: true,
        snapshot: {
            ...fixture.plan.snapshot,
            metadata: {
                ...fixture.plan.snapshot.metadata,
                platform: 'win32',
                capability: {
                    inspectable: true,
                    reproducible: true,
                    blockingReasons: []
                }
            }
        }
    };
    const fileSystem = new Proxy({}, {
        get() {
            throw new Error('The Windows guard must run before filesystem access.');
        }
    });

    await expectApplyError(
        () => applySecurityFixPlan(forgedPlan, { assumeYes: true, fileSystem }),
        2,
        'WINDOWS_APPLY_UNSUPPORTED_STRICT_METADATA'
    );
    assert.deepEqual(fs.readFileSync(fixture.file), before);
    const afterStat = fs.statSync(fixture.file);
    assert.equal(afterStat.ino, beforeStat.ino);
    assert.equal(afterStat.dev, beforeStat.dev);
    const afterSnapshot = takeSecurityFileSnapshot(fixture.file);
    assert.equal(afterSnapshot.hash, beforeSnapshot.hash);
    assert.equal(
        afterSnapshot.metadata.securityFingerprint,
        beforeSnapshot.metadata.securityFingerprint
    );
    assertNoSecurityArtifacts(fixture.root);
});

test('Security Fix Apply safety matrix', applySafetyOptions, async t => {
    await t.test('apply success', async st => {
        const fixture = createPlan(st, 'apply-success');
        const result = await applySecurityFixPlan(fixture.plan, { assumeYes: true });
        assert.equal(result.status, 'applied');
        assert.deepEqual(fs.readFileSync(fixture.file), fixture.plan.desiredBytes);
        assertNoSecurityArtifacts(fixture.root);
    });

    await t.test('stale after preview', async st => {
        const fixture = createPlan(st, 'apply-stale-preview');
        const external = Buffer.concat([fixture.original, Buffer.from("<!-- external -->\n")]);
        fs.writeFileSync(fixture.file, external);
        await expectApplyError(
            () => applySecurityFixPlan(fixture.plan, { assumeYes: true }),
            4,
            'STALE_FILE'
        );
        assert.deepEqual(fs.readFileSync(fixture.file), external);
        assertNoSecurityArtifacts(fixture.root);
    });

    await t.test('stale after temp validation', async st => {
        const fixture = createPlan(st, 'apply-stale-temp');
        const external = Buffer.concat([fixture.original, Buffer.from("<!-- changed during apply -->\n")]);
        let checks = 0;
        const takeSnapshot = target => {
            checks += 1;
            if (checks === 2) fs.writeFileSync(target, external);
            return takeSecurityFileSnapshot(target);
        };
        await expectApplyError(
            () => applySecurityFixPlan(fixture.plan, { assumeYes: true, takeSnapshot }),
            4,
            'STALE_FILE'
        );
        assert.deepEqual(fs.readFileSync(fixture.file), external);
        assertNoSecurityArtifacts(fixture.root);
    });

    await t.test('lock conflict', async st => {
        const fixture = createPlan(st, 'apply-lock');
        const lockPath = `${fixture.file}.security-fix.lock`;
        fs.writeFileSync(lockPath, 'other process\n');
        try {
            await expectApplyError(
                () => applySecurityFixPlan(fixture.plan, { assumeYes: true }),
                5,
                'LOCKED'
            );
            assert.deepEqual(fs.readFileSync(fixture.file), fixture.original);
        } finally {
            fs.rmSync(lockPath, { force: true });
        }
        assertNoSecurityArtifacts(fixture.root);
    });

    await t.test('temp lint failure preserves original', async st => {
        const fixture = createPlan(st, 'apply-lint-failure');
        await expectApplyError(
            () => applySecurityFixPlan(fixture.plan, { assumeYes: true, phpCommand: process.execPath }),
            2,
            'PHP_LINT_FAILED'
        );
        assert.deepEqual(fs.readFileSync(fixture.file), fixture.original);
        assertNoSecurityArtifacts(fixture.root);
    });

    await t.test('temp write failure preserves original', async st => {
        const fixture = createPlan(st, 'apply-write-failure');
        const fileSystem = {
            ...fsPromises,
            open: async (file, flags, ...args) => {
                if (String(file).includes('.security-fix.tmp')) {
                    const error = new Error('injected temp write failure');
                    error.code = 'EIO';
                    throw error;
                }
                return fsPromises.open(file, flags, ...args);
            }
        };
        await expectApplyError(
            () => applySecurityFixPlan(fixture.plan, { assumeYes: true, fileSystem }),
            6,
            'ATOMIC_WRITE_FAILED'
        );
        assert.deepEqual(fs.readFileSync(fixture.file), fixture.original);
        assertNoSecurityArtifacts(fixture.root);
    });

    await t.test('rename failure preserves original', async st => {
        const fixture = createPlan(st, 'apply-rename-failure');
        const fileSystem = {
            ...fsPromises,
            rename: async () => {
                const error = new Error('injected rename failure');
                error.code = 'EPERM';
                throw error;
            }
        };
        await expectApplyError(
            () => applySecurityFixPlan(fixture.plan, { assumeYes: true, fileSystem }),
            6,
            'ATOMIC_WRITE_FAILED'
        );
        assert.deepEqual(fs.readFileSync(fixture.file), fixture.original);
        assertNoSecurityArtifacts(fixture.root);
    });

    await t.test('confirmation cancel preserves original', async st => {
        const fixture = createPlan(st, 'apply-cancel');
        const input = new PassThrough();
        const output = new PassThrough();
        input.end('n\n');
        const result = await applySecurityFixPlan(fixture.plan, {
            isTTY: true,
            input,
            output
        });
        assert.equal(result.status, 'cancelled');
        assert.deepEqual(fs.readFileSync(fixture.file), fixture.original);
        assertNoSecurityArtifacts(fixture.root);
    });

    await t.test('diagnostic-only plan is a no-op', async st => {
        const fixture = createPlan(st, 'apply-no-op', Buffer.from("<?php\n$value = SCF::get('title');\n"));
        assert.equal(fixture.plan.hasChanges, false);
        const result = await applySecurityFixPlan(fixture.plan, { assumeYes: true });
        assert.equal(result.status, 'no_changes');
        assert.deepEqual(fs.readFileSync(fixture.file), fixture.original);
        assertNoSecurityArtifacts(fixture.root);
    });

    await t.test('symlink target is rejected', st => {
        const root = createTempWorkspace(st, 'apply-symlink');
        const sourceFile = writeTempFile(root, 'source.php', source);
        const linkFile = path.join(root, 'link.php');
        try {
            fs.symlinkSync(sourceFile, linkFile, 'file');
        } catch (error) {
            if (error.code === 'EPERM') {
                st.skip('The current Windows account cannot create symlinks.');
                return;
            }
            throw error;
        }
        assertTempTarget(root, linkFile);
        const plan = buildSecurityFixPlan({ workspaceRoot: root, file: linkFile });
        assert.equal(plan.snapshot.symlink, true);
        assert.equal(plan.canApply, false);
        assert.deepEqual(fs.readFileSync(sourceFile), source);
    });
});
