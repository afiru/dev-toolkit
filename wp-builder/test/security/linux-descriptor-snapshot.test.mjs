import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { takeSecurityFileSnapshot } from '../../lib/security/fix-plan.js';
import {
    createTempWorkspace,
    writeTempFile
} from '../helpers/temp-workspace.mjs';

const linuxOnly = process.platform === 'linux' ? {} : { skip: 'Linux-only descriptor snapshot test.' };
const source = Buffer.from("<p><?= SCF::get('title') ?></p>\n");
const basicAcl = 'user::rw-\ngroup::r--\nother::r--\n';

function spawnSequence({ onCall, xattrs = ['', ''] } = {}) {
    let inspectionPass = 0;
    const calls = [];
    return {
        calls,
        spawnSync(command, args, options) {
            calls.push({ command, args, options });
            onCall?.(calls.length, command);
            if (command === 'getfattr') inspectionPass += 1;
            return {
                status: 0,
                stdout: command === 'getfacl' ? basicAcl : xattrs[inspectionPass - 1],
                stderr: ''
            };
        }
    };
}

test('Linux snapshot binds two stable metadata passes to one inherited descriptor', linuxOnly, t => {
    const root = createTempWorkspace(t, 'linux-procfd-stable');
    const file = writeTempFile(root, 'case.php', source);
    fs.chmodSync(file, 0o644);
    const fake = spawnSequence();
    const snapshot = takeSecurityFileSnapshot(file, { metadata: { spawnSync: fake.spawnSync } });
    assert.equal(snapshot.state, 'present');
    assert.deepEqual(snapshot.bytes, source);
    assert.equal(snapshot.metadata.posix.binding.method, 'proc-self-fd');
    assert.equal(snapshot.metadata.posix.binding.identityVerified, true);
    assert.equal(snapshot.metadata.posix.binding.stablePasses, 2);
    assert.equal(snapshot.metadata.posix.filesystem.name, 'ext4');
    assert.equal(snapshot.metadata.posix.filesystem.supported, true);
    assert.equal(snapshot.metadata.capability.reproducible, true);
    assert.deepEqual(fake.calls.map(call => call.command), ['getfacl', 'getfattr', 'getfacl', 'getfattr']);
    for (const call of fake.calls) {
        assert.deepEqual(call.args.slice(-2), ['--', '/proc/self/fd/3']);
        assert.ok(Number.isInteger(call.options.stdio[3]));
    }
});

test('Linux snapshot blocks metadata that changes between descriptor-bound passes', linuxOnly, t => {
    const root = createTempWorkspace(t, 'linux-procfd-metadata-change');
    const file = writeTempFile(root, 'case.php', source);
    fs.chmodSync(file, 0o644);
    const fake = spawnSequence({ xattrs: ['', 'user.wpb-race=0x01\n'] });
    const snapshot = takeSecurityFileSnapshot(file, { metadata: { spawnSync: fake.spawnSync } });
    const codes = snapshot.metadata.capability.blockingReasons.map(reason => reason.code);
    assert.equal(snapshot.state, 'present');
    assert.ok(codes.includes('POSIX_METADATA_CHANGED_DURING_INSPECTION'));
    assert.equal(snapshot.metadata.posix.binding.identityVerified, false);
    assert.ok(!JSON.stringify(snapshot).includes('user.wpb-race'));
});

test('Linux snapshot rejects a pathname swapped after its descriptor is opened', linuxOnly, t => {
    const root = createTempWorkspace(t, 'linux-procfd-path-swap');
    const file = writeTempFile(root, 'case.php', source);
    const original = path.join(root, 'original.php');
    fs.chmodSync(file, 0o644);
    const fake = spawnSequence({
        onCall(callNumber) {
            if (callNumber !== 1) return;
            fs.renameSync(file, original);
            fs.writeFileSync(file, source);
            fs.chmodSync(file, 0o644);
        }
    });
    const snapshot = takeSecurityFileSnapshot(file, { metadata: { spawnSync: fake.spawnSync } });
    assert.equal(snapshot.state, 'unsafe');
    assert.match(snapshot.reason, /identity changed/);
    assert.deepEqual(fs.readFileSync(original), source);
});

test('Linux snapshot rejects a symlink swap during descriptor-bound inspection', linuxOnly, t => {
    const root = createTempWorkspace(t, 'linux-procfd-symlink-swap');
    const file = writeTempFile(root, 'case.php', source);
    const original = path.join(root, 'original.php');
    fs.chmodSync(file, 0o644);
    const fake = spawnSequence({
        onCall(callNumber) {
            if (callNumber !== 1) return;
            fs.renameSync(file, original);
            fs.symlinkSync(original, file);
        }
    });
    const snapshot = takeSecurityFileSnapshot(file, { metadata: { spawnSync: fake.spawnSync } });
    assert.equal(snapshot.state, 'unsafe');
    assert.equal(snapshot.symlink, true);
    assert.match(snapshot.reason, /identity changed/);
});
