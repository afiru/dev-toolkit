import assert from 'node:assert/strict';
import test from 'node:test';
import {
    inspectSecurityMetadata,
    metadataCanReplace,
    metadataSnapshotsMatch
} from '../../lib/security/metadata.js';

const pathWithOptionPrefix = '/tmp/-security-target.php';
const stat = {
    dev: 1,
    ino: 2,
    nlink: 1,
    mode: 0o100644,
    uid: typeof process.getuid === 'function' ? process.getuid() : 0,
    gid: typeof process.getgid === 'function' ? process.getgid() : 0
};
const basicAcl = 'user::rw-\ngroup::r--\nother::r--\n';

function createSpawn({ acl = basicAcl, xattrs = '', failures = {} } = {}) {
    const calls = [];
    const spawnSync = (command, args, options) => {
        calls.push({ command, args, options });
        if (failures[command]) return failures[command];
        return {
            status: 0,
            stdout: command === 'getfacl' ? acl : xattrs,
            stderr: ''
        };
    };
    return { spawnSync, calls };
}

function inspect(config = {}) {
    const fake = createSpawn(config);
    const metadata = inspectSecurityMetadata(pathWithOptionPrefix, stat, {
        platform: 'linux',
        spawnSync: fake.spawnSync,
        linuxFileDescriptor: 42,
        linuxFileSystemType: 0xef53,
        procFdAvailable: true
    });
    return { metadata, calls: fake.calls };
}

function codes(metadata) {
    return metadata.capability.blockingReasons.map(item => item.code);
}

test('Linux metadata inspector uses safe arguments and allows only empty ACL/xattr state', () => {
    const { metadata, calls } = inspect();
    assert.equal(metadata.capability.inspectable, true);
    assert.equal(metadata.capability.reproducible, true);
    assert.deepEqual(metadata.capability.blockingReasons, []);
    assert.equal(metadata.posix.adapter, 'linux-procfd-tools-v1');
    assert.deepEqual(metadata.posix.binding, { method: 'proc-self-fd', inspected: true });
    assert.deepEqual(metadata.posix.filesystem, {
        inspected: true,
        name: 'ext4',
        typeMagic: '0xef53',
        supported: true
    });
    assert.equal(metadata.posix.acl.present, false);
    assert.equal(metadata.posix.acl.entryCount, 3);
    assert.equal(metadata.posix.xattrs.present, false);
    assert.equal(metadata.posix.xattrs.count, 0);
    assert.deepEqual(calls.map(call => call.command), ['getfacl', 'getfattr']);
    for (const call of calls) {
        assert.deepEqual(call.args.slice(-2), ['--', '/proc/self/fd/3']);
        assert.equal(call.options.stdio[3], 42);
        assert.equal(call.options.env.LC_ALL, 'C');
        assert.equal(call.options.env.LANG, 'C');
        assert.equal(call.options.timeout, 5000);
        assert.equal(call.options.maxBuffer, 4 * 1024 * 1024);
    }
    assert.ok(calls[0].args.includes('--numeric'));
    assert.ok(calls[0].args.includes('--omit-header'));
    assert.ok(calls[0].args.includes('--absolute-names'));
    assert.ok(calls[1].args.includes('--match=-'));
    assert.ok(calls[1].args.includes('--encoding=hex'));
});

test('Linux metadata inspector blocks unverified filesystems', () => {
    const fake = createSpawn();
    const metadata = inspectSecurityMetadata(pathWithOptionPrefix, stat, {
        platform: 'linux',
        spawnSync: fake.spawnSync,
        linuxFileDescriptor: 42,
        linuxFileSystemType: 0x794c7630,
        procFdAvailable: true
    });
    assert.ok(codes(metadata).includes('POSIX_FILESYSTEM_UNSUPPORTED'));
    assert.equal(metadata.posix.filesystem.name, 'unsupported');
    assert.equal(metadata.capability.reproducible, false);
});

test('Linux metadata inspector refuses path-only inspection', () => {
    const fake = createSpawn();
    const metadata = inspectSecurityMetadata(pathWithOptionPrefix, stat, {
        platform: 'linux',
        spawnSync: fake.spawnSync,
        procFdAvailable: true
    });
    assert.ok(codes(metadata).includes('POSIX_METADATA_INSPECTOR_UNAVAILABLE'));
    assert.equal(metadata.capability.inspectable, false);
    assert.deepEqual(fake.calls, []);
});

test('Linux additional ACL is blocking and raw ACL is not retained', () => {
    const { metadata } = inspect({
        acl: `${basicAcl}user:1001:r--\nmask::r--\n`
    });
    assert.equal(metadata.capability.reproducible, false);
    assert.ok(codes(metadata).includes('POSIX_ACL_PRESENT'));
    assert.equal(metadata.posix.acl.present, true);
    assert.ok(!JSON.stringify(metadata).includes('user:1001'));
});

test('Linux user xattr is blocking and raw value is not retained', () => {
    const { metadata } = inspect({
        xattrs: '# file: /tmp/file\nuser.wpb=0x736563726574\n'
    });
    assert.ok(codes(metadata).includes('POSIX_XATTR_PRESENT'));
    assert.ok(!codes(metadata).includes('POSIX_SECURITY_XATTR_PRESENT'));
    assert.equal(metadata.posix.xattrs.count, 1);
    assert.ok(!JSON.stringify(metadata).includes('736563726574'));
    assert.ok(!JSON.stringify(metadata).includes('user.wpb'));
});

test('Linux security xattrs are blocking', async t => {
    for (const name of ['security.selinux', 'security.capability', 'system.posix_acl_access', 'trusted.wpb']) {
        await t.test(name, () => {
            const { metadata } = inspect({ xattrs: `${name}=0x0102\n` });
            assert.ok(codes(metadata).includes('POSIX_XATTR_PRESENT'));
            assert.ok(codes(metadata).includes('POSIX_SECURITY_XATTR_PRESENT'));
            assert.equal(metadata.posix.securityMetadata.present, true);
        });
    }
});

test('Linux inspector unavailable and command failures fail closed', async t => {
    await t.test('getfacl unavailable', () => {
        const { metadata } = inspect({ failures: {
            getfacl: { error: Object.assign(new Error('missing'), { code: 'ENOENT' }), status: null, stdout: '', stderr: '' }
        } });
        assert.ok(codes(metadata).includes('POSIX_METADATA_INSPECTOR_UNAVAILABLE'));
        assert.equal(metadata.capability.inspectable, false);
    });
    await t.test('getfattr unavailable', () => {
        const { metadata } = inspect({ failures: {
            getfattr: { error: Object.assign(new Error('missing'), { code: 'ENOENT' }), status: null, stdout: '', stderr: '' }
        } });
        assert.ok(codes(metadata).includes('POSIX_METADATA_INSPECTOR_UNAVAILABLE'));
    });
    await t.test('timeout', () => {
        const { metadata } = inspect({ failures: {
            getfacl: { error: Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }), status: null, stdout: '', stderr: '' }
        } });
        assert.ok(codes(metadata).includes('POSIX_METADATA_INSPECTION_FAILED'));
    });
    await t.test('nonzero exit', () => {
        const { metadata } = inspect({ failures: {
            getfattr: { status: 1, stdout: '', stderr: 'permission denied' }
        } });
        assert.ok(codes(metadata).includes('POSIX_METADATA_INSPECTION_FAILED'));
    });
});

test('Malformed Linux ACL/xattr output fails closed', async t => {
    for (const [name, config] of [
        ['empty ACL', { acl: '' }],
        ['ACL mode mismatch', { acl: 'user::r--\ngroup::r--\nother::r--\n' }],
        ['unknown ACL entry', { acl: `${basicAcl}owner@:rwx\n` }],
        ['non-hex xattr', { xattrs: 'user.wpb="text"\n' }],
        ['duplicate xattr', { xattrs: 'user.wpb=0x01\nuser.wpb=0x02\n' }]
    ]) {
        await t.test(name, () => {
            const { metadata } = inspect(config);
            assert.ok(codes(metadata).includes('POSIX_METADATA_INSPECTION_FAILED'));
            assert.equal(metadata.capability.reproducible, false);
        });
    }
});

test('ACL/xattr fingerprints participate in stale comparison', () => {
    const clean = inspect().metadata;
    const acl = inspect({ acl: `${basicAcl}user:1001:r--\nmask::r--\n` }).metadata;
    const xattr = inspect({ xattrs: 'user.wpb=0x01\n' }).metadata;
    assert.equal(metadataSnapshotsMatch(clean, acl), false);
    assert.equal(metadataSnapshotsMatch(clean, xattr), false);
    assert.equal(metadataCanReplace(clean, acl), false);
    assert.equal(metadataCanReplace(clean, xattr), false);
});

test('macOS and other POSIX platforms are blocked without invoking Linux commands', async t => {
    for (const platform of ['darwin', 'freebsd']) {
        await t.test(platform, () => {
            const fake = createSpawn();
            const metadata = inspectSecurityMetadata('/tmp/file.php', stat, {
                platform,
                spawnSync: fake.spawnSync
            });
            assert.ok(codes(metadata).includes('POSIX_METADATA_UNSUPPORTED_PLATFORM'));
            assert.equal(metadata.capability.inspectable, false);
            assert.deepEqual(fake.calls, []);
        });
    }
});
