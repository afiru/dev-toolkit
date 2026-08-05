import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function isInside(parent, target) {
    const relative = path.relative(path.resolve(parent), path.resolve(target));
    return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

export function assertTempTarget(tempRoot, targetPath) {
    assert.ok(isInside(os.tmpdir(), tempRoot), `Test workspace must be inside os.tmpdir(): ${tempRoot}`);
    assert.ok(isInside(tempRoot, targetPath), `Refusing to use a target outside the test workspace: ${targetPath}`);
}

function collectSecurityArtifacts(root) {
    if (!fs.existsSync(root)) return [];
    const artifacts = [];
    const walk = directory => {
        fs.readdirSync(directory, { withFileTypes: true }).forEach(entry => {
            const entryPath = path.join(directory, entry.name);
            if (entry.isDirectory()) walk(entryPath);
            else if (entry.name.includes('.security-fix.tmp') || entry.name.endsWith('.security-fix.lock')) artifacts.push(entryPath);
        });
    };
    walk(root);
    return artifacts;
}

export function assertNoSecurityArtifacts(tempRoot) {
    assert.deepEqual(collectSecurityArtifacts(tempRoot), [], 'Security Fix temp or lock files were left behind.');
}

export function createTempWorkspace(t, label = 'workspace') {
    const prefix = path.join(os.tmpdir(), `wp-builder-${label}-`);
    const root = fs.mkdtempSync(prefix);
    assertTempTarget(root, root);
    t.after(() => {
        try {
            assertNoSecurityArtifacts(root);
        } finally {
            fs.rmSync(root, { recursive: true, force: true });
        }
    });
    return root;
}

export function writeTempFile(tempRoot, relativePath, content) {
    const targetPath = path.resolve(tempRoot, relativePath);
    assertTempTarget(tempRoot, targetPath);
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, content);
    return targetPath;
}
