import fs from 'node:fs';

const fixtureRoot = new URL('../security/fixtures/', import.meta.url);

export function loadSecurityFixture(relativePath) {
    return fs.readFileSync(new URL(relativePath.replace(/\\/g, '/'), fixtureRoot));
}
