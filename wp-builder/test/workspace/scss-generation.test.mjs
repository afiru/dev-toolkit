import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const originalCwd = process.cwd();
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-builder-scss-generation-'));
process.chdir(workspace);

const { ensureTemplateFiles } = await import('../../lib/workspace/generator.js');
const { scanScssFile } = await import('../../lib/workspace/scanner.js');

test.after(() => {
    process.chdir(originalCwd);
    fs.rmSync(workspace, { recursive: true, force: true });
});

test('template-part SCSS keeps the standard header without generating a selector', () => {
    const common = path.join(workspace, 'scss', 'common.scss');
    fs.mkdirSync(path.dirname(common), { recursive: true });
    fs.writeFileSync(common, '/* existing common content */', 'utf8');

    ensureTemplateFiles('include/layouts/index/01_indexFv');

    const generated = path.join(workspace, 'scss', 'Layout', 'index', '_01_indexFv.scss');
    const index = path.join(workspace, 'scss', 'Layout', 'index', '_index.scss');
    const content = fs.readFileSync(generated, 'utf8');

    assert.match(content, /@use "\.\.\/\.\.\/Functions\/mixin" as mi;/);
    assert.match(content, /LAYOUT/);
    assert.doesNotMatch(content, /\.01_indexFv\s*\{/);
    assert.equal(fs.readFileSync(index, 'utf8'), '@forward "01_indexFv";\n');
    assert.equal(
        fs.readFileSync(common, 'utf8'),
        '/* existing common content */\n@use "Layout/index/index";\n'
    );
});

test('common.scss receives one Layout index use per directory', () => {
    ensureTemplateFiles('include/layouts/top/01_accessFv');
    ensureTemplateFiles('include/layouts/top/02_accessIntro');

    const common = path.join(workspace, 'scss', 'common.scss');
    const content = fs.readFileSync(common, 'utf8');
    assert.equal(content.match(/@use "Layout\/top\/top";/g)?.length, 1);
});

test('an existing active Layout use is not duplicated', () => {
    const common = path.join(workspace, 'scss', 'common.scss');
    fs.appendFileSync(common, "@use 'Layout/about/about';\n", 'utf8');

    ensureTemplateFiles('include/layouts/about/01_aboutFv');

    const content = fs.readFileSync(common, 'utf8');
    assert.equal(content.match(/Layout\/about\/about/g)?.length, 1);
});

test('a missing @forward target is created without a generated selector', () => {
    const index = path.join(workspace, 'scss', 'Layout', 'index', '_index.scss');
    fs.appendFileSync(index, '@forward "02_indexCard";\n', 'utf8');

    scanScssFile(index);

    const generated = path.join(workspace, 'scss', 'Layout', 'index', '_02_indexCard.scss');
    assert.equal(fs.readFileSync(generated, 'utf8'), '');
});
