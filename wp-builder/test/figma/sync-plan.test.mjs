import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { buildFigmaSyncPlan } from '../../lib/figma/sync-plan.js';

function makeTempScssRoot() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wpb-figma-'));
    fs.mkdirSync(path.join(root, 'Component'), { recursive: true });
    return root;
}

function makePublicationPlan(scssRoot) {
    return buildFigmaSyncPlan({
        figmaFile: {
            document: {
                children: [{
                    id: 'page-1',
                    name: 'Page 1',
                    children: [{
                        id: 'node-1',
                        name: 'Publication fixture',
                        type: 'FRAME',
                        children: []
                    }]
                }]
            }
        },
        fileKey: 'publication-fixture',
        nodeId: 'node-1',
        projectType: 'wordpress',
        scssRoot
    });
}

test('figma publication keeps _Component.scss @forward as the preferred strategy', () => {
    const scssRoot = makeTempScssRoot();
    fs.writeFileSync(
        path.join(scssRoot, 'Component', '_Component.scss'),
        '@forward "figma-generated";\n',
        'utf8'
    );
    fs.writeFileSync(
        path.join(scssRoot, 'common.scss'),
        '@use "Component/figma-generated";\n',
        'utf8'
    );

    const publication = makePublicationPlan(scssRoot).publication;
    assert.equal(publication.strategy, 'component-forward');
    assert.equal(publication.status, 'FORWARD_PRESENT');
    assert.equal(publication.requiredForward, '@forward "figma-generated";');
});

test('figma publication detects common.scss direct @use without writing preview files', () => {
    const scssRoot = makeTempScssRoot();
    const commonPath = path.join(scssRoot, 'common.scss');
    const content = '@use "Component/colorS";\n@use\n  "Component/figma-generated";\n@use "Component/slider";\n';
    fs.writeFileSync(commonPath, content, 'utf8');

    const before = fs.readFileSync(commonPath);
    const publication = makePublicationPlan(scssRoot).publication;
    assert.equal(publication.strategy, 'common-use');
    assert.equal(publication.status, 'USE_PRESENT');
    assert.equal(publication.indexPath, commonPath);
    assert.equal(publication.requiredForward, '@use "Component/figma-generated";');
    assert.deepEqual(publication.matchedSpecifiers, ['Component/figma-generated']);
    assert.deepEqual(fs.readFileSync(commonPath), before);
    assert.equal(fs.existsSync(path.join(scssRoot, 'Component', '_figma-generated.scss')), false);
});

test('figma publication reports missing and duplicate direct @use declarations', async t => {
    await t.test('missing', () => {
        const scssRoot = makeTempScssRoot();
        fs.writeFileSync(
            path.join(scssRoot, 'common.scss'),
            '@use "Component/colorS";\n@use "Component/slider";\n',
            'utf8'
        );
        const publication = makePublicationPlan(scssRoot).publication;
        assert.equal(publication.status, 'USE_MISSING');
        assert.deepEqual(publication.matchedSpecifiers, []);
    });

    await t.test('duplicate', () => {
        const scssRoot = makeTempScssRoot();
        fs.writeFileSync(
            path.join(scssRoot, 'common.scss'),
            '@use "Component/figma-generated";\n@use "Component/_figma-generated.scss" as generated;\n',
            'utf8'
        );
        const publication = makePublicationPlan(scssRoot).publication;
        assert.equal(publication.status, 'USE_DUPLICATE');
        assert.deepEqual(publication.matchedSpecifiers, [
            'Component/figma-generated',
            'Component/_figma-generated.scss'
        ]);
    });
});

test('figma publication ignores commented/string @use text and fails closed when direct use is unconfirmed', () => {
    const scssRoot = makeTempScssRoot();
    fs.writeFileSync(
        path.join(scssRoot, 'common.scss'),
        '/* @use "Component/figma-generated"; */\n$example: \'@use "Component/figma-generated";\';\nbody { content: "@use Component/figma-generated"; }\n',
        'utf8'
    );
    const publication = makePublicationPlan(scssRoot).publication;
    assert.equal(publication.status, 'COMMON_DIRECT_USE_UNCONFIRMED');
    assert.match(publication.error, /does not contain a top-level @use/);
});

test('figma publication fails closed for an ambiguous common.scss parse', () => {
    const scssRoot = makeTempScssRoot();
    fs.writeFileSync(
        path.join(scssRoot, 'common.scss'),
        '@use "Component/colorS";\n/* unterminated',
        'utf8'
    );
    const publication = makePublicationPlan(scssRoot).publication;
    assert.equal(publication.status, 'COMMON_ENTRY_PARSE_UNSAFE');
    assert.equal(publication.error, 'unterminated block comment');
});

test('figma sync treats legacy background shorthand as OWNED_SAME for bg selectors', () => {
    const scssRoot = makeTempScssRoot();

    fs.writeFileSync(
        path.join(scssRoot, 'Component', '_colorS.scss'),
        `.bg_265278 {\n  background: #265278;\n}\n`,
        'utf8'
    );

    const figmaFile = {
        document: {
            children: [
                {
                    id: 'page-1',
                    name: 'Page 1',
                    children: [
                        {
                            id: '1956:60151',
                            name: 'Frame 15',
                            type: 'FRAME',
                            fills: [
                                {
                                    type: 'SOLID',
                                    color: {
                                        r: 0x26 / 255,
                                        g: 0x52 / 255,
                                        b: 0x78 / 255
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    };

    const plan = buildFigmaSyncPlan({
        figmaFile,
        fileKey: 'dummy-file',
        nodeId: '1956:60151',
        projectType: 'wordpress',
        scssRoot
    });

    const row = plan.rows.find(item => item.selector === '.bg_265278');
    assert.ok(row);
    assert.equal(row.status, 'OWNED_SAME');

    const conflict = plan.diagnostics.find(item => item.selector === '.bg_265278');
    assert.equal(conflict, undefined);
});
test('figma sync keeps complex legacy background shorthand as CONFLICT_UNKNOWN', () => {
    const scssRoot = makeTempScssRoot();

    fs.writeFileSync(
        path.join(scssRoot, 'Component', '_colorS.scss'),
        `.bg_265278 {\n  background: url("example.png");\n}\n`,
        'utf8'
    );

    const figmaFile = {
        document: {
            children: [
                {
                    id: 'page-1',
                    name: 'Page 1',
                    children: [
                        {
                            id: '1956:60151',
                            name: 'Frame 15',
                            type: 'FRAME',
                            fills: [
                                {
                                    type: 'SOLID',
                                    color: {
                                        r: 0x26 / 255,
                                        g: 0x52 / 255,
                                        b: 0x78 / 255
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    };

    const plan = buildFigmaSyncPlan({
        figmaFile,
        fileKey: 'dummy-file',
        nodeId: '1956:60151',
        projectType: 'wordpress',
        scssRoot
    });

    const row = plan.rows.find(item => item.selector === '.bg_265278');
    assert.ok(row);
    assert.equal(row.status, 'CONFLICT_UNKNOWN');

    const conflict = plan.diagnostics.find(item => item.selector === '.bg_265278');
    assert.ok(conflict);
    assert.equal(conflict.level, 'CONFLICT_UNKNOWN');
});
