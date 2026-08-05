import fs from 'node:fs';
import path from 'node:path';

const WORDPRESS_THEME_PATH = [
    'public',
    'wp-content',
    'themes',
    'WebPTemplatebyMarcat'
];

export function getProjectContext() {
    const workspaceRoot = path.resolve(process.cwd());
    const wordpressThemeRoot = path.join(workspaceRoot, ...WORDPRESS_THEME_PATH);
    const projectType = fs.existsSync(wordpressThemeRoot) ? 'wordpress' : 'static';
    const themeRoot = projectType === 'wordpress' ? wordpressThemeRoot : null;
    const projectRoot = themeRoot ?? workspaceRoot;
    const scssRoot = path.join(projectRoot, 'scss');

    // Transitional compatibility field retained for Phase 1-A consumers.
    // Color utilities use scssRoot from Phase 1-B-2 onward; remove this field only
    // after the compatibility period has ended.
    const workspaceScssRoot = path.join(workspaceRoot, 'scss');

    return Object.freeze({
        workspaceRoot,
        projectType,
        themeRoot,
        projectRoot,
        scssRoot,
        workspaceScssRoot
    });
}
