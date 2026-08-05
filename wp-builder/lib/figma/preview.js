export function renderFigmaSyncPreview(plan, options = {}) {
    const {
        applyRequested = false,
        out = console.log,
        error = console.error
    } = options;

    out('Figma sync preview');
    out(`mode: ${applyRequested ? 'apply requested (preview first)' : 'preview'}`);
    out(`projectType: ${plan.projectType}`);
    out(`Figma file key: ${plan.source.fileKey}`);
    out(`node ID: ${plan.source.nodeId}`);
    out(`node: ${plan.source.nodeName} (${plan.source.nodeType})`);
    out(`planned output: ${plan.targetPath}`);
    out('publication:');
    out(`  [${plan.publication.status}] ${plan.publication.indexPath}`);
    out(`  required: ${plan.publication.requiredForward}`);
    if (plan.publication.matchedSpecifiers.length > 0) {
        out(`  matched: ${plan.publication.matchedSpecifiers.join(', ')}`);
    }
    if (plan.publication.error) error(`  ${plan.publication.error}`);
    out('generated classes:');
    if (plan.rows.length === 0) out('  (none)');
    plan.rows.forEach(row => out(`  [${row.status}] ${row.line}`));

    const statuses = ['ADD', 'CHANGE', 'REMOVE', 'UNCHANGED', 'OWNED_SAME', 'CONFLICT', 'CONFLICT_UNKNOWN'];
    out(`summary: ${statuses.map(status => `${status} ${plan.counts[status] ?? 0}`).join(', ')}`);

    if (plan.diagnostics.length > 0) {
        error('diagnostics:');
        plan.diagnostics.forEach(item => {
            const selector = item.selector ? ` ${item.selector}` : '';
            error(`  [${item.level}]${selector} ${item.message}`);
        });
    }

    if (plan.diff) {
        out('unified diff:');
        out(plan.diff);
    } else {
        out('No Figma changes.');
    }

    out(`Figma preview complete: ${plan.source.nodeName} (${plan.source.nodeId})`);
    out(applyRequested ? 'No files changed yet.' : 'No files changed.');
    out('Note: _Component.scss is not modified automatically.');
}
