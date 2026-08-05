export function renderFigmaForwardPreview(plan, options = {}) {
    const {
        applyRequested = false,
        out = console.log,
        error = console.error
    } = options;

    out('Figma forward preview');
    out(`mode: ${applyRequested ? 'apply requested (preview first)' : 'preview'}`);
    out(`projectType: ${plan.projectType}`);
    out(`Component index: ${plan.indexPath}`);
    out(`Figma target: ${plan.targetPath}`);
    out(`publication: ${plan.publicationStatus}`);
    out(`target: ${plan.targetStatus}`);
    out(`required: ${plan.requiredForward}`);
    if (plan.matchedSpecifiers.length > 0) out(`matched: ${plan.matchedSpecifiers.join(', ')}`);

    if (plan.findings.length > 0) {
        out('findings:');
        plan.findings.forEach(finding => {
            const print = finding.blocking ? error : out;
            print(`  [${finding.code}]${finding.blocking ? ' BLOCKING' : ''} ${finding.message}`);
        });
    }

    if (plan.diff) {
        out(plan.canApply ? 'unified diff:' : 'blocked proposed unified diff:');
        out(plan.diff);
    } else {
        out('No forward changes.');
    }

    out(`Forward preview complete: ${plan.publicationStatus}`);
    out(applyRequested ? 'No files changed yet.' : 'No files changed.');
}
