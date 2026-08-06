export function renderSecurityFixPreview(plan, options = {}) {
    const {
        applyRequested = false,
        out = console.log,
        error = console.error
    } = options;

    out('Security Fix Preview');
    out(`mode: ${applyRequested ? 'apply requested (preview first)' : 'preview'}`);
    out(`file: ${plan.targetPath}`);
    if (plan.tokenizer?.runtime) {
        const { runtime } = plan.tokenizer;
        out(`PHP runtime: ${runtime.phpVersion}`);
        out(`tokenizer: ${runtime.tokenizerAvailable ? 'available' : 'unavailable'}`);
        out(`tokenizer helper schema: ${runtime.helperSchemaVersion}`);
        out(`runtime status: ${runtime.gate.status}`);
        if (runtime.gate.warning) out(`runtime note: ${runtime.gate.warning}`);
    }
    if (plan.encoding) {
        out(`encoding: ${plan.encoding.charset}${plan.encoding.bom ? ' with BOM' : ''}`);
        out(`newline: ${plan.newline.style}`);
    }

    out('findings:');
    if (plan.findings.length === 0) out('  (none)');
    plan.findings.forEach(finding => {
        const disposition = finding.autoFixable ? 'AUTO_FIXABLE' : 'DIAGNOSTIC_ONLY';
        out(`  [${disposition}] [${finding.severity}] ${finding.ruleId}`);
        out(`    location: ${finding.location.startLine}:${finding.location.startColumn}`);
        if (finding.exactSourceExpression) out(`    source: ${finding.exactSourceExpression.replace(/\r?\n/g, '\\n')}`);
        if (finding.scf?.field !== null && finding.scf?.field !== undefined) out(`    field: ${finding.scf.field}`);
        out(`    context: ${finding.outputContext.kind}`);
        out(`    confidence: ${finding.confidence}`);
        out(`    reason: ${finding.reason}`);
        if (finding.replacement) out(`    replacement: ${finding.replacement.replacementText}`);
    });

    out(`PHP lint: ${plan.lint.available ? plan.lint.passed ? 'PASS' : 'FAIL' : 'UNAVAILABLE'}`);
    if (plan.lint.output) out(`  ${plan.lint.output.replace(/\r?\n/g, '\n  ')}`);

    if (plan.blockingReasons.length > 0) {
        error('blocking diagnostics:');
        plan.blockingReasons.forEach(item => error(`  [${item.code}] ${item.message}`));
    }

    if (plan.diff) {
        out('unified diff:');
        out(plan.diff);
    } else {
        out('No Security Fix changes.');
    }

    out(
        `summary: ${plan.counts.findings} findings, ` +
        `${plan.counts.autoFixable} auto-fixable, ` +
        `${plan.counts.diagnosticOnly} diagnostic-only, ` +
        `${plan.hasChanges ? '1 file would change' : '0 files would change'}`
    );
    out(applyRequested ? 'No files changed yet.' : 'No files changed.');
}
