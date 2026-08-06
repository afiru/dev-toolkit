export const PHP_TOKENIZER_HELPER_SCHEMA_VERSION = 1;

const REQUIRED_RUNTIME_FIELDS = [
    'phpVersion',
    'phpVersionId',
    'phpMajor',
    'phpMinor',
    'tokenizerAvailable',
    'helperSchemaVersion'
];

export function classifyPhpRuntime(runtime) {
    if (!runtime?.tokenizerAvailable) return {
        status: 'PHP_TOKENIZER_UNAVAILABLE',
        applyEligible: false,
        warning: 'PHP tokenizer extension is unavailable.'
    };

    if (runtime.phpMajor < 8) return {
        status: 'PHP_VERSION_UNSUPPORTED',
        applyEligible: false,
        warning: `PHP ${runtime.phpVersion} is unsupported. PHP 8.0 or newer is required.`
    };

    if (runtime.phpMajor === 8 && runtime.phpMinor <= 1) return {
        status: 'LEGACY_COMPATIBILITY',
        applyEligible: false,
        warning: `PHP ${runtime.phpMajor}.${runtime.phpMinor} is EOL legacy compatibility only; apply remains disabled pending matrix approval.`
    };

    if (runtime.phpMajor === 8 && runtime.phpMinor >= 2 && runtime.phpMinor <= 4) return {
        status: 'VERIFIED_APPLY_CANDIDATE',
        applyEligible: true,
        warning: null
    };

    return {
        status: 'PHP_VERSION_UNVERIFIED',
        applyEligible: false,
        warning: `PHP ${runtime.phpVersion} has not been verified for Security Fix apply.`
    };
}

export function normalizePhpRuntimeContract(value) {
    if (!value || typeof value !== 'object') return {
        ok: false,
        code: 'PHP_TOKENIZER_CONTRACT_UNSAFE',
        message: 'PHP tokenizer helper did not return runtime information.',
        runtime: null
    };

    if (value.helperSchemaVersion !== PHP_TOKENIZER_HELPER_SCHEMA_VERSION) return {
        ok: false,
        code: 'PHP_TOKENIZER_HELPER_SCHEMA_UNSUPPORTED',
        message: `Unsupported PHP tokenizer helper schema: ${String(value.helperSchemaVersion)}.`,
        runtime: null
    };

    const missing = REQUIRED_RUNTIME_FIELDS.filter(field => !(field in value));
    const validNumbers = ['phpVersionId', 'phpMajor', 'phpMinor']
        .every(field => Number.isInteger(value[field]) && value[field] >= 0);
    const versionIdMatches = validNumbers && (
        Math.floor(value.phpVersionId / 10000) === value.phpMajor &&
        Math.floor(value.phpVersionId / 100) % 100 === value.phpMinor
    );
    if (
        missing.length > 0 ||
        typeof value.phpVersion !== 'string' ||
        !validNumbers ||
        !versionIdMatches ||
        typeof value.tokenizerAvailable !== 'boolean'
    ) {
        return {
            ok: false,
            code: 'PHP_TOKENIZER_CONTRACT_UNSAFE',
            message: 'PHP tokenizer helper returned an invalid runtime contract.',
            runtime: null
        };
    }

    const gate = classifyPhpRuntime(value);
    return {
        ok: true,
        code: null,
        message: null,
        runtime: {
            phpVersion: value.phpVersion,
            phpVersionId: value.phpVersionId,
            phpMajor: value.phpMajor,
            phpMinor: value.phpMinor,
            tokenizerAvailable: value.tokenizerAvailable,
            helperSchemaVersion: value.helperSchemaVersion,
            gate
        }
    };
}

export function phpRuntimeBlockingReason(runtime) {
    if (!runtime?.gate || runtime.gate.applyEligible) return null;
    return {
        code: runtime.gate.status === 'LEGACY_COMPATIBILITY'
            ? 'PHP_VERSION_LEGACY_COMPATIBILITY'
            : runtime.gate.status,
        message: runtime.gate.warning
    };
}
