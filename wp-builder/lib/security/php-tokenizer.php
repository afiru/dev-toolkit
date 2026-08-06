<?php

declare(strict_types=1);

const WPB_TOKENIZER_HELPER_SCHEMA_VERSION = 1;

function runtimeInfo(): array
{
    return [
        'phpVersion' => PHP_VERSION,
        'phpVersionId' => PHP_VERSION_ID,
        'phpMajor' => PHP_MAJOR_VERSION,
        'phpMinor' => PHP_MINOR_VERSION,
        'tokenizerAvailable' => extension_loaded('tokenizer') && function_exists('token_get_all'),
        'helperSchemaVersion' => WPB_TOKENIZER_HELPER_SCHEMA_VERSION,
    ];
}

$source = stream_get_contents(STDIN);
$runtime = runtimeInfo();

if (!$runtime['tokenizerAvailable']) {
    fwrite(STDOUT, json_encode([
        'ok' => false,
        'runtime' => $runtime,
        'error' => [
            'code' => 'PHP_TOKENIZER_UNAVAILABLE',
            'message' => 'PHP tokenizer extension is unavailable.',
            'line' => null,
        ],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    exit(2);
}

try {
    $rawTokens = token_get_all($source, TOKEN_PARSE);
} catch (ParseError $error) {
    fwrite(STDOUT, json_encode([
        'ok' => false,
        'runtime' => $runtime,
        'error' => [
            'code' => 'WPB-SCF-PARSE-UNSAFE',
            'message' => $error->getMessage(),
            'line' => $error->getLine(),
        ],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    exit(2);
}

$tokens = [];
$offset = 0;
$line = 1;

foreach ($rawTokens as $rawToken) {
    if (is_array($rawToken)) {
        [$id, $text, $tokenLine] = $rawToken;
        $type = token_name($id);
        $line = $tokenLine;
    } else {
        $text = $rawToken;
        $type = $rawToken;
    }

    $length = strlen($text);
    $tokens[] = [
        'type' => $type,
        'text' => $text,
        'startByte' => $offset,
        'endByte' => $offset + $length,
        'line' => $line,
    ];

    $offset += $length;
    $line += substr_count($text, "\n");
}

fwrite(STDOUT, json_encode([
    'ok' => true,
    'runtime' => $runtime,
    'tokens' => $tokens,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
