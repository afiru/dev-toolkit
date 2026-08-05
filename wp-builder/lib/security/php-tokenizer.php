<?php

declare(strict_types=1);

$source = stream_get_contents(STDIN);

try {
    $rawTokens = token_get_all($source, TOKEN_PARSE);
} catch (ParseError $error) {
    fwrite(STDOUT, json_encode([
        'ok' => false,
        'error' => [
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
    'tokens' => $tokens,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
