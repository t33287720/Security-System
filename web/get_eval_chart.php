<?php
// get_eval_chart.php — 提供 eval PNG 圖檔

$allowed = [
    'trend_over_time',
];

$name = preg_replace('/[^a-z0-9_]/', '', strtolower($_GET['name'] ?? ''));

if (!in_array($name, $allowed, true)) {
    http_response_code(404);
    exit;
}

$path = __DIR__ . '/api/eval/output/' . $name . '.png';

if (!file_exists($path)) {
    http_response_code(404);
    exit;
}

header('Content-Type: image/png');
header('Cache-Control: no-cache, must-revalidate');
readfile($path);
