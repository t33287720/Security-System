<?php
require_once __DIR__ . '/config/db_security.php';
header('Content-Type: application/json');

$res = $conn->query("
    SELECT generated_at, summary, highlights, stats, top_findings
    FROM scan_reports
    ORDER BY id DESC
    LIMIT 1
");
$row = $res ? $res->fetch_assoc() : null;

if (!$row) {
    echo json_encode(['exists' => false], JSON_UNESCAPED_UNICODE);
    exit;
}

$stats = json_decode($row['stats'] ?? '{}', true) ?: [];

echo json_encode([
    'exists'        => true,
    'generated_at'  => $row['generated_at'],
    'summary'       => $row['summary'],
    'highlights'    => json_decode($row['highlights'] ?? '[]', true) ?: [],
    'total'         => $stats['total'] ?? 0,
    'severity'      => $stats['severity'] ?? ['高' => 0, '中' => 0, '低' => 0, '資訊' => 0],
    'new_count'     => $stats['new_count'] ?? 0,
    'resolved_count'=> $stats['resolved_count'] ?? 0,
    'previous_total'=> $stats['previous_total'] ?? 0,
    'top_findings'  => json_decode($row['top_findings'] ?? '[]', true) ?: [],
], JSON_UNESCAPED_UNICODE);
?>
