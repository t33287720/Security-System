<?php
require_once __DIR__ . '/config/db_security.php';
header('Content-Type: application/json; charset=utf-8');

$rows = [];
$result = $conn->query("
    SELECT ip, branch, original_level, attempted_level, outcome, created_at
    FROM llm_discrepancies
    ORDER BY created_at DESC
    LIMIT 200
");
while ($row = $result->fetch_assoc()) {
    $rows[] = $row;
}

$stats_result = $conn->query("
    SELECT
        COUNT(*) AS total,
        SUM(branch = 'RETRY')          AS n_retry,
        SUM(branch = 'LOW-DATA')       AS n_low_data,
        SUM(outcome = 'adopted')       AS n_adopted
    FROM llm_discrepancies
");
$stats = $stats_result->fetch_assoc();

echo json_encode([
    'success' => true,
    'stats'   => $stats,
    'records' => $rows,
], JSON_UNESCAPED_UNICODE);
