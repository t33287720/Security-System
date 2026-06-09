<?php
require_once __DIR__ . '/config/db_security.php';
header("Content-Type: application/json; charset=utf-8");

$sql = "
SELECT
    id,
    ip,
    attack_type,
    attack_method,
    reason,
    status,
    created_time
FROM ai_log_analysis
WHERE status = 'pending'
ORDER BY created_time DESC
";

$result = $conn->query($sql);
$attacks = [];
while ($row = $result->fetch_assoc()) {
    $attacks[] = $row;
}

echo json_encode($attacks);
