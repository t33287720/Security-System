<?php
# get_known_attacks.php
require_once __DIR__ . '/../../config/db_security.php';
header("Content-Type: application/json; charset=utf-8");

$sql = "
SELECT
    id,
    attack_type,
    attack_method,
    reason,
    status,
    created_time
FROM ai_log_analysis
WHERE status = 'approved'
ORDER BY attack_type ASC
";

$result = $conn->query($sql);
$attacks = [];
while ($row = $result->fetch_assoc()) {
    $attacks[] = $row;
}

echo json_encode($attacks);
