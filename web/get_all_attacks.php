<?php
# get_known_attacks.php
require_once __DIR__ . '/config/db_security.php';

header("Content-Type: application/json; charset=utf-8");

// 只允許黑名單和 LLM黑名單的攻擊類型
$allowedStatuses = ['黑名單', 'LLM黑名單', '警告IP'];

// 若前端傳入 statuses，與允許清單取交集
if (!empty($_GET['statuses'])) {
    $requestedStatuses = array_map('trim', explode(',', $_GET['statuses']));
    $filtered = array_values(array_intersect($requestedStatuses, $allowedStatuses));
    if (!empty($filtered)) {
        $allowedStatuses = $filtered;
    }
}

if (empty($allowedStatuses)) {
    echo json_encode([]);
    exit;
}

$placeholders = implode(',', array_fill(0, count($allowedStatuses), '?'));
$types = str_repeat('s', count($allowedStatuses));

$sql = "
SELECT DISTINCT attack_type
FROM ip_risk_status_v2
WHERE attack_type IS NOT NULL
  AND status IN ($placeholders)
ORDER BY attack_type ASC
";

$stmt = $conn->prepare($sql);
$stmt->bind_param($types, ...$allowedStatuses);
$stmt->execute();
$result = $stmt->get_result();
$attacks = [];

while ($row = $result->fetch_assoc()) {
    $attacks[] = $row;
}

echo json_encode($attacks);