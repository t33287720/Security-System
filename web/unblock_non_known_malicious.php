<?php
require_once 'config/auth.php';
require_once __DIR__ . '/config/db_security.php';

header('Content-Type: application/json');

$result = $conn->query(
    "UPDATE ip_risk_status_v2 SET live_status = 0
     WHERE status IN ('黑名單', 'LLM黑名單')
       AND attack_type <> '已知惡意IP'
       AND live_status = 1"
);

if ($result === false) {
    echo json_encode(['success' => false, 'message' => $conn->error]);
} else {
    echo json_encode(['success' => true, 'affected' => $conn->affected_rows]);
}
