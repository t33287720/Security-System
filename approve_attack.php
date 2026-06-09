<?php
require_once __DIR__ . '/../../config/db_security.php';

header("Content-Type: application/json; charset=utf-8");

$attack_id = $_POST['attack_id'] ?? null;
$action = $_POST['action'] ?? null;

if (!$attack_id || !in_array($action, ['approve', 'reject'])) {
    echo json_encode(['success' => false, 'error' => '參數錯誤']);
    exit;
}

$status = $action === 'approve' ? 'approved' : 'rejected';

$sql = "UPDATE ai_log_analysis SET status = ? WHERE id = ?";
$stmt = $conn->prepare($sql);
if (!$stmt) {
    echo json_encode(['success' => false, 'error' => 'SQL 準備失敗: ' . $conn->error]);
    exit;
}

$stmt->bind_param('si', $status, $attack_id);
if (!$stmt->execute()) {
    echo json_encode(['success' => false, 'error' => '更新失敗: ' . $stmt->error]);
    exit;
}

$actText = $action === 'approve' ? '已批准' : '已拒絕';

echo json_encode(['success' => true, 'message' => "{$actText}攻擊記錄(ID={$attack_id})"]);
