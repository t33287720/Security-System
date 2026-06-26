<?php
require_once __DIR__ . '/config/db_security.php';
header('Content-Type: application/json; charset=utf-8');

$key = $_GET['key'] ?? '';
if (!$key) {
    echo json_encode(['success' => false, 'error' => '缺少 key 參數']);
    exit;
}

$stmt = $conn->prepare("SELECT `value` FROM system_settings WHERE `key` = ? ORDER BY id DESC LIMIT 1");
$stmt->bind_param('s', $key);
$stmt->execute();
$result = $stmt->get_result();
$row = $result->fetch_assoc();

if ($row) {
    echo json_encode(['success' => true, 'key' => $key, 'value' => $row['value']]);
} else {
    echo json_encode(['success' => false, 'error' => '找不到此設定']);
}
