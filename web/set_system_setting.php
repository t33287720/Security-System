<?php
require_once __DIR__ . '/config/db_security.php';
header('Content-Type: application/json; charset=utf-8');

$key   = $_POST['key']   ?? '';
$value = $_POST['value'] ?? '';
if (!$key) {
    echo json_encode(['success' => false, 'error' => '缺少 key 參數']);
    exit;
}

$stmt = $conn->prepare("INSERT INTO system_settings (`key`, `value`) VALUES (?, ?)");
$stmt->bind_param('ss', $key, $value);
if ($stmt->execute()) {
    echo json_encode(['success' => true, 'key' => $key, 'value' => $value]);
} else {
    echo json_encode(['success' => false, 'error' => $conn->error]);
}
