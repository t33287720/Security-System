<?php
require_once 'config/auth.php';
require_once __DIR__ . '/config/db_security.php';

header('Content-Type: application/json');

$id     = intval($_POST['id'] ?? 0);
$status = $_POST['status'] ?? '';

$valid_status = ['pending', 'confirmed', 'false_positive', 'resolved'];
if (!in_array($status, $valid_status, true)) {
    echo json_encode(['success' => false, 'message' => '狀態不合法'], JSON_UNESCAPED_UNICODE);
    exit;
}
if ($id <= 0) {
    echo json_encode(['success' => false, 'message' => 'id 不可為空'], JSON_UNESCAPED_UNICODE);
    exit;
}

$stmt = $conn->prepare("UPDATE code_findings SET status = ? WHERE id = ?");
$stmt->bind_param('si', $status, $id);
$ok = $stmt->execute();
$stmt->close();

echo json_encode(['success' => $ok], JSON_UNESCAPED_UNICODE);
?>
