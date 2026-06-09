<?php
require_once 'config/auth.php'; // 如有必要做權限認證
require_once __DIR__ . '/../../config/db_security.php';

header('Content-Type: application/json');

// 只接受 POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => '只接受 POST 請求']);
    exit;
}

$ip = $_POST['ip'] ?? '';
$ip = trim($ip);

if (!$ip) {
    echo json_encode(['success' => false, 'message' => '未提供 IP']);
    exit;
}

// 防止意外修改，可自行加驗證

try {
    // 使用 prepared statement 避免 SQL 注入
    // 將 ip_risk_status 表格中該 IP 的 live_status 更新為 0
    $stmt = $conn->prepare("UPDATE ip_risk_status_v2 SET live_status = 0 WHERE ip = ?");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    
    // 檢查是否有記錄被更新
    if ($stmt->affected_rows > 0) {
        echo json_encode(['success' => true, 'message' => 'IP 狀態已成功更新']);
    } else {
        // 找不到該 IP 或 live_status 已經是 0
        echo json_encode(['success' => false, 'message' => '找不到該 IP']);
    }

    $stmt->close();
} catch (Exception $e) {
    error_log("更新 IP 狀態失敗: $ip, error: {$e->getMessage()}");
    echo json_encode(['success' => false, 'message' => '資料庫操作失敗']);
}
?>