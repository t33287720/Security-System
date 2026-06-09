<?php
require_once 'config/auth.php';
require_once __DIR__ . '/config/db_security.php';

header('Content-Type: application/json');

$ip = $_POST['ip'] ?? '';
$status = $_POST['status'] ?? '';
$type = $_POST['type'] ?? 'single';  // 預設為單一 IP
$attack_type = $_POST['attack_type'] ?? ''; // ✅ 新增

$unblock_hours = intval($_POST['unblock_hours'] ?? 24);
$unblock_time = date('Y-m-d H:i:s', time() + $unblock_hours * 3600);

$valid_status = ['黑名單', '白名單', '警告IP','LLM黑名單','暫時白名單'];
if (!in_array($status, $valid_status)) {
    echo json_encode([
        'success' => false,
        'message' => '狀態不合法',
        '_debug_received_hex' => bin2hex($status),
        '_debug_whitelist_hex' => bin2hex('白名單'),
        '_debug_match' => ($status === '白名單'),
    ]);
    exit;
}

if (empty($ip)) {
    echo json_encode(['success' => false, 'message' => 'IP 不可為空']);
    exit;
}

if (empty($attack_type)) {
    echo json_encode(['success' => false, 'message' => '必須提供 attack_type']);
    exit;
}

if ($type === 'single') {
    // ✅ UPDATE
    $stmt = $conn->prepare(
        "UPDATE ip_risk_status_v2 
         SET status = ?, attack_type = ?, last_time = NOW(), unblock_time = ? 
         WHERE ip = ? AND live_status = 1"
    );
    $stmt->bind_param('ssss',$status, $attack_type, $unblock_time, $ip);
    $stmt->execute();
    $affected_rows = $stmt->affected_rows;
    $stmt->close();

    if ($affected_rows === 0) {
        $stmt = $conn->prepare(
            "INSERT INTO ip_risk_status_v2 
            (ip, status, attack_type, first_time, last_time, unblock_time) 
            VALUES (?, ?, ?, NOW(), NOW(), ?)"
        );
        $stmt->bind_param('ssss', $ip, $status, $attack_type, $unblock_time);
        $success = $stmt->execute();
        $stmt->close();

        echo json_encode(['success' => $success]);
    } else {
        echo json_encode(['success' => true]);
    }
} elseif ($type === 'range') {
    try {
        $stmt = $conn->prepare(
            "UPDATE ip_risk_ranges
             SET status = ?, attack_type = ?, `time` = NOW()
             WHERE ip_pattern = ?"
        );
        $stmt->bind_param('sss', $status, $attack_type, $ip);
        $stmt->execute();
        $affected_rows = $stmt->affected_rows;
        $stmt->close();

        if ($affected_rows === 0) {
            $stmt = $conn->prepare(
                "INSERT INTO ip_risk_ranges (ip_pattern, status, attack_type, `time`)
                 VALUES (?, ?, ?, NOW())"
            );
            $stmt->bind_param('sss', $ip, $status, $attack_type);
            $success = $stmt->execute();
            $stmt->close();
            echo json_encode(['success' => $success]);
        } else {
            echo json_encode(['success' => true]);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'DB 錯誤: ' . $e->getMessage()]);
    }
} else {
    echo json_encode(['success' => false, 'message' => '未知的類型']);
    exit;
}