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
    // 若此 IP 目前為黑名單/LLM黑名單，且即將改為白名單 → 視為「誤判回報」
    // 額外寫入 eval_results 作為 benign 樣本（供 FPR / 自動調參使用）
    if ($status === '白名單') {
        $stmtPrev = $conn->prepare(
            "SELECT actions, attack_type FROM ip_risk_status_v2
             WHERE ip = ? AND status IN ('黑名單','LLM黑名單') AND live_status = 1 LIMIT 1"
        );
        $stmtPrev->bind_param('s', $ip);
        $stmtPrev->execute();
        $prevRow = $stmtPrev->get_result()->fetch_assoc();
        $stmtPrev->close();

        if ($prevRow) {
            $actions_raw  = $prevRow['actions'] ?? '[]';
            $danger_level = '危險';
            $confidence   = 0.0;
            $actions_arr  = json_decode($actions_raw, true);
            if (is_array($actions_arr) && count($actions_arr) > 0) {
                $last = end($actions_arr);
                $danger_level = $last['danger_level'] ?? '危險';
                $confidence   = floatval($last['confidence'] ?? 0);
            }

            $stmtCnt = $conn->prepare(
                "SELECT COUNT(*) AS cnt FROM ip_risk_logs WHERE ip = ? AND created_at >= NOW() - INTERVAL 24 HOUR"
            );
            $stmtCnt->bind_param('s', $ip);
            $stmtCnt->execute();
            $log_count = (int)($stmtCnt->get_result()->fetch_assoc()['cnt'] ?? 0);
            $stmtCnt->close();

            $orig_attack_type = $prevRow['attack_type'] ?? '';
            $stmtFp = $conn->prepare(
                "INSERT INTO eval_results
                    (ip, true_label, gt_source, danger_level, confidence, attack_type, actions, log_count, source_count, analyzed_at)
                 VALUES (?, 'benign', 'fp_report', ?, ?, ?, ?, ?, 0, NOW())"
            );
            $stmtFp->bind_param('ssdssi', $ip, $danger_level, $confidence, $orig_attack_type, $actions_raw, $log_count);
            $stmtFp->execute();
            $stmtFp->close();
        }
    }

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