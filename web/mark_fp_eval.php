<?php require_once 'config/auth.php'; ?>
<?php
// mark_fp_eval.php — 管理員標記某 IP 為「誤判（FP）」
// 1. 在 eval_results 寫一筆 true_label='benign'（gt_source='fp_report'）
// 2. 將 IP 狀態改為「白名單」並清除封鎖時間
require_once __DIR__ . '/config/db_security.php';
header('Content-Type: application/json; charset=utf-8');

$ip = trim($_POST['ip'] ?? '');
if (!$ip) {
    echo json_encode(['success' => false, 'message' => 'IP 不可為空']);
    exit;
}

// ── 1. 取得最新 LLM 分析資料
$stmt = $conn->prepare(
    "SELECT actions, attack_type FROM ip_risk_status_v2 WHERE ip = ? AND live_status = 1 LIMIT 1"
);
$stmt->bind_param('s', $ip);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();
$stmt->close();

$actions_raw  = $row['actions']     ?? '[]';
$attack_type  = $row['attack_type'] ?? '';
$danger_level = '危險';
$confidence   = 0.0;

$actions_arr = json_decode($actions_raw, true);
if (is_array($actions_arr) && count($actions_arr) > 0) {
    $last = end($actions_arr);
    $danger_level = $last['danger_level'] ?? '危險';
    $confidence   = floatval($last['confidence'] ?? 0);
}

// ── 2. 取得 24h log 數量
$stmt2 = $conn->prepare(
    "SELECT COUNT(*) AS cnt FROM ip_risk_logs WHERE ip = ? AND created_at >= NOW() - INTERVAL 24 HOUR"
);
$stmt2->bind_param('s', $ip);
$stmt2->execute();
$log_count = (int)($stmt2->get_result()->fetch_assoc()['cnt'] ?? 0);
$stmt2->close();

// ── 3. 寫入 eval_results（true_label='benign', gt_source='fp_report'）
$stmt3 = $conn->prepare(
    "INSERT INTO eval_results
        (ip, true_label, gt_source, danger_level, confidence, attack_type, actions, log_count, source_count, analyzed_at)
     VALUES (?, 'benign', 'fp_report', ?, ?, ?, ?, ?, 0, NOW())"
);
$stmt3->bind_param('ssdssi', $ip, $danger_level, $confidence, $attack_type, $actions_raw, $log_count);
$ok3 = $stmt3->execute();
$stmt3->close();

if (!$ok3) {
    echo json_encode(['success' => false, 'message' => 'eval_results 寫入失敗']);
    exit;
}

// ── 4. 將 IP 移至白名單、清除封鎖
$stmt4 = $conn->prepare(
    "UPDATE ip_risk_status_v2
     SET status = '白名單', attack_type = '管理員標記誤判', unblock_time = NULL, last_time = NOW()
     WHERE ip = ? AND live_status = 1"
);
$stmt4->bind_param('s', $ip);
$stmt4->execute();
$stmt4->close();

echo json_encode([
    'success' => true,
    'message' => "IP {$ip} 已標記為 FP 並移至白名單",
    'eval_written' => true,
]);
