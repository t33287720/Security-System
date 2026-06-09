<?php
// get_ip_detail.php
require_once '../../config/db_security.php';
header('Content-Type: application/json');

if (!isset($_POST['ip'])) {
    echo json_encode(['success' => false, 'message' => '缺少 IP 參數']);
    exit();
}

$ip = $_POST['ip'];

// ---------------------------
// 1. 查詢該 IP 的全部 log（限最新 200 筆避免資料過大）
// ---------------------------
$logs_sql = "SELECT log_type, log_content, local_ip, direction, created_at
             FROM ip_risk_logs
             WHERE ip = ?
             ORDER BY created_at DESC
             LIMIT 200";
$stmt = $conn->prepare($logs_sql);
$stmt->bind_param("s", $ip);
$stmt->execute();
$result = $stmt->get_result();

$response_data = [
    'success'     => true,
    'login_count' => 0,
    'raw_logs'    => [],
    'zeek_logs'   => [],
    'actions'     => [],
    'ip_info'     => null,   // 來自 ip_risk_status_v2 的基本資訊
    'log_stats'   => []      // 統計：各方向/類型筆數
];

$dir_count = [];
while ($row = $result->fetch_assoc()) {
    if ($row['log_type'] === 'syslog') {
        $response_data['raw_logs'][] = [
            'content'    => $row['log_content'],
            'local_ip'   => $row['local_ip'],
            'direction'  => $row['direction'],
            'created_at' => $row['created_at']
        ];
    } elseif ($row['log_type'] === 'zeeklog') {
        $response_data['zeek_logs'][] = [
            'content'    => $row['log_content'],
            'local_ip'   => $row['local_ip'],
            'direction'  => $row['direction'],
            'created_at' => $row['created_at']
        ];
    }
    $dir = $row['direction'] ?: '未知';
    $dir_count[$dir] = ($dir_count[$dir] ?? 0) + 1;
}

$response_data['login_count'] = count($response_data['raw_logs']) + count($response_data['zeek_logs']);
$response_data['log_stats']   = $dir_count;
$stmt->close();

// ---------------------------
// 2. 從 ip_risk_status_v2 取得最新一筆記錄（不限 live_status，歷史 IP 同樣可查）
// ---------------------------
$info_sql = "SELECT status, attack_type, hostname, first_time, last_time, unblock_time, live_status, actions
             FROM ip_risk_status_v2
             WHERE ip = ?
             ORDER BY time DESC
             LIMIT 1";
$info_stmt = $conn->prepare($info_sql);
$info_stmt->bind_param("s", $ip);
$info_stmt->execute();
$info_result = $info_stmt->get_result();

if ($info_result->num_rows > 0) {
    $row = $info_result->fetch_assoc();
    $response_data['ip_info'] = [
        'status'       => $row['status'],
        'attack_type'  => $row['attack_type'],
        'hostname'     => $row['hostname'],
        'first_time'   => $row['first_time'],
        'last_time'    => $row['last_time'],
        'unblock_time' => $row['unblock_time'],
        'live_status'  => $row['live_status']
    ];
    $response_data['actions'] = json_decode($row['actions'], true) ?: [];
}

$info_stmt->close();
$conn->close();

echo json_encode($response_data, JSON_UNESCAPED_UNICODE);
exit();
?>
