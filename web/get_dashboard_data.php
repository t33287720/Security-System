<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
require_once __DIR__ . '/config/db_security.php';

date_default_timezone_set('Asia/Taipei');

// ===== 今日封鎖 =====
$today = date('Y-m-d');
$start_today = $today . ' 00:00:00';
$end_today = $today . ' 23:59:59';

$sql_today = "
SELECT ip, status, last_time, hostname, attack_type
FROM ip_risk_status_v2
WHERE last_time BETWEEN ? AND ?
AND status IN ('黑名單','LLM黑名單')
ORDER BY last_time DESC
";

$stmt = $conn->prepare($sql_today);
$stmt->bind_param("ss", $start_today, $end_today);
$stmt->execute();
$result = $stmt->get_result();

$todayList = [];
while ($row = $result->fetch_assoc()) {
    $todayList[] = $row;
}
$stmt->close();


// ===== 攻擊趨勢（7天）=====
$seven_days_ago = date('Y-m-d', strtotime('-6 days'));
$start_time = $seven_days_ago . ' 00:00:00';
$end_time = $today . ' 23:59:59';

$sql_trend = "
SELECT last_time, attack_type
FROM ip_risk_status_v2
WHERE last_time BETWEEN ? AND ?
AND status IN ('黑名單','LLM黑名單')
";

$stmt = $conn->prepare($sql_trend);
$stmt->bind_param("ss", $start_time, $end_time);
$stmt->execute();
$result = $stmt->get_result();

$trendRaw = [];
while ($row = $result->fetch_assoc()) {
    $trendRaw[] = $row;
}
$stmt->close();

// 整理成 Highcharts 格式
$attackTrend = [];
for ($i = 0; $i < 7; $i++) {
    $date = date('Y-m-d', strtotime($seven_days_ago . " +$i days"));
    $attackTrend[$date] = [];
}

foreach ($trendRaw as $row) {
    $date = date('Y-m-d', strtotime($row['last_time']));
    $type = $row['attack_type'] ?: '未知';

    if (!isset($attackTrend[$date][$type])) {
        $attackTrend[$date][$type] = 0;
    }
    $attackTrend[$date][$type]++;
}

echo json_encode([
    "today" => $todayList,
    "trend" => $attackTrend
]);