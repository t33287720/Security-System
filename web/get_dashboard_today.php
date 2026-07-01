<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
require_once __DIR__ . '/config/db_security.php';
date_default_timezone_set('Asia/Taipei');

$today          = date('Y-m-d');
$start_of_today = $today . ' 00:00:00';
$end_of_today   = $today . ' 23:59:59';

// ── 今日封鎖 IP 清單 ───────────────────────────────────────────
$sql = "
SELECT ip, hostname, status, last_time, attack_type, first_time
FROM ip_risk_status_v2
WHERE last_time >= ? AND last_time <= ?
AND status IN ('黑名單','LLM黑名單')
ORDER BY last_time DESC
";
$stmt = $conn->prepare($sql);
$stmt->bind_param("ss", $start_of_today, $end_of_today);
$stmt->execute();
$result = $stmt->get_result();

$ipTodayList = [];
while ($row = $result->fetch_assoc()) {
    $ipTodayList[] = $row;
}
$stmt->close();

// 去重（取 last_time 最新的那筆），同時記錄出現次數
$ipUniqueList = [];
$ipCounts     = [];
foreach ($ipTodayList as $row) {
    $ip = $row['ip'];
    $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;
    if (!isset($ipUniqueList[$ip]) || strtotime($row['last_time']) > strtotime($ipUniqueList[$ip]['last_time'])) {
        $ipUniqueList[$ip] = $row;
    }
}

// ── 統計指標 ───────────────────────────────────────────────────
// status 有兩種黑名單，對應 worker/tools/security/policy.py 的分流邏輯：
//   '黑名單'    → 命中公開威脅情報黑名單的已知惡意 IP（openblacklist_matcher），或人工手動加入
//                 （blackfulllistv4，全 port 硬封鎖 24 小時）
//   'LLM黑名單' → AI 研判「危險」一律進此類（不論信心度高低都不會進硬封鎖黑名單）
//                 （blacklistv4 軟封鎖，80/443 網站流量仍放行；
//                  信心度僅影響解封時間：>0.8 為 24 小時，否則 5 分鐘）
$totalBlocked       = count($ipUniqueList);
$publicBlacklisted  = 0;   // 公開黑名單命中（attack_type = 已知惡意IP）
$llmBlocked         = 0;   // LLM 黑名單封鎖（AI 研判危險）
$repeatedIPs        = 0;
$attackTypeToday    = [];

foreach ($ipUniqueList as $ip => $row) {
    $attackType = trim($row['attack_type'] ?? '');
    if ($attackType === '已知惡意IP') {
        $publicBlacklisted++;
    } elseif ($row['status'] === 'LLM黑名單') {
        $llmBlocked++;
    }
    if (($ipCounts[$ip] ?? 1) > 1) {
        $repeatedIPs++;
    }
    $type = $attackType ?: '未知';
    $attackTypeToday[$type] = ($attackTypeToday[$type] ?? 0) + 1;
}

// 攻擊手法排序（多 → 少）
arsort($attackTypeToday);

// ── 網段分析（/24）────────────────────────────────────────────
$subnets = [];
foreach ($ipUniqueList as $ip => $row) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) continue;
    $parts  = explode('.', $ip);
    $subnet = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';

    if (!isset($subnets[$subnet])) {
        $subnets[$subnet] = ['count' => 0, 'ips' => [], 'types' => [], 'hosts' => [], 'cidr' => '/24'];
    }
    $subnets[$subnet]['count']++;
    $subnets[$subnet]['ips'][] = $ip;
    if (!empty($row['attack_type'])) {
        $subnets[$subnet]['types'][] = $row['attack_type'];
    }
    if (!empty($row['hostname']) && !in_array($row['hostname'], $subnets[$subnet]['hosts'])) {
        $subnets[$subnet]['hosts'][] = $row['hostname'];
    }
}

$suspiciousSubnets = [];
foreach ($subnets as $subnet => $data) {
    if ($data['count'] < 10) continue;
    $data['types'] = array_values(array_unique($data['types']));
    $suspiciousSubnets[$subnet] = $data;
}

// 按 count 排序
uasort($suspiciousSubnets, fn($a, $b) => $b['count'] - $a['count']);

// ── 主機封鎖統計 ───────────────────────────────────────────────
$hostBlockedCounts = [];
foreach ($ipUniqueList as $item) {
    $hostname = trim($item['hostname'] ?? '') ?: '未知主機';
    $hostBlockedCounts[$hostname] = ($hostBlockedCounts[$hostname] ?? 0) + 1;
}

echo json_encode([
    'totalBlocked'         => $totalBlocked,
    'publicBlacklisted'    => $publicBlacklisted,
    'llmBlocked'           => $llmBlocked,
    'repeatedIPs'          => $repeatedIPs,
    'suspiciousSubnetCount'=> count($suspiciousSubnets),
    'suspiciousSubnets'    => $suspiciousSubnets,
    'attackTypeToday'      => $attackTypeToday,
    'ipCounts'             => $ipCounts,
    'hostBlockedCounts'    => $hostBlockedCounts,
    'ipUniqueList'         => $ipUniqueList,
], JSON_UNESCAPED_UNICODE);
