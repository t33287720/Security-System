<?php
require_once '../../config/db_security.php';
header('Content-Type: application/json');

$page      = isset($_GET['page'])      ? max(0, intval($_GET['page']))      : 0;
$page_size = isset($_GET['page_size']) ? max(1, intval($_GET['page_size'])) : 50;
$search    = trim($_GET['search'] ?? '');
$statuses  = isset($_GET['statuses'])     ? $_GET['statuses']     : [];
if (!is_array($statuses))     $statuses     = explode(',', $statuses);
$attack_types = isset($_GET['attack_types']) ? $_GET['attack_types'] : [];
if (!is_array($attack_types)) $attack_types = explode(',', $attack_types);
$time_filter  = isset($_GET['time_filter'])  ? $_GET['time_filter']  : [];
if (!is_array($time_filter))  $time_filter  = explode(',', $time_filter);

$offset = $page * $page_size;

// ─── WHERE for ip_risk_status_v2 ──────────────────────────────
$where_v2 = [];
$params_v2 = [];
$types_v2  = '';

if ($search !== '') {
    $where_v2[] = "(ip LIKE CONCAT('%', ?, '%') OR status LIKE CONCAT('%', ?, '%'))";
    $params_v2[] = $search;
    $params_v2[] = $search;
    $types_v2 .= 'ss';
}
if (count($statuses) > 0) {
    $ph = implode(',', array_fill(0, count($statuses), '?'));
    $where_v2[] = "status IN ($ph)";
    $params_v2 = array_merge($params_v2, $statuses);
    $types_v2 .= str_repeat('s', count($statuses));
}
if (!empty($attack_types) && !(count($attack_types) === 1 && $attack_types[0] === '')) {
    $ph = implode(',', array_fill(0, count($attack_types), '?'));
    $where_v2[] = "attack_type IN ($ph)";
    $params_v2 = array_merge($params_v2, $attack_types);
    $types_v2 .= str_repeat('s', count($attack_types));
}
if (in_array('current', $time_filter) && !in_array('past', $time_filter)) {
    $where_v2[] = "live_status != 0";
} elseif (!in_array('current', $time_filter) && in_array('past', $time_filter)) {
    $where_v2[] = "live_status = 0";
}
$where_sql_v2 = $where_v2 ? "WHERE " . implode(' AND ', $where_v2) : '';

// ─── WHERE for ip_risk_ranges（search + status + attack_types）─
$where_r  = [];
$params_r = [];
$types_r  = '';

if ($search !== '') {
    $where_r[] = "(ip_pattern LIKE CONCAT('%', ?, '%') OR status LIKE CONCAT('%', ?, '%'))";
    $params_r[] = $search;
    $params_r[] = $search;
    $types_r .= 'ss';
}
if (count($statuses) > 0) {
    $ph = implode(',', array_fill(0, count($statuses), '?'));
    $where_r[] = "status IN ($ph)";
    $params_r = array_merge($params_r, $statuses);
    $types_r .= str_repeat('s', count($statuses));
}
if (!empty($attack_types) && !(count($attack_types) === 1 && $attack_types[0] === '')) {
    $ph = implode(',', array_fill(0, count($attack_types), '?'));
    $where_r[] = "attack_type IN ($ph)";
    $params_r = array_merge($params_r, $attack_types);
    $types_r .= str_repeat('s', count($attack_types));
}
if (in_array('current', $time_filter) && !in_array('past', $time_filter)) {
    $where_r[] = "live_status != 0";
} elseif (!in_array('current', $time_filter) && in_array('past', $time_filter)) {
    $where_r[] = "live_status = 0";
}
$where_sql_r = $where_r ? "WHERE " . implode(' AND ', $where_r) : '';

// ─── 分開計算總筆數 ───────────────────────────────────────────
$stmt = $conn->prepare("SELECT COUNT(*) FROM ip_risk_status_v2 $where_sql_v2");
if (!$stmt) { echo json_encode(['total'=>0,'data'=>[],'error'=>$conn->error]); exit; }
if ($params_v2) $stmt->bind_param($types_v2, ...$params_v2);
$stmt->execute(); $stmt->bind_result($total_v2); $stmt->fetch(); $stmt->close();

$stmt = $conn->prepare("SELECT COUNT(*) FROM ip_risk_ranges $where_sql_r");
if (!$stmt) { echo json_encode(['total'=>0,'data'=>[],'error'=>$conn->error]); exit; }
if ($params_r) $stmt->bind_param($types_r, ...$params_r);
$stmt->execute(); $stmt->bind_result($total_r); $stmt->fetch(); $stmt->close();

$total = $total_v2 + $total_r;

// ─── UNION ALL + 統一排序分頁 ─────────────────────────────────
$data_sql = "
    SELECT ip, hostname, status, last_time, actions, live_status, attack_type
    FROM ip_risk_status_v2
    $where_sql_v2
    UNION ALL
    SELECT
        ip_pattern        AS ip,
        ''                AS hostname,
        status,
        `time`            AS last_time,
        ''                AS actions,
        live_status,
        COALESCE(attack_type, '') AS attack_type
    FROM ip_risk_ranges
    $where_sql_r
    ORDER BY last_time DESC
    LIMIT ? OFFSET ?
";

$bind_params = array_merge($params_v2, $params_r, [$page_size, $offset]);
$bind_types  = $types_v2 . $types_r . 'ii';

$stmt = $conn->prepare($data_sql);
if (!$stmt) { echo json_encode(['total'=>0,'data'=>[],'error'=>$conn->error]); exit; }
$stmt->bind_param($bind_types, ...$bind_params);
$stmt->execute();
$res  = $stmt->get_result();
$data = [];
while ($row = $res->fetch_assoc()) {
    $data[] = $row;
}
$stmt->close();

echo json_encode(['total' => $total, 'data' => $data], JSON_UNESCAPED_UNICODE);
?>
