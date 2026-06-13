<?php
require_once __DIR__ . '/config/db_security.php';
header('Content-Type: application/json');

$page      = isset($_GET['page'])      ? max(0, intval($_GET['page']))      : 0;
$page_size = isset($_GET['page_size']) ? max(1, intval($_GET['page_size'])) : 50;
$search    = trim($_GET['search'] ?? '');
$statuses  = isset($_GET['statuses'])  ? $_GET['statuses']  : [];
if (!is_array($statuses))  $statuses  = explode(',', $statuses);
$severities = isset($_GET['severities']) ? $_GET['severities'] : [];
if (!is_array($severities)) $severities = explode(',', $severities);

$offset = $page * $page_size;

$where  = [];
$params = [];
$types  = '';

if ($search !== '') {
    $where[] = "(file_path LIKE CONCAT('%', ?, '%') OR rule_id LIKE CONCAT('%', ?, '%') OR title LIKE CONCAT('%', ?, '%'))";
    $params[] = $search;
    $params[] = $search;
    $params[] = $search;
    $types .= 'sss';
}
if (count($statuses) > 0 && !(count($statuses) === 1 && $statuses[0] === '')) {
    $ph = implode(',', array_fill(0, count($statuses), '?'));
    $where[] = "status IN ($ph)";
    $params = array_merge($params, $statuses);
    $types .= str_repeat('s', count($statuses));
}
if (count($severities) > 0 && !(count($severities) === 1 && $severities[0] === '')) {
    $ph = implode(',', array_fill(0, count($severities), '?'));
    $where[] = "severity IN ($ph)";
    $params = array_merge($params, $severities);
    $types .= str_repeat('s', count($severities));
}

$where_sql = $where ? "WHERE " . implode(' AND ', $where) : '';

// ─── 總筆數 ────────────────────────────────────────────────────
$stmt = $conn->prepare("SELECT COUNT(*) FROM code_findings $where_sql");
if (!$stmt) { echo json_encode(['total' => 0, 'data' => [], 'error' => $conn->error]); exit; }
if ($params) $stmt->bind_param($types, ...$params);
$stmt->execute();
$stmt->bind_result($total);
$stmt->fetch();
$stmt->close();

// ─── 分頁資料 ──────────────────────────────────────────────────
$data_sql = "
    SELECT id, file_path, line_start, line_end, source, rule_id, title,
           severity, confidence, evidence, remediation, status, scanned_at
    FROM code_findings
    $where_sql
    ORDER BY scanned_at DESC
    LIMIT ? OFFSET ?
";

$bind_params = array_merge($params, [$page_size, $offset]);
$bind_types  = $types . 'ii';

$stmt = $conn->prepare($data_sql);
if (!$stmt) { echo json_encode(['total' => 0, 'data' => [], 'error' => $conn->error]); exit; }
$stmt->bind_param($bind_types, ...$bind_params);
$stmt->execute();
$res = $stmt->get_result();

$data = [];
while ($row = $res->fetch_assoc()) {
    $data[] = $row;
}
$stmt->close();

echo json_encode(['total' => $total, 'data' => $data], JSON_UNESCAPED_UNICODE);
?>
