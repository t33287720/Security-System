<?php
require_once __DIR__ . '/config/db_security.php';
header('Content-Type: application/json');

// ─── 嚴重程度分布 ────────────────────────────────────────────
$severity_counts = ['高' => 0, '中' => 0, '低' => 0, '資訊' => 0];
$res = $conn->query("SELECT severity, COUNT(*) AS cnt FROM vuln_findings GROUP BY severity");
$total = 0;
while ($row = $res->fetch_assoc()) {
    if (isset($severity_counts[$row['severity']])) {
        $severity_counts[$row['severity']] = (int)$row['cnt'];
    }
    $total += (int)$row['cnt'];
}

// ─── 待處理筆數 ─────────────────────────────────────────────
$res = $conn->query("SELECT COUNT(*) AS cnt FROM vuln_findings WHERE status = 'pending'");
$pending = (int)($res->fetch_assoc()['cnt'] ?? 0);

// ─── 受影響主機數（高/中風險） ──────────────────────────────
$res = $conn->query("SELECT COUNT(DISTINCT target) AS cnt FROM vuln_findings WHERE severity IN ('高', '中')");
$affected_targets = (int)($res->fetch_assoc()['cnt'] ?? 0);

// ─── 最後掃描時間 ───────────────────────────────────────────
$res = $conn->query("SELECT MAX(scanned_at) AS last_scan FROM vuln_findings");
$last_scan = $res->fetch_assoc()['last_scan'] ?? null;

echo json_encode([
    'total'            => $total,
    'severity'         => $severity_counts,
    'pending'          => $pending,
    'affected_targets' => $affected_targets,
    'last_scan'        => $last_scan,
], JSON_UNESCAPED_UNICODE);
?>
