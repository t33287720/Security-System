<?php
require_once __DIR__ . '/config/db_security.php';
header('Content-Type: application/json');

$res = $conn->query("
    SELECT generated_at, summary, highlights, stats
    FROM scan_reports
    ORDER BY id DESC
    LIMIT 1
");
$row = $res ? $res->fetch_assoc() : null;

if (!$row) {
    echo json_encode(['exists' => false], JSON_UNESCAPED_UNICODE);
    exit;
}

$stats = json_decode($row['stats'] ?? '{}', true) ?: [];

// 嚴重程度分布與未結案總數：即時查詢 vuln_findings + code_findings，
// 不使用報告產生當下的快照，避免資料去重/狀態變更後數字與資料庫不一致
$severity_counts = ['高' => 0, '中' => 0, '低' => 0, '資訊' => 0];
$total = 0;
$res = $conn->query("
    SELECT severity, COUNT(*) AS cnt FROM (
        SELECT severity FROM vuln_findings WHERE status NOT IN ('resolved', 'false_positive')
        UNION ALL
        SELECT severity FROM code_findings WHERE status NOT IN ('resolved', 'false_positive')
    ) t
    GROUP BY severity
");
while ($r = $res->fetch_assoc()) {
    if (isset($severity_counts[$r['severity']])) {
        $severity_counts[$r['severity']] = (int)$r['cnt'];
    }
    $total += (int)$r['cnt'];
}

// 重點清單：同樣即時查詢，依嚴重程度、信心度排序
$top_findings = [];
$res = $conn->query("
    (SELECT 'vuln' AS type, CONCAT(target, ':', port) AS location, title, severity, confidence
       FROM vuln_findings WHERE status NOT IN ('resolved', 'false_positive'))
    UNION ALL
    (SELECT 'code' AS type, CONCAT(file_path, ':', line_start) AS location, title, severity, confidence
       FROM code_findings WHERE status NOT IN ('resolved', 'false_positive'))
    ORDER BY
        CASE severity WHEN '高' THEN 3 WHEN '中' THEN 2 WHEN '低' THEN 1 ELSE 0 END DESC,
        confidence DESC
    LIMIT 10
");
while ($r = $res->fetch_assoc()) {
    $top_findings[] = $r;
}

echo json_encode([
    'exists'        => true,
    'generated_at'  => $row['generated_at'],
    'summary'       => $row['summary'],
    'highlights'    => json_decode($row['highlights'] ?? '[]', true) ?: [],
    'total'         => $total,
    'severity'      => $severity_counts,
    'new_count'     => $stats['new_count'] ?? 0,
    'resolved_count'=> $stats['resolved_count'] ?? 0,
    'previous_total'=> $stats['previous_total'] ?? 0,
    'top_findings'  => $top_findings,
], JSON_UNESCAPED_UNICODE);
?>
