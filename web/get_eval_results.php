<?php
// get_eval_results.php — 回傳 eval_results 統計 + 最近紀錄
require_once __DIR__ . '/config/db_security.php';
header('Content-Type: application/json; charset=utf-8');

// ── 整體統計
$stats_sql = "
    SELECT
        COUNT(*)                                         AS total,
        SUM(true_label = 'attack')                       AS n_attack,
        SUM(true_label = 'benign')                       AS n_benign,
        SUM(true_label = 'attack' AND danger_level = '危險')  AS tp,
        SUM(true_label = 'attack' AND danger_level != '危險') AS fn,
        SUM(true_label = 'benign' AND danger_level = '危險')  AS fp,
        SUM(true_label = 'benign' AND danger_level != '危險') AS tn
    FROM eval_results
";
$stats_row = $conn->query($stats_sql)->fetch_assoc();

$tp = (int)$stats_row['tp'];
$fp = (int)$stats_row['fp'];
$fn = (int)$stats_row['fn'];
$tn = (int)$stats_row['tn'];

$precision = ($tp + $fp) > 0 ? round($tp / ($tp + $fp), 4) : null;
$recall    = ($tp + $fn) > 0 ? round($tp / ($tp + $fn), 4) : null;
$f1        = ($precision && $recall && ($precision + $recall) > 0)
             ? round(2 * $precision * $recall / ($precision + $recall), 4) : null;
$fpr         = ($fp + $tn) > 0 ? round($fp / ($fp + $tn), 4) : null;
$specificity = ($fp + $tn) > 0 ? round($tn / ($fp + $tn), 4) : null;

// MCC = (TP×TN − FP×FN) / √((TP+FP)(TP+FN)(TN+FP)(TN+FN))
$mcc_denom = sqrt(($tp+$fp) * ($tp+$fn) * ($tn+$fp) * ($tn+$fn));
$mcc       = $mcc_denom > 0 ? round(($tp*$tn - $fp*$fn) / $mcc_denom, 4) : null;

// ── 最近 100 筆紀錄
$records_sql = "
    SELECT ip, true_label, gt_source, danger_level, confidence, attack_type, analyzed_at
    FROM eval_results
    ORDER BY analyzed_at DESC
    LIMIT 100
";
$rows = [];
$result = $conn->query($records_sql);
while ($row = $result->fetch_assoc()) {
    // 判斷這筆是 TP / FP / FN / TN
    $is_attack_pred = ($row['danger_level'] === '危險');
    $is_attack_true = ($row['true_label']   === 'attack');
    $row['verdict'] = match(true) {
        $is_attack_true  && $is_attack_pred  => 'TP',
        !$is_attack_true && $is_attack_pred  => 'FP',
        $is_attack_true  && !$is_attack_pred => 'FN',
        default                              => 'TN',
    };
    $rows[] = $row;
}

// ── 讀取最新 JSON 報告（若已跑過 eval_metrics.py）
$report_path = __DIR__ . '/api/eval/output/metrics_report.json';
$report      = file_exists($report_path)
               ? json_decode(file_get_contents($report_path), true)
               : null;

// ── 讀取 tuning_config.json（自動調整參數 + 趨勢）
$tuning_path   = __DIR__ . '/api/eval/tuning_config.json';
$tuning_config = file_exists($tuning_path)
               ? json_decode(file_get_contents($tuning_path), true)
               : null;

// ── 讀取每日快照（daily_snapshots.csv）
$snapshot_path = __DIR__ . '/api/eval/output/daily_snapshots.csv';
$daily_rows    = [];
if (file_exists($snapshot_path)) {
    $handle = fopen($snapshot_path, 'r');
    $header = fgetcsv($handle);  // 讀標頭
    // 移除 UTF-8 BOM（EF BB BF）
    if ($header) $header[0] = ltrim($header[0], "\xEF\xBB\xBF");
    if ($header) {
        $seen = [];
        while (($row = fgetcsv($handle)) !== false) {
            $assoc = array_combine($header, $row);
            $date  = trim($assoc['date'] ?? '');
            if ($date && !isset($seen[$date])) {   // 每天只取第一筆
                $seen[$date] = true;
                $daily_rows[] = [
                    'date'      => $date,
                    'n_total'   => (int)($assoc['n_total']   ?? 0),
                    'n_attack'  => (int)($assoc['n_attack']  ?? 0),
                    'n_benign'  => (int)($assoc['n_benign']  ?? 0),
                    'precision' => isset($assoc['precision']) ? (float)$assoc['precision'] : null,
                    'recall'    => isset($assoc['recall'])    ? (float)$assoc['recall']    : null,
                    'f1'        => isset($assoc['f1'])        ? (float)$assoc['f1']        : null,
                    'fpr'       => isset($assoc['fpr'])       ? (float)$assoc['fpr']       : null,
                    'mcc'       => isset($assoc['mcc'])       ? (float)$assoc['mcc']       : null,
                    'TP'        => (int)($assoc['TP']         ?? 0),
                    'FP'        => (int)($assoc['FP']         ?? 0),
                    'FN'        => (int)($assoc['FN']         ?? 0),
                    'TN'        => (int)($assoc['TN']         ?? 0),
                ];
            }
        }
        fclose($handle);
        // 按日期降序排列（最新在前）
        usort($daily_rows, fn($a, $b) => strcmp($b['date'], $a['date']));
    }
}

echo json_encode([
    'success'   => true,
    'summary'   => [
        'total'     => (int)$stats_row['total'],
        'n_attack'  => (int)$stats_row['n_attack'],
        'n_benign'  => (int)$stats_row['n_benign'],
        'TP' => $tp, 'FP' => $fp, 'FN' => $fn, 'TN' => $tn,
        'precision' => $precision,
        'recall'    => $recall,
        'f1'        => $f1,
        'fpr'         => $fpr,
        'specificity' => $specificity,
        'mcc'         => $mcc,
    ],
    'records'      => $rows,
    'best_sweep'   => $report ? ($report['best_f1_danger_only'] ?? null) : null,
    'sweep'        => $report ? ($report['sweep'] ?? []) : [],
    'tuning'       => $tuning_config,
    'daily'        => $daily_rows,
], JSON_UNESCAPED_UNICODE);
