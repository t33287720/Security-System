<?php
header('Content-Type: application/json');
require_once __DIR__ . '/../../config/db_security.php'; // 確保資料庫連線正確

$ipRiskList = [];

// 結合兩個資料表，同時計算 live_status 次數 (這是原本的 $sql_all)
$sql_all = "
    SELECT
        t1.ip,
        t1.status,
        t1.last_time,
        t1.hostname,
        COALESCE(t2.login_count, 0) AS login_count
    FROM
        ip_risk_status AS t1
    LEFT JOIN (
        SELECT ip, COUNT(*) AS login_count FROM ip_risk_status WHERE live_status = 0 GROUP BY ip
    ) AS t2 ON t1.ip = t2.ip
    UNION ALL
    SELECT
        ip_pattern AS ip,
        status,
        time AS last_time,
        '' AS hostname,
        NULL AS login_count
    FROM
        ip_risk_ranges
    ORDER BY last_time DESC;
";

$result_all = $conn->query($sql_all);

if ($result_all !== false) {
    while ($row = $result_all->fetch_assoc()) {
        // 確保將數字類型正確轉換，避免 JSON 輸出問題
        $row['login_count'] = $row['login_count'] !== null ? intval($row['login_count']) : 0;
        $ipRiskList[] = $row;
    }
    // 輸出成功狀態和數據
    echo json_encode([
        'status' => 'success',
        'data' => $ipRiskList
    ]);
} else {
    // 查詢失敗時輸出錯誤
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => '資料庫查詢失敗: ' . $conn->error
    ]);
    error_log("API 資料庫查詢失敗: " . $conn->error);
}

// 關閉連線
$conn->close();
?>