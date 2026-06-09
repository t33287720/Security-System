<?php
// analyze_log.php
require_once __DIR__ . '/config/db_security.php';
header("Content-Type: application/json; charset=utf-8");

ini_set('display_errors', 1);
ini_set('log_errors', 1);
error_reporting(E_ALL);

/* =========================
   1. 接收參數
========================= */
$log       = trim($_POST['log']       ?? '');
$other_ip  = trim($_POST['other_ip']  ?? '');
$local_ip  = trim($_POST['local_ip']  ?? '');
$direction = trim($_POST['direction'] ?? '');

if (!$log) {
    echo json_encode(["error" => "沒有收到 log"]);
    exit;
}

/* =========================
   2. 連線資訊 JSON
========================= */
$role_info = [];
if ($other_ip)  $role_info['external_ip'] = $other_ip;
if ($local_ip)  $role_info['local_ip']    = $local_ip;
if ($direction) $role_info['direction']   = $direction;

$role_info_str = $role_info
    ? json_encode($role_info, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT)
    : '（手動輸入模式，未提供連線資訊）';

/* =========================
   3. 已知攻擊手法
========================= */
$known_attacks = [];
$result = $conn->query(
    "SELECT DISTINCT attack_type, attack_method FROM ai_log_analysis WHERE status='approved'"
);
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $known_attacks[] = "- {$row['attack_type']}: {$row['attack_method']}";
    }
}
$known_attack_str = empty($known_attacks) ? "無" : implode("\n", $known_attacks);

/* =========================
   4. 方向解讀（與 Python 端一致，僅在有方向資訊時附加）
========================= */
$direction_hint = '';
if ($direction === 'inbound') {
    $direction_hint = <<<EOT

【方向解讀】
- inbound：external_ip 主動向 local_ip 發起連線
  → 攻擊主體為 external_ip，分析其對本地的掃描、探測、暴力行為
EOT;
} elseif ($direction === 'outbound') {
    $direction_hint = <<<EOT

【方向解讀】
- outbound：local_ip 主動向 external_ip 發起連線
  → external_ip 為連線目標；若目標為已知服務（CDN、NTP、更新伺服器），視為正常；
    若本地大量外連多個不同目標，才考慮本地受害或被用作跳板
EOT;
} else {
    $direction_hint = <<<EOT

【方向解讀】
- 未提供連線方向，請根據 Log 內容自行判斷連線的主動方
EOT;
}

/* =========================
   5. Prompt（與 Python 端對齊）
========================= */
$prompt = <<<EOT
你是資安行為分析引擎，使用繁體中文輸出。

【連線資訊】
{$role_info_str}
{$direction_hint}

【Log 內容】
{$log}

【已知攻擊手法（語意參考）】
{$known_attack_str}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【danger_level 判斷規則】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

▌危險
以下任一行為模式即可判定，不需要 payload 或攻擊成功證據：

  (1) 多端口探測：對同一目標嘗試 3 個以上不同端口，且資料傳輸量為零或極少
  (2) 多目標掃描：短時間對多個不同目標 IP 發起連線（outbound 方向需排除已知合法服務）
  (3) 暴力嘗試：相同端口/服務大量重複連線，且多數連線失敗
  (4) 純探測心跳：固定週期發送且完全無資料交換（bytes_in = bytes_out = 0），持續多次，
      且無法以監控健康檢查、CDN 探活、路由守護程式合理解釋

  ★ 關鍵原則：
  「資料傳輸量為零 + 多端口或多次重複」本身就是攻擊行為，不需要 payload 才能判危險。
  不確定攻擊是否成功 ≠ 不確定是否在攻擊，兩者不同。
  但若行為模式與已知合法系統（監控、CDN、NTP）完全一致，不應套用上述規則。

▌可疑
同時符合以下所有條件才歸可疑（否則應判危險或正常）：

  - 日誌筆數少（5 筆以下），行為模式無法確認
  - 有部分資料交換，連線模式略為異常，但無明確攻擊特徵

  注意：以下情況不得歸可疑，應判危險：
  - 任何端口的高頻重複連線（如 SSH 22、RDP 3389、HTTP 80 的大量重複請求）
  - 同一 IP 對 3 個以上不同端口有連線記錄

▌正常
符合以下條件：

  - 無上述危險訊號
  - 行為有合理解釋（API 客戶端、CDN 節點、監控系統、NTP、更新服務、一般 HTTPS）
  - 目標單一、行為一致可預期
  - 允許 bytes=0 的情況，若連線模式符合監控心跳或 keepalive 特徵

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【confidence 校準】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

根據你對此次判斷的把握程度，自由給出 0.0–1.0，不受固定區間限制。

- 接近 1.0：證據充分、行為模式明確、結果高度確信
- 接近 0.5：有部分指標但不完整，存在合理疑義
- 接近 0.0：行為極度模糊，幾乎無法判斷

danger_level 與 confidence 彼此獨立，例如：
  「危險 0.72」→ 有攻擊跡象但日誌不完整
  「危險 0.95」→ 攻擊特徵非常明確
  「正常 0.90」→ 行為完全符合合法服務特徵
  「正常 0.55」→ 無異常但日誌過少難以確認

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【輸出 JSON，不附加其他文字】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{
  "analysis_basis": [],
  "overall_behavior": "",
  "danger_level": "正常 / 可疑 / 危險",
  "confidence": 0.0,
  "reason": "",
  "attack_type": "",
  "attack_method": ""
}

attack_type 規則（嚴格執行）：
- 只能是單一中文詞組，嚴禁使用「/」「、」「+」分隔多個類型
- 若有多種可能，只選最主要的一個
- 正確：「SSH暴力破解」 或 「端口掃描」
- 錯誤：「SSH暴力破解 / 端口掃描」
EOT;

/* =========================
   6. LLM call
========================= */
$data = [
    "model"   => "gemma3:27b",
    "prompt"  => $prompt,
    "stream"  => false,
    "options" => [
        "temperature" => 0.1,
        "max_tokens"  => 800
    ]
];

$ch = curl_init("http://127.0.0.1:8083/api/generate");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);

$response = curl_exec($ch);
curl_close($ch);

$result = json_decode($response, true);
$aiText = trim($result['response'] ?? '');
$aiText = preg_replace('/```json|```/', '', $aiText);
$analysis = json_decode($aiText, true);

if (!$analysis) {
    echo json_encode(["error" => "解析失敗", "raw" => $response]);
    exit;
}

/* =========================
   7. 補欄位、normalize、回傳
========================= */
$analysis = array_merge([
    "analysis_basis"   => [],
    "overall_behavior" => "",
    "danger_level"     => "正常",
    "confidence"       => 0.0,
    "reason"           => "",
    "attack_type"      => "",
    "attack_method"    => ""
], $analysis);

// normalize attack_type（去除複合類型）
if (!empty($analysis['attack_type'])) {
    $parts = preg_split('/[\/、+＋]/', $analysis['attack_type']);
    $analysis['attack_type'] = trim($parts[0]);
}

/* =========================
   8. 新攻擊類型 → 寫入待審核
========================= */
$new_attack_saved = false;
$attack_type = $analysis['attack_type'] ?? '';

if ($analysis['danger_level'] !== '正常' && !empty($attack_type)) {
    $check_sql  = "SELECT id FROM ai_log_analysis WHERE attack_type = ? AND status IN ('approved','pending') LIMIT 1";
    $check_stmt = $conn->prepare($check_sql);
    $check_stmt->bind_param('s', $attack_type);
    $check_stmt->execute();
    $check_stmt->store_result();

    if ($check_stmt->num_rows === 0) {
        $reason  = $analysis['reason']        ?? '';
        $method  = $analysis['attack_method'] ?? '';
        $ins_sql = "INSERT INTO ai_log_analysis (ip, attack_type, attack_method, reason, status) VALUES (?, ?, ?, ?, 'pending')";
        $ins_stmt = $conn->prepare($ins_sql);
        $ins_stmt->bind_param('ssss', $other_ip, $attack_type, $method, $reason);
        if ($ins_stmt->execute()) {
            $new_attack_saved = true;
        }
    }
    $check_stmt->close();
}

$response = ["data" => $analysis];
if ($new_attack_saved) {
    $response["type"] = "new_attack_saved";
}
echo json_encode($response);
