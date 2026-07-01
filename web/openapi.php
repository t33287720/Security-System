<?php
/**
 * OpenAPI 3.0 規格輸出（需登入）
 * 由 swagger.php 載入。未登入會被 auth.php 導向 login.php。
 */
require_once __DIR__ . '/config/auth.php';

// 顯示時間以台灣時區為準（UTC+8）
date_default_timezone_set('Asia/Taipei');

header('Content-Type: application/json; charset=utf-8');
// 避免瀏覽器快取舊規格，使用者免按 Ctrl+F5
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// 動態推算 API base path（例如 /web 或 /），讓 "Try it out" 能打到正確位置
$base = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'])), '/');
if ($base === '') {
    $base = '/';
}

// ── 共用元件 ───────────────────────────────────────────────
$pagination = [
    ['name' => 'page',      'in' => 'query', 'schema' => ['type' => 'integer', 'default' => 0], 'description' => '頁碼（從 0 起算）'],
    ['name' => 'page_size', 'in' => 'query', 'schema' => ['type' => 'integer', 'default' => 50], 'description' => '每頁筆數'],
    ['name' => 'search',    'in' => 'query', 'schema' => ['type' => 'string'], 'description' => '關鍵字搜尋'],
];

// form 參數產生器：把欄位陣列轉成 application/x-www-form-urlencoded requestBody
function form_body(array $required, array $optional = [], array $descs = []) {
    $props = [];
    foreach (array_merge($required, $optional) as $name) {
        $props[$name] = ['type' => 'string', 'description' => $descs[$name] ?? ''];
    }
    return [
        'required' => true,
        'content'  => [
            'application/x-www-form-urlencoded' => [
                'schema' => [
                    'type'       => 'object',
                    'required'   => $required,
                    'properties' => $props,
                ],
            ],
        ],
    ];
}

$ok = ['200' => ['description' => '成功，回傳 JSON']];

$spec = [
    'openapi' => '3.0.3',
    'info' => [
        'title'       => 'GAI 伺服器安全防護系統 API',
        // 以本檔的修改時間自動產生版本號，每次更新規格版本即遞增
        'version'     => '1.0.' . @filemtime(__FILE__),
        'description' => "本系統 web 層 REST 端點文件。所有端點皆需登入後始可存取。\n\n"
            . "讀取類為 GET，異動類為 POST（form-urlencoded）。\n\n"
            . "**最後更新：" . date('Y-m-d H:i', @filemtime(__FILE__) ?: time()) . "**",
    ],
    'servers' => [['url' => $base, 'description' => '目前站台']],
    'tags' => [
        ['name' => '儀表板'],
        ['name' => 'IP / 防護'],
        ['name' => '攻擊事件'],
        ['name' => 'Log 分析'],
        ['name' => '弱點掃描'],
        ['name' => '原始碼掃描'],
        ['name' => '掃描報告 / Eval'],
    ],
    'paths' => [

        // ── 儀表板 ──
        '/get_dashboard_data.php'  => ['get' => ['tags' => ['儀表板'], 'summary' => '儀表板總覽資料', 'responses' => $ok]],
        '/get_dashboard_today.php' => ['get' => ['tags' => ['儀表板'], 'summary' => '今日封鎖統計', 'responses' => $ok]],

        // ── IP / 防護 ──
        '/get_ip.php' => ['get' => [
            'tags' => ['IP / 防護'], 'summary' => 'IP 風險狀態清單（分頁/篩選）',
            'parameters' => array_merge($pagination, [
                ['name' => 'statuses',     'in' => 'query', 'schema' => ['type' => 'string'], 'description' => '狀態，逗號分隔'],
                ['name' => 'attack_types', 'in' => 'query', 'schema' => ['type' => 'string'], 'description' => '攻擊類型，逗號分隔'],
                ['name' => 'time_filter',  'in' => 'query', 'schema' => ['type' => 'string'], 'description' => 'current / past，逗號分隔'],
            ]),
            'responses' => $ok,
        ]],
        '/api_get_ip_risk.php' => ['get' => ['tags' => ['IP / 防護'], 'summary' => '全部 IP 風險清單（含 ip_risk_ranges）', 'responses' => $ok]],
        '/get_ip_detail.php' => ['post' => [
            'tags' => ['IP / 防護'], 'summary' => '單一 IP 詳細資訊',
            'requestBody' => form_body(['ip'], [], ['ip' => '查詢的 IP']), 'responses' => $ok,
        ]],
        '/get_ELK_detail.php' => ['get' => [
            'tags' => ['IP / 防護'], 'summary' => '防護日誌明細（時間區間/分頁）',
            'parameters' => [
                ['name' => 'start_datetime', 'in' => 'query', 'schema' => ['type' => 'string'], 'description' => '起始時間'],
                ['name' => 'end_datetime',   'in' => 'query', 'schema' => ['type' => 'string'], 'description' => '結束時間'],
                ['name' => 'page',           'in' => 'query', 'schema' => ['type' => 'integer', 'default' => 0]],
            ],
            'responses' => $ok,
        ]],
        '/database_update.php' => ['post' => [
            'tags' => ['IP / 防護'], 'summary' => '更新 IP 封鎖/狀態',
            'requestBody' => form_body(['ip', 'status'], ['attack_type', 'type', 'unblock_hours'], [
                'ip' => '目標 IP', 'status' => '新狀態', 'type' => '操作類型', 'unblock_hours' => '解除封鎖時數',
            ]),
            'responses' => $ok,
        ]],
        '/ELK_delete.php' => ['post' => [
            'tags' => ['IP / 防護'], 'summary' => '刪除指定 IP 的日誌',
            'requestBody' => form_body(['ip'], [], ['ip' => '要刪除日誌的 IP']), 'responses' => $ok,
        ]],

        // ── 攻擊事件 ──
        '/get_all_attacks.php' => ['get' => [
            'tags' => ['攻擊事件'], 'summary' => '攻擊事件清單',
            'parameters' => [['name' => 'statuses', 'in' => 'query', 'schema' => ['type' => 'string'], 'description' => '狀態，逗號分隔']],
            'responses' => $ok,
        ]],
        '/get_known_attacks.php'   => ['get' => ['tags' => ['攻擊事件'], 'summary' => '已知攻擊類型清單', 'responses' => $ok]],
        '/get_pending_attacks.php' => ['get' => ['tags' => ['攻擊事件'], 'summary' => '待審核攻擊清單', 'responses' => $ok]],
        '/approve_attack.php' => ['post' => [
            'tags' => ['攻擊事件'], 'summary' => '審核（核准/拒絕）攻擊',
            'requestBody' => form_body(['attack_id', 'action'], [], ['attack_id' => '攻擊事件 ID', 'action' => 'approve / reject']),
            'responses' => $ok,
        ]],
        '/save_attack.php' => ['post' => [
            'tags' => ['攻擊事件'], 'summary' => '新增/儲存攻擊判定',
            'requestBody' => form_body(['attack_type', 'risk_level', 'is_malicious'], ['attack_method', 'log', 'reason'], [
                'attack_type' => '攻擊類型', 'risk_level' => '風險等級', 'is_malicious' => '是否惡意',
                'attack_method' => '攻擊手法', 'log' => '原始 log', 'reason' => '判定理由',
            ]),
            'responses' => $ok,
        ]],
        '/behavior_update.php' => ['post' => [
            'tags' => ['攻擊事件'], 'summary' => '行為關鍵字維護（新增/修改/刪除）',
            'requestBody' => form_body(['action'], ['behavior_keyword', 'old_behavior_keyword', 'description', 'status'], [
                'action' => 'add / update / delete', 'behavior_keyword' => '行為關鍵字',
                'old_behavior_keyword' => '原關鍵字（更新時）', 'description' => '說明', 'status' => '狀態',
            ]),
            'responses' => $ok,
        ]],

        // ── 弱點掃描 ──
        '/get_vuln_findings.php' => ['get' => [
            'tags' => ['弱點掃描'], 'summary' => '弱點掃描結果清單',
            'parameters' => array_merge($pagination, [
                ['name' => 'severities', 'in' => 'query', 'schema' => ['type' => 'string'], 'description' => '嚴重度，逗號分隔'],
                ['name' => 'statuses',   'in' => 'query', 'schema' => ['type' => 'string'], 'description' => '狀態，逗號分隔'],
            ]),
            'responses' => $ok,
        ]],
        '/get_vuln_summary.php' => ['get' => ['tags' => ['弱點掃描'], 'summary' => '弱點掃描統計摘要', 'responses' => $ok]],
        '/update_vuln_status.php' => ['post' => [
            'tags' => ['弱點掃描'], 'summary' => '更新弱點處理狀態',
            'requestBody' => form_body(['id', 'status'], [], ['id' => '弱點紀錄 ID', 'status' => '新狀態']),
            'responses' => $ok,
        ]],

        // ── 原始碼掃描 ──
        '/get_code_findings.php' => ['get' => [
            'tags' => ['原始碼掃描'], 'summary' => '原始碼掃描結果清單',
            'parameters' => array_merge($pagination, [
                ['name' => 'severities', 'in' => 'query', 'schema' => ['type' => 'string'], 'description' => '嚴重度，逗號分隔'],
                ['name' => 'statuses',   'in' => 'query', 'schema' => ['type' => 'string'], 'description' => '狀態，逗號分隔'],
            ]),
            'responses' => $ok,
        ]],
        '/get_code_summary.php' => ['get' => ['tags' => ['原始碼掃描'], 'summary' => '原始碼掃描統計摘要', 'responses' => $ok]],
        '/update_code_status.php' => ['post' => [
            'tags' => ['原始碼掃描'], 'summary' => '更新原始碼弱點處理狀態',
            'requestBody' => form_body(['id', 'status'], [], ['id' => '紀錄 ID', 'status' => '新狀態']),
            'responses' => $ok,
        ]],

        // ── 掃描報告 / Eval ──
        '/get_scan_report.php'  => ['get' => ['tags' => ['掃描報告 / Eval'], 'summary' => '掃描報告', 'responses' => $ok]],
        '/get_eval_results.php' => ['get' => ['tags' => ['掃描報告 / Eval'], 'summary' => 'Eval 評測結果', 'responses' => $ok]],
        '/get_eval_chart.php'   => ['get' => [
            'tags' => ['掃描報告 / Eval'], 'summary' => 'Eval 圖表資料',
            'parameters' => [['name' => 'name', 'in' => 'query', 'schema' => ['type' => 'string'], 'description' => '圖表名稱']],
            'responses' => $ok,
        ]],
    ],
];

echo json_encode($spec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
