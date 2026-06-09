<?php
# get_ELK_detail.php
header('Content-Type: application/json');
require_once __DIR__ . '/../../config/db_security.php';

// 獲取參數
$page = max(0, intval($_GET['page'] ?? 0));
$size = 10;
$from = $page * $size;

$start_input = $_GET['start_datetime'] ?? '';
$end_input = $_GET['end_datetime'] ?? '';

$has_time_range = !empty(trim($start_input)) && !empty(trim($end_input));

// $query = [
//     "from" => $from,
//     "size" => $size,
//     "sort" => [ ["@timestamp" => ["order" => "desc"]] ],
//     "query" => [
//         "bool" => [
//             "filter" => [
//                 ["exists" => ["field" => "client_ip"]]
//             ],
//             "must_not" => [
//                 ["term" => ["client_ip.keyword" => ""]],
//                 ["term" => ["client_ip.keyword" => "-"]]
//             ]
//         ]
//     ]
// ];

$query = [
    "from" => $from,
    "size" => $size,
    "sort" => [["@timestamp" => ["order" => "desc"]]],
    "query" => [
        "bool" => [
            "should" => [
                ["exists" => ["field" => "client_ip"]],
                ["exists" => ["field" => "src_ip"]],
                ["exists" => ["field" => "dst_ip"]],
            ],
            "minimum_should_match" => 1,

            "must_not" => [
                ["term" => ["client_ip.keyword" => ""]],
                ["term" => ["client_ip.keyword" => "-"]],
                ["term" => ["src_ip.keyword" => ""]],
                ["term" => ["src_ip.keyword" => "-"]],
                ["term" => ["dst_ip.keyword" => ""]],
                ["term" => ["dst_ip.keyword" => "-"]]
            ]
        ]
    ]
];


if ($has_time_range) {
    // 轉換格式：2025/11/10 11:51 → 2025-11-10T11:51:00+08:00
    $start = str_replace(['/', ' '], ['-', 'T'], trim($start_input)) . ':00+08:00';
    $end = str_replace(['/', ' '], ['-', 'T'], trim($end_input)) . ':59+08:00';

    if (
        preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+08:00$/', $start) &&
        preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+08:00$/', $end)
    ) {

        $query['query']['bool']['filter'][] = [
            "range" => [
                "@timestamp" => [
                    "gte" => $start,
                    "lte" => $end,
                    "time_zone" => "+08:00"
                ]
            ]
        ];
    }
}

// Docker: read from env vars; Host: fall back to legacy config file
$es_host = getenv('ES_HOST') ?: "https://localhost:9200";
$es_user = getenv('ES_USER') ?: "elastic";
$es_pass = getenv('ES_PASS') ?: '';
if ($es_pass === '') {
    $_cfg_path = '/var/www/config/security_config.json';
    if (file_exists($_cfg_path)) {
        $_cfg = json_decode(file_get_contents($_cfg_path), true);
        $es_pass = $_cfg['es_pass'] ?? $_cfg['ES_PASS'] ?? '';
    }
}
$index = "filebeat-*";

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "$es_host/$index/_search",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_USERPWD => "$es_user:$es_pass",
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => json_encode($query),
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false
]);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curl_err = curl_error($ch);
curl_close($ch);

if ($curl_err || $http_code !== 200) {
    error_log("ES Error: $curl_err | HTTP: $http_code | Query: " . json_encode($query, JSON_UNESCAPED_UNICODE));
    echo json_encode(['success' => false, 'message' => 'Elasticsearch 查詢失敗']);
    exit;
}

$data = json_decode($response, true);

echo json_encode([
    'success' => true,
    'hits' => $data['hits']['hits'] ?? [],
    'total' => $data['hits']['total']['value'] ?? 0
]);