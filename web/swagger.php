<?php
/**
 * Swagger UI（需登入）。
 * 未登入會被 config/auth.php 導向 login.php。
 */
require_once __DIR__ . '/config/auth.php';

// 顯示時間以台灣時區為準（UTC+8）
date_default_timezone_set('Asia/Taipei');

// 規格版本號（取 openapi.php 修改時間），用於 cache-busting 與顯示更新時間
$specMtime = @filemtime(__DIR__ . '/openapi.php') ?: time();
?>
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate" />
    <title>GAI 伺服器安全防護系統 — API 文件</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    <style>
        body { margin: 0; background: #fafafa; }
        .doc-header {
            background: #1a1a2e; color: #fff;
            padding: 18px 28px;
            font-family: system-ui, "Noto Sans TC", sans-serif;
        }
        .doc-header h1 { margin: 0; font-size: 20px; font-weight: 600; letter-spacing: 0.5px; }
        .doc-header p  { margin: 4px 0 0; font-size: 13px; color: rgba(255,255,255,0.6); }
        /* 最上層工具列：返回 / 登入帳號（截圖時可避開） */
        .doc-utilbar {
            display: flex; justify-content: space-between; align-items: center;
            background: #0f0f1a; color: #c9c9d4;
            padding: 6px 28px; font-family: system-ui, "Noto Sans TC", sans-serif; font-size: 13px;
        }
        .doc-utilbar a { color: #7db3ff; text-decoration: none; }
        .doc-utilbar a:hover { text-decoration: underline; }
        /* 截圖用：隱藏 Swagger 預設頂端搜尋列，畫面更乾淨 */
        .swagger-ui .topbar { display: none; }
    </style>
</head>
<body>
    <div class="doc-utilbar">
        <a href="index.php">← 返回儀表板</a>
        <span>登入帳號：<?php echo htmlspecialchars($_SESSION['username'] ?? '', ENT_QUOTES); ?></span>
    </div>
    <header class="doc-header">
        <h1>GAI 伺服器安全防護系統　API 文件</h1>
        <p>Security Monitoring Platform — REST API Reference　·　最後更新：<?php echo date('Y-m-d H:i', $specMtime); ?></p>
    </header>
    <div id="swagger-ui"></div>

    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function () {
            window.ui = SwaggerUIBundle({
                url: 'openapi.php?v=<?php echo $specMtime; ?>',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                layout: 'StandaloneLayout',
                // 帶上 session cookie，"Try it out" 才不會被 auth 擋下
                requestInterceptor: function (req) {
                    req.credentials = 'same-origin';
                    return req;
                }
            });
        };
    </script>
</body>
</html>
