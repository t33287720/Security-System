<?php require_once 'config/auth.php'; ?>

<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
date_default_timezone_set('Asia/Taipei');
require_once __DIR__ . '/config/db_security.php';
?>

<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GAI 伺服器安全防護系統</title>
    <link href="assets/css/package/bootstrap.min.css" rel="stylesheet" />
    <link href="assets/css/package/dataTables.bootstrap5.min.css" rel="stylesheet" />
    <link rel="stylesheet" href="./assets/css/index.css?v=<?php echo @filemtime(__DIR__ . '/assets/css/index.css'); ?>">
</head>

<body>

    <!-- ===== System Header ===== -->
    <header class="sys-header">
        <div class="sys-title">
            <div class="sys-icon">GAI</div>
            GAI 伺服器安全防護系統
            <span style="font-size:0.7rem;font-weight:400;color:rgba(255,255,255,0.4);margin-left:6px;">Security Monitoring Platform</span>
        </div>
        <div class="sys-meta">
            <span id="headerClock">--:--:--</span>
            <span style="opacity:0.3">|</span>
            <span>Asia/Taipei</span>
        </div>
    </header>

    <!-- ===== Navigation ===== -->
    <nav class="sys-nav">
        <button id="showElk"       class="nav-tab active">防護日誌</button>
        <button id="showIpRisk"    class="nav-tab">IP 狀態管理</button>
        <button id="showIpToday"   class="nav-tab">今日封鎖</button>
        <button id="showAIAnalyze" class="nav-tab">Log 分析</button>
        <button id="showVulnScan"  class="nav-tab">弱點掃描</button>
        <button id="showCodeScan"  class="nav-tab">原始碼掃描</button>
        <button id="showScanReport" class="nav-tab">掃描報告</button>
        <a href="swagger.php" class="nav-tab" style="margin-left:auto;text-decoration:none;">API 文件</a>
    </nav>

    <!-- ===== Modals ===== -->
    <div class="modal fade" id="ipInputModal" tabindex="-1" aria-labelledby="ipInputModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered" style="max-width:420px;">
            <div class="modal-content">
                <form id="ipInputForm">
                    <div class="modal-header">
                        <h5 class="modal-title" id="ipInputModalLabel">手動新增 IP</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="inputIp" class="form-label" style="font-size:0.82rem;font-weight:500;">IP 位址</label>
                            <input type="text" class="form-control form-control-sm" id="inputIp" name="ip"
                                placeholder="例如 192.168.1.1 / 127.0.0.0/8 / 10.0.0.%" required>
                        </div>
                        <div class="mb-3">
                            <label for="inputAttackType" class="form-label" style="font-size:0.82rem;font-weight:500;">攻擊手法 / 白名單說明</label>
                            <input type="text" class="form-control form-control-sm" id="inputAttackType"
                                placeholder="例如：Port Scan / 公司內部設備">
                        </div>
                        <input type="hidden" id="inputStatus" name="status" value="">
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">取消</button>
                        <button type="submit" class="btn btn-primary btn-sm">確認送出</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <div class="modal fade" id="ipDetailModal" tabindex="-1" aria-labelledby="ipDetailModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="ipDetailModalLabel">IP 行為分析與原始日誌</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="關閉"></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6 border-end">
                            <h6 class="fw-bold text-center mb-3" style="font-size:0.82rem;color:#1a3050;">行為分析</h6>
                            <div id="behaviorAnalysis"></div>
                        </div>
                        <div class="col-md-6">
                            <div class="d-flex justify-content-center align-items-center mb-3" style="position:relative;">
                                <h6 class="fw-bold" style="font-size:0.82rem;color:#1a3050;margin:0;">原始 Log</h6>
                                <button type="button" id="btnRawLogDetail" class="btn btn-outline-secondary btn-sm" style="position:absolute;right:0;font-size:0.7rem;padding:1px 8px;">詳細</button>
                            </div>
                            <div id="rawLog"
                                style="white-space:pre-wrap;font-family:'Consolas','Fira Code',monospace;font-size:0.75rem;max-height:600px;overflow-y:auto;background:#f8fafc;color:#1c2a3a;padding:12px;border-radius:6px;border:1px solid #d0d7e3;line-height:1.6;"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="fullLogModal" tabindex="-1" aria-labelledby="fullLogModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="fullLogModalLabel">完整 Log 內容</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body" style="font-family:'Consolas',monospace;font-size:0.78rem;"></div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">關閉</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="confirmDeleteModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" style="color:#dc2626;font-size:0.88rem;">停用確認</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" style="font-size:0.82rem;">
                    <p id="confirmDeleteText">確定要停用此 IP 嗎？此操作將使該 IP 規則失效。</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-danger btn-sm" id="confirmDeleteBtn">確認停用</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="vulnDetailModal" tabindex="-1" aria-labelledby="vulnDetailModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="vulnDetailModalLabel">弱點詳細資訊</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body" style="font-size:0.85rem;">
                    <p class="mb-1"><strong>修補建議：</strong></p>
                    <p id="vulnDetailRemediation" style="white-space:pre-wrap;"></p>
                    <p class="mb-1"><strong>掃描證據：</strong></p>
                    <pre id="vulnDetailEvidence" style="white-space:pre-wrap;font-family:'Consolas',monospace;font-size:0.78rem;background:#f8f9fa;padding:0.75rem;border-radius:4px;"></pre>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">關閉</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="codeDetailModal" tabindex="-1" aria-labelledby="codeDetailModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="codeDetailModalLabel">原始碼弱點詳細資訊</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body" style="font-size:0.85rem;">
                    <p class="mb-1"><strong>修補建議：</strong></p>
                    <p id="codeDetailRemediation" style="white-space:pre-wrap;"></p>
                    <p class="mb-1"><strong>掃描證據：</strong></p>
                    <pre id="codeDetailEvidence" style="white-space:pre-wrap;font-family:'Consolas',monospace;font-size:0.78rem;background:#f8f9fa;padding:0.75rem;border-radius:4px;"></pre>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">關閉</button>
                </div>
            </div>
        </div>
    </div>

    <!-- ===== Main Content ===== -->
    <main class="sys-main">

        <!-- ====== Panel: 防護日誌 ====== -->
        <div id="elkTableContainer" class="panel-card">
            <div class="panel-header">
                <span class="panel-title" id="tableTitle">防護日誌</span>
                <span style="font-size:0.75rem;color:var(--muted);">Security Event Log</span>
            </div>
            <div class="query-bar">
                <form id="elk-query-form" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0;">
                    <label>開始時間</label>
                    <input type="datetime-local" id="start_datetime" name="start_datetime">
                    <label>結束時間</label>
                    <input type="datetime-local" id="end_datetime" name="end_datetime">
                    <button type="submit" class="btn btn-primary btn-sm">查詢</button>
                </form>
            </div>
            <div class="sys-table-wrap">
                <div id="elkLoadingStatus" class="text-center py-4" style="display:none;font-size:0.8rem;color:var(--muted);">
                    <div class="spinner-border spinner-border-sm me-2"></div>載入中...
                </div>
                <div id="elkLoadError" class="alert alert-danger m-3" style="display:none;">
                    <strong>載入失敗，請稍後重試。</strong>
                    <p id="elkErrorDetails" class="mb-0 mt-1"></p>
                </div>
                <table id="elkTable" class="table table-striped table-bordered align-middle mb-0">
                    <thead class="table-dark text-center">
                        <tr>
                            <th>時間</th>
                            <th>主機名稱</th>
                            <th>來源 IP</th>
                            <th>Log 內容</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
            <div class="d-flex justify-content-end gap-2 p-3" style="border-top:1px solid var(--border);background:#fafbfd;">
                <button type="button" class="btn btn-outline-primary btn-sm" id="btnNextElk">上一頁</button>
                <button type="button" class="btn btn-outline-primary btn-sm" id="btnPrevElk">下一頁</button>
            </div>
        </div>


        <!-- ====== Panel: IP 狀態管理 ====== -->
        <div id="ipRiskTableContainer" class="panel-card" style="display:none;">
            <div class="panel-header">
                <span class="panel-title">IP 狀態管理</span>
                <div class="d-flex gap-2">
                    <button id="btnAddWhitelist" class="btn btn-success btn-sm">+ 白名單</button>
                    <button id="btnAddBlacklist" class="btn btn-danger btn-sm">+ 黑名單</button>
                </div>
            </div>

            <!-- Search & Filters -->
            <div class="filter-bar">
                <input type="text" id="ipSearchInput" class="search-input" placeholder="搜尋 IP / 狀態...">
                <div class="filter-divider"></div>
                <div class="filter-group">
                    <label><input type="checkbox" class="ip-filter" value="白名單" checked> 白名單</label>
                    <label><input type="checkbox" class="ip-filter" value="黑名單" checked> 黑名單</label>
                    <label><input type="checkbox" class="ip-filter" value="警告IP" checked> 警告 IP</label>
                    <label><input type="checkbox" class="ip-filter" value="LLM黑名單" checked> LLM 黑名單</label>
                    <label><input type="checkbox" class="ip-filter" value="觀察名單" checked> 觀察名單</label>
                </div>
                <div class="filter-divider"></div>
                <div class="btn-group btn-group-sm">
                    <input type="checkbox" class="btn-check time-filter" value="current" id="time_current" checked>
                    <label class="btn btn-outline-primary" for="time_current" style="font-size:0.75rem;">現行</label>
                    <input type="checkbox" class="btn-check time-filter" value="past" id="time_past">
                    <label class="btn btn-outline-primary" for="time_past" style="font-size:0.75rem;">歷史</label>
                </div>
                <div class="filter-divider"></div>
                <button class="btn btn-outline-secondary btn-sm" data-bs-toggle="collapse" data-bs-target="#attackPanel" style="font-size:0.75rem;">
                    攻擊類型篩選
                </button>
                <button id="btnSelectAll" class="btn btn-sm btn-outline-primary" style="font-size:0.75rem;">全選</button>
                <button id="btnClearAll" class="btn btn-sm btn-outline-secondary" style="font-size:0.75rem;">清空</button>
            </div>

            <div id="attackPanel" class="collapse">
                <div id="attackTypeContainer" class="p-2 border-bottom" style="background:#fafbfd;"></div>
            </div>

            <div class="sys-table-wrap">
                <table id="ipRiskTable" class="table table-striped table-bordered align-middle mb-0">
                    <thead class="table-dark text-center">
                        <tr>
                            <th>IP 位址</th>
                            <th>主機名稱</th>
                            <th>狀態</th>
                            <th>最後更新時間</th>
                            <th>攻擊類型</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>

            <div class="p-3" style="border-top:1px solid var(--border);background:#fafbfd;">
                <nav>
                    <ul class="pagination pagination-sm justify-content-center mb-0" id="ipTablePagination"></ul>
                </nav>
            </div>
        </div>


        <!-- ====== Panel: 今日封鎖 ====== -->
        <div id="ipTodayTableContainer" class="panel-card" style="display:none;">
            <div class="panel-header">
                <span class="panel-title">今日封鎖儀表板</span>
                <span id="ipSummary" style="font-size:0.78rem;color:var(--muted);">載入中...</span>
            </div>

            <!-- Stat Cards -->
            <div class="today-stat-row">
                <div class="today-stat-card today-stat-btn" data-stat="total">
                    <div class="today-stat-label">今日新增封鎖</div>
                    <div class="today-stat-value" id="statTotal">—</div>
                    <div class="today-stat-sub">IP 筆數</div>
                </div>
                <div class="today-stat-card today-stat-card--gray today-stat-btn" data-stat="public">
                    <div class="today-stat-label">公開黑名單命中</div>
                    <div class="today-stat-value" id="statPublic">—</div>
                    <div class="today-stat-sub">Threat Intel Feed</div>
                </div>
                <div class="today-stat-card today-stat-card--blue today-stat-btn" data-stat="llmHigh">
                    <div class="today-stat-label">LLM 高信心封鎖</div>
                    <div class="today-stat-value" id="statLLMHigh">—</div>
                    <div class="today-stat-sub">系統研判 &gt;80%</div>
                </div>
                <div class="today-stat-card today-stat-card--blue today-stat-btn" style="border-left-color:#60a5fa;" data-stat="llmMid">
                    <div class="today-stat-label">LLM 中信心封鎖</div>
                    <div class="today-stat-value" id="statLLMMid">—</div>
                    <div class="today-stat-sub">系統研判 ≤80%</div>
                </div>
                <div class="today-stat-card today-stat-card--orange today-stat-btn" data-stat="repeated">
                    <div class="today-stat-label">重複攻擊 IP</div>
                    <div class="today-stat-value" id="statRepeated">—</div>
                    <div class="today-stat-sub">今日多筆紀錄</div>
                </div>
                <div class="today-stat-card today-stat-card--red today-stat-btn" data-stat="subnets">
                    <div class="today-stat-label">疑似攻擊網段</div>
                    <div class="today-stat-value" id="statSubnets">—</div>
                    <div class="today-stat-sub">/24 多 IP 命中</div>
                </div>
            </div>

            <!-- Stat Detail Drill-Down -->
            <div id="statDetailPanel" style="display:none;">
                <div class="today-stat-detail-header">
                    <span id="statDetailTitle"></span>
                    <button class="today-stat-detail-close" id="statDetailClose">&#x2715;</button>
                </div>
                <div class="sys-table-wrap">
                    <table class="table table-bordered align-middle mb-0" id="statDetailTable">
                        <thead class="table-dark text-center">
                            <tr>
                                <th style="width:130px;">IP</th>
                                <th style="width:110px;">主機</th>
                                <th style="width:110px;">攻擊手法</th>
                                <th style="width:80px;">狀態</th>
                                <th style="width:140px;">首次時間</th>
                                <th style="width:140px;">最後時間</th>
                                <th style="width:60px;">今日次數</th>
                            </tr>
                        </thead>
                        <tbody id="statDetailBody"></tbody>
                    </table>
                </div>
            </div>

            <script src="assets/js/package/highcharts.js"></script>

            <!-- Charts Row -->
            <div class="today-chart-row">
                <div class="today-chart-box">
                    <div class="today-chart-title">近 7 天封鎖趨勢（攻擊手法）</div>
                    <div id="attackTypeChart" style="height:280px;"></div>
                </div>
                <div class="today-chart-box">
                    <div class="today-chart-title">今日攻擊手法分布</div>
                    <div id="attackTypePie" style="height:280px;"></div>
                </div>
            </div>

            <!-- Subnet Analysis -->
            <div class="today-section-header" id="subnetSectionHeader" style="display:none;">
                疑似攻擊網段分析
                <span style="font-size:0.72rem;font-weight:400;color:var(--muted);margin-left:8px;">同一 /24 網段今日出現 10 個以上封鎖 IP</span>
            </div>
            <div class="sys-table-wrap" id="subnetTableWrap" style="display:none;">
                <table class="table table-bordered align-middle mb-0" id="subnetTable">
                    <thead class="table-dark text-center">
                        <tr>
                            <th style="width:160px;">網段 (/24)</th>
                            <th style="width:60px;">IP 數</th>
                            <th>涉及 IP</th>
                            <th>攻擊手法</th>
                            <th>涉及主機</th>
                        </tr>
                    </thead>
                    <tbody id="subnetTableBody"></tbody>
                </table>
            </div>

        </div>


        <!-- ====== Panel: Log 分析 ====== -->
        <div id="aiAnalyzeContainer" class="panel-card" style="display:none;">
            <div class="panel-header">
                <span class="panel-title">Log 分析</span>
                <span style="font-size:0.75rem;color:var(--muted);">AI-Assisted Log Analysis</span>
            </div>

            <div class="panel-body p-0">
                <ul class="nav nav-tabs px-4 pt-2" role="tablist" style="margin-bottom:0;border-bottom:1px solid var(--border);">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="analyzeTab" data-bs-toggle="tab"
                            data-bs-target="#analyzePanel" type="button" role="tab">分析新 Log</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="pendingTab" data-bs-toggle="tab"
                            data-bs-target="#pendingPanel" type="button" role="tab">
                            待審核
                            <span id="pendingCount" class="badge bg-danger ms-1" style="display:none;font-size:0.65rem;"></span>
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="knownTab" data-bs-toggle="tab"
                            data-bs-target="#knownPanel" type="button" role="tab">已知攻擊</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="evalTab" data-bs-toggle="tab"
                            data-bs-target="#evalPanel" type="button" role="tab">模型評估</button>
                    </li>
                </ul>

                <div class="tab-content p-4">

                    <!-- 分析新 Log -->
                    <div class="tab-pane fade show active" id="analyzePanel" role="tabpanel">
                        <div class="row g-4">
                            <div class="col-md-5">
                                <div style="font-size:0.75rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px;">Log 輸入</div>
                                <textarea id="logInput" class="form-control" rows="10"
                                    placeholder="貼上原始 log（Apache / Nginx / Syslog / Zeek 均可）..."></textarea>
                                <div class="row g-2 mt-2">
                                    <div class="col-5">
                                        <input type="text" id="logOtherIp" class="form-control form-control-sm"
                                            placeholder="外部 IP（選填）">
                                    </div>
                                    <div class="col-4">
                                        <input type="text" id="logLocalIp" class="form-control form-control-sm"
                                            placeholder="本地 IP（選填）">
                                    </div>
                                    <div class="col-3">
                                        <select id="logDirection" class="form-select form-select-sm">
                                            <option value="">方向</option>
                                            <option value="inbound">inbound</option>
                                            <option value="outbound">outbound</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="d-flex gap-2 mt-3">
                                    <button id="btnAnalyzeLog" class="btn btn-primary btn-sm">
                                        執行 LLM 分析
                                    </button>
                                    <button type="button" class="btn btn-outline-secondary btn-sm"
                                        onclick="document.getElementById('logInput').value=''">
                                        清除
                                    </button>
                                </div>
                                <div class="mt-3 p-2 rounded" style="background:#f0f6ff;border:1px solid #bfdbfe;font-size:0.72rem;color:#1e40af;line-height:1.6;">
                                    輸入單筆或多筆 log，填入連線資訊可提升分析準確度。
                                </div>
                            </div>
                            <div class="col-md-7">
                                <div style="font-size:0.75rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px;">分析結果</div>
                                <div id="aiResult" style="min-height:280px;background:#fafbfd;border:1px solid var(--border);border-radius:6px;padding:16px;font-size:0.82rem;line-height:1.75;color:var(--text);">
                                    <span style="color:var(--muted);">尚未執行分析。</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- 待審核 -->
                    <div class="tab-pane fade" id="pendingPanel" role="tabpanel">
                        <div id="pendingAttacksContainer">
                            <div class="text-center py-5" style="color:var(--muted);font-size:0.82rem;">
                                <div class="spinner-border spinner-border-sm me-2"></div>載入中...
                            </div>
                        </div>
                    </div>

                    <!-- 已知攻擊 -->
                    <div class="tab-pane fade" id="knownPanel" role="tabpanel">
                        <div id="knownAttacksContainer">
                            <div class="text-center py-5" style="color:var(--muted);font-size:0.82rem;">
                                <div class="spinner-border spinner-border-sm me-2"></div>載入中...
                            </div>
                        </div>
                    </div>

                    <!-- 模型評估 -->
                    <div class="tab-pane fade" id="evalPanel" role="tabpanel">

                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <div class="panel-title" style="font-size:0.85rem;font-weight:600;color:var(--text);padding-left:6px;border-left:3px solid var(--blue);">
                                LLM 模型效能評估
                                <span style="font-size:0.72rem;font-weight:400;color:var(--muted);margin-left:6px;">Ground Truth: 公開黑名單</span>
                            </div>
                            <button class="btn btn-outline-secondary btn-sm" id="btnRefreshEval" style="font-size:0.75rem;">重新整理</button>
                        </div>

                        <!-- 趨勢警示橫幅 -->
                        <div id="evalTrendBanner" class="mb-3" style="display:none;"></div>

                        <!-- Metric Cards -->
                        <div class="row g-3 mb-3" id="evalMetricCards">
                            <div class="text-center py-4" style="color:var(--muted);font-size:0.82rem;">
                                <div class="spinner-border spinner-border-sm me-2"></div>載入中...
                            </div>
                        </div>

                        <!-- 混淆矩陣 + 每日明細（可收合） -->
                        <div class="card mb-3" id="evalConfusionSection" style="display:none;">
                            <div class="card-header d-flex justify-content-between align-items-center"
                                 style="cursor:pointer;user-select:none;" data-bs-toggle="collapse" data-bs-target="#evalConfusionBody">
                                <span style="font-size:0.82rem;font-weight:600;">
                                    混淆矩陣 &amp; 每日 TP / FP / FN / TN
                                    <small class="text-muted fw-normal ms-2">TP=正確攔截 TN=正確放行 FP=誤報 FN=漏報</small>
                                </span>
                                <span class="eval-collapse-icon">▾</span>
                            </div>
                            <div class="collapse" id="evalConfusionBody">
                                <div class="card-body">
                                    <div class="row g-3 mb-3">
                                        <!-- 累積混淆矩陣 -->
                                        <div class="col-md-4">
                                            <div style="font-size:0.75rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px;">累積總覽</div>
                                            <table class="table table-bordered text-center mb-0" style="font-size:0.82rem;">
                                                <thead class="table-dark">
                                                    <tr><th></th><th>預測 Benign</th><th>預測 Attack</th></tr>
                                                </thead>
                                                <tbody>
                                                    <tr>
                                                        <th class="text-start" style="font-size:0.75rem;">實際 Benign</th>
                                                        <td id="cm_tn" class="table-success fw-bold fs-5"></td>
                                                        <td id="cm_fp" class="table-danger fw-bold fs-5"></td>
                                                    </tr>
                                                    <tr>
                                                        <th class="text-start" style="font-size:0.75rem;">實際 Attack</th>
                                                        <td id="cm_fn" class="table-warning fw-bold fs-5"></td>
                                                        <td id="cm_tp" class="table-success fw-bold fs-5"></td>
                                                    </tr>
                                                </tbody>
                                            </table>
                                        </div>
                                        <!-- 每日明細 -->
                                        <div class="col-md-8">
                                            <div style="font-size:0.75rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px;">每日快照</div>
                                            <div class="table-responsive" style="max-height:240px;overflow-y:auto;">
                                                <table class="table table-sm table-hover mb-0" style="font-size:0.76rem;" id="evalDailyTable">
                                                    <thead class="table-dark sticky-top">
                                                        <tr>
                                                            <th>日期</th>
                                                            <th>TP</th>
                                                            <th>FP</th>
                                                            <th>FN</th>
                                                            <th>TN</th>
                                                            <th>Recall</th>
                                                            <th>MCC</th>
                                                            <th>總筆數</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody id="evalDailyBody"></tbody>
                                                </table>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- 最佳 F1 閾值掃描（可收合） -->
                        <div class="card mb-3" id="evalSweepSection" style="display:none;">
                            <div class="card-header d-flex justify-content-between align-items-center"
                                 style="cursor:pointer;user-select:none;" data-bs-toggle="collapse" data-bs-target="#evalSweepBody">
                                <span style="font-size:0.82rem;font-weight:600;">
                                    最佳 F1 閾值掃描結果
                                    <small class="text-muted fw-normal ms-2">對 confidence 0.5~1.0 全掃描，找 F1 最高閾值</small>
                                </span>
                                <span class="eval-collapse-icon">▾</span>
                            </div>
                            <div class="collapse" id="evalSweepBody">
                                <div class="card-body" id="evalBestSweep">
                                    <span class="text-muted" style="font-size:0.8rem;">尚未執行 eval_metrics.py</span>
                                </div>
                            </div>
                        </div>

                        <!-- Eval Charts -->
                        <div class="card mb-3">
                            <div class="card-header" style="font-size:0.8rem;">Daily Trend</div>
                            <div class="card-body p-2 text-center">
                                <img src="get_eval_chart.php?name=trend_over_time&v=<?php echo @filemtime(__DIR__ . '/api/eval/output/trend_over_time.png'); ?>"
                                    id="evalTrendImg"
                                    class="img-fluid rounded" alt="Trend"
                                    onerror="this.parentNode.innerHTML='<span class=\'text-muted\' style=\'font-size:0.8rem;\'>圖表尚未產生（需 2 天以上資料）</span>'">
                            </div>
                        </div>

                        <!-- Eval Records Table -->
                        <div class="card">
                            <div class="card-header">近期評估紀錄（最新 100 筆）</div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-sm table-hover mb-0" id="evalRecordsTable">
                                        <thead class="table-dark">
                                            <tr>
                                                <th>IP</th>
                                                <th>Ground Truth</th>
                                                <th>LLM 判斷</th>
                                                <th>Confidence</th>
                                                <th>攻擊類型</th>
                                                <th>判定</th>
                                                <th>來源</th>
                                                <th>時間</th>
                                            </tr>
                                        </thead>
                                        <tbody id="evalRecordsBody"></tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                    </div>

                </div>
            </div>
        </div>

        <!-- ====== Panel: 弱點掃描 ====== -->
        <div id="vulnScanTableContainer" class="panel-card" style="display:none;">
            <div class="panel-header">
                <span class="panel-title">弱點掃描</span>
                <span id="vulnSummaryLastScan" style="font-size:0.75rem;color:var(--muted);">AI-Assisted Vulnerability Scan (nmap + searchsploit + gemma3:27b)</span>
            </div>

            <!-- Summary Stat Cards -->
            <div class="today-stat-row">
                <div class="today-stat-card">
                    <div class="today-stat-label">弱點總筆數</div>
                    <div class="today-stat-value" id="vulnStatTotal">—</div>
                    <div class="today-stat-sub">所有掃描紀錄</div>
                </div>
                <div class="today-stat-card today-stat-card--red">
                    <div class="today-stat-label">高風險</div>
                    <div class="today-stat-value" id="vulnStatHigh">—</div>
                    <div class="today-stat-sub">建議優先處理</div>
                </div>
                <div class="today-stat-card today-stat-card--orange">
                    <div class="today-stat-label">中風險</div>
                    <div class="today-stat-value" id="vulnStatMid">—</div>
                    <div class="today-stat-sub">建議排程修補</div>
                </div>
                <div class="today-stat-card today-stat-card--gray">
                    <div class="today-stat-label">低風險 / 資訊</div>
                    <div class="today-stat-value" id="vulnStatLow">—</div>
                    <div class="today-stat-sub">可持續觀察</div>
                </div>
                <div class="today-stat-card today-stat-card--blue">
                    <div class="today-stat-label">待處理項目</div>
                    <div class="today-stat-value" id="vulnStatPending">—</div>
                    <div class="today-stat-sub">尚未標記狀態</div>
                </div>
                <div class="today-stat-card today-stat-card--red">
                    <div class="today-stat-label">受影響主機</div>
                    <div class="today-stat-value" id="vulnStatTargets">—</div>
                    <div class="today-stat-sub">高 / 中風險目標數</div>
                </div>
            </div>

            <!-- Search & Filters -->
            <div class="filter-bar">
                <input type="text" id="vulnSearchInput" class="search-input" placeholder="搜尋 目標 / CVE / 標題...">
                <div class="filter-divider"></div>
                <div class="filter-group">
                    <label><input type="checkbox" class="vuln-severity-filter" value="高" checked> 高</label>
                    <label><input type="checkbox" class="vuln-severity-filter" value="中" checked> 中</label>
                    <label><input type="checkbox" class="vuln-severity-filter" value="低" checked> 低</label>
                    <label><input type="checkbox" class="vuln-severity-filter" value="資訊" checked> 資訊</label>
                </div>
                <div class="filter-divider"></div>
                <div class="filter-group">
                    <label><input type="checkbox" class="vuln-status-filter" value="pending" checked> 待處理</label>
                    <label><input type="checkbox" class="vuln-status-filter" value="confirmed" checked> 已確認</label>
                    <label><input type="checkbox" class="vuln-status-filter" value="false_positive"> 誤判</label>
                    <label><input type="checkbox" class="vuln-status-filter" value="resolved"> 已解決</label>
                </div>
            </div>

            <div class="sys-table-wrap">
                <table id="vulnScanTable" class="table table-striped table-bordered align-middle mb-0">
                    <thead class="table-dark text-center">
                        <tr>
                            <th>目標</th>
                            <th>服務 / 版本</th>
                            <th>來源</th>
                            <th>CVE</th>
                            <th>標題</th>
                            <th>嚴重程度</th>
                            <th>信心度</th>
                            <th>狀態</th>
                            <th>掃描時間</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>

            <div class="p-3" style="border-top:1px solid var(--border);background:#fafbfd;">
                <nav>
                    <ul class="pagination pagination-sm justify-content-center mb-0" id="vulnTablePagination"></ul>
                </nav>
            </div>
        </div>

        <!-- ====== Panel: 原始碼掃描 ====== -->
        <div id="codeScanTableContainer" class="panel-card" style="display:none;">
            <div class="panel-header">
                <span class="panel-title">原始碼掃描</span>
                <span id="codeSummaryLastScan" style="font-size:0.75rem;color:var(--muted);">Source Code Scan (gitleaks + semgrep + gemma3:27b 業務邏輯審查)</span>
            </div>

            <!-- Summary Stat Cards -->
            <div class="today-stat-row">
                <div class="today-stat-card">
                    <div class="today-stat-label">問題總筆數</div>
                    <div class="today-stat-value" id="codeStatTotal">—</div>
                    <div class="today-stat-sub">所有掃描紀錄</div>
                </div>
                <div class="today-stat-card today-stat-card--red">
                    <div class="today-stat-label">高風險</div>
                    <div class="today-stat-value" id="codeStatHigh">—</div>
                    <div class="today-stat-sub">建議優先處理</div>
                </div>
                <div class="today-stat-card today-stat-card--orange">
                    <div class="today-stat-label">中風險</div>
                    <div class="today-stat-value" id="codeStatMid">—</div>
                    <div class="today-stat-sub">建議排程修補</div>
                </div>
                <div class="today-stat-card today-stat-card--gray">
                    <div class="today-stat-label">低風險 / 資訊</div>
                    <div class="today-stat-value" id="codeStatLow">—</div>
                    <div class="today-stat-sub">可持續觀察</div>
                </div>
                <div class="today-stat-card today-stat-card--blue">
                    <div class="today-stat-label">待處理項目</div>
                    <div class="today-stat-value" id="codeStatPending">—</div>
                    <div class="today-stat-sub">尚未標記狀態</div>
                </div>
                <div class="today-stat-card today-stat-card--red">
                    <div class="today-stat-label">受影響檔案</div>
                    <div class="today-stat-value" id="codeStatFiles">—</div>
                    <div class="today-stat-sub">高 / 中風險檔案數</div>
                </div>
            </div>

            <!-- Search & Filters -->
            <div class="filter-bar">
                <input type="text" id="codeSearchInput" class="search-input" placeholder="搜尋 檔案路徑 / 規則 / 標題...">
                <div class="filter-divider"></div>
                <div class="filter-group">
                    <label><input type="checkbox" class="code-severity-filter" value="高" checked> 高</label>
                    <label><input type="checkbox" class="code-severity-filter" value="中" checked> 中</label>
                    <label><input type="checkbox" class="code-severity-filter" value="低" checked> 低</label>
                    <label><input type="checkbox" class="code-severity-filter" value="資訊" checked> 資訊</label>
                </div>
                <div class="filter-divider"></div>
                <div class="filter-group">
                    <label><input type="checkbox" class="code-status-filter" value="pending" checked> 待處理</label>
                    <label><input type="checkbox" class="code-status-filter" value="confirmed" checked> 已確認</label>
                    <label><input type="checkbox" class="code-status-filter" value="false_positive"> 誤判</label>
                    <label><input type="checkbox" class="code-status-filter" value="resolved"> 已解決</label>
                </div>
            </div>

            <div class="sys-table-wrap">
                <table id="codeScanTable" class="table table-striped table-bordered align-middle mb-0">
                    <thead class="table-dark text-center">
                        <tr>
                            <th>檔案路徑:行號</th>
                            <th>來源</th>
                            <th>規則</th>
                            <th>標題</th>
                            <th>嚴重程度</th>
                            <th>信心度</th>
                            <th>狀態</th>
                            <th>掃描時間</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>

            <div class="p-3" style="border-top:1px solid var(--border);background:#fafbfd;">
                <nav>
                    <ul class="pagination pagination-sm justify-content-center mb-0" id="codeTablePagination"></ul>
                </nav>
            </div>
        </div>

        <!-- ====== Panel: 掃描報告 ====== -->
        <div id="scanReportContainer" class="panel-card" style="display:none;">
            <div class="panel-header">
                <span class="panel-title">掃描報告</span>
                <span id="reportGeneratedAt" style="font-size:0.75rem;color:var(--muted);">尚無報告</span>
            </div>

            <!-- Summary Stat Cards -->
            <div class="today-stat-row">
                <div class="today-stat-card">
                    <div class="today-stat-label">未結案問題總數</div>
                    <div class="today-stat-value" id="reportStatTotal">—</div>
                    <div class="today-stat-sub" id="reportStatTotalDiff">&nbsp;</div>
                </div>
                <div class="today-stat-card today-stat-card--red">
                    <div class="today-stat-label">高風險</div>
                    <div class="today-stat-value" id="reportStatHigh">—</div>
                </div>
                <div class="today-stat-card today-stat-card--orange">
                    <div class="today-stat-label">中風險</div>
                    <div class="today-stat-value" id="reportStatMid">—</div>
                </div>
                <div class="today-stat-card today-stat-card--gray">
                    <div class="today-stat-label">低風險 / 資訊</div>
                    <div class="today-stat-value" id="reportStatLow">—</div>
                </div>
                <div class="today-stat-card today-stat-card--blue">
                    <div class="today-stat-label">本次新增</div>
                    <div class="today-stat-value" id="reportStatNew">—</div>
                </div>
                <div class="today-stat-card">
                    <div class="today-stat-label">已解決</div>
                    <div class="today-stat-value" id="reportStatResolved">—</div>
                </div>
            </div>

            <div class="p-3">
                <h6>摘要</h6>
                <p id="reportSummary" style="white-space:pre-wrap;">尚未產生過掃描報告，請等待下一輪排程掃描（或手動觸發一次掃描）完成。</p>

                <h6 class="mt-3">優先關注項目</h6>
                <ul id="reportHighlights" class="mb-3"></ul>

                <h6 class="mt-3">本次重點清單（依嚴重程度排序）</h6>
                <div class="sys-table-wrap">
                    <table id="reportTopFindingsTable" class="table table-striped table-bordered align-middle mb-0">
                        <thead class="table-dark text-center">
                            <tr>
                                <th>類型</th>
                                <th>位置</th>
                                <th>標題</th>
                                <th>嚴重程度</th>
                                <th>信心度</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>

    </main>

    <!-- Toast Container -->
    <div class="position-fixed bottom-0 end-0 p-3" style="z-index:1100; width:320px;">
        <div id="toastContainer"></div>
    </div>

    <script src="assets/js/package/jquery-3.7.0.min.js"></script>
    <script src="assets/js/package/bootstrap.bundle.min.js"></script>
    <script src="assets/js/package/jquery.dataTables.min.js"></script>
    <script src="assets/js/package/dataTables.bootstrap5.min.js"></script>
    <script src="assets/js/index.js?v=<?php echo @filemtime(__DIR__ . '/assets/js/index.js'); ?>"></script>

    <script>
    // Real-time clock
    (function tick() {
        const now = new Date();
        const t = now.toLocaleTimeString('zh-TW', { hour12: false });
        const d = now.toLocaleDateString('zh-TW', { year: 'numeric', month: '2-digit', day: '2-digit' });
        const el = document.getElementById('headerClock');
        if (el) el.textContent = d + '  ' + t;
        setTimeout(tick, 1000);
    })();
    </script>
</body>
</html>
