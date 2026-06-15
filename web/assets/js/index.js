// ============ 吐司通知函數 ============
function showToast(message, type = 'info', duration = 3000) {
    const toastId = 'toast-' + Date.now();
    const bgClass =
        type === 'success' ? 'bg-success' :
            type === 'danger' ? 'bg-danger' :
                type === 'warning' ? 'bg-warning' : 'bg-info';

    const toastHtml = `
        <div id="${toastId}" class="toast align-items-center text-white border-0 ${bgClass}" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>
    `;

    $('#toastContainer').append(toastHtml);
    const toast = new bootstrap.Toast(document.getElementById(toastId));
    toast.show();

    // 自動移除 DOM
    setTimeout(() => $(`#${toastId}`).remove(), duration + 500);
}

// 表格切換
$(document).ready(function () {
    // 所有的分頁按鈕 ID
    const TAB_BUTTONS = ['#showElk', '#showIpRisk', '#showIpToday', '#showAIAnalyze', '#showVulnScan', '#showCodeScan', '#showScanReport'];
    // 所有的表格容器 ID
    const TAB_CONTAINERS = ['#elkTableContainer', '#ipRiskTableContainer', '#ipTodayTableContainer', '#aiAnalyzeContainer', '#vulnScanTableContainer', '#codeScanTableContainer', '#scanReportContainer'];
    // 分頁 ID 與標題的對應關係
    const TITLES = {
        '#showElk': 'GAI伺服器安全防護系統日誌檢視',
        '#showIpRisk': 'IP 狀態清單',
        '#showIpToday': '今日封鎖名單',
        '#showAIAnalyze': 'Log分析',
        '#showVulnScan': '弱點掃描',
        '#showCodeScan': '原始碼掃描',
        '#showScanReport': '掃描報告'
    };

    /**
     * 統一處理分頁切換的函式
     * @param {string} activeTabId - 目前點擊的按鈕 ID (e.g., '#showBehavior')
     * @param {string} activeContainerId - 應該顯示的表格容器 ID (e.g., '#behaviorTableContainer')
     */
    function switchTab(activeTabId, activeContainerId) {
        TAB_CONTAINERS.forEach(id => $(id).hide());
        $(activeContainerId).show();

        TAB_BUTTONS.forEach(id => $(id).removeClass('active'));
        $(activeTabId).addClass('active');

        $('#tableTitle').text(TITLES[activeTabId]);

        if (activeTabId === '#showAIAnalyze') {
            loadPendingAttacks();
            loadKnownAttacks();
        }
    }

    // --- 綁定所有點擊事件 ---
    $('#showElk').click(function (e) {
        e.preventDefault();
        switchTab('#showElk', '#elkTableContainer');
    });

    $('#showIpRisk').click(function (e) {
        e.preventDefault();
        switchTab('#showIpRisk', '#ipRiskTableContainer');
    });

    $('#showIpToday').click(function (e) {
        e.preventDefault();
        switchTab('#showIpToday', '#ipTodayTableContainer');
    });

    $('#showAIAnalyze').click(function (e) {
        e.preventDefault();
        switchTab('#showAIAnalyze', '#aiAnalyzeContainer');
    });

    $('#showVulnScan').click(function (e) {
        e.preventDefault();
        switchTab('#showVulnScan', '#vulnScanTableContainer');
        loadVulnFindings(0);
        loadVulnSummary();
    });

    $('#showCodeScan').click(function (e) {
        e.preventDefault();
        switchTab('#showCodeScan', '#codeScanTableContainer');
        loadCodeFindings(0);
        loadCodeSummary();
    });

    $('#showScanReport').click(function (e) {
        e.preventDefault();
        switchTab('#showScanReport', '#scanReportContainer');
        loadScanReport();
    });

    // AI 分析區內已知攻擊 tab
    $(document).on('click', '#knownTab', function (e) {
        e.preventDefault();
        loadKnownAttacks();
    });

    // 模型評估 tab
    $(document).on('click', '#evalTab', function (e) {
        e.preventDefault();
        loadEvalResults();
    });
    $(document).on('click', '#btnRefreshEval', function () {
        loadEvalResults();
    });

    // 收合箭頭方向（監聽 Bootstrap collapse 事件）
    document.addEventListener('show.bs.collapse', function(e) {
        const header = document.querySelector(`[data-bs-target="#${e.target.id}"]`);
        if (header) header.setAttribute('aria-expanded', 'true');
    });
    document.addEventListener('hide.bs.collapse', function(e) {
        const header = document.querySelector(`[data-bs-target="#${e.target.id}"]`);
        if (header) header.setAttribute('aria-expanded', 'false');
    });

    // --- 頁面初始載入設定 ---
    if ($('#showElk').length) {
        // 預設啟動「防護日誌」
        switchTab('#showElk', '#elkTableContainer');
    }
});

// mysql 更新
$(document).ready(function () {
    $('#ipRiskTable').on('click', '.btn-change-status', function () {
        var $btn = $(this);
        var ip = $btn.data('ip');
        var newStatus = $btn.data('status');
        var prevStatus = $btn.closest('tr').find('td').eq(2).text().trim();

        // ✅ 根據狀態顯示不同提示
        let message = (newStatus === '白名單')
            ? '請輸入白名單原因 / 身份（例如：公司內部設備）'
            : '請輸入攻擊手法（例如：Port Scan / SQL Injection）';

        // 從黑名單/LLM黑名單 改為白名單 → 視為「誤判回報」，會記錄至評估資料供自動調參使用
        if (newStatus === '白名單' && (prevStatus === '黑名單' || prevStatus === 'LLM黑名單')) {
            message = `此 IP 目前為「${prevStatus}」，改為白名單將視為「誤判回報」，並記錄至評估資料供自動調參使用。\n\n` + message;
        }

        // ✅ 強制輸入
        let attackType = prompt(message);

        if (attackType === null) return; // 使用者按取消

        attackType = attackType.trim();

        if (!attackType) {
            alert('❗ 必須輸入內容才可更新');
            return;
        }

        // 印出要 POST 的參數
        var result = validateIpOrPattern(ip);
        console.log('POST data:', { ip: ip, status: newStatus, type: result.type });

        $.ajax({
            url: 'database_update.php',
            method: 'POST',
            data: {
                ip: ip,
                status: newStatus,
                type: result.type,
                attack_type: attackType   // ✅ 新增
            },
            dataType: 'json',
            success: function (response) {
                if (response.success) {
                    // 1. 更新按鈕狀態
                    if (newStatus === '白名單') {
                        $btn.prop('disabled', true).css({ 'opacity': 0.5, 'cursor': 'not-allowed' });
                        $btn.siblings('.btn-danger').prop('disabled', false).css({ 'opacity': 1, 'cursor': 'pointer' });
                    } else if (newStatus === '黑名單') {
                        $btn.prop('disabled', true).css({ 'opacity': 0.5, 'cursor': 'not-allowed' });
                        $btn.siblings('.btn-success').prop('disabled', false).css({ 'opacity': 1, 'cursor': 'pointer' });
                    }

                    // 2. 更新狀態欄位文字
                    $btn.closest('tr').find('td').eq(2).text(newStatus);

                    // ✅ 更新攻擊手法欄位（第5欄）
                    $btn.closest('tr').find('td').eq(4).text(attackType);

                    // 3. 取得目前時間並更新時間欄位
                    var now = new Date();

                    function pad(num) {
                        return num.toString().padStart(2, '0');
                    }

                    var year = now.getFullYear();
                    var month = pad(now.getMonth() + 1);  // 月份從0開始
                    var day = pad(now.getDate());
                    var hour = pad(now.getHours());
                    var minute = pad(now.getMinutes());
                    var second = pad(now.getSeconds());

                    var timeString = `${year}-${month}-${day} ${hour}:${minute}:${second}`;

                    $btn.closest('tr').find('.time-cell').text(timeString);
                } else {
                    showToast('✗ 更新失敗: ' + response.message, 'danger');
                }
            },
            error: function () {
                showToast('✗ 更新請求失敗', 'danger');
            }
        });
    });
});

// ip 狀態表格動態篩選
$(document).ready(function () {
    $('.ip-filter').change(function () {
        var selectedStatuses = $('.ip-filter:checked').map(function () {
            return $(this).val();
        }).get();

        $('#ipRiskTable tbody tr').each(function () {
            var status = $(this).find('td').eq(2).text().trim();
            if (selectedStatuses.includes(status)) {
                $(this).show();
            } else {
                $(this).hide();
            }
        });
    });
});

// 判斷單一、CIDR 或通配符範圍
function validateIpOrPattern(ip) {
    var ipv4Regex = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
    var cidrRegex = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/;
    var patternRegex = /^(\d{1,3}|x|%)(\.(\d{1,3}|x|%)){0,3}$/i;

    if (ipv4Regex.test(ip)) {
        return { valid: true, type: 'single' };
    } else if (cidrRegex.test(ip)) {
        return { valid: true, type: 'range' };  // CIDR → ip_risk_ranges
    } else if (patternRegex.test(ip)) {
        return { valid: true, type: 'range' };  // 通配符 → ip_risk_ranges
    } else {
        return { valid: false, type: null };
    }
}

// 手動新增黑白名單
$(document).ready(function () {
    var ipInputModal = new bootstrap.Modal(document.getElementById('ipInputModal'));

    // 👉 黑名單
    $('#btnAddBlacklist').click(function () {
        $('#ipInputModalLabel').text('加入黑名單');
        $('#inputStatus').val('黑名單');
        $('#inputIp').val('');
        $('#inputAttackType').val('').attr('placeholder', '例如：Port Scan / SQL Injection');
        ipInputModal.show();
    });

    // 👉 白名單
    $('#btnAddWhitelist').click(function () {
        $('#ipInputModalLabel').text('加入白名單');
        $('#inputStatus').val('白名單');
        $('#inputIp').val('');
        $('#inputAttackType').val('').attr('placeholder', '例如：公司內部設備 / 管理員');
        ipInputModal.show();
    });

    // 👉 表單送出
    $('#ipInputForm').submit(function (e) {
        e.preventDefault();
        var ip = $('#inputIp').val().trim();
        var status = $('#inputStatus').val();
        var attackType = $('#inputAttackType').val().trim(); // ✅ 新增

        if (!ip) {
            alert('請輸入有效的 IP 位址或範圍');
            return;
        }

        if (!attackType) {
            alert('請輸入攻擊手法 / 白名單原因');
            return;
        }

        var result = validateIpOrPattern(ip);
        if (!result.valid) {
            alert('IP 格式錯誤，請輸入正確的 IPv4、CIDR（如 127.0.0.0/8）或通配符格式（如 192.168.% 或 10.0.x.x）');
            return;
        }

        var unblockHours = parseInt($('#inputUnblockTime').val()) || 24;

        $.ajax({
            url: 'database_update.php',  // 您更新 IP 狀態的後端 API
            method: 'POST',
            data: {
                ip: ip,
                status: status,
                type: result.type,
                unblock_hours: unblockHours,
                attack_type: attackType   // ✅ 核心
            },
            dataType: 'json',
            success: function (response) {
                if (response.success) {

                    // ✅ 關閉 modal
                    ipInputModal.hide();

                    // ✅ 顯示成功訊息（你原本的 toast）
                    showToast('✅ 執行成功！已加入 ' + status, 'success');

                    // ✅ 停頓 2 秒再刷新（關鍵）
                    setTimeout(function () {
                        location.reload();
                    }, 2000);  // 👉 2000 = 2秒

                } else {
                    showToast('✗ 失敗：' + response.message, 'danger');
                }
            },
            error: function () {
                showToast('✗ 請求失敗，請稍後再試', 'danger');
            }
        });
    });
});

// 250630毅 即時搜尋/篩選/分頁/停用/更新 250801更新 251105合併停用功能 260415攻擊手法篩選/時間篩選
$(function () {
    const $tbody = $('#ipRiskTable tbody');
    const $pagination = $('#ipTablePagination');
    const rowsPerPage = 10;

    // 提升到內部全域變數，確保 loadData 和其他操作能存取
    let currentPage = 0;
    let currentSearch = '';
    // 確保初始狀態從 DOM 讀取（與前面的 ip-filter.change 邏輯一致）
    let currentStatuses = $(".ip-filter:checked").map(function () { return $(this).val(); }).get();

    // 分頁渲染函式 
    function renderPagination(total, page) {
        const totalPages = Math.ceil(total / rowsPerPage);
        $pagination.empty();
        if (totalPages <= 1) return;

        let pages = [];

        if (totalPages <= 7) {
            for (let i = 0; i < totalPages; i++) pages.push(i);
        } else {
            // 第一頁永遠顯示
            pages.push(0);

            // 左側省略號
            if (page > 3) pages.push('...');

            // 中間頁碼
            let start = Math.max(1, page - 2);
            let end = Math.min(totalPages - 2, page + 2);
            for (let i = start; i <= end; i++) pages.push(i);

            // 右側省略號
            if (page < totalPages - 4) pages.push('...');

            // 最後一頁
            pages.push(totalPages - 1);
        }

        pages.forEach(function (p) {
            if (p === '...') {
                $pagination.append('<li class="page-item disabled"><span class="page-link">…</span></li>');
            } else {
                $pagination.append(
                    `<li class="page-item ${p === page ? 'active' : ''}">
                        <a class="page-link" href="#" data-page="${p}">${p + 1}</a>
                    </li>`
                );
            }
        });

        // 點擊事件
        $pagination.find('a[data-page]').click(function (e) {
            e.preventDefault();
            loadData(parseInt($(this).data('page')));
        });
    }

    // 資料載入函式
    function loadData(page = 0) {
        $.ajax({
            url: 'get_ip.php', // 請改成你的API路徑
            method: 'GET',
            data: {
                page: page,
                page_size: rowsPerPage,
                search: currentSearch,
                statuses: currentStatuses.join(','),
                attack_types: currentAttackTypes.join(','), // ✅ 加這行
                time_filter: currentTimeFilter.join(',')   // ✅
            },
            dataType: 'json',
            success: function (res) {
                renderTable(res.data);
                renderPagination(res.total, page);
                currentPage = page; // 更新當前頁碼
            },
            error: function () {
                alert('IP 資料載入失敗');
            }
        });
    }

    // 表格渲染函式
    function renderTable(data) {
        let html = '';
        if (data && data.length > 0) {
            data.forEach(function (row) {
                html += `
                    <tr class="text-center">
                        <td>${row.ip}</td>
                        <td>${row.hostname ? row.hostname : ''}</td>
                        <td>${row.status}</td>
                        <td class="time-cell">${row.last_time}</td>
                        <td>${row.attack_type}</td>
                        <td>
                            <button class="btn btn-sm btn-success btn-change-status" data-ip="${row.ip}" data-status="白名單"
                                ${row.status === '白名單' ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>白名單</button>
                            <button class="btn btn-sm btn-danger btn-change-status" data-ip="${row.ip}" data-status="黑名單"
                                ${row.status === '黑名單' ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>黑名單</button>
                            <button class="btn btn-sm btn-outline-danger btn-delete-ip" data-ip="${row.ip}">停用</button>
                            <button class="btn btn-sm btn-info btn-view-detail" data-ip="${row.ip}">詳細</button>
                        </td>
                    </tr>`;
            });
        } else {
            html = '<tr><td colspan="5" class="text-center">無數據</td></tr>'; // 確保在無資料時顯示「無數據」
        }
        $('#ipRiskTable tbody').html(html);
    }

    // 分頁點擊 
    $pagination.on('click', 'a.page-link', function (e) {
        e.preventDefault();
        let page = parseInt($(this).data('page'));
        loadData(page);
    });

    // 搜尋輸入（加 debounce 減少頻繁請求）
    let searchDebounceTimer = null;
    $('#ipSearchInput').on('input', function () {
        clearTimeout(searchDebounceTimer);
        var value = $(this).val().trim();
        searchDebounceTimer = setTimeout(function () {
            currentSearch = value;
            loadData(0); // 搜尋時回到第一頁
        }, 500);
    });

    // 狀態勾選
    $('.ip-filter').on('change', function () {
        currentStatuses = $(".ip-filter:checked").map(function () { return $(this).val(); }).get();
        loadAttackTypes(); // 重新載入符合當前狀態的攻擊類型（內部會呼叫 loadData(0)）
    });

    // 250902 RU 停用即時IP，保留紀錄 【直接呼叫 loadData(currentPage)】
    let deleteTargetIp = null;
    var confirmModal = new bootstrap.Modal(document.getElementById('confirmDeleteModal'));

    // 👉 點擊「停用」
    $('#ipRiskTable').on('click', '.btn-delete-ip', function () {

        deleteTargetIp = $(this).data('ip');

        // 動態顯示 IP
        $('#confirmDeleteText').text(`確定要將 IP ${deleteTargetIp} 設為非活躍嗎？`);

        confirmModal.show();
    });

    $('#confirmDeleteBtn').click(function () {

        if (!deleteTargetIp) return;

        $.ajax({
            url: 'ELK_delete.php',
            method: 'POST',
            data: { ip: deleteTargetIp },
            dataType: 'json',

            success: function (response) {

                confirmModal.hide();

                if (response.success) {

                    // 👉 改成 toast（不要 alert）
                    showToast(response.message, 'success');

                    // 👉 停頓一下再刷新（跟你前面統一）
                    setTimeout(function () {
                        loadData(currentPage);
                    }, 2000);

                } else {
                    showToast('✗ 操作失敗: ' + (response.message || '未知錯誤'), 'danger');
                }
            },

            error: function () {
                confirmModal.hide();
                showToast('✗ 請求失敗，請稍後再試', 'danger');
            }
        });
    });
    // 250902 RU 停用即時IP，保留紀錄 END

    // 攻擊手法篩選
    let currentAttackTypes = [];

    function loadAttackTypes() {
        $.ajax({
            url: 'get_all_attacks.php',
            method: 'GET',
            data: { statuses: currentStatuses.join(',') },
            dataType: 'json',
            success: function (data) {

                let uniqueTypes = [];

                data.forEach(item => {
                    let t = item.attack_type?.trim();
                    if (t && !uniqueTypes.includes(t)) {
                        uniqueTypes.push(t);
                    }
                });

                let html = '';

                uniqueTypes.forEach(type => {

                    let safe = type.replace(/[^a-zA-Z0-9]/g, '_');

                    html += `
                    <label class="attack-filter-item">
                        <input type="checkbox"
                               class="attack-filter"
                               value="${type}"
                               id="atk_${safe}">
                        <span>${type}</span>
                    </label>
                `;
                });

                $('#attackTypeContainer').html(html);

                // ❗預設：全部不選（產品級行為）
                currentAttackTypes = [];

                loadData(0);
            }
        });
    }
    $(document).on('change', '.attack-filter', function () {

        currentAttackTypes = $(".attack-filter:checked")
            .map(function () { return $(this).val(); })
            .get();

        loadData(0);
    });
    $('#btnSelectAll').on('click', function () {
        $('.attack-filter').prop('checked', true);
        currentAttackTypes = $(".attack-filter:checked")
            .map(function () { return $(this).val(); })
            .get();

        loadData(0);
    });

    $('#btnClearAll').on('click', function () {
        $('.attack-filter').prop('checked', false);
        currentAttackTypes = [];
        loadData(0);
    });

    // 資料時間篩選
    let currentTimeFilter = ['current']; // 預設只有現在

    $('.time-filter').on('change', function () {
        currentTimeFilter = $(".time-filter:checked")
            .map(function () { return $(this).val(); }).get();

        loadData(0);
    });

    // 頁面載入
    loadAttackTypes();
});
// 250630毅 即時搜尋/篩選/分頁/停用/更新 END

// 抓取IP id
$('#ipRiskTable').on('click', '.btn-view-detail', function () {
    var ip = $(this).data('ip');

    $("#ipDetailModalLabel").text("IP 行為分析與原始日誌 — " + ip);
    $("#behaviorAnalysis").html("<div class='text-center mt-4'>載入中...</div>");
    $("#rawLog").html("");

    $.ajax({
        url: 'get_ip_detail.php',
        type: 'POST',
        dataType: 'json',
        data: { ip: ip },
        success: function (data) {
            const accessCount = data.login_count || 0;
            const rawLogs  = data.raw_logs   || [];
            const zeekLogs = data.zeek_logs  || [];
            const actions  = data.actions    || [];
            const info     = data.ip_info    || null;
            const stats    = data.log_stats  || {};

            // ===== 左欄：行為分析 =====
            let analysisHtml = '';

            // IP 基本資訊卡
            if (info) {
                const statusColor = {
                    '黑名單': '#dc2626', 'LLM黑名單': '#7c3aed',
                    '白名單': '#16a34a', '警告IP': '#d97706', '觀察名單': '#0284c7'
                }[info.status] || '#6b7280';
                const liveLabel = info.live_status == 1
                    ? `<span style="color:#16a34a;">● 啟用中</span>`
                    : `<span style="color:#9ca3af;">○ 已停用</span>`;
                analysisHtml += `
                    <div style="background:#f0f4fa;border-radius:8px;padding:10px 12px;margin-bottom:10px;font-size:0.78rem;">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                            <span style="font-weight:700;color:${statusColor};font-size:0.85rem;">${info.status || '-'}</span>
                            ${liveLabel}
                        </div>
                        ${info.attack_type ? `<div><strong>攻擊類型：</strong>${info.attack_type}</div>` : ''}
                        ${info.hostname    ? `<div><strong>主機名稱：</strong>${info.hostname}</div>` : ''}
                        <div><strong>首次發現：</strong>${info.first_time || '-'}</div>
                        <div><strong>最後活躍：</strong>${info.last_time  || '-'}</div>
                        ${info.unblock_time ? `<div><strong>解封時間：</strong>${info.unblock_time}</div>` : ''}
                    </div>`;
            }

            // Log 統計
            const sysCount  = rawLogs.length;
            const zeekCount = zeekLogs.length;
            const statParts = Object.entries(stats).map(([k,v]) => `${k}：${v} 筆`).join('　');
            analysisHtml += `
                <div style="font-size:0.78rem;margin-bottom:10px;padding:8px 10px;background:#fff8e1;border-radius:6px;border-left:3px solid #f59e0b;">
                    <div><strong>Log 總筆數：</strong>${accessCount}（系統 ${sysCount} / Zeek ${zeekCount}）</div>
                    ${statParts ? `<div><strong>流量方向：</strong>${statParts}</div>` : ''}
                </div>`;

            // AI 行為分析
            if (actions.length > 0) {
                analysisHtml += actions.map(a => {
                    if (typeof a === "object") {
                        const basisList = (a.analysis_basis || []).map(b => `<li>${b}</li>`).join("");
                        return `
                            <div style="border:1px solid #d1d5db;padding:10px;margin-bottom:10px;border-radius:6px;font-size:0.78rem;">
                                <div><strong>攻擊類型：</strong>${a.attack_type || 'N/A'}</div>
                                <div style="margin-top:5px;"><strong>行為描述：</strong><div style="color:#374151;">${a.overall_behavior || 'N/A'}</div></div>
                                ${basisList ? `<div style="margin-top:5px;"><strong>分析依據：</strong><ul style="margin:4px 0 0 18px;">${basisList}</ul></div>` : ''}
                            </div>`;
                    }
                    return `<div style="border-bottom:1px solid #e5e7eb;padding-bottom:5px;margin-bottom:5px;font-size:0.78rem;">${a}</div>`;
                }).join("");
            } else {
                analysisHtml += `<div style="color:#9ca3af;font-size:0.78rem;padding:8px;">尚無 AI 行為分析記錄</div>`;
            }

            $("#behaviorAnalysis").html(analysisHtml);

            // ===== 右欄：原始 Log =====
            let rawLogHtml = "";
            const renderLogRow = z =>
                `<div style="border-bottom:1px solid #e5e7eb;padding-bottom:5px;margin-bottom:5px;">
                    <div style="color:#6b7280;font-size:0.72rem;">${z.created_at}　${z.direction || '-'}　→　${z.local_ip || '-'}</div>
                    <div style="word-break:break-all;">${z.content}</div>
                </div>`;

            if (rawLogs.length > 0) {
                rawLogHtml += `<div style="font-weight:600;margin-bottom:4px;">系統日誌（${rawLogs.length} 筆）</div>`;
                rawLogHtml += rawLogs.map(renderLogRow).join("");
            }
            if (zeekLogs.length > 0) {
                rawLogHtml += `<hr><div style="font-weight:600;margin-bottom:4px;">Zeek 網路日誌（${zeekLogs.length} 筆）</div>`;
                rawLogHtml += zeekLogs.map(renderLogRow).join("");
            }
            if (rawLogs.length === 0 && zeekLogs.length === 0) {
                rawLogHtml += `<div style="color:#9ca3af;">無原始紀錄</div>`;
            }

            $("#rawLog").html(rawLogHtml).data('full-html', rawLogHtml).data('ip', ip);
            $('#ipDetailModal').modal('show');
        },
        error: function (xhr, status, error) {
            console.error("AJAX Error: " + status + error);
            alert('載入詳細資訊失敗');
        }
    });
});

// 原始 Log「詳細」按鈕：以較大的彈窗顯示完整原始 Log
$('#btnRawLogDetail').on('click', function () {
    const ip = $('#rawLog').data('ip') || '';
    $('#fullLogModal .modal-title').text('原始 Log 詳細內容 — ' + ip);
    $('#fullLogModal .modal-body').html(
        `<div style="white-space:pre-wrap;font-family:'Consolas','Fira Code',monospace;font-size:0.8rem;background:#f8fafc;color:#1c2a3a;padding:12px;border-radius:6px;border:1px solid #d0d7e3;line-height:1.6;">${$('#rawLog').data('full-html') || ''}</div>`
    );
    $('#fullLogModal').modal('show');
});

// 251125 RU 防護日誌更新
$(document).ready(function () {
    const ROWS_PER_PAGE = 10;
    let currentPage = 0;

    // 載入日誌（支援時間區間）
    function loadElkLogs(page = 0, start = '', end = '') {
        currentPage = page;
        // 如果 start 或 end 是空字串，就傳 null 讓 PHP 更容易判斷
        const s = start.trim() === '' ? '' : start.trim();
        const e = end.trim() === '' ? '' : end.trim();

        $('#elkTable tbody').html('<tr><td colspan="6" class="text-center py-4"><div class="spinner-border spinner-border-sm"></div> 載入中...</td></tr>');

        $.get('get_ELK_detail.php', {
            page: page,
            page_size: ROWS_PER_PAGE,
            start_datetime: s,
            end_datetime: e
        }, function (res) {
            if (res.success && res.hits && res.hits.length > 0) {
                renderTable(res.hits);
            } else {
                $('#elkTable tbody').html('<tr><td colspan="6" class="text-center text-muted py-5">無符合條件的日誌</td></tr>');
                $('#elkPagination').empty();
            }
        }, 'json').fail(function () {
            $('#elkTable tbody').html('<tr><td colspan="6" class="text-center text-danger py-5">載入失敗，請檢查網路或伺服器</td></tr>');
        });
    }

    // 渲染表格
    function renderTable(hits) {
        let html = '';
        hits.forEach(hit => {
            const s = hit._source;
            const time = s['@timestamp'] ? new Date(s['@timestamp']).toLocaleString('zh-TW', {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit', second: '2-digit',
                hour12: false, timeZone: 'Asia/Taipei'
            }).replace(/\//g, '-').replace(/[, ]/g, ' ') : 'N/A';

            const agent = s.agent?.name || 'N/A';
            // const ip = s.client_ip || 'N/A';
            // const msg = s.message || 'N/A';
            const ip =
                s.client_ip ||
                s.src_ip ||
                s.dst_ip ||
                'N/A';
            const msg =
                s.event?.original ||
                s.message ||
                'N/A';
            const shortMsg = msg.length > 150 ? msg.substring(0, 147) + '...' : msg;
            const safeMsg = msg.replace(/"/g, '&quot;').replace(/'/g, '&#39;');

            html += `
                <tr class="text-center align-middle">
                    <td>${time}</td>
                    <td>${agent}</td>
                    <td>${ip}</td>
                    <td class="log-content-cell text-start" style="cursor:pointer;" data-full-log="${safeMsg}">
                        <span class="d-inline-block w-100">${shortMsg}</span>
                    </td>
                </tr>`;
        });
        $('#elkTable tbody').html(html);
    }

    // 點擊 Log 顯示完整內容
    $('#elkTable').on('click', '.log-content-cell', function () {
        const full = $(this).data('full-log');
        $('#fullLogModal .modal-title').text('完整 Log 內容');
        $('#fullLogModal .modal-body').html(
            `<pre style="white-space: pre-wrap; word-break: break-all; background:#f8f9fa; padding:15px; border-radius:8px; max-height:70vh; overflow-y:auto;">${full}</pre>`
        );
        $('#fullLogModal').modal('show');
    });

    // 上一頁
    $(document).on('click', '#btnPrevElk', function () {
        if (currentPage > 0) {
            const start = $('#start_datetime').val().trim();
            const end = $('#end_datetime').val().trim();
            loadElkLogs(currentPage - 1, start, end);
        }
    });

    // 下一頁
    $(document).on('click', '#btnNextElk', function () {
        const start = $('#start_datetime').val().trim();
        const end = $('#end_datetime').val().trim();
        loadElkLogs(currentPage + 1, start, end);
    });

    // 查詢按鈕
    $('#elk-query-form').on('submit', function (e) {
        e.preventDefault();

        let start = $('#start_datetime').val().trim();
        let end = $('#end_datetime').val().trim();

        // 簡單驗證
        if (start && end && start > end) {
            alert('開始時間不能晚於結束時間！');
            return;
        }

        loadElkLogs(0, start, end);
    });

    // 頁面載入完成後執行
    setDefaultTimeRange();

    // 預設時間：最近 5 分鐘
    function setDefaultTimeRange() {
        // 如果使用者已經手動填過時間，就不要覆蓋
        if ($('#start_datetime').val() && $('#end_datetime').val()) {
            setTimeout(() => loadElkLogs(0, $('#start_datetime').val(), $('#end_datetime').val()), 100);
            return;
        }

        const now = new Date();
        const fiveMinutesAgo = new Date(now);
        fiveMinutesAgo.setMinutes(now.getMinutes() - 5);  // 往前推 5 分鐘

        const formatForInput = (d) => {
            const yyyy = d.getFullYear();
            const mm = String(d.getMonth() + 1).padStart(2, '0');
            const dd = String(d.getDate()).padStart(2, '0');
            const hh = String(d.getHours()).padStart(2, '0');
            const min = String(d.getMinutes()).padStart(2, '0');
            return `${yyyy}-${mm}-${dd}T${hh}:${min}`;
        };

        const startStr = formatForInput(fiveMinutesAgo);
        const endStr = formatForInput(now);

        $('#start_datetime').val(startStr);
        $('#end_datetime').val(endStr);
        loadElkLogs(0, startStr, endStr);
    }
});

$("#btnAnalyzeLog").click(function () {
    let log = $("#logInput").val().trim();

    if (!log) {
        alert("請輸入 log");
        return;
    }

    $("#aiResult").text("分析中...");

    $.ajax({
        url: "analyze_log.php",
        method: "POST",
        data: {
            log:       log,
            other_ip:  $("#logOtherIp").val().trim(),
            local_ip:  $("#logLocalIp").val().trim(),
            direction: $("#logDirection").val()
        },
        success: function (res, status, xhr) {
            console.log("AJAX success, res =", res); // ✅ 印出完整回傳
            console.log("XHR object:", xhr);
            try {
                // 嘗試解析 JSON，如果失敗就顯示原始文字
                let data;
                try {
                    data = typeof res === "object" ? res : JSON.parse(res);
                } catch (e) {
                    $("#aiResult").html(`<pre>回傳非 JSON:\n${res}</pre>`);
                    return;
                }
                let info = data.data;

                /* 顏色只看 danger_level */
                let color = "green";

                if (info.danger_level === "危險") {
                    color = "red";
                } else if (info.danger_level === "可疑") {
                    color = "orange";
                } else {
                    color = "green";
                }

                let confText = info.confidence != null
                    ? `${(info.confidence * 100).toFixed(0)}%`
                    : "—";

                let html = `
<div style="color:${color}">

    <b>分析依據：</b><br>${info.analysis_basis?.join("<br>") || "無"}<br><br>

    <b>整體行為：</b>${info.overall_behavior || "無"}<br>
    <b>危險程度：</b>${info.danger_level || "未知"}<br>
    <b>信心度：</b>${confText}<br>
    <b>攻擊類型：</b>${info.attack_type || "無"}<br>
    <b>攻擊方式：</b>${info.attack_method || "無"}<br>
    <b>原因：</b>${info.reason || "無"}<br>

</div>
`;

                $("#aiResult").html(html);

                /* 新攻擊類型 → 加入待審核列表 */
                if (data.type === "new_attack_saved") {
                    showToast("✓ 新攻擊類型已加入待審核，請到『待審核』頁籤確認", "success");
                    loadPendingAttacks();
                }

            } catch (e) {
                $("#aiResult").text("分析失敗：" + JSON.stringify(res));
            }
        },
        error: function (xhr, status, err) {
            console.log("STATUS:", status);
            console.log("ERROR:", err);
            console.log("RAW RESPONSE:");
            console.log(xhr.responseText);
        }
    });
});

// ============ 待審核攻擊管理 ============

/**
 * 加載待審核攻擊列表
 */
function loadPendingAttacks() {
    $.ajax({
        url: "get_pending_attacks.php",
        method: "GET",
        dataType: "json",
        success: function (attacks) {
            renderPendingAttacksList(attacks);
        },
        error: function () {
            $("#pendingAttacksContainer").html("<div class='alert alert-danger'>載入失敗</div>");
        }
    });
}

/**
 * 渲染待審核攻擊列表
 */
function renderPendingAttacksList(attacks) {
    if (!attacks || attacks.length === 0) {
        $("#pendingAttacksContainer").html("<div class='alert alert-info'>沒有待審核的攻擊</div>");
        $("#pendingCount").hide();
        return;
    }

    $("#pendingCount").text(attacks.length).show();

    let html = '<div class="list-group">';
    attacks.forEach(function (attack) {
        const ipBadge = attack.ip ? `<span class="badge bg-secondary ms-2" style="font-size:0.7rem;">${attack.ip}</span>` : '';
        html += `
            <div class="list-group-item">
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <div>
                        <h6 class="mb-1">
                            <strong>${attack.attack_type || '未知'}</strong>${ipBadge}
                        </h6>
                        <p class="mb-1"><small class="text-muted">時間：${attack.created_time || '—'}</small></p>
                    </div>
                </div>
                <p class="mb-2"><small><strong>攻擊方式：</strong>${attack.attack_method || '—'}</small></p>
                <p class="mb-2"><small><strong>判斷原因：</strong>${attack.reason || '—'}</small></p>
                <div class="btn-group mt-2" role="group">
                    <button type="button" class="btn btn-sm btn-success btn-approve-attack" data-attack-id="${attack.id}">批准加入</button>
                    <button type="button" class="btn btn-sm btn-danger btn-reject-attack" data-attack-id="${attack.id}">拒絕</button>
                </div>
            </div>
        `;
    });
    html += '</div>';
    $("#pendingAttacksContainer").html(html);
}

/**
 * 加載已知攻擊列表
 */
function loadKnownAttacks() {
    $.ajax({
        url: "get_known_attacks.php",
        method: "GET",
        dataType: "json",
        success: function (attacks) {
            renderKnownAttacksList(attacks);
        },
        error: function () {
            $("#knownAttacksContainer").html("<div class='alert alert-danger'>載入失敗</div>");
        }
    });
}

/**
 * 渲染已知攻擊列表
 */
function renderKnownAttacksList(attacks) {
    if (!attacks || attacks.length === 0) {
        $("#knownAttacksContainer").html("<div class='alert alert-info'>尚未有已知攻擊</div>");
        return;
    }

    let html = '<div class="accordion" id="knownAttacksAccordion">';
    attacks.forEach(function (attack, index) {
        const collapseId = `collapseKnown${index}`;
        const headingId  = `headingKnown${index}`;

        html += `
            <div class="accordion-item">
                <h2 class="accordion-header" id="${headingId}">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                        data-bs-target="#${collapseId}" aria-expanded="false" aria-controls="${collapseId}">
                        <strong>${attack.attack_type || '未知'}</strong>
                    </button>
                </h2>
                <div id="${collapseId}" class="accordion-collapse collapse"
                    aria-labelledby="${headingId}" data-bs-parent="#knownAttacksAccordion">
                    <div class="accordion-body" style="font-size:0.82rem;">
                        <p class="mb-1 text-muted">加入時間：${attack.created_time || '—'}</p>
                        <p class="mb-2"><strong>攻擊方式：</strong>${attack.attack_method || '—'}</p>
                        <p class="mb-0"><strong>判斷原因：</strong>${attack.reason || '—'}</p>
                    </div>
                </div>
            </div>
        `;
    });
    html += '</div>';
    $("#knownAttacksContainer").html(html);
}

/**
 * 批准或拒絕攻擊
 */
$(document).on('click', '.btn-approve-attack, .btn-reject-attack', function () {
    const $btn = $(this);
    const attackId = $btn.data('attack-id');
    const action = $btn.hasClass('btn-approve-attack') ? 'approve' : 'reject';
    const actionText = action === 'approve' ? '批准' : '拒絕';

    if (!confirm(`確定要${actionText}這個攻擊嗎？`)) {
        return;
    }

    $.ajax({
        url: "approve_attack.php",
        method: "POST",
        data: {
            attack_id: attackId,
            action: action
        },
        dataType: "json",
        success: function (response) {
            if (response.success) {
                showToast(`✓ ${response.message}`, "success");
                loadPendingAttacks(); // 重新載入列表
            } else {
                showToast(`✗ ${response.error}`, "danger");
            }
        },
        error: function () {
            showToast("操作失敗，請稍後重試", "danger");
        }
    });
});

let latestTodayData = null;

function refreshDashboard() {
    Promise.all([
        fetch('get_dashboard_data.php').then(r => r.json()),
        fetch('get_dashboard_today.php').then(r => r.json())
    ]).then(([dashboardData, todayData]) => {
        latestTodayData = todayData;

        // ── Stat Cards ────────────────────────────────────────────
        $('#statTotal').text(todayData.totalBlocked);
        $('#statPublic').text(todayData.publicBlacklisted);
        $('#statLLMHigh').text(todayData.llmHighBlocked);
        $('#statLLMMid').text(todayData.llmMidBlocked);
        $('#statRepeated').text(todayData.repeatedIPs);
        $('#statSubnets').text(todayData.suspiciousSubnetCount);

        const hostSummary = Object.entries(todayData.hostBlockedCounts)
            .map(([host, cnt]) => `${host} ${cnt} 個`)
            .join('、');
        $('#ipSummary').text(
            `今日封鎖 ${todayData.totalBlocked} 筆` + (hostSummary ? `（${hostSummary}）` : '')
        );

        // ── 疑似攻擊網段表格 ──────────────────────────────────────
        const subnetBody = $('#subnetTableBody');
        subnetBody.empty();
        const subnets = todayData.suspiciousSubnets || {};
        if (Object.keys(subnets).length > 0) {
            $('#subnetSectionHeader').show();
            $('#subnetTableWrap').show();
            for (const [subnet, data] of Object.entries(subnets)) {
                const shown = data.ips.slice(0, 2);
                const rest  = data.ips.slice(2);
                const restHtml = rest.length
                    ? `<span class="text-muted" style="font-size:0.7rem;cursor:default;" title="${rest.join('\n')}"> +${rest.length} 個</span>`
                    : '';
                const ipsHtml = shown.join('、') + restHtml;
                const types = data.types.length ? data.types.join('、') : '—';
                const hosts = data.hosts.length ? [...new Set(data.hosts)].join('、') : '—';
                subnetBody.append(`
                    <tr>
                        <td class="text-center fw-bold" style="font-family:monospace;color:#dc2626;">${subnet}</td>
                        <td class="text-center">
                            <span class="badge bg-danger">${data.count}</span>
                        </td>
                        <td style="font-family:monospace;font-size:0.78rem;">${ipsHtml}</td>
                        <td style="font-size:0.78rem;">${types}</td>
                        <td style="font-size:0.78rem;">${hosts}</td>
                    </tr>
                `);
            }
        } else {
            $('#subnetSectionHeader').hide();
            $('#subnetTableWrap').hide();
        }

        // ── 7天趨勢圖（stacked column）────────────────────────────
        const dates = Object.keys(dashboardData.trend);
        let allTypes = Array.from(new Set(
            dates.flatMap(d => Object.keys(dashboardData.trend[d]))
        )).sort();

        const trendSeries = allTypes.map(type => ({
            name: type,
            data: dates.map(d => dashboardData.trend[d][type] || 0)
        }));

        const trendChart = Highcharts.charts.find(c => c && c.renderTo.id === 'attackTypeChart');
        if (!trendChart) {
            Highcharts.chart('attackTypeChart', {
                chart: { type: 'column', style: { fontFamily: 'Inter, sans-serif' } },
                title: { text: null },
                credits: { enabled: false },
                xAxis: { categories: dates.map(d => d.slice(5)) },
                yAxis: { min: 0, title: { text: '封鎖次數' }, stackLabels: { enabled: true } },
                plotOptions: { column: { stacking: 'normal', borderRadius: 3 } },
                tooltip: {
                    shared: true,
                    formatter: function () {
                        const pts = this.points.filter(p => p.y > 0).sort((a, b) => b.y - a.y);
                        if (!pts.length) return false;
                        let s = `<b>${this.x}</b><br/>`;
                        pts.forEach(p => {
                            s += `<span style="color:${p.color}">●</span> ${p.series.name}: <b>${p.y}</b><br/>`;
                        });
                        return s;
                    }
                },
                legend: { itemStyle: { fontSize: '0.72rem' } },
                series: trendSeries
            });
        } else {
            while (trendChart.series.length) trendChart.series[0].remove(false);
            trendSeries.forEach(s => trendChart.addSeries(s, false));
            trendChart.xAxis[0].setCategories(dates.map(d => d.slice(5)), false);
            trendChart.redraw();
        }

        // ── 今日攻擊手法圓餅圖 ───────────────────────────────────
        const pieData = Object.entries(todayData.attackTypeToday || {})
            .map(([name, y]) => ({ name, y }));

        const pieChart = Highcharts.charts.find(c => c && c.renderTo.id === 'attackTypePie');
        if (!pieChart) {
            Highcharts.chart('attackTypePie', {
                chart: { type: 'pie', style: { fontFamily: 'Inter, sans-serif' } },
                title: { text: null },
                credits: { enabled: false },
                tooltip: {
                    pointFormat: '<b>{point.name}</b>: {point.y} 筆 ({point.percentage:.1f}%)'
                },
                plotOptions: {
                    pie: {
                        allowPointSelect: true,
                        cursor: 'pointer',
                        dataLabels: {
                            enabled: true,
                            format: '<b>{point.name}</b>: {point.y}',
                            style: { fontSize: '0.72rem' }
                        }
                    }
                },
                series: [{ name: '攻擊手法', colorByPoint: true, data: pieData }]
            });
        } else {
            pieChart.series[0].setData(pieData, true);
        }

    }).catch(err => console.error('載入資料失敗:', err));
}

// 🔁 每30秒更新
setInterval(refreshDashboard, 30000);

// 🔹 首次載入
refreshDashboard();

// ─────────────────────────────────────────────
// 今日封鎖 Stat Card 點擊展開明細
// ─────────────────────────────────────────────

const STAT_LABELS = {
    total:   '今日新增封鎖 — 所有封鎖 IP',
    public:  '公開黑名單命中 — Threat Intel Feed',
    llmHigh: 'LLM 高信心封鎖 — 系統研判 >80%',
    llmMid:  'LLM 中信心封鎖 — 系統研判 ≤80%',
    repeated:'重複攻擊 IP — 今日多筆紀錄',
    subnets: '疑似攻擊網段 — /24 多 IP 命中',
};

function renderStatDetail(key) {
    if (!latestTodayData) return;
    const data = latestTodayData;
    const ipCounts = data.ipCounts || {};

    if (key === 'subnets') {
        $('#statDetailPanel').hide();
        $('.today-stat-btn').removeClass('active');
        $(`.today-stat-btn[data-stat="subnets"]`).addClass('active');
        const $header = $('#subnetSectionHeader');
        if ($header.length) {
            $('html, body').animate({ scrollTop: $header.offset().top - 80 }, 300);
        }
        return;
    }

    let rows = Object.values(data.ipUniqueList || {});

    if (key === 'public') {
        rows = rows.filter(r => (r.attack_type || '').trim() === '已知惡意IP');
    } else if (key === 'llmHigh') {
        rows = rows.filter(r => r.status === '黑名單' && (r.attack_type || '').trim() !== '已知惡意IP');
    } else if (key === 'llmMid') {
        rows = rows.filter(r => r.status === 'LLM黑名單');
    } else if (key === 'repeated') {
        rows = rows.filter(r => (ipCounts[r.ip] || 1) > 1);
    }

    const statusBadge = s => {
        if (s === '黑名單') return `<span class="badge bg-danger">${s}</span>`;
        if (s === 'LLM黑名單') return `<span class="badge bg-warning text-dark">${s}</span>`;
        return `<span class="badge bg-secondary">${s}</span>`;
    };

    const tbody = $('#statDetailBody');
    tbody.empty();
    if (rows.length === 0) {
        tbody.append('<tr><td colspan="7" class="text-center text-muted py-3">無資料</td></tr>');
    } else {
        rows.forEach(r => {
            const cnt = ipCounts[r.ip] || 1;
            tbody.append(`
                <tr>
                    <td style="font-family:monospace;font-size:0.82rem;">${r.ip}</td>
                    <td style="font-size:0.78rem;">${r.hostname || '—'}</td>
                    <td style="font-size:0.78rem;">${r.attack_type || '—'}</td>
                    <td class="text-center">${statusBadge(r.status)}</td>
                    <td style="font-size:0.78rem;white-space:nowrap;">${r.first_time || '—'}</td>
                    <td style="font-size:0.78rem;white-space:nowrap;">${r.last_time || '—'}</td>
                    <td class="text-center">${cnt > 1 ? `<span class="badge bg-warning text-dark">${cnt}</span>` : cnt}</td>
                </tr>
            `);
        });
    }

    $('#statDetailTitle').text(`${STAT_LABELS[key]}（共 ${rows.length} 筆）`);
    $('#statDetailPanel').show();
}

$(document).on('click', '.today-stat-btn', function () {
    const key = $(this).data('stat');
    const wasActive = $(this).hasClass('active');
    $('.today-stat-btn').removeClass('active');
    if (wasActive) {
        $('#statDetailPanel').hide();
        return;
    }
    $(this).addClass('active');
    renderStatDetail(key);
});

$('#statDetailClose').on('click', function () {
    $('#statDetailPanel').hide();
    $('.today-stat-btn').removeClass('active');
});

// ─────────────────────────────────────────────
// 模型評估（eval）
// ─────────────────────────────────────────────

// 各指標的說明文字（滑鼠移到 ? 時顯示）
const EVAL_TIPS = {
    precision: 'Precision（精確率）：LLM 判斷為「危險」的 IP 中，真正是攻擊的比例。\n越高 = 誤報越少。\n計算：TP ÷ (TP + FP)',
    recall:    'Recall（召回率）：所有真實攻擊 IP 中，LLM 成功抓到的比例。\n越高 = 漏報越少。\n計算：TP ÷ (TP + FN)',
    f1:        'F1 Score：Precision 和 Recall 的調和平均。\n兩者都要高才能拿到高 F1，是綜合評量的主要指標。\n計算：2 × P × R ÷ (P + R)',
    fpr:       'FPR（False Positive Rate，誤報率）：正常 IP 中被 LLM 誤判為危險的比例。\n越低越好，高 FPR 代表會誤封合法使用者。\n計算：FP ÷ (FP + TN)',
    mcc:         'MCC（Matthews Correlation Coefficient，馬修相關係數）：\n即使 Attack 和 Benign 樣本數量嚴重不平衡，MCC 仍能公正評估模型。\n範圍 -1 到 +1，0 代表隨機猜測，1 代表完美，比 Accuracy 更可靠。',
    specificity: 'Specificity（特異性 / TNR，True Negative Rate）：正常 IP 中被正確放行的比例，等於 1 − FPR。\n越高越好，代表對合法使用者影響越小。\n計算：TN ÷ (TN + FP)',
    total:       'Eval 筆數：eval_results 資料表中累積的評估紀錄總數（含 Attack + Benign 兩類）。\n樣本越多，指標越可靠。建議至少 100 筆以上才有統計意義。',
    dist:      'Attack / Benign 樣本分布：\nAttack = 命中 2+ 個獨立公開黑名單的 IP（Spamhaus / FireHOL / DShield）\nBenign 有兩個來源：\n  ① 白名單 IP 隨機抽樣 50%（gt_source=whitelist）\n  ② 管理員手動標記誤判的 IP（gt_source=fp_report，如 claude.ai）\n兩者數量差越小，評估越可信。',
};

function makeTip(key) {
    const tip = EVAL_TIPS[key] || '';
    return `<span class="metric-help" data-bs-toggle="tooltip" data-bs-placement="top" data-bs-trigger="hover" title="${tip.replace(/\n/g, '&#10;')}">?</span>`;
}

function initTooltips(container) {
    (container || document).querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
        bootstrap.Tooltip.getOrCreateInstance(el, { html: false });
    });
}

function fmtPct(v) { return v !== null && v !== undefined ? (v * 100).toFixed(1) + '%' : '—'; }
function fmtNum(v) { return v !== null && v !== undefined ? parseFloat(v).toFixed(4)      : '—'; }

function loadEvalResults() {
    // 每次載入都刷新趨勢圖（加 ts 避免快取，確保拿到最新產出的 PNG）
    const trendImg = document.getElementById('evalTrendImg');
    if (trendImg) trendImg.src = 'get_eval_chart.php?name=trend_over_time&t=' + Date.now();

    const cards  = document.getElementById('evalMetricCards');
    const tbody  = document.getElementById('evalRecordsBody');
    const best   = document.getElementById('evalBestSweep');
    const banner = document.getElementById('evalTrendBanner');

    cards.innerHTML = '<div class="text-center py-3"><div class="spinner-border spinner-border-sm"></div> 載入中...</div>';
    banner.style.display = 'none';

    fetch('get_eval_results.php')
        .then(r => r.json())
        .then(data => {
            if (!data.success) { cards.innerHTML = '<div class="text-danger p-3">載入失敗</div>'; return; }

            const s = data.summary;

            // ── 趨勢警示橫幅（從 tuning_config）
            const t = data.tuning;
            if (t) {
                const trendIcon  = { improving: '↗', stable: '→', declining: '↘' };
                const trendColor = { improving: 'success', stable: 'warning', declining: 'danger' };
                const mccTrend    = t.mcc_trend    || 'stable';
                const recallTrend = t.recall_trend || 'stable';
                const bannerLevel = (mccTrend === 'declining' || recallTrend === 'declining') ? 'danger'
                                  : (mccTrend === 'improving' && recallTrend === 'improving') ? 'success'
                                  : 'warning';
                const bannerTitle = bannerLevel === 'danger'  ? '⚠ 模型效能下降中，已自動強化漏報矯正'
                                  : bannerLevel === 'success' ? '✓ 模型效能持續改善'
                                  : '模型效能穩定';

                banner.innerHTML = `
                <div class="alert alert-${bannerLevel} py-2 px-3 mb-0 d-flex align-items-center flex-wrap gap-3" style="font-size:0.82rem;border-radius:6px;">
                    <strong>${bannerTitle}</strong>
                    <span class="d-flex align-items-center gap-2 ms-auto flex-wrap">
                        <span class="badge bg-${trendColor[mccTrend]}">
                            MCC ${trendIcon[mccTrend]} ${mccTrend} &nbsp;${t.last_mcc !== undefined ? parseFloat(t.last_mcc).toFixed(4) : ''}
                        </span>
                        <span class="badge bg-${trendColor[recallTrend]}">
                            Recall ${trendIcon[recallTrend]} ${recallTrend} &nbsp;${t.last_recall !== undefined ? (parseFloat(t.last_recall)*100).toFixed(1)+'%' : ''}
                        </span>
                        <span class="badge bg-secondary">漏報矯正範例 fn_limit = ${t.fn_limit}</span>
                        <span class="badge bg-secondary">誤報矯正範例 fp_limit = ${t.fp_limit}</span>
                        <small class="text-muted">更新：${t.last_updated || '—'}</small>
                    </span>
                </div>`;
                banner.style.display = '';
            }

            // ── 指標卡片（含 (?) tooltip）
            const metrics = [
                { key: 'precision',   label: 'Precision',          value: fmtPct(s.precision),   color: 'success',   textColor: 'success'   },
                { key: 'recall',      label: 'Recall',             value: fmtPct(s.recall),       color: 'primary',   textColor: 'primary'   },
                { key: 'f1',          label: 'F1 Score',           value: fmtPct(s.f1),           color: 'info',      textColor: 'info'      },
                { key: 'fpr',         label: 'FPR',                value: fmtPct(s.fpr),          color: 'warning',   textColor: 'warning'   },
                { key: 'specificity', label: 'Specificity (1−FPR)', value: fmtPct(s.specificity), color: 'primary',   textColor: 'primary'   },
                { key: 'mcc',         label: 'MCC',                value: fmtNum(s.mcc),          color: 'secondary', textColor: 'secondary' },
                { key: 'total',       label: 'Eval 筆數',          value: s.total,                color: 'secondary', textColor: 'secondary' },
                { key: 'dist',        label: 'Attack / Benign',    value: `${s.n_attack} / ${s.n_benign}`, color: 'secondary', textColor: 'secondary' },
            ];

            cards.innerHTML = `<div class="col-12"><div class="row g-3">` +
                metrics.map(m => `
                <div class="col-6 col-md-4 col-lg-3 col-xl-2">
                    <div class="card text-center h-100 border-${m.color}">
                        <div class="card-body py-3 px-2">
                            <div class="fs-4 fw-bold text-${m.textColor} mb-1">${m.value}</div>
                            <div class="metric-label-row small text-muted">${m.label}${makeTip(m.key)}</div>
                        </div>
                    </div>
                </div>`).join('') +
            `</div></div>`;

            // ── 樣本分布 progress bar
            const total = s.n_attack + s.n_benign;
            if (total > 0) {
                const atkPct = ((s.n_attack / total) * 100).toFixed(1);
                const benPct = (100 - parseFloat(atkPct)).toFixed(1);
                cards.innerHTML += `
                <div class="col-12 mt-2">
                    <div class="d-flex align-items-center gap-2">
                        <small class="text-muted text-nowrap">樣本分布</small>
                        <div class="progress flex-grow-1" style="height:10px">
                            <div class="progress-bar bg-danger" style="width:${atkPct}%"
                                data-bs-toggle="tooltip" title="Attack ${s.n_attack} 筆 (${atkPct}%)"></div>
                            <div class="progress-bar bg-success" style="width:${benPct}%"
                                data-bs-toggle="tooltip" title="Benign ${s.n_benign} 筆 (${benPct}%)"></div>
                        </div>
                        <small class="text-danger text-nowrap">⬛ Attack</small>
                        <small class="text-success text-nowrap">⬛ Benign</small>
                    </div>
                </div>`;
            }
            initTooltips(cards);

            // ── 混淆矩陣（累積）
            const cmSection = document.getElementById('evalConfusionSection');
            cmSection.style.display = '';
            document.getElementById('cm_tp').textContent = `${s.TP}`;
            document.getElementById('cm_fp').textContent = `${s.FP}`;
            document.getElementById('cm_fn').textContent = `${s.FN}`;
            document.getElementById('cm_tn').textContent = `${s.TN}`;

            // ── 每日明細
            const dailyBody = document.getElementById('evalDailyBody');
            const dailyRows = data.daily || [];
            if (dailyRows.length > 0) {
                dailyBody.innerHTML = dailyRows.map((r, idx) => {
                    const isMccDown = idx < dailyRows.length - 1 && r.mcc !== null && dailyRows[idx+1].mcc !== null
                                    && r.mcc < dailyRows[idx+1].mcc;
                    return `<tr>
                        <td><strong>${r.date}</strong></td>
                        <td class="text-success">${r.TP}</td>
                        <td class="text-danger">${r.FP}</td>
                        <td class="text-warning">${r.FN}</td>
                        <td class="text-secondary">${r.TN}</td>
                        <td>${r.recall !== null ? (r.recall*100).toFixed(1)+'%' : '—'}</td>
                        <td class="${isMccDown ? 'text-danger fw-bold' : ''}">
                            ${r.mcc !== null ? parseFloat(r.mcc).toFixed(4) : '—'}${isMccDown ? ' ↘' : ''}
                        </td>
                        <td class="text-muted">${r.n_total}</td>
                    </tr>`;
                }).join('');
            } else {
                dailyBody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">尚無每日快照資料</td></tr>';
            }

            // ── 最佳 sweep 結果
            const sweepSection = document.getElementById('evalSweepSection');
            if (data.best_sweep) {
                sweepSection.style.display = '';
                const b = data.best_sweep;
                best.innerHTML = `
                    <div class="row g-2 text-center mb-2">
                        <div class="col"><div class="fw-bold">${b.threshold}</div><div class="small text-muted">Threshold</div></div>
                        <div class="col"><div class="fw-bold text-success">${(b.precision*100).toFixed(1)}%</div><div class="small text-muted">Precision${makeTip('precision')}</div></div>
                        <div class="col"><div class="fw-bold text-primary">${(b.recall*100).toFixed(1)}%</div><div class="small text-muted">Recall${makeTip('recall')}</div></div>
                        <div class="col"><div class="fw-bold text-info">${(b.f1*100).toFixed(1)}%</div><div class="small text-muted">F1${makeTip('f1')}</div></div>
                        <div class="col"><div class="fw-bold text-warning">${(b.fpr*100).toFixed(1)}%</div><div class="small text-muted">FPR${makeTip('fpr')}</div></div>
                        ${b.specificity !== undefined ? `<div class="col"><div class="fw-bold text-primary">${(b.specificity*100).toFixed(1)}%</div><div class="small text-muted">Specificity${makeTip('specificity')}</div></div>` : ''}
                        ${b.mcc !== undefined ? `<div class="col"><div class="fw-bold text-secondary">${parseFloat(b.mcc).toFixed(3)}</div><div class="small text-muted">MCC${makeTip('mcc')}</div></div>` : ''}
                    </div>
                    <div class="text-muted small mb-2">scope: ${b.scope} ｜ TP=${b.TP} FP=${b.FP} FN=${b.FN} TN=${b.TN}</div>`;

                const sweepRows = (data.sweep || []).filter(r => r.scope === '危險only');
                if (sweepRows.length > 0) {
                    const bestThr = b.threshold;
                    best.innerHTML += `
                    <div class="small text-muted mb-1">各 Confidence 閾值掃描（scope: 危險only）</div>
                    <div class="table-responsive">
                        <table class="table table-sm table-hover mb-0" style="font-size:0.78rem;">
                            <thead class="table-dark">
                                <tr><th>Threshold</th><th>Precision</th><th>Recall</th><th class="fw-bold">F1</th><th>FPR</th><th>MCC</th><th>TP / FP / FN / TN</th></tr>
                            </thead>
                            <tbody>
                                ${sweepRows.map(r => {
                                    const isBest = r.threshold === bestThr;
                                    return `<tr class="${isBest ? 'table-success fw-bold' : ''}">
                                        <td>${r.threshold.toFixed(2)}${isBest ? ' ★' : ''}</td>
                                        <td>${(r.precision*100).toFixed(1)}%</td>
                                        <td>${(r.recall*100).toFixed(1)}%</td>
                                        <td>${(r.f1*100).toFixed(1)}%</td>
                                        <td>${(r.fpr*100).toFixed(1)}%</td>
                                        <td>${parseFloat(r.mcc).toFixed(3)}</td>
                                        <td><small>${r.TP} / ${r.FP} / ${r.FN} / ${r.TN}</small></td>
                                    </tr>`;
                                }).join('')}
                            </tbody>
                        </table>
                    </div>`;
                }
                initTooltips(best);
            }

            // ── 近期紀錄
            const verdictBadge = { TP: 'bg-success', FP: 'bg-danger', FN: 'bg-warning text-dark', TN: 'bg-secondary' };
            const verdictLabel = { TP: '✓ TP 正確攔截', FP: '✗ FP 誤報', FN: '✗ FN 漏報', TN: '✓ TN 正確放行' };
            const levelBadge   = { '危險': 'bg-danger', '可疑': 'bg-warning text-dark', '正常': 'bg-success' };
            const gtLabel      = { openblacklist: '公開黑名單', whitelist: '白名單採樣', fp_report: '⚠ 管理員標記誤判' };

            tbody.innerHTML = (data.records || []).map(r => `
                <tr>
                    <td><code>${r.ip}</code></td>
                    <td><span class="badge ${r.true_label === 'attack' ? 'bg-danger' : 'bg-success'}">${r.true_label === 'attack' ? '⚠ attack' : '✓ benign'}</span></td>
                    <td><span class="badge ${levelBadge[r.danger_level] || 'bg-secondary'}">${r.danger_level || '—'}</span></td>
                    <td>${r.confidence !== null ? parseFloat(r.confidence).toFixed(2) : '—'}</td>
                    <td><small>${r.attack_type || '—'}</small></td>
                    <td><span class="badge ${verdictBadge[r.verdict] || 'bg-secondary'}" data-bs-toggle="tooltip"
                        title="${r.verdict === 'TP' ? '正確：攻擊被 LLM 判為危險' : r.verdict === 'TN' ? '正確：正常 IP 被 LLM 判為非危險' : r.verdict === 'FP' ? '錯誤：正常 IP 被誤判為危險（誤報）' : '錯誤：攻擊 IP 被 LLM 漏判（漏報）'}">${verdictLabel[r.verdict] || r.verdict}</span></td>
                    <td><small class="text-muted">${gtLabel[r.gt_source] || r.gt_source}</small></td>
                    <td><small>${r.analyzed_at}</small></td>
                </tr>`).join('');

            initTooltips(document.getElementById('evalRecordsBody'));
        })
        .catch(err => {
            cards.innerHTML = `<div class="text-danger p-3">錯誤：${err.message}</div>`;
        });
}

// ============ 弱點掃描（vuln-agent）分頁 ============
$(function () {
    const $pagination = $('#vulnTablePagination');
    const rowsPerPage = 10;

    let currentSearch = '';
    let currentSeverities = $('.vuln-severity-filter:checked').map(function () { return $(this).val(); }).get();
    let currentStatuses = $('.vuln-status-filter:checked').map(function () { return $(this).val(); }).get();

    const STATUS_LABELS = {
        pending: '待處理',
        confirmed: '已確認',
        false_positive: '誤判',
        resolved: '已解決'
    };
    const STATUS_BADGES = {
        pending: 'bg-secondary',
        confirmed: 'bg-danger',
        false_positive: 'bg-success',
        resolved: 'bg-primary'
    };
    const SEVERITY_BADGES = {
        '高': 'bg-danger',
        '中': 'bg-warning text-dark',
        '低': 'bg-info text-dark',
        '資訊': 'bg-secondary'
    };

    // 分頁渲染函式（與 ipRiskTable 相同邏輯）
    function renderVulnPagination(total, page) {
        const totalPages = Math.ceil(total / rowsPerPage);
        $pagination.empty();
        if (totalPages <= 1) return;

        let pages = [];
        if (totalPages <= 7) {
            for (let i = 0; i < totalPages; i++) pages.push(i);
        } else {
            pages.push(0);
            if (page > 3) pages.push('...');
            let start = Math.max(1, page - 2);
            let end = Math.min(totalPages - 2, page + 2);
            for (let i = start; i <= end; i++) pages.push(i);
            if (page < totalPages - 4) pages.push('...');
            pages.push(totalPages - 1);
        }

        pages.forEach(function (p) {
            if (p === '...') {
                $pagination.append('<li class="page-item disabled"><span class="page-link">…</span></li>');
            } else {
                $pagination.append(
                    `<li class="page-item ${p === page ? 'active' : ''}">
                        <a class="page-link" href="#" data-page="${p}">${p + 1}</a>
                    </li>`
                );
            }
        });

        $pagination.find('a[data-page]').click(function (e) {
            e.preventDefault();
            loadVulnFindings(parseInt($(this).data('page')));
        });
    }

    function renderVulnTable(data) {
        let html = '';
        if (data && data.length > 0) {
            data.forEach(function (row) {
                const statusKey = row.status || 'pending';
                html += `
                    <tr class="text-center">
                        <td>${row.target}${row.port ? ':' + row.port : ''}</td>
                        <td>${row.service || ''}${row.version ? ' ' + row.version : ''}</td>
                        <td>${row.source || ''}</td>
                        <td>${row.cve_id || '—'}</td>
                        <td class="text-start">${row.title || ''}</td>
                        <td><span class="badge ${SEVERITY_BADGES[row.severity] || 'bg-secondary'}">${row.severity || '—'}</span></td>
                        <td>${row.confidence !== null ? parseFloat(row.confidence).toFixed(2) : '—'}</td>
                        <td><span class="badge ${STATUS_BADGES[statusKey] || 'bg-secondary'}">${STATUS_LABELS[statusKey] || statusKey}</span></td>
                        <td><small>${row.scanned_at || ''}</small></td>
                        <td>
                            <button class="btn btn-sm btn-info btn-vuln-detail" data-id="${row.id}"
                                data-remediation="${encodeURIComponent(row.remediation || '')}"
                                data-evidence="${encodeURIComponent(row.evidence || '')}">詳細</button>
                            <button class="btn btn-sm btn-success btn-vuln-status" data-id="${row.id}" data-status="confirmed"
                                ${statusKey === 'confirmed' ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>確認</button>
                            <button class="btn btn-sm btn-outline-secondary btn-vuln-status" data-id="${row.id}" data-status="false_positive"
                                ${statusKey === 'false_positive' ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>誤判</button>
                            <button class="btn btn-sm btn-primary btn-vuln-status" data-id="${row.id}" data-status="resolved"
                                ${statusKey === 'resolved' ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>已解決</button>
                        </td>
                    </tr>`;
            });
        } else {
            html = '<tr><td colspan="10" class="text-center">無數據</td></tr>';
        }
        $('#vulnScanTable tbody').html(html);
    }

    window.loadVulnSummary = function () {
        $.ajax({
            url: 'get_vuln_summary.php',
            method: 'GET',
            dataType: 'json',
            success: function (res) {
                const sev = res.severity || {};
                $('#vulnStatTotal').text(res.total ?? '—');
                $('#vulnStatHigh').text(sev['高'] ?? 0);
                $('#vulnStatMid').text(sev['中'] ?? 0);
                $('#vulnStatLow').text((sev['低'] ?? 0) + (sev['資訊'] ?? 0));
                $('#vulnStatPending').text(res.pending ?? 0);
                $('#vulnStatTargets').text(res.affected_targets ?? 0);
                $('#vulnSummaryLastScan').text(
                    res.last_scan ? '最後掃描時間：' + res.last_scan : '尚無掃描紀錄'
                );
            },
            error: function () {
                showToast('弱點掃描總覽載入失敗', 'danger');
            }
        });
    };

    window.loadVulnFindings = function (page = 0) {
        $.ajax({
            url: 'get_vuln_findings.php',
            method: 'GET',
            data: {
                page: page,
                page_size: rowsPerPage,
                search: currentSearch,
                severities: currentSeverities.join(','),
                statuses: currentStatuses.join(',')
            },
            dataType: 'json',
            success: function (res) {
                renderVulnTable(res.data);
                renderVulnPagination(res.total, page);
            },
            error: function () {
                showToast('弱點掃描資料載入失敗', 'danger');
            }
        });
    };

    // 搜尋輸入（debounce）
    let vulnSearchDebounce = null;
    $('#vulnSearchInput').on('input', function () {
        clearTimeout(vulnSearchDebounce);
        const value = $(this).val().trim();
        vulnSearchDebounce = setTimeout(function () {
            currentSearch = value;
            loadVulnFindings(0);
        }, 500);
    });

    // 嚴重程度 / 狀態篩選
    $('.vuln-severity-filter, .vuln-status-filter').on('change', function () {
        currentSeverities = $('.vuln-severity-filter:checked').map(function () { return $(this).val(); }).get();
        currentStatuses = $('.vuln-status-filter:checked').map(function () { return $(this).val(); }).get();
        loadVulnFindings(0);
    });

    // 詳細 modal
    $('#vulnScanTable').on('click', '.btn-vuln-detail', function () {
        const remediation = decodeURIComponent($(this).data('remediation') || '');
        const evidence = decodeURIComponent($(this).data('evidence') || '');
        $('#vulnDetailRemediation').text(remediation || '（無建議）');
        $('#vulnDetailEvidence').text(evidence || '（無）');
        $('#vulnDetailModal').modal('show');
    });

    // 狀態變更
    $('#vulnScanTable').on('click', '.btn-vuln-status', function () {
        const $btn = $(this);
        const id = $btn.data('id');
        const status = $btn.data('status');

        $.ajax({
            url: 'update_vuln_status.php',
            method: 'POST',
            data: { id: id, status: status },
            dataType: 'json',
            success: function (res) {
                if (res.success) {
                    showToast('✅ 狀態已更新為「' + (STATUS_LABELS[status] || status) + '」', 'success');
                    loadVulnFindings(0);
                    loadVulnSummary();
                } else {
                    showToast('✗ 更新失敗：' + (res.message || ''), 'danger');
                }
            },
            error: function () {
                showToast('✗ 請求失敗，請稍後再試', 'danger');
            }
        });
    });
});

// ============ 原始碼掃描（vuln-agent）分頁 ============
$(function () {
    const $pagination = $('#codeTablePagination');
    const rowsPerPage = 10;

    let currentSearch = '';
    let currentSeverities = $('.code-severity-filter:checked').map(function () { return $(this).val(); }).get();
    let currentStatuses = $('.code-status-filter:checked').map(function () { return $(this).val(); }).get();

    const STATUS_LABELS = {
        pending: '待處理',
        confirmed: '已確認',
        false_positive: '誤判',
        resolved: '已解決'
    };
    const STATUS_BADGES = {
        pending: 'bg-secondary',
        confirmed: 'bg-danger',
        false_positive: 'bg-success',
        resolved: 'bg-primary'
    };
    const SEVERITY_BADGES = {
        '高': 'bg-danger',
        '中': 'bg-warning text-dark',
        '低': 'bg-info text-dark',
        '資訊': 'bg-secondary'
    };

    // 分頁渲染函式（與 vulnTable 相同邏輯）
    function renderCodePagination(total, page) {
        const totalPages = Math.ceil(total / rowsPerPage);
        $pagination.empty();
        if (totalPages <= 1) return;

        let pages = [];
        if (totalPages <= 7) {
            for (let i = 0; i < totalPages; i++) pages.push(i);
        } else {
            pages.push(0);
            if (page > 3) pages.push('...');
            let start = Math.max(1, page - 2);
            let end = Math.min(totalPages - 2, page + 2);
            for (let i = start; i <= end; i++) pages.push(i);
            if (page < totalPages - 4) pages.push('...');
            pages.push(totalPages - 1);
        }

        pages.forEach(function (p) {
            if (p === '...') {
                $pagination.append('<li class="page-item disabled"><span class="page-link">…</span></li>');
            } else {
                $pagination.append(
                    `<li class="page-item ${p === page ? 'active' : ''}">
                        <a class="page-link" href="#" data-page="${p}">${p + 1}</a>
                    </li>`
                );
            }
        });

        $pagination.find('a[data-page]').click(function (e) {
            e.preventDefault();
            loadCodeFindings(parseInt($(this).data('page')));
        });
    }

    function renderCodeTable(data) {
        let html = '';
        if (data && data.length > 0) {
            data.forEach(function (row) {
                const statusKey = row.status || 'pending';
                html += `
                    <tr class="text-center">
                        <td class="text-start"><code>${row.file_path}:${row.line_start}</code></td>
                        <td>${row.source || ''}</td>
                        <td><small>${row.rule_id || ''}</small></td>
                        <td class="text-start">${row.title || ''}</td>
                        <td><span class="badge ${SEVERITY_BADGES[row.severity] || 'bg-secondary'}">${row.severity || '—'}</span></td>
                        <td>${row.confidence !== null ? parseFloat(row.confidence).toFixed(2) : '—'}</td>
                        <td><span class="badge ${STATUS_BADGES[statusKey] || 'bg-secondary'}">${STATUS_LABELS[statusKey] || statusKey}</span></td>
                        <td><small>${row.scanned_at || ''}</small></td>
                        <td>
                            <button class="btn btn-sm btn-info btn-code-detail" data-id="${row.id}"
                                data-remediation="${encodeURIComponent(row.remediation || '')}"
                                data-evidence="${encodeURIComponent(row.evidence || '')}">詳細</button>
                            <button class="btn btn-sm btn-success btn-code-status" data-id="${row.id}" data-status="confirmed"
                                ${statusKey === 'confirmed' ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>確認</button>
                            <button class="btn btn-sm btn-outline-secondary btn-code-status" data-id="${row.id}" data-status="false_positive"
                                ${statusKey === 'false_positive' ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>誤判</button>
                            <button class="btn btn-sm btn-primary btn-code-status" data-id="${row.id}" data-status="resolved"
                                ${statusKey === 'resolved' ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>已解決</button>
                        </td>
                    </tr>`;
            });
        } else {
            html = '<tr><td colspan="9" class="text-center">無數據</td></tr>';
        }
        $('#codeScanTable tbody').html(html);
    }

    window.loadCodeSummary = function () {
        $.ajax({
            url: 'get_code_summary.php',
            method: 'GET',
            dataType: 'json',
            success: function (res) {
                const sev = res.severity || {};
                $('#codeStatTotal').text(res.total ?? '—');
                $('#codeStatHigh').text(sev['高'] ?? 0);
                $('#codeStatMid').text(sev['中'] ?? 0);
                $('#codeStatLow').text((sev['低'] ?? 0) + (sev['資訊'] ?? 0));
                $('#codeStatPending').text(res.pending ?? 0);
                $('#codeStatFiles').text(res.affected_files ?? 0);
                $('#codeSummaryLastScan').text(
                    res.last_scan ? '最後掃描時間：' + res.last_scan : '尚無掃描紀錄'
                );
            },
            error: function () {
                showToast('原始碼掃描總覽載入失敗', 'danger');
            }
        });
    };

    window.loadCodeFindings = function (page = 0) {
        $.ajax({
            url: 'get_code_findings.php',
            method: 'GET',
            data: {
                page: page,
                page_size: rowsPerPage,
                search: currentSearch,
                severities: currentSeverities.join(','),
                statuses: currentStatuses.join(',')
            },
            dataType: 'json',
            success: function (res) {
                renderCodeTable(res.data);
                renderCodePagination(res.total, page);
            },
            error: function () {
                showToast('原始碼掃描資料載入失敗', 'danger');
            }
        });
    };

    // 搜尋輸入（debounce）
    let codeSearchDebounce = null;
    $('#codeSearchInput').on('input', function () {
        clearTimeout(codeSearchDebounce);
        const value = $(this).val().trim();
        codeSearchDebounce = setTimeout(function () {
            currentSearch = value;
            loadCodeFindings(0);
        }, 500);
    });

    // 嚴重程度 / 狀態篩選
    $('.code-severity-filter, .code-status-filter').on('change', function () {
        currentSeverities = $('.code-severity-filter:checked').map(function () { return $(this).val(); }).get();
        currentStatuses = $('.code-status-filter:checked').map(function () { return $(this).val(); }).get();
        loadCodeFindings(0);
    });

    // 詳細 modal
    $('#codeScanTable').on('click', '.btn-code-detail', function () {
        const remediation = decodeURIComponent($(this).data('remediation') || '');
        const evidence = decodeURIComponent($(this).data('evidence') || '');
        $('#codeDetailRemediation').text(remediation || '（無建議）');
        $('#codeDetailEvidence').text(evidence || '（無）');
        $('#codeDetailModal').modal('show');
    });

    // 狀態變更
    $('#codeScanTable').on('click', '.btn-code-status', function () {
        const $btn = $(this);
        const id = $btn.data('id');
        const status = $btn.data('status');

        $.ajax({
            url: 'update_code_status.php',
            method: 'POST',
            data: { id: id, status: status },
            dataType: 'json',
            success: function (res) {
                if (res.success) {
                    showToast('✅ 狀態已更新為「' + (STATUS_LABELS[status] || status) + '」', 'success');
                    loadCodeFindings(0);
                    loadCodeSummary();
                } else {
                    showToast('✗ 更新失敗：' + (res.message || ''), 'danger');
                }
            },
            error: function () {
                showToast('✗ 請求失敗，請稍後再試', 'danger');
            }
        });
    });
});

// ============ 掃描報告（vuln-agent）分頁 ============
$(function () {
    const SEVERITY_BADGES = {
        '高': 'bg-danger',
        '中': 'bg-warning text-dark',
        '低': 'bg-info text-dark',
        '資訊': 'bg-secondary'
    };
    const TYPE_LABELS = {
        vuln: '網路弱點',
        code: '原始碼問題'
    };

    window.loadScanReport = function () {
        $.ajax({
            url: 'get_scan_report.php',
            method: 'GET',
            dataType: 'json',
            success: function (res) {
                if (!res.exists) {
                    $('#reportGeneratedAt').text('尚無報告');
                    $('#reportSummary').text('尚未產生過掃描報告，請等待下一輪排程掃描（或手動觸發一次掃描）完成。');
                    $('#reportHighlights').empty();
                    $('#reportTopFindingsTable tbody').html('<tr><td colspan="5" class="text-center">無數據</td></tr>');
                    ['Total', 'High', 'Mid', 'Low', 'New', 'Resolved'].forEach(function (k) {
                        $('#reportStat' + k).text('—');
                    });
                    $('#reportStatTotalDiff').html('&nbsp;');
                    return;
                }

                const sev = res.severity || {};
                $('#reportGeneratedAt').text('產生時間：' + res.generated_at);
                $('#reportSummary').text(res.summary || '（無摘要）');
                $('#reportStatTotal').text(res.total ?? '—');
                $('#reportStatHigh').text(sev['高'] ?? 0);
                $('#reportStatMid').text(sev['中'] ?? 0);
                $('#reportStatLow').text((sev['低'] ?? 0) + (sev['資訊'] ?? 0));
                $('#reportStatNew').text(res.new_count ?? 0);
                $('#reportStatResolved').text(res.resolved_count ?? 0);

                const diff = (res.total ?? 0) - (res.previous_total ?? 0);
                const diffStr = diff > 0 ? `+${diff}` : `${diff}`;
                $('#reportStatTotalDiff').text(`較上次 ${res.previous_total ?? 0} 筆（${diffStr}）`);

                let highlightsHtml = '';
                (res.highlights || []).forEach(function (h) {
                    highlightsHtml += `<li>${h}</li>`;
                });
                $('#reportHighlights').html(highlightsHtml || '<li class="text-muted">（無）</li>');

                let rowsHtml = '';
                (res.top_findings || []).forEach(function (f) {
                    rowsHtml += `
                        <tr class="text-center">
                            <td>${TYPE_LABELS[f.type] || f.type}</td>
                            <td class="text-start"><code>${f.location || ''}</code></td>
                            <td class="text-start">${f.title || ''}</td>
                            <td><span class="badge ${SEVERITY_BADGES[f.severity] || 'bg-secondary'}">${f.severity || '—'}</span></td>
                            <td>${f.confidence !== null && f.confidence !== undefined ? parseFloat(f.confidence).toFixed(2) : '—'}</td>
                        </tr>`;
                });
                $('#reportTopFindingsTable tbody').html(rowsHtml || '<tr><td colspan="5" class="text-center">無數據</td></tr>');
            },
            error: function () {
                showToast('掃描報告載入失敗', 'danger');
            }
        });
    };
});