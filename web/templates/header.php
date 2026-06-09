<?php
// 禁止瀏覽器快取
header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");
?>
<!DOCTYPE html>
<html lang="zh-TW" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>最高管理系統</title>
        <!-- PNG 格式 for modern browser -->
    <link rel="icon" type="image/png" sizes="32x32" href="./assets/images/cctg.png">
    <!-- <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png"> -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins&family=Noto+Sans+TC&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', 'Noto Sans TC', sans-serif;
            background-color: var(--bs-body-bg);
            transition: background-color 0.5s, color 0.5s;
        }
        #sidebar {
            width: 250px;
            min-height: 100vh;
            background-color: var(--bs-light);
            transition: all 0.3s;
            overflow-x: hidden;
            position: fixed;
            top: 0;
            left: 0;
            z-index: 1000;
        }
        #sidebar.collapsed {
            width: 80px;
        }
        .sidebar .nav-link {
            color: #333;
            transition: all 0.3s;
        }
        .sidebar .nav-link.active {
            background-color: #0d6efd;
            color: #fff;
        }
        .sidebar .nav-link:hover {
            background-color: #e9ecef;
        }
        .content {
            margin-left: 250px;
            padding: 20px;
            transition: margin-left 0.3s;
        }
        .content.expanded {
            margin-left: 80px;
        }
        .dark-mode #sidebar {
            background-color: #343a40;
        }
        .dark-mode .sidebar .nav-link {
            color: #adb5bd;
        }
        .dark-mode .sidebar .nav-link.active {
            background-color: #495057;
        }
        /* 新增：sidebar外側的收合按鈕 */
        #toggleSidebarBtn {
            position: fixed;
            top: 50%;
            transform: translateY(-50%);
            left: 230px; /* 展開初始位置 */
            width: 40px;
            height: 40px;
            background-color: #0d6efd;
            color: white;
            font-size: 24px; /* 圖示變大！！！ */
            font-weight: bold; /* 加粗更明顯 */
            border: none;
            border-radius: 50%;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            cursor: pointer;
            transition: background-color 0.3s, left 0.3s, font-size 0.3s; /* 加transition更滑順 */
            z-index: 1040;
        }
        #toggleSidebarBtn:hover {
            background-color: #0b5ed7;
        }
        .dark-mode #toggleSidebarBtn {
            background-color: #495057;
        }
        .dark-mode #toggleSidebarBtn:hover {
            background-color: #6c757d;
        }

        /* 新增：link-text動畫 */
        .link-text {
            opacity: 1;
            transition: opacity 0.3s;
        }
        /* #sidebar.collapsed .link-text {
            opacity: 0;
        } */
    </style>
</head>
<body>

<?php include 'templates/sidebar.php'; ?>

<!-- 收合按鈕，獨立放這裡 -->
<button id="toggleSidebarBtn">&laquo;</button>

<div class="content" id="content">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2 class="mb-0">最高管理系統</h2>
        <div>
            <button id="toggleTheme" class="btn btn-outline-secondary me-2"><i class="bi bi-moon-stars"></i></button>
            <button id="logoutBtn" class="btn btn-danger">登出</button>
        </div>
    </div>

<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<script>
    document.getElementById('logoutBtn').addEventListener('click', async function (e) {
    e.preventDefault();

    try {
        const res = await fetch('./auth/logout.php', {
        method: 'POST'
        });

        if (!res.ok) throw new Error('登出失敗');

        Swal.fire({
        title: '登出成功！',
        icon: 'success',
        timer: 1500,
        showConfirmButton: false
        }).then(() => {
        window.location.href = './auth/login.php';
        });

    } catch (err) {
        console.error(err);
        Swal.fire('錯誤', '登出失敗，請稍後再試', 'error');
    }
    });
    
</script>
