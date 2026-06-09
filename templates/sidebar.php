<link rel="stylesheet" href="./assets/css/sidebar.css">

<div id="sidebar" class="sidebar d-flex flex-column p-3">
    <div class="d-flex justify-content-center align-items-center mb-3" style="width: 100%;">
        <a href="index.php" class="text-decoration-none">
            <button class="button" data-text="Awesome">
                <span class="actual-text">&nbsp;CCT&nbsp;</span>
                <span aria-hidden="true" class="hover-text">&nbsp;CCT&nbsp;</span>
            </button>
        </a>
    </div>
    <hr>
    <ul class="nav nav-pills flex-column mb-auto">
        <!-- 產品列表下拉選單 -->
        <li class="nav-item">
            <a class="nav-link" data-bs-toggle="collapse" href="#productMenu" role="button" aria-expanded="false" aria-controls="productMenu">
                <i class="bi bi-box-seam"></i> <span class="link-text">產品列表</span>
            </a>
            <div class="collapse" id="productMenu">
                <ul class="nav flex-column ms-3">
                    <li class="nav-item"><a class="nav-link" href="index.php"><i class="bi bi-book-half"></i> 經驗傳承</a></li>
                    <li class="nav-item"><a class="nav-link" href="meeting.php"><i class="bi bi-journal-text"></i> 會議紀錄</a></li>
                    <li class="nav-item"><a class="nav-link" href="#"><i class="bi bi-translate"></i> 口譯系統</a></li>
                    <li class="nav-item"><a class="nav-link" href="#"><i class="bi bi-person-walking"></i> 導覽員</a></li>
                    <li class="nav-item"><a class="nav-link" href="#"><i class="bi bi-megaphone"></i> 語音簡報系統</a></li>
                </ul>
            </div>
        </li>

        <li>
            <a href="manage_admins.php" class="nav-link <?php echo basename($_SERVER['PHP_SELF']) == 'manage_admins.php' ? 'active' : ''; ?>">
                <i class="bi bi-person-lines-fill"></i> <span class="link-text">管理員列表</span>
            </a>
        </li>

        <li>
            <a href="gpu_dashboard.php" class="nav-link <?php echo basename($_SERVER['PHP_SELF']) == 'gpu_dashboard.php' ? 'active' : ''; ?>">
                <i class="bi bi-cpu"></i> <span class="link-text">顯示卡列表</span>
            </a>
        </li>

        <!-- AI 代理監控 -->
        <li class="nav-item">
            <a class="nav-link" data-bs-toggle="collapse" href="#aiMenu" role="button" aria-expanded="false" aria-controls="aiMenu">
                <i class="bi bi-robot"></i> <span class="link-text">監控系統</span>
            </a>
            <div class="collapse" id="aiMenu">
                <ul class="nav flex-column ms-3">
                    <li class="nav-item">
                        <a class="nav-link" href="log.php">
                            <i class="bi bi-graph-up"></i> Log 紀錄
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="ip_manager.php">
                            <i class="bi bi-shield-lock"></i> 黑白名單管理
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="ELK.php">
                            <i class="bi bi-shield-lock"></i> ELK 紀錄
                        </a>
                    </li>
                    <!-- <li class="nav-item">
                        <a class="nav-link" href="ai_agent.php">
                            <i class="bi bi-terminal"></i> AI 代理監控
                        </a>
                    </li> -->
                </ul>
            </div>
        </li>

    </ul>
</div>
