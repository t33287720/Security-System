<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
<script>
    // 深色模式記憶
    const toggleThemeBtn = document.getElementById('toggleTheme');
    if (toggleThemeBtn) {
        if (localStorage.getItem('theme') === 'dark') {
            document.documentElement.setAttribute('data-bs-theme', 'dark');
            document.body.classList.add('dark-mode');
            toggleThemeBtn.innerHTML = '<i class="bi bi-sun"></i>';
        }

        toggleThemeBtn.addEventListener('click', function () {
            const html = document.documentElement;
            if (html.getAttribute('data-bs-theme') === 'dark') {
                html.setAttribute('data-bs-theme', 'light');
                document.body.classList.remove('dark-mode');
                toggleThemeBtn.innerHTML = '<i class="bi bi-moon-stars"></i>';
                localStorage.setItem('theme', 'light');
                document.cookie = "theme=light; path=/";
            } else {
                html.setAttribute('data-bs-theme', 'dark');
                document.body.classList.add('dark-mode');
                toggleThemeBtn.innerHTML = '<i class="bi bi-sun"></i>';
                localStorage.setItem('theme', 'dark');
                document.cookie = "theme=dark; path=/";
            }
            adjustTableTheme();
        });
    }

    // Sidebar 收合/展開控制
    const toggleSidebarBtn = document.getElementById('toggleSidebarBtn');
    const sidebar = document.getElementById('sidebar');
    const content = document.getElementById('content');

    // ✅ DOM 載入時記憶 sidebar 狀態（僅當 sidebar 存在）
    document.addEventListener('DOMContentLoaded', () => {
        if (sidebar && content && toggleSidebarBtn) {
            const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';

            if (isCollapsed) {
                sidebar.classList.add('collapsed');
                content.classList.add('expanded');
                toggleSidebarBtn.innerHTML = '&raquo;';
                toggleSidebarBtn.style.left = '60px';
            } else {
                sidebar.classList.remove('collapsed');
                content.classList.remove('expanded');
                toggleSidebarBtn.innerHTML = '&laquo;';
                toggleSidebarBtn.style.left = '230px';
            }
        }

        adjustTableTheme(); // ✅ 不管有沒有 sidebar 都應該執行這個
    });

    // ✅ 點擊按鈕時切換 sidebar 狀態
    if (toggleSidebarBtn && sidebar && content) {
        toggleSidebarBtn.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            content.classList.toggle('expanded');

            const isCollapsed = sidebar.classList.contains('collapsed');
            localStorage.setItem('sidebarCollapsed', isCollapsed ? 'true' : 'false');

            toggleSidebarBtn.innerHTML = isCollapsed ? '&raquo;' : '&laquo;';
            toggleSidebarBtn.style.left = isCollapsed ? '60px' : '230px';
        });
    }

    // 表格表頭同步亮暗模式
    function adjustTableTheme() {
        const tableHead = document.getElementById('tableHead');
        if (tableHead) {
            if (localStorage.getItem('theme') === 'dark') {
                tableHead.classList.remove('table-light');
                tableHead.classList.add('table-dark');
            } else {
                tableHead.classList.remove('table-dark');
                tableHead.classList.add('table-light');
            }
        }
    }
</script>
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</body>
</html>
