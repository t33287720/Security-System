<?php
session_name('security');
session_start();

require_once __DIR__ . '/config/db_security.php';

// CSRF Token 產生與檢查
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errorMessage = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 簡單CSRF檢查
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $errorMessage = '非法的請求，請重新整理頁面後再試。';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($username === '' || $password === '') {
            $errorMessage = '請輸入完整的帳號及密碼。';
        } else {
            // 預防SQL injection
            $stmt = $conn->prepare('SELECT id, password FROM users WHERE username = ? LIMIT 1');
            $stmt->bind_param('s', $username);

            if ($stmt->execute()) {
                $stmt->store_result();
                if ($stmt->num_rows === 1) {
                    $stmt->bind_result($id, $hashed_password);
                    $stmt->fetch();

                    if (password_verify($password, $hashed_password)) {
                        session_regenerate_id(true);
                        $_SESSION['user_id'] = $id;
                        $_SESSION['username'] = $username;

                        // 登入成功重定向
                        header('Location: index.php');
                        exit();
                    } else {
                        $errorMessage = '密碼錯誤。';
                    }
                } else {
                    $errorMessage = '帳號不存在。';
                }
            } else {
                $errorMessage = '伺服器錯誤，請稍後再試。';
            }
            $stmt->close();
        }
    }
}
$conn->close();
?>

<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GAI 安全防護系統 — 登入</title>
    <link rel="stylesheet" href="assets/css/login.css" />
</head>
<body>
    <div class="login-brand">
        <div class="brand-icon">GAI</div>
        GAI Security Monitoring Platform
    </div>

    <div class="login-container">
        <div class="login-header">
            <h2>系統登入</h2>
            <p>ADMINISTRATOR ACCESS</p>
        </div>
        <div class="login-body">
            <?php if ($errorMessage): ?>
                <div class="error-message"><?= htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8') ?></div>
            <?php endif; ?>

            <form action="login.php" method="post" autocomplete="off" novalidate>
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>" />

                <div class="form-group">
                    <label for="username">帳號</label>
                    <input type="text" id="username" name="username" required autofocus
                        autocomplete="username" placeholder="請輸入帳號" />
                </div>

                <div class="form-group">
                    <label for="password">密碼</label>
                    <input type="password" id="password" name="password" required
                        autocomplete="current-password" placeholder="請輸入密碼" />
                </div>

                <button type="submit" class="btn-login">登入系統</button>
            </form>
        </div>
    </div>

    <div class="login-footer">AUTHORIZED ACCESS ONLY &nbsp;|&nbsp; GAI Security Platform</div>
</body>
</html>
