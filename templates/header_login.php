<!DOCTYPE html>
<html lang="zh-TW" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登入 - 最高管理系統</title>
    <link rel="stylesheet" href="../assets/css/animations.css">
    <link rel="icon" type="image/png" sizes="32x32" href="../assets/images/cctg.png">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins&family=Noto+Sans+TC&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', 'Noto Sans TC', sans-serif;
            background: linear-gradient(to right, #f2f2f2, #e6e6e6);
            color: #333;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .login-wrapper {
            display: flex;
            flex-direction: column;
            align-items: center;
            width: 100%;
        }

        .cct-logo {
            font-size: 72px;
            font-weight: 900;
            background: linear-gradient(90deg, #ff512f, #f09819, #ff512f);
            background-size: 200% auto;
            color: transparent;
            background-clip: text;
            -webkit-background-clip: text;
            animation: moveGradient 4s linear infinite;
            margin-bottom: 40px;
            letter-spacing: 2px;
            text-shadow: 1px 1px 1px rgba(0,0,0,0.15);
        }

        @keyframes moveGradient {
            0% { background-position: 0% center; }
            100% { background-position: 200% center; }
        }

        .login-card {
            background: rgba(255, 255, 255, 0.85);
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
            backdrop-filter: blur(12px);
            border: 1px solid #ccc;
        }

        .login-card h2 {
            text-align: center;
            font-weight: 700;
            margin-bottom: 1.5rem;
            color: #222;
        }

        .login-card label {
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #444;
        }

        .login-card .form-control {
            border: none;
            border-radius: 10px;
            background-color: #f5f5f5;
            padding: 0.75rem 1rem;
            font-size: 1rem;
            box-shadow: inset 0 0 5px rgba(0,0,0,0.05);
        }

        .login-card .form-control:focus {
            border: 1px solid #ff9800;
            outline: none;
            box-shadow: 0 0 5px rgba(255, 152, 0, 0.5);
        }

        .btn-login {
            background-color: #ff9800;
            border: none;
            padding: 0.75rem;
            font-weight: 600;
            font-size: 1rem;
            border-radius: 10px;
            transition: background-color 0.3s ease;
            color: white;
        }

        .btn-login:hover {
            background-color: #e67600;
        }
    </style>

    
</head>
<body>
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

