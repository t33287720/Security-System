<?php require_once 'config/auth.php'; ?>

<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
header('Content-Type: application/json');
require_once __DIR__ . '/config/db_security.php';

if ($conn->connect_error) {
    error_log("DB 連線錯誤：" . $conn->connect_error);
    echo json_encode(['success' => false, 'message' => '資料庫連線失敗']);
    exit;
}

$action = $_POST['action'] ?? 'add'; // 預設為新增

$keyword = trim($_POST['behavior_keyword'] ?? '');
$description = trim($_POST['description'] ?? '');
$status = isset($_POST['status']) ? intval($_POST['status']) : null;

if (!$keyword) {
    echo json_encode(['success' => false, 'message' => '缺少行為名稱']);
    exit;
}

if ($action === 'add') {
    // 新增
    if (!$description) {
        echo json_encode(['success' => false, 'message' => '描述不得為空']);
        exit;
    }
    // 檢查是否已存在
    $check = $conn->prepare("SELECT COUNT(*) FROM dangerous_behaviors WHERE behavior_keyword=?");
    $check->bind_param("s", $keyword);
    $check->execute();
    $check->bind_result($count);
    $check->fetch();
    $check->close();
    if ($count > 0) {
        echo json_encode(['success' => false, 'message' => '行為名稱已存在']);
        exit;
    }
    $stmt = $conn->prepare("INSERT INTO dangerous_behaviors (behavior_keyword, description, time) VALUES (?, ?, NOW())");
    $stmt->bind_param("ss", $keyword, $description);
    $result = $stmt->execute();
    $stmt->close();
    echo json_encode(['success' => $result]);
    exit;
}

if ($action === 'edit') {
    $old_keyword = trim($_POST['old_behavior_keyword'] ?? '');
    if (!$description || !$keyword || !$old_keyword) {
        echo json_encode(['success' => false, 'message' => '欄位不得為空']);
        exit;
    }
    // 檢查新名稱是否與其他行為重複（但允許自己原本的名稱）
    if ($keyword !== $old_keyword) {
        $check = $conn->prepare("SELECT COUNT(*) FROM dangerous_behaviors WHERE behavior_keyword=?");
        $check->bind_param("s", $keyword);
        $check->execute();
        $check->bind_result($count);
        $check->fetch();
        $check->close();
        if ($count > 0) {
            echo json_encode(['success' => false, 'message' => '行為名稱已存在']);
            exit;
        }
    }
    $stmt = $conn->prepare("UPDATE dangerous_behaviors SET behavior_keyword=?, description=?, time=NOW() WHERE behavior_keyword=?");
    $stmt->bind_param("sss", $keyword, $description, $old_keyword);
    $result = $stmt->execute();
    $stmt->close();
    echo json_encode(['success' => $result]);
    exit;
}

if ($action === 'toggle') {
    // 啟用/停用
    if (!isset($status)) {
        echo json_encode(['success' => false, 'message' => '缺少狀態']);
        exit;
    }
    $stmt = $conn->prepare("UPDATE dangerous_behaviors SET status=?, time=NOW() WHERE behavior_keyword=?");
    $stmt->bind_param("is", $status, $keyword);
    $result = $stmt->execute();
    $stmt->close();
    echo json_encode(['success' => $result]);
    exit;
}

if ($action === 'delete') {
    // 刪除
    $stmt = $conn->prepare("DELETE FROM dangerous_behaviors WHERE behavior_keyword=?");
    $stmt->bind_param("s", $keyword);
    $result = $stmt->execute();
    $stmt->close();
    echo json_encode(['success' => $result]);
    exit;
}

echo json_encode(['success' => false, 'message' => '未知操作']);
