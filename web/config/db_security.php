<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$servername    = getenv('MYSQL_HOST');
$username      = getenv('MYSQL_USER');
$password      = getenv('MYSQL_PASS');
$db_experience = getenv('MYSQL_DB');

$conn = new mysqli($servername, $username, $password, $db_experience);
if ($conn->connect_error) {
    die("資料庫連線失敗: " . $conn->connect_error);
}
?>
