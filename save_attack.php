<?php
require_once __DIR__ . '/../../config/db_security.php';

$log = $_POST['log'];
$is_malicious = $_POST['is_malicious'] ? 1 : 0;
$risk_level = $_POST['risk_level'];
$attack_type = $_POST['attack_type'];
$attack_method = $_POST['attack_method'];
$reason = $_POST['reason'];

$sql = "INSERT INTO ai_log_analysis 
(log, is_malicious, risk_level, attack_type, attack_method, reason, created_at)
VALUES (?, ?, ?, ?, ?, ?, NOW())";

$stmt = $conn->prepare($sql);
$stmt->bind_param("sissss", $log, $is_malicious, $risk_level, $attack_type, $attack_method, $reason);
$stmt->execute();

echo "ok";