-- migrate_log_type.sql
-- IF NOT EXISTS 安全可重複執行
-- 用法：mysql -u root -p CCT_Security < config/mysql/migrate_log_type.sql

USE CCT_Security;

-- ── ip_risk_logs：擴充 log_type 欄位以支援 weirdlog / noticelog ──
--    舊版欄位長度不足（"weirdlog"=8, "noticelog"=9 超出舊限制），
--    統一改為 VARCHAR(64) 與 init.sql 對齊。
ALTER TABLE ip_risk_logs
    MODIFY COLUMN log_type VARCHAR(64);

-- 確認結果
SHOW COLUMNS FROM ip_risk_logs LIKE 'log_type';
