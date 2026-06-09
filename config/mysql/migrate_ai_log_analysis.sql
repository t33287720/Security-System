-- migrate_ai_log_analysis.sql
-- IF NOT EXISTS 安全可重複執行
-- 用法：mysql -u root -p CCT_Security < config/mysql/migrate_ai_log_analysis.sql

USE CCT_Security;

-- ── ai_log_analysis：補 ip 欄位 ───────────────────────────────
ALTER TABLE ai_log_analysis
    ADD COLUMN IF NOT EXISTS ip VARCHAR(45) AFTER reason;

-- ── ip_risk_ranges：補 attack_type、time 欄位 ─────────────────
ALTER TABLE ip_risk_ranges
    ADD COLUMN IF NOT EXISTS attack_type VARCHAR(255) AFTER note,
    ADD COLUMN IF NOT EXISTS `time` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER attack_type;

-- 確認結果
SHOW COLUMNS FROM ai_log_analysis;
SHOW COLUMNS FROM ip_risk_ranges;
