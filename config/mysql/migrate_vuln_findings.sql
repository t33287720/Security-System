-- migrate_vuln_findings.sql
-- IF NOT EXISTS 安全可重複執行
-- 用法：mysql -u root -p CCT_Security < config/mysql/migrate_vuln_findings.sql

USE CCT_Security;

-- ── 弱點掃描結果（vuln-agent 經 LLM triage 後的結構化結果）───────
CREATE TABLE IF NOT EXISTS vuln_findings (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  target       VARCHAR(45)  NOT NULL,
  port         INT,
  service      VARCHAR(64),
  version      VARCHAR(128),
  source       VARCHAR(32),      -- nmap_vuln_script / searchsploit
  cve_id       VARCHAR(32),
  title        VARCHAR(255),
  severity     VARCHAR(16),      -- 高/中/低/資訊
  confidence   FLOAT,
  evidence     TEXT,             -- 原始工具輸出片段
  remediation  TEXT,             -- LLM 修補建議
  status       VARCHAR(32) DEFAULT 'pending',  -- pending/confirmed/false_positive/resolved
  scanned_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_target (target),
  INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 確認結果
SHOW COLUMNS FROM vuln_findings;
