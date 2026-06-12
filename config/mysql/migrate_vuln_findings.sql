-- migrate_vuln_findings.sql
-- 可重複執行：vuln-agent 容器啟動時也會跑一樣的升級邏輯（見 vuln-agent/tools/vuln_db.py ensure_schema）
-- 用法：mysql -u root -p CCT_Security < config/mysql/migrate_vuln_findings.sql

USE CCT_Security;

-- ── 弱點掃描結果（vuln-agent 經 LLM triage 後的結構化結果）───────
-- target+port+source+cve_id+title 為唯一鍵：每日重複掃描會 UPDATE 既有紀錄，
-- 不會無限新增 pending 紀錄（見 vuln-agent/tools/vuln_db.py save_finding）
CREATE TABLE IF NOT EXISTS vuln_findings (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  target       VARCHAR(45)  NOT NULL,
  port         INT          NOT NULL DEFAULT 0,
  service      VARCHAR(64),
  version      VARCHAR(128),
  source       VARCHAR(32)  NOT NULL DEFAULT '',  -- nmap_vuln_script / searchsploit
  cve_id       VARCHAR(32)  NOT NULL DEFAULT '',
  title        VARCHAR(255) NOT NULL DEFAULT '',
  severity     VARCHAR(16),      -- 高/中/低/資訊
  confidence   FLOAT,
  evidence     TEXT,             -- 原始工具輸出片段
  remediation  TEXT,             -- LLM 修補建議
  status       VARCHAR(32) DEFAULT 'pending',  -- pending/confirmed/false_positive/resolved
  scanned_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_target (target),
  INDEX idx_status (status),
  UNIQUE KEY uniq_finding (target, port, source, cve_id, title)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 既有資料表升級（從舊版升級時，補齊欄位預設值並加上唯一鍵）───
UPDATE vuln_findings SET port = 0 WHERE port IS NULL;
UPDATE vuln_findings SET source = '' WHERE source IS NULL;
UPDATE vuln_findings SET cve_id = '' WHERE cve_id IS NULL;
UPDATE vuln_findings SET title = '' WHERE title IS NULL;

-- 升級前先清掉既有重複紀錄（同一弱點保留最新一筆，較舊的會被刪除）
DELETE t1 FROM vuln_findings t1
INNER JOIN vuln_findings t2
  ON t1.target = t2.target AND t1.port = t2.port AND t1.source = t2.source
 AND t1.cve_id = t2.cve_id AND t1.title = t2.title AND t1.id < t2.id;

ALTER TABLE vuln_findings
  MODIFY port INT NOT NULL DEFAULT 0,
  MODIFY source VARCHAR(32) NOT NULL DEFAULT '',
  MODIFY cve_id VARCHAR(32) NOT NULL DEFAULT '',
  MODIFY title VARCHAR(255) NOT NULL DEFAULT '';

ALTER TABLE vuln_findings ADD UNIQUE KEY IF NOT EXISTS uniq_finding (target, port, source, cve_id, title);

-- 確認結果
SHOW COLUMNS FROM vuln_findings;
