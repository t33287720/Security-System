-- 評估用資料表
-- 執行方式：mysql -u root -p <db_name> < migrate_eval_table.sql

-- eval_results：儲存 LLM 對「已知標籤 IP」的分析結果
CREATE TABLE IF NOT EXISTS eval_results (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    ip           VARCHAR(50)   NOT NULL,
    true_label   ENUM('attack', 'benign') NOT NULL,
    gt_source    VARCHAR(50)   NOT NULL,       -- 'openblacklist' | 'whitelist'
    danger_level VARCHAR(20),                  -- LLM 輸出
    confidence   DECIMAL(5,4),                 -- LLM 輸出
    attack_type  VARCHAR(200),                 -- LLM 輸出
    actions      MEDIUMTEXT,                   -- LLM 完整 JSON
    log_count    INT DEFAULT 0,                -- 送入 LLM 的 log 筆數
    source_count INT DEFAULT 1,               -- 命中幾個獨立 blacklist 源（attack 用）
    analyzed_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip         (ip),
    INDEX idx_true_label (true_label),
    INDEX idx_analyzed   (analyzed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 若表已存在，補欄位（舊資料升級用）
ALTER TABLE eval_results
    ADD COLUMN IF NOT EXISTS source_count INT DEFAULT 1
    AFTER log_count;
