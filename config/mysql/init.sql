-- GAIsecurity — CCT_Security database schema
-- Generated from production schema; no data included.
-- To regenerate from your own DB:
--   mysqldump --no-data CCT_Security > config/mysql/init.sql

CREATE DATABASE IF NOT EXISTS CCT_Security CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE CCT_Security;

-- ── IP risk status ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ip_risk_status_v2 (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip           VARCHAR(45)  NOT NULL,
  status       VARCHAR(32)  NOT NULL DEFAULT '警告IP',
  actions      JSON,
  attack_type  VARCHAR(128),
  unblock_time DATETIME,
  time         DATETIME,
  live_status  TINYINT(1)   NOT NULL DEFAULT 1,
  first_time   DATETIME,
  last_time    DATETIME,
  hostname     VARCHAR(255),
  INDEX idx_ip_live (ip, live_status),
  INDEX idx_status  (status, live_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── IP activity logs ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ip_risk_logs (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip          VARCHAR(45)  NOT NULL,
  host_name   VARCHAR(255),
  log_type    VARCHAR(64),
  log_content TEXT,
  local_ip    VARCHAR(45),
  direction   VARCHAR(16),
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ip_type (ip, log_type),
  INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── IP CIDR/wildcard ranges ───────────────────────────────────
CREATE TABLE IF NOT EXISTS ip_risk_ranges (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip_pattern  VARCHAR(64)  NOT NULL,
  status      VARCHAR(32)  NOT NULL,
  note        VARCHAR(255),
  attack_type VARCHAR(255),
  time        DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── LLM analysis results ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_log_analysis (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip            VARCHAR(45),
  attack_type   VARCHAR(128),
  attack_method VARCHAR(255),
  status        VARCHAR(32)  DEFAULT 'pending',
  created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Eval results (LLM performance metrics) ────────────────────
CREATE TABLE IF NOT EXISTS eval_results (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip          VARCHAR(45)  NOT NULL,
  llm_label   VARCHAR(32),
  gt_label    VARCHAR(32),
  gt_source   VARCHAR(64),
  created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Web login users ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username   VARCHAR(64)  NOT NULL UNIQUE,
  password   VARCHAR(255) NOT NULL,
  created_at DATETIME     DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
