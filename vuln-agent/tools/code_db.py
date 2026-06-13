import hashlib

from tools.vuln_db import get_conn  # noqa: F401  (重用既有連線邏輯，供 vuln_agent.py 統一 import)


def ensure_code_schema(conn):
    """啟動時自動建立 vuln-agent 原始碼掃描所需的表（可重複執行）

    finding_hash（file_path+line_start+source+rule_id 的 SHA256）作為唯一鍵，
    讓每日重複掃描對同一個問題做 UPDATE 而不是不斷新增 pending 紀錄（見 save_code_finding）。
    """
    with conn.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS code_findings (
              id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
              file_path    VARCHAR(255) NOT NULL,
              line_start   INT          NOT NULL DEFAULT 0,
              line_end     INT          NOT NULL DEFAULT 0,
              source       VARCHAR(32)  NOT NULL DEFAULT '',
              rule_id      VARCHAR(128) NOT NULL DEFAULT '',
              title        VARCHAR(255) NOT NULL DEFAULT '',
              severity     VARCHAR(16),
              confidence   FLOAT,
              evidence     TEXT,
              remediation  TEXT,
              status       VARCHAR(32) DEFAULT 'pending',
              scanned_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
              finding_hash CHAR(64) NOT NULL,
              INDEX idx_file (file_path),
              INDEX idx_status (status),
              UNIQUE KEY uniq_finding_hash (finding_hash)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)


def make_finding_hash(file_path: str, line_start: int, source: str, rule_id: str) -> str:
    raw = f"{file_path}:{line_start}:{source}:{rule_id}"
    return hashlib.sha256(raw.encode()).hexdigest()


def save_code_finding(conn, finding: dict):
    """寫入一筆經 LLM triage 後的原始碼問題

    同一個問題（file_path+line_start+source+rule_id 的 hash）重複掃到時做 UPDATE：
    更新最新的嚴重程度/證據/建議，但保留管理員已標記的狀態；
    只有「已解決」會被打回「待處理」，提醒問題其實還在。
    """
    finding_hash = make_finding_hash(
        finding["file_path"], finding.get("line_start") or 0,
        finding.get("source") or "", finding.get("rule_id") or "",
    )
    with conn.cursor() as cursor:
        cursor.execute(
            """INSERT INTO code_findings
               (file_path, line_start, line_end, source, rule_id, title,
                severity, confidence, evidence, remediation, finding_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON DUPLICATE KEY UPDATE
                 line_end    = VALUES(line_end),
                 title       = VALUES(title),
                 severity    = VALUES(severity),
                 confidence  = VALUES(confidence),
                 evidence    = VALUES(evidence),
                 remediation = VALUES(remediation),
                 scanned_at  = CURRENT_TIMESTAMP,
                 status      = IF(status = 'resolved', 'pending', status)""",
            (
                finding["file_path"],
                finding.get("line_start") or 0,
                finding.get("line_end") or 0,
                finding.get("source") or "",
                finding.get("rule_id") or "",
                finding.get("title") or "",
                finding.get("severity"),
                finding.get("confidence"),
                finding.get("evidence"),
                finding.get("remediation"),
                finding_hash,
            ),
        )
