import os
import mariadb


def get_conn():
    return mariadb.connect(
        host=os.getenv("MYSQL_HOST", "127.0.0.1"),
        port=int(os.getenv("MYSQL_PORT", "3306")),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASS", ""),
        database=os.getenv("MYSQL_DB", "CCT_Security"),
        autocommit=True,
    )


def ensure_schema(conn):
    """啟動時自動建立/升級 vuln-agent 所需的表（可重複執行）

    target+port+source+cve_id+title 為唯一鍵，讓每日重複掃描對同一個
    弱點做 UPDATE 而不是不斷新增 pending 紀錄（見 save_finding）。
    """
    with conn.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vuln_findings (
              id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
              target       VARCHAR(45)  NOT NULL,
              port         INT          NOT NULL DEFAULT 0,
              service      VARCHAR(64),
              version      VARCHAR(128),
              source       VARCHAR(32)  NOT NULL DEFAULT '',
              cve_id       VARCHAR(32)  NOT NULL DEFAULT '',
              title        VARCHAR(255) NOT NULL DEFAULT '',
              severity     VARCHAR(16),
              confidence   FLOAT,
              evidence     TEXT,
              remediation  TEXT,
              status       VARCHAR(32) DEFAULT 'pending',
              scanned_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
              INDEX idx_target (target),
              INDEX idx_status (status),
              UNIQUE KEY uniq_finding (target, port, source, cve_id, title)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        cursor.execute("""
            SELECT COUNT(*) FROM information_schema.STATISTICS
            WHERE table_schema = DATABASE() AND table_name = 'vuln_findings'
              AND index_name = 'uniq_finding'
        """)
        if cursor.fetchone()[0] > 0:
            return

        # 既有資料表升級：補齊去重所需欄位的預設值、清掉既有重複紀錄、補上唯一鍵
        cursor.execute("UPDATE vuln_findings SET port = 0 WHERE port IS NULL")
        cursor.execute("UPDATE vuln_findings SET source = '' WHERE source IS NULL")
        cursor.execute("UPDATE vuln_findings SET cve_id = '' WHERE cve_id IS NULL")
        cursor.execute("UPDATE vuln_findings SET title = '' WHERE title IS NULL")
        cursor.execute("""
            DELETE t1 FROM vuln_findings t1
            INNER JOIN vuln_findings t2
              ON t1.target = t2.target AND t1.port = t2.port AND t1.source = t2.source
             AND t1.cve_id = t2.cve_id AND t1.title = t2.title AND t1.id < t2.id
        """)
        cursor.execute("""
            ALTER TABLE vuln_findings
              MODIFY port INT NOT NULL DEFAULT 0,
              MODIFY source VARCHAR(32) NOT NULL DEFAULT '',
              MODIFY cve_id VARCHAR(32) NOT NULL DEFAULT '',
              MODIFY title VARCHAR(255) NOT NULL DEFAULT '',
              ADD UNIQUE KEY uniq_finding (target, port, source, cve_id, title)
        """)


def save_finding(conn, finding: dict):
    """寫入一筆經 LLM triage 後的弱點結果

    同一個弱點（target+port+source+cve_id+title）重複掃到時做 UPDATE：
    更新最新的版本/嚴重程度/證據/建議，但保留管理員已標記的狀態；
    只有「已解決」會被打回「待處理」，提醒問題其實還在。
    """
    with conn.cursor() as cursor:
        cursor.execute(
            """INSERT INTO vuln_findings
               (target, port, service, version, source, cve_id, title,
                severity, confidence, evidence, remediation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON DUPLICATE KEY UPDATE
                 service     = VALUES(service),
                 version     = VALUES(version),
                 severity    = VALUES(severity),
                 confidence  = VALUES(confidence),
                 evidence    = VALUES(evidence),
                 remediation = VALUES(remediation),
                 scanned_at  = CURRENT_TIMESTAMP,
                 status      = IF(status = 'resolved', 'pending', status)""",
            (
                finding["target"],
                finding.get("port") or 0,
                finding.get("service"),
                finding.get("version"),
                finding.get("source") or "",
                finding.get("cve_id") or "",
                finding.get("title") or "",
                finding.get("severity"),
                finding.get("confidence"),
                finding.get("evidence"),
                finding.get("remediation"),
            ),
        )
