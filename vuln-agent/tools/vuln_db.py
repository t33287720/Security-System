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
    """啟動時自動建立 vuln-agent 所需的表（IF NOT EXISTS，可重複執行）"""
    with conn.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vuln_findings (
              id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
              target       VARCHAR(45)  NOT NULL,
              port         INT,
              service      VARCHAR(64),
              version      VARCHAR(128),
              source       VARCHAR(32),
              cve_id       VARCHAR(32),
              title        VARCHAR(255),
              severity     VARCHAR(16),
              confidence   FLOAT,
              evidence     TEXT,
              remediation  TEXT,
              status       VARCHAR(32) DEFAULT 'pending',
              scanned_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
              INDEX idx_target (target),
              INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)


def save_finding(conn, finding: dict):
    """寫入一筆經 LLM triage 後的弱點結果"""
    with conn.cursor() as cursor:
        cursor.execute(
            """INSERT INTO vuln_findings
               (target, port, service, version, source, cve_id, title,
                severity, confidence, evidence, remediation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding["target"],
                finding.get("port"),
                finding.get("service"),
                finding.get("version"),
                finding.get("source"),
                finding.get("cve_id"),
                finding.get("title"),
                finding.get("severity"),
                finding.get("confidence"),
                finding.get("evidence"),
                finding.get("remediation"),
            ),
        )
