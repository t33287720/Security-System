import json

SEVERITY_RANK = {"高": 3, "中": 2, "低": 1, "資訊": 0}
TOP_FINDINGS_LIMIT = 10


def ensure_report_schema(conn):
    """啟動時自動建立 vuln-agent 掃描報告所需的表（可重複執行）"""
    with conn.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_reports (
              id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
              generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              summary      TEXT,
              highlights   TEXT,
              stats        TEXT,
              top_findings TEXT,
              INDEX idx_generated_at (generated_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)


def get_latest_report(conn) -> dict:
    """回傳上一次的掃描報告（含 generated_at 與已解析的 stats），無紀錄時回傳 None"""
    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT generated_at, stats FROM scan_reports ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
    if not row:
        return None
    generated_at, stats_json = row
    try:
        stats = json.loads(stats_json) if stats_json else {}
    except (ValueError, TypeError):
        stats = {}
    return {"generated_at": generated_at, "stats": stats}


def collect_findings_snapshot(conn) -> list:
    """彙整目前 vuln_findings + code_findings 中所有紀錄，作為本次報告的快照

    每筆以 "vuln:<id>" / "code:<id>" 當作 ref（id 在重複掃描時保持不變，
    可用來與上一份報告的快照比對「新增/已解決」）
    """
    snapshot = []
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT id, target, port, title, severity, confidence, status
            FROM vuln_findings
        """)
        for row in cursor.fetchall():
            id_, target, port, title, severity, confidence, status = row
            snapshot.append({
                "ref": f"vuln:{id_}",
                "type": "vuln",
                "location": f"{target}:{port}",
                "title": title or "",
                "severity": severity,
                "confidence": confidence,
                "status": status or "pending",
            })

        cursor.execute("""
            SELECT id, file_path, line_start, title, severity, confidence, status
            FROM code_findings
        """)
        for row in cursor.fetchall():
            id_, file_path, line_start, title, severity, confidence, status = row
            snapshot.append({
                "ref": f"code:{id_}",
                "type": "code",
                "location": f"{file_path}:{line_start}",
                "title": title or "",
                "severity": severity,
                "confidence": confidence,
                "status": status or "pending",
            })

    return snapshot


def build_report_stats(snapshot: list, previous: dict) -> dict:
    """比對本次快照與上一份報告的快照，計算總覽統計與增量（新增/已解決）"""
    severity_counts = {"高": 0, "中": 0, "低": 0, "資訊": 0}
    for item in snapshot:
        if item["severity"] in severity_counts:
            severity_counts[item["severity"]] += 1

    previous_snapshot = (previous or {}).get("snapshot", [])
    previous_status = {item["ref"]: item["status"] for item in previous_snapshot}
    previous_refs = set(previous_status.keys())
    current_refs = {item["ref"] for item in snapshot}

    new_count = len(current_refs - previous_refs)
    resolved_count = sum(
        1 for item in snapshot
        if item["status"] == "resolved" and previous_status.get(item["ref"]) != "resolved"
    )

    return {
        "total": len(snapshot),
        "severity": severity_counts,
        "new_count": new_count,
        "resolved_count": resolved_count,
        "previous_total": (previous or {}).get("stats", {}).get("total", 0),
        "snapshot": snapshot,
    }


def build_top_findings(snapshot: list, limit: int = TOP_FINDINGS_LIMIT) -> list:
    """依嚴重程度（高>中>低>資訊）、信心度排序，取前 N 筆作為本次報告重點"""
    pending = [item for item in snapshot if item["status"] not in ("resolved", "false_positive")]
    ranked = sorted(
        pending,
        key=lambda item: (SEVERITY_RANK.get(item["severity"], -1), item["confidence"] or 0),
        reverse=True,
    )
    return [
        {
            "type": item["type"],
            "location": item["location"],
            "title": item["title"],
            "severity": item["severity"],
            "confidence": item["confidence"],
        }
        for item in ranked[:limit]
    ]


def save_report(conn, summary: str, highlights: list, stats: dict, top_findings: list):
    """寫入一份新的掃描報告（stats 中含本次快照，供下次比對增量）"""
    with conn.cursor() as cursor:
        cursor.execute(
            """INSERT INTO scan_reports (summary, highlights, stats, top_findings)
               VALUES (?, ?, ?, ?)""",
            (
                summary,
                json.dumps(highlights or [], ensure_ascii=False),
                json.dumps(stats, ensure_ascii=False),
                json.dumps(top_findings, ensure_ascii=False),
            ),
        )
