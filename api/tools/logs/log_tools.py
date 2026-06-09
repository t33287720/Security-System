# tools/log/log_tools.py
from tools.db.db_tools import (
    insert_raw_log,
)

def format_logs(rows):
    return "\n".join(f"[{r['created_at']}] {r['log_content']}" for r in rows)

def build_syslog(log_text, meta):
    return f"""[SYSLOG]
IP: {meta['ip']}
Host: {meta['host_name']}
Local IP: {meta['local_ip']}
Direction: {meta['direction']}
Time: {meta['log_time']}

Message:
{log_text}
""".strip()

def build_zeeklog(log_text, meta):
    fields = [
        "時間戳", "會話ID", "來源IP", "來源Port", "目的IP",
        "目的Port", "協議", "子協議", "持續時間", "來源bytes", "目的bytes"
    ]

    parts = log_text.strip().split("\t")

    parsed_lines = [
        f"{field}: {parts[i]}"
        for i, field in enumerate(fields)
        if i < len(parts)
    ]

    return "[來源: Zeek 日誌]\n" + "\n".join(parsed_lines)

def handle_logs(conn, logs, builder, log_type, ip, data):

    meta = {
        "ip": ip,
        "host_name": data["host_name"],
        "local_ip": data["local_ip"],
        "direction": data["direction"],
        "log_time": data["last_time"]
    }

    for log in logs:
        formatted = builder(log, meta)

        insert_raw_log(
            conn,
            ip,
            formatted,
            data["host_name"],
            data["last_time"],
            log_type,
            data["local_ip"],
            data["direction"]
        )