# tools/db/db_tools.py
import json
# =========================================================
# INTERNAL HELPER
# =========================================================
def fetch_all(cursor, sql, params=None, key=None):
    cursor.execute(sql, params or ())

    rows = cursor.fetchall()

    # SELECT 多欄位
    if key is None:
        return rows

    # SELECT 單欄位
    return [row[key] for row in rows]


def fetch_one(cursor, sql, params=None):
    cursor.execute(sql, params or ())
    return cursor.fetchone()


# =========================================================
# SELECT
# =========================================================

# 取得名單（白 / 黑 / 範圍）
def get_raw_ip_lists(conn):
    with conn.cursor(dictionary=True) as cursor:

        white_ips = fetch_all(
            cursor,
            "SELECT ip FROM ip_risk_status_v2 WHERE status='白名單' AND live_status=1",
            key="ip"
        )

        white_patterns = fetch_all(
            cursor,
            "SELECT ip_pattern FROM ip_risk_ranges WHERE status='白名單'",
            key="ip_pattern"
        )

        black_ips = fetch_all(
            cursor,
            "SELECT ip FROM ip_risk_status_v2 WHERE status='LLM黑名單' AND live_status=1",
            key="ip"
        )

        black_patterns = fetch_all(
            cursor,
            "SELECT ip_pattern FROM ip_risk_ranges WHERE status='黑名單'",
            key="ip_pattern"
        )

        full_black_ips = fetch_all(
            cursor,
            "SELECT ip FROM ip_risk_status_v2 WHERE status='黑名單' AND live_status=1",
            key="ip"
        )

        return white_ips, white_patterns, black_ips, black_patterns, full_black_ips


# IP logs
def get_ip_logs(conn, ip, log_type, limit=20):
    with conn.cursor(dictionary=True) as cursor:
        return fetch_all(
            cursor,
            """
            SELECT log_content, created_at
            FROM ip_risk_logs
            WHERE ip=%s AND log_type=%s
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (ip, log_type, limit)
        )


# 24h log count
def get_ip_log_count_24h(conn, ip):
    with conn.cursor(dictionary=True) as cursor:
        row = fetch_one(
            cursor,
            """
            SELECT COUNT(*) AS cnt
            FROM ip_risk_logs
            WHERE ip=%s AND created_at >= NOW() - INTERVAL 24 HOUR
            """,
            (ip,)
        )
        return row["cnt"]


# warning IPs
def get_warning_ips(conn):
    with conn.cursor(dictionary=True) as cursor:
        return fetch_all(
            cursor,
            """
            SELECT id, ip, last_time
            FROM ip_risk_status_v2
            WHERE status IN ('警告IP', '暫時白名單')
            AND live_status = 1
            AND last_time IS NOT NULL
            """
        )


# known attacks
def get_known_attacks(conn):
    with conn.cursor(dictionary=True) as cursor:
        return fetch_all(
            cursor,
            """
            SELECT DISTINCT attack_type, attack_method
            FROM ai_log_analysis
            WHERE status='approved'
            """
        )


def is_new_attack_type(conn, attack_type: str) -> bool:
    normalized = attack_type.replace(" ", "")
    with conn.cursor(dictionary=True) as cur:
        cur.execute(
            """SELECT id FROM ai_log_analysis
               WHERE REPLACE(attack_type, ' ', '') = %s
               AND status IN ('approved','pending') LIMIT 1""",
            (normalized,)
        )
        return cur.fetchone() is None


def insert_pending_attack(conn, ip: str, attack_type: str, attack_method: str, reason: str = ""):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO ai_log_analysis (ip, attack_type, attack_method, reason, status) VALUES (%s, %s, %s, %s, 'pending')",
            (ip, attack_type, attack_method, reason)
        )


# 查詢IP最後活動時間（純SQL）
def select_ip_last_time(conn, ip):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("""
            SELECT time
            FROM ip_risk_status_v2
            WHERE ip=%s
              AND live_status=1
        """, (ip,))

        row = cursor.fetchone()

        return row["time"] if row else None


# check exists
def check_ip_exists(conn, ip):
    with conn.cursor(dictionary=True) as cursor:
        row = fetch_one(
            cursor,
            """
            SELECT 1 AS ok
            FROM ip_risk_status_v2
            WHERE ip=%s AND live_status=1
            """,
            (ip,)
        )
        return row is not None


# =========================================================
# INSERT
# =========================================================

def insert_raw_log(conn, ip, log_text, host_name, log_time, log_type, local_ip, direction):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("""
            INSERT INTO ip_risk_logs
            (ip, host_name, log_type, log_content, local_ip, direction, created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (
            ip, host_name, log_type, log_text,
            local_ip, direction, log_time
        ))
    conn.commit()


def insert_ip_risk_status(conn, ip, status, actions_json, attack_type, unblock_time, now_time, host_name):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("""
            INSERT INTO ip_risk_status_v2
            (ip, status, actions, attack_type, unblock_time, time, live_status, first_time, last_time, hostname)
            VALUES (%s,%s,%s,%s,%s,%s,1,%s,%s,%s)
        """, (
            ip,
            status,
            actions_json,
            attack_type,
            unblock_time,
            now_time,
            now_time,
            now_time,
            host_name
        ))
    conn.commit()


def insert_ip_status(conn, ip, now, host_name):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("""
            INSERT INTO ip_risk_status_v2
            (ip, first_time, last_time, hostname, status, live_status)
            VALUES (%s,%s,%s,%s,'警告IP',1)
        """, (ip, now, now, host_name))
    conn.commit()


# =========================================================
# UPDATE
# =========================================================

def disable_ip(conn, ip_id):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("""
            UPDATE ip_risk_status_v2
            SET live_status = 0
            WHERE id = %s
        """, (ip_id,))
    conn.commit()


def get_old_actions(conn, ip):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("""
            SELECT actions
            FROM ip_risk_status_v2
            WHERE ip=%s AND live_status=1
        """, (ip,))

        row = cursor.fetchone()

    if not row or not row.get("actions"):
        return []

    try:
        data = json.loads(row["actions"])
    except:
        return []

    # 保證一定是 list
    if isinstance(data, dict):
        return [data]

    if isinstance(data, list):
        return data

    return []

def update_ip_risk_status(conn, ip, status, actions_json, attack_type, unblock_time, llm_time):
    # 🔥 強制 normalize
    if not isinstance(actions_json, str):
        actions_json = json.dumps(actions_json, ensure_ascii=False)
        
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("""
            UPDATE ip_risk_status_v2
            SET status=%s,
                actions=%s,
                attack_type=%s,
                unblock_time=%s,
                time=%s
            WHERE ip=%s AND live_status=1
        """, (
            status,
            actions_json,
            attack_type,
            unblock_time,
            llm_time,
            ip
        ))
    conn.commit()


def update_ip_status(conn, ip, now, host_name):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("""
            UPDATE ip_risk_status_v2
            SET last_time=%s,
                hostname=%s
            WHERE ip=%s AND live_status=1
        """, (now, host_name, ip))
    conn.commit()


# =========================================================
# CLEANUP
# =========================================================

def insert_llm_discrepancy(conn, ip, branch, original_level, attempted_level, outcome):
    with conn.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO llm_discrepancies (ip, branch, original_level, attempted_level, outcome)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (ip, branch, original_level, attempted_level, outcome)
        )
    conn.commit()


def get_system_setting(conn, key: str, default: str = None) -> str:
    with conn.cursor(dictionary=True) as cursor:
        row = fetch_one(cursor, "SELECT `value` FROM system_settings WHERE `key` = %s ORDER BY id DESC LIMIT 1", (key,))
        return row['value'] if row else default


def cleanup_blacklist(conn):
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute("""
            UPDATE ip_risk_status_v2
            SET live_status = 0
            WHERE status IN ('LLM黑名單', '黑名單')
              AND unblock_time IS NOT NULL
              AND unblock_time < NOW()
              AND live_status = 1
        """)

        affected_rows = cursor.rowcount

    conn.commit()
    return affected_rows