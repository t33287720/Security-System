# tools/security/security_tools.py
from datetime import datetime, timedelta
import json
from tools.db.db_tools import (
    get_raw_ip_lists,
    select_ip_last_time,
    get_warning_ips,
    disable_ip,
    check_ip_exists,
    insert_ip_status,
    update_ip_status
)

from tools.firewall.ipset_tools import (
    sync_ipset,
)

def expire_warning_ips(conn):
    rows = get_warning_ips(conn)

    now = datetime.now()
    expired = 0

    for row in rows:
        last_time = row["last_time"]
        ip_id = row["id"]

        if isinstance(last_time, str):
            last_time = datetime.strptime(last_time, "%Y-%m-%d %H:%M:%S")

        if now - last_time > timedelta(hours=24):
            disable_ip(conn, ip_id)
            expired += 1

    return expired

def is_in_cooldown(conn, ip, minutes=10):
    time = select_ip_last_time(conn, ip)

    if time is None:
        return False

    cooldown_delta = timedelta(minutes=minutes)

    return (datetime.now() - time) < cooldown_delta

def build_ip_lists(conn, wildcard_to_cidr):
    white_ips, white_patterns, black_ips, black_patterns, full_black_ips = \
        get_raw_ip_lists(conn)    
    # 🔧 強制轉換：如果不是 list/set，就假設是字串要解析
    if isinstance(black_ips, str):
        if black_ips.strip():
            # 假設是逗號分隔或 JSON
            try:
                black_ips_list = json.loads(black_ips)
            except:
                black_ips_list = [ip.strip() for ip in black_ips.split(',') if ip.strip()]
        else:
            black_ips_list = []
        black_ips = black_ips_list
    
    if isinstance(full_black_ips, str):
        if full_black_ips.strip():
            try:
                full_black_ips_list = json.loads(full_black_ips)
            except:
                full_black_ips_list = [ip.strip() for ip in full_black_ips.split(',') if ip.strip()]
        else:
            full_black_ips_list = []
        full_black_ips = full_black_ips_list
    
    white_ranges = {wildcard_to_cidr(p) for p in white_patterns}
    black_ranges = {wildcard_to_cidr(p) for p in black_patterns}

    return white_ips, white_ranges, black_ips, black_ranges, full_black_ips

def update_ip_activity(conn, ip, host_name):
    now = datetime.now()

    exists = check_ip_exists(conn, ip)

    if exists:
        update_ip_status(conn, ip, now, host_name)
    else:
        insert_ip_status(conn, ip, now, host_name)

    conn.commit()

def maybe_sync_ipset(conn, enabled_hosts, IPSET_NAME, IPSET_FULL_NAME, wildcard_to_cidr, last_ipset_snapshot, IPSET_WHITELIST_NAME=None):

    if last_ipset_snapshot is None:
        last_ipset_snapshot = {
            "black": None,
            "full": None,
            "white": None,
        }

    white_ips, white_ranges, black_ips, black_ranges, full_black_ips = build_ip_lists(conn, wildcard_to_cidr)

    current_black = set(black_ips)
    current_full = set(full_black_ips)
    current_white = set(white_ips) | white_ranges

    sync_mapping = {}

    if last_ipset_snapshot["black"] != current_black:
        sync_mapping[IPSET_NAME] = black_ips

    if last_ipset_snapshot["full"] != current_full:
        sync_mapping[IPSET_FULL_NAME] = full_black_ips

    if IPSET_WHITELIST_NAME and last_ipset_snapshot.get("white") != current_white:
        sync_mapping[IPSET_WHITELIST_NAME] = list(current_white)

    if sync_mapping:
        sync_ipset(enabled_hosts, sync_mapping)

        last_ipset_snapshot["black"] = current_black
        last_ipset_snapshot["full"] = current_full
        if IPSET_WHITELIST_NAME:
            last_ipset_snapshot["white"] = current_white
        return last_ipset_snapshot

    return last_ipset_snapshot
