"""
一次性清理腳本：對 DB 裡 status='黑名單' 的 IP
重新比對當前 openblacklist，更新 actions 欄位。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import mariadb
from config.settings import load_config, openblacklist_PARSED_DIR
from tools.firewall.openblacklist_matcher import load_blacklists, is_blacklisted, handle_blacklist_hit
from tools.db.db_tools import fetch_all

def get_live_blacklist_ips(conn):
    with conn.cursor(dictionary=True) as cursor:
        return fetch_all(
            cursor,
            "SELECT ip, hostname FROM ip_risk_status_v2 WHERE status='黑名單' AND live_status=1",
        )

def main():
    config = load_config()
    conn = mariadb.connect(
        host=config['db_host'],
        user=config['db_user'],
        password=config['db_password'],
        database=config['db_name'],
        autocommit=True
    )

    openblacklist = load_blacklists(openblacklist_PARSED_DIR)
    rows = get_live_blacklist_ips(conn)
    print(f"[INFO] 共 {len(rows)} 筆黑名單 IP 待更新")

    updated = 0
    skipped = 0

    for row in rows:
        ip = row['ip']
        host_name = row.get('hostname') or ''
        results = is_blacklisted(openblacklist, ip)

        if results:
            handle_blacklist_hit(conn, ip, results, host_name)
            sources = ', '.join({s for _, s in results})
            print(f"  [UPDATE] {ip} → {sources}")
            updated += 1
        else:
            print(f"  [SKIP]   {ip} 已不在任何黑名單中（不更新）")
            skipped += 1

    conn.close()
    print(f"\n[DONE] 更新 {updated} 筆，略過 {skipped} 筆")

if __name__ == '__main__':
    main()
