# tools/firewall/openblacklist_matcher.py
import os
import ipaddress
from datetime import datetime, timedelta
import json
from tools.db.db_tools import (check_ip_exists, update_ip_risk_status, insert_ip_risk_status,)

def load_blacklists(PARSED_DIR):
    BLACKLIST = []

    for file in os.listdir(PARSED_DIR):
        path = os.path.join(PARSED_DIR, file)

        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    net = ipaddress.ip_network(line)
                    BLACKLIST.append((net, file))  # ⭐ 保留來源檔案
                except:
                    continue

    print(f"[BLACKLIST] loaded {len(BLACKLIST)} networks")
    return BLACKLIST


def is_blacklisted(BLACKLIST, ip):
    ip_obj = ipaddress.ip_address(ip)

    hits = []

    for net, source in BLACKLIST:
        if ip_obj in net:
            hits.append((net, source))

    return hits

def handle_blacklist_hit(conn, ip, results, host_name):
    """
    blacklist 命中後：
    - 組 actions_json
    - 直接寫 DB
    - 回傳 True/False
    """

    if not results:
        return False

    match_list = []
    sources = set()

    for net, source in results:
        match_list.append({
            "network": str(net),
            "source": source
        })
        sources.add(source)

    actions_json = [
        {
            "analysis_basis": [
                f"IP {ip} 命中黑名單 CIDR 規則",
                f"命中來源包含 {', '.join(sources)}"
            ],
            "overall_behavior": "IP 位於已知公開惡意黑名單網段中，系統直接依規則判定風險行為。",
            "danger_level": "危險",
            "reason": "命中外部威脅情資黑名單（Threat Intelligence Feed）。",
            "attack_type": "已知惡意IP",
            "attack_method": "黑名單比對",
            "blacklist_matches": match_list
        }
    ]
    attack_type = actions_json[0]["attack_type"]
    now = datetime.now()
    unblock_time = now + timedelta(hours=24)

    exists = check_ip_exists(conn, ip)
    if exists:
        update_ip_risk_status(
            conn,
            ip,
            "黑名單",
            json.dumps(actions_json, ensure_ascii=False), 
            attack_type,
            unblock_time,
            now
        )
    else:
        insert_ip_risk_status(
            conn,
            ip,
            "黑名單",
            json.dumps(actions_json, ensure_ascii=False), 
            attack_type,
            unblock_time,
            now,
            host_name
        )

    return True