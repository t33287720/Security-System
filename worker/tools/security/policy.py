# tools/security/policy.py
from datetime import datetime, timedelta
import json
import re
from tools.db.db_tools import (
    check_ip_exists,
    update_ip_risk_status,
    insert_ip_risk_status,
    get_old_actions
)


def normalize_attack_type(raw: str) -> str:
    if not raw:
        return raw
    return re.split(r'[/、+＋]', raw)[0].strip()


def write_ip_risk_status(conn, ip, status, action_entry, attack_type, unblock_time, event_time, host_name):
    """
    唯一負責寫入 ip_risk_status_v2 status/actions 的地方。
    exists 時把 action_entry 疊加進歷史 actions（上限 50 筆），否則新增一列。
    所有會寫這張表的呼叫端（AI 判斷、公開黑名單命中...）都應該走這裡，
    避免各自組 SQL 導致「疊加歷史」規則不一致（例如某條路徑整個覆蓋掉歷史紀錄）。
    """
    exists = check_ip_exists(conn, ip)

    if exists:
        old_actions = get_old_actions(conn, ip)
        merged_actions = (old_actions + [action_entry])[-50:]

        update_ip_risk_status(
            conn, ip,
            status, merged_actions,
            attack_type, unblock_time,
            event_time
        )
    else:
        insert_ip_risk_status(
            conn, ip,
            status, json.dumps([action_entry], ensure_ascii=False),
            attack_type, unblock_time,
            event_time,
            host_name
        )


def save_analysis_result(conn, ip, analysis_data, host_name):
    level = analysis_data.get("danger_level", "正常")
    try:
        confidence = float(analysis_data.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        confidence = 0.0
    llm_time = datetime.now()

    # -------------------------
    # policy decision（業務邏輯）
    # -------------------------
    # 只有「高信心的危險」才封鎖 24h；低信心危險/可疑/正常一律進觀察名單不封鎖
    if level == "危險" and confidence > 0.8:
        status = "LLM黑名單"
        unblock_time = llm_time + timedelta(hours=24)

    else:
        status = "觀察名單"
        unblock_time = llm_time + timedelta(hours=24)

    attack_type = normalize_attack_type(analysis_data.get("attack_type", "未知"))

    write_ip_risk_status(conn, ip, status, analysis_data, attack_type, unblock_time, llm_time, host_name)