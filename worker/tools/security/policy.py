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


def save_analysis_result(conn, ip, analysis_data, host_name):
    level = analysis_data.get("danger_level", "正常")
    confidence = analysis_data.get("confidence", "0")
    llm_time = datetime.now()

    # -------------------------
    # policy decision（業務邏輯）
    # -------------------------
    if level == "危險":
        if confidence > 0.8:
            status = "黑名單"
            unblock_time = llm_time + timedelta(hours=24)
        else:
            status = "LLM黑名單"
            unblock_time = llm_time + timedelta(minutes=5)

    elif level == "可疑":
        status = "觀察名單"
        unblock_time = None

    else:
        status = "觀察名單"
        unblock_time = None

    actions_json = json.dumps([analysis_data], ensure_ascii=False)
    attack_type = normalize_attack_type(analysis_data.get("attack_type", "未知"))

    # -------------------------
    # DB decision move to service layer（重點改這裡）
    # -------------------------
    exists = check_ip_exists(conn, ip)

    if exists:
        old_actions = get_old_actions(conn, ip)
        try:
            new_actions = json.loads(actions_json) if isinstance(actions_json, str) else actions_json
        except:
            new_actions = actions_json

        if isinstance(new_actions, dict):
            new_actions = [new_actions]
        # -------------------------
        # 3️⃣ 疊加
        # -------------------------
        merged_actions = old_actions + new_actions

        # （可選）限制大小，避免爆炸
        merged_actions = merged_actions[-50:]

        update_ip_risk_status(
            conn, ip,
            status, merged_actions,
            attack_type, unblock_time,
            llm_time
        )
    else:
        insert_ip_risk_status(
            conn, ip,
            status, actions_json,
            attack_type, unblock_time,
            llm_time,
            host_name
        )