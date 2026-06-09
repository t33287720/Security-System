"""
cleanup_attack_types.py
整理 ai_log_analysis 與 ip_risk_status_v2 中的複合攻擊手法：
  1. 去除 "/" "、" "+" 等複合分隔符，取第一段
  2. 對映到 approved 記錄的標準名稱（忽略空格差異）
  3. 空跑模式（DRY_RUN=True）只印出變更預覽，不寫入 DB

用法（在容器或 api/ 目錄下執行）：
  python cleanup_attack_types.py          # 實際寫入
  DRY_RUN=true python cleanup_attack_types.py  # 預覽
"""
import os
import re
import sys
import mariadb
from config.settings import load_config

DRY_RUN = os.getenv("DRY_RUN", "").lower() in ("1", "true", "yes")

# LLM 創造的非標準詞 → 手動對映到標準名稱
# 鍵值不分大小寫、忽略空格，值必須是 ai_log_analysis approved 裡存在的名稱
MANUAL_MAP = {
    "偵查":   "信息收集",
    "偵測":   "信息收集",
    "掃描":   "端口掃描",
    "暴力破解": "SSH暴力破解",
    "洪水攻擊": "UDP 洪水攻擊",
    # 若有其他奇怪的詞，在這裡繼續補
}

SEPARATORS = re.compile(r'[/、+＋]')


def first_segment(raw: str) -> str:
    return SEPARATORS.split(raw)[0].strip()


def build_canonical_lookup(conn):
    """從 approved 記錄建立 去空格小寫 → 標準名稱 對照表"""
    with conn.cursor(dictionary=True) as cur:
        cur.execute(
            "SELECT DISTINCT attack_type FROM ai_log_analysis WHERE status='approved' AND attack_type IS NOT NULL"
        )
        rows = cur.fetchall()
    return {r["attack_type"].replace(" ", "").lower(): r["attack_type"] for r in rows if r["attack_type"]}


def normalize(raw: str, lookup: dict) -> tuple[str, str]:
    """
    回傳 (標準名稱, 來源)
    來源: 'canonical' | 'manual' | 'unmatched'
    """
    seg = first_segment(raw)
    key = seg.replace(" ", "").lower()

    if key in lookup:
        return lookup[key], "canonical"

    manual_key = key
    for mk, mv in MANUAL_MAP.items():
        if mk.replace(" ", "").lower() == manual_key:
            return mv, "manual"

    return seg, "unmatched"


def collect_changes(conn, table: str, id_col: str, lookup: dict) -> dict:
    with conn.cursor(dictionary=True) as cur:
        cur.execute(f"SELECT {id_col}, attack_type FROM {table} WHERE attack_type IS NOT NULL")
        rows = cur.fetchall()

    result = {"canonical": [], "manual": [], "unmatched": []}
    for row in rows:
        original = row["attack_type"]
        fixed, source = normalize(original, lookup)
        if fixed != original:
            result[source].append((row[id_col], original, fixed))
    return result


def apply_changes(conn, table: str, id_col: str, groups: dict):
    all_changes = groups["canonical"] + groups["manual"]
    with conn.cursor() as cur:
        for rid, _, new in all_changes:
            cur.execute(f"UPDATE {table} SET attack_type=%s WHERE {id_col}=%s", (new, rid))
    conn.commit()


def print_changes(table: str, groups: dict):
    canonical  = groups["canonical"]
    manual     = groups["manual"]
    unmatched  = groups["unmatched"]

    total = len(canonical) + len(manual) + len(unmatched)
    if total == 0:
        print(f"[{table}] 沒有需要整理的記錄。\n")
        return

    print(f"[{table}]")

    if canonical:
        print(f"  ✔ 空格對映（自動）{len(canonical)} 筆：")
        for rid, old, new in canonical:
            print(f"    {rid:>6}  {old:<45} → {new}")

    if manual:
        print(f"  ✔ 手動對映（MANUAL_MAP）{len(manual)} 筆：")
        for rid, old, new in manual:
            print(f"    {rid:>6}  {old:<45} → {new}")

    if unmatched:
        print(f"  ⚠ 無法對映（需補充 MANUAL_MAP）{len(unmatched)} 筆：")
        for rid, old, new in unmatched:
            print(f"    {rid:>6}  {old:<45}  （切完第一段 = '{new}'，未寫入）")

    print()


def run(conn):
    lookup = build_canonical_lookup(conn)
    print(f"標準攻擊手法（approved）共 {len(lookup)} 種：")
    for k, v in sorted(lookup.items()):
        print(f"  {v}")
    print()

    targets = [
        ("ai_log_analysis",  "id"),
        ("ip_risk_status_v2", "id"),
    ]

    all_groups = {}
    for table, id_col in targets:
        groups = collect_changes(conn, table, id_col, lookup)
        print_changes(table, groups)
        all_groups[table] = (id_col, groups)

    total_writable = sum(
        len(g["canonical"]) + len(g["manual"])
        for _, g in all_groups.values()
    )
    total_unmatched = sum(
        len(g["unmatched"])
        for _, g in all_groups.values()
    )

    if total_unmatched:
        print(f"⚠ 有 {total_unmatched} 筆無法對映，請在 MANUAL_MAP 補上對應後重新執行。\n")

    if total_writable == 0:
        print("沒有可寫入的變更。")
        return

    if DRY_RUN:
        print(f"[DRY RUN] 共 {total_writable} 筆可更新，未寫入。設 DRY_RUN=false 後再執行。")
        return

    confirm = input(f"確認更新兩個資料表共 {total_writable} 筆？(y/N) ").strip().lower()
    if confirm != "y":
        print("已取消。")
        return

    for table, (id_col, groups) in all_groups.items():
        writable = len(groups["canonical"]) + len(groups["manual"])
        if writable:
            apply_changes(conn, table, id_col, groups)
            print(f"[{table}] 已更新 {writable} 筆。")

    print("完成。")


if __name__ == "__main__":
    cfg = load_config()
    try:
        conn = mariadb.connect(
            host=cfg["db_host"],
            user=cfg["db_user"],
            password=cfg["db_password"],
            database=cfg["db_name"],
        )
    except mariadb.Error as e:
        print(f"DB 連線失敗: {e}")
        sys.exit(1)

    try:
        run(conn)
    finally:
        conn.close()
