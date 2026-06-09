# tools/eval/eval_tools.py
import json
import os
from datetime import datetime, timedelta

_TUNING_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), '..', '..', 'eval', 'tuning_config.json'
)


def _load_tuning_config():
    try:
        with open(_TUNING_CONFIG_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {"fn_limit": 3, "fp_limit": 2}


def get_eval_label_counts(conn):
    """回傳 eval_results 中累積的 attack/benign 筆數。"""
    with conn.cursor(dictionary=True) as cur:
        cur.execute("""
            SELECT true_label, COUNT(*) AS cnt
            FROM eval_results
            GROUP BY true_label
        """)
        counts = {row['true_label']: row['cnt'] for row in cur.fetchall()}
    return counts.get('attack', 0), counts.get('benign', 0)


def is_in_eval_cooldown(conn, ip, minutes=60):
    """同一 IP 在 N 分鐘內已做過 eval，跳過避免重複分析。"""
    with conn.cursor(dictionary=True) as cur:
        cur.execute("""
            SELECT 1 FROM eval_results
            WHERE ip = %s AND analyzed_at >= NOW() - INTERVAL %s MINUTE
            LIMIT 1
        """, (ip, minutes))
        return cur.fetchone() is not None


def _fetch_fn_examples(conn, where_clause, limit):
    """
    FN 選法：取最常失敗的 N 種攻擊類型，每種各選 confidence 最高的那筆。
    目的：以最少案例涵蓋最多失敗模式，避免同類型案例佔滿 slot。
    """
    # 先找出最常出現的 FN 攻擊類型
    with conn.cursor(dictionary=True) as cur:
        cur.execute(f"""
            SELECT attack_type
            FROM eval_results
            WHERE true_label = 'attack'
              AND danger_level != '危險'
              AND {where_clause}
              AND attack_type IS NOT NULL AND attack_type != ''
            GROUP BY attack_type
            ORDER BY COUNT(*) DESC
            LIMIT %s
        """, (limit,))
        top_types = [r['attack_type'] for r in cur.fetchall()]

    if not top_types:
        return []

    # 每個類型各取 confidence 最高的一筆（LLM 最有把握卻最錯）
    examples = []
    with conn.cursor(dictionary=True) as cur:
        for at in top_types:
            cur.execute(f"""
                SELECT attack_type, danger_level, confidence, actions
                FROM eval_results
                WHERE true_label = 'attack'
                  AND danger_level != '危險'
                  AND {where_clause}
                  AND attack_type = %s
                ORDER BY confidence DESC
                LIMIT 1
            """, (at,))
            row = cur.fetchone()
            if row:
                examples.append(row)
    return examples


def _fetch_fp_examples(conn, where_clause, limit):
    """
    FP 選法：同樣取最常誤報的 N 種類型，每種各選 confidence 最高的那筆。
    """
    with conn.cursor(dictionary=True) as cur:
        cur.execute(f"""
            SELECT attack_type
            FROM eval_results
            WHERE true_label = 'benign'
              AND danger_level = '危險'
              AND {where_clause}
              AND attack_type IS NOT NULL AND attack_type != ''
            GROUP BY attack_type
            ORDER BY COUNT(*) DESC
            LIMIT %s
        """, (limit,))
        top_types = [r['attack_type'] for r in cur.fetchall()]

    if not top_types:
        return []

    examples = []
    with conn.cursor(dictionary=True) as cur:
        for at in top_types:
            cur.execute(f"""
                SELECT attack_type, danger_level, confidence, actions
                FROM eval_results
                WHERE true_label = 'benign'
                  AND danger_level = '危險'
                  AND {where_clause}
                  AND attack_type = %s
                ORDER BY confidence DESC
                LIMIT 1
            """, (at,))
            row = cur.fetchone()
            if row:
                examples.append(row)
    return examples


def _format_hints(fn_rows, fp_rows, window_label):
    """將 FN/FP 案例格式化成 prompt 片段，包含 LLM 的錯誤推論。"""
    lines = []

    if fn_rows:
        lines.append(f"【漏報矯正（{window_label}真實攻擊但被低估的案例）】")
        for i, r in enumerate(fn_rows, 1):
            try:
                actions = json.loads(r['actions']) if r['actions'] else {}
            except (ValueError, TypeError):
                actions = {}
            wrong_reason   = actions.get('reason', '').strip()
            wrong_behavior = actions.get('overall_behavior', '').strip()
            lines.append(f"  案例{i}｜攻擊類型：{r['attack_type']}｜LLM 誤判為：{r['danger_level']}（{r['confidence']}）")
            if wrong_behavior:
                lines.append(f"    LLM 當時描述：「{wrong_behavior[:80]}」")
            if wrong_reason:
                lines.append(f"    LLM 錯誤推論：「{wrong_reason[:100]}」")
            lines.append(f"    → 此類行為應判危險，不應因缺乏 payload 就降級")

    if fp_rows:
        lines.append(f"【誤報矯正（{window_label}正常流量被過度判定的案例）】")
        for i, r in enumerate(fp_rows, 1):
            try:
                actions = json.loads(r['actions']) if r['actions'] else {}
            except (ValueError, TypeError):
                actions = {}
            wrong_reason = actions.get('reason', '').strip()
            lines.append(f"  案例{i}｜LLM 誤判類型：{r['attack_type']}｜誤判為：{r['danger_level']}（{r['confidence']}）")
            if wrong_reason:
                lines.append(f"    LLM 錯誤推論：「{wrong_reason[:100]}」")
            lines.append(f"    → 此類行為為正常流量，應審慎區分攻擊特徵")

    return "\n".join(lines)


def get_eval_hints(conn, fn_limit=None, fp_limit=None, min_records=3):
    """
    從 eval_results 提取 FN/FP 案例，附帶 LLM 的錯誤推論，回傳可注入 prompt 的字串。
    優先用昨天資料；若昨天筆數不足 min_records，退回近 7 天。
    空字串 = 完全無資料，呼叫端可直接略過注入。
    fn_limit/fp_limit 若未傳入，從 tuning_config.json 動態讀取。
    """
    if fn_limit is None or fp_limit is None:
        cfg = _load_tuning_config()
        fn_limit = fn_limit if fn_limit is not None else cfg.get('fn_limit', 3)
        fp_limit = fp_limit if fp_limit is not None else cfg.get('fp_limit', 2)

    yesterday = "DATE(analyzed_at) = CURDATE() - INTERVAL 1 DAY"
    fn_rows = _fetch_fn_examples(conn, yesterday, fn_limit)
    fp_rows = _fetch_fp_examples(conn, yesterday, fp_limit)
    window_label = "昨日"

    if len(fn_rows) + len(fp_rows) < min_records:
        week = "analyzed_at >= NOW() - INTERVAL 7 DAY"
        fn_rows = _fetch_fn_examples(conn, week, fn_limit)
        fp_rows = _fetch_fp_examples(conn, week, fp_limit)
        window_label = "近7天"

    if not fn_rows and not fp_rows:
        return ""

    return _format_hints(fn_rows, fp_rows, window_label)


def save_eval_result(conn, ip, analysis, true_label, gt_source, log_count, source_count=1):
    """
    將 LLM eval 分析結果寫入 eval_results。
    analysis:     dict（LLM 回傳的 JSON）
    true_label:   'attack' | 'benign'
    gt_source:    'openblacklist' | 'whitelist'
    log_count:    送入分析的 log 筆數
    source_count: 命中幾個獨立 blacklist 源（benign 固定傳 0）
    """
    if not analysis:
        return

    danger_level = analysis.get('danger_level', '')
    try:
        confidence = float(analysis.get('confidence', 0))
    except (ValueError, TypeError):
        confidence = 0.0
    attack_type  = analysis.get('attack_type', '')
    actions_json = json.dumps(analysis, ensure_ascii=False)

    with conn.cursor(dictionary=True) as cur:
        cur.execute("""
            INSERT INTO eval_results
                (ip, true_label, gt_source, danger_level, confidence,
                 attack_type, actions, log_count, source_count, analyzed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (ip, true_label, gt_source, danger_level, confidence,
              attack_type, actions_json, log_count, source_count))
    conn.commit()
