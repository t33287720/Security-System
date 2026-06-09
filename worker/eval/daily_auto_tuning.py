"""
每日自主調整腳本 — 根據 daily_snapshots.csv 的 MCC/Recall 趨勢
自動調整 eval_hints 的 fn_limit / fp_limit，寫入 tuning_config.json。

執行時機：每天 01:00（由 crontab 驅動）
用法：
    cd /var/www/html/GAIsecurity/api
    python3 eval/daily_auto_tuning.py
"""

import csv
import json
import os
from datetime import datetime

OUTPUT_DIR    = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'eval', 'output')
SNAPSHOT_CSV  = os.path.join(OUTPUT_DIR, 'daily_snapshots.csv')
TUNING_CONFIG = os.path.join(OUTPUT_DIR, 'tuning_config.json')
LOG_PATH      = os.path.join(OUTPUT_DIR, 'auto_tuning.log')

# 調整上下限
FN_LIMIT_MIN, FN_LIMIT_MAX = 3, 8
FP_LIMIT_MIN, FP_LIMIT_MAX = 1, 5

# 告警閾值
RECALL_WARN   = 0.90   # Recall 低於此值 → 強化 FN 矯正
FPR_WARN      = 0.15   # FPR 高於此值   → 強化 FP 矯正
MCC_IMPROVE   = 0.007  # 3天滑動視窗 delta 門檻


def log(msg):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_PATH, 'a', encoding='utf-8') as f:
        f.write(line + '\n')


def read_last_n_snapshots(n=6):
    """讀取 daily_snapshots.csv，每天只取第一筆，回傳最近 n 天（按日期排序）。"""
    if not os.path.isfile(SNAPSHOT_CSV):
        return []

    day_rows = {}
    with open(SNAPSHOT_CSV, 'r', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            d = row.get('date', '').strip()
            if d and d not in day_rows:
                day_rows[d] = row

    sorted_days = sorted(day_rows.keys())[-n:]
    return [day_rows[d] for d in sorted_days]


def read_tuning_config():
    if not os.path.isfile(TUNING_CONFIG):
        return {"fn_limit": 3, "fp_limit": 2}
    with open(TUNING_CONFIG, 'r', encoding='utf-8') as f:
        return json.load(f)


def write_tuning_config(fn_limit, fp_limit, mcc_trend, recall_trend,
                        last_mcc, last_recall, note, last_action):
    cfg = {
        "fn_limit":          fn_limit,
        "fp_limit":          fp_limit,
        "last_updated":      datetime.now().strftime('%Y-%m-%d'),
        "mcc_trend":         mcc_trend,
        "recall_trend":      recall_trend,
        "last_mcc":          round(last_mcc, 4),
        "last_recall":       round(last_recall, 4),
        "note":              note,
        "last_action":       last_action,
        "pre_action_mcc":    round(last_mcc, 4),
        "pre_action_recall": round(last_recall, 4),
    }
    with open(TUNING_CONFIG, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    log(f"tuning_config 已更新：fn_limit={fn_limit}  fp_limit={fp_limit}  note={note}")


def detect_trend(values):
    """
    3天滑動視窗趨勢判斷：比較最近3天平均 vs 再前3天平均。
    資料不足6天時退化為單點 vs 前段平均。
    回傳 'improving' / 'stable' / 'declining'
    """
    if len(values) >= 6:
        recent = sum(values[-3:]) / 3
        prior  = sum(values[-6:-3]) / 3
    elif len(values) >= 2:
        recent = values[-1]
        prior  = sum(values[:-1]) / len(values[:-1])
    else:
        return 'stable'
    delta = recent - prior
    if delta > MCC_IMPROVE:
        return 'improving'
    elif delta < -MCC_IMPROVE:
        return 'declining'
    return 'stable'


def main():
    log("=== daily_auto_tuning 開始 ===")

    # ── Idempotency：同一天只執行一次
    cfg   = read_tuning_config()
    today = datetime.now().strftime('%Y-%m-%d')
    if cfg.get('last_updated') == today:
        log(f"今日（{today}）已執行過，略過")
        return

    rows = read_last_n_snapshots(n=6)
    if len(rows) < 2:
        log("資料不足 2 天，略過調整")
        return

    mccs    = [float(r['mcc'])    for r in rows if r.get('mcc')]
    recalls = [float(r['recall']) for r in rows if r.get('recall')]
    fprs    = [float(r['fpr'])    for r in rows if r.get('fpr')]

    if not mccs:
        log("無有效 MCC 資料，略過")
        return

    last_mcc    = mccs[-1]
    last_recall = recalls[-1] if recalls else 0.0
    last_fpr    = fprs[-1]    if fprs    else 0.0

    # ── 驗證上次調整是否有效
    prev_action    = cfg.get('last_action', '無變化')
    pre_action_mcc    = cfg.get('pre_action_mcc')
    pre_action_recall = cfg.get('pre_action_recall')
    if prev_action != '無變化' and pre_action_mcc is not None:
        mcc_delta    = last_mcc    - pre_action_mcc
        recall_delta = last_recall - pre_action_recall
        effective    = mcc_delta >= 0 or recall_delta >= 0
        log(f"上次調整（{prev_action}）效果："
            f"MCC {pre_action_mcc:.4f}→{last_mcc:.4f}（{mcc_delta:+.4f}）  "
            f"Recall {pre_action_recall:.4f}→{last_recall:.4f}（{recall_delta:+.4f}）  "
            f"{'✓ 有效' if effective else '✗ 無效'}")

    mcc_trend    = detect_trend(mccs)
    recall_trend = detect_trend(recalls) if recalls else 'stable'

    log(f"趨勢偵測：MCC={mcc_trend} ({last_mcc:.4f})  "
        f"Recall={recall_trend} ({last_recall:.4f})  FPR={last_fpr:.4f}")

    fn_limit = cfg.get('fn_limit', 3)
    fp_limit = cfg.get('fp_limit', 2)
    note_parts = []

    # ── FN 矯正強度（Recall 下降 → 給更多漏報範例）
    if mcc_trend == 'declining' or recall_trend == 'declining' or last_recall < RECALL_WARN:
        if fn_limit < FN_LIMIT_MAX:
            fn_limit += 1
            note_parts.append(f"Recall={last_recall:.3f} 下降，fn_limit↑{fn_limit}")
        else:
            log("⚠ fn_limit 已達上限但指標仍在下降，參數調整空間耗盡，需人工介入")
    elif mcc_trend == 'improving' or recall_trend == 'improving':
        if fn_limit > FN_LIMIT_MIN:
            fn_limit -= 1
            note_parts.append(f"MCC/Recall 改善，fn_limit↓{fn_limit}")

    # ── FP 矯正強度（FPR 上升 → 給更多誤報範例）
    if last_fpr > FPR_WARN:
        if fp_limit < FP_LIMIT_MAX:
            fp_limit += 1
            note_parts.append(f"FPR={last_fpr:.3f} 偏高，fp_limit↑{fp_limit}")
    elif last_fpr < FPR_WARN * 0.5 and mcc_trend == 'improving':
        if fp_limit > FP_LIMIT_MIN:
            fp_limit -= 1
            note_parts.append(f"FPR 已低，fp_limit↓{fp_limit}")

    note        = "; ".join(note_parts) if note_parts else "無變化"
    last_action = note
    write_tuning_config(fn_limit, fp_limit, mcc_trend, recall_trend,
                        last_mcc, last_recall, note, last_action)

    # ── RAG 索引增量更新（把昨日新增的 FN/FP 案例加入 ChromaDB）
    log("更新 RAG ChromaDB 索引...")
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from config.settings import load_config
        import mariadb
        from eval.rag_store import build_index
        cfg_db = load_config()
        conn = mariadb.connect(
            host=cfg_db['db_host'], user=cfg_db['db_user'],
            password=cfg_db['db_password'], database=cfg_db['db_name'],
            autocommit=True
        )
        build_index(conn, verbose=False)
        conn.close()
        log("RAG 索引更新完成")
    except Exception as e:
        log(f"⚠ RAG 索引更新失敗：{e}")
        log("⚠ fn_limit/fp_limit 已調整但 RAG 索引未同步，本次調整效果可能不完整")

    log("=== daily_auto_tuning 完成 ===\n")


if __name__ == '__main__':
    main()
