"""
評估 LLM 分析效能 — 從 eval_results 計算指標並產生圖表

用法：
    cd /var/www/html/GAIsecurity/api
    python3 eval/eval_metrics.py

前置條件：
    1. 執行 migrate_eval_table.sql 建立 eval_results 表
    2. 系統已在 EVAL_MODE 下運行並累積資料（eval_results 有紀錄）

輸出：
    eval/output/metrics_report.json   所有閾值的完整指標
    eval/output/metrics_report.csv    同上（CSV，方便貼 thesis 表格）
    eval/output/roc_curve.png         ROC 曲線（兩種 scope 對比）
    eval/output/pr_curve_*.png        Precision/Recall/F1 vs Threshold
    eval/output/confusion_best.png    最佳 F1 的混淆矩陣
"""

import json
import csv
import os
import sys
import mariadb
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.metrics import matthews_corrcoef

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from config.settings import load_config

# __file__ = /app/eval/eval_metrics.py → go up 2 levels to /app, then data/eval/output
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'eval', 'output')
os.makedirs(OUTPUT_DIR, exist_ok=True)



# ─────────────────────────────────────────────
# DB
# ─────────────────────────────────────────────

def get_conn():
    cfg = load_config()
    return mariadb.connect(
        host=cfg['db_host'], user=cfg['db_user'],
        password=cfg['db_password'], database=cfg['db_name'],
        autocommit=True
    )


def fetch_eval_records(conn, up_to_date=None):
    """
    從 eval_results 取出評估紀錄。
    up_to_date: 'YYYY-MM-DD' 字串，若給定則只取該日 23:59:59 之前的累積資料。
    """
    with conn.cursor(dictionary=True) as cur:
        if up_to_date:
            cur.execute("""
                SELECT ip, true_label, danger_level, confidence, gt_source, analyzed_at
                FROM eval_results
                WHERE analyzed_at <= %s
                ORDER BY analyzed_at DESC
            """, (up_to_date + ' 23:59:59',))
        else:
            cur.execute("""
                SELECT ip, true_label, danger_level, confidence, gt_source, analyzed_at
                FROM eval_results
                ORDER BY analyzed_at DESC
            """)
        return cur.fetchall()


# ─────────────────────────────────────────────
# Metrics 計算
# ─────────────────────────────────────────────

def predict_at_threshold(records, threshold, scope):
    """
    scope:
      '危險only'  → danger_level='危險' AND confidence >= threshold → 預測 attack
      '危險+可疑' → danger_level in ('危險','可疑') AND conf >= threshold → 預測 attack
    """
    results = []
    for r in records:
        y_true = 1 if r['true_label'] == 'attack' else 0
        d = r['danger_level'] or ''
        try:
            c = float(r['confidence'] or 0)
        except (ValueError, TypeError):
            c = 0.0

        if scope == '危險only':
            y_pred = int(d == '危險' and c >= threshold)
        else:
            y_pred = int(d in ('危險', '可疑') and c >= threshold)

        results.append({'y_true': y_true, 'y_pred': y_pred, 'ip': r['ip']})
    return results


def compute_metrics(results):
    TP = sum(1 for r in results if r['y_true'] == 1 and r['y_pred'] == 1)
    FP = sum(1 for r in results if r['y_true'] == 0 and r['y_pred'] == 1)
    FN = sum(1 for r in results if r['y_true'] == 1 and r['y_pred'] == 0)
    TN = sum(1 for r in results if r['y_true'] == 0 and r['y_pred'] == 0)

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = 2*precision*recall / (precision+recall) if (precision+recall) > 0 else 0.0
    fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    accuracy  = (TP + TN) / len(results) if results else 0.0

    y_true_arr = [r['y_true'] for r in results]
    y_pred_arr = [r['y_pred'] for r in results]
    mcc = matthews_corrcoef(y_true_arr, y_pred_arr) if len(set(y_true_arr)) > 1 else 0.0

    specificity = TN / (FP + TN) if (FP + TN) > 0 else 0.0  # 1 - FPR

    return dict(TP=TP, FP=FP, FN=FN, TN=TN,
                precision=round(precision, 4),
                recall=round(recall, 4),
                f1=round(f1, 4),
                fpr=round(fpr, 4),
                specificity=round(specificity, 4),
                accuracy=round(accuracy, 4),
                mcc=round(float(mcc), 4))


# ─────────────────────────────────────────────
# 圖表
# ─────────────────────────────────────────────

SCOPE_EN = {'危險only': 'Danger Only', '危險+可疑': 'Danger+Suspicious'}


def plot_confusion(m, threshold, scope, out_path):
    scope_label = SCOPE_EN.get(scope, scope)
    cm = np.array([[m['TN'], m['FP']], [m['FN'], m['TP']]])
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, cmap=plt.cm.Blues)
    plt.colorbar(im, ax=ax)
    ax.set_xticks([0, 1]); ax.set_xticklabels(['Pred Benign', 'Pred Attack'])
    ax.set_yticks([0, 1]); ax.set_yticklabels(['True Benign', 'True Attack'])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha='center', va='center',
                    color='white' if cm[i, j] > cm.max()/2 else 'black', fontsize=14)
    ax.set_title(f'Confusion Matrix  scope={scope_label}  threshold={threshold:.2f}')
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f'[chart] Confusion -> {out_path}')


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

SNAPSHOT_CSV = os.path.join(OUTPUT_DIR, 'daily_snapshots.csv')
SNAPSHOT_FIELDS = ['date', 'n_total', 'n_attack', 'n_benign',
                   'precision', 'recall', 'f1', 'fpr', 'specificity', 'accuracy', 'mcc',
                   'TP', 'FP', 'FN', 'TN', 'best_threshold']


def save_daily_snapshot(best, n_total, n_attack, n_benign):
    """每天只寫第一筆；當天已有紀錄則略過，保持一致性。"""
    today = datetime.now().strftime('%Y-%m-%d')
    file_exists = os.path.isfile(SNAPSHOT_CSV)

    if file_exists:
        with open(SNAPSHOT_CSV, 'r', encoding='utf-8-sig') as f:
            if any(row.get('date') == today for row in csv.DictReader(f)):
                print(f'[快照] 今日已有紀錄，略過 ({today})')
                return

    with open(SNAPSHOT_CSV, 'a', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=SNAPSHOT_FIELDS)
        if not file_exists:
            w.writeheader()
        w.writerow({
            'date':           today,
            'n_total':        n_total,
            'n_attack':       n_attack,
            'n_benign':       n_benign,
            'precision':      best['precision'],
            'recall':         best['recall'],
            'f1':             best['f1'],
            'fpr':            best['fpr'],
            'specificity':    best.get('specificity', ''),
            'accuracy':       best['accuracy'],
            'mcc':            best.get('mcc', ''),
            'TP':             best['TP'],
            'FP':             best['FP'],
            'FN':             best['FN'],
            'TN':             best['TN'],
            'best_threshold': best['threshold'],
        })
    print(f'[快照] 已寫入 {today} → {SNAPSHOT_CSV}')


def plot_trend(out_path):
    """讀 daily_snapshots.csv，畫累積趨勢折線圖。"""
    if not os.path.isfile(SNAPSHOT_CSV):
        return

    # 每天只取第一筆（first-wins），用 dict 去重後按日期排序
    day_rows = {}
    with open(SNAPSHOT_CSV, 'r', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            d = row['date'].strip()
            if d and d not in day_rows:
                day_rows[d] = row

    dates, precisions, recalls, f1s, fprs, specs, mccs, totals = \
        [], [], [], [], [], [], [], []
    for d in sorted(day_rows.keys()):
        row = day_rows[d]
        dates.append(d)
        precisions.append(float(row['precision']))
        recalls.append(float(row['recall']))
        f1s.append(float(row['f1']))
        fprs.append(float(row['fpr']))
        specs.append(float(row['specificity']) if row.get('specificity') else None)
        mccs.append(float(row['mcc']) if row.get('mcc') else None)
        totals.append(int(row['n_total']))

    if len(dates) < 2:
        return  # 只有一天，不畫趨勢

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), sharex=True)

    # 上圖：P/R/F1/FPR/Specificity/MCC 趨勢
    ax1.plot(dates, precisions, marker='s', label='Precision',   color='#2ecc71')
    ax1.plot(dates, recalls,    marker='o', label='Recall',       color='#e74c3c')
    ax1.plot(dates, f1s,        marker='^', label='F1',           color='#9b59b6', linewidth=2)
    ax1.plot(dates, fprs,       marker='v', label='FPR',          color='#e67e22', linestyle='--')
    _spec_valid = [(d, v) for d, v in zip(dates, specs) if v is not None]
    if _spec_valid:
        ax1.plot([x[0] for x in _spec_valid], [x[1] for x in _spec_valid],
                 marker='P', label='Specificity (1-FPR)', color='#2980b9', linestyle='-.')
    _mcc_valid = [(d, v) for d, v in zip(dates, mccs) if v is not None]
    if _mcc_valid:
        ax1.plot([x[0] for x in _mcc_valid], [x[1] for x in _mcc_valid],
                 marker='D', label='MCC', color='#1abc9c', linestyle=':')
    ax1.set_ylabel('Score')
    ax1.set_title('LLM Evaluation Metrics — Daily Trend')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    ax1.set_ylim(0, 1.05)
    plt.setp(ax1.get_xticklabels(), rotation=30, ha='right')

    # 下圖：累積評估筆數
    ax2.bar(dates, totals, color='#3498db', alpha=0.7, label='Eval Count')
    ax2.set_ylabel('Total Count')
    ax2.set_xlabel('Date')
    ax2.legend()
    ax2.grid(True, alpha=0.3, axis='y')
    plt.setp(ax2.get_xticklabels(), rotation=30, ha='right')

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f'[圖表] 趨勢圖   → {out_path}')


def _compute_best(records):
    """計算 sweep 並回傳最佳 F1 結果（危險only）。"""
    thresholds = [round(t, 2) for t in np.arange(0.50, 1.01, 0.05)]
    scopes     = ['危險only', '危險+可疑']
    sweep = []
    for scope in scopes:
        for thr in thresholds:
            res = predict_at_threshold(records, thr, scope)
            m   = compute_metrics(res)
            sweep.append({'threshold': thr, 'scope': scope, **m})
    best = max((r for r in sweep if r['scope'] == '危險only'), key=lambda x: x['f1'])
    return best, sweep


def backfill_missing_snapshots(conn):
    """補寫 daily_snapshots.csv 中缺失的歷史日期（從最後一筆到昨天）。"""
    from datetime import date, timedelta

    # 找出 CSV 已有的日期
    existing_dates = set()
    if os.path.isfile(SNAPSHOT_CSV):
        with open(SNAPSHOT_CSV, 'r', encoding='utf-8-sig') as f:
            for row in csv.DictReader(f):
                d = row.get('date', '').strip()
                if d:
                    existing_dates.add(d)

    # 找出 DB 中最早有資料的日期
    with conn.cursor(dictionary=True) as cur:
        cur.execute("SELECT DATE(MIN(analyzed_at)) AS min_date, DATE(MAX(analyzed_at)) AS max_date FROM eval_results")
        row = cur.fetchone()
    if not row or not row['min_date']:
        print('[BACKFILL] eval_results 無資料，略過')
        return

    start = row['min_date']                    # date 物件
    end   = date.today() - timedelta(days=1)   # 昨天（不補今天，留給正常流程）

    missing = []
    d = start
    while d <= end:
        if d.strftime('%Y-%m-%d') not in existing_dates:
            missing.append(d.strftime('%Y-%m-%d'))
        d += timedelta(days=1)

    if not missing:
        print('[BACKFILL] 無缺失日期，不需補寫')
        return

    print(f'[BACKFILL] 需補寫 {len(missing)} 天：{missing[0]} → {missing[-1]}')

    for date_str in missing:
        records = fetch_eval_records(conn, up_to_date=date_str)
        if not records:
            print(f'[BACKFILL] {date_str}：無資料，略過')
            continue

        n_attack = sum(1 for r in records if r['true_label'] == 'attack')
        n_benign = sum(1 for r in records if r['true_label'] == 'benign')
        best, _ = _compute_best(records)

        file_exists = os.path.isfile(SNAPSHOT_CSV)
        with open(SNAPSHOT_CSV, 'a', newline='', encoding='utf-8-sig') as f:
            w = csv.DictWriter(f, fieldnames=SNAPSHOT_FIELDS)
            if not file_exists:
                w.writeheader()
            w.writerow({
                'date':           date_str,
                'n_total':        len(records),
                'n_attack':       n_attack,
                'n_benign':       n_benign,
                'precision':      best['precision'],
                'recall':         best['recall'],
                'f1':             best['f1'],
                'fpr':            best['fpr'],
                'specificity':    best.get('specificity', ''),
                'accuracy':       best['accuracy'],
                'mcc':            best.get('mcc', ''),
                'TP':             best['TP'],
                'FP':             best['FP'],
                'FN':             best['FN'],
                'TN':             best['TN'],
                'best_threshold': best['threshold'],
            })
        print(f'[BACKFILL] {date_str}：total={len(records)} F1={best["f1"]:.4f} 已寫入')

    print(f'[BACKFILL] 完成，共補 {len(missing)} 筆')


def main():
    backfill = '--backfill' in sys.argv

    conn    = get_conn()

    if backfill:
        backfill_missing_snapshots(conn)

    records = fetch_eval_records(conn)
    conn.close()

    n_attack = sum(1 for r in records if r['true_label'] == 'attack')
    n_benign = sum(1 for r in records if r['true_label'] == 'benign')

    print(f'\n[資料] eval_results 共 {len(records)} 筆')
    print(f'       attack={n_attack}  benign={n_benign}')

    if not records:
        print('\n[WARN] eval_results 為空，請等待系統在 EVAL_MODE 下累積資料。')
        return

    best, sweep = _compute_best(records)

    print('\n' + '═'*62)
    print(f'  最佳 F1 (危險only)  threshold = {best["threshold"]:.2f}')
    print(f'  Precision={best["precision"]:.4f}  Recall={best["recall"]:.4f}  '
          f'F1={best["f1"]:.4f}  MCC={best["mcc"]:.4f}')
    print(f'  FPR={best["fpr"]:.4f}  Specificity={best["specificity"]:.4f}  Accuracy={best["accuracy"]:.4f}')
    print(f'  TP={best["TP"]}  FP={best["FP"]}  FN={best["FN"]}  TN={best["TN"]}')
    print('═'*62 + '\n')

    # ── 儲存 JSON
    report = {
        'generated_at':        datetime.now().isoformat(),
        'n_total':             len(records),
        'n_attack':            n_attack,
        'n_benign':            n_benign,
        'best_f1_danger_only': best,
        'sweep':               sweep,
    }
    json_path = os.path.join(OUTPUT_DIR, 'metrics_report.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f'[輸出] JSON → {json_path}')

    # ── 儲存 CSV
    csv_path = os.path.join(OUTPUT_DIR, 'metrics_report.csv')
    fields   = ['scope', 'threshold', 'precision', 'recall', 'f1',
                 'fpr', 'accuracy', 'mcc', 'TP', 'FP', 'FN', 'TN']
    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in sweep:
            w.writerow({k: row[k] for k in fields})
    print(f'[輸出] CSV  → {csv_path}')

    # ── 圖表
    plot_confusion(best, best['threshold'], best['scope'],
                   os.path.join(OUTPUT_DIR, 'confusion_best.png'))

    # ── 每日快照 + 累積趨勢圖
    save_daily_snapshot(best, len(records), n_attack, n_benign)
    plot_trend(os.path.join(OUTPUT_DIR, 'trend_over_time.png'))

    # ── 自動調整 eval_hints 強度（讀取 daily_snapshots.csv 趨勢，更新 tuning_config.json）
    if not backfill:  # backfill 模式下跳過，避免用歷史資料覆蓋當前配置
        try:
            from eval.daily_auto_tuning import main as _auto_tune
            _auto_tune()
        except Exception as e:
            print(f'[WARN] auto_tuning 略過：{e}')

    print('\n[完成] 所有輸出已儲存至 eval/output/')


if __name__ == '__main__':
    main()
