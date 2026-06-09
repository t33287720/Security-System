"""
手動測試：隨機抽取 TP/FP/FN/TN 各 5 筆，用原始 log 重新跑 LLM（含 RAG）比對結果。

執行：
    conda run -n security python3 -u eval/manual_test.py 2>&1 | tee eval/output/manual_test.log
"""
import sys, random, json, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import mariadb
from config.settings import load_config, OLLAMA_URL
from tools.llm.ollama_tools import analyze_message
from tools.db.db_tools import get_known_attacks, get_ip_logs
from tools.logs.log_tools import format_logs

def p(msg=''):
    print(msg, flush=True)

cfg  = load_config()
conn = mariadb.connect(
    host=cfg['db_host'], user=cfg['db_user'],
    password=cfg['db_password'], database=cfg['db_name'],
    autocommit=True
)
cur   = conn.cursor(dictionary=True)
known = get_known_attacks(conn)
p('[START] 已連線 DB，開始測試...')

def fetch_sample(true_label, is_danger, n=5):
    # 先從 eval_results 快速撈候選 IP（避免大表 RAND 掃描）
    cond = 'danger_level = "危險"' if is_danger else 'danger_level != "危險"'
    cur.execute(f"""
        SELECT ip, danger_level AS old_level, confidence AS old_conf, attack_type AS old_type
        FROM eval_results
        WHERE true_label = %s AND {cond}
        ORDER BY RAND()
        LIMIT 50
    """, (true_label,))
    candidates = cur.fetchall()
    random.shuffle(candidates)

    results = []
    for c in candidates:
        if len(results) >= n:
            break
        # 確認此 IP 在 ip_risk_logs 有 log，取出現最多次的 direction
        cur.execute("""
            SELECT local_ip, direction, COUNT(*) as cnt
            FROM ip_risk_logs
            WHERE ip = %s AND direction IS NOT NULL
            GROUP BY direction
            ORDER BY cnt DESC
            LIMIT 1
        """, (c['ip'],))
        row = cur.fetchone()
        if row:
            results.append({**c, 'local_ip': row['local_ip'], 'direction': row['direction'],
                             'true_label': true_label})
    return results

samples = {
    'TP': fetch_sample('attack', True),
    'FP': fetch_sample('benign', True),
    'FN': fetch_sample('attack', False),
    'TN': fetch_sample('benign', False),
}
p(f'[INFO] 抽樣完成：TP={len(samples["TP"])} FP={len(samples["FP"])} FN={len(samples["FN"])} TN={len(samples["TN"])}')

SEP = '─' * 70
correct = wrong = skip = 0
results_log = []

for verdict, cases in samples.items():
    p(f'\n{"═"*70}')
    p(f'  {verdict} 組（{len(cases)} 筆）')
    p('═' * 70)

    for idx, c in enumerate(cases, 1):
        ip = c['ip']
        p(f'\n  [{verdict}-{idx}] IP={ip}  分析中...')

        rows_s   = get_ip_logs(conn, ip, 'syslog',   limit=30)
        rows_z   = get_ip_logs(conn, ip, 'zeeklog',  limit=20)
        log_text = (format_logs(rows_s) + '\n' + format_logs(rows_z)).strip()

        if not log_text:
            p(f'  → 無 log，跳過')
            skip += 1
            continue

        p(f'  log {len(rows_s)} syslog + {len(rows_z)} zeeklog = {len(log_text)} chars')

        direction = c.get('direction')
        p(f'  direction={direction}')
        result = analyze_message(
            log_text, ip,
            c.get('local_ip'), direction,
            known, OLLAMA_URL
        )
        if not result:
            p(f'  → LLM 無回應，跳過')
            skip += 1
            continue

        old_lv   = c['old_level']
        new_lv   = result.get('danger_level', '—')
        old_conf = float(c['old_conf'] or 0)
        new_conf = float(result.get('confidence', 0))

        if verdict == 'TP':   expect = ('危險',)
        elif verdict == 'FP': expect = ('正常', '可疑')
        elif verdict == 'FN': expect = ('危險',)
        else:                  expect = ('正常', '可疑')

        ok   = new_lv in expect
        mark = '✅' if ok else '❌'
        if ok: correct += 1
        else:  wrong   += 1

        p(f'{SEP}')
        p(f'  IP: {ip}  [{verdict}]  {mark}')
        p(f'  舊: {old_lv} ({old_conf:.2f})  →  新: {new_lv} ({new_conf:.2f})')
        p(f'  reason: {result.get("reason","")[:130]}')

        results_log.append({
            'verdict': verdict, 'ip': ip, 'ok': ok,
            'old_level': old_lv, 'new_level': new_lv,
            'old_conf': old_conf, 'new_conf': new_conf,
        })

conn.close()
total = correct + wrong
p(f'\n{"═"*70}')
p(f'  總計：{total} 筆有效（跳過 {skip} 筆）')
p(f'  正確：{correct}  錯誤：{wrong}  正確率：{100*correct/total:.1f}%' if total else '  無有效結果')

# 分組統計
for v in ['TP', 'FP', 'FN', 'TN']:
    grp = [r for r in results_log if r['verdict'] == v]
    if grp:
        c_cnt = sum(1 for r in grp if r['ok'])
        p(f'  {v}: {c_cnt}/{len(grp)}')

p('═' * 70)
p('[DONE]')
