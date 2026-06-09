"""
FN（False Negative）深度分析腳本
分析 eval_results 中被漏報的 507 筆攻擊 IP，回答三個問題：
  Q1. attack_type 分布 — 哪類攻擊最常被漏
  Q2. 公開黑名單來源分布 — 哪些黑名單可能不準確
  Q3. log_count 分布 — 是否因 log 太少導致判斷困難

用法：
    cd /var/www/html/GAIsecurity/api
    python3 eval/analyze_fn.py
"""

import sys, os, ipaddress
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from config.settings import load_config, openblacklist_PARSED_DIR
import mariadb
from collections import defaultdict, Counter

SEP = '═' * 62

# ─────────────────────────────────────────────────────────────
# 連線
# ─────────────────────────────────────────────────────────────
def get_conn():
    cfg = load_config()
    return mariadb.connect(
        host=cfg['db_host'], user=cfg['db_user'],
        password=cfg['db_password'], database=cfg['db_name'],
        autocommit=True
    )

# ─────────────────────────────────────────────────────────────
# 取 FN 資料
# ─────────────────────────────────────────────────────────────
def fetch_fn_records(conn):
    with conn.cursor(dictionary=True) as cur:
        cur.execute("""
            SELECT ip, danger_level, confidence, attack_type,
                   log_count, source_count, analyzed_at
            FROM eval_results
            WHERE true_label = 'attack'
              AND danger_level != '危險'
            ORDER BY analyzed_at DESC
        """)
        return cur.fetchall()

# ─────────────────────────────────────────────────────────────
# 載入黑名單（IP → 命中哪些來源）
# ─────────────────────────────────────────────────────────────
def load_blacklists_by_source(parsed_dir):
    """回傳 {source_name: [ip_network, ...]}"""
    sources = {}
    if not os.path.isdir(parsed_dir):
        print(f'[WARN] PARSED_DIR 不存在: {parsed_dir}')
        return sources
    for fname in sorted(os.listdir(parsed_dir)):
        path = os.path.join(parsed_dir, fname)
        nets = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    nets.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    pass
        sources[fname] = nets
        print(f'  [{fname}] loaded {len(nets)} networks')
    return sources

def check_ip_sources(ip_str, sources):
    """回傳這個 IP 命中哪些來源名稱"""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return []
    hits = []
    for src, nets in sources.items():
        for net in nets:
            if ip_obj in net:
                hits.append(src)
                break   # 同一來源只算一次
    return hits

# ─────────────────────────────────────────────────────────────
# 分析
# ─────────────────────────────────────────────────────────────
def analyze(records, sources):
    total = len(records)

    # ── Q1：attack_type 分布
    type_counter   = Counter()
    type_by_level  = defaultdict(lambda: Counter())   # attack_type → {danger_level: count}

    # ── Q2：公開黑名單來源
    source_counter      = Counter()   # 每個來源出現次數（只算 FN）
    source_only_one     = Counter()   # 只命中這一個來源 → 可疑準確性
    fn_source_detail    = []          # (ip, sources_hit, danger_level)

    # ── Q3：log_count 分布
    log_buckets = Counter()           # 區間 → 筆數
    log_by_level = defaultdict(list)  # danger_level → [log_count, ...]
    zero_log = 0

    for r in records:
        at    = r['attack_type'] or '未知'
        level = r['danger_level'] or '未知'
        lc    = r['log_count'] or 0

        # Q1
        type_counter[at] += 1
        type_by_level[at][level] += 1

        # Q2
        hits = check_ip_sources(r['ip'], sources) if sources else []
        for s in hits:
            source_counter[s] += 1
        fn_source_detail.append((r['ip'], hits, level, lc))
        if len(hits) == 1:
            source_only_one[hits[0]] += 1

        # Q3
        if lc == 0:
            zero_log += 1
            log_buckets['0'] += 1
        elif lc <= 3:
            log_buckets['1-3'] += 1
        elif lc <= 5:
            log_buckets['4-5'] += 1
        elif lc <= 10:
            log_buckets['6-10'] += 1
        elif lc <= 20:
            log_buckets['11-20'] += 1
        else:
            log_buckets['21+'] += 1

        log_by_level[level].append(lc)

    # ══ 輸出 ══════════════════════════════════════════════════
    print(f'\n{SEP}')
    print(f'  FN 深度分析  —  共 {total} 筆漏報')
    print(SEP)

    # ────── Q1
    print('\n【Q1】attack_type 分布（LLM 輸出的攻擊類型）')
    print(f'  {"攻擊類型":<25} {"FN數":>6}  {"比例":>6}  breakdown(danger_level)')
    print('  ' + '-'*70)
    for at, cnt in type_counter.most_common():
        pct    = cnt / total * 100
        detail = ', '.join(f'{lv}:{n}' for lv, n in type_by_level[at].most_common())
        print(f'  {at:<25} {cnt:>6}  {pct:>5.1f}%  [{detail}]')

    # ────── Q2
    print(f'\n【Q2】公開黑名單來源 — FN 命中分布')
    if not sources:
        print('  [WARN] 無法載入黑名單，跳過此分析')
    else:
        print(f'  {"來源檔案":<35} {"FN中命中":>8}  {"僅此一源":>8}  說明')
        print('  ' + '-'*75)
        all_source_names = list(sources.keys())
        for src in all_source_names:
            cnt      = source_counter.get(src, 0)
            only_cnt = source_only_one.get(src, 0)
            pct      = cnt / total * 100 if total else 0
            risk_note = '  ← 高比例「唯一命中」，請評估準確性' if only_cnt > 20 else ''
            print(f'  {src:<35} {cnt:>8} ({pct:4.1f}%)  {only_cnt:>8}{risk_note}')

        # source_count 分布
        sc_counter = Counter(r['source_count'] for r in records)
        print(f'\n  source_count 分布（命中幾個黑名單來源）:')
        for k in sorted(sc_counter):
            bar = '█' * (sc_counter[k] // 5)
            pct = sc_counter[k] / total * 100
            print(f'    命中 {k} 個來源: {sc_counter[k]:>4} 筆 ({pct:5.1f}%)  {bar}')

        # 只命中 1 個來源的 IP 詳細（前 20 筆）
        only_one = [(ip, hits, lv, lc) for ip, hits, lv, lc in fn_source_detail if len(hits) == 1]
        if only_one:
            print(f'\n  ▶ 只命中單一來源的 FN（共 {len(only_one)} 筆，顯示前 20）:')
            print(f'    {"IP":<20} {"來源":<30} {"LLM判斷":<10} {"log數"}')
            print('    ' + '-'*70)
            for ip, hits, lv, lc in only_one[:20]:
                print(f'    {ip:<20} {hits[0]:<30} {lv:<10} {lc}')

    # ────── Q3
    print(f'\n【Q3】log_count 分布 — LLM 可用的 log 量')
    print(f'  {"log 區間":<12} {"FN數":>6}  {"比例":>6}  bar')
    print('  ' + '-'*55)
    order = ['0', '1-3', '4-5', '6-10', '11-20', '21+']
    for bucket in order:
        cnt = log_buckets.get(bucket, 0)
        pct = cnt / total * 100
        bar = '█' * (cnt // 5)
        print(f'  {bucket:<12} {cnt:>6}  {pct:>5.1f}%  {bar}')

    print(f'\n  各 danger_level 的 log_count 統計:')
    for lv, counts in sorted(log_by_level.items()):
        avg  = sum(counts) / len(counts) if counts else 0
        mn   = min(counts) if counts else 0
        mx   = max(counts) if counts else 0
        n    = len(counts)
        print(f'    {lv:<6}: n={n:>4}  avg={avg:6.1f}  min={mn:>4}  max={mx:>4}')

    # ────── 建議
    print(f'\n{SEP}')
    print('  優化建議摘要')
    print(SEP)

    top_type = type_counter.most_common(1)[0] if type_counter else (None, 0)
    if top_type[0]:
        top_pct = top_type[1] / total * 100
        print(f'  1. attack_type「{top_type[0]}」佔 FN 的 {top_pct:.1f}%，'
              f'該類型主要被判為「{type_by_level[top_type[0]].most_common(1)[0][0]}」。')
        print(f'     → 針對此類型補強 Prompt 的危險判斷規則。')

    # 找最多「唯一命中」的來源
    if source_only_one:
        worst_src, worst_cnt = source_only_one.most_common(1)[0]
        worst_pct = worst_cnt / total * 100
        print(f'\n  2. 黑名單「{worst_src}」有 {worst_cnt} 筆 FN 僅由此來源命中（佔 {worst_pct:.1f}%）。')
        print(f'     → 評估此來源準確性；若 FP 率高，考慮將 EVAL_ATTACK_MIN_SRCS 提高排除單一來源。')

    # log 不足問題
    low_log = log_buckets.get('0', 0) + log_buckets.get('1-3', 0)
    low_pct = low_log / total * 100
    print(f'\n  3. {low_log} 筆 FN（{low_pct:.1f}%）的 log_count ≤ 3，LLM 資訊不足。')
    print(f'     → 考慮提高 EVAL_LOG_THRESHOLD 或 threshold（主流程的封鎖門檻）以過濾低 log 樣本。')

    print()


# ─────────────────────────────────────────────────────────────
# Entry
# ─────────────────────────────────────────────────────────────
def main():
    print('載入黑名單...')
    sources = load_blacklists_by_source(openblacklist_PARSED_DIR)

    print('\n連線 DB，取 FN 資料...')
    conn    = get_conn()
    records = fetch_fn_records(conn)
    conn.close()

    print(f'取得 {len(records)} 筆 FN 記錄\n')
    if not records:
        print('[WARN] 沒有 FN 記錄。')
        return

    analyze(records, sources)


if __name__ == '__main__':
    main()
