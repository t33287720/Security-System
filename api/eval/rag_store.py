"""
RAG 向量庫 — 以 multilingual-e5-large-instruct + ChromaDB 為基礎
提供兩個公開介面：
  build_index(conn)        — 從 eval_results 建立/更新向量索引（每日執行一次）
  get_rag_hints(log_text)  — 輸入當前 log，回傳最相似的歷史 FN/FP 矯正提示

用法（測試）：
    cd /var/www/html/GAIsecurity/api
    python3 eval/rag_store.py --build    # 建索引
    python3 eval/rag_store.py --query "多端口探測 無資料傳輸"  # 測試查詢
"""

import json
import os
import sys
import requests
import chromadb

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from config.settings import EMBED_URL

# ChromaDB 持久化路徑
CHROMA_DIR  = os.path.join(os.path.dirname(__file__), 'output', 'chroma_db')
COLLECTION  = 'eval_fn_fp'

# 每次查詢回傳的案例數
TOP_K = 5


# ─────────────────────────────────────────────
# Embedding
# ─────────────────────────────────────────────

def embed(texts: list[str]) -> list[list[float]]:
    """批次將文字轉成向量（multilingual-e5-large-instruct，1024 維）。"""
    resp = requests.post(
        EMBED_URL,
        json={'texts': texts},
        timeout=60
    )
    resp.raise_for_status()
    return resp.json()['embeddings']


def embed_one(text: str) -> list[float]:
    return embed([text])[0]


# ─────────────────────────────────────────────
# ChromaDB helpers
# ─────────────────────────────────────────────

def _get_collection():
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    return client.get_or_create_collection(
        name=COLLECTION,
        metadata={'hnsw:space': 'cosine'}   # cosine 相似度
    )


# ─────────────────────────────────────────────
# 建立 / 更新索引
# ─────────────────────────────────────────────

def build_index(conn, verbose=True):
    """
    從 eval_results 讀取 FN/FP 記錄，計算 embedding 後存入 ChromaDB。
    已存在的 ID 自動跳過（upsert），適合每日增量更新。
    """
    col = _get_collection()
    existing_ids = set(col.get(include=[])['ids'])

    with conn.cursor(dictionary=True) as cur:
        cur.execute("""
            SELECT id, ip, true_label, danger_level, confidence,
                   attack_type, actions, analyzed_at
            FROM eval_results
            WHERE true_label = 'attack' AND danger_level != '危險'   -- FN
               OR true_label = 'benign' AND danger_level = '危險'    -- FP
            ORDER BY analyzed_at DESC
        """)
        records = cur.fetchall()

    new_records = [r for r in records if str(r['id']) not in existing_ids]
    if not new_records:
        if verbose:
            print(f'[RAG] 索引已是最新（{len(existing_ids)} 筆），無需更新')
        return

    if verbose:
        print(f'[RAG] 新增 {len(new_records)} 筆到索引（現有 {len(existing_ids)} 筆）')

    # 批次處理（每次 50 筆，避免 embedding API 超時）
    BATCH = 50
    for start in range(0, len(new_records), BATCH):
        batch = new_records[start:start + BATCH]

        texts, ids, metas = [], [], []
        for r in batch:
            try:
                actions = json.loads(r['actions']) if r['actions'] else {}
                if not isinstance(actions, dict):
                    actions = {}
            except (ValueError, TypeError):
                actions = {}

            behavior = actions.get('overall_behavior', '').strip()
            reason   = actions.get('reason', '').strip()
            text = f"{r['attack_type'] or ''} {behavior} {reason}".strip()
            if not text:
                continue

            verdict = 'FN' if r['true_label'] == 'attack' else 'FP'
            texts.append(text)
            ids.append(str(r['id']))
            metas.append({
                'verdict':     verdict,
                'attack_type': r['attack_type'] or '',
                'danger_level': r['danger_level'] or '',
                'confidence':  float(r['confidence'] or 0),
                'ip':          r['ip'],
                'reason':      reason[:300],
                'behavior':    behavior[:300],
            })

        if not texts:
            continue

        embeddings = embed(texts)
        col.upsert(ids=ids, embeddings=embeddings, documents=texts, metadatas=metas)

        if verbose:
            print(f'[RAG]   upsert {start+1}~{start+len(batch)}')

    if verbose:
        print(f'[RAG] 索引完成，共 {col.count()} 筆')


# ─────────────────────────────────────────────
# Log → 行為摘要（對齊 index 的語意空間）
# ─────────────────────────────────────────────

def _extract_behavior_summary(log_text: str) -> tuple:
    """
    從原始 log 提取結構化行為特徵，回傳 (摘要文字, 特徵 dict)。
    特徵 dict 供 get_rag_hints() 做智慧 FN/FP 矯正決策。
    不呼叫 LLM，純規則萃取，速度快。
    """
    import re
    lines = log_text.splitlines()

    # 端口
    port_re = re.compile(r'(?:DPT|dport|dst_port|port)[=:\s]+(\d{2,5})', re.I)
    ports   = set()
    for ln in lines:
        for m in port_re.finditer(ln):
            p = int(m.group(1))
            if 1 <= p <= 65535:
                ports.add(p)

    # bytes / 資料傳輸
    bytes_re  = re.compile(r'(?:bytes|LEN|length)[=:\s]+(\d+)', re.I)
    byte_vals = [int(m.group(1)) for ln in lines for m in bytes_re.finditer(ln)]
    zero_bytes = sum(1 for v in byte_vals if v == 0)
    has_data   = any(v > 0 for v in byte_vals)

    # 協議
    proto_re = re.compile(r'PROTO=(\w+)|protocol[=:\s]+(\w+)', re.I)
    protos   = set()
    for ln in lines:
        for m in proto_re.finditer(ln):
            protos.add((m.group(1) or m.group(2)).upper())

    # ICMP only：bytes=0 是 ICMP 天然特性，不代表異常
    icmp_only = bool(protos) and protos <= {'ICMP', 'ICMP6'}

    # BLOCK / REJECT / 攔截
    blocked = sum(1 for ln in lines if re.search(r'BLOCK|REJECT|DROP|DENIED', ln, re.I))

    # HTTP 路徑
    path_re  = re.compile(r'(?:GET|POST|PUT|HEAD)\s+(/\S+)', re.I)
    paths    = list({m.group(1) for ln in lines for m in path_re.finditer(ln)})[:5]

    features = {
        'port_count':       len(ports),
        'has_data':         has_data,
        'zero_bytes_count': zero_bytes,
        'icmp_only':        icmp_only,
        'blocked_count':    blocked,
    }

    # 組成摘要（ICMP-only 時不把 bytes=0 標記為異常）
    parts = [f"日誌共 {len(lines)} 筆"]
    if ports:
        parts.append(f"連線端口 {len(ports)} 種：{', '.join(str(p) for p in sorted(ports)[:8])}")
    if zero_bytes and not has_data and not icmp_only:
        parts.append("所有連線無資料傳輸（bytes=0）")
    elif zero_bytes and not icmp_only:
        parts.append(f"部分連線無資料傳輸（{zero_bytes} 筆 bytes=0）")
    if protos:
        parts.append(f"協議：{', '.join(sorted(protos))}")
    if blocked:
        parts.append(f"{blocked} 筆被防火牆攔截")
    if paths:
        parts.append(f"HTTP 路徑：{', '.join(paths[:3])}")

    return '；'.join(parts), features


# ─────────────────────────────────────────────
# 查詢
# ─────────────────────────────────────────────

def get_rag_hints(log_text: str, top_k: int = TOP_K, direction: str = None) -> str:
    """
    輸入當前 log 文字，回傳最相似歷史 FN/FP 案例的矯正提示字串。
    direction: 'inbound' | 'outbound' | None
      - inbound  → 提供 FN 矯正（外部攻擊漏報）+ 少量 FP 矯正
      - outbound → 只提供 FP 矯正（避免誤判合法外連），跳過 FN 矯正
      - None     → 同 inbound（保守預設）
    查無資料或 ChromaDB 未建立時回傳空字串。
    """
    if not log_text or not log_text.strip():
        return ''

    try:
        col = _get_collection()
        if col.count() == 0:
            return ''

        # 把原始 log 轉成行為摘要，對齊 index 的語意空間
        query_summary, features = _extract_behavior_summary(log_text)
        q_emb = embed_one(query_summary)
        results = col.query(
            query_embeddings=[q_emb],
            n_results=min(top_k, col.count()),
            include=['metadatas', 'distances']
        )
    except Exception as e:
        print(f'[RAG] 查詢失敗：{e}')
        return ''

    metas     = results['metadatas'][0]
    distances = results['distances'][0]

    # FN 矯正開關：行為模式判斷，不用 port 號
    #   關閉條件：outbound AND 端口 ≤ 2 AND 有實際資料傳輸（正常外連如 HTTPS/DNS）
    #   保留條件：多端口 OR bytes=0 貫穿始終（可能是 C2、跳板、掃描）
    is_outbound     = (direction == 'outbound')
    few_ports       = features['port_count'] <= 2
    disable_fn_hint = is_outbound and few_ports and features['has_data']

    fn_cases, fp_cases = [], []
    for meta, dist in zip(metas, distances):
        similarity = 1 - dist
        if similarity < 0.5:
            continue
        if meta['verdict'] == 'FN':
            if not disable_fn_hint:
                fn_cases.append((meta, similarity))
        else:
            fp_cases.append((meta, similarity))

    if not fn_cases and not fp_cases:
        return ''

    lines = ['【RAG 語意比對｜與本次行為最相似的歷史錯判案例】']

    if fn_cases:
        lines.append('  ▌漏報矯正（過去類似行為被低估的案例）')
        for i, (m, sim) in enumerate(fn_cases, 1):
            lines.append(f"  案例{i}（相似度{sim:.2f}）｜攻擊類型：{m['attack_type']}｜LLM 誤判：{m['danger_level']}（{m['confidence']:.2f}）")
            if m['behavior']:
                lines.append(f"    過去行為：「{m['behavior'][:100]}」")
            if m['reason']:
                lines.append(f"    錯誤推論：「{m['reason'][:100]}」")
            lines.append(f"    → 此類行為應判危險")

    if fp_cases:
        lines.append('  ▌誤報矯正（過去類似行為被過度判定的案例）')
        for i, (m, sim) in enumerate(fp_cases, 1):
            lines.append(f"  案例{i}（相似度{sim:.2f}）｜LLM 誤判：{m['attack_type']}｜誤判為：{m['danger_level']}（{m['confidence']:.2f}）")
            if m['reason']:
                lines.append(f"    錯誤推論：「{m['reason'][:100]}」")
            lines.append(f"    → 此類行為為正常流量")

    return '\n'.join(lines)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

if __name__ == '__main__':
    import argparse
    from config.settings import load_config
    import mariadb

    parser = argparse.ArgumentParser()
    parser.add_argument('--build', action='store_true', help='建立/更新 ChromaDB 索引')
    parser.add_argument('--query', type=str, help='測試語意查詢')
    args = parser.parse_args()

    if args.build:
        cfg  = load_config()
        conn = mariadb.connect(
            host=cfg['db_host'], user=cfg['db_user'],
            password=cfg['db_password'], database=cfg['db_name'],
            autocommit=True
        )
        build_index(conn, verbose=True)
        conn.close()

    if args.query:
        result = get_rag_hints(args.query)
        print(result if result else '（無相似案例）')
