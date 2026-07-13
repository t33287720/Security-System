# tools/llm/ollama_utils.py
import json
import os
import re
import requests
from datetime import datetime

# RAG 語意召回（可選，失敗不影響主流程）
try:
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from eval.rag_store import get_rag_hints as _get_rag_hints
    _RAG_AVAILABLE = True
except Exception:
    _RAG_AVAILABLE = False


def normalize_attack_type(raw: str, known_attacks=None) -> str:
    """取第一個 / 或 、 前的類型，並對映到 DB 標準名稱（忽略空格差異）"""
    if not raw:
        return raw
    first = re.split(r'[/、+＋]', raw)[0].strip()
    if known_attacks:
        lookup = {
            t["attack_type"].replace(" ", "").lower(): t["attack_type"]
            for t in known_attacks if t.get("attack_type")
        }
        key = first.replace(" ", "").lower()
        canonical = lookup.get(key)
        if canonical:
            return canonical
    return first


def quick_stats(syslog_list: list, zeek_list: list) -> str:
    """輕量統計：總 log 筆數 + 不重複端口數（不做完整 log 解析）"""
    all_logs = syslog_list + zeek_list
    total = len(all_logs)
    port_re = re.compile(
        r'(?:port[=:\s]+|dport[=:\s]+|sport[=:\s]+|:\s*)(\d{2,5})\b', re.I
    )
    ports = set()
    for log in all_logs:
        for m in port_re.finditer(str(log)):
            p = int(m.group(1))
            if 1 <= p <= 65535:
                ports.add(p)
    return f"[預處理統計] 總log筆數={total} | 偵測端口種類={len(ports)}"


def parse_llm_json_response(text):
    if not text:
        return {}
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        # 嘗試提取第一個 JSON 對象
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
    # 若解析失敗，保留原始文字
    return {"raw_response": text}

def analyze_message(message, other_ip, local_ip, direction, known_attacks, OLLAMA_URL,
                    syslog_list=None, zeek_list=None, eval_hints=None,
                    historical_message=None):
    role_info_json = {
        "local_ip": local_ip,
        "external_ip": other_ip,
        "direction": direction
    }
    role_info_str = json.dumps(role_info_json, ensure_ascii=False, indent=2)

    known_attack_str = "\n".join([f"- {row['attack_type']}: {row['attack_method']}" for row in known_attacks])
    if not known_attack_str:
        known_attack_str = "無"

    stats_hint = ""
    if syslog_list is not None or zeek_list is not None:
        stats_hint = quick_stats(syslog_list or [], zeek_list or []) + "\n\n"

    # RAG：從歷史 FN/FP 中語意召回最相似案例，補充靜態 eval_hints
    # outbound 方向只提供 FP 矯正，避免把合法外連誤判為危險
    rag_section = ""
    if _RAG_AVAILABLE:
        try:
            rag_section = _get_rag_hints(message[:1500], direction=direction) or ""
        except Exception:
            rag_section = ""

    # 靜態 eval_hints（常見類型）+ RAG 語意召回（本次最相似案例），合併後注入 prompt
    hints_parts = [p for p in [eval_hints, rag_section] if p]
    eval_hints_section = ("\n" + "\n".join(hints_parts) + "\n") if hints_parts else ""

    historical_section = ""
    if historical_message:
        historical_section = f"""
【歷史補充資料】
以下為同一 IP 過去（時間不定，可能為數日至數月前）的歷史 log，用於輔助判斷行為是否持續。

使用規則：
- danger_level 以當前資料的行為模式為主要依據，歷史資料是輔助佐證，不是獨立依據
- 若歷史行為與當前行為模式一致 → 可提升 confidence
- 歷史資料只能「向上」修正 danger_level：若歷史持續出現攻擊模式，可佐證當前這次模糊/低信心的行為其實是同一波攻擊的延續，此時可將 danger_level 提升為可疑或危險
- 歷史資料不能「向下」修正 danger_level：即使歷史 log 看起來乾淨，也不能只因為過去正常就把當前已符合可疑/危險條件的行為降級——降級只能依據當前資料本身
- 歷史資料只能「確認」已在當前資料中觀察到的攻擊特徵，不能「新增」當前資料完全沒有的攻擊依據

{historical_message}

"""

    prompt = f"""你是資安行為分析引擎，使用繁體中文輸出。
{eval_hints_section}
{stats_hint}【連線資訊】
{role_info_str}

【方向解讀】
- inbound（direction = "inbound"）：external_ip 主動向 local_ip 發起連線
  → 攻擊主體為 external_ip，分析其對本地的掃描、探測、暴力行為
- outbound（direction = "outbound"）：local_ip 主動向 external_ip 發起連線
  → external_ip 為連線目標；若目標為已知服務（CDN、NTP、更新伺服器），視為正常；
    若本地大量外連多個不同目標，才考慮本地受害或被用作跳板

【Log 內容（當前，近24小時）】
{message}
{historical_section}
【已知攻擊手法（語意參考）】
{known_attack_str}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【danger_level 判斷規則】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

▌危險
以下任一行為模式即可判定，不需要 payload 或攻擊成功證據：

  (1) 多端口探測：對同一目標嘗試 3 個以上不同【目標端口（DPT/dport）】，且資料傳輸量為零或極少
      ★ 來源端口（SPT/sport）天生隨機多樣，絕對不算掃描證據；判斷掃描只看目標端口（DPT）
      ★ 禁止把「SPT 多樣」作為判危險的任何依據，即使 SPT 有幾十種也一樣
  (2) 多目標掃描：短時間對多個不同目標 IP 發起連線（outbound 方向需排除已知合法服務）
  (3) 暴力嘗試：相同端口大量重複連線，且多數連線失敗
      ★ 暴力嘗試需同時符合「大量重複」AND「多數失敗」，缺一不可
         成功的 SSH 連線本身不構成危險，除非前面有大量失敗嘗試
  (4) 純探測心跳：固定週期發送且完全無資料交換（bytes_in = bytes_out = 0），持續多次，
      且無法以監控健康檢查、CDN 探活、路由守護程式合理解釋
      ★ ICMP（ping）的 bytes=0 是協議天然特性，不構成純探測心跳的判定依據
         ICMP 要達到危險，需要：短時間對大量不同目標 IP 發送（ping sweep），
         僅對單一目標發 ICMP 不論次數多少，一律不判危險

  ★ 關鍵原則：
  「資料傳輸量為零 + 多端口或多次重複」本身就是攻擊行為，不需要 payload 才能判危險。
  不確定攻擊是否成功 ≠ 不確定是否在攻擊，兩者不同。
  但若行為模式與已知合法系統（監控、CDN、NTP）完全一致，不應套用上述規則。

  ★ 例外條件限制（嚴格執行）：
  「可能是監控系統」不是降級的理由。以下情況禁止降級為可疑或正常：
  - 來源 IP 身份未確認，且對 3 個以上不同端口進行零流量連線 → 一律判危險
  - 「需要進一步觀察」「無法排除正常行為」等不確定語句 不得作為判可疑的依據
  - 確認為合法服務的前提是：行為完全符合單一已知服務特徵（如固定 NTP port 123、
    DNS port 53），而非泛指「可能是某類服務」
  簡言之：不確定 = 危險，而非不確定 = 可疑。

  ★ 防火牆 BLOCK 記錄的正確解讀：
  BLOCK/REJECT 記錄是防火牆執行規則的結果，不是攻擊行為本身的直接證據。
  - 大量 BLOCK + 單一目標端口（如只有 443）+ 有實際資料傳輸 → 可能是合法流量被誤封
  - 判斷是否為攻擊，應看行為模式（目標端口種類、資料量、是否主動探測）
  - 不得以「被防火牆擋了很多筆」作為升級為危險的主要依據

▌可疑
同時符合以下所有條件才歸可疑（否則應判危險或正常）：

  - 日誌筆數少（5 筆以下），行為模式無法確認
  - 有部分資料交換，連線模式略為異常，但無明確攻擊特徵

  注意：以下情況不得歸可疑，應判危險：
  - 任何端口的高頻重複連線（如 SSH 22、RDP 3389、HTTP 80 的大量重複請求）
  - 同一 IP 對 3 個以上不同端口有連線記錄

▌正常
符合以下條件：

  - 無上述危險訊號
  - 行為有合理解釋（API 客戶端、CDN 節點、監控系統、NTP、更新服務、一般 HTTPS）
  - 目標單一、行為一致可預期
  - 允許 bytes=0 的情況，若連線模式符合監控心跳或 keepalive 特徵

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【confidence 校準】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

根據你對此次判斷的把握程度，自由給出 0.0–1.0，不受固定區間限制。

- 接近 1.0：證據充分、行為模式明確、結果高度確信
- 接近 0.5：有部分指標但不完整，存在合理疑義
- 接近 0.0：行為極度模糊，幾乎無法判斷

danger_level 與 confidence 彼此獨立，例如：
  「危險 0.72」→ 有攻擊跡象但日誌不完整
  「危險 0.95」→ 攻擊特徵非常明確
  「正常 0.90」→ 行為完全符合合法服務特徵
  「正常 0.55」→ 無異常但日誌過少難以確認

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【輸出 JSON，不附加其他文字】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{{
  "analysis_basis": [],
  "overall_behavior": "",
  "danger_level": "正常 / 可疑 / 危險",
  "confidence": 0.0-1.0,
  "reason": "",
  "attack_type": "",
  "attack_method": ""
}}

attack_type 規則（嚴格執行）：
- 只能是單一中文詞組，嚴禁使用「/」「、」「+」分隔多個類型
- 若有多種可能，只選最主要的一個
- 正確：「SSH暴力破解」 或 「端口掃描」
- 錯誤：「SSH暴力破解 / 端口掃描」

語言規則（嚴格執行）：
- analysis_basis、overall_behavior、reason 必須全部使用繁體中文
- 禁止出現任何英文單字或英文句子，包含技術術語也必須翻譯或加上中文說明
- 違反即視為錯誤輸出
"""

    payload = {
        "model": "gemma3:27b",
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "max_tokens": 800
        }
    }
    try:
        resp = requests.post(
            OLLAMA_URL,
            json=payload,
            verify=False,
            headers={"Content-Type": "application/json"},
            timeout=(10, 180)
        )
        resp.raise_for_status()
        result = resp.json()
        response_text = result.get("response", "").strip() if isinstance(result, dict) else str(result)
        parsed = parse_llm_json_response(response_text)
        if parsed and "raw_response" not in parsed:
            parsed["attack_type"] = normalize_attack_type(parsed.get("attack_type", ""), known_attacks)
            return parsed
        return parsed if parsed else {"raw_response": response_text}
    except Exception as e:
        print(f"[{datetime.now()}] 分析 API 失敗: {e}")
        return None