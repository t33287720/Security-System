# tools/security/reanalysis.py
from datetime import datetime, timedelta
from tools.db.db_tools import get_ip_logs, insert_llm_discrepancy
from tools.llm.ollama_tools import analyze_message

# danger_level 嚴重程度排序，用於二次判斷（RETRY / LOW-DATA）不一致時的取捨：
# 兩次判斷矛盾時採信較嚴重的一方，避免防禦系統因為信任第一次判斷而漏放真正的攻擊
DANGER_SEVERITY = {"正常": 0, "可疑": 1, "危險": 2}


def _build_hist_text(rows_list, cutoff_hist):
    lines = []
    for r in rows_list:
        if r.get("created_at") and r["created_at"] < cutoff_hist and r.get("log_content"):
            ts = r["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"[{ts}] {r['log_content']}")
    return "\n".join(lines)


def resolve_low_confidence(conn, ip, analysis, count, total_log, local_ip, direction,
                            known_attacks, ollama_url, syslog_texts, zeek_texts, eval_hints):
    """
    confidence < 0.7 時觸發的二次判斷（RETRY：24h log 足夠，擴大 limit 重分析／
    LOW-DATA：24h log 不足，補 24h 前的歷史 log 重分析）。

    回傳 (analysis, skip)：
    - analysis：最終採用的分析結果
    - skip：True 代表證據仍不足，呼叫端這輪應該 continue、不落地判斷這個 IP
    """
    confidence = analysis.get("confidence", 1.0)
    cutoff_hist = datetime.now() - timedelta(hours=24)

    def _fetch_hist_text():
        rows = (
            get_ip_logs(conn, ip, "syslog",    limit=50) +
            get_ip_logs(conn, ip, "zeeklog",   limit=50) +
            get_ip_logs(conn, ip, "weirdlog",  limit=50) +
            get_ip_logs(conn, ip, "noticelog", limit=50)
        )
        return _build_hist_text(rows, cutoff_hist)

    def _rerun(hist_text):
        return analyze_message(
            total_log, ip, local_ip, direction,
            known_attacks, ollama_url,
            syslog_list=syslog_texts,
            zeek_list=zeek_texts,
            eval_hints=eval_hints,
            historical_message=hist_text,
        )

    if count >= 20:
        print(f"[RETRY] IP={ip} confidence={confidence:.2f}，24h log={count}，擴大 limit 重分析")
        hist_text = _fetch_hist_text()
        if not hist_text.strip():
            print(f"[RETRY] 無歷史資料可補充，保留原始結果")
            return analysis, False

        analysis_ex = _rerun(hist_text)

        if analysis_ex and analysis_ex.get("danger_level") != analysis.get("danger_level"):
            orig_level = analysis.get("danger_level", "")
            new_level  = analysis_ex.get("danger_level", "")
            adopt = DANGER_SEVERITY.get(new_level, -1) > DANGER_SEVERITY.get(orig_level, -1)
            outcome = "adopted" if adopt else "kept_original"
            print(f"[RETRY] LLM 判斷分歧：danger_level {orig_level} → {new_level}（{outcome}）")
            insert_llm_discrepancy(conn, ip, "RETRY", orig_level, new_level, outcome)
            if adopt:
                print(f"[RETRY] 二次判斷風險等級較高，採信較嚴重結果 {orig_level} → {new_level}")
                return analysis_ex, False
            print(f"[RETRY] 二次判斷風險等級較低，保留原始（較嚴重）結果")
            return analysis, False

        if analysis_ex and analysis_ex.get("confidence", 0) > confidence:
            print(f"[RETRY] 信心度提升 {confidence:.2f} → {analysis_ex.get('confidence'):.2f}")
            return analysis_ex, False

        print(f"[RETRY] 信心度未改善，保留原始結果")
        return analysis, False

    # ---- LOW-DATA：24h 資料不足，從 DB 撈 24h 以前的歷史 log 作為補充參考 ----
    hist_text = _fetch_hist_text()
    if not hist_text.strip():
        print(f"[LOW-DATA] IP={ip} confidence={confidence:.2f}，無歷史資料，延後分析")
        return analysis, True

    print(f"[LOW-DATA] IP={ip} confidence={confidence:.2f}，補入歷史 log，重新分析")
    analysis_ld = _rerun(hist_text)

    if analysis_ld and analysis_ld.get("danger_level") != analysis.get("danger_level"):
        orig_level = analysis.get("danger_level", "")
        new_level  = analysis_ld.get("danger_level", "")
        adopt = DANGER_SEVERITY.get(new_level, -1) > DANGER_SEVERITY.get(orig_level, -1)
        outcome = "adopted" if adopt else "kept_original"
        print(f"[LOW-DATA] LLM 判斷分歧：danger_level {orig_level} → {new_level}（{outcome}）")
        insert_llm_discrepancy(conn, ip, "LOW-DATA", orig_level, new_level, outcome)
        if adopt:
            print(f"[LOW-DATA] 二次判斷風險等級較高，採信較嚴重結果 {orig_level} → {new_level}，繼續進行封鎖判斷")
            return analysis_ld, False
        print(f"[LOW-DATA] 二次判斷風險等級較低，資料仍不足，延後分析")
        return analysis, True

    if analysis_ld and analysis_ld.get("confidence", 0) > confidence:
        print(f"[LOW-DATA] 歷史資料提升信心度 {confidence:.2f} → {analysis_ld.get('confidence'):.2f}")
        return analysis_ld, False

    print(f"[LOW-DATA] 歷史資料未能提升信心度，延後分析")
    return analysis, True
