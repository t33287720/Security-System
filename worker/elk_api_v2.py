import time
import json
import subprocess
import sys
import os
import random
import sys
from datetime import datetime, timedelta
import urllib3
import mariadb
from tools.db.db_tools import (get_ip_log_count_24h, cleanup_blacklist, get_ip_logs, get_known_attacks,
                               is_new_attack_type, insert_pending_attack,)
from tools.firewall.ipset_tools import (ensure_ipset)
from tools.es.es_tools import (get_index_range, update_index_if_needed, search_new_logs)
from tools.utils.ip_utils import (wildcard_to_cidr, is_ip_in_list)
from tools.llm.ollama_tools import (analyze_message,)
from tools.logs.log_tools import (format_logs, build_syslog, build_zeeklog, build_weirdlog, build_noticelog, handle_logs)
from tools.security.security_tools import (expire_warning_ips, is_in_cooldown, build_ip_lists, update_ip_activity, maybe_sync_ipset,)
from tools.security.policy import (save_analysis_result,)
from tools.system.system_tools import (heartbeat,)
from config.settings import (ES_HOST, ES_USER, ES_PASS, OLLAMA_URL, POLL_INTERVAL, IPSET_NAME, IPSET_FULL_NAME, IPSET_WHITELIST_NAME, load_hosts, get_my_host_ips, load_config, RAW_DIR, PARSED_DIR, URLS, openblacklist_PARSED_DIR)
from tools.firewall.openblacklist_loader import (download_blacklists, parse_blacklists)
from tools.firewall.openblacklist_matcher import (is_blacklisted, load_blacklists, handle_blacklist_hit)
from tools.eval.eval_tools import (is_in_eval_cooldown, save_eval_result, get_eval_label_counts, get_eval_hints)

# eval 模式：對公開黑名單 IP 也跑 LLM，結果僅存 eval_results，不影響封鎖
EVAL_MODE = True
EVAL_LOG_THRESHOLD    = 5    # 至少幾筆 log 才執行 eval 分析
EVAL_COOLDOWN_MIN     = 60   # 同 IP 幾分鐘內不重複 eval
EVAL_ATTACK_MIN_SRCS  = 2    # attack GT 品質門檻：至少命中幾個獨立 blacklist 來源


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------
# MAIN LOOP
# -------------------------
def main():
    print("=== 開始日誌分析程序 ===")
    config = load_config()
    # 全局變數，確保 main 函式內都能存取並比對
    conn = mariadb.connect(
        host=config['db_host'],
        user=config['db_user'],
        password=config['db_password'],
        database=config['db_name'],
        autocommit=True  # 建議開啟自動提交
    )

    state = {
        "stored_date": None,
        "INDEX": get_index_range(2)
    }

    _eval_script = os.path.abspath(os.path.join(os.path.dirname(__file__), 'eval', 'eval_metrics.py'))
    _eval_cwd    = os.path.abspath(os.path.dirname(__file__))
    _last_eval   = None   # 時間戳記，防止同天重複執行

    _eval_hints       = get_eval_hints(conn)   # 昨日 FN/FP 回饋，注入 LLM prompt
    _last_hints_date  = datetime.now().date()  # 每日零點後刷新一次
    
    enabled_hosts = load_hosts()
    MY_HOST_IPS = get_my_host_ips()
    print("All MY_HOST_IPS:", MY_HOST_IPS)

    ensure_ipset(enabled_hosts, [IPSET_NAME, IPSET_FULL_NAME, IPSET_WHITELIST_NAME])

    # 五分鐘心跳，確認程式存活-毅251016
    last_heartbeat = datetime.utcnow()

    last_ipset_snapshot = {
        "black": None,
        "full": None,
        "white": None,
    }
    last_ip_refresh = None

    last_timestamp = datetime.utcnow().isoformat() + "Z"
    last_ip_refresh = datetime.now()


    white_ips, white_ranges, black_ips, black_ranges, full_black_ips = \
        build_ip_lists(conn, wildcard_to_cidr)
    
    download_blacklists(RAW_DIR, PARSED_DIR, URLS)
    parse_blacklists(RAW_DIR, PARSED_DIR, URLS)
    openblacklist = load_blacklists(openblacklist_PARSED_DIR)

    while True:
        last_heartbeat, need_update = heartbeat(last_heartbeat)
        if need_update:
            download_blacklists(RAW_DIR, PARSED_DIR, URLS)
            parse_blacklists(RAW_DIR, PARSED_DIR, URLS)
            openblacklist = load_blacklists(openblacklist_PARSED_DIR)

        # eval hints 每日零點後刷新一次
        _today = datetime.now().date()
        if _today != _last_hints_date:
            _eval_hints      = get_eval_hints(conn)
            _last_hints_date = _today
            if _eval_hints:
                print(f"[EVAL HINTS] 已刷新昨日 FN/FP 回饋，注入 LLM prompt")
            else:
                print(f"[EVAL HINTS] 昨日無 FN/FP 資料，略過注入")
        # -------------------------
        # 1️⃣ IPSET sync（只在 DB 變化時）
        # -------------------------
        last_ipset_snapshot = maybe_sync_ipset(conn, enabled_hosts, IPSET_NAME, IPSET_FULL_NAME, wildcard_to_cidr, last_ipset_snapshot, IPSET_WHITELIST_NAME)

        # -------------------------
        # 2️⃣ DB reconnect
        # -------------------------
        try:
            conn.ping()
        except:
            conn = mariadb.connect(
                host=config['db_host'],
                user=config['db_user'],
                password=config['db_password'],
                database=config['db_name'],
                autocommit=True
            )

        # ==================================================
        # 3️⃣ ES index update
        # ==================================================
        update_index_if_needed(state, ES_HOST, ES_USER, ES_PASS)

        # ── 每日午夜觸發 eval_metrics.py（本地時間日期切換時）
        _today = datetime.now().date()
        _eval_due = (
            _last_eval is None                      # 從未執行過（首次啟動）
            or _today > _last_eval.date()           # 本地日期已切換（午夜後第一次 loop）
        )
        if _eval_due:
            print(f"[EVAL] 觸發 eval_metrics.py（today={_today}, last_eval={_last_eval}）")
            try:
                subprocess.Popen(
                    [sys.executable, _eval_script],
                    cwd=_eval_cwd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT
                )
                _last_eval = datetime.now()
            except Exception as e:
                print(f"[EVAL] 啟動失敗: {e}")

        expire_warning_ips(conn)

        hits = search_new_logs(
            ES_HOST,
            ES_USER,
            ES_PASS,
            state["INDEX"],
            last_timestamp
        )
        ip_cache = {}
        benign_eval_cache = {}   # 白名單 IP 的 log 暫存，用於 benign eval
        batch_attack_eval_count = 0  # 本 batch 成功寫入的 attack eval 筆數

        if not hits:
            time.sleep(POLL_INTERVAL)
            continue

        # ==================================================
        # 4️⃣ parse logs
        # ==================================================
        for hit in hits:

            if datetime.now() - last_ip_refresh > timedelta(seconds=30):
                white_ips, white_ranges, black_ips, black_ranges, full_black_ips = \
                    build_ip_lists(conn, wildcard_to_cidr)
                last_ip_refresh = datetime.now()

            src = hit.get("_source", {})
            message = src.get("message")
            zeek = src.get("event", {}).get("original")
            dataset = src.get("event", {}).get("dataset", "")
            client_ip = src.get("client_ip")
            src_ip = src.get("src_ip")
            dst_ip = src.get("dst_ip")
            timestamp = src.get("@timestamp")
            host_name = src.get("host", {}).get("name", "")

            if not (message or zeek):
                continue

            try:
                log_time = datetime.strptime(timestamp[:19], "%Y-%m-%dT%H:%M:%S")
                time_str = (log_time + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
            except:
                continue

            # -------------------------
            # zeek ip resolve
            # -------------------------
            local_ip = None
            direction = None
            zeek_ip = None

            if zeek and src_ip and dst_ip:
                if dst_ip in MY_HOST_IPS:
                    zeek_ip, local_ip, direction = src_ip, dst_ip, "inbound"
                elif src_ip in MY_HOST_IPS:
                    zeek_ip, local_ip, direction = dst_ip, src_ip, "outbound"

            ip = client_ip or zeek_ip
            if not ip:
                continue

            last_timestamp = timestamp

            # -------------------------
            # whitelist / blacklist skip
            # -------------------------
            # eval 模式：公開黑名單 IP 繼續收 log（供後續 eval LLM 分析）
            # 非 eval 模式或已手動加入黑名單才直接跳過
            if is_ip_in_list(ip, full_black_ips, black_ranges):
                if not (EVAL_MODE and is_blacklisted(openblacklist, ip)):
                    continue

            if is_ip_in_list(ip, white_ips, white_ranges):
                # benign eval：將本 batch 所有白名單 IP 全納入候選池
                # 實際是否執行由 step 7 的 attack/benign 累積數平衡邏輯決定
                if EVAL_MODE:
                    if ip not in benign_eval_cache:
                        benign_eval_cache[ip] = {
                            "syslog": [], "zeeklog": [], "weirdlog": [], "noticelog": [],
                            "host_name": host_name,
                            "last_time": time_str,
                            "local_ip": local_ip, "direction": direction
                        }
                    if ip in benign_eval_cache:
                        if message:
                            benign_eval_cache[ip]["syslog"].append(message)
                        if zeek:
                            if dataset == "zeek.weird":
                                benign_eval_cache[ip]["weirdlog"].append(zeek)
                            elif dataset == "zeek.notice":
                                benign_eval_cache[ip]["noticelog"].append(zeek)
                            else:
                                benign_eval_cache[ip]["zeeklog"].append(zeek)
                        benign_eval_cache[ip]["last_time"] = time_str
                continue

            # -------------------------
            # cache logs
            # -------------------------
            if ip not in ip_cache:
                ip_cache[ip] = {
                    "syslog": [],
                    "zeeklog": [],
                    "weirdlog": [],
                    "noticelog": [],
                    "host_name": host_name,
                    "last_time": time_str,
                    "local_ip": local_ip,
                    "direction": direction
                }

            if message:
                ip_cache[ip]["syslog"].append(message)

            if zeek:
                if dataset == "zeek.weird":
                    ip_cache[ip]["weirdlog"].append(zeek)
                elif dataset == "zeek.notice":
                    ip_cache[ip]["noticelog"].append(zeek)
                else:
                    ip_cache[ip]["zeeklog"].append(zeek)

        # ==================================================
        # 5️⃣ process per IP
        # ==================================================
        for ip, data in ip_cache.items():

            # -------------------------
            # tool: insert logs
            # -------------------------
            handle_logs(conn, data["syslog"],    build_syslog,    "syslog",    ip, data)
            handle_logs(conn, data["zeeklog"],   build_zeeklog,   "zeeklog",   ip, data)
            handle_logs(conn, data["weirdlog"],  build_weirdlog,  "weirdlog",  ip, data)
            handle_logs(conn, data["noticelog"], build_noticelog, "noticelog", ip, data)
            # -------------------------
            # tool: update activity
            # -------------------------
            update_ip_activity(conn, ip, data["host_name"])
            # -------------------------
            # 公開黑名單比對
            # -------------------------
            results = is_blacklisted(openblacklist, ip)
            if handle_blacklist_hit(conn, ip, results, host_name):
                print(f"[BLACKLIST HIT] IP={ip} ｜ 狀態=已命中公開黑名單 ｜ 動作=寫入風險紀錄並跳過後續分析")

                # ── eval 模式：對公開黑名單 IP 並行跑 LLM，衡量模型獨立偵測準確度
                # GT 品質門檻：要求命中 2+ 個獨立 blacklist 來源，排除單一來源誤報
                eval_src_count = len({s for _, s in results})
                if (EVAL_MODE
                        and eval_src_count >= EVAL_ATTACK_MIN_SRCS
                        and not is_in_eval_cooldown(conn, ip, EVAL_COOLDOWN_MIN)):
                    eval_count = get_ip_log_count_24h(conn, ip)
                    if eval_count >= EVAL_LOG_THRESHOLD:
                        print(f"[EVAL] IP={ip} ｜ log={eval_count} ｜ srcs={eval_src_count} ｜ 執行 eval LLM 分析")
                        eval_syslog   = format_logs(get_ip_logs(conn, ip, "syslog"))
                        eval_zeek     = format_logs(get_ip_logs(conn, ip, "zeeklog"))
                        eval_known    = get_known_attacks(conn)
                        eval_analysis = analyze_message(
                            f"{eval_syslog}\n{eval_zeek}",
                            ip,
                            data["local_ip"],
                            data["direction"],
                            eval_known,
                            OLLAMA_URL,
                            eval_hints=_eval_hints
                        )
                        if eval_analysis:
                            save_eval_result(conn, ip, eval_analysis,
                                             true_label='attack',
                                             gt_source='openblacklist',
                                             log_count=eval_count,
                                             source_count=eval_src_count)
                            batch_attack_eval_count += 1
                            print(f"[EVAL] 儲存完成 danger_level={eval_analysis.get('danger_level')} "
                                  f"confidence={eval_analysis.get('confidence')} "
                                  f"srcs={eval_src_count}")

                continue
            # -------------------------
            # log count filter
            # -------------------------
            count = get_ip_log_count_24h(conn, ip)

            print(f"\n[DEBUG] IP: {ip}")
            print(f"DB log數量(24h): {count}")

            threshold = 5

            if count < threshold:
                continue
            
            if is_in_cooldown(conn, ip, 5):
                print(f"[SKIP] {ip} 5分鐘內已分析")
                continue

            # ==================================================
            # 6️⃣ AI analyze
            # ==================================================
            syslog_rows  = get_ip_logs(conn, ip, "syslog")
            zeek_rows    = get_ip_logs(conn, ip, "zeeklog")
            weird_rows   = get_ip_logs(conn, ip, "weirdlog")
            notice_rows  = get_ip_logs(conn, ip, "noticelog")
            syslog_text  = format_logs(syslog_rows)
            zeek_text    = "\n".join(filter(None, [
                format_logs(zeek_rows),
                format_logs(weird_rows),
                format_logs(notice_rows),
            ]))

            total_log = f"{syslog_text}\n{zeek_text}"
            # print("分析的log總合:",total_log)

            # 已知攻擊手法清單
            known_attacks = get_known_attacks(conn)

            syslog_texts = [r['log_content'] for r in syslog_rows]
            zeek_texts   = [r['log_content'] for r in zeek_rows + weird_rows + notice_rows]

            analysis = analyze_message(
                total_log,
                ip,
                data["local_ip"],
                data["direction"],
                known_attacks,
                OLLAMA_URL,
                syslog_list=syslog_texts,
                zeek_list=zeek_texts,
                eval_hints=_eval_hints
            )

            # ── confidence 低時診斷並決定是否 retry ──
            if analysis:
                confidence = analysis.get("confidence", 1.0)
                if confidence < 0.7:
                    if count >= 20:
                        # DB 有足夠歷史 log，擴大 limit 重分析
                        print(f"[RETRY] IP={ip} confidence={confidence:.2f}，24h log={count}，擴大 limit 重分析")
                        syslog_rows_ex  = get_ip_logs(conn, ip, "syslog",    limit=50)
                        zeek_rows_ex    = get_ip_logs(conn, ip, "zeeklog",   limit=50)
                        weird_rows_ex   = get_ip_logs(conn, ip, "weirdlog",  limit=50)
                        notice_rows_ex  = get_ip_logs(conn, ip, "noticelog", limit=50)
                        zeek_text_ex    = "\n".join(filter(None, [
                            format_logs(zeek_rows_ex),
                            format_logs(weird_rows_ex),
                            format_logs(notice_rows_ex),
                        ]))
                        analysis_ex = analyze_message(
                            f"{format_logs(syslog_rows_ex)}\n{zeek_text_ex}",
                            ip, data["local_ip"], data["direction"],
                            known_attacks, OLLAMA_URL,
                            syslog_list=[r['log_content'] for r in syslog_rows_ex],
                            zeek_list=[r['log_content'] for r in zeek_rows_ex + weird_rows_ex + notice_rows_ex],
                        )
                        if analysis_ex and analysis_ex.get("confidence", 0) > confidence:
                            print(f"[RETRY] 信心度提升 {confidence:.2f} → {analysis_ex.get('confidence'):.2f}")
                            analysis = analysis_ex
                        else:
                            print(f"[RETRY] 信心度未改善，保留原始結果")
                    else:
                        # log 真的太少，不儲存，等下次 poll 累積更多再判斷
                        print(f"[LOW-DATA] IP={ip} confidence={confidence:.2f}，24h log 僅 {count} 筆，延後分析")
                        continue

            print("\n==================== AI 分析結果 ====================")
            print(f"IP: {ip}")

            if analysis:
                try:
                    print(json.dumps(analysis, ensure_ascii=False, indent=2))
                except Exception:
                    print(analysis)
            else:
                print("❌ 沒有分析結果（analysis = None）")

            print("====================================================\n")

            # =========================
            # 4️⃣ tool: save result
            # =========================
            save_analysis_result(conn, ip, analysis, host_name)

            # 新攻擊類型 → 寫入待審核（供人工核准後加入 known_attacks）
            a_type  = (analysis.get("attack_type") or "").strip()
            a_level = analysis.get("danger_level", "")
            if a_level == "危險" and a_type and is_new_attack_type(conn, a_type):
                insert_pending_attack(
                    conn, ip, a_type,
                    analysis.get("attack_method", ""),
                    analysis.get("reason", "")
                )
                print(f"[PENDING] 新攻擊手法已加入待審核: {a_type} (IP={ip})")

        # ==================================================
        # 7️⃣ benign eval（白名單 IP 送 LLM，與 attack eval 筆數保持平衡）
        # ==================================================
        if EVAL_MODE:
            # ── 先把本 batch 白名單 logs 存進 DB（讓 step 7 能讀 24h 歷史）
            for ip, data in benign_eval_cache.items():
                handle_logs(conn, data["syslog"],    build_syslog,    "syslog",    ip, data)
                handle_logs(conn, data["zeeklog"],   build_zeeklog,   "zeeklog",   ip, data)
                handle_logs(conn, data["weirdlog"],  build_weirdlog,  "weirdlog",  ip, data)
                handle_logs(conn, data["noticelog"], build_noticelog, "noticelog", ip, data)

            # 查 DB 累積數，只有 attack 多於 benign 時才補充 benign 樣本
            n_attack_db, n_benign_db = get_eval_label_counts(conn)
            n_attack_total  = n_attack_db + batch_attack_eval_count
            n_benign_running = n_benign_db  # 隨本 batch 新增而遞增

            # 篩出合格候選（用 DB 24h log 數判斷），隨機排序避免固定偏差
            eligible = [
                (ip, data) for ip, data in benign_eval_cache.items()
                if get_ip_log_count_24h(conn, ip) >= EVAL_LOG_THRESHOLD
                and not is_in_eval_cooldown(conn, ip, EVAL_COOLDOWN_MIN)
            ]
            random.shuffle(eligible)

            for ip, data in eligible:
                if n_attack_total <= n_benign_running:
                    break  # 已追平，不再補 benign
                # 從 DB 讀 24h 歷史 log，與 attack eval 一致
                eval_syslog = format_logs(get_ip_logs(conn, ip, "syslog"))
                eval_zeek   = format_logs(get_ip_logs(conn, ip, "zeeklog"))
                log_count   = get_ip_log_count_24h(conn, ip)
                eval_known  = get_known_attacks(conn)
                eval_analysis = analyze_message(
                    f"{eval_syslog}\n{eval_zeek}",
                    ip,
                    data["local_ip"],
                    data["direction"],
                    eval_known,
                    OLLAMA_URL,
                    eval_hints=_eval_hints
                )
                if eval_analysis:
                    save_eval_result(conn, ip, eval_analysis,
                                     true_label='benign',
                                     gt_source='whitelist',
                                     log_count=log_count,
                                     source_count=0)
                    n_benign_running += 1
                    print(f"[EVAL-BENIGN] IP={ip} ｜ log={log_count} ｜ "
                          f"danger={eval_analysis.get('danger_level')} "
                          f"conf={eval_analysis.get('confidence')} "
                          f"[attack={n_attack_total} benign={n_benign_running}]")

        cleanup_blacklist(conn)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()