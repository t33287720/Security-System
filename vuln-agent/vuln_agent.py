import os
import re
import sys
import json
import time
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "Prompt_Chaining"))

from tools.nmap_tools import run_recon
from tools.searchsploit_tools import search_exploits
from tools.vuln_db import get_conn, ensure_schema, save_finding
from tools.agent_tools import available_tools, run_tool

from skills.triage_finding import executor as triage_finding
from skills.decide_next_action import executor as decide_next_action

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CONFIDENCE_FOLLOWUP_THRESHOLD = 0.5
MAX_REACT_ROUNDS = int(os.getenv("VULN_REACT_MAX_ROUNDS", "2"))


def extract_cve(*texts):
    for text in texts:
        if not text:
            continue
        m = CVE_RE.search(str(text))
        if m:
            return m.group(0).upper()
    return None


def build_candidates(port_info: dict) -> list:
    candidates = []

    for script in port_info.get("scripts", []):
        candidates.append({"source": "nmap_vuln_script", "finding": script})

    product = port_info.get("product")
    version = port_info.get("version")
    if product and version:
        for exploit in search_exploits(product, version):
            candidates.append({"source": "searchsploit", "finding": exploit})

    return candidates


def _candidate_label(candidate: dict) -> str:
    finding = candidate["finding"]
    if candidate["source"] == "nmap_vuln_script":
        return finding.get("id", "")
    return finding.get("title", "")


def triage_candidate(target: str, port_info: dict, candidate: dict) -> dict:
    port = port_info["port"]
    label = _candidate_label(candidate)
    print(f"[vuln-agent]   - [{target}:{port}] 分析候選弱點（{candidate['source']}）{label}")

    base_input = {
        "target": target,
        "port": port,
        "service": port_info.get("service"),
        "product": port_info.get("product"),
        "version": port_info.get("version"),
        "finding_source": candidate["source"],
        "finding": candidate["finding"],
        "followup_evidence": [],
    }

    triage = triage_finding.run(base_input)
    print(f"[vuln-agent]     初步判斷：相關={triage.get('is_relevant')} "
          f"嚴重程度={triage.get('severity')} 信心={triage.get('confidence')}")

    evidence_log = []
    round_idx = 0
    while triage.get("confidence", 0) < CONFIDENCE_FOLLOWUP_THRESHOLD and round_idx < MAX_REACT_ROUNDS:
        tools = available_tools(port_info)
        decision = decide_next_action.run({
            **base_input,
            "triage_result": triage,
            "evidence_log": evidence_log,
            "available_tools": tools,
            "round": round_idx,
            "max_round": MAX_REACT_ROUNDS,
        })

        action = decision.get("action")
        reason = decision.get("reason", "")
        print(f"[vuln-agent]     第{round_idx + 1}輪決策：{action}（{reason}）")

        if not action or action == "done":
            break
        if action not in {t["action"] for t in tools}:
            print(f"[vuln-agent]     ⚠ 決策動作不在可用工具清單中，停止補充檢測")
            break

        params = decision.get("params") or {}
        result = run_tool(action, target, port_info, params)
        if result is None:
            print(f"[vuln-agent]     ⚠ 工具執行無結果，停止補充檢測")
            break

        evidence_log.append({
            "action": action,
            "params": params,
            "result": result,
            "reason": reason,
        })
        base_input["followup_evidence"] = evidence_log

        triage = triage_finding.run(base_input)
        print(f"[vuln-agent]     第{round_idx + 1}輪後重新判斷：相關={triage.get('is_relevant')} "
              f"嚴重程度={triage.get('severity')} 信心={triage.get('confidence')}")
        round_idx += 1

    return triage


def make_finding_record(target: str, port_info: dict, candidate: dict, triage: dict) -> dict:
    finding = candidate["finding"]
    source = candidate["source"]

    if source == "nmap_vuln_script":
        title = finding.get("id")
        evidence = finding.get("output", "")[:2000]
        cve_id = extract_cve(finding.get("id"), finding.get("output"))
    else:  # searchsploit
        title = finding.get("title")
        evidence = json.dumps(finding, ensure_ascii=False)[:2000]
        cve_codes = finding.get("cve_codes") or []
        cve_id = cve_codes[0] if cve_codes else None

    return {
        "target": target,
        "port": port_info.get("port"),
        "service": port_info.get("service"),
        "version": port_info.get("version"),
        "source": source,
        "cve_id": cve_id,
        "title": title,
        "severity": triage.get("severity"),
        "confidence": triage.get("confidence"),
        "evidence": evidence,
        "remediation": triage.get("remediation"),
    }


def scan_target(conn, target: str):
    print(f"[vuln-agent] 開始掃描 {target}")
    recon = run_recon(target)
    print(f"[vuln-agent] 偵測到 {len(recon.get('ports', []))} 個開放 port")

    finding_count = 0
    for port_info in recon.get("ports", []):
        candidates = build_candidates(port_info)
        print(f"[vuln-agent] port {port_info['port']}（{port_info.get('service')} "
              f"{port_info.get('product') or ''} {port_info.get('version') or ''}）"
              f"找到 {len(candidates)} 個候選弱點")
        for candidate in candidates:
            try:
                triage = triage_candidate(target, port_info, candidate)
            except Exception as e:
                print(f"[vuln-agent] LLM分析失敗 target={target} port={port_info['port']}: {e}")
                continue

            if not triage.get("is_relevant"):
                continue

            record = make_finding_record(target, port_info, candidate, triage)
            save_finding(conn, record)
            finding_count += 1
            print(f"[vuln-agent] 發現弱點 target={target} port={port_info['port']} "
                  f"severity={record['severity']} cve={record['cve_id']}")

    print(f"[vuln-agent] {target} 掃描完成，共 {finding_count} 筆弱點紀錄")


def seconds_until(daily_time: str) -> float:
    """計算距離下一次指定時間（HH:MM，依容器本地時區）還有多少秒"""
    hour, minute = map(int, daily_time.split(":"))
    now = datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


def main():
    targets = [t.strip() for t in os.getenv("VULN_SCAN_TARGETS", "127.0.0.1").split(",") if t.strip()]
    daily_time = os.getenv("VULN_SCAN_DAILY_TIME", "00:00")
    run_once = os.getenv("VULN_SCAN_RUN_ONCE", "false").lower() == "true"

    conn = get_conn()
    ensure_schema(conn)

    if run_once:
        for target in targets:
            scan_target(conn, target)
        return

    while True:
        wait = seconds_until(daily_time)
        print(f"[vuln-agent] 下次排程掃描時間 {daily_time}，{wait / 3600:.1f} 小時後執行")
        time.sleep(wait)
        conn = get_conn()  # 重新連線，避免閒置超過 MariaDB wait_timeout 而斷線
        for target in targets:
            scan_target(conn, target)


if __name__ == "__main__":
    main()
