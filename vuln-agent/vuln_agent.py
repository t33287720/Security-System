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

from tools.gitleaks_tools import run_gitleaks
from tools.semgrep_tools import run_semgrep
from tools.code_db import ensure_code_schema, save_code_finding
from tools.code_agent_tools import available_tools as code_available_tools, run_tool as code_run_tool

from tools.report_db import (
    ensure_report_schema, get_latest_report, collect_findings_snapshot,
    build_report_stats, build_top_findings, save_report,
)

from skills.triage_finding import executor as triage_finding
from skills.decide_next_action import executor as decide_next_action
from skills.triage_code_finding import executor as triage_code_finding
from skills.generate_report import executor as generate_report

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CONFIDENCE_FOLLOWUP_THRESHOLD = 0.5
MAX_REACT_ROUNDS = int(os.getenv("VULN_REACT_MAX_ROUNDS", "2"))
CODE_REACT_MAX_ROUNDS = int(os.getenv("CODE_REACT_MAX_ROUNDS", os.getenv("VULN_REACT_MAX_ROUNDS", "2")))
CODE_SCAN_ROOT = os.getenv("CODE_SCAN_ROOT", "/app/repo")


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


def build_code_candidates(repo_path: str) -> list:
    candidates = []
    for finding in run_gitleaks(repo_path):
        candidates.append({"source": "gitleaks", "finding": finding})
    for finding in run_semgrep(repo_path):
        candidates.append({"source": "semgrep", "finding": finding})
    return candidates


def triage_code_candidate(candidate: dict) -> dict:
    finding = candidate["finding"]
    source = candidate["source"]
    print(f"[vuln-agent]   - 分析候選原始碼問題（{source}）{finding.get('file')}:{finding.get('line_start')} "
          f"{finding.get('rule_id')}")

    base_input = {
        "finding_source": source,
        "finding": finding,
        "followup_evidence": [],
    }

    triage = triage_code_finding.run(base_input)
    print(f"[vuln-agent]     初步判斷：相關={triage.get('is_relevant')} "
          f"嚴重程度={triage.get('severity')} 信心={triage.get('confidence')}")

    evidence_log = []
    round_idx = 0
    while triage.get("confidence", 0) < CONFIDENCE_FOLLOWUP_THRESHOLD and round_idx < CODE_REACT_MAX_ROUNDS:
        tools = code_available_tools(finding)
        decision = decide_next_action.run({
            **base_input,
            "triage_result": triage,
            "evidence_log": evidence_log,
            "available_tools": tools,
            "round": round_idx,
            "max_round": CODE_REACT_MAX_ROUNDS,
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
        result = code_run_tool(action, finding, params)
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

        triage = triage_code_finding.run(base_input)
        print(f"[vuln-agent]     第{round_idx + 1}輪後重新判斷：相關={triage.get('is_relevant')} "
              f"嚴重程度={triage.get('severity')} 信心={triage.get('confidence')}")
        round_idx += 1

    return triage


def make_code_finding_record(candidate: dict, triage: dict) -> dict:
    finding = candidate["finding"]
    source = candidate["source"]

    return {
        "file_path": finding.get("file"),
        "line_start": finding.get("line_start") or 0,
        "line_end": finding.get("line_end") or 0,
        "source": source,
        "rule_id": finding.get("rule_id") or "",
        "title": finding.get("rule_id") or finding.get("message") or "未命名問題",
        "severity": triage.get("severity"),
        "confidence": triage.get("confidence"),
        "evidence": json.dumps(finding, ensure_ascii=False)[:2000],
        "remediation": triage.get("remediation"),
    }


def scan_codebase(conn, paths: list):
    finding_count = 0
    for repo_path in paths:
        print(f"[vuln-agent] 開始掃描原始碼目錄 {repo_path}")
        candidates = build_code_candidates(repo_path)
        print(f"[vuln-agent] {repo_path} 找到 {len(candidates)} 個候選問題")

        for candidate in candidates:
            try:
                triage = triage_code_candidate(candidate)
            except Exception as e:
                print(f"[vuln-agent] LLM分析失敗 file={candidate['finding'].get('file')}: {e}")
                continue

            if not triage.get("is_relevant"):
                continue

            record = make_code_finding_record(candidate, triage)
            save_code_finding(conn, record)
            finding_count += 1
            print(f"[vuln-agent] 發現原始碼問題 file={record['file_path']}:{record['line_start']} "
                  f"severity={record['severity']}")

    print(f"[vuln-agent] 原始碼掃描完成，共 {finding_count} 筆紀錄")


def generate_scan_report(conn):
    """彙整本輪掃描後 vuln_findings + code_findings 的現況，
    與上一份報告比對增量（新增/已解決），交由 LLM 產生摘要後寫入 scan_reports"""
    print("[vuln-agent] 開始產生本輪掃描報告")
    previous = get_latest_report(conn)
    snapshot = collect_findings_snapshot(conn)
    stats = build_report_stats(snapshot, previous)
    top_findings = build_top_findings(snapshot)

    report = generate_report.run({
        "total": stats["total"],
        "severity": stats["severity"],
        "new_count": stats["new_count"],
        "resolved_count": stats["resolved_count"],
        "previous_total": stats["previous_total"],
        "previous_generated_at": str(previous["generated_at"]) if previous else None,
        "top_findings": top_findings,
    })

    save_report(conn, report.get("summary", ""), report.get("highlights", []), stats, top_findings)
    print(f"[vuln-agent] 報告完成：共 {stats['total']} 筆（高{stats['severity']['高']}/"
          f"中{stats['severity']['中']}/低{stats['severity']['低']}/資訊{stats['severity']['資訊']}），"
          f"新增 {stats['new_count']} 筆，已解決 {stats['resolved_count']} 筆")
    print(f"[vuln-agent] 摘要：{report.get('summary', '')}")


def seconds_until(daily_time: str) -> float:
    """計算距離下一次指定時間（HH:MM，依容器本地時區）還有多少秒"""
    hour, minute = map(int, daily_time.split(":"))
    now = datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


def get_code_scan_paths() -> list:
    code_scan_paths = [p.strip() for p in os.getenv("CODE_SCAN_PATHS", "worker,web,vuln-agent").split(",") if p.strip()]
    return [
        os.path.join(CODE_SCAN_ROOT, p)
        for p in code_scan_paths
        if os.path.isdir(os.path.join(CODE_SCAN_ROOT, p))
    ]


def main():
    targets = [t.strip() for t in os.getenv("VULN_SCAN_TARGETS", "127.0.0.1").split(",") if t.strip()]
    daily_time = os.getenv("VULN_SCAN_DAILY_TIME", "00:00")
    run_once = os.getenv("VULN_SCAN_RUN_ONCE", "false").lower() == "true"

    code_scan_enabled = os.getenv("CODE_SCAN_ENABLED", "true").lower() == "true"
    code_scan_paths = get_code_scan_paths()

    conn = get_conn()
    ensure_schema(conn)
    ensure_code_schema(conn)
    ensure_report_schema(conn)

    if run_once:
        for target in targets:
            scan_target(conn, target)
        if code_scan_enabled and code_scan_paths:
            scan_codebase(conn, code_scan_paths)
        generate_scan_report(conn)
        return

    while True:
        wait = seconds_until(daily_time)
        print(f"[vuln-agent] 下次排程掃描時間 {daily_time}，{wait / 3600:.1f} 小時後執行")
        time.sleep(wait)
        conn = get_conn()  # 重新連線，避免閒置超過 MariaDB wait_timeout 而斷線
        for target in targets:
            scan_target(conn, target)
        if code_scan_enabled and code_scan_paths:
            scan_codebase(conn, code_scan_paths)
        generate_scan_report(conn)


if __name__ == "__main__":
    main()
