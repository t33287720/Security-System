import os
import re
import sys
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "Prompt_Chaining"))

from tools.nmap_tools import run_recon, run_script_recheck
from tools.searchsploit_tools import search_exploits
from tools.http_tools import probe as http_probe
from tools.vuln_db import get_conn, ensure_schema, save_finding

from skills.triage_finding import executor as triage_finding
from skills.decide_followup import executor as decide_followup

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CONFIDENCE_FOLLOWUP_THRESHOLD = 0.5


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


def run_followup(target: str, port_info: dict, decision: dict):
    tool = decision.get("tool")
    params = decision.get("params") or {}

    if tool == "nmap_script_recheck":
        script = params.get("script")
        if not script:
            return None
        output = run_script_recheck(target, port_info["port"], script)
        return {"tool": tool, "script": script, "output": output}

    if tool == "http_banner_probe":
        path = params.get("path", "/")
        return {"tool": tool, "result": http_probe(target, port_info["port"], path)}

    return None


def triage_candidate(target: str, port_info: dict, candidate: dict) -> dict:
    base_input = {
        "target": target,
        "port": port_info["port"],
        "service": port_info.get("service"),
        "product": port_info.get("product"),
        "version": port_info.get("version"),
        "finding_source": candidate["source"],
        "finding": candidate["finding"],
        "followup_evidence": None,
    }

    triage = triage_finding.run(base_input)

    if triage.get("confidence", 0) < CONFIDENCE_FOLLOWUP_THRESHOLD:
        decision = decide_followup.run({**base_input, "triage_result": triage})
        followup_evidence = run_followup(target, port_info, decision)
        if followup_evidence:
            base_input["followup_evidence"] = followup_evidence
            triage = triage_finding.run(base_input)

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

    finding_count = 0
    for port_info in recon.get("ports", []):
        for candidate in build_candidates(port_info):
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


def main():
    targets = [t.strip() for t in os.getenv("VULN_SCAN_TARGETS", "127.0.0.1").split(",") if t.strip()]
    conn = get_conn()
    ensure_schema(conn)
    for target in targets:
        scan_target(conn, target)


if __name__ == "__main__":
    main()
