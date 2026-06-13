import json
import subprocess

DEFAULT_CONFIGS = ["p/python", "p/php"]


def run_semgrep(repo_path: str, configs: list = None, timeout: int = 600) -> list:
    """用 semgrep 對 repo_path 做 SAST 掃描，回傳候選清單

    --metrics=off：關閉遙測，適合受控/離線環境
    """
    configs = configs or DEFAULT_CONFIGS
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off"]
    for c in configs:
        cmd += ["--config", c]
    cmd.append(repo_path)

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    try:
        data = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except (ValueError, TypeError):
        return []

    candidates = []
    for r in data.get("results", []):
        candidates.append({
            "file": r.get("path"),
            "line_start": r.get("start", {}).get("line"),
            "line_end": r.get("end", {}).get("line"),
            "rule_id": r.get("check_id"),
            "message": r.get("extra", {}).get("message"),
            "snippet": (r.get("extra", {}).get("lines") or "")[:1000],
            "semgrep_severity": r.get("extra", {}).get("severity"),
        })
    return candidates
