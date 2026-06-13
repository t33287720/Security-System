import json
import subprocess

from tools.redact import redact_secret, secret_hash


def run_gitleaks(repo_path: str, timeout: int = 300) -> list:
    """用 gitleaks 對 repo_path 做 secrets 掃描，回傳已遮蔽的候選清單

    --no-git：掃描檔案系統內容而非 git history（掛載進來的是純檔案目錄）
    --exit-code 0：找到 leak 時 gitleaks 預設回傳碼為1，這裡明確改為0避免誤判為執行失敗
    """
    cmd = ["gitleaks", "detect", "--source", repo_path, "--no-git",
           "-f", "json", "-r", "/dev/stdout", "--exit-code", "0"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    try:
        results = json.loads(proc.stdout) if proc.stdout.strip() else []
    except (ValueError, TypeError):
        return []

    candidates = []
    for item in results:
        secret = item.get("Secret", "")
        candidates.append({
            "file": item.get("File"),
            "line_start": item.get("StartLine"),
            "line_end": item.get("EndLine"),
            "rule_id": item.get("RuleID"),
            "message": item.get("Description"),
            # 注意：snippet/secret 一律經過遮蔽，絕不保留原始 Secret/Match 明文
            "snippet": redact_secret(item.get("Match", "")),
            "secret_redacted": redact_secret(secret),
            "secret_hash": secret_hash(secret),
        })
    return candidates
