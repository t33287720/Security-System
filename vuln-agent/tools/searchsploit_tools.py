import json
import subprocess


def search_exploits(product: str, version: str, timeout: int = 60) -> list:
    """用 searchsploit（離線 exploit-db 資料庫）依服務名稱+版本查詢候選 CVE/exploit"""
    query = " ".join(p for p in [product, version] if p).strip()
    if not query:
        return []

    cmd = ["searchsploit", "--json", query]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    try:
        data = json.loads(proc.stdout)
    except (ValueError, TypeError):
        return []

    results = []
    for item in data.get("RESULTS_EXPLOIT", []):
        codes = item.get("Codes", "") or ""
        cve_ids = [c.strip() for c in codes.split(";") if c.strip().upper().startswith("CVE-")]
        results.append({
            "title": item.get("Title", ""),
            "edb_id": item.get("EDB-ID", ""),
            "type": item.get("Type", ""),
            "cve_codes": cve_ids,
        })

    return results
