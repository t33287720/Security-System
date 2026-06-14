import hashlib
import os

from skills.review_code_logic import executor as review_code_logic

# 僅審查 web/ 下的 .php（使用者實際會打到的 HTTP 端點），
# 排除 worker/、vuln-agent/ 等無 HTTP 端點的內部背景程式/工具模組
SCAN_EXTENSIONS = {".php"}
SCAN_DIR_NAME = "web"
MAX_BYTES = int(os.getenv("LLM_LOGIC_REVIEW_MAX_BYTES", "12000"))


def _number_lines(content: str) -> str:
    lines = content.splitlines()
    return "\n".join(f"{i + 1}| {line}" for i, line in enumerate(lines))


def _snippet(content: str, line_start: int, line_end: int) -> str:
    lines = content.splitlines()
    start = max(0, (line_start or 1) - 1)
    end = min(len(lines), line_end or line_start or 1)
    return "\n".join(lines[start:end])[:500]


def _iter_review_files(repo_path: str):
    for root, _dirs, files in os.walk(repo_path):
        for name in files:
            if os.path.splitext(name)[1].lower() not in SCAN_EXTENSIONS:
                continue
            full_path = os.path.join(root, name)
            try:
                size = os.path.getsize(full_path)
            except OSError:
                continue
            if size == 0 or size > MAX_BYTES:
                continue
            yield full_path


def run_llm_logic_review(repo_path: str) -> list:
    """對 repo_path 下的 .php 檔案逐一做 LLM 業務邏輯審查，回傳候選清單

    僅在 repo_path 為 web/ 目錄時執行（使用者實際會打到的 HTTP 端點）。
    跳過空檔案與超過 MAX_BYTES 的檔案（避免超出 LLM 上下文長度）。
    """
    if os.path.basename(repo_path.rstrip("/")) != SCAN_DIR_NAME:
        return []

    candidates = []
    for full_path in _iter_review_files(repo_path):
        rel_path = os.path.relpath(full_path, repo_path)
        print(f"[vuln-agent]   - LLM業務邏輯審查：{rel_path}")

        with open(full_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        if not content.strip():
            continue

        try:
            result = review_code_logic.run({
                "file": full_path,
                "content": _number_lines(content),
            })
        except Exception:
            continue

        for item in result.get("findings", []):
            title = (item.get("title") or "").strip()
            if not title:
                continue
            line_start = item.get("line_start") or 1
            line_end = item.get("line_end") or line_start
            candidates.append({
                "file": full_path,
                "line_start": line_start,
                "line_end": line_end,
                "rule_id": "llm-logic-" + hashlib.sha1(title.encode("utf-8")).hexdigest()[:8],
                "message": title,
                "snippet": _snippet(content, line_start, line_end),
                "llm_description": item.get("description", ""),
            })

    return candidates
