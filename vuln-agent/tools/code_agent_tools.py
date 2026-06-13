"""程式碼掃描 ReAct 迴圈可用的唯讀工具登錄表。

與 agent_tools.py 的差異：程式碼掃描沒有 target/port_info 概念，
run_tool 簽名改為 run_tool(action, finding, params)。
"""

import os
import subprocess

REPO_ROOT = os.getenv("CODE_SCAN_ROOT", "/app/repo")


def _safe_path(path: str):
    """將 LLM 提供的相對路徑限制在 REPO_ROOT 內，防止路徑跳脫"""
    if not path:
        return None
    candidate = os.path.normpath(os.path.join(REPO_ROOT, path.lstrip("/")))
    if not (candidate == REPO_ROOT or candidate.startswith(REPO_ROOT + os.sep)):
        return None
    if not os.path.isfile(candidate):
        return None
    return candidate


def read_file_context(path: str, line: int, context_lines: int = 10) -> dict:
    full = _safe_path(path)
    if not full:
        return {"error": "路徑不合法或檔案不存在"}
    with open(full, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    start = max(0, (line or 1) - 1 - context_lines)
    end = min(len(lines), (line or 1) + context_lines)
    return {
        "path": path,
        "start_line": start + 1,
        "end_line": end,
        "content": "".join(lines[start:end])[:4000],
    }


def grep_repo(pattern: str, max_results: int = 30, timeout: int = 20) -> dict:
    if not pattern or len(pattern) > 200:
        return {"error": "pattern 不合法"}
    try:
        proc = subprocess.run(
            ["grep", "-rnF", "-I", "-m", "5", "-e", pattern, REPO_ROOT],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": "grep 逾時"}
    lines = proc.stdout.splitlines()[:max_results]
    rel_lines = [l.replace(REPO_ROOT + "/", "") for l in lines]
    return {"pattern": pattern, "matches": rel_lines}


TOOLS = [
    {
        "action": "read_file_context",
        "description": "讀取指定檔案中某行附近的程式碼內容",
        "params": {"path": "相對於掃描根目錄的檔案路徑", "line": "行號", "context_lines": "前後各取幾行（預設10）"},
        "applicable": lambda finding: True,
        "run": lambda finding, params: read_file_context(
            params.get("path", finding.get("file")),
            int(params.get("line", finding.get("line_start") or 1)),
            int(params.get("context_lines", 10)),
        ),
    },
    {
        "action": "grep_repo",
        "description": "在掃描根目錄下搜尋指定固定字串，找出是否有其他相關用法/設定",
        "params": {"pattern": "要搜尋的固定字串（非正規表達式）"},
        "applicable": lambda finding: True,
        "run": lambda finding, params: grep_repo(params.get("pattern", "")),
    },
]


def available_tools(finding: dict) -> list:
    """回傳目前情境下可用的工具清單，給 LLM 當作 available_tools 輸入"""
    return [
        {"action": t["action"], "description": t["description"], "params": t["params"]}
        for t in TOOLS
        if t["applicable"](finding)
    ]


def run_tool(action: str, finding: dict, params: dict):
    """執行指定工具，回傳結果 dict；若 action 不存在、不適用或參數不足則回傳 None"""
    params = params or {}
    for t in TOOLS:
        if t["action"] == action and t["applicable"](finding):
            try:
                return t["run"](finding, params)
            except Exception:
                return None
    return None
