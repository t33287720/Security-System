"""ReAct 迴圈可用的唯讀工具登錄表。

新增工具：在 TOOLS 新增一筆項目即可（action / description / params / applicable / run），
decide_next_action 的提示詞透過 available_tools() 動態取得最新清單，
不需要再修改 prompt.txt。
"""

from tools.nmap_tools import run_script_recheck
from tools.http_tools import probe as http_probe
from tools.searchsploit_tools import search_exploits


def _is_http_service(port_info: dict) -> bool:
    return "http" in (port_info.get("service") or "").lower()


TOOLS = [
    {
        "action": "nmap_script_recheck",
        "description": "對該 port 重新執行一次指定的 nmap NSE 腳本，取得更詳細的腳本輸出",
        "params": {"script": "nse腳本名稱，例如 ssl-cert / http-title / vulners"},
        "applicable": lambda port_info: True,
        "run": lambda target, port_info, params: {
            "script": params["script"],
            "output": run_script_recheck(target, port_info["port"], params["script"]),
        } if params.get("script") else None,
    },
    {
        "action": "http_probe",
        "description": "對該 port 發送一次 HTTP(S) 請求，取得回應狀態碼、標頭與內容片段",
        "params": {"path": "請求路徑，例如 /"},
        "applicable": _is_http_service,
        "run": lambda target, port_info, params: http_probe(
            target, port_info["port"], params.get("path", "/")
        ),
    },
    {
        "action": "searchsploit_search",
        "description": "用自訂關鍵字重新查詢離線 exploit-db 資料庫",
        "params": {"query": "查詢字串，例如更精確的軟體名稱與版本"},
        "applicable": lambda port_info: True,
        "run": lambda target, port_info, params: {
            "query": params["query"],
            "results": search_exploits(params["query"], ""),
        } if params.get("query") else None,
    },
]


def available_tools(port_info: dict) -> list:
    """回傳目前情境下可用的工具清單，給 LLM 當作 available_tools 輸入"""
    return [
        {"action": t["action"], "description": t["description"], "params": t["params"]}
        for t in TOOLS
        if t["applicable"](port_info)
    ]


def run_tool(action: str, target: str, port_info: dict, params: dict):
    """執行指定工具，回傳結果 dict；若 action 不存在、不適用或參數不足則回傳 None"""
    params = params or {}
    for t in TOOLS:
        if t["action"] == action and t["applicable"](port_info):
            try:
                return t["run"](target, port_info, params)
            except Exception:
                return None
    return None
