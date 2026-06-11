import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTPS_PORTS = {443, 8443}


def probe(target: str, port: int, path: str = "/", timeout: int = 10) -> dict:
    """對指定 port 發送一次 HTTP(S) 請求，回傳狀態碼/標頭/內容片段（唯讀）"""
    schemes = ["https", "http"] if port in HTTPS_PORTS else ["http", "https"]

    for scheme in schemes:
        url = f"{scheme}://{target}:{port}{path}"
        try:
            resp = requests.get(url, timeout=timeout, verify=False)
            return {
                "url": url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:500],
            }
        except requests.RequestException:
            continue

    return {"url": f"http(s)://{target}:{port}{path}", "error": "連線失敗"}
