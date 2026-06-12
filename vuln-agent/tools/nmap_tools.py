import os
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET


def _parse_nmap_xml(xml_text: str, target: str) -> dict:
    result = {"target": target, "ports": []}
    if not xml_text.strip():
        return result

    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        return result

    for port_el in host.findall("./ports/port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue

        service_el = port_el.find("service")
        port_info = {
            "port": int(port_el.get("portid")),
            "protocol": port_el.get("protocol"),
            "service": service_el.get("name") if service_el is not None else None,
            "product": service_el.get("product") if service_el is not None else None,
            "version": service_el.get("version") if service_el is not None else None,
            "scripts": [],
        }

        for script_el in port_el.findall("script"):
            port_info["scripts"].append({
                "id": script_el.get("id"),
                "output": script_el.get("output", ""),
            })

        result["ports"].append(port_info)

    return result


# nmap 在非 tty 環境下會整批緩衝輸出，stdbuf -oL -eL 強制改為逐行緩衝
_STDBUF = ["stdbuf", "-oL", "-eL"]


def _run_nmap(cmd: list, timeout: int) -> str:
    """執行 nmap（cmd 不含 -oX），回傳 XML 結果。

    若用 -oX - 讓 XML 直接輸出到 stdout，nmap 會停止輸出 -v/--stats-every 的進度訊息，
    畫面看起來像卡住；改成把 XML 寫到暫存檔，讓 stdout 專門用來即時輸出掃描進度
    （已開啟的 port、目前階段、預估剩餘時間），即時轉印到容器日誌。
    """
    fd, xml_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)

    try:
        proc = subprocess.Popen(
            cmd + ["-oX", xml_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )

        def stream_output():
            for line in proc.stdout:
                line = line.strip()
                if line:
                    print(f"[vuln-agent][nmap] {line}", flush=True)

        t = threading.Thread(target=stream_output, daemon=True)
        t.start()

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        t.join(timeout=5)

        with open(xml_path, encoding="utf-8") as f:
            return f.read()
    finally:
        os.remove(xml_path)


def run_recon(target: str, timeout: int = 1800) -> dict:
    """對 target 執行版本偵測 + NSE 弱點腳本掃描（唯讀，TCP connect scan）"""
    cmd = _STDBUF + ["nmap", "-sT", "-sV", "-sC", "--script", "vuln", "-v", "--stats-every", "30s", target]
    return _parse_nmap_xml(_run_nmap(cmd, timeout), target)


def run_script_recheck(target: str, port: int, script: str, timeout: int = 300) -> str:
    """針對單一 port 重新執行指定 NSE 腳本，回傳該腳本的輸出文字"""
    cmd = _STDBUF + ["nmap", "-sT", "-p", str(port), "--script", script, "-v", target]
    parsed = _parse_nmap_xml(_run_nmap(cmd, timeout), target)
    for port_info in parsed["ports"]:
        if port_info["port"] == port:
            for s in port_info["scripts"]:
                if s["id"] == script:
                    return s["output"]
    return ""
