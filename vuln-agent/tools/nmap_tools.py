import subprocess
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


def run_recon(target: str, timeout: int = 1800) -> dict:
    """對 target 執行版本偵測 + NSE 弱點腳本掃描（唯讀，TCP connect scan）"""
    cmd = ["nmap", "-sT", "-sV", "-sC", "--script", "vuln", "-oX", "-", target]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return _parse_nmap_xml(proc.stdout, target)


def run_script_recheck(target: str, port: int, script: str, timeout: int = 300) -> str:
    """針對單一 port 重新執行指定 NSE 腳本，回傳該腳本的輸出文字"""
    cmd = ["nmap", "-sT", "-p", str(port), "--script", script, "-oX", "-", target]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    parsed = _parse_nmap_xml(proc.stdout, target)
    for port_info in parsed["ports"]:
        if port_info["port"] == port:
            for s in port_info["scripts"]:
                if s["id"] == script:
                    return s["output"]
    return ""
