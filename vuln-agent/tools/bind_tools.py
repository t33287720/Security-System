import socket


def _decode_ipv4(hex_ip: str) -> str:
    return socket.inet_ntop(socket.AF_INET, bytes.fromhex(hex_ip)[::-1])


def _decode_ipv6(hex_ip: str) -> str:
    raw = bytes.fromhex(hex_ip)
    groups = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    ip = socket.inet_ntop(socket.AF_INET6, groups)
    if ip.startswith("::ffff:"):
        ip = ip[len("::ffff:"):]
    return ip


def _read_listen_ports(path: str, decode) -> dict:
    bindings = {}
    try:
        with open(path) as f:
            lines = f.readlines()[1:]
    except FileNotFoundError:
        return bindings

    for line in lines:
        fields = line.split()
        if len(fields) < 4 or fields[3] != "0A":  # 0A = TCP_LISTEN
            continue
        ip_hex, port_hex = fields[1].split(":")
        bindings.setdefault(int(port_hex, 16), set()).add(decode(ip_hex))

    return bindings


def get_listen_bindings() -> dict:
    """回傳 {port: {ip, ...}}：本機目前處於 LISTEN 狀態的 TCP socket 實際綁定位址。

    讀取 /proc/net/tcp、/proc/net/tcp6（vuln-agent 以 network_mode: host 執行，
    這裡看到的就是 host 自身的監聽狀態），用來與 nmap 掃描結果比對，
    判斷某個被 nmap 視為「open」的 port，實際上是對外開放還是僅限本機。
    """
    bindings = _read_listen_ports("/proc/net/tcp", _decode_ipv4)
    for port, ips in _read_listen_ports("/proc/net/tcp6", _decode_ipv6).items():
        bindings.setdefault(port, set()).update(ips)
    return bindings


_LOOPBACK = {"127.0.0.1", "::1"}
_ANY = {"0.0.0.0", "::"}

EXPOSURE_LABELS = {
    "all_interfaces": "對外開放（綁定 0.0.0.0/::，所有網卡含對外IP皆可連線）",
    "loopback_only": "僅限本機（綁定 127.0.0.1/::1，外部網路無法直接連線，僅本機程序可存取）",
    "specific_interface": "綁定特定網卡位址，僅該介面可連線",
    "unknown": "無法確認實際綁定位址",
}


def classify_exposure(port: int, bindings: dict) -> str:
    """比對 nmap 偵測到的 open port 與本機實際監聽位址，回傳暴露範圍分類

    回傳值對應 EXPOSURE_LABELS 的 key：
    all_interfaces / loopback_only / specific_interface / unknown
    """
    ips = bindings.get(port)
    if not ips:
        return "unknown"
    if ips & _ANY:
        return "all_interfaces"
    if ips <= _LOOPBACK:
        return "loopback_only"
    return "specific_interface"
