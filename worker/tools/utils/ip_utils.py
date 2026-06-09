# tools/utils/ip_utils.py
import re
import ipaddress

# 萬用字元自動轉換為 CIDR
def wildcard_to_cidr(ip_pattern):
    if re.fullmatch(r'(\d{1,3})\.(\d{1,3})[.\-](%|\*|x)', ip_pattern):
        parts = ip_pattern.split('.')
        return f"{parts[0]}.{parts[1]}.0.0/16"
    if re.fullmatch(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})[.\-](%|\*|x)', ip_pattern):
        parts = ip_pattern.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    if re.fullmatch(r'(\d{1,3})\.(\d{1,3})\.(%|\*|x)\.(%|\*|x)', ip_pattern):
        parts = ip_pattern.split('.')
        return f"{parts[0]}.{parts[1]}.0.0/16"
    return ip_pattern

# IP 檢查
def ip_in_range(ip, ip_pattern):
    try:
        if not isinstance(ip, str):
            print(f"ip_in_range error: ip is not a string: {ip}")
            return False
        if '/' in ip_pattern:
            network = ipaddress.ip_network(ip_pattern, strict=False)
            return ipaddress.ip_address(ip) in network
        else:
            return ip == ip_pattern
    except Exception as e:
        print(f"ip_in_range error: {e}")
        return False

# 檢查IP是否在名單
def is_ip_in_list(ip, ips, ranges):
    if not ip:
        return False
    if ip in ips:
        return True
    for pattern in ranges:
        if ip_in_range(ip, pattern):
            return True
    return False