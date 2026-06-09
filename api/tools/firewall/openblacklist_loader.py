# tools/firewall/openblacklist_loader.py
import os
import requests
import ipaddress


def ensure_dirs(RAW_DIR, PARSED_DIR):
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(PARSED_DIR, exist_ok=True)


# -------------------------
# 下載 blacklist
# -------------------------
def download_blacklists(RAW_DIR, PARSED_DIR, URLS):
    ensure_dirs(RAW_DIR, PARSED_DIR)

    for name, url in URLS.items():
        try:
            print(f"[DOWNLOAD] {name}")
            r = requests.get(url, timeout=10)
            r.raise_for_status()

            path = os.path.join(RAW_DIR, f"{name}.txt")
            with open(path, "w") as f:
                f.write(r.text)

        except Exception as e:
            print(f"[ERROR] download {name}: {e}")


# -------------------------
# 清洗 + 統一 CIDR
# -------------------------
def normalize_line(line):
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    # split by whitespace or tab
    parts = line.split()

    # -------------------------
    # CASE 1: normal CIDR/IP feed
    # -------------------------
    if len(parts) == 1 or "/" in parts[0]:
        try:
            if "/" not in parts[0]:
                ipaddress.ip_address(parts[0])
                return f"{parts[0]}/32"

            ipaddress.ip_network(parts[0], strict=False)
            return parts[0]

        except:
            return None

    # -------------------------
    # CASE 2: DShield range format
    # -------------------------
    try:
        start_ip = parts[0]
        end_ip = parts[1]

        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)

        # 如果 range 無效（你說的 "0" 問題）
        if start == end:
            return f"{start_ip}/32"

        # convert range → CIDR blocks
        networks = ipaddress.summarize_address_range(start, end)

        return [str(net) for net in networks]

    except:
        return None

# -------------------------
# 解析 blacklist
# -------------------------
def parse_blacklists(RAW_DIR, PARSED_DIR, URLS):
    ensure_dirs(RAW_DIR, PARSED_DIR)

    for name in URLS.keys():
        raw_path = os.path.join(RAW_DIR, f"{name}.txt")
        parsed_path = os.path.join(PARSED_DIR, f"{name}.txt")

        if not os.path.exists(raw_path):
            continue

        networks = set()

        with open(raw_path, "r") as f:
            for line in f:
                net = normalize_line(line)

                if not net:
                    continue

                if isinstance(net, list):
                    for n in net:
                        networks.add(n)
                else:
                    networks.add(net)

        with open(parsed_path, "w") as f:
            for net in sorted(networks):
                f.write(net + "\n")

        print(f"[PARSED] {name}: {len(networks)} entries")

# if __name__ == "__main__":
#     download_blacklists()
#     parse_blacklists()