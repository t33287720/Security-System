# tools/db/ipset_tools.py
import paramiko
import subprocess
import re

# -------------------------
# SSH 抽象（保留你原本邏輯）
# -------------------------
class LocalSSH:
    class Dummy:
        def __init__(self, out):
            self.out = out
            self.channel = self

        def read(self):
            return self.out

        def decode(self):
            return self.out.decode() if isinstance(self.out, bytes) else str(self.out)

        def recv_exit_status(self):
            return 0

    def exec_command(self, cmd):
        # Container runs as root — strip sudo prefix so ipset works without sudo installed
        cmd = cmd.replace("sudo -n ", "").replace("sudo ", "")
        r = subprocess.run(cmd, shell=True, capture_output=True)
        return None, self.Dummy(r.stdout), self.Dummy(r.stderr)

    def close(self):
        pass


def get_ssh_client(host):
    if host['ip'] in ("127.0.0.1", "localhost"):
        return LocalSSH()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=host['ip'],
        port=host.get('port', 22),
        username=host['user'],
        key_filename=host['ssh_key']
    )
    return ssh


# -------------------------
# ipset 操作（安全版）
# -------------------------
def ensure_ipset(hosts, ipset_names):
    for host in hosts:
        ssh = get_ssh_client(host)

        for name in ipset_names:
            stdin, stdout, stderr = ssh.exec_command(f"sudo ipset list {name}")
            err = stderr.read().decode()

            if "does not exist" in err.lower():
                ssh.exec_command(f"sudo ipset create {name} hash:net")

        ssh.close()


def add_ip(ssh, ip, ipset_name):
    # -exist：避免重複 add error
    ssh.exec_command(f"sudo ipset add {ipset_name} {ip} -exist")


def delete_ip(ssh, ip, ipset_name):
    # ignore error
    ssh.exec_command(f"sudo ipset del {ipset_name} {ip} || true")

# 計算ipset和mariaDB差異
def calculate_ipset_diff(ssh, ipset_name, db_ips):
    stdin, stdout, stderr = ssh.exec_command(f"sudo -n ipset save {ipset_name}")
    output = stdout.read().decode()
    err = stderr.read().decode()

    # ✅ ipset 不存在
    if "does not exist" in err.lower():
        ssh.exec_command(f"sudo ipset create {ipset_name} hash:net family inet maxelem 1000000")
        return set(db_ips), set(), set()

    remote_ips = set()

    for line in output.splitlines():
        line = line.strip()

        if not line.startswith("add "):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        if parts[1] != ipset_name:
            continue

        ip = parts[2]

        if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', ip):
            remote_ips.add(ip)
            # 格式： "add blackfulllistv4 212.73.148.20"
            parts = line.split()
            if len(parts) >= 3 and parts[1] == ipset_name:
                ip = parts[2]
                # ✅ 驗證是不是有效 IP
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', ip):
                    remote_ips.add(ip)
                else:
                    print(f"[DEBUG] 忽略無效 IP: {ip}")


    db_ips_set = set(db_ips)
    to_add = db_ips_set - remote_ips
    to_del = remote_ips - db_ips_set


    return to_add, to_del, remote_ips

# 執行ipset
def apply_ipset_changes(ssh, host_ip, ipset_name, to_add, to_del):
    for ip in to_del:
        delete_ip(ssh, ip, ipset_name)
        print(f"[IPSET同步][移除] 主機={host_ip} │ 集合={ipset_name} │ IP={ip}")

    for ip in to_add:
        add_ip(ssh, ip, ipset_name)
        print(f"[IPSET同步][新增] 主機={host_ip} │ 集合={ipset_name} │ IP={ip}")

    if to_add or to_del:
        print(
            f"[IPSET同步][完成] 主機={host_ip} │ 集合={ipset_name} │ "
            f"新增={len(to_add)} │ 移除={len(to_del)}"
        )
    else:
        print(
            f"[IPSET同步][無變更] 主機={host_ip} │ 集合={ipset_name}"
        )

def safe_ips(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, set, tuple)):
        return list(v)
    return [str(v)]

# -------------------------
# 同步 DB → ipset（核心）
# -------------------------
def sync_ipset(hosts, ipset_mapping):
    MAX_CHANGE = 2000

    # =========================
    # 1️⃣ 正規化 input（修掉隱性 bug）
    # =========================
    normalized = {}

    for ipset_name, v in ipset_mapping.items():

        # ---- 防 None / str ----
        if v is None:
            v = []
        elif isinstance(v, str):
            v = [v]

        # ---- 非 list/set/tuple ----
        elif not isinstance(v, (list, set, tuple)):
            v = []

        # ---- 轉 string + 去空值 ----
        clean_ips = []
        for x in v:
            if not isinstance(x, str):
                continue
            x = x.strip()
            if not x:
                continue
            if "." not in x:
                continue
            clean_ips.append(x)

        # ---- 去重（保留穩定性）----
        normalized[ipset_name] = list(set(clean_ips))

    ipset_mapping = normalized

    # =========================
    # 2️⃣ sync 每一台 host
    # =========================
    for host in hosts:
        ssh = get_ssh_client(host)
        host_ip = host.get("ip", "unknown")

        for ipset_name, db_ips in ipset_mapping.items():

            to_add, to_del, remote_ips = calculate_ipset_diff(
                ssh,
                ipset_name,
                db_ips
            )

            # =========================
            # 3️⃣ safety guard（避免爆量）
            # =========================
            if len(to_add) + len(to_del) > MAX_CHANGE:
                print(f"[SYNC][SKIP] {ipset_name} change too large")
                continue

            # =========================
            # 4️⃣ apply
            # =========================
            apply_ipset_changes(
                ssh,
                host_ip,
                ipset_name,
                to_add,
                to_del
            )

        ssh.close()