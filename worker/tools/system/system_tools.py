# tools/system/system_tools.py
import socket
from datetime import datetime, timedelta

# 自動抓本機主要 IP
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    print("MY_HOST_IP:", ip)
    return ip

# 心跳存活確認
def heartbeat(last_heartbeat):
    now = datetime.utcnow()
    if now - last_heartbeat > timedelta(minutes=5):  # 每 5 分鐘印一次
        print(f"[{datetime.now()}] 程式運作正常")
        return now, True   # ⭐ 只回傳「要不要更新」
    
    return last_heartbeat, False