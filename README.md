# GAIsecurity — AI 驅動的網路安全監控系統

以 Zeek 擷取流量、ELK Stack 儲存分析、LLM（Ollama）判斷威脅等級，自動將惡意 IP 同步至 ipset/iptables 黑名單，並提供 PHP Web 儀表板供人工審核。

---

## 系統架構

```
網路流量
   │
   ▼
[Zeek]  ──── 擷取連線 log ────►  /var/log/zeek/
                                        │
                                        ▼
                                  [Filebeat]
                                        │
                                        ▼
                                  [Logstash]  ◄── pipeline 解析 IP
                                        │
                                        ▼
                               [Elasticsearch]
                                        │
                         ┌─────────────┘
                         ▼
               [Python Worker]  ◄── 輪詢新 log
                    │    │
                    │    └──► [Ollama LLM]  分析威脅
                    │
                    ├──► [MySQL]  儲存 IP 風險狀態
                    │
                    └──► [ipset/iptables]  封鎖惡意 IP

[PHP Web]  ◄── 查詢 MySQL ──► 儀表板、審核、白名單管理
```

---

## 包含的服務

| 服務 | 說明 | 運行方式 |
|------|------|----------|
| Elasticsearch 8.13 | 儲存所有網路 log | Docker |
| Kibana 8.13 | ELK 視覺化介面 | Docker |
| Logstash 8.13 | Log 解析與轉送 | Docker |
| Filebeat 8.13 | 讀取 Zeek log 並轉送 | Docker |
| MySQL 8.0 | IP 風險狀態資料庫 | Docker |
| Python Worker | 輪詢 ES、呼叫 LLM、同步 ipset | Docker |
| PHP Web | 管理儀表板 | Docker |
| Zeek | 網路封包擷取 | Host systemd |

> Zeek 需要直接存取實體網卡，因此安裝在 Host 而非 Docker 內。

---

## 快速部屬

### 前置需求

- Ubuntu 22.04 / 24.04（root 或 sudo 權限）
- 對外可連網（下載 Docker image 與 Zeek）
- 已有 Ollama 服務（本機或遠端 GPU 主機）

### 步驟

```bash
# 1. Clone 專案
git clone https://github.com/你的帳號/GAIsecurity.git
cd GAIsecurity

# 2. 第一次執行 — 自動產生 .env 設定檔後停止
sudo bash deploy.sh

# 3. 填入設定（見下方說明）
nano .env

# 4. 第二次執行 — 完整安裝並啟動所有服務
sudo bash deploy.sh
```

完成後：
- Web 儀表板：`http://主機IP`
- Kibana：`http://主機IP:5601`

> 重複執行 `deploy.sh` 是安全的，已安裝的元件會自動跳過。

---

## .env 設定說明

```bash
# Elasticsearch 密碼（自訂，首次啟動時會自動套用）
ES_PASS=changeme

# MySQL root 密碼（自訂）
MYSQL_ROOT_PASSWORD=changeme

# Ollama LLM 推論位址
# 本機：http://127.0.0.1:11434/api/generate
# 遠端 GPU：http://192.168.x.x:8083/api/generate
OLLAMA_URL=http://127.0.0.1:8083/api/generate

# 要監控的網卡名稱（執行 ip link 查詢）
ZEEK_IFACE=eth0

# ipset 黑名單集合名稱（通常不需修改）
IPSET_NAME=blacklistv4
IPSET_FULL_NAME=blackfulllistv4

# 本機 IP，不會被加入黑名單（逗號分隔）
MANUAL_IPS=192.168.1.1

# 對外開放的 Port（有衝突才需修改）
WEB_PORT=80
KIBANA_PORT=5601
```

---

## 受控主機設定（security_hosts.json）

`config/security_hosts.json` 定義哪些主機的 ipset 要由本系統同步管理。  
此檔案**不進 git**（含有 SSH key 路徑等敏感資訊）。  
`deploy.sh` 執行時若不存在，會從 `config/security_hosts.json.example` 自動複製，預設為本機。

```json
[
  {
    "name": "local",
    "ip": "127.0.0.1",
    "enabled": true
  },
  {
    "name": "remote-server",
    "ip": "192.168.1.100",
    "port": 22,
    "user": "admin",
    "ssh_key": "/root/.ssh/id_rsa",
    "enabled": false
  }
]
```

> 本機（`127.0.0.1`）不需要 SSH key，Worker 會直接執行 ipset 指令。  
> 遠端主機需在對方設定 `sudo ipset` 免密碼權限（sudoers）。

---

## 資料庫 Schema

`config/mysql/init.sql` 只在 MySQL **首次啟動**（Volume 為空）時執行。  
在現有機器匯出最新 schema：

```bash
mysqldump --no-data -u root -p CCT_Security > config/mysql/init.sql
git add config/mysql/init.sql && git commit -m "update schema"
```

---

## 常用指令

```bash
# 查看所有服務狀態
docker compose ps

# 查看 Python Worker 即時 log
docker compose logs -f security-worker

# 重啟單一服務
docker compose restart security-worker

# 停止所有服務（保留資料 Volume）
docker compose down

# 停止並刪除所有資料（完全重置）
docker compose down -v

# 查看 Zeek 狀態
systemctl status zeek
journalctl -u zeek -f

# 更新程式碼後重新部屬
git pull && sudo bash deploy.sh
```

---

## 不進 git 的檔案

| 檔案 | 說明 | 初始來源 |
|------|------|----------|
| `.env` | 密碼與環境設定 | 從 `.env.example` 複製後填入 |
| `config/security_hosts.json` | 受控主機清單（含 SSH key 路徑） | 從 `.example` 複製後填入 |
| `api/data/` | 公開黑名單快取（自動下載） | 程式執行時自動產生 |

---

## 在 WSL 上測試

WSL kernel 不支援 `ipset` 與 raw packet capture，不需執行 `deploy.sh`，直接用 Docker Compose 測試應用層：

```bash
cp .env.example .env
nano .env   # 至少填 ES_PASS 與 MYSQL_ROOT_PASSWORD

docker compose up -d elasticsearch kibana logstash mysql web security-worker
```

Zeek / ipset 相關功能不會運作，其餘 Web 介面、ELK 查詢、LLM 分析正常可用。
