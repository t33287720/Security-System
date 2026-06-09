# Security System

以 Zeek 擷取流量、ELK Stack 儲存分析、LLM（Ollama）判斷威脅等級，自動將惡意 IP 同步至 ipset/iptables 黑名單，並提供 PHP Web 儀表板供人工審核。

---

## 系統架構

```
網路流量
   │
   ▼
[Zeek]  ──── 擷取連線 log ────►  /var/log/zeek/
  (host systemctl)                      │
                                        ▼
                                  [Filebeat]
                                  (host systemctl)
                                        │
                                        ▼
                                  [Logstash]
                                  (host systemctl)
                                        │
                                        ▼
                               [Elasticsearch]
                               (host systemctl)
                                        │
                         ┌─────────────┘
                         ▼
                  [worker]  ◄── 輪詢新 log
                 (Docker)
                    │    │
                    │    └──► [Ollama LLM]  分析威脅
                    │         (host / 遠端 GPU)
                    │
                    ├──► [MariaDB]  儲存 IP 風險狀態
                    │    (host systemctl)
                    │
                    └──► [ipset/iptables]  封鎖惡意 IP
                          (host kernel)

[web]  ◄── 查詢 MariaDB / ES ──► 儀表板、審核、白名單管理
(Docker)
```

---

## 服務一覽

| 服務 | 版本 | 運行方式 | 說明 |
|------|------|----------|------|
| Elasticsearch | **8.18.1** | Host systemctl | 儲存所有網路 log |
| Kibana | **8.18.1** | Host systemctl | ELK 視覺化介面 |
| Logstash | **8.18.1** | Host systemctl | Log 解析與轉送 |
| Filebeat | **8.18.1** | Host systemctl | 讀取 Zeek log 並轉送 |
| Zeek | **8.0.3** | Host systemctl | 網路封包擷取 |
| MariaDB | **10.6.x** | Host systemctl | IP 風險狀態資料庫（多產品共用） |
| Ollama | **0.18.0** | Host / 遠端 GPU | LLM 威脅分析（多產品共用） |
| ipset | **7.15** | Host kernel | 黑/白名單 IP 集合 |
| iptables | —— | Host kernel | 流量封鎖規則 |
| nginx | **1.18.0** | Host | 反向代理，將 `/GAIsecurity/` 導向 Web 容器 |
| worker | —— | Docker | Python API：輪詢 ES、呼叫 LLM、同步 ipset |
| web | —— | Docker | PHP 管理儀表板（nginx + php-fpm） |

> **設計原則**：ELK、MariaDB、Ollama 是跨產品的共用資源，保留在宿主機由 systemctl 管理。  
> Zeek 需直接存取實體網卡（raw socket），不適合容器化。  
> 兩個 Docker 容器（web、worker）只負責應用邏輯。

---

## 前置需求

### 宿主機必須先安裝

以下服務需在宿主機安裝並由 systemctl 管理，**容器不包含這些服務**。

#### ELK Stack 8.18.x（三個服務版本需一致）

```bash
# 加入 Elastic 官方 apt repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update

# 安裝
sudo apt-get install -y elasticsearch=8.18.1 kibana=8.18.1 logstash=1:8.18.1-1 filebeat=8.18.1

sudo systemctl enable --now elasticsearch kibana logstash filebeat
```

**重要：ES 需額外開放 Docker bridge 網路存取（見下方設定）**

#### Zeek 8.0.3

```bash
# Ubuntu 22.04
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg
sudo apt-get update && sudo apt-get install -y zeek=8.0.3-0

sudo systemctl enable --now zeek
```

#### MariaDB 10.6.x

```bash
sudo apt-get install -y mariadb-server
sudo systemctl enable --now mariadb

# 建立 Security System 專用帳號（僅授權 CCT_Security 資料庫）
sudo mariadb -e "CREATE USER IF NOT EXISTS 'Container'@'172.%.%.%' IDENTIFIED BY 'your_password';"
sudo mariadb -e "GRANT ALL PRIVILEGES ON CCT_Security.* TO 'Container'@'172.%.%.%';"
sudo mariadb -e "FLUSH PRIVILEGES;"
```

#### Ollama 0.18.0

```bash
curl -fsSL https://ollama.com/install.sh | sh
# 或指定版本：OLLAMA_VERSION=0.18.0 curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama

# 拉取所需模型（例：gemma3:12b）
ollama pull gemma3:12b
```

#### ipset / iptables

通常 Ubuntu 已預裝，確認安裝：

```bash
sudo apt-get install -y ipset iptables

# 建立必要的 ipset 集合（首次）
sudo ipset create blacklistv4 hash:net maxelem 1000000
sudo ipset create blackfulllistv4 hash:net maxelem 1000000
sudo ipset create whitelistv4 hash:net maxelem 1000000

# 讓 iptables 套用 ipset 黑名單（首次）
sudo iptables -I INPUT -m set --match-set blackfulllistv4 src -j DROP
sudo iptables -I INPUT -m set --match-set blacklistv4 src -j DROP
sudo iptables -I INPUT -m set --match-set whitelistv4 src -j ACCEPT
```

#### nginx（反向代理）

```bash
sudo apt-get install -y nginx
```

加入 Security System 的 location 區塊至宿主機 nginx 設定（`/etc/nginx/sites-available/default`）：

```nginx
location /GAIsecurity/ {
    proxy_pass         http://127.0.0.1:8082/;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Real-IP         $remote_addr;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_read_timeout 60s;
}
```

> `8082` 對應 `.env` 中的 `WEB_PORT`，如有衝突請一併修改。

#### Docker & Docker Compose

```bash
# 安裝 Docker Engine
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Docker Compose v2（通常隨 Docker Engine 一起安裝）
docker compose version
```

---

## Elasticsearch 開放 Docker 容器存取（必要設定）

Web 容器透過 `host.docker.internal`（解析為 `172.17.0.1`）連接宿主機 ES。  
ES 預設只綁定 `127.0.0.1`，需**額外加入** Docker bridge IP，兩個 IP 同時保留：

| 綁定位址 | 用途 |
|----------|------|
| `127.0.0.1` | 宿主機本身（worker、Logstash、Kibana 照常運作） |
| `172.17.0.1` | Docker bridge gateway，讓 web 容器連進來 |

> `172.17.0.1` 是宿主機在 Docker 內部網路（docker0）的 IP，外部網際網路無法存取此位址，**不會暴露 ES 給外人**。

```bash
# 查看目前 network.host 設定（確認是否為 127.0.0.1）
sudo grep -n "network.host" /etc/elasticsearch/elasticsearch.yml

# 若目前是 network.host: 127.0.0.1，執行以下指令（兩個 IP 同時保留，非替換）：
sudo sed -i 's/^network\.host:.*/network.host: ["127.0.0.1", "172.17.0.1"]/' /etc/elasticsearch/elasticsearch.yml

# 若 elasticsearch.yml 中完全沒有 network.host，則在最後追加：
sudo grep -q "^network.host:" /etc/elasticsearch/elasticsearch.yml \
  || echo -e '\nnetwork.host: ["127.0.0.1", "172.17.0.1"]' | sudo tee -a /etc/elasticsearch/elasticsearch.yml

# 確認結果（應看到兩個 IP）
sudo grep "network.host" /etc/elasticsearch/elasticsearch.yml

# 重啟 ES
sudo systemctl restart elasticsearch
sudo systemctl status elasticsearch
```

---

## 快速部屬

```bash
# 1. Clone 專案
git clone <repository-url>
cd Security-System

# 2. 複製設定範本
cp .env.example .env
cp config/security_hosts.json.example config/security_hosts.json

# 3. 填入設定
nano .env
nano config/security_hosts.json

# 4. 建立資料目錄
sudo mkdir -p /var/opt/Security-System/data
sudo chown $USER:$USER /var/opt/Security-System/data

# 5. 建置並啟動容器
docker compose build
docker compose up -d

# 6. 確認狀態
docker compose ps
docker compose logs -f worker
```

---

## .env 設定說明

```bash
# ── Elasticsearch ──────────────────────────────
# 宿主機 ES（host systemctl）
ES_PASS=changeme                              # elastic 帳號密碼
ES_HOST_WORKER=https://localhost:9200         # worker 用（host network mode，直連 localhost）
ES_HOST_WEB=https://host.docker.internal:9200 # web 用（透過 Docker bridge 連宿主機）

# ── MariaDB（宿主機，多產品共用）──────────────
MYSQL_USER=Container      # 專用 DB 帳號（見上方 MariaDB 設定）
MYSQL_PASS=changeme
# MYSQL_DB 固定為 CCT_Security（已寫入 docker-compose.yml）

# ── Ollama LLM ─────────────────────────────────
OLLAMA_URL=http://127.0.0.1:8083/api/generate  # 本機
# OLLAMA_URL=http://192.168.x.x:8083/api/generate  # 遠端 GPU

# ── ipset 集合名稱（通常不需修改）──────────────
IPSET_NAME=blacklistv4
IPSET_FULL_NAME=blackfulllistv4
IPSET_WHITELIST_NAME=whitelistv4

# ── 白名單 IP（不會被封鎖，逗號分隔）────────────
# 必填：自己的 SSH 來源 IP 及主機對外 IP，避免自我封鎖
MANUAL_IPS=140.124.32.16,211.72.136.45

# ── Web 容器對外 Port ───────────────────────────
WEB_PORT=8082  # 視宿主機 port 占用情況調整
```

---

## 受控主機設定（security_hosts.json）

`config/security_hosts.json` 定義哪些主機的 ipset 由本系統管理。  
此檔案**不進 git**（含 SSH key 路徑等敏感資訊）。

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

> 本機（`127.0.0.1`）worker 直接執行 ipset 指令，不需要 SSH key。  
> 遠端主機需在對方設定 `ipset` 免密碼 sudo 權限（visudo）。  
> **啟動 worker 前務必先設定 `MANUAL_IPS`**，避免封鎖自己的 SSH 來源 IP。

---

## 資料庫 Schema

更新 schema 後重新匯出：

```bash
mysqldump --no-data -u Container -p CCT_Security > config/mysql/init.sql
git add config/mysql/init.sql && git commit -m "update schema"
```

---

## 常用指令

```bash
# 查看容器狀態
docker compose ps

# 即時查看 worker log
docker compose logs -f worker

# 重建並重啟單一容器（程式碼有變更時）
docker compose build web && docker compose up -d web

# 停止所有容器（保留資料）
docker compose down

# 查看 ipset 黑名單數量
sudo ipset list blackfulllistv4 | grep "Number of entries"

# 查看宿主機 ELK 狀態
sudo systemctl status elasticsearch kibana logstash filebeat

# 查看 Zeek 狀態
sudo systemctl status zeek
journalctl -u zeek -f
```

---

## 不進 git 的檔案

| 檔案 | 說明 | 初始來源 |
|------|------|----------|
| `.env` | 密碼與環境設定 | 從 `.env.example` 複製後填入 |
| `config/security_hosts.json` | 受控主機清單（含 SSH key 路徑） | 從 `.example` 複製後填入 |
| `/var/opt/Security-System/data/` | 公開黑名單快取、eval 結果（自動產生） | worker 執行時自動建立 |
