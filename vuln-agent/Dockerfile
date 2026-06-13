FROM python:3.10-slim

# nmap：弱點掃描；git：抓取 exploitdb（Debian 套件已移除 exploitdb，改用官方倉庫安裝 searchsploit）
# curl：下載 gitleaks 靜態 binary
RUN apt-get update && apt-get install -y \
    gcc \
    libmariadb-dev \
    nmap \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 安裝 searchsploit 與離線 CVE/exploit 資料庫（官方倉庫，非 Kali 系統的標準安裝方式）
# 加上 User-Agent 是因為 gitlab.com 預設 git UA 會被 Cloudflare 擋下 403
RUN git -c http.extraHeader="User-Agent: git/2.40.0" clone --depth 1 \
    https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && cp -n /opt/exploitdb/.searchsploit_rc /root/

# 安裝 gitleaks（原始碼掃描：secrets 偵測，靜態 binary）
ARG GITLEAKS_VERSION=8.18.4
RUN curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 預先下載 semgrep 規則集快取，避免執行期需要連網（原始碼掃描：SAST）
RUN mkdir -p /tmp/semgrep-warm && echo "" > /tmp/semgrep-warm/empty.py \
    && (semgrep scan --config p/python --config p/php --metrics=off /tmp/semgrep-warm || true) \
    && rm -rf /tmp/semgrep-warm

COPY . .

CMD ["python", "vuln_agent.py"]
