FROM python:3.10-slim

# nmap：弱點掃描；git：抓取 exploitdb（Debian 套件已移除 exploitdb，改用官方倉庫安裝 searchsploit）
RUN apt-get update && apt-get install -y \
    gcc \
    libmariadb-dev \
    nmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# 安裝 searchsploit 與離線 CVE/exploit 資料庫（官方倉庫，非 Kali 系統的標準安裝方式）
# 加上 User-Agent 是因為 gitlab.com 預設 git UA 會被 Cloudflare 擋下 403
RUN git -c http.extraHeader="User-Agent: git/2.40.0" clone --depth 1 \
    https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && cp -n /opt/exploitdb/.searchsploit_rc /root/

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "vuln_agent.py"]
