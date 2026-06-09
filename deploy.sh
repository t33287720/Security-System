#!/bin/bash
# deploy.sh — one-shot setup for a fresh Ubuntu server
# Usage: git clone <repo> && cd GAIsecurity && sudo bash deploy.sh
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[deploy]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
abort() { echo -e "${RED}[error]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && abort "Please run as root: sudo bash deploy.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Step 1: .env ──────────────────────────────────────────────
if [[ ! -f .env ]]; then
    cp .env.example .env
    warn ".env created from template."
    warn "Edit it now, then re-run deploy.sh"
    echo ""
    echo "  nano .env"
    echo ""
    exit 0
fi

source .env

# ── Step 2: Docker ────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
fi

if ! docker compose version &>/dev/null; then
    info "Installing docker-compose-plugin..."
    apt-get install -y docker-compose-plugin
fi

# ── Step 3: Zeek ──────────────────────────────────────────────
ZEEK_BIN=$(command -v zeek 2>/dev/null \
    || command -v /usr/local/zeek/bin/zeek 2>/dev/null \
    || command -v /opt/zeek/bin/zeek 2>/dev/null \
    || true)

if [[ -z "$ZEEK_BIN" ]]; then
    info "Zeek not found — installing..."
    UBUNTU_VER=$(lsb_release -rs 2>/dev/null || echo "22.04")
    ZEEK_REPO="xUbuntu_${UBUNTU_VER}"
    echo "deb http://download.opensuse.org/repositories/security:/zeek/${ZEEK_REPO}/ /" \
        > /etc/apt/sources.list.d/zeek.list
    curl -fsSL "https://download.opensuse.org/repositories/security:zeek/${ZEEK_REPO}/Release.key" \
        | gpg --dearmor > /etc/apt/trusted.gpg.d/zeek.gpg
    apt-get update -qq
    apt-get install -y zeek
    ZEEK_BIN=$(command -v zeek 2>/dev/null || echo "/usr/local/zeek/bin/zeek")
    info "Zeek installed: $ZEEK_BIN"
else
    info "Zeek already installed: $ZEEK_BIN — skipping install"
fi

ZEEK_SITE=$(realpath "$(dirname "$ZEEK_BIN")/../share/zeek/site" 2>/dev/null \
    || echo "/usr/local/zeek/share/zeek/site")

if [[ -f config/zeek/local.zeek ]]; then
    cp config/zeek/local.zeek "$ZEEK_SITE/local.zeek"
    info "Zeek config deployed → $ZEEK_SITE/local.zeek"
fi

# ── Step 4: ipset / iptables ──────────────────────────────────
if ! command -v ipset &>/dev/null; then
    info "Installing ipset..."
    apt-get install -y ipset iptables
fi

WHITELIST_SET="${IPSET_WHITELIST_NAME:-whitelistv4}"
BLACKLIST_SET="${IPSET_NAME:-blacklistv4}"
BLACKFULL_SET="${IPSET_FULL_NAME:-blackfulllistv4}"

for SET in "$WHITELIST_SET" "$BLACKLIST_SET" "$BLACKFULL_SET"; do
    if ! ipset list "$SET" &>/dev/null; then
        ipset create "$SET" hash:net
        info "ipset created: $SET"
    fi
done

# 白名單 ACCEPT：-C 先檢查是否已存在，避免重複新增
if ! iptables -C INPUT -m set --match-set "$WHITELIST_SET" src -j ACCEPT 2>/dev/null; then
    iptables -A INPUT -m set --match-set "$WHITELIST_SET" src -j ACCEPT
    info "iptables whitelist rule added: ACCEPT $WHITELIST_SET"
fi

# ── Step 5: security_hosts.json ───────────────────────────────
if [[ ! -f config/security_hosts.json ]]; then
    cp config/security_hosts.json.example config/security_hosts.json
    warn "config/security_hosts.json created from example. Edit it if needed."
fi

# ── Step 6: Export current DB schema (if mysql is local) ─────
if command -v mysqldump &>/dev/null && [[ -n "${MYSQL_ROOT_PASSWORD:-}" ]]; then
    info "Backing up current schema to config/mysql/init.sql ..."
    mysqldump --no-data -u root -p"${MYSQL_ROOT_PASSWORD}" CCT_Security \
        > config/mysql/init.sql 2>/dev/null || warn "mysqldump skipped (DB may not exist yet)"
fi

# ── Step 7: Zeek systemd service ────────────────────────────
IFACE="${ZEEK_IFACE:-eth0}"
LOG_DIR="/var/log/zeek"
mkdir -p "$LOG_DIR"

SERVICE_FILE=/etc/systemd/system/zeek.service
NEW_EXEC="${ZEEK_BIN} -i ${IFACE} ${ZEEK_SITE}/local.zeek -C"

if systemctl is-active --quiet zeek; then
    # Already running — only restart if ExecStart changed
    CURRENT_EXEC=$(systemctl show zeek --property=ExecStart 2>/dev/null \
        | grep -oP '(?<=argv\[\]=).*' | head -1 || true)
    if [[ "$CURRENT_EXEC" == *"$IFACE"* ]]; then
        info "Zeek already running on ${IFACE} — skipping restart"
    else
        warn "Zeek running on a different interface — restarting..."
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Zeek Network Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${LOG_DIR}
ExecStart=${NEW_EXEC}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl restart zeek
        info "Zeek restarted on interface ${IFACE}"
    fi
else
    # Not running — create/update service and start
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Zeek Network Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${LOG_DIR}
ExecStart=${NEW_EXEC}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable zeek
    systemctl start zeek
    info "Zeek started on interface ${IFACE}, logs → ${LOG_DIR}"
fi

# ── Step 8: Docker Compose ────────────────────────────────────
info "Starting Docker Compose stack..."
RUNNING=$(docker compose ps --services --filter status=running 2>/dev/null | wc -l)
if [[ "$RUNNING" -gt 0 ]]; then
    info "Stack already running ($RUNNING services) — doing rolling update..."
    docker compose pull --quiet
    docker compose build --quiet
    docker compose up -d --remove-orphans
else
    info "Fresh start — pulling images and building..."
    docker compose pull --quiet
    docker compose build --quiet
    docker compose up -d
fi

info "Waiting for services to be healthy..."
sleep 15
docker compose ps

# ── Done ──────────────────────────────────────────────────────
HOST_IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}✓ Deployment complete!${NC}"
echo "  Web dashboard : http://${HOST_IP}:${WEB_PORT:-80}"
echo "  Kibana        : http://${HOST_IP}:${KIBANA_PORT:-5601}"
echo ""
echo "  Logs: docker compose logs -f security-worker"
