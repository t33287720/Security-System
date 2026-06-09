# config/settings.py
import os
import json
from dotenv import load_dotenv, find_dotenv
from tools.system.system_tools import get_local_ip

# find_dotenv searches upward from THIS file's directory regardless of cwd
# api/config/settings.py → api/ → project root (.env)
_dotenv = find_dotenv(filename='.env', raise_error_if_not_found=False, usecwd=False)
if _dotenv:
    load_dotenv(_dotenv)

# ── Legacy host config fallback ───────────────────────────────
_LEGACY_CONFIG_PATH = '/var/www/config/security_config.json'

def _load_legacy_config():
    try:
        with open(_LEGACY_CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

_legacy = _load_legacy_config()

# ── Elasticsearch ─────────────────────────────────────────────
ES_HOST = os.getenv('ES_HOST', 'https://localhost:9200')
ES_USER = os.getenv('ES_USER', 'elastic')
ES_PASS = os.getenv('ES_PASS') or _legacy.get('es_pass', '')

# ── Ollama ────────────────────────────────────────────────────
OLLAMA_URL    = os.getenv('OLLAMA_URL',  'http://127.0.0.1:8083/api/generate')
EMBED_URL     = os.getenv('EMBED_URL',   'http://127.0.0.1:8006/embed')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '1'))

# ── ipset ─────────────────────────────────────────────────────
IPSET_FULL_NAME      = os.getenv('IPSET_FULL_NAME',      'blackfulllistv4')
IPSET_NAME           = os.getenv('IPSET_NAME',           'blacklistv4')
IPSET_WHITELIST_NAME = os.getenv('IPSET_WHITELIST_NAME', 'whitelistv4')

# ── Host IPs ──────────────────────────────────────────────────
manual_ips = [ip.strip() for ip in os.getenv('MANUAL_IPS', '').split(',') if ip.strip()]

# ── Hosts JSON (Docker: /app/config, Host: /var/www/config) ──
HOSTS_JSON_PATH = os.getenv(
    'HOSTS_JSON_PATH',
    '/var/www/config/security_hosts.json'   # host default
)

# ── Blacklists ────────────────────────────────────────────────
openblacklist_BASE_DIR   = os.getenv('BLACKLIST_DIR', 'data/blacklist')
RAW_DIR                  = os.path.join(openblacklist_BASE_DIR, 'raw')
PARSED_DIR               = os.path.join(openblacklist_BASE_DIR, 'parsed')
openblacklist_PARSED_DIR = os.path.join(openblacklist_BASE_DIR, 'parsed')

URLS = {
    'spamhaus_drop':  'https://www.spamhaus.org/drop/drop.txt',
    'spamhaus_edrop': 'https://www.spamhaus.org/drop/edrop.txt',
    'firehol_l1':     'https://iplists.firehol.org/files/firehol_level1.netset',
    'dshield':        'https://www.dshield.org/block.txt',
}

def load_hosts():
    with open(HOSTS_JSON_PATH, 'r') as f:
        hosts = json.load(f)
    return [h for h in hosts if h.get('enabled') is True]

def get_my_host_ips():
    auto_ip = get_local_ip()
    return [auto_ip] + manual_ips

def load_config():
    # Docker: MYSQL_HOST env var is set
    if os.getenv('MYSQL_HOST'):
        return {
            'db_host':     os.getenv('MYSQL_HOST', '127.0.0.1'),
            'db_user':     os.getenv('MYSQL_USER', 'root'),
            'db_password': os.getenv('MYSQL_PASS', ''),
            'db_name':     os.getenv('MYSQL_DB',   'CCT_Security'),
        }
    # Host: fall back to legacy JSON config
    return _legacy
