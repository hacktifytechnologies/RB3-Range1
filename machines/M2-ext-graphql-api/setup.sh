#!/usr/bin/env bash
# setup.sh — M2 · ext-graphql-api · RNG-EXT-01 · SETU DVAAR
# Challenge: GraphQL Field Suggestion Enumeration + batchQuery AuthZ Bypass
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
python3 -c "import strawberry, flask" 2>/dev/null || { echo "[FAIL] Run deps.sh first"; exit 1; }

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/rpal/graphql-api"
APP_USER="rpal-graphql"
DB_DIR="/var/lib/rpal/graphql-api"
LOG_DIR="/var/log/rpal/graphql-api"
SVC="rpal-exploration-api"

log "=== M2 · ext-graphql-api setup ==="
log "Challenge: GraphQL schema enumeration via suggestions + batchQuery AuthZ bypass"

id "$APP_USER" &>/dev/null || useradd -r -s /bin/false -d "$APP_DIR" \
    -c "RPAL GraphQL Exploration API" "$APP_USER"
mkdir -p "$APP_DIR/app/templates" "$DB_DIR" "$LOG_DIR"

# ── Seed database ──────────────────────────────────────────────────────────────
log "Seeding exploration database..."
python3 << 'PYEOF'
import sqlite3, os, hashlib

DB = '/var/lib/rpal/graphql-api/explore.db'
conn = sqlite3.connect(DB)
c = conn.cursor()
c.executescript("""
CREATE TABLE IF NOT EXISTS well_logs (
    well_id TEXT PRIMARY KEY, block_name TEXT, well_type TEXT,
    depth_tvdss REAL, formation TEXT, operator TEXT, spud_date TEXT, status TEXT
);
CREATE TABLE IF NOT EXISTS exploration_blocks (
    block_id TEXT PRIMARY KEY, block_name TEXT, basin TEXT, block_type TEXT,
    area_sqkm REAL, operator TEXT, round_name TEXT, award_date TEXT, status TEXT
);
CREATE TABLE IF NOT EXISTS employees (
    employee_id TEXT PRIMARY KEY, full_name TEXT, designation TEXT,
    department TEXT, email TEXT, phone TEXT, location TEXT
);
CREATE TABLE IF NOT EXISTS system_accounts (
    account_id TEXT PRIMARY KEY, username TEXT, service_name TEXT, endpoint TEXT,
    api_key TEXT, password_hash TEXT, plaintext_password TEXT, owner TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS internal_services (
    service_id TEXT PRIMARY KEY, service_name TEXT, endpoint TEXT,
    auth_type TEXT, credentials TEXT, description TEXT
);
""")

# Well logs
wells = [
    ('WL-KG-2024-001','KG-DWN-98/3','Exploration',4820.5,'Ratnagiri Formation','RPAL','2024-03-15','Suspended'),
    ('WL-KG-2024-002','KG-DWN-98/3','Appraisal',5100.0,'Godavari Formation','Gulf Drilling','2024-06-01','Drilling'),
    ('WL-MB-2024-001','MB-OSN-2005/2','Exploration',2340.0,'Bassein Formation','RPAL','2024-01-20','Completed'),
    ('WL-RJ-2023-001','RJ-ONN-2022/3','Exploration',1890.0,'Barmer Formation','Vedanta','2023-11-10','Completed'),
    ('WL-AS-2024-001','AA-ONN-2018/1','Development',1240.0','Tipam Formation','RPAL','2024-09-05','Drilling'),
]
for w in wells:
    c.execute("INSERT OR IGNORE INTO well_logs VALUES (?,?,?,?,?,?,?,?)", w)

# Exploration blocks
blocks = [
    ('BLK-001','KG-DWN-98/3','Krishna-Godavari Basin','Offshore Deepwater',4820.5,'RPAL','NELP-IX','2012-03-22','Active'),
    ('BLK-002','MB-OSN-2005/2','Mumbai Offshore Basin','Offshore Shallow',1240.0,'RPAL/ONGC JV','NELP-VII','2009-07-14','Active'),
    ('BLK-003','RJ-ONN-2022/3','Rajasthan Basin','Onshore',3100.0,'RPAL','OALP-III','2022-09-30','Active'),
    ('BLK-004','CB-ONN-2010/7','Cambay Basin','Onshore',890.0,'RPAL','NELP-VIII','2011-01-18','Active'),
    ('BLK-005','AA-ONN-2018/1','Assam-Arakan Basin','Onshore',560.0,'RPAL','OALP-I','2018-05-03','Active'),
]
for b in blocks:
    c.execute("INSERT OR IGNORE INTO exploration_blocks VALUES (?,?,?,?,?,?,?,?,?)", b)

# Employees
employees = [
    ('EMP-001','Vikram Nair','IT Infrastructure Head','Information Technology','vikram.nair@rpal.in','9820123456','Mumbai HQ'),
    ('EMP-002','Dr. Sunita Pillai','Chief Information Security Officer','Cybersecurity','sunita.pillai@rpal.in','9820234567','Mumbai HQ'),
    ('EMP-003','Arjun Mehta','DevOps Lead','IT Infrastructure','arjun.mehta@rpal.in','9820345678','Mumbai HQ'),
    ('EMP-004','Kavita Rao','OT Systems Manager','Operations Technology','kavita.rao@rpal.in','9820456789','Rajahmundry'),
    ('EMP-005','Rajan Iyer','Senior Network Engineer','IT Infrastructure','rajan.iyer@rpal.in','9820567890','Mumbai HQ'),
    ('EMP-006','Pradeep Sharma','Exploration Geologist','Upstream E&P','pradeep.sharma@rpal.in','9820678901','Rajahmundry'),
    ('EMP-007','Meena Krishnan','Permit Officer','Regulatory Affairs','meena.krishnan@rpal.in','9820789012','New Delhi'),
]
for e in employees:
    c.execute("INSERT OR IGNORE INTO employees VALUES (?,?,?,?,?,?,?)", e)

# System accounts — SENSITIVE — these are pivot credentials
# The SOAP gateway credentials are what participants extract here → M3 pivot
system_accounts = [
    ('SVC-001','rpal-explore-svc','Exploration Data API',
     'http://203.x.x.x:4000/graphql',
     'RPAL-API-2024-XK9mP3nT8qRs',
     hashlib.sha256('T@riff@Expl0re!24:rpal-explore-svc'.encode()).hexdigest(),
     None,
     'arjun.mehta@rpal.in',
     'GraphQL service account — API key auth'),

    ('SVC-002','rpal-tariff-svc','Pipeline Tariff SOAP Gateway',
     'http://203.x.x.x:8080/TariffGateway',
     None,
     None,
     'TariffGW@Soap!2024#RPAL',   # plaintext — "legacy system, no hashing"
     'rajan.iyer@rpal.in',
     'SOAP gateway service account — PNGRB tariff calculation'),

    ('SVC-003','rpal-contractor-svc','Contractor Onboarding API',
     'http://203.x.x.x:9000/api',
     'RPAL-CTR-2024-mN7pQ2xK',
     None,
     None,
     'arjun.mehta@rpal.in',
     'Contractor portal service account'),

    ('SVC-004','svc-api-gateway','API Gateway LDAP Integration',
     'ldap://203.x.x.x:389',
     None,
     None,
     'Ldap@GW!Bind2024#RPAL',
     'vikram.nair@rpal.in',
     'LDAP bind account for API gateway auth — pending Vault migration (DEVOPS-1142)'),
]
for sa in system_accounts:
    c.execute("INSERT OR IGNORE INTO system_accounts VALUES (?,?,?,?,?,?,?,?,?)", sa)

# Internal services
services = [
    ('INT-001','RPAL SOAP Tariff Gateway','http://203.x.x.x:8080/TariffGateway/wsdl',
     'HTTP Basic / WS-Security','user=rpal-tariff-svc pass=TariffGW@Soap!2024#RPAL',
     'Pipeline tariff calculation for PNGRB-regulated third-party access'),
    ('INT-002','RPAL HAProxy API Gateway','http://203.x.x.x:80',
     'Bearer Token (internal rotation)','token=rpal-sess-{rotating_token}-permit-svc',
     'External API gateway — routes to backend permit and data services'),
    ('INT-003','RPAL Contractor Portal','http://203.x.x.x:9000',
     'API Key','X-API-Key: RPAL-CTR-2024-mN7pQ2xK',
     'Contractor onboarding and HSE document submission portal'),
]
for svc in services:
    c.execute("INSERT OR IGNORE INTO internal_services VALUES (?,?,?,?,?,?)", svc)

conn.commit()
conn.close()
print("GraphQL explore.db seeded OK")
PYEOF

chown "$APP_USER:$APP_USER" "$DB_DIR/explore.db" 2>/dev/null || true

# ── Install files and service ──────────────────────────────────────────────────
cp -r "${SCRIPT_DIR}/app/"* "$APP_DIR/app/"
chown -R "$APP_USER:$APP_USER" "$APP_DIR" "$LOG_DIR"

cat > "/etc/systemd/system/${SVC}.service" << SVCEOF
[Unit]
Description=RPAL Exploration Data GraphQL API Service
After=network.target
[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${APP_DIR}/app
ExecStart=/usr/bin/python3 ${APP_DIR}/app/app.py
Restart=always
RestartSec=5
StandardOutput=append:${LOG_DIR}/api.log
StandardError=append:${LOG_DIR}/error.log
SyslogIdentifier=rpal-exploration-api
Environment=DB_PATH=${DB_DIR}/explore.db
Environment=PORT=4000
Environment=RPAL_API_KEY=RPAL-API-2024-XK9mP3nT8qRs
Environment=RPAL_SVC_PASS=T@riff@Expl0re!24
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable "$SVC"
systemctl start "$SVC"
sleep 2
systemctl is-active --quiet "$SVC" && log "GraphQL API running on :4000" \
    || { echo "[FAIL] Service failed"; journalctl -u "$SVC" -n 10; exit 1; }

echo "explore.rpal.in" > /etc/hostname
command -v ufw &>/dev/null && ufw allow 4000/tcp comment "RPAL GraphQL API" >/dev/null 2>&1 || true

MY_IP=$(hostname -I | awk '{print $1}')
info "GraphQL endpoint: http://${MY_IP}:4000/graphql"
info "API Key (from M1): RPAL-API-2024-XK9mP3nT8qRs"
info "Vulnerability: batchQuery resolver — no auth, accessible via field suggestions"
