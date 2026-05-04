#!/usr/bin/env bash
# setup.sh — M1 ext-permit-portal RNG-EXT-01 SETU DVAAR
# Ubuntu 22.04 LTS — run as root after deps.sh
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
python3 -c "from flask import Flask; from cryptography.hazmat.primitives import serialization" 2>/dev/null \
    || { echo "[FAIL] Run deps.sh first"; exit 1; }

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_USER="rpal-permit"
APP_DIR="/opt/rpal/permit-portal"
DB_DIR="/var/lib/rpal/permit-portal"
KEY_DIR="/etc/rpal/jwt"
LOG_DIR="/var/log/rpal/permit-portal"
SVC="rpal-permit-portal"

log "=== M1 ext-permit-portal setup ==="
log "Challenge: JWT Algorithm Confusion RS256 -> HS256"

# ── 1. Create service user ─────────────────────────────────────────────────────
log "Creating service user ${APP_USER}..."
id "$APP_USER" &>/dev/null || useradd -r -s /bin/false -d "$APP_DIR" \
    -c "RPAL Permit Portal Service" "$APP_USER"

# ── 2. Create ALL directories and immediately set ownership ────────────────────
log "Creating directories with correct ownership..."
mkdir -p "$APP_DIR" "$DB_DIR" "$KEY_DIR" "$LOG_DIR"

# These directories must be writable by the service user
chown "${APP_USER}:${APP_USER}" "$DB_DIR" "$LOG_DIR"
chmod 750 "$DB_DIR" "$LOG_DIR"

# App dir owned by service user
chown "${APP_USER}:${APP_USER}" "$APP_DIR"
chmod 750 "$APP_DIR"

# Key dir: root owns it, service user is the group (read access only)
chown "root:${APP_USER}" "$KEY_DIR"
chmod 750 "$KEY_DIR"

# ── 3. Generate RSA keypair ────────────────────────────────────────────────────
log "Generating RSA-2048 keypair..."
python3 << 'PYEOF'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os, stat

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

priv = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption())

pub = key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo)

with open('/etc/rpal/jwt/private.pem', 'wb') as f:
    f.write(priv)
with open('/etc/rpal/jwt/public.pem', 'wb') as f:
    f.write(pub)

print("RSA keypair generated")
PYEOF

# Key file permissions — service user must READ private key
chown "root:${APP_USER}" "$KEY_DIR/private.pem" "$KEY_DIR/public.pem"
chmod 640 "$KEY_DIR/private.pem"
chmod 644 "$KEY_DIR/public.pem"

log "Key permissions:"
ls -la "$KEY_DIR/"

# ── 4. Initialise SQLite database ──────────────────────────────────────────────
log "Initialising database..."
python3 << 'PYEOF'
import sqlite3, hashlib, os

DB = '/var/lib/rpal/permit-portal/permits.db'
conn = sqlite3.connect(DB)
c = conn.cursor()

c.executescript("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'applicant',
    full_name TEXT, organisation TEXT, email TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS permits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_number TEXT UNIQUE,
    block_name TEXT, block_type TEXT,
    applicant_username TEXT,
    status TEXT DEFAULT 'pending',
    submitted_at TEXT DEFAULT (datetime('now')),
    area_sqkm REAL, basin TEXT, operator TEXT
);
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY, value TEXT, description TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    username TEXT, action TEXT, ip_address TEXT, details TEXT
);
""")

def hp(p): return hashlib.sha256(p.encode()).hexdigest()

users = [
    ('admin',          hp('RPAL@Admin!Permit24'),  'admin',         'System Administrator',   'RPAL IT',             'admin@rpal.in'),
    ('permit.officer', hp('DGH@Officer!2024'),     'permit-officer','Rajesh Kumar Sharma',    'RPAL Licensing',      'rk.sharma@rpal.in'),
    ('vikram.nair',    hp('VikramNair@RPAL!24'),   'staff',         'Vikram Nair',            'RPAL IT Infra',       'vikram.nair@rpal.in'),
    ('contractor.01',  hp('Contractor@2024!'),     'applicant',     'Gulf Drilling Solutions', 'Gulf Drilling',      'procurement@gulfdrilling.ae'),
    ('contractor.02',  hp('Gulf@Drilling#24!'),    'applicant',     'Mahindra Energy Pvt Ltd', 'Mahindra Energy',   'env@mahindra-energy.in'),
]
for u in users:
    c.execute("INSERT OR IGNORE INTO users(username,password_hash,role,full_name,organisation,email) VALUES(?,?,?,?,?,?)", u)

permits = [
    ('PML-KG-2024-001','KG-DWN-98/3',    'Offshore Deepwater','contractor.01','approved','2024-09-01',4820.5,'Krishna-Godavari Basin','Gulf Drilling Solutions'),
    ('PML-MH-2024-002','MB-OSN-2005/2',  'Offshore Shallow',  'contractor.02','under-review','2024-10-14',1240.0,'Mumbai Offshore Basin','Mahindra Energy Pvt Ltd'),
    ('PML-CB-2024-003','CB-ONN-2010/7',  'Onshore',           'contractor.01','pending','2024-11-01',890.0,'Cambay Basin','Gulf Drilling Solutions'),
    ('PML-RJ-2024-004','RJ-ONN-2022/3',  'Onshore',           'contractor.02','pending','2024-11-15',3100.0,'Rajasthan Basin','Mahindra Energy Pvt Ltd'),
]
for p in permits:
    c.execute("INSERT OR IGNORE INTO permits(permit_number,block_name,block_type,applicant_username,status,submitted_at,area_sqkm,basin,operator) VALUES(?,?,?,?,?,?,?,?,?)", p)

config = [
    ('graphql_api_endpoint', 'http://203.x.x.x:4000/graphql',       'RPAL Exploration Data GraphQL API'),
    ('graphql_service_user', 'rpal-explore-svc',                     'Service account for Exploration Data API'),
    ('graphql_service_pass', 'T@riff@Expl0re!24',                    'Service account password — DEVOPS-1142'),
    ('graphql_api_key',      'RPAL-API-2024-XK9mP3nT8qRs',          'Static API key — rotate quarterly'),
    ('upstream_soap_endpoint','http://203.x.x.x:8080/TariffGateway','Pipeline tariff SOAP gateway'),
    ('jwt_issuer',           'https://permit.rpal.in',               'JWT issuer for permit portal'),
    ('internal_api_gateway', 'http://203.x.x.x:8000',               'Internal API gateway'),
]
for k, v, d in config:
    c.execute("INSERT OR REPLACE INTO system_config(key,value,description) VALUES(?,?,?)", (k,v,d))

conn.commit()
conn.close()
print(f"Database initialised at {DB}")
PYEOF

chown "${APP_USER}:${APP_USER}" "$DB_DIR/permits.db"
chmod 640 "$DB_DIR/permits.db"

# ── 5. Install application files ───────────────────────────────────────────────
log "Installing application files..."
mkdir -p "$APP_DIR/app"
cp "${SCRIPT_DIR}/app/app.py" "$APP_DIR/app/app.py"
chown -R "${APP_USER}:${APP_USER}" "$APP_DIR"
chmod 755 "$APP_DIR/app/app.py"

# ── 6. Create systemd service ──────────────────────────────────────────────────
log "Creating systemd service..."
cat > "/etc/systemd/system/${SVC}.service" << SVCEOF
[Unit]
Description=RPAL Exploration Permit Management Portal
Documentation=https://intranet.rpal.in/docs/permit-portal
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}/app
ExecStart=/usr/bin/python3 ${APP_DIR}/app/app.py
Restart=always
RestartSec=5
StandardOutput=append:${LOG_DIR}/access.log
StandardError=append:${LOG_DIR}/error.log
SyslogIdentifier=rpal-permit

Environment=RPAL_ENV=production
Environment=DB_PATH=${DB_DIR}/permits.db
Environment=JWT_PRIVATE_KEY=${KEY_DIR}/private.pem
Environment=JWT_PUBLIC_KEY=${KEY_DIR}/public.pem
Environment=PORT=8443

NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVCEOF

# ── 7. Start service and verify ────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable "$SVC"
systemctl restart "$SVC"
sleep 4

if systemctl is-active --quiet "$SVC"; then
    log "Service is running"
else
    echo ""
    echo "=== Service failed. Full error log: ==="
    cat "$LOG_DIR/error.log" 2>/dev/null || journalctl -u "$SVC" -n 30 --no-pager
    echo ""
    echo "[FAIL] Service did not start. See errors above."
    exit 1
fi

# Quick smoke-test
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8443/" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    log "HTTP smoke-test passed (200)"
else
    log "WARNING: smoke-test returned $HTTP_CODE — check logs"
fi

# ── 8. Hostname and firewall ───────────────────────────────────────────────────
echo "permit.rpal.in" > /etc/hostname
hostname permit.rpal.in 2>/dev/null || true
command -v ufw &>/dev/null && ufw allow 8443/tcp comment "RPAL Permit Portal" >/dev/null 2>&1 || true

MY_IP=$(hostname -I | awk '{print $1}')
echo ""
log "=== M1 setup COMPLETE ==="
info "Portal:        http://${MY_IP}:8443/"
info "JWKS:          http://${MY_IP}:8443/.well-known/jwks.json"
info "Creds (find via DGH registry path traversal): contractor.01 / Contractor@2024!"
info "Vuln:          JWT alg confusion RS256->HS256"
info "Logs:          ${LOG_DIR}/"
