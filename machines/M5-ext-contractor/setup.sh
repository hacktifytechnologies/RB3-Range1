#!/usr/bin/env bash
# setup.sh — M5 · ext-contractor · RNG-EXT-01
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
python3 -c "import flask" 2>/dev/null || { echo "[FAIL] Run deps.sh first"; exit 1; }

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/rpal/contractor-portal"
APP_USER="rpal-contractor"
DB_DIR="/var/lib/rpal/contractor-portal"
LOG_DIR="/var/log/rpal/contractor-portal"
CFG_DIR="/etc/rpal/upstream"
SVC="rpal-contractor-portal"

log "=== M5 · ext-contractor setup ==="
id "$APP_USER" &>/dev/null || useradd -r -s /bin/false -d "$APP_DIR" \
    -c "RPAL Contractor Portal Service" "$APP_USER"
mkdir -p "$APP_DIR/app/templates" "$DB_DIR" "$LOG_DIR" "$CFG_DIR"

# Generate SSH pivot key
log "Generating svc-deploy pivot SSH key..."
ssh-keygen -t rsa -b 2048 -f "${CFG_DIR}/svc-deploy-rsa" -N "Deploy@SSH!RPAL24Corp" -q
chmod 600 "${CFG_DIR}/svc-deploy-rsa"
chmod 644 "${CFG_DIR}/svc-deploy-rsa.pub"

# Plant config.ini (SSRF target)
log "Creating /etc/rpal/upstream/config.ini (SSRF target)..."
PRIV_KEY=$(cat "${CFG_DIR}/svc-deploy-rsa")
cat > "${CFG_DIR}/config.ini" << CFGEOF
; RPAL Upstream Services Configuration
; Owner: arjun.mehta@rpal.in | Last updated: 2024-11-01
; DO NOT COMMIT — see DEVOPS-1298

[upstream_ldap]
server = 203.x.x.x
port = 389
base_dn = dc=corp,dc=rpal,dc=in
bind_dn = cn=svc-api-gateway,ou=service-accounts,dc=corp,dc=rpal,dc=in
bind_password = Ldap@GW!Bind2024#RPAL
use_ssl = false

[corporate_ssh]
jump_host = 203.x.x.x
jump_port = 22
jump_user = svc-deploy
key_passphrase = Deploy@SSH!RPAL24Corp

[ssh_private_key]
; RSA key for svc-deploy@203.x.x.x (RNG-EXT-02 entry) | Rotate: 2025-05-01
key = ${PRIV_KEY}

[graphql_api]
endpoint = http://203.x.x.x:4000/graphql
api_key = RPAL-API-2024-XK9mP3nT8qRs
service_pass = T@riff@Expl0re!24

[soap_gateway]
endpoint = http://203.x.x.x:8080/TariffGateway
service_user = rpal-tariff-svc
service_pass = TariffGW@Soap!2024#RPAL
CFGEOF
chmod 640 "${CFG_DIR}/config.ini"
chown root:"$APP_USER" "${CFG_DIR}/config.ini"

# Init DB
python3 -c "
import sqlite3
conn = sqlite3.connect('/var/lib/rpal/contractor-portal/onboarding.db')
conn.execute('''CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY, application_id TEXT UNIQUE,
    contractor_username TEXT, company_name TEXT, contact_name TEXT,
    contact_email TEXT, work_category TEXT, company_profile_url TEXT,
    pan_number TEXT, status TEXT, submitted_at TEXT)''')
conn.commit(); conn.close(); print('DB OK')
"

cp -r "${SCRIPT_DIR}/app/"* "$APP_DIR/app/"
chown -R "$APP_USER:$APP_USER" "$APP_DIR" "$LOG_DIR" "$DB_DIR"

cat > "/etc/systemd/system/${SVC}.service" << SVCEOF
[Unit]
Description=RPAL Contractor Onboarding and Qualification Portal
After=network.target
[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${APP_DIR}/app
ExecStart=/usr/bin/python3 ${APP_DIR}/app/app.py
Restart=always; RestartSec=5
StandardOutput=append:${LOG_DIR}/portal.log
StandardError=append:${LOG_DIR}/error.log
SyslogIdentifier=rpal-contractor-portal
Environment=DB_PATH=${DB_DIR}/onboarding.db
Environment=WKHTMLTOPDF=/usr/local/bin/wkhtmltopdf
Environment=PORT=9000
NoNewPrivileges=true
PrivateTmp=false
[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload; systemctl enable "$SVC"; systemctl start "$SVC"
sleep 2
systemctl is-active --quiet "$SVC" && log "Contractor portal running on :9000" \
    || { journalctl -u "$SVC" -n 10; exit 1; }

echo "contractor.rpal.in" > /etc/hostname
command -v ufw &>/dev/null && ufw allow 9000/tcp comment "RPAL Contractor Portal" >/dev/null 2>&1 || true

MY_IP=$(hostname -I | awk '{print $1}')
info "Portal: http://${MY_IP}:9000/"
info "SSRF target: file:///etc/rpal/upstream/config.ini"
info "Creds: contractor.01 / Contractor@2024!"
info "Pivot SSH public key: ${CFG_DIR}/svc-deploy-rsa.pub"
echo ""
log "=== IMPORTANT: Copy the following public key to Range 2 M1 authorized_keys ==="
cat "${CFG_DIR}/svc-deploy-rsa.pub"
