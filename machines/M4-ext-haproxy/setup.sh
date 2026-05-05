#!/usr/bin/env bash
# setup.sh — M4 · ext-survey-portal · RNG-EXT-01
# Challenge: EJS Server-Side Template Injection → RCE → M5 API key
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
command -v node >/dev/null || { echo "[FAIL] Run deps.sh first"; exit 1; }

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/rpal/survey-portal"
APP_USER="rpal-survey"
SVC="rpal-survey-portal"
FLAG_DIR="/etc/rpal/contractor"

log "=== M4 · ext-survey-portal setup ==="
log "Challenge: EJS Server-Side Template Injection → RCE"

# ── Service user ───────────────────────────────────────────────────────────────
id "$APP_USER" &>/dev/null || useradd -r -s /bin/false -d "$APP_DIR" \
    -c "RPAL Geological Survey Portal" "$APP_USER"

# ── Install app files ──────────────────────────────────────────────────────────
mkdir -p "$APP_DIR/app" "$FLAG_DIR"
cp -r "${SCRIPT_DIR}/app/"* "$APP_DIR/app/"

# Install npm dependencies
cd "$APP_DIR/app"
npm install --prefer-offline -q 2>/dev/null || npm install -q
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# ── Plant M5 API key (the SSTI flag) ──────────────────────────────────────────
# Directory must be executable by service user so it can read files inside
chown "root:${APP_USER}" "$FLAG_DIR"
chmod 750 "$FLAG_DIR"

cat > "$FLAG_DIR/api-key.txt" << 'KEYEOF'
# RPAL Contractor Registration System — API Access Key
# Generated: 2024-10-01 | Owner: arjun.mehta@rpal.in
# Purpose: Contractor portal admin access for RPAL internal users
# Endpoint: http://203.x.x.x:4000

RPAL-CONTRACTOR-API-2024-xK9mP3nT8qRs7vL2
KEYEOF
chown "root:${APP_USER}" "$FLAG_DIR/api-key.txt"
chmod 640 "$FLAG_DIR/api-key.txt"
log "API key planted at ${FLAG_DIR}/api-key.txt (readable by ${APP_USER})"

# ── systemd service ────────────────────────────────────────────────────────────
cat > "/etc/systemd/system/${SVC}.service" << SVCEOF
[Unit]
Description=RPAL Geological Survey Analytics Portal
After=network.target
[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${APP_DIR}/app
ExecStart=/usr/bin/node ${APP_DIR}/app/app.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SVC}
Environment=PORT=3000
[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable "$SVC"
systemctl restart "$SVC"
sleep 3

systemctl is-active --quiet "$SVC" && log "Survey portal running on :3000" \
    || { journalctl -u "$SVC" -n 20 --no-pager; echo "[FAIL]"; exit 1; }

echo "survey.rpal.in" > /etc/hostname
hostname survey.rpal.in 2>/dev/null || true
command -v ufw &>/dev/null && ufw allow 3000/tcp comment "RPAL Survey Portal" >/dev/null 2>&1 || true

MY_IP=$(hostname -I | awk '{print $1}')
log "=== M4 setup COMPLETE ==="
info "Portal:    http://${MY_IP}:3000/"
info "Auth:      IMDS AccessKeyId + Token from M3"
info "Vuln:      POST /api/reports/generate — template field → ejs.render(template)"
info "SSTI RCE:  <%= global.process.mainModule.require('child_process').execSync('cat /etc/rpal/contractor/api-key.txt').toString() %>"
info "Flag:      ${FLAG_DIR}/api-key.txt"
