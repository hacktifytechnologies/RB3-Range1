#!/usr/bin/env bash
# setup.sh — M3 · ext-soap-gateway · RNG-EXT-01
# Challenge: XXE → SSRF → IMDS credential extraction
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
python3 -c "from lxml import etree; import flask" 2>/dev/null || { echo "[FAIL] Run deps.sh first"; exit 1; }

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/rpal/tariff-gateway"
APP_USER="rpal-tariff"
LOG_DIR="/var/log/rpal/soap-gateway"
SVC="rpal-tariff-gateway"

log "=== M3 · ext-soap-gateway setup ==="
log "Challenge: XXE → SSRF → Instance Metadata Service credential extraction"

id "$APP_USER" &>/dev/null || useradd -r -s /bin/false -d "$APP_DIR" \
    -c "RPAL Pipeline Tariff Gateway" "$APP_USER"
mkdir -p "$APP_DIR/app"
cp -r "${SCRIPT_DIR}/app/"* "$APP_DIR/app/"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# ── IMDS routing — redirect 169.254.169.254:80 to local app ──────────────────
log "Configuring IMDS simulation routing..."
# Add the link-local address to loopback
ip addr add 169.254.169.254/32 dev lo 2>/dev/null || true
# Redirect IMDS traffic to our app's /imds/ handler
iptables -t nat -A OUTPUT -d 169.254.169.254 -p tcp --dport 80 \
    -j REDIRECT --to-port 8080 2>/dev/null || true
iptables -t nat -A PREROUTING -d 169.254.169.254 -p tcp --dport 80 \
    -j REDIRECT --to-port 8080 2>/dev/null || true

# Persist iptables rule
cat > /etc/rc.local << 'RCEOF'
#!/bin/bash
ip addr add 169.254.169.254/32 dev lo 2>/dev/null || true
iptables -t nat -A OUTPUT -d 169.254.169.254 -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true
iptables -t nat -A PREROUTING -d 169.254.169.254 -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true
exit 0
RCEOF
chmod +x /etc/rc.local

# ── systemd service ────────────────────────────────────────────────────────────
cat > "/etc/systemd/system/${SVC}.service" << SVCEOF
[Unit]
Description=RPAL Pipeline Tariff Calculation Gateway — PNGRB Interface
Documentation=https://intranet.rpal.in/docs/tariff-gateway
After=network.target
[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${APP_DIR}/app
ExecStart=/usr/bin/python3 ${APP_DIR}/app/app.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rpal-tariff-gateway
Environment=PORT=8080
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=false
PrivateTmp=true
[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable "$SVC"
systemctl start "$SVC"
sleep 2
systemctl is-active --quiet "$SVC" && log "SOAP gateway running on :8080" \
    || { journalctl -u "$SVC" -n 10; exit 1; }

echo "tariff-gw.rpal.in" > /etc/hostname
command -v ufw &>/dev/null && ufw allow 8080/tcp comment "RPAL SOAP Gateway" >/dev/null 2>&1 || true

MY_IP=$(hostname -I | awk '{print $1}')
info "SOAP Endpoint: http://${MY_IP}:8080/TariffGateway"
info "WSDL:          http://${MY_IP}:8080/TariffGateway/wsdl"
info "IMDS:          http://169.254.169.254/latest/meta-data/ (via iptables DNAT)"
info "Vulnerability: XXE with resolve_entities=True + no_network=False"
info "Credentials (from M2): rpal-tariff-svc / TariffGW@Soap!2024#RPAL"
