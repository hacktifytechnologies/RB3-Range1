#!/usr/bin/env bash
# =============================================================================
# setup.sh — M4 · ext-haproxy · RNG-EXT-01 · SETU DVAAR
# OPERATION DEEPSTRIKE | RPAL API Gateway
# Challenge: HTTP Request Smuggling (CL.TE) — Session Token Capture
# MITRE: T1557 (Adversary-in-the-Middle) · T1550 (Use Alternate Auth Material)
# Ubuntu 22.04 LTS — NO internet required after deps.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

[[ $EUID -ne 0 ]] && fail "Run as root"
command -v haproxy >/dev/null 2>&1 || fail "HAProxy not found — run deps.sh first"
command -v python3 >/dev/null 2>&1 || fail "Python3 not found — run deps.sh first"
python3 -c "import flask, requests" 2>/dev/null || fail "Python deps missing — run deps.sh first"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log "=== M4 · ext-haproxy setup ==="
log "Challenge: HTTP Request Smuggling (CL.TE) with session capture"
log "OPERATION DEEPSTRIKE | SETU DVAAR | RNG-EXT-01"

APP_DIR="/opt/rpal/api-gateway"
APP_USER="rpal-gateway"

# ── Users ──────────────────────────────────────────────────────────────────────
log "Creating service users..."
id "$APP_USER" &>/dev/null || useradd -r -s /bin/false -d "$APP_DIR" \
    -c "RPAL API Gateway Service" "$APP_USER"

mkdir -p "$APP_DIR/app" 
chown -R "$APP_USER:$APP_USER" "$APP_DIR" 

# ── Copy application files ─────────────────────────────────────────────────────
log "Installing backend application files..."
cp -r "${SCRIPT_DIR}/app/"* "$APP_DIR/app/"
chown -R "$APP_USER:$APP_USER" "$APP_DIR/app"

# ── HAProxy configuration ──────────────────────────────────────────────────────
log "Installing HAProxy configuration..."
cp "${SCRIPT_DIR}/haproxy/haproxy.cfg" /etc/haproxy/haproxy.cfg
haproxy -c -f /etc/haproxy/haproxy.cfg || fail "HAProxy config invalid"

# ── Backend Flask app systemd service ─────────────────────────────────────────
log "Creating API gateway backend service..."
cat > /etc/systemd/system/rpal-api-backend.service << SVCEOF
[Unit]
Description=RPAL API Gateway Backend Application Server
Documentation=https://intranet.rpal.in/docs/api-gateway
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
ExecStart=/usr/local/bin/gunicorn \
    --bind 127.0.0.1:8000 \
    --workers 2 \
    --worker-class sync \
    --timeout 30 \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    app.app:app
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rpal-api-backend
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVCEOF

# ── HAProxy systemd ────────────────────────────────────────────────────────────
log "Enabling HAProxy..."
systemctl enable haproxy
systemctl restart haproxy

# ── Backend service ────────────────────────────────────────────────────────────
log "Starting API gateway backend..."
systemctl daemon-reload
systemctl enable rpal-api-backend
systemctl start rpal-api-backend
sleep 2

if ! systemctl is-active --quiet rpal-api-backend; then
    fail "Backend service failed — check: journalctl -u rpal-api-backend -n 20"
fi

# ── Internal monitor service (the "victim daemon") ─────────────────────────────
# Named as a legitimate internal monitoring component — NOT as a simulation.
# Blue teamers inspecting systemd services will see "RPAL API Gateway Health Monitor"
# and treat it as a legitimate operational component.
log "Installing API gateway health monitor..."

cat > /etc/systemd/system/rpal-apigw-monitor.service << SVCEOF
[Unit]
Description=RPAL API Gateway Health Monitor
Documentation=https://intranet.rpal.in/docs/sre/api-gateway-monitoring
After=network.target rpal-api-backend.service

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/python3 ${APP_DIR}/app/monitor.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rpal-apigw-monitor

Environment=RPAL_GATEWAY_URL=http://127.0.0.1:80
Environment=RPAL_BACKEND_URL=http://127.0.0.1:8000
Environment=PROBE_INTERVAL=10

NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable rpal-apigw-monitor
systemctl start rpal-apigw-monitor
sleep 2

if ! systemctl is-active --quiet rpal-apigw-monitor; then
    warn "Monitor service not active — check: journalctl -u rpal-apigw-monitor -n 10"
else
    log "API gateway monitor running — probing every 10 seconds"
fi

# ── Hostname ───────────────────────────────────────────────────────────────────
echo "api-gw.rpal.in" > /etc/hostname
hostname api-gw.rpal.in 2>/dev/null || true

# ── Firewall ───────────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    ufw allow 80/tcp comment "RPAL API Gateway (HAProxy)" >/dev/null 2>&1 || true
    ufw deny 8000/tcp comment "RPAL Backend — internal only" >/dev/null 2>&1 || true
fi

# ── Summary ────────────────────────────────────────────────────────────────────
MY_IP=$(hostname -I | awk '{print $1}')
echo ""
log "=== M4 · ext-haproxy setup COMPLETE ==="
info "HAProxy:          http://${MY_IP}:80/ (public gateway)"
info "Backend:          http://127.0.0.1:8000/ (internal only)"
info "Monitor interval: 10 seconds (probes /api/v2/permits/status with auth)"
info "Challenge target: /api/v2/admin/export (requires captured token)"
info "Vulnerability:    CL.TE request smuggling via HAProxy→Gunicorn desync"
info ""
info "Monitor service:  systemctl status rpal-apigw-monitor"
info "Token window:     rotates every 30 minutes (deterministic)"
warn "Run Honeytraps/M4-ext-haproxy.sh to deploy supporting services"
