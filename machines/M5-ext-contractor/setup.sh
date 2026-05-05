#!/usr/bin/env bash
# setup.sh — M5 · ext-contractor-portal · RNG-EXT-01
# Challenge: Exposed .git directory → git history → hardcoded admin token → SSH key
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
command -v node >/dev/null || { echo "[FAIL] Run deps.sh first"; exit 1; }
command -v git  >/dev/null || { echo "[FAIL] git not found — run deps.sh"; exit 1; }

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/rpal/contractor-portal"
APP_USER="rpal-contractor"
KEY_DIR="/etc/rpal/keys"
SVC="rpal-contractor-portal"

# The admin token — committed in old git history, then "removed" in current code
ADMIN_TOKEN="RPAL-ADMIN-TOKEN-2024-9c4e2a8f1b7d3e6a"

log "=== M5 · ext-contractor-portal setup ==="
log "Challenge: Exposed .git directory → hardcoded admin token → SSH key"

# ── Service user ───────────────────────────────────────────────────────────────
id "$APP_USER" &>/dev/null || useradd -r -s /bin/false -d "$APP_DIR" \
    -c "RPAL Contractor Registration Service" "$APP_USER"

# ── SSH key for Range 2 pivot ─────────────────────────────────────────────────
mkdir -p "$KEY_DIR"
log "Generating Range 2 pivot SSH key (svc-deploy)..."
ssh-keygen -t rsa -b 2048 -f "${KEY_DIR}/svc-deploy-rsa" \
    -N "Deploy@SSH!RPAL24Corp" -C "svc-deploy@rpal.in" -q 2>/dev/null || true
chmod 600 "${KEY_DIR}/svc-deploy-rsa"
chown "root:${APP_USER}" "${KEY_DIR}/svc-deploy-rsa"
log "SSH key: ${KEY_DIR}/svc-deploy-rsa (readable by ${APP_USER})"

# ── Install app and create git history ────────────────────────────────────────
mkdir -p "$APP_DIR/app"
cp -r "${SCRIPT_DIR}/app/"* "$APP_DIR/app/"

cd "$APP_DIR/app"
npm install --prefer-offline -q 2>/dev/null || npm install -q

# Configure git identity for commits
git config --global user.email "arjun.mehta@rpal.in" 2>/dev/null || true
git config --global user.name  "Arjun Mehta" 2>/dev/null || true

log "Initialising git repository with sensitive history..."

# ── Create git history ─────────────────────────────────────────────────────────
git init -q "$APP_DIR/app" 2>/dev/null || true
cd "$APP_DIR/app"

# ── COMMIT 1: Initial commit with hardcoded admin token ───────────────────────
# Write a version of app.js that has the token hardcoded
cat > /tmp/app_v1.js << APPEOF
'use strict';
// RPAL Contractor Registration System v1.0
// TODO: move ADMIN_TOKEN to environment variable before production deploy

const ADMIN_TOKEN = '${ADMIN_TOKEN}';
const API_KEY     = 'RPAL-CONTRACTOR-API-2024-xK9mP3nT8qRs7vL2';

console.log('RPAL Contractor Portal initialising...');
APPEOF

git add . 2>/dev/null || true
# Stash current app.js temporarily for the fake commit
cp app.js /tmp/app_current.js
cp /tmp/app_v1.js app.js

GIT_AUTHOR_DATE="2024-09-15T09:00:00+05:30" \
GIT_COMMITTER_DATE="2024-09-15T09:00:00+05:30" \
git commit -q -m "Initial commit — RPAL Contractor Registration System v1.0

- Express + EJS setup
- Contractor registration endpoint
- Admin export endpoint with static credentials
- TODO: Jira DEVOPS-1041 — move ADMIN_TOKEN to env before go-live" 2>/dev/null || true

# ── COMMIT 2: Dependency update ───────────────────────────────────────────────
GIT_AUTHOR_DATE="2024-10-01T11:30:00+05:30" \
GIT_COMMITTER_DATE="2024-10-01T11:30:00+05:30" \
git commit -q -m "chore: update npm dependencies to latest" --allow-empty 2>/dev/null || true

# ── COMMIT 3: Remove hardcoded token (current code) ──────────────────────────
# Restore the real app.js
cp /tmp/app_current.js app.js

GIT_AUTHOR_DATE="2024-10-15T14:20:00+05:30" \
GIT_COMMITTER_DATE="2024-10-15T14:20:00+05:30" \
git commit -q -a -m "security: move ADMIN_TOKEN to environment variable

Jira DEVOPS-1041 — ADMIN_TOKEN was hardcoded in source code.
Moved to systemd Environment= directive as per security review.
API_KEY unchanged (rotated separately)." 2>/dev/null || true

log "Git history created: 3 commits"
git log --oneline 2>/dev/null | head -5

# ── systemd service ────────────────────────────────────────────────────────────
cat > "/etc/systemd/system/${SVC}.service" << SVCEOF
[Unit]
Description=RPAL Contractor Registration System
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
Environment=PORT=4000
Environment=ADMIN_TOKEN=${ADMIN_TOKEN}
Environment=SSH_KEY_PATH=${KEY_DIR}/svc-deploy-rsa
[Install]
WantedBy=multi-user.target
SVCEOF

chown -R "$APP_USER:$APP_USER" "$APP_DIR"
# Note: .git must be readable by web server for the vulnerability to work
chmod -R 755 "$APP_DIR/app/.git" 2>/dev/null || true

systemctl daemon-reload
systemctl enable "$SVC"
systemctl restart "$SVC"
sleep 3

systemctl is-active --quiet "$SVC" && log "Contractor portal running on :4000" \
    || { journalctl -u "$SVC" -n 20 --no-pager; echo "[FAIL]"; exit 1; }

echo "contractor.rpal.in" > /etc/hostname
hostname contractor.rpal.in 2>/dev/null || true
command -v ufw &>/dev/null && ufw allow 4000/tcp comment "RPAL Contractor Portal" >/dev/null 2>&1 || true

MY_IP=$(hostname -I | awk '{print $1}')
log "=== M5 setup COMPLETE ==="
info "Portal:      http://${MY_IP}:4000/"
info "Vuln:        GET /.git/logs/HEAD → git log → old commit → hardcoded token"
info "Admin token: ${ADMIN_TOKEN}"
info "Admin API:   GET /admin/export (Authorization: Bearer <token>)"
info "Flag:        SSH key for svc-deploy → RNG-EXT-02 pivot"
