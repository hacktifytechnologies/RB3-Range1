#!/usr/bin/env bash
# deps.sh — M4 · ext-survey-portal · RNG-EXT-01
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[DEPS]${NC} $*"; }

log "=== M4 deps ==="
apt-get update -qq
apt-get install -y -qq nodejs npm curl
node --version; npm --version

# Install Node.js packages
cd /tmp
mkdir -p rpal-survey-deps && cd rpal-survey-deps
cp /dev/stdin package.json << 'EOF'
{"dependencies":{"express":"^4.18.2","ejs":"^3.1.9","cookie-session":"^2.0.0"}}
EOF
npm install --prefer-offline -q 2>/dev/null || npm install -q
log "npm packages installed"
cd / && rm -rf /tmp/rpal-survey-deps

log "=== deps.sh complete ==="
