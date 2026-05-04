#!/usr/bin/env bash
# deps.sh — M4 · ext-haproxy · RNG-EXT-01
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[DEPS]${NC} $*"; }
log "=== M4 ext-haproxy deps ==="
apt-get update -qq
apt-get install -y -qq haproxy python3 python3-pip netcat-openbsd ncat curl
pip3 install -q flask==2.3.3 gunicorn==21.2.0 requests==2.31.0 werkzeug==2.3.7
haproxy -v | head -1
log "=== deps.sh complete ==="
