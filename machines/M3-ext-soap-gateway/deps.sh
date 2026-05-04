#!/usr/bin/env bash
# deps.sh — M3 · ext-soap-gateway · RNG-EXT-01
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[DEPS]${NC} $*"; }
log "=== M3 ext-soap-gateway deps ==="
apt-get update -qq
apt-get install -y -qq python3 python3-pip curl netcat-openbsd ncat iptables
pip3 install -q flask==2.3.3 lxml==4.9.3 requests==2.31.0 werkzeug==2.3.7
python3 -c "from lxml import etree; print('lxml OK')"
log "=== deps.sh complete ==="
