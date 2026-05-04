#!/usr/bin/env bash
# deps.sh — M5 · ext-contractor · RNG-EXT-01
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[DEPS]${NC} $*"; }
log "=== M5 ext-contractor deps ==="
apt-get update -qq
apt-get install -y -qq python3 python3-pip sqlite3 curl netcat-openbsd ncat \
    xfonts-base xfonts-75dpi libssl-dev libxrender1 libxext6 fontconfig
pip3 install -q flask==2.3.3 werkzeug==2.3.7

# wkhtmltopdf 0.12.5 — vulnerable version
ARCH=$(dpkg --print-architecture)
WKHTML="wkhtmltox_0.12.5-1.bionic_${ARCH}.deb"
log "Downloading wkhtmltopdf 0.12.5..."
curl -fsSL -o "/tmp/${WKHTML}" \
    "https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.5/${WKHTML}" \
    || curl -fsSL -o "/tmp/${WKHTML}" \
    "https://downloads.wkhtmltopdf.org/0.12/0.12.5/${WKHTML}"
dpkg -i "/tmp/${WKHTML}" 2>/dev/null || apt-get install -f -y -qq
wkhtmltopdf --version | grep "0.12.5" && log "wkhtmltopdf 0.12.5 OK" || log "WARNING: version mismatch"
log "=== deps.sh complete ==="
