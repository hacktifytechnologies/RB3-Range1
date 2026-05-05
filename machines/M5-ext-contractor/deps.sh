#!/usr/bin/env bash
# deps.sh — M5 · ext-contractor-portal · RNG-EXT-01
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[DEPS]${NC} $*"; }

log "=== M5 deps ==="
apt-get update -qq
apt-get install -y -qq nodejs npm git curl
node --version; npm --version; git --version
log "=== deps.sh complete ==="
