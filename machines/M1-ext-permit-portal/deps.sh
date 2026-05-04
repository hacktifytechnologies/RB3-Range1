#!/usr/bin/env bash
# deps.sh — M1 ext-permit-portal RNG-EXT-01
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[DEPS]${NC} $*"; }

log "=== M1 deps ==="
apt-get update -qq
apt-get install -y -qq python3 python3-pip openssl curl ncat netcat-openbsd
# NOTE: pyjwt is NOT installed server-side — app.py implements JWT manually.
# The cryptography library is all that is needed.
pip3 install --break-system-packages -q flask==2.3.3 werkzeug==2.3.7 cryptography==41.0.7

# Verify imports work
python3 -c "
from flask import Flask
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hmac, hashlib, base64, json, time
print('All imports OK')
"
log "=== deps.sh complete — run setup.sh next ==="
