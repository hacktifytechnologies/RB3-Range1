#!/usr/bin/env bash
# deps.sh — M2 · ext-graphql-api · RNG-EXT-01 · SETU DVAAR
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[DEPS]${NC} $*"; }

log "=== M2 ext-graphql-api deps.sh ==="
apt-get update 
apt-get install -y python3 python3-pip sqlite3 curl netcat-openbsd

pip3 install \
    flask==2.3.3 \
    strawberry-graphql==0.219.2 \
    flask-cors==4.0.0 \
    werkzeug==2.3.7 \
    gunicorn==21.2.0 \
    python-dateutil==2.8.2

python3 -c "import strawberry; from importlib.metadata import version; print(version('strawberry-graphql'))"
log "=== deps.sh complete ==="
