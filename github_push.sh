#!/usr/bin/env bash
# =============================================================================
# github_push.sh — Push nexus-itgw-range to GitHub
# OPERATION GRIDFALL | RNG-IT-01
# Usage: Set GITHUB_PAT environment variable, then run this script.
# =============================================================================
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
REPO_NAME="RB3-Range1"
GITHUB_USER="hacktifytechnologies"   # <-- Set your GitHub username here
BRANCH="main"

# ── PAT check ─────────────────────────────────────────────────────────────────
if [[ -z "${GITHUB_PAT:-}" ]]; then
    echo "[!] GITHUB_PAT environment variable is not set."
    echo "    Export it before running: export GITHUB_PAT=ghp_xxxxxxxxxxxx"
    exit 1
fi

REMOTE_URL="https://${GITHUB_USER}:${GITHUB_PAT}@github.com/${GITHUB_USER}/${REPO_NAME}.git"

# ── Determine repo root ───────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# ── Git init / remote setup ───────────────────────────────────────────────────
if [[ ! -d ".git" ]]; then
    echo "[*] Initialising git repository..."
    git init
    git checkout -b "${BRANCH}" 2>/dev/null || git branch -M "${BRANCH}"
fi

# Remove existing origin if set, then re-add
git remote remove origin 2>/dev/null || true
git remote add origin "${REMOTE_URL}"
echo "[+] Remote set to github.com/${GITHUB_USER}/${REPO_NAME}"

# ── Create .gitignore ─────────────────────────────────────────────────────────
cat > .gitignore << 'EOF'
__pycache__/
*.pyc
*.pyo
*.pyd
.env
*.db
*.log
*.rdb
venv/
.DS_Store
Thumbs.db
EOF

# ── Stage all files ───────────────────────────────────────────────────────────
echo "[*] Staging all files..."
git add -A

# ── Commit ────────────────────────────────────────────────────────────────────
COMMIT_MSG="GRIDFALL RNG-IT-01: Full range build — 5 machines, reports, TTPs, honeytraps"
git commit -m "${COMMIT_MSG}" 2>/dev/null || echo "[~] Nothing new to commit."

# ── Push ─────────────────────────────────────────────────────────────────────
echo "[*] Pushing to ${BRANCH}..."
git push -u origin "${BRANCH}" --force

echo ""
echo "[+] Push complete."
echo "    Repository: https://github.com/${GITHUB_USER}/${REPO_NAME}"
