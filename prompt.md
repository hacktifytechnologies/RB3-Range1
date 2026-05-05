# prompt.md — RNG-EXT-01 SETU DVAAR → Handoff for RNG-EXT-02 PRAHARI KENDRA
## OPERATION DEEPSTRIKE | Claude Handoff Document
**For:** Claude instance building Range 2 (RNG-EXT-02 · PRAHARI KENDRA)
**Generated after:** Full completion of RNG-EXT-01 · SETU DVAAR

---

## Context

You are continuing **OPERATION DEEPSTRIKE** — a multi-range purple team cyber range simulating APT **NEEL TRISHUL** attacking **Rashtriya Petroleum Anveshan Limited (RPAL)**. You are building **Range 2: RNG-EXT-02 · PRAHARI KENDRA** — the Corporate IT backbone zone.

---

## What Has Been Built (Range 1 — COMPLETE)

**M1 — ext-permit-portal** (203.x.x.10, port 8443) — Python/Flask
- JWT RS256→HS256 algorithm confusion
- Credential discovery via DGH Registry path traversal (dev-notes.txt)
- Output: `graphql_api_key: RPAL-API-2024-XK9mP3nT8qRs`

**M2 — ext-graphql-api** (203.x.x.20, port 4000) — Python/Flask + Strawberry GraphQL
- batchQuery resolver missing @require_auth
- Output: `rpal-tariff-svc / TariffGW@Soap!2024#RPAL`

**M3 — ext-soap-gateway** (203.x.x.30, port 8080) — Python/Flask + lxml
- XXE → SSRF → 169.254.169.254 IMDS
- Output: AccessKeyId + 64-char Token + `_rpal_endpoint: http://203.x.x.x:3000`

**M4 — ext-survey-portal** (203.x.x.40, port 3000) — Node.js + Express + EJS
- Auth: IMDS credentials from M3 (date-deterministic SHA-256 derivation)
- EJS SSTI via ejs.render(user_template, data) — no sanitisation
- Output: `RPAL-CONTRACTOR-API-2024-xK9mP3nT8qRs7vL2` (from /etc/rpal/contractor/api-key.txt)

**M5 — ext-contractor-portal** (203.x.x.50, port 4000) — Node.js + Express
- express.static with dotfiles:'allow' exposes .git directory
- 2-commit history: initial commit has ADMIN_TOKEN hardcoded
- ADMIN_TOKEN: `RPAL-ADMIN-TOKEN-2024-9c4e2a8f1b7d3e6a`
- /admin/export returns SSH RSA-2048 private key + passphrase
- **PIVOT CREDENTIALS:**
  - SSH user: `svc-deploy`
  - SSH host: `203.x.x.x` (RNG-EXT-02 M1)
  - SSH passphrase: `Deploy@SSH!RPAL24Corp`
  - SSH private key: RSA-2048, generated at setup (public key available from VM5)

---

## Your Range: RNG-EXT-02 · PRAHARI KENDRA

### Entry Point (from Range 1 M5)

Participants arrive with:
- SSH private key extracted from M5 `/admin/export`
- Passphrase: `Deploy@SSH!RPAL24Corp`
- `ssh -i svc-deploy-rsa svc-deploy@203.x.x.x`

Your M1 must accept SSH from `svc-deploy` using the public key from Range 1 M5. In your M1 setup.sh:
```bash
useradd -m -s /bin/bash svc-deploy
mkdir -p /home/svc-deploy/.ssh
# Add public key from Range 1 M5: cat /etc/rpal/keys/svc-deploy-rsa.pub
echo "SSH-RSA-PUBLIC-KEY-FROM-RANGE1-M5" >> /home/svc-deploy/.ssh/authorized_keys
chmod 700 /home/svc-deploy/.ssh && chmod 600 /home/svc-deploy/.ssh/authorized_keys
chown -R svc-deploy:svc-deploy /home/svc-deploy/.ssh
```

### Zone and Network
- Zone: v-Corp (corporate IT backbone)
- Network: `10.x.x.0/24` (internal corporate zone — not internet-facing)
- Hostnames: `prahari-m1.corp.rpal.in` through `prahari-m5.corp.rpal.in`

### Your 5 Machines

**M1 — corp-ldap-portal** — LDAP Injection via Employee Self-Service Portal
- SSH pivot → web portal on :8080, OpenLDAP on :389
- Vulnerability: LDAP search filter injection `(&(uid={input})(dept=*))` → dump all accounts
- Custom attribute `rpalPasswordHint` on privileged accounts reveals next credential
- Output: GitLab service account credentials

**M2 — corp-gitlab** — GitLab CI/CD YAML Anchor Injection
- Port: 8929
- Pipeline variable passed through envsubst into YAML → YAML anchor injection → RCE in runner
- Output: HashiCorp Vault AppRole RoleID + SecretID location

**M3 — corp-vault** — Vault AppRole Misconfiguration
- Port: 8200
- SecretID derivable from runner environment; policy misconfiguration grants over-privileged access
- Output: monitoring agent config + credentials for M4

**M4 — corp-monitoring** — Custom Agent Plugin PrivEsc
- Unique: NOT detectable by linpeas — requires reading binary with strings/ltrace
- Custom rpal-netmon agent loads .so plugins from group-writable directory
- M3 user has monitoring group → write malicious .so → agent executes as root
- Output: AWX vault-encrypted SSH blob

**M5 — corp-ansible** — AWX Vault Password Derivation
- Vault password derived from hostname-based KDF in monitoring agent config (from M4)
- Verbose job template output exposes encrypted blob
- Decrypt → SSH key for OT jump host
- Output: Pivot to RNG-OPS-01 (Operational Technology zone)

---

## Naming Conventions (Maintain Consistency)

- Service names: `rpal-{function}.service` — never "decoy", "sim", "fake", "victim"
- App users: `rpal-{function}` e.g. `rpal-ldap`, `rpal-vault`
- Passwords: `{Service}@{Function}!{Year}#{Org}` e.g. `GitLab@CI!2024#RPAL`
- API keys: `RPAL-{SERVICE}-{YEAR}-{Random16}` e.g. `RPAL-VAULT-2024-Xk9mPnT8qRs7vL2`

## Technical Constraints

- Ubuntu 22.04 LTS, OpenStack, no Docker
- System fonts only (no CDN)
- Python 3.10+ or Node.js for services
- Systemd services, SQLite databases
- 6-7 supporting services per machine (honeytraps)
- All apps self-contained — no internet after deps.sh

## Quality Standards

Each machine needs: `deps.sh`, `setup.sh`, `app/`, `solve_red.md`, `solve_blue.md`, TTP YAML
Web portals: professional quality matching Indian govt/corporate IT portals
solve_red.md: explain every curl flag, full annotated exploit scripts, pitfalls section
solve_blue.md: real Splunk SPL, real Suricata rules, containment commands, remediation code

---

*prompt.md | RNG-EXT-01 → RNG-EXT-02 Handoff | OPERATION DEEPSTRIKE*
*Generated: May 2026 | Claude Sonnet 4.6*
