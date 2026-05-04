# prompt.md — RNG-EXT-01 SETU DVAAR → Handoff for RNG-EXT-02 PRAHARI KENDRA
## OPERATION DEEPSTRIKE | Claude Handoff Document
**For:** Claude instance building Range 2 (RNG-EXT-02 · PRAHARI KENDRA)
**Generated after:** Full completion of RNG-EXT-01 · SETU DVAAR

---

## Context: What You Are Building

You are continuing **OPERATION DEEPSTRIKE**, a multi-range purple team cyber range simulating an APT attack on **Rashtriya Petroleum Anveshan Limited (RPAL)**, a fictional Central Public Sector Undertaking under India's Ministry of Petroleum & Natural Gas. The APT group is **NEEL TRISHUL** (composite of APT41/APT10), targeting RPAL's URJA DRISHTI 2.0 digital platform.

You are building **Range 2: RNG-EXT-02 · PRAHARI KENDRA** — the Corporate IT backbone zone.

---

## What Has Been Built (Range 1)

Range 1 (RNG-EXT-01 · SETU DVAAR) is **complete**. It contains 5 machines in the v-Public zone (203.x.x.0/24):

### Machine Summary

**M1 — ext-permit-portal** (203.x.x.10, port 8443)
- Flask + PyJWT 1.7.1
- Vulnerability: JWT RS256→HS256 algorithm confusion
- JWKS endpoint at /.well-known/jwks.json exposes RSA-2048 public key
- Attack: extract public key from JWKS → sign forged JWT with HS256 using pubkey bytes as HMAC secret → admin role → /api/v1/admin/system-config
- Output: graphql_service_pass=`T@riff@Expl0re!24`, graphql_api_key=`RPAL-API-2024-XK9mP3nT8qRs`

**M2 — ext-graphql-api** (203.x.x.20, port 4000)
- Strawberry GraphQL, introspection disabled but suggestions enabled
- Vulnerability: batchQuery resolver has no @require_auth decorator
- Attack: enumerate schema via "Did you mean" suggestions → call batchQuery(queries:["systemAccounts"]) unauthenticated
- Output: rpal-tariff-svc plaintext password = `TariffGW@Soap!2024#RPAL`

**M3 — ext-soap-gateway** (203.x.x.30, port 8080)
- lxml with resolve_entities=True, no_network=False, load_dtd=True
- PNGRB tariff calculation SOAP service
- Vulnerability: XXE → SSRF → 169.254.169.254 IMDS
- Attack: XXE payload in SOAP body → fetch IMDS IAM credentials → exposed in SOAP fault
- Output: IAM role credentials + hint `_rpal_endpoint: http://203.x.x.x:8000/api/v2/admin/export`

**M4 — ext-haproxy** (203.x.x.40, port 80)
- HAProxy 2.x frontend → Gunicorn backend on :8000
- CL.TE desync: HAProxy honours Content-Length, Gunicorn honours Transfer-Encoding
- Internal daemon **rpal-apigw-monitor** (systemd service, legitimate-sounding name) probes /api/v2/permits/status every 10 seconds with Bearer token
- Token: `rpal-sess-{sha256(SEED:window)[:24]}-permit-svc`, rotates every 30 min
- SEED: `RPAL-APIGW-PERMIT-MONITOR-SEED-DEEPSTRIKE-EXERCISE`
- Attack: CL.TE smuggled prefix → captures monitor's Authorization header → use token on /api/v2/admin/export
- Output: `bind_dn=cn=svc-api-gateway,...`, `bind_password=Ldap@GW!Bind2024#RPAL`, SSH key info

**M5 — ext-contractor** (203.x.x.50, port 9000)
- Flask contractor onboarding portal, wkhtmltopdf 0.12.5 with --enable-local-file-access
- Vulnerability: company_profile_url passed directly to wkhtmltopdf (file:// supported)
- Attack: submit file:///etc/rpal/upstream/config.ini as profile URL → download PDF → extract credentials
- SSRF target: /etc/rpal/upstream/config.ini
- **PIVOT CREDENTIALS (connect M5 to your M1):**
  - SSH private key: `/etc/rpal/upstream/svc-deploy-rsa` (RSA-2048, generated on setup)
  - SSH passphrase: `Deploy@SSH!RPAL24Corp`
  - SSH user: `svc-deploy`
  - SSH host: `203.x.x.x` (RNG-EXT-02 M1 IP)
  - LDAP bind_dn: `cn=svc-api-gateway,ou=service-accounts,dc=corp,dc=rpal,dc=in`
  - LDAP bind_password: `Ldap@GW!Bind2024#RPAL`
  - LDAP server: `203.x.x.x` (RNG-EXT-02 M1)

---

## Your Range: RNG-EXT-02 · PRAHARI KENDRA

### Entry Point (from Range 1 M5)
Participants arrive with:
- SSH private key: `svc-deploy-rsa` (extracted from config.ini via wkhtmltopdf SSRF)
- Passphrase: `Deploy@SSH!RPAL24Corp`
- SSH: `ssh -i svc-deploy-rsa svc-deploy@203.x.x.x`
- LDAP credentials: `Ldap@GW!Bind2024#RPAL` for `cn=svc-api-gateway,...`

Your **M1** must accept SSH connections from `svc-deploy` using the public key corresponding to the private key planted in Range 1 M5. Setup: at the end of Range 1 M5's setup.sh, the public key (`/etc/rpal/upstream/svc-deploy-rsa.pub`) is printed — this must be added to svc-deploy's `authorized_keys` on your M1.

### Zone and Network
- Zone: v-Public (still external-facing, but corporate IT backbone)
- Network: `203.x.x.0/24` (same external zone, different subnet range or next block)
- Hostname convention: `prahari-kendra-m1.rpal.in` through `prahari-kendra-m5.rpal.in`

### Your 5 Machines

**M1 — corp-ldap-portal** (Corporate Employee Self-Service + LDAP)
- Entry: SSH as svc-deploy, then pivot to web service
- Vulnerability: LDAP attribute injection in Employee Self-Service portal
- Search filter vulnerable: `(&(uid={input})(dept=*))`
- Injection: `*)(uid=*))(|(uid=*` breaks filter → returns all accounts
- There is a custom LDAP attribute `rpalPasswordHint` on privileged accounts
- Real service port: 8080 (web portal), 389 (LDAP)
- Output: GitLab service account credentials

**M2 — corp-gitlab** (Internal GitLab CE)
- Vulnerability: GitLab CI/CD YAML anchor injection via pipeline variable interpolation
- A pipeline variable is passed through `envsubst` into a shell script processing YAML
- YAML anchor injection (`&anchor`/`*anchor`) achieves RCE in the pipeline runner
- Real service port: 8929 (GitLab HTTP)
- Output: HashiCorp Vault AppRole RoleID + SecretID location

**M3 — corp-vault** (HashiCorp Vault)
- Vulnerability: Vault AppRole misconfiguration — RoleID in public GitLab repo, SecretID derivable
- `secret_id_num_uses=0` but `secret_id_ttl=24h` — SecretID in container environment
- Reachable via Vault's `/sys/leases` after RoleID-only authentication
- Vault policy misconfiguration grants access to secrets beyond intended scope
- Real service port: 8200
- Output: Internal monitoring agent config + next machine credentials

**M4 — corp-monitoring** (RPAL Network Monitoring Agent)
- Vulnerability: Custom agent loads plugin .so files from directory writable by `monitoring` group
- This is a PrivEsc: NOT discoverable by linpeas
- Must read the binary with `strings`/`ltrace` to understand `dlopen()` plugin loading
- The user from M3 has `monitoring` group membership
- Write malicious .so to plugin dir → agent executes it as root
- Output: AWX/Ansible vault encrypted SSH key blob

**M5 — corp-ansible** (AWX Automation Server)
- Vulnerability: AWX job template verbose output exposes ansible-vault encrypted blob
- Vault password derived from custom KDF using hostname-based seed in monitoring agent config
- Participants must chain M4 (monitoring agent config file) → derive vault password → decrypt blob
- Output: SSH key for OT jump host → pivot to RNG-OPS-01

---

## Storyline for Range 2

**Day 4-6 of Operation DEEPSTRIKE.** Having extracted corporate IT credentials from the external portal zone, **Varuna-2** uses the `svc-deploy` SSH key to gain initial access to RPAL's corporate IT backbone — the **PRAHARI KENDRA** zone.

This zone runs RPAL's core IT services: the LDAP directory, internal GitLab for infrastructure-as-code, HashiCorp Vault for secrets management, and the AWX automation platform used to manage 200+ servers.

**Character appearances:**
- **Vikram Nair** (IT Infrastructure Head) — his rushed deployments are visible everywhere; GitLab pipelines have hardcoded secrets, Vault policies are overly permissive, the monitoring agent was written by a contractor who left
- **Arjun Mehta** (DevOps Lead) — the GitLab YAML injection lives in his pipeline templates; the AWX job template with verbose logging is his
- **Rajan Iyer** (Network Engineer) — his custom monitoring agent (`rpal-netmon`) is the privesc target

**Operator note (Varuna-2 log):** "Corporate IT is a goldmine. The DevOps team clearly prioritised velocity over security. Every service has a misconfiguration waiting to be exploited. The Vault setup would make a security engineer cry."

---

## Naming Conventions (Maintain Consistency)

### Service Naming (CRITICAL — no "decoy", "sim", "victim", "fake", "mock")
All systemd services must be named as legitimate RPAL components:
- `rpal-{service-function}.service` e.g. `rpal-ldap-selfservice.service`
- Description must sound operational: "RPAL Employee LDAP Self-Service Portal"
- No service name or description may hint at its exercise role

### Application Users
Pattern: `rpal-{function}` e.g. `rpal-ldap`, `rpal-gitlab`, `rpal-vault`

### Credentials (Use Realistic Patterns)
- Service passwords: `{ServiceName}@{Function}!{Year}#{Org}` e.g. `GitLab@CI!2024#RPAL`
- SSH keys: RSA-4096 or Ed25519, realistic comments
- API keys: `RPAL-{SERVICE}-{YEAR}-{RandomChars}` e.g. `RPAL-VAULT-2024-Xk9mPnT8`

---

## File Structure to Follow

```
RB-Range2/
├── README.md
├── STORYLINE.md
├── NETWORK_DIAGRAM.md
├── AD-Dependencies.md
├── AssessmentQuestions.md
├── prompt.md                 ← for Claude building Range 3
├── .gitignore
├── github_push.sh
├── Honeytraps/
│   ├── M1-corp-ldap-portal.sh
│   ├── M2-corp-gitlab.sh
│   ├── M3-corp-vault.sh
│   ├── M4-corp-monitoring.sh
│   └── M5-corp-ansible.sh
├── machines/
│   ├── M1-corp-ldap-portal/
│   │   ├── deps.sh
│   │   ├── setup.sh          ← MUST add Range 1 svc-deploy public key to authorized_keys
│   │   ├── app/app.py
│   │   ├── app/templates/
│   │   ├── solve_red.md
│   │   └── solve_blue.md
│   ├── M2-corp-gitlab/ ...
│   ├── M3-corp-vault/ ...
│   ├── M4-corp-monitoring/ ...
│   └── M5-corp-ansible/ ...
└── ttps/
    ├── TTP-EXT02-M1.yaml
    ├── TTP-EXT02-M2.yaml
    ├── TTP-EXT02-M3.yaml
    ├── TTP-EXT02-M4.yaml
    └── TTP-EXT02-M5.yaml
```

---

## Quality Standards

### Each Machine Must Have
- `deps.sh`: All dependencies, pinned versions where vulnerability depends on version
- `setup.sh`: Full environment setup, no internet required after deps.sh
- `app/app.py` (or equivalent): Full application code with vulnerability comments explaining WHY the vuln exists
- `solve_red.md`: Detailed writeup — Overview (What/Why/How), Prerequisites, Reconnaissance, Vulnerability Analysis, Exploitation (full scripts), Post-Exploitation, Pitfalls
- `solve_blue.md`: Detailed defender guide — Detection logs, Suricata/Splunk signatures, Containment commands, Remediation code, Lessons Learned
- Systemd service with realistic name and description
- 6-7 supporting services per machine (3 web portals + 4 TCP banners minimum), all unique per machine

### Writeup Quality
- Never assume the reader knows anything — explain every step
- Every curl command must have every flag explained
- Exploitation scripts must be fully annotated
- Blue team queries must be implementable (real Splunk SPL, real Suricata rules)
- Pitfalls section must cover what standard tools miss and why

### Web Portals
- System fonts only (no Google Fonts CDN — OpenStack blocks external CDN)
- Professional quality matching real Indian govt/corporate IT portals
- All interactive elements (login forms, search, navigation) must be rendered and realistic
- No broken links or placeholder buttons that obviously do nothing

### PrivEsc Challenges (M4 especially)
- Must NOT be solvable by linpeas or standard automated tools
- Requires reading binaries, understanding custom daemons, manual research
- The vulnerability path must be: observe running process → read binary → understand mechanism → exploit

---

## Technical Constraints

- Ubuntu 22.04 LTS on all VMs
- OpenStack hypervisor (no external CDN, system fonts only)
- Python 3.10+ for Flask apps
- Gunicorn for WSGI serving
- All apps use systemd services
- SQLite for databases (no external DB required)
- No Docker (bare metal VM deployment)

---

## Important: The svc-deploy SSH Key

The Range 1 M5 setup.sh generates an RSA-2048 key at `/etc/rpal/upstream/svc-deploy-rsa`. The **public key** is what you need to install on your M1.

In your M1 setup.sh, you must:
```bash
# Create svc-deploy user
useradd -m -s /bin/bash svc-deploy
mkdir -p /home/svc-deploy/.ssh
# The public key must be provided by the exercise admin after running M5 setup.sh
# Placeholder — replace with actual public key from Range 1 M5:
echo "SSH-RSA-PUBLIC-KEY-FROM-RANGE1-M5-SETUP" >> /home/svc-deploy/.ssh/authorized_keys
chmod 700 /home/svc-deploy/.ssh
chmod 600 /home/svc-deploy/.ssh/authorized_keys
chown -R svc-deploy:svc-deploy /home/svc-deploy/.ssh
```

Document this clearly in your README.md so the exercise admin knows to copy the public key from Range 1 M5 to Range 2 M1 before the exercise.

---

*prompt.md | RNG-EXT-01 → RNG-EXT-02 Handoff | OPERATION DEEPSTRIKE*
*Generated by: Claude Sonnet 4.5 (OPERATION DEEPSTRIKE Range 1 build session)*
