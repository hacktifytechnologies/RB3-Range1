# solve_blue.md — M1 · ext-permit-portal
## Blue Team Detection, Containment & Remediation
**Range:** RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
**Machine:** M1 — RPAL Exploration Permit Portal
**Vulnerability:** JWT Algorithm Confusion (RS256 → HS256)
**MITRE ATT&CK:** T1550.001 (Token Impersonation/Theft)

---

## 1. What the Attack Looks Like — Data Sources

### 1.1 — Application Access Log (`/var/log/rpal/permit-portal/access.log`)

Under normal conditions, you will see login events followed by role-appropriate API access:

```
2024-11-15 03:14:22 INFO LOGIN_OK user=contractor.01 role=applicant ip=198.51.100.x
2024-11-15 03:14:23 INFO ACCESS user=contractor.01 role=applicant path=/dashboard ip=198.51.100.x
2024-11-15 03:14:25 INFO ACCESS user=contractor.01 role=applicant path=/api/v1/permits ip=198.51.100.x
```

**During the attack**, you will see:
```
2024-11-15 03:22:11 INFO JWKS_FETCH from=198.51.100.x
2024-11-15 03:22:34 WARNING ADMIN_CONFIG_ACCESS user=admin role=admin ip=198.51.100.x alg_from_header=potentially_forged
2024-11-15 03:22:34 INFO ACCESS user=admin role=admin path=/api/v1/admin/system-config ip=198.51.100.x
```

**Key anomalies:**
1. `JWKS_FETCH` followed within seconds by `ADMIN_CONFIG_ACCESS` from the same IP
2. An `admin` user accessing the API who never performed a `LOGIN_OK` event
3. `ADMIN_CONFIG_ACCESS` log line (the application logs this warning specifically)
4. Admin access from an external IP (the permit portal admin should only be accessed internally)

### 1.2 — Detecting the Forged Token Structure

Extract and analyse the JWT used in the malicious request:

```bash
# From nginx/application access logs, extract the Authorization header
# Then decode the JWT header without verification:
TOKEN="eyJhbGciOiJIUzI1NiI..."  # extracted from log/packet capture

echo "$TOKEN" | cut -d'.' -f1 | base64 -d 2>/dev/null
# Output: {"alg":"HS256","kid":"rpal-permit-2024-v1","typ":"JWT"}
#                  ^^^^
#         This should ALWAYS be RS256 for tokens issued by this server.
#         HS256 indicates a forged token.
```

**The single strongest indicator:** Any JWT with `"alg":"HS256"` received by this portal is forged. The portal only issues RS256 tokens. There is no legitimate HS256 token that should ever appear.

### 1.3 — Network-Level Detection

Capture and inspect HTTPS traffic (if TLS inspection is in place) or analyse HAProxy/nginx access logs:

**Snort/Suricata Rule:**
```
# Detect JWKS fetch followed by admin API access from same source
alert http $EXTERNAL_NET any -> $HTTP_SERVERS 8443 (
  msg:"DEEPSTRIKE:RPAL JWKS endpoint enumeration from external source";
  content:"GET"; http_method;
  content:"/.well-known/jwks.json"; http_uri;
  threshold: type both, track by_src, count 1, seconds 60;
  classtype:web-application-attack;
  sid:9001101; rev:1;
)

alert http $EXTERNAL_NET any -> $HTTP_SERVERS 8443 (
  msg:"DEEPSTRIKE:RPAL admin system-config access from external source";
  content:"GET"; http_method;
  content:"/api/v1/admin/system-config"; http_uri;
  content:"Authorization"; http_header;
  classtype:web-application-attack;
  sid:9001102; rev:1;
)
```

### 1.4 — What Normal Looks Like (Baseline)

For effective anomaly detection, understand the baseline:
- JWKS endpoint is fetched by DGH OIDC clients — typically from known DGH IP ranges (not arbitrary external IPs)
- Admin API endpoints are never accessed from external internet IPs in normal operation
- No admin user ever logs in directly — admin operations use service accounts with known IPs
- JWT tokens always have `alg: RS256` — this is invariant

---

## 2. Why This Attack is Hard to Detect

**Legitimate traffic pattern:** JWKS endpoint access is expected and normal for any OIDC consumer. A WAF rule that blocks JWKS access would break DGH federation.

**No authentication failure:** The forged token passes cryptographic verification — from the server's perspective, the token is valid. There are no 401 responses in the log that would indicate an attack in progress.

**Admin access looks structured:** The attacker makes a clean API call to a known endpoint. There is no scanning, fuzzing, or error traffic that would trigger standard anomaly detection.

**The tell is in the JWT header:** The single distinguishing feature — `alg: HS256` — requires inspecting the actual token content, not just access patterns. Most WAFs and SIEMs do not automatically decode JWT headers from Authorization headers.

---

## 3. Detection Queries

### Splunk/ELK Query — Detect HS256 Tokens

```spl
index=rpal-permit-portal sourcetype=access_log
| rex field=authorization "Bearer (?<jwt_header>[^.]+)\."
| eval decoded_header=base64decode(jwt_header)
| where like(decoded_header, "%HS256%")
| table _time, src_ip, uri_path, decoded_header
| sort -_time
```

### Splunk — Admin Access Without Prior Login

```spl
index=rpal-permit-portal
| transaction src_ip startswith="LOGIN_OK" endswith="ADMIN_CONFIG_ACCESS" maxspan=1h
| where NOT match(raw, "LOGIN_OK")
| table _time, src_ip, action
```

### Python Log Parser (if Splunk not available)

```python
#!/usr/bin/env python3
"""Detect JWT algorithm confusion in RPAL permit portal logs."""
import re, base64, json, sys

LOG_FILE = '/var/log/rpal/permit-portal/access.log'

def decode_jwt_header(token):
    try:
        header_b64 = token.split('.')[0]
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += '=' * padding
        return json.loads(base64.urlsafe_b64decode(header_b64))
    except Exception:
        return {}

BEARER_RE = re.compile(r'Bearer ([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)')

with open(LOG_FILE) as f:
    for line in f:
        m = BEARER_RE.search(line)
        if m:
            header = decode_jwt_header(m.group(1))
            if header.get('alg') == 'HS256':
                print(f"[ALERT] HS256 TOKEN DETECTED:")
                print(f"  Line:    {line.strip()}")
                print(f"  Header:  {header}")
                print()
```

---

## 4. Containment

### Immediate (< 5 minutes)

```bash
# Block the attacker's IP at firewall
iptables -I INPUT -s <attacker_ip> -p tcp --dport 8443 -j DROP

# Revoke all active sessions (rotate the Flask secret key — invalidates all cookies)
# Edit /opt/rpal/permit-portal/app/app.py
# Change: app.secret_key = os.urandom(32)
# To: app.secret_key = os.urandom(32)   # generate new random bytes
# Then restart:
systemctl restart rpal-permit-portal

# Rotate JWT private key (invalidates all outstanding JWTs)
python3 -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
key = rsa.generate_private_key(65537, 2048)
with open('/etc/rpal/jwt/private.pem','wb') as f:
    f.write(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
with open('/etc/rpal/jwt/public.pem','wb') as f:
    f.write(key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
"
systemctl restart rpal-permit-portal
```

### Short-term (< 1 hour)

```bash
# Restrict admin API endpoints to internal IPs only
# Add to nginx config or HAProxy ACL in front of the portal:
# /api/v1/admin/* → only 10.0.0.0/8 or 203.x.x.x/24 internal ranges

# Review all admin API access in last 24 hours
grep "ADMIN_CONFIG_ACCESS\|/api/v1/admin" /var/log/rpal/permit-portal/access.log

# Identify what data was accessed (what the attacker saw)
# The system_config table contains downstream API credentials — treat all as compromised
```

---

## 5. Eradication

### Fix the JWT Library

```bash
# Upgrade PyJWT to a non-vulnerable version
pip3 install "pyjwt>=2.8.0"

# Verify
python3 -c "import jwt; print(jwt.__version__)"
# Should show 2.8.x or later
```

### Fix the Application Code

In `/opt/rpal/permit-portal/app/app.py`, change the `verify_token` function:

**Vulnerable (current):**
```python
decoded = jwt.decode(
    token,
    PUBLIC_KEY_PEM,
    algorithms=['RS256', 'HS256'],   # VULNERABILITY: accepts HS256
)
```

**Fixed:**
```python
# PyJWT >= 2.0 requires the key to match the algorithm type
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

decoded = jwt.decode(
    token,
    PUBLIC_KEY,              # Pass the RSAPublicKey object, not raw bytes
    algorithms=['RS256'],    # ONLY RS256 — never accept symmetric algorithms
    options={'require': ['exp', 'iss', 'sub']},
    issuer='https://permit.rpal.in',
)
```

**Why this fixes it:**
1. PyJWT >= 2.4.0 validates that the key type matches the algorithm. Passing an `RSAPublicKey` object with `algorithms=['RS256']` means HS256 tokens will be rejected regardless of what the header says.
2. Removing HS256 from the allowed list means even if the library had a future bug, HS256 would not be processed.

### Rotate All Downstream Credentials

The attacker accessed `/api/v1/admin/system-config` which contains credentials for M2 (GraphQL API) and M3 (SOAP gateway). **All of these must be treated as compromised and rotated immediately:**

```
graphql_service_pass  → Rotate at GraphQL API service
graphql_api_key       → Rotate at GraphQL API gateway
```

### Restrict JWKS Endpoint Access

```nginx
# nginx configuration — restrict JWKS to known DGH IP ranges
location /.well-known/jwks.json {
    # Allow DGH OIDC consumers
    allow 10.0.0.0/8;        # internal
    allow 192.0.2.0/24;      # DGH registered IPs
    deny all;
    proxy_pass http://permit-backend;
}
```

**Why:** While the public key is public, restricting who can fetch the JWKS reduces reconnaissance surface. Legitimate OIDC consumers (DGH) have known, stable IPs.

---

## 6. Remediation — Permanent Fix

### Architectural Fix

The root cause is conflating the JWT verification key format with the algorithm. The secure pattern is:

```python
# SECURE PATTERN — PyJWT >= 2.0
from cryptography.hazmat.primitives.serialization import load_pem_public_key

PUBLIC_KEY_OBJ = load_pem_public_key(open('/etc/rpal/jwt/public.pem', 'rb').read())

def verify_token_secure(token: str) -> dict:
    # Verify RS256 only — key object type prevents algorithm substitution
    return jwt.decode(
        token,
        PUBLIC_KEY_OBJ,          # RSAPublicKey object — incompatible with HS256
        algorithms=['RS256'],    # Strict single-algorithm allowlist
        options={
            'require': ['exp', 'iss', 'sub', 'jti'],
            'verify_iss': True,
            'verify_exp': True,
        },
        issuer='https://permit.rpal.in',
    )
```

### Why This Attack Exists (Systemic Issue)

The developer correctly understood that exposing the RSA public key is standard practice. What was not understood is:

1. JWT libraries in older versions trust the token's own `alg` claim
2. When a library accepts both asymmetric (RS256) and symmetric (HS256) algorithms for the same key parameter, an attacker can substitute algorithms
3. The RSA public key — while "public" — should never be usable as a symmetric secret

**Industry Reference:** PortSwigger Web Security Academy — JWT attacks (algorithm confusion). RFC 8725 §3.1 (JSON Web Token Best Current Practices): "Require the use of a specific set of algorithms."

---

## 7. Lessons Learned

**What failed at RPAL:**
1. **Dependency management:** PyJWT 1.7.1 was not the latest stable version. No automated dependency scanning (SCA tool) was running.
2. **Security review gap:** The 48-hour deployment window meant no cryptography review by a qualified security engineer.
3. **Over-permissive algorithm list:** The developer added HS256 "for flexibility" without understanding the security implications of accepting multiple algorithm types against the same key material.
4. **Admin API accessible from internet:** The `/api/v1/admin/*` endpoints should never be reachable from the public internet regardless of authentication.
5. **No JWT content inspection at WAF:** The WAF was not configured to decode and inspect JWT headers — a capability that would have detected the `alg: HS256` anomaly in real-time.

**What would have prevented this:**
- PyJWT >= 2.4.0 (released 2022) makes algorithm confusion impossible
- Software Composition Analysis (SCA) in the CI/CD pipeline would flag vulnerable dependencies
- `algorithms=['RS256']` — single algorithm, fixed server-side
- Admin API endpoints behind a separate internal-only service or IP allowlist

---

*solve_blue.md | M1 ext-permit-portal | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
