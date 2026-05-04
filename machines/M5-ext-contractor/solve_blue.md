# solve_blue.md — M5 · ext-contractor
## Blue Team Detection, Containment & Remediation
**Vulnerability:** wkhtmltopdf 0.12.5 SSRF via file:// URI

---

## 1. What the Attack Looks Like

### Application Log
```
2024-11-15 05:44:31 INFO APPLICATION user=contractor.01 company=NEEL-TRISHUL-OPS profile_url=file:///etc/rpal/upstream/config.ini ip=198.51.100.x
2024-11-15 05:44:32 INFO PDF_GENERATE app=A9B3F2D1 profile_url=file:///etc/rpal/upstream/config.ini
2024-11-15 05:44:35 INFO PDF_SUCCESS app=A9B3F2D1 size=89432
```

**Strongest indicator:** `company_profile_url` containing `file://` — this should never occur in legitimate use.

### Suricata — Detect file:// in POST body
```
alert http $EXTERNAL_NET any -> $HTTP_SERVERS 9000 (
  msg:"DEEPSTRIKE:SSRF via file:// URI in contractor portal application";
  content:"POST"; http_method;
  content:"/apply"; http_uri;
  content:"file%3A%2F%2F"; http_client_body; nocase;
  classtype:web-application-attack;
  sid:9001501; rev:1;
)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS 9000 (
  msg:"DEEPSTRIKE:SSRF file:// unencoded in contractor portal";
  content:"POST"; http_method;
  content:"file:///"; http_client_body;
  classtype:web-application-attack;
  sid:9001502; rev:1;
)
```

---

## 2. Containment

```bash
# Block attacker IP
iptables -I INPUT -s <ip> -p tcp --dport 9000 -j DROP

# Restrict wkhtmltopdf from reading sensitive paths
# Add wkhtmltopdf execution wrapper:
cat > /usr/local/bin/wkhtmltopdf-safe << 'WRAPPER'
#!/bin/bash
# Block file:// scheme
for arg in "$@"; do
    if echo "$arg" | grep -qiE '^file://'; then
        echo "ERROR: file:// URI blocked by security policy" >&2
        exit 1
    fi
done
exec /usr/local/bin/wkhtmltopdf.real "$@"
WRAPPER
chmod +x /usr/local/bin/wkhtmltopdf-safe

# The config file was read — rotate all credentials immediately:
# 1. Regenerate SSH key: ssh-keygen -t rsa -b 4096 -f /etc/rpal/upstream/svc-deploy-rsa
# 2. Change LDAP bind_password: contact AD admin
# 3. Rotate API keys: graphql_api_key, soap service password
```

---

## 3. Remediation — Permanent Fix

```python
# In app.py — validate company_profile_url before passing to wkhtmltopdf
from urllib.parse import urlparse

def validate_profile_url(url: str) -> bool:
    """Only allow http:// and https:// schemes from external hosts."""
    if not url:
        return True  # Empty is fine
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    # Only allow HTTP/HTTPS
    if parsed.scheme not in ('http', 'https'):
        return False
    # Block private/internal IP ranges
    import ipaddress, socket
    try:
        host = parsed.hostname
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except Exception:
        pass
    return True

# Additionally — upgrade wkhtmltopdf to 0.12.6+
# and remove --enable-local-file-access flag entirely:
cmd = [
    WKHTMLTOPDF,
    '--quiet',
    '--disable-local-file-access',  # Secure default in 0.12.6+
    html_file,
    # Only add profile URL after validation
]
if company_profile_url and validate_profile_url(company_profile_url):
    cmd.append(company_profile_url)
cmd.append(pdf_file)
```

---

## 4. Lessons Learned
1. wkhtmltopdf 0.12.5 is an 8-year-old tool. Dependency age reviews must include PDF generation libraries.
2. `--enable-local-file-access` should never be used in production. There is no legitimate reason for a web application's PDF generator to read local files.
3. Sensitive credentials must never be stored in config files accessible to web application processes. Use Vault, AWS SM, or environment variables injected at runtime.
4. User-controlled URLs passed to server-side fetchers must be validated for scheme (http/https only) AND internal IP range exclusion.

---
*solve_blue.md | M5 ext-contractor | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
