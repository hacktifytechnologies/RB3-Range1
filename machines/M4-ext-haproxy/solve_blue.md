# solve_blue.md — M4 · ext-survey-portal
## Blue Team Detection, Containment & Remediation

## 1. Detection
```
journalctl -u rpal-survey-portal | grep "execSync\|require\|child_process"
```
Suricata: `alert http any -> any 3000 (content:"execSync"; http_client_body; sid:9001401;)`

## 2. Containment
Restart service. Add input validation rejecting `<%` in template field.

## 3. Remediation
Never pass user input directly to `ejs.render(template, data)`.
The template must be server-controlled. User input is passed as DATA, not template code:
```javascript
// FIXED
const REPORT_TEMPLATE = 'Site: <%= site %>\nDate: <%= date %>';
const output = ejs.render(REPORT_TEMPLATE, { site: req.body.site, date: new Date() });
```
