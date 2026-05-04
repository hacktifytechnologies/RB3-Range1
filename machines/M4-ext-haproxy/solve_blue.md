# solve_blue.md — M4 · ext-haproxy
## Blue Team Detection, Containment & Remediation
**Vulnerability:** HTTP Request Smuggling (CL.TE) — Session Token Capture

---

## 1. What the Attack Looks Like

### Log Indicators
```
# Backend logs — suspect when /api/v2/permits/submit receives what looks like partial HTTP
2024-11-15 05:01:14 WARNING SMUGGLED_REQUEST_DETECTED content_preview=GET /api/v2/admin/export... ip=198.51.100.x
2024-11-15 05:01:24 WARNING ADMIN_EXPORT_ACCESS ip=198.51.100.x service=apigw-permit-monitor

# The tell: admin/export accessed from an EXTERNAL IP (monitor always comes from 127.0.0.1)
# X-Forwarded-For header on admin/export request shows attacker IP, not internal
```

**Strongest indicator:** `/api/v2/admin/export` accessed with a valid token, but `X-Forwarded-For` shows an external IP. The monitor always runs on localhost — external access with the monitor's token is impossible without smuggling.

### Network-Level — Anomalous Timing
HAProxy access logs show two requests in rapid succession from the attacker's IP, where the second request receives the monitor's response body. Duration anomaly: the second request's response time is shorter than expected (backend already had the response ready in buffer).

### Suricata Rule
```
alert http $EXTERNAL_NET any -> $HTTP_SERVERS 80 (
  msg:"DEEPSTRIKE:HTTP Request Smuggling CL.TE attempt";
  content:"Transfer-Encoding"; http_header;
  content:"Content-Length"; http_header;
  content:"chunked"; http_header;
  pcre:"/^0\r\n\r\n[A-Z]+(ET|OST|UT|ELETE) \//Ps";
  classtype:web-application-attack;
  sid:9001401; rev:1;
)
```

---

## 2. Containment

```bash
# Immediate: normalise Transfer-Encoding at HAProxy (add to frontend config)
# In /etc/haproxy/haproxy.cfg, add to frontend:
#   http-request del-header Transfer-Encoding
# This prevents TE headers from reaching the backend — breaks CL.TE desync

# Restart HAProxy
haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl restart haproxy

# Rotate monitor service token seed (invalidates all captured tokens)
# Edit /opt/rpal/api-gateway/app/monitor.py
# Change: STATIC_SEED = "RPAL-APIGW-PERMIT-MONITOR-SEED-DEEPSTRIKE-EXERCISE"
# To:     STATIC_SEED = "$(openssl rand -hex 32)"
systemctl restart rpal-apigw-monitor

# Block attacker IP
iptables -I INPUT -s <ip> -p tcp --dport 80 -j DROP
```

---

## 3. Remediation — Permanent Fix

```
# In haproxy.cfg frontend section — add these BEFORE default_backend:
http-request del-header Transfer-Encoding     # Strip TE before forwarding
option http-server-close                      # Prevent persistent backend connections
http-request deny if { req.body_len gt 0 } { req.hdr(Transfer-Encoding) -m found }
```

**Why:** Deleting the `Transfer-Encoding` header before forwarding means the backend only sees `Content-Length`. The CL.TE desync requires BOTH headers to reach the backend — removing one eliminates the vulnerability.

**Additionally:** Use HAProxy 2.6+ which has `option http-restricted-characters` and improved header validation by default.

---

## 4. Lessons Learned

1. HAProxy version matters — versions < 2.2 are vulnerable to CL.TE by default. Upgrade and review all reverse proxy configurations after major version changes.
2. Admin API endpoints must validate the source IP, not just the token. A token from `127.0.0.1` being used from `203.x.x.x` is an anomaly that should trigger an alert and automatic token invalidation.
3. Monitor/health-check services should use short-lived tokens that rotate frequently and are tied to the source IP of the service.
4. HTTP request smuggling is detectable at the WAF/IDS level if you inspect for requests containing both CL and TE headers simultaneously.

---
*solve_blue.md | M4 ext-haproxy | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
