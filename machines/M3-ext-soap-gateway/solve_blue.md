# solve_blue.md — M3 · ext-soap-gateway
## Blue Team Detection, Containment & Remediation
**Vulnerability:** XXE → SSRF → IMDS Credential Extraction

---

## 1. What the Attack Looks Like

### Log Indicators
```
# XXE SSRF attempt logged by application
2024-11-15 04:12:33 CRITICAL XXE_SSRF_DETECTED IMDS_ACCESS ip=198.51.100.x content_preview=...169.254.169.254...
2024-11-15 04:12:33 WARNING SOAP_REQUEST size=847 ip=198.51.100.x action=CalculateTariff
```

### Network-Level — Outbound Connections from Server
```bash
# Monitor for IMDS access (should never originate from app process)
tcpdump -i any dst 169.254.169.254 -nn
# Any traffic to 169.254.169.254 from the tariff gateway process is a red flag
```

### Suricata Rule
```
alert http $HTTP_SERVERS any -> 169.254.169.254 80 (
  msg:"DEEPSTRIKE:SSRF to cloud instance metadata service from SOAP gateway";
  flow:established,to_server;
  classtype:web-application-attack;
  sid:9001301; rev:1;
)

alert http $EXTERNAL_NET any -> $HTTP_SERVERS 8080 (
  msg:"DEEPSTRIKE:XXE DOCTYPE declaration in SOAP request";
  content:"POST"; http_method;
  content:"DOCTYPE"; http_client_body; nocase;
  content:"ENTITY"; http_client_body; nocase;
  classtype:web-application-attack;
  sid:9001302; rev:1;
)
```

---

## 2. Containment

```bash
# Block IMDS access from application processes
iptables -I OUTPUT -d 169.254.169.254 -p tcp -m owner --uid-owner rpal-tariff -j DROP

# Rotate IAM role credentials (rotate the instance role in OpenStack/AWS)
# The extracted credentials have a 6-hour TTL — rotate the instance profile immediately

# Block attacker IP
iptables -I INPUT -s <attacker_ip> -p tcp --dport 8080 -j DROP
```

---

## 3. Remediation — Permanent Fix

```python
# SECURE: lxml parser configuration
parser = etree.XMLParser(
    resolve_entities=False,    # Disable external entity resolution
    no_network=True,           # Block all network access during parsing
    load_dtd=False,            # Disable DTD loading entirely
    huge_tree=False            # Prevent billion laughs / XML bomb
)

# Additionally — block IMDS from the host network namespace:
# iptables -A OUTPUT -d 169.254.169.254 -j DROP
# (Apply at host level, not just application level)

# Use IMDSv2 with hop limit 1 (AWS) to prevent SSRF exploitation of IMDS
# aws ec2 modify-instance-metadata-options \
#   --instance-id <id> \
#   --http-put-response-hop-limit 1 \
#   --http-endpoint enabled \
#   --http-tokens required
```

---

## 4. Lessons Learned

1. XML parsers must always be configured with external entity resolution disabled. There is no legitimate use case for accepting external DTD references from untrusted input.
2. The IMDS endpoint must be blocked at the host network level, not just the application level. Defense-in-depth means SSRF cannot reach IMDS even if the app is vulnerable.
3. IAM role credentials should have minimum necessary permissions — the `rpal-upstream-api-role` had access to admin export endpoints it should not have.
4. WAFs must include XXE detection rules — `DOCTYPE` and `ENTITY` keywords in POST bodies are almost always attack signatures for SOAP/XML services.

---
*solve_blue.md | M3 ext-soap-gateway | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
