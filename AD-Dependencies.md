# AD-Dependencies.md — RNG-EXT-01 · SETU DVAAR
## Active Directory & Infrastructure Dependencies

**Note:** This range does not have a domain-joined Active Directory. Authentication is via LDAP (OpenLDAP/AD-compatible) and JWT. The AD integration is simulated at M4 admin export which returns LDAP bind credentials for the corporate AD in RNG-EXT-02.

---

## Inter-Machine Dependencies

| Machine | Depends On | Dependency Type | Details |
|---|---|---|---|
| M2 | M1 | Credentials | graphql_api_key from M1 system-config |
| M3 | M2 | Credentials | SOAP service account from M2 batchQuery |
| M4 | M3 | Workflow | IMDS creds from M3 guide to M4 admin endpoint |
| M5 | M4 | Credentials | LDAP credentials from M4 admin export |
| RNG-EXT-02 M1 | M5 | SSH Key | svc-deploy-rsa from M5 SSRF config read |

## Network Dependencies

| Service | Port | Protocol | Internal Only |
|---|---|---|---|
| M4 Backend | :8000 | HTTP | YES — only via HAProxy :80 |
| M4 rpal-apigw-monitor | internal | HTTP | YES — loops back to :80 |
| M3 IMDS Simulation | 169.254.169.254:80 | HTTP | YES — iptables DNAT |

## External Dependencies (none)
This range has zero external dependencies. All services use:
- System fonts only (no Google Fonts)
- Local SQLite databases
- Self-signed certificates (if TLS)
- Python stdlib + pip packages (installed during deps.sh)

---

*AD-Dependencies.md | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
