# Network Diagram — RNG-EXT-01 · SETU DVAAR
## OPERATION DEEPSTRIKE | External Portal Zone

---

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                         INTERNET (External Attackers)                            ║
║                         NEEL TRISHUL / Varuna-2                                  ║
╚═══════════════════════════════════════════════════╦═══════════════════════════════╝
                                                    │
                                         ┌──────────▼──────────┐
                                         │   INTERNET EDGE     │
                                         │   Firewall / ISP    │
                                         │   BGP AS 9587       │
                                         └──────────┬──────────┘
                                                    │
═══════════════════════════════════════════════════ │ ══════════════════════
                v-Public Zone — 203.x.x.0/24        │
═══════════════════════════════════════════════════ │ ══════════════════════
                                                    │
              ┌─────────────────────────────────────┼─────────────────────────────┐
              │              OpenStack Virtual Switch / OVS                        │
              │              VLAN: v-Public (203.x.x.0/24)                        │
              └──────┬──────────────┬──────────────┬──────────────┬───────────────┘
                     │              │              │              │              │
         ┌───────────▼──┐   ┌───────▼──────┐  ┌───▼──────────┐ │  ┌───────────▼──┐
         │   M1          │   │   M2          │  │   M3          │ │  │   M5          │
         │  203.x.x.10  │   │  203.x.x.20  │  │  203.x.x.30  │ │  │  203.x.x.50  │
         │              │   │              │  │              │ │  │              │
         │ ext-permit   │   │ ext-graphql  │  │ ext-soap     │ │  │ ext-contractor│
         │ portal       │   │ api          │  │ gateway      │ │  │ portal       │
         │              │   │              │  │              │ │  │              │
         │ JWT Confusion│   │ GraphQL      │  │ XXE→SSRF     │ │  │ wkhtmltopdf │
         │ PyJWT 1.7.1  │   │ batchQuery   │  │ →IMDS Creds  │ │  │ file:// SSRF │
         │              │   │ AuthZ Bypass │  │              │ │  │              │
         │ :8443  HTTPS │   │ :4000 GQL    │  │ :8080 SOAP   │ │  │ :9000 HTTP   │
         │ :7443  QHSE  │   │ :4001 Apollo │  │ :8081 PNGRB  │ │  │ :9001 VMS    │
         │ :9443  DGH   │   │ :3100 Hasura │  │ :9090 SCADA  │ │  │ :7443 HSE    │
         │ :8880  Env   │   │ :5000 Swagger│  │ :7080 WSSec  │ │  │ :8800 Invoice│
         │ :8009  AJP   │   │ :6379 Redis  │  │ :443  TLS    │ │  │ :8883 MQTT   │
         │ :9418  Git   │   │ :5672 AMQP   │  │ :502  Modbus │ │  │ :21   FTP    │
         │ :636   LDAPS │   │ :8883 MQTT   │  │ :102  S7 PLC │ │  │ :3306 MySQL  │
         │ :25    SMTP  │   │ :9200 ES     │  │ :10514 Syslog│ │  │ :445  SMB    │
         └──────────────┘   └──────────────┘  └──────────────┘ │  └──────────────┘
                                                                │
                                              ┌─────────────────▼─────────────────┐
                                              │              M4                    │
                                              │          203.x.x.40               │
                                              │                                   │
                                              │     ext-haproxy                   │
                                              │                                   │
                                              │  :80   HAProxy Frontend           │
                                              │  :8000 Flask Backend (internal)   │
                                              │  :8404 Kong Manager               │
                                              │  :8500 Consul Dashboard           │
                                              │  :9411 Zipkin Tracing             │
                                              │  :8443 HTTPS Endpoint             │
                                              │  :9999 HAProxy Runtime API        │
                                              │  :514  Syslog Relay               │
                                              │  :2003 Carbon Metrics             │
                                              │                                   │
                                              │  Internal: rpal-apigw-monitor     │
                                              │  (probes backend every 10s        │
                                              │   with privileged Bearer token)   │
                                              └───────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════════
                INTERNAL SIMULATION (link-local / loopback)
═══════════════════════════════════════════════════════════════════════════════════

         169.254.169.254:80 ──iptables DNAT──► 127.0.0.1:8080/imds/
         (IMDS simulation on M3 — SSRF target for XXE attack)

═══════════════════════════════════════════════════════════════════════════════════
                PIVOT EGRESS — to RNG-EXT-02
═══════════════════════════════════════════════════════════════════════════════════

         M5 SSRF Output:                     ─────────────────────────────────►
           file:///etc/rpal/upstream/config.ini    SSH: svc-deploy@203.x.x.x:22
           → SSH private key extracted              Passphrase: Deploy@SSH!RPAL24Corp
           → LDAP bind_password extracted           LDAP: 203.x.x.x:389
                                                    bind: cn=svc-api-gateway,...
                                                    pass: Ldap@GW!Bind2024#RPAL
                                                         │
                                                         ▼
                                               RNG-EXT-02 · PRAHARI KENDRA
                                               (Corporate IT Zone)
```

---

## Machine IP Assignments

| Machine | Hostname | IP | Primary Port | Role |
|---|---|---|---|---|
| M1 | permit.rpal.in | 203.x.x.10 | 8443 | JWT Confusion — Entry |
| M2 | explore-api.rpal.in | 203.x.x.20 | 4000 | GraphQL AuthZ Bypass |
| M3 | tariff-gw.rpal.in | 203.x.x.30 | 8080 | XXE → SSRF → IMDS |
| M4 | api-gw.rpal.in | 203.x.x.40 | 80 | HTTP Smuggling |
| M5 | contractor.rpal.in | 203.x.x.50 | 9000 | wkhtmltopdf SSRF → Pivot |

## Attack Flow Summary

```
[Attacker] → M1:8443 (JWT confusion → admin token → GraphQL creds)
          → M2:4000 (batchQuery AuthZ bypass → SOAP creds)
          → M3:8080 (XXE SSRF → 169.254.169.254 → IAM creds)
          → M4:80   (CL.TE smuggling → capture monitor token → admin export → LDAP creds)
          → M5:9000 (wkhtmltopdf file:// → config.ini → SSH key + LDAP)
          → PIVOT: ssh -i svc-deploy-rsa svc-deploy@203.x.x.x (RNG-EXT-02)
```

*RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE*
