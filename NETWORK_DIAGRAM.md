# Network Diagram — RNG-EXT-01 · SETU DVAAR

```
╔══════════════════════════════════════════════════════════════════════╗
║          INTERNET — NEEL TRISHUL / Varuna-2                         ║
╚══════════════════════════════════════════╦═══════════════════════════╝
                                           │
                              ┌────────────▼────────────┐
                              │   INTERNET EDGE / ISP   │
                              └────────────┬────────────┘
                                           │
══════════════════════ v-Public Zone — 203.x.x.0/24 ══════════════════

┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│     M1       │ │     M2       │ │     M3       │ │     M4       │ │     M5       │
│ 203.x.x.10  │ │ 203.x.x.20  │ │ 203.x.x.30  │ │ 203.x.x.40  │ │ 203.x.x.50  │
│              │ │              │ │              │ │              │ │              │
│ Permit       │ │ GraphQL      │ │ SOAP         │ │ Survey       │ │ Contractor   │
│ Portal       │ │ API          │ │ Gateway      │ │ Portal       │ │ Registration │
│              │ │              │ │              │ │ (Node.js)    │ │ (Node.js)    │
│ JWT Confusion│ │ batchQuery   │ │ XXE→SSRF     │ │ EJS SSTI     │ │ Exposed .git │
│ :8443        │ │ AuthZ Bypass │ │ →IMDS        │ │ →RCE         │ │ →Admin Token │
│ :7443 QHSE  │ │ :4000        │ │ :8080        │ │ :3000        │ │ →SSH Key     │
│ :9443 DGH   │ │ :4001 Apollo │ │ :8081 PNGRB  │ │ :8888 Jupyter│ │ :4000        │
│ :8880 Env   │ │ :3100 Hasura │ │ :9090 SCADA  │ │ :6006 TBoard │ │ :8080 Tomcat │
│ :9418 Git   │ │ :5000 Swagger│ │ :7080 WSSec  │ │ :9200 ES     │ │ :21   FTP    │
│ :636  LDAPS │ │ :6379 Redis  │ │ :502  Modbus │ │ :5432 PG     │ │ :3306 MySQL  │
│ :25   SMTP  │ │ :8883 MQTT   │ │ :102  S7 PLC │ │ :27017 Mongo │ │ :445  SMB    │
└──────────────┘ └──────────────┘ └──────────────┘ │ :4040 Spark  │ │ :2222 SSH    │
                                                    │ :11434 Ollama│ └──────────────┘
                                                    └──────────────┘

INTERNAL: 169.254.169.254:80 ──iptables DNAT──► M3 Flask IMDS routes

═══════════════════════ CREDENTIAL CHAIN ═══════════════════════

M1 → admin JWT → graphql_api_key (RPAL-API-2024-XK9mP3nT8qRs)
M2 → batchQuery → rpal-tariff-svc / TariffGW@Soap!2024#RPAL
M3 → XXE IMDS → AccessKeyId + 64-char Token → endpoint :3000
M4 → SSTI RCE → RPAL-CONTRACTOR-API-2024-xK9mP3nT8qRs7vL2
M5 → .git → ADMIN_TOKEN → /admin/export → SSH key + passphrase

═══════════════════════ PIVOT → RNG-EXT-02 ═══════════════════════

M5 /admin/export → SSH RSA key + passphrase Deploy@SSH!RPAL24Corp
→ ssh -i svc-deploy-rsa svc-deploy@203.x.x.x → RNG-EXT-02 PRAHARI KENDRA
```

## IP Assignments

| Machine | Hostname | IP | Port | Vulnerability |
|---|---|---|---|---|
| M1 | permit.rpal.in | 203.x.x.10 | 8443 | JWT Algorithm Confusion |
| M2 | explore-api.rpal.in | 203.x.x.20 | 4000 | GraphQL batchQuery AuthZ Bypass |
| M3 | tariff-gw.rpal.in | 203.x.x.30 | 8080 | XXE → SSRF → IMDS |
| M4 | survey.rpal.in | 203.x.x.40 | 3000 | EJS Server-Side Template Injection |
| M5 | contractor.rpal.in | 203.x.x.50 | 4000 | Exposed .git → Hardcoded Token |

*RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE*
