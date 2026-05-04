# RNG-EXT-01 · SETU DVAAR
## OPERATION DEEPSTRIKE — External Portal Zone
### Rashtriya Petroleum Anveshan Limited (RPAL) — URJA DRISHTI 2.0 Platform

---

**Range:** RNG-EXT-01 · SETU DVAAR (The Gateway)
**Zone:** v-Public — `203.0.0.0/8` — Subnet: `203.x.x.x/24`
**Entry Point:** External internet-facing systems (initial access vector)
**Pivot To:** RNG-EXT-02 (`203.x.x.x`) via SSH key + LDAP credentials extracted from M5

---

## Machine Manifest

| # | Slug | Service | Port | Vulnerability Class | Difficulty |
|---|---|---|---|---|---|
| M1 | ext-permit-portal | RPAL Exploration Permit Portal | 443/8443 | JWT Algorithm Confusion (RS256→HS256) | Hard |
| M2 | ext-graphql-api | RPAL Exploration Data API | 4000 | GraphQL Field Suggestion + Missing AuthZ on batchQuery | Hard |
| M3 | ext-soap-gateway | RPAL Pipeline Tariff SOAP Gateway | 8080 | XXE → SSRF → Internal IMDS Token Extraction | Extreme |
| M4 | ext-haproxy | RPAL API Gateway (HAProxy) | 80/8000 | HTTP Request Smuggling (CL.TE) — Session Hijack | Extreme |
| M5 | ext-contractor | RPAL Contractor Onboarding Portal | 9000 | wkhtmltopdf SSRF → Config File Read → Pivot Credentials | Hard |

---

## Credential / Access Chain

```
[External Internet] → M1 Permit Portal
  JWT Algorithm Confusion → admin token
  → /api/v1/admin/system-config → GraphQL API credentials
    (graphql_user: rpal-explore-svc / T@riff@Expl0re!24)

M2 GraphQL API (port 4000)
  batchQuery AuthZ bypass → internal employee enumeration
  → svc-upstream-api credentials extracted
    (X-API-Key: RPAL-API-2024-XK9mP3nT8qRs)

M3 SOAP Gateway (port 8080)
  XXE → SSRF → http://169.254.169.254/latest/meta-data/...
  → IAM role credentials (AccessKeyId, SecretAccessKey, Token)
  → Valid for internal API gateway at 203.x.x.x:8000

M4 HAProxy Gateway (port 80)
  HTTP Request Smuggling → capture victim session token
  → rpal-permit-officer session → /api/v2/admin/export
  → Corporate LDAP bind credential extracted

M5 Contractor Portal (port 9000)
  wkhtmltopdf SSRF → file:///etc/rpal/upstream/config.ini
  → SSH private key path + LDAP credentials for RNG-EXT-02
  → PIVOT: devops@203.x.x.x (corporate IT backbone)
```

---

## Setup Instructions

Each machine is a standalone Ubuntu 22.04 OpenStack VM. Deploy in order M1 → M5:

```bash
# On each VM:
sudo bash machines/MX-ext-<slug>/deps.sh     # internet required
sudo bash machines/MX-ext-<slug>/setup.sh    # no internet required
sudo bash Honeytraps/MX-ext-<slug>.sh        # deploy decoy services
```

---

## Kill Chain Coverage (Lockheed Martin)

| Phase | Machine | Activity |
|---|---|---|
| Reconnaissance | M1 | JWKS endpoint enumeration, JWT structure analysis |
| Weaponisation | M1 | RSA public key extraction → HS256 secret derivation |
| Delivery | M2 | GraphQL schema reconstruction via suggestions |
| Exploitation | M3 | XXE payload → SSRF → cloud metadata extraction |
| Installation | M4 | Request smuggling → session token capture → admin access |
| C2 | M4→M5 | LDAP credential extraction → contractor portal pivot |
| Actions on Objectives | M5 | Config file SSRF → SSH key exfil → corporate zone entry |

---

## Key Personas

| Character | Role | Relevance |
|---|---|---|
| Vikram Nair | IT Infrastructure Head | Introduced JWT algorithm confusion during rushed deployment |
| Varuna-2 | NEEL TRISHUL Web Operator | Primary operator for this range |
| Dr. Sunita Pillai | CISO | Blue team incident response anchor |

---

*RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE*
*Classification: RESTRICTED — Exercise Staff Only*
*Rashtriya Petroleum Anveshan Limited URJA DRISHTI 2.0 | © 2026 Hacktify Cybersecurity*
