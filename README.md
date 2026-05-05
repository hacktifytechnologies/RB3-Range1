# RNG-EXT-01 · SETU DVAAR
## OPERATION DEEPSTRIKE — External Portal Zone
### Rashtriya Petroleum Anveshan Limited (RPAL) — URJA DRISHTI 2.0 Platform

**Range:** RNG-EXT-01 · SETU DVAAR | **Zone:** v-Public 203.x.x.x/24
**Pivot To:** RNG-EXT-02 via SSH key from M5 /admin/export

## Machine Manifest

| # | Slug | Service | Port | Vulnerability | Difficulty |
|---|---|---|---|---|---|
| M1 | ext-permit-portal | RPAL Exploration Permit Portal | 8443 | JWT Algorithm Confusion RS256→HS256 | Hard |
| M2 | ext-graphql-api | RPAL Exploration Data API | 4000 | GraphQL Field Suggestion + batchQuery AuthZ Bypass | Hard |
| M3 | ext-soap-gateway | RPAL Pipeline Tariff SOAP Gateway | 8080 | XXE → SSRF → IMDS Credential Extraction | Extreme |
| M4 | ext-survey-portal | RPAL Geological Survey Analytics Portal | 3000 | EJS Server-Side Template Injection → RCE | Medium |
| M5 | ext-contractor-portal | RPAL Contractor Registration System | 4000 | Exposed .git → Hardcoded Token → SSH Key | Medium |

## Credential Chain

```
M1 → JWT admin → graphql_api_key: RPAL-API-2024-XK9mP3nT8qRs
M2 → batchQuery bypass → rpal-tariff-svc / TariffGW@Soap!2024#RPAL
M3 → XXE SSRF IMDS → AccessKeyId + 64-char Token → endpoint :3000
M4 → IMDS login → EJS SSTI RCE → RPAL-CONTRACTOR-API-2024-xK9mP3nT8qRs7vL2
M5 → .git dump → RPAL-ADMIN-TOKEN-2024-9c4e2a8f1b7d3e6a → SSH key → RNG-EXT-02
```

## Setup

```bash
sudo bash machines/MX-ext-<slug>/deps.sh
sudo bash machines/MX-ext-<slug>/setup.sh
sudo bash Honeytraps/MX-ext-<slug>.sh
```

M1-M3: Python 3.10 + Flask. M4-M5: Node.js + Express.

## Technology Stack

| Machine | Runtime | Key Dependency | Vulnerability Mechanism |
|---|---|---|---|
| M1 | Python 3.10 | cryptography==41.0.7 | Manual JWT — HS256 uses PUBLIC_KEY_PEM as HMAC secret |
| M2 | Python 3.10 | strawberry-graphql==0.219.2 | batchQuery resolver missing @require_auth |
| M3 | Python 3.10 | lxml | resolve_entities=True, no_network=False |
| M4 | Node.js | ejs==3.1.9 | ejs.render(user_template, data) — user controls template |
| M5 | Node.js | express.static | dotfiles:'allow' exposes .git directory over HTTP |

## Key Personas

| Character | Role | Machine |
|---|---|---|
| Arjun Mehta | DevOps Engineer | M5 git history, M4 credential file |
| Kavita Rao | Geological Survey Lead | M4 service account |
| Vikram Nair | IT Infrastructure Head | M1 rushed deployment |
| Dr. Sunita Pillai | CISO | Blue team anchor |

*RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE | © 2026 Hacktify Cybersecurity*
