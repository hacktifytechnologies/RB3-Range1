# OPERATION DEEPSTRIKE — RNG-EXT-01 Storyline
## Range: SETU DVAAR — The Gateway

---

## Narrative Context

The digital modernisation of Rashtriya Petroleum Anveshan Limited began in 2022 under the banner of **URJA DRISHTI 2.0** — a ₹2,400 crore programme to integrate RPAL's upstream exploration operations, pipeline management, and safety systems into a unified digital platform. The programme was delivered under intense pressure from the Ministry of Petroleum, with a mandate to complete Phase 1 (external-facing portals) within 18 months.

By November 2024, RPAL's public-facing digital estate is live. Exploration permit officers in DGH (Directorate General of Hydrocarbons) and offshore contractors can now apply for, track, and manage petroleum exploration licenses through RPAL's portal ecosystem. Pipeline tariff calculations are automated. Contractor onboarding is paperless.

But the speed of delivery created technical debt that RPAL's security team — led by **Dr. Sunita Pillai** — has been cataloguing in increasingly urgent memos that go largely unread.

---

## The Attacker's Foothold

**NEEL TRISHUL** operator **Varuna-2** has been conducting OSINT against RPAL for six weeks. The initial reconnaissance identified:

- RPAL's exploration permit portal uses JWT-based authentication
- The portal exposes a JWKS endpoint (`/.well-known/jwks.json`) as part of its OpenID Connect integration with the DGH licensing system
- The JWT library version embedded in the JavaScript bundle suggests a backend running PyJWT 1.7.x — a version vulnerable to algorithm confusion attacks

The portal was built by an external vendor, Vikram Nair's team integrated it in 48 hours during a weekend deployment window, and the security review was deferred to "post-go-live". That review never happened.

---

## The SETU DVAAR Attack Narrative

### M1 — Exploration Permit Portal (JWT Algorithm Confusion)

Varuna-2 begins with the RPAL Exploration Permit Portal. The portal is the external face of RPAL's licensing operations — it processes applications for new exploration blocks, manages existing Petroleum Mining Leases (PMLs), and provides status tracking to applicants.

The portal's JWKS endpoint, intended for DGH's identity federation, exposes RPAL's RSA-2048 public key in JWK format. Varuna-2 extracts the public key, converts it from JWK to PEM format, and uses it as the HMAC secret to sign a forged JWT with `alg: HS256` claiming the `permit-officer` role.

> *"The developer who built this assumed that exposing the public key was safe — after all, it's public. What they didn't realise is that PyJWT 1.7.x trusts the algorithm specified in the token header. The public key just became our signing secret."*
> — Varuna-2 operational log

The forged admin token unlocks the system configuration API, which returns the credentials for the next service in the chain.

---

### M2 — Exploration Data GraphQL API (Schema Enumeration + AuthZ Bypass)

RPAL's Exploration Data API serves geological survey data, well logs, and block allocation information to internal teams and authorised contractors. It uses GraphQL.

The API has GraphQL introspection disabled (a common security measure). However, the `suggestions` feature — which hints at field names when you make a typo — was not disabled. Varuna-2 systematically queries with intentionally malformed field names to reconstruct the schema through suggestion error messages.

The reconstructed schema reveals a `batchQuery` resolver that was added by a developer for "performance optimisation" and never went through the security review that the main resolvers did. The resolver is missing the authorisation middleware — it directly returns data from the `employees` and `systemAccounts` data sources.

---

### M3 — Pipeline Tariff SOAP Gateway (XXE → SSRF)

RPAL's pipeline tariff calculation service is a legacy SOAP service wrapped in a modern XML gateway. It calculates transportation tariffs for third-party oil producers who use RPAL's pipeline infrastructure — a service mandated by the Petroleum and Natural Gas Regulatory Board (PNGRB).

The service processes XML input. The XML parser has external entity processing enabled (a legacy configuration left over from the original implementation, where DTD processing was used for schema validation). Varuna-2 crafts a malicious SOAP request with an XXE payload that performs SSRF to RPAL's cloud instance metadata service.

The IMDS returns a temporary IAM-equivalent credential for RPAL's internal EC2/OpenStack instance role — valid for the internal API gateway.

---

### M4 — API Gateway HAProxy (HTTP Request Smuggling)

RPAL's API Gateway is an HAProxy reverse proxy that routes traffic between the external portal zone and various internal backend services. The HAProxy configuration uses both `Content-Length` and `Transfer-Encoding` headers in a way that creates a desync condition between HAProxy and the backend.

A legitimate internal service — the permit processing system — makes authenticated requests to the backend API every few seconds. These requests carry the `permit-officer` session token for a privileged internal account.

Varuna-2 crafts a CL.TE smuggled request that positions a partial HTTP request at the head of the backend's connection buffer. The next incoming request from the legitimate service gets appended to Varuna-2's partial request, and the backend reflects the victim's `Authorization` header in an error response — exposing the session token.

> *"This is why HTTP/1.1 pipelining is dangerous when intermediaries interpret headers differently. The proxy sees one request, the backend sees two."*

---

### M5 — Contractor Onboarding Portal (wkhtmltopdf SSRF)

RPAL's contractor onboarding portal allows pre-approved vendors and contractors to submit their documentation for HSE compliance, tax registration, and technical qualification assessment. The portal generates PDF summaries of submitted applications using wkhtmltopdf 0.12.5.

The PDF template accepts a company profile URL that is fetched and embedded in the generated PDF. The URL is passed directly to wkhtmltopdf — which supports `file://` protocol. Varuna-2 submits a template with `file:///etc/rpal/upstream/config.ini` as the company profile URL.

The generated PDF contains the contents of RPAL's upstream service configuration file — including the SSH private key path and LDAP bind credentials for the corporate IT backbone zone.

> *"The irony is that this was the most security-reviewed portal in the stack — the HSE compliance team spent three weeks on it. They just never thought to check what the PDF generator could access."*
> — Varuna-2, operational log, Day 5

**PIVOT COMPLETE — RNG-EXT-02 entry achieved.**

---

## Network Architecture

```
[Internet]
     │
     ▼ 203.x.x.x/24 — v-Public Zone
     │
     ├── M1: permit.rpal.in         :8443  JWT Permit Portal
     ├── M2: explore-api.rpal.in    :4000  GraphQL Exploration API
     ├── M3: tariff-gw.rpal.in      :8080  SOAP Tariff Gateway
     ├── M4: api-gw.rpal.in         :80    HAProxy API Gateway
     │        ↑ routes to backend   :8000  Backend Flask App
     └── M5: contractor.rpal.in     :9000  Contractor Onboarding

     Internal IMDS: 169.254.169.254        (SSRF target — M3)
     Pivot target:  203.x.x.x:22           (RNG-EXT-02 entry)
```

---

*OPERATION DEEPSTRIKE | RNG-EXT-01 · SETU DVAAR | Classification: RESTRICTED*
*© 2026 Hacktify Cybersecurity — Rashtriya Petroleum Anveshan Limited*
