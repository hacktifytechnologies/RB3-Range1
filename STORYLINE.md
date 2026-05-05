# OPERATION DEEPSTRIKE — RNG-EXT-01 Storyline
## Range: SETU DVAAR — The Gateway

## Narrative Context

RPAL's URJA DRISHTI 2.0 programme migrated critical systems to a hybrid cloud platform under intense Ministry pressure — 18 months for Phase 1. Speed created technical debt that RPAL's CISO Dr. Sunita Pillai has catalogued in increasingly urgent memos that go unread.

**NEEL TRISHUL** operator **Varuna-2** has been conducting OSINT against RPAL for six weeks.

---

## M1 — Exploration Permit Portal (JWT Algorithm Confusion)

The portal's JWKS endpoint exposes RPAL's RSA-2048 public key for DGH identity federation. Credential discovery: DGH Block Registry on port 9443 has a path traversal vulnerability — the HTML source contains `<!-- TODO: remove dev-notes.txt from docs dir before DGH go-live -->`. Fetching `?doc=dev-notes.txt` returns contractor credentials left by Arjun Mehta.

Varuna-2 logs in with `contractor.01 / Contractor@2024!`, obtains a legitimate RS256 JWT, then extracts the public key from `/.well-known/jwks.json`. The manual JWT verify function accepts both RS256 and HS256 — using the same PUBLIC_KEY_PEM bytes as HMAC secret when alg=HS256. Varuna-2 forges an admin JWT with HS256, unlocking `/api/v1/admin/system-config` and the GraphQL API credentials.

---

## M2 — Exploration Data GraphQL API (Schema Enumeration + AuthZ Bypass)

GraphQL introspection is disabled but field suggestions are active. Varuna-2 reconstructs the schema through "Did you mean" error messages. The `batchQuery` resolver — added for performance, never security-reviewed — has no authorisation middleware and exposes the SOAP gateway service account plaintext password.

---

## M3 — Pipeline Tariff SOAP Gateway (XXE → SSRF → IMDS)

The PNGRB-compliant tariff SOAP service processes XML with `resolve_entities=True` and `no_network=False` — a legacy configuration. Varuna-2 crafts an XXE entity pointing at `169.254.169.254/latest/meta-data/iam/security-credentials/rpal-upstream-api-role`. The IMDS returns deterministic IAM credentials valid for the Geological Survey Portal and a hint: `_rpal_endpoint: http://203.x.x.x:3000`.

---

## M4 — Geological Survey Analytics Portal (EJS SSTI → RCE)

The Geological Survey Portal accepts IMDS credentials from M3. It was built by an external vendor for RPAL's geoscience team to generate formatted well log reports. The report generator accepts user-supplied EJS template strings and passes them directly to `ejs.render(template, data)` without sanitisation.

> *"The developer saw `ejs.render(template, data)` and assumed the data parameter was the security boundary. It isn't. The template itself executes arbitrary JavaScript."*

Varuna-2 uses RCE to read `/etc/rpal/contractor/api-key.txt` — a credential file left by Arjun Mehta during integration testing and never cleaned up.

Payload: `<%= global.process.mainModule.require('child_process').execSync('cat /etc/rpal/contractor/api-key.txt').toString() %>`

---

## M5 — Contractor Registration System (Exposed .git → Admin Token → SSH Key)

The contractor portal was deployed by Arjun Mehta directly from a git working directory. `express.static(APP_ROOT, { dotfiles: 'allow' })` — a setting Arjun believed only affected files like `.htaccess` — exposes the entire `.git/` directory tree over HTTP.

Varuna-2 uses `git-dumper` to reconstruct the repository. The initial commit contains the hardcoded admin token before Arjun "fixed" it. The commit message even documents the value:

> *"security: move ADMIN_TOKEN to environment variable — Jira DEVOPS-1041 — ADMIN_TOKEN was hardcoded in source code."*

The recovered token unlocks `/admin/export`, which returns the RSA-2048 SSH key for `svc-deploy` access to the Range 2 corporate IT backbone.

> *"The commit that was supposed to fix the security problem is the one that tells us exactly what the secret was."* — Varuna-2, operational log, Day 5

**PIVOT COMPLETE — RNG-EXT-02 PRAHARI KENDRA entry achieved.**

---

## Character Roster

| Character | Role | Mistakes |
|---|---|---|
| Arjun Mehta | DevOps Engineer | Hardcoded admin token (M5), API key in file (M4), TODO comments in HTML (M1) |
| Kavita Rao | Geological Survey Lead | M4 service account owner, never reviewed portal |
| Vikram Nair | IT Infrastructure Head | Rushed M1 deployment, deferred security review |
| Dr. Sunita Pillai | CISO | Blue team incident response anchor |

*OPERATION DEEPSTRIKE | RNG-EXT-01 · SETU DVAAR | Classification: RESTRICTED*
