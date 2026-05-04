# solve_blue.md — M2 · ext-graphql-api
## Blue Team Detection, Containment & Remediation

**Vulnerability:** GraphQL Field Suggestion Schema Enumeration + batchQuery Missing Authorization

---

## 1. What the Attack Looks Like

### Application Log Indicators
```
# Schema enumeration — high-volume error responses with "Did you mean" suggestions
2024-11-15 03:45:12 WARNING GRAPHQL_ERROR field=wellLog suggestion=wellLogs ip=198.51.100.x
2024-11-15 03:45:13 WARNING GRAPHQL_ERROR field=systemAccount suggestion=systemAccounts ip=198.51.100.x
2024-11-15 03:45:14 WARNING GRAPHQL_ERROR field=batchQueery suggestion=batchQuery ip=198.51.100.x

# Unauthenticated batchQuery access
2024-11-15 03:46:01 WARNING BATCH_QUERY_ACCESSED queries=['systemAccounts','internalServices'] ip=198.51.100.x auth=False
```

**Key anomalies:**
1. Rapid sequence of error responses containing "Did you mean" from a single IP
2. `BATCH_QUERY_ACCESSED` with `auth=False` — this should never occur legitimately
3. `systemAccounts` or `internalServices` appearing in query strings

---

## 2. Detection Signatures

### Suricata Rule — Field Suggestion Enumeration
```
alert http $EXTERNAL_NET any -> $HTTP_SERVERS 4000 (
  msg:"DEEPSTRIKE:GraphQL schema enumeration via field suggestions";
  content:"POST"; http_method;
  content:"/graphql"; http_uri;
  content:"Did you mean"; http_server_body;
  threshold: type threshold, track by_src, count 5, seconds 30;
  classtype:web-application-attack;
  sid:9001201; rev:1;
)

alert http $EXTERNAL_NET any -> $HTTP_SERVERS 4000 (
  msg:"DEEPSTRIKE:GraphQL batchQuery systemAccounts access";
  content:"POST"; http_method;
  content:"/graphql"; http_uri;
  content:"systemAccounts"; http_client_body;
  classtype:web-application-attack;
  sid:9001202; rev:1;
)
```

### Splunk Query
```spl
index=rpal-graphql sourcetype=api_log
  (message="BATCH_QUERY_ACCESSED" AND auth=False)
| table _time, ip, queries
| sort -_time
```

---

## 3. Containment

```bash
# Block IP
iptables -I INPUT -s <ip> -p tcp --dport 4000 -j DROP

# Rotate API key immediately (all downstream services using old key must be updated)
# Edit /etc/systemd/system/rpal-exploration-api.service
# Change: Environment=RPAL_API_KEY=RPAL-API-2024-XK9mP3nT8qRs
# To:     Environment=RPAL_API_KEY=$(openssl rand -hex 24)
systemctl daemon-reload && systemctl restart rpal-exploration-api
```

---

## 4. Remediation — Permanent Fix

### Fix 1 — Disable Field Suggestions

```python
# In app.py — add suggestion suppression to schema
import strawberry
from strawberry.extensions import DisableIntrospection

# Custom extension to suppress suggestions
class DisableSuggestions(strawberry.extensions.SchemaExtension):
    def on_executing_start(self):
        pass  # Hook to intercept errors — modify error messages

# OR: upgrade to Strawberry version with built-in suggestion disabling
# strawberry-graphql >= 0.220.0 has disable_field_suggestions option:
schema = strawberry.Schema(
    query=Query,
    extensions=[DisableIntrospection],
    config=strawberry.schema.config.StrawberryConfig(
        disable_field_suggestions=True   # Removes "Did you mean" from errors
    )
)
```

### Fix 2 — Add Authorization to batchQuery

```python
@strawberry.field
@require_auth          # ADD THIS DECORATOR
def batch_query(self, info: Info, queries: List[str]) -> List[BatchResult]:
    ctx = info.context['auth']
    if ctx['role'] not in ('admin',):    # Restrict to admin only
        raise Exception("batchQuery requires admin role")
    ...
```

### Fix 3 — Remove Plaintext Passwords from Database

```sql
-- No service account should have plaintext_password populated
UPDATE system_accounts SET plaintext_password = NULL;
-- Use HashiCorp Vault or AWS Secrets Manager for credential storage
```

---

## 5. Lessons Learned

1. **"Introspection disabled" ≠ schema hidden.** Field suggestions are a separate feature that must be explicitly disabled. Most GraphQL security guides only mention introspection.
2. **New resolvers need security review.** The `batchQuery` resolver bypassed the existing auth pattern. Code review gates must check every new resolver for authorization.
3. **Never store plaintext credentials in application databases.** Use Vault, AWS SM, or GCP SM — inject at runtime via environment variables.
4. **GraphQL permission middleware must be verified per-resolver.** A decorator pattern is fragile — use a schema-level middleware that applies to all resolvers by default with explicit opt-out.

---
*solve_blue.md | M2 ext-graphql-api | RNG-EXT-01 SETU DVAAR | OPERATION DEEPSTRIKE*
