# Sprint 0 — Leak Intelligence Engine

Priority: CRITICAL. This is what wins real engagements.

## Goal
Automate OSINT leak discovery → credential extraction → access testing.

## New Directory
`forge_suite/leak_intel/`

## Modules to Build

### Scanners (`leak_intel/scanners/`)

1. **`github_scanner.py`** — GitHub API: search commits, gists, issues, PRs, wiki for target org secrets.
2. **`gitlab_scanner.py`** — GitLab API: same scope + snippets.
3. **`bitbucket_scanner.py`** — Bitbucket API.
4. **`pastebin_scanner.py`** — Pastebin, Ghostbin, Hastebin, Rentry keyword monitoring.
5. **`crtsh_scanner.py`** — Certificate Transparency log enumeration → hidden subdomains.
6. **`shodan_enricher.py`** — Shodan API: origin IPs, open ports, service banners, SSL certs per domain.
7. **`dns_history.py`** — SecurityTrails/PassiveTotal: historical DNS → decommissioned subdomains.
8. **`cloud_asset_enum.py`** — Open S3 buckets, Azure Blob, GCP Storage with config file detection.
9. **`npm_pypi_scanner.py`** — Registry metadata (package.json, setup.py) for internal URL leakage.
10. **`stackoverflow_scanner.py`** — Search code snippets from target domain for embedded creds.

### Parsers (`leak_intel/parsers/`)

1. **`env_parser.py`** — Extract secrets from .env file patterns.
2. **`aws_key_detector.py`** — AKIA pattern detection + STS validation.
3. **`jwt_detector.py`** — eyJ... pattern detection + decode + weak-key testing.
4. **`url_extractor.py`** — Internal URL/IP/hostname extraction from config files.
5. **`credential_tester.py`** — Auto-test discovered creds against: Azure AD, AWS STS, VPN, Jira, Confluence, internal web apps.

### DB (`leak_intel/db/`)

1. **`leak_models.py`** — SQLite models for leak findings, creds, tested status.
2. **`enrichment_cache.py`** — Cache Shodan/crt.sh/DNS results to avoid re-querying.

## Chain Integration

Add these chains to `common/attack_chains.py`:

| Chain | Trigger → Next |
|-------|---------------|
| Git Leak → Credential → Internal Web App | `git_secret_find` → `credential_tester` → `internal_web_access` |
| Pastebin Leak → VPN/RDP Credential → Perimeter | `pastebin_leak` → `credential_tester` → `vpn_access` |
| Cert Transparency → Hidden Subdomain → Forgotten App | `crtsh_find` → `subdomain_probe` → `outdated_app_exploit` |
| Shodan Origin IP → CDN Bypass → Direct Backend | `shodan_origin_find` → `direct_ip_probe` → `backend_exploit` |
| DNS History → Decommissioned Subdomain → Stale Auth | `dns_history` → `subdomain_probe` → `stale_cred_exploit` |

## Implementation Notes

- Each scanner must follow `common/base_module.py` interface.
- Findings go through `common/fp_reducer.py` before saving.
- All API keys read from env vars, never hardcoded.
- Credential tester must log every test attempt to audit log.
- Rate-limit all external API calls.

## Acceptance Criteria

- [ ] Each scanner returns normalized findings via base_module interface
- [ ] credential_tester validates at least: Azure AD, AWS, VPN, Jira
- [ ] OSINT chains fire in ChainEngine when leak scanner confirms a finding
- [ ] Results visible in dashboard under new "Leak Intel" tab
- [ ] API keys sourced from env vars only
