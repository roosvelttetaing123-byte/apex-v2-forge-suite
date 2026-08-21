> [!IMPORTANT]
> **HISTORICAL IMPLEMENTATION HANDOFF - NOT THE CURRENT MATURITY VERDICT OR PLAN**
>
> This file preserves historical implementation claims. Use [ENTERPRISE_MATURITY_ASSESSMENT.md](ENTERPRISE_MATURITY_ASSESSMENT.md) for the current verdict and [ROADMAP.md](ROADMAP.md) for the authoritative plan.

# FORGE-SUITE v5 APEX — Handoff
# Updated: 2026-06-28 | Score: 8.2/10 vs Enterprise | Sprint 1: ✅ | FP/FN: ✅ | v5.3: ✅

## Codebase: 498+ files · 135K+ lines · ~5.8MB

## STATUS (11/25 Pillars complete)

| Pillar | Status | Notes |
|--------|--------|-------|
| 1 C2 | ✅ | Server, operator shell, beacons, listeners, transport, **BOF engine**, **malleable profiles** |
| 2 Dashboard | ✅ | FastAPI+WS, 17 pages, DA-1/2/3 wired, **BOF/profile APIs**, **v5.3 module IDs wired** |
| 3 Multi-Target | ✅ | File targets, parallel, pause/resume |
| 4 Post-Exploit | ✅ | SAM/NTDS, mimikatz, lateral, rootkits |
| 5 Intel | ✅ | NVD, ExploitDB, Nuclei, MITRE ATT&CK |
| 6 Payload | ✅ | 12 formats, 11 stagers, 5 encoders |
| 7 NetForge VAPT | ✅ | **v5.3: 36 credentialed modules, 102 YAML checks, AD/ADCS/CIS/PCI/Exchange/IIS/macOS** |
| 8 Packaging | ✅ | Docker, install.sh, Makefile |
| 9 ForgeBrain | 🟡 | Core done. 9G (dashboard panel) pending |
| 10 FP/FN | ✅ | FPReducer retrofitted to 60/60 detection modules, 5 new Nessus-parity modules |
| 12 Chains | 🟡 | Engine done. Wiring to AutonomousEngine pending |
| 17A OOB Server | ✅ | ForgeCollab running |
| All others | ❌ | See ROADMAP.md |

## SPRINT 1 COMPLETE ✅ — Red Team Parity (2026-06-24)
1. **BOF Framework** — `forge_c2/bof/` — COFF loader, BeaconAPI shim, 10 built-in BOFs, task_bof.py, operator shell `bof` command
2. **Malleable C2 Profiles** — `forge_c2/profiles/` — YAML parser, 5 built-in profiles (office365/amazon/slack/cloudfront/generic_cdn), `--profile` CLI flag, dashboard APIs

## v5.3 COMPLETE ✅ — NetForge Nessus Gap Closure (2026-06-28)
1. **AD/ADCS/Kerberos** — `win_adcs_audit` (ESC1/2/4/6/8), `win_kerberos_audit` (Kerberoast/ASREPRoast/RC4/krbtgt), `win_ad_enum` (delegation, LAPS, DA bloat, reversible encryption)
2. **Compliance** — `linux_cis_audit` (CIS Linux Benchmark L1, 18 checks), `win_cis_audit` (CIS Windows Server, 18 checks), `linux_pci_audit` (PCI DSS v4.0, 19 checks)
3. **Windows App Depth** — `win_iis_audit` (9 checks, CVE-2017-7269), `win_exchange_audit` (ProxyLogon/Shell/NotShell by build number, webshell scan), `win_mssql_deep` (xp_cmdshell, SA, CLR, linked servers)
4. **macOS Coverage** — `win_mssql_deep`, `macos_patch_audit` (SIP, Gatekeeper, FileVault, unsigned kexts), `macos_user_audit` (admin accounts, NOPASSWD sudo, setuid diff)
5. **YAML Checks: 58 → 102** — new `active_directory/` (10 checks: LDAP anon bind, noPac, PetitPotam, PrintNightmare, AD CS ESC8) and `cloud/` (13 checks: AWS/Azure/GCP IMDS, k8s, Docker daemon, Grafana, Kibana, MinIO, Jupyter, Argo CD, Vault)
6. **Dashboard wired** — All 11 new modules registered in `UI_MODULE_MAP` with IDs: `adcs`, `kerberoast`, `adenum`, `cisbench`, `wincis`, `pcidss`, `iis`, `exchange`, `mssqldeep`, `macos`, `macosusers`

## NEXT SPRINT: S2 — Evasion & Process Injection (see ROADMAP.md)

## Architecture
```
forge-suite/
├── forge.py                  # Unified CLI (--profile flag added)
├── apex-ui/                  # React UI (17 pages, Vite, port 5173)
├── common/                   # Shared: brain, dashboard, intel, reporting, FP reducer
├── webforge/                 # Web app pentesting (12 phases, 87 modules)
├── netforge/                 # Network pentesting (14 phases, 108+ modules, 102 YAML checks)
├── adforge/                  # AD attacks (14 phases, 85+ modules)
├── aiforge/                  # AI/LLM red team (8 phases, 30 modules)
├── forge_c2/                 # C2 framework
│   ├── bof/                  # BOF engine (loader, API shim, 10 builtins)
│   ├── profiles/             # Malleable C2 profiles (parser, 5 builtins)
│   └── tasks/task_bof.py     # BOF task type
├── forge_payload/            # Payload generation
├── forge_collab/             # OOB callback server
├── skill.md                  # AI coding reference
├── ROADMAP.md                # ALL remaining tasks (single source)
└── HANDOFF.md                # This file
```

## Key Backend APIs (server.py)
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/scans/launch` | Launch scan (ScanBuilder config) |
| GET | `/api/v1/scans/history` | Scan history |
| GET/POST | `/api/v1/scan/templates` | Templates CRUD |
| GET | `/api/v1/findings` | Paginated findings |
| PATCH | `/api/v1/findings/{id}/status` | Update finding status |
| POST | `/api/v1/findings/{id}/retest` | Re-test finding |
| GET | `/api/v1/c2/bofs` | List available BOFs |
| POST | `/api/v1/c2/bofs/{name}/execute` | Execute BOF locally |
| GET | `/api/v1/c2/profiles` | List malleable C2 profiles |
| GET | `/api/v1/c2/profiles/{name}` | Profile detail |
| WS | `/ws/dashboard` | Real-time events |

## HOW TO RUN
```bash
cd forge-suite/apex-ui && npm run dev   # UI at http://localhost:5173
python forge.py dashboard              # Backend at https://localhost:1337
```

## KEY ENV VARS
```
ANTHROPIC_API_KEY, FORGE_BRAIN_MODEL=claude-opus-4-8, FORGE_COLLAB_DOMAIN
FORGE_DASHBOARD_PASSWORD, FORGE_C2_ADMIN_PW
```

## DO NOT TOUCH
- `index.css` design tokens
- `Sidebar.jsx` routes
- `Card.jsx` / `Button.jsx` / `Badge.jsx` base components
- `useWebSocket.js` hook

## CVE COVERAGE ENGINE (v5.2)
Three-layer architecture scaling CVE coverage from ~64 to 200,000+:

### Layer 1: CPE Version Matching (200K+ CVEs)
- `netforge/data/cve_db.py` — SQLite engine: downloads NVD JSON feeds, stores CVEs + CPE match criteria, KEV + EPSS data
- `netforge/data/cpe_generator.py` — Translates service banners to CPE 2.3 strings (138 product mappings)
- `netforge/modules/vuln/cpe_vuln_engine.py` — BaseModule that queries CVE DB with discovered CPEs at scan time
- **First run**: `forge cve-db update` to populate (~2GB NVD data → compressed SQLite)

### Layer 2: YAML Active Checks (102 checks, 60+ CVEs) — v5.3 updated
- `netforge/data/check_schema.py` — Schema for YAML check definitions (HTTP/banner/TCP/version probes)
- `netforge/modules/vuln/yaml_check_engine.py` — Engine that loads and executes YAML checks with concurrency control (rglob auto-discovers all subdirs)
- `netforge/data/checks/` — Check packs organized by category:
  - `cisa_kev/` — CISA KEV: Log4Shell, ProxyShell, ProxyLogon, Spring4Shell, MOVEit, Citrix Bleed, FortiOS
  - `network/` — 21 checks: SSH (regreSSHion, agent RCE, weak KEX), SMB (EternalBlue), FTP, RDP, SNMP, IPMI RAKP, glibc Looney Tunables
  - `web/` — 13 checks: Apache path traversal, Struts2, Drupalgeddon2, WordPress XML-RPC, Tomcat manager, IIS/Nginx/Apache version disclosure
  - `infrastructure/` — 10 checks: FortiOS (4 CVEs), Ivanti, F5 BIG-IP, Confluence OGNL, VMware vCenter, Jenkins unauth
  - `database/` — 20 checks: Redis, MongoDB, Elasticsearch, MySQL, PostgreSQL, Cassandra, InfluxDB, Neo4j, RabbitMQ, Druid RCE, Oracle TNS
  - `vpn_appliance/` — 6 checks: PAN-OS CVE-2024-3400, Cisco ASA, Citrix (Shitrix), SonicWall, Ivanti EPMM
  - `active_directory/` — **NEW (v5.3)** 10 checks: LDAP anon bind, noPac, Zerologon probe, PetitPotam, PrintNightmare, Kerberoastable indicator, AD CS ESC8
  - `cloud/` — **NEW (v5.3)** 13 checks: AWS/Azure/GCP IMDS, k8s API server, etcd, Docker daemon, Prometheus, Grafana default creds, Kibana, MinIO, Jupyter, Argo CD, Vault UI
- **Adding checks**: Just drop a `.yaml` file in the right subdirectory. Multi-doc (---) supported.

### Layer 3: External Integration (unchanged)
- `nuclei_runner.py` — Nuclei template engine wrapper
- `cve_matcher.py` — Legacy hardcoded CVE matching (to be migrated to Layer 1)
