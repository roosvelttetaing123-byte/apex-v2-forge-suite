# Forge Suite v5 APEX — P2: IMPORTANT
# Updated: 2026-06-19

---

## Pillar 6: Payload Generation — ✅ COMPLETE (merged with Pillar 22)
See HANDOFF.md "WHAT WAS BUILT THIS SESSION" for full inventory.

**Still missing from Pillar 6/22 (lower priority):**
- [ ] `forge_payload/formats/cs_builder.py` — C# in-memory assembly (reflection-based exec)
- [ ] `forge_payload/formats/rust_builder.py` — Rust shellcode runner (hardest to detect)
- [ ] `forge_payload/delivery/onenote_builder.py` — OneNote .one file with embedded OLE
- [ ] `forge_payload/stagers/dns_stager.py` — DNS TXT-based stager (firewall bypass)
- [ ] `forge_payload/stagers/smb_stager.py` — SMB named-pipe stager
- [ ] `forge_payload/evasion/import_obfuscate.py` — Delay-load + hashing-based API resolution
- [ ] `forge_payload/evasion/control_flow.py` — Opaque predicates + flattening
- [ ] BYOVD loader generator (currently metadata only; add actual driver drop + IOCTL stub)

---

## Pillar 7: Advanced Modules — NOT STARTED
- [ ] Additional exploit modules per 11A above (Log4Shell etc.)
- [ ] Additional service auditors per 11B above

---

## Pillar 13: Architecture Hardening — NOT STARTED

### 13A: StateStore Abstraction
- [ ] `common/state_store.py` — StateStore(backend="sqlite"|"redis") abstraction
- [ ] Redis optional backend (keep SQLite as default, WAL + connection pool)
- [ ] `FORGE_STATESTORE_BACKEND=redis` + `FORGE_REDIS_URL` env vars
- [ ] StateStore health check endpoint in dashboard (/api/health/statestore)

### 13B: Plugin Registry
- [ ] `common/plugin_registry.py` — auto-discover modules from plugins/ directory
- [ ] Plugin manifest: name, version, framework, phases, entry_point, author
- [ ] `forge.py --list-plugins`, `forge.py --plugin <name> --target <t>`
- [ ] Makes forge.py a thin router — adding modules doesn't require editing forge.py

### 13C: Supervisor / Process Manager
- [ ] Wrap framework subprocesses so forge.py crash doesn't kill C2 sessions
- [ ] C2 runs as independent systemd service
- [ ] Makefile: `make status` shows which services are running
- [ ] `/api/health` endpoint for dashboard backend

### 13D: Operator OPSEC
- [ ] TOTP MFA for dashboard login (pyotp + QR code setup flow)
- [ ] Certificate pinning for beacon HTTP transport
- [ ] Kill switch: `forge.py c2 killswitch` → beacon self-destruct + log wipe
- [ ] `FORGE_OPERATOR_2FA=true` env var

### 13E: Frontend Architecture
- [ ] Refactor war room JS into ES modules (1 class per file, no globals)
- [ ] Single StateManager class for WebSocket state
- [ ] esbuild for lightweight bundling if migrating to modules

### 13F: Dead-Letter Queue
- [ ] Failed targets → `results/failed_targets.json`
- [ ] Auto-retry up to 3 times (exponential backoff)
- [ ] Failure reason tracking (timeout/error/scope/etc.)
- [ ] `forge.py --retry-failed`

---

## Pillar 15: Dashboard UX — NOT STARTED

### 15A: Core Architecture
- [ ] ES module refactor (see 13E)
- [ ] WebSocket auto-reconnect with state recovery
- [ ] Command palette (Ctrl+K) — fuzzy search across targets/findings/modules
- [ ] Full-text search across findings with live filter
- [ ] Notification center with persistent bell icon

### 15B: Visual Design
- [ ] Cyberpunk dark theme: #0a0e1a background, #00d4ff cyan, #ff3366 critical red
- [ ] Light theme toggle (persisted)
- [ ] Smooth CSS transitions (200ms ease-in-out)
- [ ] Micro-animations on finding discovery
- [ ] Skeleton loading screens
- [ ] JetBrains Mono for code, Inter for UI

### 15C: Interactive Visualizations
- [ ] D3.js force-directed network graph (click → host details)
- [ ] Kill chain Gantt timeline (horizontal swimlane per framework)
- [ ] Severity heatmap (target × service)
- [ ] Real-time finding rate chart (findings/min)
- [ ] Credential matrix (hosts × creds, green = working)

### 15D: Finding Management
- [ ] Slide-out finding detail panel (40% width, no page nav)
- [ ] Inline status/severity editing (Open/Fixed/Accepted/FP)
- [ ] Bulk operations (checkbox multi-select → change/export)
- [ ] Re-test button per finding
- [ ] Evidence viewer: screenshots inline, HTTP request/response
- [ ] Copy-to-clipboard on all evidence, payloads, commands

### 15F: Page-Level Feature Completions (per-page specifics, matches built UI)
- [ ] **Discovery** — replace static host list with D3 force-directed graph; nodes = hosts, edges = services
      — Node color = highest severity finding on that host; click node → host detail popover
      — Subscribe to `HOST_DISCOVERED` events → add nodes live during scan
- [ ] **Red Teaming** — pull `CHAIN_ACTION_NEW` WebSocket events → render active kill chain timeline
      — Show current MITRE tactic stage per chain; "Trigger chain manually" → POST `/api/chains/trigger`
- [ ] **C2 Console** — beacon list panel subscribes to `BEACON_CHECKIN` / `BEACON_DEAD` events
      — Operator command input → POST `/api/c2/task`; show task output in console output feed
- [ ] **Scans Library** — load templates from `GET /api/scan/templates`; "Use Template" pre-fills ScanBuilder
      — Duplicate / Delete / Export template actions per row
- [ ] **Scheduling** — "Schedule Scan" modal POSTs to `/api/schedule`; calendar pulls from `GET /api/schedule`
      — Cancel / Edit scheduled run; upcoming run countdown timer per row
- [ ] **Reports** — "Download" → `GET /api/reports/{id}/export?format=pdf|html|docx` with progress spinner
      — "New Report" modal: pick engagement, scope, template; wire to Pillar 20 when ready
- [ ] **Agents** — subscribe to `AGENT_STATUS` events → live heartbeat per agent
      — Agent detail panel: last check-in, assigned targets, running modules, resource usage
- [ ] **Mobile Pentest** — ADB/Frida device connection wizard; live Frida session output panel
      — Subscribe to `FRIDA_OUTPUT` WebSocket events; "Hook app" button starts Frida script
- [ ] **Policies** — compute compliance % from real findings per policy rule (not static numbers)
      — Progress rings update as findings status changes; "Run compliance check" → triggers Pillar 19 scan
- [ ] **Activity Logs** — subscribe to `LOG_LINE` WebSocket events (live tail); per-module filter dropdown
- [ ] **Notifications** — bell badge count from `NOTIFICATION_NEW` events; slide-down tray in TopBar

### 15E: Operator Experience
- [ ] Live log stream panel (tail -f per module)
- [ ] Operator presence indicator ("2 operators online")
- [ ] Scan control bar always visible (Pause/Resume/Abort with confirm)
- [ ] Module status matrix (modules × targets, color = status)
- [ ] Resource monitor (CPU/RAM/network of scan node)
- [ ] Engagement timer + phase progress tracker

---

## Pillar 18: Advanced C2 — NOT STARTED

### 18A: Beacon Object Files (BOFs)
- [ ] `forge_c2/bof/bof_loader.py` — in-process COFF loader (runs compiled C in beacon memory)
- [ ] BOF APIs: calloc, print, getvalue, printint
- [ ] 10 built-in BOFs: whoami, netstat, ps, ls, reg query, sc query, arp, ipconfig, env, tasklist
- [ ] Custom BOF: operator provides .c → auto-compile to COFF → load in beacon

### 18B: P2P Beacons
- [ ] SMB named pipe P2P: beacon → pipe → parent beacon → team server
- [ ] TCP P2P transport
- [ ] link/unlink commands in operator shell
- [ ] P2P relay tree in dashboard

### 18C: Additional C2 Tasks
- [ ] task_browser_creds.py — Chrome/Firefox/Edge: cookies, passwords, history
- [ ] task_keylogger.py — SetWindowsHookEx, circular buffer
- [ ] task_uac_bypass.py — fodhelper/computerdefaults/eventvwr/cmstp (4 methods)
- [ ] task_inject.py — CreateRemoteThread / NtQueueApcThread / AtomBombing / EarlyBird APC

### 18D: Implant Evasion
- [ ] Sleep mask: encrypt heap+stack while sleeping (defeats BeaconEye/pe-sieve)
- [ ] Indirect syscalls: NtAllocate/NtWrite via indirect stub
- [ ] PE header stomping: zero MZ/PE headers after load
- [ ] Gargoyle-style RX→RW memory flip while sleeping
- [ ] Stack spoofing during WaitForSingleObject

### 18E: External C2 Channels
- [ ] Teams/Slack webhook C2
- [ ] DNS-over-HTTPS C2 (Google/Cloudflare DoH)
- [ ] ICMP C2 (requires root/admin)

### 18F: ForgeScript (Aggressor Equivalent)
- [ ] Python .forge extension scripts
- [ ] Events: on_beacon_checkin, on_finding_new, on_credential_found, on_phase_change
- [ ] Actions: send_task, get_beacons, query_findings, send_notification
- [ ] Built-in: auto_screenshot.forge, cred_spray_on_join.forge

---

## Pillar 20: Reporting Excellence — NOT STARTED

### 20A: Report Engine — common/reporting/
- [ ] **`common/reporting/report_engine.py`** — PDF/HTML/Word output
      → WeasyPrint for PDF (CSS → PDF), python-docx for Word
      → Jinja2 templates for HTML
      → VPR-sorted findings
- [ ] Delta report: current vs previous scan → new/fixed/remaining
- [ ] Finding status persistence (Open/Fixed/Accepted/FP) across re-scans
- [ ] Re-test functionality per finding → auto-update status
- [ ] Finding deduplication: same vuln+target+port = 1 finding
- [ ] Vulnerability aging: days_open field, priority escalation

### 20B: Compliance Templates
- [ ] pci_dss_report.py — PCI-DSS 4.0 mapping
- [ ] owasp_top10_report.py — OWASP Top 10 2021 mapping
- [ ] iso27001_report.py — ISO 27001:2022 Annex A
- [ ] nist_csf_report.py — NIST CSF 2.0
- [ ] hipaa_report.py — HIPAA Technical Safeguards

### 20C: Report Quality
- [ ] Professional cover page (engagement details, logo placeholder, classification)
- [ ] Auto-generated TOC (PDF-linked)
- [ ] Executive summary (brain-generated via narrator.py)
- [ ] "What an attacker could do in 30 minutes" scenario (brain-generated)
- [ ] Technical findings: severity badge, CVSS+VPR, evidence screenshots, reproduction, remediation
- [ ] Remediation roadmap: VPR-sorted, grouped by effort (Quick Win / Medium / Long-term)
- [ ] Word .docx export (editable for client delivery)

---

## Pillar 21: Integrations — NOT STARTED
- [ ] Jira ticket creation on Critical/High findings (FORGE_JIRA_URL / _TOKEN / _PROJECT)
- [ ] Slack/Teams webhook notifications (FORGE_SLACK_WEBHOOK / FORGE_TEAMS_WEBHOOK)
- [ ] Shodan API enrichment (add Shodan results to host discovery)
- [ ] MISP event export (findings → threat intelligence sharing)
- [ ] BloodHound API integration (auto-import AD findings)
- [ ] Metasploit RPC bridge (forge.py → msf module execution)
- [ ] Burp Suite import (.xml findings import)
- [ ] SIEM export (Splunk/Elastic JSON format)

---

## Pillar 23: Cloud + DevSecOps — NOT STARTED
- [ ] S3 bucket enumeration + misconfiguration audit
- [ ] Azure Blob public access audit
- [ ] GitHub/GitLab secrets scanning (truffleHog integration)
- [ ] CI/CD secrets: GitHub Actions, GitLab CI, Jenkins env var extraction
- [ ] Container escape techniques (cgroups, privileged mode, /proc/sched_debug)
- [ ] Helm chart security audit
- [ ] Kubernetes RBAC misconfiguration audit (complements k8s_audit.py)

---

## Pillar 24: Quality — NOT STARTED
- [ ] pytest suite covering all BaseModule subclasses
- [ ] mypy type checking (strict mode for common/)
- [ ] MkDocs documentation site
- [ ] Demo mode (pre-recorded scenarios, no real targets)
- [ ] GitHub Actions CI pipeline (lint + test on push)

---

## Pillar 25: Distributed Architecture — NOT STARTED
- [ ] Scan nodes: separate scan agent (forge-agent) connects to central team server
- [ ] mTLS between team server and scan nodes
- [ ] Redirector config scaffold (Apache/nginx mod_rewrite rules)
- [ ] Scan checkpointing: resume from last completed module across nodes
- [ ] Load balancing: distribute target queue across multiple scan agents
