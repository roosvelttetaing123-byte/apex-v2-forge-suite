# Forge Suite v5 APEX — P3: NICE-TO-HAVE (Enterprise / Scale / Polish)
# These are valuable but don't block core functionality. Build when P1+P2 are solid.

## Pillar 14: Observability & Ops Quality — NOT STARTED

### 14A: Structured Logging
- [ ] Add JSON logging mode: FORGE_LOG_FORMAT=json (machine-parseable logs for SIEM integration)
- [ ] Add correlation IDs: every scan, target, and finding gets a UUID that links log lines
- [ ] Add Prometheus metrics endpoint on dashboard: /metrics (scan counts, finding counts, latency)
- [ ] Add optional Grafana dashboard config for self-hosted metrics

### 14B: Transport Abstraction Layer
- [ ] Refactor C2 transport: create TransportManager with hot-swap capability
- [ ] If HTTP transport gets blocked → auto-failover to DNS transport without dropping beacon
- [ ] Transport health check: beacon reports back transport latency each check-in
- [ ] Add ICMP transport (ping-based C2 — requires root, bypasses many firewalls)

### 14C: Evasion Enhancements (Pillars 1/4/6 upgrade)
- [ ] Add sleep mask to beacon: encrypt beacon memory while sleeping (defeats memory scanners)
- [ ] Add indirect syscalls to Windows implant (bypass EDR userland hooks)
- [ ] Add stomped PE headers (defeat signature-based detection on disk)
- [ ] Add environmental keying: implant only runs in correct domain/hostname/subnet
- [ ] AMSI bypass: add 2 new techniques (hardware breakpoint + COM hijack variants)
- [ ] ETW bypass: add kernel patch technique (requires admin but undetectable from userland)

### 14D: Collaboration — Multi-Operator Features
- [ ] Operator chat in C2 team server (already scaffolded — verify and complete)
- [ ] Shared finding annotation: any operator can annotate/comment on a finding
- [ ] Finding assignment: assign findings to operators for verification
- [ ] Real-time "who is running what" visibility in war room dashboard
- [ ] Export engagement state as shareable bundle (findings + evidence + chain log as ZIP)

---

## APEX Dashboard — UI Polish & UX Upgrades

### DP-1: Global UX
- [ ] **Command Palette** (Ctrl+K) — fuzzy search across targets, findings, modules, pages, templates
      — Keyboard-navigable results list; Enter navigates or triggers action
      — Recent actions section at top when no query is typed
- [ ] **Skeleton Loading Screens** — pulse-animated placeholder rows/cards on all page mounts
      — Show skeleton for min 300ms even on fast loads to prevent content flash
- [ ] **Operator Presence** (TopBar) — avatar chips from `GET /api/operators/online`
      — Subscribe to `OPERATOR_JOIN` / `OPERATOR_LEAVE`; tooltip: name, current page, last action

### DP-2: Visual Polish
- [ ] Smooth CSS transitions on all route changes (200ms ease-in-out via React Router)
- [ ] Micro-animation on `FINDING_NEW` event: new row slides in from top with green glow fade
- [ ] Scan Builder intensity slider: thumb color animates smoothly between severity colors
- [ ] C2 beacon death event: beacon row fades to red then dims out (3s transition)
- [ ] TopBar page title: fade-in when route changes (opacity 0→1, translateY -4px→0)

### DP-3: ScanBuilder Enhancements (follow-on from 2026-06-21 rebuild)
- [ ] Target scope validator: highlight input red + tooltip if CIDR is malformed or non-routable
- [ ] Scan profile description tooltip: hover Scan Profile dropdown → show what each profile tests
- [ ] "Estimated scan time" readout: calculate from module count × intensity × thread count
- [ ] Module dependency warnings: if RCE selected but no Auth modules → warn "Consider adding auth modules"
- [ ] Recent targets dropdown: last 5 used scopes auto-populated below target input
- [ ] Import scope from Targets page: "Pick from Targets" button opens target selector modal

---

## Pillar 19: Credentialed Scanning + Compliance — NOT STARTED

### 19A: Credentialed Network Scanning — netforge/modules/credentialed/
- [ ] ssh_credentialed_audit.py — SSH agent: connects with creds, runs CIS-benchmark checks locally
  - OS version, patch level, open ports (ss -tlnp), running services (systemctl), world-writable files
  - SUID/SGID binaries, cron jobs, sudoers misconfigs, /etc/passwd shadow check
  - Kernel version vs CVE database, installed packages vs vuln database
- [ ] wmi_credentialed_audit.py — WMI agent: Windows credentialed audit
  - Patch level (KB list vs missing patches from WSUS), running services, startup items
  - Local users/groups, UAC config, Windows Defender status, firewall rules
  - Installed software vs CVE database
- [ ] snmp_credentialed_audit.py — SNMP v3 auth: enumerate full MIB tree with credentials
- [ ] CLI flags: --ssh-user/--ssh-pass/--ssh-key, --smb-user/--smb-pass/--smb-hash

### 19B: Compliance Scanning — netforge/modules/compliance/
- [ ] cis_benchmark.py — CIS Benchmark Level 1/2 for Linux (Ubuntu, RHEL, Debian) and Windows Server
- [ ] pci_dss.py — PCI-DSS v4.0 compliance checks (requirements 6, 8, 10, 11)
- [ ] hipaa.py — HIPAA Technical Safeguards audit (§164.312)
- [ ] disa_stig.py — DISA STIG checks for RHEL/Windows Server
- [ ] nist_800_53.py — NIST SP 800-53 Rev 5 control checks
- [ ] Compliance report template: compliance_report.py — pass/fail per control, % compliance score

### 19C: Vulnerability Priority Rating (VPR) — common/vpr.py
- [ ] VPR score = CVSS base + exploit availability bonus + asset criticality multiplier + age factor
- [ ] Exploit availability: check Intel Pipeline for public exploit (ExploitDB/Nuclei) → +20% if exploit exists
- [ ] Asset criticality: operator tags assets (DC, web server, database) → multiplier applied
- [ ] Age factor: vuln open >90 days → escalate priority
- [ ] VPR replaces raw CVSS for finding prioritization in reports
- [ ] Dashboard: sort findings by VPR score (not just CVSS)

---

## Pillar 21: Integration Ecosystem — NOT STARTED

### 21A: Ticketing System Integration
- [ ] Jira integration: common/integrations/jira.py
  - Auto-create Jira issues for Critical/High findings
  - Map severity → Jira priority, finding title → summary, description → description
  - Attach evidence screenshots to Jira ticket
  - CLI: --jira-url / --jira-token / --jira-project
- [ ] ServiceNow integration: common/integrations/servicenow.py
- [ ] GitHub Issues: common/integrations/github_issues.py

### 21B: Notification Webhooks
- [ ] Slack webhook: common/integrations/slack.py
- [ ] Microsoft Teams webhook: common/integrations/teams.py
- [ ] Discord webhook: common/integrations/discord.py
- [ ] Email SMTP: common/integrations/email.py
- [ ] PagerDuty: common/integrations/pagerduty.py
- [ ] CLI: --notify slack,teams,email / env vars: FORGE_SLACK_WEBHOOK, FORGE_TEAMS_WEBHOOK

### 21C: Threat Intelligence Integration
- [ ] Shodan API: common/integrations/shodan.py
- [ ] MISP integration: common/integrations/misp.py
- [ ] VirusTotal: common/integrations/virustotal.py
- [ ] AbuseIPDB: common/integrations/abuseipdb.py

### 21D: Security Tool Integration
- [ ] Burp Suite XML import: common/integrations/burp_import.py
- [ ] Metasploit RPC: common/integrations/msf_rpc.py
- [ ] BloodHound API: common/integrations/bloodhound.py
- [ ] Nessus/Tenable API: common/integrations/tenable.py
- [ ] SIEM export: common/integrations/siem.py (Splunk HEC + ELK/OpenSearch)

---

## Pillar 23: Cloud & DevSecOps Security — NOT STARTED

### 23A: Cloud Misconfiguration Audit — netforge/modules/cloud/
- [ ] s3_audit.py — AWS S3: public buckets, listable buckets, object ACLs, bucket policy misconfig
- [ ] azure_blob_audit.py — Azure Blob: public containers, SAS token exposure
- [ ] gcp_storage_audit.py — GCP Storage: allUsers/allAuthenticatedUsers on buckets
- [ ] aws_iam_audit.py — AWS IAM: overly permissive policies, unused access keys, root key usage
- [ ] azure_rbac_audit.py — Azure RBAC: Owner/Contributor overassignment
- [ ] cloud_trail_audit.py — Check if CloudTrail/Activity Log is enabled

### 23B: Secrets & Code Security — netforge/modules/secrets/
- [ ] github_secrets.py — GitHub: public repo scanning for secrets (API keys, tokens, passwords)
- [ ] gitlab_secrets.py — GitLab equivalent
- [ ] cicd_audit.py — CI/CD pipeline secrets exposure
- [ ] env_file_audit.py — Web accessible .env files (expand patterns)
- [ ] docker_secrets.py — Docker image layer scanning for embedded secrets

### 23C: Container & Orchestration Security
- [ ] docker_escape.py — Container escape techniques
- [ ] k8s_rbac_audit.py — Kubernetes RBAC misconfigs
- [ ] k8s_network_policy.py — Missing NetworkPolicies
- [ ] k8s_secrets_audit.py — Kubernetes Secrets exposure
- [ ] helm_audit.py — Helm chart security

---

## Pillar 24: Quality, Testing & Documentation — NOT STARTED

### 24A: Test Suite
- [ ] pytest test suite: tests/ directory, one test file per module
- [ ] Unit tests for all common/ modules (finding, fp_reducer, brain, engagement_bus)
- [ ] Integration tests: run against DVWA, WebGoat, Metasploitable, VulnHub targets
- [ ] Mock tests: mock HTTP responses for deterministic scanner testing
- [ ] Coverage target: >80% line coverage on common/ modules
- [ ] CI/CD: GitHub Actions workflow — lint (ruff) + type check (mypy) + test on every push
- [ ] Makefile targets: make test, make lint, make typecheck, make coverage

### 24B: Type Safety
- [ ] Complete type hints on all common/ files (mypy strict pass)
- [ ] Complete type hints on all framework orchestrators (netforge.py, webforge.py, etc.)
- [ ] Pydantic v2 models for all config files (replace raw dict parsing)
- [ ] Type stubs for external dependencies (scapy, impacket)

### 24C: Documentation
- [ ] MkDocs site: docs/ directory with Material theme (dark mode default)
- [ ] Getting started guide
- [ ] Module reference: auto-generated from docstrings
- [ ] Red team playbook: step-by-step examples for common engagement scenarios
- [ ] API reference: dashboard REST API + WebSocket events
- [ ] Contributing guide: how to add a new module (template + checklist)

### 24D: Demo / Training Mode
- [ ] demo_mode.py: spin up local vulnerable containers (DVWA, Metasploitable, HackTheBox-style)
- [ ] forge.py demo --target dvwa: auto-configure scan against local vulnerable app
- [ ] demo findings library: pre-populated sample findings for UI testing/demos
- [ ] Demo video generation: record and replay a scan for client demos

---

## Pillar 25: Distributed Architecture & Scale — NOT STARTED

### 25A: Scan Node Architecture
- [ ] Scan node agent: forge_agent.py — lightweight agent on remote hosts, reports to central dashboard
- [ ] Scan node registration: agent registers with dashboard → operator assigns targets
- [ ] Result streaming: agent streams findings via WebSocket to central dashboard
- [ ] docker-compose profiles: c2-only, dashboard-only, scan-node, full, distributed
- [ ] Makefile targets: make deploy-c2, make deploy-dashboard, make deploy-node

### 25B: mTLS Between Components
- [ ] Mutual TLS for: scan node → dashboard, operator → C2 team server, beacon → listener
- [ ] Auto-generate certificates on install (forge.py setup --generate-certs)
- [ ] Certificate rotation: forge.py setup --rotate-certs
- [ ] forge_ca/: internal CA for self-signed mTLS certs

### 25C: Redirector Scaffolding
- [ ] Apache .htaccess redirector config generator (HTTP/HTTPS C2 traffic)
- [ ] nginx redirector config generator
- [ ] Cloudflare Worker C2 redirector (domain fronting via CF)
- [ ] forge.py c2 redirector generate --type apache|nginx|cloudflare --c2-host <ip>
- [ ] Redirector health check: validate traffic flows correctly before engagement

### 25D: Performance & Scale
- [ ] Scan checkpointing: save progress every 60s, resume from checkpoint on crash
- [ ] Delta scanning: track last-scan fingerprint per host/service, only re-scan changed targets
- [ ] Smart rate adaptation: auto-reduce rate if target starts dropping connections
- [ ] Parallel framework execution: run NetForge + WebForge simultaneously on same target
- [ ] Memory-mapped result store for large engagements (>1000 targets)
