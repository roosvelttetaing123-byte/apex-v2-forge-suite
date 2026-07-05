# Forge Suite v5 APEX — P1: CRITICAL
# Updated: 2026-06-19
# These pillars close the biggest competitive gaps.

---

## Pillar 9: ForgeBrain — AI Reasoning Engine — NEARLY DONE (9A-9F + wiring done)

### 9G: Remaining (1 item)
- [x] Wire EngagementBus into netforge/webforge/adforge
- [x] Wire AttackPlanner into attack_chain.py
- [x] Wire FindingAnalyst into BaseModule.save_finding()
- [x] Add BRAIN_VERDICT + CHAIN_ACTION_NEW to event_bus.py
- [x] Add --autonomous / --brain-key flags to forge.py
- [x] Update requirements.txt with anthropic>=0.40.0
- [x] Update install.sh ForgeBrain section
- [x] Create .env.example with all brain/collab vars
- [ ] **Show brain verdicts + confidence in War Room dashboard (new JS panel)**
      — Subscribe to BRAIN_VERDICT WebSocket event → render verdict chip with confidence %
      — Add "Brain Analysis" panel to Overview tab (verdict per finding, color-coded HIGH/MED/LOW)
      — Wire FPReducer confidence into finding display in findings table

---

## Pillar 10: FP/FN Reduction — ENGINE COMPLETE, RETROFIT PENDING

### 10A: FPReducer Engine ✅ DONE (`common/fp_reducer.py`)
- [x] FPReducer class with verify(vuln_type, url, param) API
- [x] 3-layer verification: Baseline → Probe → Confirm
- [x] Confidence enum: HIGH / MEDIUM / LOW / UNVERIFIED
- [x] verify_sqli_time — 3-baseline median, 2-probe threshold
- [x] verify_sqli_error — 20+ DB error regex patterns
- [x] verify_xss_reflected — UUID canary exact match
- [x] verify_ssti — math proof {{7*7}}→49
- [x] verify_ssrf — OOB callback (HIGH) or response diff (MEDIUM)
- [x] verify_lfi — known file content (root:x:0:0, win.ini)
- [x] verify_cmdi — OOB callback or unique token echo
- [x] verify_xxe — OOB DNS or /etc/passwd content
- [x] suggest_followup_modules() for FN detection

### 10B: Scanner Retrofit — NOT STARTED (biggest remaining gap)
- [ ] **Retrofit sqli_scanner.py** — call FPReducer.verify("sqli_time"/"sqli_error") before saving finding
- [ ] **Retrofit xss_scanner.py** — UUID canary via FPReducer.verify("xss")
- [ ] **Retrofit ssti_scanner.py** — math proof via FPReducer.verify("ssti")
- [ ] **Retrofit lfi_rfi.py** — content check via FPReducer.verify("lfi")
- [ ] **Retrofit cmd_inject.py** — OOB or token via FPReducer.verify("cmdi")
- [ ] Add confidence field to Finding display in dashboard + reports
- [ ] Suppress LOW/UNVERIFIED from default report; show in --verbose section

---

## Pillar 12: Cross-Framework Attack Chains — ✅ COMPLETE

- [x] ChainTrigger dataclass with chain_id, trigger_types, next_module, MITRE, opsec_level
- [x] 10 chains: SQLi→Cred Spray, XSS→Session Hijack, SMB Signing→NTLM Relay, AD Creds→Lateral+C2, SSRF→Internal Scan, Host Comp→BloodHound, File Upload→Webshell, SSTI→RCE, XXE→SSRF Pivot, Default Creds→PrivEsc
- [x] ChainEngine with EngagementBus event subscription, opsec level gating, auto_execute flag
- [x] get_chain_suggestions(finding_type) for AI planner
- [x] list_all_chains() reference table
- [ ] **Wire ChainEngine into AutonomousEngine.run_engagement()** — instantiate at engagement start, register_all()
- [ ] **Wire ChainEngine into EngagementBus.publish()** — auto-trigger after finding confirmed
- [ ] Dashboard kill chain panel shows chain progression events (CHAIN_ACTION_NEW events)

---

## Pillar 16: Headless Browser + Authenticated Scanning — NOT STARTED
# Biggest single gap vs Acunetix. Without JS rendering, can't test React/Angular/Vue SPAs.

### 16A: Playwright Engine — webforge/core/browser_engine.py
- [ ] BrowserEngine class: async Playwright, chromium headless, page lifecycle management
- [ ] SPA detection: detect React/Angular/Vue/Next.js → auto-switch to JS-rendered mode
- [ ] Wait for network idle + DOM stable before scanning (not just page load)
- [ ] AJAX endpoint discovery: intercept XHR/fetch during crawl, add discovered endpoints to scope
- [ ] Shadow DOM traversal: inspect shadow roots for hidden inputs + forms
- [ ] Browser-based XSS confirmation: detect actual DOM alert/change (not just canary echo)
- [ ] JS resource extraction: URLs from JS bundles, source maps, web workers

### 16B: Login Sequence Recorder — webforge/core/auth_recorder.py
- [ ] Record login flow: capture username→password→MFA sequence
- [ ] Replay auth before each authenticated scan request
- [ ] Session health check: detect expiry mid-scan → re-authenticate automatically
- [ ] CLI: --login-url / --username / --password / --login-script
- [ ] Auth state export/import for scan resume

### 16C: API Schema Import — webforge/modules/api/schema_import.py
- [ ] OpenAPI 3.0 / Swagger 2.0 import → auto-generate test cases
- [ ] GraphQL introspection → fuzz all queries/mutations
- [ ] Postman collection import (.json)
- [ ] Auto-inject security tests: sqli/xss/idor/auth for each endpoint
- [ ] Parameter type awareness: string→sqli/xss, int→IDOR/overflow, file→upload bypass

### 16D: Scan Profiles — webforge/core/scan_profile.py
- [ ] Profiles: quick (5-10min), standard (30-60min), full (hours), api, compliance, custom
- [ ] CLI: --profile quick|standard|full|api|compliance|<name>

---

## Pillar 17B: OOB Module Wiring — PARTIAL

- [x] ssrf_scanner.py — `_test_blind_ssrf_oob()` wired
- [x] xxe_scanner.py — `_test_blind_xxe_oob()` wired
- [ ] **blind_sqli / sqli_scanner.py** — xp_cmdshell DNS / LOAD_FILE via ForgeCollab
- [x] **Log4Shell module (Pillar 11)** — `netforge/modules/exploit/log4shell.py` ✅
- [x] **blind_xss** — `webforge/modules/injection/blind_xss.py` ✅
- [x] **blind_cmdi** — `webforge/modules/injection/blind_cmdi.py` ✅
- [ ] CLI: --collab-server domain (sets FORGE_COLLAB_DOMAIN for all modules in one scan)

---

---


## Pillar 11: Modern CVE Coverage — NOT STARTED
# Critical CVEs that red teams actually hit. Pairs with ForgeCollab OOB.

### 11A: Web/App Exploits — netforge/modules/exploit/
- [x] **log4shell.py** — CVE-2021-44228 JNDI injection via 30+ headers + params + JSON + path
      → ForgeCollab DNS/HTTP/LDAP OOB callbacks, 14 WAF bypass payloads ✅
- [x] proxyshell.py — CVE-2021-34473/34523/31207 Exchange 3-step RCE chain ✅
- [x] spring4shell.py — CVE-2022-22965 classLoader RCE via AccessLogValve ✅
- [ ] moveit_sqli.py — CVE-2023-34362 MOVEit Transfer
- [ ] connectwise_rce.py — CVE-2024-1709 auth bypass
- [ ] fortinet_rce.py — CVE-2024-21762 OOB write

### 11B: Infrastructure Auditors — netforge/modules/services/
- [ ] k8s_audit.py — anonymous access, RBAC misconfig, secret exposure
- [ ] etcd_audit.py — no-auth, cluster key, credential extraction
- [ ] vault_audit.py — dev mode, unauthenticated secret access
- [ ] jenkins_audit.py — script console, Groovy RCE
- [ ] kafka_audit.py — no-auth, JMX, topic read
- [ ] consul_audit.py — API exposure, KV store access
- [ ] gitlab_audit.py — unauthenticated API, runner token

### 11C: Cloud Metadata Chains
- [ ] cloud_metadata.py — SSRF→IMDSv1→IAM credential extraction→cloud takeover path
      → Auto-chain: SSRF confirmed → try 169.254.169.254 → extract IAM keys → report
