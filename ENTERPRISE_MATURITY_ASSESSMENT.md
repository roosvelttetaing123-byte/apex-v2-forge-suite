# Forge Suite Enterprise Maturity Assessment

Assessment date: 2026-07-19  
Base commit: `774e0722bb4cc50a064f414e565e61feb6f4bf21`  
Assessed dirty-tree inputs: [ASSESSMENT_INPUT_MANIFEST.sha256](ASSESSMENT_INPUT_MANIFEST.sha256), 691 source/test/build/configuration files, manifest SHA-256 `feb56b17035ea9575198e3a69d0724ae296525e1caa59ff3f57f442851be1ee1`  
Scope: static code review, safe import checks, local tests/builds, and public vendor documentation  
Excluded: live target scans, credential use, payload execution, and licensed product shootouts

## Executive Verdict

Forge Suite has an unusually broad surface for a young codebase, but breadth is being mistaken for maturity. The current product is best described as an ambitious authorized-security research workbench or early alpha, not an enterprise scanner or operational C2 platform.

Current weighted portfolio parity against category leaders: **1.4/5 (2.8/10)**.

That score does not mean the project lacks value. It means the unusually broad set of security engines, modules, checks, C2/payload components, and workflow code does not yet form dependable end-to-end products. The strongest assets are the unified vision, the shared module and finding abstractions, broad scanner taxonomy, browser/crawler work, report generation, and the beginnings of durable jobs and audit logging. The largest gaps are execution correctness, authorization boundaries, detection proof, immutable evidence, retest truth, lab validation, recovery, and product operations.

The explicit **8.2/10 vs Enterprise** score in `HANDOFF.md:7` and related prior parity/completion positioning are not supported by the current implementation or test evidence.

### Readiness By Use Case

| Use case | Current verdict |
|---|---|
| Architecture demo and UI demonstration | Suitable with curated paths |
| Local authorized lab experimentation | Conditionally suitable with operator review |
| Repeatable consultant-delivered assessment | Not yet dependable |
| Enterprise vulnerability management | Not ready |
| Multi-tenant or distributed deployment | Not ready |
| Operational C2 deployment | Not ready |
| Compliance attestation | Must not be used as evidence of compliance |

## Product Direction

The correct strategy is a hard depth-first feature freeze:

- Do not add a new engine, module family, exploit family, transport, payload format, dashboard page, or mobile capability.
- Stop using file count and module count as delivery metrics.
- Mature one complete operator workflow at a time: authorization, plan, execute, observe, prove, persist, cancel, retest, report, and audit.
- Label every existing capability as `verified`, `heuristic`, `wrapper`, `simulation`, `experimental`, or `disabled`.
- Compete on transparent proof, cross-engine context, safe authorization controls, offline/self-hosted operation, and evidence quality rather than trying to match commercial plugin counts immediately.

`ROADMAP.md` is the execution plan derived from this assessment. `ROADMAP2ND.md` is archived because its MobileForge expansion conflicts with the no-new-modules direction.

## Scoring Rubric

| Score | Meaning |
|---:|---|
| 0 | Absent |
| 1 | Prototype: code or UI exists, but the core workflow is incomplete or misleading |
| 2 | Coherent alpha: meaningful implementation exists, but reliability, proof, safety, or integration is incomplete |
| 3 | Usable beta: repeatable practitioner workflow with bounded limitations and real lab validation |
| 4 | Production-ready: durable, secure, scalable, supportable, and broadly validated |
| 5 | Category-leader parity |

Scores weight detection correctness, workflow completeness, safety, evidence/retest integrity, validation, scale, and maintainability. Merely importing a module or rendering a page does not establish maturity.

Individual family scores are evidence-anchored expert estimates, not measurements accurate to one decimal place. The disclosed portfolio arithmetic is reproducible, but distinctions such as 1.1 versus 1.3 remain reviewer judgment until future rescoring uses explicit per-dimension subscores and measured fixture results.

## Enterprise Comparison Scorecard

| Forge area | Score / 5 | Portfolio weight | Primary benchmark | Current position |
|---|---:|---:|---|---|
| WebForge DAST and API testing | 2.0 | 12% | Invicti, Acunetix, Burp Suite DAST | Substantial alpha; real crawler/browser/schema work exists, but proof, scope-safe navigation, auth stability, and validation are inconsistent |
| NetForge vulnerability assessment | 1.5 | 12% | Tenable Nessus, Qualys VMDR, Rapid7 InsightVM | Prototype pipeline; discovery contracts, CVE feeds, check quality, credential security, and compliance applicability are unreliable |
| ADForge identity assessment | 1.1 | 10% | BloodHound Enterprise, PingCastle, NetExec, Certipy | Broad taxonomy with major LDAP/auth/graph/runtime contract failures |
| AIForge | 1.7 | 7% | Garak, Microsoft PyRIT | Broad prompt catalog; weak TLS, repeatability, calibrated scoring, datasets, and adapter validation |
| ForgeBrain and autonomous attack chaining | 1.2 | 4% | Pentera and Horizon3.ai NodeZero-style validation platforms | Analysis, narration, and chain scaffolding exist; execution truth, safety policy, privacy boundaries, and outcome validation are incomplete |
| Intelligence and vulnerability-content pipeline | 1.3 | 5% | Tenable Research content and ProjectDiscovery Nuclei | Multiple feed/cache concepts exist; split stores, unreliable update freshness, weak provenance, and absent content-quality gates prevent dependable use |
| Forge C2 | 1.0 | 7% | Cobalt Strike, Sliver | Architectural scaffolding; not an end-to-end authenticated, encrypted, durable C2 protocol |
| Payload and implant pipeline | 1.0 | 3% | Cobalt Strike Arsenal/Artifact Kit, Metasploit payload workflow | Many advertised formats, but artifact correctness and library-boundary authorization are insufficient |
| Cloud CSPM/CNAPP | 0.7 | 5% | Wiz, Prisma Cloud, ScoutSuite | Point probes and IAM simulations; no provider-native inventory, context graph, policy evaluation, or dependable asset attribution |
| Container and Kubernetes security | 0.9 | 3% | Trivy, Prisma Cloud Compute, Kubescape | Local-host probes and nascent Kubernetes checks exist, but workload identity, image/SBOM/config coverage, and target attribution are incomplete |
| Leak intelligence and secret exposure | 1.0 | 4% | GitGuardian, TruffleHog Enterprise | Source, parser, and limited provider-verification scaffolding exist; broad history coverage, fixture-validated verification, safe authorization, and remediation lifecycle are incomplete |
| ForgeCollab OOB verification | 1.1 | 3% | Burp Collaborator, AcuMonitor | Listener components exist, but remote token correlation and durable evidence are broken |
| Common orchestration and jobs | 2.2 | 6% | Tenable/Invicti job control planes | Useful abstractions and partial durability; authorization, dependency ordering, recovery, and idempotency are incomplete |
| Evidence integrity and custody | 1.2 | 5% | Enterprise assessment/reporting platforms | Attachments exist; no immutable observations, redaction boundary, hashes, signatures, or custody trail |
| Reporting | 1.9 | 5% | Dradis Pro, PlexTrac, Faraday, DefectDojo | Good export primitives; compliance semantics, review workflow, canonical lineage, and collaboration are weak |
| Dashboard and control plane | 1.7 | 4% | Enterprise scanner consoles | Real auth/RBAC/SSO/audit scaffolding; unsafe write paths, global controls, facade pages, and tenant isolation block production use |
| Distributed agents | 1.4 | 2% | Enterprise scan engines/nodes | Dry-run and scope concepts exist; identity, lease ownership, persistence, and recovery are immature |
| Team and vulnerability management | 1.0 | 3% | Dradis, Faraday, DefectDojo | Mostly browser-local or static presentation rather than a shared workflow |

The portfolio score is the sum of each score multiplied by the disclosed weight; the weights total 100%. The result is **1.41/5**, rounded to **1.4/5 (2.8/10)**. The weights emphasize the primary assessment engines while still making evidence, control-plane, and operator-workflow failures material. This is a repository maturity index, not a statistical head-to-head benchmark of licensed products.

## Blocking Findings

The following defects invalidate an enterprise-readiness claim even before detection breadth is considered.

### Critical: Dashboard launches active work outside a trustworthy authorization contract

- Both dashboard scan paths append `--auto-confirm`, bypassing module confirmation gates: `common/dashboard/server.py:1094`, `common/dashboard/server.py:1104`, `common/dashboard/server.py:1701`, `common/dashboard/server.py:1724`.
- The legacy web endpoint also resolves the web hostname and silently launches NetForge against the resulting IP: `common/dashboard/server.py:1020`, `common/dashboard/server.py:1154`.
- A domain authorization does not automatically authorize an active network scan against a shared CDN, reverse proxy, or hosting IP.
- Empty scope is treated as allow-all: `common/scope.py:95`, with a test that codifies the behavior at `common/scope.py:172`.

Enterprise impact: an operator can trigger undisclosed or out-of-scope network activity, while active modules are pre-approved by the control plane.

### Critical: Dashboard state and evidence can be spoofed

- `/api/v1/events/emit` accepts arbitrary event JSON without dashboard authentication: `common/dashboard/server.py:812`.
- `RemoteEventBus` sends no credential and disables TLS verification: `common/dashboard/event_bus.py:449`.
- Remote events feed the same state used by the dashboard and finding workflows.

Enterprise impact: a network client can inject false scan events or findings, corrupting operator decisions and report evidence.

### Critical: Viewer-level BOF API performs local host actions

- Local BOF execution requires only the default viewer role: `common/dashboard/server.py:1949`.
- The built-ins enumerate network state, processes, directory/file metadata, system configuration, services, and environment data: `forge_c2/bof/builtins/__init__.py:119`, `forge_c2/bof/builtins/__init__.py:182`, `forge_c2/bof/builtins/__init__.py:234`, `forge_c2/bof/builtins/__init__.py:279`, `forge_c2/bof/builtins/__init__.py:334`, `forge_c2/bof/builtins/__init__.py:411`.

Enterprise impact: a low-privilege dashboard user can inspect the dashboard host and potentially read data available to the dashboard process. This endpoint is neither a remote beacon workflow nor a safe demo boundary.

### Critical: Findings and evidence are mutable and cross-tenant

- Evidence stores raw requests, responses, paths, and arbitrary extras without redaction, encryption, hashing, signing, or custody metadata: `common/evidence.py:11`.
- Finding deduplication uses title, target host, and port only: `common/db.py:535`.
- Deduplication does not filter by tenant, run, module, path, parameter, or vulnerability identity before overwriting the existing row and evidence: `common/db.py:654`.
- Tokens contain no tenant claim, and the dashboard uses one environment-wide tenant: `common/dashboard/auth.py:270`, `common/dashboard/server.py:241`.

Enterprise impact: distinct findings can collapse, prior evidence can be replaced, and nominal tenants can contaminate each other.

### Critical: Compliance output creates false assurance

- A rule with no matching finding is treated as `PASS`, regardless of whether the relevant test ran or the scan failed: `common/reporting/compliance_engine.py:63`.
- PCI 11.3.1 is hardcoded to pass because Forge itself ran a test: `common/reporting/compliance_engine.py:253`.
- The tests explicitly require a clean/empty finding set to produce a high compliance percentage: `tests/test_compliance.py:232`, `tests/test_compliance.py:244`.

Enterprise impact: an incomplete or failed assessment can be presented as compliant. Compliance must default to `not_tested` without collection evidence and applicability.

### Critical: NetForge's discovery-to-vulnerability pipeline is internally inconsistent

- Modules within each discovery phase run concurrently through `gather`, including consumers that depend on another module's shared output: `netforge/netforge.py:789`.
- `port_scanner` stores port dictionaries: `netforge/modules/discovery/port_scanner.py:117`.
- `service_id` iterates those dictionaries as ports and ultimately passes each dictionary to `asyncio.open_connection`: `netforge/modules/discovery/service_id.py:65`, `netforge/modules/discovery/service_id.py:123`.
- Failures are swallowed, starving service fingerprints, CPEs, and downstream vulnerability matching.

Enterprise impact: scan results vary with task timing and can silently omit most vulnerability correlation.

### Critical: NetForge's CVE and YAML content cannot be trusted

- The documented update command populates the common intelligence DB, while the CPE engine reads a different NetForge cache: `Makefile:26`, `common/intel/intel_engine.py:204`, `netforge/data/cve_db.py:30`.
- The alternate NVD updater requests whole calendar years without chunking and records freshness even after failed updates: `netforge/data/cve_db.py:227`, `netforge/data/cve_db.py:275`.
- The YAML engine constructs HTTP URLs from the original target rather than discovered host/scheme context: `netforge/modules/vuln/yaml_check_engine.py:223`.
- The bundled Log4Shell check treats ordinary HTTP statuses as a critical match: `netforge/data/checks/cisa_kev/log4shell.yaml:20`.
- The native corpus loads 102 definitions but has only 101 unique IDs because Zerologon is duplicated: `netforge/data/checks/active_directory/ad_checks.yaml:131`, `netforge/data/checks/cisa_kev/critical_cves.yaml:161`.
- A `MEDIUM` confidence check is automatically marked verified: `netforge/modules/vuln/yaml_check_engine.py:654`, `common/base_module.py:319`.

Enterprise impact: feed freshness can be false, checks can target invalid URLs, and weak signals can become verified critical findings.

### Critical: ADForge's collection contract breaks advertised workflows

- For authenticated username binds, `LdapClient` accepts hash and Kerberos options but ignores them and uses `self.password` with NTLM; the separate no-username path is anonymous: `adforge/core/ldap_client.py:16`, `adforge/core/ldap_client.py:40`, `adforge/core/ldap_client.py:54`.
- Searches are not paged and errors become empty results: `adforge/core/ldap_client.py:74`.
- Thirteen modules call `client.base_dn` or `search_base=`, which the client does not expose; representative failures are `adforge/modules/enum/adcs_enum.py:71` and `adforge/modules/adcs/esc4_check.py:29`.
- AD graph collection is not wired into collectors, while the attack-path SVG links findings sequentially: `adforge/modules/reporting/attack_path_svg.py:39`.

Enterprise impact: large-directory collection truncates silently, advertised auth modes do not work, and attack paths do not represent effective identity relationships.

### Critical: C2 is not an authenticated, encrypted end-to-end protocol

- The unified CLI imports a nonexistent `C2Server` instead of the implemented `TeamServer`: `forge.py:739`, `forge_c2/server.py:806`.
- HTTP and advertised HTTPS use the same bare asyncio listener without an SSL context: `forge_c2/server.py:369`, `forge_c2/server.py:518`.
- The operator protocol is plaintext JSON over TCP: `forge_c2/server.py:935`.
- Registration does not establish a usable key exchange, encrypted inbound data cannot identify its beacon, results remain plaintext, and replay counters are not enforced: `forge_c2/server.py:579`, `forge_c2/server.py:610`, `forge_c2/server.py:652`, `forge_c2/beacon/beacon_crypto.py:176`.
- DNS and SMB listeners intentionally fail as unimplemented: `forge_c2/server.py:568`.

Enterprise impact: current C2 claims substantially exceed the working protocol. This is below a minimum Cobalt Strike or Sliver comparison baseline.

### Critical: Cloud and leak-intelligence actions are not safely attributable

- Cloud engines are not registered in the unified launcher: `forge.py:66`.
- Container escape checks inspect the scanner host's `/proc`, mounts, devices, and capabilities and attribute them to the configured target: `cloud/container_escape.py:145`, `cloud/container_escape.py:168`, `cloud/container_escape.py:304`.
- Cloud metadata scanning probes fixed metadata hosts after validating a different target and stores token-bearing responses: `cloud/cloud_api_scanner.py:83`, `cloud/cloud_api_scanner.py:93`, `cloud/cloud_api_scanner.py:241`.
- Leak Intel validates credentials against third-party and enterprise services without a scope check or explicit credential-use authorization gate: `leak_intel/parsers/credential_tester.py:67`, `leak_intel/parsers/credential_tester.py:117`, `leak_intel/parsers/credential_tester.py:293`.

Enterprise impact: results can describe the wrong asset, leave declared scope, or use credentials without a defensible authorization event.

## High-Priority Maturity Gaps

### ForgeBrain does not yet provide autonomous or privacy-safe execution

- The autonomous engine records modules as executed without invoking them, while noisy mode can broadly approve exploit-phase plans if execution is later connected: `common/brain/autonomous.py:736`, `common/brain/autonomous.py:753`.
- ForgeBrain can send complete findings and engagement context to an external model without a canonical redaction boundary: `common/brain/brain.py:499`, `common/brain/brain.py:451`.
- EngagementBus persists credential material, including passwords and hashes, in ordinary SQLite fields: `common/brain/engagement_bus.py:137`, `common/brain/engagement_bus.py:243`, `common/brain/engagement_bus.py:254`.

The planning and narration code is useful research scaffolding, but it must not claim autonomous validation until actions, approvals, outcomes, evidence, and secrets all use the canonical control plane.

### Retest is not a retest verdict

The dashboard reruns the original module, forces black-box/external mode, strips Forge environment context, appends `--auto-confirm`, and determines completion from process exit. It leaves `still_vulnerable=None`: `common/dashboard/server.py:3343`, `common/dashboard/server.py:3361`, `common/dashboard/server.py:3446`.

A real retest must preserve the exact asset, route, parameter, identity/session, payload class, check version, and evidence expectation, then return `fixed`, `still_vulnerable`, `inconclusive`, `not_authorized`, or `failed`.

### Credential handling is below enterprise minimum

- NetForge transport credentials are stored in plaintext despite the encryption claim: `netforge/core/cred_transport.py:66`.
- SSH accepts unknown host keys and WinRM disables certificate verification: `netforge/core/cred_transport.py:178`, `netforge/core/cred_transport.py:492`.
- NetForge attempts to emit discovered secret values into dashboard events, but treats `Credential` objects as dictionaries; the first `.get()` raises before event emission and prevents the subsequent memory wipe: `netforge/netforge.py:843`, `netforge/core/cred_engine.py:263`, `netforge/netforge.py:848`.
- AD modules expose hashes/passwords through files, report text, or subprocess arguments: `adforge/modules/attacks/kerberoast.py:110`, `adforge/modules/reporting/bloodhound_export.py:56`, `adforge/modules/post/secretsdump.py:69`.

### WebForge has useful depth but lacks a safe, uniform request boundary

- Crawlers and schema import retain form actions or server URLs without one final scope decision: `webforge/modules/recon/link_crawler.py:411`, `webforge/core/browser_engine.py:326`, `webforge/modules/api/schema_import.py:127`.
- SQLi and XSS POST directly to those actions using a session that can carry global authorization headers: `webforge/modules/injection/sqli_scanner.py:181`, `webforge/modules/injection/xss_scanner.py:125`, `webforge/core/session.py:126`.
- `ForgeSession` disables TLS verification by default and follows redirects: `webforge/core/session.py:27`, `webforge/core/session.py:94`.
- Retry handling does not release a 429 response before retrying: `webforge/core/session.py:98`.
- Shared helpers also create direct `aiohttp` sessions with TLS disabled, bypassing one canonical request/scope boundary: `common/base_module.py:390`, `common/base_module.py:482`.
- Browser navigation and click discovery do not revalidate the final destination and can activate non-submit state-changing controls: `webforge/core/crawl_orchestrator.py:681`, `webforge/core/crawl_orchestrator.py:825`.
- OOB remote correlation is not functional in the path wired by WebForge: `forge_collab/server.py:1285`, `webforge/webforge.py:1319`.

Whitebox mode also uses inconsistent source keys. The CLI stores `source_path`, while secret/dependency modules read `source_dir` and default to the scanner working directory: `webforge/webforge.py:1265`, `webforge/modules/whitebox/secret_scan.py:77`, `webforge/modules/whitebox/dep_audit.py:31`. This can scan and persist secrets from the wrong local tree.

### AIForge is a prompt catalog, not yet a calibrated evaluation system

- TLS verification is disabled globally: `aiforge/core/llm_client.py:100`.
- The client advertises retry/backoff but performs no retry loop, and Azure maps to the generic OpenAI handler: `aiforge/core/llm_client.py:114`, `aiforge/core/llm_client.py:142`.
- Many verdicts rely on substring or regex matches rather than separated probe, detector, scorer, attempt, and baseline contracts: `aiforge/modules/injection/direct_inject.py:290`, `aiforge/modules/jailbreak/jailbreak_test.py:196`, `aiforge/modules/output/hallucination_test.py:95`.

### Payload breadth is not artifact correctness

- Direct factory calls default several evasion features on and do not require the CLI authorization gate: `forge_payload/payload_factory.py:85`, `forge_payload/payload_factory.py:181`.
- Some advertised outputs are metadata/NOP placeholders or source text written with an executable suffix: `forge_payload/payload_factory.py:297`, `forge_payload/formats/pe_builder.py:111`.

### Distributed agents lack enterprise identity and leasing

- Agent tokens are optional; mTLS identity may be supplied in the request body: `common/dashboard/server.py:2769`, `common/dashboard/server.py:2784`.
- Agent state is JSON, leases have no expiry/ownership token, and active execution appends `--auto-confirm`: `common/dashboard/server.py:2695`, `common/dashboard/server.py:2895`, `forge_agent.py:150`.

### The dashboard is broader than its backend workflows

Scheduling is explicitly rejected at runtime: `common/dashboard/server.py:1576`. Team, activity, integrations, and several other pages are static or browser-local: `apex-ui/src/pages/TeamManagement.jsx:7`, `apex-ui/src/pages/ActivityLogs.jsx:7`, `apex-ui/src/pages/Integrations.jsx:7`. Vulnerability ownership, SLA, notes, and tickets are stored locally or simulated: `apex-ui/src/pages/Vulnerabilities.jsx:48`, `apex-ui/src/pages/Vulnerabilities.jsx:333`.

## Quality And Release Evidence

### Reproducibility record

The input manifest uses Git's tracked/untracked inventory with standard ignore rules, then applies an explicit allowlist for source, tests, frontend source/assets, workflows, and top-level build/runtime configuration. It excludes ignored files, dependencies, caches, runtime TLS material, environment overrides, engagement data, scan results/evidence, and assessment outputs. The non-output `git status --porcelain=v1 -z --untracked-files=all` stream has SHA-256 `044a3f3294d2711feec69527ff3e0ed4269b0d221fde41f7de93cf5cc8a81f88`.

Tool versions used for the final verification pass:

- Python 3.13.9; pytest 8.4.2; Coverage.py 7.8.2; mypy 2.1.0.
- Node 20.19.5; npm 9.2.0; Vite 8.0.16; Vitest 3.2.6.
- Ruff was not installed locally, so the CI Ruff command was not rerun.

Exact principal commands and results:

```bash
# Git-aware allowlisted input manifest; ignored/runtime/engagement/output files cannot enter.
export LC_ALL=C
git ls-files -co --exclude-standard -z | sort -z |
while IFS= read -r -d '' path; do
  case "$path" in
    .github/workflows/*|adforge/*|aiforge/*|cloud/*|common/*|forge_c2/*|forge_collab/*|forge_payload/*|leak_intel/*|netforge/*|tests/*|webforge/*) ;;
    apex-ui/src/*|apex-ui/public/*|apex-ui/index.html|apex-ui/package.json|apex-ui/package-lock.json|apex-ui/vite.config.js) ;;
    .dockerignore|.env.example|.gitignore|Dockerfile|Makefile|docker-compose.yml|forge.py|forge_agent.py|install.sh|requirements.txt|pyproject.toml|pytest.ini|setup.cfg|mypy.ini|tox.ini) ;;
    *) continue ;;
  esac
  case "$path" in
    */results/*|*/__pycache__/*|*/.pytest_cache/*|*/.mypy_cache/*|*/tmp/*) continue ;;
  esac
  [[ -f "$path" ]] && printf '%s\0' "$path"
done | xargs -0 sha256sum > ASSESSMENT_INPUT_MANIFEST.sha256

# Dirty-state index digest, excluding the assessment outputs/runtime artifacts.
git status --porcelain=v1 -z --untracked-files=all -- . \
  ':(exclude)ENTERPRISE_MATURITY_ASSESSMENT.md' \
  ':(exclude)ROADMAP.md' ':(exclude)COMMERCIAL_COMPARISON.md' \
  ':(exclude)HANDOFF.md' ':(exclude)ROADMAP2ND.md' \
  ':(exclude)ASSESSMENT_INPUT_MANIFEST.sha256' \
  ':(exclude).coverage' ':(exclude)coverage.xml' \
  ':(exclude)scan_jobs.db.schema.lock' | sha256sum

# All Python syntax/compile check: exit 0, one SyntaxWarning.
find . -name '*.py' ! -path './apex-ui/*' ! -path './.git/*' \
  -print0 | xargs -0 python -m py_compile

# CI-scoped Python tests: 307 passed, 3 skipped, 2 failed.
python -m pytest tests/ -v --tb=short --strict-markers \
  -p no:warnings --timeout=60

# Full repository collection plus selected-source coverage:
# 317 passed, 3 skipped, 2 failed, 2 warnings; total coverage 37%.
python -m pytest -q --cov=common --cov=webforge/core \
  --cov=netforge/data --cov-report=term

# Same mypy scope as CI: 56 errors in 15 files.
python -m mypy --ignore-missing-imports --follow-imports=silent common forge.py

# Frontend: build passed; tests 25/25 in two files.
(cd apex-ui && npm run build)
(cd apex-ui && npm test)

# Production-package test-like functions and normal package collection.
grep -R -h -E '^[[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_' \
  common webforge netforge adforge aiforge forge_c2 forge_collab \
  forge_payload cloud leak_intel --include='*.py' | wc -l
python -m pytest --collect-only -q common webforge netforge adforge \
  aiforge forge_c2 forge_collab forge_payload cloud leak_intel
```

Mapping imports were checked through each engine's existing loader:

```python
from webforge import webforge as web
from netforge import netforge as net
from adforge import adforge as ad
from aiforge import aiforge as ai

for label, mapping, loader in (
    ("WebForge", web.MODULE_MAP, web.load_module_class),
    ("NetForge", net.MODULE_MAP, net.load_module),
    ("ADForge", ad.MODULE_MAP, ad.load_module),
    ("AIForge", ai.MODULE_MAP, ai.load_module_class),
):
    failures = [name for name in mapping if loader(name) is None]
    print(label, len(mapping) - len(failures), len(mapping), failures)
```

All 33 unique public comparison URLs returned HTTP 200 through `curl -L` on 2026-07-19. Reachability confirms the cited page existed; it does not independently validate vendor claims.

### Current verification results

- Python compile: passed for all Python files, with one `SyntaxWarning` in `forge_payload/delivery/lnk_builder.py`.
- Full repository/coverage command: **317 passed, 3 skipped, 2 failed, 2 warnings**. The CI-scoped `tests/` command produced **307 passed, 3 skipped, 2 failed**.
- Failures: WebForge dry-run instantiates modules and multi-target automation returns the wrong finding summary: `tests/test_webforge_automation_contracts.py:102`, `tests/test_webforge_automation_contracts.py:206`.
- Selected coverage run across `common`, `webforge/core`, and `netforge/data`: **37% total**.
- Critical coverage examples: `webforge/core/crawl_orchestrator.py` 14%, `webforge/core/session.py` 0%, `netforge/data/check_schema.py` 0%, `netforge/data/cve_db.py` 0%, `common/evidence.py` 34%.
- Mypy result: **56 errors in 15 files** under the same scope used by CI.
- Frontend production build: passed.
- Frontend tests: **25 passed in 2 test files**; primary page workflows are not tested.
- Import check: WebForge 71/71 mappings import; NetForge 129/131; ADForge 86/86; AIForge 30/30. EternalBlue and BlueKeep fail class-name resolution at `netforge/netforge.py:296`.

### Test-count illusion

The recorded production-directory search found 1,447 embedded `test_*` functions, but standard pytest discovery collected only 10 tests from those packages because most functions are outside files matching either default discoverable pattern, `test_*.py` or `*_test.py`. CI runs only `tests/`: `.github/workflows/ci.yml:104`. The many embedded test classes therefore inflate source size without providing the advertised regression coverage.

The opt-in lab tests only prove that DVWA, WebGoat, or Metasploitable are reachable; they do not assert that Forge detects vulnerable fixtures or rejects patched controls: `tests/test_lab_integration_opt_in.py:18`.

### CI and release gaps

- Bandit is forced to exit zero, so the security job cannot fail on findings: `.github/workflows/ci.yml:143`.
- Coverage has no minimum threshold: `.github/workflows/ci.yml:211`.
- CI does not build or test the React page workflows.
- Python dependencies are lower-bound ranges with no lockfile, SBOM, or release provenance.
- Docker downloads the latest Nuclei release dynamically without checksum verification and ignores failure: `Dockerfile:65`.
- Docker and Compose set weak dashboard/C2 passwords by default: `Dockerfile:84`, `docker-compose.yml:22`, `docker-compose.yml:45`.
- The repository has nine commits, no release tags, code version `5.0.0`, frontend version `0.0.0`, and documents claiming `v5.3`.

## Primary Orchestrator Mapping Inventory

| Engine | Registered mappings | Import result | Important truth gap |
|---|---:|---:|---|
| WebForge | 71 | 71 | 16 additional Python files under module directories are absent from the mapping: 15 module implementations and one schema-import helper; several default paths run only subsets |
| NetForge | 131 | 129 | EternalBlue and BlueKeep silently skip; downstream discovery contracts are broken |
| ADForge | 86 | 86 | Import success hides LDAP runtime API failures and simulated actions |
| AIForge | 30 | 30 | Broad prompt set, but evaluation quality is largely heuristic |
| Native NetForge YAML checks | 102 loaded definitions / 101 unique IDs | Loads structurally | Duplicate IDs, weak OR/status matches, and absent positive/negative fixtures invalidate quality claims |

## What Is Worth Preserving

- A unified product vision across web, network, AD, AI, OOB, C2, evidence, reporting, and operator workflow.
- `BaseModule` scope, rate, finding, and event hooks: `common/base_module.py:149`, `common/base_module.py:161`, `common/base_module.py:182`.
- Structured job, retest, and audit model beginnings: `common/db.py:93`, `common/db.py:118`, `common/db.py:155`.
- Web crawler and browser-discovery ambition, including SPA, shadow DOM, AJAX, WebSocket, and schema concepts.
- NetForge's CPE/CVE/YAML architecture as a direction, once its contracts and content QA are rebuilt.
- ADForge's broad enumeration and ADCS taxonomy, once collection and effective-rights graphing are corrected.
- Report format breadth and confidence display.
- Payload CLI dual opt-in and safe C2 emulation work: `forge.py:1138`, `forge_c2/emulation.py`.
- Agent dry-run defaults: `forge_agent.py:106`.

## How Forge Can Eventually Beat Enterprise Tools

Matching Tenable's content volume, Invicti's years of crawler validation, BloodHound's graph semantics, or Cobalt Strike's protocol maturity is not a near-term target. Forge can become better in narrower, defensible dimensions:

1. Every finding can expose exactly which check, request, response, identity, asset, observation, and evidence artifact produced it.
2. Cross-engine context can connect a web issue, exposed service, AD privilege path, cloud identity, and retest in one evidence graph.
3. Authorization and scope can be stronger and more visible than typical offensive prototypes.
4. Self-hosted and offline workflows can give operators better privacy and inspectability.
5. Open, versioned check logic and fixture-backed precision metrics can make results easier to trust and dispute.

Those advantages require finishing the existing vertical workflows. More modules would move the project further away from them.

## Public Product Baselines

Public product material was checked on 2026-07-19. These sources define the comparison baseline; they do not substitute for a licensed lab benchmark.

- Tenable Nessus Expert: https://www.tenable.com/products/nessus/nessus-expert
- Tenable plugin feed: https://www.tenable.com/plugins
- Qualys VMDR: https://www.qualys.com/apps/vulnerability-management-detection-response/
- Rapid7 InsightVM: https://www.rapid7.com/products/insightvm/
- Invicti Application Security Platform: https://www.invicti.com/product/
- Acunetix web vulnerability scanner: https://www.acunetix.com/vulnerability-scanner/
- AcuMonitor technology: https://www.acunetix.com/vulnerability-scanner/acumonitor-technology/
- Burp Suite DAST: https://portswigger.net/burp/application-security-testing/dast
- Cobalt Strike user guide: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm
- Sliver: https://sliver.sh/
- Metasploit documentation: https://docs.metasploit.com/
- BloodHound documentation: https://bloodhound.specterops.io/get-started/introduction
- PingCastle: https://www.pingcastle.com/
- NetExec: https://www.netexec.wiki/
- Certipy: https://github.com/ly4k/Certipy
- Wiz platform: https://www.wiz.io/platform
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- GitGuardian secrets detection documentation: https://docs.gitguardian.com/secrets-detection/home
- TruffleHog: https://trufflesecurity.com/trufflehog
- Garak: https://garak.ai/
- Microsoft PyRIT repository: https://github.com/microsoft/PyRIT
- Microsoft PyRIT documentation: https://azure.github.io/PyRIT/
- Pentera: https://pentera.io/
- Horizon3.ai NodeZero: https://horizon3.ai/nodezero/
- ProjectDiscovery Nuclei templates: https://docs.projectdiscovery.io/templates/introduction
- Dradis Pro: https://dradis.com/pro/
- PlexTrac: https://plextrac.com/platform/
- Faraday: https://faradaysec.com/
- DefectDojo: https://docs.defectdojo.com/
- Burp Collaborator: https://portswigger.net/burp/documentation/collaborator
- Prisma Cloud: https://www.paloaltonetworks.com/prisma/cloud
- Trivy: https://trivy.dev/docs/latest/
- Kubescape: https://kubescape.io/

## Bottom Line

Forge Suite is not currently 7/10 against Nessus, Invicti/Acunetix, BloodHound, and Cobalt Strike. Its capability surface is impressive, but its verified enterprise maturity is approximately 2.8/10. The shortest route upward is not more security checks. It is correctness, proof, authorization, evidence integrity, recovery, and repeatable lab performance across the modules that already exist.
