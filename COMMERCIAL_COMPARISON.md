# Forge Suite Enterprise-Leader Comparison

Comparison date: 2026-07-19  
Repository basis: base commit `774e0722bb4cc50a064f414e565e61feb6f4bf21` plus [ASSESSMENT_INPUT_MANIFEST.sha256](ASSESSMENT_INPUT_MANIFEST.sha256), 691 source/test/build/configuration files, manifest SHA-256 `feb56b17035ea9575198e3a69d0724ae296525e1caa59ff3f57f442851be1ee1`  
External baseline: public vendor documentation checked on 2026-07-19  
Assessment scope: static code review, safe import checks, local tests/builds, and documentation review  
Excluded: live target scans, credential use, payload execution, licensed-product benchmarks, and vendor support evaluation

## Executive Verdict

Forge Suite is an ambitious authorized-security research workbench or early alpha. It is not currently an enterprise-grade replacement for Tenable Nessus, Invicti/Acunetix or Burp Suite DAST, BloodHound, Cobalt Strike, Wiz, GitGuardian, Garak/PyRIT, Pentera/NodeZero-style validation platforms, or Dradis Pro in their respective specialties.

Current weighted parity against category leaders: **1.4/5 (2.8/10)**.

This is a maturity score, not a count of features and not a live detection benchmark. Forge's broad taxonomy, shared abstractions, browser/crawler work, reporting primitives, and unified vision are worth preserving. The present implementation does not yet provide the execution correctness, authorization boundaries, proof quality, immutable evidence, retest integrity, recovery, validation, or product operations needed to turn that breadth into dependable enterprise workflows.

The previous `7-8/10` positioning was not supported by repository or test evidence and is superseded by this comparison and `ENTERPRISE_MATURITY_ASSESSMENT.md`.

## Product Decision: Depth Only

This comparison adopts the breadth freeze in `ROADMAP.md`:

- Add no engine, module family, exploit family, transport, payload format, dashboard page, mobile capability, or new check pack.
- Stop treating source-file, module, probe, format, or check counts as evidence of maturity.
- Deepen existing workflows through authorization, execution, observation, proof, persistence, cancellation, retest, reporting, and audit.
- Classify every existing capability as `verified`, `heuristic`, `wrapper`, `simulation`, `experimental`, or `disabled`.
- Treat deleting, disabling, merging, or relabeling a weak capability as valid progress.

Commercial products are used to define acceptance standards for Forge's existing surface, not to justify more surface.

## Method And Claim Boundaries

| Evidence class | Meaning in this document |
|---|---|
| Repository-verified | A claim supported by inspected Forge source, configuration, or a locally executed test/build/import result |
| Vendor/project-described | A capability described in a vendor's or project's public documentation; it was not independently validated here |
| Not assessed | Detection accuracy, performance, support quality, and licensed deployment behavior that would require a controlled product shootout |

No numeric score is assigned to a vendor. Forge scores use the rubric below and express current parity with the relevant category leader, not a vendor quality rating.

| Forge score | Maturity meaning |
|---:|---|
| 0 | Absent |
| 1 | Prototype: code or UI exists, but the core workflow is incomplete or misleading |
| 2 | Coherent alpha: meaningful implementation exists, but reliability, proof, safety, or integration is incomplete |
| 3 | Usable beta: repeatable practitioner workflow with bounded limitations and real lab validation |
| 4 | Production-ready: durable, secure, scalable, supportable, and broadly validated |
| 5 | Category-leader parity |

Scores weight correctness, workflow completeness, safe authorization, evidence/retest integrity, validation, scale, and maintainability. A module importing, a check loading, or a page rendering does not establish maturity.

## Enterprise-Leader Matrix

| Existing Forge area | Score / 5 | Portfolio weight | Relevant leader baseline | Evidence-based current position |
|---|---:|---:|---|---|
| WebForge DAST and API testing | 2.0 | 12% | Invicti, Acunetix, Burp Suite DAST | Substantial alpha with real crawler, browser, session, and schema work; proof, scope-safe navigation, authenticated state, OOB correlation, and validation remain inconsistent |
| NetForge vulnerability assessment | 1.5 | 12% | Tenable Nessus | Prototype architecture with discovery, CPE/CVE, YAML, and credentialed concepts; pipeline contracts, intelligence updates, check quality, credential security, and compliance applicability are unreliable |
| ADForge identity assessment | 1.1 | 10% | BloodHound Enterprise | Broad AD/ADCS taxonomy, but LDAP authentication, paging, module APIs, effective-rights graphing, and lab validation have major failures |
| AIForge model testing | 1.7 | 7% | Garak, Microsoft PyRIT | Broad prompt/probe catalog; transport safety, provider adapters, retries, repeated trials, calibrated detectors, controls, and reproducibility are immature |
| ForgeBrain and autonomous attack chaining | 1.2 | 4% | Pentera, NodeZero-style automated validation | Planning, analyst, narrator, engagement-bus, and chain scaffolding exists, but the advertised autonomous executor is simulated, can report logged actions as executed, and lacks a canonical authorization/evidence workflow |
| Intelligence and vulnerability-content pipeline | 1.3 | 5% | Tenable content lifecycle, Nuclei ecosystem | CVE, exploit, Nuclei-metadata, ATT&CK, offline-store, and native-YAML concepts exist; stores are disconnected, updates are not atomic, content provenance/maturity is weak, and synced metadata does not become a verified executable check lifecycle |
| Forge C2 | 1.0 | 7% | Cobalt Strike | Team-server and beacon scaffolding exists, but the supported CLI, TLS, authentication, encryption, replay defense, task lineage, and durable protocol are not end to end |
| Payload and implant pipeline | 1.0 | 3% | Cobalt Strike artifact workflows | Many advertised formats exist, but some artifacts are placeholders or source text and high-risk authorization is not enforced at every library boundary |
| Cloud CSPM/CNAPP | 0.7 | 5% | Wiz | Point probes exist, but provider-native inventory, stable cloud-resource identity, context graphing, and dependable target attribution do not |
| Container and Kubernetes security | 0.9 | 3% | Trivy and Wiz-style workload assessment | Local and workload-oriented checks exist, but collection mode, inspected-host identity, image/SBOM/config/runtime lineage, and remote attribution are unreliable |
| Leak intelligence and secret exposure | 1.0 | 4% | GitGuardian | Parser and source scaffolding exists; full-history coverage, detector validation, safe fingerprints, authorization, and remediation lifecycle are incomplete |
| ForgeCollab OOB verification | 1.1 | 3% | Burp Collaborator, AcuMonitor | Listener components exist, but persistent remote token registration, callback correlation, tenant isolation, restart recovery, and reportable evidence are not dependable |
| Common orchestration and jobs | 2.2 | 6% | Tenable/Invicti control planes | Useful abstractions and early durable models exist; authorization, dependency ordering, leases, restart recovery, idempotency, and cancellation are incomplete |
| Evidence integrity and custody | 1.2 | 5% | Enterprise assessment/reporting platforms | Evidence attachments exist, but observations are mutable and lack a complete redaction, hashing, signing, encryption, retention, and custody model |
| Reporting | 1.9 | 5% | Dradis Pro | Useful export and presentation primitives exist; compliance semantics, review workflow, canonical lineage, version locking, and collaboration are weak |
| Dashboard and control plane | 1.7 | 4% | Enterprise scanner consoles | Authentication, RBAC, SSO, audit, and workflow scaffolding exists; unsafe write paths, global controls, facade pages, and tenant isolation block production use |
| Distributed agents | 1.4 | 2% | Enterprise scan engines/nodes | Dry-run and scope concepts exist; agent identity, signed leases, durable ownership, result integrity, recovery, and revocation are immature |
| Team and vulnerability management | 1.0 | 3% | Dradis Pro and equivalent platforms | Several operator views exist, but ownership, notes, SLA, tickets, and activity are largely browser-local, static, or simulated rather than shared canonical state |

This 18-row inventory and weight model matches `ENTERPRISE_MATURITY_ASSESSMENT.md`. ForgeBrain, the intelligence/content pipeline, cloud CSPM/CNAPP, and container/Kubernetes are existing product families surfaced for scoring clarity; they are not proposed modules or breadth expansion.

### Weighted Method

The overall score is reproducible rather than a simple row average. The portfolio weights below are the same weights disclosed in `ENTERPRISE_MATURITY_ASSESSMENT.md`; they emphasize the primary assessment engines while keeping control-plane, evidence, and reporting failures material because those failures can invalidate results from every engine.

| Existing Forge area | Score / 5 | Weight | Weighted contribution |
|---|---:|---:|---:|
| WebForge | 2.0 | 12% | 0.240 |
| NetForge | 1.5 | 12% | 0.180 |
| ADForge | 1.1 | 10% | 0.110 |
| AIForge | 1.7 | 7% | 0.119 |
| ForgeBrain/autonomous chaining | 1.2 | 4% | 0.048 |
| Intelligence/content pipeline | 1.3 | 5% | 0.065 |
| Forge C2 | 1.0 | 7% | 0.070 |
| Payload/implant pipeline | 1.0 | 3% | 0.030 |
| Cloud CSPM | 0.7 | 5% | 0.035 |
| Container/Kubernetes | 0.9 | 3% | 0.027 |
| Leak intelligence | 1.0 | 4% | 0.040 |
| ForgeCollab OOB | 1.1 | 3% | 0.033 |
| Common orchestration/jobs | 2.2 | 6% | 0.132 |
| Evidence integrity/custody | 1.2 | 5% | 0.060 |
| Reporting | 1.9 | 5% | 0.095 |
| Dashboard/control plane | 1.7 | 4% | 0.068 |
| Distributed agents | 1.4 | 2% | 0.028 |
| Team/vulnerability management | 1.0 | 3% | 0.030 |
| **Total** |  | **100%** | **1.410 / 5** |

The raw weighted result is `1.410/5`, reported to one decimal as **1.4/5**. Doubling the raw result gives `2.820/10`, reported to one decimal as **2.8/10**. These weights are an assessment convention, not a market-share model or a claim that unlike product categories are functionally interchangeable.

## Category Comparisons

### WebForge vs Invicti, Acunetix, And Burp Suite DAST

Vendor-described baseline:

- Invicti and Acunetix describe automated DAST for web applications and APIs, authenticated scanning, proof-oriented validation, and application-security workflow integration.
- Burp Suite DAST describes automated web vulnerability scanning for enterprise application-security workflows.
- Burp Collaborator and AcuMonitor describe out-of-band interaction services for confirming blind vulnerability classes.

Repository-verified Forge position:

- WebForge has meaningful browser, crawler, authentication, session, API-schema, and finding abstractions; all 71 registered mappings imported in the assessment check.
- The crawler retains form actions without one final canonical scope decision, while SQL injection and XSS modules can post to those actions with shared authorization state: `webforge/modules/recon/link_crawler.py:411`, `webforge/modules/injection/sqli_scanner.py:181`, `webforge/modules/injection/xss_scanner.py:125`.
- `ForgeSession` disables TLS verification by default and follows redirects, and browser navigation does not consistently revalidate final destinations: `webforge/core/session.py:27`, `webforge/core/session.py:94`, `webforge/core/crawl_orchestrator.py:681`.
- The CLI stores `source_path`, while whitebox modules read `source_dir` and can default to the scanner working directory: `webforge/webforge.py:1265`, `webforge/modules/whitebox/secret_scan.py:77`, `webforge/modules/whitebox/dep_audit.py:31`.
- The remote OOB path used by WebForge does not establish dependable correlation: `forge_collab/server.py:1285`, `webforge/webforge.py:1319`.
- Two current Python test failures are WebForge automation-contract regressions: `tests/test_webforge_automation_contracts.py:102`, `tests/test_webforge_automation_contracts.py:206`.

Decision: Forge has a coherent alpha foundation, but it cannot claim proof-based DAST parity. The competitive work is to unify the existing crawl, request, mutation, proof, auth, whitebox, and OOB paths under one scope-aware evidence contract. Adding vulnerability families would deepen the trust gap.

### NetForge vs Tenable Nessus

Vendor-described baseline:

- Tenable describes Nessus Expert as vulnerability assessment across IT and internet-facing assets, with vulnerability intelligence updates, prioritization, scan policies/templates, reporting, and live-result workflows.

Repository-verified Forge position:

- NetForge contains real discovery, service identification, CPE/CVE, YAML-check, credentialed-assessment, and reporting concepts; 129 of 131 registered mappings imported in the assessment check.
- Modules within each discovery phase run concurrently, `port_scanner` stores dictionaries, and `service_id` iterates those dictionaries as ports before passing them to the socket call: `netforge/netforge.py:789`, `netforge/modules/discovery/port_scanner.py:117`, `netforge/modules/discovery/service_id.py:65`, `netforge/modules/discovery/service_id.py:123`.
- The documented intelligence update path and the NetForge CPE engine use different stores; the alternate NVD updater requests whole calendar years without chunking and records freshness after failed updates: `common/intel/intel_engine.py:204`, `netforge/data/cve_db.py:30`, `netforge/data/cve_db.py:227`, `netforge/data/cve_db.py:275`.
- The bundled Log4Shell YAML check accepts ordinary HTTP statuses as a critical match, and medium-confidence results can become verified: `netforge/data/checks/cisa_kev/log4shell.yaml:20`, `netforge/modules/vuln/yaml_check_engine.py:654`, `common/base_module.py:319`.
- The native corpus loads 102 definitions but only 101 unique IDs because Zerologon is duplicated: `netforge/data/checks/active_directory/ad_checks.yaml:131`, `netforge/data/checks/cisa_kev/critical_cves.yaml:161`.
- Compliance rules infer `PASS` from an absent finding and include a hardcoded pass: `common/reporting/compliance_engine.py:63`, `common/reporting/compliance_engine.py:253`.
- Credential transport stores secrets in plaintext and weakens SSH/WinRM identity verification: `netforge/core/cred_transport.py:66`, `netforge/core/cred_transport.py:178`, `netforge/core/cred_transport.py:492`.

Decision: architecture and content volume do not establish Nessus-like reliability. NetForge must first make the existing discovery graph deterministic, consolidate its intelligence database, remove duplicate check IDs, fixture-test the current native YAML corpus, protect credentials, and make compliance results evidence- and applicability-based. No new checks or check packs should enter before that gate passes.

### Intelligence And Detection Content vs Tenable And The Nuclei Ecosystem

Vendor/community-described baseline:

- Tenable describes a continuously updated vulnerability-content and policy ecosystem supporting its assessment workflows.
- ProjectDiscovery documents Nuclei templates as YAML detection workflows consumed by the Nuclei engine, with template structure, matchers, extractors, and community content processes.

Repository-verified Forge position:

- `IntelEngine` registers CVE, Exploit-DB, Nuclei metadata, and ATT&CK sources in one searchable SQLite model: `common/intel/intel_engine.py:340`, `common/intel/intel_engine.py:364`.
- NetForge's CPE vulnerability engine reads a different cache from the common intelligence store populated by the documented CLI: `common/intel/intel_engine.py:204`, `netforge/data/cve_db.py:30`.
- CVE pages are committed incrementally; a later fetch failure returns the partial result and `IntelEngine` marks the source `COMPLETED`, so updates are not atomic snapshots: `common/intel/cve_sync.py:190`, `common/intel/cve_sync.py:220`, `common/intel/cve_sync.py:589`, `common/intel/intel_engine.py:576`.
- GitHub-mode Nuclei sync caps inventory at 5,000 paths, derives most metadata from filenames/directories, and stores metadata rather than a validated executable template set: `common/intel/nuclei_sync.py:426`, `common/intel/nuclei_sync.py:468`, `common/intel/nuclei_sync.py:520`.
- The NetForge Nuclei wrapper invokes whichever external `nuclei` binary and template directory happen to be installed; it is not bound to the synced metadata snapshot or a reviewed Forge content version: `netforge/modules/vuln/nuclei_runner.py:49`, `netforge/modules/vuln/nuclei_runner.py:54`, `netforge/modules/vuln/nuclei_runner.py:70`.
- Native YAML checks have no complete positive/negative fixture corpus, and current examples can promote weak signals into severe verified findings.

Decision: Forge has the outline of an offline-friendly intelligence service, not an enterprise content lifecycle. Depth work must consolidate existing stores, make feed/check-pack updates atomic and recoverable, preserve provenance and hashes, bind executable content to reviewed versions, and fixture-test the current native corpus. It must not ingest or create more checks until the current content is trustworthy.

### ADForge vs BloodHound Enterprise

Vendor-described baseline:

- BloodHound documentation describes graph-based identity and attack-path analysis built from collected directory relationships and permissions.

Repository-verified Forge position:

- ADForge has broad enumeration, ACL, delegation, Kerberos, GPO, ADCS, reporting, and BloodHound-export taxonomy; all 86 registered mappings imported in the assessment check.
- `LdapClient` advertises hashes and Kerberos flags but constructs password-based NTLM authentication, does not page searches, and converts errors to empty results: `adforge/core/ldap_client.py:16`, `adforge/core/ldap_client.py:40`, `adforge/core/ldap_client.py:74`.
- Multiple modules call LDAP APIs or attributes that the client does not expose; examples include `adforge/modules/enum/adcs_enum.py:71` and `adforge/modules/adcs/esc4_check.py:29`.
- Existing attack-path rendering links findings sequentially rather than deriving paths from a canonical effective-rights graph: `adforge/modules/reporting/attack_path_svg.py:39`.

Decision: import breadth is not graph correctness. ADForge must repair collection, stable identities, auth modes, paging, rights semantics, and evidence-backed graph edges before its existing risk families can be compared credibly with BloodHound. New attack families would not address the collection foundation.

### AIForge vs Garak And Microsoft PyRIT

Vendor-described baseline:

- Garak describes an LLM vulnerability scanner organized around probes, generators, detectors, and evaluation outputs.
- Microsoft describes PyRIT as a framework for identifying generative-AI risks and orchestrating repeatable red-team evaluation workflows.

Repository-verified Forge position:

- AIForge has 30 registered mappings covering a broad prompt and behavior taxonomy; all imported in the assessment check.
- TLS verification is disabled globally, advertised retry/backoff has no retry loop, and Azure uses the generic OpenAI handler: `aiforge/core/llm_client.py:100`, `aiforge/core/llm_client.py:114`, `aiforge/core/llm_client.py:142`.
- Several verdicts rely on substring or regex matches without a separated attempt, baseline, detector, scorer, and aggregate-verdict contract: `aiforge/modules/injection/direct_inject.py:290`, `aiforge/modules/jailbreak/jailbreak_test.py:196`, `aiforge/modules/output/hallucination_test.py:95`.

Decision: AIForge is currently a broad prompt catalog, not a calibrated evaluation system. The depth target is repeatable trials, negative controls, versioned corpora, provider-contract validation, budgets, error taxonomy, and explainable aggregate confidence across the probes already present. New probe families are frozen.

### ForgeBrain And Autonomous Chaining vs Pentera/NodeZero-Style Validation

Vendor-described baseline:

- Pentera and Horizon3.ai describe automated security-validation or autonomous pentesting platforms that execute controlled assessment workflows, connect actions to verified exposure, and provide remediation-oriented results.

Repository-verified Forge position:

- Forge exposes a command described as a "Fully autonomous AI-driven VAPT engagement" and builds planner, analyst, narrator, engagement-bus, and ForgeBrain objects: `forge.py:181`, `forge.py:929`, `forge.py:963`.
- The engine models recon, scan, exploit, post, and report phases and has an approval queue, which is useful scaffolding: `common/brain/autonomous.py:386`, `common/brain/autonomous.py:425`, `common/brain/autonomous.py:475`.
- The current module execution hook explicitly does not call the framework orchestrators; it logs an action as `executed`, emits progress, and increments completed work: `common/brain/autonomous.py:490`, `common/brain/autonomous.py:493`, `common/brain/autonomous.py:743`, `common/brain/autonomous.py:757`, `common/brain/autonomous.py:764`.
- Finalization sets progress to 100% and phase to complete for any non-operator-abort path, including an error path: `common/brain/autonomous.py:514`, `common/brain/autonomous.py:528`.
- Auto-execution decisions are based largely on module-name sets, phase, and an OPSEC label rather than the canonical tenant, engagement, scope, identity, evidence, and per-action authorization contract required by the roadmap: `common/brain/autonomous.py:706`.
- ForgeBrain can send situation and engagement-memory context to an external model without a demonstrated centralized redaction policy at that boundary: `common/brain/brain.py:866`, `common/brain/brain.py:882`.

Decision: ForgeBrain is a planning/narrative prototype and the autonomous executor is currently a simulation. It must be labeled that way. The in-scope work is to connect it only after Gate 1's durable, scope-bound reference workflow exists, require human approval at risky action boundaries, redact external-model context, and evaluate recommendations against real persisted outcomes. Adding autonomous actions or attack chains would magnify unsafe and misleading behavior.

### Forge C2 And Payloads vs Cobalt Strike

Vendor-described baseline:

- Cobalt Strike documentation describes an integrated team-server, Beacon, listener, tasking, operator, customization, artifact, and reporting workflow.

Repository-verified Forge position:

- Forge contains team-server, listener, beacon, task, BOF, profile, payload, emulation, and dashboard scaffolding.
- The unified CLI imports a nonexistent `C2Server` rather than the implemented `TeamServer`: `forge.py:739`, `forge_c2/server.py:806`.
- Advertised HTTPS uses a bare asyncio listener without an SSL context, and the operator interface is plaintext JSON over TCP: `forge_c2/server.py:369`, `forge_c2/server.py:518`, `forge_c2/server.py:935`.
- Registration, key establishment, encrypted inbound identity, encrypted results, and replay counters do not form a usable end-to-end protocol: `forge_c2/server.py:579`, `forge_c2/server.py:610`, `forge_c2/server.py:652`, `forge_c2/beacon/beacon_crypto.py:176`.
- DNS and SMB listeners intentionally fail as unimplemented: `forge_c2/server.py:568`.
- Direct payload-factory calls can bypass the CLI's high-risk opt-in, and some outputs are placeholders or source written with executable suffixes while still being returned as successful artifacts: `forge_payload/payload_factory.py:85`, `forge_payload/payload_factory.py:181`, `forge_payload/payload_factory.py:297`, `forge_payload/payload_factory.py:429`, `forge_payload/formats/pe_builder.py:111`.

Decision: Forge C2 is architectural scaffolding, not an operational C2 product. Depth work is limited to making the existing HTTP/TCP, task, profile, BOF, payload, and emulation surfaces truthful, authenticated, encrypted, durable, auditable, and lab-validated. No new transport, BOF, payload format, task type, stealth, persistence, or evasion work belongs in the roadmap.

### Cloud Security Posture vs Wiz

Vendor-described baseline:

- Wiz describes a cloud-security platform that inventories cloud environments and connects resource, identity, configuration, exposure, vulnerability, and data context to prioritize risk.

Repository-verified Forge position:

- Forge has cloud point checks, but cloud engines are not registered in the unified launcher: `forge.py:66`.
- Metadata scanning validates one target, probes fixed metadata hosts, and can retain token-bearing responses: `cloud/cloud_api_scanner.py:83`, `cloud/cloud_api_scanner.py:93`, `cloud/cloud_api_scanner.py:241`.

Decision: at `0.7/5`, Forge Cloud is a set of point probes rather than CSPM. It cannot make credible cloud-context claims until every existing result identifies the actual account/project/subscription, provider resource, identity, collection mode, and source evidence. The depth path is provider-native read-only inventory and fixtures for existing checks, not additional cloud checks.

### Container And Kubernetes Assessment vs Wiz/Trivy-Style Workload Assessment

Vendor/community-described baseline:

- Wiz describes workload context as part of a broader cloud risk model, while Trivy documents vulnerability, misconfiguration, secret, license, image, filesystem, repository, and Kubernetes scanning workflows.

Repository-verified Forge position:

- Forge has container, image, runtime, escape, Docker, and Kubernetes-oriented checks, but they do not share a canonical inspected-workload identity or collection contract.
- Container-escape checks inspect the scanner host's `/proc`, mounts, devices, and capabilities while attributing the result to the configured target: `cloud/container_escape.py:145`, `cloud/container_escape.py:168`, `cloud/container_escape.py:304`.
- Local-host, image/static, cluster/provider, and remote-runtime modes are not separated strongly enough for reports to establish what was actually inspected.

Decision: at `0.9/5`, this is a prototype workload-check surface, not an enterprise container/Kubernetes assessment workflow. Existing checks need explicit local-versus-remote modes, stable workload/image identities, SBOM/config/runtime provenance, read-only defaults, and mocked plus opt-in lab fixtures. No new workload checks should be added.

### Leak Intelligence vs GitGuardian

Vendor-described baseline:

- GitGuardian documentation describes secrets detection with detector coverage, source integration, secret validity/remediation context, and operational workflows.

Repository-verified Forge position:

- Forge contains source and parser scaffolding for leaked-secret discovery.
- Credential validation can contact third-party or enterprise services without a scope check or separate credential-use authorization gate: `leak_intel/parsers/credential_tester.py:67`, `leak_intel/parsers/credential_tester.py:117`, `leak_intel/parsers/credential_tester.py:293`.
- The current implementation lacks measured full-history detector coverage, deterministic secret fingerprints, protected references, evidence-backed validity states, and a durable remediation lifecycle.

Decision: credential validation must remain disabled by default until separately authorized, provider-specific, rate-bounded, and audited. Competitive depth comes from making the existing detectors measurable and the secret lifecycle safe; it does not come from adding detector families.

### Reporting And Collaboration vs Dradis Pro

Vendor-described baseline:

- Dradis Pro describes a shared assessment workspace for importing evidence, collaborating on findings, and producing consistent client reports.

Repository-verified Forge position:

- Forge has useful HTML/PDF/JSON report generation, severity/confidence presentation, report metadata, and early database models for jobs, retests, and audit events.
- Evidence records can contain raw sensitive material without a complete redaction, encryption, hash, signature, or custody boundary: `common/evidence.py:11`.
- Finding deduplication is based on title, host, and port and can overwrite evidence without tenant, run, module, path, parameter, or vulnerability identity isolation: `common/db.py:535`, `common/db.py:654`.
- Team, activity, integrations, ownership, SLA, notes, and tickets are substantially static, browser-local, or simulated: `apex-ui/src/pages/TeamManagement.jsx:7`, `apex-ui/src/pages/ActivityLogs.jsx:7`, `apex-ui/src/pages/Integrations.jsx:7`, `apex-ui/src/pages/Vulnerabilities.jsx:48`.
- Compliance output can create false assurance from incomplete collection, so it must not be used as evidence of compliance.

Decision: report-format breadth is not an enterprise assessment workflow. Forge must persist canonical reviewer state, immutable observations, evidence custody, report versions, approvals, retests, and audited exports behind the pages that already exist. New facade pages or report formats are not the priority.

## Cross-Cutting Blockers To Any Enterprise Claim

These issues outweigh module breadth because each can invalidate results or create unsafe activity:

1. Dashboard scan paths append `--auto-confirm`, and a legacy web path can silently launch NetForge against a resolved IP: `common/dashboard/server.py:1020`, `common/dashboard/server.py:1094`, `common/dashboard/server.py:1154`.
2. `/api/v1/events/emit` accepts unauthenticated event data, while the remote sender disables TLS verification: `common/dashboard/server.py:812`, `common/dashboard/event_bus.py:449`.
3. Viewer-level BOF actions can inspect the local dashboard host because the authorization helper defaults to viewer: `common/dashboard/server.py:366`, `common/dashboard/server.py:1949`.
4. Finding/evidence deduplication is mutable and not tenant-safe: `common/db.py:535`, `common/db.py:654`.
5. Compliance can infer a pass without proof that an applicable check ran: `common/reporting/compliance_engine.py:63`, `common/reporting/compliance_engine.py:253`.
6. Retest reruns a broad module process and leaves `still_vulnerable=None` rather than reproducing the original condition: `common/dashboard/server.py:3343`, `common/dashboard/server.py:3446`, `common/dashboard/server.py:3471`.

Until these are corrected and regression-tested, Forge should not be positioned for multi-tenant use, compliance attestation, unattended active scanning, operational C2, or repeatable client delivery.

## Verification Evidence Behind The Scores

| Check | Result | Interpretation |
|---|---|---|
| Python compilation | Passed, with one `SyntaxWarning` | Syntax coverage is useful but does not validate workflows |
| Full Python test run | 317 passed, 3 skipped, 2 failed | The baseline is not green; both failures affect WebForge automation contracts |
| Selected coverage | 37% | Critical request, feed, schema, and evidence paths remain lightly or entirely untested |
| Mypy in CI scope | 56 errors in 15 files | Important data contracts are not type-consistent |
| Frontend production build | Passed | Build success does not validate backend-connected page behavior |
| Frontend tests | 25 passed in 2 files | Primary operator workflows remain largely untested |
| Registered mapping imports | WebForge 71/71; NetForge 129/131; ADForge 86/86; AIForge 30/30 | Import success measures loadability only, not runtime correctness or detection quality |
| Production-package `test_*` functions | 1,447 found by the recorded search; only 10 package tests are normally collected | Embedded test-like functions materially overstate regression coverage |

No live scanner benchmark, false-positive/false-negative corpus run, performance comparison, licensed-product deployment, or support comparison was performed. Detection parity and throughput therefore remain unmeasured.

## Competitive Work That Is In Scope

The authoritative execution order is in `ROADMAP.md`. In commercial-comparison terms, the sequence is:

| Order | Existing surface to deepen | Evidence required before advancing | Expansion explicitly excluded |
|---:|---|---|---|
| 0 | Authorization, safety, truthful labels, credentials, and green CI | Fail-closed scope, no unauthenticated writes, no false verification/compliance, protected secrets, green enforced gates | New modules, checks, engines, transports, formats, or pages |
| 1 | Jobs, observations, evidence, finding identity, retest, one reference workflow, and the existing ForgeBrain/chain boundary | Durable restart-safe state, immutable evidence, tenant isolation, exact retest, audited report export, and no simulated action represented as executed | Parallel breadth or new autonomous actions before shared contracts pass |
| 2A | Existing WebForge crawler/auth/API/whitebox/OOB paths | Measured coverage plus vulnerable/patched fixtures and uniform proof | New web vulnerability families |
| 2B | Existing NetForge discovery/CVE/YAML/credentialed/compliance and intelligence/content paths | Deterministic inventory, one atomic versioned intelligence store, unique IDs, provenance, executable-content binding, fixtures for the entire current native corpus, safe credentials | New checks, check packs, or content families |
| 2C | Existing ADForge collectors and risk families | Correct auth/paging, canonical effective-rights graph, BloodHound-compatible lab evidence | New attack families |
| 2D | Existing AIForge probes and provider adapters | Repeated controlled trials, versioned corpus, calibrated detectors, explicit budgets/errors | New probe families |
| 2E | Existing C2 and payload surfaces | Authenticated encrypted local-lab workflow, artifact correctness, lineage, library-boundary authorization | New transports, BOFs, payload formats, task types, stealth, or evasion |
| 2F | Existing cloud/container/leak/OOB checks and listeners | Correct target identity, safe read-only collection, authorization, persistent callback evidence | New cloud checks, leak detectors, or callback families |
| 3 | Existing dashboard, review, collaboration, scheduling, and reporting surfaces | Shared server-side state, reviewer workflow, report locking, audited integrations | New facade pages |
| 4 | Existing agent and deployment model | Tenant isolation, durable queue/storage, recovery, endurance, signed releases, upgrade/rollback evidence | Feature expansion before supportability |

Progress should be measured by verified-module percentage, positive/negative fixture coverage, precision and recall, explicit untested coverage, immutable evidence lineage, real-retest coverage, secret-redaction failures, out-of-scope request count, cancellation/recovery behavior, tenant isolation, and enforced release gates. Module count is rejected as a progress metric.

## Public Baseline Sources

These pages were checked on 2026-07-19. They establish vendor- or project-described comparison baselines only.

- Tenable Nessus Expert: https://www.tenable.com/products/nessus/nessus-expert
- Invicti Application Security Platform: https://www.invicti.com/product/
- Acunetix web vulnerability scanner: https://www.acunetix.com/vulnerability-scanner/
- AcuMonitor technology: https://www.acunetix.com/vulnerability-scanner/acumonitor-technology/
- Burp Suite DAST: https://portswigger.net/burp/application-security-testing/dast
- Burp Collaborator: https://portswigger.net/burp/documentation/collaborator
- ProjectDiscovery Nuclei templates: https://docs.projectdiscovery.io/templates/introduction
- Cobalt Strike user guide: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm
- BloodHound documentation: https://bloodhound.specterops.io/get-started/introduction
- Wiz platform: https://www.wiz.io/platform
- Trivy documentation: https://trivy.dev/docs/latest/
- GitGuardian secrets-detection documentation: https://docs.gitguardian.com/secrets-detection/home
- Garak: https://garak.ai/
- Microsoft PyRIT repository: https://github.com/microsoft/PyRIT
- Microsoft PyRIT documentation: https://azure.github.io/PyRIT/
- Pentera: https://pentera.io/
- Horizon3.ai NodeZero: https://horizon3.ai/nodezero/
- Dradis Pro: https://dradis.com/pro/

## Bottom Line

Forge's breadth is unusual, but enterprise parity is currently approximately **1.4/5 (2.8/10)**. The shortest credible path toward the leaders is to make the capabilities already present safe, deterministic, measurable, recoverable, auditable, and defensible. More modules would reduce, not improve, competitive maturity.
