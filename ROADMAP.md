# Forge Suite Depth-First Enterprise Roadmap

Updated: 2026-08-03  
Current enterprise parity: 1.4/5 (2.8/10)  
Source assessment: `ENTERPRISE_MATURITY_ASSESSMENT.md`

## Product Decision: Freeze Breadth

No new engines, offensive module families, exploit families, transports, payload formats, top-level dashboard pages, or mobile work enter Gates 0-4. Work Packages 107 and 306 may deepen the existing planning, authorization, activity, team, policy, and emulation surfaces with human-governed exercise control; they add no offensive action.

This specifically defers:

- MobileForge and all Android/iOS work.
- New C2 transports, evasion techniques, payload formats, BOFs, or task types.
- New WebForge, NetForge, ADForge, AIForge, cloud, leak-intelligence, or OOB module files.
- New dashboard sections that do not complete an existing backend workflow.
- No new native check definitions or check packs enter this roadmap. Post-pilot category expansion, including MobileForge and controlled competitive benchmarking, remains inactive until the enterprise-pilot audit and following evidence-based rescore pass and a separate product decision is signed.

The goal is to turn the current surface into a dependable product. Deleting, disabling, merging, or relabeling a weak module is successful roadmap work.

## Maturity Principles

1. A module is not complete because it imports, returns a `ModuleResult`, or has a UI card.
2. A finding is not verified because a server answered, a version string matched, or a process exited zero.
3. A scan is not complete when work failed, was skipped, was truncated, or continued after cancellation.
4. Every outbound action must be tied to tenant, engagement, operator, scope, target, safety mode, and authorization.
5. Every finding must trace to an immutable observation and evidence artifact.
6. Every active check needs a vulnerable fixture, a patched/negative fixture, and a deterministic expected result.
7. Simulation is allowed, but it must never claim exploitation, validation, or verified vulnerability.
8. Enterprise claims follow measured gates; documentation does not declare work complete before evidence exists.

## Definition Of Done For Every Existing Module

An existing module may be labeled `verified` only when all applicable items pass:

- It has a capability manifest: owner, version, maturity, safety mode, inputs, outputs, dependencies, timeout, cancellation behavior, and retest support.
- Its inputs and outputs use canonical typed contracts.
- It refuses missing scope and revalidates redirects, resolved hosts, and discovered child assets.
- It does not disable TLS or host identity verification without an explicit lab-only policy.
- It distinguishes `no finding`, `not applicable`, `not tested`, `partial`, `failed`, `canceled`, and `not authorized`.
- It records what ran, what was skipped, why, and how much coverage was achieved.
- It emits no password, token, cookie, hash, private key, or raw sensitive body outside the protected evidence store.
- It supports bounded rate, concurrency, timeout, retry, and cancellation.
- It has deterministic positive and negative fixture tests.
- A retest can reproduce the exact original condition or explicitly reports that retest is unsupported.
- Reports and UI use persisted canonical results rather than transient state.

## Release Gates

Gates are sequential. “Gate N passed” means every package assigned to that gate is complete with accepted evidence, the matching read-only gate audit returns PASS, and the Task 906 workflow instance for that exact audit trigger is recorded. Task 900 is repeatable per implementation-package candidate; Task 906 is repeatable per trigger; neither is a singleton status row.

Direct entry is therefore exact: Task 101 requires Task 901 plus the post-901 Task 906 rescore; Gate 2 requires Task 902 plus the post-902 rescore; Task 301 requires aggregate Task 903 plus the post-903 rescore; and Task 399 requires Tasks 904/907 plus the post-904 rescore. Domain-engine depth may proceed in parallel only after those Gate 1 conditions, including subsections 1.6 and 1.7, pass.

---

## Gate 0: Truth, Containment, And Green Baseline

Goal: remove unsafe defaults, false assurance, and claims that contradict the implementation.

### 0.1 Authorization And Scope Boundary

- Make empty scope fail closed for every active workflow.
- Remove unconditional `--auto-confirm` from dashboard and agent-launched scans.
- Define and enforce a minimal action-authorization envelope containing tenant, engagement, run, operator, target, scope decision, safety mode, and confirmation. Gate 1 will version and normalize this envelope rather than inventing it later.
- Add an explicit `safety_mode` and per-action approval record to jobs.
- Require separate operator consent before resolving a web hostname into a NetForge target.
- Revalidate every redirect, DNS result, discovered host, CA host, metadata address, OOB destination, and child asset against effective scope.
- Remove stealth decoy traffic or require a separately authorized decoy scope.
- Default all scanners to verified TLS/host identity. Keep insecure modes visibly lab-only and audited.
- Bind any approved enterprise proxy, SOCKS, proxychains, or Tor route to the exact engagement/action, configuration digest, DNS mode, compatible protocol/tool, operator, and expiry. A mandatory route fails closed without direct fallback.

Exit criteria:

- No active API or CLI path can run with an empty scope.
- Packet-capture tests prove zero requests to excluded hosts, cross-scope redirects, unapproved resolved IPs, decoy services, or implicit scan-time updaters. Separately invoked updates may contact only configured, pinned endpoints and must be audited.
- Every active action has tenant, engagement, run, operator, target, scope decision, safety mode, and confirmation in the audit log.
- Dashboard, agent, and CLI behavior use the same authorization contract.
- Mandatory-route fixtures prove approved remote-DNS behavior, zero direct fallback, zero DNS/IPv6 leak, zero proxy-secret leakage, and truthful unsupported raw/UDP/ICMP coverage.

### 0.2 Protect Dashboard Write And Host-Execution Boundaries

At this gate, agent work is containment: mandatory identity, bounded ownership, and rejection of forged/replayed results. Gate 1 makes the model durable on one node; Gate 4 hardens it for multi-node scale.

- Authenticate and authorize `/api/v1/events/emit` with a per-job, short-lived credential and verified TLS.
- Reject events that do not match the job, engine, tenant, run, and target assignment.
- Remove local BOF execution from the normal dashboard API or put it behind admin, high-risk, local-lab-only approval and a sandbox.
- Require a configured per-agent credential; remove optional unauthenticated registration/poll/result behavior.
- Accept mTLS identity only from a verified TLS connection or explicitly trusted proxy, never request JSON.
- Add signed/leased agent job ownership with expiry and replay protection.

Exit criteria:

- Zero unauthenticated state-changing endpoints except an enumerated, rate-limited authentication/bootstrap allowlist that cannot launch work, mutate findings, access tenant data, or execute host actions.
- A viewer cannot cause network, process, filesystem, BOF, payload, C2, or scan side effects.
- Forged, replayed, cross-tenant, wrong-target, and wrong-job events/results are rejected in tests.
- Agent impersonation and expired lease tests pass.

### 0.3 Stop False Compliance And Verification Claims

- Change compliance rules to `not_tested` unless a versioned check produced applicability and collection evidence.
- Remove the hardcoded PCI 11.3.1 pass.
- Prevent heuristics, product presence, ordinary status codes, simulation, and process exit from setting `verified`.
- Add explicit `proof_type`: active, passive, version-correlation, OOB, static, credentialed-config, manual, or simulation.
- Relabel every module and YAML check as `verified`, `heuristic`, `wrapper`, `simulation`, `experimental`, or `disabled`.

Exit criteria:

- An empty finding set from an empty, failed, or partial scan produces zero compliance passes.
- Simulations cannot emit `success`, `exploited`, `still_vulnerable`, or `verified`.
- Critical/high findings require a documented proof policy and cannot be promoted by confidence defaults alone.

### 0.4 Credential And Evidence Emergency Hardening

- Remove secrets from argv, reports, events, log messages, environment summaries, temporary files, and ordinary JSON stores.
- Require secure file permissions for any credential/hash artifact.
- Require SSH host-key and WinRM/TLS certificate policy.
- Disable Leak Intel credential validation until it has scope, credential-use approval, rate, audit, and safe-provider policies.
- Use one explicit canonical whitebox `source_root`; remove working-directory fallbacks, resolve symlinks, enforce containment, and reject paths outside the operator-approved root.
- Add centralized secret redaction tests using canary passwords, tokens, cookies, hashes, and private keys.

Exit criteria:

- Canary secrets do not appear in argv, process metadata, logs, events, findings, reports, exports, audit detail, or world/group-readable files.
- An outside-root canary proves whitebox mode cannot read, scan, persist, or report files beyond the approved source root through defaults, relative paths, or symlinks.
- Credential-use actions are separately authorized and auditable.
- Scanner cleanup completes even when credential discoveries exist.

### 0.5 Restore A Trustworthy Build And Test Baseline

- Fix the two failing WebForge automation tests.
- Resolve all mypy errors in the CI scope, then expand typing to engine contracts.
- Move embedded production-file tests into discoverable test files or delete duplicated dead tests.
- Make Bandit fail on the agreed severity threshold; remove `--exit-zero`.
- Add a coverage threshold and raise it by verified workflow, not blanket line count.
- Add frontend page/workflow tests and run build/tests in CI.
- Fix NetForge EternalBlue/BlueKeep class mapping and add an all-mappings import/contract gate.
- Add a release version source used by all engines, API, UI, reports, and images.
- Generate a baseline dependency snapshot and SBOM in CI so Gate 0 artifacts disclose what was tested.
- Replace lower-bound-only runtime dependency resolution with a reviewed lock/constraint set for the tested build.
- Remove weak dashboard/C2 passwords from Docker and Compose defaults; startup must require operator-provided or securely generated credentials.
- Pin the container's optional Nuclei version and checksum, or omit it when a verified artifact cannot be installed. Never download an unchecked `latest` binary during the build.

Exit criteria:

- Python: all tests pass with zero unexpected skips and zero warnings accepted without review.
- Mypy, Ruff, Bandit, import-contract, and secret-scan gates pass.
- Frontend build and primary operator workflow tests pass.
- Every registered mapping loads; every unregistered file is intentionally classified.
- CI publishes coverage, test, SBOM, and artifact reports and enforces thresholds.

---

## Gate 1: Canonical Control Plane, Evidence, And Retest

Goal: prove one complete, durable vertical workflow before deepening individual engines.

### 1.1 Canonical Data Contracts

Promote Gate 0's minimum action-authorization envelope into versioned contracts, then create the remaining contracts for:

- Tenant, client, project, engagement, operator, role, and scope decision.
- Asset and identity: host, URL, service, application, account, domain object, cloud resource, model endpoint, and beacon.
- Job, action, module execution, event, log, artifact, observation, finding, retest, report, and export.
- Intelligence source, feed snapshot, executable check-pack snapshot, and provenance record.
- Module/check manifest and versioned policy.

Mandatory finding lineage:

`tenant -> engagement -> job -> module/check version -> asset -> observation -> evidence artifact -> finding`

Applicability-specific and downstream links:

- A module/check version links to the exact intelligence/feed/check-pack snapshot when that execution consumed one.
- A finding may have zero or more retests and may appear in zero or more versioned reports/exports; every such downstream record links back to the finding and source observations.

Exit criteria:

- Every finding resolves every mandatory lineage link through stable IDs, and every applicable intelligence, retest, report, or export link is equally resolvable.
- No JSON string fields are used where a normalized relationship is required.
- Database constraints prevent cross-tenant references and orphan observations.
- Schema migrations are versioned, reversible, and tested from every supported release.

### 1.2 Immutable Observations And Evidence Custody

- Separate deduplicated findings from immutable per-run observations.
- Store evidence artifacts outside mutable finding rows.
- Add SHA-256, size, media type, collection time, collector, source target, redaction state, encryption state, signer, and retention metadata.
- Redact secrets before UI/report/export while retaining protected originals only when explicitly authorized.
- Preserve every observation when findings deduplicate.

Exit criteria:

- Tampering with an artifact or manifest is detected.
- Two paths/parameters with the same title and host remain distinct observations.
- Two tenants scanning the same target never merge data.
- Re-running a scan adds observations without overwriting earlier evidence.

### 1.3 Durable Job State Machine

- Implement the canonical single-node job/lease/event model here; Gate 4 later replaces or scales its infrastructure without changing semantics.
- Replace in-memory process ownership and JSON side stores with a transactional job/lease/event model.
- Implement explicit states: planned, pending approval, queued, leased, running, paused, canceling, canceled, partial, failed, completed, expired, and orphaned.
- Make retries idempotent and attempt-scoped.
- Add per-job pause/cancel instead of global-only controls.
- Reconcile running workers and child processes after control-plane restart.
- Record coverage, skipped work, partial results, and terminal reason.

Exit criteria:

- Kill the dashboard or worker during each state; restart produces the correct state and preserves logs/results.
- Duplicate job delivery cannot duplicate active work or observations.
- Cancellation stops queued and in-flight work within a defined SLA and terminates child processes.
- `completed` is impossible when required work failed, was truncated, or remained uncollected.

### 1.4 Real Retest

- Persist the original module/check version, asset, route, parameter, identity/session reference, payload class, proof expectation, and evidence baseline.
- Implement module-specific verifier entry points.
- Preserve authorized authenticated context without exposing secrets.
- Return one of: fixed, still vulnerable, inconclusive, failed, not applicable, not authorized, or unsupported.

Exit criteria:

- Positive fixture retest returns `still_vulnerable`; patched fixture returns `fixed`.
- Authenticated findings retest with the same identity and session policy.
- Process exit alone never determines vulnerability state.
- Retest evidence is immutable and linked to the original observation.

### 1.5 One End-To-End Reference Workflow

Use one existing WebForge or NetForge finding family as the reference vertical slice.

Prove:

1. Authenticated API job creation.
2. Scope and safety approval.
3. Durable worker lease.
4. Module execution with cancellation.
5. Immutable observation/evidence persistence.
6. Finding dedup without evidence loss.
7. Real retest.
8. Dashboard refresh/reconnect.
9. Reviewer status/notes/ownership.
10. Report generation and audited export.

Exit criteria:

- The complete workflow passes normal, negative, duplicate-delivery, timeout, cancel, restart, and two-tenant tests.

### 1.6 ForgeBrain And Attack-Chain Truth Boundary

- Treat model output, planner output, and chain triggers as advisory plans until a policy decision and operator approval authorize a canonical job.
- Replace simulated module completion with either a real canonical job/action link or an explicit `simulation` outcome. Never represent a logged suggestion as executed work.
- Resolve every planned action against the existing capability manifest and reject unknown, disabled, incompatible, or out-of-scope module IDs.
- Persist each plan and chain node with its source observation/finding, preconditions, rationale, policy decision, approval, action/job ID, terminal outcome, and evidence links.
- Replace EngagementBus plaintext credential fields with protected credential references or encrypted secret storage; migrate or purge legacy rows and apply the same policy to backups and exports.
- Remove broad phase/OPSEC-based exploit auto-approval. High-risk actions always require an explicit approval bound to the exact target and action.
- Apply the evidence-store redaction policy before any finding, credential, engagement memory, or application context is sent to an external model.
- Evaluate the existing planner, analyst, narrator, and chain definitions against deterministic benign scenarios, negative controls, failed-action cases, and restart/replay conditions.

Exit criteria:

- No simulation, suggestion, or emitted progress event can increment completed work or appear as an executed action.
- No model response or chain event can directly cause network, credential, payload, BOF, C2, filesystem, or subprocess activity.
- Every real action resolves to the Gate 1 authorization, job, observation, evidence, and audit lineage; failures cannot finalize as complete.
- Unknown/hallucinated module IDs, duplicate events, stale approvals, replayed chain triggers, and cross-tenant context are rejected.
- Canary secrets never appear in external-model requests, cache keys, logs, reports, ordinary SQLite fields, backups, or exports.
- Plans and chain state survive restart without duplicating actions, and measured fixture outcomes are reported separately from narrative quality.
- A versioned scenario corpus achieves 100% rejection of unknown, disabled, incompatible, and out-of-scope actions; 100% capability-ID resolution for supported actions; and at least 95% correct terminal-outcome classification. Narrative quality is reported separately and cannot compensate for an action-contract failure.

### 1.7 Human-In-The-Loop Exercise Control Plane

- Add canonical rules-of-engagement, campaign, objective, hypothesis, proposal, deterministic policy, approval-tier/quorum, single-use action-envelope, incident, emergency-stop, cleanup, and after-action contracts.
- Enforce server-side roles for exercise director, operator, approver, safety officer, defender/white-cell liaison, observer, and advisory planner.
- Keep planners, models, chain events, schedules, and workers advisory until the configured human approval tier authorizes one exact action.
- Bind every executable envelope to tenant, engagement, plan version, proposal, operator/worker, job, target/resolved target, capability/version, parameter digest, credential/artifact reference, safety mode, route, rate, expiry, nonce, and cleanup.
- Keep authorization, proposal, envelope, job, outcome, cleanup, and exercise states orthogonal and consistently mapped across API, events, UI, reports, and exports.
- Make emergency stop independent from ordinary cancellation and persist propagation, incidents, unresolved work, deliberate resume, and cleanup.

Exit criteria:

- Role separation and Tier 4 two-person quorum pass; one identity/token cannot satisfy both approvals.
- Altered, stale, replayed, consumed, cross-tenant, cross-target, wrong-route, wrong-operator, changed-DNS/session/capability, and superseded-plan envelopes are rejected 100%.
- Planner/model/event/scheduler output without policy and required human approval creates no executable job and reaches no side-effect boundary.
- Pause, cancel, emergency stop, restart, lost communication, incident, and failed-cleanup fixtures preserve canonical truth and prevent unauthorized resume.
- Canary secrets remain absent from proposals, approvals, events, notifications, audit detail, reports, exports, backups, and external-model requests.

---

## Gate 2A: WebForge Depth

Primary benchmark: Invicti/Acunetix and Burp Suite DAST.

### 2A.1 Crawl And Auth State Model

- Route all HTTP and browser traffic through one scope-aware request/navigation policy.
- Record final redirect destination, auth state, route state, form state, source, depth, and failure reason.
- Add authenticated session health checks and bounded reauthentication.
- Model anti-CSRF tokens and per-request dynamic values.
- Make click discovery safe: classify controls, block destructive actions, and support operator-approved workflow scripts.
- Persist crawl coverage: discovered, attempted, tested, failed, skipped, authenticated-only, duplicate, and out-of-scope.

Exit criteria:

- At least 90% route/form/API recall on seeded modern-app fixtures.
- Zero out-of-scope requests, including redirects and browser navigation.
- Authenticated crawl survives token rotation and session expiry in fixtures.
- The UI and report explain every untested route.

### 2A.2 One Mutation And Proof Engine

- Replace module-specific ad hoc request construction with a canonical mutation contract for URL, form, JSON, XML, GraphQL, headers, cookies, multipart, and WebSocket messages.
- Separate discovery, mutation, detection, verification, and reporting.
- Require context-aware proof for each existing vulnerability family.
- Make OOB correlation first-class for blind classes.
- Keep blind families `experimental` or `disabled` until the ForgeCollab/OOB subsection of Gate 2F passes; they cannot satisfy this gate through timing, reflection, or status heuristics.
- Treat WAF blocks, soft 404s, reflections, timing noise, and generic errors as negative/ambiguous controls.

Exit criteria:

- Every existing critical/high family has vulnerable and patched fixtures.
- No status-only or reflection-only result can become verified without the family proof policy.
- Target precision is at least 98% and recall at least 90% on the maintained fixture corpus.
- Every proof includes redacted request/response/OOB/browser evidence and check version.

### 2A.3 Access Control And Business Logic

- Use explicit identity A/B and state-before/state-after workflows for IDOR, privilege, mass assignment, workflow, price, race, and account-takeover checks.
- Require reversible cleanup for any state mutation.
- Model preconditions and distinguish heuristic candidates from validated outcomes.

Exit criteria:

- Existing access-control families prove authorization differences between identities.
- Business-logic modules do not report from a single response or string match.
- State-changing tests are opt-in, auditable, rate-bounded, and cleaned up.
- Every supported existing family has vulnerable and hardened/control workflows, reaches at least 98% precision and 90% recall on the versioned corpus, and produces zero false-positive critical findings.

### 2A.4 API And Whitebox Depth

- Validate OpenAPI/Postman/GraphQL imports against schema fixtures.
- Track API operation, content type, auth requirement, parameter source, and tested mutation coverage.
- Make whitebox results link source location and dependency/config evidence to the running endpoint when possible.

Exit criteria:

- Imported schemas produce a deterministic operation inventory and coverage report.
- REST/GraphQL/SOAP checks operate through the same proof/evidence contract.
- Static-only findings are never presented as dynamically verified.
- Supported operation-inventory recall reaches at least 95%, and tested coverage reaches at least 90% across declared supported operation/parameter/content-type/identity combinations, with published numerators, denominators, and exclusions.

---

## Gate 2B: NetForge Depth

Primary benchmark: Nessus/Tenable, Qualys VMDR, and Rapid7 InsightVM.

### 2B.1 Typed Discovery Dependency Graph

- Introduce one `Asset -> Interface -> Port -> ServiceFingerprint -> CPE` contract.
- Execute host discovery, port discovery, service identity, CPE generation, and vulnerability checks through an explicit DAG.
- Remove timing-dependent shared `config.extra` contracts.
- Record host/port limits, UDP coverage, privilege limitations, and skipped ranges as partial coverage.

Exit criteria:

- Repeated scans of the same fixture produce deterministic inventories.
- At least 95% open-port recall and 98% service/product precision on the maintained TCP/UDP/IPv4/IPv6 corpus.
- No downstream consumer runs before its declared producer data exists.

### 2B.2 One Versioned Intelligence Database

- Merge the common and NetForge CVE stores into one atomic versioned service.
- Implement correct NVD date chunking, pagination, retry, resume, rejected/deleted CVEs, CPE Boolean applicability, KEV, EPSS, provenance, and rollback.
- Advance freshness only after a successful atomic update.
- Sign or hash feed snapshots and check packs.

Exit criteria:

- Interrupted/failed updates leave the prior good snapshot active and do not advance freshness.
- Applicability fixtures cover version bounds, inclusive/exclusive ranges, AND/OR CPE logic, and supersedence.
- Offline snapshot import/export is deterministic and verified.
- Every CVE/check consumer resolves the same active snapshot ID; tests prove no shadow database, stale cache, or unversioned external template directory can influence a finding.

### 2B.3 Rewrite The Current Native YAML Corpus

- Do not add checks.
- Resolve the current duplicate ID first; the loader reports 102 definitions but only 101 unique IDs.
- Require metadata version, author, provenance, maturity, supported products, safety class, proof type, and positive/negative fixtures.
- Prohibit ordinary status, banner presence, or product presence as CVE confirmation.
- Split candidate detection from verification.

Exit criteria:

- Every check has at least one vulnerable and one patched fixture.
- Corpus precision is at least 98% and recall at least 95%.
- A check cannot move from experimental to stable without review and fixture results.

### 2B.4 Credentialed And Compliance Assessment

- Use a protected credential reference rather than passing secrets through ordinary config/events.
- Enforce SSH host keys and WinRM/TLS certificate policies.
- Add privilege preflight and read-only command policy.
- Replace global KB/package lists with OS/build/applicability and supersedence data.
- Make compliance results benchmark-versioned with pass, fail, not applicable, not tested, and collection error.

Exit criteria:

- Zero remote target mutation during standard audit.
- Zero false missing-patch findings on fully patched maintained images.
- Credentialed Windows/Linux/macOS/SNMP fixtures prove positive and negative cases.
- Compliance output never infers pass from absence of a finding.

---

## Gate 2C: ADForge Depth

Primary benchmark: BloodHound Enterprise, PingCastle, NetExec, and Certipy.

### 2C.1 Rebuild The Collection Foundation

- Implement RootDSE naming-context discovery, paging, ranged attributes, referrals policy, LDAPS/StartTLS, and explicit collection errors.
- Support and test password, NT hash, Kerberos, and ccache authentication.
- Use stable SID/GUID identities across domains and forests.
- Correct all module calls to the canonical LDAP/Kerberos APIs.

Exit criteria:

- Password, NT hash, and ccache collection pass against a lab domain with more than 5,000 objects and no truncation.
- Empty results are distinguishable from auth, paging, permission, referral, and transport failures.
- Trusts, nested groups, localized/moved built-ins, and multiple domains are retained correctly.

### 2C.2 Canonical Effective-Rights Graph

- Connect existing user, group, computer, trust, ACL, GPO, delegation, Kerberos, and ADCS collectors to one graph.
- Resolve object GUID rights, inheritance, group nesting, owner/control relationships, effective enrollment rights, CA publication, and principal reachability.
- Persist source object and protocol evidence for each edge.

Exit criteria:

- At least 95% edge parity for supported edge types against BloodHound on the same lab snapshot.
- Every reported path is reconstructable from persisted edges and current-principal reachability.
- Attack-path reports use graph edges, never sequential finding order.

### 2C.3 Correct Existing AD/ADCS Risk Families

- Fix Kerberos hash formats, DCSync contracts, ACL masks/GUID semantics, ADCS effective rights, GPO links, delegation, trust, and unauthenticated checks.
- Relabel simulated ticket/delegation/attack modules and separate assessment from optional lab validation.
- Validate BloodHound exports and canonical reports.

Exit criteria:

- Existing ADCS checks match Certipy on vulnerable and hardened CA/template matrices with no critical false positives.
- Existing critical/high AD and ADCS families achieve at least 98% precision and 90% recall on a versioned supported-fixture matrix.
- Existing health families produce versioned PingCastle-style category scores with evidence for each deduction.
- BloodHound export imports successfully and matches the same snapshot.
- No password/hash appears in argv, report steps, or ordinary files.

---

## Gate 2D: AIForge Depth

Primary benchmark: Garak and Microsoft PyRIT, with commercial AI security platforms as workflow references.

- Enforce TLS verification and correct provider-specific adapters.
- Add bounded retry/backoff, rate/cost/token budgets, cancellation, and provider error taxonomy.
- Version the probe corpus and separate generator, prompt, target, response, detector, scorer, attempt, baseline, and aggregate verdict.
- Run repeated attempts and record variance rather than treating one regex hit as a finding.
- Add negative controls and benign baselines for each existing probe family.
- Record model, endpoint, parameters, system context policy, corpus version, scorer version, and run seed.
- Redact sensitive model/application data before any ForgeBrain or external-LLM analysis.

Exit criteria:

- Each supported provider adapter passes contract fixtures and one opt-in lab integration.
- Each existing probe family has positive/negative controls and calibrated thresholds, with at least 95% precision and 85% recall on its versioned deterministic fixture corpus before provider-variance results are considered.
- Repeated runs produce explainable aggregate confidence and preserve raw authorized evidence securely.
- Provider 429, timeout, block, malformed response, and partial output are distinct outcomes.

---

## Gate 2E: C2 And Payload Correctness

Primary benchmark: Cobalt Strike and Sliver.

This gate deepens the current HTTP/TCP, task, profile, BOF, payload, and emulation surfaces. It adds no new transport or payload types.

- Fix the unified CLI and define one supported TeamServer/operator interface.
- Implement real TLS for HTTPS and operator APIs.
- Design an authenticated handshake and beacon identity/key lifecycle.
- Enforce bidirectional encryption, replay windows, counters, key rotation, and forged-result rejection.
- Persist listener, beacon, task, output, artifact, approval, operator, and report lineage.
- Remove DNS/SMB/P2P claims until existing implementations pass the lab gate.
- Move all payload/BOF authorization into library boundaries, not only CLI flags.
- Validate existing artifact formats; label source templates and simulations truthfully.
- Remove local host BOF execution from the normal dashboard workflow.

Exit criteria:

- Local-lab registration, check-in, task, output, cancellation, reconnect, rotation, and server restart pass end to end.
- TLS inspection confirms actual TLS; replayed/forged messages fail.
- Every task/output links to operator, beacon, target scope, artifact hash, timestamps, and evidence.
- Direct library calls cannot bypass high-risk authorization.
- Unsupported transports and placeholder artifacts are absent from user-facing capability claims.

---

## Gate 2F: Cloud, Container, Leak Intel, And OOB Depth

### Cloud And Container

- Stop attributing local scanner-host state to remote targets.
- Use provider-native read-only inventory and stable resource identities for existing cloud checks.
- Build context from account/project/subscription, identity, resource, network, data exposure, and policy evidence.
- Normalize existing container/Kubernetes results with image/SBOM/config/runtime source and target identity.
- Keep active behavior disabled by default.

Exit criteria:

- Every result identifies the actual provider/resource/workload inspected.
- Local-host and remote/provider modes are separate and impossible to confuse.
- Existing checks have mocked provider fixtures and opt-in lab validation.
- Existing supported cloud/container critical/high families achieve at least 95% precision and 90% recall on versioned fixtures, with 100% correct target attribution.

### Leak Intelligence

- Add deterministic secret fingerprints, full-history source coverage, detector provenance, deduplication, validity state, and remediation lifecycle.
- Keep credential validation separately authorized, provider-specific, rate-bounded, and disabled by default.
- Never persist full secrets when a protected reference or fingerprint is sufficient.

Exit criteria:

- Positive/negative/history fixtures measure precision and recall for existing detectors.
- Existing secret detectors achieve at least 98% precision and 90% recall on the versioned fixture/history corpus.
- Revoked, invalid, unknown, and not-tested validity states are distinct.
- No validation occurs without explicit scope and credential-use approval.

### ForgeCollab/OOB

- Add authenticated persistent token registration, callback storage, expiry, replay/dedup, polling authorization, and restart recovery.
- Use one correlation token per finding attempt.
- Wire the existing blind SSRF/XXE/SQLi/XSS/command families to the same OOB contract.

Exit criteria:

- HTTP, DNS, and SMTP callbacks correlate after service restart.
- Duplicate/delayed callbacks do not create duplicate findings.
- Wrong-tenant/job/token polling is rejected.
- Existing blind-vulnerability fixtures produce reportable callback evidence.
- The versioned callback matrix achieves 100% correct token/job/tenant correlation across normal, duplicate, delayed, and restart cases, with zero cross-token matches.

---

## Gate 3: Persistent Operator And Reporting Workflow

Goal: roll the Gate 1 single-node canonical models across the existing dashboard so it becomes useful to a real multi-user security team.

- Persist ownership, SLA, status, notes, exceptions, approvals, tickets, retests, and report versions server-side.
- Wire Reports, Activity, Team, Policies, Notifications, Integrations, Targets, Agents, and Scheduling only where backend workflows exist.
- Hide or label nonfunctional pages instead of presenting empty product surfaces.
- Implement durable scheduling with timezone, misfire, overlap, scope, policy, and credential-reference rules.
- Build reviewer approval, QA comments, evidence redaction preview, and final report locking.
- Generate reports only from canonical persisted data and immutable observations.
- Do not add export formats or integration destinations. For destinations already represented in the current UI/configuration, either wire one retained path to a real audited adapter or label/hide the placeholder.
- Audit every export and redact by default.
- Complete the human-led control-room workflow on existing surfaces: plan activation, exact proposal/approval, role/quorum, deconfliction, canonical live status, emergency stop, cleanup, and evidence-backed after-action review.

Exit criteria:

- Refresh, reconnect, second browser, and second operator see the same canonical state.
- Concurrent edits have conflict/version handling.
- If an existing issue-tracker destination is retained, its round trip preserves finding identity, status, comments, and retest updates; otherwise the placeholder is removed from the supported workflow.
- Scheduling survives restart and never overlaps contrary to policy.
- A final report has reviewer identity, source run set, evidence manifest, version, hash, and export audit event.
- The human-loop workflow survives refresh, reconnect, concurrent operators, stale decisions, worker loss, and restart without approval broadening or state drift; independent Task 907 passes.

---

## Gate 4: Scale, Isolation, And Supportability

Goal: harden the Gate 1-3 single-node implementation into a measured multi-node enterprise-pilot release candidate and produce the evidence required for an explicit milestone decision.

Before implementation, freeze and independently approve a versioned pilot topology, workload mix, latency/error/cancellation/stop/recovery objectives, RPO/RTO, owners, abort criteria, and raw-result policy. Tasks 401-407, primary audit 905, final audit 908, and the final Task 906 must consume the same profile hash; thresholds cannot be weakened after results are observed without an explicit product decision.

- Use Postgres or an equivalent transactional store for multi-node mode.
- Use a durable queue and object/artifact store.
- Require per-agent identity, heartbeats, capabilities, scoped assignments, lease renewal, offline queueing, and revocation.
- Enforce tenant isolation at token, query, database, cache, event, artifact, report, and export layers.
- Add backup/restore, disaster recovery, retention, legal hold, and deletion workflows.
- Maintain reviewed locks across supported platforms, regenerate the Gate 0 SBOM for every release artifact, sign releases/images/check packs, and publish supported upgrade paths.
- Build the first customer-facing release candidate as signed Linux/amd64 OCI images plus a versioned orchestrator bundle for the multi-node profile, with Compose and Debian packages distributed through signed APT/release metadata for declared single-node qualification, a self-contained candidate runtime, an offline bundle, and a truthful bundled/package-managed/remote/unsupported capability matrix.
- Add structured telemetry for job latency, error class, scan coverage, check precision, queue age, worker health, and report generation.
- Publish operator, deployment, data-handling, module-maturity, and troubleshooting documentation.

Exit criteria:

- Two-tenant isolation test suite passes across every API and artifact path.
- The precommitted concurrency/load profile and full 24-hour endurance run meet its SLOs.
- Backup/restore recreates jobs, findings, observations, artifacts, audit logs, and report versions within the precommitted RPO/RTO.
- Rolling upgrade and rollback pass without data loss.
- Release artifacts are reproducible, signed, versioned, and accompanied by SBOM and migration notes.
- The packaged Linux release candidate passes clean-cluster/VM install, secure first run, the exact frozen multi-node SLO/endurance profile, tenant isolation, primary workflow, observability, restart/recovery, backup/restore/RPO/RTO, upgrade/rollback, repair, and uninstall validation without hidden platform fallback.
- Every packaged-release result binds one immutable candidate-content manifest/artifact digest set without self-referential records; offline payload archives prove complete dependency closure with network denied; supported browser/client rows and `N-1 -> N` mixed-version upgrades pass; signing trust rotation/revocation/compromise recovery is verified.
- Task 407 emits `LINUX RELEASE CANDIDATE READY FOR PRIMARY AUDIT` only after all candidate gates pass; this is not a supported-release statement.
- Task 905 emits `PRIMARY ENTERPRISE-PILOT RELEASE AUDIT PASS` only after the primary read-only audit passes against the exact profile, candidate, artifact set, and release record.
- Task 908 independently re-runs a fresh full 24-hour endurance test, frozen capacity points/repetitions, at least two multi-node topology points, saturation/headroom/backpressure/fairness/recovery, isolation/failure/offline/upgrade/supply-chain/browser/source-build gates, and emits `FINAL ENTERPRISE/SCALABILITY RE-REVIEW PASS` only with zero unresolved confirmed findings at every severity and zero unanswered material questions.
- Only the following final Task 906 may emit `ENTERPRISE-PILOT MILESTONE RECORDED`; otherwise it emits `ENTERPRISE-PILOT MILESTONE NOT SUPPORTED`. Any bounded release statement remains tied to the measured Linux profile, capacity envelope, exact candidate, ordered artifact set, exact release record, and documented limitations.

## Quality Metrics That Replace Module Count

Track these per release and per engine:

- Verified module percentage.
- Positive and negative fixture coverage percentage.
- Precision, recall, and inconclusive rate by finding family.
- Crawl/asset/port/service/identity coverage and explicit untested count.
- Findings with complete lineage and immutable evidence.
- Findings with supported real retest.
- Secret-redaction failures.
- Out-of-scope request count: target is always zero.
- Cancellation SLA and orphaned child-process count.
- Crash-recovery and duplicate-delivery pass rate.
- Tenant-isolation test pass rate.
- Mypy/Ruff/Bandit/coverage/frontend gate status.
- Mean time to reproduce and resolve false positives.
- Report QA rejection rate.

## Recommended Execution Order

For a small team or solo development effort:

1. Gate 0 in full.
2. Gate 1 in full, including the reference vertical slice, ForgeBrain/attack-chain boundary, and human-in-the-loop control contracts.
3. WebForge non-blind depth and NetForge depth; complete ForgeCollab/OOB before any blind WebForge family can be marked verified.
4. ADForge depth.
5. AIForge and ForgeCollab depth.
6. C2/payload correctness in a lab-only track.
7. Cloud/container and Leak Intel depth.
8. Persistent operator and human-loop control-room workflow, followed by independent audits 904 and 907 and the post-904 Task 906 rescore.
9. Task 399 freezes the pilot SLO/load/recovery profile; Tasks 401-407 implement scale/operations and qualify the signed Linux release candidate.
10. Task 905 performs the primary release audit; Task 908 performs the final enterprise/scalability re-review; the final Task 906 records or declines the enterprise-pilot milestone; Task 500 then decides whether any post-pilot proposal may receive new task IDs.

If multiple teams work in parallel, every domain team still depends on the Gate 0 authorization contract and Gate 1 data/evidence/job contracts.

## Target Maturity Milestones

These are qualitative target bands, not scores awarded automatically by completing a gate. Recalculate the disclosed weighted portfolio score from measured evidence at every milestone.

| Milestone | Required evidence | Illustrative target band |
|---|---|---:|
| Honest internal alpha | Gate 0 complete and portfolio rescored | Roughly 1.8-2.2/5 |
| Dependable practitioner beta | Gates 0-1 plus one fully measured engine depth gate; portfolio rescored | Roughly 2.5-3.0/5 |
| Credible assessment platform | Gates 0-1 and Web/Net/AD depth gates; portfolio rescored | Roughly 3.1-3.6/5 |
| Multi-user assessment beta | Gates 0-3 with measured engine quality; portfolio rescored | Roughly 3.5-3.9/5 |
| Enterprise pilot | Gates 0-4, primary Task 905 PASS, final Task 908 PASS, and final Task 906 `ENTERPRISE-PILOT MILESTONE RECORDED`, all bound to one measured Linux release record | Roughly 3.8-4.2/5 |
| Category-leader challenger | Enterprise-pilot evidence plus multi-year content and lab performance | Portfolio 4.3+/5, with separately published family scores |

The platform should not claim a milestone until every exit criterion has authoritative test, runtime, migration, and rendered-workflow evidence.

## Post-Pilot Category-Leader Expansion

Only after Task 905, Task 908, and the final Task 906 record the required PASS/milestone outputs may Task 500 make a signed breadth decision. Proposal labels 501-507 are inactive planning labels, not assignable task IDs; an approved proposal must receive new scoped task IDs, owners, fixtures, SLOs, independent review, and claim boundaries. Possible proposals include controlled licensed competitor benchmarking, MobileForge, adversary-informed human-led campaign graphs, security-content operations, commercial/assurance readiness, a separately governed cross-platform worker supervisor around the canonical Python runtime, and a signed Windows operator distribution consuming the canonical Linux platform APIs. They may not weaken Gates 0-4 or introduce malware, stealth, covert persistence, credential theft, monitoring bypass, destructive behavior, or uncontrolled autonomy.
