# Forge Suite Enterprise Roadmap

Updated: 2026-07-18

Status: Engineering prototype / alpha

Scope: Forge Suite is for authorized assessment, defensive validation, and controlled lab use. This roadmap prioritizes trustworthy scanning, containment, and operator safety before adding offensive breadth.

## Executive Decision

Forge Suite has broad technical primitives, but it is not yet a mature replacement for Nessus, Acunetix, or Cobalt Strike. The current enterprise-readiness estimate is 3.5/10.

The next release must be measured by trust, not module count:

```text
Approved scope -> policy -> durable job -> bounded execution -> verified finding
-> deterministic retest -> remediation state -> report -> audit trail
```

Feature expansion is frozen until the control plane and scanner-accuracy gates in this document pass.

## Persistent Product Memory

This file is the single source of truth for product gaps, priorities, and exit criteria.

- `ROADMAP.md`: verified capability matrix, priorities, and release gates.
- `HANDOFF.md`: concise current architecture, runnable paths, known breakages, and latest validation results.

Legacy task and sprint documents are historical input only. A capability is not complete because a file or UI page exists. It is complete only when its end-to-end acceptance tests pass.

## Verified Baseline

The 2026-07-17 review established this local baseline without launching scans, listeners, or payloads. FM-P0-001 validation updated the Python test counts on 2026-07-18:

| Signal | Verified Result |
| --- | --- |
| Repository size | 602 files, about 28 MB |
| Python surface | 497 files, 147,276 lines, syntax parsed successfully |
| Scanner modules | 286 files defining `BaseModule` subclasses |
| Collected Python tests | 245 |
| Executed Python tests | 245 passed in 15.31 seconds |
| CLI | `python3 forge.py --help` works |
| Framework imports | NetForge, WebForge, ADForge, AIForge, and dashboard import successfully |
| React pages | 19 pages: 6 use API/WebSocket data and 13 are static or seeded |
| Frontend build | Not reproducible: `apex-ui/package.json` and lockfile are absent |
| Preferred smoke driver | Missing from the working tree |
| C2 unified launcher | Broken by class/signature mismatches |

## Maturity Scorecard

| Area | Current | Enterprise Target | Main Gap |
| --- | ---: | ---: | --- |
| Control plane and data integrity | 3/10 | 9/10 | In-memory jobs, global state, unauthenticated worker events |
| Scanner accuracy and evidence | 3/10 | 9/10 | Verification is adopted by a small minority of detectors |
| Nessus-like network VM | 4/10 | 8/10 | No credentialed policy engine, signed feed, or distributed nodes |
| Acunetix-like DAST | 4/10 | 8/10 | Browser/auth primitives do not form one stateful crawl/test graph |
| Findings and reporting | 4/10 | 9/10 | Inconsistent report sets, random retest, unsafe compliance semantics |
| C2/operator product | 2/10 | 8/10 | Broken launch path, protocol/auth/state failures, UI-only console |
| Identity, RBAC, and audit | 2/10 | 9/10 | Default secrets, weak hashing, incomplete OIDC, no tenancy |
| Packaging and operations | 3/10 | 9/10 | Missing frontend manifest, broken health checks, no upgrade process |
| Test and release engineering | 3/10 | 9/10 | Small collected suite, no frontend/E2E/fixture/upgrade gates |

### Scoring Method

The overall 3.5/10 score is a weighted engineering-readiness score (3.45 rounded half-up to one decimal). It deliberately gives scanner accuracy, control-plane integrity, and governance more weight than module count.

| Dimension | Weight | Current | Scoring Basis |
| --- | ---: | ---: | --- |
| Architecture and module breadth | 10% | 6/10 | Implemented primitives and supported surfaces |
| Control plane and data integrity | 15% | 3/10 | Durable ownership, jobs, state, events, and recovery |
| Scanner accuracy and evidence | 20% | 3/10 | Precision, recall, proof quality, deduplication, and FP handling |
| Nessus-like network VM | 10% | 4/10 | Credentialed coverage, policy/feed quality, assets, and scan nodes |
| Acunetix-like DAST | 10% | 4/10 | Stateful crawl, auth, actor model, APIs, and business workflows |
| Findings and reporting | 10% | 4/10 | Canonical lifecycle, retest, remediation, compliance, and report parity |
| C2/operator reliability | 5% | 2/10 | Containment, protocol correctness, durable state, RBAC, and audit |
| Identity, RBAC, and audit | 10% | 2/10 | Authentication, tenancy, authorization, secrets, and traceability |
| Packaging and operations | 5% | 3/10 | Reproducible build, deployment, upgrades, backup, and supportability |
| Test and release engineering | 5% | 3/10 | Unit, fixture, contract, E2E, security, load, and release gates |

Score credit requires automated acceptance evidence. New modules, pages, sprint files, imports, or demos do not raise the score by themselves. The nearest credible target is 5/10: complete Phase 0, establish the canonical run/finding/report path, and meet the first measured accuracy gates before resuming feature breadth.

## Capability Truth Matrix

| Capability | Implemented Primitives | Partial or Disconnected | Missing Enterprise Contract |
| --- | --- | --- | --- |
| Shared scanner SDK | `BaseModule`, scope, rate limit, findings, evidence | Safety calls are inconsistent across modules | Enforced module contract and conformance tests |
| False-positive reduction | `common/fp_reducer.py` supports six detector families | Only 6 of 272 finding-producing module files use it | Universal verification policy, corpus metrics, field feedback |
| Web DAST | HTTP modules, Playwright engine, auth replay, schema import | Browser, HTTP, API, and auth discoveries are not one graph | Stateful crawl, actor model, workflow invariants, logout/session handling |
| Network VM | Discovery, service audits, CPE/CVE and Nuclei primitives | Richer intel/CPE components are not the canonical production path | Credentialed host audits, asset inventory, feed/version policy, scan nodes |
| Finding lifecycle | Structured finding/evidence models, reports, delta code | Random IDs, duplicate events, status not durably linked to runs | Stable fingerprint, retest jobs, reopen/fixed history, ownership and SLA |
| Compliance | PCI/OWASP/ISO mappings exist | No finding is often interpreted as pass | Explicit control coverage, NOT_TESTED state, evidence-backed assertions |
| Intel/feed | NVD, ExploitDB, Nuclei, ATT&CK sync and offline export | Scanner paths use embedded or abbreviated datasets | Signed feed manifests, staging, rollback, freshness and compatibility SLO |
| Dashboard | FastAPI, WebSocket, React, some wired workflows | 13 of 19 pages are static/seeded; settings are often ignored | Typed APIs, canonical state, complete loading/error/stale/unauthorized states |
| Scheduling/scale | TargetManager and scheduler classes exist | Main launch paths do not consume them | Durable queue, leases, heartbeats, retry, resume, distributed cancellation |
| C2 | Server, listener, transport, task, crypto, shell, and builder files exist | Parallel implementations are not composed; launcher/protocol are broken | Secure interoperable protocol, durable campaign state, shared RBAC/audit |
| Deployment | Docker, Compose, installer, CI exist | Default secrets, broken health/volumes, unpinned updates | Hardened profiles, SBOM, signed releases, migration/backup/rollback |

## Red Team Sprint Disposition

The documents under `docs/redteam/` are historical sprint proposals, not completion evidence. The 2026-07-17 audit produced this source-to-product disposition:

| Sprint | Verified Status | Evidence And Roadmap Decision |
| --- | --- | --- |
| 0 - Leak Intel | Partial, source-only | GitHub, Pastebin, and Shodan scanners exist; planned parsers, durable data, credential-validation workflow, dashboard path, and launcher wiring are absent. Resume passive coverage after P0/P1. |
| 1 - Cloud/Container | Partial, source-only | `cloud_api_scanner.py` and `cloud_iam_chaining.py` exist; four other planned modules and production orchestration are absent. Resume bounded, read-only coverage after P0/P1. |
| 2 - Chain Engine v2 | Substantial source, broken integration | State, scoring, fallback, and DAG primitives exist, but cross-framework publishing and production wiring are inconsistent and unvalidated. Fix integration correctness now. |
| 3 - C2 Tasks | Missing and deferred | All 12 planned task files are absent; the existing typed registry is disconnected from `TaskRouter`. Allow only inert protocol/task-contract fixtures until control-plane gates pass. |
| 4 - Evasion | Mostly missing and deferred | Only `sleep_mask.py` matches the planned files. Do not expand stealth or evasion capability; prioritize containment, detection-oriented simulation, and protocol correctness. |
| 5 - CI/CD Supply Chain | Missing and deferred | No planned `cicd/` package exists. Limit future work to authorized, non-destructive validation after scope, audit, and safety controls pass. |
| 6 - Brain Intelligence | Partial | Brain, planner, and autonomous primitives exist; a verified attack graph, APT profile, defensive-awareness contract, and acceptance path do not. Keep AI outputs behind deterministic evidence gates. |
| 7 - macOS | Missing and deferred | No planned macOS implant package exists. No expansion before governed lab controls and the canonical C2 protocol pass. |
| 8 - Transport/Delivery | Missing and deferred | The six planned transports and six named delivery builders are absent. Do not add delivery breadth before protocol, artifact, scope, and audit conformance. |
| 9 - Reporting/OPSEC/Exfil | Reporting partial; other work deferred | Report, delta, and timeline primitives exist; planned OPSEC/exfil packages do not. Advance canonical evidence/reporting now and keep high-risk expansion deferred. |
| 10 - Integrations/Edge | Partial, mostly UI-only | Integrations UI is seeded and there is no integrations package; IPv6 and ICS modules exist. Build safe, auditable connector contracts only after canonical data ownership. |
| 11 - Scanner Depth | Partial equivalents; accuracy gates fail | GraphQL, WebSocket, HTTP smuggling, prototype-pollution, SSRF, IPv6, and ICS equivalents exist, but named acceptance fixtures and verification evidence are mostly absent. Scanner accuracy work is active now. |

Sprint sequencing:

1. Now: Sprint 2 integration correctness, Sprint 9 canonical evidence/reporting, Sprint 10 safe connector contracts, and Sprint 11 scanner accuracy.
2. After P0/P1: Sprint 0 and Sprint 1 passive or read-only coverage with durable scope, evidence, and tests.
3. Deferred: offensive expansion in Sprints 3 through 8 until scope, identity, protocol, durable state, audit, and inert lab conformance gates pass.

A sprint can move to complete only when its launcher or API path, authorization and scope checks, durable state, error/cancel behavior, evidence, reporting, and automated acceptance tests work end to end. File existence alone receives no completion or maturity-score credit.

## Enterprise Blockers

### P0-1: Scanner Accuracy And False Positives

This is the highest scanner priority because operator trust is already being lost in real scans.

Current evidence:

- 272 module files create findings.
- Only 6 module files import or use `FPReducer`.
- Only 12 module files set confidence explicitly.
- No scanner module passes the first-class `verification=` object into `new_finding()`.
- FM-P0-001 is fixture-validated: absent, null, blank, whitespace, and unknown finding confidence now fail closed to `UNVERIFIED` across shared creation, persistence, dashboard, engagement-bus, and report boundaries.
- HTML/PDF can suppress low/unverified findings while JSON/CSV include a different set.

Business-logic findings are especially weak:

- IDOR uses changed numeric IDs plus response length/body differences without two authenticated actors (`webforge/modules/access_control/idor_scanner.py:78`).
- Admin access can be inferred from HTTP 200 and a body longer than 100 bytes (`webforge/modules/access_control/priv_esc.py:67`).
- Mass assignment can be inferred from reflected field names or response-size change without reading authoritative role state (`webforge/modules/access_control/mass_assignment.py:116`).
- Price tampering treats broad `0` or `-1` reflections and HTTP 200 responses as evidence without proving a committed cart/order price (`webforge/modules/business_logic/price_tamper.py:71`).
- Workflow bypass relies on status codes and success keywords without proving an impossible state transition (`webforge/modules/business_logic/workflow_bypass.py:182`).
- Race-condition logic counts multiple HTTP 200 responses instead of proving a duplicated ledger/order/coupon side effect (`webforge/modules/business_logic/race_condition.py:130`).
- MFA logic relies on page keywords and a small burst of invalid attempts rather than proving authenticated post-MFA access (`webforge/modules/auth/mfa_bypass.py:135`).

Authentication checks also contain direct false-positive paths:

- Repeating the same invalid TOTP and receiving the same rejection response can be labeled replay, even though identical rejection behavior is expected (`webforge/modules/auth/totp_bypass.py:186`).
- A few backup-code attempts without lockout keywords can become a High finding without evaluating 429 responses, rate headers, delay, or account/session-scoped throttling (`webforge/modules/auth/totp_bypass.py:113`).
- Password acceptance can be inferred from the absence of error words instead of successful account creation and login (`webforge/modules/auth/password_policy.py:62`).
- Account enumeration compares a random username to hardcoded `admin` and uses a response-length threshold without proving the account exists or normalizing dynamic content (`webforge/modules/auth/password_policy.py:110`).

The shared reducer is a useful foundation but is not itself a complete accuracy guarantee:

- Error SQLi can confirm against pages that already contain database errors because it lacks a clean-response error baseline (`common/fp_reducer.py:420`).
- Reflected XSS checks response context but does not execute the candidate in a browser (`common/fp_reducer.py:504`).
- SSTI uses fixed/common arithmetic output rather than a unique per-run canary with a clean baseline (`common/fp_reducer.py:563`).
- LFI defines more platform/encoding variants than the verifier actually executes (`common/fp_reducer.py:734`).
- A global verification timeout can turn slow targets or delayed callbacks into false negatives (`common/fp_reducer.py:1048`).
- False-negative follow-up suggestions exist but have no production consumer (`common/fp_reducer.py:1089`).

#### Accuracy Contract

The required lifecycle is:

```text
DetectionCandidate -> controls -> probe variants -> VerificationAttempt -> Finding
```

Every reportable detector must emit:

```text
detector_id, detector_version, run_id, asset_id, actor_id, target, test_point,
baseline_samples, probes, confirmations, negative_controls, confidence,
proof_class, evidence_ids, normalization_method, cleanup_status, error
```

Proof classes:

| Class | Meaning | Default Report |
| --- | --- | --- |
| INFORMATIONAL | Technology or attack-surface observation | Optional |
| SUSPECTED | Weak signal or single probe | No; verification queue only |
| REPRODUCED | Repeated vulnerability behavior with negative control | Yes, clearly labeled |
| IMPACT_CONFIRMED | Authoritative state/data/access impact proved | Yes |

`HIGH` or `CRITICAL` business-logic findings require `IMPACT_CONFIRMED`. Status codes, response length, reflection, or keywords alone cannot satisfy this gate.

#### Detector-Specific Proof Requirements

| Detector Family | Required Confirmation |
| --- | --- |
| SQLi/XSS/SSTI/LFI/CMDi | Clean baseline, two independent probes, context-specific proof, WAF/error negative controls |
| Blind/OOB | Correlated one-time token, target/run binding, callback timestamp, expiration and replay rejection |
| IDOR/BOLA | User A creates/owns a canary object; user B reads or mutates that exact object; unrelated-object negative control |
| Privilege escalation | Role/permission before and after, protected action succeeds, independent identity verification, cleanup |
| Mass assignment | Privileged field changes authoritative stored state and enables a protected action; reflection is insufficient |
| Price tampering | Server-authoritative cart/order total changes and survives read-back; test transaction is canceled/cleaned |
| Workflow bypass | Explicit state machine shows a forbidden transition and resulting durable business state |
| Race condition | Barrier-synchronized requests violate a ledger, balance, inventory, coupon, or idempotency invariant |
| MFA bypass | Invalid/missing factor results in access to a protected post-MFA resource in the same session |
| CVE/version finding | Normalized product/CPE/package version plus vendor range and feed version; banner-only is suspected |
| Compliance control | Successful named checks and collected evidence; absent findings are NOT_TESTED, not PASS |

#### Accuracy Release Gates

- 100% of default-report detectors use the structured verification contract.
- Missing confidence defaults to `UNVERIFIED`, never `MEDIUM`. **Fixture-validated by FM-P0-001 on 2026-07-18.**
- All output formats consume one canonical filtered dataset.
- Critical/High precision is at least 98% on the maintained positive/negative corpus.
- Core injection recall is at least 90% on the maintained fixture corpus.
- Business-logic Critical/High false positives are zero on negative fixtures.
- Critical/High manual overturn rate is at most 2% in field telemetry.
- Duplicate finding/event rate is zero and cross-format confirmed-finding parity is 100%.
- Each detector has normal, vulnerable, WAF/block-page, auth-expired, redirect, timeout, and malformed-response controls where relevant.
- Operator false-positive decisions require a reason code and become regression fixtures after review.
- Detector health is visible by version: runs, confirmed, suppressed, FP rate, FN escapes, median verification time.

### P0-2: Scope And Execution Safety

- Dashboard scan launch accepts an operator-supplied target without an approved engagement/scope record (`common/dashboard/server.py:1181`).
- Dashboard subprocesses receive `--auto-confirm`, bypassing authorization and action gates (`common/dashboard/server.py:1255`).
- Empty scope allows all targets (`common/scope.py:95-99`).
- Redirect hops and DNS resolutions are not revalidated; authenticated requests can follow redirects out of scope.

Required outcome: canonical approved scope, exclusions, resolved-address pinning, redirect-hop validation, cross-origin credential stripping, bounded rate/concurrency/duration, and per-action policy.

### P0-3: Control-Plane Trust

- Remote event ingestion is unauthenticated (`common/dashboard/server.py:621`).
- Remote event transport disables TLS verification (`common/dashboard/event_bus.py:449`).
- Events are not tied to a worker, job, run, or replay-resistant sequence.

Required outcome: per-job worker identity, signed/versioned envelopes or mTLS, schema validation, replay protection, ownership checks, idempotent event IDs, and durable delivery state.

### P0-4: Identity And Secret Safety

- Dashboard ships `operator / forge2026` with unsalted SHA-256 (`common/dashboard/auth.py:84`).
- C2 defaults to `changeme` and also uses fast SHA-256 (`forge_c2/server.py:102`, `forge_c2/server.py:834`).
- OIDC can consume an unverified ID-token payload (`common/dashboard/server.py:433`).
- Browser bearer tokens are stored in `localStorage` (`apex-ui/src/config/api.js:43`).
- Browser auth state containing cookies/tokens is written as plaintext scan artifacts.

Required outcome: fail-closed first run, Argon2id, verified OIDC claims/signatures/nonce/audience, revocation/lockout, secure cookies, vault/KMS references, encrypted temporary auth state, and deletion/retention policy.

### P0-5: Honest Product Behavior

- Active scans are in-memory subprocess objects (`common/dashboard/server.py:183`).
- `SCAN_START` clears shared dashboard findings and state, breaking concurrent scans (`common/dashboard/state_store.py:246`).
- Finding retest returns random results (`common/dashboard/server.py:1150`).
- Several scan settings are accepted by the UI but ignored at execution.
- Vulnerability, C2, team, agents, scheduling, reports, policy, audit, and integration pages contain seeded/static data.
- Compliance maps absence of detections to pass (`common/reporting/compliance_engine.py:63`).

Required outcome: unsupported controls are disabled or labeled; no simulation appears as live data; scan terminal states and reports distinguish completed, partial, failed, canceled, and not tested.

### P0-6: Reproducible Build And Runtime

- React has no package manifest or lockfile.
- Docker has no frontend build stage.
- Docker/Compose health checks call an authenticated endpoint without credentials.
- Compose defaults expose weak dashboard/C2 secrets.
- C2 Compose startup omits required high-risk acknowledgements.
- The smoke driver referenced by workspace instructions is missing.

Required outcome: clean-checkout build, pinned locks, frontend unit/build/E2E jobs, working health endpoints, secure Compose profiles, and deterministic local smoke tests.

## Competitive Gap Programs

### Nessus-Class Network VM

Build these after P0 contracts are enforced:

1. Typed credential profiles for SSH, SMB/WMI/WinRM, SNMPv3, databases, network devices, sudo/su, and vault references.
2. Canonical asset inventory: hostname, IP history, OS, services, CPE/package inventory, criticality, owner, tags, and credentialed coverage.
3. Signed/versioned plugin and intel feed with compatibility checks, staged activation, rollback, freshness SLO, and scan-to-feed provenance.
4. Policy engine with discovery, safe, balanced, exhaustive, credentialed, compliance, and custom profiles whose settings are actually enforced.
5. Credentialed patch/configuration auditing and evidence-backed CIS/STIG/PCI mappings.
6. Durable scan nodes with enrollment, capabilities, leases, heartbeats, resource budgets, cancellation, checkpoint/resume, and result streaming.
7. Stable finding fingerprints, delta scans, reopened/fixed lifecycle, accepted risk, suppression expiry, and remediation tickets.

### Acunetix-Class DAST

1. One authenticated graph combining browser navigation, forms, XHR/fetch, HTTP crawl, JavaScript routes, OpenAPI/Postman/GraphQL, and imported sessions.
2. Login macro recording with secret references, success assertions, session health, reauthentication, logout avoidance, CSRF/token refresh, and MFA pause/resume.
3. Actor-aware authorization testing with anonymous, user A, user B, manager, and admin contexts.
4. Stateful business-workflow specifications, invariant assertions, reset/cleanup hooks, and proof of durable impact.
5. Request replay and mutation engine with canonical normalization, dependency ordering, rate/timeout/retry policy, and per-test safety class.
6. Correlated OOB callbacks for blind findings with one-time tokens and evidence retention.
7. Scan completeness report: routes reached, forms/APIs tested, auth coverage, blocked/failed/skipped tests, and reason codes.

### Cobalt-Strike-Class Operator Reliability

This track remains lab-safe and governance-first. Do not prioritize new stealth, evasion, persistence, or credential-theft capability.

1. Fix or disable the unified C2 launch/connect/listener paths.
2. Define one versioned authenticated protocol with durable server identity, fail-closed crypto, replay rejection, key rotation acknowledgment, and conformance fixtures.
3. Replace plaintext operator control traffic and default credentials with shared enterprise identity/RBAC, TLS/mTLS, expiry, revocation, and lockout.
4. Persist campaigns, approved scope, operators, listeners, sessions, tasks, results, approvals, and audit events in the canonical control plane.
5. Route one typed task registry through one listener/transport implementation with task leases, acknowledgments, retry, timeout, cancellation, and idempotency.
6. Wire real REST/WebSocket APIs to the C2 dashboard and support two-operator consistency across refresh/restart.
7. Unify build systems and validate declared artifact format, hash, expiry, protocol version, inputs, toolchain, SBOM, provenance, and approval. Never silently substitute another format.

## Phased Delivery Plan

### Phase 0: Containment, Truth, And Accuracy (Weeks 0-3)

Deliver:

- Freeze new modules and new dashboard pages.
- Change missing confidence to `UNVERIFIED`; remove implicit legacy `MEDIUM` promotion. **Fixture-validated by FM-P0-001.**
- Use one canonical filtered finding set for every report format.
- Quarantine business-logic detectors from default reports until impact proof exists.
- Authenticate remote events and remove TLS bypass.
- Enforce approved scope before launch; remove unconditional dashboard `--auto-confirm`.
- Remove default production credentials and unverified OIDC fallback.
- Disable random retest and seeded data in connected/product mode.
- Restore frontend build metadata and deterministic smoke path.
- Fix or explicitly disable C2 launcher and misleading build outputs.

Exit criteria:

- Zero out-of-scope second-hop requests in redirect/DNS tests.
- Zero unauthenticated event mutation paths.
- Zero simulated findings/retests in product mode.
- Critical/High findings cannot enter default reports without structured proof.
- Clean checkout builds backend and frontend and passes smoke tests.

### Phase 1: Canonical Control Plane (Weeks 3-10)

Deliver versioned SQLAlchemy/Alembic models for:

```text
tenant, user, service_account, role, engagement, authorization_record,
asset, scope_rule, credential_reference, policy, schedule, job, job_attempt,
module_run, finding, verification, evidence, retest, report, audit_event,
worker, worker_lease, integration_delivery
```

Use immutable IDs and ownership at every boundary. Replace global JSON and process-only state with durable job/event state. Reports read canonical persisted data only.

Exit criteria:

- Jobs, findings, status, logs, and controls survive restart.
- Concurrent scans do not overwrite each other.
- Every mutation records actor, tenant, engagement, scope decision, timestamp, and outcome.
- Duplicate/replayed events are idempotent.

### Phase 2: Accuracy And Authenticated Scanner Depth (Weeks 6-18)

Deliver:

- Detector manifest and verification SDK.
- Positive/negative fixture corpus and accuracy dashboard.
- FPReducer retrofit for all default-report injection/file/auth/access-control detectors.
- Actor-aware DAST and business-logic state engine.
- Unified authenticated crawl/API graph.
- Credentialed network profiles and vault integration.
- Canonical intel/CPE/package correlation and signed feed lifecycle.
- Honest scan completeness and compliance coverage.

Exit criteria:

- Accuracy release gates in P0-1 pass by detector version.
- Auth-only SPA routes/forms/APIs are discovered in maintained fixtures.
- Two-user IDOR, role, workflow, price, race, and MFA fixtures produce exact expected findings with clean negative controls.
- Credentialed and unauthenticated coverage differences are reported.

### Phase 3: Remediation And Operator Workflow (Months 4-7)

Deliver:

- Real target, asset, policy, schedule, job, log, finding, retest, report, team, and audit workflows.
- Stable finding fingerprint and new/fixed/reopened/changed states.
- Assignment, comments, accepted risk with expiry, suppression reason, SLA, and ticket lifecycle.
- Jira/ServiceNow/GitHub, webhook, email, SIEM, and report delivery with retries and audit.
- Evidence manifests, encryption, redaction, access logging, retention, and tamper verification.

Exit criteria:

- Retest re-runs the producing detector and stores evidence/history.
- UI state remains correct across refresh, reconnect, partial failure, and restart.
- Reports can prove what ran, what failed, and what was not tested.

### Phase 4: Governed C2 Lab Product (Months 6-10)

Deliver the C2 reliability program above only after shared identity, scope, jobs, evidence, and audit are production-worthy.

Exit criteria:

- An inert lab beacon fixture completes register/check-in/task/result over the versioned secure protocol.
- Spoofed, replayed, stale, malformed, and out-of-scope messages are rejected.
- Two operators with different roles see consistent durable state.
- Every task has engagement, scope, actor, approval policy, timestamps, result, and audit evidence.
- Artifact declarations match actual format and protocol compatibility.

### Phase 5: Distributed Enterprise Operations (Months 8-14)

Deliver:

- Durable queue and scan-node architecture with mTLS, capabilities, leases, heartbeats, checkpoint/resume, and bounded retries.
- PostgreSQL/object storage production profile, backup/restore, migrations, rollback, and disaster-recovery drills.
- Structured logs, metrics, traces, correlation IDs, alerting, support bundles, and SLO dashboards.
- Dependency locks, blocking SAST/dependency/secret scans, SBOM, signed images, provenance, and release channels.
- Load, soak, upgrade, failover, and multi-tenant isolation tests.

### Phase 6: Competitive Validation (Months 12-24+)

- Independent benchmark against representative authenticated web applications and network estates.
- Private authorized pilots with measured precision, recall, coverage, runtime, operator effort, and remediation closure.
- 30-day soak with no scope, secret, data-integrity, or audit incidents.
- Publish only capability claims backed by passing automated conformance and fixture results.

## Immediate Ordered Backlog

| Order | ID | Status | Work Item | Acceptance Signal |
| ---: | --- | --- | --- | --- |
| 1 | FM-P0-001 | Fixture-validated 2026-07-18 | Stop implicit confidence promotion | Missing confidence is UNVERIFIED in every output |
| 2 | FM-P0-002 | Unaccepted | Canonical report dataset | HTML/PDF/JSON/CSV finding IDs and dispositions match |
| 3 | FM-P0-003 | Unaccepted | Quarantine weak logic detectors | No logic High/Critical without impact proof |
| 4 | FM-P0-004 | Unaccepted | Authenticate worker events | Forged/replayed/wrong-job events rejected |
| 5 | FM-P0-005 | Unaccepted | Approved scope enforcement | Redirect/DNS/cross-origin test suite has zero escapes |
| 6 | FM-P0-006 | Unaccepted | Remove dashboard auto-confirm | Active actions follow policy and approval record |
| 7 | FM-P0-007 | Unaccepted | Secure identity baseline | No defaults, Argon2id, verified OIDC, revocation tests |
| 8 | FM-P0-008 | Unaccepted | Durable run/finding model | Concurrent jobs survive restart without state collision |
| 9 | FM-P0-009 | Unaccepted | Deterministic retest | Same fixture state produces the same verified result |
| 10 | FM-P0-010 | Unaccepted | Honest compliance states | Untested controls are never PASS |
| 11 | FM-P0-011 | Unaccepted | Frontend/build recovery | Clean install, test, build, and served SPA pass |
| 12 | FM-P0-012 | Unaccepted | Docker/runtime repair | Health, volumes, secrets, and profiles pass smoke |
| 13 | FM-P0-013 | Unaccepted | C2 truth/containment | Broken paths disabled or pass inert loopback conformance |
| 14 | FM-P0-014 | Unaccepted | CI release gates | Backend/frontend/E2E/security checks block regression |

### Verified Backlog Acceptance Evidence

- **FM-P0-001 — fixture-validated (2026-07-18):** `tests/test_confidence_policy.py` covers absent, null, blank, whitespace, unknown, malformed nested sources, source precedence, and explicit canonical confidence across the shared policy, `Finding`, `BaseModule`, SQLAlchemy persistence, dashboard snapshots, engagement-bus publication/storage, JSON, CSV, HTML, and the PDF HTML-source contract. Focused acceptance: `55 passed in 2.64s` under warnings-as-errors. Documented full Python suite: `245 passed in 15.31s`.
- The readiness score remains **3.5/10**. FM-P0-002 canonical report-set parity, detector verification adoption, and the remaining Phase 0 gates are still unaccepted. Historical `MEDIUM` rows created before confidence provenance was recorded cannot be safely distinguished from explicitly verified `MEDIUM` rows and require a future evidence-aware migration policy.

## Release Gates

### Internal Alpha

- Phase 0 exit criteria pass.
- One dashboard-driven WebForge and NetForge workflow is durable and auditable.
- Accuracy metrics exist for every enabled default-report detector.
- Product mode contains no seeded or random behavior.

### Internal Beta

- Canonical control plane and authenticated scanner depth pass fixture tests.
- Real retest, delta, report, and remediation lifecycle work.
- Verified OIDC/RBAC/audit and secret handling pass negative tests.
- Credentialed network and authenticated DAST coverage are measurable.

### Private Pilot

- Supportable hardened install and upgrade path.
- Signed authorization and scope workflow.
- Independent accuracy benchmark and triaged pilot feedback.
- Backup/restore, incident logging, and support diagnostics are proven.

### Enterprise V1

- Distributed execution, tenant isolation, SLOs, audit retention, signed releases, SBOM, migration rollback, and 30-day soak pass.
- Claims are generated from the capability registry and passing tests.
- Known limitations are explicit and enforced in UI/API behavior.

## No-New-Feature Rule

Until Phase 0 is complete, do not add:

- New exploit, cloud, mobile, C2 evasion, persistence, payload, or dashboard-page breadth.
- New detector modules without fixtures, negative controls, and the verification contract.
- New compliance mappings that infer pass from absence.
- New AI-generated findings that bypass deterministic evidence gates.

Allowed work:

- Accuracy, scope, auth, persistence, protocol correctness, packaging, tests, evidence, reporting, observability, and honest product-state fixes.

## Timeline

For a focused small team:

| Milestone | Realistic Target |
| --- | ---: |
| P0 containment and accuracy baseline | 3-5 weeks |
| Credible internal alpha | 2-3 months |
| Strong internal beta | 4-6 months |
| Private enterprise pilot | 6-9 months |
| Production enterprise V1 | 12-18 months |
| Broad mature-product parity | 18-24+ months |

## Roadmap Maintenance Rules

- Update the verified baseline after meaningful architecture or release changes.
- Every completed item must cite its automated acceptance tests.
- Track capability state as `implemented`, `partial`, `fixture-validated`, `pilot-validated`, or `production-validated`.
- Do not mark UI-only, source-only, or importable code as complete.
- Record detector accuracy by version and corpus; do not use anecdotal scan success as a quality gate.
- Keep sensitive operational details out of planning documents; focus on safe engineering, validation, and governance.
