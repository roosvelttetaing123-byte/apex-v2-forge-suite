# Forge Suite v5 APEX - Engineering Handoff

Updated: 2026-07-18

Current status: engineering prototype / alpha, enterprise readiness approximately 3.5/10.

The weighted score gives the most credit to scanner accuracy/evidence (20%), control-plane integrity (15%), and identity/governance (10%). Architecture breadth is approximately 6/10, but scanner accuracy is 3/10, business-logic detection is approximately 2.5/10, Nessus-like maturity is 4/10, Acunetix-like maturity is 4/10, and C2/operator maturity is 2/10. New files or modules do not improve the score without passing end-to-end acceptance gates.

## Authoritative Memory

- `ROADMAP.md` is the single source of truth for gaps, priorities, accuracy gates, phases, and release criteria.
- `HANDOFF.md` is the concise current-state memory for future engineering sessions.
- Older `task*.md`, `implementation_plan.md`, sprint documents, and enterprise review files are historical input only.

Read these two files first. Then inspect only the code involved in the requested change.

## Verified Local Baseline

Validation performed without scans, listeners, payload generation, or external network calls:

```text
python3 forge.py --help                                      PASS
framework/dashboard imports                                 PASS
pytest common webforge netforge adforge aiforge forge_c2 tests
                                                           245 passed in 15.31s
Python AST parse                                            497 files, 0 errors
```

The preferred `.claude/skills/run-forge-suite/smoke.py` driver is currently missing.

## Product Inventory

```text
forge.py                    unified CLI entry point
common/                     finding, evidence, scope, FP reduction, DB,
                            reporting, intel, brain, dashboard/event systems
netforge/                   network discovery, service/vulnerability modules
webforge/                   DAST, Playwright/auth, API/schema, logic modules
adforge/                    Active Directory assessment/emulation modules
aiforge/                    AI/LLM assessment modules
forge_c2/                   C2 server/listener/transport/task prototypes
forge_payload/              payload/build prototypes
forge_collab/               OOB callback service
apex-ui/                    React UI source; 19 pages
```

Repository snapshot: 602 files, 147,276 Python lines, and 286 `BaseModule` implementation files.

## What Is Real Today

- CLI help and all four framework orchestrator imports work.
- Python test suite currently collects and passes 245 tests.
- Structured findings/evidence, SQLite models, reports, compliance maps, VPR, delta code, intel sync, event bus, scan controls, browser/auth helpers, schema import, and many scanner modules exist.
- FM-P0-001 is fixture-validated: missing, null, blank, whitespace, and unknown finding confidence fail closed to `UNVERIFIED` at shared creation, persistence, dashboard, engagement-bus, and report boundaries.
- Six WebForge detector files use `FPReducer`: SQLi, XSS, SSTI, LFI/RFI, CMDi, and blind CMDi.
- Some dashboard scan, finding, credential-analysis, scan-library, and scan-detail paths use backend APIs.
- High-risk C2/payload CLI paths require both `--red-team` and `FORGE_ENABLE_HIGH_RISK=1` at the outer launcher.

## What Is Not Enterprise-Ready

### Scanner Accuracy

- 272 module files create findings; only 6 use `FPReducer`, only 12 set confidence explicitly, and no module passes structured `verification=` into `new_finding()`.
- Historical `MEDIUM` rows created before confidence provenance was recorded cannot be automatically distinguished from explicitly verified `MEDIUM` rows.
- Report formats can expose different finding sets.
- Logic modules often infer impact from status, length, reflection, or keywords without proving authoritative state changes.
- Compliance can treat missing findings as PASS instead of NOT_TESTED.

Accuracy work is P0. See `ROADMAP.md` for the proof contract, detector-specific requirements, fixture strategy, and precision/recall gates.

### Control Plane

- `/api/v1/events/emit` is unauthenticated and remote event TLS verification is disabled.
- Dashboard jobs are process handles in memory; history/templates are global JSON.
- Shared dashboard state is cleared on `SCAN_START`, so concurrent scans collide.
- Findings are not canonically owned by run/tenant/engagement.
- Finding retest is random simulation.
- Dashboard launch passes `--auto-confirm` and does not enforce an approved engagement scope.

### Identity And Secrets

- Dashboard defaults to `operator / forge2026` with unsalted SHA-256.
- C2 defaults to `changeme` with fast SHA-256.
- OIDC ID-token verification is incomplete.
- UI bearer tokens use `localStorage`.
- Browser storage-state artifacts may contain plaintext cookies/tokens.

### Frontend And Product Truth

- `apex-ui/package.json` and a lockfile are absent, so install/test/build is not reproducible.
- 6 of 19 pages use APIs/WebSockets; 13 are static or seeded.
- Several ScanBuilder controls are accepted but not applied to runtime behavior.
- Product mode can display fabricated vulnerability/C2/team/agent/schedule data.

### C2

- `forge.py` imports nonexistent `C2Server`; implementation class is `TeamServer`.
- Operator-shell construction/signature is mismatched; listener CLI is nonfunctional.
- Operator control traffic is plaintext; auth/session lifecycle is development-grade.
- Beacon handshake/encryption/result flow is not a coherent interoperable authenticated protocol.
- Parallel listener, transport, task, and build implementations are not composed.
- Dashboard C2/team/audit pages are UI-only.
- Build paths can silently substitute another artifact type while retaining the requested extension.

Do not add C2 stealth/evasion breadth. Fix containment, protocol correctness, identity, durable state, audit, and inert lab conformance first.

### Deployment And QA

- Docker/Compose ship weak default secrets.
- Health checks call an authenticated endpoint without credentials.
- Docker has no frontend build stage; result volume paths do not match all scanner output paths.
- Dependencies and downloaded tooling are not reproducibly locked/signed.
- CI runs a small suite, does not build/test the frontend, has no accuracy fixture corpus, and does not enforce a coverage or security threshold.

## Red Team Sprint Memory

The authoritative Sprint 0-11 disposition is in `ROADMAP.md`.

- Active now: Sprint 2 integration correctness, Sprint 9 evidence/reporting, Sprint 10 safe connector contracts, and Sprint 11 scanner accuracy.
- Resume after P0/P1: Sprint 0 passive leak-intel coverage and Sprint 1 bounded read-only cloud/container coverage.
- Partial: Sprints 0, 1, 2, 6, 9, 10, and 11; none currently passes its full end-to-end acceptance contract.
- Missing or mostly missing: Sprints 3, 4, 5, 7, and 8.
- Deferred: offensive C2 task, evasion, supply-chain, macOS implant, transport, delivery, OPSEC, and exfiltration expansion until scope, identity, protocol, persistence, audit, and inert lab gates pass.

Do not mark a sprint complete because files import or a UI exists. Require launcher/API wiring, authorization and scope enforcement, durable state, deterministic evidence, reporting, and automated acceptance tests.

## Immediate Work Order

`FM-P0-001` is fixture-validated. Continue with `FM-P0-002`, then process `FM-P0-003` through `FM-P0-014` in order.

Current ordered accuracy/reporting work:

1. Build one canonical report dataset shared by all formats.
2. Quarantine weak logic findings from default reports.
3. Add detector verification metadata and positive/negative fixtures.
4. Authenticate event ingestion and enforce approved scope.

## Latest Acceptance Evidence

FM-P0-001 was fixture-validated on 2026-07-18 without network activity, scans, listeners, or payload generation:

```text
pytest -q -W error tests/test_confidence_policy.py
55 passed in 2.64s under warnings-as-errors

pytest -q common webforge netforge adforge aiforge forge_c2 tests
245 passed in 15.31s
```

The acceptance matrix covers policy normalization, finding creation, module output, database persistence, dashboard snapshots, engagement-bus publication/storage, JSON, CSV, HTML, and the PDF HTML-source contract. Explicit canonical confidence remains unchanged. The score remains 3.5/10 because canonical cross-format parity, structured detector proof, measured precision/recall, and the remaining Phase 0 gates have not passed.

## Safety Boundaries

- Never scan targets without written authorization.
- Do not start listeners, generate payloads, or perform active exploit validation during ordinary tests.
- Use loopback/inert fixtures and local vulnerable applications for integration tests.
- Enforce scope at every outbound hop, including redirects and resolved IPs.
- Do not expose secrets in argv, logs, events, reports, UI state, screenshots, or test artifacts.
- High-risk actions need explicit policy, scope, actor, approval, audit, and cleanup state.

## Product Positioning

Current approved label: `Engineering Prototype / Alpha`.

Do not claim enterprise-grade status or parity with Nessus, Acunetix, or Cobalt Strike until the corresponding release gates in `ROADMAP.md` pass.
