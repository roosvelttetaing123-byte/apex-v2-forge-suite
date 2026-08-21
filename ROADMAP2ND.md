> [!CAUTION]
> **ARCHIVED MOBILEFORGE / BREADTH EXPANSION PLAN - NOT APPROVED UNDER THE CURRENT BREADTH FREEZE**
>
> Do not implement this roadmap unless the breadth freeze is explicitly lifted. Use [ENTERPRISE_MATURITY_ASSESSMENT.md](ENTERPRISE_MATURITY_ASSESSMENT.md) and [ROADMAP.md](ROADMAP.md) as the authoritative documents.

# Forge Suite Second Roadmap — Long-Term Platform And MobileForge Plan

Updated: 2026-06-30

This is the second roadmap. `ROADMAP.md` remains the active first roadmap and must be completed first, or at minimum its stabilization gate must be complete before this roadmap becomes implementation work.

## Stabilization Gate From Roadmap 1

Do not start Roadmap 2 until these Roadmap 1 outcomes are complete and verified:

- Durable scan jobs exist for all scanner launches.
- Scan logs, status transitions, artifacts, and controls survive dashboard refresh and backend restart.
- Pause, resume, abort, and cancellation are real, not UI-only.
- Finding retest reruns the correct module or verifier and stores retest evidence.
- Findings use one normalized evidence and confidence contract.
- Reports are generated from persisted canonical data, not transient UI state.
- Authenticated WebForge, NetForge, ADForge, reports, and dashboard workflows pass lab-backed tests.
- High-risk C2/payload actions remain disabled by default and require explicit authorized-engagement gates.

If any of those items are incomplete, continue executing `ROADMAP.md` first.

## Direction

Forge should remain one product with one control plane, one dashboard, one API surface, one reporting layer, and one evidence/finding model. The engines should stay isolated internally.

Long-term architecture:

```text
Forge Control Plane
  - Dashboard / API / RBAC / SSO
  - Scope and authorization
  - Durable jobs and scheduling
  - Evidence store
  - Finding store
  - Retest system
  - Reports and exports
  - Audit log
  - Policy/template engine
  - Integrations

Execution Engines
  - WebForge: web, API, DAST, browser/auth, business logic
  - NetForge: network, CVE, credentialed, compliance, cloud/container
  - ADForge: AD, ADCS, Kerberos, attack paths
  - AIForge: LLM and AI application testing
  - C2Forge: C2/team server/payload/BOF, high-risk gated
  - ForgeCollab: OOB callback verification
  - MobileForge: Android first, iOS later
```

Decision: do not merge every module into one scanner, and do not split Forge into separate products yet. Use one control plane with separate engines and shared contracts.

## Shared Contracts

Every engine must accept the same minimum job shape:

```json
{
  "job_id": "uuid",
  "engine": "webforge|netforge|adforge|aiforge|c2forge|mobileforge",
  "target": "string",
  "scope": ["string"],
  "policy_id": "string",
  "auth_ref": "string|null",
  "safety_mode": "passive|standard|active|high_risk",
  "dry_run": false,
  "created_by": "operator_id"
}
```

Every engine must emit the same minimum finding shape:

```json
{
  "id": "uuid",
  "job_id": "uuid",
  "engine": "string",
  "module": "string",
  "target": "string",
  "asset": "string",
  "title": "string",
  "severity": "Critical|High|Medium|Low|Informational",
  "confidence": "HIGH|MEDIUM|LOW|UNVERIFIED",
  "status": "open|verified|false_positive|remediated|accepted_risk",
  "proof_type": "active|passive|version_correlation|oob|manual|static",
  "evidence_refs": ["evidence_id"],
  "retest_supported": true,
  "created_at": "ISO-8601"
}
```

Every engine should expose this internal interface:

- `plan(job) -> planned modules/actions`
- `run(job, event_sink, control_channel) -> results`
- `cancel(job_id) -> status`
- `retest(finding, context) -> retest_result`
- `capabilities() -> engine metadata`

Minimum engine metadata:

```json
{
  "engine": "mobileforge",
  "version": "0.1.0",
  "capabilities": ["static_analysis", "dynamic_analysis", "api_extraction"],
  "supported_targets": ["apk"],
  "requires_agent": false,
  "requires_high_risk": false,
  "retest_supported": true
}
```

## Phase 1: Post-Stabilization Control Plane

Goal: convert the stabilized first-roadmap platform into a product-grade control plane.

Build:

- One job API for all engines.
- One engine registry for capabilities, required tools, supported policies, and retest support.
- One evidence store for screenshots, request/response snippets, logs, files, OOB callbacks, static-analysis artifacts, and report attachments.
- One audit log for task creation, scope decisions, credential use, report export, C2 actions, and integration exports.
- One policy/template system for repeatable engagement configurations.
- One report builder that can combine WebForge, NetForge, ADForge, AIForge, C2Forge, ForgeCollab, and future MobileForge findings.

Acceptance criteria:

- Operator can launch, monitor, cancel, retest, report, and export through one dashboard workflow.
- Every finding traces to a job, engine, module, policy, target, and evidence set.
- Unsupported modules/checks are rejected before execution with clear operator-facing errors.
- Secrets are not present in argv, logs, reports, history, frontend state, or exported artifacts.

## Phase 2: Policy, Evidence, And QA Maturity

Goal: make Forge trustworthy enough for repeated client-facing assessments.

Build policy templates:

- External network.
- Internal network.
- Authenticated web.
- API.
- Credentialed Windows.
- Credentialed Linux.
- Active Directory.
- Cloud/container.
- PCI.
- CIS L1/L2.
- Red-team emulation.

Build quality controls:

- Required proof type and confidence for every finding.
- Deterministic finding deduplication.
- Delta reports for new, fixed, and remaining findings.
- Vulnerability aging with first seen, last seen, days open, recurrence count, and SLA status.
- Signed or versioned check-pack metadata for YAML/native checks.
- Lab-backed CI for web/API, network, credentialed checks, AD, AI, C2 local flows, and later mobile fixtures.

Acceptance criteria:

- CI proves at least one positive and one negative fixture for each major vulnerability family.
- Reports clearly separate verified, inferred, version-correlated, OOB-confirmed, static-analysis, and manual-review findings.
- Re-running a scan against the same target deduplicates findings consistently.
- Delta reports use persisted findings, not UI state.

## Phase 3: Commercial Workflow Parity

Goal: make Forge usable in normal security-team workflows.

Build integrations:

- SARIF export.
- Jira issue creation.
- GitHub/GitLab issue creation.
- Webhook export.
- Slack/Teams notifications.
- SIEM/syslog export.
- Maintain Burp XML export for WebForge.

Build dashboard maturity:

- Global search.
- Command palette.
- Loading, empty, error, stale, reconnect, unauthorized, and partial-result states.
- Per-job logs and artifacts.
- Finding proof timeline.
- Report history.
- Integration export history.

Acceptance criteria:

- A third-party issue tracker receives enough structured data to reproduce and remediate a finding.
- Webhook/SIEM exports redact secrets by default.
- Dashboard reconnect restores canonical backend state.
- Operators can tell what ran, what did not run, and why.

## Phase 4: C2 And Red-Team Hardening

Goal: keep C2 powerful but isolated, auditable, and explicitly authorized.

Build:

- C2Forge as a separate high-risk engine behind explicit gates.
- REST API for listeners, beacons, tasks, task output, artifacts, BOFs, profiles, and operator activity.
- Artifact store for BOFs, payloads, profiles, scripts, and generated reports.
- Approval workflow for executable artifacts.
- Operator activity ledger for every listener, task, output, profile, artifact, and report action.
- Red-team report timeline with MITRE ATT&CK mapping, expected detections, observed detections, operator actions, scope decisions, and evidence references.

Rules:

- C2 and payload generation stay disabled by default.
- High-risk actions require authorized-engagement flags and operator role checks.
- DNS/SMB/P2P features must either be implemented and tested in lab-safe form or removed from user-facing claims.
- Prefer safe adversary emulation, detection validation, and after-action reporting over stealth or unrestricted exploitation.

Acceptance criteria:

- Every C2 action records operator, timestamp, target or beacon, command type, result, and evidence.
- BOFs/artifacts cannot execute unless approved and within engagement scope.
- C2 reports are usable for defensive after-action review.
- Normal VAPT mode cannot accidentally access high-risk C2 actions.

## Phase 5: Distributed Architecture

Goal: support larger environments and future mobile/device labs without overloading the dashboard host.

Build scan agents:

- Agent registration.
- mTLS.
- Health checks.
- Capability declaration.
- Scoped job assignment.
- Result streaming.
- Offline queueing.
- Agent-side cancellation.

Agent roles:

- Web scanner.
- Network scanner.
- Credentialed scanner.
- Mobile lab node.
- C2 lab node.

Storage defaults:

- SQLite for local/single-node mode.
- Postgres for multi-node mode.
- Local filesystem or object store for artifacts.

Multi-tenant groundwork:

- Clients.
- Projects.
- Engagements.
- Per-engagement scope.
- Per-engagement operators.
- Per-engagement reports.

Acceptance criteria:

- A scan agent can register, receive a scoped job, stream results, and disconnect cleanly.
- Dashboard shows central and agent-side job state.
- Artifacts and findings remain tied to the originating agent and engagement.
- Local single-node mode still works without distributed infrastructure.

## Phase 6: MobileForge Android MVP

Goal: add mobile application testing after the core product is stable. Start with Android.

MobileForge is a new engine. It must use the same job, evidence, finding, retest, policy, and report contracts as all other engines.

Initial scope:

- Android APK static analysis.
- Android manifest review.
- Permission review.
- Exported activity, service, receiver, and provider checks.
- Debuggable and backup flags.
- Hardcoded secrets and API keys.
- Insecure local storage indicators.
- Cleartext traffic configuration.
- Network security config review.
- Certificate pinning indicators.
- WebView risk checks.
- Native library inventory.
- Dependency/library inventory.
- Basic SBOM output.
- API endpoint extraction from APK.
- Optional emulator/device dynamic testing.

Recommended integrations:

- `apktool` for APK decode.
- `jadx` for Java/Kotlin decompile.
- Android build tools or `apksigner` for signing metadata.
- `adb` for emulator/device interaction.
- Frida support later, gated as active/dynamic testing.
- MobSF import/export compatibility if useful, but do not make MobSF the core engine.

MobileForge policy templates:

- `mobile-android-static`
- `mobile-android-api-discovery`
- `mobile-android-dynamic-basic`
- `mobile-android-full-lab`

MobileForge job additions:

```json
{
  "engine": "mobileforge",
  "target": "path/to/app.apk",
  "platform": "android",
  "analysis_mode": "static|dynamic|hybrid",
  "device_ref": "emulator_or_device_id|null",
  "api_scope": ["https://api.example.com"],
  "safety_mode": "passive|standard|active"
}
```

Mobile finding examples:

- Exported component without permission.
- Debuggable app enabled.
- Backup allowed.
- Cleartext traffic allowed.
- Hardcoded secret.
- Weak TLS/network security config.
- Insecure WebView setting.
- Sensitive data in local storage path.
- Vulnerable library version.
- Embedded API endpoint outside declared scope.

Dynamic testing rules:

- Dynamic tests require an authorized lab device or emulator.
- Dynamic tests must not bypass third-party services or real user accounts.
- Frida/ADB actions must be logged as active lab actions.
- Captured traffic must respect declared API scope.
- Credential/session material must be stored only as redacted evidence.

Acceptance criteria:

- APK-only static scan produces findings and a mobile report section.
- API endpoints extracted from APK can be handed to WebForge/API policy.
- Dynamic mode can run against an emulator and collect logs/artifacts.
- Mobile findings appear in the same dashboard, report, retest, and export views as web/network findings.
- Android support is stable before iOS work starts.

## Phase 7: MobileForge Expansion And iOS

Goal: expand mobile testing only after Android MVP is reliable.

Android expansion:

- Deeper runtime checks.
- Frida-assisted runtime observations.
- Certificate pinning detection/validation in lab.
- Secure storage validation.
- Authentication/session workflow capture.
- Mobile API abuse workflows.
- MASVS mapping.
- Play Integrity/root detection observations as defensive notes.

iOS later:

- IPA metadata and static analysis.
- Info.plist review.
- Entitlements review.
- URL scheme and deep-link checks.
- ATS config checks.
- Keychain/storage indicators.
- Dependency/library inventory.
- Simulator/device dynamic workflow where available.
- macOS runner requirement documented.

Acceptance criteria:

- Android support has stable tests and reports before iOS work starts.
- iOS plan explicitly documents macOS/device/tooling requirements.
- MobileForge remains an engine, not a forked platform.

## Roadmap 2 Test Plan

Before marking Roadmap 2 active:

- Verify `ROADMAP.md` stabilization gate is complete.
- Verify durable jobs, retest, evidence, reports, auth, and lab CI pass.
- Verify existing engines still work through the common job contract.
- Verify C2 high-risk gates remain enforced.

For each Roadmap 2 phase:

- Add unit tests for new contracts.
- Add integration tests for job lifecycle and evidence persistence.
- Add dashboard/API tests for visible operator workflows.
- Add fixture tests before adding new scanner checks.
- Add report tests that prove persisted data is used.

MobileForge fixture tests:

- Benign APK with no findings.
- APK with exported component.
- APK with cleartext traffic allowed.
- APK with hardcoded test secret.
- APK with insecure WebView setting.
- APK with embedded API endpoint.
- Emulator smoke test for install, launch, log collection, and cleanup.

## Defaults And Assumptions

- `ROADMAP.md` is the first roadmap and remains active until stabilized.
- `ROADMAP2ND.md` is strategic until the stabilization gate is complete.
- Forge remains one product with one dashboard and one reporting layer.
- Engines remain internally separate and communicate through shared contracts.
- Android is the first mobile target.
- iOS is deferred until Android support is proven.
- C2/payload remains high-risk gated and separate from normal VAPT mode.
- New offensive capability should prefer authorized emulation, proof, detection validation, and reporting over stealth or unrestricted exploitation.
