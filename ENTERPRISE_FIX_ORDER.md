# Forge Suite Enterprise Fix Order

Updated: 2026-06-21

Purpose: this is a handoff for agents working on Forge Suite after the enterprise-readiness review. The current codebase has strong breadth, but the product is still alpha-quality because key control-plane, auth, scan accuracy, persistence, and C2/dashboard paths are incomplete or inconsistent.

Target outcome: make Forge Suite usable as an authorized VAPT and red-team platform operated from the dashboard, with reliable scans, durable jobs, real retesting, strong auth, accurate findings, and enterprise reporting.

Current reviewer rating:

| Area | Rating | Summary |
| --- | ---: | --- |
| Overall enterprise readiness | 4/10 | Broad prototype, not enterprise-grade yet |
| Architecture direction | 6.5/10 | Good modular layout, event bus, modules, dashboard concept |
| Dashboard-driven scan UX | 4/10 | UI exists, launch path is partly broken and state is in-memory |
| Web VAPT | 5/10 | Good module breadth, weak authenticated crawl and accuracy depth |
| Network VAPT | 5/10 | Useful modules, but scanner depth and scale need hardening |
| AD assessment | 4/10 | Broad coverage, known bugs and uneven real-world validation |
| AI red teaming | 5/10 | Useful prompt/module coverage, needs deterministic test harness |
| Cloud/mobile coverage | 2/10 | Mostly absent or represented only as UI/module intent |
| Red-team/C2 | 3/10 | Some server/payload code exists, CLI/product wiring is inconsistent |
| Reporting/compliance | 5/10 | Report engines exist, but enterprise workflow is incomplete |
| Security/auth/RBAC | 3/10 | Default admin, simple hashes, no SSO/MFA/tenant/audit depth |
| CI/test reliability | 4/10 | Some tests pass, full pytest hangs, UI test command is broken |

## P0: Fix Broken Dashboard Launch Paths

### P0.1 Dashboard authenticated WebForge scan fails

Problem:
- `common/dashboard/server.py` passes `--auth-type` and `--header-name` to `webforge/webforge.py`.
- `webforge/webforge.py` does not define those CLI args.
- Result: authenticated dashboard web scans fail before scanning starts.

Evidence:
- `python webforge/webforge.py --target https://example.com --mode greybox --auth-type form --dry-run`
- Fails with: `webforge.py: error: unrecognized arguments: --auth-type form`

Likely files:
- `common/dashboard/server.py`
- `webforge/webforge.py`
- `webforge/core/session.py`
- `webforge/core/auth_recorder.py`
- `apex-ui/src/pages/ScanBuilder.jsx`
- `apex-ui/src/components/CredentialsCard.jsx`
- `tests/test_credential_security.py`

Preferred fix:
- Add WebForge args: `--auth-type`, `--header-name`.
- Read secrets from env vars already set by dashboard:
  - `FORGE_PASSWORD`
  - `FORGE_TOKEN`
  - `FORGE_COOKIE_JAR`
  - `FORGE_AUTH_TYPE`
- Do not put password, bearer token, or cookie jar in argv.
- Populate `cfg.extra["session_headers"]` and `cfg.extra["session_cookies"]` consistently.
- Make `has_session` true when env-based auth is present.

Acceptance criteria:
- Blackbox dashboard launch still works.
- Greybox form auth launch does not fail on CLI parsing.
- Bearer-token auth applies the configured header name.
- Cookie auth applies cookies to ForgeSession/browser context.
- No secret appears in process args, scan logs, scan history JSON, or templates.

Validation:
```bash
python webforge/webforge.py --target https://example.com --mode greybox --auth-type form --username user --login-url https://example.com/login --dry-run
FORGE_TOKEN=test python webforge/webforge.py --target https://example.com --mode greybox --auth-type bearer --header-name Authorization --dry-run
python -m pytest tests/test_credential_security.py -q
```

### P0.2 ScanBuilder module IDs do not map to real scanner module names

Problem:
- UI sends IDs like `sqli`, `xss`, `rce`, `portscan`, `ssltls`.
- Backend mostly uses IDs only to decide web/net/vapt.
- WebForge/NetForge expect names like `sqli_scanner`, `xss_scanner`, `cmd_inject`, `port_scanner`, `ssl_audit`.
- User-selected modules are not faithfully executed.

Likely files:
- `apex-ui/src/pages/ScanBuilder.jsx`
- `common/dashboard/server.py`
- `webforge/webforge.py`
- `netforge/netforge.py`

Preferred fix:
- Create a backend mapping table from UI module IDs to framework module names.
- Pass `--modules` to framework subprocesses.
- Split requested modules by framework.
- Reject unsupported module IDs with a clear API error instead of silently ignoring them.
- Keep category labels in UI, but store real module metadata from `/api/v1/plugins` when possible.

Acceptance criteria:
- Selecting only XSS runs only `xss_scanner` plus required prereq modules if explicitly configured.
- Selecting only network port scan runs `port_scanner`.
- Unsupported cloud/mobile module IDs return `400` with a message like `module not implemented`.
- Scan history records requested modules and actual launched modules.

Validation:
```bash
python -m pytest tests/test_integration.py -q
curl -k -X POST https://127.0.0.1:1337/api/v1/scans/launch -d '{"target":"https://example.com","modules":["xss"],"mode":"blackbox"}' -H 'Content-Type: application/json'
```

## P1: Make The Dashboard A Real Control Plane

### P1.1 Replace in-memory subprocess tracking with durable jobs

Problem:
- Dashboard tracks active scans in `_active_scans`.
- Restart loses state.
- Status is based on process polling only.
- stdout/stderr are piped but not consumed, which can eventually block noisy scans.

Likely files:
- `common/dashboard/server.py`
- `common/db.py`
- New: `common/dashboard/jobs.py`
- New migration/table in SQLite

Preferred fix:
- Add a `scan_jobs` table with:
  - `id`
  - `status`
  - `target`
  - `frameworks`
  - `requested_modules`
  - `actual_modules`
  - `mode`
  - `created_by`
  - `created_at`
  - `started_at`
  - `ended_at`
  - `pid`
  - `return_code`
  - `results_dir`
  - `stdout_log`
  - `stderr_log`
  - `error`
- Stream child output to log files asynchronously.
- Expose job detail endpoint:
  - `GET /api/v1/scans/{scan_id}`
  - `GET /api/v1/scans/{scan_id}/logs`

Acceptance criteria:
- Dashboard restart can show previous jobs.
- Long-running scan output cannot deadlock the subprocess.
- Failed subprocesses show a failure reason and log path.
- Scan history uses durable job data, not only JSON history.

Validation:
```bash
python -m pytest tests/test_integration.py -q
python forge.py dashboard --no-auth
```

### P1.2 Implement real pause/resume/abort controls

Problem:
- Dashboard emits pause/resume events, but framework subprocesses do not consume them as commands.
- Current `ScanControl` exists inside each process but dashboard cannot set it remotely.

Likely files:
- `common/dashboard/server.py`
- `common/dashboard/event_bus.py`
- `webforge/webforge.py`
- `netforge/netforge.py`
- `adforge/adforge.py`
- `aiforge/aiforge.py`

Preferred fix:
- Add a control channel each running scanner polls:
  - API polling: `GET /api/v1/scans/{id}/control`
  - Or local control file in the job results directory.
- Scanner loops check the control state before and after modules.
- Abort should terminate cleanly after current request/module if possible.
- Dashboard `stop` should target a specific scan ID, not all scans by default.

Acceptance criteria:
- Pause stops starting new modules.
- Resume continues.
- Abort marks job `aborted` and stops cleanly.
- Kill/terminate is a fallback after timeout only.

Validation:
```bash
python -m pytest tests/test_integration.py -q
```

### P1.3 Replace simulated finding retest

Problem:
- `POST /api/v1/findings/{id}/retest` returns random values.
- This is unacceptable for enterprise remediation workflows.

Likely files:
- `common/dashboard/server.py`
- `common/db.py`
- Scanner modules that created the finding

Preferred fix:
- Persist enough finding metadata to rerun the producing module:
  - module
  - target/url
  - parameter/field
  - original payload class
  - auth/session context reference
- Add a retest job type.
- Re-run only the relevant module/test path where possible.
- Store retest records:
  - `finding_id`
  - `status`
  - `still_vulnerable`
  - `confidence`
  - `evidence`
  - `retested_at`

Acceptance criteria:
- Retest is deterministic against a local vulnerable fixture.
- No random confidence or vulnerability status remains.
- UI shows retest history.

Validation:
```bash
grep -RIn "random.choice" common/dashboard webforge netforge adforge aiforge --include='*.py'
python -m pytest tests/test_integration.py -q
```

## P2: Enterprise Auth, RBAC, Audit, And Secret Handling

### P2.1 Remove production default admin behavior

Problem:
- Dashboard default credentials are `operator / forge2026`.
- Passwords use unsalted SHA256.
- User store is in-memory/static.

Likely files:
- `common/dashboard/auth.py`
- `common/db.py`
- `install.sh`
- `docker-compose.yml`

Preferred fix:
- Require `FORGE_DASHBOARD_PASSWORD` or first-run admin creation for production mode.
- Use Argon2 or bcrypt for password hashing.
- Store users in DB.
- Add lockout/rate-limit for login.
- Add session revocation.

Acceptance criteria:
- Starting dashboard in auth mode without configured admin secret fails closed or enters first-run setup.
- Password hashes are not raw SHA256.
- Auth tests cover bad password, lockout, expiry, revocation.

Validation:
```bash
python -m pytest tests/test_credential_security.py -q
python -m pytest tests/test_core.py -q
```

### P2.2 Add audit log for operator actions

Problem:
- Enterprise users need accountability.
- Scan launch, stop, retest, status changes, template changes, credential access, and C2 operations must be auditable.

Likely files:
- `common/db.py`
- `common/dashboard/server.py`
- New: `common/dashboard/audit.py`
- `apex-ui/src/pages/ActivityLogs.jsx`

Preferred fix:
- Add audit log table and helper.
- Log operator, role, source IP, action, object ID, timestamp, and result.
- Never log secrets.

Acceptance criteria:
- Activity Logs page reads real audit data.
- Every mutating API route records success/failure.
- Tests assert secrets are redacted.

## P3: Scanner Accuracy And False Positive Reduction

### P3.1 Finish known bugs in docs/REVIEW_STATUS.md

Known remaining bugs from local review doc:
- `adforge/modules/acl_abuse/acl_scanner.py`: parses binary security descriptor incorrectly.
- `adforge/modules/attacks/asrep_roast.py`: AS-REP hash format and noisy targeting.
- `webforge/modules/injection/xss_scanner.py`: verify POST form coverage is complete and tested.
- `netforge/modules/discovery/port_scanner.py`: verify WinRM/host cap fixes remain tested.

Note:
- Some fixes appear partially applied in the current filesystem. Do not assume complete; add tests.

Acceptance criteria:
- Each bug has a regression test.
- AD security descriptor parser handles real ldap3 raw byte shape.
- AS-REP roast targets only no-preauth accounts and emits hashcat-compatible output.
- XSS POST form scanner has deterministic unit/integration coverage.
- Port scanner host limit and WinRM ports have tests.

Validation:
```bash
python -m pytest tests/test_core.py tests/test_integration.py -q
```

### P3.2 Authenticated web scanning must become first-class

Problem:
- Enterprise web scanners win because they can crawl authenticated apps, SPAs, APIs, and workflows.
- Browser rendering exists but is optional and not central enough.

Likely files:
- `webforge/core/browser_engine.py`
- `webforge/core/auth_recorder.py`
- `webforge/core/session.py`
- `webforge/core/scan_profile.py`
- `webforge/modules/recon/link_crawler.py`
- `webforge/modules/recon/param_discover.py`
- `webforge/modules/api/schema_import.py`

Preferred fix:
- Make Playwright crawler a standard phase for greybox/whitebox web scans.
- Capture:
  - routes
  - forms
  - XHR/fetch endpoints
  - GraphQL endpoints
  - OpenAPI links
  - auth/session health indicators
- Feed discovered forms/endpoints into injection/access-control/API modules.
- Add session refresh after expiry.

Acceptance criteria:
- A local test app with login has authenticated-only endpoints discovered.
- Forms discovered by browser are used by SQLi/XSS/CMDi/SSRF modules.
- Session expiration is detected and refreshed.

### P3.3 Build deterministic vulnerable fixtures

Problem:
- Scanner confidence cannot improve without known-good targets.

Preferred fix:
- Add local fixtures for:
  - reflected GET XSS
  - reflected POST XSS
  - SQLi error/time boolean
  - LFI
  - SSRF callback
  - IDOR
  - weak JWT
  - authenticated-only form
- Run modules against fixtures in CI.

Acceptance criteria:
- Tests assert expected findings and expected non-findings.
- False positive reducer is tested on negative controls.

## P4: Reporting And Remediation Workflow

### P4.1 Persist finding state changes

Problem:
- Dashboard status patch updates `StateStore` only.
- It does not durably update the finding DB.

Likely files:
- `common/dashboard/server.py`
- `common/db.py`
- `apex-ui/src/pages/Vulnerabilities.jsx`

Preferred fix:
- Update DB row and emit `finding_updated`.
- Normalize statuses across backend/frontend:
  - `open`
  - `verified`
  - `fixed`
  - `accepted_risk`
  - `false_positive`
- Avoid mixed `Open` vs `open` values.

Acceptance criteria:
- Status survives dashboard restart.
- Report export reflects latest status.

### P4.2 Enterprise report quality

Problem:
- Current reporting exists but is not yet a Nessus/Acunetix-class remediation workflow.

Preferred fix:
- Add report sections:
  - Executive summary
  - Scope and methodology
  - Risk trend
  - Top exploitable paths
  - Findings with evidence
  - Retest history
  - Compliance mapping
  - Asset inventory
  - Appendix raw evidence
- Add client-ready PDF styling and stable JSON schema.

Acceptance criteria:
- One scan produces HTML, PDF, JSON, and CSV consistently.
- JSON schema is versioned.
- Report includes dashboard-updated statuses.

## P5: C2 And Red-Team Product Boundary

Important:
- Keep this platform strictly for authorized operations.
- Do not prioritize stealth/evasion payload sophistication before auth, audit, job control, and operator safeguards are enterprise-grade.

### P5.1 Fix C2 CLI consistency

Problem:
- `forge.py c2 payload ...` says payload generation is unavailable.
- `forge_payload/` exists.
- `forge.py payload ...` is gated separately.

Likely files:
- `forge.py`
- `forge_payload/payload_factory.py`
- `forge_c2/server.py`

Preferred fix:
- Decide one supported payload command path.
- If payload generation is allowed only with `--red-team`, make both CLI paths enforce the same policy.
- Remove stale "not yet available" messages once wired.
- Add audit event for payload generation.

Acceptance criteria:
- CLI help and behavior match actual functionality.
- Unauthorized/non-red-team usage fails closed with a clear message.
- Red-team payload generation creates expected output and records metadata.

Validation:
```bash
python forge.py payload --help
python forge.py c2 payload --help
```

### P5.2 C2 enterprise controls before capability expansion

Required controls before claiming Cobalt Strike-class:
- Multi-operator RBAC backed by DB.
- Listener lifecycle from dashboard.
- Beacon/task audit trail.
- Per-engagement scoping.
- Kill switch and expiration.
- Operator approval gates for sensitive tasks.
- Exportable activity timeline.

Acceptance criteria:
- Dashboard can list listeners and sessions from real backend state.
- Every task has operator, timestamp, target, and result.
- Engagement archive can be replayed.

## P6: Cloud And Mobile Reality Check

Problem:
- UI lists cloud modules, but backend implementation is not comparable to enterprise cloud security products.
- Mobile pentest page exists, but mobile scanning is not implemented as a real framework.

Preferred fix:
- Either hide unsupported cloud/mobile launch options or mark them as "planned".
- Add actual cloud framework only when credentials, providers, and permissions model are designed:
  - AWS IAM/S3/EC2/EKS/RDS/security groups
  - Azure Entra/storage/VM/AKS
  - GCP IAM/storage/GKE
- Add mobile framework only with real APK/IPA static analysis and dynamic test plan.

Acceptance criteria:
- Dashboard does not imply unsupported scans can run.
- Unsupported module IDs cannot silently launch unrelated web scans.

## P7: CI, Packaging, And Release Discipline

### P7.1 Fix test reliability

Observed:
- `python -m pytest tests/test_core.py -q`: passed, 32 tests.
- Full `python -m pytest -q`: hung after partial progress and was interrupted.
- `npm run build`: passed.
- `npm test -- --run`: failed because `vitest` was not found.

Preferred fix:
- Identify hanging Python test with:
```bash
python -m pytest -q -vv --maxfail=1
```
- Add timeouts for network/browser tests.
- Separate unit, integration, and live-network test markers.
- Fix frontend dependency install or package lock mismatch.

Acceptance criteria:
- `make test` completes locally without hanging.
- CI runs unit tests on every PR.
- Live-network tests are opt-in.

### P7.2 Packaging

Preferred fix:
- Add `.env.example`.
- Add production Docker compose with persistent volumes.
- Add health checks.
- Add DB migration command.
- Add versioned config schema validation.

Acceptance criteria:
- Fresh clone can run dashboard and a blackbox test scan with documented commands.
- No default production secret is accepted silently.

## Suggested Agent Work Sequence

1. P0.1 dashboard authenticated scan compatibility.
2. P0.2 module ID mapping and real `--modules` launch.
3. P4.1 finding status persistence.
4. P1.1 durable scan jobs and subprocess log draining.
5. P1.3 real retest job replacing random simulation.
6. P2.1 auth hardening.
7. P7.1 full test suite reliability.
8. P3.1 known scanner bug regression tests and fixes.
9. P3.2 authenticated browser crawler as standard greybox flow.
10. P5.1 C2/payload CLI consistency and audit gates.

## Definition Of "Enterprise-Grade" For This Project

Do not call Forge Suite enterprise-grade until all of these are true:

- Dashboard launches blackbox and authenticated scans reliably.
- Jobs survive dashboard restart.
- Findings, status changes, retests, reports, and audit logs are durable.
- Default credentials are not accepted in production.
- Scanner module selections map to real modules.
- Full unit test suite completes deterministically.
- Reports are client-ready.
- Unsupported cloud/mobile/C2 features are hidden, clearly marked planned, or fully implemented.
- Sensitive red-team actions require explicit authorization, scope, and auditability.
