# Forge Suite Enterprise Roadmap

Updated: 2026-06-22

Purpose: management-facing roadmap for taking Forge Suite from alpha prototype to enterprise release. This roadmap intentionally prioritizes stabilization over new feature expansion.

## Strategic Direction

Forge Suite should not add more major feature areas yet. The current priority is to make the existing dashboard-driven VAPT workflow reliable, secure, testable, and reportable.

First enterprise milestone:

```text
Dashboard -> Target/Auth -> Module Selection -> Scan Job -> Live Status/Logs -> Findings -> Retest -> Report -> Audit Trail
```

Cloud, mobile, and expanded C2/red-team capability should remain expansion tracks until the core workflow above is stable.

## Release Roadmap

| Phase | Timeline | Release Type | Primary Goal | Exit Criteria |
| --- | ---: | --- | --- | --- |
| Phase 0 | Weeks 1-3 | Engineering stabilization | Fix current critical breakages. | Dashboard authenticated scans launch successfully; ScanBuilder modules map to real modules; C2/payload CLI messaging is consistent; core tests complete without hanging. |
| Phase 1 | Month 1-2 | Internal Alpha | Make dashboard-driven scans usable for internal operators on controlled targets. | Durable scan jobs; scan logs visible; scan status survives restart; findings persist; reports export; default production credentials removed or blocked. |
| Phase 2 | Month 3-4 | Internal Beta | Reliable authenticated web/network/AD VAPT workflow with basic remediation lifecycle. | Authenticated crawler works; real retest replaces simulated retest; finding status persists; RBAC and audit logs exist; false-positive reduction improved; vulnerable test lab passes. |
| Phase 3 | Month 5-6 | Private External Pilot | Validate product value with trusted users under strict authorization and limited scope. | Signed authorization workflow; safe scan profiles; clean reports; supportable install; issue feedback loop; pilot findings triaged. |
| Phase 4 | Month 7-9 | External Beta | Limited commercial beta as a unified VAPT dashboard. | Multi-user RBAC; durable job queue; audit trail; credentialed checks; stable web/API/network scan path; deployment docs; known limitations documented. |
| Phase 5 | Month 10-12+ | v1 Enterprise Release | Production-ready enterprise VAPT platform for tested scopes. | SSO-ready auth; hardened deployment; compliance-ready reports; stable update process; regression suite; support process; release notes and admin docs. |
| Phase 6 | 12-24 months | Expanded Platform | Add serious cloud, mobile, AI, and authorized red-team workflows. | Real cloud provider checks; APK/IPA pipeline; AI scoring harness; controlled C2 campaign workflow; full auditability. |

## Positioning By Release

| Stage | Recommended Label | What To Claim | What Not To Claim |
| --- | --- | --- | --- |
| Current | Engineering Prototype / Alpha | Broad prototype with unified offensive security direction. | Do not call it enterprise-grade. Do not claim Nessus/Acunetix/Cobalt Strike parity. |
| Internal Alpha | Internal VAPT Alpha | Dashboard-driven scans are being stabilized. | Do not expose to customers. |
| Internal Beta | Internal VAPT Beta | Internal operators can run controlled assessments and generate reports. | Do not sell as a full replacement platform. |
| Private Pilot | Private Enterprise Pilot | Trusted external validation under written authorization. | Do not promise broad cloud/mobile/C2 coverage. |
| External Beta | Limited Enterprise Beta | Unified VAPT dashboard for selected web/network/AD use cases. | Do not claim mature coverage for untested modules. |
| v1 Enterprise | Enterprise VAPT Platform | Production-ready for validated web/network/AD workflows. | Do not overstate unsupported expansion tracks. |

## Immediate No-New-Feature Rule

Until Phase 1 exit criteria are met, avoid adding:

- New cloud modules.
- New mobile modules.
- New exploit modules.
- New C2 evasion features.
- New dashboard pages.
- New AI prompt packs.

Allowed work during stabilization:

- Fix broken launch paths.
- Improve persistence.
- Improve tests.
- Improve authentication and auditability.
- Improve existing scanner accuracy.
- Improve report correctness.
- Replace simulated behavior with real behavior.
- Hide or clearly mark unsupported UI features.

## Phase 0 Detailed Objectives

| Objective | Owner Area | Success Signal |
| --- | --- | --- |
| Fix dashboard authenticated WebForge launch. | Dashboard + WebForge | Greybox/form/bearer/cookie scans no longer fail on CLI args. |
| Map ScanBuilder module IDs to real modules. | Dashboard + UI | Selecting XSS runs `xss_scanner`; selecting port scan runs `port_scanner`; unsupported IDs return clear errors. |
| Stabilize tests. | QA/CI | `make test` or documented unit suite completes without hanging. |
| Fix frontend test dependency. | UI | `npm test` runs successfully. |
| Replace misleading C2 payload messaging. | CLI/C2 | CLI help and behavior match actual supported payload paths and authorization gates. |
| Persist finding status changes. | Dashboard + DB | Status survives dashboard restart and appears in reports. |

## Phase 1 Detailed Objectives

| Objective | Owner Area | Success Signal |
| --- | --- | --- |
| Durable scan job model. | Dashboard + DB | Scan jobs survive dashboard restart. |
| Scan log capture. | Dashboard | stdout/stderr are saved and viewable per job. |
| Per-scan status endpoint. | API | Operators can view running/completed/failed job details. |
| Production auth baseline. | Security | No default admin password accepted silently in production mode. |
| Basic audit trail. | Security + Dashboard | Scan launch, stop, template changes, status updates are logged. |
| Report export reliability. | Reporting | HTML/JSON/PDF export works for successful scans. |

## Phase 2 Detailed Objectives

| Objective | Owner Area | Success Signal |
| --- | --- | --- |
| Browser-authenticated crawler as standard greybox path. | WebForge | Auth-only routes and forms are discovered in a local test app. |
| Real retest workflow. | Dashboard + Scanners | Retest reruns relevant scanner logic instead of random simulation. |
| Vulnerable fixture lab. | QA/Scanners | Known vulnerable targets produce expected findings and negative controls stay clean. |
| AD bug regression fixes. | ADForge | Known ACL/AS-REP issues have tests and fixes. |
| False-positive reduction. | WebForge/Common | SQLi/XSS/SSTI/LFI/CMDi findings include confidence/evidence. |

## Management Milestones

| Date Target | Milestone | Management Decision |
| --- | --- | --- |
| End of Week 3 | Stabilization review | Decide whether internal alpha can start. |
| End of Month 2 | Internal alpha review | Decide whether selected internal operators can use it. |
| End of Month 4 | Internal beta review | Decide whether private external pilots are safe. |
| End of Month 6 | Pilot review | Decide whether to open limited external beta. |
| End of Month 9 | External beta review | Decide whether v1 enterprise release criteria are realistic. |
| Month 10-12+ | v1 release review | Release only for validated scopes. |

## Realistic Timeline

| Target | Solo Full-Time | Small Team |
| --- | ---: | ---: |
| Critical breakages fixed | 1-3 weeks | 3-7 days |
| Credible internal alpha | 1-2 months | 3-6 weeks |
| Strong internal beta | 3-4 months | 2-3 months |
| Private pilot | 5-6 months | 3-4 months |
| External beta | 7-9 months | 5-6 months |
| v1 enterprise release | 10-12+ months | 6-9 months |
| Mature competitor to Nessus + Acunetix + Cobalt Strike combined | 24-36+ months | 18-24 months |

## Roadmap Principle

Do not measure progress by module count. Measure progress by trust:

- Can operators launch scans from the dashboard reliably?
- Can users prove what was tested?
- Can findings be reproduced and retested?
- Can management trust the report?
- Can admins trust the platform security?
- Can support debug failures from logs and job state?

When those answers are consistently yes, Forge Suite is ready to move from internal use toward external release.
