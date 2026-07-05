# Sprint 5 — CI/CD & Supply Chain Attack Modules

## Goal
CI/CD pipeline attack surface coverage.

## New Directory
`forge_suite/cicd/`

## Modules to Build

1. **`pipeline_poisoner.py`** — Detect and model CI/CD config injection vectors:
   - Jenkinsfile (Groovy sandbox escape, shared library injection)
   - `.gitlab-ci.yml` (script injection via merge request variables)
   - GitHub Actions (workflow_run, pull_request_target, expression injection)
   - Azure DevOps (pipeline YAML variable injection)

2. **`dep_confusion_tester.py`** — Test if private package names resolve to public registries:
   - npm: check npmjs.com for org's private package names
   - PyPI: check pypi.org for internal package names
   - Gems: check rubygems.org
   - Report if public package would take priority

3. **`runner_abuse.py`** — Self-hosted CI runner exploitation:
   - Extract runner registration tokens from CI configs
   - Register rogue runner to receive jobs
   - Demonstrate host-level access from runner context

4. **`artifact_backdoor.py`** — Model artifact tampering in registries:
   - Detect writable container registries
   - Detect writable npm/PyPI/Maven registries
   - Model build artifact modification during pipeline

5. **`code_review_poisoner.py`** — Insider threat simulation:
   - Generate subtle backdoor PRs (typosquatting, logic bugs)
   - Detection validation: can code review catch it?

## Chain Integration

| Chain | Trigger → Next |
|-------|---------------|
| CI/CD Config Leak → Pipeline Inject → Prod Backdoor | `cicd_config_leak` → `pipeline_inject` → `production_deploy` |
| Dependency Confusion → Build RCE | `dep_confusion_pkg` → `malicious_package_resolve` → `build_server_rce` |
| Runner Token → Runner Register → Job Inject | `runner_token_extract` → `runner_register` → `job_inject` |

## Acceptance Criteria

- [ ] pipeline_poisoner detects injection vectors in all 4 CI platforms
- [ ] dep_confusion_tester validates at least npm and PyPI
- [ ] runner_abuse demonstrates token extraction → registration flow
- [ ] CI/CD chains integrated into ChainEngine
