# Sprint 1 — Cloud & Container Attack Modules

## Goal
Cloud/container attack surface coverage. AWS, Azure, GCP, K8s.

## New Directory
`forge_suite/cloud/`

## Modules to Build

1. **`cloud_api_scanner.py`** — Enumerate AWS/Azure/GCP metadata APIs (169.254.169.254), KMS, Secrets Manager, S3/Storage/DNS configurations.
2. **`cloud_iam_chaining.py`** — From stolen cloud creds → enumerate roles → assume role → escalate IAM permissions.
3. **`container_escape.py`** — Detect and exploit: cgroup escape, mount namespace escape, SYS_PTRACE, /proc/1/root traversal.
4. **`k8s_attack.py`** — kubelet unauthenticated API, etcd direct access, RBAC misconfiguration abuse, pod exec, service account token theft.
5. **`tf_state_poisoner.py`** — Detect exposed Terraform state files, parse for secrets, model state modification for backdoor injection.
6. **`serverless_inject.py`** — Lambda/Azure Functions event injection, environment variable extraction, function code manipulation.

## Chain Integration

| Chain | Trigger → Next |
|-------|---------------|
| SSRF → Cloud Metadata → IAM Pivot | `ssrf` → `cloud_metadata` → `iam_escalation` |
| Container Escape → Host → Cloud Creds | `container_escape` → `host_shell` → `cloud_metadata_exfil` |
| K8s Pod → Service Account → Cluster Admin | `kubectl_pod_exec` → `sa_token_exfil` → `k8s_admin` |

## Dependencies
- Existing `netforge/modules/vuln/` CVE modules (k8s_audit, etcd_audit already exist)
- `common/attack_chains.py` ChainEngine

## Acceptance Criteria

- [ ] cloud_api_scanner detects metadata API access from SSRF-able targets
- [ ] IAM chaining demonstrates privilege escalation path in findings
- [ ] container_escape produces proof-of-concept evidence
- [ ] K8s attack chain fires when pod access is confirmed
- [ ] All modules follow base_module interface
