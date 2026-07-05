"""Cloud & Container Attack Modules — Sprint 1.

Covers the full cloud attack surface across AWS, Azure/Entra ID, GCP,
Kubernetes, serverless functions, and Terraform infrastructure-as-code.

Modules
-------
cloud_api_scanner
    Enumerate AWS/GCP/Azure instance metadata APIs (IMDS v1/v2, 169.254.169.254).
    Extracts IAM role credentials, KMS listings, Secrets Manager values,
    storage bucket configs, and VPC metadata from SSRF-able targets.

cloud_iam_chaining
    From stolen cloud credentials, enumerate IAM roles/policies and chain
    privilege escalation paths (iam:PassRole, sts:AssumeRole, iam:PutRolePolicy,
    GCP impersonation). Maps permission boundaries and trust policies.

container_escape
    Detect and document container breakout vectors: privileged flag,
    cgroup v1 release_agent, /proc/1/root mount namespace traversal,
    Docker socket abuse, SYS_PTRACE, OverlayFS, and kernel exploit paths
    (Dirty Pipe, Dirty COW).

k8s_attack
    Kubernetes attack surface: unauthenticated kubelet API (:10250/:10255),
    etcd direct access, RBAC misconfiguration (wildcard verbs, cluster-admin
    bindings), pod exec lateral movement, service account token theft,
    and namespace escape via hostPID/hostNetwork pods.

serverless_inject
    AWS Lambda / Azure Functions / GCP Cloud Functions event injection.
    Abuses API Gateway, S3/SNS/SQS triggers, and HTTP bindings to inject
    malicious event payloads; extracts environment variables (secrets,
    connection strings) and models layer/dependency poisoning vectors.

tf_state_poisoner
    Detect exposed Terraform state files (.tfstate) on HTTP endpoints,
    S3/GCS/Azure Blob with misconfigured ACLs. Extracts secrets (passwords,
    tokens, connection strings) and maps infrastructure for backdoor vectors.

MITRE ATT&CK Cloud TTPs
-----------------------
T1078.004  Valid Cloud Accounts
T1530      Data from Cloud Storage
T1619      Cloud Storage Object Discovery
T1552.005  Cloud Instance Metadata API (IMDS)
T1098.001  Additional Cloud Credentials
T1611      Escape to Host (container escape)

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

__all__ = [
    # Cloud metadata & credential extraction
    "CloudApiScanner",
    # IAM privilege escalation chaining
    "CloudIamChaining",
    "EscalationPath",
    # Container breakout
    "ContainerEscape",
    # Kubernetes attack surface
    "K8sAttack",
    # Serverless event injection
    "ServerlessInject",
    # Terraform state exposure & secret extraction
    "TfStatePoisoner",
]
