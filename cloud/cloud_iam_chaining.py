"""Cloud IAM Privilege Escalation Chain Detection — AWS / GCP / Azure.

Analyzes IAM policies and live credentials to detect privilege escalation paths.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.

MITRE ATT&CK:
    T1078.004  Valid Cloud Accounts
    T1098.001  Additional Cloud Credentials
    T1484      Domain Policy Modification (cloud IAM analog)
"""
from __future__ import annotations

import json
import logging
import re
import unittest
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("forge.cloud.iam_chaining")

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EscalationPath:
    provider: str            # "AWS", "GCP", "AZURE"
    start_principal: str
    target_permission: str   # what you gain
    chain: list[str]         # sequence of IAM actions
    description: str
    risk: str                # "CRITICAL", "HIGH", "MEDIUM"
    mitre_ttp: str
    remediation: str
    cvss: str = ""

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "start_principal": self.start_principal,
            "target_permission": self.target_permission,
            "chain": self.chain,
            "description": self.description,
            "risk": self.risk,
            "mitre_ttp": self.mitre_ttp,
            "remediation": self.remediation,
            "cvss": self.cvss,
        }


# ---------------------------------------------------------------------------
# AWS escalation path definitions
# ---------------------------------------------------------------------------

AWS_ESCALATION_PATHS: list[dict] = [
    {
        "id": "aws_iam_create_policy_version",
        "required_perms": ["iam:CreatePolicyVersion"],
        "chain": ["iam:CreatePolicyVersion → attach new version with *:*"],
        "target": "Administrator Access",
        "risk": "CRITICAL",
        "description": (
            "With iam:CreatePolicyVersion, an attacker can create a new version of an existing "
            "managed policy containing `Action: *` and `Resource: *`, effectively granting "
            "full admin access to any principal with that policy attached."
        ),
        "mitre_ttp": "T1098.001",
        "remediation": "Remove iam:CreatePolicyVersion or restrict with conditions (e.g., only allow on specific policy ARNs via Conditions).",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    },
    {
        "id": "aws_iam_attach_role_policy",
        "required_perms": ["iam:AttachRolePolicy"],
        "chain": ["iam:AttachRolePolicy → attach arn:aws:iam::aws:policy/AdministratorAccess to target role"],
        "target": "AdministratorAccess",
        "risk": "CRITICAL",
        "description": (
            "With iam:AttachRolePolicy, the attacker can attach the AWS managed AdministratorAccess "
            "policy to any IAM role, granting full admin to that role and anyone who can assume it."
        ),
        "mitre_ttp": "T1098.001",
        "remediation": "Remove iam:AttachRolePolicy or restrict via IAM permission boundaries.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    },
    {
        "id": "aws_passrole_ec2",
        "required_perms": ["iam:PassRole", "ec2:RunInstances"],
        "chain": [
            "iam:PassRole → pass admin IAM role",
            "ec2:RunInstances → launch EC2 instance with admin profile",
            "retrieve IAM credentials from instance metadata",
        ],
        "target": "EC2 Role Credential Theft",
        "risk": "HIGH",
        "description": (
            "iam:PassRole + ec2:RunInstances allows launching an EC2 instance with an attached "
            "IAM instance profile. The attacker can retrieve credentials from IMDS and use the "
            "role's permissions directly."
        ),
        "mitre_ttp": "T1552.005",
        "remediation": "Apply iam:PassRole with Condition iam:PassedToService restriction. Use resource-based conditions.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    },
    {
        "id": "aws_passrole_lambda",
        "required_perms": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "chain": [
            "iam:PassRole → pass admin role to Lambda",
            "lambda:CreateFunction → create function with admin execution role",
            "lambda:InvokeFunction → execute function to exfiltrate credentials",
        ],
        "target": "Lambda Admin Role Abuse",
        "risk": "HIGH",
        "description": (
            "Create a Lambda function with an admin execution role. When invoked, the function "
            "runs with admin privileges — allowing secret exfiltration, resource creation, etc."
        ),
        "mitre_ttp": "T1059.007",
        "remediation": "Restrict lambda:CreateFunction with iam:PassedToService conditions. Enforce Lambda execution role boundaries.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    },
    {
        "id": "aws_sts_assume_role",
        "required_perms": ["sts:AssumeRole"],
        "chain": ["sts:AssumeRole → assume target role with overly permissive trust policy"],
        "target": "Lateral Movement via Role Assumption",
        "risk": "HIGH",
        "description": (
            "If a role's trust policy allows assumption from too-broad principals (e.g., any "
            "authenticated AWS entity, or a specific account without ExternalId), an attacker "
            "with sts:AssumeRole can pivot to that role."
        ),
        "mitre_ttp": "T1078.004",
        "remediation": "Use ExternalId conditions in trust policies. Restrict Principal to specific, necessary ARNs.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    },
    {
        "id": "aws_secretsmanager_get",
        "required_perms": ["secretsmanager:GetSecretValue"],
        "chain": ["secretsmanager:GetSecretValue → extract secrets from Secrets Manager"],
        "target": "Secret Extraction",
        "risk": "HIGH",
        "description": (
            "Access to secretsmanager:GetSecretValue allows extracting all secrets stored in "
            "AWS Secrets Manager, including database passwords, API keys, and TLS certificates."
        ),
        "mitre_ttp": "T1552.001",
        "remediation": "Restrict secretsmanager:GetSecretValue to specific secret ARNs. Enable resource-based policies. Rotate secrets regularly.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "id": "aws_s3_sensitive_buckets",
        "required_perms": ["s3:GetObject"],
        "chain": ["s3:GetObject → read sensitive data from S3 buckets"],
        "target": "Data Exfiltration from S3",
        "risk": "HIGH",
        "description": (
            "Overly broad s3:GetObject permissions allow exfiltrating data from any S3 bucket, "
            "including terraform state files, backups, config files, and application data."
        ),
        "mitre_ttp": "T1530",
        "remediation": "Restrict s3:GetObject with Resource conditions to specific bucket ARNs. Enable S3 access logging.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "id": "aws_lambda_update_code",
        "required_perms": ["lambda:UpdateFunctionCode"],
        "chain": [
            "lambda:UpdateFunctionCode → inject malicious code into existing Lambda",
            "Lambda executes with original execution role (potentially admin)",
        ],
        "target": "Lambda Code Injection → RCE",
        "risk": "HIGH",
        "description": (
            "lambda:UpdateFunctionCode allows replacing the code of an existing Lambda function. "
            "If the Lambda has elevated permissions, this constitutes RCE with those permissions."
        ),
        "mitre_ttp": "T1059.007",
        "remediation": "Restrict lambda:UpdateFunctionCode to CI/CD service accounts only. Enable Lambda code signing.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L",
    },
    {
        "id": "aws_ssm_send_command",
        "required_perms": ["ssm:SendCommand"],
        "chain": [
            "ssm:SendCommand → send shell command to EC2 instance via SSM Agent",
            "execute with instance profile permissions (potentially admin)",
        ],
        "target": "RCE via Systems Manager",
        "risk": "CRITICAL",
        "description": (
            "ssm:SendCommand allows running arbitrary OS commands on any EC2 instance with the "
            "SSM agent installed. If the instance profile is admin-level, this yields full RCE "
            "with cloud admin privileges."
        ),
        "mitre_ttp": "T1059.004",
        "remediation": "Restrict ssm:SendCommand with Resource conditions on specific instance IDs and tags. Use SSM Session Manager with MFA.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    },
    {
        "id": "aws_cloudformation_passrole",
        "required_perms": ["cloudformation:CreateStack", "iam:PassRole"],
        "chain": [
            "cloudformation:CreateStack → create stack with admin service role",
            "iam:PassRole → pass admin role to CloudFormation",
            "Stack creates IAM resources with admin permissions",
        ],
        "target": "IaC-Based Privilege Escalation",
        "risk": "CRITICAL",
        "description": (
            "With cloudformation:CreateStack + iam:PassRole, an attacker can deploy a CloudFormation "
            "template that creates IAM users/roles/policies with AdministratorAccess, using the "
            "passed role's permissions."
        ),
        "mitre_ttp": "T1098.001",
        "remediation": "Restrict iam:PassRole for cloudformation.amazonaws.com. Use CloudFormation stack policies. Enforce SCPs.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    },
]

# ---------------------------------------------------------------------------
# GCP escalation path definitions
# ---------------------------------------------------------------------------

GCP_ESCALATION_PATHS: list[dict] = [
    {
        "id": "gcp_sa_act_as",
        "required_perms": ["iam.serviceAccounts.actAs"],
        "chain": ["iam.serviceAccounts.actAs → impersonate admin service account"],
        "target": "Service Account Impersonation",
        "risk": "CRITICAL",
        "description": (
            "The iam.serviceAccounts.actAs permission allows impersonating any service account. "
            "If the target SA has project owner/editor or sensitive roles, this yields full project control."
        ),
        "mitre_ttp": "T1078.004",
        "remediation": "Grant iam.serviceAccounts.actAs only for specific SA resources. Audit SA impersonation logs in Cloud Audit Logs.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    },
    {
        "id": "gcp_compute_set_sa",
        "required_perms": ["compute.instances.setServiceAccount"],
        "chain": [
            "compute.instances.setServiceAccount → attach admin SA to running VM",
            "SSH into VM → retrieve admin SA token from metadata server",
        ],
        "target": "Admin Service Account via Compute",
        "risk": "HIGH",
        "description": (
            "With compute.instances.setServiceAccount, an attacker can attach an admin-level "
            "service account to an existing VM they have SSH access to, then retrieve the token "
            "from the GCP metadata service."
        ),
        "mitre_ttp": "T1552.005",
        "remediation": "Use Organization Policy constraints/compute.disableServiceAccountActAs. Restrict setServiceAccount with IAM conditions.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    },
    {
        "id": "gcp_gcs_sensitive",
        "required_perms": ["storage.objects.get"],
        "chain": ["storage.objects.get → read sensitive objects from GCS buckets"],
        "target": "Data Exfiltration from GCS",
        "risk": "HIGH",
        "description": (
            "Overly broad storage.objects.get allows reading all objects in GCS, "
            "including terraform state files, backups, and application secrets."
        ),
        "mitre_ttp": "T1530",
        "remediation": "Restrict storage.objects.get to specific buckets via IAM conditions. Enable GCS audit logging.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "id": "gcp_cloudfunctions_update",
        "required_perms": ["cloudfunctions.functions.update", "iam.serviceAccounts.actAs"],
        "chain": [
            "cloudfunctions.functions.update → inject malicious code into existing Cloud Function",
            "iam.serviceAccounts.actAs → function executes with SA having elevated permissions",
        ],
        "target": "Cloud Function Code Injection → RCE",
        "risk": "HIGH",
        "description": (
            "Updating a Cloud Function's source code with iam.serviceAccounts.actAs allows "
            "injecting arbitrary code that runs with the function's service account permissions."
        ),
        "mitre_ttp": "T1059.007",
        "remediation": "Restrict cloudfunctions.functions.update to CI/CD SAs. Enable binary authorization.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L",
    },
    {
        "id": "gcp_gke_credentials",
        "required_perms": ["container.clusters.getCredentials"],
        "chain": [
            "container.clusters.getCredentials → retrieve GKE cluster kubeconfig",
            "Access Kubernetes API as cluster admin (if default RBAC bindings present)",
        ],
        "target": "GKE Cluster Admin Access",
        "risk": "CRITICAL",
        "description": (
            "container.clusters.getCredentials provides kubeconfig for GKE clusters. Combined "
            "with default legacy RBAC bindings (cluster-admin for GCP IAM users), this yields "
            "full Kubernetes cluster admin access."
        ),
        "mitre_ttp": "T1613",
        "remediation": "Disable legacy RBAC authorization (remove gke-legacy-abac). Use RBAC bindings instead of IAM-based admin. Enable Workload Identity.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    },
]

# ---------------------------------------------------------------------------
# Azure escalation path definitions
# ---------------------------------------------------------------------------

AZURE_ESCALATION_PATHS: list[dict] = [
    {
        "id": "azure_contributor_role_assignment",
        "required_perms": ["Contributor", "Microsoft.Authorization/roleAssignments/write"],
        "chain": [
            "Microsoft.Authorization/roleAssignments/write → assign Owner role to attacker-controlled identity",
            "Full subscription control achieved",
        ],
        "target": "Owner Role Escalation",
        "risk": "CRITICAL",
        "description": (
            "A principal with Contributor + roleAssignments/write (or directly with Owner) can "
            "assign the Owner role to any identity in the subscription, yielding full control."
        ),
        "mitre_ttp": "T1098",
        "remediation": "Remove Microsoft.Authorization/roleAssignments/write from Contributor roles. Use PIM (Privileged Identity Management) for just-in-time access.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    },
    {
        "id": "azure_storage_account_keys",
        "required_perms": ["Microsoft.Storage/storageAccounts/listKeys/action"],
        "chain": [
            "listKeys → retrieve Storage Account access keys",
            "Full read/write/delete access to all storage account contents",
        ],
        "target": "Storage Account Full Access",
        "risk": "HIGH",
        "description": (
            "Retrieving Storage Account keys provides full access equivalent to account owner — "
            "read, write, delete all blobs, queues, tables, and file shares."
        ),
        "mitre_ttp": "T1552.001",
        "remediation": "Disable shared key access at the account level. Use RBAC data plane roles (Storage Blob Data Reader/Contributor) instead of access keys.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
    },
    {
        "id": "azure_vm_run_command",
        "required_perms": ["Microsoft.Compute/virtualMachines/runCommand/action"],
        "chain": [
            "runCommand → execute arbitrary PowerShell/shell on target VM",
            "Runs as SYSTEM/root — full VM compromise",
        ],
        "target": "VM Remote Code Execution",
        "risk": "CRITICAL",
        "description": (
            "The runCommand action allows executing arbitrary scripts on Azure VMs as SYSTEM. "
            "This constitutes full RCE without needing network access to the VM."
        ),
        "mitre_ttp": "T1059.001",
        "remediation": "Remove runCommand from operator roles. Use Just-in-Time VM access. Monitor for runCommand invocations in Activity Log.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    },
    {
        "id": "azure_keyvault_get_secret",
        "required_perms": ["Microsoft.KeyVault/vaults/secrets/read"],
        "chain": [
            "Key Vault secrets/read → retrieve all secrets from Key Vault",
            "Includes database passwords, API keys, certificates, encryption keys",
        ],
        "target": "Secret Extraction from Key Vault",
        "risk": "HIGH",
        "description": (
            "Access to Key Vault secrets/read allows extracting all secrets, keys, and certificates "
            "stored in Azure Key Vault, which often includes database connection strings, "
            "external API credentials, and TLS private keys."
        ),
        "mitre_ttp": "T1552.001",
        "remediation": "Use Key Vault access policies with least privilege. Enable Key Vault firewall and private endpoints. Enable Purge Protection.",
        "cvss": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    },
]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class CloudIamChaining:
    """Detect IAM privilege escalation chains for AWS, GCP, and Azure."""

    def __init__(self):
        self._findings: list[EscalationPath] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, provider: str, credentials: dict) -> dict[str, Any]:
        """Detect escalation paths for the given cloud provider.

        Args:
            provider: "AWS", "GCP", or "AZURE"
            credentials: dict of credential key/values appropriate to the provider
        Returns:
            dict with 'provider', 'escalation_paths', 'critical_count', 'high_count'
        """
        self._findings = []
        provider = provider.upper()
        log.info("IAM chaining scan: provider=%s", provider)

        if provider == "AWS":
            self._findings.extend(self._check_aws_live(credentials))
            # Also do static analysis if policy_json provided
            if "policy_json" in credentials:
                try:
                    policy_doc = json.loads(credentials["policy_json"])
                    self._findings.extend(self._analyze_aws_policy(policy_doc))
                except Exception as exc:
                    log.warning("Policy JSON parse error: %s", exc)

        elif provider == "GCP":
            self._findings.extend(self._check_gcp(credentials))

        elif provider == "AZURE":
            self._findings.extend(self._check_azure(credentials))

        else:
            log.warning("Unknown provider: %s", provider)

        self._emit_findings(self._findings)

        critical = sum(1 for f in self._findings if f.risk == "CRITICAL")
        high = sum(1 for f in self._findings if f.risk == "HIGH")

        return {
            "provider": provider,
            "escalation_paths": [p.to_dict() for p in self._findings],
            "critical_count": critical,
            "high_count": high,
            "total_paths": len(self._findings),
        }

    # ------------------------------------------------------------------
    # AWS
    # ------------------------------------------------------------------

    def _analyze_aws_policy(self, policy_doc: dict) -> list[EscalationPath]:
        """Static analysis of an IAM policy document for dangerous permission combinations."""
        paths: list[EscalationPath] = []
        granted_perms: set[str] = set()

        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect", "Deny") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action == "*" or action == "iam:*":
                    # Wildcard — grants everything
                    granted_perms.update([
                        "iam:CreatePolicyVersion", "iam:AttachRolePolicy",
                        "iam:PassRole", "sts:AssumeRole", "ssm:SendCommand",
                        "cloudformation:CreateStack", "lambda:CreateFunction",
                        "lambda:InvokeFunction", "lambda:UpdateFunctionCode",
                        "secretsmanager:GetSecretValue", "s3:GetObject",
                        "ec2:RunInstances",
                    ])
                else:
                    granted_perms.add(action)

        for path_def in AWS_ESCALATION_PATHS:
            required = set(path_def["required_perms"])
            # expand wildcard
            if self._wildcard_grants(granted_perms, required):
                paths.append(EscalationPath(
                    provider="AWS",
                    start_principal="analyzed_principal",
                    target_permission=path_def["target"],
                    chain=path_def["chain"],
                    description=path_def["description"],
                    risk=path_def["risk"],
                    mitre_ttp=path_def["mitre_ttp"],
                    remediation=path_def["remediation"],
                    cvss=path_def.get("cvss", ""),
                ))
        return paths

    def _wildcard_grants(self, granted: set[str], required: set[str]) -> bool:
        """Check if granted permissions cover required (respecting * wildcards)."""
        for req in required:
            found = False
            for granted_perm in granted:
                if granted_perm == req:
                    found = True
                    break
                # service wildcard e.g. "iam:*"
                if granted_perm.endswith(":*"):
                    service = granted_perm.split(":")[0]
                    if req.startswith(service + ":"):
                        found = True
                        break
                # full wildcard
                if granted_perm == "*":
                    found = True
                    break
            if not found:
                return False
        return True

    def _check_aws_live(self, credentials: dict) -> list[EscalationPath]:
        """Attempt live enumeration via boto3 if available."""
        paths: list[EscalationPath] = []
        try:
            import boto3
            import botocore.exceptions

            session = boto3.Session(
                aws_access_key_id=credentials.get("aws_access_key_id"),
                aws_secret_access_key=credentials.get("aws_secret_access_key"),
                aws_session_token=credentials.get("aws_session_token"),
                region_name=credentials.get("region", "us-east-1"),
            )
            iam = session.client("iam")

            # Get caller identity
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            principal_arn = identity.get("Arn", "unknown")
            log.info("AWS live check: principal=%s", principal_arn)

            # Simulate principal policy
            for path_def in AWS_ESCALATION_PATHS:
                try:
                    result = iam.simulate_principal_policy(
                        PolicySourceArn=principal_arn,
                        ActionNames=path_def["required_perms"],
                        ResourceArns=["*"],
                    )
                    allowed = all(
                        r.get("EvalDecision") == "allowed"
                        for r in result.get("EvaluationResults", [])
                    )
                    if allowed:
                        paths.append(EscalationPath(
                            provider="AWS",
                            start_principal=principal_arn,
                            target_permission=path_def["target"],
                            chain=path_def["chain"],
                            description=path_def["description"],
                            risk=path_def["risk"],
                            mitre_ttp=path_def["mitre_ttp"],
                            remediation=path_def["remediation"],
                            cvss=path_def.get("cvss", ""),
                        ))
                except botocore.exceptions.ClientError:
                    pass

        except ImportError:
            log.info("boto3 not available — skipping live AWS IAM check")
        except Exception as exc:
            log.warning("AWS live check error: %s", exc)

        return paths

    # ------------------------------------------------------------------
    # GCP
    # ------------------------------------------------------------------

    def _check_gcp(self, credentials: dict) -> list[EscalationPath]:
        """Detect GCP escalation paths — static + optionally live via google-auth."""
        paths: list[EscalationPath] = []
        granted = set(credentials.get("granted_permissions", []))

        for path_def in GCP_ESCALATION_PATHS:
            required = set(path_def["required_perms"])
            if required.issubset(granted) or not granted:
                # if no granted_permissions provided, report all as potential
                if granted:
                    paths.append(EscalationPath(
                        provider="GCP",
                        start_principal=credentials.get("service_account", "unknown"),
                        target_permission=path_def["target"],
                        chain=path_def["chain"],
                        description=path_def["description"],
                        risk=path_def["risk"],
                        mitre_ttp=path_def["mitre_ttp"],
                        remediation=path_def["remediation"],
                        cvss=path_def.get("cvss", ""),
                    ))
        return paths

    def _check_gcp_live(self, credentials: dict) -> list[EscalationPath]:
        """Attempt live GCP IAM check via google-auth library."""
        paths: list[EscalationPath] = []
        try:
            import google.auth
            import google.auth.transport.requests
            import googleapiclient.discovery

            log.info("GCP live IAM check not implemented — use _check_gcp with granted_permissions")
        except ImportError:
            log.debug("google-auth not available")
        return paths

    # ------------------------------------------------------------------
    # Azure
    # ------------------------------------------------------------------

    def _check_azure(self, credentials: dict) -> list[EscalationPath]:
        """Detect Azure escalation paths."""
        paths: list[EscalationPath] = []
        granted = set(credentials.get("granted_permissions", []))
        roles = set(credentials.get("roles", []))

        for path_def in AZURE_ESCALATION_PATHS:
            required = set(path_def["required_perms"])
            # Check if any required perm is in granted or implied by a role
            if any(perm in granted for perm in required) or "Owner" in roles:
                paths.append(EscalationPath(
                    provider="AZURE",
                    start_principal=credentials.get("principal_id", "unknown"),
                    target_permission=path_def["target"],
                    chain=path_def["chain"],
                    description=path_def["description"],
                    risk=path_def["risk"],
                    mitre_ttp=path_def["mitre_ttp"],
                    remediation=path_def["remediation"],
                    cvss=path_def.get("cvss", ""),
                ))
        return paths

    # ------------------------------------------------------------------
    # Finding emission
    # ------------------------------------------------------------------

    def _emit_findings(self, paths: list[EscalationPath]) -> None:
        """Log findings at appropriate severity levels."""
        for path in paths:
            if path.risk == "CRITICAL":
                log.critical(
                    "[%s] CRITICAL IAM escalation: %s | Chain: %s | MITRE: %s",
                    path.provider,
                    path.target_permission,
                    " -> ".join(path.chain),
                    path.mitre_ttp,
                )
            elif path.risk == "HIGH":
                log.warning(
                    "[%s] HIGH IAM escalation: %s | Chain: %s",
                    path.provider,
                    path.target_permission,
                    " -> ".join(path.chain),
                )
            else:
                log.info(
                    "[%s] MEDIUM IAM escalation: %s",
                    path.provider,
                    path.target_permission,
                )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCloudIamChaining(unittest.TestCase):

    def setUp(self):
        self.chaining = CloudIamChaining()

    # --- EscalationPath dataclass ---
    def test_escalation_path_dataclass(self):
        ep = EscalationPath(
            provider="AWS",
            start_principal="arn:aws:iam::123:user/attacker",
            target_permission="AdministratorAccess",
            chain=["iam:CreatePolicyVersion → *:*"],
            description="Test",
            risk="CRITICAL",
            mitre_ttp="T1098.001",
            remediation="Remove permission",
        )
        self.assertEqual(ep.provider, "AWS")
        self.assertEqual(ep.risk, "CRITICAL")

    def test_escalation_path_to_dict(self):
        ep = EscalationPath(
            provider="GCP",
            start_principal="sa@project.iam.gserviceaccount.com",
            target_permission="Admin",
            chain=["iam.serviceAccounts.actAs"],
            description="desc",
            risk="HIGH",
            mitre_ttp="T1078.004",
            remediation="fix",
        )
        d = ep.to_dict()
        self.assertIn("provider", d)
        self.assertIn("chain", d)

    # --- Wildcard matching ---
    def test_wildcard_grants_exact(self):
        granted = {"iam:CreatePolicyVersion"}
        required = {"iam:CreatePolicyVersion"}
        self.assertTrue(self.chaining._wildcard_grants(granted, required))

    def test_wildcard_grants_service_wildcard(self):
        granted = {"iam:*"}
        required = {"iam:CreatePolicyVersion", "iam:AttachRolePolicy"}
        self.assertTrue(self.chaining._wildcard_grants(granted, required))

    def test_wildcard_grants_full_wildcard(self):
        granted = {"*"}
        required = {"iam:PassRole", "ec2:RunInstances"}
        self.assertTrue(self.chaining._wildcard_grants(granted, required))

    def test_wildcard_grants_missing_perm(self):
        granted = {"s3:GetObject"}
        required = {"iam:CreatePolicyVersion"}
        self.assertFalse(self.chaining._wildcard_grants(granted, required))

    # --- Static policy analysis ---
    def test_analyze_aws_policy_admin_wildcard(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }]
        }
        paths = self.chaining._analyze_aws_policy(policy)
        self.assertGreater(len(paths), 0)
        risks = {p.risk for p in paths}
        self.assertIn("CRITICAL", risks)

    def test_analyze_aws_policy_specific_perm(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:CreatePolicyVersion"],
                "Resource": "*",
            }]
        }
        paths = self.chaining._analyze_aws_policy(policy)
        found_ids = [p.target_permission for p in paths]
        self.assertTrue(any("Administrator" in t or "Policy" in t for t in found_ids))

    def test_analyze_aws_policy_deny_skipped(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }]
        }
        paths = self.chaining._analyze_aws_policy(policy)
        self.assertEqual(len(paths), 0)

    # --- AWS live (no boto3 available in test environment) ---
    def test_check_aws_live_no_boto3(self):
        """Without boto3, should return empty list gracefully."""
        import unittest.mock
        with unittest.mock.patch.dict("sys.modules", {"boto3": None}):
            paths = self.chaining._check_aws_live({})
            self.assertIsInstance(paths, list)

    # --- GCP checks ---
    def test_check_gcp_with_granted_permissions(self):
        credentials = {
            "granted_permissions": ["iam.serviceAccounts.actAs"],
            "service_account": "test@project.iam.gserviceaccount.com",
        }
        paths = self.chaining._check_gcp(credentials)
        self.assertTrue(any(p.provider == "GCP" for p in paths))
        self.assertTrue(any(p.risk == "CRITICAL" for p in paths))

    def test_check_gcp_empty_permissions(self):
        """Empty granted permissions → no specific match findings."""
        paths = self.chaining._check_gcp({"granted_permissions": []})
        self.assertEqual(len(paths), 0)

    # --- Azure checks ---
    def test_check_azure_with_permissions(self):
        credentials = {
            "granted_permissions": ["Microsoft.Compute/virtualMachines/runCommand/action"],
            "principal_id": "test-user-id",
            "roles": [],
        }
        paths = self.chaining._check_azure(credentials)
        self.assertTrue(any(p.risk == "CRITICAL" for p in paths))

    # --- run() integration ---
    def test_run_returns_dict(self):
        result = self.chaining.run("AWS", {"policy_json": json.dumps({
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]
        })})
        self.assertIn("escalation_paths", result)
        self.assertIn("provider", result)
        self.assertEqual(result["provider"], "AWS")

    def test_run_unknown_provider(self):
        result = self.chaining.run("UNKNOWN_CLOUD", {})
        self.assertEqual(result["total_paths"], 0)


if __name__ == "__main__":
    unittest.main()
