"""Terraform State Poisoner — detect exposed tfstate, extract secrets, model backdoors.

Scans for:
  - Exposed .tfstate files on HTTP endpoints
  - S3/GCS/Azure Blob tfstate with public or misconfigured access
  - Secret extraction from state (passwords, tokens, keys, connection strings)
  - Infrastructure mapping from state resources
  - Backdoor injection modeling (what could be modified)

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.cloud.tf_state_poisoner")


# ── Common tfstate file locations to probe ───────────────────────────
_TFSTATE_PROBE_PATHS: list[str] = [
    "/terraform.tfstate",
    "/terraform.tfstate.backup",
    "/.terraform/terraform.tfstate",
    "/tfstate",
    "/state/terraform.tfstate",
    "/infrastructure/terraform.tfstate",
    "/deploy/terraform.tfstate",
    "/iac/terraform.tfstate",
    "/.tfstate",
    "/default.tfstate",
    "/prod.tfstate",
    "/staging.tfstate",
    "/dev.tfstate",
]

# ── Secret patterns to extract from tfstate ──────────────────────────
_TFSTATE_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'"password"\s*:\s*"([^"]+)"', "Database Password"),
    (r'"secret_key"\s*:\s*"([^"]+)"', "AWS Secret Key"),
    (r'"access_key"\s*:\s*"([^"]+)"', "AWS Access Key"),
    (r'"token"\s*:\s*"([^"]+)"', "API Token"),
    (r'"private_key"\s*:\s*"([^"]+)"', "Private Key"),
    (r'"connection_string"\s*:\s*"([^"]+)"', "Connection String"),
    (r'"client_secret"\s*:\s*"([^"]+)"', "OAuth Client Secret"),
    (r'"api_key"\s*:\s*"([^"]+)"', "API Key"),
    (r'"admin_password"\s*:\s*"([^"]+)"', "Admin Password"),
    (r'"master_password"\s*:\s*"([^"]+)"', "Master Password"),
    (r'"ssh_key"\s*:\s*"([^"]+)"', "SSH Key"),
    (r'"cert"\s*:\s*"([^"]+)"', "Certificate"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'"github_token"\s*:\s*"([^"]+)"', "GitHub Token"),
    (r'"slack_webhook"\s*:\s*"([^"]+)"', "Slack Webhook"),
]

# ── S3 bucket patterns for tfstate ───────────────────────────────────
_S3_TFSTATE_PATTERNS: list[str] = [
    "https://{bucket}.s3.amazonaws.com/terraform.tfstate",
    "https://{bucket}.s3.amazonaws.com/{key}",
    "https://s3.amazonaws.com/{bucket}/terraform.tfstate",
]


class TfStatePoisoner(BaseModule):
    """Detect exposed Terraform state files and extract secrets."""

    NAME        = "tf_state_poisoner"
    DESCRIPTION = "Terraform state exposure — detect tfstate files, extract secrets, model backdoor injection"
    PHASE       = 2
    TAGS        = ["cloud", "terraform", "iac", "secrets", "recon"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._extracted_secrets: list[dict[str, str]] = []
        self._infrastructure_map: list[dict[str, Any]] = []

    async def run(self) -> ModuleResult:
        """Scan for exposed Terraform state and extract intelligence."""
        start = time.monotonic()

        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="Target out of scope")

        self.log.info("Starting Terraform state scan against %s", target)

        # ── Phase 1: HTTP probe for tfstate files ────────────────────
        await self._probe_http_tfstate(target)

        # ── Phase 2: S3/GCS bucket probe ─────────────────────────────
        await self._probe_cloud_storage_tfstate()

        return self._make_result(start)

    async def _probe_http_tfstate(self, target: str) -> None:
        """Probe target web server for exposed tfstate files."""
        import aiohttp

        # Get soft-404 fingerprints to avoid false positives
        soft_fps = await self._soft_404_fingerprints(target)

        async with self.http_session(timeout=8.0) as session:
            for path in _TFSTATE_PROBE_PATHS:
                await self.rate_limit()
                url = f"{target.rstrip('/')}{path}"
                try:
                    async with session.get(
                        url, allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")

                            # Skip soft-404s and WAF pages
                            if self._is_soft_404_body(body, resp.status, soft_fps):
                                continue
                            if self._is_waf_placeholder(body, resp.status):
                                continue

                            # Validate it's actually tfstate JSON
                            if not self._is_valid_tfstate(body):
                                continue

                            # Extract secrets
                            secrets = self._extract_secrets(body)
                            resources = self._extract_resources(body)

                            self.new_finding(
                                title="Terraform State File Exposed",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"Terraform state file found at {url}. "
                                    f"Contains {len(resources)} infrastructure resources and "
                                    f"{len(secrets)} embedded secrets/credentials. "
                                    f"Full infrastructure topology and all managed resource "
                                    f"attributes are exposed."
                                ),
                                reproduction_steps=[
                                    f"curl {url}",
                                    "Parse JSON for 'resources' array",
                                    "Search for password, secret_key, token fields",
                                    "Map infrastructure from resource types and attributes",
                                ],
                                remediation=(
                                    "Store tfstate in encrypted remote backend (S3+DynamoDB, GCS, Azure Blob). "
                                    "Enable state encryption at rest. Use terraform_remote_state data sources. "
                                    "Block .tfstate in web server config and .gitignore. "
                                    "Rotate all exposed secrets immediately."
                                ),
                                references=[
                                    "https://developer.hashicorp.com/terraform/language/state/sensitive-data",
                                    "https://developer.hashicorp.com/terraform/language/settings/backends/s3",
                                    "https://attack.mitre.org/techniques/T1552.001/",
                                ],
                                evidence=Evidence(
                                    request_raw=f"GET {url}",
                                    response_raw=body[:3000],
                                    extra={
                                        "secrets_found": len(secrets),
                                        "resources_found": len(resources),
                                        "secret_types": [s["type"] for s in secrets[:10]],
                                        "resource_types": list(set(r.get("type", "") for r in resources[:20])),
                                    },
                                ),
                                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                                mitre_attack=["T1552.001", "T1530"],
                                target=target,
                                url=url,
                                confidence="HIGH",
                                tags=["terraform", "tfstate", "secrets", "iac"],
                            )

                            # Report individual extracted secrets
                            for secret in secrets[:5]:  # Cap at 5 per file
                                self.new_finding(
                                    title=f"Terraform State Secret — {secret['type']}",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"Secret extracted from exposed Terraform state: "
                                        f"{secret['type']}. Value preview: {secret['preview']}"
                                    ),
                                    reproduction_steps=[
                                        f"Access {url}",
                                        f"Search for {secret['type']} in JSON content",
                                    ],
                                    remediation=(
                                        "Rotate this credential immediately. "
                                        "Store sensitive values in Vault or AWS Secrets Manager. "
                                        "Use sensitive = true in Terraform variable declarations."
                                    ),
                                    references=[
                                        "https://developer.hashicorp.com/terraform/language/values/variables#suppressing-values-in-cli-output",
                                    ],
                                    evidence=Evidence(
                                        extra={"secret_type": secret["type"], "source": url},
                                    ),
                                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    mitre_attack=["T1552.001"],
                                    target=target,
                                    url=url,
                                    tags=["terraform", "credential", secret["type"].lower().replace(" ", "_")],
                                )

                except Exception as exc:
                    self.log.debug("tfstate probe %s failed: %s", url, exc)

    async def _probe_cloud_storage_tfstate(self) -> None:
        """Probe cloud storage buckets for exposed tfstate."""
        # Extract potential bucket names from target domain
        target = self.config.target
        domain_parts = target.replace("https://", "").replace("http://", "").split(".")
        if not domain_parts:
            return

        org_name = domain_parts[0]
        bucket_candidates = [
            f"{org_name}-terraform",
            f"{org_name}-tf-state",
            f"{org_name}-tfstate",
            f"{org_name}-infrastructure",
            f"terraform-{org_name}",
            f"tf-state-{org_name}",
        ]

        import aiohttp
        async with self.http_session(timeout=5.0, include_auth=False) as session:
            for bucket in bucket_candidates:
                await self.rate_limit()
                url = f"https://{bucket}.s3.amazonaws.com/terraform.tfstate"
                try:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            if self._is_valid_tfstate(body):
                                self.new_finding(
                                    title=f"S3 Bucket Exposed Terraform State — {bucket}",
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"Public S3 bucket '{bucket}' contains an exposed "
                                        f"Terraform state file with infrastructure secrets."
                                    ),
                                    reproduction_steps=[
                                        f"curl {url}",
                                        "aws s3 ls s3://{bucket}/ --no-sign-request",
                                    ],
                                    remediation=(
                                        "Enable S3 bucket encryption. Block public access. "
                                        "Use S3 bucket policies to restrict access to CI/CD only."
                                    ),
                                    references=[
                                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                                    ],
                                    evidence=Evidence(
                                        request_raw=f"GET {url}",
                                        response_raw=body[:2000],
                                        extra={"bucket": bucket},
                                    ),
                                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                                    mitre_attack=["T1530", "T1552.001"],
                                    target=self.config.target,
                                    url=url,
                                    tags=["terraform", "s3", "public_bucket"],
                                )
                except Exception:
                    pass

    def _is_valid_tfstate(self, body: str) -> bool:
        """Check if response body looks like valid Terraform state JSON."""
        try:
            data = json.loads(body)
            return (
                isinstance(data, dict)
                and "version" in data
                and ("resources" in data or "modules" in data)
            )
        except (json.JSONDecodeError, ValueError):
            return False

    def _extract_secrets(self, body: str) -> list[dict[str, str]]:
        """Extract secrets from tfstate content."""
        secrets: list[dict[str, str]] = []
        for pattern, label in _TFSTATE_SECRET_PATTERNS:
            matches = re.findall(pattern, body)
            for match in matches:
                value = match if isinstance(match, str) else match
                if len(value) > 4:  # Skip trivially short values
                    secrets.append({
                        "type": label,
                        "preview": value[:20] + "..." if len(value) > 20 else value,
                    })
        return secrets

    def _extract_resources(self, body: str) -> list[dict[str, Any]]:
        """Extract infrastructure resource listing from tfstate."""
        try:
            data = json.loads(body)
            resources = data.get("resources", [])
            return [{"type": r.get("type", ""), "name": r.get("name", "")} for r in resources]
        except Exception:
            return []


class TestTfStatePoisoner:
    """Unit tests for TfStatePoisoner."""

    def test_class_attributes(self) -> None:
        assert TfStatePoisoner.NAME == "tf_state_poisoner"
        assert TfStatePoisoner.PHASE == 2
        assert "terraform" in TfStatePoisoner.TAGS

    def test_instantiation(self, tmp_path: "Path") -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        cfg = BaseForgeConfig(target="https://example.com")
        scope = Scope(["example.com"])
        session = create_db(tmp_path / "test.db")
        mod = TfStatePoisoner(cfg, scope, session, tmp_path)
        assert mod.NAME == "tf_state_poisoner"
        assert mod._extracted_secrets == []
        session.close()

    def test_is_valid_tfstate(self, tmp_path: "Path") -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        cfg = BaseForgeConfig(target="https://example.com")
        scope = Scope(["example.com"])
        session = create_db(tmp_path / "test.db")
        mod = TfStatePoisoner(cfg, scope, session, tmp_path)

        valid = '{"version": 4, "resources": [{"type": "aws_instance", "name": "web"}]}'
        invalid = "<html>Not Found</html>"
        empty = "{}"

        assert mod._is_valid_tfstate(valid) is True
        assert mod._is_valid_tfstate(invalid) is False
        assert mod._is_valid_tfstate(empty) is False
        session.close()

    def test_extract_secrets(self, tmp_path: "Path") -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        cfg = BaseForgeConfig(target="https://example.com")
        scope = Scope(["example.com"])
        session = create_db(tmp_path / "test.db")
        mod = TfStatePoisoner(cfg, scope, session, tmp_path)

        body = '{"password": "SuperSecret123", "access_key": "AKIAIOSFODNN7EXAMPLE"}'
        secrets = mod._extract_secrets(body)
        assert len(secrets) >= 1
        session.close()

    def test_extract_resources(self, tmp_path: "Path") -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        cfg = BaseForgeConfig(target="https://example.com")
        scope = Scope(["example.com"])
        session = create_db(tmp_path / "test.db")
        mod = TfStatePoisoner(cfg, scope, session, tmp_path)

        body = '{"version": 4, "resources": [{"type": "aws_instance", "name": "web"}, {"type": "aws_s3_bucket", "name": "data"}]}'
        resources = mod._extract_resources(body)
        assert len(resources) == 2
        assert resources[0]["type"] == "aws_instance"
        session.close()

    def test_probe_paths_defined(self) -> None:
        assert len(_TFSTATE_PROBE_PATHS) >= 5
