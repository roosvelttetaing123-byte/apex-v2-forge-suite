"""Cloud Asset Enumerator — open S3 buckets, Azure Blob, GCP Storage with config file detection.

Brute-forces common cloud storage naming patterns for the target org:
  - AWS S3:    {org}.s3.amazonaws.com, s3.amazonaws.com/{org}
  - Azure Blob: {org}.blob.core.windows.net
  - GCP Storage: storage.googleapis.com/{org}

No API keys required — uses unauthenticated HEAD/GET requests.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.leak_intel.cloud_asset_enum")

_S3_PERMUTATIONS = [
    "{org}", "{org}-dev", "{org}-staging", "{org}-prod", "{org}-backup",
    "{org}-data", "{org}-assets", "{org}-uploads", "{org}-static",
    "{org}-logs", "{org}-internal", "{org}-config", "{org}-media",
    "{org}-public", "{org}-private", "{org}-test",
]

_SENSITIVE_FILES = [
    ".env", "config.json", "credentials.json", "secrets.yml", "database.yml",
    "wp-config.php", "settings.py", "application.yml", "docker-compose.yml",
    "terraform.tfstate", ".git/config", "backup.sql", "dump.sql",
]


class CloudAssetEnumerator(BaseModule):
    """Enumerate open cloud storage buckets for the target organization."""

    NAME        = "cloud_asset_enum"
    DESCRIPTION = "Cloud storage enumeration — open S3, Azure Blob, GCP Storage detection"
    PHASE       = 0
    TAGS        = ["osint", "leak_intel", "cloud", "s3", "azure", "gcp", "recon"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        org = self._extract_org()
        if not org:
            return self._make_result(start, skipped=True, skip_reason="No org name derivable from target")

        self.log.info("Enumerating cloud storage for org: %s", org)

        try:
            import aiohttp
        except ImportError:
            return self._make_result(start, skipped=True, skip_reason="aiohttp not installed")

        async with aiohttp.ClientSession() as session:
            for pattern in _S3_PERMUTATIONS:
                bucket = pattern.format(org=org)
                await self._check_s3(session, bucket)
                await self._check_azure_blob(session, bucket)
                await self._check_gcp_storage(session, bucket)

        return self._make_result(start)

    async def _check_s3(self, session: Any, bucket: str) -> None:
        """Check if an S3 bucket exists and is publicly accessible."""
        url = f"https://{bucket}.s3.amazonaws.com/"
        try:
            await self.rate_limit()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if "<ListBucketResult" in body:
                        self.new_finding(
                            title=f"Open S3 Bucket: {bucket}",
                            severity=Severity.HIGH,
                            description=(
                                f"S3 bucket '{bucket}' is publicly listable.\n"
                                "This may expose sensitive data, backups, or configuration files."
                            ),
                            reproduction_steps=[
                                f"1. Navigate to https://{bucket}.s3.amazonaws.com/",
                                "2. Observe directory listing of bucket contents",
                            ],
                            remediation=(
                                "1. Disable public access: aws s3api put-public-access-block\n"
                                "2. Review bucket policy and ACLs\n"
                                "3. Enable S3 Block Public Access at account level"
                            ),
                            references=[
                                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                            ],
                            evidence=Evidence(extra={"bucket": bucket, "provider": "aws", "listing": True}),
                            url=url,
                            tags=["cloud", "s3", "open_bucket", "data_exposure"],
                            mitre_attack=["T1530"],
                            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        )
                        # Check for sensitive files
                        await self._probe_sensitive_files(session, url, bucket, "s3")

                elif resp.status == 403:
                    # Bucket exists but not listable — still note it
                    self.new_finding(
                        title=f"S3 Bucket Exists (Not Listable): {bucket}",
                        severity=Severity.INFORMATIONAL,
                        description=f"S3 bucket '{bucket}' exists but is not publicly listable.",
                        reproduction_steps=[f"1. HEAD https://{bucket}.s3.amazonaws.com/"],
                        remediation="Ensure bucket policy is restrictive.",
                        references=["https://docs.aws.amazon.com/AmazonS3/"],
                        evidence=Evidence(extra={"bucket": bucket, "provider": "aws", "listing": False}),
                        tags=["cloud", "s3", "bucket_exists"],
                        mitre_attack=["T1530"],
                    )
        except Exception:
            pass

    async def _check_azure_blob(self, session: Any, container: str) -> None:
        """Check if an Azure Blob container is publicly accessible."""
        url = f"https://{container}.blob.core.windows.net/?comp=list&restype=container"
        try:
            await self.rate_limit()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if "<EnumerationResults" in body:
                        self.new_finding(
                            title=f"Open Azure Blob Container: {container}",
                            severity=Severity.HIGH,
                            description=f"Azure Blob container '{container}' is publicly listable.",
                            reproduction_steps=[f"1. Navigate to {url}"],
                            remediation="Disable public access on the storage account.",
                            references=["https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent"],
                            evidence=Evidence(extra={"container": container, "provider": "azure"}),
                            url=url,
                            tags=["cloud", "azure", "open_container", "data_exposure"],
                            mitre_attack=["T1530"],
                            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        )
        except Exception:
            pass

    async def _check_gcp_storage(self, session: Any, bucket: str) -> None:
        """Check if a GCP Storage bucket is publicly accessible."""
        url = f"https://storage.googleapis.com/{bucket}/"
        try:
            await self.rate_limit()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if "<ListBucketResult" in body:
                        self.new_finding(
                            title=f"Open GCP Storage Bucket: {bucket}",
                            severity=Severity.HIGH,
                            description=f"GCP Storage bucket '{bucket}' is publicly listable.",
                            reproduction_steps=[f"1. Navigate to {url}"],
                            remediation="Set uniform bucket-level access and remove allUsers/allAuthenticatedUsers.",
                            references=["https://cloud.google.com/storage/docs/access-control"],
                            evidence=Evidence(extra={"bucket": bucket, "provider": "gcp"}),
                            url=url,
                            tags=["cloud", "gcp", "open_bucket", "data_exposure"],
                            mitre_attack=["T1530"],
                            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        )
        except Exception:
            pass

    async def _probe_sensitive_files(self, session: Any, base_url: str, bucket: str, provider: str) -> None:
        """Check for known sensitive files in an open bucket."""
        for filename in _SENSITIVE_FILES[:6]:
            await self.rate_limit()
            url = f"{base_url}{filename}"
            try:
                async with session.head(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        self.new_finding(
                            title=f"Sensitive File in {provider.upper()} Bucket: {bucket}/{filename}",
                            severity=Severity.CRITICAL,
                            description=f"Sensitive file '{filename}' is publicly accessible in bucket '{bucket}'.",
                            reproduction_steps=[f"1. GET {url}"],
                            remediation="Remove file or restrict bucket access immediately.",
                            references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
                            evidence=Evidence(extra={"bucket": bucket, "file": filename, "provider": provider}),
                            url=url,
                            tags=["cloud", provider, "sensitive_file", "data_exposure"],
                            mitre_attack=["T1530", "T1552.001"],
                            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        )
            except Exception:
                pass

    def _extract_org(self) -> str:
        target = self.config.target.replace("https://", "").replace("http://", "")
        target = target.split("/")[0].split(":")[0]
        parts = target.split(".")
        return parts[0] if parts else ""


import aiohttp  # noqa: E402
