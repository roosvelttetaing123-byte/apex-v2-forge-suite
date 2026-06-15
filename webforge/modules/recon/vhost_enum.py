"""Virtual host enumerator — discover hidden vhosts via Host header fuzzing."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_VHOST = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

DEFAULT_SUBDOMAINS = [
    "admin", "dev", "development", "staging", "stage", "test", "testing",
    "api", "api2", "api-v1", "api-v2", "internal", "intranet", "portal",
    "app", "app2", "beta", "demo", "old", "legacy", "backup",
    "mail", "smtp", "pop", "imap", "webmail", "remote",
    "vpn", "gateway", "proxy", "cdn", "static", "assets",
    "db", "database", "mysql", "redis", "mongo",
    "jenkins", "gitlab", "jira", "confluence", "sonar",
    "monitor", "metrics", "grafana", "kibana", "elastic",
    "git", "svn", "repo", "ci", "cd", "build",
    "manage", "management", "control", "panel", "cpanel", "whm",
    "login", "auth", "sso", "oauth", "id",
    "docs", "doc", "wiki", "knowledge",
    "shop", "store", "checkout", "cart",
    "mobile", "m", "www2", "web", "secure",
]


class VhostEnum(BaseModule):
    """Virtual host enumeration via Host header brute-forcing."""

    NAME        = "vhost_enum"
    DESCRIPTION = "Discover hidden virtual hosts by fuzzing the Host header"
    PHASE       = 1
    TAGS        = ["recon", "vhost", "subdomain", "owasp-a05"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Extract base domain from target
        base_domain = self._extract_domain(target)
        base_response = await self._get_baseline(target, base_domain)
        if base_response is None:
            self.log.warning("Could not get baseline response from %s", target)
            return self._make_result(start)

        self.log.info("Testing %d vhost candidates for %s", len(DEFAULT_SUBDOMAINS), base_domain)

        sem = asyncio.Semaphore(5)
        tasks = [
            self._test_vhost(target, f"{sub}.{base_domain}", base_response, sem)
            for sub in DEFAULT_SUBDOMAINS
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _get_baseline(self, target: str, domain: str) -> dict | None:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    target, headers={"Host": domain}, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    body = await resp.text(errors="ignore")
                    return {
                        "status": resp.status,
                        "length": len(body),
                        "title": self._extract_title(body),
                    }
        except Exception:
            return None

    async def _test_vhost(
        self, target: str, vhost: str, baseline: dict, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        target,
                        headers={"Host": vhost, "User-Agent": "Mozilla/5.0"},
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=False,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        length = len(body)
                        status = resp.status
                        title  = self._extract_title(body)

                        # Different from baseline = potential vhost
                        diff = abs(length - baseline["length"])
                        if (
                            status in (200, 301, 302, 401, 403)
                            and status != baseline["status"]
                        ) or (status == 200 and diff > 200 and title != baseline["title"]):
                            ev = Evidence(
                                request_raw=f"GET / HTTP/1.1\nHost: {vhost}",
                                response_raw=body[:500],
                                extra={
                                    "vhost": vhost,
                                    "status": status,
                                    "length": length,
                                    "title": title,
                                    "baseline_status": baseline["status"],
                                    "baseline_length": baseline["length"],
                                },
                            )
                            self.new_finding(
                                title=f"Virtual Host Discovered — {vhost}",
                                severity=Severity.LOW,
                                description=(
                                    f"Virtual host '{vhost}' responds differently than the baseline "
                                    f"(status {status}, length {length}, title '{title}'). "
                                    "This may be a hidden development or staging environment."
                                ),
                                reproduction_steps=[
                                    f"curl -H 'Host: {vhost}' {target}",
                                    f"Add '{target.split('//')[1]} {vhost}' to /etc/hosts",
                                ],
                                remediation=(
                                    "Ensure development/staging vhosts are not accessible from the internet. "
                                    "Remove or restrict non-production environments."
                                ),
                                references=["CWE-200", "OWASP A05:2021"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_VHOST,
                                target=target,
                                url=f"{target}/ [Host: {vhost}]",
                            )
            except Exception:
                pass

    def _extract_domain(self, target: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc.split(":")[0]
        return host

    def _extract_title(self, html: str) -> str:
        import re
        m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        return m.group(1).strip()[:60] if m else ""


class TestVhostEnum:
    def test_extract_domain(self) -> None:
        mod = VhostEnum.__new__(VhostEnum)
        assert mod._extract_domain("https://example.com/path") == "example.com"

    def test_extract_domain_with_port(self) -> None:
        mod = VhostEnum.__new__(VhostEnum)
        assert mod._extract_domain("http://10.0.0.1:8080") == "10.0.0.1"

    def test_extract_title(self) -> None:
        mod = VhostEnum.__new__(VhostEnum)
        assert mod._extract_title("<title>Hello</title>") == "Hello"
