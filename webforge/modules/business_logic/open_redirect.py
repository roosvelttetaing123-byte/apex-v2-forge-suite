"""Open redirect scanner — detect unvalidated redirect/forward vulnerabilities."""
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

CVSS_OPEN_REDIR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"

EVIL_DOMAIN = "evil.forge-test.example.com"
EVIL_URLS = [
    f"https://{EVIL_DOMAIN}",
    f"//evil.forge-test.example.com",
    f"//{EVIL_DOMAIN}",
    f"https://google.com@{EVIL_DOMAIN}",
    f"https://{EVIL_DOMAIN}/path",
    f"htTpS://{EVIL_DOMAIN}",
    f"javascript:alert(1)",
    f"data:text/html,<h1>test</h1>",
    f"http://0x{int('169.254.169.254'.replace('.','')[:8], 16):x}/",  # hex IP
]

REDIRECT_PARAMS = [
    "redirect", "next", "return", "url", "goto", "dest", "destination",
    "ref", "returnUrl", "returnTo", "back", "forward", "target",
    "redir", "redirectUrl", "redirect_url", "continue", "location",
    "success_url", "failure_url", "cancel_url",
]


class OpenRedirect(BaseModule):
    """Open redirect vulnerability scanner."""

    NAME        = "open_redirect"
    DESCRIPTION = "Detect open redirect vulnerabilities in URL parameters"
    PHASE       = 9
    TAGS        = ["business-logic", "redirect", "phishing", "cwe-601", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        crawled = self.config.extra.get("crawled_urls", [target])
        redirect_param_pattern = re.compile("|".join(REDIRECT_PARAMS), re.IGNORECASE)

        test_targets: list[tuple[str, str]] = []
        for url in crawled[:50]:
            if "?" in url:
                parsed = urlparse(url)
                for param in parse_qs(parsed.query):
                    if redirect_param_pattern.search(param):
                        test_targets.append((url, param))

        # Also probe common redirect endpoints
        for path in ["/login", "/logout", "/oauth/callback", "/auth"]:
            for param in REDIRECT_PARAMS[:5]:
                test_targets.append((
                    f"{target}{path}?{param}=https://example.com", param
                ))

        self.log.info("Testing %d redirect parameter(s)", len(test_targets))

        sem = asyncio.Semaphore(3)
        tasks = [self._test_redirect(url, param, target, sem)
                 for url, param in test_targets[:30]]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _test_redirect(
        self, url: str, param_name: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            if not self.check_scope(url):
                return

            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            for evil_url in EVIL_URLS[:5]:
                await self.rate_limit()
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = evil_url
                test_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{urlencode(test_params)}"
                )

                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            test_url,
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            location = resp.headers.get("Location", "")

                    if resp.status in (301, 302, 303, 307, 308) and \
                       EVIL_DOMAIN in location or (
                           evil_url.startswith("javascript:") and location.startswith("javascript:")
                       ):
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=f"HTTP {resp.status}\nLocation: {location}",
                            extra={
                                "param":     param_name,
                                "evil_url":  evil_url,
                                "location":  location,
                                "status":    resp.status,
                            },
                        )
                        self.new_finding(
                            title=f"Open Redirect — {param_name} ({url.split('?')[0].split('/')[-1]})",
                            severity=Severity.MEDIUM,
                            description=(
                                f"Open redirect via '{param_name}' parameter. "
                                f"Redirects to: {location}. "
                                "Attackers can craft phishing links using the trusted domain "
                                "that redirect to malicious sites, bypassing security filters."
                            ),
                            reproduction_steps=[
                                f"curl -v '{test_url}' 2>&1 | grep Location",
                                f"Redirect to: {location}",
                            ],
                            remediation=(
                                "Validate redirect destinations against an allowlist. "
                                "Use relative paths or internal redirect tokens instead of "
                                "full URLs in redirect parameters."
                            ),
                            references=["CWE-601", "OWASP A01:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_OPEN_REDIR,
                            target=target,
                            url=url,
                        )
                        return

                except Exception:
                    pass


class TestOpenRedirect:
    def test_evil_urls_not_empty(self) -> None:
        assert len(EVIL_URLS) >= 4

    def test_redirect_params_not_empty(self) -> None:
        assert "redirect" in REDIRECT_PARAMS
        assert "next" in REDIRECT_PARAMS
        assert "url" in REDIRECT_PARAMS

    def test_evil_domain_in_urls(self) -> None:
        assert any(EVIL_DOMAIN in u for u in EVIL_URLS)
