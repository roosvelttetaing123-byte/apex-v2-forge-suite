"""API rate limit checker — detect missing rate limiting on sensitive endpoints."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NO_RATE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"

SENSITIVE_PATHS = [
    "/api/login", "/api/auth", "/api/token",
    "/api/password-reset", "/api/forgot-password",
    "/api/verify-otp", "/api/otp",
    "/api/register", "/api/signup",
    "/login", "/auth/login",
]

RATE_LIMIT_HEADERS = [
    "X-RateLimit-Limit", "X-RateLimit-Remaining",
    "X-Rate-Limit-Limit", "Retry-After",
    "X-RateLimit-Reset", "RateLimit-Limit",
]


class ApiRateCheck(BaseModule):
    """API rate limiting checker."""

    NAME        = "api_rate_check"
    DESCRIPTION = "Detect missing rate limiting on authentication and sensitive API endpoints"
    PHASE       = 7
    TAGS        = ["api", "rate-limit", "brute-force", "cwe-307", "owasp-api4"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        for path in SENSITIVE_PATHS:
            url = f"{target}{path}"
            if not self.check_scope(url):
                continue
            await self.rate_limit()
            await self._test_rate_limiting(url, target)

        return self._make_result(start)

    async def _test_rate_limiting(self, url: str, target: str) -> None:
        """Send 15 rapid requests and check for rate limiting."""
        import aiohttp

        responses: list[int] = []
        has_rate_headers = False

        # Check if endpoint exists first
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 404:
                        return
                    # Check for rate limit headers in first response
                    has_rate_headers = any(
                        h in resp.headers for h in RATE_LIMIT_HEADERS
                    )
        except Exception:
            return

        # Send 15 rapid POST requests
        async def _attempt():
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.post(
                        url,
                        data={"username": "test", "password": f"forge_{time.time()}"},
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        return resp.status
            except Exception:
                return 0

        tasks = [_attempt() for _ in range(15)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        responses = [r for r in results if isinstance(r, int) and r > 0]

        # Check if any 429 (Too Many Requests) was returned
        got_429 = 429 in responses
        got_503 = 503 in responses

        if not got_429 and not got_503 and not has_rate_headers:
            success_count = sum(1 for s in responses if s not in (429, 503))
            ev = Evidence(
                extra={
                    "url":             url,
                    "requests_sent":   15,
                    "responses":       responses[:10],
                    "got_429":         got_429,
                    "has_rate_headers": has_rate_headers,
                }
            )
            self.new_finding(
                title=f"No Rate Limiting on Sensitive Endpoint — {url.split(target)[1]}",
                severity=Severity.HIGH,
                description=(
                    f"Sent 15 rapid requests to {url} — "
                    f"no rate limiting detected (no 429 responses, no rate-limit headers). "
                    "An attacker can brute-force credentials or enumerate users without restriction."
                ),
                reproduction_steps=[
                    f"for i in $(seq 1 100); do",
                    f"  curl -X POST {url} -d 'username=admin&password=password$i';",
                    "done",
                ],
                remediation=(
                    "Implement rate limiting: max 5-10 attempts per IP per minute. "
                    "Use progressive delays, CAPTCHA, or account lockout after failures. "
                    "Return 429 Too Many Requests with Retry-After header."
                ),
                references=["CWE-307", "OWASP API4:2023"],
                evidence=ev,
                cvss_v31_vector=CVSS_NO_RATE,
                mitre_attack=["TA0006/T1110"],
                target=target,
                url=url,
            )


class TestApiRateCheck:
    def test_sensitive_paths_not_empty(self) -> None:
        assert len(SENSITIVE_PATHS) >= 5

    def test_rate_limit_headers(self) -> None:
        assert "X-RateLimit-Limit" in RATE_LIMIT_HEADERS
        assert "Retry-After" in RATE_LIMIT_HEADERS
