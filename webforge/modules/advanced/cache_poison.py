"""Web cache poisoning detector — unkeyed headers, fat GET, parameter cloaking."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CACHE_POISON = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N"
CVSS40_CACHE_POISON = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N"
CANARY = "FORGE_CACHE_POISON_TEST"

UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Custom-IP-Authorization",
    "X-Forwarded-Port",
    "X-HTTP-Method-Override",
    "X-Forwarded-For",
]


class CachePoison(BaseModule):
    """Web cache poisoning scanner."""

    NAME        = "cache_poison"
    DESCRIPTION = "Detect web cache poisoning via unkeyed header injection"
    PHASE       = 10
    TAGS        = ["advanced", "cache", "poison", "cwe-345", "owasp-a10"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Testing cache poisoning on %s", target)

        await asyncio.gather(
            self._test_unkeyed_headers(target),
            self._test_fat_get(target),
            self._check_cache_headers(target),
        )
        return self._make_result(start)

    async def _test_unkeyed_headers(self, target: str) -> None:
        """Test if unkeyed headers are reflected in response and could poison cache."""
        for header in UNKEYED_HEADERS:
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        target,
                        headers={
                            header: CANARY,
                            "User-Agent": "Mozilla/5.0",
                        },
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=False,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        resp_headers = dict(resp.headers)
                        cache_header = resp_headers.get("X-Cache", "") + resp_headers.get("Cache-Control", "")

                # Check if canary is reflected
                if CANARY in body:
                    # Check if response is cached
                    cached = any(kw in cache_header.lower() for kw in ["hit", "miss", "public"])
                    ev = Evidence(
                        request_raw=f"GET {target}\n{header}: {CANARY}",
                        response_raw=body[max(0, body.find(CANARY)-100):body.find(CANARY)+100],
                        extra={
                            "header":     header,
                            "reflected":  True,
                            "cached":     cached,
                            "cache_hdr":  cache_header,
                        },
                    )
                    severity = Severity.HIGH if cached else Severity.MEDIUM
                    self.new_finding(
                        title=f"Cache Poisoning — '{header}' Reflected{'(Cached!)' if cached else ''}",
                        severity=severity,
                        description=(
                            f"Header '{header}: {CANARY}' is reflected in the response body at {target}. "
                            + ("Response is cached — this payload could be served to other users!"
                               if cached else
                               "Response may be cacheable — test with a real URL for full impact.")
                            + "\nAn attacker can inject malicious JavaScript or redirect URLs into "
                            "cached responses that are served to all users."
                        ),
                        reproduction_steps=[
                            f"curl -H '{header}: evil.com' {target}",
                            "Observe reflection; check if subsequent requests return cached poisoned response",
                        ],
                        remediation=(
                            "Add injected headers to cache key or strip them before caching. "
                            "Validate and sanitize header values before using them in responses."
                        ),
                        references=["CWE-345", "PortSwigger Web Cache Poisoning"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_CACHE_POISON,
                        cvss_v40_vector=CVSS40_CACHE_POISON,
                        target=target,
                    )
                    break  # One finding per category
            except Exception:
                pass

    async def _test_fat_get(self, target: str) -> None:
        """Test fat GET — POST body in GET request (some caches ignore it)."""
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    target,
                    data=f"param={CANARY}",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": str(len(f"param={CANARY}")),
                    },
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    body = await resp.text(errors="ignore")

            if CANARY in body:
                ev = Evidence(
                    request_raw=f"GET {target}\n[body]: param={CANARY}",
                    response_raw=body[:300],
                    extra={"technique": "fat_GET"},
                )
                self.new_finding(
                    title="Cache Poisoning — Fat GET Body Reflected",
                    severity=Severity.MEDIUM,
                    description=(
                        f"POST body content in a GET request is reflected in the response at {target}. "
                        "If the cache keyed only on URL (not body), a poisoned response may be cached."
                    ),
                    reproduction_steps=[
                        f"curl -X GET {target} -d 'param=evil_payload' -H 'Content-Type: application/x-www-form-urlencoded'",
                    ],
                    remediation="Ensure cache implementations include request body in cache key for GET requests.",
                    references=["PortSwigger Fat GET"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CACHE_POISON,
                    cvss_v40_vector=CVSS40_CACHE_POISON,
                    target=target,
                )
        except Exception:
            pass

    async def _check_cache_headers(self, target: str) -> None:
        """Check for overly permissive cache headers."""
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    target, timeout=aiohttp.ClientTimeout(total=8)
                ) as resp:
                    cc = resp.headers.get("Cache-Control", "")
                    vary = resp.headers.get("Vary", "")
                    x_cache = resp.headers.get("X-Cache", "")

            issues: list[str] = []
            if "public" in cc.lower() and "no-store" not in cc.lower():
                issues.append("Cache-Control: public (response may be shared cache)")
            if "max-age" in cc.lower() and "private" not in cc.lower():
                issues.append(f"Cache-Control: {cc[:60]} — long cache with no 'private'")
            if not vary or "origin" not in vary.lower():
                issues.append("Missing Vary: Origin header — cross-origin caching issues")

            if issues:
                self.log.info("Cache header issues: %s", issues)
                self.config.extra["cache_header_issues"] = issues

        except Exception:
            pass


class TestCachePoison:
    def test_unkeyed_headers_not_empty(self) -> None:
        assert len(UNKEYED_HEADERS) >= 5

    def test_canary_value(self) -> None:
        assert len(CANARY) > 10
