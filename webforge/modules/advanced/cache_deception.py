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
from common.fp_reducer import FPReducer, Confidence

CVSS_CACHE_DECEPTION = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
CVSS40_CACHE_DECEPTION = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
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
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        # Detect SPA catch-all routing (Vercel, Netlify, etc.) — every path returns
        # the same index.html, which would flood the report with false positives.
        self._spa_fp = await self._spa_fingerprint(target)
        if self._spa_fp:
            self.log.info("SPA catch-all routing detected — will filter false positives")

        session_cookies = self.config.extra.get("session_cookies", {})
        if not session_cookies:
            self.log.info("No session cookies — testing without authentication")

        # Accumulate hits per base path so we emit ONE finding per path,
        # not one per (path × suffix) combination.
        self._path_hits: dict[str, list[str]] = {}
        self._path_evidence: dict[str, tuple[str, str]] = {}  # path → (url, body)
        self._hits_lock = asyncio.Lock()

        sem = asyncio.Semaphore(3)
        tasks = []
        for path in SENSITIVE_PATHS:
            for suffix in CACHEABLE_SUFFIXES[:5]:
                tasks.append(
                    self._test_cache_deception(target, path, suffix, session_cookies, sem)
                )

        await asyncio.gather(*tasks, return_exceptions=True)

        # Emit one consolidated finding per affected base path
        for path, suffixes in self._path_hits.items():
            first_url, first_body = self._path_evidence[path]
            self._emit_grouped_finding(target, path, suffixes, first_url, first_body)

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
            crafted_url = f"{target}{path}{suffix}"
            if not self.check_scope(crafted_url):
                return

            await self.rate_limit()
            try:
                import aiohttp

                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    cookies=cookies,
                ) as session:
                    async with session.get(
                        crafted_url,
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=True,
                    ) as resp1:
                        body1    = await resp1.text(errors="ignore")
                        status1  = resp1.status

                if status1 not in (200, 301, 302, 304):
                    return

                # Skip if the response is just the SPA catch-all shell —
                # that's not sensitive user data, it's the public app entry point.
                if self._is_spa_body(body1, getattr(self, "_spa_fp", None)):
                    return

                has_sensitive = any(
                    ind.lower() in body1.lower()
                    for ind in SENSITIVE_INDICATORS
                )
                if not has_sensitive:
                    return

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

                is_cached = self._is_cache_hit(headers2)
                contains_sensitive_unauth = any(
                    ind.lower() in body2.lower()
                    for ind in SENSITIVE_INDICATORS
                )

                if (is_cached or contains_sensitive_unauth) and status2 == 200:
                    # Accumulate per base path — emit one finding per path, not per suffix
                    async with self._hits_lock:
                        if path not in self._path_hits:
                            self._path_hits[path] = []
                            self._path_evidence[path] = (crafted_url, body2)
                        self._path_hits[path].append(suffix)

            except Exception:
                pass

    def _emit_grouped_finding(
        self,
        target: str,
        path: str,
        suffixes: list[str],
        first_url: str,
        first_body: str,
    ) -> None:
        """Emit one finding for a base path listing all triggered suffixes."""
        suffix_list = ", ".join(suffixes)
        ev = Evidence(
            request_raw=f"GET {first_url}",
            response_raw=first_body[:500],
            extra={
                "base_path": path,
                "triggered_suffixes": suffixes,
            },
        )
        self.new_finding(
            title=f"Web Cache Deception — {path} (suffixes: {suffix_list})",
            severity=Severity.HIGH,
            description=(
                f"Appending cacheable suffixes to '{path}' returns sensitive data "
                f"that may be served from cache to unauthenticated users.\n\n"
                f"Confirmed with suffixes: {suffix_list}\n\n"
                "Web cache deception occurs when:\n"
                f"1. The application serves sensitive content for '{path}.css' "
                "(treating the suffix as irrelevant)\n"
                "2. The CDN/cache stores the response because the suffix suggests "
                "a static resource\n"
                "3. An attacker who tricks the victim into visiting the crafted URL "
                "can fetch the cached response without authentication.\n\n"
                "Practical attack: send victim a phishing link to the crafted URL, "
                "cache stores their sensitive data, attacker retrieves it unauthenticated."
            ),
            reproduction_steps=[
                "# Step 1: Trick authenticated user into visiting:",
                f"curl -b 'session=<victim_session>' '{first_url}'",
                "# Step 2: Attacker retrieves cached response (no auth):",
                f"curl '{first_url}'",
                "# Repeat for each suffix: " + ", ".join(
                    f"{path}{s}" for s in suffixes
                ),
            ],
            remediation=(
                "Configure cache to use Cache-Control: no-store on all "
                "authenticated/sensitive responses. "
                "Ensure the application returns 404 for non-existent paths rather than "
                "falling back to the base path. "
                "Set Vary: Cookie so cached responses are user-specific. "
                "Normalize URL paths at the application layer before routing."
            ),
            references=[
                "CWE-525",
                "PortSwigger Web Cache Deception research",
                "https://portswigger.net/research/web-cache-deception-escalated",
            ],
            evidence=ev,
            cvss_v31_vector=CVSS_CACHE_DECEPTION,
            cvss_v40_vector=CVSS40_CACHE_DECEPTION,
            mitre_attack=["TA0009/T1530"],
            target=target,
            url=first_url,
        )

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
