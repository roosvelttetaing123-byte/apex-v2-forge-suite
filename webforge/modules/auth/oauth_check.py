"""OAuth 2.0 security checker — CSRF, open redirect, token leakage."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_OAUTH_CSRF    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
CVSS40_OAUTH_CSRF  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_OAUTH_REDIR   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
CVSS40_OAUTH_REDIR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_OAUTH_LEAK    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
CVSS40_OAUTH_LEAK  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
OAUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
    "/connect/authorize", "/api/oauth/authorize",
    "/login/oauth/authorize", "/.well-known/openid-configuration",
]


class OauthCheck(BaseModule):
    """OAuth 2.0 security auditor."""

    NAME        = "oauth_check"
    DESCRIPTION = "Audit OAuth 2.0 flows: CSRF (missing state), open redirect, token in URL"
    PHASE       = 5
    TAGS        = ["auth", "oauth", "csrf", "redirect", "cwe-601", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        oauth_endpoints = await self._discover_oauth(target)
        self.log.info("Found %d OAuth endpoint(s)", len(oauth_endpoints))

        for ep in oauth_endpoints:
            await self._audit_endpoint(ep, target)

        # Check redirect_uri validation across the site
        await self._check_redirect_uri_validation(target)

        return self._make_result(start)

    async def _discover_oauth(self, target: str) -> list[str]:
        """Find OAuth authorization endpoints."""
        found: list[str] = []
        for path in OAUTH_PATHS:
            await self.rate_limit()
            url = f"{target}{path}"
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (200, 302, 400, 401, 403):
                            body = await resp.text(errors="ignore")
                            if any(kw in body.lower() for kw in
                                   ["oauth", "client_id", "redirect_uri", "response_type",
                                    "authorization", "openid"]):
                                found.append(url)
            except Exception:
                pass

        # Also check crawled URLs for OAuth flows
        for url in self.config.extra.get("crawled_urls", []):
            if any(kw in url.lower() for kw in
                   ["oauth", "client_id", "redirect_uri", "response_type=code"]):
                found.append(url)

        return list(dict.fromkeys(found))

    async def _audit_endpoint(self, endpoint: str, target: str) -> None:
        """Audit a single OAuth endpoint."""
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)

        # Check for missing state parameter (CSRF)
        if "state" not in params and "code" not in params:
            ev = Evidence(
                extra={"endpoint": endpoint, "params": list(params.keys())}
            )
            self.new_finding(
                title=f"OAuth — Missing 'state' Parameter (CSRF Risk) ({parsed.path})",
                severity=Severity.HIGH,
                description=(
                    f"OAuth authorization request at {endpoint} does not include a 'state' parameter. "
                    "Without state, an attacker can initiate an OAuth flow and trick a victim "
                    "into completing it (CSRF on OAuth), linking the victim's account to the attacker's."
                ),
                reproduction_steps=[
                    "Initiate OAuth flow without state parameter",
                    "Capture authorization URL",
                    "Trick victim into visiting URL",
                    "Victim's session gets associated with attacker's account",
                ],
                remediation=(
                    "Always include a cryptographically random 'state' parameter. "
                    "Validate state on callback before exchanging authorization code."
                ),
                references=["RFC 6749 §10.12", "CWE-352"],
                evidence=ev,
                cvss_v31_vector=CVSS_OAUTH_CSRF,
                cvss_v40_vector=CVSS40_OAUTH_CSRF,
                target=target,
                url=endpoint,
            )

        # Check for token in URL (response_type=token)
        if "response_type" in params:
            response_type = params["response_type"][0].lower()
            if "token" in response_type:
                ev = Evidence(
                    extra={"endpoint": endpoint, "response_type": response_type}
                )
                self.new_finding(
                    title="OAuth Implicit Flow — Access Token in URL Fragment",
                    severity=Severity.MEDIUM,
                    description=(
                        f"OAuth implicit flow (response_type=token) used at {endpoint}. "
                        "Access tokens in URL fragments are logged by browsers, proxies, "
                        "and server access logs. Use authorization code flow instead."
                    ),
                    reproduction_steps=["Check browser history, server logs for token leakage"],
                    remediation="Use authorization code flow with PKCE instead of implicit flow.",
                    references=["RFC 9700", "OAuth 2.0 Security BCP"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_OAUTH_LEAK,
                    cvss_v40_vector=CVSS40_OAUTH_LEAK,
                    target=target,
                    url=endpoint,
                )

    async def _check_redirect_uri_validation(self, target: str) -> None:
        """Test if redirect_uri is validated strictly."""
        base_oauth = None
        for path in OAUTH_PATHS[:3]:
            url = f"{target}{path}"
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status in (200, 400):
                            base_oauth = url
                            break
            except Exception:
                pass

        if not base_oauth:
            return

        # Test open redirect in redirect_uri
        evil_redirects = [
            "https://evil.com",
            f"{target.rstrip('/')}.evil.com",
            f"https://evil.com/{target}",
            f"{target}//../../../evil.com",
        ]

        for evil_uri in evil_redirects:
            await self.rate_limit()
            test_url = (
                f"{base_oauth}?response_type=code&client_id=test"
                f"&redirect_uri={evil_uri}&state=test"
            )
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        test_url, timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=False,
                    ) as resp:
                        location = resp.headers.get("Location", "")
                        if resp.status in (302, 301) and "evil.com" in location:
                            ev = Evidence(
                                request_raw=f"GET {test_url}",
                                response_raw=f"Location: {location}",
                                extra={"evil_redirect": evil_uri},
                            )
                            self.new_finding(
                                title="OAuth Open Redirect — redirect_uri Not Validated",
                                severity=Severity.HIGH,
                                description=(
                                    f"OAuth authorization endpoint redirects to attacker-controlled "
                                    f"URI: {evil_uri}. Authorization codes will be leaked to attacker."
                                ),
                                reproduction_steps=[f"curl -v '{test_url}'"],
                                remediation=(
                                    "Validate redirect_uri against a pre-registered exact match. "
                                    "Never use partial matching or wildcard URIs."
                                ),
                                references=["RFC 6749 §10.6", "CWE-601"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_OAUTH_REDIR,
                                cvss_v40_vector=CVSS40_OAUTH_REDIR,
                                target=target,
                                url=base_oauth,
                            )
                            return
            except Exception:
                pass


class TestOauthCheck:
    def test_oauth_paths_not_empty(self) -> None:
        assert len(OAUTH_PATHS) >= 4

    def test_cvss_vectors(self) -> None:
        assert CVSS_OAUTH_CSRF.startswith("CVSS:3.1")
        assert CVSS_OAUTH_REDIR.startswith("CVSS:3.1")
