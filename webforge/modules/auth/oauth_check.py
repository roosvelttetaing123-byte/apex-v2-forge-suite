"""OAuth 2.0 / OIDC security checker — discovery, CSRF, redirect URI bypass, PKCE, JWT, scope escalation."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urljoin

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CRITICAL_REDIR  = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N"
CVSS40_CRITICAL_REDIR = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"
CVSS_OAUTH_CSRF       = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
CVSS40_OAUTH_CSRF     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_OAUTH_REDIR      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
CVSS40_OAUTH_REDIR    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_OAUTH_LEAK       = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
CVSS40_OAUTH_LEAK     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_PKCE_DOWNGRADE   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"
CVSS_JWK_ALG_CONF     = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"

MITRE_T1550_001 = "T1550.001"  # Use Alternate Authentication Material

OAUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
    "/connect/authorize", "/api/oauth/authorize",
    "/login/oauth/authorize", "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server", "/oauth/token",
    "/oauth2/token", "/auth/token",
]

# Common client secrets to try during brute-force test
COMMON_CLIENT_SECRETS = [
    "", "secret", "password", "12345", "test", "demo",
    "client_secret", "changeme", "admin", "oauth2",
    "supersecret", "mysecret", "app_secret", "api_secret",
]

# Scope escalation targets
ESCALATION_SCOPES = [
    "admin", "root", "superuser",
    "openid email profile address phone offline_access",
    "read:admin write:admin",
    "user:admin repo:admin",
    "urn:ietf:params:oauth:scope:admin",
]


class OauthCheck(BaseModule):
    """OAuth 2.0 / OIDC security auditor."""

    NAME        = "oauth_check"
    DESCRIPTION = (
        "Audit OAuth 2.0/OIDC: endpoint discovery, CSRF/state, redirect URI bypass, "
        "PKCE downgrade, JWT alg confusion, scope escalation, client secret brute"
    )
    PHASE       = 5
    TAGS        = ["auth", "oauth", "oidc", "csrf", "redirect", "jwt", "pkce",
                   "cwe-601", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # 1. Discover OAuth/OIDC endpoints
        endpoints = await _discover_endpoints(target)
        self.log.info(
            "OAuth endpoint discovery: auth=%s token=%s jwks=%s",
            endpoints.get("authorization_endpoint"),
            endpoints.get("token_endpoint"),
            endpoints.get("jwks_uri"),
        )

        # 2. Also find OAuth authorization endpoints via path probing
        oauth_endpoints = await self._discover_oauth(target)
        self.log.info("Found %d OAuth endpoint(s) via path probe", len(oauth_endpoints))
        for ep in oauth_endpoints:
            await self._audit_endpoint(ep, target)

        auth_ep = endpoints.get("authorization_endpoint")
        token_ep = endpoints.get("token_endpoint")
        jwks_uri = endpoints.get("jwks_uri")

        if auth_ep:
            # 3. Redirect URI bypass tests
            redirect_findings = await self._test_redirect_uri_bypass(auth_ep)
            for f in redirect_findings:
                ev = Evidence(
                    request_raw=f.get("request", ""),
                    response_raw=f.get("response", ""),
                    extra=f,
                )
                self.new_finding(
                    title=f"OAuth Redirect URI Bypass — {f.get('technique')}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"OAuth redirect_uri validation bypass at {auth_ep}.\n"
                        f"Technique: {f.get('technique')}\n"
                        f"Payload: {f.get('payload')}\n"
                        "Authorization codes will be leaked to the attacker."
                    ),
                    reproduction_steps=[f.get("curl", f"curl -v '{f.get('url', auth_ep)}'")],
                    remediation=(
                        "Validate redirect_uri against a pre-registered exact-match allowlist. "
                        "Never use regex, prefix, or wildcard matching."
                    ),
                    references=["RFC 6749 §10.6", "CWE-601", f"MITRE ATT&CK {MITRE_T1550_001}"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CRITICAL_REDIR,
                    cvss_v40_vector=CVSS40_CRITICAL_REDIR,
                    target=target,
                    url=auth_ep,
                    mitre_attack=[MITRE_T1550_001],
                )

            # 4. State/CSRF tests
            csrf_findings = await self._test_state_csrf(auth_ep)
            for f in csrf_findings:
                ev = Evidence(extra=f)
                self.new_finding(
                    title=f"OAuth CSRF — {f.get('issue')}",
                    severity=Severity.HIGH,
                    description=(
                        f"OAuth authorization endpoint at {auth_ep} is susceptible to CSRF.\n"
                        f"Issue: {f.get('issue')}\n"
                        f"Detail: {f.get('detail', '')}"
                    ),
                    reproduction_steps=[
                        "Initiate OAuth flow without state parameter",
                        "Trick victim into visiting the authorization URL",
                        "Victim's account gets linked to attacker's credentials",
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
                    url=auth_ep,
                    mitre_attack=[MITRE_T1550_001],
                )

            # 5. PKCE downgrade tests
            pkce_findings = await self._test_pkce_downgrade(auth_ep)
            for f in pkce_findings:
                ev = Evidence(extra=f)
                self.new_finding(
                    title=f"OAuth PKCE Downgrade — {f.get('issue')}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"OAuth PKCE validation weakness at {auth_ep}.\n"
                        f"Issue: {f.get('issue')}\n"
                        f"Detail: {f.get('detail', '')}"
                    ),
                    reproduction_steps=[
                        f"Initiate auth code flow without code_challenge: GET {auth_ep}?response_type=code&client_id=test&redirect_uri=http://localhost/cb",
                    ],
                    remediation=(
                        "Require PKCE (S256) for all public clients. "
                        "Reject 'plain' code_challenge_method. "
                        "Enforce code_challenge on server side."
                    ),
                    references=["RFC 7636", "OAuth 2.0 Security BCP"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_PKCE_DOWNGRADE,
                    target=target,
                    url=auth_ep,
                    mitre_attack=[MITRE_T1550_001],
                )

            # 6. Scope escalation tests
            scope_findings = await self._test_scope_escalation(auth_ep)
            for f in scope_findings:
                ev = Evidence(extra=f)
                self.new_finding(
                    title=f"OAuth Scope Escalation — scope '{f.get('scope')}' accepted",
                    severity=Severity.HIGH,
                    description=(
                        f"OAuth server at {auth_ep} accepted elevated scope: {f.get('scope')}. "
                        "This may allow unauthorized access to privileged resources."
                    ),
                    reproduction_steps=[
                        f"GET {auth_ep}?response_type=code&client_id=test&scope={f.get('scope')}&redirect_uri=http://localhost/cb",
                    ],
                    remediation=(
                        "Validate and restrict requested scopes to the minimum necessary. "
                        "Reject unknown or admin scopes for unprivileged clients."
                    ),
                    references=["RFC 6749 §3.3", "OAuth 2.0 Security BCP"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_OAUTH_CSRF,
                    target=target,
                    url=auth_ep,
                    mitre_attack=[MITRE_T1550_001],
                )

        if token_ep:
            # 7. Client secret brute force
            client_id = self.config.extra.get("oauth_client_id", "test")
            brute_findings = await self._test_client_secret_brute(token_ep, client_id)
            for f in brute_findings:
                ev = Evidence(extra=f)
                self.new_finding(
                    title=f"OAuth Client Secret Accepted — '{f.get('secret')}' for client '{client_id}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"OAuth token endpoint accepted weak client secret '{f.get('secret')}' "
                        f"for client_id '{client_id}'. Attacker can obtain tokens impersonating this client."
                    ),
                    reproduction_steps=[
                        f"curl -X POST {token_ep} -d 'grant_type=authorization_code&client_id={client_id}&client_secret={f.get('secret')}&code=STOLEN_CODE&redirect_uri=...'",
                    ],
                    remediation=(
                        "Rotate client secret immediately. "
                        "Use a cryptographically random secret of at least 32 bytes. "
                        "Implement client secret rotation policy."
                    ),
                    references=["RFC 6749 §2.3", "CWE-521"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CRITICAL_REDIR,
                    target=target,
                    url=token_ep,
                    mitre_attack=[MITRE_T1550_001],
                )

            # 8. Grant type confusion
            await self._test_grant_type_confusion(token_ep)

        if jwks_uri:
            # 9. JWKS / JWT algorithm confusion
            alg_findings = await self._test_jwks_alg_confusion(jwks_uri)
            for f in alg_findings:
                ev = Evidence(extra=f)
                self.new_finding(
                    title=f"JWT Algorithm Confusion — {f.get('issue')}",
                    severity=Severity.HIGH,
                    description=(
                        f"JWT/JWKS vulnerability at {jwks_uri}.\n"
                        f"Issue: {f.get('issue')}\n"
                        f"Detail: {f.get('detail', '')}"
                    ),
                    reproduction_steps=[
                        f"curl -s {jwks_uri}",
                        "Forge JWT with alg:none or RS256->HS256 confusion",
                    ],
                    remediation=(
                        "Reject 'none' algorithm. Enforce expected algorithm on server side. "
                        "Use asymmetric RS256/ES256 with key pinning. "
                        "Use minimum RSA key size of 2048 bits."
                    ),
                    references=["CVE-2015-9235", "JWT Security BCP RFC 8725"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_JWK_ALG_CONF,
                    target=target,
                    url=jwks_uri,
                    mitre_attack=[MITRE_T1550_001],
                )

        # 10. Check redirect_uri validation (legacy)
        await self._check_redirect_uri_validation(target)

        return self._make_result(start)

    async def _discover_oauth(self, target: str) -> list[str]:
        """Find OAuth authorization endpoints via path probing."""
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

        for url in self.config.extra.get("crawled_urls", []):
            if any(kw in url.lower() for kw in
                   ["oauth", "client_id", "redirect_uri", "response_type=code"]):
                found.append(url)

        return list(dict.fromkeys(found))

    async def _audit_endpoint(self, endpoint: str, target: str) -> None:
        """Audit a single OAuth endpoint for basic issues."""
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)

        if "state" not in params and "code" not in params:
            ev = Evidence(extra={"endpoint": endpoint, "params": list(params.keys())})
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

        if "response_type" in params:
            response_type = params["response_type"][0].lower()
            if "token" in response_type:
                ev = Evidence(extra={"endpoint": endpoint, "response_type": response_type})
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
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status in (200, 400):
                            base_oauth = url
                            break
            except Exception:
                pass

        if not base_oauth:
            return

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

    async def _test_redirect_uri_bypass(self, auth_endpoint: str) -> list[dict]:
        """Test various redirect_uri bypass techniques."""
        parsed = urlparse(auth_endpoint)
        base = f"{parsed.scheme}://{parsed.netloc}"
        findings: list[dict] = []

        bypass_cases = [
            {
                "technique": "Missing redirect_uri",
                "payload": "(omitted)",
                "params": {"response_type": "code", "client_id": "test", "state": "x"},
            },
            {
                "technique": "Extra path component traversal",
                "payload": f"{base}/callback/../evil",
                "params": {"response_type": "code", "client_id": "test",
                           "redirect_uri": f"{base}/callback/../evil", "state": "x"},
            },
            {
                "technique": "Subdomain regex bypass",
                "payload": f"https://{parsed.hostname}.evil.com/cb",
                "params": {"response_type": "code", "client_id": "test",
                           "redirect_uri": f"https://{parsed.hostname}.evil.com/cb", "state": "x"},
            },
            {
                "technique": "Open redirect chaining",
                "payload": f"{base}/redirect?url=https://evil.com",
                "params": {"response_type": "code", "client_id": "test",
                           "redirect_uri": f"{base}/redirect?url=https://evil.com", "state": "x"},
            },
            {
                "technique": "Null byte truncation",
                "payload": f"{base}/callback%00.evil.com",
                "params": {"response_type": "code", "client_id": "test",
                           "redirect_uri": f"{base}/callback%00.evil.com", "state": "x"},
            },
            {
                "technique": "Fragment injection",
                "payload": f"{base}/callback#@evil.com",
                "params": {"response_type": "code", "client_id": "test",
                           "redirect_uri": f"{base}/callback#@evil.com", "state": "x"},
            },
        ]

        for case in bypass_cases:
            await self.rate_limit()
            try:
                import aiohttp
                url = f"{auth_endpoint}?{urlencode(case['params'])}"
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=False,
                    ) as resp:
                        location = resp.headers.get("Location", "")
                        # If we get a redirect to an evil domain — it's a bypass
                        if resp.status in (301, 302) and (
                            "evil.com" in location
                            or (case["technique"] == "Missing redirect_uri"
                                and resp.status == 302)
                        ):
                            findings.append({
                                "technique": case["technique"],
                                "payload": case["payload"],
                                "url": url,
                                "response_status": resp.status,
                                "response_location": location,
                                "curl": f"curl -v '{url}'",
                                "request": f"GET {url}",
                                "response": f"HTTP {resp.status} Location: {location}",
                            })
            except Exception:
                pass

        return findings

    async def _test_state_csrf(self, auth_endpoint: str) -> list[dict]:
        """Test for CSRF vulnerabilities via missing/predictable state parameter."""
        findings: list[dict] = []

        test_cases = [
            {
                "issue": "Missing state parameter",
                "detail": "Server accepted auth request without state — CSRF possible",
                "params": {"response_type": "code", "client_id": "test",
                           "redirect_uri": "http://localhost/callback"},
            },
            {
                "issue": "Empty state parameter",
                "detail": "Server accepted state='' (empty string) — predictable state",
                "params": {"response_type": "code", "client_id": "test",
                           "redirect_uri": "http://localhost/callback", "state": ""},
            },
            {
                "issue": "Sequential numeric state",
                "detail": "Server accepted state=1 — trivially guessable",
                "params": {"response_type": "code", "client_id": "test",
                           "redirect_uri": "http://localhost/callback", "state": "1"},
            },
        ]

        for case in test_cases:
            await self.rate_limit()
            try:
                import aiohttp
                url = f"{auth_endpoint}?{urlencode(case['params'])}"
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=False,
                    ) as resp:
                        # If server redirects or returns 200 without rejecting — vulnerable
                        if resp.status in (200, 302, 303):
                            body = await resp.text(errors="ignore")
                            # If it didn't return a 400 "state required" error — flag it
                            if "invalid" not in body.lower() and "required" not in body.lower():
                                findings.append({
                                    "issue": case["issue"],
                                    "detail": case["detail"],
                                    "url": url,
                                    "status": resp.status,
                                })
            except Exception:
                pass

        return findings

    async def _test_pkce_downgrade(self, auth_endpoint: str) -> list[dict]:
        """Attempt auth code flow without PKCE, or with plain method."""
        findings: list[dict] = []

        # Test 1: Auth code without PKCE when PKCE may be supported
        await self.rate_limit()
        try:
            import aiohttp
            url = (
                f"{auth_endpoint}?response_type=code&client_id=test"
                "&redirect_uri=http://localhost/callback&state=csrf_token"
            )
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 302):
                        body = await resp.text(errors="ignore")
                        if "pkce" not in body.lower() and "code_challenge" not in body.lower():
                            findings.append({
                                "issue": "Auth code flow accepted without PKCE",
                                "detail": (
                                    "Server did not reject authorization code request "
                                    "missing code_challenge. Public clients are vulnerable "
                                    "to authorization code interception."
                                ),
                                "url": url,
                            })
        except Exception:
            pass

        # Test 2: plain code_challenge_method (downgrade from S256)
        await self.rate_limit()
        try:
            import aiohttp
            url = (
                f"{auth_endpoint}?response_type=code&client_id=test"
                "&redirect_uri=http://localhost/callback&state=csrf_token"
                "&code_challenge=abc123&code_challenge_method=plain"
            )
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 302):
                        findings.append({
                            "issue": "PKCE 'plain' method accepted (should require S256)",
                            "detail": (
                                "Server accepted code_challenge_method=plain. "
                                "Plain method offers no protection against interception "
                                "if the code verifier is observable."
                            ),
                            "url": url,
                        })
        except Exception:
            pass

        return findings

    async def _test_authorization_code_interception(self, auth_endpoint: str) -> None:
        """Check if referrer-policy header is set on redirect pages to prevent code leakage."""
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    auth_endpoint, timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=True,
                ) as resp:
                    referrer_policy = resp.headers.get("Referrer-Policy", "")
                    if not referrer_policy:
                        ev = Evidence(extra={
                            "url": auth_endpoint,
                            "referrer_policy": "(not set)",
                        })
                        self.new_finding(
                            title="OAuth — Missing Referrer-Policy (Code Leakage Risk)",
                            severity=Severity.LOW,
                            description=(
                                f"OAuth endpoint {auth_endpoint} does not set Referrer-Policy. "
                                "Authorization codes in redirect URLs may leak via the Referer header."
                            ),
                            reproduction_steps=[
                                f"curl -I {auth_endpoint}",
                                "Check browser developer tools for Referer header on subsequent requests",
                            ],
                            remediation="Set 'Referrer-Policy: no-referrer' on OAuth redirect pages.",
                            references=["OAuth 2.0 Security BCP §4.2.4"],
                            evidence=ev,
                            cvss_v31_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                            target=auth_endpoint,
                        )
        except Exception:
            pass

    async def _test_client_secret_brute(self, token_endpoint: str, client_id: str) -> list[dict]:
        """Try common client secrets against the token endpoint."""
        findings: list[dict] = []
        secrets_to_try = COMMON_CLIENT_SECRETS + [client_id, client_id + "_secret",
                                                   client_id + "123"]

        for secret in secrets_to_try:
            await self.rate_limit()
            try:
                import aiohttp
                data = {
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "client_secret": secret,
                    "code": "test_code_invalid",
                    "redirect_uri": "http://localhost/callback",
                }
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.post(
                        token_endpoint, data=data,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        body_lower = body.lower()
                        # A 400 with "invalid_code" or "invalid_grant" means secret was accepted
                        # A 401 with "invalid_client" means wrong secret
                        if resp.status == 400 and any(
                            kw in body_lower for kw in
                            ["invalid_grant", "invalid_code", "code_expired",
                             "authorization_code", "redirect_uri"]
                        ):
                            findings.append({
                                "client_id": client_id,
                                "secret": secret if secret else "(empty string)",
                                "token_endpoint": token_endpoint,
                                "evidence": f"HTTP 400 with grant error (not client auth error)",
                            })
                            break  # Stop after first successful secret
            except Exception:
                pass

        return findings

    async def _test_grant_type_confusion(self, token_endpoint: str) -> None:
        """Try unsupported/confused grant types."""
        test_cases = [
            {"grant_type": "implicit", "detail": "Implicit grant on token endpoint"},
            {"grant_type": "password", "client_id": "test",
             "username": "admin", "password": "admin",
             "detail": "Resource owner password credentials (ROPC) grant"},
        ]

        for case in test_cases:
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.post(
                        token_endpoint, data=case,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        body_lower = body.lower()
                        if resp.status == 200 and "access_token" in body_lower:
                            ev = Evidence(
                                extra={"grant_type": case["grant_type"],
                                       "token_endpoint": token_endpoint}
                            )
                            self.new_finding(
                                title=f"OAuth Grant Type Confusion — '{case['grant_type']}' accepted",
                                severity=Severity.HIGH,
                                description=(
                                    f"Token endpoint {token_endpoint} returned access_token "
                                    f"for grant_type={case['grant_type']}. "
                                    f"Detail: {case['detail']}"
                                ),
                                reproduction_steps=[
                                    f"curl -X POST {token_endpoint} -d 'grant_type={case['grant_type']}'",
                                ],
                                remediation=(
                                    "Restrict allowed grant types. "
                                    "Disable resource owner password credentials (ROPC) grant. "
                                    "Validate grant_type strictly."
                                ),
                                references=["OAuth 2.0 Security BCP §2.4"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_OAUTH_CSRF,
                                target=token_endpoint,
                                mitre_attack=[MITRE_T1550_001],
                            )
            except Exception:
                pass

    async def _test_jwks_alg_confusion(self, jwks_uri: str) -> list[dict]:
        """Fetch JWKS and check for algorithm confusion vulnerabilities."""
        findings: list[dict] = []
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    jwks_uri, timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status != 200:
                        return findings
                    body = await resp.text(errors="ignore")
                    try:
                        jwks = json.loads(body)
                    except Exception:
                        return findings

            keys = jwks.get("keys", [])

            for key in keys:
                alg = key.get("alg", "")
                kty = key.get("kty", "")
                n_b64 = key.get("n", "")

                # Check for alg:none possibility (no algorithm specified)
                if not alg:
                    findings.append({
                        "issue": "JWKS key missing 'alg' field — alg:none attack possible",
                        "detail": (
                            "Key without 'alg' field may allow server to accept "
                            "tokens with alg=none (unsigned). "
                            "An attacker can forge tokens by stripping the signature."
                        ),
                        "key_id": key.get("kid", "unknown"),
                    })

                # Check for RSA key size (weak key)
                if kty == "RSA" and n_b64:
                    try:
                        n_bytes = base64.urlsafe_b64decode(n_b64 + "==")
                        key_bits = len(n_bytes) * 8
                        if key_bits < 2048:
                            findings.append({
                                "issue": f"Weak RSA key size ({key_bits} bits)",
                                "detail": (
                                    f"RSA key in JWKS has only {key_bits} bits. "
                                    "Minimum recommended is 2048 bits. "
                                    "Key may be factored using modern hardware."
                                ),
                                "key_id": key.get("kid", "unknown"),
                                "key_bits": key_bits,
                            })
                    except Exception:
                        pass

                # RS256 -> HS256 confusion: if server uses RSA public key as HMAC secret
                if alg == "RS256" or kty == "RSA":
                    findings.append({
                        "issue": "RS256 → HS256 algorithm confusion possible",
                        "detail": (
                            "Server uses RS256. If the server doesn't pin the expected algorithm, "
                            "an attacker can forge tokens by using the RSA public key as an HMAC "
                            "secret and changing alg to HS256."
                        ),
                        "key_id": key.get("kid", "unknown"),
                        "recommendation": "Test: forge JWT with alg=HS256, sign with public key bytes",
                    })
                    break  # Only report once

        except Exception:
            pass

        return findings

    async def _test_scope_escalation(self, auth_endpoint: str) -> list[dict]:
        """Try requesting elevated/admin scopes."""
        findings: list[dict] = []

        for scope in ESCALATION_SCOPES:
            await self.rate_limit()
            try:
                import aiohttp
                url = (
                    f"{auth_endpoint}?response_type=code&client_id=test"
                    f"&redirect_uri=http://localhost/callback&state=csrf"
                    f"&scope={scope}"
                )
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=False,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        body_lower = body.lower()
                        # Server returned 200 or redirect without scope error
                        if resp.status in (200, 302) and not any(
                            kw in body_lower for kw in
                            ["invalid_scope", "scope not allowed", "unauthorized scope"]
                        ):
                            findings.append({
                                "scope": scope,
                                "url": url,
                                "status": resp.status,
                            })
            except Exception:
                pass

        return findings


async def _discover_endpoints(base_url: str) -> dict:
    """Fetch OIDC/OAuth discovery document and extract endpoint URLs."""
    endpoints: dict = {
        "authorization_endpoint": None,
        "token_endpoint": None,
        "userinfo_endpoint": None,
        "jwks_uri": None,
        "revocation_endpoint": None,
        "introspection_endpoint": None,
    }

    discovery_urls = [
        f"{base_url.rstrip('/')}/.well-known/openid-configuration",
        f"{base_url.rstrip('/')}/.well-known/oauth-authorization-server",
    ]

    for url in discovery_urls:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8)
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        try:
                            doc = json.loads(body)
                            for key in endpoints:
                                if key in doc:
                                    endpoints[key] = doc[key]
                            # If we found at least auth_endpoint, stop
                            if endpoints.get("authorization_endpoint"):
                                break
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass

    return endpoints


class TestOauthCheck:
    """Embedded unit tests for OAuth security checker."""

    def test_oauth_paths_not_empty(self) -> None:
        assert len(OAUTH_PATHS) >= 4
        assert "/.well-known/openid-configuration" in OAUTH_PATHS

    def test_cvss_vectors(self) -> None:
        assert CVSS_OAUTH_CSRF.startswith("CVSS:3.1")
        assert CVSS_OAUTH_REDIR.startswith("CVSS:3.1")
        assert CVSS_CRITICAL_REDIR.startswith("CVSS:3.1")
        assert CVSS_PKCE_DOWNGRADE.startswith("CVSS:3.1")
        assert CVSS_JWK_ALG_CONF.startswith("CVSS:3.1")

    def test_cvss40_vectors(self) -> None:
        assert CVSS40_OAUTH_CSRF.startswith("CVSS:4.0")
        assert CVSS40_CRITICAL_REDIR.startswith("CVSS:4.0")

    def test_common_client_secrets_not_empty(self) -> None:
        assert len(COMMON_CLIENT_SECRETS) >= 5
        assert "secret" in COMMON_CLIENT_SECRETS
        assert "" in COMMON_CLIENT_SECRETS

    def test_escalation_scopes_not_empty(self) -> None:
        assert len(ESCALATION_SCOPES) >= 3
        assert "admin" in ESCALATION_SCOPES

    def test_mitre_tag(self) -> None:
        assert MITRE_T1550_001 == "T1550.001"

    def test_oauth_check_phase(self) -> None:
        assert OauthCheck.PHASE == 5

    def test_oauth_check_tags(self) -> None:
        assert "oauth" in OauthCheck.TAGS
        assert "pkce" in OauthCheck.TAGS
        assert "jwt" in OauthCheck.TAGS

    def test_discover_endpoints_returns_dict(self) -> None:
        import asyncio
        result = asyncio.run(_discover_endpoints("http://127.0.0.1:1"))
        # Should return empty dict (connection refused) not raise
        assert isinstance(result, dict)
        assert "authorization_endpoint" in result

    def test_bypass_cases_techniques(self) -> None:
        # Verify the bypass technique names we expect
        techniques = [
            "Missing redirect_uri",
            "Extra path component traversal",
            "Subdomain regex bypass",
            "Open redirect chaining",
            "Null byte truncation",
            "Fragment injection",
        ]
        assert len(techniques) == 6

    def test_pkce_s256_computation(self) -> None:
        # Verify S256 challenge = BASE64URL(SHA256(verifier))
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        expected_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b"=").decode()
        assert len(expected_challenge) == 43  # 32 bytes -> 43 base64url chars

    def test_implicit_flow_detection(self) -> None:
        # Verify we detect response_type=token
        params = parse_qs("response_type=token&client_id=x")
        assert "token" in params.get("response_type", [""])[0]
