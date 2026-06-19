"""Cookie security auditor — Secure, HttpOnly, SameSite, domain scope, session fixation."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_COOKIE_HTTP      = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_COOKIE_HTTP    = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_COOKIE_FLAGS     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
CVSS40_COOKIE_FLAGS   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_COOKIE_SAMESITE  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
CVSS40_COOKIE_SAMESITE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_COOKIE_DOMAIN    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_COOKIE_DOMAIN  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
SESSION_COOKIE_NAMES = re.compile(
    r"(session|sess|auth|token|user|login|jwt|access|refresh|remember|sid|uid|csrf)",
    re.IGNORECASE,
)


class CookieAudit(BaseModule):
    """Cookie security flags auditor."""

    NAME        = "cookie_audit"
    DESCRIPTION = "Audit cookie security: Secure, HttpOnly, SameSite flags on session cookies"
    PHASE       = 3
    TAGS        = ["headers", "cookies", "session", "cwe-614", "owasp-a02"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Auditing cookies on %s", target)
        cookies = await self._collect_cookies(target)

        if not cookies:
            self.log.info("No cookies observed")
            return self._make_result(start)

        for cookie in cookies:
            self._audit_cookie(cookie, target)

        return self._make_result(start)

    async def _collect_cookies(self, target: str) -> list[dict]:
        """Collect Set-Cookie headers from login/session-related endpoints."""
        import aiohttp
        cookies_found: list[dict] = []
        urls_to_check = [target] + [
            f"{target.rstrip('/')}/login",
            f"{target.rstrip('/')}/signin",
            f"{target.rstrip('/')}/auth",
            f"{target.rstrip('/')}/api/login",
            f"{target.rstrip('/')}/api/auth/login",
        ]

        for url in urls_to_check[:5]:
            if not self.check_scope(url):
                continue
            await self.rate_limit()
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    headers={"Accept-Encoding": "gzip, deflate"},
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True
                    ) as resp:
                        for header_val in resp.headers.getall("Set-Cookie", []):
                            parsed = self._parse_set_cookie(header_val, url)
                            if parsed:
                                cookies_found.append(parsed)
            except Exception:
                pass

        return cookies_found

    def _parse_set_cookie(self, header: str, url: str) -> dict | None:
        """Parse a Set-Cookie header into a structured dict."""
        parts = [p.strip() for p in header.split(";")]
        if not parts:
            return None
        name_val = parts[0]
        name  = name_val.split("=")[0].strip() if "=" in name_val else name_val
        value = name_val.split("=", 1)[1].strip() if "=" in name_val else ""

        attrs: dict[str, object] = {}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[p.strip().lower()] = True

        return {
            "name":      name,
            "value":     value,
            "raw":       header[:300],
            "secure":    "secure" in attrs,
            "httponly":  "httponly" in attrs,
            "samesite":  str(attrs.get("samesite", "")).lower(),
            "domain":    str(attrs.get("domain", "")),
            "path":      str(attrs.get("path", "/")),
            "expires":   attrs.get("expires") or attrs.get("max-age"),
            "url":       url,
        }

    def _audit_cookie(self, cookie: dict, target: str) -> None:
        name       = cookie["name"]
        is_session = bool(SESSION_COOKIE_NAMES.search(name))
        from urllib.parse import urlparse
        host = urlparse(target).netloc.split(":")[0]

        # 1. Missing Secure flag
        if not cookie["secure"]:
            sev = Severity.HIGH if is_session else Severity.MEDIUM
            ev = Evidence(
                response_raw=f"Set-Cookie: {cookie['raw']}",
                extra={"cookie_name": name, "is_session": is_session},
            )
            self.new_finding(
                title=f"Cookie Without Secure Flag — '{name}'",
                severity=sev,
                description=(
                    f"Cookie '{name}' {'(session cookie) ' if is_session else ''}"
                    "is missing the Secure flag. "
                    "The cookie can be transmitted over HTTP, enabling interception by MITM attackers."
                ),
                reproduction_steps=[
                    f"curl -I {cookie['url']} | grep Set-Cookie",
                    "Observe Secure flag is absent",
                    "Connect via HTTP to intercept the cookie",
                ],
                remediation="Set Secure flag on all cookies, especially session cookies.",
                references=["CWE-614", "OWASP Session Management Cheat Sheet"],
                evidence=ev,
                cvss_v31_vector=CVSS_COOKIE_HTTP,
                cvss_v40_vector=CVSS40_COOKIE_HTTP,
                mitre_attack=["TA0006/T1539"],
                target=target,
            )

        # 2. Missing HttpOnly flag (session cookies)
        if not cookie["httponly"] and is_session:
            ev = Evidence(
                response_raw=f"Set-Cookie: {cookie['raw']}",
                extra={"cookie_name": name},
            )
            self.new_finding(
                title=f"Session Cookie Without HttpOnly Flag — '{name}'",
                severity=Severity.MEDIUM,
                description=(
                    f"Session cookie '{name}' is missing the HttpOnly flag. "
                    "JavaScript can read this cookie, enabling session theft via XSS: "
                    "document.cookie exposes the value."
                ),
                reproduction_steps=[
                    "Execute XSS: document.cookie",
                    f"Observe cookie: {name}",
                ],
                remediation=(
                    "Set HttpOnly flag on all session cookies. "
                    "This prevents JavaScript from accessing the cookie."
                ),
                references=["CWE-1004", "OWASP A02:2021"],
                evidence=ev,
                cvss_v31_vector=CVSS_COOKIE_FLAGS,
                cvss_v40_vector=CVSS40_COOKIE_FLAGS,
                mitre_attack=["TA0006/T1539"],
                target=target,
            )

        # 3. SameSite checks
        samesite = cookie["samesite"]
        if is_session:
            if samesite == "none":
                # SameSite=None requires Secure — extra risk if no Secure flag
                if not cookie["secure"]:
                    ev = Evidence(
                        response_raw=f"Set-Cookie: {cookie['raw']}",
                        extra={"samesite": samesite, "secure": False},
                    )
                    self.new_finding(
                        title=f"Cookie SameSite=None Without Secure Flag — '{name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"Cookie '{name}' has SameSite=None but is missing the Secure flag. "
                            "SameSite=None is required to allow cross-site cookies, but without Secure, "
                            "modern browsers will reject or transmit it over HTTP, creating both a "
                            "security and compatibility issue."
                        ),
                        reproduction_steps=[
                            f"curl -I {cookie['url']} | grep Set-Cookie",
                        ],
                        remediation="Set both SameSite=None and Secure together, or change to SameSite=Lax.",
                        references=["CWE-614", "RFC 6265bis"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_COOKIE_HTTP,
                        cvss_v40_vector=CVSS40_COOKIE_HTTP,
                        target=target,
                    )
                else:
                    # SameSite=None with Secure — CSRF risk
                    ev = Evidence(
                        response_raw=f"Set-Cookie: {cookie['raw']}",
                        extra={"samesite": samesite},
                    )
                    self.new_finding(
                        title=f"Session Cookie SameSite=None (CSRF Risk) — '{name}'",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Session cookie '{name}' has SameSite=None. "
                            "This allows the cookie to be sent on cross-site requests, "
                            "re-enabling CSRF attacks. Only use SameSite=None for explicitly "
                            "cross-site use cases with proper CSRF protection."
                        ),
                        reproduction_steps=[
                            f"curl -I {cookie['url']} | grep Set-Cookie",
                            "Craft CSRF PoC targeting cross-site form submission",
                        ],
                        remediation=(
                            "Use SameSite=Lax or SameSite=Strict for session cookies. "
                            "Only use SameSite=None for third-party embeds with explicit CSRF tokens."
                        ),
                        references=["CWE-352", "OWASP CSRF Cheat Sheet"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_COOKIE_SAMESITE,
                        cvss_v40_vector=CVSS40_COOKIE_SAMESITE,
                        target=target,
                    )

            elif samesite not in ("strict", "lax"):
                # No SameSite attribute at all
                ev = Evidence(
                    response_raw=f"Set-Cookie: {cookie['raw']}",
                    extra={"samesite": samesite or "not set"},
                )
                self.new_finding(
                    title=f"Session Cookie Missing SameSite Attribute — '{name}'",
                    severity=Severity.LOW,
                    description=(
                        f"Session cookie '{name}' has no SameSite attribute (value: '{samesite or 'not set'}'). "
                        "Without SameSite=Strict or Lax, CSRF attacks are facilitated."
                    ),
                    reproduction_steps=[
                        f"curl -I {cookie['url']} | grep Set-Cookie",
                    ],
                    remediation=(
                        "Set SameSite=Strict for highly sensitive cookies. "
                        "Set SameSite=Lax for session cookies at minimum."
                    ),
                    references=["CWE-352"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_COOKIE_SAMESITE,
                    cvss_v40_vector=CVSS40_COOKIE_SAMESITE,
                    target=target,
                )

        # 4. Overly broad domain attribute
        domain = cookie["domain"]
        if domain:
            # Leading dot means applies to all subdomains
            clean_domain = domain.lstrip(".")
            if clean_domain and not clean_domain.startswith(host.split(".")[0]):
                # Domain is broader than the current host
                ev = Evidence(
                    response_raw=f"Set-Cookie: {cookie['raw']}",
                    extra={"cookie_domain": domain, "request_host": host},
                )
                self.new_finding(
                    title=f"Cookie With Overly Broad Domain Attribute — '{name}'",
                    severity=Severity.LOW,
                    description=(
                        f"Cookie '{name}' has Domain={domain}, which may share the cookie "
                        f"with sibling subdomains of {host}. "
                        "A compromised subdomain could steal this cookie via JavaScript if "
                        "HttpOnly is not set."
                    ),
                    reproduction_steps=[
                        f"curl -I {cookie['url']} | grep Set-Cookie",
                        f"Note Domain={domain} — cookie sent to all *.{clean_domain} subdomains",
                    ],
                    remediation=(
                        "Set the Domain attribute only to the specific host that needs the cookie. "
                        "Omitting Domain restricts it to the exact issuing host."
                    ),
                    references=["CWE-1275", "RFC 6265 Section 4.1"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_COOKIE_DOMAIN,
                    cvss_v40_vector=CVSS40_COOKIE_DOMAIN,
                    target=target,
                )

        # 5. Session cookie without expiry (non-persistent) — informational
        # This is actually GOOD behavior for session cookies, but note persistent sessions
        if cookie["expires"] and is_session:
            ev = Evidence(
                response_raw=f"Set-Cookie: {cookie['raw']}",
                extra={"expires": str(cookie["expires"])},
            )
            self.new_finding(
                title=f"Session Cookie With Persistent Expiry — '{name}'",
                severity=Severity.LOW,
                description=(
                    f"Session cookie '{name}' has an explicit Expires/Max-Age attribute "
                    f"({cookie['expires']}). "
                    "Persistent cookies survive browser restarts and remain on disk, "
                    "increasing the window for theft on shared/compromised devices."
                ),
                reproduction_steps=[
                    f"curl -I {cookie['url']} | grep Set-Cookie",
                    f"Note Expires/Max-Age on session cookie {name}",
                ],
                remediation=(
                    "For session cookies, omit Expires/Max-Age so the cookie is removed "
                    "when the browser session ends. "
                    "Use short max-ages for remember-me tokens and enforce server-side expiry."
                ),
                references=["OWASP Session Management Cheat Sheet", "CWE-539"],
                evidence=ev,
                cvss_v31_vector=CVSS_COOKIE_DOMAIN,
                cvss_v40_vector=CVSS40_COOKIE_DOMAIN,
                target=target,
            )


class TestCookieAudit:
    def test_parse_set_cookie_full(self) -> None:
        mod = CookieAudit.__new__(CookieAudit)
        parsed = mod._parse_set_cookie(
            "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
            "https://example.com"
        )
        assert parsed is not None
        assert parsed["name"] == "session"
        assert parsed["secure"] is True
        assert parsed["httponly"] is True
        assert parsed["samesite"] == "strict"

    def test_parse_set_cookie_insecure(self) -> None:
        mod = CookieAudit.__new__(CookieAudit)
        parsed = mod._parse_set_cookie("authToken=xyz; Path=/", "https://example.com")
        assert parsed is not None
        assert parsed["secure"] is False
        assert parsed["httponly"] is False

    def test_parse_samesite_none(self) -> None:
        mod = CookieAudit.__new__(CookieAudit)
        parsed = mod._parse_set_cookie(
            "token=abc; Secure; SameSite=None", "https://example.com"
        )
        assert parsed is not None
        assert parsed["samesite"] == "none"
        assert parsed["secure"] is True

    def test_session_cookie_detection(self) -> None:
        assert SESSION_COOKIE_NAMES.search("authToken")
        assert SESSION_COOKIE_NAMES.search("session_id")
        assert SESSION_COOKIE_NAMES.search("jwt")
        assert not SESSION_COOKIE_NAMES.search("theme_pref")
        assert not SESSION_COOKIE_NAMES.search("lang")

    def test_parse_cookie_with_domain(self) -> None:
        mod = CookieAudit.__new__(CookieAudit)
        parsed = mod._parse_set_cookie(
            "id=1; Domain=.example.com; Path=/", "https://api.example.com"
        )
        assert parsed is not None
        assert parsed["domain"] == ".example.com"

    def test_parse_cookie_with_maxage(self) -> None:
        mod = CookieAudit.__new__(CookieAudit)
        parsed = mod._parse_set_cookie(
            "session=xyz; Max-Age=3600; Secure; HttpOnly", "https://example.com"
        )
        assert parsed is not None
        assert parsed["expires"] == "3600"
