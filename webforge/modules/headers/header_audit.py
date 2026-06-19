"""Security headers auditor — checks all OWASP-required response headers."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

REQUIRED_HEADERS: list[dict[str, Any]] = [
    {
        "name": "Strict-Transport-Security",
        "severity": Severity.HIGH,
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "cvss40": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "check": lambda v: bool(v and "max-age" in v.lower() and _safe_int_max_age(v) >= 31536000),
        "description": "Missing or weak HSTS header allows protocol downgrade to HTTP.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "references": ["CWE-319", "OWASP A05:2021"],
    },
    {
        "name": "Content-Security-Policy",
        "severity": Severity.MEDIUM,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
        "check": lambda v: (
            v is not None
            and "default-src" in v
            and "unsafe-inline" not in v
            and "unsafe-eval" not in v
        ),
        "description": "Missing or weak CSP allows XSS and data injection attacks.",
        "remediation": "Add CSP with restrictive directives. Avoid 'unsafe-inline' and 'unsafe-eval'.",
        "references": ["CWE-1021", "OWASP A05:2021"],
    },
    {
        "name": "X-Content-Type-Options",
        "severity": Severity.LOW,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cvss40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "check": lambda v: v and v.lower().strip() == "nosniff",
        "description": "Missing X-Content-Type-Options allows MIME sniffing attacks.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "references": ["CWE-116"],
    },
    {
        "name": "X-Frame-Options",
        "severity": Severity.MEDIUM,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "cvss40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N",
        "check": lambda v: v and v.upper().strip() in ("DENY", "SAMEORIGIN"),
        "description": (
            "Missing X-Frame-Options allows clickjacking attacks. "
            "Note: prefer CSP frame-ancestors for modern browsers."
        ),
        "remediation": "Add: X-Frame-Options: DENY (or SAMEORIGIN). Prefer CSP frame-ancestors.",
        "references": ["CWE-1021", "OWASP A05:2021"],
    },
    {
        "name": "Referrer-Policy",
        "severity": Severity.LOW,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cvss40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "check": lambda v: v and v.lower().strip() in (
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "same-origin", "origin", "origin-when-cross-origin",
            "no-referrer-when-downgrade",
        ),
        "description": "Missing Referrer-Policy may leak sensitive URLs to third parties.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "references": ["CWE-116"],
    },
    {
        "name": "Permissions-Policy",
        "severity": Severity.LOW,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cvss40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "check": lambda v: v is not None,
        "description": "Missing Permissions-Policy allows unrestricted browser feature access.",
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "references": ["OWASP A05:2021"],
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "severity": Severity.LOW,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cvss40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "check": lambda v: v and v.lower().strip() in (
            "same-origin", "same-origin-allow-popups", "unsafe-none"
        ),
        "description": (
            "Missing Cross-Origin-Opener-Policy (COOP) allows cross-origin windows "
            "to retain a reference to this window, enabling XS-Leaks and Spectre-based "
            "side-channel attacks on sensitive page data."
        ),
        "remediation": "Add: Cross-Origin-Opener-Policy: same-origin",
        "references": ["CWE-1021", "OWASP A05:2021"],
    },
    {
        "name": "Cross-Origin-Embedder-Policy",
        "severity": Severity.LOW,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cvss40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "check": lambda v: v and v.lower().strip() in ("require-corp", "credentialless"),
        "description": (
            "Missing Cross-Origin-Embedder-Policy (COEP) prevents enabling powerful features "
            "such as SharedArrayBuffer and precise timers required to mitigate Spectre. "
            "Required alongside COOP for cross-origin isolation."
        ),
        "remediation": "Add: Cross-Origin-Embedder-Policy: require-corp",
        "references": ["CWE-1021", "OWASP A05:2021"],
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "severity": Severity.LOW,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cvss40": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "check": lambda v: v and v.lower().strip() in ("same-origin", "same-site", "cross-origin"),
        "description": (
            "Missing Cross-Origin-Resource-Policy (CORP) allows any cross-origin site "
            "to embed or no-cors-fetch this resource, enabling side-channel leaks "
            "of sensitive response data (Spectre / XS-Leaks)."
        ),
        "remediation": "Add: Cross-Origin-Resource-Policy: same-origin (or same-site for CDN assets)",
        "references": ["CWE-1021", "OWASP A05:2021"],
    },
]

# Headers whose presence indicates information disclosure
DANGEROUS_HEADERS: list[tuple[str, str, str]] = [
    ("Server",              "Exposes server software version",          "LOW"),
    ("X-Powered-By",        "Exposes technology stack (PHP/ASP.NET version)", "LOW"),
    ("X-AspNet-Version",    "Exposes ASP.NET framework version",        "LOW"),
    ("X-AspNetMvc-Version", "Exposes ASP.NET MVC version",              "LOW"),
    ("X-Runtime",           "Exposes backend runtime/version (Rails etc.)", "LOW"),
    ("X-Generator",         "Exposes CMS or generator tool",            "LOW"),
    ("Via",                 "Exposes proxy infrastructure",              "INFO"),
]

# Deprecated security header — report if present
DEPRECATED_HEADERS: list[tuple[str, str]] = [
    (
        "X-XSS-Protection",
        "X-XSS-Protection is deprecated. Modern browsers ignore or disable it. "
        "It can also introduce XSS vulnerabilities via bypass techniques. "
        "Remove it and rely on a strong CSP header instead.",
    ),
    (
        "Expect-CT",
        "Expect-CT is deprecated as of Chrome 107 and will be removed. "
        "Modern certificate transparency is enforced natively by browsers.",
    ),
]


def _safe_int_max_age(hsts_value: str) -> int:
    """Safely extract max-age integer from HSTS header value."""
    try:
        for part in hsts_value.lower().split(";"):
            part = part.strip()
            if part.startswith("max-age="):
                return int(part.split("=", 1)[1].strip())
    except (ValueError, IndexError):
        pass
    return 0


class HeaderAudit(BaseModule):
    """Security headers auditor."""

    NAME        = "header_audit"
    DESCRIPTION = "Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc."
    PHASE       = 3
    TAGS        = ["headers", "owasp-a05", "cwe-116"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Auditing security headers on %s", target)

        from webforge.core.session import ForgeSession
        async with ForgeSession(
            rate=self.config.rate.requests_per_second,
            proxy=self.config.extra.get("proxy"),
        ) as session:
            try:
                await self.rate_limit()
                resp = await session.get(target)
                headers = dict(resp.headers)
                headers_lower = {k.lower(): v for k, v in headers.items()}
                body = await resp.text()
            except Exception as exc:
                self.log.error("Could not fetch %s: %s", target, exc)
                return self._make_result(start)

        ss = self.capture_screenshot(target, "header_audit", highlight_js=None)

        request_raw  = f"GET / HTTP/1.1\r\nHost: {target}\r\n"
        response_raw = "\n".join(f"{k}: {v}" for k, v in headers.items())

        # 1. Required security headers check
        for hdr_def in REQUIRED_HEADERS:
            name     = hdr_def["name"]
            val      = headers_lower.get(name.lower())
            check_fn = hdr_def["check"]
            passed   = False
            try:
                passed = bool(check_fn(val))
            except Exception:
                passed = False

            if not passed:
                issue = "Missing" if val is None else f"Weak value: {val!r}"
                ev = Evidence(
                    request_raw=request_raw,
                    response_raw=response_raw,
                    screenshot_path=ss,
                    extra={"header": name, "value": val, "issue": issue},
                )
                self.new_finding(
                    title=f"Security Header {issue}: {name}",
                    severity=hdr_def["severity"],
                    description=hdr_def["description"],
                    reproduction_steps=[
                        f"Send GET request to {target}",
                        f"Check response for '{name}' header",
                        f"Result: {issue}",
                    ],
                    remediation=hdr_def["remediation"],
                    references=hdr_def["references"],
                    evidence=ev,
                    cvss_v31_vector=hdr_def["cvss"],
                    cvss_v40_vector=hdr_def["cvss40"],
                    mitre_attack=["TA0043/T1595"],
                    target=target,
                )

        # 2. Information disclosure headers
        for hdr_name, description, _ in DANGEROUS_HEADERS:
            val = headers_lower.get(hdr_name.lower())
            if val:
                ev = Evidence(
                    request_raw=request_raw,
                    response_raw=response_raw,
                    extra={"header": hdr_name, "value": val},
                )
                self.new_finding(
                    title=f"Information Disclosure — Response Header '{hdr_name}'",
                    severity=Severity.LOW,
                    description=f"{description}. Value: {val!r}",
                    reproduction_steps=[
                        f"Send GET request to {target}",
                        f"Observe response header: {hdr_name}: {val}",
                    ],
                    remediation=f"Remove or suppress the '{hdr_name}' response header in server/framework config.",
                    references=["CWE-200", "OWASP A05:2021"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                    target=target,
                )

        # 3. Deprecated/dangerous headers present
        for hdr_name, dep_description in DEPRECATED_HEADERS:
            val = headers_lower.get(hdr_name.lower())
            if val:
                ev = Evidence(
                    request_raw=request_raw,
                    response_raw=response_raw,
                    extra={"header": hdr_name, "value": val},
                )
                self.new_finding(
                    title=f"Deprecated Security Header Present — '{hdr_name}'",
                    severity=Severity.LOW,
                    description=(
                        f"The deprecated header '{hdr_name}: {val}' is present in the response. "
                        f"{dep_description}"
                    ),
                    reproduction_steps=[
                        f"curl -I {target} | grep -i {hdr_name.lower()}",
                    ],
                    remediation=f"Remove the '{hdr_name}' header and implement a proper CSP policy.",
                    references=["CWE-116", "OWASP A05:2021"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
                    target=target,
                )

        # 4. Cache-Control on authenticated pages
        cache_ctrl  = headers_lower.get("cache-control", "")
        pragma      = headers_lower.get("pragma", "")
        auth_header = headers_lower.get("authorization", "")
        if not any(d in cache_ctrl.lower() for d in ("no-store", "private")) and auth_header:
            ev = Evidence(
                response_raw=response_raw,
                extra={"cache-control": cache_ctrl, "pragma": pragma},
            )
            self.new_finding(
                title="Missing Cache-Control: no-store on Authenticated Response",
                severity=Severity.LOW,
                description=(
                    "The response to an authenticated request does not include "
                    "Cache-Control: no-store. Sensitive content may be cached by browsers "
                    "or proxies and disclosed to other users on shared systems."
                ),
                reproduction_steps=[
                    f"Send authenticated GET request to {target}",
                    "Check response Cache-Control header",
                ],
                remediation=(
                    "Add: Cache-Control: no-store, no-cache, must-revalidate\n"
                    "Also add: Pragma: no-cache\n"
                    "On all responses containing sensitive or personalised data."
                ),
                references=["CWE-525", "OWASP A05:2021"],
                evidence=ev,
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                target=target,
            )

        return self._make_result(start)


class TestHeaderAudit:
    def test_safe_int_max_age(self) -> None:
        assert _safe_int_max_age("max-age=31536000; includeSubDomains") == 31536000
        assert _safe_int_max_age("max-age=300") == 300
        assert _safe_int_max_age("no-max-age") == 0
        assert _safe_int_max_age("") == 0

    def test_hsts_check_passes(self) -> None:
        hdr = next(h for h in REQUIRED_HEADERS if h["name"] == "Strict-Transport-Security")
        assert hdr["check"]("max-age=31536000; includeSubDomains") is True

    def test_hsts_check_fails_short(self) -> None:
        hdr = next(h for h in REQUIRED_HEADERS if h["name"] == "Strict-Transport-Security")
        assert hdr["check"]("max-age=300") is False

    def test_hsts_missing(self) -> None:
        hdr = next(h for h in REQUIRED_HEADERS if h["name"] == "Strict-Transport-Security")
        assert hdr["check"](None) is False

    def test_xcto_passes(self) -> None:
        hdr = next(h for h in REQUIRED_HEADERS if h["name"] == "X-Content-Type-Options")
        assert hdr["check"]("nosniff") is True

    def test_csp_weak_unsafe_inline(self) -> None:
        hdr = next(h for h in REQUIRED_HEADERS if h["name"] == "Content-Security-Policy")
        assert hdr["check"]("default-src * 'unsafe-inline'") is False

    def test_csp_weak_unsafe_eval(self) -> None:
        hdr = next(h for h in REQUIRED_HEADERS if h["name"] == "Content-Security-Policy")
        assert hdr["check"]("default-src 'self' 'unsafe-eval'") is False

    def test_csp_strong_passes(self) -> None:
        hdr = next(h for h in REQUIRED_HEADERS if h["name"] == "Content-Security-Policy")
        assert hdr["check"]("default-src 'self'; object-src 'none'") is True

    def test_deprecated_headers_defined(self) -> None:
        names = [h[0] for h in DEPRECATED_HEADERS]
        assert "X-XSS-Protection" in names

    def test_dangerous_headers_list(self) -> None:
        names = [h[0] for h in DANGEROUS_HEADERS]
        assert "Server" in names
        assert "X-Powered-By" in names
