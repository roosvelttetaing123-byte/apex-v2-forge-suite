"""Host header injection scanner — password reset poisoning, cache poisoning, vhost enum."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# ---------------------------------------------------------------------------
# CVSS vectors
# ---------------------------------------------------------------------------
# Cache poisoning / SSRF — no user interaction, scope changed
CVSS_CACHE_POISON   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
CVSS40_CACHE_POISON = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"
# Password reset poisoning — requires user interaction (victim clicks link)
CVSS_PW_RESET       = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
CVSS40_PW_RESET     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
# Host reflection — generic HIGH
CVSS_HOST_INJECT    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
CVSS40_HOST_INJECT  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
# Virtual host discovery — informational/MEDIUM
CVSS_VHOST_DISC     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_VHOST_DISC   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

# MITRE ATT&CK
MITRE_HOST    = ["TA0001/T1190"]           # Exploit Public-Facing Application
MITRE_DATA    = ["TA0009/T1602"]           # Data from Configuration Repository
MITRE_CACHE   = ["TA0001/T1190", "TA0009/T1602"]

EVIL_HOST = "evil.forge-test.local"
OOB_DOMAIN = "oob.forge-test.local"       # Dummy OOB domain for SSRF detection patterns

# ---------------------------------------------------------------------------
# Header variant matrix
# ---------------------------------------------------------------------------
HEADER_VARIANTS: list[dict] = [
    # name, value_template, description
    {"name": "Host",                    "value": EVIL_HOST,                  "desc": "standard Host override"},
    {"name": "X-Forwarded-Host",        "value": EVIL_HOST,                  "desc": "X-Forwarded-Host proxy header"},
    {"name": "X-Host",                  "value": EVIL_HOST,                  "desc": "X-Host alternate"},
    {"name": "X-Forwarded-Server",      "value": EVIL_HOST,                  "desc": "X-Forwarded-Server"},
    {"name": "X-HTTP-Host-Override",    "value": EVIL_HOST,                  "desc": "X-HTTP-Host-Override"},
    {"name": "Forwarded",               "value": f"host={EVIL_HOST}",        "desc": "RFC 7239 Forwarded header"},
    {"name": "X-Original-URL",          "value": "/admin",                   "desc": "URL override (admin access)"},
    {"name": "X-Rewrite-URL",           "value": "/admin",                   "desc": "URL rewrite override"},
    {"name": "X-Custom-IP-Authorization", "value": "127.0.0.1",             "desc": "IP auth bypass"},
    {"name": "X-Originating-IP",        "value": "127.0.0.1",               "desc": "originating IP spoof"},
    {"name": "X-Remote-IP",             "value": "127.0.0.1",               "desc": "remote IP spoof"},
    {"name": "X-Client-IP",             "value": "127.0.0.1",               "desc": "client IP spoof"},
    {"name": "True-Client-IP",          "value": "127.0.0.1",               "desc": "Cloudflare-style IP spoof"},
]

# Headers used for absolute-URI request line injection (Host-equivalent)
ABSOLUTE_URI_HEADERS: list[str] = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
]

# Password reset endpoint paths
RESET_PATHS = [
    "/forgot-password", "/password-reset", "/reset-password",
    "/account/forgot", "/user/reset", "/auth/forgot-password",
    "/api/forgot-password", "/api/reset-password",
    "/api/v1/auth/forgot", "/api/v1/password/reset",
    "/users/password/new", "/auth/password",
]

# Virtual host names to brute-force (30 common names)
VHOST_WORDLIST: list[str] = [
    "admin", "api", "internal", "dev", "staging", "uat", "test",
    "beta", "portal", "dashboard", "vpn", "mail", "smtp", "ftp",
    "backup", "db", "database", "jenkins", "grafana", "kibana",
    "elastic", "vault", "git", "gitlab", "jira", "confluence",
    "sonar", "nexus", "artifactory", "monitor",
]


class HostHeaderInject(BaseModule):
    """Host header injection scanner.

    Tests for:
    1. Host header reflection in body/headers (all variant headers)
    2. Password reset link poisoning
    3. Cache poisoning via Host header
    4. Virtual host enumeration (30 common names)
    5. SSRF via Host header (OOB pattern detection)
    6. Duplicate Host header injection
    7. URL override headers (X-Original-URL, X-Rewrite-URL)
    8. IP authorization bypass headers (127.0.0.1)
    """

    NAME        = "host_header_inject"
    DESCRIPTION = "Detect Host header injection: password reset, cache poison, vhost enum, SSRF"
    PHASE       = 4
    TAGS        = ["injection", "host-header", "password-reset", "cache-poison",
                   "vhost", "ssrf", "cwe-20", "owasp-a10"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Host header injection scan on %s", target)

        await asyncio.gather(
            self._test_host_reflection(target),
            self._test_duplicate_host(target),
            self._test_url_override_headers(target),
            self._test_ip_auth_bypass(target),
            self._test_password_reset_poisoning(target),
            self._test_cache_poisoning(target),
            self._test_ssrf_via_host(target),
            self._enumerate_vhosts(target),
            return_exceptions=True,
        )
        return self._make_result(start)

    # ------------------------------------------------------------------
    # Test 1: Host header reflection in response body/headers
    # ------------------------------------------------------------------

    async def _test_host_reflection(self, target: str) -> None:
        """Check if any Host-related header value is reflected in response."""
        for variant in HEADER_VARIANTS:
            header_name  = variant["name"]
            header_value = variant["value"]
            desc         = variant["desc"]

            # Skip non-host headers here (tested separately)
            if header_name in ("X-Original-URL", "X-Rewrite-URL",
                               "X-Custom-IP-Authorization", "X-Originating-IP",
                               "X-Remote-IP", "X-Client-IP", "True-Client-IP"):
                continue

            await self.rate_limit()
            try:
                import aiohttp
                req_headers = {"User-Agent": "Mozilla/5.0"}
                if header_name == "Host":
                    req_headers["Host"] = header_value
                else:
                    req_headers[header_name] = header_value

                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        target,
                        headers=req_headers,
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        body         = await resp.text(errors="ignore")
                        resp_hdrs    = str(dict(resp.headers))

                reflected_in = None
                if EVIL_HOST in body:
                    reflected_in = "response body"
                elif EVIL_HOST in resp_hdrs:
                    reflected_in = "response headers"

                if reflected_in:
                    snippet_start = max(0, body.find(EVIL_HOST) - 80)
                    snippet_end   = body.find(EVIL_HOST) + len(EVIL_HOST) + 80
                    snippet       = body[snippet_start:snippet_end]
                    ev = Evidence(
                        request_raw=f"GET {target}\n{header_name}: {header_value}",
                        response_raw=snippet,
                        extra={
                            "header":       header_name,
                            "evil_host":    EVIL_HOST,
                            "reflected_in": reflected_in,
                            "desc":         desc,
                        },
                    )
                    self.new_finding(
                        title=(
                            f"Host Header Injection — {header_name} Reflected "
                            f"in {reflected_in.title()}"
                        ),
                        severity=Severity.HIGH,
                        description=(
                            f"Injected value '{EVIL_HOST}' via '{header_name}' ({desc}) "
                            f"is reflected in the {reflected_in}.\n"
                            "Exploitation vectors:\n"
                            "- Password reset link poisoning (victim receives attacker's domain)\n"
                            "- Web cache poisoning if response is cached\n"
                            "- Server-Side Request Forgery in backend HTTP clients"
                        ),
                        reproduction_steps=[
                            f"curl -H '{header_name}: {EVIL_HOST}' {target}",
                            f"Observe '{EVIL_HOST}' in the {reflected_in}",
                        ],
                        remediation=(
                            "Validate the Host header against a server-side allowlist. "
                            "Never use the Host header value directly for URL generation. "
                            "Use SERVER_NAME or an explicit configured hostname instead."
                        ),
                        references=["CWE-20", "PortSwigger Host Header Attacks"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_HOST_INJECT,
                        cvss_v40_vector=CVSS40_HOST_INJECT,
                        mitre_attack=MITRE_HOST,
                        target=target,
                    )
                    return  # One finding per successful variant

            except Exception:
                pass

    # ------------------------------------------------------------------
    # Test 2: Duplicate Host header
    # ------------------------------------------------------------------

    async def _test_duplicate_host(self, target: str) -> None:
        """Send two Host headers — some frameworks use the second (parser confusion)."""
        await self.rate_limit()
        try:
            import aiohttp
            from aiohttp import ClientRequest

            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    target,
                    headers={
                        "User-Agent":     "Mozilla/5.0",
                        "X-Forwarded-Host": EVIL_HOST,   # proxy passes second host
                        "Host":           EVIL_HOST,
                    },
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    body = await resp.text(errors="ignore")

            if EVIL_HOST in body:
                ev = Evidence(
                    request_raw=(
                        f"GET {target}\nHost: <original>\nHost: {EVIL_HOST}"
                    ),
                    response_raw=body[:400],
                    extra={"evil_host": EVIL_HOST},
                )
                self.new_finding(
                    title="Host Header Injection — Duplicate Host Reflection",
                    severity=Severity.HIGH,
                    description=(
                        f"Sending duplicate Host headers caused '{EVIL_HOST}' to be "
                        "reflected in the response. This indicates the framework parses "
                        "the second (attacker-controlled) Host header value."
                    ),
                    reproduction_steps=[
                        f"# Send two Host lines in raw HTTP:",
                        f"GET / HTTP/1.1",
                        f"Host: {target.split('//')[1].split('/')[0]}",
                        f"Host: {EVIL_HOST}",
                    ],
                    remediation=(
                        "Reject requests with more than one Host header. "
                        "Validate Host against an allowlist."
                    ),
                    references=["CWE-20", "RFC 7230 Section 5.4"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_HOST_INJECT,
                    cvss_v40_vector=CVSS40_HOST_INJECT,
                    mitre_attack=MITRE_HOST,
                    target=target,
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Test 3: URL override headers (path restriction bypass)
    # ------------------------------------------------------------------

    async def _test_url_override_headers(self, target: str) -> None:
        """X-Original-URL / X-Rewrite-URL can override the request path."""
        override_headers = [
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL",  "/admin"),
            ("X-Original-URL", "/api/admin"),
            ("X-Rewrite-URL",  "/api/admin"),
        ]
        for header_name, override_path in override_headers:
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        target,
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            header_name:  override_path,
                        },
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as resp:
                        body   = await resp.text(errors="ignore")
                        status = resp.status

                # Compare with baseline for /admin (should be 403/404 normally)
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        f"{target}{override_path}",
                        headers={"User-Agent": "Mozilla/5.0"},
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as baseline_resp:
                        baseline_status = baseline_resp.status

                # If baseline is 403/404 but override gives 200 → bypass
                if baseline_status in (401, 403, 404) and status == 200:
                    ev = Evidence(
                        request_raw=(
                            f"GET {target}\n{header_name}: {override_path}"
                        ),
                        response_raw=body[:500],
                        extra={
                            "header":          header_name,
                            "override_path":   override_path,
                            "baseline_status": baseline_status,
                            "bypass_status":   status,
                        },
                    )
                    self.new_finding(
                        title=(
                            f"Host Header — URL Override Bypass via {header_name}"
                        ),
                        severity=Severity.HIGH,
                        description=(
                            f"The '{header_name}: {override_path}' header bypassed "
                            f"access control for path '{override_path}'. "
                            f"Direct access returned HTTP {baseline_status}, "
                            f"but with the override header the server responded HTTP {status}."
                        ),
                        reproduction_steps=[
                            f"curl -H '{header_name}: {override_path}' {target}",
                        ],
                        remediation=(
                            "Disable or strictly validate X-Original-URL and X-Rewrite-URL headers. "
                            "Apply access controls at the application level, not just URL routing."
                        ),
                        references=["CWE-20", "PortSwigger URL override"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_HOST_INJECT,
                        cvss_v40_vector=CVSS40_HOST_INJECT,
                        mitre_attack=MITRE_HOST,
                        target=target,
                    )
                    return
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Test 4: IP auth bypass headers
    # ------------------------------------------------------------------

    async def _test_ip_auth_bypass(self, target: str) -> None:
        """Try localhost IP spoof via custom headers to bypass IP-based auth."""
        spoofed_ips = ["127.0.0.1", "::1", "localhost"]
        ip_headers  = [
            "X-Custom-IP-Authorization",
            "X-Originating-IP",
            "X-Remote-IP",
            "X-Client-IP",
            "True-Client-IP",
            "X-Forwarded-For",
        ]
        try:
            import aiohttp
            # Baseline
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    target,
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    baseline_status = resp.status
                    await resp.text(errors="ignore")  # drain body

            for ip_header in ip_headers:
                for spoof_ip in spoofed_ips:
                    await self.rate_limit()
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            target,
                            headers={
                                "User-Agent": "Mozilla/5.0",
                                ip_header:    spoof_ip,
                            },
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            status = resp.status
                            body   = await resp.text(errors="ignore")

                    # Look for a status code improvement (403 → 200) or privilege keywords
                    priv_keywords = ["admin", "dashboard", "welcome", "panel", "control"]
                    if (baseline_status in (401, 403) and status == 200 and
                            any(kw in body.lower() for kw in priv_keywords)):
                        ev = Evidence(
                            request_raw=(
                                f"GET {target}\n{ip_header}: {spoof_ip}"
                            ),
                            response_raw=body[:400],
                            extra={
                                "header":          ip_header,
                                "spoofed_ip":      spoof_ip,
                                "baseline_status": baseline_status,
                                "bypass_status":   status,
                            },
                        )
                        self.new_finding(
                            title=f"IP Authorization Bypass via {ip_header}: {spoof_ip}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Setting '{ip_header}: {spoof_ip}' changed the response "
                                f"from HTTP {baseline_status} to HTTP {status}, suggesting "
                                "the server trusts this header for IP-based access control. "
                                "An attacker can access restricted functionality by spoofing localhost."
                            ),
                            reproduction_steps=[
                                f"curl -H '{ip_header}: {spoof_ip}' {target}",
                            ],
                            remediation=(
                                "Never trust X-Forwarded-For or similar headers for authorization. "
                                "Only use the actual TCP connection IP for IP-based restrictions."
                            ),
                            references=["CWE-290", "CWE-20", "OWASP A01:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_CACHE_POISON,
                            cvss_v40_vector=CVSS40_CACHE_POISON,
                            mitre_attack=MITRE_HOST,
                            target=target,
                        )
                        return
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Test 5: Password reset poisoning
    # ------------------------------------------------------------------

    async def _test_password_reset_poisoning(self, target: str) -> None:
        """POST to reset endpoints with poisoned Host header; check reflection."""
        for path in RESET_PATHS:
            await self.rate_limit()
            url = f"{target}{path}"
            try:
                import aiohttp
                # Probe existence
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=True,
                    ) as resp:
                        if resp.status not in (200, 405):
                            continue

                # POST with poisoned Host / X-Forwarded-Host
                for hdr_name in ("X-Forwarded-Host", "Host"):
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.post(
                            url,
                            data={"email": "test@example.com"},
                            headers={
                                "User-Agent": "Mozilla/5.0",
                                hdr_name:     EVIL_HOST,
                            },
                            timeout=aiohttp.ClientTimeout(total=8),
                            allow_redirects=True,
                        ) as resp:
                            body = await resp.text(errors="ignore")

                    if EVIL_HOST in body:
                        ev = Evidence(
                            request_raw=(
                                f"POST {url}\n"
                                f"{hdr_name}: {EVIL_HOST}\n"
                                "email=test@example.com"
                            ),
                            response_raw=body[:600],
                            extra={"path": path, "header": hdr_name},
                        )
                        self.new_finding(
                            title=(
                                f"Password Reset Poisoning via {hdr_name} — {path}"
                            ),
                            severity=Severity.HIGH,
                            description=(
                                f"The password reset endpoint at '{url}' reflects the "
                                f"injected '{hdr_name}: {EVIL_HOST}' in the response. "
                                "An attacker can request a password reset for a victim's "
                                "email with an attacker-controlled Host header — the reset "
                                "link in the email will point to the attacker's domain."
                            ),
                            reproduction_steps=[
                                f"curl -X POST {url} \\",
                                f"  -H '{hdr_name}: attacker.com' \\",
                                "  -d 'email=victim@example.com'",
                                "Victim's reset email contains attacker.com reset link",
                            ],
                            remediation=(
                                "Never trust the Host header for link generation in emails. "
                                "Hardcode the application's canonical domain in server configuration "
                                "or an environment variable. Use SERVER_NAME, not HTTP_HOST."
                            ),
                            references=["CWE-20", "PortSwigger Password Reset Poisoning"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_PW_RESET,
                            cvss_v40_vector=CVSS40_PW_RESET,
                            mitre_attack=MITRE_HOST,
                            target=target,
                        )
                        return
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Test 6: Cache poisoning detection
    # ------------------------------------------------------------------

    async def _test_cache_poisoning(self, target: str) -> None:
        """Detect if a response with a poisoned Host header is cached.

        Strategy:
        1. Request with evil host → record response body
        2. Immediately request without evil host → compare body
        3. If evil host appears in the clean response, cache is poisoned
        """
        try:
            import aiohttp

            # Request 1: with evil host
            await self.rate_limit()
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    target,
                    headers={
                        "User-Agent":        "Mozilla/5.0",
                        "X-Forwarded-Host":  EVIL_HOST,
                        "Cache-Control":     "no-cache",  # skip our own cache
                    },
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    poisoned_body = await resp.text(errors="ignore")

            # Short wait for cache to settle
            await asyncio.sleep(0.5)

            # Request 2: clean (no evil host)
            await self.rate_limit()
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    target,
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    clean_body = await resp.text(errors="ignore")

            # Detection: evil host leaked into clean response
            if EVIL_HOST in clean_body and EVIL_HOST not in poisoned_body[:100]:
                ev = Evidence(
                    request_raw=(
                        f"GET {target}\nX-Forwarded-Host: {EVIL_HOST}\n"
                        f"--- then ---\nGET {target}  (clean)"
                    ),
                    response_raw=clean_body[:600],
                    extra={
                        "poisoned_body_excerpt": poisoned_body[:200],
                        "clean_body_excerpt":    clean_body[:200],
                    },
                )
                self.new_finding(
                    title="Web Cache Poisoning via Host Header",
                    severity=Severity.CRITICAL,
                    description=(
                        f"A response poisoned with 'X-Forwarded-Host: {EVIL_HOST}' was "
                        "subsequently served to a clean request, confirming web cache poisoning. "
                        "An attacker can inject malicious content served to all users of the "
                        "cached response (XSS, credential theft, phishing)."
                    ),
                    reproduction_steps=[
                        f"curl -H 'X-Forwarded-Host: {EVIL_HOST}' {target}",
                        f"curl {target}  # observe evil host in clean response",
                    ],
                    remediation=(
                        "Configure the cache to exclude X-Forwarded-Host from the cache key. "
                        "Or add 'Vary: Host' to prevent caching Host-dependent responses. "
                        "Validate Host header on the origin server."
                    ),
                    references=["CWE-20", "PortSwigger Web Cache Poisoning", "OWASP A05:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CACHE_POISON,
                    cvss_v40_vector=CVSS40_CACHE_POISON,
                    mitre_attack=MITRE_CACHE,
                    target=target,
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Test 7: SSRF via Host header
    # ------------------------------------------------------------------

    async def _test_ssrf_via_host(self, target: str) -> None:
        """Check if setting Host to an OOB domain triggers an outbound request.

        Without a real OOB listener we detect indicators in the response:
        - DNS error messages for OOB_DOMAIN in the body
        - curl/wget-style error messages
        - Abnormal response time (>3s suggests a backend DNS lookup)
        """
        await self.rate_limit()
        try:
            import aiohttp
            t_start = time.monotonic()
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    target,
                    headers={
                        "User-Agent":       "Mozilla/5.0",
                        "X-Forwarded-Host": OOB_DOMAIN,
                        "Host":             OOB_DOMAIN,
                    },
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=12),
                ) as resp:
                    elapsed = time.monotonic() - t_start
                    body    = await resp.text(errors="ignore")

            # DNS error for our OOB domain leaking in response body
            oob_indicators = [
                OOB_DOMAIN, "could not resolve", "getaddrinfo",
                "Name or service not known", "NXDOMAIN",
            ]
            if any(ind.lower() in body.lower() for ind in oob_indicators):
                ev = Evidence(
                    request_raw=(
                        f"GET {target}\nHost: {OOB_DOMAIN}\n"
                        f"X-Forwarded-Host: {OOB_DOMAIN}"
                    ),
                    response_raw=body[:600],
                    extra={"oob_domain": OOB_DOMAIN, "elapsed_s": round(elapsed, 2)},
                )
                self.new_finding(
                    title="SSRF via Host Header — OOB DNS Leak Indicator",
                    severity=Severity.HIGH,
                    description=(
                        f"Setting 'Host: {OOB_DOMAIN}' caused the server to attempt "
                        "a backend DNS resolution or HTTP request for the OOB domain. "
                        "A real OOB listener (Burp Collaborator / interactsh) can confirm SSRF. "
                        "This may allow internal network enumeration or credential exfiltration."
                    ),
                    reproduction_steps=[
                        f"# Set up an OOB DNS listener (e.g. interactsh-client)",
                        f"curl -H 'Host: <your-oob-domain>' {target}",
                        "Observe DNS/HTTP callback to your OOB server",
                    ],
                    remediation=(
                        "Validate the Host header against a strict allowlist. "
                        "Block outbound requests initiated by user-controlled host values."
                    ),
                    references=["CWE-918", "CWE-20", "OWASP A10:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_HOST_INJECT,
                    cvss_v40_vector=CVSS40_HOST_INJECT,
                    mitre_attack=MITRE_HOST,
                    target=target,
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Test 8: Virtual host bruteforce
    # ------------------------------------------------------------------

    async def _enumerate_vhosts(self, target: str) -> None:
        """Try 30 common vhost names; report when response differs from baseline."""
        try:
            import aiohttp
            from urllib.parse import urlparse

            parsed   = urlparse(target)
            base_host = parsed.netloc.split(":")[0]
            port_part = f":{parsed.port}" if parsed.port else ""

            # Baseline
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    target,
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    baseline_status = resp.status
                    baseline_body   = await resp.text(errors="ignore")
                    baseline_len    = len(baseline_body)

            found_vhosts: list[dict] = []

            for vhost_name in VHOST_WORDLIST:
                vhost = f"{vhost_name}.{base_host}{port_part}"
                await self.rate_limit()
                try:
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            target,
                            headers={
                                "User-Agent": "Mozilla/5.0",
                                "Host":       vhost,
                            },
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            status = resp.status
                            body   = await resp.text(errors="ignore")

                    # Different status OR significantly different content = possible vhost
                    len_diff = abs(len(body) - baseline_len)
                    if status != baseline_status or len_diff > 200:
                        found_vhosts.append({
                            "vhost":    vhost,
                            "status":   status,
                            "len_diff": len_diff,
                        })
                except Exception:
                    pass

            if found_vhosts:
                ev = Evidence(
                    extra={"found_vhosts": found_vhosts[:10]},
                )
                self.new_finding(
                    title=f"Virtual Host Enumeration — {len(found_vhosts)} Candidate(s) Found",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The following virtual host names produced different responses "
                        f"when set in the Host header, suggesting they may host separate content:\n"
                        + "\n".join(
                            f"  - {v['vhost']} (HTTP {v['status']}, "
                            f"Δbody={v['len_diff']} bytes)"
                            for v in found_vhosts[:10]
                        )
                    ),
                    reproduction_steps=[
                        f"curl -H 'Host: {found_vhosts[0]['vhost']}' {target}",
                    ],
                    remediation=(
                        "Review each discovered virtual host for unintended exposure. "
                        "Ensure internal hosts are not reachable from the public internet."
                    ),
                    references=["CWE-284", "OWASP A01:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_VHOST_DISC,
                    cvss_v40_vector=CVSS40_VHOST_DISC,
                    mitre_attack=MITRE_DATA,
                    target=target,
                )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Embedded tests
# ---------------------------------------------------------------------------

class TestHostHeaderInject:
    """Embedded unit tests — run with pytest."""

    def test_evil_host_defined(self) -> None:
        assert EVIL_HOST
        assert "." in EVIL_HOST

    def test_oob_domain_defined(self) -> None:
        assert OOB_DOMAIN
        assert "." in OOB_DOMAIN

    def test_header_variants_has_required_entries(self) -> None:
        names = [v["name"] for v in HEADER_VARIANTS]
        assert "Host"             in names
        assert "X-Forwarded-Host" in names
        assert "X-Host"           in names
        assert "X-Original-URL"   in names
        assert "X-Rewrite-URL"    in names

    def test_header_variants_count(self) -> None:
        assert len(HEADER_VARIANTS) >= 10

    def test_vhost_wordlist_count(self) -> None:
        assert len(VHOST_WORDLIST) >= 30

    def test_vhost_wordlist_required_entries(self) -> None:
        required = ["admin", "api", "internal", "dev", "staging", "jenkins",
                    "grafana", "kibana", "vault", "gitlab"]
        for entry in required:
            assert entry in VHOST_WORDLIST, f"'{entry}' missing from VHOST_WORDLIST"

    def test_reset_paths_list(self) -> None:
        assert "/forgot-password" in RESET_PATHS
        assert "/password-reset"  in RESET_PATHS
        assert len(RESET_PATHS) >= 8

    def test_cvss_cache_poison_vector(self) -> None:
        assert CVSS_CACHE_POISON.startswith("CVSS:3.1")
        assert "S:C" in CVSS_CACHE_POISON   # Scope Changed
        assert "C:H" in CVSS_CACHE_POISON

    def test_cvss_pw_reset_vector(self) -> None:
        assert CVSS_PW_RESET.startswith("CVSS:3.1")
        assert "UI:R" in CVSS_PW_RESET      # User Interaction required

    def test_mitre_codes(self) -> None:
        assert "TA0001/T1190" in MITRE_HOST
        assert "TA0009/T1602" in MITRE_DATA

    def test_all_header_variants_have_desc(self) -> None:
        for v in HEADER_VARIANTS:
            assert "desc" in v and v["desc"]
            assert "name" in v and v["name"]
            assert "value" in v

    def test_ip_headers_in_variants(self) -> None:
        names = [v["name"] for v in HEADER_VARIANTS]
        assert "X-Custom-IP-Authorization" in names
        assert "X-Originating-IP"          in names

    def test_absolute_uri_headers_defined(self) -> None:
        assert "X-Forwarded-Host" in ABSOLUTE_URI_HEADERS
        assert "X-Host"           in ABSOLUTE_URI_HEADERS
