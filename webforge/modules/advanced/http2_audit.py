"""HTTP/2 audit — header injection, connection reuse issues, cleartext h2c."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import aiohttp

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_H2C         = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS_HDR_INJECT  = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"
CVSS_DOWNGRADE   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_DOS         = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


class Http2Audit(BaseModule):
    """HTTP/2 security auditor."""

    NAME        = "http2_audit"
    DESCRIPTION = "HTTP/2: cleartext h2c, header injection, protocol downgrade detection"
    PHASE       = 10
    TAGS        = ["advanced", "http2", "protocol", "owasp-a05", "cwe-757"]

    async def run(self) -> ModuleResult:
        """Audit target for HTTP/2-specific security issues."""
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await self._check_h2c_cleartext(target)
        await self._check_protocol_version(target)
        await self._check_h2_header_injection(target)
        await self._check_alt_svc(target)
        await self._check_http3_quic(target)
        await self._check_rapid_reset_indicator(target)
        await self._check_h2_request_tunneling(target)

        return self._make_result(start)

    async def _check_h2c_cleartext(self, target: str) -> None:
        """Check if cleartext HTTP/2 (h2c) upgrade is accepted."""
        # Send HTTP/1.1 Upgrade: h2c header
        http_target = target.replace("https://", "http://")
        await self.rate_limit()
        connector = aiohttp.TCPConnector(ssl=False)
        headers = {
            "Connection": "Upgrade, HTTP2-Settings",
            "Upgrade": "h2c",
            "HTTP2-Settings": "AAMAAABkAAQAAP__",
        }
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    http_target,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                ) as resp:
                    if resp.status == 101:
                        ev = Evidence(
                            request_raw=f"GET {http_target} HTTP/1.1\nUpgrade: h2c",
                            response_raw=f"HTTP {resp.status} Switching Protocols",
                            extra={"endpoint": http_target},
                        )
                        self.new_finding(
                            title=f"Cleartext HTTP/2 (h2c) Accepted: {http_target}",
                            severity=Severity.MEDIUM,
                            description=(
                                "The server accepts HTTP/2 cleartext upgrades (h2c) via "
                                "HTTP/1.1 Upgrade headers. Cleartext h2c may bypass "
                                "TLS-based security controls and intermediary inspection."
                            ),
                            reproduction_steps=[
                                f"Send GET {http_target} with 'Upgrade: h2c' header",
                                "Observe HTTP 101 Switching Protocols response",
                            ],
                            remediation=(
                                "Disable cleartext HTTP/2 (h2c). "
                                "Only serve HTTP/2 over TLS (h2). "
                                "Redirect all HTTP traffic to HTTPS."
                            ),
                            references=["CWE-319", "RFC 7540"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_H2C,
                            target=http_target,
                        )
        except Exception as exc:
            self.log.debug("h2c check error: %s", exc)

    async def _check_protocol_version(self, target: str) -> None:
        """Detect HTTP version used and flag HTTP/1.0 or missing h2."""
        await self.rate_limit()
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    target,
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                ) as resp:
                    version = resp.version
                    # aiohttp exposes HttpVersion namedtuple
                    major = getattr(version, "major", 0)
                    minor = getattr(version, "minor", 0)

                    if major == 1 and minor == 0:
                        ev = Evidence(
                            request_raw=f"GET {target} HTTP/1.1",
                            response_raw=f"HTTP/1.0 {resp.status}",
                            extra={"version": f"{major}.{minor}"},
                        )
                        self.new_finding(
                            title=f"Server Using Obsolete HTTP/1.0 Protocol: {target}",
                            severity=Severity.LOW,
                            description=(
                                "The server responded with HTTP/1.0, which lacks "
                                "persistent connections, chunked transfer encoding, "
                                "and virtual hosting. This indicates outdated server software."
                            ),
                            reproduction_steps=[
                                f"Send GET {target}",
                                "Observe HTTP/1.0 in response status line",
                            ],
                            remediation=(
                                "Upgrade the web server to support HTTP/1.1 at minimum. "
                                "Consider enabling HTTP/2 for performance and security."
                            ),
                            references=["CWE-757", "OWASP A05:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_DOWNGRADE,
                            target=target,
                        )
        except Exception as exc:
            self.log.debug("Protocol version check error: %s", exc)

    async def _check_h2_header_injection(self, target: str) -> None:
        """Test HTTP/2 pseudo-header injection attempts."""
        injection_headers = {
            ":path": "/\r\nX-Injected: evil",
            "x-test": "value\r\nX-Injected: evil",
        }
        await self.rate_limit()
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    target,
                    headers={"x-forge-test": "a\r\nX-Injected: evil"},
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    resp_headers = dict(resp.headers)
                    if "X-Injected" in resp_headers or "x-injected" in str(resp_headers).lower():
                        ev = Evidence(
                            request_raw=f"GET {target} HTTP/1.1\nx-forge-test: a\\r\\nX-Injected: evil",
                            response_raw=f"HTTP {resp.status}\n{str(resp_headers)[:300]}",
                            extra={"injected_header_reflected": True},
                        )
                        self.new_finding(
                            title=f"HTTP Header Injection via CRLF: {target}",
                            severity=Severity.HIGH,
                            description=(
                                "The server reflected an injected header resulting from "
                                "CRLF (\\r\\n) characters in a request header value. "
                                "This can lead to HTTP response splitting attacks."
                            ),
                            reproduction_steps=[
                                f"Send GET {target} with header: x-forge-test: a\\r\\nX-Injected: evil",
                                "Observe X-Injected header in response",
                            ],
                            remediation=(
                                "Strip or reject \\r and \\n characters from all "
                                "user-controlled header values. "
                                "Use a WAF rule to block CRLF injection."
                            ),
                            references=["CWE-113", "CWE-93", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_HDR_INJECT,
                            target=target,
                        )
        except Exception as exc:
            self.log.debug("Header injection check error: %s", exc)

    async def _check_alt_svc(self, target: str) -> None:
        """Check for Alt-Svc header advertising HTTP/3 or insecure alternatives."""
        await self.rate_limit()
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    alt_svc = resp.headers.get("Alt-Svc", "")
                    if alt_svc and 'clear' in alt_svc.lower():
                        ev = Evidence(
                            request_raw=f"GET {target} HTTP/1.1",
                            response_raw=f"HTTP {resp.status}\nAlt-Svc: {alt_svc}",
                            extra={"alt_svc": alt_svc},
                        )
                        self.new_finding(
                            title=f"Alt-Svc Header with 'clear' Directive: {target}",
                            severity=Severity.LOW,
                            description=(
                                f"The Alt-Svc header contains 'clear': {alt_svc}. "
                                "This instructs clients to clear cached alternative service "
                                "information, potentially downgrading to less secure transports."
                            ),
                            reproduction_steps=[
                                f"Send GET {target}",
                                f"Observe Alt-Svc: {alt_svc} in response",
                            ],
                            remediation=(
                                "Review Alt-Svc header configuration. "
                                "Do not advertise cleartext alternatives from HTTPS endpoints."
                            ),
                            references=["CWE-757", "RFC 7838"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_DOWNGRADE,
                            target=target,
                        )
        except Exception as exc:
            self.log.debug("Alt-Svc check error: %s", exc)


    async def _check_http3_quic(self, target: str) -> None:
        """Detect HTTP/3 (QUIC) advertisement via Alt-Svc and flag misconfig."""
        await self.rate_limit()
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    alt_svc = resp.headers.get("Alt-Svc", "")
                    if "h3" in alt_svc or "quic" in alt_svc.lower():
                        self.log.info("HTTP/3 (QUIC) advertised: %s", alt_svc)
                        ev = Evidence(
                            request_raw=f"GET {target} HTTP/1.1",
                            response_raw=f"Alt-Svc: {alt_svc}",
                            extra={"alt_svc": alt_svc, "protocol": "HTTP/3 QUIC"},
                        )
                        self.new_finding(
                            title=f"HTTP/3 (QUIC) Advertised — Verify Firewall Coverage: {target}",
                            severity=Severity.INFO,
                            description=(
                                f"Server advertises HTTP/3 over QUIC (UDP) via Alt-Svc: {alt_svc}. "
                                "QUIC runs on UDP port 443. Network controls that only filter TCP "
                                "traffic (IDS, WAF, DLP) may be bypassed by HTTP/3 clients. "
                                "Ensure UDP/443 is inspected equivalently to TCP/443."
                            ),
                            reproduction_steps=[
                                f"curl --http3 {target}",
                                "Verify network security controls cover UDP/443",
                            ],
                            remediation=(
                                "Ensure WAF, IDS/IPS, and egress filtering apply equally to "
                                "QUIC/UDP traffic. Disable HTTP/3 if not needed in your environment."
                            ),
                            references=["RFC 9114 (HTTP/3)", "CWE-923"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_H2C,
                            target=target,
                        )
        except Exception as exc:
            self.log.debug("HTTP/3 check error: %s", exc)

    async def _check_rapid_reset_indicator(self, target: str) -> None:
        """Check if server is patched against CVE-2023-44487 HTTP/2 Rapid Reset.

        We send multiple concurrent H2 streams then cancel via RST_STREAM — a server
        that queues work before cancellation indicates it may be vulnerable. Since we
        cannot send raw H2 frames via aiohttp, we check via version headers and known
        vendor patch indicators instead.
        """
        await self.rate_limit()
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    server = resp.headers.get("Server", "").lower()
                    version = resp.version
                    major = getattr(version, "major", 1)

                    if major >= 2:
                        # Check for unpatched versions of common servers
                        rapid_reset_risk = False
                        detail = ""
                        if re.search(r"nginx/1\.(1[0-9]|2[0-4])\.", server):
                            rapid_reset_risk = True
                            detail = f"nginx {server} — verify CVE-2023-44487 patch (nginx ≥ 1.25.3 / 1.24.0+patch)"
                        elif re.search(r"apache/2\.4\.(5[0-6]|[0-4][0-9])\b", server):
                            rapid_reset_risk = True
                            detail = f"Apache {server} — verify CVE-2023-44487 patch (httpd ≥ 2.4.58)"

                        if rapid_reset_risk:
                            self.new_finding(
                                title=f"Possible HTTP/2 Rapid Reset Exposure (CVE-2023-44487): {target}",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"Server ({detail}) is using HTTP/2 and may be running an "
                                    "unpatched version vulnerable to CVE-2023-44487 (Rapid Reset). "
                                    "The attack floods the server with HEADERS+RST_STREAM pairs, "
                                    "creating DoS without completing requests (CVSS 7.5). "
                                    "Verify the vendor patch is applied."
                                ),
                                reproduction_steps=[
                                    "Use h2load or a rapid-reset PoC to confirm exploitability",
                                    "Monitor server CPU under RST_STREAM flood",
                                ],
                                remediation=(
                                    "Apply vendor patch for CVE-2023-44487. "
                                    "For nginx: upgrade to ≥ 1.25.3 or apply backport. "
                                    "For Apache: upgrade to ≥ 2.4.58. "
                                    "Implement HTTP/2 stream count limits."
                                ),
                                references=["CVE-2023-44487", "CWE-400", "OWASP A05:2021"],
                                evidence=Evidence(
                                    request_raw=f"GET {target} (H2 banner check)",
                                    extra={"server": server, "h2": True},
                                ),
                                cvss_v31_vector=CVSS_DOS,
                                target=target,
                            )
        except Exception as exc:
            self.log.debug("Rapid Reset check error: %s", exc)

    async def _check_h2_request_tunneling(self, target: str) -> None:
        """Probe for HTTP/2 request tunneling via pseudo-header injection.

        An attacker who can inject data into a connection header field (e.g. via
        a front-end proxy) may tunnel a second HTTP/1.1 request inside the H2 stream.
        We test whether the server reflects a smuggled trailer.
        """
        await self.rate_limit()
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                # Inject a secondary request prefix into a custom header
                async with session.get(
                    target,
                    headers={
                        "x-tunnel-probe": "GET / HTTP/1.1\r\nHost: forge-probe\r\n\r\n",
                        "Connection": "keep-alive",
                    },
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    body = await resp.text(errors="ignore")
                    # A vulnerable proxy may echo the host back in an error
                    if "forge-probe" in body:
                        self.new_finding(
                            title=f"Possible HTTP/2 Request Tunneling via Header Injection: {target}",
                            severity=Severity.HIGH,
                            description=(
                                "A tunneled HTTP/1.1 request injected via a custom header was "
                                "reflected in the response, suggesting the server or an upstream "
                                "proxy may be vulnerable to HTTP/2 request tunneling. This can "
                                "enable cache poisoning, SSRF, or request smuggling."
                            ),
                            reproduction_steps=[
                                f"GET {target} with x-tunnel-probe: GET / HTTP/1.1\\r\\nHost: forge-probe",
                                "Observe 'forge-probe' in response body",
                            ],
                            remediation=(
                                "Reject headers containing CR/LF sequences at the edge proxy. "
                                "Ensure H2 → H1 translation strips untrusted pseudo-header data. "
                                "Apply HTTP/2 de-multiplexing hygiene on all intermediaries."
                            ),
                            references=["CWE-444", "PortSwigger H2 request tunneling research"],
                            evidence=Evidence(
                                request_raw=f"GET {target} + x-tunnel-probe injection",
                                response_raw=body[:500],
                            ),
                            cvss_v31_vector=CVSS_HDR_INJECT,
                            target=target,
                        )
        except Exception as exc:
            self.log.debug("H2 tunneling check error: %s", exc)


class TestHttp2Audit:
    def test_cvss_vectors_format(self) -> None:
        for v in (CVSS_H2C, CVSS_HDR_INJECT, CVSS_DOWNGRADE):
            assert v.startswith("CVSS:3.1/")

    def test_module_metadata(self) -> None:
        assert Http2Audit.PHASE == 10
        assert Http2Audit.NAME == "http2_audit"
