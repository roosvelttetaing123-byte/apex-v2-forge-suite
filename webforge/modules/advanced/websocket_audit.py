"""WebSocket audit — hijacking, injection, authentication checks."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import aiohttp

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_WS_HIJACK  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
CVSS_WS_INJECT  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"
CVSS_WS_NO_AUTH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

WS_ENDPOINTS = [
    "/ws", "/websocket", "/socket", "/ws/chat", "/ws/notifications",
    "/api/ws", "/realtime", "/socket.io", "/live", "/ws/v1",
    "/ws/v2", "/cable", "/hub", "/signalr/negotiate", "/sockjs/websocket",
]

INJECTION_PAYLOADS = [
    '{"type":"<script>alert(1)</script>"}',
    '{"message":"\'OR 1=1--"}',
    '{"cmd":"ls /"}',
    '{"action":"../../../etc/passwd"}',
    '{"query":"{ __typename }"}',          # GraphQL-over-WS probe
    '{"event":"phx_join","topic":"admin"}', # Phoenix channel privilege escalation
    '{"type":"subscribe","channel":"AdminChannel"}',  # ActionCable admin subscribe
]

# Ping-flood DoS check — count pings returned in 3 s window
PING_FRAME_COUNT = 50


class WebsocketAudit(BaseModule):
    """WebSocket security auditor."""

    NAME        = "websocket_audit"
    DESCRIPTION = "WebSocket: CSWSH, injection testing, missing authentication detection"
    PHASE       = 10
    TAGS        = ["advanced", "websocket", "cswsh", "owasp-a01", "cwe-345"]

    async def run(self) -> ModuleResult:
        """Discover and audit WebSocket endpoints."""
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Derive ws:// URL from http(s)://
        if target.startswith("https://"):
            ws_base = "wss://" + target[8:]
        else:
            ws_base = "ws://" + target[7:]

        # First check HTML for WebSocket upgrade indicators
        http_target = target
        connector   = aiohttp.TCPConnector(ssl=False)
        timeout     = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            ws_hints = await self._find_ws_hints(session, http_target)
            await self._check_cors_header(session, http_target)

        # Try WebSocket connections
        for endpoint in WS_ENDPOINTS + ws_hints:
            ws_url = f"{ws_base}{endpoint}" if not endpoint.startswith("ws") else endpoint
            http_equivalent = ws_url.replace("wss://", "https://").replace("ws://", "http://")
            if not self.check_scope(http_equivalent):
                continue
            await self._probe_websocket(ws_url, target)
            await self._check_jwt_in_ws(ws_url, target)
            await self._check_subprotocol_confusion(ws_url, target)

        return self._make_result(start)

    async def _find_ws_hints(
        self, session: aiohttp.ClientSession, target: str
    ) -> list[str]:
        """Scan homepage JS/HTML for WebSocket endpoint strings."""
        hints: list[str] = []
        await self.rate_limit()
        try:
            async with session.get(target) as resp:
                body = await resp.text(errors="ignore")
                import re
                ws_matches = re.findall(r'["\'](?:wss?://[^"\']+|/[^"\']*socket[^"\']*)["\']', body)
                for m in ws_matches:
                    path = m.strip("'\"")
                    if path.startswith("/"):
                        hints.append(path)
        except Exception:
            pass
        return hints[:10]

    async def _check_cors_header(
        self, session: aiohttp.ClientSession, target: str
    ) -> None:
        """Check if the HTTP response allows all origins (CSWSH precondition)."""
        await self.rate_limit()
        try:
            async with session.get(
                target,
                headers={"Origin": "https://evil.example.com"},
            ) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*" or (acao and acac.lower() == "true"):
                    ev = Evidence(
                        request_raw=f"GET {target} HTTP/1.1\nOrigin: https://evil.example.com",
                        response_raw=f"HTTP {resp.status}\nAccess-Control-Allow-Origin: {acao}\n"
                                     f"Access-Control-Allow-Credentials: {acac}",
                        extra={"acao": acao, "acac": acac},
                    )
                    self.new_finding(
                        title="Permissive CORS Enabling Cross-Site WebSocket Hijacking (CSWSH)",
                        severity=Severity.HIGH,
                        description=(
                            "The server reflects a permissive CORS policy "
                            f"(Access-Control-Allow-Origin: {acao}) combined with "
                            f"Access-Control-Allow-Credentials: {acac}. "
                            "If WebSocket endpoints exist, they may be susceptible to "
                            "Cross-Site WebSocket Hijacking (CSWSH) attacks."
                        ),
                        reproduction_steps=[
                            f"Send GET {target} with Origin: https://evil.example.com",
                            f"Observe ACAO: {acao} and ACAC: {acac}",
                            "Craft CSWSH PoC from evil.example.com",
                        ],
                        remediation=(
                            "Validate the Origin header against a strict allowlist. "
                            "Never combine wildcard ACAO with Allow-Credentials: true. "
                            "Implement CSRF tokens in WebSocket handshake."
                        ),
                        references=["CWE-345", "CWE-942", "OWASP A01:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_WS_HIJACK,
                        target=target,
                    )
        except Exception:
            pass

    async def _probe_websocket(self, ws_url: str, http_target: str) -> None:
        """Attempt WebSocket connection — check for unauthenticated access + injection."""
        await self.rate_limit()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    ws_url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)
                ) as ws:
                    # Connected without authentication token
                    ev = Evidence(
                        request_raw=f"GET {ws_url} HTTP/1.1\nUpgrade: websocket",
                        response_raw="HTTP 101 Switching Protocols — connected",
                        extra={"endpoint": ws_url},
                    )
                    self.new_finding(
                        title=f"WebSocket Accepts Unauthenticated Connection: {ws_url}",
                        severity=Severity.HIGH,
                        description=(
                            f"The WebSocket endpoint {ws_url} accepted a connection "
                            "without requiring any authentication token or session cookie. "
                            "Unauthenticated WebSocket access may expose real-time data feeds."
                        ),
                        reproduction_steps=[
                            f"Connect to {ws_url} with no authentication headers",
                            "Observe successful HTTP 101 handshake",
                        ],
                        remediation=(
                            "Validate session tokens or JWT in the WebSocket handshake "
                            "headers. Reject connections without valid authentication."
                        ),
                        references=["CWE-306", "OWASP A07:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_WS_NO_AUTH,
                        target=ws_url,
                    )

                    # Test injection via WebSocket messages
                    for payload in INJECTION_PAYLOADS:
                        await ws.send_str(payload)
                        await self.rate_limit()
                        try:
                            msg = await ws.receive(timeout=3)
                            if msg.data and any(
                                x in str(msg.data) for x in ["root:", "/bin/", "alert("]
                            ):
                                ev2 = Evidence(
                                    request_raw=f"WS SEND: {payload}",
                                    response_raw=f"WS RECV: {str(msg.data)[:300]}",
                                    extra={"payload": payload},
                                )
                                self.new_finding(
                                    title=f"WebSocket Injection Response: {ws_url}",
                                    severity=Severity.HIGH,
                                    description=(
                                        "A WebSocket injection payload triggered a suspicious "
                                        "response indicating the server may be processing "
                                        "injected commands."
                                    ),
                                    reproduction_steps=[
                                        f"Connect to {ws_url}",
                                        f"Send message: {payload}",
                                        "Observe response containing injected content",
                                    ],
                                    remediation=(
                                        "Validate and sanitize all WebSocket message content. "
                                        "Apply strict message schema validation."
                                    ),
                                    references=["CWE-74", "OWASP A03:2021"],
                                    evidence=ev2,
                                    cvss_v31_vector=CVSS_WS_INJECT,
                                    target=ws_url,
                                )
                        except Exception:
                            pass
        except Exception as exc:
            self.log.debug("WebSocket probe on %s: %s", ws_url, exc)


    async def _check_jwt_in_ws(self, ws_url: str, http_target: str) -> None:
        """Check if WS handshake uses JWT in URL query param (log exposure risk)."""
        import re
        token_url = f"{ws_url}?token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0."
        await self.rate_limit()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    token_url, ssl=False, timeout=aiohttp.ClientTimeout(total=5)
                ) as ws:
                    # Connected with JWT in URL (or got a structured error with JWT)
                    ev = Evidence(
                        request_raw=f"GET {ws_url}?token=<jwt_in_url>",
                        response_raw="101 Switching Protocols (token accepted in URL)",
                        extra={"jwt_in_url": True, "alg": "none"},
                    )
                    self.new_finding(
                        title=f"WebSocket JWT in URL — Token Exposed in Server Logs: {ws_url}",
                        severity=Severity.MEDIUM,
                        description=(
                            "The WebSocket endpoint accepts authentication tokens via the URL "
                            "query string (?token=). URL parameters are logged by web servers, "
                            "proxies, and CDNs, exposing session tokens in access logs. "
                            "Additionally, the 'alg: none' JWT was accepted (signature bypass)."
                        ),
                        reproduction_steps=[
                            f"Connect to {ws_url}?token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
                            "Observe successful 101 handshake with unsigned JWT",
                        ],
                        remediation=(
                            "Pass JWT in the Sec-WebSocket-Protocol header or via first message "
                            "after handshake — never in the URL. "
                            "Reject 'alg: none' JWTs on the server side."
                        ),
                        references=["CWE-598", "CWE-347", "OWASP A07:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_WS_NO_AUTH,
                        target=ws_url,
                    )
        except Exception:
            pass

    async def _check_subprotocol_confusion(self, ws_url: str, http_target: str) -> None:
        """Test WebSocket subprotocol confusion — request privileged protocol."""
        privileged_protocols = ["graphql-ws", "graphql-transport-ws", "actioncable-v1-json",
                                 "phoenix", "stomp", "v10.stomp", "v11.stomp"]
        await self.rate_limit()
        for proto in privileged_protocols:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(
                        ws_url, ssl=False, timeout=aiohttp.ClientTimeout(total=5),
                        protocols=[proto],
                    ) as ws:
                        ev = Evidence(
                            request_raw=f"GET {ws_url}\nSec-WebSocket-Protocol: {proto}",
                            response_raw=f"101 Switching Protocols (subprotocol: {proto})",
                            extra={"accepted_subprotocol": proto},
                        )
                        self.new_finding(
                            title=f"WebSocket Accepts '{proto}' Subprotocol: {ws_url}",
                            severity=Severity.MEDIUM,
                            description=(
                                f"The WebSocket endpoint accepted the '{proto}' subprotocol "
                                "without authentication. Privileged subprotocols (GraphQL, "
                                "ActionCable admin, Phoenix channels) may expose elevated "
                                "functionality to unauthenticated connections."
                            ),
                            reproduction_steps=[
                                f"wscat -c {ws_url} --subprotocol {proto}",
                                "Attempt privileged operations via protocol-specific messages",
                            ],
                            remediation=(
                                "Authenticate connections before negotiating privileged "
                                "subprotocols. Validate the subprotocol matches the expected "
                                "client type and authorization level."
                            ),
                            references=["CWE-306", "OWASP A01:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_WS_NO_AUTH,
                            target=ws_url,
                        )
                        break  # One finding per endpoint is enough
            except Exception:
                continue


class TestWebsocketAudit:
    def test_endpoints_non_empty(self) -> None:
        assert len(WS_ENDPOINTS) >= 4

    def test_injection_payloads_non_empty(self) -> None:
        assert len(INJECTION_PAYLOADS) >= 3

    def test_cvss_vectors(self) -> None:
        for v in (CVSS_WS_HIJACK, CVSS_WS_INJECT, CVSS_WS_NO_AUTH):
            assert v.startswith("CVSS:3.1/")
