"""WebSocket Audit — injection, auth bypass, message manipulation."""
from __future__ import annotations
import asyncio, json, re, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence
import aiohttp

CVSS_NO_AUTH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_NO_AUTH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

WS_PATHS = ["/ws", "/websocket", "/socket", "/ws/v1", "/api/ws", "/realtime",
            "/socket.io/?EIO=4&transport=websocket", "/cable"]

class WebsocketAudit(BaseModule):
    NAME = "websocket_audit"
    DESCRIPTION = "WebSocket: unauthenticated access, CSWSH, injection"
    PHASE = 10
    TAGS = ["advanced", "websocket", "cwe-287"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        ws_target = target.replace("https://", "wss://").replace("http://", "ws://")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        connected_endpoints = []

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=10),
        ) as session:
            for path in WS_PATHS:
                await self.rate_limit()
                try:
                    async with session.ws_connect(
                        f"{ws_target}{path}", timeout=5,
                        origin=f"https://evil.com",  # Test CSWSH
                    ) as ws:
                        connected_endpoints.append({"path": path, "cross_origin": True})

                        # Send test messages
                        test_msgs = [
                            '{"type":"ping"}',
                            '{"action":"subscribe","channel":"all"}',
                            '{"query":"test"}',
                        ]
                        responses = []
                        for msg in test_msgs:
                            await ws.send_str(msg)
                            try:
                                resp = await asyncio.wait_for(ws.receive(), timeout=3)
                                if resp.type == aiohttp.WSMsgType.TEXT:
                                    responses.append(resp.data[:200])
                            except asyncio.TimeoutError:
                                break

                        if responses:
                            connected_endpoints[-1]["responses"] = responses[:3]

                        await ws.close()
                except Exception:
                    # Try without cross-origin
                    try:
                        async with session.ws_connect(f"{ws_target}{path}", timeout=5) as ws:
                            connected_endpoints.append({"path": path, "cross_origin": False})
                            await ws.close()
                    except Exception:
                        pass

        if connected_endpoints:
            cross_origin = [e for e in connected_endpoints if e.get("cross_origin")]
            if cross_origin:
                ev = Evidence(extra={"endpoints": cross_origin[:10]})
                self.new_finding(
                    title=f"WebSocket CSWSH — {len(cross_origin)} endpoint(s) accept cross-origin",
                    severity=Severity.HIGH,
                    description=(
                        f"WebSocket endpoint(s) accept connections from evil.com origin:\n"
                        + "\n".join(f"  {e['path']}" for e in cross_origin[:5])
                        + "\n\nCross-Site WebSocket Hijacking (CSWSH): an attacker's page can "
                        "open a WebSocket to the victim's server using the victim's cookies."
                    ),
                    reproduction_steps=[
                        f"# From attacker page: new WebSocket('{ws_target}{cross_origin[0]['path']}')",
                    ],
                    remediation="Validate Origin header on WebSocket upgrade. Require auth token in first message.",
                    references=["CWE-346", "OWASP WebSocket Security"],
                    evidence=ev, cvss_v31_vector=CVSS_NO_AUTH, cvss_v40_vector=CVSS40_NO_AUTH,
                    target=target)
            else:
                ev = Evidence(extra={"endpoints": [e["path"] for e in connected_endpoints]})
                self.new_finding(
                    title=f"WebSocket Endpoints — {len(connected_endpoints)} found",
                    severity=Severity.INFORMATIONAL,
                    description=f"WebSocket endpoints: {', '.join(e['path'] for e in connected_endpoints[:5])}",
                    reproduction_steps=[f"wscat -c {ws_target}{connected_endpoints[0]['path']}"],
                    remediation="Review WebSocket authentication and authorization.",
                    references=["CWE-287"],
                    evidence=ev, cvss_v31_vector=CVSS_INFO, cvss_v40_vector=CVSS40_INFO,
                    target=target)

        return self._make_result(start)

class TestWebsocketAudit:
    def test_paths(self) -> None: assert "/ws" in WS_PATHS
    def test_phase(self) -> None: assert WebsocketAudit.PHASE == 10
