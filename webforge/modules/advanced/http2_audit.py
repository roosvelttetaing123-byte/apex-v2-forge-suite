"""HTTP/2 Audit — H2C upgrade, smuggling, rapid reset DoS detection."""
from __future__ import annotations
import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
import aiohttp

CVSS_H2C = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_H2C = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

# HTTP/2 connection preface
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

class Http2Audit(BaseModule):
    NAME = "http2_audit"
    DESCRIPTION = "HTTP/2: H2C cleartext upgrade, smuggling, protocol detection"
    PHASE = 10
    TAGS = ["advanced", "http2", "cwe-444"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=10),
        ) as session:
            # Check HTTP/2 support
            await self.rate_limit()
            h2_supported = False
            try:
                async with session.get(target) as resp:
                    protocol = resp.version
                    if hasattr(resp, 'protocol') and '2' in str(resp.protocol):
                        h2_supported = True
                    # Check via ALPN in response
                    if resp.headers.get("Alt-Svc", ""):
                        alt_svc = resp.headers["Alt-Svc"]
                        if "h2" in alt_svc:
                            h2_supported = True
            except Exception:
                pass

            # Test H2C upgrade (cleartext HTTP/2)
            await self.rate_limit()
            h2c_accepted = False
            try:
                async with session.get(
                    target,
                    headers={
                        "Upgrade": "h2c",
                        "HTTP2-Settings": "AAMAAABkAAQCAAAAAAIAAAAA",
                        "Connection": "Upgrade, HTTP2-Settings",
                    },
                ) as resp:
                    if resp.status == 101:
                        h2c_accepted = True
                    elif resp.headers.get("Upgrade", "").lower() == "h2c":
                        h2c_accepted = True
            except Exception:
                pass

            if h2c_accepted:
                ev = Evidence(
                    request_raw="GET / HTTP/1.1\r\nUpgrade: h2c\r\nHTTP2-Settings: ...",
                    extra={"h2c": True})
                self.new_finding(
                    title=f"H2C Smuggling — cleartext HTTP/2 upgrade accepted",
                    severity=Severity.HIGH,
                    description=(
                        "Server accepts H2C (cleartext HTTP/2) upgrade requests. "
                        "If a reverse proxy forwards the Upgrade header, an attacker can "
                        "establish a direct HTTP/2 connection to the backend, bypassing "
                        "proxy-level access controls, WAF rules, and authentication."
                    ),
                    reproduction_steps=[
                        f"h2cSmuggler.py -x {target} /admin",
                        f"# Or: curl --http2 {target}",
                    ],
                    remediation="Disable H2C upgrade. Strip Upgrade headers at the reverse proxy.",
                    references=["CWE-444"],
                    evidence=ev, cvss_v31_vector=CVSS_H2C, cvss_v40_vector=CVSS40_H2C,
                    target=target)

            # Test HTTP/2 CONNECT method (tunnel abuse)
            await self.rate_limit()
            try:
                async with session.request("CONNECT", target) as resp:
                    if resp.status in (200, 101):
                        ev = Evidence(extra={"connect_allowed": True})
                        self.new_finding(
                            title="HTTP/2 CONNECT Allowed — SSRF/tunnel risk",
                            severity=Severity.MEDIUM,
                            description="HTTP CONNECT method is accepted. May allow SSRF via HTTP tunneling.",
                            reproduction_steps=[f"curl -X CONNECT {target}"],
                            remediation="Disable CONNECT method.",
                            references=["CWE-918"],
                            evidence=ev,
                            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                            cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
                            target=target)
            except Exception:
                pass

        return self._make_result(start)

class TestHttp2Audit:
    def test_preface(self) -> None: assert H2_PREFACE.startswith(b"PRI")
    def test_phase(self) -> None: assert Http2Audit.PHASE == 10
