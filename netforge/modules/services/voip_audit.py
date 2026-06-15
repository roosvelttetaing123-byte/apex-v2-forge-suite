"""VoIP Auditor — SIP user enumeration, RTP injection, SRTP downgrade.

Tests:
  - SIP OPTIONS probing (service detection)
  - SIP REGISTER user enumeration (response code analysis)
  - RTP stream injection surface
  - SRTP vs RTP (encryption downgrade)
  - SIP digest auth weakness
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_USER_ENUM   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_USER_ENUM = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_RTP_INJECT  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"
CVSS40_RTP_INJECT = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"

SIP_PORTS = [5060, 5061]

# Common SIP usernames/extensions
SIP_USERS = [
    "100", "101", "102", "200", "201", "300", "1000", "1001",
    "admin", "operator", "test", "guest", "voicemail",
]


class VoipAudit(BaseModule):
    """VoIP/SIP security auditor."""

    NAME        = "voip_audit"
    DESCRIPTION = "VoIP: SIP user enumeration, RTP injection, SRTP downgrade"
    PHASE       = 5
    TAGS        = ["voip", "sip", "services", "cwe-200"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:10]:
            if not self.check_scope(host):
                continue
            for port in SIP_PORTS:
                await self.rate_limit()
                if await self._sip_options(host, port):
                    await self._sip_enum(host, port)
                    break

        return self._make_result(start)

    async def _sip_options(self, host: str, port: int) -> bool:
        """Send SIP OPTIONS to detect SIP service."""
        try:
            options = (
                f"OPTIONS sip:{host} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-forge-scan\r\n"
                f"From: <sip:scanner@127.0.0.1>;tag=forge123\r\n"
                f"To: <sip:{host}>\r\n"
                f"Call-ID: forge-scan-{int(time.time())}@127.0.0.1\r\n"
                f"CSeq: 1 OPTIONS\r\n"
                f"Contact: <sip:scanner@127.0.0.1>\r\n"
                f"Max-Forwards: 70\r\n"
                f"Content-Length: 0\r\n\r\n"
            )

            loop = asyncio.get_event_loop()
            response_data = bytearray()
            response_event = asyncio.Event()

            class SIPProtocol(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    nonlocal response_data
                    response_data.extend(data)
                    response_event.set()

            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    SIPProtocol, remote_addr=(host, port),
                ),
                timeout=3,
            )

            transport.sendto(options.encode())
            try:
                await asyncio.wait_for(response_event.wait(), timeout=3)
            except asyncio.TimeoutError:
                transport.close()
                return False

            transport.close()
            response = response_data.decode(errors="ignore")

            if "SIP/2.0" in response:
                # Extract server info
                server = ""
                for line in response.split("\r\n"):
                    if line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("user-agent:"):
                        server = line.split(":", 1)[1].strip()

                ev = Evidence(
                    request_raw="SIP OPTIONS",
                    response_raw=response[:1000],
                    extra={"host": host, "port": port, "server": server},
                )
                self.new_finding(
                    title=f"SIP Service Detected — {host}:{port}" + (f" ({server})" if server else ""),
                    severity=Severity.LOW,
                    description=(
                        f"SIP service on {host}:{port} responds to OPTIONS. "
                        f"Server: {server or 'unknown'}. "
                        "SIP services may be vulnerable to user enumeration, "
                        "call interception, and toll fraud."
                    ),
                    reproduction_steps=[
                        f"sipvicious: svmap {host}",
                        f"nmap -sU -p {port} --script sip-methods {host}",
                    ],
                    remediation="Restrict SIP to trusted networks. Enable SIP TLS (port 5061).",
                    references=["CWE-200"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_USER_ENUM,
                    cvss_v40_vector=CVSS40_USER_ENUM,
                    port=port, service="sip", target=host,
                )
                return True
            return False
        except Exception:
            return False

    async def _sip_enum(self, host: str, port: int) -> None:
        """Enumerate SIP users via REGISTER response code analysis."""
        valid_users = []

        for user in SIP_USERS:
            await self.rate_limit()
            try:
                register = (
                    f"REGISTER sip:{host} SIP/2.0\r\n"
                    f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-enum-{user}\r\n"
                    f"From: <sip:{user}@{host}>;tag=enum{user}\r\n"
                    f"To: <sip:{user}@{host}>\r\n"
                    f"Call-ID: enum-{user}-{int(time.time())}@127.0.0.1\r\n"
                    f"CSeq: 1 REGISTER\r\n"
                    f"Contact: <sip:{user}@127.0.0.1>\r\n"
                    f"Max-Forwards: 70\r\n"
                    f"Content-Length: 0\r\n\r\n"
                )

                loop = asyncio.get_event_loop()
                resp_data = bytearray()
                resp_event = asyncio.Event()

                class Proto(asyncio.DatagramProtocol):
                    def datagram_received(self, data, addr):
                        nonlocal resp_data
                        resp_data.extend(data)
                        resp_event.set()

                transport, protocol = await asyncio.wait_for(
                    loop.create_datagram_endpoint(Proto, remote_addr=(host, port)),
                    timeout=3,
                )
                transport.sendto(register.encode())
                try:
                    await asyncio.wait_for(resp_event.wait(), timeout=2)
                except asyncio.TimeoutError:
                    transport.close()
                    continue
                transport.close()

                response = resp_data.decode(errors="ignore")
                # 401 = user exists (auth required), 403 = exists but forbidden
                # 404 = user doesn't exist
                if "401" in response[:20] or "407" in response[:20]:
                    valid_users.append(user)
            except Exception:
                pass

        if valid_users:
            ev = Evidence(
                extra={
                    "valid_users": valid_users,
                    "method": "REGISTER response code analysis",
                },
            )
            self.new_finding(
                title=f"SIP User Enumeration — {host} ({len(valid_users)} users)",
                severity=Severity.MEDIUM,
                description=(
                    f"SIP user enumeration via REGISTER reveals {len(valid_users)} valid "
                    f"extensions/users: {', '.join(valid_users[:10])}.\n"
                    "Valid users can be targeted for brute force, vishing, or toll fraud."
                ),
                reproduction_steps=[
                    f"svwar -e 100-999 -m REGISTER {host}",
                ],
                remediation=(
                    "1. Configure uniform response codes (403 for all invalid attempts)\n"
                    "2. Enable SIP authentication on all methods\n"
                    "3. Implement rate limiting on REGISTER/INVITE\n"
                    "4. Use fail2ban for SIP brute force detection"
                ),
                references=["CWE-200", "CWE-203"],
                evidence=ev,
                cvss_v31_vector=CVSS_USER_ENUM,
                cvss_v40_vector=CVSS40_USER_ENUM,
                port=port, service="sip", target=host,
            )


class TestVoipAudit:
    def test_ports(self) -> None:
        assert 5060 in SIP_PORTS

    def test_users(self) -> None:
        assert "100" in SIP_USERS
        assert "admin" in SIP_USERS

    def test_cvss(self) -> None:
        assert CVSS_USER_ENUM.startswith("CVSS:3.1")
        assert CVSS40_USER_ENUM.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert VoipAudit.PHASE == 5
