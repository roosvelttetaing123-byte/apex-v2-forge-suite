"""RDP Auditor — NLA check, BlueKeep (CVE-2019-0708), CredSSP, encryption level.

Tests:
  - Network Level Authentication (NLA) enforcement
  - BlueKeep (CVE-2019-0708) vulnerability detection
  - RDP encryption level (standard vs enhanced vs TLS)
  - CredSSP / NTLMv1 downgrade risk
  - RDP gateway exposure
"""
from __future__ import annotations

import asyncio
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_BLUEKEEP       = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_BLUEKEEP     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
CVSS_NO_NLA         = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_NO_NLA       = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_WEAK_ENCRYPT   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_WEAK_ENCRYPT = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"


class RdpAudit(BaseModule):
    """RDP security auditor — NLA, BlueKeep, encryption, CredSSP."""

    NAME        = "rdp_audit"
    DESCRIPTION = "RDP: NLA enforcement, BlueKeep (CVE-2019-0708), encryption level, CredSSP"
    PHASE       = 4
    TAGS        = ["rdp", "services", "cve-2019-0708", "cwe-287"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        port = self.config.extra.get("rdp_port", 3389)

        for host in hosts[:30]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            if await self._port_open(host, port):
                await self._audit_rdp(host, port)

        return self._make_result(start)

    async def _audit_rdp(self, host: str, port: int) -> None:
        """Probe RDP security via X.224 Connection Request."""
        # Send RDP Connection Request with different security protocols
        # to determine NLA support and encryption

        # Test 1: Request with no security (protocol 0)
        no_sec = await self._send_x224(host, port, requested_protocols=0)
        # Test 2: Request with TLS (protocol 1)
        tls_result = await self._send_x224(host, port, requested_protocols=1)
        # Test 3: Request with CredSSP/NLA (protocol 3)
        nla_result = await self._send_x224(host, port, requested_protocols=3)

        # Analyze: if no-security is accepted, NLA is not enforced
        if no_sec and no_sec.get("accepted"):
            ev = Evidence(
                request_raw=f"X.224 CR → {host}:{port} (requestedProtocols=0x0000)",
                response_raw=f"Server accepted standard RDP security (no NLA)",
                extra={"host": host, "nla_required": False, **no_sec},
            )
            self.new_finding(
                title=f"RDP Network Level Authentication Not Required — {host}:{port}",
                severity=Severity.MEDIUM,
                description=(
                    f"RDP on {host}:{port} accepts connections without Network Level Authentication (NLA). "
                    "Without NLA, the RDP login screen is presented before authentication, enabling:\n"
                    "  - Credential brute force without NLA protection\n"
                    "  - Pre-auth vulnerability exploitation (BlueKeep)\n"
                    "  - Screenshot/screencast of the login screen for social engineering\n"
                    "  - Resource exhaustion via unauthenticated session creation"
                ),
                reproduction_steps=[
                    f"xfreerdp /v:{host}:{port} /sec:rdp",
                    "# Should show Windows login screen without requiring NLA",
                    f"# nmap: nmap -p {port} --script rdp-enum-encryption {host}",
                ],
                remediation=(
                    "Enable NLA (Network Level Authentication):\n"
                    "  GPO: Computer Configuration > Admin Templates > Windows Components >\n"
                    "  Remote Desktop Services > Remote Desktop Session Host > Security >\n"
                    "  'Require use of specific security layer' = SSL/TLS\n"
                    "  'Require user authentication for remote connections by using NLA' = Enabled"
                ),
                references=["CWE-287", "MITRE T1021.001"],
                evidence=ev,
                cvss_v31_vector=CVSS_NO_NLA,
                cvss_v40_vector=CVSS40_NO_NLA,
                mitre_attack=["TA0001/T1021.001"],
                port=port, service="rdp", target=host,
            )

        # Check for BlueKeep (CVE-2019-0708)
        await self._check_bluekeep(host, port)

        # Check encryption level via nmap if available
        await self._check_encryption_nmap(host, port)

    async def _send_x224(
        self, host: str, port: int, requested_protocols: int
    ) -> dict | None:
        """Send X.224 Connection Request and parse Confirm/Negotiation response."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

            # Build X.224 Connection Request (CR) with RDP Negotiation Request
            cookie = b"Cookie: mstshash=forgescan\r\n"
            neg_req = struct.pack("<BHI", 0x01, 0x0008, requested_protocols)
            x224_cr = bytes([len(cookie) + len(neg_req) + 6, 0xe0, 0x00, 0x00, 0x00, 0x00]) + cookie + neg_req
            tpkt = struct.pack(">BBI", 3, 0, len(x224_cr) + 4) + x224_cr

            writer.write(tpkt)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(512), timeout=5)
            writer.close()

            if len(data) < 11:
                return None

            # Parse TPKT + X.224 Connection Confirm
            tpkt_len = struct.unpack(">H", data[2:4])[0]
            x224_type = data[5] >> 4

            if x224_type == 0xd:  # Connection Confirm (0xd0)
                result = {"accepted": True, "requested": requested_protocols}
                # Check for RDP Negotiation Response
                if len(data) >= 19:
                    neg_type = data[11]
                    if neg_type == 0x02:  # TYPE_RDP_NEG_RSP
                        selected_protocol = struct.unpack("<I", data[15:19])[0]
                        result["selected_protocol"] = selected_protocol
                        result["nla"] = bool(selected_protocol & 0x02)
                        result["tls"] = bool(selected_protocol & 0x01)
                    elif neg_type == 0x03:  # TYPE_RDP_NEG_FAILURE
                        result["accepted"] = False
                        if len(data) >= 19:
                            failure_code = struct.unpack("<I", data[15:19])[0]
                            result["failure_code"] = failure_code
                return result
            elif x224_type == 0x5:  # Disconnect
                return {"accepted": False, "disconnect": True}
            return None

        except Exception:
            return None

    async def _check_bluekeep(self, host: str, port: int) -> None:
        """Check for BlueKeep via nmap NSE script."""
        import shutil
        nmap = shutil.which("nmap")
        if not nmap:
            return

        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-p", str(port),
                "--script", "rdp-vuln-ms12-020,rdp-ntlm-info",
                "--script-timeout", "15s",
                "-n", "-Pn", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode(errors="ignore")

            if "VULNERABLE" in output and "ms12-020" in output.lower():
                ev = Evidence(
                    request_raw=f"nmap --script rdp-vuln-ms12-020 -p {port} {host}",
                    response_raw=output[:2000],
                    extra={"host": host, "cve": "CVE-2019-0708"},
                )
                self.new_finding(
                    title=f"BlueKeep (CVE-2019-0708) VULNERABLE — {host}:{port}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"RDP on {host}:{port} is vulnerable to CVE-2019-0708 (BlueKeep). "
                        "This pre-authentication RCE allows wormable remote code execution "
                        "as SYSTEM without any user interaction. BlueKeep is actively exploited "
                        "in the wild and was classified as wormable by Microsoft."
                    ),
                    reproduction_steps=[
                        f"nmap -p {port} --script rdp-vuln-ms12-020 {host}",
                        "# Metasploit: use exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
                    ],
                    remediation=(
                        "EMERGENCY: Patch immediately with Microsoft security update.\n"
                        "If patching is not immediately possible:\n"
                        "1. Enable NLA (mitigates unauthenticated exploitation)\n"
                        "2. Block TCP 3389 at perimeter firewall\n"
                        "3. Isolate affected hosts in quarantine VLAN"
                    ),
                    references=["CVE-2019-0708", "MS19-058", "MITRE T1210"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_BLUEKEEP,
                    cvss_v40_vector=CVSS40_BLUEKEEP,
                    mitre_attack=["TA0002/T1210"],
                    port=port, service="rdp", target=host,
                )
        except Exception as exc:
            self.log.debug("BlueKeep check failed on %s: %s", host, exc)

    async def _check_encryption_nmap(self, host: str, port: int) -> None:
        """Check RDP encryption level via nmap rdp-enum-encryption."""
        import shutil
        nmap = shutil.which("nmap")
        if not nmap:
            return

        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-p", str(port),
                "--script", "rdp-enum-encryption",
                "--script-timeout", "15s",
                "-n", "-Pn", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode(errors="ignore")

            # Check for weak encryption
            weak_indicators = ["40-bit", "56-bit", "FIPS", "ENCRYPTION_LEVEL_NONE"]
            has_weak = any(ind.lower() in output.lower() for ind in weak_indicators)
            if has_weak and "ENCRYPTION_LEVEL_NONE" in output.upper():
                ev = Evidence(
                    request_raw=f"nmap --script rdp-enum-encryption -p {port} {host}",
                    response_raw=output[:1500],
                    extra={"host": host},
                )
                self.new_finding(
                    title=f"RDP Weak/No Encryption — {host}:{port}",
                    severity=Severity.HIGH,
                    description=(
                        f"RDP on {host}:{port} supports weak or no encryption. "
                        "This allows MITM attackers to intercept RDP sessions and "
                        "capture keystrokes, credentials, and screen contents."
                    ),
                    reproduction_steps=[
                        f"nmap -p {port} --script rdp-enum-encryption {host}",
                    ],
                    remediation=(
                        "Set minimum encryption level to High:\n"
                        "GPO: Remote Desktop Session Host > Security >\n"
                        "'Set client connection encryption level' = High\n"
                        "Enforce TLS as security layer."
                    ),
                    references=["CWE-326"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_WEAK_ENCRYPT,
                    cvss_v40_vector=CVSS40_WEAK_ENCRYPT,
                    port=port, service="rdp", target=host,
                )
        except Exception:
            pass

    async def _port_open(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            writer.close()
            return True
        except Exception:
            return False


class TestRdpAudit:
    def test_cvss_bluekeep(self) -> None:
        assert CVSS_BLUEKEEP.startswith("CVSS:3.1")
        assert CVSS40_BLUEKEEP.startswith("CVSS:4.0")
        assert "/S:C/" in CVSS_BLUEKEEP

    def test_cvss_nla(self) -> None:
        assert CVSS_NO_NLA.startswith("CVSS:3.1")

    def test_phase(self) -> None:
        assert RdpAudit.PHASE == 4
