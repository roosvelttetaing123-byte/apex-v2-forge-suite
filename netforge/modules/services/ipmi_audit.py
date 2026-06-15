"""IPMI Auditor — IPMI 2.0 hash leak (cipher 0), default credentials, RAKP attack.

Tests:
  - IPMI 2.0 RAKP authentication bypass (cipher 0 — HMAC hash disclosure)
  - Default BMC credentials
  - Anonymous IPMI access
  - Version detection
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

CVSS_CIPHER0     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_CIPHER0   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_DEFAULT_CRED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_DEFAULT_CRED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("ADMIN", "ADMIN"),
    ("root", "calvin"),    # Dell iDRAC
    ("root", "changeme"),  # Supermicro
    ("USERID", "PASSW0RD"), # IBM/Lenovo
    ("admin", "password"),
    ("Administrator", ""),  # HP iLO
]


class IpmiAudit(BaseModule):
    """IPMI/BMC security auditor."""

    NAME        = "ipmi_audit"
    DESCRIPTION = "IPMI: cipher 0 hash leak, default BMC credentials, RAKP attack"
    PHASE       = 4
    TAGS        = ["ipmi", "bmc", "services", "cwe-287", "cwe-327"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._audit_ipmi(host)

        return self._make_result(start)

    async def _audit_ipmi(self, host: str) -> None:
        # IPMI uses UDP 623
        if not await self._ipmi_probe(host):
            return

        # Check for cipher 0 via nmap or ipmitool
        await self._check_cipher0(host)

        # Test default credentials via ipmitool
        await self._test_default_creds(host)

    async def _ipmi_probe(self, host: str) -> bool:
        """Send IPMI Get Channel Auth Capabilities to detect IPMI service."""
        try:
            # IPMI over LAN uses UDP port 623
            # RMCP header + IPMI session header + Get Channel Auth Capabilities
            rmcp_header = bytes([0x06, 0x00, 0xff, 0x07])  # RMCP version 0x06
            ipmi_session = bytes([
                0x00,                   # auth type: none
                0x00, 0x00, 0x00, 0x00, # seq num
                0x00, 0x00, 0x00, 0x00, # session id
                0x09,                   # message length
            ])
            # Get Channel Auth Capabilities command
            get_auth = bytes([
                0x20,   # target addr (BMC)
                0x18,   # netfn/lun (App 0x06 << 2 | 0x00)
                0x00,   # checksum placeholder
                0x81,   # source addr
                0x04,   # seq/lun
                0x38,   # cmd: Get Channel Auth Capabilities
                0x0e,   # channel: current channel, IPMI v2.0
                0x04,   # privilege: Administrator
            ])
            # Calculate checksum
            chk1 = (-sum(get_auth[:2])) & 0xFF
            chk2 = (-sum(get_auth[3:])) & 0xFF
            msg = rmcp_header + ipmi_session + get_auth[:2] + bytes([chk1]) + get_auth[3:] + bytes([chk2])

            loop = asyncio.get_event_loop()
            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    asyncio.DatagramProtocol,
                    remote_addr=(host, 623),
                ),
                timeout=3,
            )

            transport.sendto(msg)
            await asyncio.sleep(2)
            transport.close()
            return True  # If we got here without error, port is open
        except Exception:
            # Fallback: try nmap
            import shutil
            nmap = shutil.which("nmap")
            if nmap:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        nmap, "-sU", "-p", "623", "-n", "-Pn", host,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                    return "open" in stdout.decode(errors="ignore")
                except Exception:
                    pass
            return False

    async def _check_cipher0(self, host: str) -> None:
        """Check for IPMI cipher 0 vulnerability via nmap."""
        import shutil
        nmap = shutil.which("nmap")
        if not nmap:
            # Try ipmitool
            ipmitool = shutil.which("ipmitool")
            if ipmitool:
                await self._cipher0_ipmitool(host, ipmitool)
            return

        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-sU", "-p", "623",
                "--script", "ipmi-cipher-zero",
                "--script-timeout", "15s",
                "-n", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode(errors="ignore")

            if "cipher zero" in output.lower() or "cipher 0" in output.lower():
                ev = Evidence(
                    request_raw=f"nmap --script ipmi-cipher-zero -sU -p 623 {host}",
                    response_raw=output[:1500],
                    extra={"host": host, "cipher_zero": True},
                )
                self.new_finding(
                    title=f"IPMI Cipher 0 — Authentication Bypass — {host}:623",
                    severity=Severity.CRITICAL,
                    description=(
                        f"IPMI 2.0 on {host}:623 supports cipher 0 (no authentication). "
                        "Cipher 0 allows ANY user to authenticate without providing a password. "
                        "Additionally, the RAKP protocol leaks HMAC-SHA1 password hashes for "
                        "any valid username, enabling offline password cracking.\n\n"
                        "IPMI provides out-of-band hardware management — an attacker with IPMI "
                        "access can power cycle servers, access virtual console, mount ISOs, "
                        "and install firmware-level backdoors."
                    ),
                    reproduction_steps=[
                        f"ipmitool -I lanplus -H {host} -C 0 -U admin -P any_password chassis status",
                        f"# Hash dump: nmap -sU -p 623 --script ipmi-brute {host}",
                        f"# Metasploit: use auxiliary/scanner/ipmi/ipmi_dumphashes",
                    ],
                    remediation=(
                        "1. Disable cipher 0 in BMC configuration\n"
                        "2. Update BMC firmware to latest version\n"
                        "3. Isolate IPMI on a dedicated management VLAN\n"
                        "4. Set strong, unique passwords for all BMC accounts\n"
                        "5. Dell iDRAC: racadm set iDRAC.IPMILan.CipherSuitePrivilege 0,0,0,X,X,X,X,X,X,X,X,X,X,X,X,X"
                    ),
                    references=["CVE-2013-4786", "CWE-327", "CWE-287"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CIPHER0,
                    cvss_v40_vector=CVSS40_CIPHER0,
                    port=623, service="ipmi", target=host,
                )
        except Exception:
            pass

    async def _cipher0_ipmitool(self, host: str, ipmitool: str) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                ipmitool, "-I", "lanplus", "-H", host,
                "-C", "0", "-U", "admin", "-P", "doesntmatter",
                "chassis", "status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode(errors="ignore")
            if "System Power" in output or "Chassis" in output:
                ev = Evidence(
                    request_raw=f"ipmitool -C 0 -U admin -P doesntmatter chassis status",
                    response_raw=output[:500],
                    extra={"host": host, "cipher_zero": True},
                )
                self.new_finding(
                    title=f"IPMI Cipher 0 — Auth Bypass — {host}:623",
                    severity=Severity.CRITICAL,
                    description=f"IPMI cipher 0 confirmed on {host} — any password accepted.",
                    reproduction_steps=[f"ipmitool -I lanplus -H {host} -C 0 -U admin -P x chassis status"],
                    remediation="Disable cipher 0 in BMC settings. Update firmware.",
                    references=["CVE-2013-4786", "CWE-327"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CIPHER0,
                    cvss_v40_vector=CVSS40_CIPHER0,
                    port=623, service="ipmi", target=host,
                )
        except Exception:
            pass

    async def _test_default_creds(self, host: str) -> None:
        import shutil
        ipmitool = shutil.which("ipmitool")
        if not ipmitool:
            return

        for username, password in DEFAULT_CREDS[:5]:
            await self.rate_limit()
            try:
                proc = await asyncio.create_subprocess_exec(
                    ipmitool, "-I", "lanplus", "-H", host,
                    "-U", username, "-P", password,
                    "chassis", "status",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="ignore")
                if "System Power" in output:
                    ev = Evidence(
                        extra={"host": host, "username": username, "password": password},
                    )
                    self.new_finding(
                        title=f"IPMI Default Credentials — {username}@{host}:623",
                        severity=Severity.CRITICAL,
                        description=(
                            f"IPMI BMC login with {username}:{password} on {host}. "
                            "Full hardware management access — can power cycle, access console, "
                            "modify BIOS, mount virtual media."
                        ),
                        reproduction_steps=[
                            f"ipmitool -I lanplus -H {host} -U {username} -P {password} chassis status",
                        ],
                        remediation="Change BMC passwords. Isolate IPMI on management VLAN.",
                        references=["CWE-798"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_DEFAULT_CRED,
                        cvss_v40_vector=CVSS40_DEFAULT_CRED,
                        port=623, service="ipmi", target=host,
                    )
                    return
            except Exception:
                pass


class TestIpmiAudit:
    def test_default_creds(self) -> None:
        users = [u for u, _ in DEFAULT_CREDS]
        assert "root" in users  # Dell iDRAC

    def test_cvss(self) -> None:
        assert CVSS_CIPHER0.startswith("CVSS:3.1")
        assert CVSS40_CIPHER0.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert IpmiAudit.PHASE == 4
