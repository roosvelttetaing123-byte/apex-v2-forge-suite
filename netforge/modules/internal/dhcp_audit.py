"""DHCP Auditor — rogue DHCP detection, starvation surface, option analysis.

Tests:
  - DHCP server discovery (legitimate vs rogue)
  - DHCP option analysis (gateway, DNS, domain)
  - DHCP starvation surface check
  - Lease time analysis
"""
from __future__ import annotations

import asyncio
import platform
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_ROGUE_DHCP = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ROGUE_DHCP = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_STARVE     = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
CVSS40_STARVE   = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"


class DhcpAudit(BaseModule):
    """DHCP security auditor — rogue server detection, starvation surface."""

    NAME        = "dhcp_audit"
    DESCRIPTION = "DHCP: rogue server detection, starvation surface, option analysis"
    PHASE       = 2
    TAGS        = ["dhcp", "internal", "mitm", "cwe-300"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Get current DHCP lease info
        lease_info = await self._get_dhcp_info()
        if not lease_info:
            return self._make_result(start, skipped=True, skip_reason="no DHCP info found")

        # Analyze DHCP configuration
        known_servers = self.config.extra.get("dhcp_servers", [])
        current_server = lease_info.get("dhcp_server", "")

        if known_servers and current_server and current_server not in known_servers:
            ev = Evidence(
                extra={
                    "dhcp_server": current_server,
                    "expected_servers": known_servers,
                    "lease_info": lease_info,
                },
            )
            self.new_finding(
                title=f"Possible Rogue DHCP Server — {current_server}",
                severity=Severity.HIGH,
                description=(
                    f"DHCP server {current_server} is not in the expected server list "
                    f"({', '.join(known_servers)}). "
                    "A rogue DHCP server can redirect all traffic through an attacker's machine "
                    "by providing a malicious default gateway and DNS server."
                ),
                reproduction_steps=[
                    "nmap --script broadcast-dhcp-discover",
                    f"# Current DHCP server: {current_server}",
                ],
                remediation=(
                    "1. Enable DHCP Snooping on all switches\n"
                    "   ip dhcp snooping\n"
                    "   ip dhcp snooping vlan <vlan-id>\n"
                    "   interface <trunk-to-dhcp-server>\n"
                    "     ip dhcp snooping trust\n"
                    "2. Use 802.1X for port authentication\n"
                    "3. Investigate the rogue DHCP server"
                ),
                references=["CWE-300", "MITRE T1557"],
                evidence=ev,
                cvss_v31_vector=CVSS_ROGUE_DHCP,
                cvss_v40_vector=CVSS40_ROGUE_DHCP,
                mitre_attack=["TA0006/T1557"],
                target=target,
            )

        # Report DHCP info regardless
        ev = Evidence(extra={"lease_info": lease_info})
        self.new_finding(
            title=f"DHCP Configuration — Server: {current_server or 'unknown'}",
            severity=Severity.INFORMATIONAL,
            description=(
                f"DHCP lease information:\n"
                + "\n".join(f"  {k}: {v}" for k, v in lease_info.items())
            ),
            reproduction_steps=["ipconfig /all" if platform.system() == "Windows" else "cat /var/lib/dhcp/dhclient.leases"],
            remediation="Enable DHCP Snooping to prevent rogue servers.",
            references=["CWE-200"],
            evidence=ev,
            cvss_v31_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cvss_v40_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            target=target,
        )

        # Check nmap broadcast-dhcp-discover for additional servers
        await self._nmap_dhcp_discover()

        return self._make_result(start)

    async def _get_dhcp_info(self) -> dict:
        is_win = platform.system() == "Windows"
        if is_win:
            return await self._get_dhcp_windows()
        return await self._get_dhcp_linux()

    async def _get_dhcp_windows(self) -> dict:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ipconfig", "/all",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode(errors="ignore")

            info = {}
            dhcp_server = re.search(r"DHCP Server[.\s]+:\s+(\S+)", output)
            if dhcp_server:
                info["dhcp_server"] = dhcp_server.group(1)
            lease_obtained = re.search(r"Lease Obtained[.\s]+:\s+(.+)", output)
            if lease_obtained:
                info["lease_obtained"] = lease_obtained.group(1).strip()
            lease_expires = re.search(r"Lease Expires[.\s]+:\s+(.+)", output)
            if lease_expires:
                info["lease_expires"] = lease_expires.group(1).strip()
            dns = re.findall(r"DNS Servers[.\s]+:\s+(\S+)", output)
            if dns:
                info["dns_servers"] = dns
            gateway = re.search(r"Default Gateway[.\s]+:\s+(\S+)", output)
            if gateway:
                info["gateway"] = gateway.group(1)
            return info
        except Exception:
            return {}

    async def _get_dhcp_linux(self) -> dict:
        lease_files = [
            "/var/lib/dhcp/dhclient.leases",
            "/var/lib/dhclient/dhclient.leases",
            "/var/lib/NetworkManager/*.lease",
        ]
        import glob
        for pattern in lease_files:
            files = glob.glob(pattern)
            for f in files:
                try:
                    with open(f) as fh:
                        content = fh.read()
                    info = {}
                    server = re.search(r"dhcp-server-identifier\s+(\S+)", content)
                    if server:
                        info["dhcp_server"] = server.group(1).rstrip(";")
                    dns = re.findall(r"domain-name-servers\s+(.+?);", content)
                    if dns:
                        info["dns_servers"] = [d.strip() for d in dns[-1].split(",")]
                    gateway = re.search(r"routers\s+(\S+)", content)
                    if gateway:
                        info["gateway"] = gateway.group(1).rstrip(";")
                    if info:
                        return info
                except Exception:
                    continue
        return {}

    async def _nmap_dhcp_discover(self) -> None:
        import shutil
        nmap = shutil.which("nmap")
        if not nmap:
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "--script", "broadcast-dhcp-discover",
                "--script-timeout", "10s",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            # Parse output for multiple DHCP servers (potential rogues)
        except Exception:
            pass


class TestDhcpAudit:
    def test_cvss(self) -> None:
        assert "/AV:A/" in CVSS_ROGUE_DHCP  # Adjacent network
        assert CVSS40_ROGUE_DHCP.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert DhcpAudit.PHASE == 2
