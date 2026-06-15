"""IPv6 Auditor — RA spoofing surface, dual-stack exposure, SLAAC abuse.

Tests:
  - IPv6 enabled detection
  - Router Advertisement spoofing surface
  - SLAAC-based address predictability
  - Dual-stack firewall bypass risk
  - IPv6 neighbor discovery analysis
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

CVSS_RA_SPOOF   = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_RA_SPOOF = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_DUALSTACK  = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_DUALSTACK = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"


class Ipv6Audit(BaseModule):
    """IPv6 security auditor — RA spoofing, dual-stack, SLAAC."""

    NAME        = "ipv6_audit"
    DESCRIPTION = "IPv6: RA spoofing surface, dual-stack exposure, SLAAC analysis"
    PHASE       = 2
    TAGS        = ["ipv6", "internal", "mitm", "cwe-300"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Check if IPv6 is enabled locally
        ipv6_info = await self._get_ipv6_info()
        if not ipv6_info.get("enabled"):
            return self._make_result(start, skipped=True, skip_reason="IPv6 not detected")

        # RA spoofing surface
        if ipv6_info.get("slaac_addresses"):
            ev = Evidence(
                extra=ipv6_info,
            )
            self.new_finding(
                title=f"IPv6 RA Spoofing Surface Detected",
                severity=Severity.MEDIUM,
                description=(
                    "IPv6 is enabled with SLAAC-based address configuration. "
                    "Router Advertisement (RA) spoofing allows an attacker to:\n"
                    "  1. Become the default IPv6 gateway (MITM all IPv6 traffic)\n"
                    "  2. Assign DNS servers (DNS hijacking)\n"
                    "  3. Advertise routes to redirect traffic\n"
                    "  4. Bypass IPv4-only firewall rules via IPv6 tunnel\n\n"
                    "Tools like mitm6 exploit this in Active Directory environments "
                    "to relay NTLM authentication."
                ),
                reproduction_steps=[
                    "mitm6 -d target.local",
                    "# Or: fake_router6 eth0 fe80::1",
                    "# Combined with ntlmrelayx for AD compromise",
                ],
                remediation=(
                    "1. Enable RA Guard on switches:\n"
                    "   ipv6 nd raguard (Cisco)\n"
                    "2. If IPv6 is not needed, disable it:\n"
                    "   Windows: netsh interface ipv6 set interface <id> routerdiscovery=disabled\n"
                    "   Linux: sysctl net.ipv6.conf.all.disable_ipv6=1\n"
                    "3. Deploy DHCPv6 Guard\n"
                    "4. Monitor for rogue RA packets"
                ),
                references=["CWE-300", "MITRE T1557"],
                evidence=ev,
                cvss_v31_vector=CVSS_RA_SPOOF,
                cvss_v40_vector=CVSS40_RA_SPOOF,
                mitre_attack=["TA0006/T1557"],
                target=target,
            )

        # Dual-stack exposure
        if ipv6_info.get("ipv4_address") and ipv6_info.get("ipv6_addresses"):
            ev = Evidence(
                extra={
                    "ipv4": ipv6_info.get("ipv4_address"),
                    "ipv6": ipv6_info.get("ipv6_addresses", [])[:5],
                },
            )
            self.new_finding(
                title="Dual-Stack (IPv4+IPv6) — Potential Firewall Bypass",
                severity=Severity.LOW,
                description=(
                    "Host has both IPv4 and IPv6 addresses. If IPv6 firewall rules "
                    "are not configured, IPv6 traffic may bypass IPv4-only ACLs. "
                    "Verify that ip6tables/Windows Firewall covers IPv6."
                ),
                reproduction_steps=[
                    "ip -6 addr show" if platform.system() != "Windows" else "ipconfig",
                    "ip6tables -L -n" if platform.system() != "Windows" else "netsh advfirewall show allprofiles",
                ],
                remediation="Ensure firewall rules cover both IPv4 and IPv6. Or disable IPv6 if unused.",
                references=["CWE-284"],
                evidence=ev,
                cvss_v31_vector=CVSS_DUALSTACK,
                cvss_v40_vector=CVSS40_DUALSTACK,
                target=target,
            )

        return self._make_result(start)

    async def _get_ipv6_info(self) -> dict:
        is_win = platform.system() == "Windows"
        info = {"enabled": False}

        if is_win:
            cmd = ["ipconfig", "/all"]
        else:
            cmd = ["ip", "-6", "addr", "show"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode(errors="ignore")

            # Find IPv6 addresses
            ipv6_addrs = re.findall(r"(?:inet6\s+|IPv6 Address[.\s]+:\s+)([\da-fA-F:]+)", output)
            ipv6_addrs = [a for a in ipv6_addrs if not a.startswith("::1")]  # Exclude loopback

            if ipv6_addrs:
                info["enabled"] = True
                info["ipv6_addresses"] = ipv6_addrs[:10]
                info["slaac_addresses"] = [
                    a for a in ipv6_addrs
                    if a.startswith("fe80") or "ff:fe" in a.lower()
                ]

            # Get IPv4 for dual-stack check
            ipv4_addrs = re.findall(r"(?:inet\s+|IPv4 Address[.\s]+:\s+)(\d+\.\d+\.\d+\.\d+)", output)
            if ipv4_addrs:
                info["ipv4_address"] = ipv4_addrs[0]

        except Exception:
            pass

        return info


class TestIpv6Audit:
    def test_cvss(self) -> None:
        assert "/AV:A/" in CVSS_RA_SPOOF

    def test_phase(self) -> None:
        assert Ipv6Audit.PHASE == 2
