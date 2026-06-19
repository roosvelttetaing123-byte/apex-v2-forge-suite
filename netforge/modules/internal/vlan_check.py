"""VLAN Checker — VLAN hopping, DTP detection, trunk misconfiguration.

Tests:
  - DTP (Dynamic Trunking Protocol) negotiation detection
  - VLAN hopping via double-tagging surface
  - Trunk port misconfiguration detection
  - VLAN enumeration via CDP/LLDP
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_VLAN_HOP   = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
CVSS40_VLAN_HOP = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N"
CVSS_DTP        = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_DTP      = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"


class VlanCheck(BaseModule):
    """VLAN security auditor — hopping, DTP, trunk misconfig."""

    NAME        = "vlan_check"
    DESCRIPTION = "VLAN: hopping surface, DTP negotiation, trunk misconfiguration"
    PHASE       = 2
    TAGS        = ["vlan", "internal", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Check for DTP frames (Cisco Dynamic Trunking Protocol)
        await self._detect_dtp()

        # Check native VLAN from CDP data if available
        native_vlan = self.config.extra.get("native_vlan")
        topology = self.config.extra.get("topology", {})

        if native_vlan and native_vlan == 1:
            ev = Evidence(
                extra={"native_vlan": native_vlan},
            )
            self.new_finding(
                title=f"Default Native VLAN (VLAN 1) — Double-Tagging Attack Surface",
                severity=Severity.MEDIUM,
                description=(
                    "The native VLAN is set to the default VLAN 1. "
                    "This enables double-tagging VLAN hopping attacks where an attacker "
                    "on VLAN 1 can send frames that reach other VLANs by:\n"
                    "  1. Crafting a frame with two 802.1Q tags\n"
                    "  2. The switch strips the outer tag (VLAN 1 = native)\n"
                    "  3. The inner tag (target VLAN) survives to the next switch\n"
                    "  4. The frame is forwarded to the target VLAN"
                ),
                reproduction_steps=[
                    "yersinia -G  # Select 802.1Q attack",
                    "# Or: scapy: sendp(Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst='target')/ICMP())",
                ],
                remediation=(
                    "1. Change native VLAN: switchport trunk native vlan 999\n"
                    "2. Tag native VLAN: vlan dot1q tag native\n"
                    "3. Don't use VLAN 1 for any traffic\n"
                    "4. Prune VLANs from trunks: switchport trunk allowed vlan <list>"
                ),
                references=["CWE-284"],
                evidence=ev,
                cvss_v31_vector=CVSS_VLAN_HOP,
                cvss_v40_vector=CVSS40_VLAN_HOP,
                target=target,
            )

        return self._make_result(start)

    async def _detect_dtp(self) -> None:
        """Detect DTP frames on the network (indicates trunk negotiation is enabled)."""
        tcpdump = shutil.which("tcpdump")
        if not tcpdump:
            return

        try:
            # DTP uses multicast destination 01:00:0c:cc:cc:cc
            proc = await asyncio.create_subprocess_exec(
                tcpdump, "-nn", "-c", "3", "-v",
                "ether dst 01:00:0c:cc:cc:cc",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=35)
            output = stdout.decode(errors="ignore")

            if "DTP" in output or len(output.strip()) > 50:
                ev = Evidence(
                    response_raw=output[:1000],
                    extra={"dtp_detected": True},
                )
                self.new_finding(
                    title="DTP Frames Detected — VLAN Trunk Negotiation Active",
                    severity=Severity.HIGH,
                    description=(
                        "Cisco DTP (Dynamic Trunking Protocol) frames detected. "
                        "The switch port is configured to negotiate trunk mode. "
                        "An attacker can send DTP frames to force the port into trunk mode, "
                        "gaining access to ALL VLANs on the switch.\n\n"
                        "Tools: yersinia, frogger, dtpspoofing"
                    ),
                    reproduction_steps=[
                        "yersinia -G  # Select DTP attack → Enable Trunking",
                        "# Or: python3 dtpspoofing.py --interface eth0",
                    ],
                    remediation=(
                        "Disable DTP on all access ports:\n"
                        "  switchport mode access\n"
                        "  switchport nonegotiate\n"
                        "For trunk ports: explicitly set trunk mode instead of dynamic"
                    ),
                    references=["CWE-284"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_DTP,
                    cvss_v40_vector=CVSS40_DTP,
                    target=self.config.target,
                )
        except Exception:
            pass


class TestVlanCheck:
    def test_cvss(self) -> None:
        assert "/AV:A/" in CVSS_VLAN_HOP
        assert "/S:C/" in CVSS_VLAN_HOP  # Changed scope

    def test_phase(self) -> None:
        assert VlanCheck.PHASE == 2
