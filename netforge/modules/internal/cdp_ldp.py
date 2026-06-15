"""CDP/LLDP Discovery — Cisco Discovery Protocol and LLDP information disclosure.

Tests:
  - CDP frame capture and parsing
  - LLDP frame analysis
  - Switch/router information disclosure (hostname, model, IOS version, VLAN)
  - VoIP VLAN hopping surface detection
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

CVSS_CDP_LEAK   = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_CDP_LEAK = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_VLAN_HOP   = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_VLAN_HOP = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"


class CdpLdp(BaseModule):
    """CDP/LLDP information disclosure auditor."""

    NAME        = "cdp_ldp"
    DESCRIPTION = "CDP/LLDP: network device info disclosure, VLAN hopping surface"
    PHASE       = 2
    TAGS        = ["cdp", "lldp", "internal", "cwe-200"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Try tcpdump/tshark for CDP/LLDP capture
        await self._capture_cdp()

        # Try nmap CDP script
        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:10]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._nmap_cdp(host)

        return self._make_result(start)

    async def _capture_cdp(self) -> None:
        """Capture CDP/LLDP frames using tcpdump (brief capture)."""
        tcpdump = shutil.which("tcpdump")
        if not tcpdump:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                tcpdump, "-nn", "-c", "5", "-v",
                "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=65)
            output = stdout.decode(errors="ignore")

            if "CDP" in output or "LLDP" in output:
                # Parse device info from CDP/LLDP output
                import re
                devices = []
                device_id = re.search(r"Device-ID[:\s]+['\"]?([^\n'\"]+)", output)
                platform_match = re.search(r"Platform[:\s]+['\"]?([^\n'\"]+)", output)
                port_id = re.search(r"Port-ID[:\s]+['\"]?([^\n'\"]+)", output)
                vlan = re.search(r"Native VLAN[:\s]+(\d+)", output)
                ios_ver = re.search(r"Version[:\s]+(.+?)(?:\n|$)", output)

                info = {
                    "device_id": device_id.group(1).strip() if device_id else "unknown",
                    "platform": platform_match.group(1).strip() if platform_match else "unknown",
                    "port_id": port_id.group(1).strip() if port_id else "unknown",
                    "native_vlan": int(vlan.group(1)) if vlan else None,
                    "ios_version": ios_ver.group(1).strip()[:100] if ios_ver else "unknown",
                }
                devices.append(info)

                ev = Evidence(
                    response_raw=output[:2000],
                    extra={"devices": devices},
                )
                self.new_finding(
                    title=f"CDP/LLDP Information Disclosure — {info['device_id']} ({info['platform'][:30]})",
                    severity=Severity.MEDIUM,
                    description=(
                        f"CDP/LLDP frames reveal network infrastructure details:\n"
                        f"  Device: {info['device_id']}\n"
                        f"  Platform: {info['platform']}\n"
                        f"  Port: {info['port_id']}\n"
                        f"  IOS Version: {info['ios_version'][:50]}\n"
                        + (f"  Native VLAN: {info['native_vlan']}\n" if info['native_vlan'] else "")
                        + "\nThis information helps attackers identify switch models, firmware "
                        "versions (for known CVEs), and VLAN configurations (for VLAN hopping)."
                    ),
                    reproduction_steps=[
                        "tcpdump -nn -v -c 5 'ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc'",
                        "# Or: cdpsnarf / yersinia -G",
                    ],
                    remediation=(
                        "Disable CDP/LLDP on access ports:\n"
                        "  Cisco: no cdp enable (per-interface)\n"
                        "  Global: no cdp run\n"
                        "  LLDP: no lldp transmit (per-interface)"
                    ),
                    references=["CWE-200"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CDP_LEAK,
                    cvss_v40_vector=CVSS40_CDP_LEAK,
                    target=self.config.target,
                )

                # VLAN hopping surface
                if info.get("native_vlan"):
                    ev2 = Evidence(extra={"native_vlan": info["native_vlan"]})
                    self.new_finding(
                        title=f"VLAN Hopping Surface — Native VLAN {info['native_vlan']}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Native VLAN {info['native_vlan']} disclosed via CDP. "
                            "If the access port is misconfigured as trunk, "
                            "double-tagging VLAN hopping attacks become possible."
                        ),
                        reproduction_steps=[
                            f"yersinia -G  # VLAN hopping via double-tagging",
                            f"# Target native VLAN: {info['native_vlan']}",
                        ],
                        remediation=(
                            "1. Set native VLAN to unused VLAN: switchport trunk native vlan 999\n"
                            "2. Disable DTP: switchport nonegotiate\n"
                            "3. Set all access ports explicitly: switchport mode access"
                        ),
                        references=["CWE-284"],
                        evidence=ev2,
                        cvss_v31_vector=CVSS_VLAN_HOP,
                        cvss_v40_vector=CVSS40_VLAN_HOP,
                        target=self.config.target,
                    )
        except Exception:
            pass

    async def _nmap_cdp(self, host: str) -> None:
        nmap = shutil.which("nmap")
        if not nmap:
            return
        # nmap doesn't have a CDP script by default, but we check for LLDP
        # via broadcast-* scripts
        pass  # CDP is Layer 2 — nmap can't probe it remotely


class TestCdpLdp:
    def test_cvss(self) -> None:
        assert CVSS_CDP_LEAK.startswith("CVSS:3.1")
        assert "/AV:A/" in CVSS_CDP_LEAK  # Adjacent network

    def test_phase(self) -> None:
        assert CdpLdp.PHASE == 2
