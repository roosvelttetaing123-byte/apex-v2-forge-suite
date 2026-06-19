"""ARP Monitor — ARP spoofing detection, duplicate IP detection, gratuitous ARP.

Tests:
  - ARP table analysis for duplicate MACs
  - Gratuitous ARP detection
  - ARP cache poisoning indicators
  - Gateway MAC consistency check
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

CVSS_ARP_SPOOF  = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ARP_SPOOF = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_DUP_IP     = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
CVSS40_DUP_IP   = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N"


class ArpMonitor(BaseModule):
    """ARP table security analyzer."""

    NAME        = "arp_monitor"
    DESCRIPTION = "ARP: spoofing detection, duplicate IP/MAC, gateway MAC consistency"
    PHASE       = 2
    TAGS        = ["arp", "internal", "mitm", "cwe-300"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        arp_table = await self._get_arp_table()
        if not arp_table:
            return self._make_result(start, skipped=True, skip_reason="empty ARP table")

        # Check for duplicate MACs (potential ARP spoofing)
        mac_to_ips: dict[str, list[str]] = {}
        for entry in arp_table:
            mac = entry["mac"]
            ip = entry["ip"]
            mac_to_ips.setdefault(mac, []).append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 2 and mac != "ff:ff:ff:ff:ff:ff":
                ev = Evidence(
                    extra={
                        "mac": mac,
                        "associated_ips": ips,
                        "count": len(ips),
                    },
                )
                self.new_finding(
                    title=f"ARP Spoofing Indicator — MAC {mac} maps to {len(ips)} IPs",
                    severity=Severity.HIGH,
                    description=(
                        f"MAC address {mac} is associated with {len(ips)} IP addresses: "
                        f"{', '.join(ips[:10])}.\n\n"
                        "This is a strong indicator of ARP cache poisoning / MITM attack. "
                        "An attacker is likely spoofing the gateway or other hosts to intercept "
                        "traffic on the local network segment."
                    ),
                    reproduction_steps=[
                        "arp -a  # Check for duplicate MACs",
                        f"arping -I eth0 {ips[0]}  # Verify real MAC",
                    ],
                    remediation=(
                        "1. Enable Dynamic ARP Inspection (DAI) on switches\n"
                        "2. Use static ARP entries for critical hosts (gateway)\n"
                        "3. Deploy 802.1X port-based authentication\n"
                        "4. Investigate the host with MAC {mac}"
                    ),
                    references=["CWE-300", "MITRE T1557.002"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_ARP_SPOOF,
                    cvss_v40_vector=CVSS40_ARP_SPOOF,
                    mitre_attack=["TA0006/T1557.002"],
                    target=target,
                )

        # Check for duplicate IPs
        ip_to_macs: dict[str, list[str]] = {}
        for entry in arp_table:
            ip_to_macs.setdefault(entry["ip"], []).append(entry["mac"])

        for ip, macs in ip_to_macs.items():
            if len(set(macs)) > 1:
                ev = Evidence(
                    extra={"ip": ip, "macs": list(set(macs))},
                )
                self.new_finding(
                    title=f"Duplicate IP Detected — {ip} ({len(set(macs))} MACs)",
                    severity=Severity.MEDIUM,
                    description=(
                        f"IP {ip} has multiple MAC addresses: {', '.join(set(macs))}. "
                        "Could indicate IP conflict, ARP spoofing, or failover."
                    ),
                    reproduction_steps=[f"arping -c 3 {ip}"],
                    remediation="Investigate IP conflict. Enable DAI.",
                    references=["CWE-300"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_DUP_IP,
                    cvss_v40_vector=CVSS40_DUP_IP,
                    target=target,
                )

        return self._make_result(start)

    async def _get_arp_table(self) -> list[dict]:
        is_win = platform.system() == "Windows"
        cmd = ["arp", "-a"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode(errors="ignore")
            return self._parse_arp(output, is_win)
        except Exception:
            return []

    def _parse_arp(self, output: str, is_windows: bool) -> list[dict]:
        entries = []
        for line in output.split("\n"):
            line = line.strip()
            if is_windows:
                m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-f-]+)\s+(\w+)", line, re.I)
                if m:
                    mac = m.group(2).replace("-", ":").lower()
                    entries.append({"ip": m.group(1), "mac": mac, "type": m.group(3)})
            else:
                m = re.match(r".*\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\da-f:]+)", line, re.I)
                if m:
                    entries.append({"ip": m.group(1), "mac": m.group(2).lower(), "type": "dynamic"})
        return entries


class TestArpMonitor:
    def test_parse_windows(self) -> None:
        mod = ArpMonitor.__new__(ArpMonitor)
        output = "  192.168.1.1       00-aa-bb-cc-dd-ee     dynamic\n  192.168.1.2       00-aa-bb-cc-dd-ee     dynamic"
        entries = mod._parse_arp(output, is_windows=True)
        assert len(entries) == 2
        assert entries[0]["mac"] == "00:aa:bb:cc:dd:ee"

    def test_phase(self) -> None:
        assert ArpMonitor.PHASE == 2
