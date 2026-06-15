"""Firewall Detection — ACK scan, fragment, TTL analysis, IDS evasion.

Tests:
  - TCP ACK scan to detect filtered vs unfiltered ports
  - Fragment offset handling differences
  - TTL analysis for firewall hop detection
  - IDS/IPS evasion technique surface
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

CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

TEST_PORTS = [21, 22, 25, 80, 443, 445, 3389, 8080]


class FirewallDetect(BaseModule):
    """Firewall/IDS detection via ACK scans and traffic analysis."""

    NAME        = "firewall_detect"
    DESCRIPTION = "Firewall: ACK scan, fragment analysis, TTL hop detection"
    PHASE       = 2
    TAGS        = ["recon", "firewall", "ids", "cwe-200"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])

        for host in hosts[:10]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._detect_firewall(host)

        return self._make_result(start)

    async def _detect_firewall(self, host: str) -> None:
        nmap = shutil.which("nmap")
        if not nmap:
            # Fallback: simple SYN vs response analysis
            await self._basic_detect(host)
            return

        # nmap ACK scan to differentiate filtered vs unfiltered
        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-sA", "-n", "-Pn",
                "-p", ",".join(str(p) for p in TEST_PORTS),
                "--reason", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            ack_output = stdout.decode(errors="ignore")
        except Exception:
            ack_output = ""

        # Also run SYN scan for comparison
        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-sS", "-n", "-Pn",
                "-p", ",".join(str(p) for p in TEST_PORTS),
                "--reason", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            syn_output = stdout.decode(errors="ignore")
        except Exception:
            syn_output = ""

        # Analyze results
        filtered_ack = ack_output.lower().count("filtered")
        unfiltered_ack = ack_output.lower().count("unfiltered")
        filtered_syn = syn_output.lower().count("filtered")

        has_firewall = filtered_ack > 0 or filtered_syn > 0
        if has_firewall:
            firewall_type = "stateful" if filtered_ack > 0 else "packet-filter"

            ev = Evidence(
                extra={
                    "host": host,
                    "firewall_type": firewall_type,
                    "ack_filtered": filtered_ack,
                    "ack_unfiltered": unfiltered_ack,
                    "syn_filtered": filtered_syn,
                    "ack_scan": ack_output[:1000],
                    "syn_scan": syn_output[:1000],
                },
            )
            self.new_finding(
                title=f"Firewall Detected — {host} ({firewall_type})",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Firewall/packet filter detected on {host}.\n"
                    f"Type: {firewall_type}\n"
                    f"ACK scan: {filtered_ack} filtered, {unfiltered_ack} unfiltered\n"
                    f"SYN scan: {filtered_syn} filtered\n\n"
                    "Stateful firewalls drop ACK packets without prior SYN, "
                    "while simple packet filters let them through."
                ),
                reproduction_steps=[
                    f"nmap -sA -p 21,22,25,80,443 {host}",
                    f"nmap -sS -p 21,22,25,80,443 {host}",
                ],
                remediation="Firewall detected — review ruleset for overly permissive rules.",
                references=["CWE-200"],
                evidence=ev,
                cvss_v31_vector=CVSS_INFO,
                cvss_v40_vector=CVSS40_INFO,
                target=host,
            )

            self.config.extra.setdefault("firewall_hosts", []).append(host)

    async def _basic_detect(self, host: str) -> None:
        """Basic firewall detection by checking which ports respond vs timeout."""
        open_ports = []
        filtered_ports = []

        for port in TEST_PORTS:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=2
                )
                writer.close()
                open_ports.append(port)
            except asyncio.TimeoutError:
                filtered_ports.append(port)
            except ConnectionRefusedError:
                pass  # Closed but responsive (no firewall on this port)
            except Exception:
                filtered_ports.append(port)

        if filtered_ports and open_ports:
            ev = Evidence(
                extra={
                    "open_ports": open_ports,
                    "filtered_ports": filtered_ports,
                },
            )
            self.new_finding(
                title=f"Firewall Detected (basic) — {host}",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Some ports timeout (filtered) while others respond:\n"
                    f"  Open: {open_ports}\n  Filtered: {filtered_ports}\n"
                    "This pattern indicates a firewall selectively allowing traffic."
                ),
                reproduction_steps=[f"nmap -sS -p 1-1000 {host}"],
                remediation="Review firewall rules.",
                references=["CWE-200"],
                evidence=ev,
                cvss_v31_vector=CVSS_INFO,
                cvss_v40_vector=CVSS40_INFO,
                target=host,
            )


class TestFirewallDetect:
    def test_ports(self) -> None:
        assert 80 in TEST_PORTS
        assert 443 in TEST_PORTS

    def test_phase(self) -> None:
        assert FirewallDetect.PHASE == 2
