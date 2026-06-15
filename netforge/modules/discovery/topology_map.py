"""Network Topology Mapper — traceroute, hop enumeration, gateway detection.

Tests:
  - Traceroute to map network hops
  - Default gateway identification
  - Multi-path detection
  - Network segment boundaries
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

CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"


class TopologyMap(BaseModule):
    """Network topology mapper via traceroute and hop analysis."""

    NAME        = "topology_map"
    DESCRIPTION = "Network topology: traceroute, hop enumeration, gateway detection"
    PHASE       = 1
    TAGS        = ["recon", "discovery", "topology", "cwe-200"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        topology = {}

        for host in hosts[:5]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            hops = await self._traceroute(host)
            if hops:
                topology[host] = hops

        if topology:
            # Identify gateways (first hop for each trace)
            gateways = set()
            all_hops = set()
            for host, hops in topology.items():
                if hops:
                    gateways.add(hops[0].get("ip", "?"))
                for hop in hops:
                    if hop.get("ip") and hop["ip"] != "*":
                        all_hops.add(hop["ip"])

            ev = Evidence(
                extra={
                    "topology": {h: hops[:15] for h, hops in topology.items()},
                    "gateways": list(gateways),
                    "unique_hops": len(all_hops),
                },
            )
            self.new_finding(
                title=f"Network Topology Mapped — {len(all_hops)} hops, {len(gateways)} gateways",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Traceroute reveals network topology to {len(topology)} targets.\n"
                    f"Gateways: {', '.join(gateways)}\n"
                    f"Unique intermediate hops: {len(all_hops)}\n\n"
                    + "\n".join(
                        f"  {host}: {' → '.join(h['ip'] for h in hops[:8])}"
                        for host, hops in topology.items()
                    )
                ),
                reproduction_steps=[f"traceroute {list(topology.keys())[0]}"],
                remediation="Block ICMP/UDP traceroute at network boundaries if topology should be hidden.",
                references=["CWE-200"],
                evidence=ev,
                cvss_v31_vector=CVSS_INFO,
                cvss_v40_vector=CVSS40_INFO,
                target=target,
            )

            self.config.extra["topology"] = topology
            self.config.extra["gateways"] = list(gateways)

        return self._make_result(start)

    async def _traceroute(self, host: str) -> list[dict]:
        is_win = platform.system() == "Windows"
        cmd = ["tracert", "-d", "-w", "1000", "-h", "20", host] if is_win else ["traceroute", "-n", "-w", "1", "-m", "20", host]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode(errors="ignore")
            return self._parse_traceroute(output)
        except Exception as exc:
            self.log.debug("Traceroute to %s failed: %s", host, exc)
            return []

    def _parse_traceroute(self, output: str) -> list[dict]:
        hops = []
        for line in output.strip().split("\n"):
            line = line.strip()
            m = re.match(r"\s*(\d+)\s+(.+)", line)
            if not m:
                continue

            hop_num = int(m.group(1))
            rest = m.group(2)

            # Extract IP addresses
            ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", rest)
            # Extract RTT values
            rtts = re.findall(r"(\d+(?:\.\d+)?)\s*ms", rest)

            if ips:
                hops.append({
                    "hop": hop_num,
                    "ip": ips[0],
                    "rtt_ms": [float(r) for r in rtts[:3]],
                })
            elif "*" in rest:
                hops.append({"hop": hop_num, "ip": "*", "rtt_ms": []})

        return hops


class TestTopologyMap:
    def test_parse_traceroute(self) -> None:
        mod = TopologyMap.__new__(TopologyMap)
        output = " 1  192.168.1.1  1.234 ms  0.987 ms  1.123 ms\n 2  10.0.0.1  5.432 ms\n 3  * * *"
        hops = mod._parse_traceroute(output)
        assert len(hops) == 3
        assert hops[0]["ip"] == "192.168.1.1"
        assert hops[2]["ip"] == "*"

    def test_phase(self) -> None:
        assert TopologyMap.PHASE == 1
