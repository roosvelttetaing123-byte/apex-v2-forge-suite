"""Host discovery — ICMP ping, ARP, TCP port probe."""
from __future__ import annotations

import asyncio
import ipaddress
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity


class HostDiscover(BaseModule):
    """Network host discovery using ICMP/TCP probes."""

    NAME        = "host_discover"
    DESCRIPTION = "Discover live hosts on the network via ICMP and TCP port probing"
    PHASE       = 1
    TAGS        = ["discovery", "ping", "arp", "network"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            network = None

        if network and network.num_addresses > 1:
            hosts = [str(h) for h in network.hosts()]
            self.log.info("Scanning %d hosts in %s", len(hosts), target)
        else:
            hosts = [target]

        live_hosts: list[str] = []
        sem = asyncio.Semaphore(50)
        tasks = [self._probe_host(h, sem) for h in hosts[:254]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for host, alive in zip(hosts[:254], results):
            if alive is True:
                live_hosts.append(host)

        self.log.info("Discovered %d live host(s)", len(live_hosts))
        self.config.extra["live_hosts"] = live_hosts

        if live_hosts:
            ev = Evidence(
                extra={"live_hosts": live_hosts, "network": target}
            )
            self.new_finding(
                title=f"Live Hosts Discovered — {len(live_hosts)} host(s) in {target}",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"{len(live_hosts)} live host(s) discovered in {target}: "
                    f"{', '.join(live_hosts[:10])}"
                    + (" ..." if len(live_hosts) > 10 else "")
                ),
                reproduction_steps=[f"nmap -sn {target}"],
                remediation="Inventory all active hosts. Remove unauthorized devices.",
                references=[],
                evidence=ev,
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                target=target,
            )

        return self._make_result(start)

    async def _probe_host(self, host: str, sem: asyncio.Semaphore) -> bool:
        async with sem:
            await self.rate_limit()
            # Try TCP ports first (more reliable than ICMP without root)
            for port in [80, 443, 22, 445, 3389, 8080]:
                if await self._tcp_probe(host, port):
                    return True
            # Try ICMP via nmap if available
            return await self._ping_probe(host)

    async def _tcp_probe(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=1.0
            )
            writer.close()
            return True
        except Exception:
            return False

    async def _ping_probe(self, host: str) -> bool:
        import shutil
        nmap = shutil.which("nmap")
        if not nmap:
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-sn", "-n", "--max-rtt-timeout", "500ms", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            return "Host is up" in stdout.decode()
        except Exception:
            return False


class TestHostDiscover:
    def test_single_host(self) -> None:
        import ipaddress
        try:
            net = ipaddress.ip_network("192.168.1.1", strict=False)
            assert net.num_addresses == 1
        except ValueError:
            pass

    def test_cidr_expansion(self) -> None:
        import ipaddress
        net = ipaddress.ip_network("192.168.1.0/30", strict=False)
        hosts = [str(h) for h in net.hosts()]
        assert len(hosts) == 2
