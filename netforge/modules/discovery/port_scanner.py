"""Port scanner — TCP SYN/connect scan with banner grabbing."""
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

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 1723,
    2049, 2375, 3306, 3389, 4848, 5432, 5900, 5985, 5986,
    6379, 7001, 8080, 8443, 8888, 9000, 9090, 9200, 9300,
    11211, 27017, 50000,
]

BANNER_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
    8080: "HTTP-Alt", 27017: "MongoDB", 5432: "PostgreSQL",
    6379: "Redis", 11211: "Memcached", 9200: "Elasticsearch",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    1433: "MSSQL",
    2049: "NFS",
    7001: "WebLogic",
    9300: "Elasticsearch-Cluster",
}


class PortScanner(BaseModule):
    """TCP port scanner with banner grabbing."""

    NAME        = "port_scanner"
    DESCRIPTION = "TCP connect port scan on live hosts with service banner grabbing"
    PHASE       = 1
    TAGS        = ["discovery", "port-scan", "network"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        hosts = self.config.extra.get("live_hosts", [self.config.target])

        self.log.info("Port scanning %d host(s)", len(hosts))
        open_ports: dict[str, list[dict]] = {}

        sem = asyncio.Semaphore(100)
        host_limit = self.config.extra.get("host_limit", 254)
        for host in hosts[:host_limit]:
            ports = await self._scan_host(host, sem)
            if ports:
                open_ports[host] = ports

        self.config.extra["open_ports"] = open_ports

        # Report interesting open ports
        for host, ports in open_ports.items():
            risky = [p for p in ports if p["port"] in [23, 21, 135, 445, 3389, 5900, 5985, 5986, 2375]]
            if risky:
                ev = Evidence(
                    extra={"host": host, "open_ports": ports, "risky_ports": risky}
                )
                self.new_finding(
                    title=f"Risky Services Open — {host} ({', '.join(str(p['port']) for p in risky)})",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Potentially risky services detected on {host}: "
                        ", ".join(str(p["port"]) + "/" + p.get("service", "?") for p in risky)
                    ),
                    reproduction_steps=[f"nmap -sV {host}"],
                    remediation="Close unnecessary ports. Restrict access with firewall rules.",
                    references=["CWE-200"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                    target=host,
                )

        return self._make_result(start)

    async def _scan_host(
        self, host: str, sem: asyncio.Semaphore
    ) -> list[dict]:
        ports_to_scan = (
            self.config.extra.get("ports", TOP_PORTS)
            if isinstance(self.config.extra.get("ports"), list)
            else TOP_PORTS
        )

        tasks = [self._probe_port(host, port, sem) for port in ports_to_scan]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _probe_port(
        self, host: str, port: int, sem: asyncio.Semaphore
    ) -> dict | None:
        async with sem:
            await self.rate_limit()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=1.5
                )
                banner = ""
                try:
                    banner_data = await asyncio.wait_for(reader.read(256), timeout=2.0)
                    banner = banner_data.decode(errors="ignore").strip()[:100]
                except Exception:
                    pass
                writer.close()
                return {
                    "port":    port,
                    "state":   "open",
                    "service": BANNER_PORTS.get(port, "unknown"),
                    "banner":  banner,
                }
            except Exception:
                return None


class TestPortScanner:
    def test_top_ports_not_empty(self) -> None:
        assert len(TOP_PORTS) >= 20
        assert 22 in TOP_PORTS
        assert 445 in TOP_PORTS

    def test_banner_ports_dict(self) -> None:
        assert BANNER_PORTS.get(22) == "SSH"
        assert BANNER_PORTS.get(3306) == "MySQL"
