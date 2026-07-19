"""
Forge C2 — Port Scanner Task
=================================
Beacon-side TCP port scan for internal network reconnaissance.

Features:
    • Async TCP connect scanning (fast, non-blocking)
    • Configurable port ranges and common port presets
    • Service banner grabbing on open ports
    • Concurrent connection limit to control scan speed
    • CIDR subnet support for host ranges
    • Output in text or JSON format

MITRE ATT&CK: T1046 — Network Service Discovery
FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.portscan")


# ══════════════════════════════════════════════════════════════════════
#  COMMON PORT PRESETS
# ══════════════════════════════════════════════════════════════════════

COMMON_PORTS = {
    "top20": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
              143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    "top100": [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88,
               106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199,
               389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544,
               548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025,
               1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755,
               1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
               3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
               5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
               7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100,
               9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156],
    "web": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 9443],
    "windows": [135, 139, 445, 3389, 5985, 5986, 47001],
    "database": [1433, 1521, 3306, 5432, 6379, 27017, 9042, 5984],
    "mail": [25, 110, 143, 465, 587, 993, 995],
    "smb": [139, 445],
    "rdp": [3389],
    "ssh": [22],
}

# Service identification by port
PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 5985: "winrm",
    5986: "winrm-ssl", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9090: "web-console", 27017: "mongodb",
}


# ══════════════════════════════════════════════════════════════════════
#  SCAN RESULTS
# ══════════════════════════════════════════════════════════════════════

@dataclass
class PortResult:
    """Result for a single port scan."""
    host: str
    port: int
    state: str = "closed"  # open, closed, filtered
    service: str = ""
    banner: str = ""
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner[:200] if self.banner else "",
            "latency_ms": round(self.latency_ms, 1),
        }


@dataclass
class ScanResult:
    """Aggregated scan result for a host or range."""
    hosts_scanned: int = 0
    ports_scanned: int = 0
    open_ports: list[PortResult] = field(default_factory=list)
    closed_count: int = 0
    filtered_count: int = 0
    duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts_scanned": self.hosts_scanned,
            "ports_scanned": self.ports_scanned,
            "open_count": len(self.open_ports),
            "closed_count": self.closed_count,
            "filtered_count": self.filtered_count,
            "duration": round(self.duration, 2),
            "open_ports": [p.to_dict() for p in self.open_ports],
        }


# ══════════════════════════════════════════════════════════════════════
#  SCANNER ENGINE
# ══════════════════════════════════════════════════════════════════════

class PortScanner:
    """Async TCP port scanner."""

    def __init__(
        self,
        timeout: float = 2.0,
        concurrency: int = 100,
        banner_grab: bool = True,
        banner_timeout: float = 3.0,
    ) -> None:
        self.timeout = timeout
        self.concurrency = concurrency
        self.banner_grab = banner_grab
        self.banner_timeout = banner_timeout

    async def scan(
        self,
        hosts: list[str],
        ports: list[int],
    ) -> ScanResult:
        """Scan hosts for open ports."""
        result = ScanResult(
            hosts_scanned=len(hosts),
            ports_scanned=len(hosts) * len(ports),
        )

        start = time.time()
        semaphore = asyncio.Semaphore(self.concurrency)

        # Build scan targets
        targets = [
            (host, port)
            for host in hosts
            for port in ports
        ]

        # Execute scans concurrently
        tasks = [
            self._scan_port(semaphore, host, port)
            for host, port in targets
        ]

        port_results = await asyncio.gather(*tasks, return_exceptions=True)

        for pr in port_results:
            if isinstance(pr, Exception):
                continue
            if pr.state == "open":
                result.open_ports.append(pr)
            elif pr.state == "filtered":
                result.filtered_count += 1
            else:
                result.closed_count += 1

        result.duration = time.time() - start

        # Sort open ports by host, then port
        result.open_ports.sort(key=lambda p: (p.host, p.port))

        return result

    async def _scan_port(
        self,
        semaphore: asyncio.Semaphore,
        host: str,
        port: int,
    ) -> PortResult:
        """Scan a single port."""
        async with semaphore:
            start = time.time()

            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout,
                )

                latency = (time.time() - start) * 1000
                service = PORT_SERVICES.get(port, "")

                # Banner grab
                banner = ""
                if self.banner_grab:
                    banner = await self._grab_banner(writer, host, port)

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                if not service and banner:
                    service = self._detect_service(banner)

                return PortResult(
                    host=host, port=port, state="open",
                    service=service, banner=banner,
                    latency_ms=latency,
                )

            except asyncio.TimeoutError:
                return PortResult(host=host, port=port, state="filtered")
            except ConnectionRefusedError:
                return PortResult(host=host, port=port, state="closed")
            except OSError:
                return PortResult(host=host, port=port, state="filtered")

    async def _grab_banner(
        self,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> str:
        """Attempt to grab a service banner."""
        try:
            reader = writer.transport.get_extra_info("reader")
            if not reader:
                # Re-open connection for reading
                reader, _ = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.banner_timeout,
                )

            # Some services send banners immediately
            try:
                data = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=self.banner_timeout,
                )
                if data:
                    return data.decode(errors="replace").strip()[:200]
            except (asyncio.TimeoutError, ConnectionError):
                pass

            # Try sending a probe for HTTP
            if port in (80, 443, 8080, 8443, 8000, 3000):
                try:
                    writer.write(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                    await writer.drain()
                    data = await asyncio.wait_for(
                        reader.read(1024),
                        timeout=self.banner_timeout,
                    )
                    if data:
                        return data.decode(errors="replace").strip()[:200]
                except Exception:
                    pass

        except Exception:
            pass

        return ""

    @staticmethod
    def _detect_service(banner: str) -> str:
        """Detect service from banner content."""
        lower = banner.lower()
        if "ssh" in lower:
            return "ssh"
        if "http" in lower:
            return "http"
        if "smtp" in lower or "220" in banner and "mail" in lower:
            return "smtp"
        if "ftp" in lower:
            return "ftp"
        if "mysql" in lower:
            return "mysql"
        if "postgresql" in lower:
            return "postgresql"
        return ""


def _expand_hosts(target: str) -> list[str]:
    """Expand a target specification into a list of host IPs.

    Supports:
        • Single IP: 10.0.0.1
        • CIDR:      10.0.0.0/24
        • Range:     10.0.0.1-10
        • Hostname:  dc01.corp.local
    """
    hosts: list[str] = []

    try:
        # Try CIDR notation
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            # Cap at 1024 hosts
            if len(hosts) > 1024:
                hosts = hosts[:1024]
                log.warning("Host range capped at 1024 addresses")
            return hosts

        # Try range notation (10.0.0.1-10)
        if "-" in target:
            parts = target.rsplit(".", 1)
            if len(parts) == 2 and "-" in parts[1]:
                base = parts[0]
                range_parts = parts[1].split("-")
                if len(range_parts) == 2:
                    start = int(range_parts[0])
                    end = int(range_parts[1])
                    return [f"{base}.{i}" for i in range(start, end + 1)]

        # Single IP or hostname
        return [target]

    except (ValueError, TypeError):
        return [target]


def _parse_ports(port_spec: str) -> list[int]:
    """Parse port specification string into list of ports.

    Supports:
        • Single: "80"
        • Range:  "1-1024"
        • List:   "80,443,8080"
        • Mixed:  "22,80,443,8000-8100"
        • Preset: "top20", "web", "windows"
    """
    # Check for presets
    if port_spec.lower() in COMMON_PORTS:
        return COMMON_PORTS[port_spec.lower()]

    ports: set[int] = set()

    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                for p in range(int(start), int(end) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue

    return sorted(ports)


# ══════════════════════════════════════════════════════════════════════
#  TASK CLASS
# ══════════════════════════════════════════════════════════════════════

@register_task
class PortScanTask(BaseTask):
    """Beacon-side TCP port scan for internal reconnaissance.

    Args (via kwargs):
        targets:       Target hosts (IP, CIDR, range, or hostname).
                       Can be string or list of strings.
        ports:         Port specification: number, range, list, or preset.
                       Presets: top20, top100, web, windows, database, smb, rdp
        timeout:       Connection timeout per port (default 2.0s).
        concurrency:   Max concurrent connections (default 100).
        banner:        Grab service banners (default True).
        output_format: "text" or "json" (default "text").

    MITRE ATT&CK: T1046 — Network Service Discovery
    """

    TASK_TYPE = "portscan"
    DESCRIPTION = "Beacon-side TCP port scan (internal recon)"
    OPSEC_RISK = "medium"
    MITRE_ID = "T1046"

    async def execute(self) -> TaskResult:
        targets = self.args.get("targets", "")
        port_spec = self.args.get("ports", "top20")
        timeout = self.args.get("timeout", 2.0)
        concurrency = self.args.get("concurrency", 100)
        banner = self.args.get("banner", True)
        output_format = self.args.get("output_format", "text")

        start = time.time()

        # ── Parse targets ──────────────────────────────────────────
        if not targets:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error="No targets specified.",
                started_at=start, completed_at=time.time(),
            )

        if isinstance(targets, str):
            targets = [targets]

        hosts: list[str] = []
        for t in targets:
            hosts.extend(_expand_hosts(t))

        if not hosts:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error="No valid hosts after target expansion.",
                started_at=start, completed_at=time.time(),
            )

        # ── Parse ports ────────────────────────────────────────────
        if isinstance(port_spec, str):
            ports = _parse_ports(port_spec)
        elif isinstance(port_spec, list):
            ports = [int(p) for p in port_spec if 1 <= int(p) <= 65535]
        else:
            ports = COMMON_PORTS["top20"]

        if not ports:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error="No valid ports specified.",
                started_at=start, completed_at=time.time(),
            )

        # ── Scan ───────────────────────────────────────────────────
        log.info(
            "Port scan: %d hosts × %d ports (%d total)",
            len(hosts), len(ports), len(hosts) * len(ports),
        )

        scanner = PortScanner(
            timeout=timeout,
            concurrency=concurrency,
            banner_grab=banner,
        )

        try:
            result = await asyncio.wait_for(
                scanner.scan(hosts, ports),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.TIMEOUT,
                error=f"Scan timed out after {self.timeout}s",
                started_at=start, completed_at=time.time(),
            )

        # ── Format output ──────────────────────────────────────────
        if output_format == "json":
            import json
            output = json.dumps(result.to_dict(), indent=2)
        else:
            output = self._format_scan_result(result)

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            output=output,
            started_at=start,
            completed_at=time.time(),
            metadata={
                "hosts_scanned": result.hosts_scanned,
                "ports_scanned": result.ports_scanned,
                "open_count": len(result.open_ports),
                "duration": round(result.duration, 2),
                "mitre": self.MITRE_ID,
            },
        )

    @staticmethod
    def _format_scan_result(result: ScanResult) -> str:
        """Format scan results as readable text."""
        lines = [
            f"Port Scan Complete",
            f"  Hosts: {result.hosts_scanned} | Ports/host: "
            f"{result.ports_scanned // max(result.hosts_scanned, 1)} | "
            f"Duration: {result.duration:.1f}s",
            f"  Open: {len(result.open_ports)} | Closed: {result.closed_count} | "
            f"Filtered: {result.filtered_count}",
            "",
        ]

        if result.open_ports:
            lines.append(f"  {'HOST':20s} {'PORT':>6s}  {'STATE':8s}  {'SERVICE':12s}  {'BANNER'}")
            lines.append(f"  {'─' * 80}")

            for p in result.open_ports:
                banner_preview = p.banner[:40].replace("\n", " ") if p.banner else ""
                lines.append(
                    f"  {p.host:20s} {p.port:6d}  {p.state:8s}  "
                    f"{p.service:12s}  {banner_preview}"
                )
        else:
            lines.append("  No open ports found.")

        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestPortScanTask:
    """Tests for port scanner task."""

    def test_encode(self) -> None:
        task = PortScanTask(task_id="ps1", targets="10.0.0.1", ports="80,443")
        encoded = task.encode()
        assert encoded["type"] == "portscan"

    def test_decode(self) -> None:
        data = {"task_id": "ps2", "type": "portscan",
                "args": {"targets": "10.0.0.0/24", "ports": "top20"}}
        task = PortScanTask.decode(data)
        assert task.args["targets"] == "10.0.0.0/24"

    def test_no_targets(self) -> None:
        import asyncio
        task = PortScanTask(task_id="ps3", ports="80")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_expand_cidr(self) -> None:
        hosts = _expand_hosts("192.168.1.0/30")
        assert len(hosts) == 2  # .1 and .2 (network and broadcast excluded)

    def test_expand_single(self) -> None:
        hosts = _expand_hosts("10.0.0.1")
        assert hosts == ["10.0.0.1"]

    def test_expand_range(self) -> None:
        hosts = _expand_hosts("10.0.0.1-5")
        assert len(hosts) == 5

    def test_parse_ports_preset(self) -> None:
        ports = _parse_ports("top20")
        assert len(ports) == 20
        assert 80 in ports

    def test_parse_ports_range(self) -> None:
        ports = _parse_ports("1-5")
        assert ports == [1, 2, 3, 4, 5]

    def test_parse_ports_list(self) -> None:
        ports = _parse_ports("80,443,8080")
        assert ports == [80, 443, 8080]

    def test_parse_ports_mixed(self) -> None:
        ports = _parse_ports("22,80,443,8000-8002")
        assert 22 in ports
        assert 8001 in ports

    def test_port_result_to_dict(self) -> None:
        p = PortResult(host="10.0.0.1", port=80, state="open", service="http")
        d = p.to_dict()
        assert d["state"] == "open"

    def test_scan_result_to_dict(self) -> None:
        r = ScanResult(hosts_scanned=1, ports_scanned=20)
        d = r.to_dict()
        assert d["hosts_scanned"] == 1

    def test_common_ports_presets(self) -> None:
        assert "top20" in COMMON_PORTS
        assert "web" in COMMON_PORTS
        assert "windows" in COMMON_PORTS
        assert "database" in COMMON_PORTS
