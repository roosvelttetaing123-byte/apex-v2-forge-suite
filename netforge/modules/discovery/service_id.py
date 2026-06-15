"""Service Identification — banner grabbing + nmap version detection.

Tests:
  - TCP banner grabbing on discovered open ports
  - nmap service/version detection (-sV)
  - Protocol-specific probes (HTTP, SSH, SMTP, etc.)
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

CVSS_VERSION = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_VERSION = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

BANNER_PORTS = [
    21, 22, 23, 25, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
]

PROTOCOL_PROBES = {
    80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
}


class ServiceId(BaseModule):
    """Service identification via banner grabbing and version detection."""

    NAME        = "service_id"
    DESCRIPTION = "Service identification: TCP banner grabbing, nmap -sV, protocol probes"
    PHASE       = 2
    TAGS        = ["recon", "discovery", "service-id", "cwe-200"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        open_ports = self.config.extra.get("open_ports", {})

        services: dict[str, list[dict]] = {}

        for host in hosts[:20]:
            if not self.check_scope(host):
                continue

            # Get ports to probe for this host
            ports = open_ports.get(host, BANNER_PORTS)
            host_services = []

            for port in ports[:50]:
                await self.rate_limit()
                banner = await self._grab_banner(host, port)
                if banner:
                    service_info = self._identify_service(port, banner)
                    host_services.append({
                        "port": port,
                        "banner": banner[:200],
                        "service": service_info.get("service", "unknown"),
                        "version": service_info.get("version", ""),
                    })

            if host_services:
                services[host] = host_services

        # Try nmap -sV for more accurate detection
        for host in list(services.keys())[:5]:
            await self._nmap_version_detect(host, services)

        # Report findings
        for host, svc_list in services.items():
            version_disclosures = [s for s in svc_list if s.get("version")]
            if version_disclosures:
                ev = Evidence(
                    extra={
                        "host": host,
                        "services": svc_list[:30],
                        "version_disclosures": len(version_disclosures),
                    },
                )
                self.new_finding(
                    title=f"Service Identification — {host} ({len(svc_list)} services)",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"Services identified on {host}:\n"
                        + "\n".join(
                            f"  Port {s['port']}: {s['service']}"
                            + (f" ({s['version']})" if s['version'] else "")
                            for s in svc_list[:15]
                        )
                    ),
                    reproduction_steps=[f"nmap -sV {host}"],
                    remediation="Suppress version banners where possible.",
                    references=["CWE-200"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_VERSION,
                    cvss_v40_vector=CVSS40_VERSION,
                    target=host,
                )

            # Store results for downstream modules
            self.config.extra.setdefault("service_map", {})[host] = svc_list

        return self._make_result(start)

    async def _grab_banner(self, host: str, port: int) -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )

            # Send protocol-specific probe if available
            probe = PROTOCOL_PROBES.get(port)
            if probe:
                probe = probe.replace(b"target", host.encode())
                writer.write(probe)
                await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=3)
            writer.close()

            return data.decode(errors="ignore").strip()[:500] if data else None
        except Exception:
            return None

    def _identify_service(self, port: int, banner: str) -> dict:
        """Identify service and version from banner text."""
        import re
        result = {"service": "unknown", "version": ""}

        banner_lower = banner.lower()

        # SSH
        if banner_lower.startswith("ssh-"):
            result["service"] = "ssh"
            m = re.search(r"SSH-[\d.]+-(\S+)", banner)
            if m:
                result["version"] = m.group(1)

        # HTTP
        elif "http/" in banner_lower:
            result["service"] = "http"
            m = re.search(r"(?:Server|server):\s*(\S+)", banner)
            if m:
                result["version"] = m.group(1)

        # SMTP
        elif banner_lower.startswith("220"):
            result["service"] = "smtp"
            m = re.search(r"220\s+\S+\s+(\S+)", banner)
            if m:
                result["version"] = m.group(1)

        # FTP
        elif "ftp" in banner_lower or banner_lower.startswith("220"):
            result["service"] = "ftp"

        # MySQL
        elif any(x in banner for x in ["mysql", "MariaDB", "\x00"]):
            result["service"] = "mysql"

        # Redis
        elif "redis" in banner_lower:
            result["service"] = "redis"

        # RDP (binary)
        elif port == 3389:
            result["service"] = "rdp"

        # Default by port
        else:
            port_map = {
                22: "ssh", 23: "telnet", 25: "smtp", 80: "http",
                110: "pop3", 143: "imap", 443: "https", 445: "smb",
                1433: "mssql", 1521: "oracle", 3306: "mysql",
                5432: "postgresql", 5900: "vnc", 6379: "redis",
                8080: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
            }
            result["service"] = port_map.get(port, f"unknown-{port}")

        return result

    async def _nmap_version_detect(self, host: str, services: dict) -> None:
        nmap = shutil.which("nmap")
        if not nmap:
            return

        ports = [str(s["port"]) for s in services.get(host, [])]
        if not ports:
            return

        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-sV", "--version-light",
                "-p", ",".join(ports[:20]),
                "-n", "-Pn", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45)
            output = stdout.decode(errors="ignore")

            # Parse nmap output and update services
            import re
            for line in output.split("\n"):
                m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line.strip())
                if m:
                    port = int(m.group(1))
                    service = m.group(2)
                    version = m.group(3).strip()
                    for svc in services.get(host, []):
                        if svc["port"] == port:
                            svc["service"] = service
                            if version:
                                svc["version"] = version
        except Exception:
            pass


class TestServiceId:
    def test_banner_ports(self) -> None:
        assert 22 in BANNER_PORTS
        assert 80 in BANNER_PORTS

    def test_identify_ssh(self) -> None:
        mod = ServiceId.__new__(ServiceId)
        result = mod._identify_service(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert result["service"] == "ssh"
        assert "OpenSSH" in result["version"]

    def test_identify_http(self) -> None:
        mod = ServiceId.__new__(ServiceId)
        result = mod._identify_service(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18")
        assert result["service"] == "http"

    def test_phase(self) -> None:
        assert ServiceId.PHASE == 2
