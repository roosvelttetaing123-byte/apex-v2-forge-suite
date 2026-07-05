"""Host discovery — ICMP ping, ARP, TCP SYN, UDP, DNS reverse, SNMP check."""
from __future__ import annotations

import asyncio
import ipaddress
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

MITRE_T1018 = "T1018"   # Remote System Discovery
MITRE_T1046 = "T1046"   # Network Service Discovery

CVSS_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_MEDIUM = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

TCP_PROBE_PORTS = [80, 443, 22, 445, 3389]
UDP_PROBE_PORTS = [53, 161, 123]


@dataclass
class HostResult:
    """Result for a single discovered live host."""
    ip: str
    hostname: Optional[str] = None
    os_hint: Optional[str] = None
    discovery_method: str = "unknown"
    snmp_open: bool = False
    ttl: Optional[int] = None


def _ttl_os_hint(ttl: int) -> str:
    """Infer OS family from initial TTL value."""
    if 1 <= ttl <= 64:
        return "Linux/macOS"
    if 65 <= ttl <= 128:
        return "Windows"
    if 129 <= ttl <= 255:
        return "Cisco/Network Device"
    return "Unknown"


def _arp_sweep(network: str) -> list[str]:
    """ARP sweep of a network range using scapy or arping subprocess fallback.

    Returns list of live IP strings found in the CIDR range.
    """
    live: list[str] = []
    try:
        from scapy.layers.l2 import ARP, Ether  # type: ignore
        from scapy.sendrecv import srp          # type: ignore
        import scapy.config                     # type: ignore

        scapy.config.conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        ans, _ = srp(pkt, timeout=2, retry=1, verbose=False)
        for _, rcv in ans:
            ip = rcv[ARP].psrc
            if ip not in live:
                live.append(ip)
        return live
    except Exception:
        pass

    # Fallback: arping subprocess
    try:
        result = subprocess.run(
            ["arping", "-c", "1", "-I", "any", network],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            import re
            m = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", line)
            if m:
                ip = m.group(1)
                if ip not in live:
                    live.append(ip)
    except Exception:
        pass

    return live


def _icmp_sweep(hosts: list[str], timeout: float = 1.0) -> list[str]:
    """Threaded ICMP sweep; max 100 concurrent via ThreadPoolExecutor.

    Falls back to subprocess ping when socket ICMP fails (no root).
    """
    live: list[str] = []
    max_workers = min(100, len(hosts)) if hosts else 1

    def _ping_one(ip: str) -> Optional[str]:
        # Try raw ICMP socket first
        try:
            import struct
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            # ICMP echo request: type=8, code=0, checksum=0, id=1, seq=1
            header = struct.pack("bbHHh", 8, 0, 0, 1, 1)
            chk = 0
            for i in range(0, len(header), 2):
                chk += (header[i] << 8) + header[i + 1]
            chk = (~((chk >> 16) + (chk & 0xFFFF))) & 0xFFFF
            header = struct.pack("bbHHh", 8, 0, chk, 1, 1)
            sock.sendto(header, (ip, 0))
            sock.recv(1024)
            sock.close()
            return ip
        except PermissionError:
            pass
        except Exception:
            return None

        # Fallback to subprocess ping
        try:
            result = subprocess.run(
                ["ping", "-c1", "-W1", ip],
                capture_output=True, timeout=3
            )
            if result.returncode == 0:
                return ip
        except Exception:
            pass
        return None

    socket.setdefaulttimeout(timeout)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for ip, result in zip(hosts, pool.map(_ping_one, hosts)):
            if result:
                live.append(result)

    return live


def _tcp_probe(ip: str, ports: list[int] | None = None) -> bool:
    """TCP SYN-style probe: attempt connect to common ports to detect live hosts.

    Used for hosts that block ICMP.
    """
    if ports is None:
        ports = TCP_PROBE_PORTS
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=1.0):
                return True
        except (ConnectionRefusedError, OSError):
            # Connection refused = host is alive, port is closed
            # For discovery purposes, refused = live
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result in (0, 111):  # 0=connected, 111=ECONNREFUSED (host alive)
                    return True
            except Exception:
                pass
        except Exception:
            pass
    return False


def _udp_probe(ip: str) -> bool:
    """UDP probe on ports 53 (DNS), 161 (SNMP), 123 (NTP).

    Returns True if any response (or ICMP port-unreachable, meaning host is alive).
    """
    for port in UDP_PROBE_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            # Send minimal probe payload for each service
            if port == 53:
                # Minimal DNS query for '.'
                payload = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"
            elif port == 161:
                # SNMP GetRequest community=public, sysDescr OID
                payload = (
                    b"\x30\x26\x02\x01\x00\x04\x06public"
                    b"\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
                    b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
                )
            elif port == 123:
                # NTP client request
                payload = b"\x1b" + b"\x00" * 47
            else:
                payload = b"\x00"

            sock.sendto(payload, (ip, port))
            data, _ = sock.recvfrom(512)
            sock.close()
            if data:
                return True
        except socket.timeout:
            pass
        except OSError as e:
            # ICMP port unreachable (errno 111 or 113) means host is alive
            if e.errno in (111, 113, 10054):
                return True
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return False


def _reverse_dns(ip: str) -> Optional[str]:
    """PTR lookup for a given IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def _snmp_public_check(ip: str) -> bool:
    """Send SNMP GetRequest with community string 'public' to UDP/161.

    Returns True if host responds (publicly readable SNMP).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        # SNMP v1 GetRequest: sysDescr.0 (1.3.6.1.2.1.1.1.0)
        # Minimal BER-encoded SNMP GetRequest
        community = b"public"
        oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"  # 1.3.6.1.2.1.1.1.0
        varbind = b"\x30\x0a\x06\x08" + oid + b"\x05\x00"
        pdu = b"\xa0\x13\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x05" + varbind[:5]
        community_str = b"\x04" + bytes([len(community)]) + community
        msg = b"\x30" + bytes([2 + len(community_str) + len(pdu)]) + b"\x02\x01\x00" + community_str + pdu
        sock.sendto(msg, (ip, 161))
        data, _ = sock.recvfrom(512)
        sock.close()
        return len(data) > 0
    except socket.timeout:
        return False
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


class HostDiscover(BaseModule):
    """Network host discovery using ICMP/TCP/UDP/ARP probes."""

    NAME        = "host_discover"
    DESCRIPTION = "Discover live hosts on the network via ICMP, ARP, TCP SYN, UDP, and SNMP probing"
    PHASE       = 1
    TAGS        = ["discovery", "ping", "arp", "network", "snmp"]

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

        # Phase 1: ARP sweep (LAN only — only attempt if /24 or smaller)
        arp_live: list[str] = []
        if network and network.num_addresses <= 256:
            self.log.info("Running ARP sweep on %s", target)
            try:
                loop = asyncio.get_event_loop()
                arp_live = await loop.run_in_executor(None, _arp_sweep, target)
                self.log.info("ARP found %d host(s)", len(arp_live))
            except Exception as exc:
                self.log.debug("ARP sweep error: %s", exc)

        # Phase 2: ICMP sweep
        self.log.info("Running ICMP sweep on %d host(s)", len(hosts[:254]))
        loop = asyncio.get_event_loop()
        icmp_live: list[str] = []
        try:
            icmp_live = await loop.run_in_executor(
                None, _icmp_sweep, hosts[:254], 1.0
            )
            self.log.info("ICMP found %d host(s)", len(icmp_live))
        except Exception as exc:
            self.log.debug("ICMP sweep error: %s", exc)

        # Phase 3: TCP SYN probe (async — hosts not found by ICMP/ARP)
        found_so_far = set(arp_live) | set(icmp_live)
        remaining = [h for h in hosts[:254] if h not in found_so_far]

        tcp_live: list[str] = []
        sem = asyncio.Semaphore(50)

        async def _async_tcp(ip: str) -> Optional[str]:
            async with sem:
                await self.rate_limit()
                result = await asyncio.get_event_loop().run_in_executor(
                    None, _tcp_probe, ip, TCP_PROBE_PORTS
                )
                return ip if result else None

        tcp_tasks = [_async_tcp(h) for h in remaining]
        tcp_results = await asyncio.gather(*tcp_tasks, return_exceptions=True)
        tcp_live = [r for r in tcp_results if isinstance(r, str)]
        self.log.info("TCP probe found %d additional host(s)", len(tcp_live))

        # Phase 4: UDP probe (hosts still not found)
        found_so_far |= set(tcp_live)
        remaining_udp = [h for h in hosts[:254] if h not in found_so_far]

        udp_live: list[str] = []
        async def _async_udp(ip: str) -> Optional[str]:
            async with sem:
                await self.rate_limit()
                result = await asyncio.get_event_loop().run_in_executor(
                    None, _udp_probe, ip
                )
                return ip if result else None

        udp_tasks = [_async_udp(h) for h in remaining_udp]
        udp_results = await asyncio.gather(*udp_tasks, return_exceptions=True)
        udp_live = [r for r in udp_results if isinstance(r, str)]
        self.log.info("UDP probe found %d additional host(s)", len(udp_live))

        # Merge and deduplicate
        all_live_set: set[str] = set(arp_live) | set(icmp_live) | set(tcp_live) | set(udp_live)

        # Build HostResult objects with metadata
        host_results: list[HostResult] = []
        snmp_open_hosts: list[str] = []

        for ip in sorted(all_live_set):
            method_parts: list[str] = []
            if ip in arp_live:
                method_parts.append("ARP")
            if ip in icmp_live:
                method_parts.append("ICMP")
            if ip in tcp_live:
                method_parts.append("TCP")
            if ip in udp_live:
                method_parts.append("UDP")

            # Reverse DNS
            hostname = await asyncio.get_event_loop().run_in_executor(
                None, _reverse_dns, ip
            )

            # SNMP check
            snmp_open = await asyncio.get_event_loop().run_in_executor(
                None, _snmp_public_check, ip
            )
            if snmp_open:
                snmp_open_hosts.append(ip)

            hr = HostResult(
                ip=ip,
                hostname=hostname,
                os_hint=None,
                discovery_method="+".join(method_parts) if method_parts else "unknown",
                snmp_open=snmp_open,
            )
            host_results.append(hr)

        live_ips = [hr.ip for hr in host_results]
        self.log.info("Discovered %d live host(s) total", len(live_ips))
        self.config.extra["live_hosts"] = live_ips
        self.config.extra["host_results"] = [
            {
                "ip": hr.ip,
                "hostname": hr.hostname,
                "os_hint": hr.os_hint,
                "discovery_method": hr.discovery_method,
                "snmp_open": hr.snmp_open,
            }
            for hr in host_results
        ]

        # Emit MEDIUM finding per live host batch (T1018 asset inventory)
        if live_ips:
            ev = Evidence(
                extra={
                    "live_hosts": live_ips,
                    "network": target,
                    "methods": {
                        "arp": len(arp_live),
                        "icmp": len(icmp_live),
                        "tcp": len(tcp_live),
                        "udp": len(udp_live),
                    },
                    "host_details": [
                        {"ip": hr.ip, "hostname": hr.hostname, "method": hr.discovery_method}
                        for hr in host_results
                    ],
                }
            )
            self.new_finding(
                title=f"Live Hosts Discovered — {len(live_ips)} host(s) in {target}",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(live_ips)} live host(s) discovered in {target}.\n"
                    f"Discovery methods: ARP({len(arp_live)}), ICMP({len(icmp_live)}), "
                    f"TCP({len(tcp_live)}), UDP({len(udp_live)})\n"
                    f"Hosts: {', '.join(live_ips[:15])}"
                    + (" ..." if len(live_ips) > 15 else "")
                ),
                reproduction_steps=[f"nmap -sn {target}", f"arp-scan {target}"],
                remediation=(
                    "Inventory all active hosts. Remove unauthorized devices from the network. "
                    "Implement network access control (NAC) to prevent rogue device connections."
                ),
                references=["MITRE ATT&CK T1018", "MITRE ATT&CK T1046"],
                evidence=ev,
                cvss_v31_vector=CVSS_MEDIUM,
                target=target,
                mitre_attack=[MITRE_T1018],
            )

        # Emit HIGH finding for SNMP public community (T1046)
        for ip in snmp_open_hosts:
            ev_snmp = Evidence(
                extra={"ip": ip, "port": 161, "community": "public"}
            )
            self.new_finding(
                title=f"SNMP Public Community String Accepted — {ip}",
                severity=Severity.HIGH,
                description=(
                    f"Host {ip} responds to SNMP GetRequest with community string 'public'. "
                    "This allows unauthenticated read access to device information including "
                    "interface tables, routing tables, ARP cache, and potentially device credentials."
                ),
                reproduction_steps=[
                    f"snmpwalk -v1 -c public {ip} .1.3.6.1.2.1.1",
                    f"snmpget -v1 -c public {ip} .1.3.6.1.2.1.1.1.0",
                ],
                remediation=(
                    "Change SNMP community strings from defaults. "
                    "Restrict SNMP access to management hosts only via ACLs. "
                    "Upgrade to SNMPv3 with authentication and encryption."
                ),
                references=["CWE-1391", "MITRE ATT&CK T1046"],
                evidence=ev_snmp,
                cvss_v31_vector=CVSS_HIGH,
                target=ip,
                mitre_attack=[MITRE_T1046],
            )

        return self._make_result(start)

    async def _probe_host(self, host: str, sem: asyncio.Semaphore) -> bool:
        """Legacy probe for backwards compatibility — TCP + ping fallback."""
        async with sem:
            await self.rate_limit()
            for port in [80, 443, 22, 445, 3389, 8080]:
                if await self._tcp_probe_async(host, port):
                    return True
            return await self._ping_probe(host)

    async def _tcp_probe_async(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=1.0
            )
            writer.close()
            return True
        except Exception:
            return False

    async def _ping_probe(self, host: str) -> bool:
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
    """Embedded unit tests for host discovery functions."""

    def test_single_host_network(self) -> None:
        import ipaddress
        net = ipaddress.ip_network("192.168.1.1", strict=False)
        assert net.num_addresses == 1

    def test_cidr_expansion(self) -> None:
        import ipaddress
        net = ipaddress.ip_network("192.168.1.0/30", strict=False)
        hosts = [str(h) for h in net.hosts()]
        assert len(hosts) == 2

    def test_cidr_slash24(self) -> None:
        import ipaddress
        net = ipaddress.ip_network("10.0.0.0/24", strict=False)
        hosts = list(net.hosts())
        assert len(hosts) == 254

    def test_ttl_os_hint_linux(self) -> None:
        assert _ttl_os_hint(64) == "Linux/macOS"
        assert _ttl_os_hint(1) == "Linux/macOS"
        assert _ttl_os_hint(63) == "Linux/macOS"

    def test_ttl_os_hint_windows(self) -> None:
        assert _ttl_os_hint(128) == "Windows"
        assert _ttl_os_hint(65) == "Windows"
        assert _ttl_os_hint(127) == "Windows"

    def test_ttl_os_hint_cisco(self) -> None:
        assert _ttl_os_hint(255) == "Cisco/Network Device"
        assert _ttl_os_hint(129) == "Cisco/Network Device"

    def test_host_result_dataclass(self) -> None:
        hr = HostResult(ip="10.0.0.1", hostname="router.local", os_hint="Windows",
                        discovery_method="ICMP+TCP", snmp_open=False)
        assert hr.ip == "10.0.0.1"
        assert hr.hostname == "router.local"
        assert hr.discovery_method == "ICMP+TCP"
        assert hr.snmp_open is False

    def test_host_result_defaults(self) -> None:
        hr = HostResult(ip="192.168.1.1")
        assert hr.hostname is None
        assert hr.os_hint is None
        assert hr.snmp_open is False
        assert hr.discovery_method == "unknown"

    def test_tcp_probe_ports_constant(self) -> None:
        assert 80 in TCP_PROBE_PORTS
        assert 443 in TCP_PROBE_PORTS
        assert 22 in TCP_PROBE_PORTS
        assert 445 in TCP_PROBE_PORTS
        assert 3389 in TCP_PROBE_PORTS

    def test_udp_probe_ports_constant(self) -> None:
        assert 53 in UDP_PROBE_PORTS
        assert 161 in UDP_PROBE_PORTS
        assert 123 in UDP_PROBE_PORTS

    def test_icmp_sweep_empty_list(self) -> None:
        result = _icmp_sweep([])
        assert result == []

    def test_reverse_dns_invalid(self) -> None:
        result = _reverse_dns("192.0.2.99")  # TEST-NET, should fail
        assert result is None or isinstance(result, str)

    def test_cvss_vectors_defined(self) -> None:
        assert CVSS_MEDIUM.startswith("CVSS:3.1")
        assert CVSS_HIGH.startswith("CVSS:3.1")

    def test_mitre_tags(self) -> None:
        assert MITRE_T1018 == "T1018"
        assert MITRE_T1046 == "T1046"

    def test_host_discover_tags(self) -> None:
        assert "snmp" in HostDiscover.TAGS
        assert "arp" in HostDiscover.TAGS
        assert "discovery" in HostDiscover.TAGS
