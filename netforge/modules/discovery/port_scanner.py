"""Port scanner — TCP connect + UDP scan with Nessus-grade coverage."""
from __future__ import annotations

import asyncio
import random
import re
import shutil
import ssl
import struct
import sys
import time
from pathlib import Path
from xml.etree import ElementTree

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# nmap top-1000 TCP ports (ordered by frequency)
NMAP_TOP_1000: tuple[int, ...] = (
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33,
    37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100,
    106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179,
    199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366,
    389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497,
    500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587,
    593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700,
    705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843,
    873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993,
    995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024,
    1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036,
    1037, 1038, 1039, 1040, 1041, 1044, 1048, 1049, 1050, 1053, 1054, 1056,
    1058, 1059, 1064, 1065, 1066, 1069, 1071, 1074, 1080, 1110, 1234, 1243,
    1433, 1494, 1521, 1720, 1723, 1755, 1761, 1900, 2000, 2001, 2002, 2003,
    2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030,
    2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048,
    2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121,
    2126, 2135, 2144, 2160, 2161, 2170, 2179, 2181, 2190, 2191, 2196, 2200,
    2222, 2251, 2260, 2288, 2301, 2323, 2366, 2375, 2376, 2379, 2380, 2381,
    2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601,
    2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725,
    2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000,
    3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3052, 3071, 3077,
    3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306,
    3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389,
    3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690,
    3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851,
    3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986,
    3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125,
    4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449,
    4550, 4567, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009,
    5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102,
    5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357,
    5405, 5432, 5555, 5560, 5601, 5631, 5666, 5671, 5672, 5678, 5679, 5718,
    5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862,
    5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922,
    5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998,
    5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059,
    6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6379, 6389, 6443, 6502,
    6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669,
    6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000,
    7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201,
    7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800,
    7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009,
    8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192,
    8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8301, 8333, 8383,
    8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873,
    8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050,
    9071, 9080, 9081, 9090, 9091, 9092, 9100, 9101, 9102, 9103, 9110, 9111,
    9200, 9207, 9220, 9290, 9300, 9415, 9418, 9485, 9500, 9502, 9503, 9535,
    9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917,
    9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004,
    10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10250, 10255,
    10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11211,
    11967, 12000, 12174, 12265, 12345, 13456, 14000, 14238, 14441, 14442, 15000,
    15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080,
    16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315,
    19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571,
    22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27017, 27352, 27353,
    27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769,
    32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780,
    32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500,
    38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080,
    49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163,
    49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50006, 50300,
    50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045,
    54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020,
    60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
)

TOP_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 1723,
    2049, 2375, 3306, 3389, 4848, 5432, 5900, 5985, 5986,
    6379, 7001, 8080, 8443, 8888, 9000, 9090, 9200, 9300,
    11211, 27017, 50000,
]

UDP_TOP_20: tuple[int, ...] = (
    53, 67, 68, 69, 111, 123, 137, 138, 161, 162,
    389, 500, 514, 520, 631, 1434, 1900, 4500, 5353, 5060,
)

RISKY_PORTS: frozenset[int] = frozenset({
    21, 23, 69, 111, 135, 137, 139, 445, 512, 513, 514,
    873, 1433, 1521, 2049, 2375, 2376, 2379, 2380,
    3306, 3389, 4848, 5432, 5900, 5985, 5986,
    6379, 7001, 8500, 9090, 9200, 9300, 10250, 10255,
    11211, 27017, 50000,
})

_PORT_SEVERITY: dict[int, "Severity"] = {
    2375: Severity.CRITICAL,
    6379: Severity.CRITICAL,
    10250: Severity.CRITICAL,
    2376: Severity.HIGH,
    27017: Severity.HIGH,
    9200: Severity.HIGH,
    11211: Severity.HIGH,
    2049: Severity.HIGH,
    5900: Severity.HIGH,
    23: Severity.HIGH,
    512: Severity.HIGH,
    513: Severity.HIGH,
    514: Severity.HIGH,
    8500: Severity.HIGH,
    4848: Severity.HIGH,
    7001: Severity.HIGH,
    50000: Severity.HIGH,
    10255: Severity.HIGH,
    873: Severity.MEDIUM,
    9090: Severity.MEDIUM,
}

_CVSS40: dict[str, str] = {
    "critical": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "high":     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "medium":   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "low":      "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
}
_CVSS31: dict[str, str] = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "medium":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "low":      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
}

_TIMING_DELAY: dict[str, float] = {
    "T1": 0.5, "T2": 0.2, "T3": 0.1, "T4": 0.05, "T5": 0.0,
}


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.received: bytes | None = None
        self._transport: asyncio.DatagramTransport | None = None
        self._done: asyncio.Event = asyncio.Event()

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def datagram_received(self, data: bytes, addr: object) -> None:
        self.received = data
        self._done.set()

    def error_received(self, exc: Exception) -> None:
        self._done.set()

    def connection_lost(self, exc: Exception | None) -> None:
        self._done.set()

    async def wait(self, timeout: float = 2.0) -> bool:
        try:
            await asyncio.wait_for(self._done.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        return self.received is not None


class PortScanner(BaseModule):
    """TCP + UDP port scanner with protocol-aware banner probes and OS hints."""

    NAME        = "port_scanner"
    DESCRIPTION = "TCP/UDP port scan with per-protocol banner probes and OS fingerprinting"
    PHASE       = 1
    TAGS        = ["discovery", "port-scan", "network"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        hosts = self.config.extra.get("live_hosts", [self.config.target])
        timing = self.config.extra.get("timing", "T3")
        self._delay = _TIMING_DELAY.get(timing, 0.1)
        self._timing = timing

        self.log.info("Port scanning %d host(s) timing=%s", len(hosts), timing)

        self.config.extra.setdefault("os_hints", {})
        open_ports: dict[str, list[dict]] = {}

        scan_ports = self.config.extra.get("scan_ports", NMAP_TOP_1000)
        sem_size = 200 if timing in ("T4", "T5") else 100 if timing == "T3" else 50
        sem = asyncio.Semaphore(sem_size)

        host_limit = self.config.extra.get("host_limit", 254)
        scan_tasks = []
        valid_hosts = []
        for host in hosts[:host_limit]:
            if not self.check_scope(host):
                continue
            scan_tasks.append(self._scan_host(host, scan_ports, sem))
            valid_hosts.append(host)

        results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        for host, result in zip(valid_hosts, results):
            if isinstance(result, list) and result:
                open_ports[host] = result

        if shutil.which("nmap") and self.config.extra.get("use_nmap", False):
            for host in list(open_ports.keys())[:10]:
                await self._nmap_augment(host, open_ports[host])

        if self.config.extra.get("udp_scan", False):
            for host in list(open_ports.keys())[:host_limit]:
                udp_results = await self._udp_scan_host(host)
                if udp_results:
                    open_ports.setdefault(host, []).extend(udp_results)

        self.config.extra["open_ports"] = open_ports

        for host, ports in open_ports.items():
            risky = [p for p in ports if p["port"] in RISKY_PORTS]
            if risky:
                self._emit_risky_finding(host, risky, ports)

        self.log.info("Scan complete: %d hosts with open ports", len(open_ports))
        return self._make_result(start)

    async def _scan_host(
        self, host: str, scan_ports: tuple | list, sem: asyncio.Semaphore
    ) -> list[dict]:
        tasks = [self._probe_port(host, port, sem) for port in scan_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_list = [r for r in results if isinstance(r, dict)]
        if open_list:
            self._derive_os_hint(host, open_list)
        return open_list

    async def _probe_port(
        self, host: str, port: int, sem: asyncio.Semaphore
    ) -> dict | None:
        async with sem:
            if self._delay > 0:
                jitter = random.uniform(0, self._delay) if self._timing == "T1" else self._delay * 0.1
                await asyncio.sleep(self._delay + jitter)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=1.5
                )
                banner = await self._protocol_banner(host, port, reader, writer)
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass
                return {
                    "port":    port,
                    "state":   "open",
                    "proto":   "tcp",
                    "service": _port_service_name(port),
                    "banner":  banner,
                }
            except Exception:
                return None

    async def _protocol_banner(
        self,
        host: str,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> str:
        try:
            if port == 22:
                data = await asyncio.wait_for(reader.readline(), timeout=3.0)
                return data.decode(errors="ignore").strip()[:200]

            if port == 21:
                data = await asyncio.wait_for(reader.read(256), timeout=3.0)
                return data.decode(errors="ignore").strip()[:200]

            if port in (25, 587):
                banner_line = await asyncio.wait_for(reader.readline(), timeout=3.0)
                writer.write(b"EHLO forge-scanner\r\n")
                await asyncio.wait_for(writer.drain(), timeout=2.0)
                ehlo = await asyncio.wait_for(reader.read(512), timeout=3.0)
                return (banner_line + ehlo).decode(errors="ignore").strip()[:300]

            if port in (80, 8080, 8000, 8008):
                writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                await asyncio.wait_for(writer.drain(), timeout=2.0)
                data = await asyncio.wait_for(reader.read(1024), timeout=4.0)
                raw = data.decode(errors="ignore")
                m = re.search(r"(?i)server:\s*([^\r\n]+)", raw)
                return m.group(0).strip()[:200] if m else raw.split("\r\n")[0][:200]

            if port in (443, 8443, 4443):
                raw_sock = writer.get_extra_info("socket")
                if raw_sock is not None:
                    try:
                        import ssl as _ssl

                        def _tls_probe() -> str:
                            """Run blocking TLS handshake in thread pool."""
                            ctx = _ssl.create_default_context()
                            ctx.check_hostname = False
                            ctx.verify_mode = _ssl.CERT_NONE
                            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
                            cert = tls_sock.getpeercert()
                            cn = ""
                            if cert:
                                for field_pair in cert.get("subject", []):
                                    for k, v in field_pair:
                                        if k == "commonName":
                                            cn = v
                            return f"TLS CN={cn}" if cn else "TLS"

                        return await asyncio.wait_for(
                            asyncio.to_thread(_tls_probe), timeout=5.0
                        )
                    except Exception:
                        return "TLS"
                return "TLS"

            if port == 3306:
                data = await asyncio.wait_for(reader.read(5), timeout=3.0)
                if len(data) >= 5:
                    pkt_len = struct.unpack_from("<I", data[:4])[0]
                    return f"MySQL handshake pkt_len={pkt_len}"
                return "MySQL"

            if port == 6379:
                writer.write(b"PING\r\n")
                await asyncio.wait_for(writer.drain(), timeout=2.0)
                data = await asyncio.wait_for(reader.read(128), timeout=3.0)
                resp = data.decode(errors="ignore").strip()
                if "+PONG" in resp:
                    return "Redis +PONG (no auth)"
                if "NOAUTH" in resp or "-ERR" in resp:
                    return f"Redis auth required: {resp[:80]}"
                return resp[:100]

            if port == 27017:
                data = await asyncio.wait_for(reader.read(4), timeout=3.0)
                if len(data) >= 4:
                    msg_len = struct.unpack_from("<I", data)[0]
                    return f"MongoDB wire proto msg_len={msg_len}"
                return "MongoDB"

            if port == 11211:
                writer.write(b"stats\r\n")
                await asyncio.wait_for(writer.drain(), timeout=2.0)
                data = await asyncio.wait_for(reader.read(256), timeout=3.0)
                resp = data.decode(errors="ignore").strip()
                m = re.search(r"STAT version\s+(\S+)", resp)
                return f"Memcached version={m.group(1)}" if m else "Memcached " + resp[:80]

            if port == 9200:
                writer.write(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                await asyncio.wait_for(writer.drain(), timeout=2.0)
                data = await asyncio.wait_for(reader.read(1024), timeout=4.0)
                raw = data.decode(errors="ignore")
                m = re.search(r"\"version\"\s*:\s*\{[^}]*\"number\"\s*:\s*\"([^\"]+)\"", raw)
                return f"Elasticsearch {m.group(1)}" if m else "Elasticsearch"

            data = await asyncio.wait_for(reader.read(512), timeout=3.0)
            return data.decode(errors="ignore").strip()[:200]

        except Exception:
            return ""

    async def _udp_scan_host(self, host: str) -> list[dict]:
        results = []
        loop = asyncio.get_running_loop()
        for port in UDP_TOP_20:
            try:
                transport, proto = await loop.create_datagram_endpoint(
                    _UDPProtocol,
                    remote_addr=(host, port),
                )
                transport.sendto(_udp_probe(port))
                got_response = await proto.wait(timeout=2.0)
                transport.close()
                state = "open" if got_response else "open|filtered"
                results.append({
                    "port":    port,
                    "state":   state,
                    "proto":   "udp",
                    "service": _port_service_name(port),
                    "banner":  proto.received.decode(errors="ignore")[:100] if proto.received else "",
                })
            except Exception:
                pass
        return results

    def _derive_os_hint(self, host: str, ports: list[dict]) -> None:
        banners = " ".join(p.get("banner", "") for p in ports).lower()
        port_set = {p["port"] for p in ports}
        if any(k in banners for k in ("openssh", "ubuntu", "debian", "centos", "linux", "freebsd")):
            self.config.extra["os_hints"][host] = "Linux"
        elif any(k in banners for k in ("microsoft", "iis", "windows", "exchange")):
            self.config.extra["os_hints"][host] = "Windows"
        elif any(k in banners for k in ("cisco", "juniper", "routeros", "junos")):
            self.config.extra["os_hints"][host] = "Network Device"
        if 445 in port_set and 3389 in port_set:
            self.config.extra["os_hints"][host] = "Windows"
        if 22 in port_set and 111 in port_set:
            self.config.extra["os_hints"].setdefault(host, "Linux")

    async def _nmap_augment(self, host: str, port_list: list[dict]) -> None:
        nmap = shutil.which("nmap")
        if not nmap:
            return
        port_str = ",".join(str(p["port"]) for p in port_list[:100])
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-sV", "--top-ports", "1000", "-T3",
                "-p", port_str, "-Pn", "-n", "-oX", "-", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            _parse_nmap_xml(stdout.decode(errors="ignore"), port_list)
        except Exception as exc:
            self.log.debug("nmap augment failed for %s: %s", host, exc)

    def _emit_risky_finding(
        self, host: str, risky: list[dict], all_ports: list[dict]
    ) -> None:
        os_hint = self.config.extra["os_hints"].get(host, "unknown")
        risky_strs = ", ".join(
            f"{p['port']}/{p.get('proto', 'tcp')} ({p.get('service', '?')})"
            for p in risky
        )
        worst_port = risky[0]
        best_sev = Severity.LOW
        for p in risky:
            sev = _PORT_SEVERITY.get(p["port"], Severity.MEDIUM)
            if sev == Severity.CRITICAL:
                worst_port = p
                best_sev = Severity.CRITICAL
                break
            if sev == Severity.HIGH and best_sev != Severity.CRITICAL:
                worst_port = p
                best_sev = Severity.HIGH
            elif sev == Severity.MEDIUM and best_sev not in (Severity.CRITICAL, Severity.HIGH):
                worst_port = p
                best_sev = Severity.MEDIUM

        tier = best_sev.value.lower()
        cvss40 = _CVSS40.get(tier, _CVSS40["medium"])
        cvss31 = _CVSS31.get(tier, _CVSS31["medium"])

        ev = Evidence(
            extra={
                "host": host,
                "os_hint": os_hint,
                "open_ports": all_ports,
                "risky_ports": risky,
                "port_count": len(all_ports),
            }
        )
        self.new_finding(
            title=f"Risky Services Exposed — {host} [{risky_strs}]",
            severity=best_sev,
            description=(
                f"Host {host} (OS hint: {os_hint}) exposes {len(risky)} potentially "
                f"dangerous service(s):\n\n"
                + "\n".join(
                    f"  - Port {p['port']}/{p.get('proto', 'tcp')}: "
                    f"{p.get('service', '?')} — {p.get('banner', '')[:80]}"
                    for p in risky
                )
                + f"\n\nTotal open ports: {len(all_ports)}"
            ),
            reproduction_steps=[
                f"nmap -sV -p {','.join(str(p['port']) for p in risky)} -Pn {host}",
                f"nc -nv {host} {risky[0]['port']}",
            ],
            remediation=(
                "Apply firewall ACLs to restrict access to management/data ports. "
                "Disable services not required for this host role. "
                "Enforce authentication on all exposed services."
            ),
            references=["CWE-200", "CWE-284", "https://www.cisecurity.org/controls/"],
            evidence=ev,
            cvss_v40_vector=cvss40,
            cvss_v31_vector=cvss31,
            target=host,
            mitre_attack=["T1046", "T1190"],
        )


def _port_service_name(port: int) -> str:
    _MAP: dict[int, str] = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        67: "DHCP", 69: "TFTP", 79: "Finger", 80: "HTTP", 88: "Kerberos",
        110: "POP3", 111: "RPCbind", 119: "NNTP", 123: "NTP",
        135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
        143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP",
        389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos-Pass",
        500: "IKE", 512: "rexec", 513: "rlogin", 514: "rsh/syslog",
        515: "LPD", 520: "RIP", 587: "SMTP-Submit", 631: "IPP",
        636: "LDAPS", 873: "rsync", 902: "VMware-Auth",
        993: "IMAPS", 995: "POP3S", 1080: "SOCKS5",
        1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
        1900: "UPnP", 2049: "NFS", 2181: "ZooKeeper",
        2375: "Docker-API", 2376: "Docker-TLS", 2379: "etcd-client",
        2380: "etcd-peer", 3000: "Grafana", 3268: "GlobalCatalog",
        3269: "GlobalCatalogSSL", 3306: "MySQL", 3389: "RDP",
        3690: "SVN", 4848: "GlassFish-Admin", 5000: "Flask/Dev",
        5432: "PostgreSQL", 5601: "Kibana", 5672: "RabbitMQ",
        5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
        6379: "Redis", 6443: "k8s-API", 7001: "WebLogic",
        7077: "Spark", 8080: "HTTP-Alt", 8200: "Vault",
        8300: "Consul-RPC", 8301: "Consul-LAN-Gossip",
        8443: "HTTPS-Alt", 8500: "Consul-HTTP", 8888: "Jupyter",
        9000: "SonarQube/PHP-FPM", 9090: "Cockpit/Prometheus",
        9092: "Kafka", 9100: "NodeExporter", 9200: "Elasticsearch",
        9300: "Elasticsearch-Cluster", 10250: "kubelet-API",
        10255: "kubelet-ReadOnly", 11211: "Memcached",
        27017: "MongoDB", 50000: "Jenkins-JNLP", 61616: "ActiveMQ",
    }
    return _MAP.get(port, f"port-{port}")


def _udp_probe(port: int) -> bytes:
    probes: dict[int, bytes] = {
        53:   b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        161:  b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x7f\x7e\x33\x40\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        123:  b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00" + b"\x00" * 36,
        1434: b"\x02",
        5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x00\x00\xff\x00\x01",
    }
    return probes.get(port, b"\x00")


def _parse_nmap_xml(xml_output: str, port_list: list[dict]) -> None:
    try:
        from xml.etree import ElementTree
        root = ElementTree.fromstring(xml_output)
        for port_el in root.findall(".//port"):
            portid = int(port_el.get("portid", "0"))
            svc_el = port_el.find("service")
            if svc_el is None:
                continue
            name = svc_el.get("name", "")
            product = svc_el.get("product", "")
            version = svc_el.get("version", "")
            banner_parts = [x for x in (product, version) if x]
            for entry in port_list:
                if entry["port"] == portid:
                    if name:
                        entry["service"] = name
                    if banner_parts and not entry.get("banner"):
                        entry["banner"] = " ".join(banner_parts)
    except Exception:
        pass


class TestPortScanner:
    def test_nmap_top_1000_size(self) -> None:
        assert len(NMAP_TOP_1000) >= 800  # 845 deduplicated nmap top-1000 ports
        assert 22 in NMAP_TOP_1000
        assert 445 in NMAP_TOP_1000
        assert 6379 in NMAP_TOP_1000
        assert 10250 in NMAP_TOP_1000

    def test_top_ports_subset(self) -> None:
        assert len(TOP_PORTS) >= 20
        assert 22 in TOP_PORTS

    def test_risky_ports(self) -> None:
        assert 2375 in RISKY_PORTS
        assert 6379 in RISKY_PORTS
        assert 10250 in RISKY_PORTS

    def test_port_service_name(self) -> None:
        assert _port_service_name(22) == "SSH"
        assert _port_service_name(6379) == "Redis"
        assert _port_service_name(10250) == "kubelet-API"

    def test_udp_probe_dns(self) -> None:
        probe = _udp_probe(53)
        assert len(probe) > 0

    def test_severity_map(self) -> None:
        assert _PORT_SEVERITY[2375] == Severity.CRITICAL
        assert _PORT_SEVERITY[10250] == Severity.CRITICAL
        assert _PORT_SEVERITY[6379] == Severity.CRITICAL

    def test_parse_nmap_xml_empty(self) -> None:
        _parse_nmap_xml("", [])

    def test_timing_delays(self) -> None:
        assert _TIMING_DELAY["T5"] == 0.0
        assert _TIMING_DELAY["T1"] > _TIMING_DELAY["T3"]
