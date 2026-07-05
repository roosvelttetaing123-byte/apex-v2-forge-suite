"""Network Topology Mapper — traceroute (ICMP/UDP/TCP), ASN lookup, SNMP neighbors, graph.

Tests:
  - Traceroute to map network hops
  - Default gateway identification
  - Multi-path detection
  - Network segment boundaries
  - ASN / cloud CDN detection
"""
from __future__ import annotations

import asyncio
import json
import platform
import re
import socket
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_HIGH = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N"

MITRE_T1590_004 = "T1590.004"  # Network Topology

# Known cloud/CDN ASNs
CLOUD_ASNS: dict[str, str] = {
    "16509": "AWS (Amazon Web Services)",
    "14618": "AWS (Amazon)",
    "8075":  "Microsoft Azure",
    "15169": "Google Cloud Platform",
    "13335": "Cloudflare",
    "20940": "Akamai",
    "54113": "Fastly",
    "209242": "Cloudflare (alt)",
    "16625": "Akamai (alt)",
    "22697": "Rackspace",
    "6185":  "Apple iCloud",
}


@dataclass
class HopResult:
    """A single traceroute hop."""
    hop_num: int
    ip: Optional[str]
    rtt_ms: Optional[float]
    hostname: Optional[str] = None
    asn: Optional[str] = None
    cloud_provider: Optional[str] = None


def _lookup_asn(ip: str) -> Optional[str]:
    """Query BGPView API or Team Cymru WHOIS for ASN info.

    Returns formatted string like 'AS15169 (Google LLC)' or None.
    """
    # Try BGPView REST API
    try:
        url = f"https://api.bgpview.io/ip/{ip}"
        with urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        prefixes = data.get("data", {}).get("prefixes", [])
        if prefixes:
            asn_info = prefixes[0].get("asn", {})
            asn_num = asn_info.get("asn", "")
            asn_desc = asn_info.get("description", "")
            if asn_num:
                return f"AS{asn_num} ({asn_desc})"
    except Exception:
        pass

    # Fallback: Team Cymru WHOIS
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"
        answers = socket.getaddrinfo(query, None, socket.AF_INET)
        if answers:
            # TXT record lookup via nslookup subprocess
            result = subprocess.run(
                ["nslookup", "-type=TXT", query, "whois.cymru.com"],
                capture_output=True, text=True, timeout=5
            )
            m = re.search(r'"(\d+)\s*\|.*?"', result.stdout)
            if m:
                return f"AS{m.group(1)}"
    except Exception:
        pass

    return None


def _traceroute_icmp(target: str, max_hops: int = 30) -> list[HopResult]:
    """ICMP echo traceroute using system traceroute/tracert command."""
    is_win = platform.system() == "Windows"
    cmd = (
        ["tracert", "-d", "-w", "1000", "-h", str(max_hops), target]
        if is_win
        else ["traceroute", "-I", "-n", "-w", "1", "-m", str(max_hops), target]
    )
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return _parse_traceroute_output(result.stdout)
    except Exception:
        return []


def _traceroute_udp(target: str, max_hops: int = 30) -> list[HopResult]:
    """UDP traceroute using ports 33434+ (classic UNIX traceroute default)."""
    cmd = ["traceroute", "-U", "-n", "-w", "1", "-m", str(max_hops), target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return _parse_traceroute_output(result.stdout)
    except Exception:
        pass
    # Windows fallback or UDP not supported — use default traceroute
    return _traceroute_icmp(target, max_hops)


def _traceroute_tcp(target: str, max_hops: int = 30) -> list[HopResult]:
    """TCP SYN traceroute targeting port 80 (useful against firewalls that block ICMP/UDP)."""
    cmd = ["traceroute", "-T", "-p", "80", "-n", "-w", "1", "-m", str(max_hops), target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return _parse_traceroute_output(result.stdout)
    except Exception:
        pass
    # Fall back to ICMP
    return _traceroute_icmp(target, max_hops)


def _parse_traceroute_output(output: str) -> list[HopResult]:
    """Parse traceroute/tracert output into HopResult list."""
    hops: list[HopResult] = []
    for line in output.strip().split("\n"):
        line = line.strip()
        m = re.match(r"\s*(\d+)\s+(.+)", line)
        if not m:
            continue

        hop_num = int(m.group(1))
        rest = m.group(2)

        ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", rest)
        rtts = re.findall(r"(\d+(?:\.\d+)?)\s*ms", rest)
        avg_rtt = sum(float(r) for r in rtts[:3]) / len(rtts[:3]) if rtts else None

        if ips:
            hops.append(HopResult(
                hop_num=hop_num,
                ip=ips[0],
                rtt_ms=avg_rtt,
            ))
        elif "*" in rest:
            hops.append(HopResult(hop_num=hop_num, ip=None, rtt_ms=None))

    return hops


def _enum_snmp_neighbors(ip: str) -> list[str]:
    """Query SNMP ipNetToMediaTable (ARP table) for neighboring IPs via community 'public'.

    OID: 1.3.6.1.2.1.4.22 (ipNetToMediaTable)
    Returns list of neighbor IP strings.
    """
    neighbors: list[str] = []
    try:
        result = subprocess.run(
            ["snmpwalk", "-v1", "-c", "public", "-On", ip, "1.3.6.1.2.1.4.22"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            m = re.search(r"IpAddress:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                neighbor = m.group(1)
                if neighbor not in neighbors and neighbor != ip:
                    neighbors.append(neighbor)
    except Exception:
        pass

    # Also try ifTable walk for interface info
    try:
        result = subprocess.run(
            ["snmpwalk", "-v1", "-c", "public", ip, "1.3.6.1.2.1.2.2"],
            capture_output=True, text=True, timeout=10
        )
        # Extract IP addresses from interface descriptions
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)", result.stdout):
            candidate = m.group(1)
            if candidate not in neighbors and not candidate.startswith("0."):
                neighbors.append(candidate)
    except Exception:
        pass

    return neighbors[:20]  # Cap to avoid noise


def _detect_cloud_provider(asn_num: str) -> Optional[str]:
    """Return cloud/CDN provider name if ASN matches known providers."""
    return CLOUD_ASNS.get(asn_num)


def build_topology_graph(targets: list[str]) -> dict:
    """Run traceroute for each target, build JSON-serializable topology graph.

    Returns:
        {
            nodes: [{ip, hostname, asn, is_gateway, hop_num, cloud_provider}],
            edges: [{src, dst, rtt_ms}]
        }
    """
    all_traces: dict[str, list[HopResult]] = {}
    for target in targets:
        hops = _traceroute_icmp(target, max_hops=20)
        if not hops:
            hops = _traceroute_udp(target, max_hops=20)
        if hops:
            all_traces[target] = hops

    # Count how often each IP appears as a hop (gateway detection)
    hop_ip_counts: Counter = Counter()
    for hops in all_traces.values():
        for hop in hops:
            if hop.ip:
                hop_ip_counts[hop.ip] += 1

    total_targets = len(all_traces)
    gateway_threshold = max(1, total_targets // 2 + 1)

    nodes_by_ip: dict[str, dict] = {}
    edges: list[dict] = []

    for target, hops in all_traces.items():
        prev_ip: Optional[str] = None
        for hop in hops:
            if not hop.ip:
                prev_ip = None
                continue

            is_gateway = hop_ip_counts[hop.ip] >= gateway_threshold
            asn_str = hop.asn or _lookup_asn(hop.ip)
            asn_num = ""
            if asn_str:
                m = re.search(r"AS(\d+)", asn_str)
                if m:
                    asn_num = m.group(1)

            cloud_provider = _detect_cloud_provider(asn_num) if asn_num else None

            if hop.ip not in nodes_by_ip:
                nodes_by_ip[hop.ip] = {
                    "ip": hop.ip,
                    "hostname": hop.hostname,
                    "asn": asn_str,
                    "is_gateway": is_gateway,
                    "hop_num": hop.hop_num,
                    "cloud_provider": cloud_provider,
                }
            else:
                # Update gateway flag if newly determined
                if is_gateway:
                    nodes_by_ip[hop.ip]["is_gateway"] = True
                if cloud_provider and not nodes_by_ip[hop.ip].get("cloud_provider"):
                    nodes_by_ip[hop.ip]["cloud_provider"] = cloud_provider

            if prev_ip and prev_ip != hop.ip:
                edges.append({
                    "src": prev_ip,
                    "dst": hop.ip,
                    "rtt_ms": hop.rtt_ms,
                })
            prev_ip = hop.ip

    return {
        "nodes": list(nodes_by_ip.values()),
        "edges": edges,
        "gateway_count": sum(1 for n in nodes_by_ip.values() if n["is_gateway"]),
        "cloud_nodes": [n for n in nodes_by_ip.values() if n.get("cloud_provider")],
    }


class TopologyMap(BaseModule):
    """Network topology mapper via traceroute, SNMP, ASN lookup, and graph construction."""

    NAME        = "topology_map"
    DESCRIPTION = "Network topology: traceroute (ICMP/UDP/TCP), SNMP neighbors, ASN/CDN detection, graph"
    PHASE       = 1
    TAGS        = ["recon", "discovery", "topology", "snmp", "bgp", "cwe-200"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        topology: dict[str, list[dict]] = {}

        for host in hosts[:5]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            hops = await self._traceroute(host)
            if hops:
                topology[host] = hops

        if topology:
            gateways: set[str] = set()
            all_hops: set[str] = set()
            cloud_hops: list[dict] = []

            for host, hops in topology.items():
                if hops:
                    first_ip = hops[0].get("ip")
                    if first_ip and first_ip != "*":
                        gateways.add(first_ip)
                for hop in hops:
                    ip = hop.get("ip")
                    if ip and ip != "*":
                        all_hops.add(ip)
                        # Check cloud provider
                        asn = hop.get("asn", "")
                        if asn:
                            m = re.search(r"AS(\d+)", asn)
                            if m:
                                provider = _detect_cloud_provider(m.group(1))
                                if provider:
                                    cloud_hops.append({"ip": ip, "provider": provider})

            # SNMP neighbor enrichment for gateway IPs
            snmp_neighbors: list[str] = []
            loop = asyncio.get_event_loop()
            for gw_ip in list(gateways)[:3]:
                try:
                    neighbors = await loop.run_in_executor(
                        None, _enum_snmp_neighbors, gw_ip
                    )
                    snmp_neighbors.extend(neighbors)
                    self.log.debug("SNMP neighbors of %s: %s", gw_ip, neighbors)
                except Exception:
                    pass

            # Build topology graph
            try:
                graph = await loop.run_in_executor(
                    None, build_topology_graph, list(topology.keys())
                )
            except Exception:
                graph = {}

            ev = Evidence(
                extra={
                    "topology": {h: hops[:15] for h, hops in topology.items()},
                    "gateways": list(gateways),
                    "unique_hops": len(all_hops),
                    "snmp_neighbors": snmp_neighbors[:20],
                    "cloud_hops": cloud_hops,
                    "graph": graph,
                },
            )
            self.new_finding(
                title=f"Network Topology Mapped — {len(all_hops)} hops, {len(gateways)} gateways",
                severity=Severity.MEDIUM,
                description=(
                    f"Traceroute reveals network topology to {len(topology)} targets.\n"
                    f"Gateways: {', '.join(gateways)}\n"
                    f"Unique intermediate hops: {len(all_hops)}\n"
                    + (f"Cloud/CDN hops: {', '.join(h['provider'] for h in cloud_hops)}\n"
                       if cloud_hops else "")
                    + "\n".join(
                        f"  {host}: {' → '.join(str(h.get('ip','*')) for h in hops[:8])}"
                        for host, hops in topology.items()
                    )
                ),
                reproduction_steps=[
                    f"traceroute {list(topology.keys())[0]}",
                    f"traceroute -T -p 80 {list(topology.keys())[0]}",
                ],
                remediation=(
                    "Block ICMP/UDP traceroute at network boundaries if topology should be hidden. "
                    "Use RFC 2827 ingress filtering to prevent route manipulation."
                ),
                references=["CWE-200", f"MITRE ATT&CK {MITRE_T1590_004}"],
                evidence=ev,
                cvss_v31_vector=CVSS_INFO,
                cvss_v40_vector=CVSS40_INFO,
                target=target,
                mitre_attack=[MITRE_T1590_004],
            )

            self.config.extra["topology"] = topology
            self.config.extra["gateways"] = list(gateways)

            # Emit HIGH finding for cloud traffic routing exposure
            if cloud_hops:
                ev_cloud = Evidence(extra={"cloud_hops": cloud_hops})
                self.new_finding(
                    title=f"Traffic Routed Through Cloud/CDN Infrastructure ({len(cloud_hops)} hop(s))",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Network traffic passes through cloud/CDN infrastructure: "
                        f"{', '.join(set(h['provider'] for h in cloud_hops))}. "
                        "This may indicate misconfigured routing or CDN provider visibility."
                    ),
                    reproduction_steps=[f"traceroute {target}", "mtr --report " + target],
                    remediation=(
                        "Review network routing to verify CDN/cloud transit is intentional. "
                        "Ensure sensitive traffic is not inadvertently routed through third-party infrastructure."
                    ),
                    references=[f"MITRE ATT&CK {MITRE_T1590_004}"],
                    evidence=ev_cloud,
                    cvss_v31_vector=CVSS_MEDIUM,
                    target=target,
                    mitre_attack=[MITRE_T1590_004],
                )

        return self._make_result(start)

    async def _traceroute(self, host: str) -> list[dict]:
        """Async wrapper — tries ICMP, falls back to UDP."""
        loop = asyncio.get_event_loop()

        # Try ICMP first
        hops = await loop.run_in_executor(None, _traceroute_icmp, host, 20)
        if not hops:
            # Fall back to UDP
            hops = await loop.run_in_executor(None, _traceroute_udp, host, 20)

        # Enrich hops with reverse DNS (best effort)
        enriched: list[dict] = []
        for hop in hops:
            d: dict = {
                "hop": hop.hop_num,
                "ip": hop.ip or "*",
                "rtt_ms": [hop.rtt_ms] if hop.rtt_ms is not None else [],
                "hostname": hop.hostname,
                "asn": hop.asn,
            }
            if hop.ip and hop.ip != "*":
                try:
                    hostname = await loop.run_in_executor(
                        None, socket.gethostbyaddr, hop.ip
                    )
                    d["hostname"] = hostname[0]
                except Exception:
                    pass
            enriched.append(d)

        return enriched

    def _parse_traceroute(self, output: str) -> list[dict]:
        """Parse traceroute output — kept for backwards compatibility."""
        hops = _parse_traceroute_output(output)
        return [
            {
                "hop": h.hop_num,
                "ip": h.ip or "*",
                "rtt_ms": [h.rtt_ms] if h.rtt_ms else [],
            }
            for h in hops
        ]


class TestTopologyMap:
    """Embedded unit tests for topology mapping functions."""

    def test_parse_traceroute(self) -> None:
        mod = TopologyMap.__new__(TopologyMap)
        output = " 1  192.168.1.1  1.234 ms  0.987 ms  1.123 ms\n 2  10.0.0.1  5.432 ms\n 3  * * *"
        hops = mod._parse_traceroute(output)
        assert len(hops) == 3
        assert hops[0]["ip"] == "192.168.1.1"
        assert hops[2]["ip"] == "*"

    def test_phase(self) -> None:
        assert TopologyMap.PHASE == 1

    def test_hop_result_dataclass(self) -> None:
        hop = HopResult(hop_num=1, ip="10.0.0.1", rtt_ms=1.5, hostname="router.local", asn="AS15169")
        assert hop.hop_num == 1
        assert hop.ip == "10.0.0.1"
        assert hop.rtt_ms == 1.5
        assert hop.asn == "AS15169"

    def test_hop_result_none_ip(self) -> None:
        hop = HopResult(hop_num=3, ip=None, rtt_ms=None)
        assert hop.ip is None
        assert hop.rtt_ms is None

    def test_parse_traceroute_output_basic(self) -> None:
        output = " 1  192.168.1.1  1.234 ms\n 2  * * *\n 3  8.8.8.8  15.0 ms"
        hops = _parse_traceroute_output(output)
        assert len(hops) == 3
        assert hops[0].ip == "192.168.1.1"
        assert hops[1].ip is None
        assert hops[2].ip == "8.8.8.8"

    def test_cloud_asns_defined(self) -> None:
        assert "16509" in CLOUD_ASNS  # AWS
        assert "15169" in CLOUD_ASNS  # GCP
        assert "13335" in CLOUD_ASNS  # Cloudflare
        assert "8075" in CLOUD_ASNS   # Azure

    def test_detect_cloud_provider_aws(self) -> None:
        result = _detect_cloud_provider("16509")
        assert result is not None
        assert "AWS" in result

    def test_detect_cloud_provider_unknown(self) -> None:
        result = _detect_cloud_provider("99999")
        assert result is None

    def test_detect_cloud_provider_cloudflare(self) -> None:
        result = _detect_cloud_provider("13335")
        assert result is not None
        assert "Cloudflare" in result

    def test_build_topology_graph_empty(self) -> None:
        graph = build_topology_graph([])
        assert "nodes" in graph
        assert "edges" in graph
        assert graph["nodes"] == []
        assert graph["edges"] == []

    def test_cvss_vectors(self) -> None:
        assert CVSS_INFO.startswith("CVSS:3.1")
        assert CVSS40_INFO.startswith("CVSS:4.0")

    def test_mitre_tag(self) -> None:
        assert MITRE_T1590_004 == "T1590.004"

    def test_topology_map_tags(self) -> None:
        assert "topology" in TopologyMap.TAGS
        assert "snmp" in TopologyMap.TAGS
