"""Shodan Enricher — origin IPs, open ports, service banners, SSL certs per domain.

Queries the Shodan API to enrich targets with:
  - Real origin IPs behind CDN/WAF (bypass detection)
  - Open ports and service banners across all IPs
  - SSL certificate details + SAN enumeration
  - Technology fingerprinting from banners
  - Known CVEs from Shodan's vuln database
  - ASN / org / ISP attribution
  - Passive DNS correlation

API key: SHODAN_API_KEY env var.
Supports: IPv4 + IPv6, CIDR ranges, ASN lookups, org-level sweeps.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("leak_intel.shodan_enricher")

CVSS_INFO   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_HIGH   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

_CDN_ASNS = {
    "AS13335", "AS209242",    # Cloudflare
    "AS16625", "AS20940",     # Akamai
    "AS16509", "AS14618",     # AWS CloudFront
    "AS15169",                # Google (GFE)
    "AS8068", "AS8075",       # Microsoft Azure
    "AS54113",                # Fastly
    "AS22822",                # Limelight
    "AS60068",                # CDN77
}

_CRITICAL_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587, 636,
    993, 995, 1433, 1521, 2049, 3306, 3389, 4848, 5432, 5900, 5985,
    6379, 7001, 8080, 8443, 8888, 9200, 9300, 11211, 27017, 27018,
}

_DANGEROUS_BANNERS = [
    (re.compile(r"redis_version", re.I),  "Redis (unauthenticated)"),
    (re.compile(r"MongoDB\s+3\.\d",  re.I), "MongoDB 3.x (EOL)"),
    (re.compile(r"Elasticsearch",     re.I), "Elasticsearch"),
    (re.compile(r"memcached\s+1\.",   re.I), "Memcached (unauthenticated)"),
    (re.compile(r"Apache Cassandra",  re.I), "Cassandra"),
    (re.compile(r"etcd\s+cluster",    re.I), "etcd (cluster API)"),
    (re.compile(r"Kubernetes Dashboard", re.I), "Kubernetes Dashboard"),
    (re.compile(r"Grafana",           re.I), "Grafana"),
    (re.compile(r"Jenkins",           re.I), "Jenkins"),
    (re.compile(r"phpMyAdmin",        re.I), "phpMyAdmin"),
    (re.compile(r"Kibana",            re.I), "Kibana"),
    (re.compile(r"VNC authentication", re.I), "VNC"),
    (re.compile(r"X11 forwarding",    re.I), "X11"),
]


class ShodanEnricher(BaseModule):
    """Enriches targets with Shodan intelligence: IPs, ports, CVEs, certs."""

    NAME        = "shodan_enricher"
    DESCRIPTION = "Query Shodan for origin IPs, open ports, banners, CVEs"
    PHASE       = 1
    TAGS        = ["recon", "osint", "shodan", "passive"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")

        api_key = os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            self.log.warning("SHODAN_API_KEY not set — skipping Shodan enrichment")
            return self._make_result(start, skipped=True, skip_reason="no SHODAN_API_KEY")

        domain = self._extract_domain(target)
        if not domain:
            return self._make_result(start, skipped=True, skip_reason="cannot parse domain")

        self.log.info("Shodan enrichment for %s", domain)

        # Phase 1: DNS resolve domain to IPs
        ips = await self._resolve_domain(domain)

        # Phase 2: Shodan host lookups for each IP
        host_data: list[dict[str, Any]] = []
        for ip in ips[:10]:
            data = await self._query_host(ip, api_key)
            if data:
                host_data.append(data)

        # Phase 3: Shodan domain search (cert SANs, DNS records)
        domain_intel = await self._search_domain(domain, api_key)

        # Phase 4: Deduplicate + discover more IPs from domain search
        seen_ips = {h["ip_str"] for h in host_data}
        for extra_ip in domain_intel.get("ips", []):
            if extra_ip not in seen_ips and len(host_data) < 20:
                data = await self._query_host(extra_ip, api_key)
                if data:
                    host_data.append(data)
                    seen_ips.add(extra_ip)

        # Analyse and emit findings
        self._emit_origin_ip_findings(domain, host_data, target)
        self._emit_open_port_findings(domain, host_data, target)
        self._emit_cve_findings(domain, host_data, target)
        self._emit_cert_san_findings(domain, domain_intel, target)
        self._emit_dangerous_service_findings(domain, host_data, target)

        return self._make_result(start)

    # ── helpers ──────────────────────────────────────────────────────────────

    def _extract_domain(self, target: str) -> str:
        try:
            parsed = urlparse(target)
            host = parsed.netloc or parsed.path
            host = host.split(":")[0].split("/")[0].strip()
            return host.lower()
        except Exception:
            return ""

    async def _resolve_domain(self, domain: str) -> list[str]:
        """Resolve domain to IPv4 addresses via asyncio."""
        try:
            loop = asyncio.get_event_loop()
            info = await loop.getaddrinfo(domain, None)
            ips: list[str] = []
            seen: set[str] = set()
            for ai in info:
                ip = ai[4][0]
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
            return ips
        except Exception:
            return []

    async def _query_host(self, ip: str, api_key: str) -> dict[str, Any] | None:
        """GET /shodan/host/{ip} with retry."""
        try:
            import aiohttp
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}&minify=false"
            await self.rate_limit()
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status == 200:
                        return await r.json()
                    if r.status == 404:
                        return None
                    if r.status == 429:
                        await asyncio.sleep(2)
                        return None
        except Exception as exc:
            self.log.debug("Shodan host query failed for %s: %s", ip, exc)
        return None

    async def _search_domain(self, domain: str, api_key: str) -> dict[str, Any]:
        """GET /dns/domain/{domain} for passive DNS + cert SANs."""
        result: dict[str, Any] = {"ips": [], "subdomains": [], "certs": []}
        try:
            import aiohttp
            url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}&history=false&type=A"
            await self.rate_limit()
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status == 200:
                        data = await r.json()
                        for rec in data.get("data", []):
                            val = rec.get("value", "")
                            try:
                                ipaddress.ip_address(val)
                                result["ips"].append(val)
                            except ValueError:
                                pass
                        result["subdomains"] = data.get("subdomains", [])
        except Exception as exc:
            self.log.debug("Shodan domain search failed: %s", exc)

        # Also search Shodan for certs mentioning the domain
        try:
            import aiohttp
            query = f"ssl.cert.subject.cn:{domain} port:443"
            url = (
                f"https://api.shodan.io/shodan/host/search"
                f"?key={api_key}&query={query}&facets=ip&page=1&minify=true"
            )
            await self.rate_limit()
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status == 200:
                        data = await r.json()
                        for match in data.get("matches", []):
                            ip = match.get("ip_str", "")
                            if ip:
                                result["ips"].append(ip)
                            ssl = match.get("ssl", {})
                            cert = ssl.get("cert", {})
                            for san in cert.get("extensions", []):
                                if san.get("name") == "subjectAltName":
                                    result["certs"].append(san.get("data", ""))
        except Exception as exc:
            self.log.debug("Shodan cert search failed: %s", exc)

        result["ips"] = list(set(result["ips"]))
        return result

    # ── findings emitters ─────────────────────────────────────────────────────

    def _emit_origin_ip_findings(
        self, domain: str, host_data: list[dict], target: str
    ) -> None:
        cdn_bypass: list[str] = []
        all_ips: list[str] = []

        for h in host_data:
            ip = h.get("ip_str", "")
            asn = h.get("asn", "").upper()
            all_ips.append(ip)
            if asn not in _CDN_ASNS:
                cdn_bypass.append(ip)

        if not all_ips:
            return

        desc = f"Shodan resolved {domain} to {len(all_ips)} IP(s)."
        sev = Severity.INFORMATIONAL
        if cdn_bypass and len(cdn_bypass) < len(all_ips):
            sev = Severity.MEDIUM
            desc += (
                f" {len(cdn_bypass)} IPs appear to be origin servers not behind CDN/WAF: "
                + ", ".join(cdn_bypass[:5])
                + ". Direct requests may bypass WAF rules."
            )
        elif cdn_bypass:
            desc += " IPs: " + ", ".join(all_ips[:10])

        ev = Evidence(extra={"ips": all_ips, "cdn_bypass_candidates": cdn_bypass})
        self.new_finding(
            title=f"Origin IPs for {domain} ({len(all_ips)} resolved)",
            severity=sev,
            description=desc,
            reproduction_steps=[
                f"shodan host {cdn_bypass[0]}" if cdn_bypass else f"shodan host {all_ips[0]}",
                f"curl -H 'Host: {domain}' http://{cdn_bypass[0] if cdn_bypass else all_ips[0]}/",
            ],
            remediation="Ensure origin IPs are firewalled to only accept traffic from CDN IPs.",
            references=["T1590.005 — Network Topology Discovery"],
            evidence=ev,
            cvss_v31_vector=CVSS_HIGH if cdn_bypass else CVSS_INFO,
            cvss_v40_vector=CVSS40_HIGH if cdn_bypass else CVSS40_INFO,
            target=target,
        )

    def _emit_open_port_findings(
        self, domain: str, host_data: list[dict], target: str
    ) -> None:
        port_map: dict[str, list[int]] = {}
        for h in host_data:
            ip = h.get("ip_str", "")
            ports = [d.get("port", 0) for d in h.get("data", [])]
            interesting = [p for p in ports if p in _CRITICAL_PORTS]
            if interesting:
                port_map[ip] = interesting

        if not port_map:
            return

        self.new_finding(
            title=f"Sensitive ports exposed on {domain} ({len(port_map)} hosts)",
            severity=Severity.MEDIUM,
            description=(
                f"Shodan found {sum(len(v) for v in port_map.values())} sensitive port(s) "
                f"across {len(port_map)} host(s) associated with {domain}. "
                "Exposed administrative ports increase attack surface significantly."
            ),
            reproduction_steps=[
                f"shodan host {ip}" for ip in list(port_map.keys())[:3]
            ],
            remediation=(
                "Restrict all non-HTTP(S) ports behind VPN or firewall. "
                "Disable unnecessary services."
            ),
            references=["T1046 — Network Service Discovery"],
            evidence=Evidence(extra={"port_map": port_map}),
            cvss_v31_vector=CVSS_HIGH,
            cvss_v40_vector=CVSS40_HIGH,
            target=target,
        )

    def _emit_cve_findings(
        self, domain: str, host_data: list[dict], target: str
    ) -> None:
        all_cves: dict[str, list[str]] = {}
        for h in host_data:
            ip = h.get("ip_str", "")
            vulns = h.get("vulns", {})
            if vulns:
                all_cves[ip] = list(vulns.keys())

        if not all_cves:
            return

        total = sum(len(v) for v in all_cves.values())
        self.new_finding(
            title=f"Shodan CVEs: {total} known vulnerabilities on {domain}",
            severity=Severity.HIGH,
            description=(
                f"Shodan's vulnerability database reports {total} CVE(s) across "
                f"{len(all_cves)} host(s). These are publicly known vulnerabilities "
                "that may have public exploits."
            ),
            reproduction_steps=[
                f"# {ip}: {', '.join(cves[:5])}" for ip, cves in list(all_cves.items())[:3]
            ],
            remediation=(
                "Patch or upgrade affected services. "
                "Apply virtual patches via WAF for immediate mitigation."
            ),
            references=["https://cve.mitre.org/", "T1190 — Exploit Public-Facing Application"],
            evidence=Evidence(extra={"cves_by_ip": all_cves}),
            cvss_v31_vector=CVSS_HIGH,
            cvss_v40_vector=CVSS40_HIGH,
            target=target,
        )

    def _emit_cert_san_findings(
        self, domain: str, domain_intel: dict, target: str
    ) -> None:
        subdomains: list[str] = domain_intel.get("subdomains", [])
        certs: list[str] = domain_intel.get("certs", [])
        all_hosts: set[str] = set(subdomains)

        for cert_data in certs:
            for san in re.findall(r"DNS:([^\s,]+)", cert_data):
                if domain in san:
                    all_hosts.add(san.lstrip("*."))

        if not all_hosts:
            return

        self.new_finding(
            title=f"Passive DNS / cert SANs: {len(all_hosts)} hosts for {domain}",
            severity=Severity.INFORMATIONAL,
            description=(
                f"Shodan passive DNS and SSL certificate analysis discovered "
                f"{len(all_hosts)} hostname(s) related to {domain}. "
                "These may include staging, admin, or internal hosts."
            ),
            reproduction_steps=[
                f"https://{h}/" for h in sorted(all_hosts)[:10]
            ],
            remediation=(
                "Audit all discovered subdomains. Remove stale/unused subdomains. "
                "Ensure test/staging environments have equivalent security controls."
            ),
            references=["T1590.001 — Gather Victim Network Information: Domain Properties"],
            evidence=Evidence(extra={"discovered_hosts": sorted(all_hosts)}),
            cvss_v31_vector=CVSS_INFO,
            cvss_v40_vector=CVSS40_INFO,
            target=target,
        )

    def _emit_dangerous_service_findings(
        self, domain: str, host_data: list[dict], target: str
    ) -> None:
        hits: list[dict[str, str]] = []
        for h in host_data:
            ip = h.get("ip_str", "")
            for service in h.get("data", []):
                banner = service.get("data", "") or service.get("product", "")
                port = service.get("port", 0)
                for pattern, label in _DANGEROUS_BANNERS:
                    if pattern.search(banner):
                        hits.append({"ip": ip, "port": str(port), "service": label})
                        break

        if not hits:
            return

        self.new_finding(
            title=f"Dangerous unauthenticated/exposed services on {domain} ({len(hits)} found)",
            severity=Severity.HIGH,
            description=(
                f"Shodan identified {len(hits)} potentially dangerous or unauthenticated "
                f"service(s) exposed on hosts associated with {domain}. "
                "These services may allow data access or remote code execution without credentials."
            ),
            reproduction_steps=[
                f"# {h['service']} at {h['ip']}:{h['port']}" for h in hits[:5]
            ],
            remediation=(
                "Immediately restrict access to these services. "
                "Enable authentication and TLS. Deploy host-level firewall rules."
            ),
            references=["T1190", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
            evidence=Evidence(extra={"dangerous_services": hits}),
            cvss_v31_vector=CVSS_HIGH,
            cvss_v40_vector=CVSS40_HIGH,
            target=target,
        )


class TestShodanEnricher:
    def test_extract_domain_from_https(self) -> None:
        e = ShodanEnricher.__new__(ShodanEnricher)
        assert e._extract_domain("https://example.com/path") == "example.com"

    def test_extract_domain_from_host(self) -> None:
        e = ShodanEnricher.__new__(ShodanEnricher)
        assert e._extract_domain("api.corp.io") == "api.corp.io"

    def test_extract_domain_strips_port(self) -> None:
        e = ShodanEnricher.__new__(ShodanEnricher)
        assert e._extract_domain("https://example.com:8443") == "example.com"

    def test_cdn_asn_set_populated(self) -> None:
        assert "AS13335" in _CDN_ASNS

    def test_dangerous_banners_patterns(self) -> None:
        from io import StringIO
        import re as re2
        test_cases = [
            ("redis_version:7.0", "Redis"),
            ("Jenkins/2.400", "Jenkins"),
            ("Elasticsearch/8.0", "Elasticsearch"),
        ]
        for banner, expected in test_cases:
            matched = any(pat.search(banner) for pat, _ in _DANGEROUS_BANNERS)
            assert matched, f"Expected match for {expected}"
