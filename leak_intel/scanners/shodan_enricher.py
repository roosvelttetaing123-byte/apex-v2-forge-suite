"""Shodan Enricher — origin IPs, open ports, service banners, SSL certs per domain.

Queries the Shodan API to enrich targets with:
  - Real origin IPs behind CDN/WAF
  - Open ports and service banners
  - SSL certificate details
  - Technology detection
  - Known vulnerabilities (CVEs)

API key: SHODAN_API_KEY env var.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.leak_intel.shodan_enricher")


class ShodanEnricher(BaseModule):
    """Enrich target domains with Shodan intelligence."""

    NAME        = "shodan_enricher"
    DESCRIPTION = "Shodan API — origin IPs, open ports, service banners, SSL certs, CVEs"
    PHASE       = 0
    TAGS        = ["osint", "leak_intel", "shodan", "recon", "enrichment"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._api_key = ""

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        if not self._api_key:
            return self._make_result(start, skipped=True, skip_reason="SHODAN_API_KEY not set")

        domain = self._extract_domain()
        if not domain:
            return self._make_result(start, skipped=True, skip_reason="No domain derivable from target")

        self.log.info("Querying Shodan for: %s", domain)

        try:
            import aiohttp
        except ImportError:
            return self._make_result(start, skipped=True, skip_reason="aiohttp not installed")

        async with aiohttp.ClientSession() as session:
            # DNS resolve to get IPs
            await self.rate_limit()
            ips = await self._resolve_domain(session, domain)

            if not ips:
                self.log.info("No IPs resolved for %s via Shodan DNS", domain)
                return self._make_result(start)

            # Query each IP for host details
            for ip in ips[:5]:
                await self.rate_limit()
                await self._query_host(session, ip, domain)

            # Search for the domain across Shodan
            await self.rate_limit()
            await self._search_domain(session, domain)

        return self._make_result(start)

    async def _resolve_domain(self, session: Any, domain: str) -> list[str]:
        """Resolve domain to IPs via Shodan DNS."""
        url = f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={self._api_key}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                ip = data.get(domain)
                return [ip] if ip else []
        except Exception as exc:
            self.log.debug("Shodan DNS resolve error (%s)", type(exc).__name__)
            return []

    async def _query_host(self, session: Any, ip: str, domain: str) -> None:
        """Query Shodan for detailed host information."""
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self._api_key}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return
                host = await resp.json()
        except Exception as exc:
            self.log.debug(
                "Shodan host query error for %s (%s)",
                ip,
                type(exc).__name__,
            )
            return

        # Extract open ports and services
        ports = host.get("ports", [])
        org = host.get("org", "Unknown")
        os_info = host.get("os", "Unknown")
        vulns = host.get("vulns", [])

        if ports:
            services_detail = []
            for item in host.get("data", [])[:20]:
                port = item.get("port")
                product = item.get("product", "")
                version = item.get("version", "")
                transport = item.get("transport", "tcp")
                banner_snippet = (item.get("data", "")[:200]).replace("\n", " ")
                services_detail.append({
                    "port": port, "product": product, "version": version,
                    "transport": transport, "banner": banner_snippet,
                })

            self.new_finding(
                title=f"Shodan Origin IP Intelligence: {ip} ({domain})",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Shodan reveals {len(ports)} open ports on {ip} (org: {org}, OS: {os_info}).\n"
                    f"Open ports: {ports[:20]}\n"
                    f"Services: {', '.join(s.get('product', '?') + ':' + str(s.get('port', '')) for s in services_detail[:10])}"
                ),
                reproduction_steps=[
                    f"1. Query Shodan: https://www.shodan.io/host/{ip}",
                    "2. Review open ports and service banners",
                ],
                remediation=(
                    "Review all exposed services. Close unnecessary ports.\n"
                    "Ensure CDN/WAF is properly configured to hide origin IP."
                ),
                references=["https://www.shodan.io/", "https://developer.shodan.io/api"],
                evidence=Evidence(extra={
                    "ip": ip, "domain": domain, "ports": ports, "org": org,
                    "os": os_info, "services": services_detail[:10],
                }),
                target=ip,
                tags=["osint", "shodan", "recon", "ports"],
                mitre_attack=["T1595.001", "T1046"],
            )

        # Report known CVEs
        if vulns:
            self.new_finding(
                title=f"Shodan CVE Detection: {len(vulns)} known vulnerabilities on {ip}",
                severity=Severity.HIGH,
                description=(
                    f"Shodan reports {len(vulns)} known CVEs for {ip}:\n"
                    f"{', '.join(vulns[:20])}"
                ),
                reproduction_steps=[
                    f"1. Query Shodan for {ip}",
                    "2. Review reported CVEs",
                    "3. Verify exploitability against running services",
                ],
                remediation="Patch affected services to address known CVEs.",
                references=[f"https://nvd.nist.gov/vuln/detail/{v}" for v in vulns[:5]],
                evidence=Evidence(extra={"ip": ip, "cves": vulns}),
                target=ip,
                tags=["osint", "shodan", "cve", "vuln"],
                mitre_attack=["T1595.002"],
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            )

    async def _search_domain(self, session: Any, domain: str) -> None:
        """Search Shodan for all hosts mentioning the domain."""
        url = f"https://api.shodan.io/shodan/host/search?key={self._api_key}&query=hostname:{domain}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()

            total = data.get("total", 0)
            matches = data.get("matches", [])

            # Look for origin IPs different from the main IP (CDN bypass)
            seen_ips: set[str] = set()
            for match in matches[:20]:
                ip = match.get("ip_str", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)

            if len(seen_ips) > 1:
                self.new_finding(
                    title=f"Shodan Multiple Origin IPs: {len(seen_ips)} IPs for {domain}",
                    severity=Severity.LOW,
                    description=(
                        f"Shodan shows {domain} resolves to {len(seen_ips)} distinct IPs: "
                        f"{', '.join(sorted(seen_ips)[:10])}\n"
                        "Some may be CDN-bypassed origin servers."
                    ),
                    reproduction_steps=[f"1. Shodan search: hostname:{domain}"],
                    remediation="Ensure origin IPs are not directly accessible, restrict via firewall.",
                    references=["https://www.shodan.io/"],
                    evidence=Evidence(extra={"domain": domain, "ips": sorted(seen_ips), "total_results": total}),
                    tags=["osint", "shodan", "origin_ip", "cdn_bypass"],
                    mitre_attack=["T1590.004"],
                )

        except Exception as exc:
            self.log.debug("Shodan domain search error (%s)", type(exc).__name__)

    def _extract_domain(self) -> str:
        target = self.config.target.replace("https://", "").replace("http://", "")
        target = target.split("/")[0].split(":")[0]
        parts = target.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return target


import aiohttp  # noqa: E402
