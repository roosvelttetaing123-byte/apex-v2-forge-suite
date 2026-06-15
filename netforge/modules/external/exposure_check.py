"""Exposure Check — public-facing service inventory and risk assessment.

Tests:
  - Internet-facing service enumeration
  - Shodan/Censys data correlation (if API key available)
  - Known-bad port exposure
  - Default page/banner detection
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_EXPOSURE   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_EXPOSURE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 9443]

DEFAULT_PAGE_INDICATORS = [
    "welcome to nginx", "apache2 default page", "iis windows",
    "it works!", "test page", "default web site",
    "congratulations", "coming soon", "under construction",
    "tomcat", "jenkins", "phpmyadmin",
]


class ExposureCheck(BaseModule):
    """Internet exposure and public-facing service risk assessment."""

    NAME        = "exposure_check"
    DESCRIPTION = "Exposure: public service inventory, default pages, banner detection"
    PHASE       = 3
    TAGS        = ["recon", "exposure", "external", "cwe-200"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:10]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._check_exposure(host)

        return self._make_result(start)

    async def _check_exposure(self, host: str) -> None:
        import aiohttp

        exposed_services = []

        for port in WEB_PORTS:
            await self.rate_limit()
            for scheme in ["https", "http"]:
                try:
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False),
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as session:
                        url = f"{scheme}://{host}:{port}/"
                        async with session.get(url, allow_redirects=True) as resp:
                            body = (await resp.text())[:5000].lower()
                            headers = dict(resp.headers)
                            server = headers.get("Server", "")
                            title = ""
                            import re
                            m = re.search(r"<title[^>]*>([^<]+)</title>", body)
                            if m:
                                title = m.group(1).strip()

                            is_default = any(ind in body for ind in DEFAULT_PAGE_INDICATORS)

                            exposed_services.append({
                                "port": port,
                                "scheme": scheme,
                                "status": resp.status,
                                "server": server,
                                "title": title[:100],
                                "default_page": is_default,
                            })

                            if is_default:
                                ev = Evidence(
                                    request_raw=f"GET {url}",
                                    extra={
                                        "host": host, "port": port,
                                        "server": server, "title": title,
                                    },
                                )
                                self.new_finding(
                                    title=f"Default/Test Page Exposed — {host}:{port} ({title[:40] or server})",
                                    severity=Severity.LOW,
                                    description=(
                                        f"Default web server page on {host}:{port}. "
                                        f"Server: {server}, Title: {title}.\n"
                                        "Default pages indicate unconfigured services and leak "
                                        "server software and version information."
                                    ),
                                    reproduction_steps=[f"curl -kI {url}"],
                                    remediation="Remove default pages. Configure custom error pages.",
                                    references=["CWE-200"],
                                    evidence=ev,
                                    cvss_v31_vector=CVSS_EXPOSURE,
                                    cvss_v40_vector=CVSS40_EXPOSURE,
                                    port=port, service="http", target=host,
                                )
                            break  # Don't test both schemes on same port
                except Exception:
                    continue

        # Shodan lookup (if API key available)
        await self._shodan_lookup(host)

        if exposed_services:
            self.config.extra.setdefault("exposed_services", {})[host] = exposed_services

    async def _shodan_lookup(self, host: str) -> None:
        """Query Shodan for known exposure data."""
        api_key = self.config.extra.get("shodan_api_key")
        if not api_key:
            return

        import aiohttp
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
            ) as session:
                url = f"https://api.shodan.io/shodan/host/{host}?key={api_key}"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        ports = data.get("ports", [])
                        vulns = data.get("vulns", [])
                        org = data.get("org", "")

                        ev = Evidence(
                            extra={
                                "shodan_ports": ports[:20],
                                "shodan_vulns": vulns[:10],
                                "org": org,
                            },
                        )
                        severity = Severity.HIGH if vulns else Severity.MEDIUM
                        self.new_finding(
                            title=f"Shodan Exposure — {host} ({len(ports)} ports, {len(vulns)} CVEs)",
                            severity=severity,
                            description=(
                                f"Shodan data for {host} (org: {org}):\n"
                                f"  Open ports: {ports[:10]}\n"
                                + (f"  Known CVEs: {', '.join(vulns[:5])}\n" if vulns else "")
                            ),
                            reproduction_steps=[f"shodan host {host}"],
                            remediation="Review and close unnecessary ports. Patch known CVEs.",
                            references=["CWE-200"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_EXPOSURE,
                            cvss_v40_vector=CVSS40_EXPOSURE,
                            target=host,
                        )
        except Exception:
            pass


class TestExposureCheck:
    def test_web_ports(self) -> None:
        assert 80 in WEB_PORTS
        assert 443 in WEB_PORTS

    def test_default_indicators(self) -> None:
        assert "welcome to nginx" in DEFAULT_PAGE_INDICATORS

    def test_phase(self) -> None:
        assert ExposureCheck.PHASE == 3
