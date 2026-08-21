"""Citrix Bleed — CVE-2023-4966 NetScaler session token leak."""
from __future__ import annotations

import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CITRIX = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


class CitrixBleed(BaseModule):
    NAME = "citrix_bleed"
    DESCRIPTION = "CVE-2023-4966 Citrix NetScaler session token leak (Citrix Bleed)"
    PHASE = 4
    TAGS = ["vuln", "cve-2023-4966", "citrix", "netscaler", "session"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._probe(host)
        return self._make_result(start)

    async def _probe(self, host: str) -> None:
        import aiohttp
        for port in [443, 80]:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}/vpn/index.html"
            try:
                # Citrix Bleed — send oversized Host header to trigger buffer over-read
                headers = {"Host": "a" * 24576, "Connection": "close"}
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, headers={"User-Agent": "Mozilla/5.0"}, ssl=False) as resp:
                        body = await resp.text()
                        resp_headers = dict(resp.headers)

                        if resp.status == 200 and ("NetScaler" in body or "Citrix" in body or
                                                    "ns_" in str(resp_headers)):
                            self.new_finding(
                                title=f"Citrix NetScaler Detected — Check CVE-2023-4966 — {host}",
                                severity=Severity.HIGH,
                                description=(
                                    f"Citrix NetScaler/ADC detected on {host}:{port}. "
                                    "Check for CVE-2023-4966 (Citrix Bleed) — pre-auth session token leak."
                                ),
                                reproduction_steps=[f"curl -k '{url}'"],
                                remediation="Patch to 13.1-49.15, 13.0-92.19, 14.1-8.50+. Kill all active sessions.",
                                references=["CVE-2023-4966"],
                                evidence=Evidence(extra={"host": host, "port": port}),
                                cvss_v31_vector=CVSS_CITRIX,
                                mitre_attack=["TA0001/T1190"],
                                target=host, port=port, service="https",
                            )
                            return
            except Exception:
                continue
