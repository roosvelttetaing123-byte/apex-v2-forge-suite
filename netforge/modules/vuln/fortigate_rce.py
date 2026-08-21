"""FortiGate RCE — CVE-2024-21762 FortiOS SSL VPN out-of-bounds write."""
from __future__ import annotations

import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_FORTI = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class FortigateRce(BaseModule):
    NAME = "fortigate_rce"
    DESCRIPTION = "CVE-2024-21762 FortiOS SSL VPN out-of-bounds write — pre-auth RCE"
    PHASE = 4
    TAGS = ["vuln", "cve-2024-21762", "fortinet", "fortigate", "vpn", "rce"]

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
        for port in [443, 10443, 8443]:
            url = f"https://{host}:{port}/remote/logincheck"
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(f"https://{host}:{port}/remote/login",
                                          ssl=False) as resp:
                        body = await resp.text()
                        headers = dict(resp.headers)

                        if ("FortiGate" in body or "fortinet" in body.lower() or
                            "SVPNCOOKIE" in str(headers) or "fgt_lang" in body):
                            self.new_finding(
                                title=f"FortiGate SSL VPN Detected — Check CVE-2024-21762 — {host}",
                                severity=Severity.HIGH,
                                description=(
                                    f"FortiGate SSL VPN on {host}:{port}. Check for CVE-2024-21762 "
                                    "(pre-auth out-of-bounds write RCE). CISA KEV listed."
                                ),
                                reproduction_steps=[f"curl -k 'https://{host}:{port}/remote/login'"],
                                remediation=(
                                    "Upgrade FortiOS to 7.4.3+, 7.2.7+, 7.0.14+, 6.4.15+. "
                                    "Disable SSL VPN if not needed."
                                ),
                                references=["CVE-2024-21762", "CVE-2024-23113"],
                                evidence=Evidence(extra={"host": host, "port": port}),
                                cvss_v31_vector=CVSS_FORTI,
                                mitre_attack=["TA0001/T1190"],
                                target=host, port=port, service="https",
                            )
                            return
            except Exception:
                continue
