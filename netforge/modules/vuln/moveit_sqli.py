"""MOVEit SQLi — CVE-2023-34362 MOVEit Transfer auth bypass + RCE."""
from __future__ import annotations

import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_MOVEIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class MoveitSqli(BaseModule):
    NAME = "moveit_sqli"
    DESCRIPTION = "CVE-2023-34362 MOVEit Transfer SQL injection — auth bypass detection"
    PHASE = 4
    TAGS = ["vuln", "cve-2023-34362", "moveit", "sqli", "rce"]

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
        probe_paths = [
            "/moveitisapi/moveitisapi.dll?action=m2",
            "/human.aspx",
            "/guestaccess.aspx",
        ]
        for port in [443, 80]:
            scheme = "https" if port == 443 else "http"
            for path in probe_paths:
                try:
                    url = f"{scheme}://{host}:{port}{path}"
                    timeout = aiohttp.ClientTimeout(total=10)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get(url, ssl=False) as resp:
                            body = await resp.text()
                            if resp.status == 200 and ("MOVEit" in body or "moveit" in body.lower()):
                                self.new_finding(
                                    title=f"MOVEit Transfer Detected — {host}:{port}",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"MOVEit Transfer found on {host}:{port}. Check for CVE-2023-34362 "
                                        "(pre-auth SQL injection → RCE). Clop ransomware actively exploits this."
                                    ),
                                    reproduction_steps=[f"curl -k '{url}'"],
                                    remediation="Patch to MOVEit 2023.0.2+. Check for IOCs.",
                                    references=["CVE-2023-34362"],
                                    evidence=Evidence(extra={"host": host, "port": port}),
                                    cvss_v31_vector=CVSS_MOVEIT,
                                    mitre_attack=["TA0001/T1190"],
                                    target=host, port=port, service="https",
                                )
                                return
                except Exception:
                    continue
