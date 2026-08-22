"""ProxyShell Detector — CVE-2021-34473/34523/31207 Exchange RCE chain."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_PROXYSHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

PROXYSHELL_PATHS = [
    "/autodiscover/autodiscover.json?@zdi/PowerShell",
    "/autodiscover/autodiscover.json?a]@foo.com/ews/exchange.asmx",
    "/autodiscover/autodiscover.json?a]@foo.com/mapi/nspi/",
]


class ProxyShell(BaseModule):
    NAME        = "proxyshell"
    DESCRIPTION = "CVE-2021-34473 Exchange ProxyShell — SSRF + privesc + RCE chain detection"
    PHASE       = 4
    TAGS        = ["vuln", "cve-2021-34473", "exchange", "proxyshell", "rce"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._probe_proxyshell(host)

        return self._make_result(start)

    async def _probe_proxyshell(self, host: str) -> None:
        import aiohttp

        for port in [443, 80]:
            scheme = "https" if port == 443 else "http"
            for path in PROXYSHELL_PATHS:
                url = f"{scheme}://{host}:{port}{path}"
                try:
                    timeout = aiohttp.ClientTimeout(total=10)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get(url, ssl=False, allow_redirects=False) as resp:
                            body = await resp.text()
                            body_lower = body.lower()

                            # Tight detection: require Exchange-specific markers
                            # "xmlns" alone fires on any XML/SOAP page = massive FP risk
                            exchange_markers = [
                                "powershell",
                                "exchange",
                                "autodiscover",
                                "microsoft.exchange",
                                "owa",
                                "x-owa-version",
                            ]
                            has_exchange = any(m in body_lower for m in exchange_markers)
                            has_exchange_header = any(
                                h.lower() in ("x-owa-version", "x-feserver", "x-calculatedbetarget")
                                for h in resp.headers
                            )

                            if resp.status == 200 and (has_exchange or has_exchange_header):
                                self.new_finding(
                                    title=f"ProxyShell (CVE-2021-34473) — Exchange {host}",
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"Exchange server {host} responds to ProxyShell SSRF probe. "
                                        "CVE-2021-34473 + CVE-2021-34523 + CVE-2021-31207 = pre-auth RCE chain."
                                    ),
                                    reproduction_steps=[f"curl -k '{url}'"],
                                    remediation="Apply Exchange cumulative updates. KB5001779 or later.",
                                    references=["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
                                    evidence=Evidence(extra={
                                        "host": host, "port": port, "path": path,
                                        "status": resp.status, "snippet": body[:300],
                                    }),
                                    cvss_v31_vector=CVSS_PROXYSHELL,
                                    mitre_attack=["TA0001/T1190"],
                                    target=host, port=port, service="https",
                                    confidence="HIGH" if has_exchange_header else "MEDIUM",
                                )
                                return
                except Exception:
                    continue
