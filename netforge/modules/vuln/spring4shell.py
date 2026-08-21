"""Spring4Shell Detector — CVE-2022-22965 Spring Framework RCE."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_SPRING4SHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Spring4Shell probe — classLoader manipulation indicator
SPRING4SHELL_PARAMS = {
    "class.module.classLoader.URLs[0]": "https://probe.test",
    "class.module.classLoader.DefaultAssertionStatus": "true",
}


class Spring4Shell(BaseModule):
    NAME        = "spring4shell"
    DESCRIPTION = "CVE-2022-22965 Spring Framework RCE — classLoader manipulation probe"
    PHASE       = 4
    TAGS        = ["vuln", "cve-2022-22965", "spring", "rce", "java"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        web_ports = self.config.extra.get("web_ports", [80, 443, 8080, 8443])

        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            for port in web_ports:
                await self.rate_limit()
                await self._probe_spring4shell(host, port)

        return self._make_result(start)

    async def _probe_spring4shell(self, host: str, port: int) -> None:
        import aiohttp

        scheme = "https" if port in (443, 8443) else "http"
        urls = [f"{scheme}://{host}:{port}/", f"{scheme}://{host}:{port}/login",
                f"{scheme}://{host}:{port}/api"]

        for url in urls:
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    # Send classLoader probe as POST params
                    async with session.post(url, data=SPRING4SHELL_PARAMS, ssl=False) as resp:
                        status = resp.status
                        body = await resp.text()

                        # 400 with specific Spring error = potentially vulnerable
                        # 200 after classLoader manipulation = definitely vulnerable
                        if status == 200 and "classLoader" not in body:
                            # Verify with a second request
                            async with session.get(
                                f"{url}?class.module.classLoader.DefaultAssertionStatus",
                                ssl=False
                            ) as verify:
                                if verify.status != 400:
                                    self.new_finding(
                                        title=f"Spring4Shell (CVE-2022-22965) — {host}:{port}",
                                        severity=Severity.CRITICAL,
                                        description=(
                                            f"Spring Framework classLoader manipulation succeeded on {host}:{port}. "
                                            "Indicates CVE-2022-22965 Spring4Shell RCE."
                                        ),
                                        reproduction_steps=[
                                            f"curl -X POST {url} -d 'class.module.classLoader.DefaultAssertionStatus=true'",
                                        ],
                                        remediation="Upgrade Spring Framework to 5.3.18+ or 5.2.20+.",
                                        references=["CVE-2022-22965"],
                                        evidence=Evidence(extra={
                                            "host": host, "port": port, "url": url,
                                            "status": status,
                                        }),
                                        cvss_v31_vector=CVSS_SPRING4SHELL,
                                        mitre_attack=["TA0001/T1190"],
                                        target=host, port=port, service="http",
                                        confidence="MEDIUM",
                                    )
                                    return
            except Exception:
                continue
