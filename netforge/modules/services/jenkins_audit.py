"""Jenkins Audit — anonymous access, script console, credential exposure."""
from __future__ import annotations

import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_ANON_ACCESS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_SCRIPT      = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


class JenkinsAudit(BaseModule):
    NAME = "jenkins_audit"
    DESCRIPTION = "Jenkins: anonymous access, script console, credential exposure, outdated version"
    PHASE = 4
    TAGS = ["services", "jenkins", "ci", "cwe-306"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._audit(host)
        return self._make_result(start)

    async def _audit(self, host: str) -> None:
        import aiohttp
        for port in [8080, 8443, 443, 80, 9090]:
            scheme = "https" if port in (443, 8443) else "http"
            base = f"{scheme}://{host}:{port}"
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    # Check main page
                    async with session.get(base, ssl=False) as resp:
                        body = await resp.text()
                        headers = dict(resp.headers)
                        jenkins_ver = headers.get("X-Jenkins", "")

                        if not jenkins_ver and "jenkins" not in body.lower():
                            continue

                    # Anonymous access to API
                    async with session.get(f"{base}/api/json", ssl=False) as api_resp:
                        if api_resp.status == 200:
                            api_body = await api_resp.text()
                            self.new_finding(
                                title=f"Jenkins Anonymous Access — {host}:{port}",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"Jenkins {jenkins_ver} on {host}:{port} allows anonymous API access. "
                                    "Full job listing, build history, and potentially script console exposed."
                                ),
                                reproduction_steps=[f"curl {base}/api/json"],
                                remediation="Enable authentication. Disable anonymous read. Configure Matrix Authorization.",
                                references=["CWE-306"],
                                evidence=Evidence(extra={
                                    "host": host, "port": port, "version": jenkins_ver,
                                    "api_snippet": api_body[:300],
                                }),
                                cvss_v31_vector=CVSS_ANON_ACCESS,
                                mitre_attack=["TA0001/T1190"],
                                target=host, port=port, service="http", confidence="HIGH",
                            )

                    # Script console check
                    async with session.get(f"{base}/script", ssl=False) as script_resp:
                        if script_resp.status == 200:
                            script_body = await script_resp.text()
                            if "Groovy script" in script_body or "script" in script_body.lower():
                                self.new_finding(
                                    title=f"Jenkins Script Console Exposed — {host}:{port}",
                                    severity=Severity.CRITICAL,
                                    description="Jenkins Groovy script console accessible — arbitrary code execution on server.",
                                    reproduction_steps=[f"curl {base}/script"],
                                    remediation="Restrict script console access to admins only.",
                                    references=["CWE-94"],
                                    evidence=Evidence(extra={"host": host, "port": port}),
                                    cvss_v31_vector=CVSS_SCRIPT,
                                    mitre_attack=["TA0002/T1059"],
                                    target=host, port=port, service="http", confidence="HIGH",
                                )

                    # Credential page check
                    async with session.get(f"{base}/credentials/", ssl=False) as cred_resp:
                        if cred_resp.status == 200:
                            cred_body = await cred_resp.text()
                            if "credential" in cred_body.lower() and "global" in cred_body.lower():
                                self.new_finding(
                                    title=f"Jenkins Credentials Page Accessible — {host}:{port}",
                                    severity=Severity.HIGH,
                                    description="Jenkins credential store accessible without proper auth.",
                                    reproduction_steps=[f"curl {base}/credentials/"],
                                    remediation="Restrict credential access to authorized users.",
                                    references=["CWE-522"],
                                    evidence=Evidence(extra={"host": host, "port": port}),
                                    mitre_attack=["TA0006/T1552"],
                                    target=host, port=port, service="http",
                                )
                    return  # Found Jenkins, done with this host
            except Exception:
                continue
