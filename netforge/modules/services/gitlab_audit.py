"""GitLab Audit — public repos, registration, API exposure, known CVEs."""
from __future__ import annotations

import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_OPEN_REG = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"


class GitlabAudit(BaseModule):
    NAME = "gitlab_audit"
    DESCRIPTION = "GitLab: open registration, public repos, API exposure, version CVEs"
    PHASE = 4
    TAGS = ["services", "gitlab", "git", "cwe-306"]

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
        for port in [443, 80, 8080, 8443]:
            scheme = "https" if port in (443, 8443) else "http"
            base = f"{scheme}://{host}:{port}"
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(f"{base}/api/v4/version", ssl=False) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            version = data.get("version", "unknown")
                            self.new_finding(
                                title=f"GitLab API Unauthenticated — Version {version} — {host}",
                                severity=Severity.MEDIUM,
                                description=f"GitLab {version} on {host}:{port} exposes version via unauthenticated API.",
                                reproduction_steps=[f"curl {base}/api/v4/version"],
                                remediation="Restrict API access. Require authentication for version endpoint.",
                                references=["CWE-200"],
                                evidence=Evidence(extra={"host": host, "port": port, "version": version}),
                                target=host, port=port, service="http",
                            )

                    # Check open registration
                    async with session.get(f"{base}/users/sign_up", ssl=False) as reg_resp:
                        reg_body = await reg_resp.text()
                        if reg_resp.status == 200 and ("sign_up" in reg_body or "Register" in reg_body):
                            self.new_finding(
                                title=f"GitLab Open Registration — {host}:{port}",
                                severity=Severity.HIGH,
                                description="GitLab allows open user registration. Anyone can create an account.",
                                reproduction_steps=[f"curl {base}/users/sign_up"],
                                remediation="Disable open registration in Admin > Settings > Sign-up restrictions.",
                                references=["CWE-306"],
                                evidence=Evidence(extra={"host": host, "port": port}),
                                cvss_v31_vector=CVSS_OPEN_REG,
                                target=host, port=port, service="http",
                            )

                    # Public projects
                    async with session.get(f"{base}/api/v4/projects?visibility=public&per_page=5",
                                          ssl=False) as proj_resp:
                        if proj_resp.status == 200:
                            projects = await proj_resp.json()
                            if isinstance(projects, list) and projects:
                                proj_names = [p.get("name", "?") for p in projects[:5]]
                                self.new_finding(
                                    title=f"GitLab Public Repos ({len(projects)}+) — {host}",
                                    severity=Severity.LOW,
                                    description=f"Public repos on {host}: {', '.join(proj_names)}.",
                                    reproduction_steps=[f"curl '{base}/api/v4/projects?visibility=public'"],
                                    remediation="Review public repos for sensitive content.",
                                    references=["CWE-200"],
                                    evidence=Evidence(extra={"host": host, "repos": proj_names}),
                                    target=host, port=port, service="http",
                                )
                    return
            except Exception:
                continue
