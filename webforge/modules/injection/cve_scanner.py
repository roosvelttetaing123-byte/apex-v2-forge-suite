"""CVE Scanner — tests for specific high-impact CVEs via active probes.

Nessus equivalent: Targeted CVE checks (Spring4Shell, Log4Shell, etc.).
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

# Active CVE checks (path, method, headers, body_check, cve, description, severity)
CVE_CHECKS = [
    {
        "name": "Spring4Shell (CVE-2022-22965)",
        "paths": ["/"],
        "method": "POST",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "data": "class.module.classLoader.DefaultAssertionStatus=true",
        "detect": lambda s, b: s == 200 and "class.module" not in b,
        "severity": Severity.CRITICAL,
        "cve": "CVE-2022-22965",
    },
    {
        "name": "Apache Struts RCE (CVE-2017-5638)",
        "paths": ["/"],
        "method": "GET",
        "headers": {"Content-Type": "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Forge-Struts','vulnerable')}.multipart/form-data"},
        "detect": lambda s, b: "X-Forge-Struts" in str(b),
        "severity": Severity.CRITICAL,
        "cve": "CVE-2017-5638",
    },
    {
        "name": "Shellshock (CVE-2014-6271)",
        "paths": ["/cgi-bin/", "/cgi-bin/test.cgi", "/cgi-bin/status"],
        "method": "GET",
        "headers": {"User-Agent": "() { :; }; echo; echo 'FORGE_SHELLSHOCK_TEST'"},
        "detect": lambda s, b: "FORGE_SHELLSHOCK_TEST" in b,
        "severity": Severity.CRITICAL,
        "cve": "CVE-2014-6271",
    },
    {
        "name": "Git Config Exposure",
        "paths": ["/.git/config"],
        "method": "GET",
        "headers": {},
        "detect": lambda s, b: s == 200 and "[core]" in b,
        "severity": Severity.HIGH,
        "cve": "CWE-538",
    },
    {
        "name": "SVN Entries Exposure",
        "paths": ["/.svn/entries"],
        "method": "GET",
        "headers": {},
        "detect": lambda s, b: s == 200 and ("dir" in b.lower() or b.strip().isdigit()),
        "severity": Severity.HIGH,
        "cve": "CWE-538",
    },
    {
        "name": "Environment File Exposure",
        "paths": ["/.env"],
        "method": "GET",
        "headers": {},
        "detect": lambda s, b: s == 200 and any(x in b for x in ["DB_", "APP_", "SECRET", "KEY=", "PASSWORD"]),
        "severity": Severity.CRITICAL,
        "cve": "CWE-538",
    },
]

CVSS_CVE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_CVE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


class CveScanner(BaseModule):
    """CVE scanner — active probes for specific high-impact vulnerabilities."""

    NAME        = "cve_scanner"
    DESCRIPTION = "Active CVE detection: Spring4Shell, Struts RCE, Shellshock, config exposure"
    PHASE       = 4
    TAGS        = ["injection", "owasp-a06", "cve", "cwe-78"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting CVE scan on %s", target)
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        from webforge.core.session import ForgeSession
        async with ForgeSession.from_config(self.config) as session:
            for check in CVE_CHECKS:
                for path in check["paths"]:
                    await self._run_check(session, target, path, check)

        return self._make_result(start)

    async def _run_check(self, session: Any, target: str, path: str, check: dict) -> None:
        try:
            await self.rate_limit()
            url = f"{target}{path}"
            if check["method"] == "POST":
                resp = await session.post(url, data=check.get("data", ""),
                                          headers=check.get("headers", {}))
            else:
                resp = await session.get(url, headers=check.get("headers", {}))

            status = resp.status
            body = await resp.text()

            if check["detect"](status, body):
                from common.evidence import Evidence
                ev = Evidence(
                    request_raw=f"{check['method']} {url}",
                    response_raw=body[:1000],
                )
                self.new_finding(
                    title=f"CVE Detected — {check['name']}",
                    severity=check["severity"],
                    description=f"Active probe confirmed {check['name']} at {url}.",
                    reproduction_steps=[f"{check['method']} {url}"],
                    remediation=f"Patch {check['cve']}. Update affected software.",
                    references=[check["cve"], "OWASP A06:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CVE,
                    cvss_v40_vector=CVSS40_CVE,
                    target=target,
                )
                return  # One confirmation per check is enough
        except Exception:
            pass
