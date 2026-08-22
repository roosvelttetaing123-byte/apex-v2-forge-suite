"""Version Vulnerability Scanner — matches detected versions against known CVEs.

Nessus equivalent: Core version-based vulnerability detection.
"""
from __future__ import annotations

import re
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

# Known vulnerable version ranges (product, version_regex, vuln, severity, cve)
KNOWN_VULNS = [
    ("Apache", r"Apache/2\.4\.(?:[0-9]|[1-4][0-9])\b", "Apache < 2.4.50 — Path Traversal", Severity.CRITICAL, "CVE-2021-41773"),
    ("Apache", r"Apache/2\.2\.\d+", "Apache 2.2.x — End of Life", Severity.MEDIUM, ""),
    ("nginx", r"nginx/1\.(?:[0-9]|1[0-9])\.\d+", "nginx < 1.20 — Multiple CVEs", Severity.MEDIUM, "CVE-2021-23017"),
    ("IIS", r"Microsoft-IIS/(?:[5-7]\.[05])", "IIS < 8.0 — Legacy Version", Severity.MEDIUM, ""),
    ("PHP", r"PHP/(?:[5-6]\.|7\.[0-3])", "PHP < 7.4 — End of Life", Severity.MEDIUM, ""),
    ("PHP", r"PHP/7\.4\.\d+", "PHP 7.4 — End of Life (Nov 2022)", Severity.LOW, ""),
    ("jQuery", r"jquery[/\-]([12]\.[0-9]+)", "jQuery < 3.0 — XSS vulnerabilities", Severity.MEDIUM, "CVE-2020-11022"),
    ("WordPress", r"WordPress\s+([0-5]\.[0-9])", "WordPress < 6.0 — Multiple CVEs", Severity.MEDIUM, ""),
    ("ASP.NET", r"X-AspNet-Version:\s*([234]\.\d+)", "ASP.NET Version Detected", Severity.LOW, ""),
    ("OpenSSL", r"OpenSSL/(?:0\.|1\.0)", "OpenSSL < 1.1 — Multiple CVEs", Severity.HIGH, "CVE-2016-2183"),
]

CVSS_VER = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_VER = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"


class VersionVulnCheck(BaseModule):
    """Version vulnerability scanner — matches detected software versions against known CVEs."""

    NAME        = "version_vuln_check"
    DESCRIPTION = "CVE-based version vulnerability detection for web servers, frameworks, libraries"
    PHASE       = 2
    TAGS        = ["recon", "owasp-a06", "version-check", "cwe-1104"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting version vulnerability check on %s", target)
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        from webforge.core.session import ForgeSession
        async with ForgeSession.from_config(self.config) as session:
            await self.rate_limit()
            resp = await session.get(target)
            headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            body = await resp.text()
            combined = headers_str + "\n" + body[:10000]

            # Also check tech_detect results
            detected_tech = self.config.extra.get("detected_tech", {})

            for product, pattern, vuln_name, severity, cve in KNOWN_VULNS:
                if re.search(pattern, combined, re.IGNORECASE):
                    refs = ["CWE-1104", "OWASP A06:2021"]
                    if cve:
                        refs.append(cve)
                    from common.evidence import Evidence
                    match = re.search(pattern, combined, re.IGNORECASE)
                    ev = Evidence(
                        request_raw=f"GET {target}",
                        response_raw=match.group() if match else "",
                    )
                    self.new_finding(
                        title=f"Vulnerable Version — {vuln_name}",
                        severity=severity,
                        description=f"Detected {product} version matching known vulnerability: {vuln_name}.",
                        reproduction_steps=[f"GET {target}", f"Check Server/X-Powered-By headers"],
                        remediation=f"Update {product} to the latest stable version.",
                        references=refs,
                        evidence=ev,
                        cvss_v31_vector=CVSS_VER,
                        cvss_v40_vector=CVSS40_VER,
                        target=target,
                    )

        return self._make_result(start)
