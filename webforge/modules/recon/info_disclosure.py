"""Information Disclosure Scanner — verbose errors, stack traces, debug endpoints.

Nessus equivalent: 10759, 10107, 26194 (Web server info disclosure).
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

# Error patterns that leak internal info
ERROR_PATTERNS = [
    (r"(?:Fatal error|Warning).*?(?:on line|in file)\s+[/\\][\w/\\.]+:\d+", "PHP Error with Path", Severity.MEDIUM),
    (r"at\s+[\w.]+\.[\w]+\([\w]+\.(?:java|cs|py):\d+\)", "Stack Trace Leak", Severity.MEDIUM),
    (r"Traceback \(most recent call last\)", "Python Traceback", Severity.MEDIUM),
    (r"Microsoft OLE DB Provider for .+error", "ASP.NET DB Error", Severity.HIGH),
    (r"(?:ASP\.NET|System\.Web).*?Exception", ".NET Exception Leak", Severity.MEDIUM),
    (r"(?:mysql_|pg_|ora_)(?:query|connect|fetch)", "DB Function Leak", Severity.MEDIUM),
    (r"\\x[0-9a-f]{2}.*?at\s", "Memory Leak in Error", Severity.HIGH),
    (r"Directory listing for /", "Directory Listing Enabled", Severity.MEDIUM),
    (r"Index of /", "Apache Directory Listing", Severity.MEDIUM),
    (r"phpinfo\(\)", "phpinfo() Exposed", Severity.HIGH),
]

# Debug/admin endpoints Nessus checks
DEBUG_PATHS = [
    "/__debug__", "/_debugbar", "/debug", "/debug/default/view",
    "/elmah.axd", "/trace.axd", "/server-status", "/server-info",
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/wp-config.php.bak", "/config.php.bak", "/web.config.bak",
    "/phpinfo.php", "/info.php", "/test.php",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/beans",
    "/api/swagger.json", "/swagger-ui.html", "/api-docs",
    "/graphql", "/graphiql",
    "/.git/HEAD", "/.svn/entries", "/.hg/dirstate",
    "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/robots.txt", "/sitemap.xml",
    "/error", "/errors", "/404",
    "/admin", "/administrator", "/manage",
]

CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"


class InfoDisclosure(BaseModule):
    """Information Disclosure scanner — finds leaked debug info, errors, paths."""

    NAME        = "info_disclosure"
    DESCRIPTION = "Information disclosure: stack traces, debug endpoints, version leaks"
    PHASE       = 2
    TAGS        = ["recon", "owasp-a01", "info-disclosure", "cwe-200"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting information disclosure scan on %s", target)
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        from webforge.core.session import ForgeSession
        async with ForgeSession.from_config(self.config) as session:
            # 1. Check main page + crawled URLs for error patterns
            urls = self.config.extra.get("crawled_urls", [target])[:20]
            for url in urls:
                await self._check_error_patterns(session, url)

            # 2. Probe debug/admin endpoints
            sem = asyncio.Semaphore(5)
            tasks = [self._check_debug_path(session, target, path, sem)
                     for path in DEBUG_PATHS]
            await asyncio.gather(*tasks, return_exceptions=True)

            # 3. Check HTTP headers for version leaks
            await self._check_header_leaks(session, target)

        return self._make_result(start)

    async def _check_error_patterns(self, session: Any, url: str) -> None:
        """Check response body for information-leaking error patterns."""
        try:
            await self.rate_limit()
            resp = await session.get(url)
            body = await resp.text()
            for pattern, name, severity in ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    from common.evidence import Evidence
                    match = re.search(pattern, body, re.IGNORECASE)
                    ev = Evidence(
                        request_raw=f"GET {url}",
                        response_raw=body[max(0,match.start()-100):match.end()+100],
                    )
                    self.new_finding(
                        title=f"Information Disclosure — {name}",
                        severity=severity,
                        description=f"{name} detected at {url}. The response contains error information that reveals internal implementation details.",
                        reproduction_steps=[f"GET {url}", f"Pattern: {pattern}"],
                        remediation="Disable verbose error messages in production. Use custom error pages.",
                        references=["CWE-200", "CWE-209", "OWASP A01:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_INFO,
                        cvss_v40_vector=CVSS40_INFO,
                        target=self.config.target,
                    )
                    break  # One finding per URL
        except Exception:
            pass

    async def _check_debug_path(self, session: Any, target: str, path: str, sem: asyncio.Semaphore) -> None:
        """Check if a debug/admin path is accessible."""
        async with sem:
            try:
                await self.rate_limit()
                url = f"{target}{path}"
                resp = await session.get(url, allow_redirects=False)
                status = resp.status
                body = await resp.text()

                # Only report if we get a real page (not 404/redirect)
                if status == 200 and len(body) > 100:
                    # Verify it's not a custom 404 / SPA catch-all
                    if not any(x in body.lower() for x in ["page not found", "404", "not exist"]):
                        severity = Severity.HIGH if any(x in path for x in [".env", "phpinfo", "actuator", "WEB-INF", ".git"]) else Severity.MEDIUM
                        from common.evidence import Evidence
                        ev = Evidence(
                            request_raw=f"GET {url}",
                            response_raw=body[:1000],
                        )
                        self.new_finding(
                            title=f"Sensitive Endpoint Exposed — {path}",
                            severity=severity,
                            description=f"The endpoint {url} returned HTTP {status} with {len(body)} bytes. This may expose sensitive configuration, debug info, or admin interfaces.",
                            reproduction_steps=[f"GET {url}"],
                            remediation="Restrict access to debug/admin endpoints. Remove from production.",
                            references=["CWE-200", "CWE-538", "OWASP A01:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_INFO,
                            cvss_v40_vector=CVSS40_INFO,
                            target=self.config.target,
                        )
            except Exception:
                pass

    async def _check_header_leaks(self, session: Any, target: str) -> None:
        """Check response headers for version/technology leaks."""
        try:
            await self.rate_limit()
            resp = await session.get(target)
            headers = dict(resp.headers)
            leaky_headers = {
                "X-Powered-By": "Technology Stack",
                "Server": "Web Server Version",
                "X-AspNet-Version": "ASP.NET Version",
                "X-AspNetMvc-Version": "ASP.NET MVC Version",
                "X-Generator": "CMS Generator",
                "X-Drupal-Cache": "Drupal CMS",
                "X-Debug-Token": "Debug Token",
                "X-Runtime": "Runtime Information",
            }
            for header, desc in leaky_headers.items():
                val = headers.get(header)
                if val:
                    from common.evidence import Evidence
                    ev = Evidence(
                        request_raw=f"GET {target}",
                        response_raw=f"{header}: {val}",
                    )
                    self.new_finding(
                        title=f"Version Disclosure via {header} Header",
                        severity=Severity.LOW,
                        description=f"The {header} header reveals: {val}. This helps attackers fingerprint the technology stack.",
                        reproduction_steps=[f"GET {target}", f"Check {header} header"],
                        remediation=f"Remove or suppress the {header} header in production.",
                        references=["CWE-200", "OWASP A01:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_INFO,
                        cvss_v40_vector=CVSS40_INFO,
                        target=target,
                    )
        except Exception:
            pass
