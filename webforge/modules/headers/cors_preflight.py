"""CORS Preflight Scanner — detailed CORS misconfiguration detection.

Nessus equivalent: 98069 (CORS misconfiguration).
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    None,  # null origin
]

CVSS_CORS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"
CVSS40_CORS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"


class CorsPreflight(BaseModule):
    """CORS preflight scanner — deep CORS misconfiguration analysis."""

    NAME        = "cors_preflight"
    DESCRIPTION = "Detailed CORS preflight analysis and misconfiguration detection"
    PHASE       = 6
    TAGS        = ["headers", "owasp-a01", "cors", "cwe-942"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting CORS preflight analysis on %s", target)
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        from webforge.core.session import ForgeSession
        async with ForgeSession.from_config(self.config) as session:
            urls = self.config.extra.get("crawled_urls", [target])[:10]
            for url in urls:
                await self._test_cors(session, url)

        return self._make_result(start)

    async def _test_cors(self, session: Any, url: str) -> None:
        parsed = urlparse(url)
        target_origin = f"{parsed.scheme}://{parsed.hostname}"
        
        for evil_origin in EVIL_ORIGINS:
            try:
                await self.rate_limit()
                headers = {"Origin": evil_origin or "null"}
                resp = await session.get(url, headers=headers)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                
                if acao == "*" and acac.lower() == "true":
                    self.new_finding(
                        title="Critical CORS Misconfiguration — Wildcard + Credentials",
                        severity=Severity.CRITICAL,
                        description=f"CORS at {url} allows any origin (*) WITH credentials. Any website can steal authenticated data.",
                        reproduction_steps=[f"GET {url} with Origin: {evil_origin}", f"ACAO: {acao}, ACAC: {acac}"],
                        remediation="Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true.",
                        references=["CWE-942", "OWASP A01:2021"],
                        cvss_v31_vector=CVSS_CORS,
                        cvss_v40_vector=CVSS40_CORS,
                        target=self.config.target,
                    )
                    return
                elif evil_origin and acao == evil_origin:
                    severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                    self.new_finding(
                        title=f"CORS Origin Reflection — {evil_origin}",
                        severity=severity,
                        description=f"CORS at {url} reflects arbitrary origin {evil_origin}. Credentials: {acac}.",
                        reproduction_steps=[f"GET {url} with Origin: {evil_origin}"],
                        remediation="Whitelist specific trusted origins instead of reflecting the Origin header.",
                        references=["CWE-942", "OWASP A01:2021"],
                        cvss_v31_vector=CVSS_CORS,
                        cvss_v40_vector=CVSS40_CORS,
                        target=self.config.target,
                    )
                    return
                elif acao == "null":
                    self.new_finding(
                        title="CORS Null Origin Allowed",
                        severity=Severity.MEDIUM,
                        description=f"CORS at {url} accepts null origin. Sandboxed iframes can exploit this.",
                        reproduction_steps=[f"GET {url} with Origin: null"],
                        remediation="Do not allow null origin in CORS configuration.",
                        references=["CWE-942"],
                        cvss_v31_vector=CVSS_CORS,
                        cvss_v40_vector=CVSS40_CORS,
                        target=self.config.target,
                    )
                    return
            except Exception:
                continue
