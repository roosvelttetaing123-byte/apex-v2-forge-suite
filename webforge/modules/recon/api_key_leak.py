"""API Key Leak Scanner — detects exposed API keys in responses and JS files.

Nessus equivalent: 158432 (API key disclosure).
"""
from __future__ import annotations

import re
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

# Regex patterns for common API key formats
KEY_PATTERNS = [
    (r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\x27]([a-zA-Z0-9_-]{20,})', "Generic API Key", Severity.HIGH),
    (r'AIza[0-9A-Za-z_-]{35}', "Google API Key", Severity.HIGH),
    (r'(?:AKIA|ASIA)[0-9A-Z]{16}', "AWS Access Key", Severity.CRITICAL),
    (r'(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}', "Stripe API Key", Severity.CRITICAL),
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token", Severity.CRITICAL),
    (r'glpat-[0-9a-zA-Z-]{20,}', "GitLab Personal Access Token", Severity.CRITICAL),
    (r'xox[bsarp]-[0-9a-zA-Z-]{10,}', "Slack Token", Severity.HIGH),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key", Severity.CRITICAL),
    (r'(?:password|passwd|pwd)\s*[=:]\s*["\x27]([^\x27"]{6,})', "Hardcoded Password", Severity.HIGH),
    (r'(?:mysql|postgres|mongodb)://[^\s"]{10,}', "Database Connection String", Severity.CRITICAL),
    (r'Bearer\s+[a-zA-Z0-9._~+/-]+=*', "Bearer Token", Severity.MEDIUM),
    (r'(?:private[_-]?key)\s*[=:]\s*["\x27]([^\x27"]{20,})', "Private Key Reference", Severity.HIGH),
]

CVSS_LEAK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_LEAK = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"


class ApiKeyLeak(BaseModule):
    """API Key Leak scanner — finds exposed credentials in responses and JS."""

    NAME        = "api_key_leak"
    DESCRIPTION = "API key and credential leak detection in responses and JavaScript"
    PHASE       = 2
    TAGS        = ["recon", "owasp-a01", "api-key-leak", "cwe-312"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting API key leak scan on %s", target)
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        self._found_keys: set[str] = set()

        from webforge.core.session import ForgeSession
        async with ForgeSession.from_config(self.config) as session:
            # Scan crawled pages
            urls = self.config.extra.get("crawled_urls", [target])[:25]
            for url in urls:
                await self._scan_page(session, url)

            # Scan discovered JS files
            js_files = self.config.extra.get("js_files", [])[:15]
            for js_url in js_files:
                await self._scan_page(session, js_url)

        return self._make_result(start)

    async def _scan_page(self, session: Any, url: str) -> None:
        try:
            await self.rate_limit()
            resp = await session.get(url)
            body = await resp.text()
            for pattern, name, severity in KEY_PATTERNS:
                matches = re.findall(pattern, body, re.IGNORECASE)
                for match in matches[:3]:
                    key_preview = match[:8] + "..." if len(match) > 8 else match
                    dedup_key = f"{name}:{key_preview}"
                    if dedup_key in self._found_keys:
                        continue
                    self._found_keys.add(dedup_key)
                    from common.evidence import Evidence
                    ev = Evidence(
                        request_raw=f"GET {url}",
                        response_raw=f"Found: {name} = {key_preview}***",
                    )
                    self.new_finding(
                        title=f"API Key Exposed — {name}",
                        severity=severity,
                        description=f"{name} found in response from {url}. Key preview: {key_preview}***. Exposed credentials can lead to unauthorized access.",
                        reproduction_steps=[f"GET {url}", f"Search for pattern: {name}"],
                        remediation="Remove hardcoded credentials. Use environment variables or secrets management.",
                        references=["CWE-312", "CWE-798", "OWASP A01:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_LEAK,
                        cvss_v40_vector=CVSS40_LEAK,
                        target=self.config.target,
                    )
        except Exception:
            pass
