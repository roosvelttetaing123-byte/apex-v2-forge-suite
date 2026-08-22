"""SRI (Subresource Integrity) checker — detect external scripts without integrity hashes."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

CVSS_NO_SRI = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N"
CVSS40_NO_SRI = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"
class SriCheck(BaseModule):
    """Subresource Integrity checker."""

    NAME        = "sri_check"
    DESCRIPTION = "Detect external scripts/styles loaded without Subresource Integrity hashes"
    PHASE       = 3
    TAGS        = ["headers", "sri", "supply-chain", "cwe-353"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        from urllib.parse import urlparse
        target_domain = urlparse(target).netloc.split(":")[0]

        html = await self._fetch(target)
        if not html:
            return self._make_result(start)

        issues = self._check_sri(html, target_domain)
        if issues:
            ev = Evidence(
                response_raw=html[:2000],
                extra={"issues": issues[:10], "total": len(issues)},
            )
            self.new_finding(
                title=f"External Resources Without SRI ({len(issues)} found)",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(issues)} external script(s)/stylesheet(s) loaded without "
                    "Subresource Integrity hashes. If the CDN is compromised, malicious "
                    "code will execute in users' browsers without any warning."
                ),
                reproduction_steps=[
                    f"curl -s {target} | grep -E '<script|<link' | grep -v integrity",
                    f"Missing SRI on: {', '.join(i['src'] for i in issues[:3])}",
                ],
                remediation=(
                    "Add integrity attributes to all external script/link tags. "
                    "Generate SRI hash: openssl dgst -sha384 -binary file.js | openssl base64 -A\n"
                    "Or use: https://www.srihash.org/"
                ),
                references=["CWE-353", "W3C SRI Specification"],
                evidence=ev,
                cvss_v31_vector=CVSS_NO_SRI,
                cvss_v40_vector=CVSS40_NO_SRI,
                mitre_attack=["TA0001/T1195.002"],
                target=target,
            )

        return self._make_result(start)

    def _check_sri(self, html: str, target_domain: str) -> list[dict]:
        issues: list[dict] = []

        # External scripts
        for m in re.finditer(
            r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE
        ):
            src  = m.group(1)
            full = m.group(0)
            if self._is_external(src, target_domain):
                if "integrity=" not in full.lower():
                    issues.append({"type": "script", "src": src[:80], "tag": full[:120]})

        # External stylesheets
        for m in re.finditer(
            r'<link[^>]+href=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE
        ):
            href = m.group(1)
            full = m.group(0)
            if ("stylesheet" in full.lower() or ".css" in href) and \
               self._is_external(href, target_domain):
                if "integrity=" not in full.lower():
                    issues.append({"type": "stylesheet", "src": href[:80], "tag": full[:120]})

        return issues

    def _is_external(self, src: str, target_domain: str) -> bool:
        if src.startswith("//"):
            return True
        if src.startswith("http"):
            from urllib.parse import urlparse
            src_domain = urlparse(src).netloc.split(":")[0]
            return src_domain != target_domain
        return False

    async def _fetch(self, url: str) -> str | None:
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        return await resp.text(errors="ignore")
        except Exception:
            pass
        return None


class TestSriCheck:
    def test_is_external_protocol_relative(self) -> None:
        mod = SriCheck.__new__(SriCheck)
        assert mod._is_external("//cdn.example.com/lib.js", "myapp.com")

    def test_is_external_same_domain(self) -> None:
        mod = SriCheck.__new__(SriCheck)
        assert not mod._is_external("https://myapp.com/js/app.js", "myapp.com")

    def test_is_external_different_domain(self) -> None:
        mod = SriCheck.__new__(SriCheck)
        assert mod._is_external("https://cdnjs.cloudflare.com/jquery.min.js", "myapp.com")

    def test_check_sri_detects_missing(self) -> None:
        mod = SriCheck.__new__(SriCheck)
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        issues = mod._check_sri(html, "myapp.com")
        assert len(issues) == 1

    def test_check_sri_passes_with_integrity(self) -> None:
        mod = SriCheck.__new__(SriCheck)
        html = '<script src="https://cdn.example.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>'
        issues = mod._check_sri(html, "myapp.com")
        assert len(issues) == 0
