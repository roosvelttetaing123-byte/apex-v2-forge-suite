"""Clickjacking detector — check X-Frame-Options and CSP frame-ancestors."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CLICKJACKING = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
CVSS40_CLICKJACKING = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
class Clickjacking(BaseModule):
    """Clickjacking vulnerability detector."""

    NAME        = "clickjacking"
    DESCRIPTION = "Detect missing X-Frame-Options and CSP frame-ancestors protections"
    PHASE       = 3
    TAGS        = ["headers", "clickjacking", "iframe", "cwe-1021"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        headers = await self._fetch_headers(target)
        if headers is None:
            return self._make_result(start)

        xfo = headers.get("X-Frame-Options", "")
        csp = headers.get("Content-Security-Policy", "")
        has_csp_protection = "frame-ancestors" in csp.lower()
        has_xfo = xfo.strip().upper() in ("DENY", "SAMEORIGIN")

        if not has_xfo and not has_csp_protection:
            ev = Evidence(
                response_raw=(
                    f"X-Frame-Options: {xfo or '(missing)'}\n"
                    f"Content-Security-Policy: {csp[:200] or '(missing)'}"
                ),
                extra={
                    "xfo":               xfo,
                    "csp_frame_ancestors": has_csp_protection,
                },
            )
            ev.screenshot_path = self.capture_screenshot(
                target, finding_id="clickjacking"
            )
            self.new_finding(
                title="Clickjacking Protection Missing",
                severity=Severity.MEDIUM,
                description=(
                    f"{target} is missing both X-Frame-Options and CSP frame-ancestors. "
                    "The page can be embedded in an attacker-controlled iframe, "
                    "enabling clickjacking attacks where users unknowingly click on "
                    "hidden UI elements (change password, authorize OAuth, etc.)."
                ),
                reproduction_steps=[
                    "Create iframe: <iframe src='{target}' style='opacity:0.5'></iframe>",
                    f"curl -I {target} | grep -iE 'X-Frame|frame-ancestors'",
                ],
                remediation=(
                    "Add X-Frame-Options: DENY (or SAMEORIGIN if framing is needed by same origin). "
                    "Or add to CSP: frame-ancestors 'none' (preferred). "
                    "CSP frame-ancestors overrides X-Frame-Options in modern browsers."
                ),
                references=["CWE-1021", "OWASP Clickjacking Cheat Sheet"],
                evidence=ev,
                cvss_v31_vector=CVSS_CLICKJACKING,
                cvss_v40_vector=CVSS40_CLICKJACKING,
                mitre_attack=["TA0001/T1192"],
                target=target,
            )

        elif xfo and xfo.strip().upper() == "ALLOWALL":
            self.new_finding(
                title="X-Frame-Options Set to ALLOWALL",
                severity=Severity.MEDIUM,
                description=(
                    "X-Frame-Options: ALLOWALL explicitly permits framing from any origin. "
                    "This is equivalent to no protection."
                ),
                reproduction_steps=[f"curl -I {target} | grep X-Frame-Options"],
                remediation="Change to X-Frame-Options: DENY or use CSP frame-ancestors.",
                references=["CWE-1021"],
                evidence=Evidence(response_raw=f"X-Frame-Options: {xfo}"),
                cvss_v31_vector=CVSS_CLICKJACKING,
                cvss_v40_vector=CVSS40_CLICKJACKING,
                target=target,
            )

        return self._make_result(start)

    async def _fetch_headers(self, url: str) -> dict | None:
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True
                ) as resp:
                    return dict(resp.headers)
        except Exception:
            return None


class TestClickjacking:
    def test_xfo_values(self) -> None:
        valid = {"DENY", "SAMEORIGIN"}
        assert "DENY" in valid
        assert "ALLOWALL" not in valid

    def test_csp_frame_ancestors_check(self) -> None:
        csp = "default-src 'self'; frame-ancestors 'none'"
        assert "frame-ancestors" in csp.lower()
