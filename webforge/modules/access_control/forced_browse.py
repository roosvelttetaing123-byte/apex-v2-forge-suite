"""Forced browsing / broken access control — access resources without auth."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_FORCED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
CVSS40_FORCED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_403    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_403  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
PROTECTED_PATHS = [
    "/admin", "/admin/", "/admin/users", "/admin/settings",
    "/api/admin", "/api/users", "/api/settings",
    "/user/1", "/user/2", "/users/1",
    "/api/v1/users", "/api/v1/admin",
    "/dashboard", "/settings", "/profile",
    "/internal", "/private", "/secret",
    "/management", "/manage", "/console",
    "/debug", "/phpinfo", "/info",
    "/actuator", "/actuator/env", "/actuator/health",
    "/metrics", "/health", "/status",
    "/.env", "/config.json", "/app-config.json",
]

BYPASS_HEADERS = [
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
]


class ForcedBrowse(BaseModule):
    """Forced browsing and access control bypass scanner."""

    NAME        = "forced_browse"
    DESCRIPTION = "Test unauthenticated access to protected endpoints"
    PHASE       = 6
    TAGS        = ["access-control", "forced-browse", "auth-bypass", "cwe-284", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        sem = asyncio.Semaphore(5)
        tasks = [self._check_path(target, path, sem) for path in PROTECTED_PATHS]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _check_path(self, target: str, path: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            url = f"{target}{path}"
            if not self.check_scope(url):
                return
            await self.rate_limit()

            status, body = await self._get(url)

            if status == 200 and len(body) > 100:
                # Accessible without auth
                ev = Evidence(
                    request_raw=f"GET {url}",
                    response_raw=body[:500],
                    extra={"path": path, "status": status, "body_length": len(body)},
                )
                ev.screenshot_path = await self.capture_screenshot(
                    url, finding_id=f"forced_browse_{path.replace('/', '_')}"
                )
                self.new_finding(
                    title=f"Forced Browsing — Unauthenticated Access to {path}",
                    severity=Severity.HIGH,
                    description=(
                        f"Protected resource {url} is accessible without authentication "
                        f"(HTTP {status}, {len(body)} bytes). "
                        "This may expose administrative functions, user data, or internal APIs."
                    ),
                    reproduction_steps=[f"curl -i {url}"],
                    remediation=(
                        "Implement server-side authentication checks on all protected paths. "
                        "Do not rely on security-by-obscurity (hidden paths). "
                        "Use centralized authorization middleware."
                    ),
                    references=["CWE-284", "OWASP A01:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_FORCED,
                    cvss_v40_vector=CVSS40_FORCED,
                    mitre_attack=["TA0007/T1590"],
                    target=target,
                    url=url,
                )

            elif status == 403:
                # 403 forbidden — try bypass techniques
                await self._try_403_bypass(url, path, target)

    async def _try_403_bypass(self, url: str, path: str, target: str) -> None:
        """Try common 403 bypass techniques."""
        # Path variation bypass
        variations = [
            path + "/",
            path + "//",
            path + "?",
            path + ".json",
            path + "#",
            "/" + path.lstrip("/").replace("/", "//"),
            "/%2e" + path,
        ]

        for variation in variations:
            var_url = f"{target}{variation}"
            if not self.check_scope(var_url):
                continue
            await self.rate_limit()
            status, body = await self._get(var_url)
            if status == 200 and len(body) > 100:
                ev = Evidence(
                    request_raw=f"GET {var_url}",
                    response_raw=body[:300],
                    extra={"original_path": path, "bypass_path": variation},
                )
                self.new_finding(
                    title=f"403 Bypass — Path Variation ({path} → {variation})",
                    severity=Severity.HIGH,
                    description=(
                        f"403 at {url} bypassed using path variation '{variation}'. "
                        "The access control check does not normalize paths before evaluating."
                    ),
                    reproduction_steps=[
                        f"Original: curl -i {url} → 403",
                        f"Bypass: curl -i {var_url} → 200",
                    ],
                    remediation="Normalize paths before access control checks.",
                    references=["CWE-284"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_403,
                    cvss_v40_vector=CVSS40_403,
                    target=target,
                    url=url,
                )
                return

        # Header-based bypass
        for header_dict in BYPASS_HEADERS:
            await self.rate_limit()
            headers = {
                k: v.replace("{path}", path)
                for k, v in header_dict.items()
            }
            headers["User-Agent"] = "Mozilla/5.0"
            status, body = await self._get(url, headers=headers)
            if status == 200 and len(body) > 100:
                header_name = list(header_dict.keys())[0]
                ev = Evidence(
                    request_raw=f"GET {url}\n{header_name}: {headers[header_name]}",
                    response_raw=body[:300],
                    extra={"bypass_header": header_name},
                )
                self.new_finding(
                    title=f"403 Bypass via {header_name} Header ({path})",
                    severity=Severity.HIGH,
                    description=(
                        f"403 at {url} bypassed using '{header_name}' header. "
                        "Application trusts IP/host from headers without validation."
                    ),
                    reproduction_steps=[
                        f"curl -i -H '{header_name}: {headers[header_name]}' {url}",
                    ],
                    remediation=(
                        "Do not use untrusted headers for access control. "
                        "Only trust IP addresses from the actual network connection."
                    ),
                    references=["CWE-807"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_403,
                    cvss_v40_vector=CVSS40_403,
                    target=target,
                    url=url,
                )
                return

    async def _get(self, url: str, headers: dict | None = None) -> tuple[int, str]:
        try:
            import aiohttp
            h = {"User-Agent": "Mozilla/5.0"}
            if headers:
                h.update(headers)
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, headers=h,
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                ) as resp:
                    return resp.status, await resp.text(errors="ignore")
        except Exception:
            return 0, ""


class TestForcedBrowse:
    def test_protected_paths_not_empty(self) -> None:
        assert len(PROTECTED_PATHS) >= 10

    def test_bypass_headers_not_empty(self) -> None:
        assert len(BYPASS_HEADERS) >= 5

    def test_path_has_admin(self) -> None:
        assert any("admin" in p for p in PROTECTED_PATHS)
