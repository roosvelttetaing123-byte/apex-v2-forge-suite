"""Privilege escalation scanner — horizontal and vertical access control bypass."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_PRIV_ESC  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_PRIV_ESC = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_HORIZ_ESC = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
CVSS40_HORIZ_ESC = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
ADMIN_PATHS = [
    "/admin", "/admin/users", "/admin/settings", "/admin/dashboard",
    "/api/admin", "/api/v1/admin", "/api/admin/users",
    "/management", "/manage/users", "/superadmin",
    "/api/users", "/api/v1/users",
]

ROLE_ESCALATION_PAYLOADS = [
    {"role": "admin"},
    {"role": "administrator"},
    {"is_admin": True},
    {"admin": True},
    {"userType": "admin"},
    {"privilege": "admin"},
    {"group": "admin"},
]


class PrivEsc(BaseModule):
    """Privilege escalation scanner."""

    NAME        = "priv_esc"
    DESCRIPTION = "Test for vertical (admin) and horizontal (other user) privilege escalation"
    PHASE       = 6
    TAGS        = ["access-control", "priv-esc", "idor", "cwe-269", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await asyncio.gather(
            self._test_admin_access(target),
            self._test_role_parameter_injection(target),
        )
        return self._make_result(start)

    async def _test_admin_access(self, target: str) -> None:
        """Test admin endpoints for access without admin role."""
        for path in ADMIN_PATHS:
            await self.rate_limit()
            url = f"{target}{path}"
            if not self.check_scope(url):
                continue

            status, body = await self._get(url)
            if status == 200 and len(body) > 100:
                ev = Evidence(
                    request_raw=f"GET {url}",
                    response_raw=body[:400],
                    extra={"path": path, "status": status},
                )
                ev.screenshot_path = await self.capture_screenshot(
                    url, finding_id=f"privesc_{path.replace('/', '_')}"
                )
                self.new_finding(
                    title=f"Vertical Privilege Escalation — Admin Endpoint Accessible ({path})",
                    severity=Severity.HIGH,
                    description=(
                        f"Admin endpoint {url} accessible without elevated privileges. "
                        "May expose user management, settings, or administrative functions."
                    ),
                    reproduction_steps=[f"curl -i {url}"],
                    remediation=(
                        "Implement role-based access control. "
                        "Check user role server-side on every admin request."
                    ),
                    references=["CWE-269", "OWASP A01:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_PRIV_ESC,
                    cvss_v40_vector=CVSS40_PRIV_ESC,
                    target=target,
                    url=url,
                )

    async def _test_role_parameter_injection(self, target: str) -> None:
        """Test if role/privilege can be injected via profile update."""
        import aiohttp

        # Test common profile/account update endpoints
        update_paths = [
            "/api/v1/profile", "/api/v1/user", "/api/profile",
            "/api/user/update", "/account/profile",
        ]

        for path in update_paths:
            for payload in ROLE_ESCALATION_PAYLOADS[:3]:
                await self.rate_limit()
                url = f"{target}{path}"
                if not self.check_scope(url):
                    continue

                try:
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.patch(
                            url,
                            json=payload,
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            body = await resp.text(errors="ignore")

                    # If response echoes back admin/true
                    if resp.status == 200 and any(
                        str(v).lower() in body.lower() for v in payload.values()
                        if str(v).lower() in ("admin", "true")
                    ):
                        ev = Evidence(
                            request_raw=f"PATCH {url}\n{payload}",
                            response_raw=body[:300],
                            extra={"payload": payload},
                        )
                        self.new_finding(
                            title=f"Role Injection — Privilege Escalation via PATCH ({path})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Sending role escalation payload to {url} returned success. "
                                f"Payload: {payload}. "
                                "User may have escalated to admin."
                            ),
                            reproduction_steps=[
                                f"PATCH {url}",
                                f"Body: {payload}",
                                "Verify admin access after update",
                            ],
                            remediation="Use allowlist of updatable fields; never allow role changes via API.",
                            references=["CWE-269", "CWE-915"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_PRIV_ESC,
                            cvss_v40_vector=CVSS40_PRIV_ESC,
                            target=target,
                            url=url,
                        )
                        return
                except Exception:
                    pass

    async def _get(self, url: str) -> tuple[int, str]:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False
                ) as resp:
                    return resp.status, await resp.text(errors="ignore")
        except Exception:
            return 0, ""


class TestPrivEsc:
    def test_admin_paths_not_empty(self) -> None:
        assert len(ADMIN_PATHS) >= 5

    def test_role_payloads(self) -> None:
        assert any("admin" in str(p) for p in ROLE_ESCALATION_PAYLOADS)
