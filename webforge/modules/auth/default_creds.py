"""Default Credentials Scanner — tests common default login pairs.

Nessus equivalent: 10862, 56208 (Default credentials).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

# Common default credential pairs (service, username, password)
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", ""), ("administrator", "administrator"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("test", "test"), ("guest", "guest"), ("user", "user"),
    ("demo", "demo"), ("operator", "operator"),
    # CMS defaults
    ("admin", "admin@123"), ("admin", "changeme"), ("admin", "P@ssw0rd"),
    # Database defaults
    ("sa", ""), ("sa", "sa"), ("postgres", "postgres"),
    ("mysql", "mysql"), ("oracle", "oracle"),
    # Appliance defaults
    ("cisco", "cisco"), ("admin", "default"),
]

CVSS_CREDS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_CREDS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


class DefaultCreds(BaseModule):
    """Default credentials scanner — tests login forms with common defaults."""

    NAME        = "default_creds"
    DESCRIPTION = "Default credential testing against discovered login forms"
    PHASE       = 5
    TAGS        = ["auth", "owasp-a07", "default-creds", "cwe-798"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting default credentials scan on %s", target)
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        forms = self.config.extra.get("found_forms", [])
        login_forms = [f for f in forms if self._is_login_form(f)]
        self.log.info("Found %d login form(s) to test", len(login_forms))

        from webforge.core.session import ForgeSession
        async with ForgeSession.from_config(self.config) as session:
            for form in login_forms[:5]:
                await self._test_form(session, form, target)

        return self._make_result(start)

    def _is_login_form(self, form: dict) -> bool:
        """Detect if a form looks like a login form."""
        inputs = [i.lower() for i in form.get("inputs", [])]
        action = (form.get("action") or "").lower()
        has_password = any("pass" in i or "pwd" in i for i in inputs)
        has_user = any("user" in i or "login" in i or "email" in i or "name" in i for i in inputs)
        login_action = any(x in action for x in ["login", "signin", "auth", "session"])
        return has_password and (has_user or login_action)

    async def _test_form(self, session: Any, form: dict, target: str) -> None:
        """Test a login form with default credentials."""
        action = form.get("action") or target
        inputs = form.get("inputs", [])
        user_field = next((i for i in inputs if any(x in i.lower() for x in ["user", "login", "email", "name"])), None)
        pass_field = next((i for i in inputs if any(x in i.lower() for x in ["pass", "pwd"])), None)

        if not user_field or not pass_field:
            return

        # First, get baseline failed login response
        await self.rate_limit()
        try:
            baseline_data = {i: "forge_baseline_value" for i in inputs}
            baseline_data[user_field] = "forge_nonexistent_user_12345"
            baseline_data[pass_field] = "forge_wrong_pass_12345"
            resp = await session.post(action, data=baseline_data)
            baseline_body = await resp.text()
            baseline_len = len(baseline_body)
            baseline_status = resp.status
        except Exception:
            return

        for username, password in DEFAULT_CREDS[:15]:
            await self.rate_limit()
            try:
                data = {i: "" for i in inputs}
                data[user_field] = username
                data[pass_field] = password
                resp = await session.post(action, data=data)
                body = await resp.text()

                # Detect successful login via differential analysis
                is_success = False
                if resp.status != baseline_status:
                    is_success = True
                elif abs(len(body) - baseline_len) > 200:
                    # Significant response size difference
                    success_markers = ["welcome", "dashboard", "logout", "profile", "account", "session"]
                    fail_markers = ["invalid", "incorrect", "failed", "error", "wrong"]
                    has_success = any(m in body.lower() for m in success_markers)
                    has_fail = any(m in body.lower() for m in fail_markers)
                    if has_success and not has_fail:
                        is_success = True

                if is_success:
                    from common.evidence import Evidence
                    ev = Evidence(
                        request_raw=f"POST {action} | {user_field}={username}&{pass_field}=****",
                        response_raw=body[:500],
                    )
                    self.new_finding(
                        title=f"Default Credentials — {username}:{password}",
                        severity=Severity.CRITICAL,
                        description=f"Login form at {action} accepts default credentials {username}:{password}. This grants unauthorized access.",
                        reproduction_steps=[f"POST {action}", f"Set {user_field}={username}, {pass_field}={password}"],
                        remediation="Change all default credentials. Enforce strong password policy. Implement account lockout.",
                        references=["CWE-798", "CWE-1393", "OWASP A07:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_CREDS,
                        cvss_v40_vector=CVSS40_CREDS,
                        target=target,
                    )
                    return  # One confirmed cred pair is enough
            except Exception:
                continue
