"""Password policy tester — check for weak password acceptance."""
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

CVSS_WEAK_POLICY = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_WEAK_POLICY = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
WEAK_PASSWORDS_TO_TEST = [
    "a",           # 1 char
    "123",         # 3 chars
    "password",    # common word
    "12345678",    # all numeric
    "aaaaaaaaaa",  # all same char
    "abc",         # 3 chars
]

REGISTER_PATHS = [
    "/register", "/signup", "/create-account", "/new-user",
    "/user/register", "/auth/register", "/api/register",
    "/account/create",
]

CHANGE_PASS_PATHS = [
    "/change-password", "/account/password", "/profile/password",
    "/user/password", "/api/change-password",
]

ERROR_KEYWORDS = ["error", "invalid", "too short", "must contain", "complexity",
                  "requirement", "minimum", "at least", "weak"]


class PasswordPolicy(BaseModule):
    """Password policy tester."""

    NAME        = "password_policy"
    DESCRIPTION = "Test registration/change-password forms for weak password policy enforcement"
    PHASE       = 5
    TAGS        = ["auth", "password", "policy", "cwe-521", "owasp-a07"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await asyncio.gather(
            self._test_registration_policy(target),
            self._check_account_enumeration(target),
        )
        return self._make_result(start)

    async def _test_registration_policy(self, target: str) -> None:
        """Find a registration/change-password form and test weak passwords."""
        reg_url = await self._find_registration_form(target)
        if not reg_url:
            self.log.info("No registration form found")
            return

        accepted_weak: list[str] = []
        for weak_pass in WEAK_PASSWORDS_TO_TEST:
            await self.rate_limit()
            result = await self._attempt_register(reg_url, weak_pass)
            if result and not any(kw in result.lower() for kw in ERROR_KEYWORDS):
                accepted_weak.append(weak_pass)

        if accepted_weak:
            ev = Evidence(
                extra={
                    "registration_url": reg_url,
                    "accepted_weak_passwords": accepted_weak,
                }
            )
            self.new_finding(
                title=f"Weak Password Policy — {len(accepted_weak)} Weak Password(s) Accepted",
                severity=Severity.HIGH,
                description=(
                    f"Registration form at {reg_url} accepted these weak passwords: "
                    f"{', '.join(repr(p) for p in accepted_weak)}. "
                    "Weak passwords greatly increase the risk of credential-based attacks."
                ),
                reproduction_steps=[
                    f"POST {reg_url} with password='{accepted_weak[0]}'",
                    "No error message — password accepted",
                ],
                remediation=(
                    "Enforce minimum password requirements:\n"
                    "- Minimum 8 characters\n"
                    "- Mix of uppercase, lowercase, numbers, special chars\n"
                    "- Reject common/dictionary passwords (use HaveIBeenPwned API)\n"
                    "- Do not use custom password strength meters as sole enforcement"
                ),
                references=["CWE-521", "NIST SP 800-63B", "OWASP A07:2021"],
                evidence=ev,
                cvss_v31_vector=CVSS_WEAK_POLICY,
                cvss_v40_vector=CVSS40_WEAK_POLICY,
                target=target,
                url=reg_url,
            )

    async def _check_account_enumeration(self, target: str) -> None:
        """Check if login form reveals whether an account exists."""
        login_url = None
        for path in ["/login", "/signin", "/auth"]:
            url = f"{target}{path}"
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            login_url = url
                            break
            except Exception:
                pass

        if not login_url:
            return

        # Test with invalid user vs. valid-format but wrong password
        resp1 = await self._post(login_url, {"username": "NONEXISTENT_USER_999XZZ", "password": "WrongPass1!"})
        resp2 = await self._post(login_url, {"username": "admin", "password": "WrongPass1!"})

        if resp1 and resp2:
            # Different response length suggests account enumeration
            diff = abs(len(resp1) - len(resp2))
            # Or different error messages
            if diff > 50:
                ev = Evidence(
                    extra={
                        "login_url": login_url,
                        "response_diff_chars": diff,
                    }
                )
                self.new_finding(
                    title="Account Enumeration via Login Error Message",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Login form at {login_url} returns different response lengths "
                        f"for existing vs. non-existing accounts (diff: {diff} chars). "
                        "Attackers can enumerate valid usernames."
                    ),
                    reproduction_steps=[
                        f"POST {login_url} username=nonexistent → response length {len(resp1)}",
                        f"POST {login_url} username=admin → response length {len(resp2)}",
                    ],
                    remediation=(
                        "Return identical error messages for wrong username and wrong password. "
                        "Use generic: 'Invalid username or password.'"
                    ),
                    references=["CWE-204", "OWASP Testing Guide OTG-IDENT-004"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    target=target,
                    url=login_url,
                )

    async def _find_registration_form(self, target: str) -> str | None:
        for path in REGISTER_PATHS:
            await self.rate_limit()
            url = f"{target}{path}"
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            if "password" in body.lower() and ("register" in body.lower()
                                or "sign up" in body.lower() or "create" in body.lower()):
                                return url
            except Exception:
                pass
        return None

    async def _attempt_register(self, url: str, password: str) -> str | None:
        try:
            import aiohttp
            data = {
                "username":         f"testuser_{int(time.time())}",
                "email":            f"test{int(time.time())}@example.com",
                "password":         password,
                "password_confirm": password,
            }
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.post(
                    url, data=data, timeout=aiohttp.ClientTimeout(total=8)
                ) as resp:
                    return await resp.text(errors="ignore")
        except Exception:
            return None

    async def _post(self, url: str, data: dict) -> str | None:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.post(
                    url, data=data, timeout=aiohttp.ClientTimeout(total=8)
                ) as resp:
                    return await resp.text(errors="ignore")
        except Exception:
            return None


class TestPasswordPolicy:
    def test_weak_passwords_list(self) -> None:
        assert len(WEAK_PASSWORDS_TO_TEST) >= 4
        assert "password" in WEAK_PASSWORDS_TO_TEST

    def test_error_keywords(self) -> None:
        response = "Error: Password too short, minimum 8 characters required"
        assert any(kw in response.lower() for kw in ERROR_KEYWORDS)
