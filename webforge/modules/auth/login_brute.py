"""Login brute force — smart credential stuffing with lockout detection."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.confirm_gate import confirm
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence
from common.outbound_policy import OutboundDenied, OutboundReason

CVSS_BRUTE  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_BRUTE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_WEAK   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_WEAK = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
DEFAULT_USERNAMES = [
    "admin", "administrator", "root", "user", "test",
    "guest", "demo", "support", "operator", "manager",
]
DEFAULT_PASSWORDS = [
    "admin", "password", "password1", "123456", "12345678",
    "admin123", "root", "toor", "pass", "test",
    "demo", "guest", "123123", "qwerty", "letmein",
    "welcome", "changeme", "default", "admin@123", "Password1",
]

LOCKOUT_INDICATORS = [
    "locked", "too many", "temporarily disabled", "blocked",
    "account locked", "try again later", "captcha",
]
SUCCESS_INDICATORS = [
    "dashboard", "welcome", "logged in", "account",
    "logout", "profile", "home", "success",
]


def _deny_unmigrated_credential_effect() -> NoReturn:
    """Keep legacy credential transports inert pending protected adapters."""
    raise OutboundDenied(OutboundReason.OUTBOUND_POLICY_UNSUPPORTED)


class LoginBrute(BaseModule):
    """Login brute force with lockout detection and confirm gate."""

    NAME        = "login_brute"
    DESCRIPTION = "Credential brute-force on login forms with lockout protection"
    PHASE       = 5
    TAGS        = ["auth", "brute", "credential", "cwe-521", "owasp-a07"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        # Find login forms
        login_url, user_field, pass_field = await self._find_login_form(target)
        if not login_url:
            self.log.info("No login form found — skipping brute force")
            return self._make_result(start)

        # REQUIRE operator confirmation
        confirmed = self.confirm_action(
            module=self.NAME,
            action=f"Brute-force login form at {login_url} "
                   f"({len(DEFAULT_USERNAMES)} users × {len(DEFAULT_PASSWORDS)} passwords)",
            target=login_url,
            risk=(
                "ACCOUNT LOCKOUT RISK. Module stops at first lockout indicator. "
                "Default wordlists only — customize via config if needed."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        # Get baseline (failed login response)
        baseline_body = await self._post_login(
            login_url, user_field, pass_field, "INVALIDUSER_FORGE", "INVALIDPASS_FORGE"
        )

        valid_creds: list[dict] = []

        for username in DEFAULT_USERNAMES:
            for password in DEFAULT_PASSWORDS:
                await asyncio.sleep(self.config.brute_force.delay_seconds)

                body = await self._post_login(login_url, user_field, pass_field, username, password)
                if body is None:
                    continue

                # Lockout detection — stop immediately
                if any(ind in body.lower() for ind in LOCKOUT_INDICATORS):
                    self.log.warning("Account lockout detected for %s — stopping!", username)
                    self.new_finding(
                        title=f"Account Lockout Triggered — {username}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Account lockout triggered for '{username}' during brute force. "
                            "Attack was stopped immediately."
                        ),
                        reproduction_steps=[f"POST {login_url} with invalid credentials"],
                        remediation="Ensure lockout policy is properly configured.",
                        references=["CWE-307"],
                        evidence=Evidence(extra={"username": username}),
                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        target=target,
                        url=login_url,
                    )
                    await self._report_valid(valid_creds, login_url, target)
                    return self._make_result(start)

                # Success detection
                if baseline_body and len(body) != len(baseline_body) and \
                   any(ind in body.lower() for ind in SUCCESS_INDICATORS):
                    self.log.warning("VALID CREDENTIALS: %s:%s", username, password)
                    valid_creds.append({"username": username, "password": password})

        await self._report_valid(valid_creds, login_url, target)
        return self._make_result(start)

    async def _find_login_form(
        self, target: str
    ) -> tuple[str | None, str, str]:
        """Find a login form and identify username/password field names."""
        _deny_unmigrated_credential_effect()
        paths = ["", "/login", "/signin", "/auth", "/user/login", "/admin",
                 "/account/login", "/wp-login.php"]

        for path in paths:
            url = f"{target}{path}"
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=8)
                    ) as resp:
                        html = await resp.text(errors="ignore")

                # Find form with password field
                if "password" not in html.lower():
                    continue

                # Extract field names
                user_field = "username"
                pass_field = "password"

                for m in re.finditer(
                    r'<input[^>]+type=["\'](?:text|email)["\'][^>]+name=["\']([^"\']+)["\']',
                    html, re.IGNORECASE
                ):
                    user_field = m.group(1)
                    break

                for m in re.finditer(
                    r'<input[^>]+type=["\']password["\'][^>]+name=["\']([^"\']+)["\']',
                    html, re.IGNORECASE
                ):
                    pass_field = m.group(1)
                    break

                # Find form action
                action_match = re.search(
                    r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE
                )
                action = action_match.group(1) if action_match else path
                if not action.startswith("http"):
                    action = f"{target.rstrip('/')}/{action.lstrip('/')}"

                return action, user_field, pass_field

            except Exception:
                pass

        return None, "username", "password"

    async def _post_login(
        self, url: str, user_field: str, pass_field: str,
        username: str, password: str
    ) -> str | None:
        _deny_unmigrated_credential_effect()
        try:
            import aiohttp
            data = {user_field: username, pass_field: password}
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.post(
                    url, data=data,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                ) as resp:
                    return await resp.text(errors="ignore")
        except Exception:
            return None

    async def _report_valid(
        self, creds: list[dict], login_url: str, target: str
    ) -> None:
        if not creds:
            return
        ev = Evidence(
            extra={
                "credentials": [
                    {"username": c["username"], "password": "*" * len(c["password"])}
                    for c in creds
                ],
                "login_url": login_url,
            }
        )
        self.new_finding(
            title=f"Weak/Default Credentials Found ({len(creds)} account(s))",
            severity=Severity.CRITICAL,
            description=(
                f"{len(creds)} account(s) with weak/default passwords at {login_url}. "
                "Accounts: " + ", ".join(c["username"] for c in creds)
            ),
            reproduction_steps=[
                f"curl -X POST {login_url} -d '{creds[0]['username']}:<password>'",
            ],
            remediation=(
                "Immediately change all default/weak passwords. "
                "Enforce minimum password complexity. "
                "Implement MFA for all accounts."
            ),
            references=["CWE-521", "OWASP A07:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_BRUTE,
            cvss_v40_vector=CVSS40_BRUTE,
            mitre_attack=["TA0006/T1110.001"],
            target=target,
            url=login_url,
            operator_confirmed=True,
        )


class TestLoginBrute:
    def test_default_wordlists_not_empty(self) -> None:
        assert len(DEFAULT_USERNAMES) >= 5
        assert len(DEFAULT_PASSWORDS) >= 10

    def test_lockout_indicators(self) -> None:
        body = "Your account has been temporarily locked."
        assert any(ind in body.lower() for ind in LOCKOUT_INDICATORS)
