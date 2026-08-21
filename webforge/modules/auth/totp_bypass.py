"""TOTP/2FA bypass via account takeover through password reset flow."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

CVSS_RESET_BYPASS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_RESET_BYPASS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_TOTP_REUSE   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_TOTP_REUSE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
RESET_PATHS = [
    "/password-reset", "/forgot-password", "/reset-password",
    "/account/forgot", "/auth/forgot",
]


class TotpBypass(BaseModule):
    """TOTP/2FA bypass via password reset and code reuse attacks."""

    NAME        = "totp_bypass"
    DESCRIPTION = "Test 2FA bypass via password reset, code reuse, and backup code attacks"
    PHASE       = 5
    TAGS        = ["auth", "totp", "2fa", "bypass", "account-takeover", "cwe-287"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        await asyncio.gather(
            self._check_reset_bypasses_2fa(target),
            self._check_backup_codes(target),
            self._check_totp_window(target),
        )
        return self._make_result(start)

    async def _check_reset_bypasses_2fa(self, target: str) -> None:
        """Test if password reset disables 2FA requirement."""
        for path in RESET_PATHS:
            url = f"{target}{path}"
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status != 200:
                            continue
                        body = await resp.text(errors="ignore")

                if "password" not in body.lower():
                    continue

                # Check if reset flow mentions 2FA
                mfa_mentioned = any(kw in body.lower() for kw in
                                    ["2fa", "mfa", "authenticator", "two-factor", "otp"])

                ev = Evidence(
                    extra={
                        "reset_url": url,
                        "2fa_mentioned_in_reset": mfa_mentioned,
                    }
                )
                self.new_finding(
                    title=f"Password Reset Flow — Verify 2FA Bypass ({path})",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"Password reset endpoint found at {url}. "
                        + ("2FA is not mentioned in the reset flow — verify manually if "
                           "password reset bypasses the 2FA requirement."
                           if not mfa_mentioned else
                           "2FA appears to be mentioned in reset flow — verify it is enforced.")
                        + "\n\nManual test:\n"
                        "1. Enable 2FA on a test account\n"
                        "2. Request password reset\n"
                        "3. Reset password via email link\n"
                        "4. Try to login — does it still ask for 2FA?\n"
                        "5. If no 2FA prompt: vulnerability confirmed"
                    ),
                    reproduction_steps=[
                        f"POST {url} with email=victim@example.com",
                        "Use reset link to set new password",
                        "Login with new password — check if 2FA is required",
                    ],
                    remediation=(
                        "Password reset MUST NOT disable 2FA. "
                        "After password reset, still require 2FA on next login. "
                        "Consider requiring 2FA to initiate password reset."
                    ),
                    references=["CWE-287", "OWASP A07:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_RESET_BYPASS,
                    cvss_v40_vector=CVSS40_RESET_BYPASS,
                    target=target,
                    url=url,
                )
                break
            except Exception:
                pass

    async def _check_backup_codes(self, target: str) -> None:
        """Check if backup/recovery codes are single-use and rate-limited."""
        backup_paths = [
            "/auth/backup-code", "/mfa/backup", "/2fa/recovery",
            "/account/recovery-codes", "/settings/2fa/backup",
        ]

        # Detect SPA catch-all once — avoids false positives where every path
        # returns HTTP 200 with the app shell (React/Vercel, Next.js, etc.).
        spa_fp = await self._spa_fingerprint(target)

        for path in backup_paths:
            url = f"{target}{path}"
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status in (200, 405):
                            body = await resp.text(errors="ignore")

                            # Skip if this is just the SPA shell, not a real endpoint
                            if self._is_spa_body(body, spa_fp):
                                continue

                            if any(kw in body.lower() for kw in
                                   ["backup", "recovery", "code"]):
                                codes_tried = 0
                                locked = False
                                last_body = ""
                                for code in ["00000001", "00000002", "00000003"]:
                                    async with session.post(
                                        url,
                                        data={"code": code, "backup_code": code},
                                        timeout=aiohttp.ClientTimeout(total=5),
                                    ) as resp2:
                                        last_body = await resp2.text(errors="ignore")
                                        codes_tried += 1
                                        if any(kw in last_body.lower() for kw in
                                               ["locked", "blocked", "too many"]):
                                            locked = True
                                            break

                                if codes_tried >= 3 and not locked:
                                    # Final SPA check on POST responses
                                    if self._is_spa_body(last_body, spa_fp):
                                        continue

                                    ev = Evidence(extra={"path": path})
                                    self.new_finding(
                                        title=f"Backup Code Endpoint — No Rate Limiting ({path})",
                                        severity=Severity.HIGH,
                                        description=(
                                            f"Backup code endpoint {url} does not rate-limit attempts. "
                                            "Backup codes are typically 8-digit — brute-forceable without rate limiting."
                                        ),
                                        reproduction_steps=[f"POST {url} with backup_code=00000001..99999999"],
                                        remediation="Rate limit backup code attempts. Lock after 5 failures.",
                                        references=["CWE-307"],
                                        evidence=ev,
                                        cvss_v31_vector=CVSS_TOTP_REUSE,
                                        cvss_v40_vector=CVSS40_TOTP_REUSE,
                                        target=target,
                                        url=url,
                                    )
                                return
            except Exception:
                pass

    async def _check_totp_window(self, target: str) -> None:
        """Document TOTP time window check (informational guidance)."""
        mfa_paths = ["/mfa", "/otp", "/2fa/verify", "/auth/otp"]
        for path in mfa_paths:
            url = f"{target}{path}"
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            # Test if recently used codes are rejected (anti-replay)
                            # Send same code twice rapidly
                            code = "123456"
                            r1 = r2 = None
                            async with session.post(
                                url, data={"otp": code},
                                timeout=aiohttp.ClientTimeout(total=5)
                            ) as rr1:
                                r1 = await rr1.text(errors="ignore")
                            async with session.post(
                                url, data={"otp": code},
                                timeout=aiohttp.ClientTimeout(total=5)
                            ) as rr2:
                                r2 = await rr2.text(errors="ignore")

                            if r1 and r2 and r1 == r2:
                                self.new_finding(
                                    title=f"TOTP Code Reuse Not Detected ({path})",
                                    severity=Severity.MEDIUM,
                                    description=(
                                        f"Submitting the same OTP code twice at {url} "
                                        "returns the same response. Server may not be "
                                        "tracking used codes (replay attack possible)."
                                    ),
                                    reproduction_steps=[
                                        f"POST {url} otp=123456 → identical response twice",
                                    ],
                                    remediation=(
                                        "Track each TOTP code as used and reject reuse within validity window. "
                                        "TOTP codes should only be valid once."
                                    ),
                                    references=["RFC 6238", "CWE-294"],
                                    evidence=Evidence(
                                        extra={"path": path, "same_response": True}
                                    ),
                                    cvss_v31_vector=CVSS_TOTP_REUSE,
                                    cvss_v40_vector=CVSS40_TOTP_REUSE,
                                    target=target,
                                    url=url,
                                )
                            return
            except Exception:
                pass


class TestTotpBypass:
    def test_reset_paths_not_empty(self) -> None:
        assert len(RESET_PATHS) >= 3

    def test_cvss_vectors(self) -> None:
        assert CVSS_RESET_BYPASS.startswith("CVSS:3.1")
        assert CVSS_TOTP_REUSE.startswith("CVSS:3.1")
