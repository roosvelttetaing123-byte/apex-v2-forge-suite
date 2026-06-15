"""MFA/2FA bypass scanner — response manipulation, code reuse, brute force."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_MFA_BYPASS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_MFA_BRUTE  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"

MFA_PATHS = [
    "/mfa", "/otp", "/2fa", "/verify", "/confirmation",
    "/auth/verify", "/auth/mfa", "/auth/otp",
    "/login/verify", "/login/mfa",
    "/api/mfa/verify", "/api/otp/verify",
]


class MfaBypass(BaseModule):
    """MFA/2FA bypass vulnerability scanner."""

    NAME        = "mfa_bypass"
    DESCRIPTION = "Detect MFA/2FA bypass: response manipulation, brute-force, code reuse"
    PHASE       = 5
    TAGS        = ["auth", "mfa", "2fa", "otp", "bypass", "cwe-287", "owasp-a07"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await asyncio.gather(
            self._find_mfa_endpoints(target),
            self._check_mfa_brute_protection(target),
        )
        return self._make_result(start)

    async def _find_mfa_endpoints(self, target: str) -> None:
        """Detect MFA pages and test for bypass techniques."""
        for path in MFA_PATHS:
            await self.rate_limit()
            url = f"{target}{path}"
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status not in (200, 302, 405):
                            continue
                        body = await resp.text(errors="ignore")

                # MFA page detected
                if any(kw in body.lower() for kw in
                       ["otp", "verification code", "2fa", "two-factor", "authentication code"]):

                    await self._test_response_manipulation(url, target)
                    await self._test_code_bypass(url, target)
                    break

            except Exception:
                pass

    async def _test_response_manipulation(self, mfa_url: str, target: str) -> None:
        """Test if changing response status from 'invalid' to 'success' bypasses MFA."""
        # This is a manual test guide — we document the attack vector
        ev = Evidence(
            extra={
                "mfa_url": mfa_url,
                "test_type": "response_manipulation_guidance",
            }
        )
        self.new_finding(
            title=f"MFA Endpoint Found — Verify Response Manipulation ({mfa_url})",
            severity=Severity.INFORMATIONAL,
            description=(
                f"MFA verification endpoint found at {mfa_url}. "
                "Manually verify:\n"
                "1. Intercept failed MFA response (e.g., 403 or {success:false})\n"
                "2. Modify response to {success:true} or HTTP 200\n"
                "3. Check if application proceeds past MFA\n"
                "This is a common client-side trust issue where MFA is enforced by the UI, not the server."
            ),
            reproduction_steps=[
                "Use Burp Suite proxy",
                "Submit invalid OTP",
                "In response, change status to 200 or success:true",
                "Observe if session is created",
            ],
            remediation=(
                "MFA verification MUST be server-side. "
                "Never trust client-side MFA state. "
                "Always validate OTP on the server before granting access."
            ),
            references=["CWE-287", "OWASP A07:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_MFA_BYPASS,
            target=target,
            url=mfa_url,
        )

    async def _test_code_bypass(self, mfa_url: str, target: str) -> None:
        """Test common OTP bypass codes."""
        bypass_codes = ["000000", "123456", "111111", "999999", "000001",
                        "0", "null", "undefined", ""]

        for code in bypass_codes:
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    for data_key in ["otp", "code", "token", "mfa_code", "verification_code"]:
                        async with session.post(
                            mfa_url,
                            data={data_key: code},
                            timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=True,
                        ) as resp:
                            body = await resp.text(errors="ignore")

                        if resp.status == 200 and any(
                            kw in body.lower() for kw in
                            ["dashboard", "welcome", "success", "logged in"]
                        ):
                            ev = Evidence(
                                request_raw=f"POST {mfa_url}\n{data_key}={code}",
                                response_raw=body[:300],
                                extra={"bypass_code": code, "field": data_key},
                            )
                            self.new_finding(
                                title=f"MFA Bypass — Common Code Accepted ({code})",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"MFA can be bypassed using trivial code '{code}' "
                                    f"in field '{data_key}' at {mfa_url}."
                                ),
                                reproduction_steps=[
                                    f"POST {mfa_url}",
                                    f"Body: {data_key}={code}",
                                ],
                                remediation="Use cryptographically secure TOTP/HOTP. Reject trivial codes.",
                                references=["CWE-287"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_MFA_BYPASS,
                                target=target,
                                url=mfa_url,
                            )
                            return
            except Exception:
                pass

    async def _check_mfa_brute_protection(self, target: str) -> None:
        """Check if MFA codes are rate-limited (detect brute-force protection absence)."""
        import aiohttp

        MFA_KEYWORDS = ["otp", "verification code", "2fa", "two-factor",
                        "authentication code", "one-time", "authenticator"]

        for path in MFA_PATHS[:5]:
            url = f"{target}{path}"

            # Verify this is actually an MFA endpoint before brute-forcing
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status not in (200, 405):
                            continue
                        probe_body = await resp.text(errors="ignore")
                if not any(kw in probe_body.lower() for kw in MFA_KEYWORDS):
                    continue
            except Exception:
                continue

            codes_tried = 0
            locked = False

            for code in ["000001", "000002", "000003", "000004", "000005"]:
                await self.rate_limit()
                try:
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.post(
                            url,
                            data={"otp": code, "code": code},
                            timeout=aiohttp.ClientTimeout(total=5),
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            codes_tried += 1

                    if any(kw in body.lower() for kw in
                           ["locked", "too many", "blocked", "limit"]):
                        locked = True
                        break
                except Exception:
                    break

            if codes_tried >= 5 and not locked:
                ev = Evidence(
                    extra={
                        "mfa_url": url,
                        "attempts_without_lockout": codes_tried,
                    }
                )
                self.new_finding(
                    title=f"MFA Code Brute-Force — No Rate Limiting ({path})",
                    severity=Severity.HIGH,
                    description=(
                        f"MFA endpoint {url} did not lock out or rate-limit after {codes_tried} "
                        "invalid code attempts. A 6-digit TOTP has 10^6 combinations — "
                        "an unprotected endpoint allows brute-forcing the code within seconds."
                    ),
                    reproduction_steps=[
                        f"for i in $(seq 0 9999); do",
                        f"  curl -X POST {url} -d \"otp=$(printf '%06d' $i)\";",
                        "done",
                    ],
                    remediation=(
                        "Implement rate limiting on MFA verification (max 5 attempts). "
                        "Lock account/session after repeated failures. "
                        "Use TOTP with short validity window (30s)."
                    ),
                    references=["CWE-307", "CWE-287"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_MFA_BRUTE,
                    target=target,
                    url=url,
                )
                return


class TestMfaBypass:
    def test_mfa_paths_not_empty(self) -> None:
        assert len(MFA_PATHS) >= 5

    def test_cvss_vectors(self) -> None:
        assert CVSS_MFA_BYPASS.startswith("CVSS:3.1")
        assert CVSS_MFA_BRUTE.startswith("CVSS:3.1")
