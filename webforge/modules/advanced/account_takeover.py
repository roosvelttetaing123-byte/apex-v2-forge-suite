"""Account takeover via password reset flow — weak tokens, no expiry, user enumeration."""
from __future__ import annotations

import asyncio
import hashlib
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_RESET_TOKEN  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_ENUM         = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_HOST_POISON  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"

RESET_PATHS = [
    "/password-reset", "/forgot-password", "/reset-password",
    "/account/forgot", "/auth/forgot", "/user/forgot",
    "/api/auth/forgot-password", "/api/reset-password",
]


class AccountTakeover(BaseModule):
    """Account takeover via password reset vulnerability scanner."""

    NAME        = "account_takeover"
    DESCRIPTION = "Test password reset flow for weak tokens, user enumeration, host header poisoning"
    PHASE       = 10
    TAGS        = ["advanced", "account-takeover", "password-reset", "cwe-640", "owasp-a07"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        reset_url = await self._find_reset_endpoint(target)
        if not reset_url:
            self.log.info("No password reset endpoint found")
            return self._make_result(start)

        self.log.info("Testing password reset flow at %s", reset_url)

        await asyncio.gather(
            self._test_user_enumeration(reset_url, target),
            self._test_token_entropy(reset_url, target),
            self._test_host_header_poisoning(reset_url, target),
            self._test_token_reuse(reset_url, target),
        )

        return self._make_result(start)

    async def _find_reset_endpoint(self, target: str) -> str | None:
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
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            if any(kw in body.lower() for kw in
                                   ["email", "reset", "forgot", "password"]):
                                return url
            except Exception:
                pass
        return None

    async def _test_user_enumeration(self, reset_url: str, target: str) -> None:
        """Check if different responses reveal valid vs. invalid accounts."""
        await self.rate_limit()

        resp1 = await self._post_reset(reset_url, "nonexistent_user_ZZZXXX@example.com")
        resp2 = await self._post_reset(reset_url, "admin@example.com")

        if resp1 and resp2 and abs(len(resp1) - len(resp2)) > 50:
            ev = Evidence(
                extra={
                    "reset_url":       reset_url,
                    "nonexistent_len": len(resp1),
                    "existing_len":    len(resp2),
                }
            )
            self.new_finding(
                title="Password Reset — User Enumeration via Response Difference",
                severity=Severity.MEDIUM,
                description=(
                    f"Password reset at {reset_url} returns different response sizes "
                    f"for existing vs. non-existing accounts "
                    f"({len(resp2)} vs {len(resp1)} chars). "
                    "Attackers can enumerate valid email addresses."
                ),
                reproduction_steps=[
                    f"POST {reset_url} email=nonexistent@test.com → {len(resp1)} chars",
                    f"POST {reset_url} email=admin@example.com → {len(resp2)} chars",
                ],
                remediation="Return identical response for existing and non-existing accounts.",
                references=["CWE-204", "OWASP Testing OTG-IDENT-004"],
                evidence=ev,
                cvss_v31_vector=CVSS_ENUM,
                target=target,
                url=reset_url,
            )

    async def _test_token_entropy(self, reset_url: str, target: str) -> None:
        """Check if reset tokens appear in the response (wrong) or are weak."""
        resp = await self._post_reset(reset_url, "test@example.com")
        if not resp:
            return

        # Look for token-like strings in the response
        token_pattern = re.compile(
            r'(?:token|reset|key)["\s=:]+([a-zA-Z0-9_\-]{8,})', re.IGNORECASE
        )
        tokens = token_pattern.findall(resp)

        if tokens:
            # Token exposed in response body!
            ev = Evidence(
                response_raw=resp[:500],
                extra={"tokens_found_in_body": tokens[:3]},
            )
            self.new_finding(
                title="Password Reset — Token Exposed in Response Body",
                severity=Severity.CRITICAL,
                description=(
                    f"Password reset token(s) found in response body at {reset_url}. "
                    "Tokens should only be sent via email, never returned in HTTP response."
                ),
                reproduction_steps=[
                    f"POST {reset_url} email=victim@example.com",
                    "Token visible in JSON response",
                ],
                remediation=(
                    "Never return reset tokens in HTTP responses. "
                    "Send tokens only via email. "
                    "Use cryptographically random tokens (256+ bits)."
                ),
                references=["CWE-640"],
                evidence=ev,
                cvss_v31_vector=CVSS_RESET_TOKEN,
                target=target,
                url=reset_url,
            )

        # Check for weak token patterns (md5, timestamps)
        weak_patterns = [
            (r'\b[0-9a-f]{32}\b', "MD5-like token"),
            (r'\b\d{10}\b', "Unix timestamp"),
            (r'\b\d{13}\b', "Unix millisecond timestamp"),
        ]
        for pattern, name in weak_patterns:
            if re.search(pattern, resp):
                self.new_finding(
                    title=f"Password Reset — Weak Token Pattern ({name})",
                    severity=Severity.HIGH,
                    description=(
                        f"Response from {reset_url} contains a {name} pattern. "
                        "Predictable reset tokens can be brute-forced."
                    ),
                    reproduction_steps=[f"POST {reset_url} and inspect response"],
                    remediation="Use cryptographically random tokens (os.urandom(32), secrets module).",
                    references=["CWE-330"],
                    evidence=Evidence(response_raw=resp[:300], extra={"pattern": name}),
                    cvss_v31_vector=CVSS_RESET_TOKEN,
                    target=target,
                    url=reset_url,
                )
                break

    async def _test_host_header_poisoning(self, reset_url: str, target: str) -> None:
        """Already covered in host_header_inject — provide guidance finding here."""
        pass  # Covered by host_header_inject module

    async def _test_token_reuse(self, reset_url: str, target: str) -> None:
        """Test if old reset links still work (no expiry/single-use enforcement)."""
        # This is a manual test — document as guidance finding
        ev = Evidence(
            extra={
                "reset_url": reset_url,
                "test_type": "token_reuse_guidance",
            }
        )
        self.new_finding(
            title=f"Password Reset — Verify Token Expiry and Single-Use ({reset_url.split('/')[-1]})",
            severity=Severity.INFORMATIONAL,
            description=(
                f"Password reset endpoint found at {reset_url}. "
                "Manually verify:\n"
                "1. Request a reset link\n"
                "2. Use the link to reset password\n"
                "3. Try using the same link again — it should fail\n"
                "4. Request a new link, wait >15 min, try using old link — should fail\n"
                "Both tests should return 'invalid or expired token'."
            ),
            reproduction_steps=[
                f"Request reset, use token, reuse same token — expect failure",
                f"Request reset, wait >15 min, try token — expect expired",
            ],
            remediation=(
                "Implement single-use tokens (mark as used after first redemption). "
                "Implement token expiry (15-60 minutes). "
                "Invalidate all existing tokens when new one is requested."
            ),
            references=["CWE-640", "OWASP A07:2021"],
            evidence=ev,
            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            target=target,
            url=reset_url,
        )

    async def _post_reset(self, url: str, email: str) -> str | None:
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.post(
                    url,
                    data={"email": email},
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    return await resp.text(errors="ignore")
        except Exception:
            return None


class TestAccountTakeover:
    def test_reset_paths_not_empty(self) -> None:
        assert len(RESET_PATHS) >= 5

    def test_cvss_vectors(self) -> None:
        assert CVSS_RESET_TOKEN.startswith("CVSS:3.1")
        assert CVSS_ENUM.startswith("CVSS:3.1")
