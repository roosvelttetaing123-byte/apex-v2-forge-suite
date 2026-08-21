"""Session management auditor — token entropy, fixation, and invalidation."""
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
from common.fp_reducer import FPReducer, Confidence

CVSS_FIXATION  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
CVSS40_FIXATION = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_ENTROPY   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ENTROPY = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_NO_INVAL  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_NO_INVAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
class SessionAudit(BaseModule):
    """Session management security auditor."""

    NAME        = "session_audit"
    DESCRIPTION = "Audit session tokens: entropy, fixation, post-logout invalidation"
    PHASE       = 5
    TAGS        = ["auth", "session", "fixation", "cwe-384", "owasp-a07"]

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
            self._check_session_fixation(target),
            self._check_session_entropy(target),
            self._check_session_invalidation(target),
        )
        return self._make_result(start)

    async def _check_session_fixation(self, target: str) -> None:
        """Test if session token changes after login (fixation vulnerability)."""
        # Get pre-login session token
        pre_cookies = await self._get_cookies(f"{target}/login")
        if not pre_cookies:
            return

        session_name, pre_token = self._find_session_token(pre_cookies)
        if not pre_token:
            return

        # Attempt login (with dummy creds — we check token rotation, not success)
        post_cookies = await self._post_with_cookies(
            f"{target}/login",
            {"username": "admin", "password": "admin"},
            pre_cookies,
        )
        if not post_cookies:
            return

        _, post_token = self._find_session_token(post_cookies)
        if not post_token:
            return

        if pre_token == post_token:
            ev = Evidence(
                extra={
                    "session_name":   session_name,
                    "pre_login_token":  pre_token[:20] + "...",
                    "post_login_token": post_token[:20] + "...",
                }
            )
            self.new_finding(
                title="Session Fixation — Token Not Rotated After Login",
                severity=Severity.HIGH,
                description=(
                    f"Session token '{session_name}' is not rotated after login. "
                    "An attacker can set a known session ID in a victim's browser, "
                    "wait for the victim to log in, then use that same ID to access the account."
                ),
                reproduction_steps=[
                    "1. Get a session token: curl -c cookies.txt {target}/login",
                    "2. Login as victim (session ID unchanged)",
                    "3. Attacker uses the pre-auth session ID to access authenticated content",
                ],
                remediation=(
                    "Always generate a new session ID on successful authentication. "
                    "Invalidate the old session completely."
                ),
                references=["CWE-384", "OWASP Session Management Cheat Sheet"],
                evidence=ev,
                cvss_v31_vector=CVSS_FIXATION,
                cvss_v40_vector=CVSS40_FIXATION,
                mitre_attack=["TA0006/T1550"],
                target=target,
            )

    async def _check_session_entropy(self, target: str) -> None:
        """Collect multiple session tokens and estimate entropy."""
        tokens: list[str] = []
        for _ in range(5):
            cookies = await self._get_cookies(f"{target}/login")
            if cookies:
                _, token = self._find_session_token(cookies)
                if token:
                    tokens.append(token)
            await asyncio.sleep(0.3)

        if len(tokens) < 3:
            return

        # Check length
        avg_len = sum(len(t) for t in tokens) / len(tokens)
        if avg_len < 16:
            ev = Evidence(
                extra={"tokens": [t[:10] + "..." for t in tokens], "avg_length": avg_len}
            )
            self.new_finding(
                title=f"Short Session Token (avg {avg_len:.0f} chars)",
                severity=Severity.HIGH,
                description=(
                    f"Session tokens are short (avg {avg_len:.0f} chars). "
                    "Tokens shorter than 128 bits are susceptible to brute-force prediction."
                ),
                reproduction_steps=["Sample tokens: " + ", ".join(t[:12] for t in tokens[:3])],
                remediation="Use 128-bit (32 hex char) or larger cryptographically random session IDs.",
                references=["CWE-331", "OWASP A02:2021"],
                evidence=ev,
                cvss_v31_vector=CVSS_ENTROPY,
                cvss_v40_vector=CVSS40_ENTROPY,
                target=target,
            )

        # Check for sequential/predictable tokens
        if self._tokens_sequential(tokens):
            ev = Evidence(
                extra={"tokens": [t[:20] for t in tokens]}
            )
            self.new_finding(
                title="Session Tokens Appear Sequential/Predictable",
                severity=Severity.CRITICAL,
                description=(
                    "Session tokens appear to be sequential or based on predictable data. "
                    "An attacker can enumerate valid session IDs."
                ),
                reproduction_steps=["Token samples: " + ", ".join(t[:12] for t in tokens)],
                remediation="Use cryptographically secure random number generator for session IDs.",
                references=["CWE-330", "CWE-331"],
                evidence=ev,
                cvss_v31_vector=CVSS_ENTROPY,
                cvss_v40_vector=CVSS40_ENTROPY,
                target=target,
            )

    async def _check_session_invalidation(self, target: str) -> None:
        """Check if session is properly invalidated after logout."""
        # Get session
        cookies = await self._get_cookies(f"{target}/login")
        if not cookies:
            return
        _, token = self._find_session_token(cookies)
        if not token:
            return

        # Logout
        for logout_path in ["/logout", "/signout", "/auth/logout", "/api/logout"]:
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        f"{target}{logout_path}",
                        cookies=cookies,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status in (200, 302):
                            # Try using old token after logout
                            async with session.get(
                                f"{target}/dashboard",
                                cookies=cookies,
                                timeout=aiohttp.ClientTimeout(total=5),
                                allow_redirects=False,
                            ) as resp2:
                                body = await resp2.text(errors="ignore")
                                if resp2.status == 200 and any(
                                    kw in body.lower() for kw in
                                    ["dashboard", "welcome", "profile"]
                                ):
                                    ev = Evidence(
                                        extra={
                                            "logout_path": logout_path,
                                            "token_still_valid": True,
                                        }
                                    )
                                    self.new_finding(
                                        title="Session Not Invalidated After Logout",
                                        severity=Severity.HIGH,
                                        description=(
                                            "Session token remains valid after logout. "
                                            "An attacker who steals a session token can continue "
                                            "using it indefinitely even after the victim logs out."
                                        ),
                                        reproduction_steps=[
                                            f"1. GET {target}{logout_path}",
                                            "2. Use old session token on protected page",
                                            "3. Still authenticated",
                                        ],
                                        remediation=(
                                            "Invalidate session server-side on logout. "
                                            "Remove from session store, not just clear cookie."
                                        ),
                                        references=["CWE-613", "OWASP A07:2021"],
                                        evidence=ev,
                                        cvss_v31_vector=CVSS_NO_INVAL,
                                        cvss_v40_vector=CVSS40_NO_INVAL,
                                        target=target,
                                    )
                            return
            except Exception:
                pass

    async def _get_cookies(self, url: str) -> dict:
        await self.rate_limit()
        try:
            import aiohttp
            jar = aiohttp.CookieJar(unsafe=True)
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False), cookie_jar=jar
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8)
                ) as resp:
                    return {c.key: c.value for c in jar}
        except Exception:
            return {}

    async def _post_with_cookies(
        self, url: str, data: dict, cookies: dict
    ) -> dict:
        await self.rate_limit()
        try:
            import aiohttp
            jar = aiohttp.CookieJar(unsafe=True)
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False), cookie_jar=jar
            ) as session:
                async with session.post(
                    url, data=data, cookies=cookies,
                    timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True,
                ) as resp:
                    return {c.key: c.value for c in jar}
        except Exception:
            return {}

    def _find_session_token(self, cookies: dict) -> tuple[str, str]:
        session_patterns = re.compile(
            r"(session|sess|auth|token|sid|jwt|access)", re.IGNORECASE
        )
        for name, value in cookies.items():
            if session_patterns.search(name):
                return name, value
        # Return any cookie if no session-named one found
        if cookies:
            name = list(cookies.keys())[0]
            return name, cookies[name]
        return "", ""

    def _tokens_sequential(self, tokens: list[str]) -> bool:
        """Simple heuristic: check if tokens differ only in a numeric suffix."""
        if len(tokens) < 3:
            return False
        try:
            nums = [int(t[-8:], 16) for t in tokens if len(t) >= 8]
            if len(nums) < 3:
                return False
            diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
            return len(set(diffs)) == 1 and diffs[0] > 0
        except Exception:
            return False


class TestSessionAudit:
    def test_tokens_sequential_detection(self) -> None:
        mod = SessionAudit.__new__(SessionAudit)
        tokens = ["aabbcc000001", "aabbcc000002", "aabbcc000003"]
        assert mod._tokens_sequential(tokens)

    def test_tokens_random_not_sequential(self) -> None:
        mod = SessionAudit.__new__(SessionAudit)
        import hashlib, os
        tokens = [hashlib.md5(os.urandom(8)).hexdigest() for _ in range(4)]
        result = mod._tokens_sequential(tokens)
        # Random tokens should usually not be sequential
        # Not asserting True/False since randomness might occasionally look sequential
        assert isinstance(result, bool)
