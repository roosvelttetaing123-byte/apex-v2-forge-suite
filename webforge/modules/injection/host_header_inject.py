"""Host header injection scanner — password reset poisoning, cache poisoning vectors."""
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

CVSS_HOST_INJECT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
CVSS40_HOST_INJECT = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
EVIL_HOST = "evil.forge-test.local"

# Secondary host header names to try
HEADER_VARIANTS = [
    "Host",
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
]


class HostHeaderInject(BaseModule):
    """Host header injection scanner."""

    NAME        = "host_header_inject"
    DESCRIPTION = "Detect Host header injection for password reset poisoning and SSRF"
    PHASE       = 4
    TAGS        = ["injection", "host-header", "password-reset", "cache-poison", "cwe-20"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Testing host header injection on %s", target)
        # Initialise FPReducer for false-positive verification
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        # Test all crawled URLs, not just target
        urls_to_test = self.config.extra.get("crawled_urls", [target])[:10]
        if target not in urls_to_test:
            urls_to_test.insert(0, target)
        tasks = []
        for url in urls_to_test:
            tasks.append(self._test_host_reflection(url))
        tasks.append(self._test_password_reset_poisoning(target))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._make_result(start)

    async def _test_host_reflection(self, target: str) -> None:
        """Check if injected Host is reflected in response body/headers."""
        for header_name in HEADER_VARIANTS:
            await self.rate_limit()
            try:
                import aiohttp
                headers = {"User-Agent": "Mozilla/5.0"}
                if header_name == "Host":
                    headers["Host"] = EVIL_HOST
                elif header_name == "Forwarded":
                    headers["Forwarded"] = f"host={EVIL_HOST}"
                else:
                    headers[header_name] = EVIL_HOST

                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        target,
                        headers=headers,
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        response_headers = str(dict(resp.headers))

                # Check if evil host is reflected in body or response headers
                if EVIL_HOST in body:
                    ev = Evidence(
                        request_raw=f"GET {target}\n{header_name}: {EVIL_HOST}",
                        response_raw=body[max(0, body.index(EVIL_HOST)-100):
                                          body.index(EVIL_HOST)+100],
                        extra={
                            "header":      header_name,
                            "evil_host":   EVIL_HOST,
                            "reflected_in": "response body",
                        },
                    )
                    self.new_finding(
                        title=f"Host Header Injection — {header_name} Reflected in Body",
                        severity=Severity.HIGH,
                        description=(
                            f"Injected value '{EVIL_HOST}' via '{header_name}' header "
                            f"is reflected in the response body. "
                            "This enables:\n"
                            "- Password reset link poisoning (send victim's reset email with attacker's domain)\n"
                            "- Web cache poisoning if response is cached\n"
                            "- SSRF in password reset flows"
                        ),
                        reproduction_steps=[
                            f"curl -H '{header_name}: {EVIL_HOST}' {target}",
                            "Look for evil.forge-test.local in the response body",
                        ],
                        remediation=(
                            "Validate the Host header against an allowlist of trusted hostnames. "
                            "Never use the Host header value directly in link generation. "
                            "Use server-side configuration for absolute URL generation."
                        ),
                        references=["CWE-20", "PortSwigger Host Header Injection"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_HOST_INJECT,
                        cvss_v40_vector=CVSS40_HOST_INJECT,
                        mitre_attack=["TA0001/T1190"],
                        target=target,
                        url=target,
                    )
                    break  # One finding per test is enough

            except Exception:
                pass

    async def _test_password_reset_poisoning(self, target: str) -> None:
        """Test password reset endpoints for host header poisoning."""
        reset_paths = [
            "/forgot-password", "/password-reset", "/reset-password",
            "/account/forgot", "/user/reset", "/auth/forgot-password",
            "/api/forgot-password", "/api/reset-password",
        ]

        for path in reset_paths:
            await self.rate_limit()
            url = f"{target}{path}"
            try:
                import aiohttp
                # GET to see if page exists
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status not in (200, 405):
                            continue

                # POST with evil host
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    for header_name in ["X-Forwarded-Host", "Host"]:
                        headers = {
                            "User-Agent": "Mozilla/5.0",
                            header_name: EVIL_HOST,
                        }
                        async with session.post(
                            url,
                            data={"email": "test@example.com"},
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=8),
                            allow_redirects=True,
                        ) as resp:
                            body = await resp.text(errors="ignore")

                        if EVIL_HOST in body or resp.status == 200:
                            if EVIL_HOST in body:
                                ev = Evidence(
                                    request_raw=f"POST {url}\n{header_name}: {EVIL_HOST}\nemail=test@example.com",
                                    response_raw=body[:500],
                                    extra={"path": path, "header": header_name},
                                )
                                self.new_finding(
                                    title=f"Password Reset Poisoning via {header_name} — {path}",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"Password reset at {url} reflects the injected "
                                        f"'{header_name}: {EVIL_HOST}' in the response. "
                                        "An attacker can request a reset for victim's account "
                                        "with attacker's domain — reset link goes to attacker."
                                    ),
                                    reproduction_steps=[
                                        f"curl -X POST {url} \\",
                                        f"  -H '{header_name}: attacker.com' \\",
                                        "  -d 'email=victim@example.com'",
                                        "Victim's reset email will contain attacker.com link",
                                    ],
                                    remediation=(
                                        "Never trust the Host header for link generation in emails. "
                                        "Hardcode the application's canonical domain in server config."
                                    ),
                                    references=["CWE-20", "PortSwigger Password Reset Poisoning"],
                                    evidence=ev,
                                    cvss_v31_vector=CVSS_HOST_INJECT,
                                    cvss_v40_vector=CVSS40_HOST_INJECT,
                                    target=target,
                                    url=url,
                                )
                                return
            except Exception:
                pass


class TestHostHeaderInject:
    def test_evil_host_defined(self) -> None:
        assert EVIL_HOST
        assert "." in EVIL_HOST

    def test_header_variants(self) -> None:
        assert "Host" in HEADER_VARIANTS
        assert "X-Forwarded-Host" in HEADER_VARIANTS
