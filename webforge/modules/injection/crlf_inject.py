"""CRLF injection scanner — detect HTTP response splitting via CRLF in headers."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CRLF = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

CANARY_HEADER = "X-CRLF-Test"
CANARY_VALUE  = "ForgeCRLFTest"

CRLF_PAYLOADS = [
    f"\r\n{CANARY_HEADER}: {CANARY_VALUE}",
    f"%0d%0a{CANARY_HEADER}:%20{CANARY_VALUE}",
    f"%0D%0A{CANARY_HEADER}:%20{CANARY_VALUE}",
    f"%0d%0a{CANARY_HEADER}:{CANARY_VALUE}",
    f"\r\n\t{CANARY_HEADER}: {CANARY_VALUE}",
    f"%E5%98%8A%E5%98%8D{CANARY_HEADER}: {CANARY_VALUE}",  # Unicode CRLF
    f"%C0%8D%C0%8A{CANARY_HEADER}: {CANARY_VALUE}",        # Overlong encoding
]


class CrlfInject(BaseModule):
    """CRLF injection (HTTP response splitting) scanner."""

    NAME        = "crlf_inject"
    DESCRIPTION = "Detect CRLF injection / HTTP response splitting in redirect parameters"
    PHASE       = 4
    TAGS        = ["injection", "crlf", "http-splitting", "cwe-93", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Test redirect/location parameters (most common CRLF vectors)
        test_urls = self._build_test_urls(target)
        crawled   = self.config.extra.get("crawled_urls", [])

        # Add crawled URLs with redirect-style params
        for url in crawled[:50]:
            if any(kw in url.lower() for kw in
                   ["redirect", "next", "return", "url=", "goto=", "location=", "ref="]):
                test_urls.append(url)

        self.log.info("Testing %d URL(s) for CRLF injection", len(test_urls))

        sem = asyncio.Semaphore(3)
        tasks = [self._test_url(url, target, sem) for url in test_urls[:30]]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    def _build_test_urls(self, target: str) -> list[str]:
        redirect_params = ["redirect", "next", "return", "url", "goto", "location",
                           "ref", "back", "target", "redir", "returnTo", "returnUrl"]
        urls = []
        for param in redirect_params:
            urls.append(f"{target}?{param}=https://example.com")
        return urls

    async def _test_url(self, url: str, target: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                # No params in URL — inject into path or try standard redirect paths
                for path in ["/redirect", "/login", "/logout", "/auth"]:
                    test = f"{target}{path}"
                    await self._probe_url(test, "url", "https://example.com", target)
                return

            for param_name, values in params.items():
                original = values[0] if values else ""
                for payload in CRLF_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = original + payload
                    test_url = (
                        f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        f"?{urlencode(test_params)}"
                    )
                    found = await self._probe_url(test_url, param_name, payload, target)
                    if found:
                        return

    async def _probe_url(
        self, url: str, param_name: str, payload: str, target: str
    ) -> bool:
        if not self.check_scope(url):
            return False
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=8),
                    headers={"User-Agent": "Mozilla/5.0"},
                ) as resp:
                    # Check if injected header appears in response
                    if CANARY_HEADER.lower() in str(resp.headers).lower() or \
                       CANARY_VALUE in str(resp.headers).values():
                        ev = Evidence(
                            request_raw=f"GET {url}",
                            response_raw=str(dict(resp.headers)),
                            extra={
                                "param":   param_name,
                                "payload": payload[:60],
                                "injected_header": CANARY_HEADER,
                            },
                        )
                        self.new_finding(
                            title=f"CRLF Injection — HTTP Response Splitting ({param_name})",
                            severity=Severity.HIGH,
                            description=(
                                f"CRLF injection confirmed in parameter '{param_name}'. "
                                f"Injected header '{CANARY_HEADER}' appears in the HTTP response. "
                                "An attacker can inject arbitrary HTTP headers, enabling:\n"
                                "- XSS via header injection\n"
                                "- Session fixation\n"
                                "- Cache poisoning"
                            ),
                            reproduction_steps=[
                                f"curl -v '{url}' 2>&1 | grep -i {CANARY_HEADER}",
                                f"Payload: {payload[:60]}",
                            ],
                            remediation=(
                                "Strip or encode CR (\\r) and LF (\\n) characters from all "
                                "user input used in HTTP response headers. "
                                "Most web frameworks do this automatically — verify framework config."
                            ),
                            references=["CWE-93", "CWE-113", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_CRLF,
                            mitre_attack=["TA0001/T1190"],
                            target=target,
                            url=url,
                        )
                        return True

                    # Also check Location header if it's a redirect
                    if resp.status in (301, 302, 307, 308):
                        location = resp.headers.get("Location", "")
                        if CANARY_HEADER in location or CANARY_VALUE in location:
                            ev = Evidence(
                                request_raw=f"GET {url}",
                                response_raw=f"Location: {location}",
                                extra={"param": param_name, "payload": payload[:60]},
                            )
                            self.new_finding(
                                title=f"CRLF Injection in Redirect Location ({param_name})",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"CRLF in Location header via parameter '{param_name}'. "
                                    "Injected content appears in redirect URL."
                                ),
                                reproduction_steps=[f"curl -v '{url}'"],
                                remediation="Validate/encode redirect URLs before writing to Location header.",
                                references=["CWE-93"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_CRLF,
                                target=target,
                                url=url,
                            )
                            return True
        except Exception:
            pass
        return False


class TestCrlfInject:
    def test_payloads_not_empty(self) -> None:
        assert len(CRLF_PAYLOADS) >= 4

    def test_canary_values(self) -> None:
        assert CANARY_HEADER
        assert CANARY_VALUE
        # Encoded payloads should contain %0d%0a or raw CRLF
        assert any("%0d%0a" in p.lower() or "\r\n" in p for p in CRLF_PAYLOADS)
