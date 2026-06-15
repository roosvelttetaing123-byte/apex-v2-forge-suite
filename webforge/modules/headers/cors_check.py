"""CORS misconfiguration checker — detect overly permissive CORS policies."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CORS_CRED   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
CVSS_CORS_WILDCARD = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"

EVIL_ORIGINS = [
    "https://evil.example.com",
    "null",
    "https://attacker.io",
    "https://subdomain.evil.example.com",
]

# Common CMS/API sub-paths to probe when a backend is detected
CMS_API_PROBE_PATHS = [
    "/api/",
    "/api/v1/",
    "/cms/api/",
    "/strapi/api/",
    "/graphql",
]


class CorsCheck(BaseModule):
    """CORS misconfiguration detector."""

    NAME        = "cors_check"
    DESCRIPTION = "Detect CORS misconfigurations: wildcard, null origin, credential leakage"
    PHASE       = 3
    TAGS        = ["headers", "cors", "owasp-a05", "cwe-942"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        urls_to_test = [target] + self.config.extra.get("api_base_paths", [])[:5]

        # Also probe standard CMS/API sub-paths on the base target that
        # js_analyzer may not have found (e.g. when running standalone)
        from urllib.parse import urlparse
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in CMS_API_PROBE_PATHS:
            candidate = f"{base}{path}"
            if candidate not in urls_to_test:
                urls_to_test.append(candidate)

        seen: set[str] = set()
        for url in urls_to_test:
            if url in seen:
                continue
            seen.add(url)
            await self.rate_limit()
            await self._test_cors(url)

        return self._make_result(start)

    async def _test_cors(self, url: str) -> None:
        import aiohttp

        for origin in EVIL_ORIGINS:
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url,
                        headers={
                            "Origin": origin,
                            "User-Agent": "Mozilla/5.0",
                        },
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=False,
                    ) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "false").lower()
                        acam = resp.headers.get("Access-Control-Allow-Methods", "")

                        if not acao:
                            continue

                        # Wildcard
                        if acao == "*":
                            ev = Evidence(
                                request_raw=f"GET {url}\nOrigin: {origin}",
                                response_raw=(
                                    f"Access-Control-Allow-Origin: {acao}\n"
                                    f"Access-Control-Allow-Methods: {acam}"
                                ),
                                extra={"acao": acao, "acac": acac, "origin_sent": origin},
                            )
                            self.new_finding(
                                title=f"CORS Wildcard Origin — {url}",
                                severity=Severity.LOW,
                                description=(
                                    f"CORS policy at {url} allows all origins (*). "
                                    "While not immediately exploitable without credentials, "
                                    "any website can read responses from this endpoint."
                                ),
                                reproduction_steps=[
                                    f"curl -H 'Origin: https://evil.com' {url} -I | grep -i cors",
                                ],
                                remediation=(
                                    "Replace wildcard ACAO with a specific allowlist of trusted origins. "
                                    "Do not combine '*' with 'Access-Control-Allow-Credentials: true'."
                                ),
                                references=["CWE-942", "OWASP CORS Cheat Sheet"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_CORS_WILDCARD,
                                target=self.config.target,
                                url=url,
                            )

                        # Reflected origin (mirrors whatever we send)
                        elif acao == origin or (origin.lower() == "null" and acao == "null"):
                            if acac == "true":
                                # Critical: reflected origin + credentials
                                ev = Evidence(
                                    request_raw=f"GET {url}\nOrigin: {origin}",
                                    response_raw=(
                                        f"Access-Control-Allow-Origin: {acao}\n"
                                        f"Access-Control-Allow-Credentials: {acac}"
                                    ),
                                    extra={"acao": acao, "acac": acac, "origin_sent": origin},
                                )
                                ev.screenshot_path = await self.capture_screenshot(
                                    url, finding_id=f"cors_{url.replace('https://','').replace('/','_')}"
                                )
                                self.new_finding(
                                    title=f"CORS — Reflected Origin with Credentials ({url})",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"CORS policy at {url} reflects the attacker-controlled origin "
                                        f"'{origin}' and sets Access-Control-Allow-Credentials: true. "
                                        "A malicious website can send cross-origin requests WITH session cookies "
                                        "and read the response — full account takeover possible."
                                    ),
                                    reproduction_steps=[
                                        f"curl -H 'Origin: {origin}' -H 'Cookie: session=victim_token' {url}",
                                        "The response includes ACAO: {origin} + ACAC: true",
                                        "Malicious JS can read authenticated responses",
                                    ],
                                    remediation=(
                                        "Validate the Origin header against a strict allowlist. "
                                        "Never reflect arbitrary Origins. "
                                        "Never combine 'Access-Control-Allow-Credentials: true' "
                                        "with dynamic/reflective ACAO."
                                    ),
                                    references=["CWE-942", "MITRE T1557"],
                                    evidence=ev,
                                    cvss_v31_vector=CVSS_CORS_CRED,
                                    mitre_attack=["TA0009/T1557"],
                                    target=self.config.target,
                                    url=url,
                                )
                            else:
                                ev = Evidence(
                                    request_raw=f"GET {url}\nOrigin: {origin}",
                                    response_raw=f"Access-Control-Allow-Origin: {acao}",
                                    extra={"acao": acao, "origin_sent": origin},
                                )
                                self.new_finding(
                                    title=f"CORS — Origin Reflection Detected ({url})",
                                    severity=Severity.MEDIUM,
                                    description=(
                                        f"CORS policy reflects the sent Origin header ({origin}). "
                                        "Without credentials, impact is limited, but this is a misconfiguration."
                                    ),
                                    reproduction_steps=[
                                        f"curl -H 'Origin: https://evil.com' {url} -I | grep ACAO",
                                    ],
                                    remediation="Validate Origin against a strict allowlist.",
                                    references=["CWE-942"],
                                    evidence=ev,
                                    cvss_v31_vector=CVSS_CORS_WILDCARD,
                                    target=self.config.target,
                                    url=url,
                                )
            except Exception:
                pass


class TestCorsCheck:
    def test_evil_origins_list(self) -> None:
        assert "null" in EVIL_ORIGINS
        assert any("evil" in o for o in EVIL_ORIGINS)

    def test_cvss_vectors_defined(self) -> None:
        assert CVSS_CORS_CRED.startswith("CVSS:3.1")
        assert CVSS_CORS_WILDCARD.startswith("CVSS:3.1")
