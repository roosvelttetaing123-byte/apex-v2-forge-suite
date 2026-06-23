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
CVSS40_CORS_CRED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_CORS_WILDCARD = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
CVSS40_CORS_WILDCARD = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
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

        # Detect SPA catch-all routing — all probe paths on a Vercel/Netlify SPA
        # will return the same index.html with the platform-level CORS wildcard.
        # We still test them, but group into ONE finding instead of one per path.
        spa_fp = await self._spa_fingerprint(target)

        from urllib.parse import urlparse
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        urls_to_test = [target] + self.config.extra.get("api_base_paths", [])[:5]
        for path in CMS_API_PROBE_PATHS:
            candidate = f"{base}{path}"
            if candidate not in urls_to_test:
                urls_to_test.append(candidate)

        # Accumulate wildcard URLs → emit ONE consolidated finding at the end
        self._wildcard_urls: list[str] = []
        self._wildcard_spa_paths: list[str] = []   # paths that are SPA catch-all
        self._wildcard_real_paths: list[str] = []  # paths that are real endpoints

        seen: set[str] = set()
        for url in urls_to_test:
            if url in seen:
                continue
            seen.add(url)
            await self.rate_limit()
            await self._test_cors(url, spa_fp)

        # Emit one grouped finding for wildcard CORS instead of one per URL/origin
        if self._wildcard_urls:
            self._emit_wildcard_finding(target)

        return self._make_result(start)

    async def _test_cors(self, url: str, spa_fp: str | None) -> None:
        """Test CORS for one URL. Wildcard hits are accumulated, not immediately emitted."""
        import aiohttp

        # Probe with first origin to determine policy type; wildcard is binary
        # so we only need one probe — no point repeating with 4 origins.
        probe_origin = EVIL_ORIGINS[0]
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url,
                    headers={"Origin": probe_origin, "User-Agent": "Mozilla/5.0"},
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                ) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "false").lower()
                    body = await resp.text(errors="ignore")
        except Exception:
            return

        if not acao:
            return

        is_spa_path = spa_fp is not None and self._is_spa_body(body, spa_fp)

        if acao == "*":
            # Accumulate — emit ONE consolidated finding after all URLs are tested
            self._wildcard_urls.append(url)
            if is_spa_path:
                self._wildcard_spa_paths.append(url)
            else:
                self._wildcard_real_paths.append(url)
            return

        # Reflected origin — test all evil origins, emit one finding per URL
        for origin in EVIL_ORIGINS:
            if origin == probe_origin:
                acao_this, acac_this = acao, acac
            else:
                try:
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            url,
                            headers={"Origin": origin, "User-Agent": "Mozilla/5.0"},
                            timeout=aiohttp.ClientTimeout(total=8),
                            allow_redirects=False,
                        ) as resp2:
                            acao_this = resp2.headers.get("Access-Control-Allow-Origin", "")
                            acac_this = resp2.headers.get(
                                "Access-Control-Allow-Credentials", "false"
                            ).lower()
                except Exception:
                    continue

            is_reflected = acao_this == origin or (
                origin.lower() == "null" and acao_this == "null"
            )
            if not is_reflected:
                continue

            if acac_this == "true":
                ev = Evidence(
                    request_raw=f"GET {url}\nOrigin: {origin}",
                    response_raw=(
                        f"Access-Control-Allow-Origin: {acao_this}\n"
                        f"Access-Control-Allow-Credentials: {acac_this}"
                    ),
                    extra={"acao": acao_this, "acac": acac_this, "origin_sent": origin},
                )
                ev.screenshot_path = self.capture_screenshot(
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
                        f"The response includes ACAO: {origin} + ACAC: true",
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
                    cvss_v40_vector=CVSS40_CORS_CRED,
                    mitre_attack=["TA0009/T1557"],
                    target=self.config.target,
                    url=url,
                )
            else:
                ev = Evidence(
                    request_raw=f"GET {url}\nOrigin: {origin}",
                    response_raw=f"Access-Control-Allow-Origin: {acao_this}",
                    extra={"acao": acao_this, "origin_sent": origin},
                )
                self.new_finding(
                    title=f"CORS — Origin Reflection Detected ({url})",
                    severity=Severity.MEDIUM,
                    description=(
                        f"CORS policy at {url} reflects the sent Origin header ({origin}). "
                        "Without credentials, impact is limited, but this is a misconfiguration."
                    ),
                    reproduction_steps=[
                        f"curl -H 'Origin: https://evil.com' {url} -I | grep ACAO",
                    ],
                    remediation="Validate Origin against a strict allowlist.",
                    references=["CWE-942"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CORS_WILDCARD,
                    cvss_v40_vector=CVSS40_CORS_WILDCARD,
                    target=self.config.target,
                    url=url,
                )
            return  # one finding per URL regardless of how many origins reflect

    def _emit_wildcard_finding(self, target: str) -> None:
        """Emit ONE consolidated finding for all URLs that returned ACAO: *."""
        real = self._wildcard_real_paths
        spa  = self._wildcard_spa_paths
        all_urls = self._wildcard_urls

        url_list = "\n".join(f"  • {u}" for u in all_urls)

        if spa and not real:
            spa_note = (
                "\n\nNote: All confirmed paths are Vercel SPA catch-all routes. "
                "The wildcard CORS is a platform-level default, not an app-specific policy. "
                "No sensitive authenticated data is served from these paths."
            )
        elif spa and real:
            spa_note = (
                f"\n\nNote: {len(spa)} of the above path(s) are SPA catch-all routes "
                "(Vercel platform default). The remaining {len(real)} path(s) are real endpoints."
            )
        else:
            spa_note = ""

        representative_url = real[0] if real else all_urls[0]
        ev = Evidence(
            request_raw=f"GET {representative_url}\nOrigin: https://evil.example.com",
            response_raw="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Methods: ",
            extra={"wildcard_urls": all_urls, "real_endpoints": real, "spa_paths": spa},
        )
        self.new_finding(
            title=f"CORS Wildcard Origin — {target} ({len(all_urls)} URL(s) confirmed)",
            severity=Severity.LOW,
            description=(
                f"CORS policy returns 'Access-Control-Allow-Origin: *' for {len(all_urls)} URL(s). "
                "Any website can read responses from these endpoints without credentials.\n\n"
                f"Affected URLs:\n{url_list}"
                f"{spa_note}"
            ),
            reproduction_steps=[
                f"curl -H 'Origin: https://evil.com' {representative_url} -I | grep -i cors",
                "Observe: Access-Control-Allow-Origin: *",
            ],
            remediation=(
                "Replace the wildcard ACAO with a specific allowlist of trusted origins. "
                "Do not combine '*' with 'Access-Control-Allow-Credentials: true'. "
                "For static SPAs, the Vercel platform-level wildcard is generally acceptable "
                "since no sensitive data is served without authentication."
            ),
            references=["CWE-942", "OWASP CORS Cheat Sheet"],
            evidence=ev,
            cvss_v31_vector=CVSS_CORS_WILDCARD,
            cvss_v40_vector=CVSS40_CORS_WILDCARD,
            target=target,
            url=representative_url,
        )


class TestCorsCheck:
    def test_evil_origins_list(self) -> None:
        assert "null" in EVIL_ORIGINS
        assert any("evil" in o for o in EVIL_ORIGINS)

    def test_cvss_vectors_defined(self) -> None:
        assert CVSS_CORS_CRED.startswith("CVSS:3.1")
        assert CVSS_CORS_WILDCARD.startswith("CVSS:3.1")
