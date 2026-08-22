"""HSTS policy checker — verify HSTS header strength and preload eligibility."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

CVSS_NO_HSTS   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
CVSS40_NO_HSTS = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_WEAK_HSTS = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"
CVSS40_WEAK_HSTS = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
MIN_MAX_AGE    = 31536000  # 1 year in seconds


class HstsCheck(BaseModule):
    """HSTS header strength validator."""

    NAME        = "hsts_check"
    DESCRIPTION = "Verify HSTS: presence, max-age >= 1yr, includeSubDomains, preload, HTTP redirect"
    PHASE       = 2
    TAGS        = ["ssl", "hsts", "headers", "cwe-319"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        from urllib.parse import urlparse
        parsed = urlparse(target)
        https_target = target
        http_target  = target

        if parsed.scheme == "http":
            https_target = target.replace("http://", "https://", 1)
        else:
            http_target = target.replace("https://", "http://", 1)

        self.log.info("Checking HSTS on %s", https_target)
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        # Always check HTTPS for HSTS header
        headers = await self._fetch_headers(https_target)
        if not headers:
            self.log.warning("Could not fetch headers from %s", https_target)
            return self._make_result(start)

        hsts_value = headers.get("strict-transport-security", "")
        response_raw = "\n".join(f"{k}: {v}" for k, v in headers.items())
        request_raw  = f"GET / HTTP/1.1\r\nHost: {parsed.netloc}\r\n"

        # 1. Check HTTP → HTTPS redirect
        http_redirect = await self._check_http_redirect(http_target, https_target)
        if not http_redirect:
            ev = Evidence(
                request_raw=f"GET {http_target}",
                response_raw="No redirect to HTTPS",
                extra={"http_target": http_target},
            )
            self.new_finding(
                title="HTTP Does Not Redirect to HTTPS",
                severity=Severity.HIGH,
                description=(
                    f"The server at {http_target} does not redirect HTTP traffic to HTTPS. "
                    "Users connecting over HTTP receive unencrypted responses, enabling MITM attacks."
                ),
                reproduction_steps=[f"curl -I {http_target}"],
                remediation=(
                    "Add a permanent HTTP → HTTPS redirect (301 or 308):\n"
                    "• Nginx: return 301 https://$host$request_uri;\n"
                    "• Apache: RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n"
                    "• Combine with HSTS header on the HTTPS endpoint."
                ),
                references=["RFC 6797", "CWE-319"],
                evidence=ev,
                cvss_v31_vector=CVSS_NO_HSTS,
                cvss_v40_vector=CVSS40_NO_HSTS,
                target=target,
                url=http_target,
            )

        # 2. HSTS header missing
        if not hsts_value:
            ev = Evidence(
                request_raw=request_raw,
                response_raw=response_raw,
                extra={
                    "has_hsts":                False,
                    "http_redirects_to_https": http_redirect,
                },
            )
            self.new_finding(
                title="HSTS Header Missing",
                severity=Severity.MEDIUM,
                description=(
                    f"Strict-Transport-Security header is not set on {https_target}. "
                    "Without HSTS, browsers may accept HTTP connections, enabling protocol downgrade attacks. "
                    + ("HTTP does redirect to HTTPS, but HSTS is still required for maximum protection."
                       if http_redirect else "")
                ),
                reproduction_steps=[f"curl -I {https_target} | grep -i strict"],
                remediation=(
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
                    "Then submit to https://hstspreload.org/ for browser preloading."
                ),
                references=["RFC 6797", "CWE-319"],
                evidence=ev,
                cvss_v31_vector=CVSS_NO_HSTS,
                cvss_v40_vector=CVSS40_NO_HSTS,
                target=target,
                url=https_target,
            )
            return self._make_result(start)

        # 3. Parse HSTS directives
        max_age            = 0
        include_subdomains = False
        preload            = False

        for part in hsts_value.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                except ValueError:
                    pass
            elif part == "includesubdomains":
                include_subdomains = True
            elif part == "preload":
                preload = True

        # 4. max-age too short
        if max_age == 0:
            self.new_finding(
                title="HSTS max-age Missing or Zero",
                severity=Severity.HIGH,
                description=(
                    f"HSTS header present but max-age is {max_age} (zero or missing). "
                    f"Header: {hsts_value!r}. "
                    "A zero or missing max-age means the HSTS policy is immediately expired — "
                    "browsers will not enforce HTTPS."
                ),
                reproduction_steps=[f"curl -I {https_target} | grep Strict"],
                remediation=f"Set max-age to at least {MIN_MAX_AGE} (1 year).",
                references=["RFC 6797"],
                evidence=Evidence(
                    request_raw=request_raw,
                    response_raw=f"Strict-Transport-Security: {hsts_value}",
                ),
                cvss_v31_vector=CVSS_NO_HSTS,
                cvss_v40_vector=CVSS40_NO_HSTS,
                target=target,
                url=https_target,
            )
        elif max_age < MIN_MAX_AGE:
            self.new_finding(
                title=f"HSTS max-age Too Short ({max_age}s < {MIN_MAX_AGE}s required)",
                severity=Severity.LOW,
                description=(
                    f"HSTS max-age is {max_age} seconds, below the recommended minimum of "
                    f"{MIN_MAX_AGE}s (1 year). "
                    "Short max-age values provide weaker protection as the policy expires frequently."
                ),
                reproduction_steps=[f"curl -I {https_target} | grep Strict"],
                remediation=f"Set max-age to at least {MIN_MAX_AGE} (1 year).",
                references=["RFC 6797"],
                evidence=Evidence(
                    response_raw=f"Strict-Transport-Security: {hsts_value}",
                    extra={"max_age": max_age, "required": MIN_MAX_AGE},
                ),
                cvss_v31_vector=CVSS_WEAK_HSTS,
                cvss_v40_vector=CVSS40_WEAK_HSTS,
                target=target,
                url=https_target,
            )

        # 5. includeSubDomains missing
        if not include_subdomains:
            self.new_finding(
                title="HSTS Missing includeSubDomains Directive",
                severity=Severity.LOW,
                description=(
                    "HSTS policy does not include 'includeSubDomains'. "
                    "Subdomains can still be accessed over HTTP, enabling cookie theft via MITM "
                    "on subdomain connections (since cookies set on parent domain may be sent to subdomains)."
                ),
                reproduction_steps=[f"curl -I {https_target} | grep Strict"],
                remediation="Add 'includeSubDomains' to the HSTS header.",
                references=["RFC 6797"],
                evidence=Evidence(
                    response_raw=f"Strict-Transport-Security: {hsts_value}",
                    extra={"include_subdomains": False},
                ),
                cvss_v31_vector=CVSS_WEAK_HSTS,
                cvss_v40_vector=CVSS40_WEAK_HSTS,
                target=target,
                url=https_target,
            )

        # 6. preload missing (advisory only — not a vulnerability per se)
        if not preload and max_age >= MIN_MAX_AGE and include_subdomains:
            # Only report if they already have a strong HSTS but haven't added preload
            self.new_finding(
                title="HSTS Not Submitted for Browser Preload",
                severity=Severity.INFORMATIONAL,
                description=(
                    "HSTS header has sufficient max-age and includeSubDomains but is missing "
                    "the 'preload' directive. "
                    "Without preload list submission, users visiting the site for the first time "
                    "over HTTP are not protected (first-visit TOFU attack)."
                ),
                reproduction_steps=[f"curl -I {https_target} | grep Strict"],
                remediation=(
                    "Add 'preload' to the HSTS header and submit to https://hstspreload.org/. "
                    "Ensure all subdomains also support HTTPS before submitting."
                ),
                references=["https://hstspreload.org/", "RFC 6797"],
                evidence=Evidence(
                    response_raw=f"Strict-Transport-Security: {hsts_value}",
                ),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                target=target,
                url=https_target,
            )

        return self._make_result(start)

    async def _fetch_headers(self, url: str) -> dict | None:
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                headers={"Accept-Encoding": "gzip, deflate"},
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False
                ) as resp:
                    return {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            return None

    async def _check_http_redirect(self, http_url: str, https_url: str) -> bool:
        """Return True if HTTP redirects to HTTPS."""
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                headers={"Accept-Encoding": "gzip, deflate"},
            ) as session:
                async with session.get(
                    http_url, timeout=aiohttp.ClientTimeout(total=6), allow_redirects=False
                ) as resp:
                    location = resp.headers.get("Location", "")
                    return resp.status in (301, 302, 307, 308) and "https" in location.lower()
        except Exception:
            return False


class TestHstsCheck:
    def test_min_max_age_constant(self) -> None:
        assert MIN_MAX_AGE == 31536000

    def test_parse_hsts_full(self) -> None:
        hsts = "max-age=63072000; includeSubDomains; preload"
        max_age = 0
        include_subdomains = False
        preload = False
        for part in hsts.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age="):
                max_age = int(part.split("=", 1)[1])
            elif part == "includesubdomains":
                include_subdomains = True
            elif part == "preload":
                preload = True
        assert max_age == 63072000
        assert include_subdomains is True
        assert preload is True

    def test_parse_hsts_minimal(self) -> None:
        hsts = "max-age=0"
        max_age = 0
        for part in hsts.split(";"):
            if part.strip().lower().startswith("max-age="):
                max_age = int(part.split("=", 1)[1])
        assert max_age == 0

    def test_cvss_vectors_valid(self) -> None:
        assert CVSS_NO_HSTS.startswith("CVSS:3.1/")
        assert CVSS_WEAK_HSTS.startswith("CVSS:3.1/")
