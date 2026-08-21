"""JSONP injection scanner — detect JSONP endpoints enabling cross-domain data theft."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, urlencode

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

CVSS_JSONP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"
CVSS40_JSONP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N"
CALLBACK_PARAMS = [
    "callback", "cb", "jsonp", "jsonpcallback", "jcb",
    "call", "func", "function", "callfunc", "handler",
]
EVIL_CALLBACK = "FORGE_JSONP_TEST"

JSONP_PATTERN = re.compile(
    r"^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(", re.MULTILINE
)


class JsonpInject(BaseModule):
    """JSONP injection and cross-domain data theft scanner."""

    NAME        = "jsonp_inject"
    DESCRIPTION = "Detect JSONP endpoints that allow cross-domain sensitive data theft"
    PHASE       = 4
    TAGS        = ["injection", "jsonp", "xss", "cwe-79", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Test known API paths and discovered endpoints
        api_paths = self.config.extra.get("api_base_paths", [])
        endpoints  = self.config.extra.get("api_endpoints", [])
        crawled    = self.config.extra.get("crawled_urls", [target])

        test_urls: list[str] = list(api_paths)

        # Convert endpoint descriptions to URLs
        for ep in endpoints[:20]:
            if isinstance(ep, str) and ep.startswith("GET "):
                path = ep[4:].strip()
                test_urls.append(f"{target}{path}")

        # Find JSON-returning URLs from crawler
        for url in crawled[:30]:
            if ".json" in url or "api" in url.lower():
                test_urls.append(url)

        # Also probe known JSONP paths
        for path in ["/api/user", "/api/profile", "/api/data", "/user.json",
                     "/data.json", "/api/me", "/api/account"]:
            test_urls.append(f"{target}{path}")

        self.log.info("Testing %d URLs for JSONP endpoints", len(test_urls))
        # Initialise FPReducer for false-positive verification
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        sem = asyncio.Semaphore(3)
        seen: set[str] = set()
        tasks = []
        for url in test_urls[:40]:
            base = url.split("?")[0]
            if base not in seen:
                seen.add(base)
                tasks.append(self._test_jsonp(url, target, sem))

        await asyncio.gather(*tasks, return_exceptions=True)
        return self._make_result(start)

    async def _test_jsonp(self, url: str, target: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            if not self.check_scope(url):
                return

            for cb_param in CALLBACK_PARAMS:
                await self.rate_limit()
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}{cb_param}={EVIL_CALLBACK}"

                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            test_url,
                            headers={"Accept": "application/javascript, */*"},
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            ctype = resp.headers.get("Content-Type", "")

                    # JSONP confirmed if our callback is at start of response
                    if body.strip().startswith(EVIL_CALLBACK + "("):
                        # Check if it contains sensitive data
                        sensitive = self._check_sensitive_data(body)
                        severity = Severity.HIGH if sensitive else Severity.MEDIUM

                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:500],
                            extra={
                                "callback_param": cb_param,
                                "url":            test_url,
                                "sensitive_data": sensitive,
                            },
                        )
                        ev.screenshot_path = self.capture_screenshot(
                            test_url, finding_id=f"jsonp_{cb_param}"
                        )
                        self.new_finding(
                            title=f"JSONP Endpoint — {cb_param} Parameter ({url.split('/')[-1]})",
                            severity=severity,
                            description=(
                                f"JSONP endpoint at {url} accepts the '{cb_param}' callback parameter. "
                                "Any website can include this URL as a <script> tag and steal the "
                                "response data (including session-specific information if cookies are sent). "
                                + (f"Sensitive data detected in response: {', '.join(sensitive)}"
                                   if sensitive else "")
                            ),
                            reproduction_steps=[
                                f"<script src='{test_url}'></script>",
                                "In same page JS: function FORGE_JSONP_TEST(data) {{ console.log(data); }}",
                            ],
                            remediation=(
                                "Remove JSONP support — use CORS instead. "
                                "If JSONP must be supported, validate callback name against a strict allowlist. "
                                "Set Content-Type to application/json to prevent script execution."
                            ),
                            references=["CWE-79", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_JSONP,
                            cvss_v40_vector=CVSS40_JSONP,
                            target=target,
                            url=url,
                        )
                        return  # One finding per URL

                except Exception:
                    pass

    def _check_sensitive_data(self, body: str) -> list[str]:
        """Check if the JSONP response contains sensitive field names."""
        sensitive_keys = [
            "email", "password", "token", "api_key", "secret",
            "address", "phone", "ssn", "credit_card", "balance",
            "auth", "session", "private", "internal",
        ]
        found = [k for k in sensitive_keys if f'"{k}"' in body or f"'{k}'" in body]
        return found


class TestJsonpInject:
    def test_callback_params_list(self) -> None:
        assert "callback" in CALLBACK_PARAMS
        assert "jsonp" in CALLBACK_PARAMS

    def test_evil_callback(self) -> None:
        body = f"{EVIL_CALLBACK}({{\"data\": 1}})"
        assert body.strip().startswith(EVIL_CALLBACK + "(")

    def test_sensitive_data_detection(self) -> None:
        mod = JsonpInject.__new__(JsonpInject)
        body = f'{EVIL_CALLBACK}({{"email": "test@test.com", "token": "abc123"}})'
        found = mod._check_sensitive_data(body)
        assert "email" in found
        assert "token" in found
