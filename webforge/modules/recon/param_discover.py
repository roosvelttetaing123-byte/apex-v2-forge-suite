"""Parameter discovery — find hidden GET/POST parameters via brute-force and reflection."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_PARAM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_PARAM = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
COMMON_PARAMS = [
    "id", "user", "username", "email", "password", "pass", "pwd",
    "name", "firstname", "lastname", "fullname", "search", "q", "query",
    "page", "limit", "offset", "per_page", "sort", "order", "filter",
    "file", "path", "dir", "folder", "url", "redirect", "next", "return",
    "callback", "ref", "token", "key", "api_key", "auth", "session",
    "action", "cmd", "command", "type", "mode", "format", "output",
    "debug", "test", "dev", "admin", "config", "setting",
    "lang", "locale", "language", "country", "region",
    "category", "tag", "item", "product", "order", "cart", "price",
    "code", "hash", "signature", "data", "payload", "input",
    "from", "to", "date", "time", "start", "end", "year", "month",
    "view", "template", "theme", "layout", "include", "require",
    "host", "port", "server", "ip", "address", "domain",
    "message", "subject", "body", "content", "text", "html",
]

CANARY = "FORGE_CANARY_7x9z"


class ParamDiscover(BaseModule):
    """Parameter discovery — find hidden parameters via reflection and brute force."""

    NAME        = "param_discover"
    DESCRIPTION = "Discover hidden GET/POST parameters via reflection probing and wordlist"
    PHASE       = 1
    TAGS        = ["recon", "parameters", "fuzzing", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Use URLs discovered by the crawler
        urls_to_test = self.config.extra.get("crawled_urls", [target])
        if not urls_to_test:
            urls_to_test = [target]

        self.log.info("Parameter discovery on %d URL(s)", min(len(urls_to_test), 20))
        self._all_discovered: dict[str, list[dict]] = {}  # Collect across all URLs

        sem = asyncio.Semaphore(3)
        tasks = [self._probe_url(url, sem) for url in urls_to_test[:20]]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Emit ONE consolidated finding
        if self._all_discovered:
            all_params = set()
            pages_with_params = []
            for url, params in self._all_discovered.items():
                path = urlparse(url).path or "/"
                pages_with_params.append(f"{path} ({len(params)} params)")
                for p in params:
                    all_params.add(p["name"])

            self.new_finding(
                title=f"Hidden Parameters Discovered — {len(all_params)} across {len(self._all_discovered)} pages",
                severity=Severity.LOW,
                description=(
                    f"Hidden parameters found across {len(self._all_discovered)} page(s): "
                    f"{', '.join(sorted(all_params)[:15])}. "
                    f"Pages affected: {'; '.join(pages_with_params[:10])}. "
                    "These parameters were not visible in normal application flow."
                ),
                reproduction_steps=[
                    f"curl '{url}?{list(all_params)[0]}=test'" for url in list(self._all_discovered.keys())[:3]
                ],
                remediation=(
                    "Remove unused/debug parameters from production. "
                    "Ensure all accepted parameters are documented and validated."
                ),
                references=["OWASP A01:2021", "CWE-200"],
                cvss_v31_vector=CVSS_PARAM,
                cvss_v40_vector=CVSS40_PARAM,
                target=self.config.target,
            )

        return self._make_result(start)

    async def _probe_url(self, url: str, sem: asyncio.Semaphore) -> None:
        """Probe a URL for hidden parameters."""
        async with sem:
            await self.rate_limit()
            baseline = await self._get_baseline(url)
            if baseline is None:
                return

            found_params: list[dict] = []

            # Test parameters in batches of 10
            batch_size = 10
            for i in range(0, len(COMMON_PARAMS), batch_size):
                batch = COMMON_PARAMS[i:i + batch_size]
                params = {p: CANARY for p in batch}
                reflected = await self._test_params(url, params, baseline)
                found_params.extend(reflected)
                await self.rate_limit()

            if found_params:
                # Collect — consolidated finding emitted in run()
                self._all_discovered[url] = found_params

                # Store discovered params for injection tests
                existing = self.config.extra.get("discovered_params", {})
                existing[url] = [p["name"] for p in found_params]
                self.config.extra["discovered_params"] = existing

    async def _get_baseline(self, url: str) -> dict | None:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8)
                ) as resp:
                    body = await resp.text(errors="ignore")
                    return {"status": resp.status, "length": len(body)}
        except Exception:
            return None

    async def _test_params(
        self, url: str, params: dict[str, str], baseline: dict
    ) -> list[dict]:
        """Test a batch of parameters and detect reflection."""
        found: list[dict] = []
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                # Test GET parameters
                async with session.get(
                    url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                ) as resp:
                    body = await resp.text(errors="ignore")
                    # Check for reflection of any param
                    for param_name in params:
                        if CANARY in body:
                            found.append({
                                "name":   param_name,
                                "method": "GET",
                                "reflected": True,
                            })
                            break  # Found at least one reflected param in this batch
                        # Also check for behavior change by length
                        diff = abs(len(body) - baseline["length"])
                        if diff > 500 and resp.status != baseline["status"]:
                            found.append({
                                "name":   param_name,
                                "method": "GET",
                                "behavior_change": True,
                            })
                            break
        except Exception:
            pass
        return found


class TestParamDiscover:
    def test_canary_defined(self) -> None:
        assert len(CANARY) > 5

    def test_common_params_list(self) -> None:
        assert "id" in COMMON_PARAMS
        assert "token" in COMMON_PARAMS
        assert "redirect" in COMMON_PARAMS

    def test_param_count(self) -> None:
        assert len(COMMON_PARAMS) >= 20
