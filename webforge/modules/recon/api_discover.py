"""API endpoint discovery — find REST/GraphQL/Swagger endpoints."""
from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_API_DOCS   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_API_DOCS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_API_UNAUTH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
CVSS40_API_UNAUTH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
SWAGGER_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json", "/api/swagger.json", "/api/swagger.yaml",
    "/api-docs", "/api-docs.json", "/api-docs/swagger.json",
    "/openapi.json", "/openapi.yaml", "/openapi/v1/openapi.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/docs", "/redoc", "/api/redoc",
]

GRAPHQL_PATHS = [
    "/graphql", "/graphql/v1", "/api/graphql", "/gql",
    "/query", "/api/query", "/graphiql", "/playground",
]

API_VERSION_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/v1", "/v2", "/v3", "/rest", "/rest/v1", "/rest/v2",
    "/service", "/services", "/ws", "/webservice",
]


class ApiDiscover(BaseModule):
    """API endpoint and documentation discovery."""

    NAME        = "api_discover"
    DESCRIPTION = "Discover API endpoints, Swagger/OpenAPI docs, and GraphQL interfaces"
    PHASE       = 1
    TAGS        = ["recon", "api", "swagger", "graphql", "owasp-a09"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Discovering API endpoints on %s", target)

        await asyncio.gather(
            self._find_swagger(target),
            self._find_graphql(target),
            self._find_api_versions(target),
        )
        return self._make_result(start)

    async def _find_swagger(self, target: str) -> None:
        for path in SWAGGER_PATHS:
            await self.rate_limit()
            content = await self._fetch(f"{target}{path}")
            if content and ('"swagger"' in content or '"openapi"' in content
                           or "openapi:" in content):
                endpoints = self._parse_openapi_endpoints(content)
                self.config.extra.setdefault("api_endpoints", []).extend(endpoints)
                ev = Evidence(
                    response_raw=content[:2000],
                    extra={
                        "swagger_url": f"{target}{path}",
                        "endpoint_count": len(endpoints),
                        "endpoints": endpoints[:20],
                    },
                )
                ev.screenshot_path = await self.capture_screenshot(
                    f"{target}{path}", finding_id=f"swagger_{path.replace('/', '_')}"
                )
                self.new_finding(
                    title=f"API Documentation Exposed — {path}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"API documentation (Swagger/OpenAPI) found at {target}{path}. "
                        f"{len(endpoints)} endpoint(s) discovered. "
                        "Publicly accessible API docs reveal the full API attack surface "
                        "including endpoints, parameters, and authentication methods."
                    ),
                    reproduction_steps=[
                        f"curl -s {target}{path} | python3 -m json.tool",
                        f"Import into Burp Suite or Postman for testing",
                        f"Endpoints found: {', '.join(endpoints[:5])}",
                    ],
                    remediation=(
                        "Restrict API documentation access to authenticated users or internal networks. "
                        "Do not expose Swagger/OpenAPI docs in production unless intentional."
                    ),
                    references=["OWASP API9:2023", "CWE-200"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_API_DOCS,
                    cvss_v40_vector=CVSS40_API_DOCS,
                    mitre_attack=["TA0007/T1590"],
                    target=target,
                    url=f"{target}{path}",
                )
                break  # Found one, that's enough for the finding

    async def _find_graphql(self, target: str) -> None:
        for path in GRAPHQL_PATHS:
            await self.rate_limit()
            # Test with introspection query
            introspection = '{"query":"{__schema{types{name}}}"}'
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.post(
                        f"{target}{path}",
                        data=introspection,
                        headers={"Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as resp:
                        if resp.status in (200, 400):
                            body = await resp.text(errors="ignore")
                            if '"data"' in body or '"errors"' in body or '"__schema"' in body:
                                introspection_enabled = '"__schema"' in body
                                ev = Evidence(
                                    request_raw=f"POST {path}\n{introspection}",
                                    response_raw=body[:1000],
                                    extra={
                                        "path": path,
                                        "introspection_enabled": introspection_enabled,
                                    },
                                )
                                ev.screenshot_path = await self.capture_screenshot(
                                    f"{target}{path}", finding_id="graphql_endpoint"
                                )
                                self.new_finding(
                                    title=f"GraphQL Endpoint Found — {path}"
                                          + (" (Introspection Enabled)" if introspection_enabled else ""),
                                    severity=Severity.MEDIUM if introspection_enabled else Severity.LOW,
                                    description=(
                                        f"GraphQL endpoint found at {target}{path}. "
                                        + ("Introspection is enabled, exposing the full schema. "
                                           "This allows attackers to enumerate all types, fields, and mutations."
                                           if introspection_enabled else
                                           "GraphQL endpoint detected.")
                                    ),
                                    reproduction_steps=[
                                        f"curl -s -X POST {target}{path} -H 'Content-Type: application/json' "
                                        f"-d '{introspection}'",
                                    ],
                                    remediation=(
                                        "Disable GraphQL introspection in production. "
                                        "Implement query depth limiting and rate limiting. "
                                        "Use persisted queries instead of ad-hoc queries."
                                    ),
                                    references=["OWASP API9:2023"],
                                    evidence=ev,
                                    cvss_v31_vector=CVSS_API_DOCS,
                                    cvss_v40_vector=CVSS40_API_DOCS,
                                    target=target,
                                    url=f"{target}{path}",
                                )
                                break
            except Exception:
                pass

    async def _find_api_versions(self, target: str) -> None:
        discovered: list[str] = []
        for path in API_VERSION_PATHS:
            await self.rate_limit()
            status, content = await self._fetch_with_status(f"{target}{path}")
            if status in (200, 401, 403):
                discovered.append(f"{path} ({status})")
                self.config.extra.setdefault("api_base_paths", []).append(f"{target}{path}")

        if discovered:
            self.log.info("API base paths found: %s", discovered)
            self.config.extra["discovered_api_paths"] = discovered

    async def _fetch(self, url: str) -> str | None:
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8),
                    headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
                ) as resp:
                    if resp.status == 200:
                        return await resp.text(errors="ignore")
        except Exception:
            pass
        return None

    async def _fetch_with_status(self, url: str) -> tuple[int, str]:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False
                ) as resp:
                    body = await resp.text(errors="ignore")
                    return resp.status, body
        except Exception:
            return 0, ""

    def _parse_openapi_endpoints(self, content: str) -> list[str]:
        endpoints: list[str] = []
        try:
            data = json.loads(content)
            paths = data.get("paths", {})
            for path, methods in paths.items():
                for method in methods.keys():
                    if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        endpoints.append(f"{method.upper()} {path}")
        except Exception:
            # YAML or malformed JSON — extract paths via regex
            for m in re.finditer(r'"(/[a-zA-Z0-9/_{}.\-]+)"', content):
                endpoints.append(m.group(1))
        return endpoints[:100]


class TestApiDiscover:
    def test_parse_openapi_endpoints(self) -> None:
        mod = ApiDiscover.__new__(ApiDiscover)
        swagger = json.dumps({
            "swagger": "2.0",
            "paths": {
                "/users": {"get": {}, "post": {}},
                "/users/{id}": {"get": {}, "delete": {}},
            }
        })
        endpoints = mod._parse_openapi_endpoints(swagger)
        assert any("GET /users" in ep for ep in endpoints)
        assert any("POST /users" in ep for ep in endpoints)

    def test_parse_openapi_empty(self) -> None:
        mod = ApiDiscover.__new__(ApiDiscover)
        endpoints = mod._parse_openapi_endpoints("{}")
        assert isinstance(endpoints, list)
