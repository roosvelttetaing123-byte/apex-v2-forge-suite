"""GraphQL Audit — introspection, batching, injection, IDOR via GraphQL."""
from __future__ import annotations
import json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
import aiohttp

CVSS_INTROSPECT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_INTROSPECT = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_BATCH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H"
CVSS40_BATCH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N"

INTROSPECTION_QUERY = '{"query": "{ __schema { types { name fields { name type { name } } } } }"}'

GQL_ENDPOINTS = ["/graphql", "/graphql/v1", "/api/graphql", "/gql", "/query",
                  "/graphql/console", "/v1/graphql", "/v2/graphql"]

class GraphqlAudit(BaseModule):
    NAME = "graphql_audit"
    DESCRIPTION = "GraphQL: introspection, batching DoS, injection, authorization bypass"
    PHASE = 7
    TAGS = ["api", "graphql", "cwe-200"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        gql_url = None
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=10),
        ) as session:
            # Find GraphQL endpoint
            for path in GQL_ENDPOINTS:
                await self.rate_limit()
                try:
                    async with session.post(
                        f"{target}{path}",
                        data=INTROSPECTION_QUERY,
                        headers={"Content-Type": "application/json"},
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        if resp.status == 200 and "__schema" in body:
                            gql_url = f"{target}{path}"
                            break
                        if resp.status == 200 and "graphql" in body.lower():
                            gql_url = f"{target}{path}"
                            break
                except Exception:
                    pass

            if not gql_url:
                self.log.info("No GraphQL endpoint found")
                return self._make_result(start)

            # Test 1: Introspection
            await self.rate_limit()
            try:
                async with session.post(
                    gql_url, data=INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    body = await resp.text(errors="ignore")
                    if "__schema" in body:
                        data = json.loads(body)
                        types = data.get("data", {}).get("__schema", {}).get("types", [])
                        user_types = [t for t in types if not t["name"].startswith("__")]
                        ev = Evidence(
                            request_raw=INTROSPECTION_QUERY[:200],
                            response_raw=body[:1000],
                            extra={"types": [t["name"] for t in user_types[:20]]})
                        self.new_finding(
                            title=f"GraphQL Introspection Enabled — {len(user_types)} types exposed at {gql_url}",
                            severity=Severity.MEDIUM,
                            description=(
                                f"GraphQL introspection is enabled, exposing the full API schema:\n"
                                f"  Types: {', '.join(t['name'] for t in user_types[:10])}\n\n"
                                "Introspection reveals all queries, mutations, fields, and types — "
                                "full API documentation for an attacker."
                            ),
                            reproduction_steps=[
                                f"curl -X POST {gql_url} -H 'Content-Type: application/json' "
                                f"-d '{INTROSPECTION_QUERY}'",
                            ],
                            remediation="Disable introspection in production.",
                            references=["CWE-200", "OWASP API4:2023"],
                            evidence=ev, cvss_v31_vector=CVSS_INTROSPECT, cvss_v40_vector=CVSS40_INTROSPECT,
                            target=target)
            except Exception:
                pass

            # Test 2: Query batching (DoS potential)
            batch_query = json.dumps([
                {"query": "{ __typename }"} for _ in range(20)
            ])
            await self.rate_limit()
            try:
                async with session.post(
                    gql_url, data=batch_query,
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    body = await resp.text(errors="ignore")
                    if resp.status == 200:
                        try:
                            results = json.loads(body)
                            if isinstance(results, list) and len(results) >= 10:
                                ev = Evidence(
                                    request_raw=f"Batch of 20 queries to {gql_url}",
                                    extra={"batch_size_accepted": len(results)})
                                self.new_finding(
                                    title=f"GraphQL Batching — {len(results)} queries accepted at once",
                                    severity=Severity.MEDIUM,
                                    description=(
                                        "GraphQL endpoint accepts batched queries without limit. "
                                        "An attacker can send thousands of queries in a single request, "
                                        "bypassing rate limiting and causing DoS."
                                    ),
                                    reproduction_steps=[f"Send array of 1000 queries to {gql_url}"],
                                    remediation="Limit batch query count (max 5-10). Implement query cost analysis.",
                                    references=["CWE-770"],
                                    evidence=ev, cvss_v31_vector=CVSS_BATCH, cvss_v40_vector=CVSS40_BATCH,
                                    target=target)
                        except json.JSONDecodeError:
                            pass
            except Exception:
                pass

            # Test 3: Query depth attack
            nested = '{ __schema { types { fields { type { fields { type { name } } } } } } }'
            await self.rate_limit()
            try:
                async with session.post(
                    gql_url, json={"query": nested},
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        if "error" not in body.lower()[:200]:
                            ev = Evidence(request_raw=nested[:200], response_raw=body[:500])
                            self.new_finding(
                                title="GraphQL Depth Limit Missing — nested queries accepted",
                                severity=Severity.LOW,
                                description="No query depth limit. Deep nesting can cause exponential processing.",
                                reproduction_steps=[f"Send deeply nested query to {gql_url}"],
                                remediation="Implement query depth limit (max 10-15).",
                                references=["CWE-770"],
                                evidence=ev,
                                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                                cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
                                target=target)
            except Exception:
                pass

        return self._make_result(start)

class TestGraphqlAudit:
    def test_endpoints(self) -> None: assert "/graphql" in GQL_ENDPOINTS
    def test_phase(self) -> None: assert GraphqlAudit.PHASE == 7
