"""GraphQL audit — introspection, injection, batching abuse, field enumeration."""
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

CVSS_INTROSPECTION = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_INJECTION      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
CVSS_BATCHING       = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H"
CVSS_SQLI           = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"

GRAPHQL_ENDPOINTS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/gql", "/graphql/console", "/api/query",
    "/graphql/v1", "/graphql/v2", "/hasura/v1/graphql",
    "/api/v1/graphql", "/api/v2/graphql",
]

INTROSPECTION_QUERY = {"query": "{ __schema { types { name } } }"}

# Field suggestion harvesting — Apollo/GraphQL servers leak valid field names
# even when introspection is disabled (via "Did you mean X?" errors)
SUGGESTION_PROBE_QUERY = {"query": "{ __typenme }"}  # typo triggers "Did you mean __typename?"

# Alias batching for rate-limit bypass (OWASP API4:2023)
ALIAS_BATCH_QUERY = {
    "query": " ".join(
        f'a{i}: __typename' for i in range(100)
    ).join(["{", "}"])
}

INJECTION_PAYLOADS = [
    '{ user(id: "1 OR 1=1") { id name email } }',
    '{ __typename \n__schema { types { name } } }',
    '{ user(id: "1\\"){ id } }',
    '{ user(id: "1; DROP TABLE users--") { id } }',
    '{ search(query: "{{7*7}}") { results } }',  # SSTI canary
]

# Persisted query abuse — send arbitrary hash to probe APQ endpoint
PERSISTED_QUERY_PROBE = {
    "extensions": {
        "persistedQuery": {
            "version": 1,
            "sha256Hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    },
    "query": "{ __typename }"
}


class GraphqlAudit(BaseModule):
    """GraphQL security auditor — OWASP API Top 10 coverage."""

    NAME        = "graphql_audit"
    DESCRIPTION = "GraphQL: introspection leakage, injection, batching abuse, DoS vectors"
    PHASE       = 7
    TAGS        = ["api", "graphql", "introspection", "owasp-api-security", "cwe-200"]

    async def run(self) -> ModuleResult:
        """Discover GraphQL endpoints and audit them."""
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=12)
        headers   = {"Content-Type": "application/json", "Accept": "application/json"}

        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            for endpoint in GRAPHQL_ENDPOINTS:
                url = f"{target}{endpoint}"
                if not self.check_scope(url):
                    continue
                if await self._is_graphql(session, url):
                    self.log.info("GraphQL endpoint found: %s", url)
                    await self._audit_introspection(session, url)
                    await self._audit_field_suggestions(session, url)
                    await self._audit_injection(session, url)
                    await self._audit_batching(session, url)
                    await self._audit_alias_batching(session, url)
                    await self._audit_depth(session, url)
                    await self._audit_persisted_queries(session, url)
                    await self._audit_get_queries(session, url)

        return self._make_result(start)

    async def _post_gql(
        self, session: aiohttp.ClientSession, url: str, payload: dict
    ) -> tuple[int, str]:
        """POST a GraphQL payload and return (status, body)."""
        await self.rate_limit()
        try:
            async with session.post(url, json=payload) as resp:
                body = await resp.text(errors="ignore")
                return resp.status, body
        except Exception as exc:
            self.log.debug("GQL request error on %s: %s", url, exc)
            return -1, ""

    async def _is_graphql(self, session: aiohttp.ClientSession, url: str) -> bool:
        """Return True if endpoint responds to a basic GraphQL query."""
        status, body = await self._post_gql(session, url, {"query": "{ __typename }"})
        if status == -1:
            return False
        return "data" in body or "errors" in body or "graphql" in body.lower()

    async def _audit_introspection(self, session: aiohttp.ClientSession, url: str) -> None:
        """Check if introspection is enabled (schema disclosure)."""
        status, body = await self._post_gql(session, url, INTROSPECTION_QUERY)
        if status == -1:
            return
        try:
            data = json.loads(body)
        except Exception:
            return
        if "data" in data and "__schema" in str(data.get("data", "")):
            ev = Evidence(
                request_raw=f"POST {url} HTTP/1.1\n{json.dumps(INTROSPECTION_QUERY)}",
                response_raw=body[:600],
                extra={"endpoint": url},
            )
            self.new_finding(
                title=f"GraphQL Introspection Enabled: {url}",
                severity=Severity.MEDIUM,
                description=(
                    "GraphQL introspection is enabled in production. "
                    "Attackers can enumerate the entire API schema — all types, "
                    "fields, mutations — without authentication."
                ),
                reproduction_steps=[
                    f"POST {url}",
                    f"Body: {json.dumps(INTROSPECTION_QUERY)}",
                    "Observe __schema response with full type list",
                ],
                remediation=(
                    "Disable GraphQL introspection in production environments. "
                    "Most GraphQL servers support disableIntrospection middleware."
                ),
                references=["CWE-200", "OWASP API7:2023"],
                evidence=ev,
                cvss_v31_vector=CVSS_INTROSPECTION,
                target=url,
            )

    async def _audit_injection(self, session: aiohttp.ClientSession, url: str) -> None:
        """Test basic injection payloads in GraphQL arguments."""
        for payload_str in INJECTION_PAYLOADS:
            payload = {"query": payload_str}
            status, body = await self._post_gql(session, url, payload)
            if status == -1:
                continue
            sql_errors = ["sql syntax", "ora-", "mysql", "syntax error", "pg_query"]
            found_error = any(e in body.lower() for e in sql_errors)
            if found_error:
                ev = Evidence(
                    request_raw=f"POST {url} HTTP/1.1\n{json.dumps(payload)}",
                    response_raw=body[:500],
                    extra={"payload": payload_str},
                )
                self.new_finding(
                    title=f"GraphQL SQL Injection Indicator: {url}",
                    severity=Severity.HIGH,
                    description=(
                        "A GraphQL argument injection payload triggered a database error "
                        "response, indicating insufficient input sanitization. "
                        "This may enable SQL injection via GraphQL arguments."
                    ),
                    reproduction_steps=[
                        f"POST {url}",
                        f"Body: {json.dumps(payload)}",
                        "Observe SQL error in response body",
                    ],
                    remediation=(
                        "Validate and sanitize all GraphQL resolver arguments. "
                        "Use parameterized queries in resolvers. "
                        "Apply input validation at the schema level."
                    ),
                    references=["CWE-89", "OWASP A03:2021", "OWASP API8:2023"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_SQLI,
                    target=url,
                )
                break

    async def _audit_batching(self, session: aiohttp.ClientSession, url: str) -> None:
        """Check if query batching is enabled (brute-force/DoS risk)."""
        # Send an array of queries
        batch = [{"query": "{ __typename }"} for _ in range(10)]
        await self.rate_limit()
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=12),
                headers={"Content-Type": "application/json"},
            ) as sess:
                async with sess.post(url, json=batch) as resp:
                    body = await resp.text(errors="ignore")
                    if resp.status == 200 and "__typename" in body:
                        ev = Evidence(
                            request_raw=f"POST {url} HTTP/1.1\n[array of 10 queries]",
                            response_raw=body[:400],
                            extra={"batch_size": 10},
                        )
                        self.new_finding(
                            title=f"GraphQL Query Batching Enabled: {url}",
                            severity=Severity.MEDIUM,
                            description=(
                                "GraphQL query batching is enabled. An attacker can send "
                                "hundreds of queries in a single HTTP request, enabling "
                                "brute-force and rate-limit bypass attacks."
                            ),
                            reproduction_steps=[
                                f"POST {url} with a JSON array of queries",
                                "Observe all queries are resolved in one response",
                            ],
                            remediation=(
                                "Disable or limit GraphQL query batching. "
                                "Implement per-request complexity and depth limits."
                            ),
                            references=["OWASP API4:2023", "CWE-770"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_BATCHING,
                            target=url,
                        )
        except Exception:
            pass

    async def _audit_depth(self, session: aiohttp.ClientSession, url: str) -> None:
        """Test deeply nested queries (DoS via query complexity)."""
        deep_query = "{ a { b { c { d { e { f { g { __typename } } } } } } } }"
        status, body = await self._post_gql(session, url, {"query": deep_query})
        if status == 200 and "data" in body:
            ev = Evidence(
                request_raw=f"POST {url}\n{deep_query}",
                response_raw=body[:300],
                extra={"depth": 7},
            )
            self.new_finding(
                title=f"GraphQL No Query Depth Limit: {url}",
                severity=Severity.LOW,
                description=(
                    "The GraphQL server accepted a deeply nested query (depth=7) without "
                    "error. Unbounded query depth can be exploited for DoS via exponential "
                    "data fetching."
                ),
                reproduction_steps=[
                    f"POST {url}",
                    f"Body: {{query: \"{deep_query}\"}}",
                    "Observe successful response (no depth error)",
                ],
                remediation=(
                    "Implement query depth limiting (max depth 5-7). "
                    "Use query complexity analysis middleware."
                ),
                references=["OWASP API4:2023", "CWE-770"],
                evidence=ev,
                cvss_v31_vector=CVSS_BATCHING,
                target=url,
            )


    async def _audit_field_suggestions(self, session: aiohttp.ClientSession, url: str) -> None:
        """Apollo/GraphQL field suggestion leak — works even with introspection disabled.

        Servers that disable introspection still return 'Did you mean X?' error messages,
        leaking valid field/type names (OWASP API7:2023).
        """
        status, body = await self._post_gql(session, url, SUGGESTION_PROBE_QUERY)
        if status == -1:
            return
        import re
        suggestions = re.findall(r'Did you mean ["\']?(\w+)["\']?', body, re.I)
        if suggestions:
            ev = Evidence(
                request_raw=f"POST {url}\n{json.dumps(SUGGESTION_PROBE_QUERY)}",
                response_raw=body[:600],
                extra={"leaked_names": suggestions[:20]},
            )
            self.new_finding(
                title=f"GraphQL Field Suggestion Leaks Schema Names: {url}",
                severity=Severity.MEDIUM,
                description=(
                    f"GraphQL 'Did you mean?' suggestions leak valid field/type names even "
                    f"with introspection disabled. Leaked names: {suggestions[:10]}. "
                    "Attackers can enumerate the entire schema iteratively (OWASP API7:2023)."
                ),
                reproduction_steps=[
                    f"POST {url} with a deliberately misspelled field name",
                    "Observe 'Did you mean X?' hints in error response",
                    "Iterate to enumerate all fields without introspection",
                ],
                remediation=(
                    "Disable field suggestions in production (Apollo: fieldSuggestions: false). "
                    "Return generic 'Unknown field' errors without hints."
                ),
                references=["OWASP API7:2023", "CWE-200"],
                evidence=ev,
                cvss_v31_vector=CVSS_INTROSPECTION,
                target=url,
            )

    async def _audit_alias_batching(self, session: aiohttp.ClientSession, url: str) -> None:
        """Alias batching — 100 mutations in one request bypasses per-request rate limits."""
        await self.rate_limit()
        try:
            async with session.post(url, json=ALIAS_BATCH_QUERY) as resp:
                body = await resp.text(errors="ignore")
                if resp.status == 200 and body.count("__typename") > 10:
                    ev = Evidence(
                        request_raw=f"POST {url} — 100 aliased queries in single request",
                        response_raw=body[:400],
                        extra={"alias_count": 100},
                    )
                    self.new_finding(
                        title=f"GraphQL Alias Batching Bypass (100 ops/request): {url}",
                        severity=Severity.HIGH,
                        description=(
                            "GraphQL alias batching allows 100+ operations in one HTTP request, "
                            "completely bypassing per-request rate limits. This enables brute-force "
                            "of credentials, OTP codes, or enumeration without rate limiting. "
                            "Critical for login mutations (OWASP API4:2023)."
                        ),
                        reproduction_steps=[
                            f"POST {url} with query: {{ a1: login(user:'x',pass:'a') a2: login(user:'x',pass:'b') ... }}",
                            "Observe all 100 attempts return results in one response",
                        ],
                        remediation=(
                            "Implement per-operation rate limiting inside the GraphQL resolver. "
                            "Limit maximum aliases per query (Apollo: maxAliasCount: 15). "
                            "Use a query complexity analysis library."
                        ),
                        references=["OWASP API4:2023", "CWE-770"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_BATCHING,
                        target=url,
                    )
        except Exception:
            pass

    async def _audit_persisted_queries(self, session: aiohttp.ClientSession, url: str) -> None:
        """Automatic Persisted Queries (APQ) — check if arbitrary queries can be submitted."""
        await self.rate_limit()
        try:
            async with session.post(url, json=PERSISTED_QUERY_PROBE) as resp:
                body = await resp.text(errors="ignore")
                if "PersistedQueryNotFound" in body or "PersistedQueryNotSupported" in body:
                    # APQ enabled but hash not found — attacker can register arbitrary queries
                    ev = Evidence(
                        request_raw=f"POST {url}\n{json.dumps(PERSISTED_QUERY_PROBE)}",
                        response_raw=body[:400],
                        extra={"apq_enabled": True},
                    )
                    self.new_finding(
                        title=f"GraphQL Automatic Persisted Queries (APQ) Enabled: {url}",
                        severity=Severity.LOW,
                        description=(
                            "APQ is enabled. If not restricted to an allowlist, attackers can "
                            "register and cache arbitrary queries server-side. Combined with "
                            "introspection, this may expand the attack surface for future requests."
                        ),
                        reproduction_steps=[
                            f"POST {url} with extensions.persistedQuery and any sha256Hash",
                            "Observe PersistedQueryNotFound response — APQ is active",
                        ],
                        remediation=(
                            "Restrict APQ to a pre-approved query allowlist. "
                            "Disable APQ in production or pair with query complexity limits."
                        ),
                        references=["OWASP API7:2023"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_INTROSPECTION,
                        target=url,
                    )
        except Exception:
            pass

    async def _audit_get_queries(self, session: aiohttp.ClientSession, url: str) -> None:
        """Check if GET-method GraphQL queries are accepted (CSRF vector for mutations)."""
        get_url = f"{url}?query={{__typename}}"
        if not self.check_scope(get_url):
            return
        await self.rate_limit()
        try:
            async with session.get(get_url) as resp:
                body = await resp.text(errors="ignore")
                if resp.status == 200 and "__typename" in body:
                    ev = Evidence(
                        request_raw=f"GET {get_url}",
                        response_raw=body[:300],
                        extra={"get_queries_enabled": True},
                    )
                    self.new_finding(
                        title=f"GraphQL GET Method Queries Accepted (CSRF Risk): {url}",
                        severity=Severity.MEDIUM,
                        description=(
                            "GraphQL accepts queries via GET requests. If mutations are also "
                            "accepted via GET, this creates a CSRF vector — an attacker can "
                            "trigger state-changing operations from a victim's browser via a "
                            "simple URL or img tag."
                        ),
                        reproduction_steps=[
                            f"Navigate to: {url}?query={{mutation{{deleteAccount}}}}",
                            "Observe if mutation executes without CSRF protection",
                        ],
                        remediation=(
                            "Restrict mutations to POST only. "
                            "Validate Content-Type: application/json on all mutation requests. "
                            "Implement CSRF tokens for state-changing GraphQL operations."
                        ),
                        references=["OWASP API8:2023", "CWE-352"],
                        evidence=ev,
                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        target=url,
                    )
        except Exception:
            pass


class TestGraphqlAudit:
    def test_endpoints_non_empty(self) -> None:
        assert len(GRAPHQL_ENDPOINTS) >= 4

    def test_introspection_query_valid(self) -> None:
        assert "__schema" in INTROSPECTION_QUERY["query"]

    def test_cvss_vectors_format(self) -> None:
        for v in (CVSS_INTROSPECTION, CVSS_INJECTION, CVSS_BATCHING, CVSS_SQLI):
            assert v.startswith("CVSS:3.1/")
