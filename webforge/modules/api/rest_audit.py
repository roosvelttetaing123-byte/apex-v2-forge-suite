"""REST API security auditor — versioning, auth bypass, verb tampering, mass assignment."""
from __future__ import annotations

import asyncio
import json as _json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_API_UNAUTH   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_VERB         = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_MASS_ASSIGN  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_INFO_DISC    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

HTTP_VERBS = ["GET", "POST", "PUT", "PATCH", "DELETE",
              "OPTIONS", "HEAD", "TRACE", "CONNECT"]

# Common API paths to discover/probe
API_DISCOVERY_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/admin", "/api/v1/admin",
    "/api/profile", "/api/me", "/api/self",
    "/api/config", "/api/settings",
    "/api/docs", "/api/swagger", "/swagger.json", "/openapi.json",
    "/api-docs", "/api/health", "/api/status",
]

# Mass assignment probe bodies — include admin/privilege fields
MASS_ASSIGN_PROBE_FIELDS = [
    {"is_admin": True},
    {"admin": True},
    {"role": "admin"},
    {"roles": ["admin"]},
    {"permissions": ["*"]},
    {"user_type": "admin"},
    {"privilege": "superuser"},
    {"account_type": "premium"},
    {"verified": True},
    {"email_verified": True},
    {"balance": 999999},
    {"credits": 999999},
]


class RestAudit(BaseModule):
    """REST API security auditor."""

    NAME        = "rest_audit"
    DESCRIPTION = "Audit REST APIs: verb tampering, auth bypass, versioning, mass assignment"
    PHASE       = 7
    TAGS        = ["api", "rest", "verb-tampering", "mass-assignment", "cwe-284", "owasp-api"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        api_paths = self.config.extra.get("api_base_paths", [])
        if not api_paths:
            api_paths = [f"{target}/api/v1", f"{target}/api/v2", f"{target}/api"]

        # Discover API endpoints from pre-crawled data plus known paths
        discovered_endpoints = self.config.extra.get("api_endpoints", [])
        # Add discovery paths
        for path in API_DISCOVERY_PATHS:
            url = f"{target}{path}"
            if self.check_scope(url) and url not in discovered_endpoints:
                discovered_endpoints.append(url)

        await asyncio.gather(
            self._test_verb_tampering(api_paths, target),
            self._test_old_api_versions(target),
            self._check_api_verbose_errors(api_paths, target),
            self._check_trace_method(target),
        )

        # Mass assignment tests (sequential to avoid flooding)
        for endpoint in discovered_endpoints[:15]:
            if self.check_scope(endpoint):
                await self._test_mass_assignment(endpoint, target)

        # Unauthenticated access tests
        await self._test_unauthenticated_access(discovered_endpoints[:20], target)

        return self._make_result(start)

    async def _test_verb_tampering(self, api_paths: list[str], target: str) -> None:
        """Test HTTP verb tampering on API endpoints."""
        for base in api_paths[:5]:
            if not self.check_scope(base):
                continue
            # First check GET to get baseline
            try:
                await self.rate_limit()
                base_status, base_body = await self._request("GET", base)
                if base_status in (-1, 404):
                    continue
            except Exception:
                continue

            for verb in HTTP_VERBS:
                if verb == "GET":
                    continue
                if verb == "TRACE":
                    # Check TRACE separately
                    continue
                await self.rate_limit()
                status, body = await self._request(verb, base)
                if status in (200, 201, 202, 204) and base_status not in (200, 201):
                    ev = Evidence(
                        request_raw=f"{verb} {base} HTTP/1.1",
                        response_raw=f"HTTP {status}\n{body[:300]}",
                        extra={"verb": verb, "status": status, "base_status": base_status},
                    )
                    self.new_finding(
                        title=f"HTTP Verb Tampering on API — {verb} {base}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"API endpoint {base} returns {base_status} on GET but {status} on {verb}. "
                            "This indicates the access control is not applied uniformly across HTTP methods."
                        ),
                        reproduction_steps=[
                            f"curl -X GET {base}  # {base_status}",
                            f"curl -X {verb} {base}  # {status}",
                        ],
                        remediation=(
                            "Apply authorization checks on all HTTP methods, not just GET. "
                            "Use a deny-all default for unused methods."
                        ),
                        references=["CWE-284", "OWASP API3:2023"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_VERB,
                        target=base,
                    )

    async def _test_old_api_versions(self, target: str) -> None:
        """Check if deprecated/old API versions are still active."""
        version_paths = [
            ("/v0", "/v1"), ("/api/v0", "/api/v1"), ("/api/v1", "/api/v2"),
            ("/api/v2", "/api/v3"), ("/v1.0", "/v2.0"),
        ]
        for old_path, new_path in version_paths:
            old_url = f"{target}{old_path}"
            new_url = f"{target}{new_path}"
            if not self.check_scope(old_url):
                continue
            await self.rate_limit()
            old_status, old_body = await self._request("GET", old_url)
            if old_status in (200, 201):
                await self.rate_limit()
                new_status, _ = await self._request("GET", new_url)
                if new_status in (200, 201):
                    # Both versions active
                    ev = Evidence(
                        request_raw=f"GET {old_url} HTTP/1.1",
                        response_raw=f"HTTP {old_status}\n{old_body[:300]}",
                        extra={"old_path": old_path, "new_path": new_path},
                    )
                    self.new_finding(
                        title=f"Old API Version Active — {old_path}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Deprecated API version at {old_url} is still active (HTTP {old_status}). "
                            "Old API versions may lack security patches applied to newer versions "
                            "and expose deprecated functionality."
                        ),
                        reproduction_steps=[
                            f"curl {old_url}",
                            f"Observe HTTP {old_status} — endpoint is still accessible",
                        ],
                        remediation=(
                            "Deprecate and eventually disable old API versions. "
                            "Return 410 Gone for deprecated endpoints. "
                            "Notify API consumers in advance and enforce sunset dates."
                        ),
                        references=["OWASP API9:2023", "CWE-284"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_INFO_DISC,
                        target=old_url,
                    )

    async def _check_api_verbose_errors(self, api_paths: list[str], target: str) -> None:
        """Check for verbose error messages on malformed API requests."""
        for base in api_paths[:3]:
            if not self.check_scope(base):
                continue
            # Send malformed JSON to trigger verbose errors
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    headers={"Accept-Encoding": "gzip, deflate"},
                ) as session:
                    async with session.post(
                        base,
                        data="{{malformed json}",
                        headers={"Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        # Look for stack traces, file paths, framework errors
                        verbose_patterns = [
                            r"at [A-Za-z]+\.[A-Za-z]+\([A-Za-z]+\.java:\d+\)",  # Java stacktrace
                            r"File \"/.+\.py\", line \d+",                         # Python traceback
                            r"Traceback \(most recent call last\)",                 # Python
                            r"#\d+ .+\(.*\)$",                                     # C stackframe
                            r"at\s+\w+\s+\(.*:\d+:\d+\)",                         # JS stacktrace
                            r"System\.Web\.",                                        # ASP.NET
                            r"System\.Exception",                                   # .NET
                            r"org\.springframework\.",                               # Spring
                            r"com\.mysql\.jdbc",                                    # MySQL JDBC
                            r"Exception in thread",                                 # Java
                        ]
                        for pattern in verbose_patterns:
                            if re.search(pattern, body, re.I | re.M):
                                ev = Evidence(
                                    request_raw=f"POST {base}\nContent-Type: application/json\n\n{{malformed json}}",
                                    response_raw=body[:800],
                                    extra={"pattern_matched": pattern},
                                )
                                self.new_finding(
                                    title=f"Verbose API Error — Stack Trace Disclosed at {base}",
                                    severity=Severity.MEDIUM,
                                    description=(
                                        f"The API at {base} returned a verbose error message including "
                                        "internal implementation details (stack trace, class names, file paths). "
                                        "This aids attackers in understanding backend architecture and finding vulnerabilities."
                                    ),
                                    reproduction_steps=[
                                        f"curl -X POST {base} -H 'Content-Type: application/json' -d '{{malformed}}'",
                                        "Observe stack trace in response",
                                    ],
                                    remediation=(
                                        "Return generic error messages to clients. "
                                        "Log verbose errors server-side only. "
                                        "Disable debug mode in production."
                                    ),
                                    references=["CWE-209", "OWASP A05:2021"],
                                    evidence=ev,
                                    cvss_v31_vector=CVSS_INFO_DISC,
                                    target=base,
                                )
                                break
            except Exception:
                pass

    async def _check_trace_method(self, target: str) -> None:
        """Check if HTTP TRACE method is enabled (XST vector)."""
        await self.rate_limit()
        status, body = await self._request("TRACE", target)
        if status in (200, 405) and "TRACE" in (body or "").upper()[:200]:
            ev = Evidence(
                request_raw=f"TRACE / HTTP/1.1\nHost: {target}",
                response_raw=f"HTTP {status}\n{body[:300]}",
            )
            self.new_finding(
                title="HTTP TRACE Method Enabled (XST Risk)",
                severity=Severity.LOW,
                description=(
                    f"The server at {target} has HTTP TRACE method enabled (HTTP {status}). "
                    "TRACE echoes the request back including headers, enabling Cross-Site Tracing (XST) "
                    "attacks that can steal cookies even with HttpOnly set (in some older browser scenarios)."
                ),
                reproduction_steps=[
                    f"curl -X TRACE {target}",
                    "Observe request echoed in response body",
                ],
                remediation=(
                    "Disable HTTP TRACE method.\n"
                    "• Apache: TraceEnable Off\n"
                    "• Nginx: if ($request_method = TRACE) { return 405; }"
                ),
                references=["CVE-2003-1567", "CWE-16"],
                evidence=ev,
                cvss_v31_vector=CVSS_INFO_DISC,
                target=target,
            )

    async def _test_mass_assignment(self, endpoint: str, target: str) -> None:
        """Test POST/PUT/PATCH endpoints for mass assignment vulnerabilities."""
        # Only test endpoints that look like resource creation/update
        if not any(m in endpoint.lower() for m in ["/user", "/profile", "/account",
                                                     "/register", "/signup", "/create",
                                                     "/update", "/edit", "/me", "/self"]):
            return

        # First check if endpoint accepts POST/PUT/PATCH
        for method in ["POST", "PUT", "PATCH"]:
            await self.rate_limit()
            # Craft body with both legitimate and privilege-escalation fields
            for extra_fields in MASS_ASSIGN_PROBE_FIELDS[:5]:
                base_body = {"username": "testuser", "email": "test@test.com", "name": "Test"}
                probe_body = {**base_body, **extra_fields}

                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False),
                        headers={"Accept-Encoding": "gzip, deflate"},
                    ) as session:
                        async with session.request(
                            method, endpoint,
                            json=probe_body,
                            headers={"Content-Type": "application/json"},
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            status = resp.status

                            if status in (200, 201, 204):
                                # Check if the privileged field appears accepted in response
                                field_name = list(extra_fields.keys())[0]
                                field_value = str(list(extra_fields.values())[0])

                                if (field_name in body or field_value in body or
                                        "admin" in body.lower() and "admin" in field_name.lower()):
                                    ev = Evidence(
                                        request_raw=f"{method} {endpoint}\nContent-Type: application/json\n\n{_json.dumps(probe_body)[:300]}",
                                        response_raw=body[:600],
                                        extra={
                                            "method":        method,
                                            "probe_body":    probe_body,
                                            "extra_field":   field_name,
                                            "status":        status,
                                        },
                                    )
                                    self.new_finding(
                                        title=f"Potential Mass Assignment — '{field_name}' Field Accepted",
                                        severity=Severity.HIGH,
                                        description=(
                                            f"The endpoint {endpoint} accepted a {method} request "
                                            f"containing the privilege field '{field_name}: {field_value}'. "
                                            "If the backend binds request body directly to model objects without "
                                            "field whitelisting, attackers can escalate privileges by setting "
                                            "admin/role fields during registration or profile updates."
                                        ),
                                        reproduction_steps=[
                                            f"curl -X {method} {endpoint} \\",
                                            f"  -H 'Content-Type: application/json' \\",
                                            f"  -d '{_json.dumps(probe_body)}'",
                                            f"Observe HTTP {status} — check if '{field_name}' was applied",
                                        ],
                                        remediation=(
                                            "Use a strict field allowlist (whitelist) when binding request "
                                            "body to model objects. "
                                            "Never use 'bind all' patterns (e.g., params.permit! in Rails, "
                                            "@RequestBody to full model in Spring). "
                                            "Define explicit DTOs with only permitted fields."
                                        ),
                                        references=["CWE-915", "OWASP API6:2023"],
                                        evidence=ev,
                                        cvss_v31_vector=CVSS_MASS_ASSIGN,
                                        mitre_attack=["TA0004/T1548"],
                                        target=endpoint,
                                    )
                                    return  # One mass assignment finding per endpoint
                except Exception:
                    pass

    async def _test_unauthenticated_access(self, endpoints: list[str], target: str) -> None:
        """Check if sensitive API endpoints are accessible without authentication."""
        sensitive_patterns = [
            "/admin", "/users", "/accounts", "/config", "/settings",
            "/metrics", "/actuator", "/internal", "/private", "/secret",
            "/debug", "/dump", "/backup", "/export",
        ]

        for endpoint in endpoints[:20]:
            if not self.check_scope(endpoint):
                continue
            # Only check endpoints matching sensitive patterns
            path_lower = endpoint.lower()
            if not any(p in path_lower for p in sensitive_patterns):
                continue

            await self.rate_limit()
            try:
                import aiohttp
                # Request without auth headers
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    headers={"Accept-Encoding": "gzip, deflate"},
                ) as session:
                    async with session.get(
                        endpoint,
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=False,
                    ) as resp:
                        status = resp.status
                        body   = await resp.text(errors="ignore")
                        if status in (200, 201):
                            # Check response looks like data (not just a splash page)
                            has_data = (
                                "{" in body or "[" in body or
                                len(body) > 500 or
                                "email" in body.lower() or
                                "username" in body.lower() or
                                "password" in body.lower()
                            )
                            if has_data:
                                ev = Evidence(
                                    request_raw=f"GET {endpoint} HTTP/1.1\n(no Authorization header)",
                                    response_raw=body[:600],
                                    extra={"status": status, "endpoint": endpoint},
                                )
                                self.new_finding(
                                    title=f"Sensitive API Endpoint Accessible Without Auth — {endpoint}",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"The API endpoint {endpoint} returned HTTP {status} "
                                        "without any authentication headers. "
                                        "Sensitive data may be accessible anonymously."
                                    ),
                                    reproduction_steps=[
                                        f"curl {endpoint}",
                                        f"Observe HTTP {status} with data in response",
                                    ],
                                    remediation=(
                                        "Enforce authentication on all sensitive API endpoints. "
                                        "Return 401 Unauthorized for unauthenticated requests. "
                                        "Implement an API gateway with centralised auth enforcement."
                                    ),
                                    references=["CWE-284", "OWASP API1:2023"],
                                    evidence=ev,
                                    cvss_v31_vector=CVSS_API_UNAUTH,
                                    mitre_attack=["TA0006/T1552"],
                                    target=endpoint,
                                )
            except Exception:
                pass

    async def _request(self, method: str, url: str) -> tuple[int, str]:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                headers={"Accept-Encoding": "gzip, deflate"},
            ) as session:
                async with session.request(
                    method, url,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    body = await resp.text(errors="ignore")
                    return resp.status, body
        except Exception as exc:
            self.log.debug("REST request %s %s failed: %s", method, url, exc)
            return -1, ""


class TestRestAudit:
    def test_http_verbs_list(self) -> None:
        assert "GET" in HTTP_VERBS
        assert "DELETE" in HTTP_VERBS
        assert "TRACE" in HTTP_VERBS

    def test_mass_assign_fields_defined(self) -> None:
        assert len(MASS_ASSIGN_PROBE_FIELDS) >= 5
        field_names = [list(f.keys())[0] for f in MASS_ASSIGN_PROBE_FIELDS]
        assert "is_admin" in field_names or "admin" in field_names
        assert "role" in field_names

    def test_api_discovery_paths_nonempty(self) -> None:
        assert "/api/v1" in API_DISCOVERY_PATHS
        assert "/swagger.json" in API_DISCOVERY_PATHS

    def test_cvss_vectors_valid(self) -> None:
        for v in (CVSS_API_UNAUTH, CVSS_VERB, CVSS_MASS_ASSIGN, CVSS_INFO_DISC):
            assert v.startswith("CVSS:3.1/")
