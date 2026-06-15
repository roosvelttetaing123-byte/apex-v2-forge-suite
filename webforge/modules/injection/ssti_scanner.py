"""SSTI Scanner — Server-Side Template Injection for Jinja2, Twig, Freemarker, Pebble, Velocity."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# Engine-specific probes: (payload, expected_output_contains, engine_name)
SSTI_PROBES: list[tuple[str, str, str]] = [
    ("{{7*7}}",          "49",    "Jinja2/Twig"),
    ("${7*7}",           "49",    "Freemarker/Spring"),
    ("#{7*7}",           "49",    "Pebble/Thymeleaf"),
    ("*{7*7}",           "49",    "Thymeleaf"),
    ("<%= 7*7 %>",       "49",    "ERB/Ruby"),
    ("{{7*'7'}}",        "7777777","Jinja2"),
    ("{7*7}",            "49",    "Smarty"),
    ("{% 49 %}",        "49",    "Django (error)"),
    ("{{config}}",       "SECRET","Jinja2 (config leak)"),
    ("{{request}}",      "Request","Jinja2 (object leak)"),
    ("${\"freemarker\".class}", "freemarker", "Freemarker"),
    ("#set($x=7*7)$x",   "49",    "Velocity"),
]

CVSS_SSTI = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


class SstiScanner(BaseModule):
    """SSTI scanner — detects template injection across multiple engine types."""

    NAME        = "ssti_scanner"
    DESCRIPTION = "Server-Side Template Injection: Jinja2, Twig, Freemarker, Velocity, ERB"
    PHASE       = 4
    TAGS        = ["ssti", "injection", "owasp-a03", "cwe-94", "rce"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting SSTI scan on %s", target)

        from webforge.core.session import ForgeSession
        async with ForgeSession(
            rate=self.config.rate.requests_per_second,
            proxy=self.config.extra.get("proxy"),
        ) as session:
            await self._test_params(session, target)

        return self._make_result(start)

    async def _test_params(self, session: Any, url: str) -> None:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        for param_name in params:
            for payload, expected, engine in SSTI_PROBES:
                await self.rate_limit()
                test_url = self._inject_param(url, param_name, payload)
                try:
                    resp = await session.get(test_url)
                    body = await resp.text()
                    if expected.lower() in body.lower():
                        ss = self.capture_screenshot(
                            test_url, f"ssti_{param_name}",
                            highlight_js=(
                                f"(function(){{var body=document.body.innerHTML;"
                                f"document.body.innerHTML=body.replace(/{re.escape(expected)}/g,"
                                f"'<span style=\"background:red;color:white;padding:2px\">{expected}</span>');}})();"
                            )
                        )
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:3000],
                            screenshot_path=ss,
                            extra={"payload": payload, "param": param_name,
                                   "expected": expected, "engine": engine},
                        )
                        self.new_finding(
                            title=f"Server-Side Template Injection ({engine}) — Parameter '{param_name}'",
                            severity=Severity.CRITICAL,
                            description=(
                                f"SSTI detected in parameter '{param_name}' using {engine} syntax. "
                                f"Payload {payload!r} returned {expected!r}, confirming template expression evaluation. "
                                "SSTI typically leads to Remote Code Execution (RCE) on the server."
                            ),
                            reproduction_steps=[
                                f"Send GET request to: {test_url}",
                                f"Observe '{expected}' in response (7×7=49 confirms expression evaluation)",
                                f"For {engine}: attempt RCE with class traversal payloads",
                                "Test: {{config.items()}} or {{''.__class__.__mro__[1].__subclasses__()}}",
                            ],
                            remediation=(
                                "Never pass user-controlled input directly to template engines. "
                                "Use sandboxed template environments. "
                                "Validate and sanitize all user input before template rendering. "
                                "Consider using template engines that auto-escape output."
                            ),
                            references=["CWE-94", "OWASP A03:2021",
                                        "https://portswigger.net/research/server-side-template-injection"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_SSTI,
                            mitre_attack=["TA0002/T1059"],
                            target=test_url,
                        )
                        return  # Found — stop testing this param
                except Exception as exc:
                    self.log.debug("SSTI probe failed: %s", exc)

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in params.items()})))


class TestSstiScanner:
    def test_probes_not_empty(self) -> None:
        assert len(SSTI_PROBES) >= 10

    def test_probe_structure(self) -> None:
        for payload, expected, engine in SSTI_PROBES:
            assert payload and expected and engine

    def test_jinja2_probe(self) -> None:
        payload, expected, engine = SSTI_PROBES[0]
        assert "7*7" in payload
        assert "49" == expected
