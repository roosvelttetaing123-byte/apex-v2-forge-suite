"""Command injection scanner — detect OS command injection in parameters."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_RCE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_RCE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
# Canary for time-based detection
SLEEP_SECONDS = 5

INJECT_PAYLOADS = [
    # Linux time-based (most reliable — no output needed)
    (f"; sleep {SLEEP_SECONDS}", "sleep-semicolon-linux"),
    (f"| sleep {SLEEP_SECONDS}", "sleep-pipe-linux"),
    (f"& sleep {SLEEP_SECONDS}", "sleep-amp-linux"),
    (f"`sleep {SLEEP_SECONDS}`", "sleep-backtick-linux"),
    (f"$(sleep {SLEEP_SECONDS})", "sleep-subshell-linux"),
    # Windows time-based
    (f"& timeout /T {SLEEP_SECONDS}", "timeout-windows"),
    (f"; timeout /T {SLEEP_SECONDS}", "timeout-semi-windows"),
    # Output-based
    ("; echo CMDINJECT", "echo-semicolon"),
    ("| echo CMDINJECT", "echo-pipe"),
    ("& echo CMDINJECT", "echo-amp"),
    ("\necho CMDINJECT", "echo-newline"),
]

OUTPUT_INDICATORS = ["CMDINJECT"]


class CmdInject(BaseModule):
    """OS command injection scanner."""

    NAME        = "cmd_inject"
    DESCRIPTION = "Detect OS command injection via time-based and output-based probes"
    PHASE       = 4
    TAGS        = ["injection", "rce", "command", "cwe-78", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Gather test parameters from crawler
        crawled = self.config.extra.get("crawled_urls", [target])
        forms   = self.config.extra.get("found_forms", [])

        sem = asyncio.Semaphore(2)
        tasks: list = []

        # Test URL parameters
        for url in crawled[:30]:
            if "?" in url:
                tasks.append(self._test_url_params(url, target, sem))

        # Test forms
        for form in forms[:10]:
            if form.get("method") == "POST" and form.get("inputs"):
                tasks.append(self._test_form(form, target, sem))

        await asyncio.gather(*tasks, return_exceptions=True)
        return self._make_result(start)

    async def _test_url_params(self, url: str, target: str, sem: asyncio.Semaphore) -> None:
        from urllib.parse import urlparse, parse_qs, urlencode
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            original_val = params[param_name][0] if params[param_name] else ""
            for payload, label in INJECT_PAYLOADS[:6]:  # Test first 6 payloads
                async with sem:
                    await self.rate_limit()
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = original_val + payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                    if not self.check_scope(test_url):
                        continue

                    found = await self._probe(test_url, label, param_name, target)
                    if found:
                        return  # Already reported for this param

    async def _test_form(self, form: dict, target: str, sem: asyncio.Semaphore) -> None:
        action = form["action"]
        if not action.startswith("http"):
            action = f"{target.rstrip('/')}/{action.lstrip('/')}"
        if not self.check_scope(action):
            return

        for input_name in form.get("inputs", []):
            for payload, label in INJECT_PAYLOADS[:6]:
                async with sem:
                    await self.rate_limit()
                    data = {i: "test" for i in form["inputs"]}
                    data[input_name] = "test" + payload
                    found = await self._probe_post(action, data, label, input_name, target)
                    if found:
                        return

    async def _probe(
        self, url: str, label: str, param: str, target: str
    ) -> bool:
        """Probe via GET for time-based or output-based injection."""
        is_time_based = "sleep" in label or "timeout" in label
        try:
            import aiohttp
            start_time = time.monotonic()
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                timeout = aiohttp.ClientTimeout(total=SLEEP_SECONDS + 5)
                async with session.get(url, timeout=timeout) as resp:
                    elapsed = time.monotonic() - start_time
                    body = await resp.text(errors="ignore")

            if is_time_based and elapsed >= SLEEP_SECONDS * 0.9:
                self._report_injection(url, param, label, "time-based", elapsed, "", target)
                return True
            elif not is_time_based and any(ind in body for ind in OUTPUT_INDICATORS):
                self._report_injection(url, param, label, "output-based", 0, body, target)
                return True
        except asyncio.TimeoutError:
            if is_time_based:
                self._report_injection(url, param, label, "time-based (timeout)", SLEEP_SECONDS, "", target)
                return True
        except Exception:
            pass
        return False

    async def _probe_post(
        self, url: str, data: dict, label: str, param: str, target: str
    ) -> bool:
        is_time_based = "sleep" in label or "timeout" in label
        try:
            import aiohttp
            start_time = time.monotonic()
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                timeout = aiohttp.ClientTimeout(total=SLEEP_SECONDS + 5)
                async with session.post(url, data=data, timeout=timeout) as resp:
                    elapsed = time.monotonic() - start_time
                    body = await resp.text(errors="ignore")

            if is_time_based and elapsed >= SLEEP_SECONDS * 0.9:
                self._report_injection(url, param, label, "time-based", elapsed, "", target)
                return True
            elif not is_time_based and any(ind in body for ind in OUTPUT_INDICATORS):
                self._report_injection(url, param, label, "output-based", 0, body, target)
                return True
        except asyncio.TimeoutError:
            if is_time_based:
                self._report_injection(url, param, label, "time-based (timeout)", SLEEP_SECONDS, "", target)
                return True
        except Exception:
            pass
        return False

    def _report_injection(
        self, url: str, param: str, label: str,
        detection_method: str, elapsed: float, body: str, target: str
    ) -> None:
        ev = Evidence(
            request_raw=f"URL: {url}\nParam: {param}\nPayload: {label}",
            response_raw=body[:500] if body else f"Elapsed: {elapsed:.1f}s",
            extra={
                "url": url, "param": param, "payload": label,
                "detection": detection_method, "elapsed": elapsed,
            },
        )
        self.new_finding(
            title=f"OS Command Injection ({detection_method}) — {param} @ {url.split('?')[0].split('/')[-1]}",
            severity=Severity.CRITICAL,
            description=(
                f"OS command injection confirmed in parameter '{param}' at {url}. "
                f"Detection method: {detection_method}. "
                "An attacker can execute arbitrary OS commands on the server, "
                "leading to full system compromise."
            ),
            reproduction_steps=[
                f"Test: curl '{url}'",
                f"Payload type: {label}",
                f"Evidence: {detection_method}",
            ],
            remediation=(
                "Never pass user input to OS shell functions. "
                "Use parameterized API calls instead of shell commands. "
                "If shell execution is required, use allowlists and strict input validation."
            ),
            references=["CWE-78", "OWASP A03:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_RCE,
            cvss_v40_vector=CVSS40_RCE,
            mitre_attack=["TA0002/T1059"],
            target=target,
            url=url,
        )


class TestCmdInject:
    def test_payloads_not_empty(self) -> None:
        assert len(INJECT_PAYLOADS) >= 6

    def test_sleep_seconds_positive(self) -> None:
        assert SLEEP_SECONDS > 0

    def test_output_indicators(self) -> None:
        body = "result: CMDINJECT done"
        assert any(ind in body for ind in OUTPUT_INDICATORS)
