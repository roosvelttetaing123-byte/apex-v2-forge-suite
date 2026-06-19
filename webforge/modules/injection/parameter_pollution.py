"""HTTP Parameter Pollution (HPP) scanner."""
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

CVSS_HPP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_HPP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
CANARY_SAFE    = "FORGE_HPP_SAFE_VALUE"
CANARY_INJECT  = "FORGE_HPP_INJECT_VALUE"


class ParameterPollution(BaseModule):
    """HTTP Parameter Pollution (HPP) scanner."""

    NAME        = "parameter_pollution"
    DESCRIPTION = "Detect HTTP Parameter Pollution — duplicate parameter injection"
    PHASE       = 4
    TAGS        = ["injection", "hpp", "parameter", "cwe-235", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        crawled = self.config.extra.get("crawled_urls", [target])
        forms   = self.config.extra.get("found_forms", [])

        sem = asyncio.Semaphore(3)

        # Test URL params
        tasks = [
            self._test_url(url, target, sem)
            for url in crawled[:30]
            if "?" in url
        ]

        # Test form params
        for form in forms[:10]:
            if form.get("inputs"):
                tasks.append(self._test_form(form, target, sem))

        await asyncio.gather(*tasks, return_exceptions=True)
        return self._make_result(start)

    async def _test_url(self, url: str, target: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                return

            for param_name, values in params.items():
                await self.rate_limit()
                if not self.check_scope(url):
                    continue

                # Baseline with normal value
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = CANARY_SAFE
                baseline_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{urlencode(test_params)}"
                )
                baseline_status, baseline_body = await self._get(baseline_url)

                # HPP: duplicate param — first normal, then injected
                hpp_query = urlencode(test_params) + f"&{param_name}={CANARY_INJECT}"
                hpp_url   = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{hpp_query}"
                )
                hpp_status, hpp_body = await self._get(hpp_url)

                # Detect: if injected value appears in response, the server uses the last value
                if CANARY_INJECT in hpp_body and CANARY_SAFE not in hpp_body:
                    ev = Evidence(
                        request_raw=f"GET {hpp_url}",
                        response_raw=hpp_body[:500],
                        extra={
                            "param":          param_name,
                            "normal_url":     baseline_url,
                            "hpp_url":        hpp_url,
                            "server_uses":    "last value",
                        },
                    )
                    self.new_finding(
                        title=f"HTTP Parameter Pollution — {param_name} (last-value wins)",
                        severity=Severity.MEDIUM,
                        description=(
                            f"HPP detected in parameter '{param_name}'. "
                            f"When '{param_name}' is supplied twice, the server uses the LAST value. "
                            "This can be exploited to bypass input validation or WAF rules by splitting "
                            "a malicious payload across two instances of the same parameter."
                        ),
                        reproduction_steps=[
                            f"curl '{hpp_url}'",
                            f"Compare with: curl '{baseline_url}'",
                        ],
                        remediation=(
                            "Explicitly handle duplicate parameters. "
                            "Use only the first occurrence of each parameter. "
                            "Reject requests with duplicate security-critical parameters."
                        ),
                        references=["CWE-235", "OWASP HPP", "OWASP A03:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_HPP,
                        cvss_v40_vector=CVSS40_HPP,
                        target=target,
                        url=url,
                    )

                elif CANARY_INJECT in hpp_body and CANARY_SAFE in hpp_body:
                    ev = Evidence(
                        request_raw=f"GET {hpp_url}",
                        response_raw=hpp_body[:300],
                        extra={"param": param_name, "server_uses": "array/concat"},
                    )
                    self.new_finding(
                        title=f"HTTP Parameter Pollution — {param_name} (array/concat behavior)",
                        severity=Severity.LOW,
                        description=(
                            f"HPP detected — server concatenates or arrays duplicate '{param_name}' values. "
                            "May enable filter bypass depending on application logic."
                        ),
                        reproduction_steps=[f"curl '{hpp_url}'"],
                        remediation="Validate that duplicate parameters are handled safely.",
                        references=["CWE-235"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_HPP,
                        cvss_v40_vector=CVSS40_HPP,
                        target=target,
                        url=url,
                    )

    async def _test_form(self, form: dict, target: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            action = form["action"]
            if not action.startswith("http"):
                action = f"{target.rstrip('/')}/{action.lstrip('/')}"
            if not self.check_scope(action):
                return

            await self.rate_limit()
            inputs = form.get("inputs", [])
            if not inputs:
                return

            first_param = inputs[0]

            # Baseline
            data = {i: "test" for i in inputs}
            data[first_param] = CANARY_SAFE
            baseline_status, baseline_body = await self._post(action, data)

            # HPP via duplicate field in POST body
            body_str = urlencode(data) + f"&{first_param}={CANARY_INJECT}"

            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.post(
                        action,
                        data=body_str,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as resp:
                        body = await resp.text(errors="ignore")

                if CANARY_INJECT in body:
                    ev = Evidence(
                        request_raw=f"POST {action}\n{body_str}",
                        response_raw=body[:300],
                        extra={"param": first_param},
                    )
                    self.new_finding(
                        title=f"HPP in POST Form — {first_param} ({action})",
                        severity=Severity.MEDIUM,
                        description=f"POST parameter pollution: duplicate {first_param} uses last value.",
                        reproduction_steps=[f"curl -X POST {action} -d '{body_str}'"],
                        remediation="Reject or explicitly handle duplicate POST parameters.",
                        references=["CWE-235"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_HPP,
                        cvss_v40_vector=CVSS40_HPP,
                        target=target,
                        url=action,
                    )
            except Exception:
                pass

    async def _get(self, url: str) -> tuple[int, str]:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
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
                    url, data=data, timeout=aiohttp.ClientTimeout(total=8)
                ) as resp:
                    return resp.status, await resp.text(errors="ignore")
        except Exception:
            return 0, ""


class TestParameterPollution:
    def test_canary_values_distinct(self) -> None:
        assert CANARY_SAFE != CANARY_INJECT

    def test_cvss_vector(self) -> None:
        assert CVSS_HPP.startswith("CVSS:3.1")
