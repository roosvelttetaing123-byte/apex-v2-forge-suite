"""Rate limit testing — probe API rate limiting, throttling, and abuse prevention controls."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L"

RATE_TEST_CONFIGS: list[dict[str, Any]] = [
    {"id": "burst_10", "name": "10-request burst",
     "count": 10, "delay_ms": 0,
     "description": "Rapid-fire 10 requests with zero delay"},
    {"id": "burst_25", "name": "25-request burst",
     "count": 25, "delay_ms": 0,
     "description": "25 requests with no throttling"},
    {"id": "sustained_50", "name": "50 requests at 100ms interval",
     "count": 50, "delay_ms": 100,
     "description": "Sustained load simulating aggressive automation"},
    {"id": "concurrent_5", "name": "5 concurrent requests",
     "count": 5, "delay_ms": 0, "concurrent": True,
     "description": "Parallel request batch to test concurrency limits"},
]


class RateLimitTest(BaseModule):
    """Rate limit testing — probe API throttling and abuse prevention.

    This module tests whether the target enforces rate limits by sending
    controlled bursts and sustained request streams. It does NOT aim to
    cause denial of service — it measures the enforcement response.
    """

    NAME        = "rate_limit_test"
    DESCRIPTION = "Test API rate limiting: burst detection, sustained load response, concurrency limits"
    PHASE       = 7
    TAGS        = ["dos", "rate-limit", "owasp-llm04"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        from aiforge.core.llm_client import LLMClient
        async with LLMClient(
            api_type=self.config.extra.get("api_type", "custom"),
            endpoint=target,
            api_key=self.config.extra.get("api_key", ""),
            model_name=self.config.extra.get("model_name", ""),
            max_tokens=50, temperature=0.0,
            proxy=self.config.extra.get("proxy"),
            outbound_policy=self.outbound_policy,
        ) as client:
            test_results: list[dict[str, Any]] = []

            for config in RATE_TEST_CONFIGS:
                is_concurrent = config.get("concurrent", False)

                if is_concurrent:
                    result = await self._test_concurrent(client, config)
                else:
                    result = await self._test_sequential(client, config)

                test_results.append(result)

            # Analyze rate limit enforcement
            no_limit = [r for r in test_results if r["rate_limited_count"] == 0]
            has_limit = [r for r in test_results if r["rate_limited_count"] > 0]

            if no_limit:
                severity = Severity.MEDIUM if len(no_limit) >= 2 else Severity.LOW
                self.new_finding(
                    title=f"Weak Rate Limiting: {len(no_limit)} test patterns not throttled",
                    severity=severity,
                    description=(
                        f"The API did not enforce rate limits for {len(no_limit)} test patterns.\n\n"
                        + "\n".join(
                            f"- {r['name']}: {r['success_count']}/{r['total']} succeeded, "
                            f"0 rate-limited"
                            for r in no_limit
                        )
                        + "\n\nWithout rate limiting, an attacker can:\n"
                        "- Exhaust API quotas and increase costs\n"
                        "- Perform brute-force attacks on guardrails\n"
                        "- Extract training data via high-volume probing\n"
                        "- Degrade service for other users"
                    ),
                    reproduction_steps=[
                        f"Send {no_limit[0]['total']} requests with {no_limit[0].get('delay_ms', 0)}ms delay",
                        "Observe: all requests succeed without 429/throttling",
                    ],
                    remediation=(
                        "1. Implement token-bucket or sliding-window rate limiting\n"
                        "2. Set per-user and per-IP request quotas\n"
                        "3. Return HTTP 429 with Retry-After header\n"
                        "4. Implement exponential backoff enforcement\n"
                        "5. Monitor for anomalous request patterns"
                    ),
                    references=["OWASP LLM04", "CWE-770"],
                    evidence=Evidence(extra={"tests": test_results}),
                    cvss_v31_vector=CVSS31,
                    cvss_v40_vector=CVSS40,
                    target=target,
                )

            if has_limit:
                self.log.info(
                    "Rate limiting detected in %d/%d tests",
                    len(has_limit), len(test_results),
                )

        return self._make_result(start)

    async def _test_sequential(self, client: Any, config: dict[str, Any]) -> dict[str, Any]:
        success = 0
        rate_limited = 0
        errors = 0
        latencies: list[float] = []

        for _ in range(config["count"]):
            t0 = time.monotonic()
            try:
                resp = await client.send("Say 'pong'.")
                latencies.append(time.monotonic() - t0)
                if resp.success:
                    success += 1
                elif resp.status_code == 429:
                    rate_limited += 1
                else:
                    errors += 1
            except Exception:
                errors += 1
                latencies.append(time.monotonic() - t0)

            if config["delay_ms"] > 0:
                await asyncio.sleep(config["delay_ms"] / 1000)

        return {
            "id": config["id"], "name": config["name"],
            "total": config["count"],
            "success_count": success, "rate_limited_count": rate_limited,
            "error_count": errors,
            "avg_latency_ms": round(sum(latencies) / len(latencies) * 1000, 1) if latencies else 0,
            "delay_ms": config["delay_ms"],
        }

    async def _test_concurrent(self, client: Any, config: dict[str, Any]) -> dict[str, Any]:
        async def single_request() -> tuple[bool, bool, float]:
            t0 = time.monotonic()
            try:
                resp = await client.send("Say 'pong'.")
                elapsed = time.monotonic() - t0
                return (resp.success, getattr(resp, "status_code", 200) == 429, elapsed)
            except Exception:
                return (False, False, time.monotonic() - t0)

        tasks = [single_request() for _ in range(config["count"])]
        results = await asyncio.gather(*tasks)

        success = sum(1 for s, _, _ in results if s)
        rate_limited = sum(1 for _, rl, _ in results if rl)
        latencies = [e for _, _, e in results]

        return {
            "id": config["id"], "name": config["name"],
            "total": config["count"], "concurrent": True,
            "success_count": success, "rate_limited_count": rate_limited,
            "error_count": config["count"] - success - rate_limited,
            "avg_latency_ms": round(sum(latencies) / len(latencies) * 1000, 1) if latencies else 0,
        }


class TestRateLimitTest:
    def test_config_count(self) -> None:
        assert len(RATE_TEST_CONFIGS) >= 4

    def test_configs_have_count(self) -> None:
        for c in RATE_TEST_CONFIGS:
            assert c["count"] > 0
