"""Race condition scanner — detect TOCTOU and race conditions in sensitive operations."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.confirm_gate import confirm
from common.evidence import Evidence
from common.finding import Severity

CVSS_RACE = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:N"
CVSS40_RACE = "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N"
RACE_TARGETS = [
    # (path_pattern, method, description)
    ("/api/redeem", "POST", "coupon/voucher redemption"),
    ("/api/use-coupon", "POST", "coupon use"),
    ("/coupon/redeem", "POST", "coupon redemption"),
    ("/api/transfer", "POST", "fund transfer"),
    ("/api/vote", "POST", "voting endpoint"),
    ("/api/like", "POST", "like endpoint"),
    ("/api/withdraw", "POST", "withdrawal"),
    ("/api/gift", "POST", "gift card"),
    ("/api/promo", "POST", "promo code"),
    ("/api/purchase", "POST", "purchase"),
    ("/register", "POST", "user registration"),
    ("/api/claim", "POST", "claim endpoint"),
]

RACE_THREADS = 10
RACE_TIMEOUT = 5.0


class RaceCondition(BaseModule):
    """Race condition (TOCTOU) scanner."""

    NAME        = "race_condition"
    DESCRIPTION = "Detect race condition vulnerabilities in coupon/transfer/voting endpoints"
    PHASE       = 9
    TAGS        = ["business-logic", "race-condition", "toctou", "cwe-362", "owasp-a04"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Find race-prone endpoints
        race_endpoints: list[tuple[str, str, str]] = []
        crawled = self.config.extra.get("crawled_urls", [])

        for path, method, desc in RACE_TARGETS:
            url = f"{target}{path}"
            if self.check_scope(url):
                race_endpoints.append((url, method, desc))

        # Also check crawled URLs for race-prone patterns
        import re
        race_pattern = re.compile(
            r"(redeem|coupon|promo|voucher|transfer|withdraw|vote|like|claim|gift)",
            re.IGNORECASE
        )
        for url in crawled[:50]:
            if race_pattern.search(url):
                race_endpoints.append((url, "POST", "detected from crawl"))

        if not race_endpoints:
            self.log.info("No race-prone endpoints found")
            return self._make_result(start)

        confirmed = self.confirm_action(
            module=self.NAME,
            action=(
                f"Test {len(race_endpoints)} endpoint(s) for race conditions "
                f"({RACE_THREADS} concurrent requests per endpoint)"
            ),
            target=target,
            risk=(
                "Sends concurrent duplicate requests — may trigger duplicate operations "
                "(double charges, double redemptions). Test only on test/staging environments."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        for url, method, desc in race_endpoints[:5]:
            await self._test_race(url, method, desc, target)

        return self._make_result(start)

    async def _test_race(
        self, url: str, method: str, desc: str, target: str
    ) -> None:
        """Send concurrent requests and look for race condition indicators."""
        self.log.info("Testing race condition on %s (%s)", url, desc)

        # Prepare simultaneous requests
        results: list[tuple[int, str]] = []

        async def _single_request():
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    req = getattr(session, method.lower(), session.post)
                    async with req(
                        url,
                        data={"amount": "1", "code": "TEST10", "quantity": "1"},
                        json={"amount": 1, "code": "TEST10", "quantity": 1},
                        timeout=aiohttp.ClientTimeout(total=RACE_TIMEOUT),
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        return resp.status, body
            except Exception:
                return 0, ""

        # Launch all at once
        tasks = [_single_request() for _ in range(RACE_THREADS)]
        start_time = time.monotonic()
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.monotonic() - start_time

        for r in raw_results:
            if isinstance(r, tuple):
                results.append(r)

        success_count = sum(1 for status, _ in results if status == 200)
        unique_bodies = len(set(body[:50] for _, body in results if body))

        # Race condition indicators:
        # - Multiple 200 responses (should only be 1)
        # - Different response bodies (some succeeded, some failed)
        if success_count > 1 and unique_bodies > 1:
            ev = Evidence(
                extra={
                    "url":             url,
                    "description":     desc,
                    "success_count":   success_count,
                    "total_requests":  RACE_THREADS,
                    "elapsed_s":       round(elapsed, 2),
                    "unique_responses": unique_bodies,
                }
            )
            self.new_finding(
                title=f"Race Condition — Multiple Successes in {desc} ({url.split('/')[-1]})",
                severity=Severity.HIGH,
                description=(
                    f"Sent {RACE_THREADS} concurrent requests to {url} ({desc}). "
                    f"Got {success_count} success responses — expected 1. "
                    "This suggests a race condition: the action was processed multiple times "
                    "before the first completion was recorded."
                ),
                reproduction_steps=[
                    f"# Send {RACE_THREADS} concurrent requests:",
                    f"python3 -c \"import asyncio, aiohttp; ...(concurrent POST to {url})\"",
                    f"Or use Burp Intruder with {RACE_THREADS} threads, single-packet attack",
                ],
                remediation=(
                    "Use database-level locks or atomic operations. "
                    "Implement idempotency keys for POST requests. "
                    "Use SELECT FOR UPDATE in database transactions. "
                    "Rate-limit per-user, not just globally."
                ),
                references=["CWE-362", "OWASP A04:2021"],
                evidence=ev,
                cvss_v31_vector=CVSS_RACE,
                cvss_v40_vector=CVSS40_RACE,
                target=target,
                url=url,
                operator_confirmed=True,
            )


class TestRaceCondition:
    def test_race_targets_not_empty(self) -> None:
        assert len(RACE_TARGETS) >= 5

    def test_race_threads_positive(self) -> None:
        assert RACE_THREADS > 5
