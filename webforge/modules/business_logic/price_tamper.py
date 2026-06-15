"""Price/quantity manipulation detection — business logic flaw."""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import aiohttp

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_PRICE_TAMPER = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"

PRICE_PARAMS   = ["price", "amount", "cost", "total", "subtotal", "unit_price", "fee"]
QTY_PARAMS     = ["quantity", "qty", "count", "num", "number", "units"]
TAMPER_VALUES  = ["0", "-1", "-0.01", "0.001", "99999999", "null", "undefined", "NaN"]


class PriceTamper(BaseModule):
    """Detect price and quantity manipulation in e-commerce/checkout flows."""

    NAME        = "price_tamper"
    DESCRIPTION = "Detect price/quantity parameter manipulation in checkout/cart flows"
    PHASE       = 9
    TAGS        = ["business-logic", "price-tamper", "owasp-a04", "cwe-840"]

    async def run(self) -> ModuleResult:
        """Scan target for price/quantity manipulation vulnerabilities."""
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        confirmed = self.confirm_action(
            action="Submit modified price/quantity values to cart/checkout endpoints",
            target=target,
            risk="May generate fraudulent order entries if endpoint is live",
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=12)
        headers   = {
            "User-Agent": "Mozilla/5.0 (forge-suite price_tamper)",
            "Content-Type": "application/json",
        }

        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            cart_urls = await self._discover_cart_urls(session, target)
            for url, method, params in cart_urls:
                await self._test_parameter_tampering(session, url, method, params)

        return self._make_result(start)

    async def _discover_cart_urls(
        self, session: aiohttp.ClientSession, target: str
    ) -> list[tuple[str, str, dict]]:
        """Probe common cart/checkout endpoint patterns."""
        candidates = [
            ("/cart", "GET"), ("/cart/add", "POST"), ("/checkout", "POST"),
            ("/api/cart", "POST"), ("/api/order", "POST"),
            ("/shop/cart", "POST"), ("/store/checkout", "POST"),
        ]
        found: list[tuple[str, str, dict]] = []
        for path, method in candidates:
            url = f"{target}{path}"
            if not self.check_scope(url):
                continue
            await self.rate_limit()
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    body = await resp.text(errors="ignore")
                    if resp.status in (200, 302, 405):
                        # Look for price/qty params in response body
                        params: dict = {}
                        for p in PRICE_PARAMS + QTY_PARAMS:
                            if p in body.lower():
                                params[p] = "1.00" if p in PRICE_PARAMS else "1"
                        if params:
                            found.append((url, method, params))
            except Exception:
                pass
        return found

    async def _test_parameter_tampering(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        params: dict,
    ) -> None:
        """Send manipulated parameter values and check for acceptance."""
        for param, original_val in params.items():
            for tamper_val in TAMPER_VALUES:
                payload = {**params, param: tamper_val}
                await self.rate_limit()
                try:
                    if method == "POST":
                        async with session.post(url, json=payload) as resp:
                            status = resp.status
                            body   = await resp.text(errors="ignore")
                    else:
                        async with session.get(url, params=payload) as resp:
                            status = resp.status
                            body   = await resp.text(errors="ignore")

                    # Success indicators: 200/201 without an error mentioning invalid price
                    error_words = ["invalid", "error", "negative", "must be", "greater than"]
                    accepted = (
                        status in (200, 201, 202)
                        and not any(e in body.lower() for e in error_words)
                    )

                    if accepted:
                        ev = Evidence(
                            request_raw=(
                                f"{method} {url} HTTP/1.1\n"
                                f"Content-Type: application/json\n\n"
                                f"{json.dumps(payload)}"
                            ),
                            response_raw=f"HTTP {status}\n{body[:400]}",
                            extra={
                                "param": param,
                                "original": original_val,
                                "tampered": tamper_val,
                            },
                        )
                        self.new_finding(
                            title=f"Price/Quantity Manipulation Accepted: {param}={tamper_val} at {url}",
                            severity=Severity.HIGH,
                            description=(
                                f"The parameter '{param}' was manipulated to '{tamper_val}' "
                                f"in a {method} request to {url}. "
                                "The server accepted the request without rejecting the "
                                "invalid value, indicating a business logic flaw that "
                                "may allow free or negative-cost purchases."
                            ),
                            reproduction_steps=[
                                f"Submit {method} request to {url}",
                                f"Set parameter '{param}' = '{tamper_val}'",
                                f"Observe HTTP {status} — request accepted",
                            ],
                            remediation=(
                                "Validate all price and quantity values server-side. "
                                "Reject negative, zero, or non-numeric values. "
                                "Never trust client-submitted price data — always "
                                "fetch the canonical price from the product catalog."
                            ),
                            references=["CWE-840", "OWASP A04:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_PRICE_TAMPER,
                            mitre_attack=["TA0040/T1565"],
                            target=url,
                        )
                        return  # one finding per param
                except Exception:
                    pass


class TestPriceTamper:
    def test_price_params_non_empty(self) -> None:
        assert len(PRICE_PARAMS) >= 4

    def test_tamper_values_include_negative(self) -> None:
        assert "-1" in TAMPER_VALUES

    def test_cvss_format(self) -> None:
        assert CVSS_PRICE_TAMPER.startswith("CVSS:3.1/")
