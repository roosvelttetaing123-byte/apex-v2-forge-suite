"""Price Tamper — detect client-side price manipulation in e-commerce."""
from __future__ import annotations
import re, json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"

class PriceTamper(BaseModule):
    NAME = "price_tamper"
    DESCRIPTION = "Business Logic: detect client-side price/quantity tampering"
    PHASE = 9
    TAGS = ["business-logic", "price", "cwe-472"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        confirmed = self.confirm_action(
            module=self.NAME,
            action="POST modified price/quantity values (-1, 0) to cart/checkout endpoints",
            target=target,
            risk=(
                "Sends POST requests with tampered price fields to checkout endpoints — "
                "may affect cart state or trigger partial orders. Run on test/staging only."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        async with self.http_session(timeout=10) as session:
            # Look for forms with price/amount/total/quantity fields
            cart_paths = ["/cart", "/checkout", "/basket", "/order", "/api/cart", "/api/orders"]
            price_fields = []

            for path in cart_paths:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}{path}") as resp:
                        body = await resp.text(errors="ignore")
                        # Find hidden inputs with price/amount values
                        for m in re.finditer(
                            r'<input[^>]*(?:name|id)="([^"]*(?:price|amount|total|cost|quantity|qty)[^"]*)"'
                            r'[^>]*(?:value="([^"]*)")?', body, re.I):
                            price_fields.append({"path": path, "field": m.group(1), "value": m.group(2) or "?"})

                        # Check for JSON API responses with price data
                        if resp.content_type and "json" in resp.content_type:
                            try:
                                data = json.loads(body)
                                self._find_price_keys(data, path, price_fields)
                            except json.JSONDecodeError:
                                pass
                except Exception as exc:
                    self.log.debug("price_tamper: GET %s%s error: %s", target, path, exc)

            if price_fields:
                # Test: Try submitting modified prices
                tamper_results = []
                for field_info in price_fields[:5]:
                    path = field_info["path"]
                    field = field_info["field"]
                    orig_value = field_info["value"]

                    for tamper_value in ("-1", "0"):
                        # Probe 1: POST the tampered value
                        await self.rate_limit()
                        try:
                            async with session.post(
                                f"{target}{path}",
                                data={field: tamper_value, "quantity": "1"},
                            ) as resp:
                                body = await resp.text(errors="ignore")
                                if resp.status != 200 or "error" in body.lower()[:200]:
                                    continue

                            # Probe 2: re-fetch the resource and check if tampered value persisted
                            # Only flag HIGH if server reflects the tampered value back
                            await self.rate_limit()
                            async with session.get(f"{target}{path}") as confirm_resp:
                                confirm_body = await confirm_resp.text(errors="ignore")

                            # Look for the tampered value or zero-cost indicators in the re-fetched body
                            price_keywords = [tamper_value, '"price":0', '"amount":0',
                                              '"total":0', 'price=0', 'amount=0']
                            confirmed_server = (
                                any(kw in confirm_body for kw in price_keywords)
                                or (tamper_value == "-1" and "-1" in confirm_body)
                            )

                            if confirmed_server:
                                tamper_results.append({
                                    "field": field, "original": orig_value,
                                    "tampered": tamper_value, "accepted": True,
                                    "confirmed": True})
                            else:
                                # POST accepted (200, no "error") but not confirmed server-side
                                tamper_results.append({
                                    "field": field, "original": orig_value,
                                    "tampered": tamper_value, "accepted": True,
                                    "confirmed": False})
                        except Exception as exc:
                            self.log.debug("price_tamper: POST %s%s error: %s", target, path, exc)

                confirmed_tampers = [t for t in tamper_results if t.get("confirmed")]
                unconfirmed_tampers = [t for t in tamper_results if not t.get("confirmed")]

                if confirmed_tampers:
                    ev = Evidence(extra={"tamper_results": confirmed_tampers[:10]})
                    self.new_finding(
                        title=f"Price Tampering — {len(confirmed_tampers)} field(s) accept modified values (confirmed)",
                        severity=Severity.HIGH,
                        description=(
                            f"Client-side price values accepted and reflected back by server:\n"
                            + "\n".join(
                                f"  {t['field']}: {t['original']} → {t['tampered']} (server confirmed)"
                                for t in confirmed_tampers[:5])
                        ),
                        reproduction_steps=["Intercept POST, modify price field to 0 or -1, re-fetch to confirm"],
                        remediation="Validate prices server-side. Never trust client-submitted price values.",
                        references=["CWE-472", "OWASP Business Logic"],
                        evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                        target=target)

                if unconfirmed_tampers:
                    ev = Evidence(extra={"tamper_results": unconfirmed_tampers[:10]})
                    self.new_finding(
                        title=f"Price Tampering — {len(unconfirmed_tampers)} field(s) accepted without error (manual verify)",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Server returned HTTP 200 without an error message for tampered price fields, "
                            f"but the modified value was not confirmed in a follow-up GET. "
                            f"Manual testing recommended to determine if server-side validation is present:\n"
                            + "\n".join(
                                f"  {t['field']}: {t['original']} → {t['tampered']} (unconfirmed)"
                                for t in unconfirmed_tampers[:5])
                        ),
                        reproduction_steps=["Intercept POST, modify price field, manually inspect cart state"],
                        remediation="Validate prices server-side. Never trust client-submitted price values.",
                        references=["CWE-472", "OWASP Business Logic"],
                        evidence=ev,
                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
                        target=target)

                if not tamper_results:
                    ev = Evidence(extra={"price_fields": price_fields[:10]})
                    self.new_finding(
                        title=f"Price Fields Detected — {len(price_fields)} client-side price fields",
                        severity=Severity.LOW,
                        description=f"Client-side price fields found (manual testing recommended):\n"
                            + "\n".join(f"  {f['field']}={f['value']} at {f['path']}" for f in price_fields[:5]),
                        reproduction_steps=["Intercept and modify price values in Burp Suite"],
                        remediation="Ensure server-side price validation.",
                        references=["CWE-472"],
                        evidence=ev,
                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
                        target=target)

        return self._make_result(start)

    def _find_price_keys(self, data: any, path: str, results: list) -> None:
        if isinstance(data, dict):
            for k, v in data.items():
                if any(kw in k.lower() for kw in ["price", "amount", "total", "cost"]):
                    results.append({"path": path, "field": k, "value": str(v)[:20]})
                elif isinstance(v, (dict, list)):
                    self._find_price_keys(v, path, results)
        elif isinstance(data, list):
            for item in data[:5]:
                self._find_price_keys(item, path, results)

class TestPriceTamper:
    def test_phase(self) -> None: assert PriceTamper.PHASE == 9

    def test_confirm_gate_declined(self) -> None:
        """Operator declining confirmation must skip the module."""
        import asyncio
        from unittest.mock import MagicMock, patch

        mod = PriceTamper.__new__(PriceTamper)
        mod.config = MagicMock()
        mod.config.target = "http://example.com"
        mod.config.extra = {}
        mod.log = MagicMock()
        mod._seen_finding_keys = {}
        mod._event_bus = None
        mod.findings = []

        with patch.object(mod, "check_scope", return_value=True), \
             patch.object(mod, "confirm_action", return_value=False):
            result = asyncio.run(mod.run())

        assert result.skipped is True
        assert result.skip_reason == "operator declined"
