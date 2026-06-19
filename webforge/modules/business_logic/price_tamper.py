"""Price Tamper — detect client-side price manipulation in e-commerce."""
from __future__ import annotations
import re, json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
import aiohttp

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

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=10),
        ) as session:
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
                except Exception:
                    pass

            if price_fields:
                # Test: Try submitting modified prices
                tamper_results = []
                for field_info in price_fields[:5]:
                    path = field_info["path"]
                    field = field_info["field"]
                    orig_value = field_info["value"]

                    # Try negative price
                    await self.rate_limit()
                    try:
                        async with session.post(
                            f"{target}{path}",
                            data={field: "-1", "quantity": "1"},
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            if resp.status == 200 and "error" not in body.lower()[:200]:
                                tamper_results.append({
                                    "field": field, "original": orig_value,
                                    "tampered": "-1", "accepted": True})
                    except Exception:
                        pass

                    # Try zero price
                    await self.rate_limit()
                    try:
                        async with session.post(
                            f"{target}{path}",
                            data={field: "0", "quantity": "1"},
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            if resp.status == 200 and "error" not in body.lower()[:200]:
                                tamper_results.append({
                                    "field": field, "original": orig_value,
                                    "tampered": "0", "accepted": True})
                    except Exception:
                        pass

                if tamper_results:
                    ev = Evidence(extra={"tamper_results": tamper_results[:10]})
                    self.new_finding(
                        title=f"Price Tampering — {len(tamper_results)} field(s) accept modified values",
                        severity=Severity.HIGH,
                        description=(
                            f"Client-side price values accepted by server:\n"
                            + "\n".join(
                                f"  {t['field']}: {t['original']} → {t['tampered']} (accepted)"
                                for t in tamper_results[:5])
                        ),
                        reproduction_steps=["Intercept POST, modify price field to 0 or -1"],
                        remediation="Validate prices server-side. Never trust client-submitted price values.",
                        references=["CWE-472", "OWASP Business Logic"],
                        evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                        target=target)
                else:
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
