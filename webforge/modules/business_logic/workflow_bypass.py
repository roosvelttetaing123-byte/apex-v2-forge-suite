"""Multi-step workflow bypass — step skipping, forced browsing in flows."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import aiohttp

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_WORKFLOW_BYPASS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"

WORKFLOW_PATTERNS: list[dict] = [
    {
        "name": "Checkout flow",
        "steps": [
            "/cart", "/checkout/shipping", "/checkout/payment",
            "/checkout/review", "/checkout/confirm",
        ],
    },
    {
        "name": "Registration flow",
        "steps": [
            "/register/step1", "/register/step2",
            "/register/step3", "/register/complete",
        ],
    },
    {
        "name": "Password reset flow",
        "steps": [
            "/forgot-password", "/reset-password/verify",
            "/reset-password/new", "/reset-password/complete",
        ],
    },
    {
        "name": "Payment flow",
        "steps": [
            "/payment/start", "/payment/verify",
            "/payment/3ds", "/payment/complete",
        ],
    },
    {
        "name": "Admin setup wizard",
        "steps": [
            "/setup/step1", "/setup/step2",
            "/setup/step3", "/setup/complete",
        ],
    },
]


class WorkflowBypass(BaseModule):
    """Multi-step workflow bypass detector."""

    NAME        = "workflow_bypass"
    DESCRIPTION = "Detect ability to skip steps in multi-step checkout/registration/payment flows"
    PHASE       = 9
    TAGS        = ["business-logic", "workflow", "owasp-a04", "cwe-841"]

    async def run(self) -> ModuleResult:
        """Test workflow step-skipping on the target."""
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        confirmed = self.confirm_action(
            action="Access workflow steps directly without completing prior steps",
            target=target,
            risk="May trigger partial workflow execution",
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=10)
        headers   = {"User-Agent": "Mozilla/5.0 (forge-suite workflow_bypass)"}

        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            for workflow in WORKFLOW_PATTERNS:
                await self._test_workflow(session, target, workflow)

        return self._make_result(start)

    async def _test_workflow(
        self,
        session: aiohttp.ClientSession,
        target: str,
        workflow: dict,
    ) -> None:
        """Attempt to directly access later steps without completing earlier ones."""
        steps: list[str] = workflow["steps"]
        name: str        = workflow["name"]

        if len(steps) < 2:
            return

        # First verify step-1 exists
        step1_url = f"{target}{steps[0]}"
        if not self.check_scope(step1_url):
            return
        await self.rate_limit()
        try:
            async with session.get(step1_url, allow_redirects=False) as resp:
                if resp.status not in (200, 302):
                    return  # workflow doesn't exist on this target
        except Exception:
            return

        # Try jumping directly to final/middle steps
        for i, step_path in enumerate(steps[1:], start=2):
            url = f"{target}{step_path}"
            if not self.check_scope(url):
                continue
            await self.rate_limit()
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    body = await resp.text(errors="ignore")
                    redirect_to = resp.headers.get("Location", "")

                    # Bypass detected: got a 200 on a later step without visiting earlier steps
                    bypass_indicators = [
                        resp.status == 200 and "complete" in url.lower(),
                        resp.status == 200 and i > 2,
                        resp.status == 200 and "confirm" in url.lower(),
                        resp.status == 200 and "payment" in url.lower() and i > 1,
                    ]
                    # Also detect redirect back to step1 — means it's PROPERLY enforced
                    properly_blocked = (
                        resp.status in (302, 301)
                        and steps[0] in redirect_to
                    )

                    if any(bypass_indicators) and not properly_blocked:
                        ev = Evidence(
                            request_raw=f"GET {url} HTTP/1.1",
                            response_raw=f"HTTP {resp.status}\n{body[:400]}",
                            extra={
                                "workflow": name,
                                "skipped_to_step": i,
                                "step_path": step_path,
                            },
                        )
                        self.new_finding(
                            title=f"Workflow Step Bypass: Step {i} directly accessible — {name}",
                            severity=Severity.HIGH,
                            description=(
                                f"In the '{name}' workflow, step {i} ({step_path}) is directly "
                                f"accessible without completing prior steps. "
                                "An attacker can skip mandatory steps such as payment "
                                "verification or identity confirmation."
                            ),
                            reproduction_steps=[
                                f"Without completing steps 1-{i-1}, navigate directly to {url}",
                                f"Observe HTTP {resp.status} — step is accessible",
                            ],
                            remediation=(
                                "Enforce sequential workflow state server-side using a "
                                "session-stored workflow state machine. Redirect to step 1 "
                                "if session state does not show prior steps completed."
                            ),
                            references=["CWE-841", "OWASP A04:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_WORKFLOW_BYPASS,
                            mitre_attack=["TA0006/T1078"],
                            target=url,
                        )
            except Exception:
                pass


class TestWorkflowBypass:
    def test_workflow_patterns_non_empty(self) -> None:
        assert len(WORKFLOW_PATTERNS) >= 3

    def test_each_workflow_has_multiple_steps(self) -> None:
        for wf in WORKFLOW_PATTERNS:
            assert len(wf["steps"]) >= 2

    def test_cvss_format(self) -> None:
        assert CVSS_WORKFLOW_BYPASS.startswith("CVSS:3.1/")
