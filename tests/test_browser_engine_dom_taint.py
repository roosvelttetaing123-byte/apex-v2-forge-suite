from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from webforge.core.browser_engine import (
    BrowserEngine,
    DOMTaintResult,
    _build_taint_tracking_script,
    _dom_taint_canary,
    dom_xss_taint_scan,
)
from tests.test_outbound_policy import NOW, TARGET, _policy


class FakePage:
    def __init__(self) -> None:
        self.init_scripts: list[str] = []
        self.visited_urls: list[str] = []
        self.closed = False

    async def add_init_script(self, script: str) -> None:
        self.init_scripts.append(script)

    async def goto(self, url: str, **_: Any) -> None:
        self.visited_urls.append(url)

    async def wait_for_timeout(self, _wait_ms: int) -> None:
        return None

    async def evaluate(self, script: str) -> Any:
        if "HashChangeEvent" in script:
            return None
        canary = _dom_taint_canary("https://app.example.test/page")
        return {
            "canary": canary,
            "flows": [
                {
                    "source": "location.hash",
                    "source_value": f"forge-dom-canary-{canary}",
                    "sink": "innerHTML",
                    "sink_data": f"<div>forge-dom-canary-{canary}</div>",
                    "canary_present": True,
                }
            ],
            "mutations": [
                {
                    "source": "location.search",
                    "mutation_type": "childList",
                    "element": "forge-canary",
                    "html": f"<forge-canary data-token=\"{canary}\"></forge-canary>",
                    "canary_present": True,
                }
            ],
            "canary_executions": [
                {
                    "sink": "DOMMutation",
                    "kind": "mutation_observed",
                    "executed": False,
                    "data": canary,
                }
            ],
        }

    async def close(self) -> None:
        self.closed = True


class FakeContext:
    def __init__(self) -> None:
        self.pages: list[FakePage] = []

    async def new_page(self) -> FakePage:
        page = FakePage()
        self.pages.append(page)
        return page


def test_dom_xss_taint_scan_uses_passive_deterministic_canary_without_browser() -> None:
    async def run_scan() -> tuple[DOMTaintResult, FakeContext]:
        engine = BrowserEngine(Path("/tmp/forge-test-results"))
        context = FakeContext()
        engine._context = context

        result = await dom_xss_taint_scan(
            engine,
            "https://app.example.test/page",
            extra_payloads=[],
            wait_ms=0,
            max_payloads=1,
        )
        return result, context

    result, context = asyncio.run(run_scan())

    canary = _dom_taint_canary("https://app.example.test/page")
    assert result.canary == canary
    assert result.flows[0]["source"] == "location.hash"
    assert result.flows[0]["sink"] == "innerHTML"
    assert result.mutations[0]["mutation_type"] == "childList"
    assert result.canary_executions[0]["executed"] is False
    assert canary in context.pages[0].init_scripts[0]
    assert "alert(" not in context.pages[0].visited_urls[0]
    assert canary in context.pages[0].visited_urls[0]
    assert context.pages[0].closed is True


def test_dom_taint_result_serializes_counts_and_canary() -> None:
    result = DOMTaintResult(
        url="https://app.example.test",
        canary="FORGETAINT_TEST",
        flows=[{"source": "location.search", "sink": "document.write"}],
        mutations=[{"mutation_type": "attributes"}],
        canary_executions=[{"sink": "eval", "executed": False}],
    )

    data = result.to_dict()

    assert data["canary"] == "FORGETAINT_TEST"
    assert data["total_flows"] == 1
    assert data["total_mutations"] == 1
    assert data["total_canary_executions"] == 1


def test_browser_snapshot_serializes_shadow_dom_metadata() -> None:
    from webforge.core.browser_engine import BrowserSnapshot

    snap = BrowserSnapshot(
        url="https://app.example.test",
        shadow_dom=[
            {
                "host": "checkout-form#payment",
                "mode": "open",
                "inputs": ["cardNumber"],
                "links": [],
                "forms": 1,
            },
        ],
    )

    data = snap.to_dict()

    assert data["shadow_dom"][0]["host"] == "checkout-form#payment"
    assert data["shadow_dom"][0]["inputs"] == ["cardNumber"]


def test_taint_tracking_script_covers_required_sources_sinks_and_mutations() -> None:
    script = _build_taint_tracking_script("FORGETAINT_STATIC")

    assert "FORGETAINT_STATIC" in script
    assert "location.hash" in script
    assert "location.search" in script
    assert "innerHTML" in script
    assert "document.write" in script
    assert "window.eval" in script
    assert "MutationObserver" in script
    assert "Math.random" not in script


def test_browser_route_aborts_excluded_navigation_before_continue(tmp_path) -> None:
    policy, session = _policy(
        tmp_path,
        allowed_scope=["127.0.0.0/8", TARGET, "https://127.0.0.2:8443"],
        excluded_scope=["127.0.0.2/32"],
        now=NOW,
    )
    calls: list[str] = []

    class FakeRoute:
        async def abort(self, reason: str) -> None:
            calls.append(f"abort:{reason}")

        async def continue_(self) -> None:
            calls.append("continue")

    class FakeRequest:
        url = "https://127.0.0.2:8443/excluded"

    engine = BrowserEngine(tmp_path)
    engine._browser_policy = policy

    asyncio.run(engine._route_request(FakeRoute(), FakeRequest()))

    assert calls == ["abort:blockedbyclient"]
    session.close()
