from __future__ import annotations

import asyncio
from typing import Any

import pytest

from common import fp_reducer
from common.fp_reducer import Confidence


def _run(coro: Any):
    return asyncio.run(coro)


def test_block_page_detection_requires_block_status() -> None:
    assert fp_reducer._looks_like_block_page(403, "Request rejected by web application firewall")
    assert not fp_reducer._looks_like_block_page(200, "Request rejected by web application firewall")
    assert not fp_reducer._looks_like_block_page(403, "normal application forbidden message")


def test_xss_context_rejects_html_escaped_reflection() -> None:
    canary = "abc123"
    body = f"&lt;script&gt;alert(&quot;{canary}&quot;)&lt;/script&gt;"

    assert not fp_reducer._xss_payload_executably_reflected(body, canary)


def test_xss_context_accepts_executable_script_reflection() -> None:
    canary = "abc123"
    body = f'<script>alert("{canary}")</script>'

    assert fp_reducer._xss_payload_executably_reflected(body, canary)


def test_verify_xss_suppresses_escaped_reflection(monkeypatch) -> None:
    async def fake_get(url, params=None, headers=None, timeout=15.0, session=None):
        payload = params["q"]
        return 200, payload.replace("<", "&lt;").replace(">", "&gt;"), 0.01

    monkeypatch.setattr(fp_reducer, "_http_get", fake_get)

    result = _run(fp_reducer.verify_xss_reflected("http://example.test", "q"))

    assert result.confidence == Confidence.LOW
    assert result.probe_hits == 0
    assert any("escaped/non-executable" in item for item in result.evidence)


def test_verify_xss_confirms_executable_reflection(monkeypatch) -> None:
    async def fake_get(url, params=None, headers=None, timeout=15.0, session=None):
        return 200, params["q"], 0.01

    monkeypatch.setattr(fp_reducer, "_http_get", fake_get)

    result = _run(fp_reducer.verify_xss_reflected("http://example.test", "q"))

    assert result.confidence == Confidence.HIGH
    assert result.confirmed is True
    assert result.probe_hits == 2


def test_verify_sqli_error_ignores_generic_block_page(monkeypatch) -> None:
    async def fake_get(url, params=None, headers=None, timeout=15.0, session=None):
        return 403, "Request rejected by web application firewall. Support ID 12345", 0.01

    monkeypatch.setattr(fp_reducer, "_http_get", fake_get)

    result = _run(fp_reducer.verify_sqli_error("http://example.test", "q"))

    assert result.confidence == Confidence.LOW
    assert result.probe_hits == 0
    assert any("block page" in item for item in result.evidence)


def test_verify_sqli_error_confirms_db_specific_errors(monkeypatch) -> None:
    async def fake_get(url, params=None, headers=None, timeout=15.0, session=None):
        return 500, "You have an error in your SQL syntax near quote", 0.01

    monkeypatch.setattr(fp_reducer, "_http_get", fake_get)

    result = _run(fp_reducer.verify_sqli_error("http://example.test", "q"))

    assert result.confidence == Confidence.HIGH
    assert result.confirmed is True
    assert result.probe_hits == 2


def test_verify_ssti_rejects_literal_reflection(monkeypatch) -> None:
    async def fake_get(url, params=None, headers=None, timeout=15.0, session=None):
        return 200, f"Hello {params['name']}", 0.01

    monkeypatch.setattr(fp_reducer, "_http_get", fake_get)

    result = _run(fp_reducer.verify_ssti("http://example.test", "name"))

    assert result.confidence == Confidence.LOW
    assert result.probe_hits == 0
    assert any("reflected literally" in item for item in result.evidence)


def test_verify_ssti_confirms_evaluated_math(monkeypatch) -> None:
    async def fake_get(url, params=None, headers=None, timeout=15.0, session=None):
        return 200, "Hello 49", 0.01

    monkeypatch.setattr(fp_reducer, "_http_get", fake_get)

    result = _run(fp_reducer.verify_ssti("http://example.test", "name"))

    assert result.confidence == Confidence.HIGH
    assert result.confirmed is True
    assert result.probe_hits == 2


def test_verify_cmdi_rejects_unbounded_token_noise(monkeypatch) -> None:
    async def fake_get(url, params=None, headers=None, timeout=15.0, session=None):
        probe = params["q"]
        token = probe.rsplit(" ", 1)[-1]
        return 200, f"tracking-id={token}ffff", 0.01

    monkeypatch.setattr(fp_reducer, "_http_get", fake_get)

    result = _run(fp_reducer.verify_cmdi("http://example.test", "q"))

    assert result.confidence == Confidence.LOW
    assert result.probe_hits == 0


def test_verify_cmdi_accepts_bounded_output_token(monkeypatch) -> None:
    async def fake_get(url, params=None, headers=None, timeout=15.0, session=None):
        probe = params["q"]
        token = probe.rsplit(" ", 1)[-1]
        return 200, f"\n{token}\n", 0.01

    monkeypatch.setattr(fp_reducer, "_http_get", fake_get)

    result = _run(fp_reducer.verify_cmdi("http://example.test", "q"))

    assert result.confidence == Confidence.HIGH
    assert result.confirmed is True
    assert result.probe_hits == 2


def test_fp_reducer_timeout_returns_low(monkeypatch) -> None:
    async def slow_verify(*args, **kwargs):
        await asyncio.sleep(0.05)

    monkeypatch.setattr(fp_reducer, "verify_xss_reflected", slow_verify)
    reducer = fp_reducer.FPReducer(verify_timeout=0.001)

    result = _run(reducer.verify("xss", "http://example.test", "q"))

    assert result.confidence == Confidence.LOW
    assert "timed out" in result.error
