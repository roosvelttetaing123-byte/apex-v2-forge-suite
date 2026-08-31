"""Acceptance coverage for FM-P0-001 fail-closed finding confidence."""
from __future__ import annotations

import asyncio
import csv
import json
import time
import warnings
from pathlib import Path
from typing import Any

import pytest

from common.brain.engagement_bus import EngagementBus
from common.confidence_policy import (
    infer_confidence,
    normalise_confidence,
    normalise_finding,
    should_include_default,
)
from common.dashboard.event_bus import Event, EventBus, EventType
from common.dashboard.state_store import StateStore
from common.db import FindingModel, create_db, save_finding
from common.finding import Finding, Severity
from common.reporter import BaseReporter
from common.reporting.report_engine import ReportConfig, ReportEngine


MISSING = object()
INVALID_CONFIDENCE = (MISSING, None, "", "   ", "UNKNOWN")


def _finding_dict(finding_id: str = "legacy-1") -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": "Legacy finding without verification",
        "severity": "High",
        "target": "https://fixture.invalid",
        "module": "fixture_module",
        "description": "Inert confidence-policy fixture",
        "reproduction_steps": [],
        "remediation": "Verify before reporting",
        "references": [],
        "evidence": {},
    }


def _finding_object(**kwargs: Any) -> Finding:
    values: dict[str, Any] = {
        "title": "Legacy finding",
        "severity": Severity.HIGH,
        "target": "https://fixture.invalid",
        "module": "fixture_module",
        "description": "Inert confidence-policy fixture",
        "reproduction_steps": [],
        "remediation": "Verify before reporting",
        "references": [],
    }
    values.update(kwargs)
    return Finding(**values)


@pytest.mark.parametrize("value", INVALID_CONFIDENCE)
def test_invalid_confidence_fails_closed(value: object) -> None:
    finding = {} if value is MISSING else {"confidence": value}

    assert infer_confidence(finding, default="MEDIUM") == "UNVERIFIED"
    assert normalise_finding(finding, legacy_default="MEDIUM")["confidence"] == "UNVERIFIED"
    assert normalise_finding(finding)["status"] == "open"
    assert not should_include_default(finding)


@pytest.mark.parametrize("value", (None, "", "   ", "UNKNOWN"))
def test_unsafe_caller_default_cannot_promote(value: object) -> None:
    assert normalise_confidence(value, default="MEDIUM") == "UNVERIFIED"


@pytest.mark.parametrize(
    ("value", "expected"),
    (("high", "HIGH"), (" medium ", "MEDIUM"), ("LOW", "LOW"), ("unverified", "UNVERIFIED")),
)
def test_explicit_canonical_confidence_is_preserved(value: str, expected: str) -> None:
    assert normalise_confidence(value) == expected


def test_nested_verification_confidence_is_preserved() -> None:
    assert infer_confidence({"verification": {"confidence": "HIGH"}}) == "HIGH"
    assert infer_confidence({"evidence": {"extra": {"fp_confidence": "MEDIUM"}}}) == "MEDIUM"
    assert should_include_default({"verification": {"confidence": "HIGH"}})


@pytest.mark.parametrize("value", (None, "", "   ", False, 0, "UNKNOWN"))
def test_explicit_invalid_confidence_cannot_fall_back_to_nested_high(
    value: object,
) -> None:
    finding = {
        "confidence": value,
        "verification": {"confidence": "HIGH"},
        "evidence": {"extra": {"fp_confidence": "HIGH"}},
    }

    assert infer_confidence(finding) == "UNVERIFIED"
    assert not should_include_default(finding)


@pytest.mark.parametrize(
    "finding",
    (
        {"verification": "HIGH"},
        {"evidence": "raw evidence"},
        {"evidence": {"extra": "HIGH"}},
    ),
)
def test_malformed_confidence_containers_fail_closed(
    tmp_path: Path, finding: dict[str, Any],
) -> None:
    assert infer_confidence(finding) == "UNVERIFIED"
    assert normalise_finding(finding)["confidence"] == "UNVERIFIED"
    assert not should_include_default(finding)

    engine = ReportEngine(
        [{**_finding_dict(), **finding}],
        ReportConfig(output_dir=str(tmp_path), include_unverified=True),
    )
    assert engine._enrich_findings()[0]["confidence"] == "UNVERIFIED"


def test_nested_verification_confidence_is_canonicalised() -> None:
    normalised = normalise_finding({
        "verification": {"confidence": "UNKNOWN", "probe_count": 1},
    })
    finding = _finding_object(verification={"confidence": "UNKNOWN"})

    assert normalised["verification"]["confidence"] == "UNVERIFIED"
    assert finding.to_dict()["verification"]["confidence"] == "UNVERIFIED"


@pytest.mark.parametrize("value", (None, "", "   ", "UNKNOWN"))
def test_finding_model_serializes_invalid_confidence_as_unverified(value: object) -> None:
    finding = _finding_object(confidence=value)

    assert finding.confidence == "UNVERIFIED"
    assert finding.to_dict()["confidence"] == "UNVERIFIED"


def test_base_module_accepts_null_confidence_without_promotion(tmp_path: Path) -> None:
    from common.base_module import BaseModule, ModuleResult
    from common.config import BaseForgeConfig
    from common.evidence import Evidence
    from common.scope import Scope

    class FixtureModule(BaseModule):
        NAME = "confidence_fixture"
        DESCRIPTION = "Inert confidence fixture"
        PHASE = 0

        async def run(self) -> ModuleResult:
            return self._make_result(time.monotonic())

    session = create_db(tmp_path / "module.db")
    config = BaseForgeConfig(target="https://fixture.invalid")
    config.extra["allow_legacy_compat"] = True
    module = FixtureModule(
        config,
        Scope(["fixture.invalid"]),
        session,
        tmp_path,
    )
    finding = module.new_finding(
        title="Legacy finding",
        severity=Severity.HIGH,
        description="Inert confidence-policy fixture",
        reproduction_steps=[],
        remediation="Verify before reporting",
        references=[],
        evidence=Evidence(extra={"fp_confidence": "HIGH"}),
        confidence=None,
    )
    derived = module.new_finding(
        title="Verified evidence finding",
        severity=Severity.HIGH,
        description="Inert confidence-policy fixture",
        reproduction_steps=[],
        remediation="Verify before reporting",
        references=[],
        evidence=Evidence(extra={"fp_confidence": "HIGH"}),
    )
    malformed = module.new_finding(
        title="Malformed verification finding",
        severity=Severity.HIGH,
        description="Inert confidence-policy fixture",
        reproduction_steps=[],
        remediation="Verify before reporting",
        references=[],
        verification="HIGH",  # type: ignore[arg-type]
    )

    assert finding.confidence == "UNVERIFIED"
    assert finding.status == "open"
    assert derived.confidence == "HIGH"
    assert derived.status == "open"
    assert derived.verification_state != "verified"
    assert malformed.confidence == "UNVERIFIED"
    assert malformed.status == "open"
    engine = session.get_bind()
    session.close()
    engine.dispose()


@pytest.mark.parametrize("value", INVALID_CONFIDENCE)
def test_database_persists_invalid_confidence_as_unverified(
    tmp_path: Path, value: object,
) -> None:
    session = create_db(tmp_path / "findings.db")
    finding = _finding_dict("db-finding")
    if value is not MISSING:
        finding["confidence"] = value

    save_finding(session, finding, allow_legacy_compat=True)
    stored = session.get(FindingModel, "db-finding")

    assert stored is not None
    assert stored.confidence == "UNVERIFIED"
    engine = session.get_bind()
    session.close()
    engine.dispose()


def test_database_canonicalises_nested_verification_confidence(tmp_path: Path) -> None:
    session = create_db(tmp_path / "verification.db")
    finding = _finding_dict("db-verification")
    finding["verification"] = {"confidence": "UNKNOWN", "probe_count": 1}
    finding["evidence"] = "raw evidence"

    save_finding(session, finding, allow_legacy_compat=True)
    stored = session.get(FindingModel, "db-verification")

    assert stored is not None
    assert json.loads(stored.verification)["confidence"] == "UNVERIFIED"
    engine = session.get_bind()
    session.close()
    engine.dispose()


@pytest.mark.parametrize("value", INVALID_CONFIDENCE)
def test_dashboard_snapshot_rejects_unresolved_confidence(value: object) -> None:
    bus = EventBus(run_id="confidence-fixture")
    store = StateStore(bus, framework="webforge", target="https://fixture.invalid")
    data = _finding_dict("dashboard-finding")
    if value is not MISSING:
        data["confidence"] = value

    store._on_finding(Event(EventType.FINDING_NEW, data=data, source="fixture_module"))

    assert store.findings_snapshot() == []
    assert store.snapshot()["findings"] == []


def test_dashboard_rejects_unresolved_nested_confidence() -> None:
    bus = EventBus(run_id="confidence-fixture")
    store = StateStore(bus, framework="webforge", target="https://fixture.invalid")
    nested = _finding_dict("dashboard-nested")
    nested["verification"] = {"confidence": "HIGH"}
    explicit_null = _finding_dict("dashboard-null")
    explicit_null["confidence"] = None
    explicit_null["verification"] = {"confidence": "HIGH"}

    store._on_finding(Event(EventType.FINDING_NEW, data=nested, source="fixture_module"))
    store._on_finding(Event(EventType.FINDING_NEW, data=explicit_null, source="fixture_module"))

    assert store.findings_snapshot() == []


@pytest.mark.parametrize("value", INVALID_CONFIDENCE)
def test_engagement_bus_outputs_invalid_confidence_as_unverified(value: object) -> None:
    bus = EngagementBus(db_path=":memory:")
    received: list[dict[str, Any]] = []
    bus.subscribe(lambda _framework, finding: received.append(dict(finding)))
    finding = _finding_dict("engagement-finding")
    if value is not MISSING:
        finding["confidence"] = value

    asyncio.run(bus.publish("webforge", finding))

    assert received[0]["confidence"] == "UNVERIFIED"
    assert bus.get_all_findings()[0]["confidence"] == "UNVERIFIED"
    bus.close()


def test_engagement_bus_canonicalises_nested_verification_confidence() -> None:
    bus = EngagementBus(db_path=":memory:")
    received: list[dict[str, Any]] = []
    bus.subscribe(lambda _framework, finding: received.append(dict(finding)))
    finding = _finding_dict("engagement-verification")
    finding["verification"] = {"confidence": "UNKNOWN"}

    asyncio.run(bus.publish("webforge", finding))

    assert received[0]["verification"]["confidence"] == "UNVERIFIED"
    assert bus.get_all_findings()[0]["verification"]["confidence"] == "UNVERIFIED"
    bus.close()


def test_engagement_bus_projects_untrusted_evidence_without_mutating_input() -> None:
    bus = EngagementBus(db_path=":memory:")
    received: list[dict[str, Any]] = []
    bus.subscribe(lambda _framework, finding: received.append(dict(finding)))
    raw_canary = "TASK102_ENGAGEMENT_BUS_RAW_CANARY"
    finding = _finding_dict("engagement-raw-boundary")
    finding["evidence"] = {
        "request_raw": raw_canary,
        "response_raw": raw_canary,
        "screenshot_path": f"/untrusted/{raw_canary}.png",
    }
    original = json.loads(json.dumps(finding))

    asyncio.run(bus.publish("webforge", finding))

    stored = bus.get_all_findings()[0]
    assert finding == original
    assert received[0]["evidence"] == {
        "observations": [],
        "state": "unavailable",
    }
    assert stored["evidence"] == received[0]["evidence"]
    assert raw_canary not in json.dumps(received[0])
    assert raw_canary not in json.dumps(stored)
    bus.close()


def test_engagement_bus_preserves_verified_persisted_derivative() -> None:
    bus = EngagementBus(db_path=":memory:")
    finding = _finding_dict("engagement-persisted-boundary")
    digest = "sha256:" + "a" * 64
    derivative = "redacted persisted derivative"
    finding["evidence"] = {
        "finding_id": "engagement-persisted-boundary",
        "observations": [
            {
                "artifacts": [
                    {
                        "artifact_id": "artifact-persisted-boundary",
                        "capture_kind": "request",
                        "derivative": derivative,
                        "derivative_sha256": digest,
                        "derivative_size": len(derivative.encode("utf-8")),
                        "integrity_state": "verified",
                        "manifest_digest": digest,
                        "media_type": "text/plain",
                        "primary_sha256": digest,
                        "primary_size": 128,
                        "redaction_state": "redacted",
                        "role": "primary",
                        "sequence": 0,
                    }
                ],
                "observation_id": "observation-persisted-boundary",
            }
        ],
        "state": "persisted",
    }

    asyncio.run(bus.publish("webforge", finding))

    stored = bus.get_all_findings()[0]
    assert stored["evidence"]["state"] == "persisted"
    assert stored["evidence"]["observations"][0]["artifacts"][0][
        "derivative"
    ] == derivative
    bus.close()


def test_base_reporter_json_csv_and_fallback_html_are_unverified(tmp_path: Path) -> None:
    legacy_finding = _finding_dict()
    legacy_finding["verification"] = {"confidence": "UNKNOWN"}
    reporter = BaseReporter(
        [legacy_finding], tmp_path, formats=["json", "csv", "html"],
    )

    async def generate_from_scan_context() -> dict[str, str]:
        return reporter.generate_all()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        paths = asyncio.run(generate_from_scan_context())

    payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    with Path(paths["csv"]).open(newline="", encoding="utf-8") as handle:
        csv_rows = list(csv.DictReader(handle))
    html = Path(paths["html"]).read_text(encoding="utf-8")

    assert reporter.findings[0]["confidence"] == "UNVERIFIED"
    assert payload["findings"][0]["confidence"] == "UNVERIFIED"
    assert payload["findings"][0]["verification"]["confidence"] == "UNVERIFIED"
    assert csv_rows[0]["confidence"] == "UNVERIFIED"
    assert "Legacy finding without verification" in html
    assert "Confidence" in html
    assert "UNVERIFIED" in html
    assert not caught, [str(warning.message) for warning in caught]


def test_inline_html_fallback_labels_unverified(tmp_path: Path) -> None:
    reporter = BaseReporter([_finding_dict()], tmp_path, formats=["html"])

    html = reporter._build_html_inline()

    assert "Confidence" in html
    assert "UNVERIFIED" in html


@pytest.mark.parametrize("value", INVALID_CONFIDENCE)
def test_report_engine_normalises_before_default_filter(
    tmp_path: Path, value: object,
) -> None:
    finding = _finding_dict("report-engine-finding")
    if value is not MISSING:
        finding["confidence"] = value

    default_engine = ReportEngine(
        [finding], ReportConfig(output_dir=str(tmp_path / "default")),
    )
    verbose_engine = ReportEngine(
        [finding],
        ReportConfig(
            output_dir=str(tmp_path / "verbose"),
            formats=["html", "json"],
            include_unverified=True,
            include_exec_summary=False,
        ),
    )

    assert default_engine.findings == []
    assert default_engine._suppressed_count == 1
    assert verbose_engine.findings[0]["confidence"] == "UNVERIFIED"

    paths = asyncio.run(verbose_engine.generate())
    html = Path(paths["html"]).read_text(encoding="utf-8")
    payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert "UNVERIFIED" in html
    assert payload["findings"][0]["confidence"] == "UNVERIFIED"


def test_pdf_consumes_html_with_canonical_confidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = ReportEngine(
        [_finding_dict()],
        ReportConfig(
            output_dir=str(tmp_path),
            formats=["pdf"],
            include_unverified=True,
            include_exec_summary=False,
        ),
    )
    captured: dict[str, str] = {}

    def fake_pdf(html_path: str | None) -> str:
        assert html_path is not None
        captured["html"] = Path(html_path).read_text(encoding="utf-8")
        pdf_path = tmp_path / "report.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n% inert test fixture\n")
        return str(pdf_path)

    monkeypatch.setattr(engine, "_generate_pdf", fake_pdf)
    paths = asyncio.run(engine.generate())

    assert "pdf" in paths
    assert "UNVERIFIED" in captured["html"]
