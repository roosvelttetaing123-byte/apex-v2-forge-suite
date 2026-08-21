"""Focused tests for core platform components.

Covers: Finding schema, BaseModule lifecycle, FPReducer confidence,
ReportEngine filtering and rendering.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path

import pytest

# ── Finding ───────────────────────────────────────────────────────────────────

def _make_finding(**kwargs):
    from common.finding import Finding, Severity
    defaults = dict(
        title="Test Finding",
        severity=Severity.HIGH,
        target="https://example.com",
        module="test_module",
        description="A test finding",
        reproduction_steps=["Step 1"],
        remediation="Fix it",
        references=["CWE-89"],
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestFindingSchema:
    def test_new_fields_have_defaults(self):
        f = _make_finding()
        assert f.url is None
        assert f.confidence == "UNVERIFIED"
        assert f.status == "open"
        assert f.vpr is None
        assert f.verification["state"] == "unknown"
        assert f.verification["verified"] is False
        assert f.proof_type == "unknown"
        assert f.maturity == "experimental"
        assert f.verification_state == "unknown"

    def test_url_field_accepted(self):
        f = _make_finding(url="https://example.com/search?q=1")
        assert f.url == "https://example.com/search?q=1"

    def test_confidence_field_accepted(self):
        f = _make_finding(confidence="HIGH")
        assert f.confidence == "HIGH"

    def test_unsupported_verified_status_is_downgraded(self):
        f = _make_finding(status="verified")
        assert f.status == "open"
        assert f.verification_state == "unknown"
        assert f.verification["legacy_status"] == "verified"

    def test_verification_field_accepted(self):
        vr = {"confidence": "HIGH", "probe_hits": 2, "probe_count": 2}
        f = _make_finding(verification=vr)
        assert f.verification["probe_hits"] == 2

    def test_to_dict_includes_new_fields(self):
        vr = {"confidence": "MEDIUM", "evidence": ["matched pattern"]}
        f = _make_finding(
            url="https://example.com/path",
            confidence="MEDIUM",
            status="verified",
            vpr="HIGH",
            verification=vr,
        )
        d = f.to_dict()
        assert d["url"] == "https://example.com/path"
        assert d["confidence"] == "MEDIUM"
        assert d["status"] == "open"
        assert d["vpr"] == "HIGH"
        assert d["verification"]["confidence"] == "MEDIUM"
        assert d["verification"]["evidence"] == ["matched pattern"]
        assert d["verification"]["legacy_status"] == "verified"
        assert d["verification_state"] == "unknown"
        assert d["proof_type"] == "unknown"
        assert d["maturity"] == "experimental"

    def test_to_dict_evidence_preserved(self):
        from common.evidence import Evidence
        ev = Evidence(request_raw="GET / HTTP/1.1", response_raw="200 OK")
        f = _make_finding(evidence=ev)
        d = f.to_dict()
        assert d["evidence"]["request_raw"] == "GET / HTTP/1.1"

    def test_cvss_auto_computed(self):
        from common.finding import cvss31_score
        f = _make_finding(cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert f.cvss_v31_score is not None
        assert f.cvss_v31_score >= 9.0


# ── BaseModule ────────────────────────────────────────────────────────────────

def _make_module(tmp_path: Path):
    from common.config import BaseForgeConfig
    from common.scope import Scope
    from common.db import create_db
    from common.base_module import BaseModule, ModuleResult

    class DummyModule(BaseModule):
        NAME = "dummy"
        DESCRIPTION = "test"
        PHASE = 1

        async def fixture_run(self) -> ModuleResult:
            start = time.monotonic()
            return self._make_result(start)

        async def run(self) -> ModuleResult:
            return await self.fixture_run()

    cfg = BaseForgeConfig(target="https://example.com")
    scope = Scope(["example.com"])
    session = create_db(tmp_path / "test.db")
    return DummyModule(cfg, scope, session, tmp_path), session


class TestBaseModule:
    def test_run_returns_result(self, tmp_path):
        mod, session = _make_module(tmp_path)
        result = asyncio.run(mod.fixture_run())
        assert result.module_name == "dummy"
        assert result.findings == []
        assert result.duration_s >= 0
        session.close()

    def test_new_finding_sets_url(self, tmp_path):
        from common.finding import Severity
        mod, session = _make_module(tmp_path)
        f = mod.new_finding(
            title="XSS",
            severity=Severity.HIGH,
            description="Reflected XSS",
            reproduction_steps=["inject payload"],
            remediation="encode output",
            references=["CWE-79"],
            url="https://example.com/search?q=xss",
            confidence="HIGH",
        )
        assert f.url == "https://example.com/search?q=xss"
        assert f.confidence == "HIGH"
        assert f.status == "open"
        assert f.verification_state == "unknown"
        session.close()

    def test_new_finding_unverified_stays_open(self, tmp_path):
        from common.finding import Severity
        mod, session = _make_module(tmp_path)
        f = mod.new_finding(
            title="Info leak",
            severity=Severity.LOW,
            description="Possible info leak",
            reproduction_steps=[],
            remediation="review headers",
            references=[],
            confidence="UNVERIFIED",
        )
        assert f.status == "open"
        session.close()

    def test_new_finding_operator_confirmed_and_tags(self, tmp_path):
        from common.finding import Severity
        mod, session = _make_module(tmp_path)
        f = mod.new_finding(
            title="Confirmed risky probe",
            severity=Severity.HIGH,
            description="d",
            reproduction_steps=[],
            remediation="r",
            references=[],
            operator_confirmed=True,
            tags=["business-logic"],
        )
        assert f.operator_confirmed is True
        assert f.tags == ["business-logic"]
        session.close()

    def test_auth_headers_merge_token_cookie_and_overrides(self, tmp_path):
        mod, session = _make_module(tmp_path)
        mod.config.extra["token"] = "tok123"
        mod.config.extra["cookie"] = "Cookie: session=abc; Path=/; theme=dark"
        mod.config.extra["session_headers"] = {"X-CSRF-Token": "csrf"}
        headers = mod.auth_headers({"Authorization": "ApiKey override"})
        cookies = mod.auth_cookies()
        assert headers["Authorization"] == "ApiKey override"
        assert headers["X-CSRF-Token"] == "csrf"
        assert headers["Cookie"].startswith("session=abc")
        assert cookies == {"session": "abc", "theme": "dark"}
        session.close()

    def test_dedup_suppresses_duplicate(self, tmp_path):
        from common.finding import Severity
        mod, session = _make_module(tmp_path)
        mod.new_finding(
            title="SQLi", severity=Severity.CRITICAL,
            description="d", reproduction_steps=[], remediation="r", references=[],
            url="https://example.com/login",
        )
        mod.new_finding(
            title="SQLi", severity=Severity.CRITICAL,
            description="d", reproduction_steps=[], remediation="r", references=[],
            url="https://example.com/login",
        )
        assert len(mod.findings) == 1
        session.close()

    def test_scope_check_returns_bool(self, tmp_path):
        mod, session = _make_module(tmp_path)
        assert mod.check_scope("https://example.com/path") is True
        session.close()


# ── FPReducer ─────────────────────────────────────────────────────────────────

class TestFPReducer:
    def test_confidence_enum_values(self):
        from common.fp_reducer import Confidence
        assert Confidence.HIGH.value == "HIGH"
        assert Confidence.MEDIUM.value == "MEDIUM"
        assert Confidence.LOW.value == "LOW"
        assert Confidence.UNVERIFIED.value == "UNVERIFIED"

    def test_should_report_high(self):
        from common.fp_reducer import FPReducer, VerificationResult, Confidence
        reducer = FPReducer()
        result = VerificationResult(confidence=Confidence.HIGH, confirmed=True)
        assert reducer.should_report(result) is True

    def test_should_report_medium(self):
        from common.fp_reducer import FPReducer, VerificationResult, Confidence
        reducer = FPReducer()
        result = VerificationResult(confidence=Confidence.MEDIUM)
        assert reducer.should_report(result) is True

    def test_should_not_report_low(self):
        from common.fp_reducer import FPReducer, VerificationResult, Confidence
        reducer = FPReducer()
        result = VerificationResult(confidence=Confidence.LOW)
        assert reducer.should_report(result) is False

    def test_should_not_report_unverified(self):
        from common.fp_reducer import FPReducer, VerificationResult, Confidence
        reducer = FPReducer()
        result = VerificationResult(confidence=Confidence.UNVERIFIED)
        assert reducer.should_report(result) is False

    def test_verification_result_to_dict(self):
        from common.fp_reducer import VerificationResult, Confidence
        vr = VerificationResult(
            confidence=Confidence.HIGH,
            confirmed=True,
            probe_count=2,
            probe_hits=2,
            evidence=["match found"],
        )
        d = vr.to_dict()
        assert d["confidence"] == "HIGH"
        assert d["confirmed"] is True
        assert d["probe_hits"] == 2

    def test_unknown_vuln_type_returns_unverified(self):
        from common.fp_reducer import FPReducer, Confidence
        reducer = FPReducer()
        result = asyncio.run(reducer.verify(
            vuln_type="nonexistent_type",
            url="http://example.com",
            param="q",
        ))
        assert result.confidence == Confidence.UNVERIFIED
        assert "nonexistent_type" in result.error

    def test_vpr_label_from_cvss(self):
        from common.fp_reducer import _vpr_label_from_cvss
        assert _vpr_label_from_cvss(9.5) == "CRITICAL"
        assert _vpr_label_from_cvss(7.5) == "HIGH"
        assert _vpr_label_from_cvss(5.0) == "MEDIUM"
        assert _vpr_label_from_cvss(2.0) == "LOW"
        assert _vpr_label_from_cvss(0.0) == "INFO"


# ── ReportEngine ──────────────────────────────────────────────────────────────

def _sample_findings(with_low: bool = False) -> list[dict]:
    findings = [
        {
            "id": "f1", "title": "SQL Injection", "severity": "Critical",
            "cvss_v31_score": 9.8, "cvss_v40_score": None,
            "target": "https://example.com", "url": "https://example.com/login",
            "port": 443, "service": "https", "module": "sqli_scanner",
            "description": "SQLi in login form",
            "reproduction_steps": ["POST /login with payload"],
            "remediation": "Use parameterized queries",
            "references": ["CWE-89"], "mitre_attack": ["T1190"],
            "discovered_at": "2026-06-20T00:00:00Z",
            "evidence": {"request_raw": "POST /login", "response_raw": "error"},
            "operator_confirmed": False, "tags": [],
            "confidence": "HIGH", "status": "verified", "vpr": "CRITICAL",
            "verification": {"confidence": "HIGH", "probe_hits": 2, "probe_count": 2,
                             "evidence": ["time-delay 6.1s"], "baseline_time": 0.3,
                             "probe_times": [6.1, 5.9], "confirmed": True, "error": ""},
        },
    ]
    if with_low:
        findings.append({
            "id": "f2", "title": "Low confidence noise", "severity": "Low",
            "cvss_v31_score": 1.0, "cvss_v40_score": None,
            "target": "https://example.com", "url": None,
            "port": None, "service": None, "module": "scanner",
            "description": "Weak signal", "reproduction_steps": [],
            "remediation": "Monitor", "references": [], "mitre_attack": [],
            "discovered_at": "2026-06-20T00:00:00Z",
            "evidence": {}, "operator_confirmed": False, "tags": [],
            "confidence": "LOW", "status": "open", "vpr": "LOW", "verification": None,
        })
    return findings


class TestReportEngine:
    def test_filters_low_by_default(self):
        from common.reporting.report_engine import ReportEngine, ReportConfig
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir)
            engine = ReportEngine(_sample_findings(with_low=True), config)
            assert len(engine.findings) == 1
            assert engine._suppressed_count == 1

    def test_include_unverified_shows_all(self):
        from common.reporting.report_engine import ReportEngine, ReportConfig
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir, include_unverified=True)
            engine = ReportEngine(_sample_findings(with_low=True), config)
            assert len(engine.findings) == 2
            assert engine._suppressed_count == 0

    def test_enrich_normalises_confidence(self):
        from common.reporting.report_engine import ReportEngine, ReportConfig
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir)
            engine = ReportEngine(_sample_findings(), config)
            enriched = engine._enrich_findings()
            assert enriched[0]["confidence"] == "HIGH"
            # A legacy status claim has no registered proof lineage and is
            # therefore normalized to an ordinary workflow status.
            assert enriched[0]["status"] == "open"
            assert enriched[0]["verification_state"] == "unknown"
            assert enriched[0]["url"] == "https://example.com/login"

    def test_enrich_conf_color_set(self):
        from common.reporting.report_engine import ReportEngine, ReportConfig
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir)
            engine = ReportEngine(_sample_findings(), config)
            enriched = engine._enrich_findings()
            assert enriched[0]["_conf_color"] == "#27ae60"  # HIGH = green

    def test_generate_html_includes_confidence_column(self):
        from common.reporting.report_engine import ReportEngine, ReportConfig
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir, formats=["html"])
            engine = ReportEngine(_sample_findings(), config)
            paths = asyncio.run(engine.generate())
            html = Path(paths["html"]).read_text()
            assert "Confidence" in html
            assert "HIGH" in html
            assert "unknown" in html

    def test_generate_html_shows_verification_block(self):
        from common.reporting.report_engine import ReportEngine, ReportConfig
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir, formats=["html"])
            engine = ReportEngine(_sample_findings(), config)
            paths = asyncio.run(engine.generate())
            html = Path(paths["html"]).read_text()
            assert "FP Verification" in html
            assert "time-delay" in html

    def test_suppressed_note_in_html(self):
        from common.reporting.report_engine import ReportEngine, ReportConfig
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir, formats=["html"])
            engine = ReportEngine(_sample_findings(with_low=True), config)
            paths = asyncio.run(engine.generate())
            html = Path(paths["html"]).read_text()
            assert "suppressed" in html.lower()

    def test_severity_sort_preserved(self):
        from common.reporting.report_engine import ReportEngine, ReportConfig
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir)
            engine = ReportEngine(_sample_findings(), config)
            assert engine.findings[0]["severity"] == "Critical"


class TestFPReducerWiring:
    def test_unknown_vuln_type_returns_unverified(self):
        """Unknown vuln_type must return UNVERIFIED rather than raise."""
        from common.fp_reducer import FPReducer, Confidence
        fp = FPReducer()
        result = asyncio.run(fp.verify("nonexistent_type", "http://127.0.0.1", "p"))
        assert result.confidence == Confidence.UNVERIFIED

    def test_should_report_rejects_low_and_unverified(self):
        from common.fp_reducer import FPReducer, Confidence, VerificationResult
        fp = FPReducer()
        assert not fp.should_report(VerificationResult(confidence=Confidence.LOW))
        assert not fp.should_report(VerificationResult(confidence=Confidence.UNVERIFIED))
        assert fp.should_report(VerificationResult(confidence=Confidence.MEDIUM))
        assert fp.should_report(VerificationResult(confidence=Confidence.HIGH))

    def test_verification_result_to_dict_has_required_keys(self):
        from common.fp_reducer import Confidence, VerificationResult
        vr = VerificationResult(
            confidence=Confidence.HIGH,
            confirmed=True,
            probe_count=3,
            probe_hits=3,
            evidence=["timing >5s x3"],
        )
        d = vr.to_dict()
        for key in ("confidence", "confirmed", "probe_count", "probe_hits", "evidence"):
            assert key in d, f"Missing key: {key}"
