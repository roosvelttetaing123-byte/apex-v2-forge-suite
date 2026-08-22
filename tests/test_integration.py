"""Integration tests — full scan→finding→report pipeline.

These tests exercise the complete data flow without making real HTTP calls:
  BaseForgeConfig → BaseModule.new_finding() → BaseReporter.generate_all()
  → JSON / CSV / HTML / compliance_report.json outputs.

Validates that the pieces assembled across the codebase actually work together.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from common.config import BaseForgeConfig
from common.reporter import BaseReporter


# ── Shared fixtures ───────────────────────────────────────────────────────────

def _make_findings() -> list[dict]:
    return [
        {
            "id": "int-sqli-01",
            "title": "SQL Injection — Login Bypass",
            "severity": "Critical",
            "cvss_v31_score": 9.8,
            "cvss_v40_score": None,
            "target": "https://demo.forge.local",
            "url": "https://demo.forge.local/login?id=1",
            "port": 443,
            "service": "https",
            "module": "sqli_scanner",
            "description": "Time-based blind SQLi in login form",
            "reproduction_steps": [
                "Navigate to /login",
                "Set id=1' AND SLEEP(5)--",
                "Observe 5-second delay",
            ],
            "remediation": "Use parameterized queries (PDO/PreparedStatement)",
            "references": ["CWE-89", "OWASP-A03"],
            "mitre_attack": ["T1190"],
            "discovered_at": "2026-06-21T00:00:00Z",
            "evidence": {
                "request_raw": "POST /login HTTP/1.1\n\nid=1%27+AND+SLEEP(5)--",
                "response_raw": "HTTP/1.1 200 OK\n\n...",
                "screenshot_path": None,
            },
            "operator_confirmed": False,
            "tags": ["cwe-89", "sqli"],
            "confidence": "HIGH",
            "status": "verified",
            "vpr": "CRITICAL",
            "verification": {
                "confidence": "HIGH",
                "probe_hits": 3,
                "probe_count": 3,
                "evidence": ["time-delay 5.1s", "time-delay 4.9s", "time-delay 5.3s"],
                "baseline_time": 0.25,
                "probe_times": [5.1, 4.9, 5.3],
                "confirmed": True,
                "error": "",
            },
        },
        {
            "id": "int-xss-01",
            "title": "Reflected XSS — Search Parameter",
            "severity": "High",
            "cvss_v31_score": 7.4,
            "cvss_v40_score": None,
            "target": "https://demo.forge.local",
            "url": "https://demo.forge.local/search?q=<script>alert(1)</script>",
            "port": 443,
            "service": "https",
            "module": "xss_scanner",
            "description": "Reflected XSS in search parameter q",
            "reproduction_steps": [
                "GET /search?q=<script>alert(1)</script>",
                "Observe script executed in response",
            ],
            "remediation": "Apply context-aware output encoding and CSP",
            "references": ["CWE-79", "OWASP-A03"],
            "mitre_attack": ["T1059.007"],
            "discovered_at": "2026-06-21T00:00:00Z",
            "evidence": {"request_raw": "GET /search?q=<script>", "response_raw": "200 OK"},
            "operator_confirmed": False,
            "tags": ["cwe-79", "xss"],
            "confidence": "HIGH",
            "status": "verified",
            "vpr": "HIGH",
            "verification": None,
        },
        {
            "id": "int-ssl-01",
            "title": "Weak TLS 1.0 Accepted",
            "severity": "Medium",
            "cvss_v31_score": 5.3,
            "cvss_v40_score": None,
            "target": "https://demo.forge.local",
            "url": None,
            "port": 443,
            "service": "https",
            "module": "ssl_audit",
            "description": "Server accepts deprecated TLS 1.0",
            "reproduction_steps": ["openssl s_client -tls1 -connect demo.forge.local:443"],
            "remediation": "Disable TLS 1.0 and 1.1; enforce TLS 1.2+",
            "references": ["CWE-326"],
            "mitre_attack": [],
            "discovered_at": "2026-06-21T00:00:00Z",
            "evidence": {},
            "operator_confirmed": False,
            "tags": ["ssl", "tls", "weak-cipher"],
            "confidence": "HIGH",
            "status": "verified",
            "vpr": "MEDIUM",
            "verification": None,
        },
    ]


# ── BaseForgeConfig integration ───────────────────────────────────────────────

class TestBaseForgeConfigIntegration:
    def test_default_config_has_verify_findings(self):
        cfg = BaseForgeConfig()
        assert hasattr(cfg, "verify_findings")
        assert cfg.verify_findings is True

    def test_verify_findings_can_be_disabled(self):
        cfg = BaseForgeConfig(verify_findings=False)
        assert cfg.verify_findings is False

    def test_profile_verify_findings_propagates(self):
        from webforge.core.scan_profile import get_profile
        profile = get_profile("quick")
        cfg = BaseForgeConfig()
        cfg.verify_findings = profile.verify_findings
        assert cfg.verify_findings is False

    def test_profile_rate_propagates(self):
        from webforge.core.scan_profile import get_profile
        profile = get_profile("stealth")
        cfg = BaseForgeConfig()
        cfg.rate.requests_per_second = profile.rate_limit
        assert cfg.rate.requests_per_second == 1.0

    def test_config_yaml_round_trip(self, tmp_path):
        from common.config import generate_default_config, load_config
        yaml_path = tmp_path / "forge.yaml"
        generate_default_config(BaseForgeConfig, yaml_path)
        loaded = load_config(yaml_path)
        assert loaded.workers == 10
        assert loaded.verify_findings is True


# ── BaseReporter pipeline ─────────────────────────────────────────────────────

class TestReporterPipeline:
    def test_json_output_structure(self, tmp_path):
        reporter = BaseReporter(
            _make_findings(), tmp_path,
            engagement="forge-integration-test",
            target="https://demo.forge.local",
            formats=["json"],
        )
        paths = reporter.generate_all()

        assert "json" in paths
        data = json.loads(Path(paths["json"]).read_text())

        assert data["engagement"] == "forge-integration-test"
        assert data["target"] == "https://demo.forge.local"
        assert data["total"] == 3
        assert "summary" in data
        assert "findings" in data
        assert len(data["findings"]) == 3

    def test_json_severity_summary(self, tmp_path):
        reporter = BaseReporter(_make_findings(), tmp_path, formats=["json"])
        paths = reporter.generate_all()
        data = json.loads(Path(paths["json"]).read_text())

        summary = data["summary"]
        assert summary["Critical"] == 1
        assert summary["High"] == 1
        assert summary["Medium"] == 1

    def test_json_findings_sorted_by_severity(self, tmp_path):
        reporter = BaseReporter(_make_findings(), tmp_path, formats=["json"])
        paths = reporter.generate_all()
        data = json.loads(Path(paths["json"]).read_text())

        severities = [f["severity"] for f in data["findings"]]
        assert severities[0] == "Critical"

    def test_csv_output_structure(self, tmp_path):
        reporter = BaseReporter(_make_findings(), tmp_path, formats=["csv"])
        paths = reporter.generate_all()

        assert "csv" in paths
        content = Path(paths["csv"]).read_text()
        assert "SQL Injection" in content
        assert "Reflected XSS" in content
        assert "id,title,severity" in content

    def test_html_output_is_valid(self, tmp_path):
        reporter = BaseReporter(_make_findings(), tmp_path, formats=["html"])
        paths = reporter.generate_all()

        assert "html" in paths
        html = Path(paths["html"]).read_text()
        assert "<!DOCTYPE html>" in html.lower() or "<html" in html.lower()
        assert "SQL Injection" in html
        assert "Reflected XSS" in html

    def test_html_escapes_xss_payload(self, tmp_path):
        findings = [{
            "id": "xss-escape-test",
            "title": "XSS <script>alert(1)</script> Test",
            "severity": "High",
            "cvss_v31_score": 7.4,
            "target": "https://example.com",
            "url": None,
            "port": 443,
            "service": "https",
            "module": "xss_scanner",
            "description": "<img src=x onerror=alert(1)>",
            "reproduction_steps": [],
            "remediation": "Encode output",
            "references": [],
            "mitre_attack": [],
            "discovered_at": "2026-06-21T00:00:00Z",
            "evidence": {},
            "operator_confirmed": False,
            "tags": [],
            "confidence": "HIGH",
            "status": "verified",
            "vpr": "HIGH",
            "verification": None,
            "cvss_v40_score": None,
        }]
        reporter = BaseReporter(findings, tmp_path, formats=["html"])
        paths = reporter.generate_all()
        html = Path(paths["html"]).read_text()
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html or "script" not in html.split("alert")[0][-20:]

    def test_compliance_report_generated(self, tmp_path):
        reporter = BaseReporter(_make_findings(), tmp_path, formats=["json"])
        paths = reporter.generate_all()

        assert "compliance" in paths
        compliance_path = Path(paths["compliance"])
        assert compliance_path.exists()

        data = json.loads(compliance_path.read_text())
        assert "pci-dss-4.0" in data
        assert "owasp-top10-2021" in data
        assert "iso-27001-2022" in data

    def test_compliance_report_pci_fails_on_sqli(self, tmp_path):
        reporter = BaseReporter(_make_findings(), tmp_path, formats=["json"])
        paths = reporter.generate_all()

        data = json.loads(Path(paths["compliance"]).read_text())
        pci = data["pci-dss-4.0"]
        assert pci["fail"] >= 1

    def test_compliance_report_owasp_fails_on_xss(self, tmp_path):
        reporter = BaseReporter(_make_findings(), tmp_path, formats=["json"])
        paths = reporter.generate_all()

        data = json.loads(Path(paths["compliance"]).read_text())
        owasp = data["owasp-top10-2021"]
        assert owasp["fail"] >= 1

    def test_compliance_pct_in_range(self, tmp_path):
        reporter = BaseReporter(_make_findings(), tmp_path, formats=["json"])
        paths = reporter.generate_all()

        data = json.loads(Path(paths["compliance"]).read_text())
        for fw_key, report in data.items():
            pct = report["compliance_pct"]
            assert 0.0 <= pct <= 100.0, f"{fw_key} pct out of range: {pct}"

    def test_empty_findings_clean_compliance(self, tmp_path):
        reporter = BaseReporter([], tmp_path, formats=["json"])
        paths = reporter.generate_all()

        data = json.loads(Path(paths["compliance"]).read_text())
        pci = data["pci-dss-4.0"]
        assert pci["fail"] == 0


# ── BaseModule → finding → reporter pipeline ──────────────────────────────────

class TestModuleToReporterPipeline:
    def _make_module(self, tmp_path: Path):
        from common.base_module import BaseModule, ModuleResult
        from common.scope import Scope
        from common.db import create_db
        from common.finding import Severity

        class SqliModule(BaseModule):
            NAME = "sqli_scanner"
            DESCRIPTION = "SQL injection scanner"
            PHASE = 4

            async def fixture_run(self) -> ModuleResult:
                start = time.monotonic()
                self.new_finding(
                    title="SQL Injection",
                    severity=Severity.CRITICAL,
                    description="Time-based SQLi",
                    reproduction_steps=["Send payload"],
                    remediation="Use parameterized queries",
                    references=["CWE-89"],
                    url="https://demo.forge.local/login",
                    confidence="HIGH",
                )
                return self._make_result(start)

            async def run(self) -> ModuleResult:
                return await self.fixture_run()

        cfg = BaseForgeConfig(target="https://demo.forge.local")
        cfg.extra["allow_legacy_compat"] = True
        scope = Scope(["demo.forge.local"])
        session = create_db(tmp_path / "test.db")
        return SqliModule(cfg, scope, session, tmp_path), session

    def test_module_finding_flows_into_reporter(self, tmp_path):
        module, session = self._make_module(tmp_path)
        result = asyncio.run(module.fixture_run())
        session.close()

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.title == "SQL Injection"
        assert finding.confidence == "HIGH"

        reporter = BaseReporter(
            [finding.to_dict()],
            tmp_path / "reports",
            engagement="pipeline-test",
            formats=["json"],
        )
        paths = reporter.generate_all()

        data = json.loads(Path(paths["json"]).read_text())
        assert data["total"] == 1
        assert data["findings"][0]["title"] == "SQL Injection"

    def test_duplicate_findings_deduplicated(self, tmp_path):
        from common.base_module import BaseModule, ModuleResult
        from common.scope import Scope
        from common.db import create_db
        from common.finding import Severity

        class DupModule(BaseModule):
            NAME = "dup_scanner"
            DESCRIPTION = "test"
            PHASE = 1

            async def fixture_run(self) -> ModuleResult:
                start = time.monotonic()
                for _ in range(3):
                    self.new_finding(
                        title="XSS",
                        severity=Severity.HIGH,
                        description="same",
                        reproduction_steps=[],
                        remediation="fix",
                        references=[],
                        url="https://example.com/search",
                    )
                return self._make_result(start)

            async def run(self) -> ModuleResult:
                return await self.fixture_run()

        cfg = BaseForgeConfig(target="https://example.com")
        cfg.extra["allow_legacy_compat"] = True
        scope = Scope(["example.com"])
        session = create_db(tmp_path / "test.db")
        mod = DupModule(cfg, scope, session, tmp_path)
        result = asyncio.run(mod.fixture_run())
        session.close()

        assert len(result.findings) == 1

    def test_full_pipeline_with_compliance(self, tmp_path):
        module, session = self._make_module(tmp_path)
        result = asyncio.run(module.fixture_run())
        session.close()

        finding_dicts = [f.to_dict() for f in result.findings]
        reporter = BaseReporter(
            finding_dicts,
            tmp_path / "full_reports",
            engagement="full-pipeline",
            formats=["json", "csv"],
        )
        paths = reporter.generate_all()

        assert "json" in paths
        assert "csv" in paths
        assert "compliance" in paths

        compliance = json.loads(Path(paths["compliance"]).read_text())
        assert compliance["pci-dss-4.0"]["fail"] >= 1


# ── Compliance engine wired correctly from reporter ───────────────────────────

class TestComplianceWiring:
    def test_reporter_calls_compliance_engine(self, tmp_path):
        findings = _make_findings()
        reporter = BaseReporter(findings, tmp_path, formats=[])
        paths = reporter.generate_all()
        assert "compliance" in paths

    def test_compliance_json_has_rule_details(self, tmp_path):
        reporter = BaseReporter(_make_findings(), tmp_path, formats=[])
        paths = reporter.generate_all()

        data = json.loads(Path(paths["compliance"]).read_text())
        pci_rules = data["pci-dss-4.0"]["rules"]
        assert len(pci_rules) >= 8
        for rule in pci_rules:
            assert "rule_id" in rule
            assert "title" in rule
            assert "status" in rule
            assert "matched_findings" in rule

    def test_compliance_matched_findings_have_structure(self, tmp_path):
        reporter = BaseReporter(_make_findings(), tmp_path, formats=[])
        paths = reporter.generate_all()

        data = json.loads(Path(paths["compliance"]).read_text())
        for fw_key, fw_data in data.items():
            for rule in fw_data["rules"]:
                for mf in rule.get("matched_findings", []):
                    assert "id" in mf
                    assert "title" in mf
                    assert "severity" in mf
