"""Compliance Engine — full test coverage.

Tests: rule matching, status logic, to_dict() structure, evaluate_all(),
compliance_pct calculation, and all three registered frameworks.
"""
from __future__ import annotations

import pytest

from common.reporting.compliance_engine import (
    ComplianceEngine,
    ComplianceFramework,
    ComplianceRule,
    ComplianceStatus,
    RuleResult,
    ComplianceReport,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _sqli_finding() -> dict:
    return {
        "id": "f-sqli-01",
        "title": "SQL Injection — param 'id'",
        "severity": "critical",
        "tags": ["cwe-89", "sqli"],
        "references": ["CWE-89"],
        "description": "Time-based SQLi in login endpoint",
    }


def _xss_finding() -> dict:
    return {
        "id": "f-xss-01",
        "title": "Cross-Site Scripting (Reflected XSS)",
        "severity": "critical",
        "tags": ["cwe-79", "xss"],
        "references": ["CWE-79"],
        "description": "Reflected XSS in search parameter",
    }


def _ssl_finding() -> dict:
    return {
        "id": "f-ssl-01",
        "title": "Weak TLS Cipher Suite Accepted",
        "severity": "critical",
        "tags": ["ssl", "tls", "weak-cipher"],
        "references": [],
        "description": "Server accepts RC4 and export-grade ciphers",
    }


def _password_finding() -> dict:
    return {
        "id": "f-pw-01",
        "title": "Weak Password Policy",
        "severity": "medium",
        "tags": ["weak-password", "password-policy"],
        "references": [],
        "description": "Application allows 4-character passwords",
    }


def _idor_finding() -> dict:
    return {
        "id": "f-idor-01",
        "title": "IDOR — Horizontal Privilege Escalation",
        "severity": "critical",
        "tags": ["idor", "cwe-639"],
        "references": ["CWE-639"],
        "description": "User can access another user's orders via ?id=",
    }


def _cmd_inject_finding() -> dict:
    return {
        "id": "f-cmd-01",
        "title": "OS Command Injection",
        "severity": "critical",
        "tags": ["cwe-78", "cmdi"],
        "references": ["CWE-78"],
        "description": "Remote code execution via parameter injection",
    }


# ── ComplianceRule unit tests ──────────────────────────────────────────────────

class TestComplianceRule:
    def test_evaluate_returns_rule_result(self):
        rule = ComplianceRule(
            rule_id="TEST-1", title="Test Rule", description="",
            framework=ComplianceFramework.PCI_DSS,
            match_tags=["sqli"],
        )
        result = rule.evaluate([_sqli_finding()])
        assert isinstance(result, RuleResult)
        assert result.rule is rule

    def test_tag_match_causes_fail(self):
        rule = ComplianceRule(
            rule_id="T-1", title="Tag Test", description="",
            framework=ComplianceFramework.PCI_DSS,
            severity="critical",
            match_tags=["sqli"],
        )
        result = rule.evaluate([_sqli_finding()])
        assert result.status == ComplianceStatus.FAIL

    def test_title_pattern_match_causes_fail(self):
        rule = ComplianceRule(
            rule_id="T-2", title="Pattern Test", description="",
            framework=ComplianceFramework.PCI_DSS,
            severity="high",
            match_title_patterns=[r"sql.?inject"],
        )
        result = rule.evaluate([_sqli_finding()])
        assert result.status == ComplianceStatus.FAIL

    def test_no_match_returns_pass(self):
        rule = ComplianceRule(
            rule_id="T-3", title="No Match", description="",
            framework=ComplianceFramework.PCI_DSS,
            match_tags=["nonexistent-tag"],
        )
        result = rule.evaluate([_sqli_finding()])
        assert result.status == ComplianceStatus.PASS

    def test_low_severity_finding_returns_partial(self):
        rule = ComplianceRule(
            rule_id="T-4", title="Severity Test", description="",
            framework=ComplianceFramework.PCI_DSS,
            severity="critical",
            match_tags=["password-policy"],
        )
        finding = {
            "id": "f-low", "title": "Weak Password Policy",
            "severity": "low", "tags": ["password-policy"], "references": [],
        }
        result = rule.evaluate([finding])
        assert result.status == ComplianceStatus.PARTIAL

    def test_custom_check_fn_overrides_default(self):
        rule = ComplianceRule(
            rule_id="T-5", title="Custom Check", description="",
            framework=ComplianceFramework.PCI_DSS,
            check_fn=lambda _findings: ComplianceStatus.NOT_TESTED,
        )
        result = rule.evaluate([_sqli_finding()])
        assert result.status == ComplianceStatus.NOT_TESTED

    def test_matched_findings_populated(self):
        rule = ComplianceRule(
            rule_id="T-6", title="Match Count", description="",
            framework=ComplianceFramework.PCI_DSS,
            severity="critical",
            match_tags=["sqli"],
        )
        result = rule.evaluate([_sqli_finding(), _xss_finding()])
        assert len(result.matched_findings) == 1
        assert result.matched_findings[0]["id"] == "f-sqli-01"

    def test_reference_tag_match(self):
        rule = ComplianceRule(
            rule_id="T-7", title="Ref Match", description="",
            framework=ComplianceFramework.PCI_DSS,
            severity="high",
            match_tags=["cwe-89"],
        )
        result = rule.evaluate([_sqli_finding()])
        assert result.status == ComplianceStatus.FAIL


# ── RuleResult.to_dict() ──────────────────────────────────────────────────────

class TestRuleResultToDict:
    def _make_result(self, findings: list[dict]) -> RuleResult:
        rule = ComplianceRule(
            rule_id="PCI-6.2.4", title="Injection Prevention",
            description="Prevent injection attacks",
            section="6.2.4",
            framework=ComplianceFramework.PCI_DSS,
            severity="critical",
            match_tags=["sqli"],
            remediation="Use parameterized queries",
        )
        return rule.evaluate(findings)

    def test_required_keys_present(self):
        result = self._make_result([_sqli_finding()])
        d = result.to_dict()
        for key in ("rule_id", "title", "section", "severity", "status",
                    "finding_count", "finding_titles", "matched_findings", "remediation"):
            assert key in d, f"Missing key: {key}"

    def test_matched_findings_structure(self):
        result = self._make_result([_sqli_finding()])
        d = result.to_dict()
        assert len(d["matched_findings"]) == 1
        mf = d["matched_findings"][0]
        assert "id" in mf
        assert "title" in mf
        assert "severity" in mf

    def test_matched_findings_capped_at_5(self):
        findings = [
            {"id": f"f{i}", "title": f"Finding {i}", "severity": "critical",
             "tags": ["sqli"], "references": []}
            for i in range(10)
        ]
        result = self._make_result(findings)
        d = result.to_dict()
        assert len(d["matched_findings"]) == 5
        assert len(d["finding_titles"]) == 5

    def test_pass_result_has_empty_findings(self):
        result = self._make_result([])
        d = result.to_dict()
        assert d["finding_count"] == 0
        assert d["matched_findings"] == []
        assert d["status"] == "pass"


# ── ComplianceReport ──────────────────────────────────────────────────────────

class TestComplianceReport:
    def _make_report(self, findings: list[dict]) -> ComplianceReport:
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        return engine.evaluate(findings)

    def test_pass_count_clean_scan(self):
        report = self._make_report([])
        assert report.pass_count >= 3

    def test_fail_count_sqli(self):
        report = self._make_report([_sqli_finding()])
        assert report.fail_count >= 1

    def test_compliance_pct_0_to_100(self):
        report = self._make_report([_sqli_finding()])
        assert 0.0 <= report.compliance_pct <= 100.0

    def test_compliance_pct_clean_is_high(self):
        report = self._make_report([])
        assert report.compliance_pct >= 50.0

    def test_summary_contains_framework(self):
        report = self._make_report([])
        s = report.summary()
        assert "pci-dss" in s.lower()

    def test_to_dict_structure(self):
        report = self._make_report([_sqli_finding()])
        d = report.to_dict()
        assert d["framework"] == "pci-dss-4.0"
        assert isinstance(d["rules"], list)
        assert "compliance_pct" in d
        for key in ("pass", "fail", "partial", "not_tested"):
            assert key in d


# ── ComplianceEngine — per-framework ─────────────────────────────────────────

class TestComplianceEnginePciDss:
    def test_rule_count(self):
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        assert len(engine.rules) >= 8

    def test_sqli_fails_pci_6_2_4(self):
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate([_sqli_finding()])
        failed_ids = {r.rule.rule_id for r in report.results if r.status == ComplianceStatus.FAIL}
        assert "PCI-6.2.4" in failed_ids

    def test_cmd_inject_fails_pci_6_5_1(self):
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate([_cmd_inject_finding()])
        failed_ids = {r.rule.rule_id for r in report.results if r.status == ComplianceStatus.FAIL}
        assert "PCI-6.5.1" in failed_ids

    def test_ssl_fails_pci_4_2_1(self):
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate([_ssl_finding()])
        failed_ids = {r.rule.rule_id for r in report.results if r.status == ComplianceStatus.FAIL}
        assert "PCI-4.2.1" in failed_ids

    def test_password_fails_pci_8_3_6(self):
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate([_password_finding()])
        failed_ids = {r.rule.rule_id for r in report.results if r.status == ComplianceStatus.FAIL}
        assert "PCI-8.3.6" in failed_ids

    def test_pci_11_3_1_always_passes(self):
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate([_sqli_finding()])
        pci_11 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.1")
        assert pci_11.status == ComplianceStatus.PASS

    def test_pci_11_3_2_always_not_tested(self):
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate([])
        pci_11_2 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.2")
        assert pci_11_2.status == ComplianceStatus.NOT_TESTED


class TestComplianceEngineOwasp:
    def test_rule_count_exactly_10(self):
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        assert len(engine.rules) == 10

    def test_all_rule_ids_a01_to_a10(self):
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        rule_ids = {r.rule_id for r in engine.rules}
        for n in range(1, 11):
            expected = f"A{n:02d}:2021"
            assert expected in rule_ids, f"Missing OWASP rule: {expected}"

    def test_sqli_fails_a03(self):
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        report = engine.evaluate([_sqli_finding()])
        failed_ids = {r.rule.rule_id for r in report.results if r.status == ComplianceStatus.FAIL}
        assert "A03:2021" in failed_ids

    def test_idor_fails_a01(self):
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        report = engine.evaluate([_idor_finding()])
        failed_ids = {r.rule.rule_id for r in report.results if r.status == ComplianceStatus.FAIL}
        assert "A01:2021" in failed_ids

    def test_xss_fails_a03(self):
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        report = engine.evaluate([_xss_finding()])
        failed_ids = {r.rule.rule_id for r in report.results if r.status == ComplianceStatus.FAIL}
        assert "A03:2021" in failed_ids

    def test_ssl_failure_hits_a02_or_a05(self):
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        report = engine.evaluate([_ssl_finding()])
        failed_ids = {r.rule.rule_id for r in report.results if r.status == ComplianceStatus.FAIL}
        assert failed_ids, "SSL finding should fail at least one OWASP rule"

    def test_framework_value(self):
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        assert engine.framework.value == "owasp-top10-2021"


class TestComplianceEngineIso27001:
    def test_rule_count(self):
        engine = ComplianceEngine(ComplianceFramework.ISO_27001)
        assert len(engine.rules) >= 4

    def test_evaluate_returns_report(self):
        engine = ComplianceEngine(ComplianceFramework.ISO_27001)
        report = engine.evaluate([_sqli_finding()])
        assert isinstance(report, ComplianceReport)
        assert report.framework == ComplianceFramework.ISO_27001

    def test_framework_value(self):
        engine = ComplianceEngine(ComplianceFramework.ISO_27001)
        assert engine.framework.value == "iso-27001-2022"


class TestComplianceEngineEvaluateAll:
    def test_evaluate_all_returns_all_frameworks(self):
        reports = ComplianceEngine.evaluate_all([_sqli_finding()])
        expected = {"pci-dss-4.0", "owasp-top10-2021", "iso-27001-2022"}
        assert set(reports.keys()) == expected

    def test_evaluate_all_each_has_results(self):
        reports = ComplianceEngine.evaluate_all([_sqli_finding()])
        for fw_key, report in reports.items():
            assert len(report.results) > 0, f"{fw_key} has no rules"

    def test_evaluate_all_to_dict_serializable(self):
        import json
        reports = ComplianceEngine.evaluate_all([_sqli_finding(), _xss_finding()])
        # Must not raise
        serialized = json.dumps({k: v.to_dict() for k, v in reports.items()})
        data = json.loads(serialized)
        assert "pci-dss-4.0" in data
        assert "owasp-top10-2021" in data

    def test_evaluate_all_empty_findings(self):
        reports = ComplianceEngine.evaluate_all([])
        for fw_key, report in reports.items():
            assert report.compliance_pct >= 0.0

    def test_unknown_framework_raises(self):
        with pytest.raises(ValueError):
            ComplianceEngine(ComplianceFramework.NIST_CSF)

    def test_unknown_hipaa_framework_raises(self):
        with pytest.raises(ValueError):
            ComplianceEngine(ComplianceFramework.HIPAA)

    def test_multiple_findings_increases_fail_count(self):
        reports = ComplianceEngine.evaluate_all([
            _sqli_finding(), _xss_finding(), _ssl_finding(), _cmd_inject_finding(),
        ])
        pci = reports["pci-dss-4.0"]
        owasp = reports["owasp-top10-2021"]
        assert pci.fail_count >= 3
        assert owasp.fail_count >= 2
