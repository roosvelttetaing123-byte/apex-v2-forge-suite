"""Compliance Engine — full test coverage.

Tests: rule matching, status logic, to_dict() structure, evaluate_all(),
compliance_pct calculation, and all three registered frameworks.
"""
from __future__ import annotations

import base64
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import common.reporting.compliance_engine as compliance_engine
from common.evidence import immutable_evidence_exists, persist_immutable_evidence
from common.reporting.compliance_engine import (
    CollectionEvidence,
    ComplianceExecutionRecord,
    CollectionStatus,
    ComplianceEngine,
    ComplianceFramework,
    ComplianceRule,
    ComplianceStatus,
    RuleResult,
    ComplianceReport,
    TrustedComplianceAuthority,
    _compliance_execution_attestation_payload,
)
from common.verification_policy import ProofType


_TEST_AUTHORITY_PRIVATE_KEY = Ed25519PrivateKey.generate()


@pytest.fixture(autouse=True)
def _ephemeral_compliance_trust_root(monkeypatch):
    key = ("forge:fixture-compliance-check", "1.0")
    policy = compliance_engine._COMPLIANCE_PROOF_POLICIES[key]
    public_key = base64.b64encode(
        _TEST_AUTHORITY_PRIVATE_KEY.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
    ).decode("ascii")
    monkeypatch.setitem(
        compliance_engine._COMPLIANCE_PROOF_POLICIES,
        key,
        replace(policy, issuer_public_key=public_key),
    )


def _attest_execution(
    record: ComplianceExecutionRecord,
) -> ComplianceExecutionRecord:
    signature = _TEST_AUTHORITY_PRIVATE_KEY.sign(
        _compliance_execution_attestation_payload(record)
    )
    return replace(record, attestation=base64.b64encode(signature).decode("ascii"))


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


def _successful_collection(
    tmp_path,
    *,
    passing_rules: list[str] | None = None,
) -> tuple[CollectionEvidence, TrustedComplianceAuthority]:
    passing = passing_rules or []
    proof_evidence: dict[str, str] = {}
    evidence_store = tmp_path / "compliance-evidence"
    if len(passing) == 1:
        evidence_ref = persist_immutable_evidence(
            f"compliance proof for {passing[0]}",
            evidence_store,
        )
        proof_evidence = {
            "rule_id": passing[0],
            "collector_id": "fixture-collector",
            "collector_version": "1.0",
            "execution_id": "fixture-execution-1",
            "scope_binding": "sha256:" + "b" * 64,
            "target_binding": "sha256:" + "c" * 64,
            "evidence_ref": evidence_ref,
        }
    collection = CollectionEvidence(
        collector_id="fixture-collector",
        collector_version="1.0",
        status=CollectionStatus.SUCCESS,
        check_id="forge:fixture-compliance-check",
        check_version="1.0",
        execution_id="fixture-execution-1",
        scope_binding="sha256:" + "b" * 64,
        target_binding="sha256:" + "c" * 64,
        evidence_store=evidence_store,
        applicable=True,
        covered_rule_ids=passing,
        passing_rule_ids=passing,
        proof_type="credentialed_config",
        proof_evidence=proof_evidence,
    )
    execution = _attest_execution(
        ComplianceExecutionRecord(
            execution_id=collection.execution_id,
            check_id=collection.check_id,
            check_version=collection.check_version,
            collector_id=collection.collector_id,
            collector_version=collection.collector_version,
            status=collection.status,
            scope_binding=collection.scope_binding,
            target_binding=collection.target_binding,
            applicable=collection.applicable,
            covered_rule_ids=frozenset(collection.covered_rule_ids),
            passing_rule_evidence=tuple(
                (rule_id, proof_evidence["evidence_ref"])
                for rule_id in passing
            ),
            proof_type=ProofType.CREDENTIALED_CONFIG,
            authority_id="fixture-compliance-authority",
            issuer_id="forge-fixture-authority-v1",
        )
    )
    policy_key = ("forge:fixture-compliance-check", "1.0")
    policy = compliance_engine._COMPLIANCE_PROOF_POLICIES[policy_key]
    compliance_engine._COMPLIANCE_PROOF_POLICIES[policy_key] = replace(
        policy,
        evidence_resolver=lambda ref: immutable_evidence_exists(ref, evidence_store),
    )
    authority = TrustedComplianceAuthority(
        authority_id="fixture-compliance-authority",
        executions=(execution,),
    )
    return collection, authority


def _signed_collection_state(
    tmp_path,
    *,
    status: CollectionStatus,
    applicable: bool | None,
    covered_rules: list[str] | None = None,
    applicability_reason: str = "",
    error_reason: str = "",
) -> tuple[CollectionEvidence, TrustedComplianceAuthority]:
    """Build a signed non-PASS collection state owned by the test authority."""
    covered = list(covered_rules or [])
    collection = CollectionEvidence(
        collector_id="fixture-collector",
        collector_version="1.0",
        status=status,
        check_id="forge:fixture-compliance-check",
        check_version="1.0",
        execution_id=f"fixture-state-{status.value}",
        scope_binding="sha256:" + "b" * 64,
        target_binding="sha256:" + "c" * 64,
        evidence_store=tmp_path / "unused-claimant-store",
        applicable=applicable,
        covered_rule_ids=covered,
        proof_type=ProofType.CREDENTIALED_CONFIG,
        applicability_reason="claimant metadata is ignored",
        error="claimant metadata is ignored",
    )
    execution = _attest_execution(
        ComplianceExecutionRecord(
            execution_id=collection.execution_id,
            check_id=collection.check_id,
            check_version=collection.check_version,
            collector_id=collection.collector_id,
            collector_version=collection.collector_version,
            status=status,
            scope_binding=collection.scope_binding,
            target_binding=collection.target_binding,
            applicable=applicable,
            covered_rule_ids=frozenset(covered),
            passing_rule_evidence=(),
            proof_type=ProofType.CREDENTIALED_CONFIG,
            applicability_reason=applicability_reason,
            error_reason=error_reason,
            authority_id="fixture-compliance-authority",
            issuer_id="forge-fixture-authority-v1",
        )
    )
    return collection, TrustedComplianceAuthority(
        authority_id="fixture-compliance-authority",
        executions=(execution,),
    )


def test_claimant_cannot_construct_trusted_compliance_authority() -> None:
    unsigned = ComplianceExecutionRecord(
        execution_id="claimant-execution",
        check_id="forge:fixture-compliance-check",
        check_version="1.0",
        collector_id="fixture-collector",
        collector_version="1.0",
        status=CollectionStatus.SUCCESS,
        scope_binding="sha256:" + "b" * 64,
        target_binding="sha256:" + "c" * 64,
        applicable=True,
        covered_rule_ids=frozenset({"PCI-11.3.1"}),
        passing_rule_evidence=(("PCI-11.3.1", "sha256:" + "d" * 64),),
        proof_type=ProofType.CREDENTIALED_CONFIG,
        authority_id="claimant",
        issuer_id="forge-fixture-authority-v1",
    )
    with pytest.raises(ValueError, match="attestation is invalid"):
        TrustedComplianceAuthority(
            authority_id="claimant",
            executions=(unsigned,),
        )


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

    def test_no_match_without_collection_returns_not_tested(self):
        rule = ComplianceRule(
            rule_id="T-3", title="No Match", description="",
            framework=ComplianceFramework.PCI_DSS,
            match_tags=["nonexistent-tag"],
        )
        result = rule.evaluate([_sqli_finding()])
        assert result.status == ComplianceStatus.NOT_TESTED
        assert result.reason == "collection_evidence_missing"

    def test_no_match_with_versioned_passing_evidence_returns_pass(self, tmp_path):
        rule = ComplianceRule(
            rule_id="T-3", title="No Match", description="",
            framework=ComplianceFramework.PCI_DSS,
            match_tags=["nonexistent-tag"],
        )
        collection, authority = _successful_collection(
            tmp_path,
            passing_rules=["T-3"],
        )
        result = rule.evaluate([_sqli_finding()], collection, authority)
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
        assert d["status"] == "not_tested"
        assert d["reason"] == "collection_evidence_missing"


# ── ComplianceReport ──────────────────────────────────────────────────────────

class TestComplianceReport:
    def _make_report(self, findings: list[dict]) -> ComplianceReport:
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        return engine.evaluate(findings)

    def test_empty_scan_has_zero_inferred_passes(self):
        report = self._make_report([])
        assert report.pass_count == 0
        assert report.not_tested_count == len(report.results)

    def test_fail_count_sqli(self):
        report = self._make_report([_sqli_finding()])
        assert report.fail_count >= 1

    def test_compliance_pct_0_to_100(self):
        report = self._make_report([_sqli_finding()])
        assert 0.0 <= report.compliance_pct <= 100.0

    def test_empty_scan_percentage_is_zero(self):
        report = self._make_report([])
        assert report.compliance_pct == 0.0

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
        for key in (
            "pass", "fail", "partial", "not_applicable", "not_tested",
            "collection_error",
        ):
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

    def test_pci_11_3_1_is_not_hardcoded_pass(self):
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate([_sqli_finding()])
        pci_11 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.1")
        assert pci_11.status == ComplianceStatus.NOT_TESTED
        assert pci_11.reason == "collection_evidence_missing"

    def test_pci_11_3_2_always_not_tested(self):
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate([])
        pci_11_2 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.2")
        assert pci_11_2.status == ComplianceStatus.NOT_TESTED


    def test_failed_canceled_unauthorized_and_partial_scans_have_zero_passes(self):
        for status in (
            CollectionStatus.FAILED,
            CollectionStatus.CANCELED,
            CollectionStatus.UNAUTHORIZED,
            CollectionStatus.PARTIAL,
        ):
            evidence = CollectionEvidence(
                collector_id="fixture",
                collector_version="1.0",
                status=status,
                applicable=True,
                covered_rule_ids=["*"],
                passing_rule_ids=["*"],
                proof_type="credentialed_config",
                proof_evidence={"fixture": True},
            )
            report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate([], evidence)
            assert report.pass_count == 0

    def test_non_applicable_is_distinct_from_not_tested(self, tmp_path):
        evidence, authority = _signed_collection_state(
            tmp_path,
            status=CollectionStatus.SUCCESS,
            applicable=False,
            applicability_reason="No cardholder data environment in assessed scope",
        )
        report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate(
            [], evidence, authority
        )
        assert report.not_applicable_count == len(report.results)
        assert report.not_tested_count == 0
        assert {
            result.reason for result in report.results
        } == {"No cardholder data environment in assessed scope"}
        assert {
            result.collection["applicability_reason"]
            for result in report.results
        } == {"No cardholder data environment in assessed scope"}

    def test_collection_error_is_visible_and_not_counted_as_pass(self, tmp_path):
        evidence, authority = _signed_collection_state(
            tmp_path,
            status=CollectionStatus.COLLECTION_ERROR,
            applicable=True,
            error_reason="fixture collector failed",
        )
        report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate(
            [], evidence, authority
        )
        assert report.collection_error_count == len(report.results)
        assert report.pass_count == 0
        assert report.compliance_pct == 0.0
        assert report.to_dict()["collection_error"] == len(report.results)
        assert {result.reason for result in report.results} == {
            "fixture collector failed"
        }
        assert {result.collection["error"] for result in report.results} == {
            "fixture collector failed"
        }

    def test_versioned_successful_collection_can_produce_pass(self, tmp_path):
        evidence, authority = _successful_collection(
            tmp_path,
            passing_rules=["PCI-11.3.1"],
        )
        report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate(
            [],
            evidence,
            authority,
        )
        pci_11 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.1")
        assert pci_11.status == ComplianceStatus.PASS
        assert pci_11.collection["collector_version"] == "1.0"
        assert pci_11.proof_type == "credentialed_config"

    def test_tampered_persisted_compliance_evidence_cannot_pass(self, tmp_path):
        evidence, authority = _successful_collection(
            tmp_path,
            passing_rules=["PCI-11.3.1"],
        )
        evidence_ref = evidence.proof_evidence["evidence_ref"]
        evidence_path = evidence.evidence_store / f"{evidence_ref.removeprefix('sha256:')}.evidence"
        evidence_path.chmod(0o600)
        evidence_path.write_text("tampered", encoding="utf-8")

        report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate(
            [],
            evidence,
            authority,
        )
        pci_11 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.1")
        assert pci_11.status == ComplianceStatus.NOT_TESTED
        assert pci_11.reason == "required_pass_proof_missing_or_unsupported"

    def test_fabricated_collector_and_generic_evidence_cannot_pass(self):
        evidence = CollectionEvidence(
            collector_id="made-up-collector",
            collector_version="9.9",
            status=CollectionStatus.SUCCESS,
            check_id="made-up-check",
            check_version="9.9",
            execution_id="made-up-execution",
            scope_binding="scope",
            target_binding="target",
            applicable=True,
            covered_rule_ids=["PCI-11.3.1"],
            passing_rule_ids=["PCI-11.3.1"],
            proof_type="passive",
            proof_evidence={
                "rule_id": "PCI-11.3.1",
                "collector_id": "made-up-collector",
                "collector_version": "9.9",
                "execution_id": "made-up-execution",
                "scope_binding": "scope",
                "target_binding": "target",
                "evidence_ref": "x",
                "http_status": 200,
            },
        )
        report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate([], evidence)
        pci_11 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.1")
        assert pci_11.status == ComplianceStatus.NOT_TESTED

    def test_registered_constants_and_caller_store_cannot_mint_pass(self, tmp_path):
        caller_store = tmp_path / "caller-selected-store"
        evidence_ref = persist_immutable_evidence(
            b"caller-authored compliance assertion",
            caller_store,
        )
        evidence = CollectionEvidence(
            collector_id="fixture-collector",
            collector_version="1.0",
            status=CollectionStatus.SUCCESS,
            check_id="forge:fixture-compliance-check",
            check_version="1.0",
            execution_id="caller-selected-execution",
            scope_binding="sha256:" + "b" * 64,
            target_binding="sha256:" + "c" * 64,
            evidence_store=caller_store,
            applicable=True,
            covered_rule_ids=["PCI-11.3.1"],
            passing_rule_ids=["PCI-11.3.1"],
            proof_type="credentialed_config",
            proof_evidence={
                "rule_id": "PCI-11.3.1",
                "collector_id": "fixture-collector",
                "collector_version": "1.0",
                "execution_id": "caller-selected-execution",
                "scope_binding": "sha256:" + "b" * 64,
                "target_binding": "sha256:" + "c" * 64,
                "evidence_ref": evidence_ref,
            },
        )

        report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate([], evidence)
        pci_11 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.1")

        assert pci_11.status == ComplianceStatus.NOT_TESTED
        assert pci_11.reason == "collection_execution_authority_missing"
        assert pci_11.collection["execution_authority_bound"] is False
        assert pci_11.collection["claimant_evidence_store_ignored"] is True

    def test_authority_rejects_replayed_or_mutated_collection_binding(self, tmp_path):
        evidence, authority = _successful_collection(
            tmp_path,
            passing_rules=["PCI-11.3.1"],
        )
        replayed = replace(evidence, target_binding="sha256:" + "d" * 64)
        replayed.proof_evidence["target_binding"] = replayed.target_binding

        report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate(
            [],
            replayed,
            authority,
        )
        pci_11 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.1")

        assert pci_11.status == ComplianceStatus.NOT_TESTED
        assert pci_11.reason == "collection_execution_authority_missing"

    def test_signed_execution_requires_policy_owned_evidence_resolver(self, tmp_path):
        evidence, authority = _successful_collection(
            tmp_path,
            passing_rules=["PCI-11.3.1"],
        )
        key = ("forge:fixture-compliance-check", "1.0")
        policy = compliance_engine._COMPLIANCE_PROOF_POLICIES[key]
        compliance_engine._COMPLIANCE_PROOF_POLICIES[key] = replace(
            policy,
            evidence_resolver=None,
        )

        report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate(
            [],
            evidence,
            authority,
        )
        pci_11 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.1")

        assert pci_11.status == ComplianceStatus.NOT_TESTED
        assert pci_11.reason == "required_pass_proof_missing_or_unsupported"

    @pytest.mark.parametrize("proof_type", ["unknown", "simulation", "version_correlation"])
    def test_passing_marker_without_supported_proof_cannot_pass(self, proof_type: str):
        evidence = CollectionEvidence(
            collector_id="fixture",
            collector_version="1.0",
            status=CollectionStatus.SUCCESS,
            applicable=True,
            covered_rule_ids=["PCI-11.3.1"],
            passing_rule_ids=["PCI-11.3.1"],
            proof_type=proof_type,
            proof_evidence={"fixture": True},
        )
        report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate([], evidence)
        pci_11 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.1")
        assert pci_11.status == ComplianceStatus.NOT_TESTED
        assert pci_11.reason == "collection_execution_authority_missing"

    def test_passing_marker_without_proof_evidence_cannot_pass(self):
        evidence = CollectionEvidence(
            collector_id="fixture",
            collector_version="1.0",
            status=CollectionStatus.SUCCESS,
            applicable=True,
            covered_rule_ids=["PCI-11.3.1"],
            passing_rule_ids=["PCI-11.3.1"],
            proof_type="credentialed_config",
        )
        report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate([], evidence)
        pci_11 = next(r for r in report.results if r.rule.rule_id == "PCI-11.3.1")
        assert pci_11.status == ComplianceStatus.NOT_TESTED


    def test_untrusted_collection_state_cannot_override_matching_findings(self):
        rule = ComplianceRule(
            rule_id="T-precedence",
            title="Precedence",
            description="",
            framework=ComplianceFramework.PCI_DSS,
            match_tags=["sqli"],
        )
        non_applicable = CollectionEvidence(
            collector_id="fixture",
            collector_version="1.0",
            status=CollectionStatus.SUCCESS,
            applicable=False,
            covered_rule_ids=["T-precedence"],
        )
        assert rule.evaluate([_sqli_finding()], non_applicable).status == ComplianceStatus.FAIL

        failed = CollectionEvidence(
            collector_id="fixture",
            collector_version="1.0",
            status=CollectionStatus.COLLECTION_ERROR,
            applicable=True,
            covered_rule_ids=["T-precedence"],
            error="fixture failure",
        )
        assert rule.evaluate([_sqli_finding()], failed).status == ComplianceStatus.FAIL

    def test_signed_collection_state_precedes_matching_findings(self, tmp_path):
        rule = ComplianceRule(
            rule_id="T-precedence",
            title="Precedence",
            description="",
            framework=ComplianceFramework.PCI_DSS,
            match_tags=["sqli"],
        )
        non_applicable, na_authority = _signed_collection_state(
            tmp_path,
            status=CollectionStatus.SUCCESS,
            applicable=False,
            covered_rules=[rule.rule_id],
            applicability_reason="Control is outside the signed fixture scope",
        )
        assert rule.evaluate(
            [_sqli_finding()], non_applicable, na_authority
        ).status == ComplianceStatus.NOT_APPLICABLE

        failed, error_authority = _signed_collection_state(
            tmp_path,
            status=CollectionStatus.COLLECTION_ERROR,
            applicable=True,
            covered_rules=[rule.rule_id],
            error_reason="Signed fixture collector failure",
        )
        assert rule.evaluate(
            [_sqli_finding()], failed, error_authority
        ).status == ComplianceStatus.COLLECTION_ERROR

    def test_wildcard_or_status_only_pass_marker_is_rejected(self):
        evidence = CollectionEvidence(
            collector_id="fixture",
            collector_version="1.0",
            status=CollectionStatus.SUCCESS,
            applicable=True,
            covered_rule_ids=["*"],
            passing_rule_ids=["*"],
            proof_type="active",
            proof_evidence={"status_code": 200},
        )
        report = ComplianceEngine(ComplianceFramework.PCI_DSS).evaluate([], evidence)
        assert report.pass_count == 0
        assert report.compliance_pct == 0.0


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
