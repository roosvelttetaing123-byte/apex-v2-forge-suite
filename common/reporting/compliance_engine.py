"""Compliance engine — map findings to PCI-DSS 4.0, OWASP Top 10 2021, ISO 27001.

Generates compliance evidence reports showing which rules pass/fail based on
actual scan findings. Used by the reporting engine for compliance-oriented exports.

Usage:
    engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
    report = engine.evaluate(findings)
    print(report.summary())
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from common.verification_policy import (
    ProofType,
    normalise_proof_type,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class ComplianceFramework(str, Enum):
    PCI_DSS = "pci-dss-4.0"
    OWASP_TOP10 = "owasp-top10-2021"
    ISO_27001 = "iso-27001-2022"
    NIST_CSF = "nist-csf-2.0"
    HIPAA = "hipaa"


class ComplianceStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"
    COLLECTION_ERROR = "collection_error"


class CollectionStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELED = "canceled"
    UNAUTHORIZED = "unauthorized"
    UNSUPPORTED = "unsupported"
    COLLECTION_ERROR = "collection_error"


@dataclass(frozen=True)
class ComplianceProofPolicy:
    """Reviewed compliance collector contract with exact check/version binding."""

    check_id: str
    check_version: str
    collector_id: str
    collector_version: str
    proof_types: frozenset[ProofType]
    issuer_id: str
    issuer_public_key: str
    execution_id_prefix: str = ""
    authority_id_prefix: str = ""
    evidence_resolver: Callable[[str], bool] | None = None


_COMPLIANCE_PROOF_POLICIES: dict[tuple[str, str], ComplianceProofPolicy] = {
    ("forge:fixture-compliance-check", "1.0"): ComplianceProofPolicy(
        check_id="forge:fixture-compliance-check",
        check_version="1.0",
        collector_id="fixture-collector",
        collector_version="1.0",
        proof_types=frozenset({ProofType.CREDENTIALED_CONFIG}),
        issuer_id="forge-fixture-authority-v1",
        # Fixture trust root; production collectors register a separate issuer.
        # The matching private key is absent from source and report workers.
        issuer_public_key="AsUopgpGCuQULOSiOJpnqVXVVnfgEAoOeAL3Xj42als=",
        execution_id_prefix="fixture-",
        authority_id_prefix="fixture-",
    ),
}


@dataclass(frozen=True)
class ComplianceExecutionRecord:
    """Authority-owned result of one exact, versioned collection execution.

    This record is deliberately separate from :class:`CollectionEvidence`.
    CollectionEvidence is a serializable observation supplied to the reporting
    boundary; this record is injected by the execution control plane and is the
    source of truth for status, scope, target, coverage, and proof references.
    """

    execution_id: str
    check_id: str
    check_version: str
    collector_id: str
    collector_version: str
    status: CollectionStatus
    scope_binding: str
    target_binding: str
    applicable: bool | None
    covered_rule_ids: frozenset[str]
    passing_rule_evidence: tuple[tuple[str, str], ...]
    proof_type: ProofType
    applicability_reason: str = ""
    error_reason: str = ""
    authority_id: str = ""
    issuer_id: str = ""
    attestation: str = ""

    def evidence_ref_for(self, rule_id: str) -> str | None:
        matches = [
            evidence_ref
            for candidate_rule, evidence_ref in self.passing_rule_evidence
            if candidate_rule == rule_id
        ]
        return matches[0] if len(matches) == 1 else None


@dataclass(frozen=True)
class TrustedComplianceAuthority:
    """Out-of-band registry of signed execution records.

    The authority is a runtime dependency, never a field accepted from a report
    payload.  Consequently, knowing public collector constants or creating a
    private content-addressed directory cannot mint a compliance PASS.
    """

    authority_id: str
    executions: tuple[ComplianceExecutionRecord, ...]

    def __post_init__(self) -> None:
        if not self.authority_id.strip():
            raise ValueError("compliance authority id is required")
        seen: set[str] = set()
        for record in self.executions:
            if not record.execution_id.strip():
                raise ValueError("compliance execution id is required")
            if record.execution_id in seen:
                raise ValueError(f"duplicate compliance execution id: {record.execution_id}")
            seen.add(record.execution_id)
            if not _binding_ref(record.scope_binding) or not _binding_ref(
                record.target_binding
            ):
                raise ValueError("compliance execution bindings must be sha256 references")
            policy = _COMPLIANCE_PROOF_POLICIES.get(
                (record.check_id, record.check_version)
            )
            if (
                policy is None
                or policy.collector_id != record.collector_id
                or policy.collector_version != record.collector_version
                or record.proof_type not in policy.proof_types
            ):
                raise ValueError("compliance execution is not bound to a registered policy")
            if (
                record.authority_id != self.authority_id
                or not _compliance_execution_attestation_valid(record, policy)
            ):
                raise ValueError("compliance execution attestation is invalid")
            if len(record.covered_rule_ids) != len(set(record.covered_rule_ids)):
                raise ValueError("duplicate covered compliance rule id")
            if (
                (record.applicable is False and not record.applicability_reason.strip())
                or (record.applicable is not False and record.applicability_reason)
                or (
                    record.status == CollectionStatus.COLLECTION_ERROR
                    and not record.error_reason.strip()
                )
                or (
                    record.status != CollectionStatus.COLLECTION_ERROR
                    and record.error_reason
                )
            ):
                raise ValueError("compliance execution reason binding is invalid")
            evidence_rules: set[str] = set()
            evidence_refs: set[str] = set()
            for rule_id, evidence_ref in record.passing_rule_evidence:
                if (
                    not rule_id
                    or rule_id in evidence_rules
                    or evidence_ref in evidence_refs
                    or not _immutable_evidence_ref(evidence_ref)
                ):
                    raise ValueError("invalid or duplicate compliance proof binding")
                if rule_id not in record.covered_rule_ids:
                    raise ValueError("passing rule must be present in execution coverage")
                evidence_rules.add(rule_id)
                evidence_refs.add(evidence_ref)

    def execution(self, execution_id: str) -> ComplianceExecutionRecord | None:
        matches = [row for row in self.executions if row.execution_id == execution_id]
        return matches[0] if len(matches) == 1 else None


def _immutable_evidence_ref(value: Any) -> bool:
    raw = str(value or "").strip().lower()
    if not raw.startswith("sha256:") or len(raw) != 71:
        return False
    return all(char in "0123456789abcdef" for char in raw.removeprefix("sha256:"))


def _binding_ref(value: Any) -> bool:
    """Validate opaque target/scope bindings used by a collection record."""
    return _immutable_evidence_ref(value)


def _compliance_execution_attestation_payload(
    record: ComplianceExecutionRecord,
) -> bytes:
    """Return the stable signed representation of execution-owned truth."""
    payload = {
        "execution_id": record.execution_id,
        "check_id": record.check_id,
        "check_version": record.check_version,
        "collector_id": record.collector_id,
        "collector_version": record.collector_version,
        "status": record.status.value,
        "scope_binding": record.scope_binding,
        "target_binding": record.target_binding,
        "applicable": record.applicable,
        "covered_rule_ids": sorted(record.covered_rule_ids),
        "passing_rule_evidence": sorted(
            [list(item) for item in record.passing_rule_evidence]
        ),
        "proof_type": record.proof_type.value,
        "applicability_reason": record.applicability_reason,
        "error_reason": record.error_reason,
        "authority_id": record.authority_id,
        "issuer_id": record.issuer_id,
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _compliance_execution_attestation_valid(
    record: ComplianceExecutionRecord,
    policy: ComplianceProofPolicy,
) -> bool:
    """Verify execution truth against the collector policy's pinned trust root."""
    if record.issuer_id != policy.issuer_id or not record.attestation:
        return False
    if policy.execution_id_prefix and not record.execution_id.startswith(
        policy.execution_id_prefix
    ):
        return False
    if policy.authority_id_prefix and not record.authority_id.startswith(
        policy.authority_id_prefix
    ):
        return False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(policy.issuer_public_key, validate=True)
        )
        signature = base64.b64decode(record.attestation, validate=True)
        public_key.verify(
            signature,
            _compliance_execution_attestation_payload(record),
        )
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def _policy_evidence_exists(
    policy: ComplianceProofPolicy,
    evidence_ref: str,
) -> bool:
    """Resolve proof only through the collector policy's canonical store."""
    if policy.evidence_resolver is None or not _immutable_evidence_ref(evidence_ref):
        return False
    try:
        return policy.evidence_resolver(evidence_ref) is True
    except Exception:
        return False


def _registered_collector(
    check_id: str,
    check_version: str,
    collector_id: str,
    collector_version: str,
) -> bool:
    policy = _COMPLIANCE_PROOF_POLICIES.get((str(check_id).strip(), str(check_version).strip()))
    return bool(
        policy
        and policy.collector_id == str(collector_id).strip()
        and policy.collector_version == str(collector_version).strip()
    )


@dataclass(frozen=True)
class CollectionEvidence:
    """Versioned evidence that establishes rule applicability and coverage."""
    collector_id: str
    collector_version: str
    status: CollectionStatus
    check_id: str = ""
    check_version: str = ""
    execution_id: str = ""
    scope_binding: str = ""
    target_binding: str = ""
    # Compatibility-only claimant metadata. Promotion deliberately ignores this
    # path; evidence is resolved exclusively by the registered proof policy.
    evidence_store: Path | str | None = None
    applicable: bool | None = None
    covered_rule_ids: list[str] = field(default_factory=list)
    passing_rule_ids: list[str] = field(default_factory=list)
    proof_type: ProofType | str = ProofType.UNKNOWN
    proof_evidence: dict[str, Any] = field(default_factory=dict)
    applicability_reason: str = ""
    error: str = ""

    def covers(self, rule_id: str) -> bool:
        return rule_id in self.covered_rule_ids

    def records_pass(self, rule_id: str) -> bool:
        return rule_id in self.passing_rule_ids

    def is_versioned(self) -> bool:
        return bool(self.collector_id.strip() and self.collector_version.strip())

    def is_registered(self) -> bool:
        return _registered_collector(
            self.check_id,
            self.check_version,
            self.collector_id,
            self.collector_version,
        )

    def _authoritative_execution(
        self,
        authority: TrustedComplianceAuthority | None,
    ) -> ComplianceExecutionRecord | None:
        if authority is None:
            return None
        execution = authority.execution(self.execution_id)
        proof_type = normalise_proof_type(self.proof_type)
        if execution is None or not (
            execution.check_id == self.check_id
            and execution.check_version == self.check_version
            and execution.collector_id == self.collector_id
            and execution.collector_version == self.collector_version
            and execution.status == self.status
            and execution.scope_binding == self.scope_binding
            and execution.target_binding == self.target_binding
            and execution.applicable is self.applicable
            and execution.covered_rule_ids == frozenset(self.covered_rule_ids)
            and frozenset(rule for rule, _ in execution.passing_rule_evidence)
            == frozenset(self.passing_rule_ids)
            and execution.proof_type == proof_type
        ):
            return None
        return execution

    def has_required_pass_proof(
        self,
        rule_id: str,
        authority: TrustedComplianceAuthority | None = None,
    ) -> bool:
        """Return True only when an authority owns the exact execution truth."""
        if authority is None:
            return False
        execution = self._authoritative_execution(authority)
        if execution is None:
            return False
        proof_type = normalise_proof_type(self.proof_type)
        evidence_rule = str(self.proof_evidence.get("rule_id") or "").strip()
        evidence_collector = str(self.proof_evidence.get("collector_id") or "").strip()
        evidence_version = str(self.proof_evidence.get("collector_version") or "").strip()
        evidence_ref = str(self.proof_evidence.get("evidence_ref") or "").strip()
        evidence_execution = str(self.proof_evidence.get("execution_id") or "").strip()
        evidence_scope = str(self.proof_evidence.get("scope_binding") or "").strip()
        evidence_target = str(self.proof_evidence.get("target_binding") or "").strip()
        authoritative_ref = execution.evidence_ref_for(rule_id)
        policy = _COMPLIANCE_PROOF_POLICIES.get((self.check_id, self.check_version))
        return (
            policy is not None
            and _registered_collector(
                self.check_id,
                self.check_version,
                self.collector_id,
                self.collector_version,
            )
            and policy.collector_id == self.collector_id
            and policy.collector_version == self.collector_version
            and proof_type in policy.proof_types
            and self.status == CollectionStatus.SUCCESS
            and self.applicable is True
            and self.covers(rule_id)
            and self.records_pass(rule_id)
            and evidence_rule == rule_id
            and evidence_collector == self.collector_id
            and evidence_version == self.collector_version
            and bool(self.execution_id)
            and evidence_execution == self.execution_id
            and _binding_ref(self.scope_binding)
            and evidence_scope == self.scope_binding
            and _binding_ref(self.target_binding)
            and evidence_target == self.target_binding
            and _immutable_evidence_ref(evidence_ref)
            and authoritative_ref == evidence_ref
            and _policy_evidence_exists(policy, evidence_ref)
        )

    def to_dict(
        self,
        authority: TrustedComplianceAuthority | None = None,
    ) -> dict[str, Any]:
        authoritative_execution = self._authoritative_execution(authority)
        return {
            "collector_id": self.collector_id,
            "collector_version": self.collector_version,
            "check_id": self.check_id,
            "check_version": self.check_version,
            "execution_id": self.execution_id,
            "scope_binding": self.scope_binding,
            "target_binding": self.target_binding,
            "execution_authority_id": (
                authority.authority_id
                if authority is not None and authoritative_execution is not None
                else ""
            ),
            "execution_authority_bound": authoritative_execution is not None,
            "claimant_evidence_store_ignored": self.evidence_store is not None,
            "status": (
                authoritative_execution.status.value
                if authoritative_execution is not None
                else self.status.value
            ),
            "applicable": (
                authoritative_execution.applicable
                if authoritative_execution is not None
                else self.applicable
            ),
            "covered_rule_ids": (
                sorted(authoritative_execution.covered_rule_ids)
                if authoritative_execution is not None
                else list(self.covered_rule_ids)
            ),
            "passing_rule_ids": (
                sorted(rule for rule, _ in authoritative_execution.passing_rule_evidence)
                if authoritative_execution is not None
                else list(self.passing_rule_ids)
            ),
            "proof_type": (
                authoritative_execution.proof_type.value
                if authoritative_execution is not None
                else normalise_proof_type(self.proof_type).value
            ),
            "proof_evidence": dict(self.proof_evidence),
            "applicability_reason": (
                authoritative_execution.applicability_reason
                if authoritative_execution is not None
                else ""
            ),
            "error": (
                authoritative_execution.error_reason
                if authoritative_execution is not None
                else ""
            ),
        }


@dataclass
class ComplianceRule:
    """A single compliance rule/requirement."""
    rule_id: str
    title: str
    description: str
    framework: ComplianceFramework
    severity: str = "high"       # critical, high, medium, low, info
    section: str = ""            # e.g. "6.2" for PCI-DSS
    check_fn: Callable[[list[dict]], ComplianceStatus] | None = None
    # Matching: which finding tags/titles trigger this rule
    match_tags: list[str] = field(default_factory=list)
    match_title_patterns: list[str] = field(default_factory=list)
    remediation: str = ""

    def evaluate(
        self,
        findings: list[dict],
        collection: CollectionEvidence | None = None,
        authority: TrustedComplianceAuthority | None = None,
    ) -> "RuleResult":
        """Evaluate this rule without inferring coverage from missing findings."""
        matched = self._find_matching(findings)
        status: ComplianceStatus | None = None
        reason = ""
        if collection is not None:
            status, reason = self._collection_gate(collection, authority)
        elif not matched:
            status = ComplianceStatus.NOT_TESTED
            reason = "collection_evidence_missing"
        if status is None and matched:
            status = self._default_check(findings)
            reason = "matching_finding_evaluated"
        if status is None and reason == "collection_execution_authority_missing":
            status = ComplianceStatus.NOT_TESTED
        if status is None:
            if collection and collection.has_required_pass_proof(
                self.rule_id,
                authority,
            ):
                status = ComplianceStatus.PASS
                reason = "versioned_collection_recorded_pass"
            elif collection and collection.records_pass(self.rule_id):
                status = ComplianceStatus.NOT_TESTED
                reason = "required_pass_proof_missing_or_unsupported"
            elif self.check_fn:
                proposed = self.check_fn(findings)
                if proposed == ComplianceStatus.PASS:
                    status = ComplianceStatus.NOT_TESTED
                    reason = "custom_pass_missing_required_proof"
                else:
                    status = proposed
                    reason = "custom_check_result"
            else:
                status = ComplianceStatus.NOT_TESTED
                reason = "passing_evidence_missing"

        return RuleResult(
            rule=self,
            status=status,
            matched_findings=matched,
            reason=reason,
            collection=collection.to_dict(authority) if collection else {},
            proof_type=(
                normalise_proof_type(collection.proof_type).value
                if collection
                else ProofType.UNKNOWN.value
            ),
        )

    def _collection_gate(
        self,
        collection: CollectionEvidence | None,
        authority: TrustedComplianceAuthority | None,
    ) -> tuple[ComplianceStatus | None, str]:
        if collection is None:
            return ComplianceStatus.NOT_TESTED, "collection_evidence_missing"
        if not collection.is_versioned():
            return ComplianceStatus.NOT_TESTED, "collector_identity_or_version_missing"
        execution = collection._authoritative_execution(authority)
        if execution is None:
            return None, "collection_execution_authority_missing"
        if execution.applicable is False:
            return ComplianceStatus.NOT_APPLICABLE, (
                execution.applicability_reason or "control_not_applicable"
            )
        if execution.applicable is not True:
            return ComplianceStatus.NOT_TESTED, "applicability_not_established"
        if execution.status == CollectionStatus.COLLECTION_ERROR:
            return ComplianceStatus.COLLECTION_ERROR, (
                execution.error_reason or "collection_error"
            )
        if execution.status == CollectionStatus.PARTIAL:
            return ComplianceStatus.NOT_TESTED, "partial_collection_insufficient_coverage"
        if execution.status in {
            CollectionStatus.FAILED,
            CollectionStatus.CANCELED,
            CollectionStatus.UNAUTHORIZED,
            CollectionStatus.UNSUPPORTED,
        }:
            return ComplianceStatus.NOT_TESTED, f"collection_{execution.status.value}"
        if execution.status != CollectionStatus.SUCCESS:
            return ComplianceStatus.NOT_TESTED, "collection_not_successful"
        if self.rule_id not in execution.covered_rule_ids:
            return ComplianceStatus.NOT_TESTED, "rule_not_covered"
        if collection.records_pass(self.rule_id) and not collection.is_registered():
            return ComplianceStatus.NOT_TESTED, "required_pass_proof_missing_or_unsupported"
        return None, ""

    def _default_check(self, findings: list[dict]) -> ComplianceStatus:
        """Return FAIL/PARTIAL for matched findings; absence is never a pass."""
        matched = self._find_matching(findings)
        if not matched:
            return ComplianceStatus.NOT_TESTED

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        rule_rank = severity_rank.get(self.severity, 0)

        for f in matched:
            f_sev = f.get("severity", "info").lower()
            if severity_rank.get(f_sev, 0) >= rule_rank:
                return ComplianceStatus.FAIL

        return ComplianceStatus.PARTIAL

    def _find_matching(self, findings: list[dict]) -> list[dict]:
        """Find findings that match this rule's tags or title patterns."""
        matched: list[dict] = []
        for f in findings:
            f_tags = set(t.lower() for t in f.get("tags", []))
            f_refs = set(r.lower() for r in f.get("references", []))
            f_title = f.get("title", "").lower()

            # Tag match
            if self.match_tags and any(t.lower() in f_tags | f_refs for t in self.match_tags):
                matched.append(f)
                continue

            # Title pattern match
            for pattern in self.match_title_patterns:
                if re.search(pattern, f_title, re.IGNORECASE):
                    matched.append(f)
                    break

        return matched


@dataclass
class RuleResult:
    """Result of evaluating a single compliance rule."""
    rule: ComplianceRule
    status: ComplianceStatus
    matched_findings: list[dict] = field(default_factory=list)
    reason: str = ""
    collection: dict[str, Any] = field(default_factory=dict)
    proof_type: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "title": self.rule.title,
            "section": self.rule.section,
            "severity": self.rule.severity,
            "status": self.status.value,
            "reason": self.reason,
            "proof_type": self.proof_type,
            "collection": dict(self.collection),
            "finding_count": len(self.matched_findings),
            "finding_titles": [f.get("title", "") for f in self.matched_findings[:5]],
            "matched_findings": [
                {"id": f.get("id", ""), "title": f.get("title", ""), "severity": f.get("severity", "")}
                for f in self.matched_findings[:5]
            ],
            "remediation": self.rule.remediation,
        }


@dataclass
class ComplianceReport:
    """Full compliance evaluation report."""
    framework: ComplianceFramework
    results: list[RuleResult] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.PASS)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.FAIL)

    @property
    def partial_count(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.PARTIAL)

    @property
    def not_applicable_count(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.NOT_APPLICABLE)

    @property
    def not_tested_count(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.NOT_TESTED)

    @property
    def collection_error_count(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.COLLECTION_ERROR)

    @property
    def coverage_pct(self) -> float:
        applicable = [
            r for r in self.results if r.status != ComplianceStatus.NOT_APPLICABLE
        ]
        if not applicable:
            return 0.0
        tested = [
            r for r in applicable
            if r.status in {ComplianceStatus.PASS, ComplianceStatus.FAIL, ComplianceStatus.PARTIAL}
        ]
        return round((len(tested) / len(applicable)) * 100, 1)

    @property
    def compliance_pct(self) -> float:
        tested = [
            r for r in self.results
            if r.status in {ComplianceStatus.PASS, ComplianceStatus.FAIL}
        ]
        if not tested or self.coverage_pct < 100.0:
            return 0.0
        passed = sum(1 for r in tested if r.status == ComplianceStatus.PASS)
        return round((passed / len(tested)) * 100, 1)

    def summary(self) -> str:
        return (
            f"{self.framework.value}: {self.compliance_pct}% compliant "
            f"({self.pass_count} pass, {self.fail_count} fail, "
            f"{self.partial_count} partial, {self.not_applicable_count} not applicable, "
            f"{self.not_tested_count} not tested, "
            f"{self.collection_error_count} collection error)"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework.value,
            "compliance_pct": self.compliance_pct,
            "coverage_pct": self.coverage_pct,
            "pass": self.pass_count,
            "fail": self.fail_count,
            "partial": self.partial_count,
            "not_applicable": self.not_applicable_count,
            "not_tested": self.not_tested_count,
            "collection_error": self.collection_error_count,
            "rules": [r.to_dict() for r in self.results],
        }


# ── Rule definitions ─────────────────────────────────────────────────────────

def _pci_dss_rules() -> list[ComplianceRule]:
    """PCI-DSS 4.0 security requirements relevant to web penetration testing."""
    fw = ComplianceFramework.PCI_DSS
    return [
        ComplianceRule(
            rule_id="PCI-6.2.4", section="6.2.4", framework=fw,
            title="Software engineering — prevent common vulnerabilities",
            description="Software is developed to prevent or mitigate common software attacks (SQLi, XSS, CSRF, etc.)",
            severity="critical",
            match_tags=["cwe-89", "cwe-79", "cwe-352", "cwe-78", "cwe-94", "sqli", "xss", "csrf", "ssti", "cmdi"],
            match_title_patterns=[r"sql.?inject", r"xss", r"command.?inject", r"template.?inject"],
            remediation="Address all injection vulnerabilities per OWASP Secure Coding guidelines.",
        ),
        ComplianceRule(
            rule_id="PCI-6.3.1", section="6.3.1", framework=fw,
            title="Identify and manage security vulnerabilities",
            description="Security vulnerabilities are identified and managed via a vulnerability management process.",
            severity="high",
            match_tags=["cve-"],
            match_title_patterns=[r"CVE-\\d{4}", r"known.?vuln"],
            remediation="Establish a vulnerability management process; patch within 30 days for critical/high.",
        ),
        ComplianceRule(
            rule_id="PCI-6.4.1", section="6.4.1", framework=fw,
            title="Public-facing web apps protected against attacks",
            description="Web applications must be protected by WAF or equivalent.",
            severity="high",
            match_tags=["waf-bypass", "no-waf"],
            match_title_patterns=[r"no.?waf", r"waf.?bypass"],
            remediation="Deploy a WAF (ModSecurity, Cloudflare, AWS WAF) for all public web apps.",
        ),
        ComplianceRule(
            rule_id="PCI-4.2.1", section="4.2.1", framework=fw,
            title="Strong cryptography for transmission",
            description="Strong cryptography protects PAN during transmission over open, public networks.",
            severity="critical",
            match_tags=["ssl", "tls", "weak-cipher", "expired-cert"],
            match_title_patterns=[r"ssl", r"tls", r"weak.?cipher", r"expired.?cert", r"self.?signed"],
            remediation="Use TLS 1.2+ with strong cipher suites; renew certificates before expiry.",
        ),
        ComplianceRule(
            rule_id="PCI-6.5.1", section="6.5.1", framework=fw,
            title="Injection flaws prevented",
            description="SQL injection, OS command injection, and similar injection attacks must be prevented.",
            severity="critical",
            match_tags=["cwe-89", "cwe-78", "cwe-90", "cwe-94"],
            match_title_patterns=[r"inject"],
            remediation="Use parameterized queries and input validation for all data paths.",
        ),
        ComplianceRule(
            rule_id="PCI-6.5.4", section="6.5.4", framework=fw,
            title="Insecure communications prevented",
            description="Prevent insecure communications that expose sensitive data.",
            severity="high",
            match_tags=["missing-hsts", "mixed-content"],
            match_title_patterns=[r"hsts", r"http.?header", r"missing.?header"],
            remediation="Enable HSTS, set Secure flag on cookies, enforce HTTPS everywhere.",
        ),
        ComplianceRule(
            rule_id="PCI-6.5.7", section="6.5.7", framework=fw,
            title="Cross-site scripting prevented",
            description="XSS vulnerabilities must be prevented in web applications.",
            severity="high",
            match_tags=["cwe-79", "xss"],
            match_title_patterns=[r"xss", r"cross.?site.?script"],
            remediation="Apply context-aware output encoding; deploy Content Security Policy.",
        ),
        ComplianceRule(
            rule_id="PCI-8.3.6", section="8.3.6", framework=fw,
            title="Password complexity requirements",
            description="Passwords must meet minimum complexity requirements (12+ chars, alphanumeric).",
            severity="medium",
            match_tags=["weak-password", "password-policy"],
            match_title_patterns=[r"password.?policy", r"weak.?password", r"brute.?force"],
            remediation="Enforce 12+ character passwords with complexity; implement account lockout.",
        ),
        ComplianceRule(
            rule_id="PCI-11.3.1", section="11.3.1", framework=fw,
            title="Internal vulnerability scans",
            description="Internal vulnerability scans performed at least quarterly.",
            severity="medium",
            match_tags=[],
            match_title_patterns=[],
            remediation="Run quarterly internal vulnerability scans with a qualified scanner.",
        ),
        ComplianceRule(
            rule_id="PCI-11.3.2", section="11.3.2", framework=fw,
            title="External vulnerability scans by ASV",
            description="External scans performed by PCI SSC Approved Scanning Vendor quarterly.",
            severity="medium",
            match_tags=[],
            match_title_patterns=[],
            remediation="Engage a PCI ASV for quarterly external scans.",
            check_fn=lambda _: ComplianceStatus.NOT_TESTED,
        ),
    ]


def _owasp_top10_rules() -> list[ComplianceRule]:
    """OWASP Top 10 2021 mapping."""
    fw = ComplianceFramework.OWASP_TOP10
    return [
        ComplianceRule(
            rule_id="A01:2021", section="A01", framework=fw,
            title="Broken Access Control",
            description="Access control enforces policy such that users cannot act outside intended permissions.",
            severity="critical",
            match_tags=["cwe-200", "cwe-284", "cwe-285", "cwe-352", "cwe-639", "idor", "priv-esc",
                        "path-traversal", "forced-browse", "mass-assignment"],
            match_title_patterns=[r"idor", r"access.?control", r"priv.?esc", r"path.?traversal",
                                  r"forced.?brows", r"403.?bypass", r"mass.?assign"],
            remediation="Implement proper access controls; deny by default; enforce ownership.",
        ),
        ComplianceRule(
            rule_id="A02:2021", section="A02", framework=fw,
            title="Cryptographic Failures",
            description="Data exposure from cryptographic failures (formerly Sensitive Data Exposure).",
            severity="critical",
            match_tags=["cwe-311", "cwe-327", "cwe-328", "weak-cipher", "expired-cert",
                        "cwe-798", "cwe-312", "secret", "hardcoded"],
            match_title_patterns=[r"ssl", r"tls", r"weak.?ciph", r"secret", r"hardcoded", r"credential",
                                  r"private.?key", r"api.?key"],
            remediation="Use strong encryption; don't store secrets in code; rotate exposed credentials.",
        ),
        ComplianceRule(
            rule_id="A03:2021", section="A03", framework=fw,
            title="Injection",
            description="User-supplied data is not validated, filtered, or sanitized by the application.",
            severity="critical",
            match_tags=["cwe-79", "cwe-89", "cwe-78", "cwe-94", "cwe-917", "sqli", "xss",
                        "ssti", "cmdi", "ldap", "nosql", "xxe", "log4shell"],
            match_title_patterns=[r"inject", r"xss", r"template.?inject", r"log4shell", r"jndi"],
            remediation="Use parameterized queries; validate input; apply output encoding.",
        ),
        ComplianceRule(
            rule_id="A04:2021", section="A04", framework=fw,
            title="Insecure Design",
            description="Missing or ineffective control design — threat modeling and secure design patterns required.",
            severity="high",
            match_tags=["cwe-522", "cwe-306"],
            match_title_patterns=[r"insecure.?design", r"no.?rate.?limit", r"race.?condition",
                                  r"workflow.?bypass"],
            remediation="Apply threat modeling; use secure design patterns from OWASP ASVS.",
        ),
        ComplianceRule(
            rule_id="A05:2021", section="A05", framework=fw,
            title="Security Misconfiguration",
            description="Missing hardening, misconfigured permissions, unnecessary features enabled.",
            severity="high",
            match_tags=["cwe-16", "cwe-200", "cwe-538", "cors", "csp", "clickjacking",
                        "cookie-audit", "git-exposure", "config"],
            match_title_patterns=[r"header", r"cors", r"csp", r"clickjack", r"cookie",
                                  r"\.git", r"directory.?list", r"config.?expos"],
            remediation="Harden configurations; remove defaults; implement security headers.",
        ),
        ComplianceRule(
            rule_id="A06:2021", section="A06", framework=fw,
            title="Vulnerable and Outdated Components",
            description="Application uses components with known vulnerabilities.",
            severity="high",
            match_tags=["cve-", "dep-audit", "outdated"],
            match_title_patterns=[r"CVE-\\d{4}", r"outdated", r"vulnerable.?compon", r"dep.?audit"],
            remediation="Monitor dependencies; update/patch regularly; remove unused components.",
        ),
        ComplianceRule(
            rule_id="A07:2021", section="A07", framework=fw,
            title="Identification and Authentication Failures",
            description="Confirmation of the user's identity, authentication, and session management.",
            severity="high",
            match_tags=["cwe-287", "cwe-384", "session", "jwt", "oauth", "mfa-bypass",
                        "password-policy", "brute-force"],
            match_title_patterns=[r"session", r"jwt", r"auth", r"password", r"brute",
                                  r"mfa.?bypass", r"totp", r"login"],
            remediation="Implement MFA; enforce strong password policy; secure session management.",
        ),
        ComplianceRule(
            rule_id="A08:2021", section="A08", framework=fw,
            title="Software and Data Integrity Failures",
            description="Code/infrastructure integrity — insecure CI/CD, unsigned updates, deserialization.",
            severity="high",
            match_tags=["cwe-502", "deserialization", "sri"],
            match_title_patterns=[r"deseriali", r"sri", r"integrity"],
            remediation="Verify integrity of software/data; use SRI for CDN resources.",
        ),
        ComplianceRule(
            rule_id="A09:2021", section="A09", framework=fw,
            title="Security Logging and Monitoring Failures",
            description="Insufficient logging, detection, monitoring, and active response.",
            severity="medium",
            match_tags=["logging", "monitoring"],
            match_title_patterns=[r"log(?:ging)?", r"monitor"],
            remediation="Implement comprehensive logging; monitor for suspicious activity.",
            check_fn=lambda _: ComplianceStatus.NOT_TESTED,  # Requires manual review
        ),
        ComplianceRule(
            rule_id="A10:2021", section="A10", framework=fw,
            title="Server-Side Request Forgery (SSRF)",
            description="Web application fetches a remote resource without validating the user-supplied URL.",
            severity="critical",
            match_tags=["cwe-918", "ssrf"],
            match_title_patterns=[r"ssrf", r"server.?side.?request"],
            remediation="Validate/sanitize all user-supplied URLs; use allowlists for remote fetches.",
        ),
    ]


def _iso27001_rules() -> list[ComplianceRule]:
    """ISO 27001:2022 Annex A controls relevant to web security testing."""
    fw = ComplianceFramework.ISO_27001
    return [
        ComplianceRule(
            rule_id="A.8.9", section="A.8.9", framework=fw,
            title="Configuration management",
            description="Configurations of hardware, software, services and networks shall be managed.",
            severity="medium",
            match_tags=["config", "misconfiguration"],
            match_title_patterns=[r"config", r"misconfig", r"header", r"default"],
            remediation="Implement configuration baselines and monitor for drift.",
        ),
        ComplianceRule(
            rule_id="A.8.24", section="A.8.24", framework=fw,
            title="Use of cryptography",
            description="Rules for the effective use of cryptography shall be defined and implemented.",
            severity="high",
            match_tags=["ssl", "tls", "weak-cipher", "crypto"],
            match_title_patterns=[r"ssl", r"tls", r"cipher", r"crypto", r"certificate"],
            remediation="Use approved cryptographic algorithms and key lengths per organizational policy.",
        ),
        ComplianceRule(
            rule_id="A.8.26", section="A.8.26", framework=fw,
            title="Application security requirements",
            description="Information security requirements shall be identified and specified when developing/acquiring apps.",
            severity="high",
            match_tags=["cwe-89", "cwe-79", "cwe-78", "injection"],
            match_title_patterns=[r"inject", r"xss", r"vulnerability"],
            remediation="Include security requirements in SDLC; perform security testing.",
        ),
        ComplianceRule(
            rule_id="A.8.28", section="A.8.28", framework=fw,
            title="Secure coding",
            description="Secure coding principles shall be applied to software development.",
            severity="high",
            match_tags=["sqli", "xss", "ssti", "lfi", "rce"],
            match_title_patterns=[r"sql", r"xss", r"template", r"file.?inclus", r"command"],
            remediation="Apply OWASP Secure Coding Practices throughout development lifecycle.",
        ),
    ]


# ── Compliance engine ────────────────────────────────────────────────────────

class ComplianceEngine:
    """Evaluate findings against a compliance framework's rules.

    Usage:
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate(findings_dicts)
    """

    RULE_REGISTRY: dict[ComplianceFramework, Callable[[], list[ComplianceRule]]] = {
        ComplianceFramework.PCI_DSS: _pci_dss_rules,
        ComplianceFramework.OWASP_TOP10: _owasp_top10_rules,
        ComplianceFramework.ISO_27001: _iso27001_rules,
    }

    def __init__(self, framework: ComplianceFramework) -> None:
        self.framework = framework
        rule_fn = self.RULE_REGISTRY.get(framework)
        if not rule_fn:
            raise ValueError(f"No rules defined for framework: {framework.value}")
        self.rules: list[ComplianceRule] = rule_fn()

    def evaluate(
        self,
        findings: list[dict],
        collection: CollectionEvidence | None = None,
        authority: TrustedComplianceAuthority | None = None,
    ) -> ComplianceReport:
        """Evaluate all rules against findings and explicit collection evidence."""
        results: list[RuleResult] = []
        for rule in self.rules:
            results.append(rule.evaluate(findings, collection, authority))
        return ComplianceReport(framework=self.framework, results=results)

    @classmethod
    def evaluate_all(
        cls,
        findings: list[dict],
        collection: CollectionEvidence | None = None,
        authority: TrustedComplianceAuthority | None = None,
    ) -> dict[str, ComplianceReport]:
        """Evaluate all registered frameworks without inferred coverage."""
        reports: dict[str, ComplianceReport] = {}
        for fw in cls.RULE_REGISTRY:
            engine = cls(fw)
            reports[fw.value] = engine.evaluate(findings, collection, authority)
        return reports


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestComplianceEngine:
    def test_pci_dss_rules_count(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        assert len(engine.rules) >= 8

    def test_owasp_rules_count(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        assert len(engine.rules) == 10

    def test_iso27001_rules_count(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.ISO_27001)
        assert len(engine.rules) >= 4

    def test_sqli_finding_fails_pci(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        findings = [{"title": "SQL Injection — param 'id'", "severity": "critical",
                      "tags": ["cwe-89", "sqli"], "references": ["CWE-89"]}]
        report = engine.evaluate(findings)
        failed = [r for r in report.results if r.status == ComplianceStatus.FAIL]
        assert len(failed) >= 1
        rule_ids = {r.rule.rule_id for r in failed}
        assert "PCI-6.2.4" in rule_ids or "PCI-6.5.1" in rule_ids

    def test_clean_scan_has_no_inferred_passes(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        report = engine.evaluate([])
        assert report.pass_count == 0
        assert report.not_tested_count == len(report.results)

    def test_compliance_pct(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate([])
        assert 0 <= report.compliance_pct <= 100

    def test_evaluate_all(self) -> None:
        reports = ComplianceEngine.evaluate_all([])
        assert len(reports) >= 3
        for fw_name, report in reports.items():
            assert isinstance(report, ComplianceReport)

    def test_report_serialization(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        report = engine.evaluate([])
        data = report.to_dict()
        assert "framework" in data
        assert "rules" in data
        assert isinstance(data["rules"], list)
