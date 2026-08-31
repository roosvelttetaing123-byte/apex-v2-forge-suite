from __future__ import annotations

import base64
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import common.verification_policy as verification_policy
import common.reporting.compliance_engine as compliance_engine
from common.confidence_policy import normalise_finding
from common.evidence import immutable_evidence_exists, persist_immutable_evidence
from common.verification_policy import (
    CapabilityMaturity,
    ProofType,
    TrustedProofObservation,
    TrustedProofRecord,
    VerificationAuthority,
    VerificationState,
    classify_capabilities,
    classify_current_capability_inventory,
    classify_registered_capabilities,
    evaluate_verification,
    _trusted_proof_attestation_payload,
)
from netforge.data.check_schema import VulnCheck


_TEST_AUTHORITY_PRIVATE_KEY = Ed25519PrivateKey.generate()


@pytest.fixture(autouse=True)
def _ephemeral_proof_trust_root(monkeypatch):
    key = ("forge-active-proof-v1", "1.0")
    policy = verification_policy._PROOF_POLICIES[key]
    public_key = base64.b64encode(
        _TEST_AUTHORITY_PRIVATE_KEY.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
    ).decode("ascii")
    monkeypatch.setitem(
        verification_policy._PROOF_POLICIES,
        key,
        replace(policy, issuer_public_key=public_key),
    )


def _attest(record: TrustedProofRecord) -> TrustedProofRecord:
    signature = _TEST_AUTHORITY_PRIVATE_KEY.sign(
        _trusted_proof_attestation_payload(record)
    )
    return replace(record, attestation=base64.b64encode(signature).decode("ascii"))


def _authority_for(record: TrustedProofRecord) -> VerificationAuthority:
    return VerificationAuthority(
        record_resolver=lambda record_id: record if record_id == record.record_id else None,
    )


def _trusted_active_proof(tmp_path, *, subject_id: str = "fixture:finding-proof"):
    evidence_store = tmp_path / "trusted-evidence-store"
    refs = [
        persist_immutable_evidence(payload, evidence_store)
        for payload in (b"request", b"response", b"semantic-match")
    ]
    record = TrustedProofRecord(
        record_id="proof-record-1",
        subject_id=subject_id,
        proof_policy_id="forge-active-proof-v1",
        proof_policy_version="1.0",
        capability_id="forge:active-proof-review",
        capability_version="1.0",
        capability_maturity=CapabilityMaturity.VERIFIED,
        proof_type=ProofType.ACTIVE,
        policy_satisfied=True,
        observations=tuple(
            TrustedProofObservation(observation_type, evidence_ref)
            for observation_type, evidence_ref in zip(
                ("request", "response", "semantic_match"),
                refs,
                strict=True,
            )
        ),
        issuer_id="forge-fixture-authority-v1",
    )
    record = _attest(record)
    key = ("forge-active-proof-v1", "1.0")
    policy = verification_policy._PROOF_POLICIES[key]
    verification_policy._PROOF_POLICIES[key] = replace(
        policy,
        evidence_resolver=lambda evidence_ref: immutable_evidence_exists(
            evidence_ref,
            evidence_store,
        ),
    )
    return record, _authority_for(record), evidence_store


@pytest.mark.parametrize("status_code", [200, 302, 401, 403, 404, 500])
def test_http_status_alone_cannot_verify_high_or_critical(status_code: int) -> None:
    decision = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.HEURISTIC,
        observations={"status_code": status_code},
        confidence="HIGH",
    )

    assert decision.state == VerificationState.CANDIDATE
    assert decision.verified is False
    assert "status_code_only" in decision.reasons


@pytest.mark.parametrize("confidence", ["HIGH", "MEDIUM"])
def test_confidence_cannot_promote_a_finding(confidence: str) -> None:
    row = normalise_finding({"title": "Legacy signal", "confidence": confidence})

    assert row["status"] == "open"
    assert row["verification_state"] == "unknown"
    assert row["proof_type"] == "unknown"
    assert row["maturity"] == "experimental"


def test_banner_presence_remains_candidate() -> None:
    decision = evaluate_verification(
        severity="high",
        proof_type=ProofType.PASSIVE,
        maturity=CapabilityMaturity.HEURISTIC,
        observations={"banner": "Example Server 1.2.3", "product": "Example Server"},
        confidence="HIGH",
    )

    assert decision.state == VerificationState.CANDIDATE
    assert decision.verified is False


def test_version_correlation_remains_candidate() -> None:
    decision = evaluate_verification(
        severity="critical",
        proof_type=ProofType.VERSION_CORRELATION,
        maturity=CapabilityMaturity.VERIFIED,
        observations={"product": "Example Server", "version": "1.2.3"},
        confidence="HIGH",
    )

    assert decision.state == VerificationState.CANDIDATE
    assert decision.verified is False
    assert "version_correlation_is_candidate" in decision.reasons


def test_process_exit_zero_is_not_proof() -> None:
    decision = evaluate_verification(
        severity="high",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={"process_exit_code": 0},
        confidence="HIGH",
    )

    assert decision.state == VerificationState.CANDIDATE
    assert decision.verified is False
    assert "process_exit_only" in decision.reasons


def test_explicit_active_proof_policy_can_verify(tmp_path) -> None:
    record, authority, _ = _trusted_active_proof(tmp_path)
    decision = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.EXPERIMENTAL,
        observations={"proof_record_id": record.record_id},
        confidence="HIGH",
        subject_id=record.subject_id,
        authority=authority,
    )

    assert decision.state == VerificationState.VERIFIED
    assert decision.verified is True
    assert decision.maturity == CapabilityMaturity.VERIFIED


def test_normalised_finding_re_resolves_trusted_record_out_of_band(tmp_path) -> None:
    from common.verification_policy import normalise_finding_truth

    record, authority, _ = _trusted_active_proof(
        tmp_path,
        subject_id="fixture:finding-round-trip",
    )
    finding = {
        "id": record.subject_id,
        "severity": "critical",
        "status": "open",
        "verification_state": "verified",
        "proof_type": "active",
        "maturity": "verified",
        "verification": {"proof_record_id": record.record_id},
    }

    without_authority = normalise_finding_truth(finding)
    with_authority = normalise_finding_truth(finding, authority=authority)

    assert without_authority["verification_state"] == "candidate"
    assert without_authority["maturity"] == "experimental"
    assert with_authority["verification_state"] == "verified"
    assert with_authority["maturity"] == "verified"


def test_claimant_selected_store_and_public_constants_cannot_verify(tmp_path) -> None:
    claimant_store = tmp_path / "claimant-evidence-store"
    refs = [
        persist_immutable_evidence(payload, claimant_store)
        for payload in (b"caller-request", b"caller-response", b"caller-semantic-claim")
    ]
    decision = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={
            "proof_policy_id": "forge-active-proof-v1",
            "proof_policy_version": "1.0",
            "proof_record_id": "caller-minted-record",
            "proof_satisfied": True,
            "capability_id": "forge:active-proof-review",
            "capability_version": "1.0",
            "evidence_store": claimant_store,
            "independent_observations": [
                {"type": "request", "evidence_ref": refs[0]},
                {"type": "response", "evidence_ref": refs[1]},
                {"type": "semantic_match", "evidence_ref": refs[2]},
            ],
        },
        subject_id="caller-finding",
    )

    assert decision.verified is False
    assert decision.state == VerificationState.CANDIDATE
    # Maturity is resolved from the reviewed inventory even though claimant
    # metadata still lacks the out-of-band signed proof authority.
    assert decision.maturity == CapabilityMaturity.VERIFIED


def test_caller_created_authority_cannot_attest_a_proof_record(tmp_path) -> None:
    record, _, evidence_store = _trusted_active_proof(tmp_path)
    forged = replace(record, attestation="")
    caller_authority = VerificationAuthority(
        record_resolver=lambda record_id: forged if record_id == forged.record_id else None,
    )

    decision = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={"proof_record_id": forged.record_id},
        subject_id=forged.subject_id,
        authority=caller_authority,
    )

    assert decision.verified is False
    assert decision.state == VerificationState.CANDIDATE
    assert decision.maturity == CapabilityMaturity.EXPERIMENTAL
    assert immutable_evidence_exists(record.observations[0].evidence_ref, evidence_store)


def test_signed_record_still_requires_policy_owned_evidence_resolver(tmp_path) -> None:
    record, authority, _ = _trusted_active_proof(tmp_path)
    key = ("forge-active-proof-v1", "1.0")
    policy = verification_policy._PROOF_POLICIES[key]
    verification_policy._PROOF_POLICIES[key] = replace(
        policy,
        evidence_resolver=None,
    )

    decision = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={"proof_record_id": record.record_id},
        subject_id=record.subject_id,
        authority=authority,
    )

    assert decision.verified is False
    assert decision.state == VerificationState.CANDIDATE


def test_tampered_authority_owned_evidence_cannot_verify(tmp_path) -> None:
    record, authority, evidence_store = _trusted_active_proof(tmp_path)
    response_ref = record.observations[1].evidence_ref
    tampered_path = evidence_store / f"{response_ref.removeprefix('sha256:')}.evidence"
    tampered_path.chmod(0o600)
    tampered_path.write_bytes(b"tampered-response")

    decision = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={"proof_record_id": record.record_id},
        subject_id=record.subject_id,
        authority=authority,
    )

    assert decision.verified is False
    assert decision.state == VerificationState.CANDIDATE


def test_self_asserted_or_duplicate_observations_cannot_verify() -> None:
    decision = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={
            "proof_policy_id": "unregistered-policy",
            "proof_policy_version": "1.0",
            "proof_satisfied": True,
            "capability_id": "unknown:probe",
            "capability_version": "1.0",
            "status_code": 200,
            "independent_observations": ["response", "response"],
        },
    )

    assert decision.verified is False
    assert decision.state == VerificationState.CANDIDATE
    assert "status_code_only" in decision.reasons


def test_exact_authority_capability_version_and_distinct_evidence_are_required(tmp_path) -> None:
    record, _, evidence_store = _trusted_active_proof(tmp_path)
    wrong_version_record = _attest(
        replace(record, capability_version="2.0", attestation="")
    )
    wrong_version = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={"proof_record_id": wrong_version_record.record_id},
        subject_id=wrong_version_record.subject_id,
        authority=_authority_for(wrong_version_record),
    )
    assert wrong_version.verified is False
    assert "proof_policy_binding_mismatch" in wrong_version.reasons

    shared_ref = record.observations[0].evidence_ref
    reused_record = _attest(
        replace(
            record,
            observations=tuple(
                TrustedProofObservation(name, shared_ref)
                for name in ("request", "response", "semantic_match")
            ),
            attestation="",
        )
    )
    reused_evidence = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={"proof_record_id": reused_record.record_id},
        subject_id=reused_record.subject_id,
        authority=_authority_for(reused_record),
    )
    assert reused_evidence.verified is False


def test_registry_version_and_maturity_override_signed_record_claims(
    tmp_path,
    monkeypatch,
) -> None:
    record, authority, _ = _trusted_active_proof(tmp_path)
    capability_id = "forge:active-proof-review"

    monkeypatch.setitem(
        verification_policy._REVIEWED_CAPABILITY_REGISTRATIONS,
        capability_id,
        ("2.0", CapabilityMaturity.VERIFIED),
    )
    drifted = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={"proof_record_id": record.record_id},
        subject_id=record.subject_id,
        authority=authority,
    )
    assert drifted.verified is False
    assert drifted.reasons == ("proof_policy_binding_mismatch",)

    monkeypatch.setitem(
        verification_policy._REVIEWED_CAPABILITY_REGISTRATIONS,
        capability_id,
        ("1.0", CapabilityMaturity.EXPERIMENTAL),
    )
    spoofed_maturity = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={"proof_record_id": record.record_id},
        subject_id=record.subject_id,
        authority=authority,
    )
    assert spoofed_maturity.verified is False
    assert spoofed_maturity.maturity == CapabilityMaturity.EXPERIMENTAL
    assert spoofed_maturity.reasons == ("capability_not_verified",)


def test_trusted_proof_record_cannot_be_replayed_to_another_subject(tmp_path) -> None:
    record, authority, _ = _trusted_active_proof(tmp_path)
    decision = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={"proof_record_id": record.record_id},
        subject_id="another-finding",
        authority=authority,
    )

    assert decision.verified is False
    assert decision.maturity == CapabilityMaturity.EXPERIMENTAL


def test_unregistered_finding_cannot_self_assert_verified_maturity() -> None:
    decision = evaluate_verification(
        severity="critical",
        proof_type=ProofType.ACTIVE,
        maturity=CapabilityMaturity.VERIFIED,
        observations={
            "capability_id": "made-up:capability",
            "proof_satisfied": True,
        },
    )

    assert decision.verified is False
    assert decision.maturity == CapabilityMaturity.EXPERIMENTAL

    row = normalise_finding(
        {
            "id": "made-up-finding",
            "module": "made-up-module",
            "proof_type": "active",
            "maturity": "verified",
            "verification_state": "verified",
        }
    )
    assert row["verification_state"] == "candidate"
    assert row["maturity"] == "experimental"


def test_workflow_status_is_independent_from_verification() -> None:
    for workflow_status in ("false_positive", "remediated", "accepted_risk"):
        row = normalise_finding(
            {
                "title": "Reviewed finding",
                "status": workflow_status,
                "verification_state": "verified",
            }
        )
        assert row["status"] == workflow_status
        assert row["verification_state"] == "unknown"


def test_simulation_never_verifies() -> None:
    decision = evaluate_verification(
        severity="critical",
        proof_type=ProofType.SIMULATION,
        maturity=CapabilityMaturity.SIMULATION,
        observations={
            "proof_policy_id": "forge-active-proof-v1",
            "proof_policy_version": "1.0",
            "proof_satisfied": True,
        },
        confidence="HIGH",
    )

    assert decision.state == VerificationState.SIMULATION
    assert decision.verified is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("success", True),
        ("exploited", True),
        ("still_vulnerable", True),
        ("fixed", True),
        ("status", "success"),
    ],
)
def test_normalised_simulation_finding_rejects_outcome_claims(
    field: str,
    value,
) -> None:
    finding = {
        "id": "simulation-finding",
        "title": "Simulation observation",
        "proof_type": "simulation",
        "maturity": "simulation",
        field: value,
    }

    with pytest.raises(ValueError, match="simulation cannot serialize outcome"):
        normalise_finding(finding)


def test_normalised_simulation_finding_rejects_nested_outcome_claims() -> None:
    with pytest.raises(ValueError, match="simulation cannot serialize outcome: fixed"):
        normalise_finding(
            {
                "id": "nested-simulation-finding",
                "proof_type": "simulation",
                "evidence": {"extra": {"result": {"fixed": True}}},
            }
        )


def test_legacy_verified_status_without_lineage_is_downgraded() -> None:
    row = normalise_finding(
        {"title": "Legacy record", "status": "verified", "confidence": "HIGH"}
    )

    assert row["status"] == "open"
    assert row["verification_state"] == "unknown"
    assert row["verification"]["legacy_status"] == "verified"


def test_unknown_maturity_fails_closed() -> None:
    decision = evaluate_verification(
        severity="high",
        proof_type="active",
        maturity="stable",
        observations={"proof_satisfied": True},
        confidence="HIGH",
    )

    assert decision.maturity == CapabilityMaturity.EXPERIMENTAL
    assert decision.state == VerificationState.CANDIDATE


def test_yaml_check_defaults_to_experimental_and_is_classifiable() -> None:
    check = VulnCheck.from_yaml_str(
        """
id: status-only-check
name: Status only check
severity: critical
detection:
  - type: http
    path: /
    match:
      status_code: 200
"""
    )

    assert check.maturity == "experimental"
    assert check.proof_type == "active"
    assert check.verification_state == "candidate"


def test_every_registered_module_resolves_to_allowed_maturity() -> None:
    from adforge.adforge import MODULE_MAP as AD_MODULES
    from aiforge.aiforge import MODULE_MAP as AI_MODULES
    from netforge.netforge import MODULE_MAP as NET_MODULES
    from webforge.webforge import MODULE_MAP as WEB_MODULES

    registered = [
        *(f"adforge:{module_id}" for module_id in AD_MODULES),
        *(f"aiforge:{module_id}" for module_id in AI_MODULES),
        *(f"netforge:{module_id}" for module_id in NET_MODULES),
        *(f"webforge:{module_id}" for module_id in WEB_MODULES),
    ]
    classified = classify_registered_capabilities(registered)

    assert set(classified) == set(registered)
    assert set(classified.values()) <= set(CapabilityMaturity)
    assert CapabilityMaturity.VERIFIED not in classified.values()


def test_unknown_registry_override_fails_classification_gate() -> None:
    with pytest.raises(ValueError, match="unknown capability id"):
        classify_registered_capabilities(
            ["netforge:known"],
            {"netforge:missing": "verified"},
        )


def test_duplicate_and_unknown_capabilities_fail_classification_gate() -> None:
    with pytest.raises(ValueError, match="duplicate capability id"):
        classify_capabilities(
            [
                {"id": "same", "maturity": "heuristic"},
                {"id": "same", "maturity": "experimental"},
            ]
        )

    with pytest.raises(ValueError, match="unknown maturity"):
        classify_capabilities([{"id": "unknown", "maturity": "stable"}])


def test_native_checks_join_the_central_registered_inventory() -> None:
    classified = classify_current_capability_inventory()

    assert len(classified) >= 420
    assert classified["forge:active-proof-review"] == CapabilityMaturity.VERIFIED
    assert set(classified.values()) <= set(CapabilityMaturity)
    assert classified["forge_c2:emulation"] == CapabilityMaturity.SIMULATION


def test_chain_adapter_requires_verified_state_not_confidence() -> None:
    from common.brain.autonomous import _EngagementBusChainAdapter

    class Bus:
        def subscribe(self, handler):
            self.handler = handler

    adapter = _EngagementBusChainAdapter(Bus())
    confirmed: list[dict] = []
    adapter.subscribe("finding.confirmed", confirmed.append)

    adapter._on_finding(
        "webforge",
        {
            "title": "SQL Injection",
            "confidence": "HIGH",
            "verification_state": "candidate",
        },
    )
    assert confirmed == []

    adapter._on_finding(
        "webforge",
        {
            "title": "SQL Injection",
            "confidence": "LOW",
            "verification_state": "verified",
        },
    )
    assert len(confirmed) == 1


def test_autonomous_placeholder_serializes_simulation_not_execution() -> None:
    import asyncio

    from common.brain.autonomous import AutonomousEngine, EngagementConfig

    engine = AutonomousEngine()
    asyncio.run(
        engine._execute_module(
            "webforge",
            "sqli_scanner",
            EngagementConfig(target="fixture.invalid"),
        )
    )

    assert engine.progress.modules_run == 0
    assert engine._chain_log[0]["result"] == "simulation"
    assert engine._chain_log[0]["verification_state"] == "simulation"
    assert "executed" not in str(engine._chain_log[0]).lower()


def test_attack_narrative_rejects_caller_verification_and_result_wording() -> None:
    from common.brain.narrator import ReportNarrator

    narrative = ReportNarrator()._template_attack_narrative(
        [
            {
                "action": "Candidate probe",
                "target": "fixture.invalid",
                "result": "successfully exploited according to process log",
                "verification_state": "candidate",
                "proof_type": "active",
                "maturity": "experimental",
            },
            {
                "action": "Reviewed proof",
                "target": "fixture.invalid",
                "result": "documented proof policy satisfied",
                "verification_state": "verified",
                "proof_type": "manual",
                "maturity": "verified",
            },
        ]
    )

    assert "Advisory projection only" in narrative
    assert "does not assert" in narrative
    assert "Recorded advisory entries: **2**" in narrative
    assert "produced verified outcomes" not in narrative
    assert "successfully exploited according to process log" not in narrative
    assert "documented proof policy satisfied" not in narrative
    assert narrative.count("Observation detail withheld") == 1
    assert "verification_state=candidate" not in narrative
    assert "verification_state=verified" not in narrative
    assert "proof_type=active" not in narrative


def test_event_and_api_adapters_reject_unresolved_finding_truth() -> None:
    from common.dashboard.event_bus import Event, EventBus, EventType
    from common.dashboard.server import DashboardArtifactError, DashboardServer
    from common.dashboard.state_store import StateStore

    bus = EventBus()
    store = StateStore(bus, target="fixture.invalid")
    store._on_finding(
        Event(
            event_type=EventType.FINDING_NEW,
            source="fixture",
            data={
                "id": "finding-truth",
                "title": "Candidate signal",
                "severity": "High",
                "module": "fixture",
                "target": "fixture.invalid",
                "status": "open",
                "verification_state": "candidate",
                "proof_type": "version_correlation",
                "maturity": "heuristic",
            },
        )
    )
    assert store.findings == []
    assert store.timeline == []

    fabricated = Event(
        event_type=EventType.FINDING_NEW,
        source="fixture",
        data={
            "id": "fabricated-verified",
            "title": "Fabricated verified claim",
            "severity": "High",
            "module": "fixture",
            "target": "fixture.invalid",
            "status": "verified",
            "verification_state": "verified",
            "proof_type": "active",
            "maturity": "verified",
        },
    )
    with pytest.raises(DashboardArtifactError, match="canonical snapshot refresh"):
        DashboardServer(auth=False)._public_event(fabricated)


def test_legacy_persisted_finding_migrates_to_unknown_unverified(tmp_path) -> None:
    from common.db import FindingModel, create_db, finding_to_dict
    from sqlalchemy import text

    db_path = tmp_path / "legacy-truth.db"
    session = create_db(db_path)
    session.add(
        FindingModel(
            id="legacy-finding",
            title="Legacy verified claim",
            severity="High",
            target="fixture.invalid",
            module="legacy",
            description="No proof lineage",
            confidence="HIGH",
            status="verified",
            verification="{}",
            verification_state="",
            proof_type="",
            maturity="",
        )
    )
    session.commit()
    session.execute(text("DELETE FROM schema_migrations WHERE version='wp006_legacy_verification_truth_v2'"))
    session.commit()
    session.close()

    migrated = create_db(db_path)
    model = migrated.get(FindingModel, "legacy-finding")
    assert model is not None
    row = finding_to_dict(model)
    assert row["status"] == "open"
    assert row["verification_state"] == "unknown"
    assert row["proof_type"] == "unknown"
    assert row["maturity"] == "experimental"
    assert row["verification"]["legacy_status"] == "verified"
    migrated.close()


def test_legacy_asserted_proof_without_lineage_is_persistently_downgraded(tmp_path) -> None:
    from common.db import FindingModel, create_db
    from sqlalchemy import text

    db_path = tmp_path / "legacy-asserted-proof.db"
    session = create_db(db_path)
    session.add(
        FindingModel(
            id="legacy-asserted",
            title="Legacy asserted proof",
            severity="High",
            target="fixture.invalid",
            module="legacy",
            description="No registered proof policy or evidence references",
            confidence="HIGH",
            status="open",
            verification='{"state":"verified","verified":true}',
            verification_state="verified",
            proof_type="active",
            maturity="verified",
        )
    )
    session.commit()
    session.execute(text("DELETE FROM schema_migrations WHERE version='wp006_legacy_verification_truth_v2'"))
    session.commit()
    session.close()

    migrated = create_db(db_path)
    model = migrated.get(FindingModel, "legacy-asserted")
    assert model is not None
    assert model.status == "open"
    assert model.verification_state == "unknown"
    assert model.proof_type == "unknown"
    assert model.maturity == "experimental"
    migrated.close()


def test_legacy_v2_downgrades_public_metadata_and_is_idempotent(tmp_path) -> None:
    import json

    from common.db import FindingModel, create_db
    from sqlalchemy import text

    db_path = tmp_path / "lineage-aware-migration.db"
    session = create_db(db_path)
    session.add_all([
        FindingModel(
            id="json-only-legacy",
            title="JSON-only legacy claim",
            severity="High",
            target="fixture.invalid",
            module="legacy",
            description="Legacy JSON claim",
            status="open",
            verification='{"state":"VERIFIED","verified":true}',
            verification_state="unknown",
            proof_type="active",
            maturity="experimental",
        ),
        FindingModel(
            id="public-metadata-only",
            title="Public metadata is not revalidation",
            severity="High",
            target="fixture.invalid",
            module="current",
            description="Public policy constants without trusted authority",
            status=" VeRiFiEd ",
            verification=(
                '{"state":"verified","verified":true,'
                '"policy_id":"forge-verification-policy",'
                '"policy_version":"1.0",'
                '"proof_policy_id":"forge-active-proof-v1",'
                '"proof_policy_version":"1.0",'
                '"capability_id":"forge:active-proof-review",'
                '"capability_version":"1.0",'
                '"legacy_status":"prior-review"}'
            ),
            verification_state="VERIFIED",
            proof_type="active",
            maturity="verified",
        ),
        FindingModel(
            id="json-shape-legacy",
            title="Additional JSON legacy shapes",
            severity="Medium",
            target="fixture.invalid",
            module="legacy",
            description="JSON verification state and workflow status",
            status="open",
            verification=(
                '{"verification_state":"VeRiFiEd",'
                '"status":"VERIFIED","maturity":"verified",'
                '"lineage":{"record":"preserve"}}'
            ),
            verification_state="unknown",
            proof_type="manual",
            maturity="experimental",
        ),
    ])
    session.commit()
    session.execute(
        text(
            "DELETE FROM schema_migrations "
            "WHERE version='wp006_legacy_verification_truth_v2'"
        )
    )
    session.commit()
    session.close()

    first_open = create_db(db_path)
    rows = {
        row.id: row
        for row in first_open.query(FindingModel)
        .filter(
            FindingModel.id.in_(
                (
                    "json-only-legacy",
                    "public-metadata-only",
                    "json-shape-legacy",
                )
            )
        )
        .all()
    }
    assert set(rows) == {
        "json-only-legacy",
        "public-metadata-only",
        "json-shape-legacy",
    }
    for row in rows.values():
        assert row.status == "open"
        assert row.verification_state == "unknown"
        assert row.proof_type == "unknown"
        assert row.maturity == "experimental"
    public_metadata = json.loads(rows["public-metadata-only"].verification)
    assert public_metadata["policy_id"] == "forge-verification-policy"
    assert public_metadata["proof_policy_id"] == "forge-active-proof-v1"
    assert public_metadata["capability_id"] == "forge:active-proof-review"
    assert public_metadata["legacy_status"] == "prior-review"
    json_shape = json.loads(rows["json-shape-legacy"].verification)
    assert json_shape["lineage"] == {"record": "preserve"}
    assert json_shape["legacy_status"] == "verified"
    first_state = first_open.execute(
        text(
            "SELECT id, status, verification_state, proof_type, maturity, "
            "verification FROM findings "
            "WHERE id IN ('json-only-legacy', 'public-metadata-only', "
            "'json-shape-legacy') ORDER BY id"
        )
    ).all()
    first_bytes = [
        tuple(str(value).encode("utf-8") for value in row)
        for row in first_state
    ]
    marker_count = first_open.execute(
        text(
            "SELECT COUNT(*) FROM schema_migrations "
            "WHERE version='wp006_legacy_verification_truth_v2'"
        )
    ).scalar_one()
    assert marker_count == 1
    first_open.close()

    second_open = create_db(db_path)
    second_state = second_open.execute(
        text(
            "SELECT id, status, verification_state, proof_type, maturity, "
            "verification FROM findings "
            "WHERE id IN ('json-only-legacy', 'public-metadata-only', "
            "'json-shape-legacy') ORDER BY id"
        )
    ).all()
    second_bytes = [
        tuple(str(value).encode("utf-8") for value in row)
        for row in second_state
    ]
    marker_count_after_second_open = second_open.execute(
        text(
            "SELECT COUNT(*) FROM schema_migrations "
            "WHERE version='wp006_legacy_verification_truth_v2'"
        )
    ).scalar_one()
    assert second_bytes == first_bytes
    assert marker_count_after_second_open == 1
    second_open.close()


def test_report_round_trip_preserves_compliance_truth(tmp_path, monkeypatch) -> None:
    import json
    from pathlib import Path

    from common.reporter import BaseReporter
    from common.reporting.compliance_engine import (
        CollectionEvidence,
        CollectionStatus,
        ComplianceExecutionRecord,
        TrustedComplianceAuthority,
        _compliance_execution_attestation_payload,
    )
    from common.reporting.report_engine import _build_compliance_html

    evidence_store = tmp_path / "compliance-evidence"
    evidence_ref = persist_immutable_evidence(b"compliance-proof", evidence_store)
    collection = CollectionEvidence(
        collector_id="fixture-collector",
        collector_version="1.0",
        status=CollectionStatus.SUCCESS,
        check_id="forge:fixture-compliance-check",
        check_version="1.0",
        execution_id="fixture-report-execution-1",
        scope_binding="sha256:" + "c" * 64,
        target_binding="sha256:" + "d" * 64,
        evidence_store=evidence_store,
        applicable=True,
        covered_rule_ids=["PCI-11.3.1"],
        passing_rule_ids=["PCI-11.3.1"],
        proof_type="credentialed_config",
        proof_evidence={
            "rule_id": "PCI-11.3.1",
            "collector_id": "fixture-collector",
            "collector_version": "1.0",
            "execution_id": "fixture-report-execution-1",
            "scope_binding": "sha256:" + "c" * 64,
            "target_binding": "sha256:" + "d" * 64,
            "evidence_ref": evidence_ref,
        },
    )
    policy_key = (collection.check_id, collection.check_version)
    policy = compliance_engine._COMPLIANCE_PROOF_POLICIES[policy_key]
    public_key = base64.b64encode(
        _TEST_AUTHORITY_PRIVATE_KEY.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
    ).decode("ascii")
    monkeypatch.setitem(
        compliance_engine._COMPLIANCE_PROOF_POLICIES,
        policy_key,
        replace(
            policy,
            issuer_public_key=public_key,
            evidence_resolver=lambda ref: immutable_evidence_exists(
                ref,
                evidence_store,
            ),
        ),
    )
    execution = ComplianceExecutionRecord(
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
        passing_rule_evidence=(("PCI-11.3.1", evidence_ref),),
        proof_type=ProofType.CREDENTIALED_CONFIG,
        authority_id="fixture-report-authority",
        issuer_id=policy.issuer_id,
    )
    execution = replace(
        execution,
        attestation=base64.b64encode(
            _TEST_AUTHORITY_PRIVATE_KEY.sign(
                _compliance_execution_attestation_payload(execution)
            )
        ).decode("ascii"),
    )
    authority = TrustedComplianceAuthority(
        authority_id="fixture-report-authority",
        executions=(execution,),
    )
    paths = BaseReporter(
        [],
        tmp_path,
        formats=["json"],
        compliance_collection=collection,
        compliance_authority=authority,
    ).generate_all()
    payload = json.loads(Path(paths["compliance"]).read_text())
    pci = payload["pci-dss-4.0"]
    passed = next(rule for rule in pci["rules"] if rule["rule_id"] == "PCI-11.3.1")
    untested = next(rule for rule in pci["rules"] if rule["rule_id"] == "PCI-6.2.4")

    assert passed["status"] == "pass"
    assert passed["proof_type"] == "credentialed_config"
    assert passed["collection"]["collector_version"] == "1.0"
    assert passed["collection"]["execution_authority_id"] == "fixture-report-authority"
    assert passed["collection"]["execution_authority_bound"] is True
    assert untested["status"] == "not_tested"
    assert untested["reason"] == "rule_not_covered"

    html = _build_compliance_html([pci])
    assert "not an attestation" in html
    assert "rule_not_covered" in html
    assert "credentialed_config" in html


def test_csv_and_html_exports_preserve_finding_truth(tmp_path) -> None:
    from pathlib import Path

    from common.reporter import BaseReporter
    from common.reporting.report_engine import ReportConfig, ReportEngine, _HTML_TEMPLATE

    finding = {
        "id": "truth-export",
        "title": "Candidate signal",
        "severity": "High",
        "target": "fixture.invalid",
        "confidence": "UNVERIFIED",
        "verification_state": "candidate",
        "proof_type": "version_correlation",
        "maturity": "heuristic",
    }
    reporter = BaseReporter([finding], tmp_path, formats=[])
    csv_text = Path(reporter.generate_csv()).read_text(encoding="utf-8")
    assert "verification_state" in csv_text
    assert "candidate" in csv_text
    assert "version_correlation" in csv_text
    assert "experimental" in csv_text

    engine = ReportEngine(
        [finding],
        ReportConfig(output_dir=tmp_path, include_unverified=True),
    )
    enriched = engine._enrich_findings()
    assert enriched[0]["verification_state"] == "candidate"
    assert enriched[0]["proof_type"] == "version_correlation"
    assert enriched[0]["maturity"] == "experimental"
    assert "f.verification_state" in _HTML_TEMPLATE
    assert "f.proof_type" in _HTML_TEMPLATE
    assert "f.maturity" in _HTML_TEMPLATE

    fallback_jinja = reporter._build_html_jinja2()
    fallback_inline = reporter._build_html_inline()
    for rendered in (fallback_jinja, fallback_inline):
        assert "candidate" in rendered
        assert "version_correlation" in rendered
        assert "experimental" in rendered
        assert "UNVERIFIED" in rendered
