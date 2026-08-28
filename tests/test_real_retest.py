"""Deterministic Task 104 retest contract and verifier fixtures.

These tests deliberately inject the HTTP fetch boundary.  No socket, target,
credential, subprocess, or external service is used.  The service-side tests
exercise only fail-closed admission paths that do not require a live fixture.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from common.action_authorization import (
    AuthorizationContext,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    compute_envelope_digest,
    consume_authorization,
    issue_authorization,
    module_set_binding,
)
from common.canonical import RetestAttempt, RetestProof, RetestRequest, RetestStatus
from common.canonical_evidence import CanonicalEvidenceContext, CanonicalEvidenceReader, CanonicalEvidenceService
from common.confirm_gate import ActionConfirmation
from common.credential_boundary import CredentialUseApproval, InMemorySecretProvider
from common.db import create_db
from common.evidence import Evidence
from common.evidence_custody import ArtifactIntegrityError, EvidenceCustodyStore
from common.finding import Finding, Severity
from common.job_state import JobState, JobStateService
from common.schema_migrations import JOB_STATE_SCHEMA_VERSION, MigrationError, MigrationManager
from common.retest import (
    DEFAULT_RETEST_REGISTRY,
    HEADER_CSP_CHECK_ID,
    HEADER_CSP_PROOF_POLICY,
    HEADER_CSP_VERIFIER_ID,
    HEADER_CSP_VERIFIER_VERSION,
    HeaderAuditCspVerifier,
    HeaderResponse,
    RetestService,
    RetestExecutionResult,
    RetestPersistenceError,
    RetestVerifierRegistry,
    VerifierInput,
    VerifierOutput,
    VerifierRegistration,
    classify_csp,
)
from common.version import VERSION


def _digest(seed: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _request(**overrides: Any) -> RetestRequest:
    values: dict[str, Any] = {
        "id": "retest-request-fixture",
        "tenant_id": "tenant-a",
        "engagement_id": "engagement-current",
        "original_engagement_id": "engagement-original",
        "finding_id": "finding-header",
        "source_observation_id": "observation-original",
        "source_artifact_id": "artifact-original",
        "source_proof_artifact_id": "artifact-original-proof",
        "source_snapshot_id": "retest-source-snapshot-fixture",
        "original_job_id": "job-original",
        "original_attempt_id": "attempt-original",
        "original_action_id": "action-original",
        "original_authorization_decision_id": "decision-original",
        "original_module_version_id": "module-version-original",
        "asset_id": "asset-header",
        "current_operator_id": "operator-a",
        "current_role_id": "role-operator",
        "current_scope_decision_id": "decision-current",
        "module_id": "header_audit",
        "check_id": HEADER_CSP_CHECK_ID,
        "module_version": "1.0.0",
        "content_snapshot_digest": _digest("header-audit-source"),
        "policy_snapshot": HEADER_CSP_PROOF_POLICY,
        "target_url": "https://fixture.test/account",
        "route": "/account",
        "method": "GET",
        "parameter": None,
        "location": None,
        "identity_ref": None,
        "session_reference": None,
        "session_policy_digest": _digest("original-session-policy"),
        "mutation_class": "passive_header_get",
        "proof_expectation": "csp_missing",
        "proof_policy_version": HEADER_CSP_PROOF_POLICY,
        "evidence_baseline_digest": _digest("original-evidence"),
        "verifier_id": HEADER_CSP_VERIFIER_ID,
        "verifier_version": HEADER_CSP_VERIFIER_VERSION,
        "verifier_policy_id": "retest-verifier-policy-fixture",
        "idempotency_key": "request-fixture-1",
    }
    values.update(overrides)
    return RetestRequest(**values)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _input(request: RetestRequest) -> VerifierInput:
    return VerifierInput(request=request, outbound_policy=object())


def _authorization(
    session: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    run_id: str,
    job_id: str,
    operator_id: str,
    module_id: str,
    target: str,
    credential_reference: str = "",
    allowed_scope: tuple[str, ...] = ("fixture.test",),
    now: datetime | None = None,
    consume_boundary: str | None = "retest.verifier",
) -> Any:
    issued_at = now or datetime.now(timezone.utc)
    context = AuthorizationContext(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        run_id=run_id,
        job_id=job_id,
        operator_id=operator_id,
        operator_role=OperatorRole.OPERATOR,
        action_kind="engine.execute",
        engine="webforge",
        module_id=module_id,
        requested_target=target,
        resolved_target=target,
        allowed_scope=allowed_scope,
        excluded_scope=(),
        safety_mode=SafetyMode.ACTIVE,
        credential_approval_required=bool(credential_reference),
        credential_reference=credential_reference,
        confirmation_method=ConfirmationMethod.DASHBOARD,
        confirmed_by=operator_id,
    )
    confirmation = ActionConfirmation.create(
        job_id=job_id,
        target=target,
        engine="webforge",
        action="engine.execute",
        issued_at=issued_at,
    )
    issued = issue_authorization(
        session=session,
        context=context,
        confirmation=confirmation,
        now=issued_at,
    )
    assert issued.allowed
    if consume_boundary is None:
        return issued.envelope
    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=context,
        boundary=consume_boundary,
        now=issued_at,
    )
    assert consumed.allowed
    return consumed.envelope


def _active_fixture(
    tmp_path: Path,
    *,
    proof_expectation: str = "csp_missing",
    module_id: str = "header_audit",
    session_values: dict[str, Any] | None = None,
) -> dict[str, Any]:
    database = tmp_path / "canonical.db"
    custody = tmp_path / "evidence-custody"
    session = create_db(database)
    jobs = JobStateService(database, authorization_checker=lambda *_args: True)
    target = "https://fixture.test/account"
    original_reference = ""
    resolver = None
    provider = None
    if session_values is not None:
        provider = InMemorySecretProvider()
        original_reference = provider.put(session_values).value

        class Resolver:
            @contextmanager
            def resolve(
                self,
                reference_value: Any,
                *,
                approval: CredentialUseApproval,
                target: str,
            ):
                assert provider is not None
                with provider.resolve(
                    reference_value,
                    approval=approval,
                    target=target,
                ) as values:
                    yield {"headers": values}

        resolver = Resolver()
    original = _authorization(
        session,
        tenant_id="tenant-a",
        engagement_id="engagement-original",
        run_id="run-original",
        job_id="job-original",
        operator_id="operator-original",
        module_id=module_id,
        target=target,
        credential_reference=original_reference,
        consume_boundary="webforge.module",
    )
    jobs.create_job(
        tenant_id="tenant-a",
        job_id=original.job_id,
        engagement_id=original.engagement_id,
        run_id=original.run_id,
        job_kind="webforge",
        target=target,
        authorization_decision_id=original.decision_id,
        authorization_action_id=original.action_id,
        state=JobState.QUEUED,
        work_items=(module_id,),
    )
    original_attempt = jobs.acquire_lease(
        original.job_id,
        "original-worker",
        tenant_id="tenant-a",
        attempt_id="attempt-original",
        idempotency_key="original-attempt",
    )
    jobs.start_attempt(
        str(original_attempt["id"]),
        str(original_attempt["lease_token"]),
        tenant_id="tenant-a",
        worker_id="original-worker",
    )
    issue = "Missing" if proof_expectation == "csp_missing" else "Weak value: 'unsafe-inline'"
    finding = Finding(
        title="Security Header Missing: Content-Security-Policy",
        severity=Severity.MEDIUM,
        target=target,
        url=target,
        module=module_id,
        description="Persisted CSP proof fixture.",
        reproduction_steps=["GET /account"],
        remediation="Configure a restrictive CSP.",
        references=["CWE-1021"],
        confidence="HIGH",
        proof_type="passive",
        verification_state="verified",
        maturity="stable",
        evidence=Evidence(
            request_raw="GET /account HTTP/1.1\r\nHost: fixture.test\r\n",
            response_raw="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
            extra={
                "header": HEADER_CSP_CHECK_ID,
                "value": None if proof_expectation == "csp_missing" else "default-src 'self' 'unsafe-inline'",
                "issue": issue,
                "route": "/account",
                "check_id": module_id,
            },
        ),
    )
    evidence = CanonicalEvidenceService(
        session,
        custody,
        CanonicalEvidenceContext.from_authorization(
            original,
            attempt_id="attempt-original",
        ),
    )
    if session.in_transaction():
        session.rollback()
    projection = evidence.persist_finding(finding)
    current = _authorization(
        session,
        tenant_id="tenant-a",
        engagement_id="engagement-current",
        run_id="run-current",
        job_id="job-current",
        operator_id="operator-current",
        module_id=module_set_binding([module_id]),
        target=target,
        credential_reference=original_reference,
    )
    return {
        "session": session,
        "jobs": jobs,
        "database": database,
        "custody": custody,
        "finding_id": projection["id"],
        "authorization": current,
        "original_authorization": original,
        "resolver": resolver,
        "provider": provider,
        "target": target,
    }


def test_reference_verifier_vulnerable_and_corrected_fixtures_produce_proof_backed_verdicts() -> None:
    calls: list[str] = []

    async def fetch_missing(target: str, *_args: Any) -> HeaderResponse:
        calls.append(target)
        return HeaderResponse(200, {"content-type": "text/html"}, target)

    vulnerable = _run(
        HeaderAuditCspVerifier(fetcher=fetch_missing).verify(
            _input(_request(proof_expectation="csp_missing"))
        )
    )
    assert vulnerable.verdict is RetestStatus.STILL_VULNERABLE
    assert vulnerable.sufficient is True
    assert vulnerable.observed_condition == "csp_missing"
    assert vulnerable.header_value_digest is None

    async def fetch_weak(target: str, *_args: Any) -> HeaderResponse:
        calls.append(target)
        return HeaderResponse(
            200,
            {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"},
            target,
        )

    weak = _run(
        HeaderAuditCspVerifier(fetcher=fetch_weak).verify(
            _input(_request(proof_expectation="csp_weak"))
        )
    )
    assert weak.verdict is RetestStatus.STILL_VULNERABLE
    assert weak.sufficient is True
    assert weak.observed_condition == "csp_weak"
    changed_without_correction = _run(
        HeaderAuditCspVerifier(fetcher=fetch_weak).verify(
            _input(_request(proof_expectation="csp_missing"))
        )
    )
    assert changed_without_correction.verdict is RetestStatus.INCONCLUSIVE
    assert changed_without_correction.sufficient is False

    async def fetch_corrected(target: str, *_args: Any) -> HeaderResponse:
        calls.append(target)
        return HeaderResponse(
            200,
            {"Content-Security-Policy": "default-src 'self'; object-src 'none'"},
            target,
        )

    corrected = _run(
        HeaderAuditCspVerifier(fetcher=fetch_corrected).verify(
            _input(_request(proof_expectation="csp_weak"))
        )
    )
    assert corrected.verdict is RetestStatus.FIXED
    assert corrected.sufficient is True
    assert corrected.observed_condition == "csp_strong"
    assert corrected.header_value_digest is not None
    assert calls == ["https://fixture.test/account"] * 4
    assert corrected.proof_payload(_request(proof_expectation="csp_weak"))["verdict"] == "fixed"


@pytest.mark.parametrize(
    ("proof_expectation", "response_headers", "expected_verdict"),
    [
        ("csp_missing", {}, RetestStatus.STILL_VULNERABLE),
        (
            "csp_weak",
            {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"},
            RetestStatus.STILL_VULNERABLE,
        ),
        (
            "csp_missing",
            {"Content-Security-Policy": "default-src 'self'; object-src 'none'"},
            RetestStatus.FIXED,
        ),
    ],
)
def test_active_service_persists_task102_task103_and_retest_proof_lineage(
    tmp_path: Path,
    proof_expectation: str,
    response_headers: dict[str, str],
    expected_verdict: RetestStatus,
) -> None:
    fixture = _active_fixture(tmp_path, proof_expectation=proof_expectation)
    fetch_calls = 0

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, response_headers, target)

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else fixture["authorization"]
            if decision_id == fixture["authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="active-fixture",
            )
        )
        assert result.verdict is expected_verdict
        assert result.state == "terminal"
        assert fetch_calls == 1
        assert result.observation_id and result.artifact_id
        row = fixture["session"].execute(
            text(
                "SELECT r.source_observation_id,r.source_artifact_id,"
                "r.source_proof_artifact_id,r.source_snapshot_id,"
                "r.verifier_policy_id,r.original_attempt_id,"
                "r.original_engagement_id,r.original_job_id,r.original_action_id,"
                "r.original_authorization_decision_id,r.original_module_version_id,"
                "r.asset_id,r.current_operator_id,r.current_role_id,"
                "r.current_scope_decision_id,r.authorization_decision_id,"
                "r.authorization_action_id,r.module_id,r.check_id,r.module_version,"
                "r.content_snapshot_digest,r.policy_snapshot,r.target_url,r.route,r.method,r.parameter,"
                "r.location,r.identity_ref,r.mutation_class,r.proof_expectation,"
                "r.proof_policy_version,r.evidence_baseline_digest,"
                "r.session_policy_digest,r.verifier_id,"
                "r.verifier_version,"
                "ra.durable_attempt_id,ra.verdict,p.original_observation_id,"
                "p.observation_id,p.artifact_id,p.proof_digest,o.attempt_id,"
                "m.sha256,m.manifest_digest FROM canonical_retests r "
                "JOIN canonical_retest_source_snapshots ss "
                "ON ss.tenant_id=r.tenant_id AND ss.id=r.source_snapshot_id "
                "JOIN canonical_retest_verifier_policies vp "
                "ON vp.tenant_id=r.tenant_id AND vp.id=r.verifier_policy_id "
                "JOIN canonical_retest_attempts ra ON ra.tenant_id=r.tenant_id "
                "AND ra.retest_id=r.id "
                "JOIN canonical_retest_proofs p ON p.tenant_id=ra.tenant_id "
                "AND p.id=ra.proof_id "
                "JOIN canonical_observations o ON o.tenant_id=p.tenant_id "
                "AND o.id=p.observation_id "
                "JOIN canonical_artifact_manifests m ON m.tenant_id=p.tenant_id "
                "AND m.artifact_id=p.artifact_id"
            )
        ).mappings().one()
        assert row["source_observation_id"] == row["original_observation_id"]
        source_kinds = {
            str(item["id"]): json.loads(str(item["metadata_json"]))[
                "capture_kind"
            ]
            for item in fixture["session"].execute(
                text(
                    "SELECT a.id,m.metadata_json FROM canonical_artifact_refs a "
                    "JOIN canonical_artifact_manifests m "
                    "ON m.tenant_id=a.tenant_id AND m.artifact_id=a.id "
                    "WHERE a.tenant_id='tenant-a' AND a.observation_id="
                    ":observation_id"
                ),
                {"observation_id": row["source_observation_id"]},
            ).mappings()
        }
        assert source_kinds[str(row["source_artifact_id"])] == "request"
        assert source_kinds[str(row["source_proof_artifact_id"])] == "structured_proof"
        assert row["source_artifact_id"] != row["source_proof_artifact_id"]
        assert str(row["source_snapshot_id"]).startswith("retest-source-snapshot:")
        assert str(row["verifier_policy_id"]).startswith("retest-verifier-policy:")
        assert row["original_attempt_id"] == "attempt-original"
        assert row["original_engagement_id"] == "engagement-original"
        assert row["original_job_id"] == "job-original"
        assert row["original_action_id"]
        assert row["original_authorization_decision_id"]
        assert row["original_module_version_id"]
        assert row["asset_id"]
        assert row["current_operator_id"] == "operator-current"
        assert row["current_role_id"]
        assert row["current_scope_decision_id"] == row["authorization_decision_id"]
        assert row["authorization_action_id"]
        assert row["module_id"] == "header_audit"
        assert row["check_id"] == "header_audit"
        assert row["module_version"] == VERSION
        assert str(row["content_snapshot_digest"]).startswith("sha256:")
        assert row["policy_snapshot"] == HEADER_CSP_PROOF_POLICY
        assert row["target_url"] == "https://fixture.test/account"
        assert row["route"] == "/account"
        assert row["method"] == "GET"
        assert row["parameter"] is None
        assert row["location"] is None
        assert row["identity_ref"] is None
        assert row["mutation_class"] == "passive_header_get"
        assert row["proof_expectation"] == proof_expectation
        assert row["proof_policy_version"] == HEADER_CSP_PROOF_POLICY
        assert str(row["evidence_baseline_digest"]).startswith("sha256:")
        assert str(row["session_policy_digest"]).startswith("sha256:")
        assert row["verifier_id"] == HEADER_CSP_VERIFIER_ID
        assert row["verifier_version"] == HEADER_CSP_VERIFIER_VERSION
        assert row["durable_attempt_id"] == row["attempt_id"]
        assert row["verdict"] == expected_verdict.value
        assert row["observation_id"] == result.observation_id
        assert row["artifact_id"] == result.artifact_id
        assert str(row["manifest_digest"]).startswith("sha256:")
        assert row["proof_digest"] == row["sha256"]
        fixture["session"].rollback()
        projection = CanonicalEvidenceReader(
            fixture["session"],
            fixture["custody"],
            "tenant-a",
            audit_actor_id="operator-current",
        ).get_finding_projection(fixture["finding_id"])
        assert projection is not None
        assert projection["retest_verdict"] == expected_verdict.value
        assert projection["retest_status"] == expected_verdict.value
        assert projection["status"] == "open"
        retest_artifacts = [
            artifact
            for observation in projection["evidence"]["observations"]
            for artifact in observation["artifacts"]
            if artifact["capture_kind"] == "retest_proof"
        ]
        assert len(retest_artifacts) == 1
        assert expected_verdict.value in retest_artifacts[0]["derivative"]
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_active_unknown_family_is_unsupported_without_fetch(
    tmp_path: Path,
) -> None:
    module_id = "sqli_scanner"
    fixture = _active_fixture(
        tmp_path,
        module_id=module_id,
    )
    fetch_calls = 0

    async def fetch(*_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, {}, fixture["target"])

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="unsupported-fixture",
            )
        )
        assert result.verdict is RetestStatus.UNSUPPORTED
        assert fetch_calls == 0
        assert fixture["session"].execute(
            text("SELECT verdict FROM canonical_retest_attempts")
        ).scalar_one() == "unsupported"
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_duplicate_delivery_and_refresh_are_idempotent_without_duplicate_proof(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)
    fetch_calls = 0

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, {}, target)

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        values = dict(
            finding_id=fixture["finding_id"],
            tenant_id="tenant-a",
            authorization=fixture["authorization"],
            allowed_scope=("fixture.test",),
            idempotency_key="duplicate-fixture",
        )
        first = _run(service.execute(**values))
        counts_before = {
            table: fixture["session"].execute(
                text(f"SELECT COUNT(*) FROM {table}")
            ).scalar_one()
            for table in (
                "canonical_retests",
                "canonical_retest_attempts",
                "canonical_retest_proofs",
                "canonical_retest_proof_artifacts",
                "canonical_retest_attempt_events",
                "canonical_observations",
                "canonical_artifact_manifests",
            )
        }
        fixture["session"].rollback()
        second = _run(service.execute(**values))
        counts_after = {
            table: fixture["session"].execute(
                text(f"SELECT COUNT(*) FROM {table}")
            ).scalar_one()
            for table in counts_before
        }
        assert first.verdict is RetestStatus.STILL_VULNERABLE
        assert second.verdict is RetestStatus.STILL_VULNERABLE
        assert second.duplicate is True
        assert fetch_calls == 1
        assert counts_after == counts_before
        assert counts_after["canonical_retests"] == 1
        assert counts_after["canonical_retest_attempts"] == 1
        assert counts_after["canonical_retest_proofs"] == 1
        assert counts_after["canonical_retest_proof_artifacts"] == 1
        assert counts_after["canonical_retest_attempt_events"] == 3
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_concurrent_same_key_has_one_execution_and_two_canonical_results(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)
    second_session = create_db(fixture["database"])
    second_jobs = JobStateService(
        fixture["database"],
        authorization_checker=lambda *_args: True,
    )
    fetch_started = asyncio.Event()
    fetch_calls = 0

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        fetch_started.set()
        await asyncio.sleep(0.2)
        return HeaderResponse(200, {}, target)

    def build(session: Any, jobs: JobStateService) -> RetestService:
        return RetestService(
            session,
            fixture["custody"],
            jobs,
            authorization_loader=lambda decision_id: (
                fixture["original_authorization"]
                if decision_id == fixture["original_authorization"].decision_id
                else None
            ),
            outbound_policy_factory=lambda *_args: object(),
            header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
        )

    async def scenario() -> tuple[Any, Any]:
        values = {
            "finding_id": fixture["finding_id"],
            "tenant_id": "tenant-a",
            "authorization": fixture["authorization"],
            "allowed_scope": ("fixture.test",),
            "idempotency_key": "concurrent-same-key",
        }
        first_task = asyncio.create_task(
            build(fixture["session"], fixture["jobs"]).execute(**values)
        )
        await fetch_started.wait()
        second_task = asyncio.create_task(
            build(second_session, second_jobs).execute(**values)
        )
        return await asyncio.gather(first_task, second_task)

    try:
        first, second = _run(scenario())
        assert first.verdict is RetestStatus.STILL_VULNERABLE
        assert second.verdict is RetestStatus.STILL_VULNERABLE
        assert {first.duplicate, second.duplicate} == {False, True}
        assert first.retest_id == second.retest_id
        assert first.retest_attempt_id == second.retest_attempt_id
        assert first.observation_id == second.observation_id
        assert first.artifact_id == second.artifact_id
        assert fetch_calls == 1
        fixture["session"].rollback()
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retests")
        ).scalar_one() == 1
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_attempts")
        ).scalar_one() == 1
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_proofs")
        ).scalar_one() == 1
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_attempt_events "
                 "WHERE to_state='terminal'")
        ).scalar_one() == 1
    finally:
        second_session.close()
        second_jobs.close()
        fixture["session"].close()
        fixture["jobs"].close()


def test_tampered_retest_artifact_blocks_projection_and_duplicate_verdict(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        return HeaderResponse(200, {}, target)

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    values = dict(
        finding_id=fixture["finding_id"],
        tenant_id="tenant-a",
        authorization=fixture["authorization"],
        allowed_scope=("fixture.test",),
        idempotency_key="tamper-fixture",
    )
    try:
        result = _run(service.execute(**values))
        assert result.artifact_id is not None
        manifest = EvidenceCustodyStore(
            fixture["custody"], "tenant-a"
        ).get_manifest(result.artifact_id)
        derivative = (
            fixture["custody"]
            / manifest.derivative_relative_path
        )
        derivative.write_bytes(b"tampered")
        with pytest.raises(ArtifactIntegrityError):
            CanonicalEvidenceReader(
                fixture["session"],
                fixture["custody"],
                "tenant-a",
                audit_actor_id="operator-current",
            ).get_finding_projection(fixture["finding_id"])
        fixture["session"].rollback()
        duplicate = _run(service.execute(**values))
        assert duplicate.verdict is RetestStatus.INCONCLUSIVE
        assert duplicate.reason_code == "original_evidence_integrity_failure"
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_explicit_retry_uses_new_task103_job_attempt_and_preserves_prior_proof(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)
    fetch_number = 0

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        nonlocal fetch_number
        fetch_number += 1
        if fetch_number == 1:
            raise OSError("first verifier attempt failed")
        return HeaderResponse(200, {}, target)

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        first = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="retry-fixture-1",
            )
        )
        retry_authorization = _authorization(
            fixture["session"],
            tenant_id="tenant-a",
            engagement_id="engagement-retry",
            run_id="run-retry",
            job_id="job-retry",
            operator_id="operator-current",
            module_id=module_set_binding(["header_audit"]),
            target=fixture["target"],
        )
        second = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=retry_authorization,
                allowed_scope=("fixture.test",),
                idempotency_key="retry-fixture-2",
            )
        )
        assert first.verdict is RetestStatus.FAILED
        assert second.verdict is RetestStatus.STILL_VULNERABLE
        assert first.job_id != second.job_id
        assert first.durable_attempt_id != second.durable_attempt_id
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retests")
        ).scalar_one() == 2
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_attempts")
        ).scalar_one() == 2
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_proofs")
        ).scalar_one() == 2
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_source_snapshots")
        ).scalar_one() == 1
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_verifier_policies")
        ).scalar_one() == 1
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_observations")
        ).scalar_one() == 3
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_restart_replays_terminal_retest_without_new_fetch_or_evidence(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)
    fetch_calls = 0

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, {}, target)

    def build(session: Any, jobs: JobStateService) -> RetestService:
        return RetestService(
            session,
            fixture["custody"],
            jobs,
            authorization_loader=lambda decision_id: (
                fixture["original_authorization"]
                if decision_id == fixture["original_authorization"].decision_id
                else None
            ),
            outbound_policy_factory=lambda *_args: object(),
            header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
        )

    values = dict(
        finding_id=fixture["finding_id"],
        tenant_id="tenant-a",
        authorization=fixture["authorization"],
        allowed_scope=("fixture.test",),
        idempotency_key="restart-fixture",
    )
    first = _run(build(fixture["session"], fixture["jobs"]).execute(**values))
    assert first.verdict is RetestStatus.STILL_VULNERABLE
    fixture["session"].close()
    fixture["jobs"].close()

    restarted_session = create_db(fixture["database"])
    restarted_jobs = JobStateService(
        fixture["database"],
        authorization_checker=lambda *_args: True,
    )
    try:
        restarted_jobs.reconcile(tenant_id="tenant-a")
        second = _run(build(restarted_session, restarted_jobs).execute(**values))
        assert second.verdict is RetestStatus.STILL_VULNERABLE
        assert second.duplicate is True
        assert fetch_calls == 1
        assert restarted_session.execute(
            text("SELECT COUNT(*) FROM canonical_retest_proofs")
        ).scalar_one() == 1
        assert restarted_session.execute(
            text("SELECT COUNT(*) FROM canonical_retest_attempts")
        ).scalar_one() == 1
    finally:
        restarted_session.close()
        restarted_jobs.close()


def test_restart_recovers_result_after_task103_finish_before_retest_terminal_write(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)
    fetch_calls = 0

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, {}, target)

    def interrupt() -> None:
        raise RuntimeError("fixture crash after Task 103 finish")

    first_service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
        post_job_finish_hook=interrupt,
    )
    values = dict(
        finding_id=fixture["finding_id"],
        tenant_id="tenant-a",
        authorization=fixture["authorization"],
        allowed_scope=("fixture.test",),
        idempotency_key="crash-window-fixture",
    )
    with pytest.raises(RuntimeError, match="fixture crash"):
        _run(first_service.execute(**values))
    assert fixture["session"].execute(
        text("SELECT state FROM canonical_retest_attempts")
    ).scalar_one() == "running"
    assert fixture["session"].execute(
        text("SELECT COUNT(*) FROM canonical_retest_proofs")
    ).scalar_one() == 0
    assert fixture["jobs"].get_job(
        "job-current", tenant_id="tenant-a"
    )["state"] == "completed"
    fixture["session"].close()
    fixture["jobs"].close()

    restarted_session = create_db(fixture["database"])
    restarted_jobs = JobStateService(
        fixture["database"], authorization_checker=lambda *_args: True
    )
    restarted = RetestService(
        restarted_session,
        fixture["custody"],
        restarted_jobs,
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        expired = RetestService(
            restarted_session,
            fixture["custody"],
            restarted_jobs,
            authorization_loader=lambda decision_id: (
                fixture["original_authorization"]
                if decision_id == fixture["original_authorization"].decision_id
                else None
            ),
            outbound_policy_factory=lambda *_args: object(),
            header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
            clock=lambda: datetime.now(timezone.utc) + timedelta(days=1),
        )
        denied_recovery = _run(expired.execute(**values))
        assert denied_recovery.verdict is RetestStatus.NOT_AUTHORIZED
        assert denied_recovery.retest_id is None
        assert fetch_calls == 1
        assert restarted_session.execute(
            text("SELECT state FROM canonical_retest_attempts")
        ).scalar_one() == "running"
        restarted_session.rollback()
        result = _run(restarted.execute(**values))
        assert result.verdict is RetestStatus.STILL_VULNERABLE
        assert result.duplicate is True
        assert fetch_calls == 1
        assert restarted_session.execute(
            text("SELECT state FROM canonical_retest_attempts")
        ).scalar_one() == "terminal"
        assert restarted_session.execute(
            text("SELECT COUNT(*) FROM canonical_retest_proofs")
        ).scalar_one() == 1
        assert restarted_session.execute(
            text("SELECT COUNT(*) FROM canonical_observations")
        ).scalar_one() == 2
    finally:
        restarted_session.close()
        restarted_jobs.close()


def test_terminal_replay_rejects_different_authorization_identity_without_fetch(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)
    fetch_calls = 0

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, {}, target)

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        first = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="identity-replay-fixture",
            )
        )
        replacement = _authorization(
            fixture["session"],
            tenant_id="tenant-a",
            engagement_id="engagement-replacement",
            run_id="run-replacement",
            job_id="job-replacement",
            operator_id="operator-replacement",
            module_id=module_set_binding(["header_audit"]),
            target=fixture["target"],
        )
        rejected = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=replacement,
                allowed_scope=("fixture.test",),
                idempotency_key="identity-replay-fixture",
            )
        )
        assert first.verdict is RetestStatus.STILL_VULNERABLE
        assert rejected.verdict is RetestStatus.NOT_AUTHORIZED
        assert rejected.reason_code == "replay_authorization_mismatch"
        assert fetch_calls == 1
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_proofs")
        ).scalar_one() == 1
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retests")
        ).scalar_one() == 1
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_terminal_replay_rejects_expired_and_denied_exact_identity_without_disclosure(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)
    fetch_calls = 0

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, {}, target)

    def service(*, expired: bool = False) -> RetestService:
        return RetestService(
            fixture["session"],
            fixture["custody"],
            fixture["jobs"],
            authorization_loader=lambda decision_id: (
                fixture["original_authorization"]
                if decision_id == fixture["original_authorization"].decision_id
                else None
            ),
            outbound_policy_factory=lambda *_args: object(),
            header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
            clock=(
                (lambda: datetime.now(timezone.utc) + timedelta(days=1))
                if expired
                else (lambda: datetime.now(timezone.utc))
            ),
        )

    values = {
        "finding_id": fixture["finding_id"],
        "tenant_id": "tenant-a",
        "authorization": fixture["authorization"],
        "allowed_scope": ("fixture.test",),
        "idempotency_key": "invalid-terminal-replay",
    }
    try:
        terminal = _run(service().execute(**values))
        assert terminal.verdict is RetestStatus.STILL_VULNERABLE

        expired_result = _run(service(expired=True).execute(**values))
        assert expired_result.verdict is RetestStatus.NOT_AUTHORIZED
        assert expired_result.retest_id is None
        assert expired_result.artifact_id is None

        denied = fixture["authorization"].to_dict()
        denied.update(
            {
                "scope_decision": "denied",
                "decision_outcome": "deny",
                "reason_code": "approval_mismatch",
                "decision_reason": "fixture denial",
            }
        )
        denied["binding_digest"] = compute_envelope_digest(denied)
        denied_result = _run(
            service().execute(**{**values, "authorization": denied})
        )
        assert denied_result.verdict is RetestStatus.NOT_AUTHORIZED
        assert denied_result.retest_id is None
        assert denied_result.artifact_id is None
        assert fetch_calls == 1
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_nonempty_task104_history_blocks_destructive_downgrade(tmp_path: Path) -> None:
    fixture = _active_fixture(tmp_path)

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        return HeaderResponse(200, {}, target)

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="downgrade-fixture",
            )
        )
        assert result.verdict is RetestStatus.STILL_VULNERABLE
        manager = MigrationManager(fixture["session"].get_bind())
        with pytest.raises(MigrationError, match="would destroy retained history"):
            manager.downgrade(target=JOB_STATE_SCHEMA_VERSION)
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_proofs")
        ).scalar_one() == 1
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_wrong_retest_relationship_identity_and_terminal_mutation_are_rejected(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        return HeaderResponse(200, {}, target)

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="identity-guard-fixture",
            )
        )
        assert result.verdict is RetestStatus.STILL_VULNERABLE
        persisted_request = dict(
            fixture["session"].execute(
                text(
                    "SELECT * FROM canonical_retests WHERE id=:retest_id"
                ),
                {"retest_id": result.retest_id},
            ).mappings().one()
        )
        fixture["session"].rollback()
        columns = tuple(persisted_request)
        insert_clone = text(
            "INSERT INTO canonical_retests("
            + ",".join(columns)
            + ") VALUES("
            + ",".join(f":{column}" for column in columns)
            + ")"
        )
        for sequence, (column, value) in enumerate(
            (
                ("source_proof_artifact_id", persisted_request["source_artifact_id"]),
                ("source_snapshot_id", persisted_request["verifier_policy_id"]),
                ("check_id", "wrong-check"),
                ("route", "/wrong-route"),
                ("method", "POST"),
                ("parameter", "wrong-parameter"),
                ("location", "wrong-location"),
                ("identity_ref", "wrong-identity"),
                ("session_reference", "cred:memory:wrong-session"),
                ("session_policy_digest", _digest("wrong-session-policy")),
                ("mutation_class", "stateful_replay"),
                ("proof_expectation", "csp_changed"),
                ("proof_policy_version", "wrong-proof-policy"),
                ("policy_snapshot", "wrong-policy-snapshot"),
                ("verifier_id", "wrong-verifier"),
                ("verifier_version", "9.9.9"),
                ("verifier_policy_id", persisted_request["source_snapshot_id"]),
                ("content_snapshot_digest", _digest("wrong-content")),
                ("evidence_baseline_digest", _digest("wrong-evidence")),
                ("engagement_id", "engagement-original"),
            )
        ):
            clone = {
                **persisted_request,
                "id": f"retest-clone-{sequence}",
                "idempotency_key": f"retest-clone-{sequence}",
                column: value,
            }
            with pytest.raises(IntegrityError):
                fixture["session"].execute(insert_clone, clone)
                fixture["session"].commit()
            fixture["session"].rollback()
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_source_snapshots")
        ).scalar_one() == 1
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_verifier_policies")
        ).scalar_one() == 1
        fixture["session"].rollback()
        for table in (
            "canonical_retest_source_snapshots",
            "canonical_retest_verifier_policies",
        ):
            with pytest.raises(IntegrityError):
                fixture["session"].execute(
                    text(f"UPDATE {table} SET created_at='2099-01-01T00:00:00Z'")
                )
                fixture["session"].commit()
            fixture["session"].rollback()
        for column, value in (
            ("tenant_id", "tenant-b"),
            ("finding_id", "wrong-finding"),
            ("source_observation_id", "wrong-observation"),
            ("source_proof_artifact_id", "wrong-proof-artifact"),
            ("original_attempt_id", "wrong-attempt"),
            ("new_job_id", "wrong-job"),
            ("verifier_id", "wrong-verifier"),
            ("engagement_id", "wrong-engagement"),
            ("current_scope_decision_id", "wrong-scope"),
            ("session_reference", "cred:memory:wrong-session"),
            ("authorization_decision_id", "wrong-authorization"),
        ):
            with pytest.raises(IntegrityError):
                fixture["session"].execute(
                    text(
                        f"UPDATE canonical_retests SET {column}=:value "
                        "WHERE id=:retest_id"
                    ),
                    {"value": value, "retest_id": result.retest_id},
                )
                fixture["session"].commit()
            fixture["session"].rollback()
        with pytest.raises(IntegrityError):
            fixture["session"].execute(
                text(
                    "UPDATE canonical_retest_attempts SET verdict='fixed' "
                    "WHERE id=:attempt_id"
                ),
                {"attempt_id": result.retest_attempt_id},
            )
            fixture["session"].commit()
        fixture["session"].rollback()
        with pytest.raises(IntegrityError):
            fixture["session"].execute(
                text(
                    "UPDATE canonical_retest_proofs SET sufficient=0 "
                    "WHERE retest_attempt_id=:attempt_id"
                ),
                {"attempt_id": result.retest_attempt_id},
            )
            fixture["session"].commit()
        fixture["session"].rollback()
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_cancellation_preserves_task103_terminal_truth_without_retest_verdict(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)

    async def canceled_fetch(*_args: Any) -> HeaderResponse:
        raise asyncio.CancelledError

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=canceled_fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="canceled-fixture",
            )
        )
        assert result.state == "canceled"
        assert result.verdict is None
        job = fixture["jobs"].get_job("job-current", tenant_id="tenant-a")
        assert job is not None
        assert job["state"] in {"canceled", "partial"}
        assert fixture["session"].execute(
            text("SELECT state FROM canonical_retest_attempts")
        ).scalar_one() == "canceled"
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_proofs")
        ).scalar_one() == 0
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_late_cancellation_reloads_existing_terminal_truth_without_false_event(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        return HeaderResponse(200, {}, target)

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        terminal = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="late-cancel-fixture",
            )
        )
        assert terminal.verdict is RetestStatus.STILL_VULNERABLE
        before = fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_attempt_events")
        ).scalar_one()
        fixture["session"].rollback()
        replay = service._mark_canceled(
            SimpleNamespace(
                tenant_id="tenant-a",
                id=terminal.retest_id,
                finding_id=fixture["finding_id"],
                new_job_id=terminal.job_id,
            ),
            SimpleNamespace(
                id=terminal.retest_attempt_id,
                durable_attempt_id=terminal.durable_attempt_id,
            ),
            reason_code="late_cancellation_race",
        )
        assert replay.verdict is RetestStatus.STILL_VULNERABLE
        assert replay.duplicate is True
        after = fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retest_attempt_events")
        ).scalar_one()
        assert after == before
        states = fixture["session"].execute(
            text("SELECT to_state FROM canonical_retest_attempt_events")
        ).scalars().all()
        assert "canceled" not in states
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


@pytest.mark.parametrize(
    ("response", "exception"),
    [
        (None, TimeoutError("fixture timeout")),
        (None, OSError("fixture connection failure")),
        (None, ValueError("fixture verifier failure")),
        (HeaderResponse(500, {}, "https://fixture.test/account"), None),
        (HeaderResponse(404, {}, "https://fixture.test/account"), None),
        (HeaderResponse(401, {}, "https://fixture.test/account"), None),
        (
            HeaderResponse(
                200,
                {"Content-Security-Policy": "default-src 'self'; object-src 'none'"},
                "https://fixture.test/changed",
            ),
            None,
        ),
        (
            HeaderResponse(
                200,
                {"Content-Security-Policy": "default-src 'self'; object-src 'none'"},
                "https://user:password@fixture.test/account",
            ),
            None,
        ),
        (
            HeaderResponse(
                200,
                {"Content-Security-Policy": "default-src 'self'"},
                "https://fixture.test/account",
                evidence_complete=False,
            ),
            None,
        ),
    ],
)
def test_transport_auth_http_and_inadequate_evidence_never_return_fixed(
    response: HeaderResponse | None,
    exception: Exception | None,
) -> None:
    async def fetch(_target: str, *_args: Any) -> HeaderResponse:
        if exception is not None:
            raise exception
        assert response is not None
        return response

    result = _run(
        HeaderAuditCspVerifier(fetcher=fetch).verify(
            _input(_request(proof_expectation="csp_missing"))
        )
    )
    assert result.verdict is not RetestStatus.FIXED
    assert result.sufficient is False


@pytest.mark.parametrize(
    ("response", "exception", "expected"),
    [
        (None, TimeoutError("fixture timeout"), RetestStatus.FAILED),
        (None, OSError("fixture connection failure"), RetestStatus.FAILED),
        (None, ValueError("fixture verifier failure"), RetestStatus.FAILED),
        (
            HeaderResponse(500, {}, "https://fixture.test/account"),
            None,
            RetestStatus.INCONCLUSIVE,
        ),
        (
            HeaderResponse(404, {}, "https://fixture.test/account"),
            None,
            RetestStatus.INCONCLUSIVE,
        ),
        (
            HeaderResponse(401, {}, "https://fixture.test/account"),
            None,
            RetestStatus.INCONCLUSIVE,
        ),
        (
            HeaderResponse(
                200,
                {"Content-Security-Policy": "default-src 'self'"},
                "https://fixture.test/account",
                evidence_complete=False,
            ),
            None,
            RetestStatus.INCONCLUSIVE,
        ),
        (
            HeaderResponse(
                200,
                {"Content-Security-Policy": "default-src 'self'; object-src 'none'"},
                "https://fixture.test/changed",
            ),
            None,
            RetestStatus.INCONCLUSIVE,
        ),
    ],
)
def test_active_failure_evidence_is_persisted_without_fixed_verdict(
    tmp_path: Path,
    response: HeaderResponse | None,
    exception: Exception | None,
    expected: RetestStatus,
) -> None:
    fixture = _active_fixture(tmp_path)

    async def fetch(_target: str, *_args: Any) -> HeaderResponse:
        if exception is not None:
            raise exception
        assert response is not None
        return response

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="failure-fixture",
            )
        )
        assert result.verdict is expected
        assert result.verdict is not RetestStatus.FIXED
        assert result.observation_id and result.artifact_id
        assert fixture["session"].execute(
            text("SELECT verdict FROM canonical_retest_attempts")
        ).scalar_one() == expected.value
        job = fixture["jobs"].get_job("job-current", tenant_id="tenant-a")
        assert job is not None
        assert job["state"] == (
            "failed" if expected is RetestStatus.FAILED else "completed"
        )
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_exit_and_no_finding_claims_are_not_verifier_inputs_or_fixed_proof() -> None:
    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        del target
        return HeaderResponse(200, {}, "https://fixture.test/account")

    request = _request(metadata={"process_exit_code": 0, "no_finding": True})
    result = _run(HeaderAuditCspVerifier(fetcher=fetch).verify(_input(request)))
    assert result.verdict is RetestStatus.STILL_VULNERABLE
    assert result.sufficient is True
    proof = result.proof_payload(request)
    assert "process_exit_code" not in proof
    assert "no_finding" not in proof


def test_missing_authorization_returns_not_authorized_without_fetch(tmp_path: Path) -> None:
    session = create_db(tmp_path / "retest.db")
    calls = 0

    async def fetch(*_args: Any) -> HeaderResponse:
        nonlocal calls
        calls += 1
        return HeaderResponse(200, {}, "https://fixture.test/account")

    service = RetestService(
        session,
        tmp_path / "custody",
        SimpleNamespace(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id="finding-header",
                tenant_id="tenant-a",
                authorization=None,
                allowed_scope=("fixture.test",),
                idempotency_key="missing-auth",
            )
        )
        assert result.verdict is RetestStatus.NOT_AUTHORIZED
        assert calls == 0
    finally:
        session.close()


@pytest.mark.parametrize("mismatch", ["target", "expired", "credential", "unconsumed"])
def test_mismatched_or_expired_authorization_opens_no_connection(
    tmp_path: Path,
    mismatch: str,
) -> None:
    fixture = _active_fixture(
        tmp_path,
        session_values={"Authorization": "Bearer SESSION_SECRET_TASK104_CANARY"}
        if mismatch == "credential"
        else None,
    )
    authorization = fixture["authorization"]
    allowed_scope = ("fixture.test",)
    if mismatch == "target":
        authorization = _authorization(
            fixture["session"],
            tenant_id="tenant-a",
            engagement_id="engagement-current-target-mismatch",
            run_id="run-current-target-mismatch",
            job_id="job-current-target-mismatch",
            operator_id="operator-current",
            module_id=module_set_binding(["header_audit"]),
            target="https://other.test/account",
            allowed_scope=("other.test",),
        )
        allowed_scope = ("other.test",)
    elif mismatch == "expired":
        authorization = _authorization(
            fixture["session"],
            tenant_id="tenant-a",
            engagement_id="engagement-current-expired",
            run_id="run-current-expired",
            job_id="job-current-expired",
            operator_id="operator-current",
            module_id=module_set_binding(["header_audit"]),
            target=fixture["target"],
            now=datetime.now(timezone.utc) - timedelta(hours=1),
        )
    elif mismatch == "credential":
        authorization = _authorization(
            fixture["session"],
            tenant_id="tenant-a",
            engagement_id="engagement-current-credential-mismatch",
            run_id="run-current-credential-mismatch",
            job_id="job-current-credential-mismatch",
            operator_id="operator-current",
            module_id=module_set_binding(["header_audit"]),
            target=fixture["target"],
            credential_reference="",
        )
    elif mismatch == "unconsumed":
        authorization = _authorization(
            fixture["session"],
            tenant_id="tenant-a",
            engagement_id="engagement-current-unconsumed",
            run_id="run-current-unconsumed",
            job_id="job-current-unconsumed",
            operator_id="operator-current",
            module_id=module_set_binding(["header_audit"]),
            target=fixture["target"],
            consume_boundary=None,
        )
    fetch_calls = 0

    async def fetch(*_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, {}, fixture["target"])

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=authorization,
                allowed_scope=allowed_scope,
                idempotency_key=f"auth-{mismatch}",
            )
        )
        assert result.verdict is RetestStatus.NOT_AUTHORIZED
        assert fetch_calls == 0
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retests")
        ).scalar_one() == 0
    finally:
        fixture["session"].close()
        fixture["jobs"].close()
        if fixture["provider"] is not None:
            fixture["provider"].discard_all()


def test_cross_tenant_finding_retest_and_projection_fail_closed(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)
    fetch_calls = 0

    async def fetch(*_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, {}, fixture["target"])

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-b",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="cross-tenant-fixture",
            )
        )
        assert result.verdict is RetestStatus.NOT_AUTHORIZED
        assert fetch_calls == 0
        assert CanonicalEvidenceReader(
            fixture["session"],
            fixture["custody"],
            "tenant-b",
        ).get_finding_projection(fixture["finding_id"]) is None
        fixture["session"].rollback()
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retests")
        ).scalar_one() == 0
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_malformed_original_canonical_evidence_is_inconclusive_without_fetch(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)
    fetch_calls = 0

    async def fetch(*_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, {}, fixture["target"])

    trigger_names = fixture["session"].execute(
        text(
            "SELECT name FROM sqlite_master WHERE type='trigger' "
            "AND tbl_name='canonical_artifact_manifests'"
        )
    ).scalars().all()
    fixture["session"].rollback()
    for trigger_name in trigger_names:
        fixture["session"].execute(
            text(f'DROP TRIGGER "{trigger_name}"')
        )
    fixture["session"].execute(
        text(
            "UPDATE canonical_artifact_manifests SET metadata_json='[]' "
            "WHERE observation_id=(SELECT observation_id FROM canonical_findings "
            "WHERE id=:finding_id)"
        ),
        {"finding_id": fixture["finding_id"]},
    )
    fixture["session"].commit()

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="malformed-source-evidence",
            )
        )
        assert result.verdict is RetestStatus.INCONCLUSIVE
        assert result.reason_code == "original_evidence_integrity_failure"
        assert fetch_calls == 0
        assert fixture["session"].execute(
            text("SELECT COUNT(*) FROM canonical_retests")
        ).scalar_one() == 0
    finally:
        fixture["session"].close()
        fixture["jobs"].close()


def test_registry_is_allowlisted_and_unknown_or_incompatible_families_are_unsupported() -> None:
    assert DEFAULT_RETEST_REGISTRY.resolve(
        module_id="header_audit",
        check_id=HEADER_CSP_CHECK_ID,
        source_version=VERSION,
        proof_expectation="csp_missing",
    ) is not None
    assert DEFAULT_RETEST_REGISTRY.resolve(
        module_id="sqli_scanner",
        check_id="sqli",
        source_version="1.0.0",
        proof_expectation="payload",
    ) is None
    assert DEFAULT_RETEST_REGISTRY.resolve(
        module_id="header_audit",
        check_id=HEADER_CSP_CHECK_ID,
        source_version="9.9.9",
        proof_expectation="csp_missing",
    ) is None


def test_changed_lineage_dimensions_are_contract_fields_and_not_hidden_metadata() -> None:
    names = {item.name for item in fields(RetestRequest)}
    required = {
        "finding_id", "source_observation_id", "source_artifact_id",
        "source_proof_artifact_id", "asset_id",
        "source_snapshot_id", "verifier_policy_id",
        "target_url", "route", "method", "parameter", "location", "identity_ref",
        "module_id", "module_version", "check_id", "proof_expectation",
        "proof_policy_version", "evidence_baseline_digest", "session_reference",
    }
    assert required <= names
    with pytest.raises(ValueError):
        _request(method="GET", route="relative")
    with pytest.raises(ValueError):
        _request(target_url="https://user:password@fixture.test/account")


def test_session_reference_uses_single_use_protected_provider_without_serializing_secret(
    tmp_path: Path,
) -> None:
    secret = "SESSION_SECRET_TASK104_CANARY"
    provider = InMemorySecretProvider()
    reference = provider.put({"unused": secret})

    class Resolver:
        @staticmethod
        def resolve(reference_value: Any, *, approval: CredentialUseApproval, target: str):
            assert approval.matches(reference, target=target)
            class _Context:
                def __enter__(self) -> dict[str, dict[str, str]]:
                    return {"headers": {"Authorization": f"Bearer {secret}"}}

                def __exit__(self, *_args: Any) -> None:
                    return None

            return _Context()

    request = _request(session_reference=reference.value)
    session = create_db(tmp_path / "session.db")
    service = RetestService(session, tmp_path / "custody", SimpleNamespace(), session_resolver=Resolver())
    envelope = SimpleNamespace(decision_id="decision-current")
    try:
        with service._resolved_session(request, envelope) as (headers, cookies):
            assert secret in headers["Authorization"]
            rendered = json.dumps(request.to_dict())
            assert secret not in rendered
        raw_db = b"".join(path.read_bytes() for path in tmp_path.glob("session.db*"))
        assert secret.encode() not in raw_db
    finally:
        session.close()
        provider.discard_all()


def test_active_authenticated_context_resolves_reference_without_secret_persistence(
    tmp_path: Path,
) -> None:
    secret = "SESSION_SECRET_TASK104_CANARY_ACTIVE"
    fixture = _active_fixture(
        tmp_path,
        session_values={"Authorization": f"Bearer {secret}"},
    )
    fetch_calls = 0

    async def fetch(
        target: str,
        _policy: Any,
        headers: dict[str, str],
        _cookies: dict[str, str],
    ) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        assert headers["Authorization"] == f"Bearer {secret}"
        return HeaderResponse(200, {}, target)

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        session_resolver=fixture["resolver"],
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="authenticated-fixture",
            )
        )
        assert result.verdict is RetestStatus.STILL_VULNERABLE
        assert fetch_calls == 1
        assert secret not in json.dumps(result.to_dict(), sort_keys=True)
        fixture["session"].close()
        fixture["jobs"].close()
        persisted = b"".join(
            item.read_bytes()
            for item in sorted(tmp_path.rglob("*"))
            if item.is_file()
        )
        assert secret.encode("utf-8") not in persisted
    finally:
        fixture["session"].close()
        fixture["jobs"].close()
        if fixture["provider"] is not None:
            fixture["provider"].discard_all()


def test_unavailable_protected_session_returns_persisted_not_authorized_without_fetch(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(
        tmp_path,
        session_values={"Authorization": "Bearer SESSION_SECRET_TASK104_CANARY"},
    )
    fetch_calls = 0

    async def fetch(*_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, {}, fixture["target"])

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        session_resolver=None,
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="session-unavailable-fixture",
            )
        )
        assert result.verdict is RetestStatus.NOT_AUTHORIZED
        assert fetch_calls == 0
        job = fixture["jobs"].get_job("job-current", tenant_id="tenant-a")
        assert job is not None and job["state"] == "failed"
        fixture["session"].rollback()
        projection = CanonicalEvidenceReader(
            fixture["session"],
            fixture["custody"],
            "tenant-a",
            audit_actor_id="operator-current",
        ).get_finding_projection(fixture["finding_id"])
        assert projection is not None
        assert projection["retest_verdict"] == "not_authorized"
    finally:
        fixture["session"].close()
        fixture["jobs"].close()
        if fixture["provider"] is not None:
            fixture["provider"].discard_all()


def test_protected_session_provider_failure_is_terminal_not_authorized_without_fetch(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(
        tmp_path,
        session_values={"Authorization": "Bearer SESSION_SECRET_TASK104_CANARY"},
    )
    fetch_calls = 0

    class FailingResolver:
        @contextmanager
        def resolve(self, *_args: Any, **_kwargs: Any):
            raise RuntimeError("PROVIDER_DETAIL_MUST_NOT_ESCAPE")
            yield {}

    async def fetch(*_args: Any) -> HeaderResponse:
        nonlocal fetch_calls
        fetch_calls += 1
        return HeaderResponse(200, {}, fixture["target"])

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        session_resolver=FailingResolver(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="session-provider-failure-fixture",
            )
        )
        assert result.verdict is RetestStatus.NOT_AUTHORIZED
        assert result.reason_code == "protected_session_authorization_invalid"
        assert "PROVIDER_DETAIL" not in json.dumps(result.to_dict())
        assert fetch_calls == 0
    finally:
        fixture["session"].close()
        fixture["jobs"].close()
        if fixture["provider"] is not None:
            fixture["provider"].discard_all()


def test_verdict_enum_is_exactly_the_seven_task104_terminal_values() -> None:
    assert {item.value for item in RetestStatus} == {
        "fixed",
        "still_vulnerable",
        "inconclusive",
        "failed",
        "not_applicable",
        "not_authorized",
        "unsupported",
    }


def test_attempt_and_proof_contracts_require_verdict_only_at_terminal_state() -> None:
    assert "verdict" in {item.name for item in fields(RetestAttempt)}
    assert "original_observation_id" in {item.name for item in fields(RetestProof)}
    with pytest.raises(ValueError):
        RetestAttempt(
            tenant_id="tenant-a",
            retest_id="retest-request-fixture",
            job_id="job-current",
            verifier_id=HEADER_CSP_VERIFIER_ID,
            verifier_version=HEADER_CSP_VERIFIER_VERSION,
            proof_policy_version=HEADER_CSP_PROOF_POLICY,
            idempotency_key="attempt-1",
            state="terminal",
        )
    canceled = RetestAttempt(
        tenant_id="tenant-a",
        retest_id="retest-request-fixture",
        job_id="job-current",
        verifier_id=HEADER_CSP_VERIFIER_ID,
        verifier_version=HEADER_CSP_VERIFIER_VERSION,
        proof_policy_version=HEADER_CSP_PROOF_POLICY,
        idempotency_key="attempt-canceled",
        state="canceled",
        reason_code="retest_canceled",
    )
    assert canceled.verdict is None


def test_retest_request_attempt_and_proof_contracts_round_trip_exactly() -> None:
    request = _request()
    assert RetestRequest.from_dict(request.to_dict()) == request
    attempt = RetestAttempt(
        id="retest-attempt-fixture",
        tenant_id=request.tenant_id,
        retest_id=request.id,
        job_id="job-current",
        durable_attempt_id="durable-attempt-current",
        verifier_id=request.verifier_id,
        verifier_version=request.verifier_version,
        proof_policy_version=request.proof_policy_version,
        idempotency_key="attempt-round-trip",
        state="terminal",
        verdict="inconclusive",
        reason_code="fixture_inconclusive",
        proof_id="proof-round-trip",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    assert RetestAttempt.from_dict(attempt.to_dict()) == attempt
    proof = RetestProof(
        id="proof-round-trip",
        tenant_id=request.tenant_id,
        retest_id=request.id,
        retest_attempt_id=attempt.id,
        durable_job_id=attempt.job_id,
        durable_attempt_id=attempt.durable_attempt_id or "",
        original_observation_id=request.source_observation_id,
        observation_id="observation-current",
        artifact_id="artifact-current",
        verifier_id=request.verifier_id,
        verifier_version=request.verifier_version,
        proof_policy_version=request.proof_policy_version,
        proof_expectation=request.proof_expectation,
        observed_condition="evidence_incomplete",
        route=request.route,
        method=request.method,
        sufficient=False,
        proof_digest=_digest("proof-round-trip"),
        response_status=500,
    )
    assert RetestProof.from_dict(proof.to_dict()) == proof


def test_existing_header_rule_classification_is_deterministic() -> None:
    assert classify_csp(None) == "csp_missing"
    assert classify_csp("default-src 'self' 'unsafe-inline'") == "csp_weak"
    assert classify_csp("default-src 'self'; object-src 'none'") == "csp_strong"


def test_canonical_retest_tables_are_present_in_private_fixture_database(tmp_path: Path) -> None:
    session = create_db(tmp_path / "schema.db")
    try:
        tables = {
            str(row[0])
            for row in session.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            ).all()
        }
        assert {
            "canonical_retests",
            "canonical_retest_source_snapshots",
            "canonical_retest_verifier_policies",
            "canonical_retest_attempts",
            "canonical_retest_proofs",
            "canonical_retest_proof_artifacts",
            "canonical_retest_attempt_events",
        } <= tables
    finally:
        session.close()


def test_request_and_proof_links_keep_original_and_new_task103_identity_distinct() -> None:
    request = _request(
        new_job_id="job-current",
        authorization_decision_id="decision-current",
        authorization_action_id="action-current",
    )
    assert request.finding_id == "finding-header"
    assert request.source_observation_id == "observation-original"
    assert request.source_artifact_id == "artifact-original"
    assert request.source_proof_artifact_id == "artifact-original-proof"
    assert request.source_snapshot_id == "retest-source-snapshot-fixture"
    assert request.verifier_policy_id == "retest-verifier-policy-fixture"
    assert request.original_attempt_id == "attempt-original"
    assert request.new_job_id != request.original_job_id
    assert request.target_url.endswith(request.route)


def test_version_migration_is_explicit_and_unknown_versions_do_not_resolve() -> None:
    registration = DEFAULT_RETEST_REGISTRY.resolve(
        module_id="header_audit",
        check_id=HEADER_CSP_CHECK_ID,
        source_version=VERSION,
        proof_expectation="csp_weak",
    )
    assert registration is not None
    assert registration.compatibility_migrations == {}
    assert DEFAULT_RETEST_REGISTRY.resolve(
        module_id="header_audit",
        check_id=HEADER_CSP_CHECK_ID,
        source_version="header-audit-unreviewed",
        proof_expectation="csp_weak",
    ) is None


def test_not_applicable_requires_explicit_registered_family_policy(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)
    registration = VerifierRegistration(
        module_id="header_audit",
        check_ids=("header_audit", HEADER_CSP_CHECK_ID),
        source_versions=(VERSION,),
        verifier_id=HEADER_CSP_VERIFIER_ID,
        verifier_version=HEADER_CSP_VERIFIER_VERSION,
        proof_policy_version=HEADER_CSP_PROOF_POLICY,
        proof_expectations=("csp_missing", "csp_weak"),
        allows_not_applicable=True,
    )

    class NotApplicableVerifier:
        @staticmethod
        async def verify(_value: VerifierInput) -> VerifierOutput:
            return VerifierOutput(
                verdict=RetestStatus.NOT_APPLICABLE,
                reason_code="documented_fixture_policy_not_applicable",
                observed_condition="family_policy_not_applicable",
                response_status=200,
                sufficient=False,
                header_value_digest=None,
            )

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        registry=RetestVerifierRegistry((registration,)),
        header_verifier=NotApplicableVerifier(),
    )
    try:
        result = _run(
            service.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=fixture["authorization"],
                allowed_scope=("fixture.test",),
                idempotency_key="not-applicable-fixture",
            )
        )
        assert result.verdict is RetestStatus.NOT_APPLICABLE
        projection = CanonicalEvidenceReader(
            fixture["session"],
            fixture["custody"],
            "tenant-a",
            audit_actor_id="operator-current",
        ).get_finding_projection(fixture["finding_id"])
        assert projection is not None
        assert projection["retest_verdict"] == "not_applicable"
    finally:
        fixture["session"].close()
        fixture["jobs"].close()
    explicitly_migrated = RetestVerifierRegistry(
        (
            VerifierRegistration(
                module_id="header_audit",
                check_ids=(HEADER_CSP_CHECK_ID,),
                source_versions=(VERSION,),
                verifier_id=HEADER_CSP_VERIFIER_ID,
                verifier_version=HEADER_CSP_VERIFIER_VERSION,
                proof_policy_version=HEADER_CSP_PROOF_POLICY,
                proof_expectations=("csp_weak",),
                compatibility_migrations={
                    "4.9.0": HEADER_CSP_VERIFIER_VERSION,
                },
            ),
        )
    )
    assert explicitly_migrated.resolve(
        module_id="header_audit",
        check_id=HEADER_CSP_CHECK_ID,
        source_version="4.9.0",
        proof_expectation="csp_weak",
    ) is not None
    assert explicitly_migrated.resolve(
        module_id="header_audit",
        check_id=HEADER_CSP_CHECK_ID,
        source_version="4.8.0",
        proof_expectation="csp_weak",
    ) is None


def test_result_projection_preserves_each_terminal_verdict_exactly() -> None:
    expected = {
        "fixed",
        "still_vulnerable",
        "inconclusive",
        "failed",
        "not_applicable",
        "not_authorized",
        "unsupported",
    }
    projected = {
        RetestExecutionResult(
            state="terminal",
            verdict=RetestStatus(value),
            reason_code="fixture",
            finding_id="finding-header",
        ).to_dict()["retest_verdict"]
        for value in expected
    }
    assert projected == expected


def test_dashboard_api_serializer_preserves_each_terminal_verdict_exactly() -> None:
    from common.dashboard.server import DashboardServer

    server = object.__new__(DashboardServer)
    verdicts = {
        "fixed",
        "still_vulnerable",
        "inconclusive",
        "failed",
        "not_applicable",
        "not_authorized",
        "unsupported",
    }
    projected = {
        server._public_finding(
            {
                "id": f"finding-{verdict}",
                "title": "Header finding",
                "severity": "medium",
                "module": "header_audit",
                "target": "https://fixture.test/",
                "description": "Persisted API fixture.",
                "status": "open",
                "confidence": "HIGH",
                "verification_state": "verified",
                "proof_type": "passive",
                "maturity": "stable",
                "retest_state": "terminal",
                "retest_status": verdict,
                "retest_verdict": verdict,
                "retest_reason_code": f"fixture_{verdict}",
                "evidence": {"observations": [], "state": "unavailable"},
            }
        )["retest_verdict"]
        for verdict in verdicts
    }
    assert projected == verdicts
    with pytest.raises(ValueError, match="retest_verdict is invalid"):
        server._public_finding(
            {
                "id": "finding-invented",
                "title": "Header finding",
                "severity": "medium",
                "module": "header_audit",
                "target": "https://fixture.test/",
                "description": "Persisted API fixture.",
                "status": "open",
                "confidence": "HIGH",
                "verification_state": "verified",
                "proof_type": "passive",
                "maturity": "stable",
                "retest_state": "terminal",
                "retest_status": "invented",
                "retest_verdict": "invented",
                "evidence": {"observations": [], "state": "unavailable"},
            }
        )


def test_retest_request_idempotency_and_tenant_keys_are_schema_constrained(tmp_path: Path) -> None:
    session = create_db(tmp_path / "idempotency.db")
    try:
        rows = session.execute(
            text("PRAGMA index_list('canonical_retests')")
        ).all()
        indexes = {str(row[1]) for row in rows}
        assert any("idempotency" in name or "canonical_retests" in name for name in indexes)
        columns = {
            str(row[1])
            for row in session.execute(
                text("PRAGMA table_info(canonical_retests)")
            ).all()
        }
        assert {
            "tenant_id",
            "idempotency_key",
            "source_observation_id",
            "source_artifact_id",
            "source_proof_artifact_id",
            "source_snapshot_id",
            "verifier_policy_id",
            "new_job_id",
        } <= columns
    finally:
        session.close()
