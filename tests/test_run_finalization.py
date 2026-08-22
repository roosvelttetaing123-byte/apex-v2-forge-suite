from __future__ import annotations

import base64
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from common.action_authorization import (
    AuthorizationContext,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    consume_authorization,
    issue_authorization,
    module_set_binding,
)
from common.confirm_gate import ActionConfirmation
from common.db import (
    FindingRunMembershipModel,
    PersistedFindingDeltaModel,
    RunCollectionTruthModel,
    ScanRunModel,
    create_db,
    save_finding,
)
from common.run_finalization import (
    RUN_TRUTH_AUTHORITY_ID_ENV,
    RUN_TRUTH_ISSUER_ID_ENV,
    RUN_TRUTH_POLICY_ID_ENV,
    RUN_TRUTH_POLICY_VERSION_ENV,
    RUN_TRUTH_PRIVATE_KEY_FILE_ENV,
    RUN_TRUTH_PUBLIC_KEY_ENV,
    RunCompletionManifest,
    RunFinalizationError,
    finalize_authorized_run,
    load_configured_persisted_delta,
    load_managed_run_truth_signer,
)


TARGET = "http://127.0.0.1:8080/fixture"
SCOPE = ("127.0.0.1/32",)
PLANNED = ("header_audit", "security_txt")
COMPLETED_AT = datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)


def _signer_environment(tmp_path: Path) -> dict[str, str]:
    private_key = Ed25519PrivateKey.generate()
    encoded_private = base64.b64encode(
        private_key.private_bytes_raw()
    )
    key_file = tmp_path / "run-truth-signing.key"
    key_file.write_bytes(encoded_private)
    key_file.chmod(0o600)
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    return {
        RUN_TRUTH_POLICY_ID_ENV: "forge-run-coverage-v1",
        RUN_TRUTH_POLICY_VERSION_ENV: "1.0",
        RUN_TRUTH_ISSUER_ID_ENV: "fixture-run-issuer",
        RUN_TRUTH_PUBLIC_KEY_ENV: public_key,
        RUN_TRUTH_PRIVATE_KEY_FILE_ENV: str(key_file),
        RUN_TRUTH_AUTHORITY_ID_ENV: "fixture-run-authority",
    }


def _authorization_context(
    run_id: str,
    *,
    tenant_id: str = "tenant-a",
    target: str = TARGET,
    planned: tuple[str, ...] = PLANNED,
) -> AuthorizationContext:
    return AuthorizationContext(
        tenant_id=tenant_id,
        engagement_id="engagement-a",
        run_id=run_id,
        job_id=f"job-{run_id}",
        operator_id="operator-a",
        operator_role=OperatorRole.OPERATOR,
        action_kind="engine.execute",
        engine="webforge",
        module_id=module_set_binding(planned),
        requested_target=target,
        resolved_target=target,
        allowed_scope=SCOPE,
        excluded_scope=(),
        scope_policy_version="scope-policy-v1",
        safety_mode=SafetyMode.ACTIVE,
        confirmation_method=ConfirmationMethod.CLI_PROMPT,
        confirmed_by="operator-a",
    )


def _issue_consumed_authorization(
    central_db: Path,
    run_id: str,
    *,
    tenant_id: str = "tenant-a",
    target: str = TARGET,
    planned: tuple[str, ...] = PLANNED,
):
    session = create_db(central_db)
    engine = session.get_bind()
    context = _authorization_context(
        run_id,
        tenant_id=tenant_id,
        target=target,
        planned=planned,
    )
    issued_at = datetime.now(timezone.utc)
    confirmation = ActionConfirmation.create(
        job_id=context.job_id,
        target=context.resolved_target,
        engine=context.engine,
        action=context.action_kind,
        issued_at=issued_at,
    )
    issued = issue_authorization(
        session=session,
        context=context,
        confirmation=confirmation,
        now=issued_at,
    )
    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=context,
        boundary="webforge.engine",
        now=issued_at,
    )
    assert consumed.allowed is True
    session.close()
    engine.dispose()
    return consumed.envelope


def _finding(
    finding_id: str,
    title: str,
    target: str,
    *,
    tenant_id: str = "tenant-a",
) -> dict[str, object]:
    return {
        "id": finding_id,
        "tenant_id": tenant_id,
        "title": title,
        "severity": "High",
        "target": target,
        "port": 443,
        "service": "https",
        "module": "fixture-module",
        "description": f"{title} fixture observation",
        "reproduction_steps": ["inspect local fixture"],
        "remediation": "Apply the fixture remediation.",
        "references": ["CWE-000"],
        "confidence": "HIGH",
    }


def _source_run(
    path: Path,
    *,
    run_id: str,
    findings: tuple[dict[str, object], ...],
    tenant_id: str = "tenant-a",
    target: str = TARGET,
    status: str = "completed",
    completed_at: datetime = COMPLETED_AT,
):
    session = create_db(path)
    session.add(
        ScanRunModel(
            id=run_id,
            tenant_id=tenant_id,
            framework="webforge",
            target=target,
            status=status,
            ended_at=completed_at,
        )
    )
    session.commit()
    for finding in findings:
        save_finding(session, finding, run_id=run_id)
    return session


def _manifest(
    *,
    status: str = "completed",
    completed_at: datetime = COMPLETED_AT,
    planned: tuple[str, ...] = PLANNED,
    completed: tuple[str, ...] = PLANNED,
    engine_version: str = "1.0.0",
) -> RunCompletionManifest:
    return RunCompletionManifest(
        planned_capabilities=planned,
        completed_capabilities=completed,
        status=status,
        completed_at=completed_at,
        engine_version=engine_version,
    )


def test_authorized_runs_finalize_to_signed_truth_and_restart_safe_delta(
    tmp_path,
) -> None:
    central_db = tmp_path / "central.db"
    environ = _signer_environment(tmp_path)

    authorization_a = _issue_consumed_authorization(central_db, "run-a")
    source_a = _source_run(
        tmp_path / "source-a.db",
        run_id="run-a",
        findings=(
            _finding("fixed-a", "Exposed Admin", "https://127.0.0.1/admin"),
            _finding("remaining-a", "Missing HSTS", "https://127.0.0.1/"),
        ),
    )
    first = finalize_authorized_run(
        source_a,
        authorization=authorization_a,
        framework="webforge",
        target=TARGET,
        manifest=_manifest(),
        central_db_path=central_db,
        environ=environ,
    )
    assert first.truth.run_id == "run-a:webforge"
    assert first.truth.run_sequence == 1
    assert first.truth.predecessor_run_id == ""
    assert first.truth.coverage_complete is True
    assert first.delta["comparison_state"] == "inconclusive"
    assert first.delta["new"] == []
    assert first.delta["fixed"] == []
    assert first.delta["summary"]["inconclusive"] == 2

    authorization_b = _issue_consumed_authorization(central_db, "run-b")
    source_b = _source_run(
        tmp_path / "source-b.db",
        run_id="run-b",
        findings=(
            _finding("remaining-b", "Missing HSTS", "https://127.0.0.1/"),
            _finding("new-b", "Default Credential", "https://127.0.0.1/login"),
        ),
        completed_at=COMPLETED_AT + timedelta(minutes=1),
    )
    manifest_b = _manifest(completed_at=COMPLETED_AT + timedelta(minutes=1))
    second = finalize_authorized_run(
        source_b,
        authorization=authorization_b,
        framework="webforge",
        target=TARGET,
        manifest=manifest_b,
        central_db_path=central_db,
        environ=environ,
    )
    assert second.truth.run_sequence == 2
    assert second.truth.predecessor_run_id == "run-a:webforge"
    assert second.delta["comparison_state"] == "comparable"
    assert [row["title"] for row in second.delta["new"]] == ["Default Credential"]
    assert [row["title"] for row in second.delta["fixed"]] == ["Exposed Admin"]
    assert [row["title"] for row in second.delta["remaining"]] == ["Missing HSTS"]

    restarted = load_configured_persisted_delta(
        tenant_id="tenant-a",
        current_run_id="run-b:webforge",
        central_db_path=central_db,
        environ=environ,
    )
    assert restarted == second.delta

    retry = finalize_authorized_run(
        source_b,
        authorization=authorization_b,
        framework="webforge",
        target=TARGET,
        manifest=manifest_b,
        central_db_path=central_db,
        environ=environ,
    )
    assert retry.truth == second.truth
    assert retry.delta == second.delta

    central = create_db(central_db)
    central_engine = central.get_bind()
    assert central.query(RunCollectionTruthModel).count() == 2
    assert central.query(PersistedFindingDeltaModel).count() == 2
    assert central.query(FindingRunMembershipModel).count() == 4
    central.close()
    central_engine.dispose()
    for source in (source_a, source_b):
        engine = source.get_bind()
        source.close()
        engine.dispose()


def test_finalization_rejects_replay_conflicts_and_forged_delta(tmp_path) -> None:
    central_db = tmp_path / "central.db"
    environ = _signer_environment(tmp_path)
    authorization = _issue_consumed_authorization(central_db, "run-a")
    source = _source_run(
        tmp_path / "source.db",
        run_id="run-a",
        findings=(_finding("finding-a", "Missing HSTS", "https://127.0.0.1/"),),
    )
    finalized = finalize_authorized_run(
        source,
        authorization=authorization,
        framework="webforge",
        target=TARGET,
        manifest=_manifest(),
        central_db_path=central_db,
        environ=environ,
    )

    with pytest.raises(RunFinalizationError, match="run_finalization_replay_conflict"):
        finalize_authorized_run(
            source,
            authorization=authorization,
            framework="webforge",
            target=TARGET,
            manifest=_manifest(engine_version="2.0.0"),
            central_db_path=central_db,
            environ=environ,
        )

    from common.db import append_persisted_finding_delta

    central = create_db(central_db)
    forged = dict(finalized.delta)
    forged["summary"] = {"new": 0, "fixed": 1, "remaining": 0, "inconclusive": 0}
    forged["fixed"] = [{"id": "invented", "title": "Invented fixed finding"}]
    with pytest.raises(ValueError, match="does not match signed run truth"):
        append_persisted_finding_delta(
            central,
            tenant_id="tenant-a",
            report=forged,
            authorization_decision_id=authorization.decision_id,
            authorization_binding=authorization.binding_digest,
            policy=load_managed_run_truth_signer(environ).policy,
        )
    central_engine = central.get_bind()
    central.close()
    central_engine.dispose()
    source_engine = source.get_bind()
    source.close()
    source_engine.dispose()


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("missing", "run_truth_issuer_config_missing"),
        ("wrong_key", "run_truth_signing_key_mismatch"),
        ("world_readable", "run_truth_private_key_permissions_invalid"),
        ("symlink", "run_truth_private_key_permissions_invalid"),
        ("hardlink", "run_truth_private_key_permissions_invalid"),
    ],
)
def test_managed_signer_configuration_and_key_boundary_fail_closed(
    tmp_path,
    mutation: str,
    reason: str,
) -> None:
    environ = _signer_environment(tmp_path)
    key_path = Path(environ[RUN_TRUTH_PRIVATE_KEY_FILE_ENV])
    if mutation == "missing":
        environ.pop(RUN_TRUTH_ISSUER_ID_ENV)
    elif mutation == "wrong_key":
        other = Ed25519PrivateKey.generate()
        key_path.write_bytes(base64.b64encode(other.private_bytes_raw()))
    elif mutation == "world_readable":
        key_path.chmod(0o644)
    elif mutation == "symlink":
        link = tmp_path / "signing-link.key"
        link.symlink_to(key_path)
        environ[RUN_TRUTH_PRIVATE_KEY_FILE_ENV] = str(link)
    elif mutation == "hardlink":
        os.link(key_path, tmp_path / "signing-hardlink.key")

    with pytest.raises(RunFinalizationError, match=reason):
        load_managed_run_truth_signer(environ)


@pytest.mark.parametrize(
    ("framework", "target", "planned", "reason"),
    [
        ("netforge", TARGET, PLANNED, "run_finalization_engine_mismatch"),
        ("webforge", "http://127.0.0.1:9090/other", PLANNED, "run_finalization_target_mismatch"),
        ("webforge", TARGET, ("different-module",), "run_finalization_coverage_mismatch"),
    ],
)
def test_finalization_rejects_wrong_authorization_bindings(
    tmp_path,
    framework: str,
    target: str,
    planned: tuple[str, ...],
    reason: str,
) -> None:
    central_db = tmp_path / "central.db"
    environ = _signer_environment(tmp_path)
    authorization = _issue_consumed_authorization(central_db, "run-a")
    source = _source_run(tmp_path / "source.db", run_id="run-a", findings=())
    with pytest.raises(RunFinalizationError, match=reason):
        finalize_authorized_run(
            source,
            authorization=authorization,
            framework=framework,
            target=target,
            manifest=_manifest(planned=planned, completed=planned),
            central_db_path=central_db,
            environ=environ,
        )
    engine = source.get_bind()
    source.close()
    engine.dispose()


def test_source_completion_identity_is_required(tmp_path) -> None:
    central_db = tmp_path / "central.db"
    environ = _signer_environment(tmp_path)
    authorization = _issue_consumed_authorization(central_db, "run-a")
    source = _source_run(
        tmp_path / "source.db",
        run_id="different-run",
        findings=(),
    )
    with pytest.raises(RunFinalizationError, match="run_completion_record_missing"):
        finalize_authorized_run(
            source,
            authorization=authorization,
            framework="webforge",
            target=TARGET,
            manifest=_manifest(),
            central_db_path=central_db,
            environ=environ,
        )
    engine = source.get_bind()
    source.close()
    engine.dispose()
