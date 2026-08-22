from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from common.run_truth import (
    RUN_TRUTH_POLICY,
    RunCollectionStatus,
    RunCollectionTruth,
    RunTruthPolicy,
    persisted_run_comparability,
    run_collection_truth_attestation_payload,
    validate_run_collection_truth,
)


def _policy_and_signer() -> tuple[RunTruthPolicy, Ed25519PrivateKey]:
    signer = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(
        signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    return replace(RUN_TRUTH_POLICY, issuer_public_key=public_key), signer


def _signed_truth(
    run_id: str,
    *,
    status: RunCollectionStatus = RunCollectionStatus.SUCCESS,
    coverage_identity: str = "sha256:" + "c" * 64,
    coverage_complete: bool = True,
    tenant_id: str = "fixture-tenant",
    framework: str = "webforge",
    scope_binding: str = "sha256:" + "a" * 64,
    target_binding: str = "sha256:" + "b" * 64,
    predecessor_run_id: str = "",
    run_sequence: int = 1,
    finding_set_identity: str | None = None,
    policy: RunTruthPolicy,
    signer: Ed25519PrivateKey,
) -> RunCollectionTruth:
    if finding_set_identity is None:
        material = json.dumps(
            {
                "schema": "forge-finding-run-set-v1",
                "tenant_id": tenant_id,
                "run_id": run_id,
                "members": [],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        finding_set_identity = "sha256:" + hashlib.sha256(material).hexdigest()
    record = RunCollectionTruth(
        run_id=run_id,
        authorization_run_id=f"auth-{run_id}",
        job_id=f"job-{run_id}",
        tenant_id=tenant_id,
        framework=framework,
        scope_binding=scope_binding,
        target_binding=target_binding,
        collection_status=status,
        coverage_complete=coverage_complete,
        coverage_identity=coverage_identity,
        finding_set_identity=finding_set_identity,
        predecessor_run_id=predecessor_run_id,
        run_sequence=run_sequence,
        completed_at=f"2026-08-02T00:00:0{min(run_sequence, 9)}+00:00",
        authorization_decision_id=f"decision-{run_id}",
        authorization_binding="sha256:" + "e" * 64,
        authority_id="fixture-run-authority",
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        issuer_id=policy.issuer_id,
    )
    signature = signer.sign(run_collection_truth_attestation_payload(record))
    return replace(record, attestation=base64.b64encode(signature).decode("ascii"))


def test_signed_matching_persisted_runs_are_comparable() -> None:
    policy, signer = _policy_and_signer()
    previous = _signed_truth("run-a", policy=policy, signer=signer)
    current = _signed_truth(
        "run-b",
        predecessor_run_id="run-a",
        run_sequence=2,
        policy=policy,
        signer=signer,
    )

    assert validate_run_collection_truth(current, policy=policy) == (True, "")
    assert persisted_run_comparability(previous, current, policy=policy) == (
        True,
        "",
    )


def test_unsigned_or_mutated_run_truth_fails_closed() -> None:
    policy, signer = _policy_and_signer()
    signed = _signed_truth("run-a", policy=policy, signer=signer)

    assert validate_run_collection_truth(
        replace(signed, attestation=""),
        policy=policy,
    ) == (False, "run_attestation_binding_mismatch")
    assert validate_run_collection_truth(
        replace(signed, coverage_complete=False),
        policy=policy,
    ) == (False, "run_attestation_invalid")


def test_failed_or_mismatched_coverage_is_not_comparable() -> None:
    policy, signer = _policy_and_signer()
    previous = _signed_truth("run-a", policy=policy, signer=signer)
    failed = _signed_truth(
        "run-b",
        status=RunCollectionStatus.FAILED,
        predecessor_run_id="run-a",
        run_sequence=2,
        policy=policy,
        signer=signer,
    )
    mismatch = _signed_truth(
        "run-c",
        coverage_identity="sha256:" + "d" * 64,
        predecessor_run_id="run-a",
        run_sequence=2,
        policy=policy,
        signer=signer,
    )

    assert persisted_run_comparability(previous, failed, policy=policy) == (
        False,
        "current_collection_failed",
    )
    assert persisted_run_comparability(previous, mismatch, policy=policy) == (
        False,
        "persisted_coverage_identity_mismatch",
    )



def test_persisted_run_truth_is_validated_append_only_and_idempotent(
    tmp_path,
    monkeypatch,
) -> None:
    import common.run_truth as run_truth_module
    from common.db import (
        RunCollectionTruthModel,
        append_run_collection_truth,
        create_db,
        load_run_collection_truth,
    )
    from sqlalchemy import text
    from sqlalchemy.exc import DatabaseError

    policy, signer = _policy_and_signer()
    monkeypatch.setattr(run_truth_module, "RUN_TRUTH_POLICY", policy)
    record = _signed_truth("run-a", policy=policy, signer=signer)
    session = create_db(tmp_path / "persisted-run-truth.db")

    first = append_run_collection_truth(session, record)
    recorded_at = first.recorded_at
    duplicate = append_run_collection_truth(session, record)

    assert duplicate.sequence == first.sequence
    assert duplicate.recorded_at == recorded_at
    assert session.query(RunCollectionTruthModel).count() == 1
    assert load_run_collection_truth(
        session, "run-a", tenant_id="fixture-tenant"
    ) == record

    conflicting = _signed_truth(
        "run-a",
        coverage_identity="sha256:" + "d" * 64,
        policy=policy,
        signer=signer,
    )
    with pytest.raises(ValueError, match="conflicting persisted run truth"):
        append_run_collection_truth(session, conflicting)
    assert load_run_collection_truth(
        session, "run-a", tenant_id="fixture-tenant"
    ) == record

    with pytest.raises(DatabaseError, match="security records are append-only"):
        session.execute(
            text(
                "UPDATE run_collection_truth "
                "SET coverage_complete=0 WHERE run_id='run-a'"
            )
        )
        session.commit()
    session.rollback()
    with pytest.raises(DatabaseError, match="security records are append-only"):
        session.execute(
            text("DELETE FROM run_collection_truth WHERE run_id='run-a'")
        )
        session.commit()
    session.rollback()
    assert load_run_collection_truth(
        session, "run-a", tenant_id="fixture-tenant"
    ) == record
    session.close()


def test_persisted_run_truth_rejects_wrong_policy_and_malformed_raw_rows(
    tmp_path,
    monkeypatch,
) -> None:
    import common.run_truth as run_truth_module
    from common.db import (
        PersistedRunTruthValidationError,
        append_run_collection_truth,
        create_db,
        load_run_collection_truth,
    )
    from sqlalchemy import text

    configured_policy, _ = _policy_and_signer()
    attacker_policy, attacker_signer = _policy_and_signer()
    monkeypatch.setattr(
        run_truth_module,
        "RUN_TRUTH_POLICY",
        configured_policy,
    )
    session = create_db(tmp_path / "invalid-run-truth.db")

    attacker_record = _signed_truth(
        "attacker-run",
        policy=attacker_policy,
        signer=attacker_signer,
    )
    with pytest.raises(ValueError, match="run_attestation_invalid"):
        append_run_collection_truth(session, attacker_record)

    session.execute(
        text(
            "INSERT INTO run_collection_truth ("
            "run_id, authorization_run_id, job_id, tenant_id, framework, "
            "scope_binding, target_binding, "
            "collection_status, coverage_complete, coverage_identity, "
            "finding_set_identity, predecessor_run_id, run_sequence, completed_at, "
            "authorization_decision_id, authorization_binding, "
            "authority_id, policy_id, policy_version, issuer_id, "
            "attestation, recorded_at) VALUES ("
            ":run_id, :authorization_run_id, :job_id, :tenant_id, :framework, :scope_binding, "
            ":target_binding, :collection_status, :coverage_complete, "
            ":coverage_identity, :finding_set_identity, :predecessor_run_id, "
            ":run_sequence, :completed_at, :authorization_decision_id, "
            ":authorization_binding, :authority_id, :policy_id, "
            ":policy_version, :issuer_id, :attestation, :recorded_at)"
        ),
        {
            "run_id": "malformed-run",
            "authorization_run_id": "auth-malformed-run",
            "job_id": "job-malformed-run",
            "tenant_id": "fixture-tenant",
            "framework": "webforge",
            "scope_binding": "sha256:" + "a" * 64,
            "target_binding": "sha256:" + "b" * 64,
            "collection_status": "success",
            "coverage_complete": 1,
            "coverage_identity": "sha256:" + "c" * 64,
            "finding_set_identity": _signed_truth(
                "malformed-run",
                policy=configured_policy,
                signer=attacker_signer,
            ).finding_set_identity,
            "predecessor_run_id": "",
            "run_sequence": 1,
            "completed_at": "2026-08-02T00:00:01+00:00",
            "authorization_decision_id": "decision-malformed-run",
            "authorization_binding": "sha256:" + "e" * 64,
            "authority_id": "fixture-run-authority",
            "policy_id": configured_policy.policy_id,
            "policy_version": configured_policy.policy_version,
            "issuer_id": configured_policy.issuer_id,
            "attestation": "not-a-signature",
            "recorded_at": datetime.now(timezone.utc),
        },
    )
    session.commit()
    with pytest.raises(
        PersistedRunTruthValidationError,
        match="run_attestation_invalid",
    ):
        load_run_collection_truth(
            session, "malformed-run", tenant_id="fixture-tenant"
        )
    session.close()


def test_missing_persisted_run_truth_reason_names_the_missing_side() -> None:
    policy, signer = _policy_and_signer()
    current = _signed_truth("run-b", policy=policy, signer=signer)

    assert persisted_run_comparability(None, current, policy=policy) == (
        False,
        "previous_persisted_run_truth_missing",
    )
    assert persisted_run_comparability(current, None, policy=policy) == (
        False,
        "current_persisted_run_truth_missing",
    )


def test_concurrent_exact_run_truth_appends_converge_on_one_row(
    tmp_path,
    monkeypatch,
) -> None:
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import common.run_truth as run_truth_module
    from common.db import (
        RunCollectionTruthModel,
        append_run_collection_truth,
        create_db,
    )

    policy, signer = _policy_and_signer()
    monkeypatch.setattr(run_truth_module, "RUN_TRUTH_POLICY", policy)
    record = _signed_truth("run-concurrent", policy=policy, signer=signer)
    db_path = tmp_path / "concurrent-run-truth.db"
    initial = create_db(db_path)
    initial_engine = initial.get_bind()
    initial.close()
    initial_engine.dispose()

    worker_count = 4
    start = threading.Barrier(worker_count)

    def append_once() -> int:
        session = create_db(db_path)
        try:
            start.wait(timeout=10)
            return int(append_run_collection_truth(session, record).sequence)
        finally:
            engine = session.get_bind()
            session.close()
            engine.dispose()

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        sequences = list(executor.map(lambda _: append_once(), range(worker_count)))

    assert sequences == [1] * worker_count
    final = create_db(db_path)
    final_engine = final.get_bind()
    assert final.query(RunCollectionTruthModel).count() == 1
    final.close()
    final_engine.dispose()


@pytest.mark.parametrize(
    ("current_overrides", "reason"),
    [
        ({"tenant_id": "tenant-b"}, "persisted_tenant_mismatch"),
        ({"framework": "netforge"}, "persisted_framework_mismatch"),
        ({"scope_binding": "sha256:" + "1" * 64}, "persisted_scope_binding_mismatch"),
        ({"target_binding": "sha256:" + "2" * 64}, "persisted_target_binding_mismatch"),
        ({"coverage_identity": "sha256:" + "3" * 64}, "persisted_coverage_identity_mismatch"),
    ],
)
def test_each_signed_series_binding_mismatch_is_incomparable(
    current_overrides: dict[str, str],
    reason: str,
) -> None:
    policy, signer = _policy_and_signer()
    previous = _signed_truth("run-a", policy=policy, signer=signer)
    current = _signed_truth(
        "run-b",
        predecessor_run_id="run-a",
        run_sequence=2,
        policy=policy,
        signer=signer,
        **current_overrides,
    )
    assert persisted_run_comparability(previous, current, policy=policy) == (
        False,
        reason,
    )


def test_reverse_gap_and_wrong_predecessor_are_rejected() -> None:
    policy, signer = _policy_and_signer()
    first = _signed_truth("run-a", policy=policy, signer=signer)
    reverse_previous = _signed_truth(
        "run-b",
        predecessor_run_id="run-x",
        run_sequence=2,
        policy=policy,
        signer=signer,
    )
    gap = _signed_truth(
        "run-c",
        predecessor_run_id="run-a",
        run_sequence=3,
        policy=policy,
        signer=signer,
    )
    wrong_predecessor = _signed_truth(
        "run-d",
        predecessor_run_id="run-other",
        run_sequence=2,
        policy=policy,
        signer=signer,
    )

    assert persisted_run_comparability(
        reverse_previous, first, policy=policy
    ) == (False, "signed_run_order_invalid")
    assert persisted_run_comparability(first, gap, policy=policy) == (
        False,
        "signed_run_sequence_gap",
    )
    assert persisted_run_comparability(
        first, wrong_predecessor, policy=policy
    ) == (False, "signed_predecessor_mismatch")


def _persisted_finding(
    finding_id: str,
    *,
    tenant_id: str,
    description: str,
) -> dict[str, object]:
    return {
        "id": finding_id,
        "tenant_id": tenant_id,
        "title": "Missing HSTS",
        "severity": "High",
        "target": "https://127.0.0.1/",
        "port": 443,
        "service": "https",
        "module": "fixture-module",
        "description": description,
        "reproduction_steps": ["inspect local fixture"],
        "remediation": "Enable HSTS.",
        "references": ["CWE-319"],
        "confidence": "HIGH",
    }


def test_a_b_c_snapshots_remain_historical_and_tenant_isolated(tmp_path) -> None:
    from common.db import list_findings_for_run, save_finding, create_db

    session = create_db(tmp_path / "historical-snapshots.db")
    save_finding(
        session,
        _persisted_finding(
            "finding-a",
            tenant_id="tenant-a",
            description="run A observation",
        ),
        run_id="run-a",
        allow_legacy_compat=True,
    )
    save_finding(
        session,
        _persisted_finding(
            "finding-b",
            tenant_id="tenant-a",
            description="run B observation",
        ),
        run_id="run-b",
        allow_legacy_compat=True,
    )
    save_finding(
        session,
        _persisted_finding(
            "finding-c",
            tenant_id="tenant-a",
            description="run C observation",
        ),
        run_id="run-c",
        allow_legacy_compat=True,
    )
    save_finding(
        session,
        _persisted_finding(
            "finding-tenant-b",
            tenant_id="tenant-b",
            description="tenant B observation",
        ),
        run_id="run-a",
        allow_legacy_compat=True,
    )

    assert list_findings_for_run(
        session, "run-a", tenant_id="tenant-a"
    )[0]["description"] == "run A observation"
    assert list_findings_for_run(
        session, "run-b", tenant_id="tenant-a"
    )[0]["description"] == "run B observation"
    assert list_findings_for_run(
        session, "run-c", tenant_id="tenant-a"
    )[0]["description"] == "run C observation"
    assert list_findings_for_run(
        session, "run-a", tenant_id="tenant-b"
    )[0]["description"] == "tenant B observation"

    with pytest.raises(ValueError, match="belongs to another tenant"):
        save_finding(
            session,
            {
                **_persisted_finding(
                    "finding-a",
                    tenant_id="tenant-b",
                    description="cross-tenant id collision",
                ),
                "title": "Different finding",
            },
            run_id="run-b",
            allow_legacy_compat=True,
        )
    session.close()


def test_post_finalization_membership_mutation_is_rejected(
    tmp_path,
    monkeypatch,
) -> None:
    import common.run_truth as run_truth_module
    from common.db import (
        append_run_collection_truth,
        create_db,
        finding_set_identity,
        save_finding,
    )
    from sqlalchemy import text
    from sqlalchemy.exc import DatabaseError

    policy, signer = _policy_and_signer()
    monkeypatch.setattr(run_truth_module, "RUN_TRUTH_POLICY", policy)
    session = create_db(tmp_path / "finalized-membership.db")
    save_finding(
        session,
        _persisted_finding(
            "finding-a",
            tenant_id="tenant-a",
            description="finalized observation",
        ),
        run_id="run-a",
        allow_legacy_compat=True,
    )
    record = _signed_truth(
        "run-a",
        tenant_id="tenant-a",
        finding_set_identity=finding_set_identity(
            session, tenant_id="tenant-a", run_id="run-a"
        ),
        policy=policy,
        signer=signer,
    )
    append_run_collection_truth(session, record)

    with pytest.raises(ValueError, match="run membership is finalized"):
        save_finding(
            session,
            {
                **_persisted_finding(
                    "finding-b",
                    tenant_id="tenant-a",
                    description="late observation",
                ),
                "title": "Late finding",
            },
            run_id="run-a",
            allow_legacy_compat=True,
        )
    with pytest.raises(DatabaseError, match="security records are append-only"):
        session.execute(
            text(
                "UPDATE finding_run_membership SET finding_id='mutated' "
                "WHERE tenant_id='tenant-a' AND run_id='run-a'"
            )
        )
        session.commit()
    session.rollback()
    session.close()


def test_concurrent_exact_and_conflicting_snapshot_appends(tmp_path) -> None:
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from common.db import (
        FindingRunMembershipModel,
        append_finding_run_snapshot,
        create_db,
    )
    from sqlalchemy import text

    db_path = tmp_path / "concurrent-snapshots.db"
    initial = create_db(db_path)
    initial_engine = initial.get_bind()
    initial.close()
    initial_engine.dispose()
    exact_snapshot = {
        "id": "finding-a",
        "tenant_id": "tenant-a",
        "title": "Fixture finding",
        "target": "fixture-target",
        "port": 443,
        "description": "exact",
        "dedup_key": "a" * 64,
    }
    worker_count = 6
    barrier = threading.Barrier(worker_count)

    def append_exact(_: int) -> int:
        session = create_db(db_path)
        engine = session.get_bind()
        try:
            session.execute(text("SELECT COUNT(*) FROM finding_run_membership"))
            barrier.wait(timeout=10)
            return int(
                append_finding_run_snapshot(
                    session,
                    tenant_id="tenant-a",
                    run_id="run-a",
                    snapshot=exact_snapshot,
                ).sequence
            )
        finally:
            session.close()
            engine.dispose()

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        assert list(executor.map(append_exact, range(worker_count))) == [1] * worker_count

    conflict_barrier = threading.Barrier(2)

    def append_conflict(index: int) -> str:
        session = create_db(db_path)
        engine = session.get_bind()
        try:
            conflict_barrier.wait(timeout=10)
            append_finding_run_snapshot(
                session,
                tenant_id="tenant-a",
                run_id="run-conflict",
                snapshot={
                    **exact_snapshot,
                    "id": f"conflict-{index}",
                    "description": f"conflict-{index}",
                },
            )
            return "stored"
        except ValueError:
            return "conflict"
        finally:
            session.close()
            engine.dispose()

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(append_conflict, range(2)))
    assert sorted(outcomes) == ["conflict", "stored"]
    final = create_db(db_path)
    final_engine = final.get_bind()
    assert final.query(FindingRunMembershipModel).filter_by(run_id="run-a").count() == 1
    assert final.query(FindingRunMembershipModel).filter_by(run_id="run-conflict").count() == 1
    final.close()
    final_engine.dispose()


def test_concurrent_pretransaction_truth_exact_and_conflicting_writers(
    tmp_path,
    monkeypatch,
) -> None:
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import common.run_truth as run_truth_module
    from common.db import (
        RunCollectionTruthModel,
        ScanRunModel,
        append_run_collection_truth,
        create_db,
    )
    from sqlalchemy import text

    policy, signer = _policy_and_signer()
    monkeypatch.setattr(run_truth_module, "RUN_TRUTH_POLICY", policy)
    record = _signed_truth("run-exact", policy=policy, signer=signer)
    db_path = tmp_path / "pretransaction-truth.db"
    initial = create_db(db_path)
    initial_engine = initial.get_bind()
    initial.close()
    initial_engine.dispose()
    worker_count = 6
    barrier = threading.Barrier(worker_count)

    def append_exact(index: int) -> int:
        session = create_db(db_path)
        engine = session.get_bind()
        try:
            session.execute(text("SELECT COUNT(*) FROM run_collection_truth"))
            session.add(
                ScanRunModel(
                    id=f"unrelated-{index}",
                    tenant_id="fixture-tenant",
                    framework="webforge",
                    target="fixture-target",
                )
            )
            barrier.wait(timeout=10)
            return int(append_run_collection_truth(session, record).sequence)
        finally:
            session.close()
            engine.dispose()

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        assert list(executor.map(append_exact, range(worker_count))) == [1] * worker_count

    conflicting_records = (
        _signed_truth(
            "run-conflict",
            predecessor_run_id="run-exact",
            run_sequence=2,
            policy=policy,
            signer=signer,
        ),
        _signed_truth(
            "run-conflict",
            coverage_identity="sha256:" + "9" * 64,
            predecessor_run_id="run-exact",
            run_sequence=2,
            policy=policy,
            signer=signer,
        ),
    )
    conflict_barrier = threading.Barrier(2)

    def append_conflicting(index: int) -> str:
        session = create_db(db_path)
        engine = session.get_bind()
        try:
            session.execute(text("SELECT COUNT(*) FROM run_collection_truth"))
            conflict_barrier.wait(timeout=10)
            append_run_collection_truth(session, conflicting_records[index])
            return "stored"
        except ValueError:
            return "conflict"
        finally:
            session.close()
            engine.dispose()

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(append_conflicting, range(2)))
    assert sorted(outcomes) == ["conflict", "stored"]
    final = create_db(db_path)
    final_engine = final.get_bind()
    assert final.query(RunCollectionTruthModel).filter_by(run_id="run-exact").count() == 1
    assert final.query(RunCollectionTruthModel).filter_by(run_id="run-conflict").count() == 1
    assert final.query(ScanRunModel).filter(
        ScanRunModel.id.like("unrelated-%")
    ).count() == worker_count
    final.close()
    final_engine.dispose()


def test_multi_finding_legacy_membership_migration_is_stable_on_reopen(
    tmp_path,
) -> None:
    from common.db import FindingRunMembershipModel, create_db, save_finding
    from sqlalchemy import text

    db_path = tmp_path / "legacy-membership.db"
    source = create_db(db_path)
    for finding_id, title, target in (
        ("legacy-a", "Legacy A", "fixture-a"),
        ("legacy-b", "Legacy B", "fixture-b"),
    ):
        save_finding(
            source,
            {
                **_persisted_finding(
                    finding_id,
                    tenant_id="tenant-a",
                    description=f"{title} description",
                ),
                "title": title,
                "target": target,
            },
            run_id="legacy-run",
            allow_legacy_compat=True,
        )
    source.execute(text("DROP TRIGGER finding_run_membership_no_update"))
    source.execute(text("DROP TRIGGER finding_run_membership_no_delete"))
    source.execute(text("DROP TRIGGER finding_run_membership_finalized_guard"))
    source.execute(text("DELETE FROM finding_run_membership"))
    source.execute(
        text(
            "DELETE FROM schema_migrations "
            "WHERE version='wp006_finding_run_membership_v1'"
        )
    )
    source.commit()
    source_engine = source.get_bind()
    source.close()
    source_engine.dispose()

    migrated = create_db(db_path)
    first_state = [
        (
            row.finding_id,
            row.dedup_key,
            row.snapshot_json,
            row.snapshot_identity,
            row.recorded_at,
        )
        for row in migrated.query(FindingRunMembershipModel)
        .filter_by(tenant_id="tenant-a", run_id="legacy-run")
        .order_by(FindingRunMembershipModel.dedup_key)
        .all()
    ]
    assert len(first_state) == 2
    assert all(key != "<redacted>" and len(key) == 64 for _, key, *_ in first_state)
    migrated_engine = migrated.get_bind()
    migrated.close()
    migrated_engine.dispose()

    reopened = create_db(db_path)
    second_state = [
        (
            row.finding_id,
            row.dedup_key,
            row.snapshot_json,
            row.snapshot_identity,
            row.recorded_at,
        )
        for row in reopened.query(FindingRunMembershipModel)
        .filter_by(tenant_id="tenant-a", run_id="legacy-run")
        .order_by(FindingRunMembershipModel.dedup_key)
        .all()
    ]
    assert second_state == first_state
    reopened_engine = reopened.get_bind()
    reopened.close()
    reopened_engine.dispose()


def test_concurrent_snapshot_reads_observe_only_complete_committed_sets(
    tmp_path,
) -> None:
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    from common.db import (
        append_finding_run_snapshot,
        create_db,
        list_findings_for_run,
    )

    db_path = tmp_path / "snapshot-read-write.db"
    initial = create_db(db_path)
    initial_engine = initial.get_bind()
    initial.close()
    initial_engine.dispose()
    total = 20
    started = threading.Barrier(2)
    finished = threading.Event()

    def writer() -> None:
        session = create_db(db_path)
        engine = session.get_bind()
        try:
            started.wait(timeout=10)
            for index in range(total):
                append_finding_run_snapshot(
                    session,
                    tenant_id="tenant-a",
                    run_id="run-a",
                    snapshot={
                        "id": f"finding-{index}",
                        "tenant_id": "tenant-a",
                        "title": f"Finding {index}",
                        "target": "fixture-target",
                        "dedup_key": f"{index:064x}",
                    },
                )
                time.sleep(0.001)
        finally:
            finished.set()
            session.close()
            engine.dispose()

    def reader() -> list[int]:
        session = create_db(db_path)
        engine = session.get_bind()
        counts: list[int] = []
        try:
            started.wait(timeout=10)
            while not finished.is_set() or not counts or counts[-1] < total:
                rows = list_findings_for_run(
                    session,
                    "run-a",
                    tenant_id="tenant-a",
                )
                keys = [str(row["dedup_key"]) for row in rows]
                assert len(keys) == len(set(keys))
                assert all(row["tenant_id"] == "tenant-a" for row in rows)
                counts.append(len(rows))
                session.rollback()
                time.sleep(0.001)
            return counts
        finally:
            session.close()
            engine.dispose()

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future = executor.submit(writer)
        reader_future = executor.submit(reader)
        writer_future.result(timeout=20)
        observed = reader_future.result(timeout=20)
    assert observed == sorted(observed)
    assert observed[-1] == total
