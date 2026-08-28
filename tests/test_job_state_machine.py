"""Deterministic contract tests for the Task-103 durable job authority."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import sqlite3
import threading
import time

import pytest

from common.job_state import (
    IdempotencyConflict,
    InvalidTransition,
    JobState,
    JobStateService,
    LeaseError,
    LeaseUnavailable,
    ObservationReceipt,
    ProcessIdentity,
    ProcessIdentityError,
    RunTruthReceipt,
    TerminalStateError,
    WorkState,
    allowed_transitions,
    process_identity,
    transition_table,
)


@dataclass
class FakeClock:
    value: float = 1_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class FakeSupervisor:
    """Inert process fixture keyed by complete process identity."""

    def __init__(self, *alive: ProcessIdentity, terminate_stops: bool = True) -> None:
        self.alive = {self._key(identity) for identity in alive}
        self.terminate_stops = terminate_stops
        self.terminated: list[ProcessIdentity] = []
        self.killed: list[ProcessIdentity] = []
        self.paused: list[ProcessIdentity] = []
        self.resumed: list[ProcessIdentity] = []

    @staticmethod
    def _key(identity: ProcessIdentity) -> tuple[int, str, str, str]:
        return (
            identity.pid,
            identity.start_token,
            identity.command_digest,
            identity.boot_id,
        )

    def is_alive(self, identity: ProcessIdentity) -> bool:
        return self._key(identity) in self.alive

    def terminate(self, identity: ProcessIdentity) -> None:
        self.terminated.append(identity)
        if self.terminate_stops:
            self.alive.discard(self._key(identity))

    def kill(self, identity: ProcessIdentity) -> None:
        self.killed.append(identity)
        self.alive.discard(self._key(identity))

    def pause(self, identity: ProcessIdentity) -> None:
        if not self.is_alive(identity):
            raise ProcessLookupError("fixture child is not alive")
        self.paused.append(identity)

    def resume(self, identity: ProcessIdentity) -> None:
        if not self.is_alive(identity):
            raise ProcessLookupError("fixture child is not alive")
        self.resumed.append(identity)

    def discover(self, _launch_nonce: str) -> ProcessIdentity | None:
        return None


def _auth(tenant: str, _job: str, decision: str, action: str) -> bool:
    """Strict fixture authorization: only this tenant's exact pair is valid."""

    return decision == f"decision-{tenant}" and action == f"action-{tenant}"


def _observed(receipt: ObservationReceipt) -> bool:
    """Typed receipt validator used by every state-machine fixture."""

    return (
        receipt.observation_id.startswith("observation-")
        and receipt.artifact_id.startswith("artifact-")
        and receipt.result_ref.startswith("result:")
    )


def _service(
    path: object,
    *,
    clock: FakeClock | None = None,
    process_supervisor: FakeSupervisor | None = None,
) -> JobStateService:
    return JobStateService(
        path,
        clock=clock,
        process_supervisor=process_supervisor,
        authorization_checker=_auth,
        observation_checker=_observed,
    )


def _receipt(
    job: dict[str, object],
    attempt: dict[str, object],
    *,
    tenant: str = "default",
    suffix: str = "one",
) -> ObservationReceipt:
    return ObservationReceipt(
        tenant_id=tenant,
        job_id=str(job["id"]),
        attempt_id=str(attempt["id"]),
        observation_id=f"observation-{suffix}",
        artifact_id=f"artifact-{suffix}",
        result_ref=f"result:{suffix}",
        manifest_digest="sha256:" + "a" * 64,
    )


def _queued_job(
    service: JobStateService,
    *,
    required_work: int = 0,
    max_attempts: int = 1,
    tenant_id: str = "default",
    work_items: tuple[str, ...] | None = None,
) -> dict[str, object]:
    planned = work_items or tuple(
        f"required:{index + 1}" for index in range(required_work)
    )
    return service.create_job(
        {"target": "fixture.local"},
        tenant_id=tenant_id,
        state=JobState.QUEUED,
        required_work=required_work,
        max_attempts=max_attempts,
        authorization_decision_id=f"decision-{tenant_id}",
        authorization_action_id=f"action-{tenant_id}",
        work_items=planned,
    )


def _running_attempt(
    service: JobStateService,
    job_id: str,
    *,
    tenant_id: str = "default",
    worker_id: str = "worker-a",
    lease_seconds: float = 60,
    control_boot_id: str = "fixture-boot",
) -> dict[str, object]:
    leased = service.acquire_lease(
        job_id,
        worker_id,
        tenant_id=tenant_id,
        lease_seconds=lease_seconds,
        control_boot_id=control_boot_id,
    )
    service.start_attempt(
        str(leased["id"]),
        str(leased["lease_token"]),
        tenant_id=tenant_id,
        worker_id=worker_id,
    )
    return leased


def _reserve_process(
    service: JobStateService,
    job: dict[str, object],
    attempt: dict[str, object],
    identity_key: str = "main",
    *,
    tenant_id: str = "default",
) -> dict[str, object]:
    return service.reserve_process(
        str(job["id"]),
        str(attempt["id"]),
        identity_key,
        lease_token=str(attempt["lease_token"]),
        worker_id=str(attempt["worker_id"]),
        control_boot_id=str(attempt["control_boot_id"]),
        tenant_id=tenant_id,
    )


def _register_process(
    service: JobStateService,
    job: dict[str, object],
    attempt: dict[str, object],
    identity: ProcessIdentity,
    identity_key: str = "main",
    *,
    tenant_id: str = "default",
) -> dict[str, object]:
    return service.register_process(
        str(job["id"]),
        str(attempt["id"]),
        identity,
        lease_token=str(attempt["lease_token"]),
        worker_id=str(attempt["worker_id"]),
        control_boot_id=str(attempt["control_boot_id"]),
        identity_key=identity_key,
        tenant_id=tenant_id,
    )


def _record_process_exit(
    service: JobStateService,
    job: dict[str, object],
    attempt: dict[str, object],
    identity: ProcessIdentity,
    *,
    return_code: int | None = None,
    identity_key: str = "main",
    tenant_id: str = "default",
) -> dict[str, object]:
    return service.record_process_exit(
        str(job["id"]),
        str(attempt["id"]),
        identity,
        worker_id=str(attempt["worker_id"]),
        control_boot_id=str(attempt["control_boot_id"]),
        identity_key=identity_key,
        tenant_id=tenant_id,
        return_code=return_code,
    )


def test_transition_table_is_versioned_and_illegal_transition_is_atomic(tmp_path):
    service = _service(tmp_path / "jobs.db")
    table = transition_table()
    assert table["version"]
    assert set(table["states"]) == {state.value for state in JobState}
    assert "completed" in table["terminal_states"]

    job = service.create_job(
        state=JobState.PLANNED,
        authorization_decision_id="decision-default",
        authorization_action_id="action-default",
    )
    before = service.get_job(str(job["id"]))
    events_before = service.list_events(str(job["id"]))
    with pytest.raises(InvalidTransition):
        service.transition(str(job["id"]), JobState.RUNNING)
    assert service.get_job(str(job["id"])) == before
    assert service.list_events(str(job["id"])) == events_before

    service.transition(
        str(job["id"]),
        JobState.QUEUED,
        expected_version=int(job["version"]),
    )
    with pytest.raises(InvalidTransition):
        service.transition(str(job["id"]), JobState.COMPLETED)
    before = service.get_job(str(job["id"]))
    with pytest.raises(InvalidTransition, match="lifecycle operation"):
        service.transition(str(job["id"]), JobState.LEASED)
    assert service.get_job(str(job["id"])) == before


def test_complete_legal_and_illegal_transition_matrix_is_atomic(tmp_path):
    service = _service(tmp_path / "transition-matrix.db")
    expected = {
        "planned": {
            "pending_approval", "queued", "paused", "canceling", "canceled",
        },
        "pending_approval": {"queued", "paused", "canceling", "canceled"},
        "queued": {
            "pending_approval", "leased", "paused", "canceling", "canceled",
        },
        "leased": {
            "pending_approval", "running", "queued", "paused", "canceling",
            "expired", "orphaned", "completed", "partial", "failed",
        },
        "running": {
            "pending_approval", "queued", "paused", "canceling", "completed",
            "partial", "failed", "expired", "orphaned",
        },
        "paused": {
            "planned", "pending_approval", "queued", "leased", "running",
            "canceling", "canceled", "completed", "partial", "failed",
            "orphaned",
        },
        "canceling": {"canceled", "partial", "failed", "orphaned"},
        "expired": {"queued", "canceling", "canceled", "failed"},
        "orphaned": {"queued", "canceling", "canceled", "failed"},
        "canceled": set(),
        "partial": set(),
        "failed": set(),
        "completed": set(),
    }
    assert {
        state: set(targets)
        for state, targets in allowed_transitions().items()
    } == expected

    states = sorted(expected)
    for source in states:
        for target in states:
            job_id = f"matrix-{source}-{target}"
            job = service.create_job(
                job_id=job_id,
                state=JobState.PLANNED,
                authorization_decision_id="decision-default",
                authorization_action_id="action-default",
            )
            attempt_id = f"attempt-{source}-{target}"
            with service._tx():
                service.conn.execute(
                    "UPDATE durable_job_state_jobs SET state=? "
                    "WHERE tenant_id='default' AND id=?",
                    (source, job_id),
                )
                if target == JobState.COMPLETED.value and target in expected[source]:
                    service.conn.execute(
                        """
                        INSERT INTO durable_job_state_attempts(
                            tenant_id,id,job_id,number,idempotency_key,
                            delivery_idempotency_key,run_id,state,worker_id,
                            lease_generation,launch_nonce,control_version
                        ) VALUES(
                            'default',?,?,1,?,?,?,'completed','matrix-worker',
                            1,?,0
                        )
                        """,
                        (
                            attempt_id,
                            job_id,
                            f"lease-{attempt_id}",
                            f"delivery-{attempt_id}",
                            f"run-{attempt_id}",
                            f"launch-{attempt_id}",
                        ),
                    )
                    service.conn.execute(
                        """
                        INSERT INTO durable_job_state_deliveries(
                            tenant_id,attempt_id,job_id,idempotency_key,state,
                            payload_identity,observation_id,artifact_id,
                            result_ref,result_identity,manifest_digest,outcome,
                            work_json,run_truth_json,reserved_at,accepted_at
                        ) VALUES(
                            'default',?,?,?,'accepted',?,?,?,
                            'result:matrix',?,?,'success','[]','[]',?,?
                        )
                        """,
                        (
                            attempt_id,
                            job_id,
                            f"delivery-{attempt_id}",
                            f"sha256:{'b' * 64}",
                            f"observation-{attempt_id}",
                            f"artifact-{attempt_id}",
                            f"sha256:{'b' * 64}",
                            f"sha256:{'a' * 64}",
                            service.clock(),
                            service.clock(),
                        ),
                    )
                    service.conn.execute(
                        """
                        INSERT INTO durable_job_state_terminal_proofs(
                            tenant_id,job_id,attempt_id,proof_type,outcome,
                            proof_identity,coverage_identity,result_ref,recorded_at
                        ) VALUES(
                            'default',?,?,'observation_receipt','success',
                            ?,?,'result:matrix',?
                        )
                        """,
                        (
                            job_id,
                            attempt_id,
                            f"sha256:{'a' * 64}",
                            f"sha256:{'b' * 64}",
                            service.clock(),
                        ),
                    )
            before = service.get_job(job_id)
            events_before = service.list_events(job_id)
            if source == target:
                with service._tx():
                    result = service._transition_tx(
                        "default",
                        job_id,
                        target,
                        expected_version=int(job["version"]),
                        actor="matrix",
                        reason="matrix self replay",
                        idempotency_key=None,
                        data=None,
                        allow_completion=target == JobState.COMPLETED.value,
                    )
                assert result["state"] == source
                assert service.list_events(job_id) == events_before
            elif target in expected[source]:
                with service._tx():
                    result = service._transition_tx(
                        "default",
                        job_id,
                        target,
                        expected_version=int(job["version"]),
                        actor="matrix",
                        reason=f"matrix {source} to {target}",
                        idempotency_key=None,
                        data=None,
                        allow_completion=target == JobState.COMPLETED.value,
                    )
                assert result["state"] == target
                assert len(service.list_events(job_id)) == len(events_before) + 1
            else:
                with pytest.raises(InvalidTransition), service._tx():
                    service._transition_tx(
                        "default",
                        job_id,
                        target,
                        expected_version=int(job["version"]),
                        actor="matrix",
                        reason=f"illegal matrix {source} to {target}",
                        idempotency_key=None,
                        data=None,
                        allow_completion=target == JobState.COMPLETED.value,
                    )
                assert service.get_job(job_id) == before
                assert service.list_events(job_id) == events_before
def test_idempotent_job_transition_result_and_terminal_finish_replay(tmp_path):
    service = _service(tmp_path / "jobs.db")
    job = service.create_job({"target": "fixture"}, idempotency_key="request-1",
                             authorization_decision_id="decision-default",
                             authorization_action_id="action-default")
    replay = service.create_job({"target": "fixture"}, idempotency_key="request-1",
                                authorization_decision_id="decision-default",
                                authorization_action_id="action-default")
    assert replay["id"] == job["id"]
    with pytest.raises(IdempotencyConflict):
        service.create_job({"target": "different"}, idempotency_key="request-1",
                           authorization_decision_id="decision-default",
                           authorization_action_id="action-default")

    service.transition(str(job["id"]), JobState.QUEUED, idempotency_key="enqueue-1")
    service.transition(str(job["id"]), JobState.QUEUED, idempotency_key="enqueue-1")
    attempt = service.acquire_lease(str(job["id"]), "worker-a")
    service.start_attempt(str(attempt["id"]), str(attempt["lease_token"]))
    service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=_receipt(job, attempt, suffix="finish"),
    )
    finished = service.finish_attempt(
        str(attempt["id"]), lease_token=str(attempt["lease_token"])
    )
    assert finished["state"] == JobState.COMPLETED.value
    assert service.get_job(str(job["id"]))["state"] == JobState.COMPLETED.value
    # A crash after the terminal write can redeliver the exact finish safely.
    assert service.finish_attempt(
        str(attempt["id"]), lease_token=str(attempt["lease_token"])
    )["state"] == JobState.COMPLETED.value


def test_reason_codes_and_database_history_guards_are_enforced(tmp_path):
    service = _service(tmp_path / "history-guards.db")
    job = _queued_job(service, required_work=1, work_items=("one",))
    attempt = _running_attempt(service, str(job["id"]))
    service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=_receipt(job, attempt, suffix="history"),
        work=[{"work_key": "one"}],
    )
    service.append_log(
        str(job["id"]),
        "accepted history fixture",
        attempt_id=str(attempt["id"]),
    )
    service.finish_attempt(
        str(attempt["id"]),
        lease_token=str(attempt["lease_token"]),
        terminal_reason="verified result completed",
    )
    stored = service.get_job(str(job["id"]))
    assert stored["terminal_reason_code"] == "verified_result_completed"
    assert service.conn.execute(
        "SELECT status FROM canonical_jobs "
        "WHERE tenant_id='default' AND id=?",
        (job["id"],),
    ).fetchone()[0] == JobState.COMPLETED.value
    assert all(event["reason_code"] for event in service.list_events(str(job["id"])))

    guarded_statements = (
        (
            "UPDATE durable_job_state_jobs SET state='failed' "
            "WHERE tenant_id='default' AND id=?",
            (job["id"],),
        ),
        (
            "UPDATE durable_job_state_work_items SET reason='rewritten' "
            "WHERE tenant_id='default' AND job_id=?",
            (job["id"],),
        ),
        (
            "DELETE FROM durable_job_state_terminal_proofs "
            "WHERE tenant_id='default' AND job_id=?",
            (job["id"],),
        ),
        (
            "DELETE FROM durable_job_state_events "
            "WHERE tenant_id='default' AND job_id=?",
            (job["id"],),
        ),
        (
            "DELETE FROM durable_job_state_logs "
            "WHERE tenant_id='default' AND job_id=?",
            (job["id"],),
        ),
    )
    for statement, parameters in guarded_statements:
        with pytest.raises(sqlite3.IntegrityError), service._tx():
            service.conn.execute(statement, parameters)
    assert service.get_job(str(job["id"])) == stored


def test_lease_replay_recovers_an_active_capability_and_every_attempt_has_a_key(tmp_path):
    service = _service(tmp_path / "jobs.db")
    job = _queued_job(service, max_attempts=2)
    first = service.acquire_lease(
        str(job["id"]),
        "worker-a",
        idempotency_key="lease-request-1",
    )
    replay = service.acquire_lease(
        str(job["id"]),
        "worker-a",
        idempotency_key="lease-request-1",
    )
    assert replay["id"] == first["id"]
    assert replay["lease_token"] == first["lease_token"]
    service.start_attempt(str(replay["id"]), str(replay["lease_token"]))
    service.record_result(
        str(replay["id"]),
        str(replay["lease_token"]),
        delivery_key=str(replay["delivery_idempotency_key"]),
        receipt=_receipt(job, replay, suffix="failure"),
        outcome="failure",
    )
    service.finish_attempt(
        str(first["id"]),
        lease_token=str(first["lease_token"]),
        success=False,
        error_reason="fixture failure",
    )
    second = service.acquire_lease(str(job["id"]), "worker-a")
    attempts = service.list_attempts(str(job["id"]))
    assert second["id"] != first["id"]
    assert all(item["idempotency_key"] for item in attempts)


def test_completed_required_work_requires_an_accepted_evidence_delivery(tmp_path):
    service = _service(tmp_path / "jobs.db")
    job = _queued_job(service, required_work=1, work_items=("required",))
    with pytest.raises(InvalidTransition, match="accepted through a result delivery"):
        service.mark_work(str(job["id"]), "required")
    service.pause_job(str(job["id"]))
    with pytest.raises(TerminalStateError, match="required_work_incomplete"):
        service.complete_job(str(job["id"]))


def test_attempt_cannot_finish_before_it_is_started(tmp_path):
    service = _service(tmp_path / "jobs.db")
    job = _queued_job(service)
    leased = service.acquire_lease(str(job["id"]), "worker-a")
    with pytest.raises(InvalidTransition, match="must be running"):
        service.finish_attempt(
            str(leased["id"]),
            lease_token=str(leased["lease_token"]),
        )
    assert service.get_job(str(job["id"]))["state"] == JobState.LEASED.value
    assert service.list_attempts(str(job["id"]))[0]["started_at"] is None


def test_concurrent_lease_acquisition_has_one_owner_and_one_attempt(tmp_path):
    path = tmp_path / "jobs.db"
    first = _service(path)
    second = _service(path)
    job = _queued_job(first)
    barrier = threading.Barrier(2)

    def acquire(service: JobStateService, worker: str) -> object:
        barrier.wait()
        try:
            return service.acquire_lease(str(job["id"]), worker)
        except LeaseUnavailable:
            return "unavailable"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda args: acquire(*args), ((first, "a"), (second, "b"))))
    successful = [item for item in outcomes if isinstance(item, dict)]
    assert len(successful) == 1
    assert outcomes.count("unavailable") == 1
    assert len(first.list_attempts(str(job["id"]))) == 1


def test_duplicate_result_and_observation_delivery_do_not_duplicate_work(tmp_path):
    service = _service(tmp_path / "jobs.db")
    job = _queued_job(service, required_work=1, work_items=("route:/health",))
    attempt = _running_attempt(service, str(job["id"]))
    work = [{"work_key": "route:/health", "observation_id": "observation-1"}]
    receipt = _receipt(job, attempt, suffix="one")
    accepted = service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=receipt,
        work=work,
    )
    assert accepted["duplicate"] is False
    assert service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=receipt,
        work=work,
    )["duplicate"] is True
    with pytest.raises(IdempotencyConflict):
        service.record_result(
            str(attempt["id"]),
            str(attempt["lease_token"]),
            delivery_key=str(attempt["delivery_idempotency_key"]),
            receipt=_receipt(job, attempt, suffix="different"),
            work=work,
        )
    with pytest.raises(IdempotencyConflict):
        service.record_result(
            str(attempt["id"]),
            str(attempt["lease_token"]),
            delivery_key="delivery-wrong",
            receipt=receipt,
            work=work,
        )

    service.finish_attempt(str(attempt["id"]), lease_token=str(attempt["lease_token"]))
    # Exact redelivery after terminal state uses the stored token digest only
    # for replay authentication; it cannot create another observation.
    assert service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=receipt,
        work=work,
    )["duplicate"] is True
    assert len(service.coverage_snapshot(str(job["id"]))["items"]) == 1
    assert sum(
        event["event_type"] == "result_accepted"
        for event in service.list_events(str(job["id"]))
    ) == 1


def test_signed_run_truth_is_attempt_bound_idempotent_and_required_for_completion(
    tmp_path,
    monkeypatch,
):
    import base64
    from dataclasses import replace

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    import common.run_truth as run_truth_module
    from common.db import (
        append_run_collection_truth,
        create_db,
        finding_set_identity,
    )
    from common.run_truth import (
        RUN_TRUTH_POLICY,
        RunCollectionStatus,
        RunCollectionTruth,
        run_collection_truth_attestation_payload,
    )

    path = tmp_path / "run-truth.db"
    service = _service(path)
    job = service.create_job(
        {"target": "fixture.local", "dry_run": False},
        job_id="run-truth-job",
        run_id="authorization-run",
        job_kind="webforge",
        state=JobState.QUEUED,
        authorization_decision_id="decision-default",
        authorization_action_id="action-default",
        authorization_bindings=(
            {
                "authorization_decision_id": "decision-default",
                "authorization_action_id": "action-default",
                "framework": "webforge",
            },
        ),
        work_items=("webforge",),
    )
    attempt = _running_attempt(service, str(job["id"]))
    signer = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(
        signer.public_key().public_bytes_raw()
    ).decode("ascii")
    policy = replace(RUN_TRUTH_POLICY, issuer_public_key=public_key)
    monkeypatch.setattr(run_truth_module, "RUN_TRUTH_POLICY", policy)
    session = create_db(path)
    try:
        record = RunCollectionTruth(
            run_id="authorization-run:webforge",
            authorization_run_id="authorization-run",
            job_id=str(job["id"]),
            tenant_id="default",
            framework="webforge",
            scope_binding="sha256:" + "a" * 64,
            target_binding="sha256:" + "b" * 64,
            collection_status=RunCollectionStatus.SUCCESS,
            coverage_complete=True,
            coverage_identity="sha256:" + "c" * 64,
            finding_set_identity=finding_set_identity(
                session,
                tenant_id="default",
                run_id="authorization-run:webforge",
            ),
            predecessor_run_id="",
            run_sequence=1,
            completed_at="2026-08-26T00:00:00+00:00",
            authorization_decision_id="decision-default",
            authorization_binding="sha256:" + "d" * 64,
            authority_id="fixture-run-authority",
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            issuer_id=policy.issuer_id,
        )
        record = replace(
            record,
            attestation=base64.b64encode(
                signer.sign(run_collection_truth_attestation_payload(record))
            ).decode("ascii"),
        )
        append_run_collection_truth(session, record, policy=policy)
    finally:
        session.close()
    accepted = service.record_run_truth(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        record.run_id,
        worker_id="worker-a",
    )
    assert service.record_run_truth(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        record.run_id,
        worker_id="worker-a",
    ) == accepted
    assert service.coverage_snapshot(str(job["id"]))["completed"] == 0
    with pytest.raises(
        TerminalStateError,
        match="accepted Task 102 delivery",
    ):
        service.finish_attempt(
            str(attempt["id"]),
            lease_token=str(attempt["lease_token"]),
            worker_id="worker-a",
        )
    inspected = service.inspect_run_truth(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        record.run_id,
        worker_id="worker-a",
    )
    service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=_receipt(job, attempt, suffix="run-truth"),
        outcome=str(inspected["outcome"]),
        work=inspected["work"],
        run_truths=[inspected["receipt"]],
        worker_id="worker-a",
    )
    finished = service.finish_attempt(
        str(attempt["id"]),
        lease_token=str(attempt["lease_token"]),
        worker_id="worker-a",
    )
    assert finished["state"] == JobState.COMPLETED.value
    assert service.get_job(str(job["id"]))["state"] == JobState.COMPLETED.value
    assert service.coverage_snapshot(str(job["id"]))["completed"] == 1


def test_retry_preserves_prior_events_and_resolves_prior_failed_work(tmp_path):
    service = _service(tmp_path / "jobs.db")
    job = _queued_job(service, required_work=1, max_attempts=2, work_items=("route:/health",))
    first = _running_attempt(service, str(job["id"]))
    service.record_result(
        str(first["id"]),
        str(first["lease_token"]),
        delivery_key=str(first["delivery_idempotency_key"]),
        receipt=_receipt(job, first, suffix="failure"),
        outcome="failure",
        work=[{"work_key": "route:/health", "state": "failed", "reason": "fixture timeout"}],
    )
    service.finish_attempt(
        str(first["id"]),
        lease_token=str(first["lease_token"]),
        success=False,
        error_reason="fixture timeout",
    )
    assert service.get_job(str(job["id"]))["state"] == JobState.QUEUED.value
    second = _running_attempt(service, str(job["id"]))
    service.record_result(
        str(second["id"]),
        str(second["lease_token"]),
        delivery_key=str(second["delivery_idempotency_key"]),
        receipt=_receipt(job, second, suffix="retry-success"),
        work=[{"work_key": "route:/health"}],
    )
    service.finish_attempt(
        str(second["id"]),
        lease_token=str(second["lease_token"]),
    )
    attempts = service.list_attempts(str(job["id"]))
    assert [attempt["state"] for attempt in attempts] == ["failed", "completed"]
    assert service.get_job(str(job["id"]))["state"] == JobState.COMPLETED.value
    assert service.coverage_snapshot(str(job["id"]))["failed"] == 0
    event_attempts = {event["attempt_id"] for event in service.list_events(str(job["id"]))}
    assert {str(first["id"]), str(second["id"])} <= event_attempts


def test_active_completion_cannot_use_an_observation_delivery_without_run_truth(
    tmp_path,
):
    service = _service(tmp_path / "active-without-truth.db")
    job = service.create_job(
        {"target": "fixture.local", "dry_run": False},
        run_id="active-run",
        job_kind="webforge",
        state=JobState.QUEUED,
        authorization_decision_id="decision-default",
        authorization_action_id="action-default",
        authorization_bindings=(
            {
                "authorization_decision_id": "decision-default",
                "authorization_action_id": "action-default",
                "framework": "webforge",
            },
        ),
        work_items=("webforge",),
    )
    attempt = _running_attempt(service, str(job["id"]))
    service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=_receipt(job, attempt, suffix="unproved-active"),
        outcome="success",
        work=[{"work_key": "webforge", "required": True}],
    )

    finished = service.finish_attempt(
        str(attempt["id"]),
        lease_token=str(attempt["lease_token"]),
    )

    assert finished["state"] == JobState.PARTIAL.value
    assert service.get_job(str(job["id"]))["state"] == JobState.PARTIAL.value
    assert "run_truth_missing:webforge" in service.completion_blockers(
        str(job["id"])
    )


def test_pause_prevents_start_and_cancel_revokes_paused_active_attempt(tmp_path):
    service = _service(tmp_path / "jobs.db")
    job = _queued_job(service)
    attempt = service.acquire_lease(str(job["id"]), "worker-a")
    service.pause_job(str(job["id"]))
    with pytest.raises((InvalidTransition, LeaseError)):
        service.start_attempt(str(attempt["id"]), str(attempt["lease_token"]))
    resumed = service.resume_job(str(job["id"]))
    assert resumed["state"] == JobState.LEASED.value
    service.start_attempt(str(attempt["id"]), str(resumed["lease_token"]))
    service.pause_job(str(job["id"]))
    canceled = service.cancel_job(str(job["id"]))
    assert canceled["state"] == JobState.CANCELED.value
    assert service.list_attempts(str(job["id"]))[0]["state"] == "canceled"
    assert not service.validate_lease(str(attempt["id"]), str(attempt["lease_token"]))


@pytest.mark.parametrize(
    "source",
    [
        JobState.PLANNED,
        JobState.PENDING_APPROVAL,
        JobState.QUEUED,
        JobState.LEASED,
        JobState.RUNNING,
        JobState.PAUSED,
    ],
)
def test_pause_and_resume_are_per_job_for_each_supported_state(tmp_path, source):
    service = _service(tmp_path / f"pause-{source.value}.db")
    job = service.create_job(
        state=(
            source
            if source
            in {JobState.PLANNED, JobState.PENDING_APPROVAL, JobState.QUEUED}
            else JobState.QUEUED
        ),
        authorization_decision_id="decision-default",
        authorization_action_id="action-default",
    )
    attempt = None
    if source in {JobState.LEASED, JobState.RUNNING, JobState.PAUSED}:
        attempt = service.acquire_lease(str(job["id"]), "worker-a")
    if source in {JobState.RUNNING, JobState.PAUSED}:
        service.start_attempt(
            str(attempt["id"]),
            str(attempt["lease_token"]),
        )
    if source is JobState.PAUSED:
        service.pause_job(str(job["id"]))

    paused = service.pause_job(str(job["id"]))
    assert paused["state"] == JobState.PAUSED.value
    assert service.pause_job(str(job["id"])) == paused
    resumed = service.resume_job(str(job["id"]))
    expected_resume = (
        JobState.RUNNING.value
        if source is JobState.PAUSED
        else source.value
    )
    assert resumed["state"] == expected_resume
    if attempt is not None:
        assert resumed["lease_token"] != attempt["lease_token"]
        assert not service.validate_lease(
            str(attempt["id"]),
            str(attempt["lease_token"]),
        )
        assert service.validate_lease(
            str(attempt["id"]),
            str(resumed["lease_token"]),
        )


@pytest.mark.parametrize(
    "source",
    [JobState.CANCELING, JobState.EXPIRED, JobState.ORPHANED],
)
def test_pause_rejects_uncertain_control_states_without_mutation(tmp_path, source):
    service = _service(tmp_path / f"pause-reject-{source.value}.db")
    job = _queued_job(service)
    with service._tx():
        service.conn.execute(
            "UPDATE durable_job_state_jobs SET state=? "
            "WHERE tenant_id='default' AND id=?",
            (source.value, job["id"]),
        )
    before = service.get_job(str(job["id"]))
    events = service.list_events(str(job["id"]))
    with pytest.raises(InvalidTransition):
        service.pause_job(str(job["id"]))
    assert service.get_job(str(job["id"])) == before
    assert service.list_events(str(job["id"])) == events


def test_retry_approval_fence_rejects_old_authorization_and_leasing(tmp_path):
    service = JobStateService(
        tmp_path / "retry-approval.db",
        authorization_checker=lambda *_args: True,
        observation_checker=_observed,
    )
    job = _queued_job(service, max_attempts=2)
    pending = service.require_approval(
        str(job["id"]),
        reason="active retry requires fresh authorization",
    )
    assert pending["state"] == JobState.PENDING_APPROVAL.value
    with pytest.raises(InvalidTransition, match="newly bound authorization"):
        service.retry_job(str(job["id"]))
    with pytest.raises(InvalidTransition, match="cannot lease"):
        service.acquire_lease(str(job["id"]), "worker-a")
    assert service.list_attempts(str(job["id"])) == []
    rebound = service.bind_retry_authorization(
        str(job["id"]),
        authorization_decision_id="decision-default-retry",
        authorization_action_id="action-default-retry",
        run_id="run-retry-generation-2",
        authorization_bindings=(
            {
                "authorization_decision_id": "decision-default-retry",
                "authorization_action_id": "action-default-retry",
                "framework": "job",
            },
        ),
        payload_updates={"retry_generation": 2},
    )
    assert rebound["state"] == JobState.QUEUED.value
    assert rebound["authorization_generation"] == 2
    rebound_attempt = service.acquire_lease(
        str(job["id"]),
        "worker-a",
    )
    assert rebound_attempt["number"] == 1
    generations = service.conn.execute(
        "SELECT generation,active FROM "
        "durable_job_state_job_authorizations "
        "WHERE tenant_id='default' AND job_id=? ORDER BY generation",
        (job["id"],),
    ).fetchall()
    assert [tuple(row) for row in generations] == [(1, 0), (2, 1)]


def test_cancel_preserves_partial_evidence_and_materializes_missing_coverage(tmp_path):
    service = _service(tmp_path / "jobs.db")
    job = _queued_job(service, required_work=2, work_items=("one", "two"))
    attempt = _running_attempt(service, str(job["id"]))
    service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=_receipt(job, attempt, suffix="one"),
        work=[{"work_key": "one"}],
    )
    canceled = service.cancel_job(str(job["id"]), reason="operator cancellation")
    snapshot = service.coverage_snapshot(str(job["id"]))
    assert canceled["state"] == JobState.PARTIAL.value
    assert snapshot["completed"] == 1
    assert snapshot["uncollected"] == 1
    missing = next(item for item in snapshot["items"] if item["state"] == "uncollected")
    assert missing["reason"] == "operator cancellation"


def test_terminal_failure_and_partial_materialize_declared_missing_work(tmp_path):
    service = _service(tmp_path / "jobs.db")
    failed_job = _queued_job(service, required_work=1)
    failed_attempt = _running_attempt(service, str(failed_job["id"]))
    service.record_result(
        str(failed_attempt["id"]),
        str(failed_attempt["lease_token"]),
        delivery_key=str(failed_attempt["delivery_idempotency_key"]),
        receipt=_receipt(failed_job, failed_attempt, suffix="failure"),
        outcome="failure",
    )
    service.finish_attempt(
        str(failed_attempt["id"]),
        lease_token=str(failed_attempt["lease_token"]),
        success=False,
        error_reason="fixture timeout",
    )
    failed_coverage = service.coverage_snapshot(str(failed_job["id"]))
    assert service.get_job(str(failed_job["id"]))["state"] == JobState.FAILED.value
    assert failed_coverage["uncollected"] == 1
    assert failed_coverage["items"][0]["reason"] == "fixture timeout"

    partial_job = _queued_job(service, required_work=2)
    partial_attempt = _running_attempt(service, str(partial_job["id"]))
    service.record_result(
        str(partial_attempt["id"]),
        str(partial_attempt["lease_token"]),
        delivery_key=str(partial_attempt["delivery_idempotency_key"]),
        receipt=_receipt(partial_job, partial_attempt, suffix="incomplete"),
        outcome="partial",
    )
    service.finish_attempt(
        str(partial_attempt["id"]),
        lease_token=str(partial_attempt["lease_token"]),
        terminal_reason="fixture incomplete coverage",
    )
    partial_coverage = service.coverage_snapshot(str(partial_job["id"]))
    assert service.get_job(str(partial_job["id"]))["state"] == JobState.PARTIAL.value
    assert partial_coverage["uncollected"] == 2
    assert all(item["reason"] == "fixture incomplete coverage" for item in partial_coverage["items"])


@pytest.mark.parametrize("state", [JobState.PLANNED, JobState.PENDING_APPROVAL, JobState.QUEUED])
def test_cancel_is_idempotent_for_non_started_work(tmp_path, state):
    service = _service(tmp_path / f"{state.value}.db")
    job = service.create_job(
        state=state,
        authorization_decision_id="decision-default",
        authorization_action_id="action-default",
    )
    assert service.cancel_job(str(job["id"]))["state"] == JobState.CANCELED.value
    assert service.cancel_job(str(job["id"]))["state"] == JobState.CANCELED.value
    reconciled = [
        event
        for event in service.list_events(str(job["id"]))
        if event["event_type"] == "cancel_reconciled"
    ]
    assert len(reconciled) == 1
    assert reconciled[0]["data"]["immediate"] is True
    assert reconciled[0]["data"]["within_sla"] is True


@pytest.mark.parametrize(
    "source",
    [JobState.CANCELING, JobState.EXPIRED, JobState.ORPHANED],
)
def test_cancel_finishes_each_uncertain_nonterminal_state(tmp_path, source):
    service = _service(tmp_path / f"cancel-{source.value}.db")
    job = _queued_job(service)
    with service._tx():
        service.conn.execute(
            "UPDATE durable_job_state_jobs SET state=? "
            "WHERE tenant_id='default' AND id=?",
            (source.value, job["id"]),
        )
    canceled = service.cancel_job(str(job["id"]), sla_seconds=1.0)
    assert canceled["state"] == JobState.CANCELED.value
    assert canceled["terminal_reason_code"] == "operator_cancellation"


def test_cancellation_stops_mocked_child_within_sla_and_pid_reuse_is_not_signaled(tmp_path):
    identity = process_identity(
        4242,
        start_token="first",
        command="fixture-worker",
        boot_id="fixture-boot",
    )
    supervisor = FakeSupervisor(identity)
    service = _service(tmp_path / "jobs.db", process_supervisor=supervisor)
    job = _queued_job(service)
    attempt = _running_attempt(service, str(job["id"]))
    intent = _reserve_process(service, job, attempt)
    assert _reserve_process(service, job, attempt) == intent
    identity = process_identity(
        4242,
        start_token="first",
        command="fixture-worker",
        boot_id="fixture-boot",
        launch_nonce=str(intent["launch_nonce"]),
    )
    _register_process(service, job, attempt, identity)
    _register_process(service, job, attempt, identity)
    assert service.conn.execute(
        "SELECT COUNT(*) FROM durable_job_state_child_processes "
        "WHERE tenant_id='default' AND attempt_id=?",
        (attempt["id"],),
    ).fetchone()[0] == 1
    started = time.monotonic()
    assert service.cancel_job(str(job["id"]), sla_seconds=0.1)["state"] == JobState.CANCELED.value
    assert time.monotonic() - started < 0.1
    assert supervisor.terminated == [identity]
    assert supervisor.killed == []

    reused = process_identity(
        5151,
        start_token="old",
        command="old-command",
        boot_id="fixture-boot",
    )
    unrelated = process_identity(
        5151,
        start_token="new",
        command="new-command",
        boot_id="fixture-boot",
    )
    reuse_supervisor = FakeSupervisor(unrelated)
    second = _service(tmp_path / "pid-reuse.db", process_supervisor=reuse_supervisor)
    reuse_job = _queued_job(second)
    reuse_attempt = _running_attempt(second, str(reuse_job["id"]))
    reuse_intent = _reserve_process(second, reuse_job, reuse_attempt)
    reused = process_identity(
        5151,
        start_token="old",
        command="old-command",
        boot_id="fixture-boot",
        launch_nonce=str(reuse_intent["launch_nonce"]),
    )
    _register_process(second, reuse_job, reuse_attempt, reused)
    assert second.cancel_job(str(reuse_job["id"]), sla_seconds=0)["state"] == JobState.CANCELED.value
    assert reuse_supervisor.terminated == []
    assert reuse_supervisor.killed == []

    stubborn = process_identity(
        6161,
        start_token="stubborn",
        command="fixture-worker",
        boot_id="fixture-boot",
    )
    stubborn_supervisor = FakeSupervisor(stubborn, terminate_stops=False)
    stubborn_service = _service(
        tmp_path / "escalation.db",
        process_supervisor=stubborn_supervisor,
    )
    stubborn_job = _queued_job(stubborn_service)
    stubborn_attempt = _running_attempt(stubborn_service, str(stubborn_job["id"]))
    stubborn_intent = _reserve_process(
        stubborn_service, stubborn_job, stubborn_attempt
    )
    stubborn = process_identity(
        6161,
        start_token="stubborn",
        command="fixture-worker",
        boot_id="fixture-boot",
        launch_nonce=str(stubborn_intent["launch_nonce"]),
    )
    _register_process(stubborn_service, stubborn_job, stubborn_attempt, stubborn)
    stubborn_service.cancel_job(str(stubborn_job["id"]), sla_seconds=0)
    assert stubborn_supervisor.terminated == [stubborn]
    assert stubborn_supervisor.killed == [stubborn]
    # The supervisor boundary records the escalation; no process is created.
    assert stubborn_supervisor.killed == [stubborn]


def test_process_launch_is_atomically_lease_worker_boot_and_nonce_fenced(tmp_path):
    service = _service(tmp_path / "process-fence.db")
    job = _queued_job(service)
    attempt = _running_attempt(service, str(job["id"]))

    with pytest.raises(LeaseError):
        service.reserve_process(
            str(job["id"]),
            str(attempt["id"]),
            "main",
            lease_token="wrong-token",
            worker_id=str(attempt["worker_id"]),
            control_boot_id=str(attempt["control_boot_id"]),
        )
    with pytest.raises(LeaseError):
        service.reserve_process(
            str(job["id"]),
            str(attempt["id"]),
            "main",
            lease_token=str(attempt["lease_token"]),
            worker_id="worker-b",
            control_boot_id=str(attempt["control_boot_id"]),
        )
    with pytest.raises(ProcessIdentityError):
        service.reserve_process(
            str(job["id"]),
            str(attempt["id"]),
            "main",
            lease_token=str(attempt["lease_token"]),
            worker_id=str(attempt["worker_id"]),
            control_boot_id="another-boot",
        )
    assert service.conn.execute(
        "SELECT COUNT(*) FROM durable_job_state_launch_intents"
    ).fetchone()[0] == 0
    with pytest.raises(sqlite3.IntegrityError):
        with service._tx():
            service.conn.execute(
                "UPDATE durable_job_state_attempts SET control_boot_id='forged' "
                "WHERE tenant_id='default' AND id=?",
                (attempt["id"],),
            )

    intent = _reserve_process(service, job, attempt)
    with pytest.raises(ProcessIdentityError):
        service.reserve_process(
            str(job["id"]),
            str(attempt["id"]),
            "main",
            lease_token=str(attempt["lease_token"]),
            worker_id=str(attempt["worker_id"]),
            control_boot_id=str(attempt["control_boot_id"]),
            expected_launch_nonce="forged-launch-nonce",
        )
    service.cancel_job(str(job["id"]), sla_seconds=0)
    identity = process_identity(
        7701,
        start_token="post-cancel",
        command="fixture-child",
        boot_id="fixture-boot",
        launch_nonce=str(intent["launch_nonce"]),
    )
    with pytest.raises(LeaseError):
        _register_process(service, job, attempt, identity)
    abandoned = service.abandon_process_launch(
        str(job["id"]),
        str(attempt["id"]),
        "main",
        worker_id=str(attempt["worker_id"]),
        control_boot_id=str(attempt["control_boot_id"]),
    )
    assert abandoned["state"] == "abandoned"
    assert service.abandon_process_launch(
        str(job["id"]),
        str(attempt["id"]),
        "main",
        worker_id=str(attempt["worker_id"]),
        control_boot_id=str(attempt["control_boot_id"]),
    ) == abandoned


def test_exact_owner_can_record_one_late_exit_after_lease_revocation(tmp_path):
    service = _service(tmp_path / "late-exit.db")
    job = _queued_job(service)
    attempt = _running_attempt(service, str(job["id"]))
    intent = _reserve_process(service, job, attempt)
    identity = process_identity(
        7702,
        start_token="late-exit",
        command="fixture-child",
        boot_id="fixture-boot",
        launch_nonce=str(intent["launch_nonce"]),
    )
    _register_process(service, job, attempt, identity)
    service.revoke_lease(str(attempt["id"]), reason="fixture cancellation race")

    with pytest.raises(ProcessIdentityError):
        service.record_process_exit(
            str(job["id"]),
            str(attempt["id"]),
            identity,
            worker_id="wrong-worker",
            control_boot_id="fixture-boot",
        )
    with pytest.raises(ProcessIdentityError):
        service.record_process_exit(
            str(job["id"]),
            str(attempt["id"]),
            identity,
            worker_id=str(attempt["worker_id"]),
            control_boot_id="wrong-boot",
        )
    first = _record_process_exit(service, job, attempt, identity, return_code=-15)
    second = _record_process_exit(service, job, attempt, identity, return_code=-15)
    assert first == second == identity.to_dict()
    assert len(
        [
            event
            for event in service.list_events(str(job["id"]))
            if event["event_type"] == "child_exited"
        ]
    ) == 1


@pytest.mark.parametrize(
    ("work_state", "expected"),
    [
        (WorkState.PENDING, "required_work_pending"),
        (WorkState.SKIPPED, "required_work_skipped"),
        (WorkState.FAILED, "required_work_failed"),
        (WorkState.TRUNCATED, "required_work_truncated"),
        (WorkState.UNCOLLECTED, "required_work_uncollected"),
    ],
)
def test_completion_rejects_each_uncertain_required_coverage_state(tmp_path, work_state, expected):
    service = _service(tmp_path / f"{work_state.value}.db")
    job = service.create_job(
        state=JobState.QUEUED,
        required_work=1,
        work_items=("required",),
        authorization_decision_id="decision-default",
        authorization_action_id="action-default",
    )
    attempt = _running_attempt(service, str(job["id"]))
    service.mark_work(
        str(job["id"]), "required", state=work_state, reason="fixture",
        attempt_id=str(attempt["id"]),
    )
    service.pause_job(str(job["id"]))
    assert expected in service.completion_blockers(str(job["id"]))
    with pytest.raises(TerminalStateError):
        service.complete_job(str(job["id"]))


def test_completion_rejects_active_attempt_and_required_child_and_terminal_is_immutable(tmp_path):
    service = _service(tmp_path / "jobs.db")
    active_job = _queued_job(service)
    active = service.acquire_lease(str(active_job["id"]), "worker-a")
    assert "active_attempt" in service.completion_blockers(str(active_job["id"]))
    with pytest.raises(TerminalStateError):
        service.complete_job(str(active_job["id"]))
    service.cancel_job(str(active_job["id"]))

    parent = service.create_job(
        authorization_decision_id="decision-default",
        authorization_action_id="action-default",
    )
    service.create_child(str(parent["id"]), "child-1")
    service.pause_job(str(parent["id"]))
    assert "unresolved_child:child-1" in service.completion_blockers(str(parent["id"]))
    with pytest.raises(TerminalStateError):
        service.complete_job(str(parent["id"]))

    complete = _queued_job(service, required_work=1, work_items=("late",))
    complete_attempt = _running_attempt(service, str(complete["id"]))
    service.record_result(
        str(complete_attempt["id"]), str(complete_attempt["lease_token"]),
        delivery_key=str(complete_attempt["delivery_idempotency_key"]),
        receipt=_receipt(complete, complete_attempt, suffix="complete"),
        work=[{"work_key": "late"}],
    )
    service.finish_attempt(
        str(complete_attempt["id"]), lease_token=str(complete_attempt["lease_token"])
    )
    with pytest.raises((TerminalStateError, IdempotencyConflict)):
        service.mark_work(
            str(complete["id"]), "late", state=WorkState.FAILED,
            reason="late mutation", attempt_id=str(complete_attempt["id"]),
        )
    with pytest.raises(TerminalStateError):
        service.create_child(str(complete["id"]), "late-child")
    assert service.get_job(str(complete["id"]))["state"] == JobState.COMPLETED.value
    assert service.validate_lease(str(active["id"]), str(active["lease_token"])) is False


def test_child_creation_cannot_forge_terminal_state_or_bypass_parent_ownership(tmp_path):
    service = _service(tmp_path / "jobs.db")
    parent = service.create_job(
        authorization_decision_id="decision-default",
        authorization_action_id="action-default",
    )
    with pytest.raises(InvalidTransition, match="new child jobs must start"):
        service.create_child(str(parent["id"]), "forged", state=JobState.COMPLETED)

    direct_child = service.create_job(
        parent_id=str(parent["id"]),
        job_id="direct-child",
        state=JobState.QUEUED,
        authorization_decision_id="decision-default",
        authorization_action_id="action-default",
    )
    assert service.children(str(parent["id"]))[0]["id"] == direct_child["id"]
    service.pause_job(str(parent["id"]))
    with pytest.raises(TerminalStateError, match="unresolved_child"):
        service.complete_job(str(parent["id"]))


def test_unresolved_child_process_blocks_retry_and_is_canceled_without_duplicate_work(tmp_path):
    identity = process_identity(
        8801,
        start_token="child-start",
        command="fixture-child",
        boot_id="fixture-boot",
    )
    supervisor = FakeSupervisor(identity)
    service = _service(tmp_path / "jobs.db", process_supervisor=supervisor)
    job = _queued_job(service, max_attempts=2)
    attempt = _running_attempt(service, str(job["id"]))
    intent = _reserve_process(service, job, attempt)
    identity = process_identity(
        8801,
        start_token="child-start",
        command="fixture-child",
        boot_id="fixture-boot",
        launch_nonce=str(intent["launch_nonce"]),
    )
    _register_process(service, job, attempt, identity)
    service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=_receipt(job, attempt, suffix="child-failure"),
        outcome="failure",
    )
    service.finish_attempt(
        str(attempt["id"]),
        lease_token=str(attempt["lease_token"]),
        success=False,
        error_reason="fixture worker failure",
    )
    assert service.get_job(str(job["id"]))["state"] == JobState.ORPHANED.value
    with pytest.raises(LeaseUnavailable, match="unresolved child"):
        service.acquire_lease(str(job["id"]), "worker-b")
    assert service.cancel_job(str(job["id"]), sla_seconds=0.1)["state"] == JobState.CANCELED.value
    assert supervisor.terminated == [identity]


def test_partial_state_records_exact_coverage(tmp_path):
    service = _service(tmp_path / "jobs.db")
    plan = ("completed", "skipped", "failed", "truncated", "uncollected")
    job = _queued_job(service, required_work=5, work_items=plan)
    attempt = _running_attempt(service, str(job["id"]))
    service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=_receipt(job, attempt, suffix="partial-coverage"),
        outcome="partial",
        work=[{"work_key": "completed"}],
    )
    service.finish_attempt(
        str(attempt["id"]),
        lease_token=str(attempt["lease_token"]),
        skipped=[{"work_key": "skipped", "reason": "scope exclusion"}],
        failed=[{"work_key": "failed", "reason": "timeout"}],
        truncated=[{"work_key": "truncated", "reason": "limit"}],
        uncollected=[{"work_key": "uncollected", "reason": "worker loss"}],
    )
    snapshot = service.coverage_snapshot(str(job["id"]))
    assert service.get_job(str(job["id"]))["state"] == JobState.PARTIAL.value
    assert {key: snapshot[key] for key in ("completed", "skipped", "failed", "truncated", "uncollected")} == {
        "completed": 1,
        "skipped": 1,
        "failed": 1,
        "truncated": 1,
        "uncollected": 1,
    }


def test_restart_reconciles_leases_live_children_cancel_window_and_result_window(tmp_path):
    clock = FakeClock()
    path = tmp_path / "jobs.db"
    first = _service(path, clock=clock)
    leased_job = _queued_job(first, max_attempts=2)
    leased = first.acquire_lease(str(leased_job["id"]), "worker-a", lease_seconds=5)
    clock.advance(6)
    first.close()
    restarted = _service(path, clock=clock)
    assert str(leased["id"]) in restarted.reconcile()
    assert restarted.get_job(str(leased_job["id"]))["state"] == JobState.QUEUED.value

    # Accepted result + durable log survive a restart before terminal finalization.
    result_job = _queued_job(restarted, required_work=1, work_items=("one",))
    result_attempt = _running_attempt(restarted, str(result_job["id"]), lease_seconds=60)
    restarted.record_result(
        str(result_attempt["id"]),
        str(result_attempt["lease_token"]),
        delivery_key=str(result_attempt["delivery_idempotency_key"]),
        receipt=_receipt(result_job, result_attempt, suffix="accepted-before-restart"),
        work=[{"work_key": "one"}],
    )
    restarted.append_log(str(result_job["id"]), "accepted result", attempt_id=str(result_attempt["id"]))
    restarted.close()
    restarted = _service(path, clock=clock)
    assert any(event["event_type"] == "result_accepted" for event in restarted.list_events(str(result_job["id"])))
    assert restarted.list_logs(str(result_job["id"]))[0]["message"] == "accepted result"
    restarted.finish_attempt(
        str(result_attempt["id"]), lease_token=str(result_attempt["lease_token"])
    )
    assert restarted.get_job(str(result_job["id"]))["state"] == JobState.COMPLETED.value

    # A live child with an expired lease is orphaned, never requeued.
    live_identity = process_identity(
        9001,
        start_token="live",
        command="fixture",
        boot_id="fixture-boot",
    )
    live_supervisor = FakeSupervisor(live_identity)
    live_path = tmp_path / "live.db"
    live = _service(live_path, clock=clock, process_supervisor=live_supervisor)
    live_job = _queued_job(live, max_attempts=2)
    live_attempt = _running_attempt(live, str(live_job["id"]), lease_seconds=5)
    live_intent = _reserve_process(live, live_job, live_attempt)
    live_identity = process_identity(
        9001,
        start_token="live",
        command="fixture",
        boot_id="fixture-boot",
        launch_nonce=str(live_intent["launch_nonce"]),
    )
    _register_process(live, live_job, live_attempt, live_identity)
    clock.advance(6)
    live.close()
    live = _service(live_path, clock=clock, process_supervisor=live_supervisor)
    live.reconcile()
    assert live.get_job(str(live_job["id"]))["state"] == JobState.ORPHANED.value
    assert len(live.list_attempts(str(live_job["id"]))) == 1

    cancel_job = _queued_job(restarted, max_attempts=1)
    cancel_attempt = _running_attempt(restarted, str(cancel_job["id"]), lease_seconds=5)
    # Simulate the crash window after the cancellation request commits but
    # before the cancellation worker revokes the attempt.
    with restarted._tx():
        running = restarted._job("default", str(cancel_job["id"]))
        restarted._transition_tx(
            "default",
            str(cancel_job["id"]),
            JobState.CANCELING.value,
            expected_version=int(running["version"]),
            actor="fixture",
            reason="fixture cancellation request",
            idempotency_key=None,
            data={},
        )
    clock.advance(6)
    restarted.reconcile()
    assert restarted.get_job(str(cancel_job["id"]))["state"] == JobState.CANCELED.value
    assert restarted.list_attempts(str(cancel_job["id"]))[0]["state"] == "canceled"
    assert not restarted.validate_lease(str(cancel_attempt["id"]), str(cancel_attempt["lease_token"]))


def test_tenant_isolation_and_reconstruction_without_compatibility_json(tmp_path):
    path = tmp_path / "jobs.db"
    service = _service(path)
    alpha = service.create_job(
        {"target": "same.fixture.local"},
        job_id="alpha-job",
        tenant_id="alpha",
        state=JobState.QUEUED,
        authorization_decision_id="decision-alpha",
        authorization_action_id="action-alpha",
    )
    bravo = service.create_job(
        {"target": "same.fixture.local"},
        job_id="bravo-job",
        tenant_id="bravo",
        state=JobState.QUEUED,
        authorization_decision_id="decision-bravo",
        authorization_action_id="action-bravo",
    )
    alpha_attempt = service.acquire_lease(
        "alpha-job", "alpha-worker", tenant_id="alpha"
    )
    bravo_attempt = service.acquire_lease(
        "bravo-job", "bravo-worker", tenant_id="bravo"
    )
    assert alpha["tenant_id"] != bravo["tenant_id"]
    assert service.validate_lease(
        str(alpha_attempt["id"]), str(alpha_attempt["lease_token"]), tenant_id="alpha"
    )
    assert not service.validate_lease(
        str(alpha_attempt["id"]), str(alpha_attempt["lease_token"]), tenant_id="bravo"
    )
    assert service.list_events("alpha-job", tenant_id="alpha")
    assert service.list_events("bravo-job", tenant_id="bravo")
    assert service.get_job("alpha-job", tenant_id="bravo") is None
    assert service.get_job("bravo-job", tenant_id="alpha") is None

    compatibility_cache = tmp_path / "scan_jobs.json"
    compatibility_cache.write_text('{"non_authoritative": true}', encoding="utf-8")
    service.close()
    compatibility_cache.unlink()
    rebuilt = _service(path)
    assert rebuilt.get_job("alpha-job", tenant_id="alpha")["id"] == "alpha-job"
    assert rebuilt.get_job("bravo-job", tenant_id="bravo")["id"] == "bravo-job"
    assert rebuilt.list_attempts("alpha-job", tenant_id="alpha")[0]["id"] == alpha_attempt["id"]
    assert rebuilt.list_attempts("bravo-job", tenant_id="bravo")[0]["id"] == bravo_attempt["id"]


def test_wrong_owner_expired_and_revoked_leases_cannot_report(tmp_path):
    clock = FakeClock()
    service = _service(tmp_path / "jobs.db", clock=clock)
    job = _queued_job(service)
    attempt = _running_attempt(service, str(job["id"]), worker_id="worker-a", lease_seconds=5)
    with pytest.raises(LeaseError):
        service.start_attempt(
            str(attempt["id"]), str(attempt["lease_token"]), worker_id="worker-b"
        )
    with pytest.raises(LeaseError, match="owner"):
        service.record_result(
            str(attempt["id"]),
            str(attempt["lease_token"]),
            delivery_key=str(attempt["delivery_idempotency_key"]),
            receipt=_receipt(job, attempt, suffix="wrong-owner"),
            worker_id="worker-b",
        )
    assert service.latest_delivery(str(attempt["id"])) is None
    clock.advance(6)
    with pytest.raises(LeaseError):
        service.record_result(
            str(attempt["id"]), str(attempt["lease_token"]),
            delivery_key=str(attempt["delivery_idempotency_key"]),
            receipt=_receipt(job, attempt, suffix="late"),
        )
    service.reconcile()
    assert service.get_job(str(job["id"]))["state"] == JobState.EXPIRED.value


def test_renewal_rotates_tokens_without_extending_maximum_lease_lifetime(
    tmp_path,
):
    clock = FakeClock()
    service = _service(tmp_path / "bounded-renewal.db", clock=clock)
    job = _queued_job(service)
    leased = service.acquire_lease(
        str(job["id"]),
        "worker-a",
        lease_seconds=5,
        max_lease_seconds=12,
    )
    service.start_attempt(
        str(leased["id"]),
        str(leased["lease_token"]),
        worker_id="worker-a",
    )
    clock.advance(4)
    first = service.renew_lease(
        str(leased["id"]),
        str(leased["lease_token"]),
        lease_seconds=5,
        worker_id="worker-a",
    )
    assert first["lease_token"] != leased["lease_token"]
    assert first["lease_expires_at"] == 1_009.0
    clock.advance(4)
    second = service.renew_lease(
        str(first["id"]),
        str(first["lease_token"]),
        lease_seconds=5,
        worker_id="worker-a",
    )
    assert second["lease_expires_at"] == 1_012.0
    clock.advance(4)
    with pytest.raises(LeaseError, match="expired"):
        service.renew_lease(
            str(second["id"]),
            str(second["lease_token"]),
            lease_seconds=5,
            worker_id="worker-a",
        )


@pytest.mark.parametrize(
    "boundary",
    ["wrong_owner", "rotated", "revoked", "expired"],
)
def test_client_cannot_promote_custodied_result_after_lease_fence(
    tmp_path,
    boundary,
):
    from sqlalchemy import text

    from common.db import create_db

    clock = FakeClock()
    path = tmp_path / f"custodied-{boundary}.db"
    service = _service(path, clock=clock)
    job = _queued_job(
        service,
        required_work=1,
        work_items=("fixture-work",),
    )
    attempt = _running_attempt(
        service,
        str(job["id"]),
        worker_id="worker-a",
        lease_seconds=5,
    )
    receipt = _receipt(job, attempt, suffix=boundary)
    work = [{"work_key": "fixture-work", "required": True}]
    session = create_db(path)
    try:
        session.execute(text("BEGIN IMMEDIATE"))
        service.reserve_custodied_result(
            session,
            str(attempt["id"]),
            str(attempt["lease_token"]),
            delivery_key=str(attempt["delivery_idempotency_key"]),
            tenant_id="default",
            receipt=receipt,
            outcome="success",
            work=work,
            worker_id="worker-a",
        )
        session.commit()
    finally:
        session.close()

    token = str(attempt["lease_token"])
    worker = "worker-a"
    if boundary == "wrong_owner":
        worker = "worker-b"
    elif boundary == "rotated":
        service.renew_lease(
            str(attempt["id"]),
            token,
            worker_id="worker-a",
            lease_seconds=5,
        )
    elif boundary == "revoked":
        service.revoke_lease(
            str(attempt["id"]),
            reason="fixture revocation after custody",
        )
    else:
        clock.advance(6)

    with pytest.raises(LeaseError):
        service.record_result(
            str(attempt["id"]),
            token,
            delivery_key=str(attempt["delivery_idempotency_key"]),
            receipt=receipt,
            work=work,
            worker_id=worker,
        )
    delivery = service.conn.execute(
        "SELECT state FROM durable_job_state_deliveries "
        "WHERE tenant_id='default' AND attempt_id=?",
        (attempt["id"],),
    ).fetchone()
    assert delivery["state"] == "custodied"
    assert service.coverage_snapshot(str(job["id"]))["completed"] == 0
    assert service.get_job(str(job["id"]))["state"] != JobState.COMPLETED.value


@pytest.mark.parametrize(
    "boundary",
    ["wrong_owner", "rotated", "revoked", "expired"],
)
def test_accepted_duplicate_requires_current_or_normally_finished_lease(
    tmp_path,
    boundary,
):
    clock = FakeClock()
    service = _service(tmp_path / f"accepted-{boundary}.db", clock=clock)
    job = _queued_job(
        service,
        required_work=1,
        work_items=("fixture-work",),
    )
    attempt = _running_attempt(
        service,
        str(job["id"]),
        worker_id="worker-a",
        lease_seconds=5,
    )
    receipt = _receipt(job, attempt, suffix=f"accepted-{boundary}")
    work = [{"work_key": "fixture-work", "required": True}]
    service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=receipt,
        work=work,
        worker_id="worker-a",
    )
    token = str(attempt["lease_token"])
    worker = "worker-a"
    if boundary == "wrong_owner":
        worker = "worker-b"
    elif boundary == "rotated":
        service.renew_lease(
            str(attempt["id"]),
            token,
            worker_id="worker-a",
            lease_seconds=5,
        )
    elif boundary == "revoked":
        service.revoke_lease(
            str(attempt["id"]),
            reason="explicit fixture revocation",
        )
    else:
        clock.advance(6)
    before_job = service.get_job(str(job["id"]))
    before_events = service.list_events(str(job["id"]))

    with pytest.raises(LeaseError):
        service.record_result(
            str(attempt["id"]),
            token,
            delivery_key=str(attempt["delivery_idempotency_key"]),
            receipt=receipt,
            work=work,
            worker_id=worker,
        )

    assert service.get_job(str(job["id"])) == before_job
    assert service.list_events(str(job["id"])) == before_events
    assert service.conn.execute(
        "SELECT state FROM durable_job_state_deliveries "
        "WHERE tenant_id='default' AND attempt_id=?",
        (attempt["id"],),
    ).fetchone()["state"] == "accepted"


def test_dashboard_projection_declares_work_before_process_monitoring(tmp_path, monkeypatch):
    """A dashboard process exit cannot complete an otherwise empty projection."""

    from common.dashboard.server import DashboardServer
    path = tmp_path / "dashboard-jobs.db"
    service = _service(path)
    job = service.create_job(
        {"target": "https://fixture.local"},
        job_id="dashboard-scan",
        state=JobState.QUEUED,
        required_work=2,
        work_items=("sqli", "xss"),
        authorization_decision_id="decision-default",
        authorization_action_id="action-default",
    )
    attempt = _running_attempt(service, str(job["id"]), worker_id="dashboard")
    intent = _reserve_process(service, job, attempt)
    identity = process_identity(
        4242,
        start_token="dashboard",
        command="scanner",
        boot_id="fixture-boot",
        launch_nonce=str(intent["launch_nonce"]),
    )
    _register_process(service, job, attempt, identity)
    _record_process_exit(service, job, attempt, identity, return_code=0)
    server = DashboardServer(auth=False)
    monkeypatch.setattr(DashboardServer, "_scan_jobs_db_path", property(lambda _self: path))
    server._job_state_service = service
    server._job_state_service_path = str(path)
    try:
        job = service.get_job("dashboard-scan", tenant_id=server.tenant_id)
        assert job is not None
        assert job["required_work"] == 2
        # The dashboard finalizer has no accepted receipt/run truth to apply.
        server._finalize_durable_scan_after_exit("dashboard-scan")
        assert service.get_job("dashboard-scan", tenant_id=server.tenant_id)["state"] == JobState.RUNNING.value
        assert service.coverage_snapshot("dashboard-scan", tenant_id=server.tenant_id)["uncollected"] == 0
    finally:
        if server._job_state_service is not None:
            server._job_state_service.close()


def test_dashboard_process_exit_without_delivery_never_completes_zero_work(
    tmp_path, monkeypatch
):
    from common.dashboard.server import DashboardServer

    path = tmp_path / "monitor-jobs.db"
    monkeypatch.setattr(DashboardServer, "_scan_jobs_db_path", property(lambda _self: path))
    server = DashboardServer(auth=False)
    service = _service(path)
    server._job_state_service = service
    server._job_state_service_path = str(path)
    try:
        job = service.create_job(
            job_id="zero-coverage",
            state=JobState.QUEUED,
            required_work=0,
            authorization_decision_id="decision-default",
            authorization_action_id="action-default",
        )
        attempt = service.acquire_lease(str(job["id"]), "dashboard")
        service.start_attempt(
            str(attempt["id"]),
            str(attempt["lease_token"]),
            worker_id="dashboard",
        )
        server._finalize_durable_scan_after_exit("zero-coverage")
        assert service.get_job("zero-coverage")["state"] == JobState.RUNNING.value
    finally:
        if server._job_state_service is not None:
            server._job_state_service.close()


def test_dashboard_pause_adapter_reconstructs_from_durable_payload_after_restart(
    tmp_path,
    monkeypatch,
):
    import json

    from common.dashboard.server import DashboardServer

    path = tmp_path / "pause-adapter.db"
    control_dir = tmp_path / "controls"
    control_dir.mkdir(mode=0o700)
    control_file = control_dir / "pause-adapter.json"
    first_server = DashboardServer(auth=False)
    first_server._control_dir = control_dir
    first_server._write_control_file(
        control_file,
        paused=False,
        aborted=False,
    )
    first = _service(path)
    job = first.create_job(
        {
            "target": "fixture.local",
            "control_file": str(control_file),
        },
        job_id="pause-adapter",
        state=JobState.QUEUED,
        authorization_decision_id="decision-default",
        authorization_action_id="action-default",
    )
    attempt = _running_attempt(first, str(job["id"]), worker_id="dashboard")
    first.pause_job(str(job["id"]))
    assert json.loads(control_file.read_text(encoding="utf-8"))["paused"] is False
    first.close()

    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda _self: path),
    )
    restarted = DashboardServer(auth=False)
    restarted._control_dir = control_dir
    recovered = restarted._durable_job_state()
    assert json.loads(control_file.read_text(encoding="utf-8"))["paused"] is True
    recovered.close()
    restarted._job_state_service = None
    service = _service(path)
    restarted._job_state_service = service
    restarted._job_state_service_path = str(path)
    assert restarted._active_scans == {}
    resumed = service.resume_job(str(job["id"]))
    restarted._write_scan_control_files(
        str(job["id"]),
        {"paused": False, "aborted": False},
    )
    payload = json.loads(control_file.read_text(encoding="utf-8"))
    assert resumed["state"] == JobState.RUNNING.value
    assert payload["paused"] is False
    assert payload["aborted"] is False
    assert resumed["lease_token"] != attempt["lease_token"]
    service.close()


def test_dashboard_pause_and_resume_signal_only_persisted_full_identity(
    tmp_path,
    monkeypatch,
):
    from common.dashboard.server import DashboardServer

    path = tmp_path / "pause-signal.db"
    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda _self: path),
    )
    base_identity = process_identity(
        42_424,
        start_token="pause-start",
        command="inert-pause-child",
        boot_id="fixture-boot",
    )
    supervisor = FakeSupervisor(base_identity)
    service = _service(path, process_supervisor=supervisor)
    job = _queued_job(service)
    attempt = _running_attempt(service, str(job["id"]), worker_id="dashboard")
    intent = _reserve_process(service, job, attempt)
    identity = ProcessIdentity(
        **{
            **base_identity.to_dict(),
            "launch_nonce": str(intent["launch_nonce"]),
        }
    )
    _register_process(service, job, attempt, identity)
    server = DashboardServer(auth=False)
    server._job_state_service = service
    server._job_state_service_path = str(path)
    server._job_process_supervisor = supervisor
    service.pause_job(str(job["id"]))
    server._signal_scan_processes(str(job["id"]), "pause")
    resumed = service.resume_job(str(job["id"]))
    server._signal_scan_processes(str(job["id"]), "resume")
    assert supervisor.paused == [identity]
    assert supervisor.resumed == [identity]
    assert resumed["lease_token"] != attempt["lease_token"]
    service.close()


def test_dashboard_unverifiable_post_popen_child_is_orphaned_not_completed(
    tmp_path,
    monkeypatch,
):
    import json

    from common.dashboard.server import DashboardServer

    class UnverifiableProcess:
        pid = 999_999

        @staticmethod
        def poll():
            return None

    path = tmp_path / "launch-failure.db"
    control_dir = tmp_path / "controls"
    control_dir.mkdir(mode=0o700)
    control_file = control_dir / "launch-failure.json"
    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda _self: path),
    )
    server = DashboardServer(auth=False)
    server._control_dir = control_dir
    server._write_control_file(
        control_file,
        paused=True,
        aborted=False,
    )
    service = _service(path)
    server._job_state_service = service
    server._job_state_service_path = str(path)
    job = _queued_job(service)
    attempt = service.acquire_lease(
        str(job["id"]),
        "dashboard",
        control_boot_id="fixture-boot",
    )
    intent = _reserve_process(
        service,
        job,
        attempt,
        "unverifiable",
    )
    server._abort_durable_scan_launch(
        scan_id=str(job["id"]),
        prepared={
            "attempt": attempt,
            "intents": {"unverifiable": intent},
            "lease_token": attempt["lease_token"],
        },
        processes={"unverifiable": UnverifiableProcess()},
        control_file=control_file,
        reason="fixture identity failure",
    )
    stored = service.get_job(str(job["id"]))
    control = json.loads(control_file.read_text(encoding="utf-8"))
    assert stored["state"] == JobState.ORPHANED.value
    assert stored["terminal_at"] is None
    assert control == {
        "aborted": True,
        "paused": False,
        "updated_at": control["updated_at"],
    }
    assert not service.validate_lease(
        str(attempt["id"]),
        str(attempt["lease_token"]),
    )
    service.close()


def test_dashboard_process_supervisor_discovers_exact_nonce_and_pidfd_fences(
    monkeypatch,
):
    """Recovery and signaling require the same complete child identity."""

    import signal as signal_module
    from types import SimpleNamespace

    import common.dashboard.server as server_module

    supervisor_type = server_module._DashboardProcessSupervisor
    launch_nonce = "fixture-launch-nonce"
    identity = process_identity(
        105,
        start_token="fixture-start",
        command="fixture-command",
        boot_id="fixture-boot",
        launch_nonce=launch_nonce,
    )
    marker = (
        f"{server_module.JOB_ATTEMPT_ID_ENV}_LAUNCH_NONCE={launch_nonce}"
    ).encode()

    class FakeEnviron:
        def __init__(self, payload: bytes = b"", *, unreadable: bool = False) -> None:
            self.payload = payload
            self.unreadable = unreadable

        def read_bytes(self) -> bytes:
            if self.unreadable:
                raise OSError("inert unreadable proc fixture")
            return self.payload

    class FakeEntry:
        def __init__(
            self,
            name: str,
            *,
            uid: int = 1000,
            payload: bytes = b"",
            unreadable: bool = False,
        ) -> None:
            self.name = name
            self.uid = uid
            self.environ = FakeEnviron(payload, unreadable=unreadable)

        def stat(self):
            return SimpleNamespace(st_uid=self.uid)

        def __truediv__(self, name: str):
            assert name == "environ"
            return self.environ

    class ProcRoot:
        def __init__(self, entries=(), *, unreadable: bool = False) -> None:
            self.entries = entries
            self.unreadable = unreadable

        def iterdir(self):
            if self.unreadable:
                raise OSError("inert unreadable proc root")
            return iter(self.entries)

    monkeypatch.setattr(server_module.os, "getuid", lambda: 1000)
    monkeypatch.setattr(
        supervisor_type,
        "_identity",
        classmethod(
            lambda _cls, pid, nonce: (
                identity if pid == identity.pid and nonce == launch_nonce else None
            )
        ),
    )
    monkeypatch.setattr(
        server_module,
        "Path",
        lambda _value: ProcRoot(unreadable=True),
    )
    assert supervisor_type.discover(launch_nonce) is None
    assert supervisor_type.discover("") is None
    assert supervisor_type.discover("bad\x00nonce") is None

    entries = (
        FakeEntry("not-a-pid"),
        FakeEntry("101", uid=2000, payload=marker),
        FakeEntry("102", unreadable=True),
        FakeEntry("103", payload=b"UNRELATED=1\x00"),
        FakeEntry("104", payload=marker),
        FakeEntry("105", payload=marker),
    )
    monkeypatch.setattr(server_module, "Path", lambda _value: ProcRoot(entries))
    assert supervisor_type.discover(launch_nonce) == identity

    supervisor = supervisor_type()
    monkeypatch.setattr(
        supervisor_type,
        "_matches",
        classmethod(lambda _cls, _identity: False),
    )
    with pytest.raises(ProcessIdentityError, match="no longer matches"):
        supervisor.terminate(identity)

    monkeypatch.setattr(
        supervisor_type,
        "_matches",
        classmethod(lambda _cls, _identity: True),
    )
    monkeypatch.setattr(server_module.os, "pidfd_open", None)
    monkeypatch.setattr(
        server_module.signal,
        "pidfd_send_signal",
        None,
        raising=False,
    )
    with pytest.raises(ProcessIdentityError, match="pidfd signaling is unavailable"):
        supervisor.kill(identity)

    descriptors: list[int] = []
    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(server_module.os, "pidfd_open", lambda pid: pid + 7000)
    monkeypatch.setattr(
        server_module.signal,
        "pidfd_send_signal",
        lambda descriptor, sig: signals.append((descriptor, sig)),
        raising=False,
    )
    monkeypatch.setattr(server_module.os, "close", descriptors.append)
    supervisor.pause(identity)
    assert signals == [(identity.pid + 7000, signal_module.SIGSTOP)]
    assert descriptors == [identity.pid + 7000]

    checks = iter((True, False))
    monkeypatch.setattr(
        supervisor_type,
        "_matches",
        classmethod(lambda _cls, _identity: next(checks)),
    )
    with pytest.raises(ProcessIdentityError, match="changed before signal"):
        supervisor.resume(identity)
    assert signals == [(identity.pid + 7000, signal_module.SIGSTOP)]
    assert descriptors == [identity.pid + 7000, identity.pid + 7000]

    wrapper_signals: list[int] = []
    monkeypatch.setattr(
        supervisor,
        "_signal",
        lambda _identity, sig: wrapper_signals.append(sig),
    )
    supervisor.terminate(identity)
    supervisor.kill(identity)
    supervisor.pause(identity)
    supervisor.resume(identity)
    assert wrapper_signals == [
        signal_module.SIGTERM,
        signal_module.SIGKILL,
        signal_module.SIGSTOP,
        signal_module.SIGCONT,
    ]


def test_dashboard_activation_abort_and_exit_truth_use_durable_identity(
    tmp_path,
    monkeypatch,
):
    """Dashboard adapters persist identity before start and never trust exit."""

    import json

    from common.dashboard.server import DashboardServer

    class FakeProcess:
        def __init__(self, pid: int, returncode: int | None = None) -> None:
            self.pid = pid
            self.returncode = returncode

        def poll(self):
            return self.returncode

    class CaptureSupervisor(FakeSupervisor):
        def __init__(self) -> None:
            super().__init__()
            self.captures: dict[int, ProcessIdentity] = {}

        def capture(self, process, *, launch_nonce: str):
            captured = self.captures.get(process.pid)
            if captured is None or captured.launch_nonce != launch_nonce:
                return None
            self.alive.add(self._key(captured))
            return captured

    path = tmp_path / "dashboard-adapters.db"
    control_dir = tmp_path / "controls"
    control_dir.mkdir(mode=0o700)
    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda _self: path),
    )
    supervisor = CaptureSupervisor()
    service = _service(path, process_supervisor=supervisor)
    server = DashboardServer(auth=False)
    server._control_dir = control_dir
    server._job_state_service = service
    server._job_state_service_path = str(path)
    server._job_process_supervisor = supervisor

    activated_job = _queued_job(service, work_items=("webforge",))
    activated_attempt = service.acquire_lease(
        str(activated_job["id"]),
        "dashboard",
        control_boot_id="fixture-boot",
    )
    activated_key = f"{activated_job['id']}_web"
    activated_intent = _reserve_process(
        service,
        activated_job,
        activated_attempt,
        activated_key,
    )
    activated_identity = process_identity(
        7001,
        start_token="activate-start",
        command="inert-web-child",
        boot_id="fixture-boot",
        launch_nonce=str(activated_intent["launch_nonce"]),
    )
    activated_process = FakeProcess(activated_identity.pid)
    supervisor.captures[activated_process.pid] = activated_identity
    server._active_scans = {
        "unrelated_web": {"proc": FakeProcess(7999)},
        activated_key: {"proc": activated_process},
    }
    activated_control = control_dir / "activated.json"
    server._write_control_file(activated_control, paused=True, aborted=False)
    server._activate_durable_scan_processes(
        scan_id=str(activated_job["id"]),
        prepared={
            "attempt": activated_attempt,
            "intents": {
                activated_key: activated_intent,
            },
            "lease_token": activated_attempt["lease_token"],
        },
        control_file=activated_control,
        actor_id="fixture-operator",
        actor_role="operator",
    )
    activated_info = server._active_scans[activated_key]
    assert service.get_job(str(activated_job["id"]))["state"] == JobState.RUNNING.value
    assert service.list_processes(str(activated_job["id"]))[0]["pid"] == 7001
    assert activated_info["durable_process_identity"] == activated_identity.to_dict()
    assert activated_info["durable_worker_id"] == "dashboard"
    assert json.loads(activated_control.read_text(encoding="utf-8"))["paused"] is False

    aborted_job = _queued_job(service)
    aborted_attempt = service.acquire_lease(
        str(aborted_job["id"]),
        "dashboard",
        control_boot_id="fixture-boot",
    )
    aborted_intent = _reserve_process(
        service,
        aborted_job,
        aborted_attempt,
        "abort-process",
    )
    aborted_identity = process_identity(
        7002,
        start_token="abort-start",
        command="inert-abort-child",
        boot_id="fixture-boot",
        launch_nonce=str(aborted_intent["launch_nonce"]),
    )
    aborted_process = FakeProcess(aborted_identity.pid)
    supervisor.captures[aborted_process.pid] = aborted_identity
    aborted_control = control_dir / "aborted.json"
    server._write_control_file(aborted_control, paused=True, aborted=False)
    server._abort_durable_scan_launch(
        scan_id=str(aborted_job["id"]),
        prepared={
            "attempt": aborted_attempt,
            "intents": {"abort-process": aborted_intent},
            "lease_token": aborted_attempt["lease_token"],
        },
        processes={"abort-process": aborted_process},
        control_file=aborted_control,
        reason="fixture launch aborted",
    )
    assert service.get_job(str(aborted_job["id"]))["state"] == JobState.CANCELED.value
    assert supervisor.terminated[-1] == aborted_identity
    assert json.loads(aborted_control.read_text(encoding="utf-8"))["aborted"] is True

    uncertain_job = _queued_job(
        service,
        work_items=("webforge",),
    )
    uncertain_attempt = _running_attempt(
        service,
        str(uncertain_job["id"]),
        worker_id="dashboard",
    )
    server._active_scans = {
        f"{uncertain_job['id']}_web": {
            "proc": FakeProcess(7003, returncode=0),
            "returncode": 0,
            "durable_lease_token": uncertain_attempt["lease_token"],
        }
    }
    server._finalize_durable_scan_after_exit(str(uncertain_job["id"]))
    stored_uncertain = service.get_job(str(uncertain_job["id"]))
    assert stored_uncertain["state"] == JobState.ORPHANED.value
    assert stored_uncertain["terminal_at"] is None
    assert not service.validate_lease(
        str(uncertain_attempt["id"]),
        str(uncertain_attempt["lease_token"]),
    )
    service.close()


def test_dashboard_prepares_durable_job_lease_and_intents_before_launch(
    tmp_path,
    monkeypatch,
):
    """Preparation persists every authoritative record before any Popen seam."""

    import common.dashboard.server as server_module

    monkeypatch.setenv(
        "FORGE_DASHBOARD_STATE_DIR",
        str(tmp_path / "dashboard-state"),
    )
    server = server_module.DashboardServer(auth=False)
    call_order: list[tuple[str, object]] = []

    class FixtureAuthorization:
        def __init__(self, framework: str) -> None:
            self.framework = framework
            self.decision_id = f"decision-{framework}"
            self.action_id = f"action-{framework}"
            self.engagement_id = "engagement-fixture"
            self.run_id = "run-fixture"

        def to_dict(self) -> dict[str, str]:
            return {
                "decision_id": self.decision_id,
                "action_id": self.action_id,
                "framework": self.framework,
            }

    class FixtureService:
        def create_job(self, payload, **kwargs):
            call_order.append(("job", payload))
            assert kwargs["state"] == JobState.QUEUED
            assert kwargs["work_items"] == ["webforge", "netforge"]
            return {"id": kwargs["job_id"], "state": JobState.QUEUED.value}

        def acquire_lease(self, job_id, worker_id, **kwargs):
            call_order.append(("lease", job_id))
            assert worker_id == "dashboard"
            assert kwargs["control_boot_id"] == "fixture-boot"
            return {
                "id": "attempt-fixture",
                "lease_token": "lease-fixture",
                "control_boot_id": "fixture-boot",
                "authorization_decision_id": "decision-webforge",
            }

        def reserve_process(self, job_id, attempt_id, identity_key, **kwargs):
            call_order.append(("intent", identity_key))
            assert job_id == "prepared-scan"
            assert attempt_id == "attempt-fixture"
            assert kwargs["lease_token"] == "lease-fixture"
            return {
                "identity_key": identity_key,
                "launch_nonce": f"nonce-{identity_key}",
            }

    service = FixtureService()
    monkeypatch.setattr(server, "_durable_job_state", lambda: service)
    writes: list[tuple[object, bool, bool]] = []
    monkeypatch.setattr(
        server,
        "_write_control_file",
        lambda path, *, paused, aborted: writes.append((path, paused, aborted)),
    )
    authorizations = {
        "webforge": FixtureAuthorization("webforge"),
        "netforge": FixtureAuthorization("netforge"),
    }
    control_file = server._control_dir / "prepared-scan.json"

    with pytest.raises(InvalidTransition, match="process and authorization"):
        server._prepare_durable_scan_job(
            scan_id="prepared-scan",
            target="fixture.local",
            process_specs=[],
            authorizations=authorizations,
            modules=[],
            results_dir=str(tmp_path / "results"),
            control_file=control_file,
            actor_id="fixture-operator",
            actor_role="operator",
        )
    monkeypatch.setattr(
        server_module._DashboardProcessSupervisor,
        "_boot_id",
        staticmethod(lambda: ""),
    )
    with pytest.raises(ProcessIdentityError, match="local boot identity"):
        server._prepare_durable_scan_job(
            scan_id="prepared-scan",
            target="fixture.local",
            process_specs=[("prepared-scan_web", "web")],
            authorizations=authorizations,
            modules=[],
            results_dir=str(tmp_path / "results"),
            control_file=control_file,
            actor_id="fixture-operator",
            actor_role="operator",
        )
    monkeypatch.setattr(
        server_module._DashboardProcessSupervisor,
        "_boot_id",
        staticmethod(lambda: "fixture-boot"),
    )
    prepared = server._prepare_durable_scan_job(
        scan_id="prepared-scan",
        target="fixture.local",
        process_specs=[
            ("prepared-scan_web", "web"),
            ("prepared-scan_net", "net"),
        ],
        authorizations=authorizations,
        modules=["headers"],
        results_dir=str(tmp_path / "results"),
        control_file=control_file,
        actor_id="fixture-operator",
        actor_role="operator",
    )

    assert [entry[0] for entry in call_order] == [
        "job",
        "lease",
        "intent",
        "intent",
    ]
    assert set(prepared["intents"]) == {
        "prepared-scan_web",
        "prepared-scan_net",
    }
    assert prepared["lease_token"] == "lease-fixture"
    assert writes == [(control_file, True, False)]


def test_dashboard_control_projection_and_global_cancel_use_durable_jobs_only(
    tmp_path,
    monkeypatch,
):
    """Compatibility controls never authorize PID-only global cancellation."""

    import common.dashboard.server as server_module

    monkeypatch.setenv(
        "FORGE_DASHBOARD_STATE_DIR",
        str(tmp_path / "dashboard-state"),
    )
    server = server_module.DashboardServer(auth=False)
    good_control = server._control_dir / "good.json"
    bad_control = server._control_dir / "bad.json"
    active_control = server._control_dir / "good-active.json"
    legacy_control = server._control_dir / "legacy.json"
    jobs = {
        "good": {
            "id": "good",
            "payload": {"control_file": str(good_control)},
        },
        "bad": {"id": "bad", "payload": {}},
    }

    class FixtureService:
        process_rows: list[dict[str, object]] = []
        logs: list[tuple[str, str, dict[str, object]]] = []

        def list_jobs(self, **_kwargs):
            return list(jobs.values())

        def get_job(self, job_id, **_kwargs):
            return jobs.get(job_id)

        def cancel_job(self, job_id, **_kwargs):
            if job_id == "bad":
                raise InvalidTransition("fixture cancellation conflict")
            return {"id": job_id, "state": JobState.CANCELED.value}

        def list_processes(self, _job_id, **_kwargs):
            return self.process_rows

        def append_log(self, job_id, message, **kwargs):
            self.logs.append((job_id, message, kwargs))

    service = FixtureService()
    monkeypatch.setattr(server, "_durable_job_state", lambda: service)
    writes: list[tuple[object, bool, bool]] = []
    monkeypatch.setattr(
        server,
        "_write_control_file",
        lambda path, *, paused, aborted: writes.append((path, paused, aborted)),
    )
    syncs: list[str] = []
    monkeypatch.setattr(
        server,
        "_sync_scan_job_from_active",
        syncs.append,
    )
    server._active_scans = {
        "good_web": {
            "control_file": str(good_control),
            "status": "running",
        },
        "good_net": {
            "control_file": str(active_control),
            "status": "running",
        },
        "bad_web": {
            "control_file": str(bad_control),
            "status": "running",
        },
        "legacy_web": {
            "control_file": str(legacy_control),
            "status": "running",
        },
    }

    assert server._durable_control_file_path({"id": "none", "payload": {}}) is None
    with pytest.raises(
        server_module.DashboardArtifactError,
        match="outside the scan adapter",
    ):
        server._durable_control_file_path(
            {"id": "good", "payload": {"control_file": str(tmp_path / "wrong.json")}}
        )
    assert server._durable_control_file_path(jobs["good"]) == good_control

    server._write_scan_control_files(
        "good",
        {"paused": True, "aborted": False},
    )
    assert writes == [
        (good_control, True, False),
        (active_control, True, False),
    ]
    writes.clear()
    server._write_all_control_files({"paused": False, "aborted": True})
    assert set(writes) == {
        (good_control, False, True),
        (active_control, False, True),
        (bad_control, False, True),
        (legacy_control, False, True),
    }

    stopped_identity = process_identity(
        8101,
        start_token="stopped-start",
        command="inert-stopped-child",
        boot_id="fixture-boot",
        launch_nonce="stopped-nonce",
    )
    orphaned_identity = process_identity(
        8102,
        start_token="orphaned-start",
        command="inert-orphaned-child",
        boot_id="fixture-boot",
        launch_nonce="orphaned-nonce",
    )
    running_identity = process_identity(
        8103,
        start_token="running-start",
        command="inert-running-child",
        boot_id="fixture-boot",
        launch_nonce="running-nonce",
    )
    service.process_rows = [
        {
            **stopped_identity.to_dict(),
            "state": "stopped",
            "attempt_id": "attempt-stopped",
            "identity_key": "stopped",
        },
        {
            **orphaned_identity.to_dict(),
            "state": "orphaned",
            "attempt_id": "attempt-orphaned",
            "identity_key": "orphaned",
        },
        {
            **running_identity.to_dict(),
            "state": "running",
            "attempt_id": "attempt-running",
            "identity_key": "running",
        },
    ]

    class FixtureSupervisor:
        paused: list[ProcessIdentity] = []

        def pause(self, identity: ProcessIdentity) -> None:
            self.paused.append(identity)

        @staticmethod
        def resume(_identity: ProcessIdentity) -> None:
            raise ProcessLookupError("inert identity mismatch")

    supervisor = FixtureSupervisor()
    server._job_process_supervisor = supervisor
    with pytest.raises(ValueError, match="unsupported"):
        server._signal_scan_processes("good", "stop")
    server._signal_scan_processes("good", "pause")
    assert supervisor.paused == [running_identity]
    assert service.logs[-1][1] == "process pause enforced"
    with pytest.raises(
        server_module.DashboardArtifactError,
        match="resume could not be enforced",
    ):
        server._signal_scan_processes("good", "resume")
    assert service.logs[-1][1] == "process resume could not be enforced"

    canceled = server._terminate_active_scans("stopped")
    assert canceled == ["good_web", "good_net"]
    assert server._active_scans["good_web"]["status"] == JobState.CANCELED.value
    assert server._active_scans["bad_web"]["status"] == "running"
    assert server._active_scans["legacy_web"]["status"] == "running"
    assert syncs == ["good"]


def test_dashboard_exit_finalizer_guards_and_finishes_only_after_run_truth(
    tmp_path,
    monkeypatch,
):
    """Every early-return window and the signed-truth finish path are explicit."""

    import common.dashboard.server as server_module

    monkeypatch.setenv(
        "FORGE_DASHBOARD_STATE_DIR",
        str(tmp_path / "dashboard-state"),
    )
    server = server_module.DashboardServer(auth=False)

    class FixtureService:
        mode = "missing"
        inspected: list[str] = []
        finished: list[tuple[str, str]] = []
        revoked: list[str] = []

        def get_job(self, job_id, **_kwargs):
            if self.mode == "missing":
                return None
            state = (
                JobState.COMPLETED.value
                if self.mode == "terminal"
                else JobState.RUNNING.value
            )
            return {
                "id": job_id,
                "state": state,
                "run_id": "run-fixture",
                "target": "fixture.local",
                "payload": {
                    "target": "fixture.local",
                    "authorization_envelopes": {"webforge": {}},
                },
            }

        def list_attempts(self, _job_id, **_kwargs):
            if self.mode == "no-attempt":
                return []
            return [
                {
                    "id": "attempt-fixture",
                    "authorization_decision_id": "decision-fixture",
                    "delivery_idempotency_key": "delivery-fixture",
                }
            ]

        def coverage_snapshot(self, _job_id, **_kwargs):
            return {
                "items": [
                    {"work_key": "webforge", "state": WorkState.PENDING.value},
                ]
            }

        def inspect_run_truth(self, _attempt_id, _lease_token, run_truth_id, **_kwargs):
            if self.mode == "truth-failure":
                raise InvalidTransition("fixture truth missing")
            self.inspected.append(run_truth_id)
            receipt = RunTruthReceipt(
                tenant_id="default",
                job_id="fixture-scan",
                attempt_id="attempt-fixture",
                run_id=run_truth_id,
                authorization_run_id="run-fixture",
                framework="webforge",
                authorization_decision_id="decision-fixture",
                proof_identity="sha256:" + "a" * 64,
                coverage_identity="sha256:" + "b" * 64,
                result_ref=f"run-truth:{run_truth_id}",
                outcome="success",
                collection_status="success",
                coverage_complete=True,
            )
            return {
                "receipt": receipt,
                "outcome": "success",
                "work": [
                    {
                        "work_key": "webforge",
                        "required": True,
                        "state": WorkState.COMPLETED.value,
                    }
                ],
            }

        def revoke_lease(self, attempt_id, **_kwargs):
            self.revoked.append(attempt_id)

        def finish_attempt(self, attempt_id, *, lease_token, **_kwargs):
            self.finished.append((attempt_id, lease_token))

    service = FixtureService()
    monkeypatch.setattr(server, "_durable_job_state", lambda: service)
    monkeypatch.setattr(
        server_module.ActionAuthorizationEnvelope,
        "from_value",
        classmethod(lambda _cls, _value: object()),
    )
    persisted: list[dict[str, object]] = []

    def persist_result(**kwargs):
        persisted.append(kwargs)
        return object(), {"accepted": True, "result_identity": "fixture-result"}

    monkeypatch.setattr(server, "_persist_custodied_job_result", persist_result)

    server._active_scans = {}
    server._finalize_durable_scan_after_exit("fixture-scan")
    service.mode = "terminal"
    server._finalize_durable_scan_after_exit("fixture-scan")
    service.mode = "no-attempt"
    server._finalize_durable_scan_after_exit("fixture-scan")

    service.mode = "running"
    server._active_scans = {
        "fixture-scan_web": {"returncode": None},
    }
    server._finalize_durable_scan_after_exit("fixture-scan")
    server._active_scans = {
        "fixture-scan_web": {"returncode": 0},
    }
    server._finalize_durable_scan_after_exit("fixture-scan")

    service.mode = "truth-failure"
    server._active_scans = {
        "fixture-scan_web": {
            "returncode": 0,
            "durable_lease_token": "lease-fixture",
        },
    }
    server._finalize_durable_scan_after_exit("fixture-scan")
    assert service.revoked == ["attempt-fixture"]

    service.mode = "running"
    server._finalize_durable_scan_after_exit("fixture-scan")
    assert service.inspected == ["run-fixture:webforge"]
    assert len(persisted) == 1
    assert persisted[0]["outcome"] == "success"
    assert len(persisted[0]["run_truths"]) == 1
    assert service.finished == [("attempt-fixture", "lease-fixture")]


def test_dashboard_exit_persists_canonical_custody_before_completion(
    tmp_path,
    monkeypatch,
):
    """Process exit only triggers a custodied, signed-truth terminal result."""

    import base64
    from dataclasses import replace

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    import common.run_truth as run_truth_module
    from common.action_authorization import (
        AuthorizationContext,
        ConfirmationMethod,
        OperatorRole,
        SafetyMode,
        consume_authorization,
        issue_authorization,
    )
    from common.confirm_gate import ActionConfirmation
    from common.dashboard.server import DashboardServer
    from common.db import (
        append_run_collection_truth,
        create_db,
        finding_set_identity,
    )
    from common.run_truth import (
        RUN_TRUTH_POLICY,
        RunCollectionStatus,
        RunCollectionTruth,
        run_collection_truth_attestation_payload,
    )

    state_root = tmp_path / "dashboard-state"
    monkeypatch.setenv("FORGE_DASHBOARD_STATE_DIR", str(state_root))
    database = tmp_path / "dashboard-custody.db"
    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda _self: database),
    )
    server = DashboardServer(auth=False)
    target = "https://fixture.invalid/"
    context = AuthorizationContext(
        tenant_id=server.tenant_id,
        engagement_id="engagement-dashboard-custody",
        run_id="run-dashboard-custody",
        job_id="dashboard-custody-job",
        operator_id="operator-dashboard-custody",
        operator_role=OperatorRole.OPERATOR,
        engine="webforge",
        module_id="webforge.scan",
        action_kind="webforge.scan",
        scope_policy_version="scope-policy-v1",
        requested_target=target,
        resolved_target=target,
        allowed_scope=[target],
        excluded_scope=[],
        safety_mode=SafetyMode.ACTIVE,
        confirmation_method=ConfirmationMethod.CLI_PROMPT,
        confirmed_by="operator-dashboard-custody",
    )
    contexts = {
        "webforge": context,
        "netforge": replace(
            context,
            engine="netforge",
            module_id="netforge.scan",
            action_kind="netforge.scan",
        ),
    }
    authorizations = {}
    authorization_session = create_db(database)
    try:
        for framework, framework_context in contexts.items():
            issued = issue_authorization(
                session=authorization_session,
                context=framework_context,
                confirmation=ActionConfirmation.create(
                    job_id=framework_context.job_id,
                    target=framework_context.resolved_target,
                    engine=framework_context.engine,
                    action=framework_context.action_kind,
                ),
            )
            assert issued.allowed
            consumed = consume_authorization(
                session=authorization_session,
                envelope=issued.envelope,
                expected=framework_context,
                boundary=f"{framework}.engine",
            )
            assert consumed.allowed
            authorizations[framework] = issued.envelope
    finally:
        authorization_session.close()

    service = server._durable_job_state()
    job = service.create_job(
        {
            "target": target,
            "frameworks": list(authorizations),
            "authorization_envelopes": {
                framework: envelope.to_dict()
                for framework, envelope in authorizations.items()
            },
            "source": "dashboard",
        },
        job_id=context.job_id,
        engagement_id=context.engagement_id,
        run_id=context.run_id,
        job_kind="dashboard_scan",
        target=target,
        state=JobState.QUEUED,
        authorization_decision_id=authorizations["webforge"].decision_id,
        authorization_action_id=authorizations["webforge"].action_id,
        authorization_bindings=tuple(
            {
                "authorization_decision_id": envelope.decision_id,
                "authorization_action_id": envelope.action_id,
                "framework": framework,
            }
            for framework, envelope in authorizations.items()
        ),
        work_items=tuple(authorizations),
    )
    leased = service.acquire_lease(
        context.job_id,
        "dashboard",
        control_boot_id="fixture-boot",
    )
    attempt = service.start_attempt(
        str(leased["id"]),
        str(leased["lease_token"]),
        worker_id="dashboard",
    )

    signer = Ed25519PrivateKey.generate()
    policy = replace(
        RUN_TRUTH_POLICY,
        issuer_public_key=base64.b64encode(
            signer.public_key().public_bytes_raw()
        ).decode("ascii"),
    )
    monkeypatch.setattr(run_truth_module, "RUN_TRUTH_POLICY", policy)
    truth_session = create_db(database)
    try:
        for index, (framework, envelope) in enumerate(
            authorizations.items(),
            start=1,
        ):
            run_truth_id = f"{context.run_id}:{framework}"
            truth = RunCollectionTruth(
                run_id=run_truth_id,
                authorization_run_id=context.run_id,
                job_id=context.job_id,
                tenant_id=context.tenant_id,
                framework=framework,
                scope_binding="sha256:" + f"{index:x}" * 64,
                target_binding="sha256:" + "b" * 64,
                collection_status=RunCollectionStatus.SUCCESS,
                coverage_complete=True,
                coverage_identity="sha256:" + f"{index + 2:x}" * 64,
                finding_set_identity=finding_set_identity(
                    truth_session,
                    tenant_id=context.tenant_id,
                    run_id=run_truth_id,
                ),
                predecessor_run_id="",
                run_sequence=1,
                completed_at="2026-08-27T00:00:00+00:00",
                authorization_decision_id=envelope.decision_id,
                authorization_binding=envelope.binding_digest,
                authority_id="fixture-run-authority",
                policy_id=policy.policy_id,
                policy_version=policy.policy_version,
                issuer_id=policy.issuer_id,
            )
            truth = replace(
                truth,
                attestation=base64.b64encode(
                    signer.sign(run_collection_truth_attestation_payload(truth))
                ).decode("ascii"),
            )
            append_run_collection_truth(truth_session, truth, policy=policy)
    finally:
        truth_session.close()

    server._active_scans = {
        f"{context.job_id}_web": {
            "returncode": 0,
            "durable_lease_token": attempt["lease_token"],
        },
        f"{context.job_id}_net": {
            "returncode": 0,
            "durable_lease_token": attempt["lease_token"],
        },
    }
    server._finalize_durable_scan_after_exit(context.job_id)

    stored = service.get_job(context.job_id)
    assert stored is not None
    assert stored["state"] == JobState.COMPLETED.value
    assert service.coverage_snapshot(context.job_id)["completed"] == 2
    assert service.conn.execute(
        "SELECT COUNT(*) FROM durable_job_state_deliveries "
        "WHERE tenant_id=? AND job_id=? AND state='accepted'",
        (context.tenant_id, context.job_id),
    ).fetchone()[0] == 1
    assert service.conn.execute(
        "SELECT COUNT(*) FROM durable_job_state_terminal_proofs "
        "WHERE tenant_id=? AND job_id=? AND proof_type='run_truth'",
        (context.tenant_id, context.job_id),
    ).fetchone()[0] == 2
    assert service.conn.execute(
        "SELECT COUNT(*) FROM canonical_observations "
        "WHERE tenant_id=? AND job_id=? AND attempt_id=?",
        (context.tenant_id, context.job_id, attempt["id"]),
    ).fetchone()[0] == 1
    custody_root = server._scan_results_dir / context.job_id / "evidence-custody"
    assert any(path.is_file() for path in custody_root.rglob("*"))
