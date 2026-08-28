"""Crash-window and restart-reconciliation contracts for Task 103.

These tests deliberately use only the public ``JobStateService`` operations.
The clock, authorization/evidence validators, process supervisor, and process
identities are all inert fixtures: no worker or child process is created.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import threading

import pytest

from common.job_state import (
    IdempotencyConflict,
    InvalidTransition,
    JobState,
    JobStateService,
    LeaseError,
    ObservationReceipt,
    ProcessIdentity,
    TerminalStateError,
    process_identity,
)


@dataclass
class FakeClock:
    value: float = 10_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@dataclass
class FakeSupervisor:
    """An inert identity-aware supervisor and launch discovery fixture."""

    alive: set[ProcessIdentity] = field(default_factory=set)
    discovered: dict[str, ProcessIdentity] = field(default_factory=dict)
    terminated: list[ProcessIdentity] = field(default_factory=list)
    killed: list[ProcessIdentity] = field(default_factory=list)

    def is_alive(self, identity: ProcessIdentity) -> bool:
        return identity in self.alive

    def terminate(self, identity: ProcessIdentity) -> None:
        self.terminated.append(identity)
        self.alive.discard(identity)

    def kill(self, identity: ProcessIdentity) -> None:
        self.killed.append(identity)
        self.alive.discard(identity)

    def discover(self, launch_nonce: str) -> ProcessIdentity | None:
        return self.discovered.get(launch_nonce)


class BlockingSupervisor(FakeSupervisor):
    """Pause cancellation at the public supervisor boundary."""

    def __init__(self, *args: object, block: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.block = block
        self.reached = threading.Event()
        self.release = threading.Event()

    def is_alive(self, identity: ProcessIdentity) -> bool:
        if self.block == "before-signal":
            self.reached.set()
            self.release.wait(timeout=5)
        return super().is_alive(identity)

    def terminate(self, identity: ProcessIdentity) -> None:
        if self.block == "after-signal":
            super().terminate(identity)
            self.reached.set()
            self.release.wait(timeout=5)
            return
        super().terminate(identity)


def _auth(_tenant: str, _job: str, _decision: str, _action: str) -> bool:
    return True


def _observed(_receipt: ObservationReceipt) -> bool:
    return True


def _service(
    path: object,
    clock: FakeClock,
    supervisor: FakeSupervisor | None = None,
) -> JobStateService:
    return JobStateService(
        path,
        clock=clock,
        process_supervisor=supervisor,
        authorization_checker=_auth,
        observation_checker=_observed,
    )


def _job(
    service: JobStateService,
    *,
    tenant: str = "tenant-a",
    job_id: str | None = None,
    state: JobState = JobState.QUEUED,
    required_work: int = 0,
    max_attempts: int = 1,
) -> dict[str, object]:
    decision = f"decision-{tenant}"
    action = f"action-{tenant}"
    return service.create_job(
        {"target": "fixture.invalid"},
        tenant_id=tenant,
        job_id=job_id,
        state=state,
        authorization_decision_id=decision,
        authorization_action_id=action,
        required_work=required_work,
        max_attempts=max_attempts,
        work_items=(f"work-{job_id or tenant}",) if required_work else (),
    )


def _running(
    service: JobStateService,
    job: dict[str, object],
    *,
    tenant: str = "tenant-a",
    worker: str = "worker-a",
    lease_seconds: float = 60.0,
    control_boot_id: str = "fixture-boot",
) -> dict[str, object]:
    leased = service.acquire_lease(
        str(job["id"]),
        worker,
        tenant_id=tenant,
        lease_seconds=lease_seconds,
        control_boot_id=control_boot_id,
    )
    return service.start_attempt(
        str(leased["id"]),
        str(leased["lease_token"]),
        tenant_id=tenant,
        worker_id=worker,
    )


def _reserve_process(
    service: JobStateService,
    job: dict[str, object],
    attempt: dict[str, object],
    *,
    identity_key: str = "main",
    tenant: str = "tenant-a",
) -> dict[str, object]:
    return service.reserve_process(
        str(job["id"]),
        str(attempt["id"]),
        identity_key,
        lease_token=str(attempt["lease_token"]),
        worker_id=str(attempt["worker_id"]),
        control_boot_id=str(attempt["control_boot_id"]),
        tenant_id=tenant,
    )


def _register_process(
    service: JobStateService,
    job: dict[str, object],
    attempt: dict[str, object],
    identity: ProcessIdentity,
    *,
    identity_key: str = "main",
    tenant: str = "tenant-a",
) -> dict[str, object]:
    return service.register_process(
        str(job["id"]),
        str(attempt["id"]),
        identity,
        lease_token=str(attempt["lease_token"]),
        worker_id=str(attempt["worker_id"]),
        control_boot_id=str(attempt["control_boot_id"]),
        identity_key=identity_key,
        tenant_id=tenant,
    )
def _receipt(
    job: dict[str, object],
    attempt: dict[str, object],
    *,
    tenant: str = "tenant-a",
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


def _accept_result(
    service: JobStateService,
    job: dict[str, object],
    attempt: dict[str, object],
    *,
    tenant: str = "tenant-a",
    outcome: str = "success",
    suffix: str = "one",
) -> None:
    service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        tenant_id=tenant,
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=_receipt(job, attempt, tenant=tenant, suffix=suffix),
        outcome=outcome,
    )


def _active_signed_truth_fixture(
    service: JobStateService,
    path: object,
    monkeypatch: pytest.MonkeyPatch,
    *,
    job_id: str,
) -> tuple[dict[str, object], dict[str, object], object]:
    """Create one active job and a locally signed persisted run-truth record."""

    import base64
    from dataclasses import replace

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    import common.run_truth as run_truth_module
    from common.db import append_run_collection_truth, create_db, finding_set_identity
    from common.run_truth import (
        RUN_TRUTH_POLICY,
        RunCollectionStatus,
        RunCollectionTruth,
        run_collection_truth_attestation_payload,
    )

    job = service.create_job(
        {"target": "fixture.invalid", "dry_run": False},
        tenant_id="tenant-a",
        job_id=job_id,
        run_id="authorization-run",
        job_kind="webforge",
        state=JobState.QUEUED,
        authorization_decision_id="decision-tenant-a",
        authorization_action_id="action-tenant-a",
        authorization_bindings=(
            {
                "authorization_decision_id": "decision-tenant-a",
                "authorization_action_id": "action-tenant-a",
                "framework": "webforge",
            },
        ),
        work_items=("webforge",),
    )
    attempt = _running(service, job)
    signer = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(signer.public_key().public_bytes_raw()).decode(
        "ascii"
    )
    policy = replace(RUN_TRUTH_POLICY, issuer_public_key=public_key)
    monkeypatch.setattr(run_truth_module, "RUN_TRUTH_POLICY", policy)
    session = create_db(path)
    try:
        record = RunCollectionTruth(
            run_id="authorization-run:webforge",
            authorization_run_id="authorization-run",
            job_id=str(job["id"]),
            tenant_id="tenant-a",
            framework="webforge",
            scope_binding="sha256:" + "a" * 64,
            target_binding="sha256:" + "b" * 64,
            collection_status=RunCollectionStatus.SUCCESS,
            coverage_complete=True,
            coverage_identity="sha256:" + "c" * 64,
            finding_set_identity=finding_set_identity(
                session,
                tenant_id="tenant-a",
                run_id="authorization-run:webforge",
            ),
            predecessor_run_id="",
            run_sequence=1,
            completed_at="2026-08-26T00:00:00+00:00",
            authorization_decision_id="decision-tenant-a",
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
    return job, attempt, record


def test_restart_reconciles_each_nonterminal_state_without_terminalizing_uncertainty(
    tmp_path,
):
    clock = FakeClock()
    path = tmp_path / "states.db"
    first = _service(path, clock)
    planned = _job(first, job_id="planned", state=JobState.PLANNED)
    pending = _job(first, job_id="pending", state=JobState.PENDING_APPROVAL)
    queued = _job(first, job_id="queued")
    leased_job = _job(first, job_id="leased")
    leased = first.acquire_lease(
        str(leased_job["id"]), "worker-leased", tenant_id="tenant-a"
    )
    running_job = _job(first, job_id="running")
    running = _running(first, running_job, worker="worker-running")
    paused_job = _job(first, job_id="paused")
    paused_attempt = _running(first, paused_job, worker="worker-paused")
    first.pause_job(str(paused_job["id"]), tenant_id="tenant-a")
    first.close()

    restarted = _service(path, clock)
    assert restarted.reconcile(tenant_id="tenant-a") == [str(running["id"])]
    assert restarted.get_job(str(planned["id"]), tenant_id="tenant-a")["state"] == JobState.PLANNED.value
    assert restarted.get_job(str(pending["id"]), tenant_id="tenant-a")["state"] == JobState.PENDING_APPROVAL.value
    assert restarted.get_job(str(queued["id"]), tenant_id="tenant-a")["state"] == JobState.QUEUED.value
    assert restarted.get_job(str(leased_job["id"]), tenant_id="tenant-a")["state"] == JobState.LEASED.value
    assert restarted.get_job(str(running_job["id"]), tenant_id="tenant-a")["state"] == JobState.ORPHANED.value
    assert restarted.get_job(str(paused_job["id"]), tenant_id="tenant-a")["state"] == JobState.PAUSED.value
    assert restarted.list_attempts(str(paused_job["id"]), tenant_id="tenant-a")[0]["state"] == "paused"
    assert restarted.list_attempts(str(leased_job["id"]), tenant_id="tenant-a")[0]["id"] == leased["id"]
    assert restarted.list_attempts(str(paused_job["id"]), tenant_id="tenant-a")[0]["id"] == paused_attempt["id"]
    # A second recovery is a no-op and cannot manufacture another attempt/event.
    events = restarted.list_events(str(running_job["id"]), tenant_id="tenant-a")
    assert restarted.reconcile(tenant_id="tenant-a") == []
    assert restarted.list_events(str(running_job["id"]), tenant_id="tenant-a") == events
    restarted.close()


@pytest.mark.parametrize("terminal", [JobState.PARTIAL, JobState.FAILED])
def test_restart_preserves_terminal_states_and_their_immutable_history(
    tmp_path, terminal: JobState
):
    clock = FakeClock()
    path = tmp_path / f"{terminal.value}.db"
    service = _service(path, clock)
    job = _job(service, job_id=terminal.value)
    if terminal is JobState.PARTIAL:
        attempt = _running(service, job)
        _accept_result(service, job, attempt, outcome="partial")
        service.finish_attempt(
            str(attempt["id"]),
            lease_token=str(attempt["lease_token"]),
            tenant_id="tenant-a",
        )
    else:
        attempt = _running(service, job)
        _accept_result(service, job, attempt, outcome="failure")
        service.finish_attempt(
            str(attempt["id"]),
            lease_token=str(attempt["lease_token"]),
            tenant_id="tenant-a",
            success=False,
            error_reason="fixture failure",
        )
    assert service.get_job(str(job["id"]), tenant_id="tenant-a")["state"] == terminal.value
    service.close()

    restarted = _service(path, clock)
    before = restarted.get_job(str(job["id"]), tenant_id="tenant-a")
    events = restarted.list_events(str(job["id"]), tenant_id="tenant-a")
    assert restarted.reconcile() == []
    assert restarted.get_job(str(job["id"]), tenant_id="tenant-a") == before
    assert restarted.list_events(str(job["id"]), tenant_id="tenant-a") == events
    with pytest.raises(InvalidTransition):
        restarted.transition(str(job["id"]), JobState.QUEUED, tenant_id="tenant-a")
    with pytest.raises(InvalidTransition):
        restarted.retry_job(str(job["id"]), tenant_id="tenant-a")


def test_restart_preserves_completed_and_canceled_terminal_states(tmp_path):
    clock = FakeClock()
    path = tmp_path / "terminal.db"
    service = _service(path, clock)

    completed = _job(service, job_id="completed")
    attempt = _running(service, completed)
    _accept_result(service, completed, attempt)
    service.finish_attempt(
        str(attempt["id"]), lease_token=str(attempt["lease_token"]), tenant_id="tenant-a"
    )
    canceled = _job(service, job_id="canceled")
    service.cancel_job(str(canceled["id"]), tenant_id="tenant-a")
    before = {
        str(job["id"]): (
            service.get_job(str(job["id"]), tenant_id="tenant-a"),
            service.list_events(str(job["id"]), tenant_id="tenant-a"),
        )
        for job in (completed, canceled)
    }
    service.close()

    restarted = _service(path, clock)
    assert restarted.reconcile() == []
    for job in (completed, canceled):
        current = restarted.get_job(str(job["id"]), tenant_id="tenant-a")
        assert current == before[str(job["id"])][0]
        assert restarted.list_events(str(job["id"]), tenant_id="tenant-a") == before[str(job["id"])][1]
        # Cancellation may be replayed safely, but must not mutate the terminal row.
        assert restarted.cancel_job(str(job["id"]), tenant_id="tenant-a") == current


def test_crash_after_lease_before_start_keeps_attempt_and_expiry_requeues_once(tmp_path):
    clock = FakeClock()
    path = tmp_path / "lease-window.db"
    service = _service(path, clock)
    job = _job(service, job_id="lease-window", max_attempts=2)
    leased = service.acquire_lease(
        str(job["id"]), "worker-a", tenant_id="tenant-a", lease_seconds=5
    )
    events_before = service.list_events(str(job["id"]), tenant_id="tenant-a")
    service.close()

    restarted = _service(path, clock)
    assert restarted.reconcile() == []
    assert restarted.get_job(str(job["id"]), tenant_id="tenant-a")["state"] == JobState.LEASED.value
    assert restarted.list_attempts(str(job["id"]), tenant_id="tenant-a")[0]["id"] == leased["id"]
    assert restarted.list_events(str(job["id"]), tenant_id="tenant-a") == events_before
    clock.advance(6)
    assert restarted.reconcile() == [str(leased["id"])]
    assert restarted.get_job(str(job["id"]), tenant_id="tenant-a")["state"] == JobState.QUEUED.value
    assert restarted.list_attempts(str(job["id"]), tenant_id="tenant-a")[0]["state"] == "expired"
    assert restarted.reconcile() == []


def test_crash_at_launch_intent_and_registered_child_windows_never_completes_work(
    tmp_path,
):
    clock = FakeClock()
    path = tmp_path / "process-windows.db"
    supervisor = FakeSupervisor()
    service = _service(path, clock, supervisor)

    intent_job = _job(service, job_id="intent")
    intent_attempt = _running(service, intent_job)
    intent = _reserve_process(service, intent_job, intent_attempt)
    service.close()
    restarted = _service(path, clock, supervisor)
    assert restarted.reconcile() == [str(intent_attempt["id"])]
    assert restarted.get_job(str(intent_job["id"]), tenant_id="tenant-a")["state"] == JobState.ORPHANED.value
    assert restarted.list_attempts(str(intent_job["id"]), tenant_id="tenant-a")[0]["id"] == intent_attempt["id"]
    assert any(event["event_type"] == "child_launch_reserved" for event in restarted.list_events(str(intent_job["id"]), tenant_id="tenant-a"))
    assert restarted.reconcile() == []

    child_job = _job(restarted, job_id="registered-before-running")
    child_attempt = restarted.acquire_lease(
        str(child_job["id"]),
        "worker-child",
        tenant_id="tenant-a",
        control_boot_id="fixture-boot",
    )
    launch = _reserve_process(restarted, child_job, child_attempt)
    identity = process_identity(
        31001,
        start_token="fixture-start",
        command="inert-fixture-child",
        boot_id="fixture-boot",
        launch_nonce=str(launch["launch_nonce"]),
    )
    _register_process(restarted, child_job, child_attempt, identity)
    restarted.close()
    # The child is already dead at restart; the leased attempt remains leased,
    # while the dead identity is durably marked stopped.
    dead_supervisor = FakeSupervisor()
    restarted = _service(path, clock, dead_supervisor)
    assert restarted.reconcile() == [str(child_attempt["id"])]
    assert restarted.get_job(str(child_job["id"]), tenant_id="tenant-a")["state"] == JobState.LEASED.value
    assert restarted.children(str(child_job["id"]), tenant_id="tenant-a") == []
    assert restarted.list_attempts(str(child_job["id"]), tenant_id="tenant-a")[0]["state"] == "leased"
    assert restarted.list_events(str(child_job["id"]), tenant_id="tenant-a")[-1]["event_type"] == "child_reconciled_stopped"


def test_result_and_proof_before_terminal_write_are_reconciled_without_duplicate_delivery(
    tmp_path,
):
    clock = FakeClock()
    path = tmp_path / "result-window.db"
    service = _service(path, clock)
    job = _job(service, job_id="result-window")
    attempt = _running(service, job)
    _accept_result(service, job, attempt)
    service.append_log(
        str(job["id"]),
        "accepted result before terminal transition",
        tenant_id="tenant-a",
        attempt_id=str(attempt["id"]),
    )
    events_before = service.list_events(str(job["id"]), tenant_id="tenant-a")
    service.close()

    restarted = _service(path, clock)
    assert restarted.reconcile() == [str(attempt["id"])]
    assert restarted.get_job(str(job["id"]), tenant_id="tenant-a")["state"] == JobState.COMPLETED.value
    assert restarted.list_attempts(str(job["id"]), tenant_id="tenant-a")[0]["state"] == "completed"
    assert restarted.latest_delivery(str(attempt["id"]), tenant_id="tenant-a")["observation_id"] == "observation-one"
    assert restarted.list_logs(str(job["id"]), tenant_id="tenant-a")[0]["message"] == "accepted result before terminal transition"
    assert len([event for event in restarted.list_events(str(job["id"]), tenant_id="tenant-a") if event["event_type"] == "result_accepted"]) == 1
    assert len(restarted.list_events(str(job["id"]), tenant_id="tenant-a")) > len(events_before)
    assert restarted.reconcile() == []


def test_restart_run_truth_proof_without_delivery_never_finalizes_attempt(
    tmp_path, monkeypatch
):
    clock = FakeClock()
    path = tmp_path / "run-truth-only.db"
    supervisor = FakeSupervisor()
    service = _service(path, clock, supervisor)
    job, attempt, record = _active_signed_truth_fixture(
        service,
        path,
        monkeypatch,
        job_id="run-truth-only",
    )
    service.record_run_truth(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        record.run_id,
        tenant_id="tenant-a",
        worker_id="worker-a",
    )
    events_before_restart = service.list_events(
        str(job["id"]), tenant_id="tenant-a"
    )
    service.close()

    restarted = _service(path, clock, supervisor)
    assert restarted.reconcile(tenant_id="tenant-a") == [str(attempt["id"])]
    assert restarted.get_job(
        str(job["id"]), tenant_id="tenant-a"
    )["state"] == JobState.ORPHANED.value
    assert restarted.list_attempts(
        str(job["id"]), tenant_id="tenant-a"
    )[0]["state"] == "orphaned"
    assert restarted.latest_delivery(
        str(attempt["id"]), tenant_id="tenant-a"
    ) is None
    assert "accepted_delivery_missing" in restarted.completion_blockers(
        str(job["id"]), tenant_id="tenant-a"
    )
    events_after_restart = restarted.list_events(
        str(job["id"]), tenant_id="tenant-a"
    )
    assert sum(event["event_type"] == "run_truth_accepted" for event in events_after_restart) == 1
    assert not any(
        event["event_type"] == "attempt_finished" for event in events_after_restart
    )
    assert restarted.reconcile(tenant_id="tenant-a") == []
    assert restarted.list_events(
        str(job["id"]), tenant_id="tenant-a"
    ) == events_after_restart
    assert len(events_after_restart) > len(events_before_restart)
    restarted.close()


def test_restart_reconciles_exact_delivery_and_signed_truth_once(
    tmp_path, monkeypatch
):
    clock = FakeClock()
    path = tmp_path / "run-truth-delivery.db"
    supervisor = FakeSupervisor()
    service = _service(path, clock, supervisor)
    job, attempt, record = _active_signed_truth_fixture(
        service,
        path,
        monkeypatch,
        job_id="run-truth-delivery",
    )
    service.record_run_truth(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        record.run_id,
        tenant_id="tenant-a",
        worker_id="worker-a",
    )
    inspected = service.inspect_run_truth(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        record.run_id,
        tenant_id="tenant-a",
        worker_id="worker-a",
    )
    accepted = service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        tenant_id="tenant-a",
        delivery_key=str(attempt["delivery_idempotency_key"]),
        receipt=_receipt(job, attempt, tenant="tenant-a", suffix="restart"),
        outcome=str(inspected["outcome"]),
        work=inspected["work"],
        run_truths=[inspected["receipt"]],
        worker_id="worker-a",
    )
    assert accepted["duplicate"] is False
    service.close()

    restarted = _service(path, clock, supervisor)
    assert restarted.reconcile(tenant_id="tenant-a") == [str(attempt["id"])]
    assert restarted.get_job(
        str(job["id"]), tenant_id="tenant-a"
    )["state"] == JobState.COMPLETED.value
    assert restarted.list_attempts(
        str(job["id"]), tenant_id="tenant-a"
    )[0]["state"] == "completed"
    assert restarted.latest_delivery(
        str(attempt["id"]), tenant_id="tenant-a"
    )["observation_id"] == "observation-restart"
    events_after_reconcile = restarted.list_events(
        str(job["id"]), tenant_id="tenant-a"
    )
    assert sum(event["event_type"] == "run_truth_accepted" for event in events_after_reconcile) == 1
    assert sum(event["event_type"] == "result_accepted" for event in events_after_reconcile) == 1
    assert sum(event["event_type"] == "attempt_finished" for event in events_after_reconcile) == 1
    assert restarted.coverage_snapshot(
        str(job["id"]), tenant_id="tenant-a"
    )["completed"] == 1
    assert restarted.reconcile(tenant_id="tenant-a") == []
    assert restarted.list_events(
        str(job["id"]), tenant_id="tenant-a"
    ) == events_after_reconcile
    restarted.close()


def test_cancel_crash_before_signal_is_finished_by_a_restarted_reconciler(tmp_path):
    clock = FakeClock()
    path = tmp_path / "cancel-before-signal.db"
    identity = process_identity(
        32001,
        start_token="start",
        command="inert-child",
        boot_id="fixture-boot",
    )
    blocking = BlockingSupervisor({identity}, block="before-signal")
    service = _service(path, clock, blocking)
    job = _job(service, job_id="cancel-before-signal")
    attempt = _running(service, job)
    launch = _reserve_process(service, job, attempt)
    registered = ProcessIdentity(
        **{**identity.to_dict(), "launch_nonce": str(launch["launch_nonce"])}
    )
    _register_process(service, job, attempt, registered)
    blocking.alive = {registered}

    outcome: list[dict[str, object]] = []

    def cancel() -> None:
        outcome.append(
            service.cancel_job(str(job["id"]), tenant_id="tenant-a", sla_seconds=5)
        )

    thread = threading.Thread(target=cancel)
    thread.start()
    assert blocking.reached.wait(timeout=5)
    restart_supervisor = FakeSupervisor({registered})
    restarted = _service(path, clock, restart_supervisor)
    assert restarted.reconcile() == [str(job["id"])]
    assert restarted.get_job(str(job["id"]), tenant_id="tenant-a")["state"] == JobState.CANCELED.value
    blocking.release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert outcome[0]["state"] == JobState.CANCELED.value
    assert restart_supervisor.terminated == [registered]
    assert len(restarted.list_attempts(str(job["id"]), tenant_id="tenant-a")) == 1


def test_cancel_crash_after_signal_is_finished_without_duplicate_signal(tmp_path):
    clock = FakeClock()
    path = tmp_path / "cancel-after-signal.db"
    identity = process_identity(
        32002,
        start_token="start",
        command="inert-child",
        boot_id="fixture-boot",
    )
    blocking = BlockingSupervisor({identity}, block="after-signal")
    service = _service(path, clock, blocking)
    job = _job(service, job_id="cancel-after-signal")
    attempt = _running(service, job)
    launch = _reserve_process(service, job, attempt)
    registered = ProcessIdentity(
        **{**identity.to_dict(), "launch_nonce": str(launch["launch_nonce"])}
    )
    _register_process(service, job, attempt, registered)
    blocking.alive = {registered}
    outcome: list[dict[str, object]] = []

    thread = threading.Thread(
        target=lambda: outcome.append(
            service.cancel_job(str(job["id"]), tenant_id="tenant-a", sla_seconds=5)
        )
    )
    thread.start()
    assert blocking.reached.wait(timeout=5)
    # The signal has committed at the supervisor boundary; a restarted reader
    # observes the dead identity and completes the durable cancel phase.
    restarted = _service(path, clock, FakeSupervisor())
    assert restarted.reconcile() == [str(attempt["id"]), str(job["id"])]
    assert restarted.get_job(str(job["id"]), tenant_id="tenant-a")["state"] == JobState.CANCELED.value
    blocking.release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert outcome[0]["state"] == JobState.CANCELED.value
    assert blocking.terminated == [registered]
    assert blocking.killed == []


def test_revoked_or_expired_leases_cannot_report_and_preserve_prior_attempts(tmp_path):
    clock = FakeClock()
    path = tmp_path / "lease-fencing.db"
    service = _service(path, clock)
    revoked_job = _job(service, job_id="revoked")
    revoked = service.acquire_lease(
        str(revoked_job["id"]), "worker-a", tenant_id="tenant-a", lease_seconds=60
    )
    assert service.revoke_lease(
        str(revoked["id"]), tenant_id="tenant-a", reason="agent revoked"
    ) is True
    with pytest.raises(LeaseError):
        service.record_result(
            str(revoked["id"]), str(revoked["lease_token"]),
            delivery_key=str(revoked["delivery_idempotency_key"]),
            tenant_id="tenant-a",
            receipt=_receipt(revoked_job, revoked),
        )
    service.close()

    restarted = _service(path, clock)
    assert restarted.reconcile() == []
    assert restarted.get_job(str(revoked_job["id"]), tenant_id="tenant-a")["state"] == JobState.ORPHANED.value
    assert len(restarted.list_attempts(str(revoked_job["id"]), tenant_id="tenant-a")) == 1
    expired_job = _job(restarted, job_id="expired", max_attempts=1)
    expired = restarted.acquire_lease(
        str(expired_job["id"]), "worker-a", tenant_id="tenant-a", lease_seconds=5
    )
    clock.advance(6)
    with pytest.raises(LeaseError):
        restarted.record_result(
            str(expired["id"]), str(expired["lease_token"]),
            delivery_key=str(expired["delivery_idempotency_key"]),
            tenant_id="tenant-a",
            receipt=_receipt(expired_job, expired, suffix="expired"),
        )
    assert restarted.reconcile() == [str(expired["id"])]
    assert restarted.get_job(str(expired_job["id"]), tenant_id="tenant-a")["state"] == JobState.EXPIRED.value
    assert len(restarted.list_attempts(str(expired_job["id"]), tenant_id="tenant-a")) == 1
    preserved = {
        str(job["id"]): restarted.list_events(
            str(job["id"]),
            tenant_id="tenant-a",
        )
        for job in (revoked_job, expired_job)
    }
    restarted.close()
    restarted = _service(path, clock)
    assert restarted.reconcile() == []
    assert restarted.get_job(
        str(revoked_job["id"]),
        tenant_id="tenant-a",
    )["state"] == JobState.ORPHANED.value
    assert restarted.get_job(
        str(expired_job["id"]),
        tenant_id="tenant-a",
    )["state"] == JobState.EXPIRED.value
    for job in (revoked_job, expired_job):
        assert restarted.list_events(
            str(job["id"]),
            tenant_id="tenant-a",
        ) == preserved[str(job["id"])]


def test_tenant_scoped_reconciliation_keeps_same_ids_and_history_isolated(tmp_path):
    clock = FakeClock()
    path = tmp_path / "tenants.db"
    service = _service(path, clock)
    alpha = _job(service, tenant="alpha", job_id="same-shape-alpha", max_attempts=2)
    bravo = _job(service, tenant="bravo", job_id="same-shape-bravo", max_attempts=2)
    alpha_attempt = service.acquire_lease("same-shape-alpha", "alpha-worker", tenant_id="alpha", lease_seconds=5)
    bravo_attempt = service.acquire_lease("same-shape-bravo", "bravo-worker", tenant_id="bravo", lease_seconds=60)
    alpha_events = service.list_events("same-shape-alpha", tenant_id="alpha")
    bravo_events = service.list_events("same-shape-bravo", tenant_id="bravo")
    clock.advance(6)
    assert service.reconcile(tenant_id="alpha") == [str(alpha_attempt["id"])]
    assert service.get_job("same-shape-alpha", tenant_id="alpha")["state"] == JobState.QUEUED.value
    assert service.get_job("same-shape-bravo", tenant_id="bravo")["state"] == JobState.LEASED.value
    assert service.list_attempts("same-shape-bravo", tenant_id="bravo")[0]["id"] == bravo_attempt["id"]
    assert service.list_events("same-shape-alpha", tenant_id="alpha") != bravo_events
    assert service.list_events("same-shape-bravo", tenant_id="bravo") == bravo_events
    assert service.list_events("same-shape-alpha", tenant_id="alpha")[: len(alpha_events)] == alpha_events
    assert not service.validate_lease(
        str(alpha_attempt["id"]), str(alpha_attempt["lease_token"]), tenant_id="bravo"
    )
    assert service.get_job(str(alpha["id"]), tenant_id="alpha")["tenant_id"] == "alpha"
    assert service.get_job(str(bravo["id"]), tenant_id="bravo")["tenant_id"] == "bravo"


def test_restart_fences_a_revoked_agent_assignment_before_new_work(tmp_path):
    clock = FakeClock()
    path = tmp_path / "revoked-agent.db"
    service = _service(path, clock)
    service.register_agent(
        "agent-revoked",
        tenant_id="tenant-a",
        key_id="key-revoked",
        credential_digest="a" * 64,
        engines=("webforge",),
        capabilities=("dry_run",),
        scope=("fixture.invalid",),
    )
    job = service.create_job(
        {"target": "fixture.invalid"},
        tenant_id="tenant-a",
        job_id="revoked-agent-job",
        state=JobState.QUEUED,
        assigned_agent_id="agent-revoked",
        authorization_decision_id="decision-tenant-a",
        authorization_action_id="action-tenant-a",
    )
    attempt = service.acquire_lease(
        str(job["id"]),
        "agent-revoked",
        tenant_id="tenant-a",
    )
    service.start_attempt(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        tenant_id="tenant-a",
        worker_id="agent-revoked",
    )
    _agent, jobs = service.revoke_agent(
        "agent-revoked",
        tenant_id="tenant-a",
    )
    assert jobs == [str(job["id"])]
    service.close()

    restarted = _service(path, clock)
    assert restarted.reconcile(tenant_id="tenant-a") == [str(job["id"])]
    assert restarted.get_job(
        str(job["id"]),
        tenant_id="tenant-a",
    )["state"] == JobState.CANCELED.value
    assert not restarted.validate_lease(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        tenant_id="tenant-a",
    )
