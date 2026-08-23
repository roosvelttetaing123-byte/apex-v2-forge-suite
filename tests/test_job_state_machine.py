"""Deterministic contract tests for the Task-103 durable job authority."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
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
    ProcessIdentity,
    TerminalStateError,
    WorkState,
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


def _queued_job(
    service: JobStateService,
    *,
    required_work: int = 0,
    max_attempts: int = 1,
    tenant_id: str = "default",
) -> dict[str, object]:
    return service.create_job(
        {"target": "fixture.local"},
        tenant_id=tenant_id,
        state=JobState.QUEUED,
        required_work=required_work,
        max_attempts=max_attempts,
    )


def _running_attempt(
    service: JobStateService,
    job_id: str,
    *,
    tenant_id: str = "default",
    worker_id: str = "worker-a",
    lease_seconds: float = 60,
) -> dict[str, object]:
    leased = service.acquire_lease(
        job_id,
        worker_id,
        tenant_id=tenant_id,
        lease_seconds=lease_seconds,
    )
    service.start_attempt(
        str(leased["id"]),
        str(leased["lease_token"]),
        tenant_id=tenant_id,
        worker_id=worker_id,
    )
    return leased


def test_transition_table_is_versioned_and_illegal_transition_is_atomic(tmp_path):
    service = JobStateService(tmp_path / "jobs.db")
    table = transition_table()
    assert table["version"]
    assert set(table["states"]) == {state.value for state in JobState}
    assert "completed" in table["terminal_states"]

    job = service.create_job(state=JobState.PLANNED)
    before = service.get_job(str(job["id"]))
    events_before = service.list_events(str(job["id"]))
    with pytest.raises(InvalidTransition):
        service.transition(str(job["id"]), JobState.RUNNING)
    assert service.get_job(str(job["id"])) == before
    assert service.list_events(str(job["id"])) == events_before

    service.transition(str(job["id"]), JobState.QUEUED, expected_version=int(job["version"]))
    with pytest.raises(InvalidTransition):
        service.transition(str(job["id"]), JobState.COMPLETED)
    before = service.get_job(str(job["id"]))
    with pytest.raises(InvalidTransition, match="lifecycle operation"):
        service.transition(str(job["id"]), JobState.LEASED)
    assert service.get_job(str(job["id"])) == before


def test_idempotent_job_transition_result_and_terminal_finish_replay(tmp_path):
    service = JobStateService(tmp_path / "jobs.db")
    job = service.create_job({"target": "fixture"}, idempotency_key="request-1")
    replay = service.create_job({"target": "fixture"}, idempotency_key="request-1")
    assert replay["id"] == job["id"]
    with pytest.raises(IdempotencyConflict):
        service.create_job({"target": "different"}, idempotency_key="request-1")

    service.transition(str(job["id"]), JobState.QUEUED, idempotency_key="enqueue-1")
    service.transition(str(job["id"]), JobState.QUEUED, idempotency_key="enqueue-1")
    attempt = service.acquire_lease(str(job["id"]), "worker-a")
    service.start_attempt(str(attempt["id"]), str(attempt["lease_token"]))
    finished = service.finish_attempt(
        str(attempt["id"]), lease_token=str(attempt["lease_token"])
    )
    assert finished["state"] == "succeeded"
    assert service.get_job(str(job["id"]))["state"] == JobState.COMPLETED.value
    # A crash after the terminal write can redeliver the exact finish safely.
    assert service.finish_attempt(
        str(attempt["id"]), lease_token=str(attempt["lease_token"])
    )["state"] == "succeeded"


def test_lease_replay_recovers_an_active_capability_and_every_attempt_has_a_key(tmp_path):
    service = JobStateService(tmp_path / "jobs.db")
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
    service = JobStateService(tmp_path / "jobs.db")
    job = _queued_job(service, required_work=1)
    with pytest.raises(InvalidTransition, match="accepted through a result delivery"):
        service.mark_work(str(job["id"]), "required")
    service.pause_job(str(job["id"]))
    with pytest.raises(TerminalStateError, match="required_work_incomplete"):
        service.complete_job(str(job["id"]))


def test_attempt_cannot_finish_before_it_is_started(tmp_path):
    service = JobStateService(tmp_path / "jobs.db")
    job = _queued_job(service)
    leased = service.acquire_lease(str(job["id"]), "worker-a")
    with pytest.raises(InvalidTransition, match="must be started"):
        service.finish_attempt(
            str(leased["id"]),
            lease_token=str(leased["lease_token"]),
        )
    assert service.get_job(str(job["id"]))["state"] == JobState.LEASED.value
    assert service.list_attempts(str(job["id"]))[0]["started_at"] is None


def test_concurrent_lease_acquisition_has_one_owner_and_one_attempt(tmp_path):
    path = tmp_path / "jobs.db"
    first = JobStateService(path)
    second = JobStateService(path)
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
    service = JobStateService(tmp_path / "jobs.db")
    job = _queued_job(service, required_work=1)
    attempt = _running_attempt(service, str(job["id"]))
    work = [{"work_key": "route:/health", "observation_id": "observation-1"}]
    accepted = service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key="delivery-1",
        observation_id="observation-1",
        result_ref="observation:1",
        work=work,
    )
    assert accepted["duplicate"] is False
    assert service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key="delivery-1",
        observation_id="observation-1",
        result_ref="observation:1",
        work=work,
    )["duplicate"] is True
    with pytest.raises(IdempotencyConflict):
        service.record_result(
            str(attempt["id"]),
            str(attempt["lease_token"]),
            delivery_key="delivery-1",
            observation_id="observation-1",
            result_ref="different",
            work=work,
        )
    with pytest.raises(IdempotencyConflict):
        service.record_result(
            str(attempt["id"]),
            str(attempt["lease_token"]),
            delivery_key="delivery-2",
            observation_id="observation-1",
            result_ref="different",
            work=work,
        )

    service.finish_attempt(str(attempt["id"]), lease_token=str(attempt["lease_token"]))
    # Exact redelivery after terminal state uses the stored token digest only
    # for replay authentication; it cannot create another observation.
    assert service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key="delivery-1",
        observation_id="observation-1",
        result_ref="observation:1",
        work=work,
    )["duplicate"] is True
    assert len(service.coverage_snapshot(str(job["id"]))["items"]) == 1
    assert sum(
        event["event_type"] == "result_accepted"
        for event in service.list_events(str(job["id"]))
    ) == 1


def test_retry_preserves_prior_events_and_resolves_prior_failed_work(tmp_path):
    service = JobStateService(tmp_path / "jobs.db")
    job = _queued_job(service, required_work=1, max_attempts=2)
    first = _running_attempt(service, str(job["id"]))
    service.finish_attempt(
        str(first["id"]),
        lease_token=str(first["lease_token"]),
        success=False,
        failed=[{"work_key": "route:/health", "reason": "fixture timeout"}],
        error_reason="fixture timeout",
    )
    assert service.get_job(str(job["id"]))["state"] == JobState.QUEUED.value
    second = _running_attempt(service, str(job["id"]))
    service.finish_attempt(
        str(second["id"]),
        lease_token=str(second["lease_token"]),
        coverage_keys=["route:/health"],
        result_ref="observation:retry-success",
    )
    attempts = service.list_attempts(str(job["id"]))
    assert [attempt["state"] for attempt in attempts] == ["failed", "succeeded"]
    assert service.get_job(str(job["id"]))["state"] == JobState.COMPLETED.value
    assert service.coverage_snapshot(str(job["id"]))["failed"] == 0
    event_attempts = {event["attempt_id"] for event in service.list_events(str(job["id"]))}
    assert {str(first["id"]), str(second["id"])} <= event_attempts


def test_pause_prevents_start_and_cancel_revokes_paused_active_attempt(tmp_path):
    service = JobStateService(tmp_path / "jobs.db")
    job = _queued_job(service)
    attempt = service.acquire_lease(str(job["id"]), "worker-a")
    service.pause_job(str(job["id"]))
    with pytest.raises(InvalidTransition, match="paused"):
        service.start_attempt(str(attempt["id"]), str(attempt["lease_token"]))
    assert service.resume_job(str(job["id"]))["state"] == JobState.LEASED.value
    service.start_attempt(str(attempt["id"]), str(attempt["lease_token"]))
    service.pause_job(str(job["id"]))
    canceled = service.cancel_job(str(job["id"]))
    assert canceled["state"] == JobState.CANCELED.value
    assert service.list_attempts(str(job["id"]))[0]["state"] == "canceled"
    assert not service.validate_lease(str(attempt["id"]), str(attempt["lease_token"]))


def test_cancel_preserves_partial_evidence_and_materializes_missing_coverage(tmp_path):
    service = JobStateService(tmp_path / "jobs.db")
    job = _queued_job(service, required_work=2)
    attempt = _running_attempt(service, str(job["id"]))
    service.record_result(
        str(attempt["id"]),
        str(attempt["lease_token"]),
        delivery_key="first-evidence",
        observation_id="observation:one",
        result_ref="observation:one",
        work=[{"work_key": "one", "observation_id": "observation:one"}],
    )
    canceled = service.cancel_job(str(job["id"]), reason="operator cancellation")
    snapshot = service.coverage_snapshot(str(job["id"]))
    assert canceled["state"] == JobState.PARTIAL.value
    assert snapshot["completed"] == 1
    assert snapshot["uncollected"] == 1
    missing = next(item for item in snapshot["items"] if item["state"] == "uncollected")
    assert missing["reason"] == "operator cancellation"


def test_terminal_failure_and_partial_materialize_declared_missing_work(tmp_path):
    service = JobStateService(tmp_path / "jobs.db")
    failed_job = _queued_job(service, required_work=1)
    failed_attempt = _running_attempt(service, str(failed_job["id"]))
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
    service.finish_attempt(
        str(partial_attempt["id"]),
        lease_token=str(partial_attempt["lease_token"]),
        result_ref="observation:incomplete",
        terminal_reason="fixture incomplete coverage",
    )
    partial_coverage = service.coverage_snapshot(str(partial_job["id"]))
    assert service.get_job(str(partial_job["id"]))["state"] == JobState.PARTIAL.value
    assert partial_coverage["uncollected"] == 2
    assert all(item["reason"] == "fixture incomplete coverage" for item in partial_coverage["items"])


@pytest.mark.parametrize("state", [JobState.PLANNED, JobState.PENDING_APPROVAL, JobState.QUEUED])
def test_cancel_is_idempotent_for_non_started_work(tmp_path, state):
    service = JobStateService(tmp_path / f"{state.value}.db")
    job = service.create_job(state=state)
    assert service.cancel_job(str(job["id"]))["state"] == JobState.CANCELED.value
    assert service.cancel_job(str(job["id"]))["state"] == JobState.CANCELED.value


def test_cancellation_stops_mocked_child_within_sla_and_pid_reuse_is_not_signaled(tmp_path):
    identity = process_identity(4242, start_token="first", command="fixture-worker")
    supervisor = FakeSupervisor(identity)
    service = JobStateService(tmp_path / "jobs.db", process_supervisor=supervisor)
    job = _queued_job(service)
    attempt = _running_attempt(service, str(job["id"]))
    service.register_process(str(job["id"]), str(attempt["id"]), identity)
    started = time.monotonic()
    assert service.cancel_job(str(job["id"]), sla_seconds=0.1)["state"] == JobState.CANCELED.value
    assert time.monotonic() - started < 0.1
    assert supervisor.terminated == [identity]
    assert supervisor.killed == []

    reused = process_identity(5151, start_token="old", command="old-command")
    unrelated = process_identity(5151, start_token="new", command="new-command")
    reuse_supervisor = FakeSupervisor(unrelated)
    second = JobStateService(tmp_path / "pid-reuse.db", process_supervisor=reuse_supervisor)
    reuse_job = _queued_job(second)
    reuse_attempt = _running_attempt(second, str(reuse_job["id"]))
    second.register_process(str(reuse_job["id"]), str(reuse_attempt["id"]), reused)
    assert second.cancel_job(str(reuse_job["id"]), sla_seconds=0)["state"] == JobState.CANCELED.value
    assert reuse_supervisor.terminated == []
    assert reuse_supervisor.killed == []

    stubborn = process_identity(6161, start_token="stubborn", command="fixture-worker")
    stubborn_supervisor = FakeSupervisor(stubborn, terminate_stops=False)
    stubborn_service = JobStateService(
        tmp_path / "escalation.db",
        process_supervisor=stubborn_supervisor,
    )
    stubborn_job = _queued_job(stubborn_service)
    stubborn_attempt = _running_attempt(stubborn_service, str(stubborn_job["id"]))
    stubborn_service.register_process(
        str(stubborn_job["id"]), str(stubborn_attempt["id"]), stubborn
    )
    stubborn_service.cancel_job(str(stubborn_job["id"]), sla_seconds=0)
    assert stubborn_supervisor.terminated == [stubborn]
    assert stubborn_supervisor.killed == [stubborn]
    assert any(
        event["event_type"] == "child_kill_requested"
        for event in stubborn_service.list_events(str(stubborn_job["id"]))
    )


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
    service = JobStateService(tmp_path / f"{work_state.value}.db")
    job = service.create_job(required_work=1)
    service.mark_work(str(job["id"]), "required", state=work_state, reason="fixture")
    service.pause_job(str(job["id"]))
    assert expected in service.completion_blockers(str(job["id"]))
    with pytest.raises(TerminalStateError):
        service.complete_job(str(job["id"]))


def test_completion_rejects_active_attempt_and_required_child_and_terminal_is_immutable(tmp_path):
    service = JobStateService(tmp_path / "jobs.db")
    active_job = _queued_job(service)
    active = service.acquire_lease(str(active_job["id"]), "worker-a")
    assert "active_attempt" in service.completion_blockers(str(active_job["id"]))
    with pytest.raises(TerminalStateError):
        service.complete_job(str(active_job["id"]))
    service.cancel_job(str(active_job["id"]))

    parent = service.create_job()
    service.create_child(str(parent["id"]), "child-1")
    service.pause_job(str(parent["id"]))
    assert "unresolved_child:child-1" in service.completion_blockers(str(parent["id"]))
    with pytest.raises(TerminalStateError):
        service.complete_job(str(parent["id"]))

    complete = service.create_job()
    service.pause_job(str(complete["id"]))
    service.complete_job(str(complete["id"]))
    with pytest.raises(TerminalStateError):
        service.mark_work(str(complete["id"]), "late", state=WorkState.FAILED)
    with pytest.raises(TerminalStateError):
        service.create_child(str(complete["id"]), "late-child")
    assert service.get_job(str(complete["id"]))["state"] == JobState.COMPLETED.value
    assert service.validate_lease(str(active["id"]), str(active["lease_token"])) is False


def test_child_creation_cannot_forge_terminal_state_or_bypass_parent_ownership(tmp_path):
    service = JobStateService(tmp_path / "jobs.db")
    parent = service.create_job()
    with pytest.raises(InvalidTransition, match="new child jobs must start"):
        service.create_child(str(parent["id"]), "forged", state=JobState.COMPLETED)

    direct_child = service.create_job(
        parent_id=str(parent["id"]),
        job_id="direct-child",
        state=JobState.QUEUED,
    )
    assert service.children(str(parent["id"]))[0]["id"] == direct_child["id"]
    service.pause_job(str(parent["id"]))
    with pytest.raises(TerminalStateError, match="unresolved_child"):
        service.complete_job(str(parent["id"]))


def test_unresolved_child_process_blocks_retry_and_is_canceled_without_duplicate_work(tmp_path):
    identity = process_identity(8801, start_token="child-start", command="fixture-child")
    supervisor = FakeSupervisor(identity)
    service = JobStateService(tmp_path / "jobs.db", process_supervisor=supervisor)
    job = _queued_job(service, max_attempts=2)
    attempt = _running_attempt(service, str(job["id"]))
    service.register_process(str(job["id"]), str(attempt["id"]), identity)
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
    service = JobStateService(tmp_path / "jobs.db")
    job = _queued_job(service, required_work=4)
    attempt = _running_attempt(service, str(job["id"]))
    service.finish_attempt(
        str(attempt["id"]),
        lease_token=str(attempt["lease_token"]),
        coverage_keys=["completed"],
        result_ref="observation:partial-coverage",
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
    first = JobStateService(path, clock=clock)
    leased_job = _queued_job(first, max_attempts=2)
    leased = first.acquire_lease(str(leased_job["id"]), "worker-a", lease_seconds=5)
    clock.advance(6)
    first.close()
    restarted = JobStateService(path, clock=clock)
    assert str(leased["id"]) in restarted.reconcile()
    assert restarted.get_job(str(leased_job["id"]))["state"] == JobState.QUEUED.value

    # Accepted result + durable log survive a restart before terminal finalization.
    result_job = _queued_job(restarted, required_work=1)
    result_attempt = _running_attempt(restarted, str(result_job["id"]), lease_seconds=60)
    restarted.record_result(
        str(result_attempt["id"]),
        str(result_attempt["lease_token"]),
        delivery_key="accepted-before-restart",
        result_ref="observation:accepted-before-restart",
        work=[{"work_key": "one"}],
    )
    restarted.append_log(str(result_job["id"]), "accepted result", attempt_id=str(result_attempt["id"]))
    restarted.close()
    restarted = JobStateService(path, clock=clock)
    assert any(event["event_type"] == "result_accepted" for event in restarted.list_events(str(result_job["id"])))
    assert restarted.list_logs(str(result_job["id"]))[0]["message"] == "accepted result"
    restarted.finish_attempt(
        str(result_attempt["id"]), lease_token=str(result_attempt["lease_token"])
    )
    assert restarted.get_job(str(result_job["id"]))["state"] == JobState.COMPLETED.value

    # A live child with an expired lease is orphaned, never requeued.
    live_identity = process_identity(9001, start_token="live", command="fixture")
    live_supervisor = FakeSupervisor(live_identity)
    live_path = tmp_path / "live.db"
    live = JobStateService(live_path, clock=clock, process_supervisor=live_supervisor)
    live_job = _queued_job(live, max_attempts=2)
    live_attempt = _running_attempt(live, str(live_job["id"]), lease_seconds=5)
    live.register_process(str(live_job["id"]), str(live_attempt["id"]), live_identity)
    clock.advance(6)
    live.close()
    live = JobStateService(live_path, clock=clock, process_supervisor=live_supervisor)
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
    assert restarted.list_attempts(str(cancel_job["id"]))[0]["state"] == "expired"
    assert not restarted.validate_lease(str(cancel_attempt["id"]), str(cancel_attempt["lease_token"]))


def test_tenant_isolation_and_reconstruction_without_compatibility_json(tmp_path):
    path = tmp_path / "jobs.db"
    service = JobStateService(path)
    alpha = service.create_job(job_id="same-job", tenant_id="alpha", state=JobState.QUEUED)
    bravo = service.create_job(job_id="same-job", tenant_id="bravo", state=JobState.QUEUED)
    alpha_attempt = service.acquire_lease("same-job", "alpha-worker", tenant_id="alpha")
    bravo_attempt = service.acquire_lease("same-job", "bravo-worker", tenant_id="bravo")
    assert alpha["tenant_id"] != bravo["tenant_id"]
    assert service.validate_lease(
        str(alpha_attempt["id"]), str(alpha_attempt["lease_token"]), tenant_id="alpha"
    )
    assert not service.validate_lease(
        str(alpha_attempt["id"]), str(alpha_attempt["lease_token"]), tenant_id="bravo"
    )
    assert service.list_events("same-job", tenant_id="alpha")
    assert service.list_events("same-job", tenant_id="bravo")

    compatibility_cache = tmp_path / "scan_jobs.json"
    compatibility_cache.write_text('{"non_authoritative": true}', encoding="utf-8")
    service.close()
    compatibility_cache.unlink()
    rebuilt = JobStateService(path)
    assert rebuilt.get_job("same-job", tenant_id="alpha")["id"] == "same-job"
    assert rebuilt.get_job("same-job", tenant_id="bravo")["id"] == "same-job"
    assert rebuilt.list_attempts("same-job", tenant_id="alpha")[0]["id"] == alpha_attempt["id"]
    assert rebuilt.list_attempts("same-job", tenant_id="bravo")[0]["id"] == bravo_attempt["id"]


def test_wrong_owner_expired_and_revoked_leases_cannot_report(tmp_path):
    clock = FakeClock()
    service = JobStateService(tmp_path / "jobs.db", clock=clock)
    job = _queued_job(service)
    attempt = _running_attempt(service, str(job["id"]), worker_id="worker-a", lease_seconds=5)
    with pytest.raises(LeaseError):
        service.start_attempt(
            str(attempt["id"]), str(attempt["lease_token"]), worker_id="worker-b"
        )
    clock.advance(6)
    with pytest.raises(LeaseError):
        service.record_result(
            str(attempt["id"]), str(attempt["lease_token"]), delivery_key="late"
        )
    service.reconcile()
    assert service.get_job(str(job["id"]))["state"] == JobState.EXPIRED.value


def test_dashboard_projection_declares_work_before_process_monitoring(tmp_path, monkeypatch):
    """A dashboard process exit cannot complete an otherwise empty projection."""

    from common.dashboard.server import DashboardServer

    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda _self: tmp_path / "dashboard-jobs.db"),
    )
    server = DashboardServer(auth=False)
    try:
        server._ensure_durable_scan_job(
            "dashboard-scan",
            target="https://fixture.local",
            frameworks=["web"],
            modules=["sqli", "xss"],
        )
        service = server._durable_job_state()
        job = service.get_job("dashboard-scan", tenant_id=server.tenant_id)
        assert job is not None
        assert job["required_work"] == 2

        attempt = service.acquire_lease(
            "dashboard-scan",
            "dashboard",
            tenant_id=server.tenant_id,
            idempotency_key="dashboard-attempt:dashboard-scan",
        )
        service.finish_attempt(
            str(attempt["id"]),
            lease_token=str(attempt["lease_token"]),
            success=True,
            terminal_reason="scanner process exited without accepted evidence",
            tenant_id=server.tenant_id,
            actor="dashboard-monitor",
        )
        assert service.get_job("dashboard-scan", tenant_id=server.tenant_id)["state"] == "partial"
        assert service.coverage_snapshot(
            "dashboard-scan", tenant_id=server.tenant_id
        )["uncollected"] == 2
        service.close()
        server._job_state_service = None

        restarted_reader = DashboardServer(auth=False)
        try:
            rows = restarted_reader._durable_jobs_for_read_projection(
                scan_id="dashboard-scan",
            )
            assert rows[0]["state"] == "partial"
            # Opening the dashboard to inspect existing state must not create
            # a mutable JobStateService or run reconciliation.
            assert restarted_reader._job_state_service is None
        finally:
            if restarted_reader._job_state_service is not None:
                restarted_reader._job_state_service.close()
    finally:
        if server._job_state_service is not None:
            server._job_state_service.close()


def test_dashboard_process_exit_without_delivery_never_completes_zero_work(
    tmp_path, monkeypatch
):
    from common.dashboard.server import DashboardServer

    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda _self: tmp_path / "monitor-jobs.db"),
    )
    server = DashboardServer(auth=False)
    try:
        service = server._durable_job_state()
        job = service.create_job(
            job_id="zero-coverage",
            state=JobState.QUEUED,
            required_work=0,
        )
        attempt = service.acquire_lease(str(job["id"]), "dashboard")
        service.start_attempt(
            str(attempt["id"]),
            str(attempt["lease_token"]),
            worker_id="dashboard",
        )
        server._finish_durable_scan("zero-coverage", "completed")
        assert service.get_job("zero-coverage")["state"] == JobState.ORPHANED.value
    finally:
        if server._job_state_service is not None:
            server._job_state_service.close()
