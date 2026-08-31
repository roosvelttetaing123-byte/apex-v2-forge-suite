"""Task 106 negative scenarios for the ForgeBrain advisory truth boundary.

These tests deliberately use inert spies.  They are contract tests: until the
boundary lands, the legacy chain engine is expected to fail some assertions.
"""

from __future__ import annotations

import asyncio

import pytest

from common.attack_chains import ChainEngine, ChainState, ChainTrigger
from common.brain.autonomous import AutonomousEngine, EngagementConfig
from common.brain.truth_boundary import (
    SUPPORTED_CAPABILITY_ID,
    SUPPORTED_CAPABILITY_VERSION,
    SUPPORTED_IMPLEMENTATION,
)
from common.dashboard.event_bus import Event, EventBus, EventType
from common.dashboard.kill_chain import KillChainPhase, KillChainState
from common.dashboard.state_store import StateStore
from common.scope import canonical_target
from common.version import VERSION


_CANONICAL_TARGET = "https://fixture.example"
_CANONICAL_TARGET_DIGEST = canonical_target(_CANONICAL_TARGET)
_CANONICAL_TENANT = "tenant-fixture"
_CANONICAL_ENGAGEMENT = "engagement-fixture"
_CANONICAL_RUN = "run-fixture"
_CANONICAL_PLAN = "plan-fixture"
_CANONICAL_NODE = "node-fixture"
_CANONICAL_ACTION = "action-fixture"
_CANONICAL_JOB = "job-fixture"
_CANONICAL_ATTEMPT = "attempt-fixture"
_CANONICAL_OBSERVATION = "observation-fixture"
_CANONICAL_FINDING = "finding-fixture"
_CANONICAL_EVIDENCE = "artifact:fixture"
_CANONICAL_SIGNED_REF = "run-truth:fixture"


def _canonical_truth() -> dict[str, object]:
    lineage = {
        "plan_id": _CANONICAL_PLAN,
        "node_id": _CANONICAL_NODE,
        "action_id": _CANONICAL_ACTION,
        "job_id": _CANONICAL_JOB,
        "attempt_id": _CANONICAL_ATTEMPT,
        "capability_id": SUPPORTED_CAPABILITY_ID,
        "capability_version": SUPPORTED_CAPABILITY_VERSION,
        "module_id": SUPPORTED_IMPLEMENTATION,
        "runtime_module_version": VERSION,
        "target_digest": _CANONICAL_TARGET_DIGEST,
        "observation_id": _CANONICAL_OBSERVATION,
        "observation_status": "observed",
        "finding_id": _CANONICAL_FINDING,
        "finding_status": "open",
        "finding_title": "Canonical CSP finding",
        "finding_severity": "medium",
        "finding_description": "Persisted canonical CSP fixture.",
        "finding_created_at": "2026-08-31T00:00:00Z",
        "verification_state": "candidate",
        "proof_type": "passive",
        "confidence": "HIGH",
        "maturity": "experimental",
        "evidence_ref": _CANONICAL_EVIDENCE,
    }
    return {
        "tenant_id": _CANONICAL_TENANT,
        "engagement_id": _CANONICAL_ENGAGEMENT,
        "run_id": _CANONICAL_RUN,
        "canonical_plan_id": _CANONICAL_PLAN,
        "canonical_node_id": _CANONICAL_NODE,
        "canonical_action_id": _CANONICAL_ACTION,
        "canonical_job_id": _CANONICAL_JOB,
        "canonical_attempt_id": _CANONICAL_ATTEMPT,
        "canonical_capability_id": SUPPORTED_CAPABILITY_ID,
        "canonical_capability_version": SUPPORTED_CAPABILITY_VERSION,
        "canonical_module_id": SUPPORTED_IMPLEMENTATION,
        "canonical_runtime_module_version": VERSION,
        "canonical_target": _CANONICAL_TARGET_DIGEST,
        "canonical_target_display": _CANONICAL_TARGET,
        "canonical_lineage": (lineage,),
        "canonical_outcome": "success",
        "signed_outcome_ref": _CANONICAL_SIGNED_REF,
        "evidence_refs": (_CANONICAL_EVIDENCE,),
    }


def _canonical_event_data(**updates: object) -> dict[str, object]:
    data: dict[str, object] = {
        "tenant_id": _CANONICAL_TENANT,
        "engagement_id": _CANONICAL_ENGAGEMENT,
        "run_id": _CANONICAL_RUN,
        "canonical_plan_id": _CANONICAL_PLAN,
        "canonical_node_id": _CANONICAL_NODE,
        "canonical_action_id": _CANONICAL_ACTION,
        "canonical_job_id": _CANONICAL_JOB,
        "canonical_attempt_id": _CANONICAL_ATTEMPT,
        "canonical_capability_id": SUPPORTED_CAPABILITY_ID,
        "canonical_capability_version": SUPPORTED_CAPABILITY_VERSION,
        "canonical_module_id": SUPPORTED_IMPLEMENTATION,
        "canonical_runtime_module_version": VERSION,
        "canonical_target": _CANONICAL_TARGET_DIGEST,
        "target": _CANONICAL_TARGET,
        "canonical_outcome": "success",
        "signed_outcome_ref": _CANONICAL_SIGNED_REF,
        "evidence_refs": (_CANONICAL_EVIDENCE,),
    }
    data.update(updates)
    return data


class InertModuleSpy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def run_chain(self, payload: object) -> object:
        self.calls.append(("run_chain", payload))
        return {"status": "success"}

    async def run_for_target(self, target: object) -> object:
        self.calls.append(("run_for_target", target))
        return {"status": "success"}


class AdvisorySinkSpy:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def __call__(self, record: dict[str, object]) -> dict[str, object]:
        self.records.append(dict(record))
        return {
            "accepted": True,
            "id": f"canonical-advisory-{len(self.records)}",
            "state": "advisory",
        }


def _chain(*, auto_execute: bool = True, next_chains: list[str] | None = None,
           branch_conditions: dict[str, str] | None = None) -> ChainTrigger:
    return ChainTrigger(
        chain_id="scenario-a",
        name="Scenario A",
        trigger_event="finding.confirmed",
        trigger_types=["sqli"],
        next_module="dangerous_module",
        description="test-only chain",
        opsec_level="NOISY",
        auto_execute=auto_execute,
        next_chains=next_chains or [],
        branch_conditions=branch_conditions or {},
    )


@pytest.mark.parametrize("auto_trigger", [False, True])
@pytest.mark.parametrize("auto_execute", [False, True])
def test_chain_is_advisory_under_legacy_execution_flags(
    auto_trigger: bool, auto_execute: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = InertModuleSpy()
    sink = AdvisorySinkSpy()
    scheduled = 0

    def forbidden_create_task(*args: object, **kwargs: object) -> object:
        nonlocal scheduled
        scheduled += 1
        raise AssertionError("advisory chain scheduled an asyncio task")

    monkeypatch.setattr(asyncio, "create_task", forbidden_create_task)
    engine = ChainEngine(
        auto_trigger=auto_trigger,
        opsec_level="NOISY",
        module_registry={"dangerous_module": spy},
        advisory_sink=sink,
    )
    engine.register_chain(_chain(auto_execute=auto_execute))
    engine._bus.emit("finding.confirmed", {"type": "sqli", "target": "fixture.invalid"})

    assert spy.calls == []
    assert scheduled == 0
    assert engine.chain_states["scenario-a"] is ChainState.ADVISORY
    assert engine.triggered_chains[0]["canonical_advisory_id"].startswith(
        "canonical-advisory-"
    )


def test_duplicate_events_are_idempotent_at_advisory_sink() -> None:
    sink = AdvisorySinkSpy()
    engine = ChainEngine(
        auto_trigger=True,
        opsec_level="NOISY",
        module_registry={"dangerous_module": InertModuleSpy()},
        advisory_sink=sink,
    )
    engine.register_chain(_chain())
    payload = {"type": "sqli", "target": "fixture.invalid", "source_event_id": "evt-1"}
    engine._bus.emit("finding.confirmed", payload)
    engine._bus.emit("finding.confirmed", payload)

    assert len(sink.records) == 1
    assert len(engine.triggered_chains) == 1
    assert engine.triggered_chains[0]["canonical_advisory_state"] == "advisory"


def test_advisory_sink_failure_does_not_accept_or_suppress_retry() -> None:
    calls = 0

    def sink(record: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("synthetic persistence failure")
        return {
            "accepted": True,
            "id": "canonical-advisory-retry",
            "state": "advisory",
        }

    engine = ChainEngine(advisory_sink=sink, opsec_level="NOISY")
    engine.register_chain(_chain())
    payload = {"type": "sqli", "source_event_id": "retry-event"}
    engine._bus.emit("finding.confirmed", payload)
    assert engine.triggered_chains == []
    assert engine.chain_states["scenario-a"] is ChainState.BLOCKED
    engine._bus.emit("finding.confirmed", payload)
    assert len(engine.triggered_chains) == 1
    assert engine.chain_states["scenario-a"] is ChainState.ADVISORY


def test_advisory_sink_without_canonical_acceptance_is_blocked() -> None:
    engine = ChainEngine(
        advisory_sink=lambda _record: None,
        opsec_level="NOISY",
    )
    engine.register_chain(_chain())
    engine._bus.emit(
        "finding.confirmed",
        {"type": "sqli", "source_event_id": "missing-canonical-id"},
    )
    assert engine.triggered_chains == []
    assert engine.chain_states["scenario-a"] is ChainState.BLOCKED


def test_multihop_and_branch_never_depend_on_synthetic_success() -> None:
    spy = InertModuleSpy()
    sink = AdvisorySinkSpy()
    engine = ChainEngine(
        auto_trigger=True,
        opsec_level="NOISY",
        module_registry={"dangerous_module": spy},
        advisory_sink=sink,
    )
    engine.register_chain(_chain(next_chains=["scenario-b"], branch_conditions={"cloud": "scenario-b"}))
    engine.register_chain(ChainTrigger(
        chain_id="scenario-b", name="Scenario B", trigger_event="finding.confirmed",
        trigger_types=["pivot"], next_module="dangerous_module", description="branch",
        opsec_level="NOISY", auto_execute=True,
    ))
    engine._bus.emit("finding.confirmed", {"type": "sqli", "target": "fixture.invalid"})

    assert spy.calls == []
    assert all(state is not ChainState.COMPLETED for state in engine.chain_states.values())


def test_autonomous_simulation_does_not_claim_executed_work() -> None:
    engine = AutonomousEngine()
    report = asyncio.run(engine.run_engagement(EngagementConfig(
        target="fixture.invalid", frameworks=["webforge"], max_time_seconds=30,
    )))

    assert engine.progress.modules_run == 0
    assert engine.progress.modules_simulated >= 0
    assert report.progress["modules_run"] == 0
    assert report.progress["modules_simulated"] >= 0
    assert report.progress["percent_complete"] < 100.0


def test_kill_chain_rejects_transient_completion_and_compromise_claims() -> None:
    state = KillChainState()
    state.set_module_totals(["sqli_scanner"])
    assert state.record_module_complete("sqli_scanner") is False
    assert state.completion_pct() == 0.0
    assert state.record_finding("dcsync", verification_state="verified") is False
    assert state.compromise_achieved is False

    assert state.record_module_complete(
        "sqli_scanner",
        canonical_job_id="job-fixture",
        outcome="success",
        evidence_refs=("artifact:fixture",),
    ) is True
    assert state.completion_pct() == 100.0
    assert state.record_finding(
        "dcsync",
        verification_state="verified",
        observation_id="observation-fixture",
        evidence_refs=("artifact:fixture",),
    ) is True
    assert state.record_finding(
        "dcsync",
        verification_state="verified",
        observation_id="observation-fixture",
        evidence_refs=("artifact:fixture",),
    ) is False
    assert state.compromise_achieved is True
    assert state.phase_findings[KillChainPhase.ACTIONS_ON_OBJECTIVE] == 1


def test_dashboard_module_and_target_events_are_advisory_without_lineage() -> None:
    store = StateStore(EventBus(run_id="task106-dashboard"), target="fixture.invalid")
    store._on_module_start(Event(EventType.MODULE_START, {"name": "sqli_scanner"}))
    store._on_module_progress(
        Event(EventType.MODULE_PROGRESS, {"name": "sqli_scanner", "progress": 100})
    )
    store._on_module_complete(
        Event(EventType.MODULE_COMPLETE, {"name": "sqli_scanner"})
    )
    assert store.modules["sqli_scanner"].status == "advisory"
    assert store.modules["sqli_scanner"].progress_pct == 99.0
    assert sum(store.kill_chain.phase_modules_run.values()) == 0

    store.targets["fixture.invalid"] = type(
        "Target", (), {"pwned": False, "access_level": "", "shell": False}
    )()
    store._on_target_pwned(
        Event(EventType.TARGET_PWNED, {"target": "fixture.invalid"})
    )
    store._on_shell_session(
        Event(EventType.SHELL_SESSION, {"target": "fixture.invalid"})
    )
    assert store.targets["fixture.invalid"].pwned is False
    assert store.sessions == []


def test_dashboard_canonical_completion_replay_is_idempotent() -> None:
    truth = _canonical_truth()
    store = StateStore(
        EventBus(run_id=_CANONICAL_RUN),
        target=_CANONICAL_TARGET,
        canonical_truth_resolver=lambda _value: truth,
    )
    store.kill_chain.set_module_totals([SUPPORTED_IMPLEMENTATION])
    store._on_module_start(Event(
        EventType.MODULE_START,
        {"name": SUPPORTED_IMPLEMENTATION},
        source=SUPPORTED_IMPLEMENTATION,
    ))
    event = Event(
        EventType.MODULE_COMPLETE,
        _canonical_event_data(
            name=SUPPORTED_IMPLEMENTATION,
            findings_count=999,
        ),
        source=SUPPORTED_IMPLEMENTATION,
    )
    store._on_module_complete(event)
    first_duration = store.modules[SUPPORTED_IMPLEMENTATION].duration
    store._on_module_complete(event)
    assert store.modules[SUPPORTED_IMPLEMENTATION].status == "complete"
    assert store.modules[SUPPORTED_IMPLEMENTATION].duration == first_duration
    assert store.kill_chain.completion_pct() == 100.0
    assert sum(store.kill_chain.phase_modules_run.values()) == 1
    assert store.modules[SUPPORTED_IMPLEMENTATION].findings_count == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", "tenant-other"),
        ("engagement_id", "engagement-other"),
        ("run_id", "run-other"),
        ("plan_id", "plan-conflict"),
        ("node_id", "node-conflict"),
        ("action_id", "action-conflict"),
        ("job_id", "job-conflict"),
        ("attempt_id", "attempt-conflict"),
        ("capability_id", "webforge:other"),
        ("capability_version", "999.0.0"),
        ("module_id", "other_module"),
        ("target", "https://other.example"),
        ("target", "malformed target"),
        ("target", None),
        ("target_digest", "sha256:" + "0" * 64),
        ("outcome", "failed"),
        ("signed_outcome_ref", "run-truth:other"),
        ("evidence_refs", ("artifact:other",)),
    ],
)
def test_dashboard_completion_rejects_mismatch_alias_conflict_and_bad_target(
    field: str,
    value: object,
) -> None:
    truth = _canonical_truth()
    store = StateStore(
        EventBus(run_id=_CANONICAL_RUN),
        target=_CANONICAL_TARGET,
        canonical_truth_resolver=lambda _value: truth,
    )
    store.kill_chain.set_module_totals([SUPPORTED_IMPLEMENTATION])
    store._on_module_start(Event(
        EventType.MODULE_START,
        {"name": SUPPORTED_IMPLEMENTATION},
        source=SUPPORTED_IMPLEMENTATION,
    ))
    event_data = _canonical_event_data(name=SUPPORTED_IMPLEMENTATION)
    if value is None:
        event_data.pop(field)
    else:
        event_data[field] = value

    store._on_module_complete(Event(
        EventType.MODULE_COMPLETE,
        event_data,
        source=SUPPORTED_IMPLEMENTATION,
    ))

    assert store.modules[SUPPORTED_IMPLEMENTATION].status == "advisory"
    assert store.modules[SUPPORTED_IMPLEMENTATION].progress_pct < 100.0
    assert sum(store.kill_chain.phase_modules_run.values()) == 0


@pytest.mark.parametrize(
    ("canonical_name", "legacy_name", "expected"),
    [
        ("canonical_action_id", "action_id", _CANONICAL_ACTION),
        ("canonical_job_id", "job_id", _CANONICAL_JOB),
        ("canonical_attempt_id", "attempt_id", _CANONICAL_ATTEMPT),
        (
            "canonical_capability_version",
            "capability_version",
            SUPPORTED_CAPABILITY_VERSION,
        ),
    ],
)
def test_dashboard_completion_rejects_blank_canonical_alias(
    canonical_name: str,
    legacy_name: str,
    expected: str,
) -> None:
    truth = _canonical_truth()
    store = StateStore(
        EventBus(run_id=_CANONICAL_RUN),
        target=_CANONICAL_TARGET,
        canonical_truth_resolver=lambda _value: truth,
    )
    store.kill_chain.set_module_totals([SUPPORTED_IMPLEMENTATION])
    store._on_module_start(Event(
        EventType.MODULE_START,
        {"name": SUPPORTED_IMPLEMENTATION},
        source=SUPPORTED_IMPLEMENTATION,
    ))
    event_data = _canonical_event_data(name=SUPPORTED_IMPLEMENTATION)
    event_data[canonical_name] = ""
    event_data[legacy_name] = expected
    store._on_module_complete(Event(
        EventType.MODULE_COMPLETE,
        event_data,
        source=SUPPORTED_IMPLEMENTATION,
    ))
    assert store.modules[SUPPORTED_IMPLEMENTATION].status == "advisory"
    assert sum(store.kill_chain.phase_modules_run.values()) == 0


def test_canonical_success_cannot_project_target_or_shell_without_typed_proof() -> None:
    truth = _canonical_truth()
    store = StateStore(
        EventBus(run_id=_CANONICAL_RUN),
        target=_CANONICAL_TARGET,
        canonical_truth_resolver=lambda _value: truth,
    )
    store.targets[_CANONICAL_TARGET] = type(
        "Target", (), {"pwned": False, "access_level": "", "shell": False}
    )()
    compromise_data = _canonical_event_data(
        observation_id=_CANONICAL_OBSERVATION,
        canonical_observation_id=_CANONICAL_OBSERVATION,
        access_level="root",
        shell_type="BASH",
    )

    store._on_target_pwned(Event(
        EventType.TARGET_PWNED,
        dict(compromise_data),
        source=SUPPORTED_IMPLEMENTATION,
    ))
    store._on_shell_session(Event(
        EventType.SHELL_SESSION,
        dict(compromise_data),
        source=SUPPORTED_IMPLEMENTATION,
    ))

    assert store.targets[_CANONICAL_TARGET].pwned is False
    assert store.targets[_CANONICAL_TARGET].shell is False
    assert store.targets[_CANONICAL_TARGET].access_level == ""
    assert store.sessions == []
    assert all(item["type"] != "target_pwned" for item in store.timeline)
