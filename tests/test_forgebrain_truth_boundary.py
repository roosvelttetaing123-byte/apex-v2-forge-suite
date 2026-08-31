"""Deterministic Task 106 ForgeBrain/chain truth-boundary acceptance."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sqlite3
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.action_authorization import OperatorRole, SafetyMode, issue_authorization
from common.artifact_io import ArtifactBoundaryError, open_private_directory
from common.attack_chains import ChainEngine, ChainState, ChainTrigger
from common.brain.brain import ForgeBrain, PlannedAction
from common.brain.engagement_bus import EngagementBus
from common.brain.planner import AttackPlanner, KillChainPhase
from common.brain.truth_boundary import (
    AdvisoryPlan,
    AdvisoryPlanNode,
    ApprovalReference,
    BoundaryConflict,
    BoundaryDenied,
    CapabilityReason,
    CapabilityRegistry,
    ExecutionOutcome,
    ForgeBrainTruthBoundary,
    NarrativeProjection,
    PolicyDecision,
    Task103InertJobFactory,
    classify_terminal_outcome,
    model_cache_key,
    project_model_input,
    validated_job_success,
)
from common.canonical import (
    ArtifactReference,
    Asset,
    AssetKind,
    CanonicalStore,
    Client,
    Engagement,
    Finding,
    FindingSeverity,
    FindingStatus,
    Job,
    ModuleVersion,
    Observation,
    ObservationStatus,
    Project,
    Tenant,
)
from common.confirm_gate import ActionConfirmation
from common.db import (
    append_finding_run_snapshot,
    append_run_collection_truth,
    create_db,
    finding_set_identity,
)
from common.job_state import JobState, JobStateService, ObservationReceipt
from common.engagement_scheduler import EngagementRun, EngagementScheduler, ScheduleConfig
from common.evidence_custody import CustodyError, EvidenceCustodyStore
from common.redaction import clear_sensitive_values, register_sensitive_values
from common.retest import HEADER_CSP_CHECK_ID
import common.run_truth as run_truth_module
from common.run_truth import (
    RUN_TRUTH_POLICY,
    RunCollectionStatus,
    RunCollectionTruth,
    run_collection_truth_attestation_payload,
)
from common.schema_migrations import (
    BRAIN_TRUTH_SCHEMA_VERSION,
    MigrationError,
    MigrationInterruptedError,
    MigrationManager,
    REFERENCE_SLICE_SCHEMA_VERSION,
)
from common.version import VERSION
from netforge.core.attack_chain import AttackChain as NetForgeAttackChain


CORPUS_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "forgebrain_truth_boundary_v1.json.fixture"
)
TARGET = "https://fixture.example/"
NOW_EPOCH = 1_725_000_000.0
NOW = datetime.fromtimestamp(NOW_EPOCH, timezone.utc)


class FakeClock:
    def __init__(self, value: float = NOW_EPOCH) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class RecordingJobFactory:
    """Record the exact call and delegate to the real inert Task 103 adapter."""

    def __init__(self, jobs: JobStateService) -> None:
        self.delegate = Task103InertJobFactory(jobs)
        self.calls: list[dict[str, Any]] = []

    def create_job(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(dict(kwargs))
        return dict(self.delegate.create_job(**kwargs))


class RecordingCanonicalAdvisorySink:
    """Deterministic sink fixture for the EngagementBus chain boundary."""

    def __init__(self, *, accepted: bool = True, advisory_id: str = "canonical-advisory-1") -> None:
        self.accepted = accepted
        self.advisory_id = advisory_id
        self.calls: list[dict[str, Any]] = []

    def __call__(self, record: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(dict(record))
        if not self.accepted:
            return {"accepted": False}
        return {"accepted": True, "id": self.advisory_id}


@dataclass
class Environment:
    database: Path
    tenant_id: str
    engagement_id: str
    source_finding_id: str
    clock: FakeClock
    jobs: JobStateService
    factory: RecordingJobFactory
    service: ForgeBrainTruthBoundary

    def close(self) -> None:
        self.service.close()
        self.jobs.close()


def corpus() -> dict[str, Any]:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def _seed_source(
    database: Path,
    *,
    tenant_id: str,
    engagement_id: str,
    suffix: str,
) -> str:
    session = create_db(database)
    store = CanonicalStore(session)
    tenant = Tenant(id=tenant_id, name=f"Tenant {suffix}")
    client = Client(id=f"client-{suffix}", tenant_id=tenant.id, name="Client")
    project = Project(
        id=f"project-{suffix}", tenant_id=tenant.id, client_id=client.id, name="Project"
    )
    engagement = Engagement(
        id=engagement_id,
        tenant_id=tenant.id,
        project_id=project.id,
        name=f"Engagement {suffix}",
    )
    job = Job(
        id=f"source-job-{suffix}",
        tenant_id=tenant.id,
        engagement_id=engagement.id,
        job_kind="fixture-source",
    )
    module = ModuleVersion(
        id=f"source-module-{suffix}",
        tenant_id=tenant.id,
        module_id="fixture.source",
        version="1.0.0",
    )
    asset = Asset(
        id=f"source-asset-{suffix}",
        tenant_id=tenant.id,
        kind=AssetKind.URL,
        identity_key=f"https://source-{suffix}.example/",
        display_name=f"source-{suffix}.example",
    )
    observation = Observation(
        id=f"source-observation-{suffix}",
        tenant_id=tenant.id,
        engagement_id=engagement.id,
        job_id=job.id,
        module_version_id=module.id,
        asset_id=asset.id,
        status=ObservationStatus.OBSERVED,
    )
    artifact = ArtifactReference(
        id=f"source-artifact-{suffix}",
        tenant_id=tenant.id,
        observation_id=observation.id,
        reference=f"artifact:source-{suffix}",
        digest="sha256:" + hashlib.sha256(suffix.encode()).hexdigest(),
        media_type="application/json",
        size=0,
    )
    finding = Finding(
        id=f"source-finding-{suffix}",
        tenant_id=tenant.id,
        observation_id=observation.id,
        artifact_id=artifact.id,
        title="Fixture source finding",
        severity=FindingSeverity.INFORMATIONAL,
        description="Inert canonical source for Task 106.",
        finding_key=f"fixture:{suffix}",
    )
    store.create_lineage(
        tenant=tenant,
        client=client,
        project=project,
        engagement=engagement,
        job=job,
        module_version=module,
        asset=asset,
        observation=observation,
        artifact=artifact,
        finding=finding,
    )
    session.commit()
    session.close()
    return finding.id


def _environment(
    tmp_path: Path,
    *,
    suffix: str = "a",
    database: Path | None = None,
    failure_hook: Any = None,
) -> Environment:
    database = database or (tmp_path / "truth-boundary.db")
    tenant_id = f"tenant-{suffix}"
    engagement_id = f"engagement-{suffix}"
    source = _seed_source(
        database,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        suffix=suffix,
    )
    clock = FakeClock()
    jobs = JobStateService(database, clock=clock)
    factory = RecordingJobFactory(jobs)
    service = ForgeBrainTruthBoundary(
        database_path=database,
        tenant_id=tenant_id,
        clock=clock,
        job_service=jobs,
        job_factory=factory,
        failure_hook=failure_hook,
    )
    return Environment(
        database,
        tenant_id,
        engagement_id,
        source,
        clock,
        jobs,
        factory,
        service,
    )


def _node(
    env: Environment,
    *,
    target: str = TARGET,
    capability_id: str = "webforge:header_audit",
    capability_version: str = "1.0.0",
    input_kind: str = "url",
    parameters: dict[str, Any] | None = None,
    state: str = "advisory",
    revision: int = 1,
) -> AdvisoryPlanNode:
    plan = env.service.plan(
        source_id=env.source_finding_id,
        source_kind="finding",
        capability_id=capability_id,
        capability_version=capability_version,
        target=target,
        parameters=parameters or {},
        engagement_id=env.engagement_id,
        rationale="Review the canonical CSP observation.",
        state=state,
        revision=revision,
    )
    return env.service.node(
        plan,
        target=target,
        parameters=parameters or {},
        capability_id=capability_id,
        capability_version=capability_version,
        input_kind=input_kind,
    )


def _issue(
    env: Environment,
    node: AdvisoryPlanNode,
    decision: PolicyDecision,
    *,
    operator_id: str = "operator-fixture",
    allowed_scope: tuple[str, ...] | None = None,
    confirmed: bool = True,
) -> tuple[Any, Any, Any]:
    effective_scope = allowed_scope or (node.target,)
    context = env.service.action_context(
        node,
        decision,
        operator_id=operator_id,
        operator_role=OperatorRole.OPERATOR,
        allowed_scope=effective_scope,
    )
    session = create_db(env.database)
    confirmation = ActionConfirmation.create(
        job_id=context.job_id,
        target=context.resolved_target,
        engine=context.engine,
        action=context.action_kind,
        issued_at=NOW,
        confirmed=confirmed,
    )
    issued = issue_authorization(
        session=session,
        context=context,
        confirmation=confirmation,
        now=NOW,
    )
    return session, context, issued


def _approve(
    env: Environment,
    node: AdvisoryPlanNode,
    decision: PolicyDecision,
) -> ApprovalReference:
    session, context, issued = _issue(env, node, decision)
    try:
        assert issued.allowed
        return env.service.bind_approval(
            node,
            decision,
            session=session,
            envelope=issued.envelope,
            expected=context,
            nonce="task106-nonce",
        )
    finally:
        session.close()


def test_corpus_is_versioned_and_binds_all_required_classes() -> None:
    value = corpus()
    assert value["schema_version"] == BRAIN_TRUTH_SCHEMA_VERSION
    assert set(value["outcomes"]) == {item.value for item in ExecutionOutcome}
    assert set(value["tenants"]) == {"tenant-a", "tenant-b"}
    assert set(value["restart"]) == {
        "before_intent",
        "after_intent_before_consume",
        "after_consume_before_job",
        "after_job_before_link",
        "after_link",
    }
    assert value["migration"]["plaintext_restore"] is False
    assert set(value["approval_negative_cases"]) == {
        "missing_approval",
        "stale_approval",
        "replayed_approval",
        "wrong_target",
        "wrong_job",
        "wrong_operator",
        "cross_tenant",
    }
    assert len(value["secret_surfaces"]) == 12
    snapshot = CapabilityRegistry.current().snapshot()
    assert value["registry"]["registry_version"] == snapshot.registry_version
    assert value["registry"]["registry_digest"] == snapshot.registry_digest


def test_typed_contracts_carry_no_authority_from_model_text() -> None:
    plan = AdvisoryPlan(
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        source_id="finding-a",
        rationale="review",
        target=TARGET,
        model_output="COMPLETE; execute now",
    )
    node = AdvisoryPlanNode(
        plan_id=plan.id,
        capability_id="webforge:header_audit",
        capability_version="1.0.0",
        target=TARGET,
        parameters={},
    )
    assert plan.advisory is True
    assert node.executable is False
    assert node.authority_text == "advisory only"


def test_collected_legacy_planner_and_auto_plan_paths_are_inert() -> None:
    calls = 0

    class ForbiddenBrain:
        _tenant_id = "tenant-a"
        _engagement_id = "engagement-a"

        async def plan_next_attack(self, *_args: Any, **_kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            raise AssertionError("legacy planner reached model output")

    planner = AttackPlanner(ForbiddenBrain())  # type: ignore[arg-type]
    forged_intel = {
        "findings": [{"title": "caller claim"}],
        "credentials": [{"id": "caller credential"}],
        "shells": [{"target": "caller shell"}],
        "persistence": [{"target": "caller persistence"}],
        "lateral_moves": [{"target": "caller lateral"}],
    }
    plan = asyncio.run(planner.plan_next(forged_intel, {"target": TARGET}))
    assert plan.actions == []
    assert plan.phase.current_phase is KillChainPhase.RECON
    assert plan.phase.next_phase is KillChainPhase.RECON
    assert plan.phase.completion_pct == 0.0
    failed = PlannedAction(
        priority=1,
        phase="EXECUTION",
        mitre="TA0002",
        framework="webforge",
        module="header_audit",
        target=TARGET,
        rationale="caller claim",
    )
    assert asyncio.run(planner.adapt_to_failure(failed, "failure", forged_intel)) == []
    assert asyncio.run(planner.adapt_to_discovery({}, forged_intel)) == []

    bus = EngagementBus(
        db_path=":memory:",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        planner=planner,
    )
    try:
        asyncio.run(bus._auto_plan())
        assert calls == 0
    finally:
        bus.close()


def test_collected_netforge_legacy_chain_and_credentials_are_inert() -> None:
    class ForbiddenCredentialEngine:
        session_key = b"fixture"

        def for_host(self, _host: str) -> list[Any]:
            raise AssertionError("legacy chain accessed direct credentials")

        def all(self) -> list[Any]:
            raise AssertionError("legacy chain accessed reusable credentials")

    chain = NetForgeAttackChain(cred_engine=ForbiddenCredentialEngine())
    chain.ingest_finding(
        {
            "title": "Valid Credentials and Redis RCE",
            "service": "redis",
            "target": "caller.invalid",
            "severity": "Critical",
        }
    )
    assert chain.recommend_next() == []
    assert chain.get_creds_for_host("caller.invalid") == []
    assert chain.pending_actions == []
    assert chain.stats["compromised_hosts"] == 0
    assert chain.stats["valid_creds"] == 0
    assert chain.stats["exploitable_vulns"] == 0


def test_exact_capability_resolution_and_rejection_metrics() -> None:
    value = corpus()["registry"]
    registry = CapabilityRegistry.from_entries(
        [value["supported"], value["versionless"], value["disabled"]]
    )
    supported = registry.resolve(
        "webforge:header_audit",
        "1.0.0",
        expected_engine="webforge",
        input_kind="url",
        source_digest=value["supported"]["source_digest"],
    )
    assert supported.supported and supported.engine == "webforge"
    rejected = [
        registry.resolve("unknown:fixture", "1.0.0"),
        registry.resolve("webforge:xss_scanner", "1.0.0"),
        registry.resolve("webforge:disabled_fixture", "1.0.0"),
        registry.resolve("webforge:header_audit", "2.0.0"),
        registry.resolve(
            "webforge:header_audit", "1.0.0", expected_engine="netforge"
        ),
        registry.resolve("webforge:header_audit", "1.0.0", input_kind="host"),
        registry.resolve(
            "webforge:header_audit",
            "1.0.0",
            source_digest="sha256:" + "0" * 64,
        ),
    ]
    assert [item.reason for item in rejected] == [
        CapabilityReason.UNKNOWN.value,
        CapabilityReason.VERSION_MISSING.value,
        CapabilityReason.DISABLED.value,
        CapabilityReason.INCOMPATIBLE_VERSION.value,
        CapabilityReason.WRONG_ENGINE.value,
        CapabilityReason.WRONG_INPUT.value,
        CapabilityReason.SOURCE_MISMATCH.value,
    ]
    assert sum(not item.supported for item in rejected) == len(rejected)


def test_plan_requires_canonical_source_tenant_and_secret_free_parameters(
    tmp_path: Path,
) -> None:
    env = _environment(tmp_path)
    try:
        with pytest.raises(BoundaryDenied, match="source_not_found"):
            env.service.plan(
                source_id="invented-finding",
                capability_id="webforge:header_audit",
                capability_version="1.0.0",
                target=TARGET,
                parameters={},
                engagement_id=env.engagement_id,
            )
        with pytest.raises(BoundaryDenied, match="cross_tenant"):
            env.service.plan(
                source_id=env.source_finding_id,
                capability_id="webforge:header_audit",
                capability_version="1.0.0",
                target=TARGET,
                parameters={},
                engagement_id=env.engagement_id,
                tenant_id="tenant-b",
            )
        with pytest.raises(BoundaryDenied, match="cross_engagement_source"):
            env.service.plan(
                source_id=env.source_finding_id,
                capability_id="webforge:header_audit",
                capability_version="1.0.0",
                target=TARGET,
                parameters={},
                engagement_id="engagement-other",
            )
        with pytest.raises(BoundaryDenied, match="secret_parameter_rejected"):
            env.service.plan(
                source_id=env.source_finding_id,
                capability_id="webforge:header_audit",
                capability_version="1.0.0",
                target=TARGET,
                parameters={"token": "synthetic-secret"},
                engagement_id=env.engagement_id,
            )
    finally:
        env.close()


def test_chain_sink_persists_one_unsupported_advisory_and_no_job(
    tmp_path: Path,
) -> None:
    env = _environment(tmp_path)
    try:
        engine = ChainEngine(
            auto_trigger=True,
            opsec_level="NOISY",
            advisory_sink=env.service.record_chain_advisory,
        )
        engine.register_chain(
            ChainTrigger(
                chain_id="task106-chain-fixture",
                name="Task 106 chain fixture",
                trigger_event="finding.confirmed",
                trigger_types=["sqli"],
                next_module="header_audit",
                description="Inert advisory fixture",
                auto_execute=True,
            )
        )
        event = {
            "type": "sqli",
            "tenant_id": env.tenant_id,
            "engagement_id": env.engagement_id,
            "finding_id": env.source_finding_id,
            "target": TARGET,
            "source_event_id": "task106-source-event",
        }
        engine._bus.emit("finding.confirmed", event)
        engine._bus.emit("finding.confirmed", event)
        rows = env.jobs.conn.execute(
            "SELECT resolution_reason,state FROM canonical_advisory_nodes WHERE tenant_id=?",
            (env.tenant_id,),
        ).fetchall()
        assert [tuple(row) for row in rows] == [("unknown_capability", "rejected")]
        assert engine.triggered_chains == []
        assert engine.chain_states["task106-chain-fixture"] is ChainState.BLOCKED
        assert env.jobs.list_jobs(tenant_id=env.tenant_id) == []
    finally:
        env.close()


def test_engagement_bus_duplicate_finding_creates_one_advisory_chain() -> None:
    sink = RecordingCanonicalAdvisorySink()
    bus = EngagementBus(
        db_path=":memory:",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        canonical_advisory_sink=sink,
    )
    finding = {
        "id": "finding-duplicate",
        "canonical_finding_id": "canonical-finding-duplicate",
        "title": "SQL Injection candidate",
        "severity": "High",
        "target": TARGET,
    }
    try:
        asyncio.run(bus.publish("webforge", finding))
        asyncio.run(bus.publish("webforge", finding))
        assert len(bus.get_all_findings()) == 1
        assert len(bus.get_chain_actions()) == 1
        assert len(sink.calls) == 1
        assert bus.stats["total_chains_triggered"] == 1
    finally:
        bus.close()


def test_engagement_bus_canonical_sink_precedes_legacy_chain_projection_and_survives_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "engagement-bus-chain.db"
    sink = RecordingCanonicalAdvisorySink()
    events: list[Any] = []

    class EventCapture:
        def emit(self, event: Any) -> None:
            events.append(event)

    bus = EngagementBus(
        db_path=str(database),
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        run_id="run-a",
        event_bus=EventCapture(),
        canonical_advisory_sink=sink,
    )
    finding = {
        "id": "finding-canonical-chain",
        "canonical_finding_id": "canonical-source-finding",
        "canonical_observation_id": "canonical-source-observation",
        "title": "SQL Injection candidate",
        "severity": "High",
        "target": TARGET,
    }
    try:
        asyncio.run(bus.publish("webforge", finding))
        assert len(sink.calls) == 1
        record = sink.calls[0]
        assert record["tenant_id"] == "tenant-a"
        assert record["engagement_id"] == "engagement-a"
        assert record["source_finding_id"] == "canonical-source-finding"
        # The canonical service accepts one lineage kind; the observation is
        # retained as non-authoritative descriptive metadata.
        assert record["source_observation_id"] == ""
        assert record["metadata"]["source_observation_id"] == (
            "canonical-source-observation"
        )
        assert record["target_framework"] == "netforge"
        assert record["target_module"] == "credential_spray"
        assert record["target"] == TARGET
        assert record["idempotency_key"] == record["metadata"]["idempotency_key"]
        assert len(bus.get_chain_actions()) == 1
        chain_events = [
            event
            for event in events
            if getattr(getattr(event, "event_type", None), "value", "")
            == "chain_action_new"
        ]
        assert len(chain_events) == 1
        assert chain_events[0].data["canonical_advisory_id"] == (
            "canonical-advisory-1"
        )
        assert chain_events[0].data["run_id"] == "run-a"
        assert chain_events[0].run_id == "run-a"
    finally:
        bus.close()

    restarted = EngagementBus(
        db_path=str(database),
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        canonical_advisory_sink=sink,
    )
    try:
        asyncio.run(restarted.publish("webforge", finding))
        assert len(sink.calls) == 1
        assert len(restarted.get_chain_actions()) == 1
    finally:
        restarted.close()


@pytest.mark.parametrize(
    "sink",
    [
        None,
        RecordingCanonicalAdvisorySink(accepted=False),
        RecordingCanonicalAdvisorySink(advisory_id=""),
    ],
)
def test_engagement_bus_missing_or_rejected_canonical_sink_fails_closed(
    sink: Any,
) -> None:
    events: list[Any] = []

    class EventCapture:
        def emit(self, event: Any) -> None:
            events.append(event)

    bus = EngagementBus(
        db_path=":memory:",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        run_id="run-a",
        event_bus=EventCapture(),
        canonical_advisory_sink=sink,
    )
    finding = {
        "id": "finding-suppressed-chain",
        "canonical_finding_id": "canonical-source-suppressed",
        "title": "SQL Injection candidate",
        "severity": "High",
        "target": TARGET,
    }
    try:
        asyncio.run(bus.publish("webforge", finding))
        assert bus.get_chain_actions() == []
        chain_events = [
            event
            for event in events
            if getattr(getattr(event, "event_type", None), "value", "")
            == "chain_action_new"
        ]
        assert chain_events == []
        if sink is not None:
            assert len(sink.calls) == 1
    finally:
        bus.close()


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"allowed_scope": ("https://outside.example/",)}, "out_of_scope"),
        ({"allowed_scope": (TARGET,), "safety_mode": SafetyMode.ACTIVE}, "wrong_safety_mode"),
        ({"allowed_scope": (TARGET,), "credential_reference": "cred:fixture:opaque"}, "credential_forbidden"),
        ({"allowed_scope": (TARGET,), "modules": ("header_audit", "xss_scanner")}, "extra_module_forbidden"),
    ],
)
def test_deterministic_policy_denies_non_reference_inputs(
    tmp_path: Path, kwargs: dict[str, Any], reason: str
) -> None:
    env = _environment(tmp_path)
    try:
        decision = env.service.policy(_node(env), **kwargs)
        assert not decision.allowed and decision.reason == reason
        assert env.factory.calls == []
    finally:
        env.close()


def test_exact_approval_creates_one_queued_inert_canonical_job(tmp_path: Path) -> None:
    env = _environment(tmp_path)
    try:
        node = _node(env)
        decision = env.service.policy(node, allowed_scope=(TARGET,))
        approval = _approve(env, node, decision)
        first = env.service.create_action(node, approval)
        second = env.service.create_action(node, approval)
        assert first == second
        assert len(env.factory.calls) == 1
        call = env.factory.calls[0]
        assert call["state"] is JobState.QUEUED
        assert call["inert"] is True
        assert call["acquire_lease"] is False
        assert env.jobs.get_job(first.job_id, tenant_id=env.tenant_id)["state"] == "queued"
        assert env.jobs.list_attempts(first.job_id, tenant_id=env.tenant_id) == []
        lineage = env.jobs.conn.execute(
            """
            SELECT n.scope_decision_id,n.module_version_id,n.asset_id,
                   a.authorization_decision_id,m.manifest_digest,s.outcome
            FROM canonical_advisory_nodes n
            JOIN canonical_actions a
              ON a.tenant_id=n.tenant_id AND a.id=n.action_id
            JOIN canonical_module_versions m
              ON m.tenant_id=n.tenant_id AND m.id=n.module_version_id
            JOIN canonical_scope_decisions s
              ON s.tenant_id=n.tenant_id AND s.id=n.scope_decision_id
            WHERE n.tenant_id=? AND n.id=?
            """,
            (env.tenant_id, node.id),
        ).fetchone()
        assert all(lineage[:3])
        assert lineage[0] == lineage[3]
        assert lineage[4] == corpus()["registry"]["supported"]["source_digest"]
        assert lineage[5] == "allow"
        replay_node = _node(env, revision=2)
        with pytest.raises(BoundaryDenied, match="approval_reference_mismatch"):
            env.service.create_action(replay_node, approval)
        assert len(env.factory.calls) == 1
        with pytest.raises(BoundaryDenied, match="approval_reference_mismatch"):
            env.service.create_action(
                node, replace(approval, nonce="forged-replay-nonce")
            )
    finally:
        env.close()


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "wrong_authorization_binding",
        "runtime_version",
        "check_id",
        "proof_policy",
        "observation_status",
        "signed_member",
    ],
)
def test_real_completed_job_resolves_exact_signed_dashboard_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    """Exercise the real Task 103/run-truth resolver with two evidence observations."""

    env = _environment(tmp_path)
    try:
        node = _node(env)
        decision = env.service.policy(node, allowed_scope=(TARGET,))
        approval = _approve(env, node, decision)
        link = env.service.create_action(node, approval)
        stored_job = env.jobs.get_job(link.job_id, tenant_id=env.tenant_id)
        assert stored_job is not None
        assert env.jobs.coverage_snapshot(
            link.job_id, tenant_id=env.tenant_id
        )["items"][0]["work_key"] == "webforge"

        attempt = env.jobs.acquire_lease(
            link.job_id,
            "worker-task106",
            tenant_id=env.tenant_id,
        )
        attempt_id = str(attempt["id"])
        lease_token = str(attempt["lease_token"])
        env.jobs.start_attempt(
            attempt_id,
            lease_token,
            tenant_id=env.tenant_id,
            worker_id="worker-task106",
        )

        session = create_db(env.database)
        store = CanonicalStore(session)
        result_asset = Asset(
            id="asset-task106-result",
            tenant_id=env.tenant_id,
            kind=AssetKind.URL,
            identity_key=TARGET,
            display_name=TARGET,
            canonical_uri=TARGET,
        )
        delivery_module = ModuleVersion(
            id="module-task106-delivery",
            tenant_id=env.tenant_id,
            module_id="webforge-job-result",
            version=VERSION,
        )
        runtime_module = ModuleVersion(
            id="module-task106-runtime",
            tenant_id=env.tenant_id,
            module_id="header_audit",
            version="999.0.0" if fault == "runtime_version" else VERSION,
        )
        custody = EvidenceCustodyStore(
            env.database.parent / "evidence-custody",
            env.tenant_id,
        )

        def custody_artifact(
            *,
            artifact_id: str,
            observation_id: str,
            capture_kind: str,
            content: str,
        ) -> tuple[Any, ArtifactReference]:
            manifest = custody.store_artifact(
                content,
                source_observation_id=observation_id,
                collector_id="collector:task106-inert",
                media_type="application/json"
                if capture_kind in {"structured_proof", "job_result"}
                else "text/plain",
                source_target=TARGET,
                source_asset_id=result_asset.id,
                metadata={"capture_kind": capture_kind},
                artifact_id=artifact_id,
            )
            retention_expires_at = (
                datetime.fromisoformat(
                    manifest.retention_expires_at.replace("Z", "+00:00")
                )
                if manifest.retention_expires_at is not None
                else None
            )
            artifact = ArtifactReference(
                id=manifest.artifact_id,
                tenant_id=env.tenant_id,
                observation_id=observation_id,
                reference=manifest.artifact_id,
                digest=manifest.sha256,
                media_type=manifest.media_type,
                size=manifest.byte_size,
                redaction_state=manifest.redaction_state,
                encryption_state=manifest.encryption_state,
                collected_at=datetime.fromisoformat(
                    manifest.collected_at.replace("Z", "+00:00")
                ),
                metadata={"capture_kind": capture_kind},
                collector_id=manifest.collector_id,
                collector_version=VERSION,
                source_target=manifest.source_target or "unknown",
                source_asset_id=manifest.source_asset_id,
                redaction_version=manifest.redaction_version,
                protection_state=manifest.protection_state,
                signer_state=manifest.signer_state,
                integrity_state=manifest.integrity_state,
                retention_class=manifest.retention_class,
                retention_expires_at=retention_expires_at,
                protected_original_authorization_ref=(
                    manifest.protected_original_authorization_ref
                ),
                derivative_reference=manifest.derivative_artifact_id,
                manifest_digest=manifest.manifest_digest,
            )
            return manifest, artifact

        delivery_observation = Observation(
            id="observation-task106-delivery",
            tenant_id=env.tenant_id,
            engagement_id=env.engagement_id,
            job_id=link.job_id,
            attempt_id=attempt_id,
            module_version_id=delivery_module.id,
            asset_id=result_asset.id,
            action_id=link.action_id,
            status=ObservationStatus.OBSERVED,
        )
        delivery_manifest, delivery_artifact = custody_artifact(
            artifact_id="artifact:task106-delivery",
            observation_id=delivery_observation.id,
            capture_kind="job_result",
            content='{"outcome":"success"}',
        )
        finding_observation = Observation(
            id="observation-task106-finding",
            tenant_id=env.tenant_id,
            engagement_id=env.engagement_id,
            job_id=link.job_id,
            attempt_id=attempt_id,
            module_version_id=runtime_module.id,
            asset_id=result_asset.id,
            action_id=link.action_id,
            status=(
                ObservationStatus.NO_FINDING
                if fault == "observation_status"
                else ObservationStatus.OBSERVED
            ),
            proof_type="passive",
            check_id=(
                "Other-Header" if fault == "check_id" else HEADER_CSP_CHECK_ID
            ),
            route="/account",
        )
        request_manifest, finding_artifact = custody_artifact(
            artifact_id="artifact:task106-request",
            observation_id=finding_observation.id,
            capture_kind="request",
            content="GET /account HTTP/1.1\r\nHost: fixture.example\r\n",
        )
        response_manifest, response_artifact = custody_artifact(
            artifact_id="artifact:task106-response",
            observation_id=finding_observation.id,
            capture_kind="response",
            content="HTTP/1.1 200 OK\r\n",
        )
        proof_manifest, proof_artifact = custody_artifact(
            artifact_id="artifact:task106-proof",
            observation_id=finding_observation.id,
            capture_kind="structured_proof",
            content=json.dumps(
                {
                    "check_id": HEADER_CSP_CHECK_ID,
                    "proof_policy": (
                        "wrong-proof-policy"
                        if fault == "proof_policy"
                        else "header-audit-csp-proof-v1"
                    ),
                    "proof_type": "passive",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        canonical_finding = Finding(
            id="finding-task106-verified",
            tenant_id=env.tenant_id,
            observation_id=finding_observation.id,
            artifact_id=finding_artifact.id,
            title="Verified CSP fixture",
            severity=FindingSeverity.MEDIUM,
            description="Inert verified Task 106 finding fixture.",
            status=FindingStatus.OPEN,
            finding_key=HEADER_CSP_CHECK_ID,
            metadata={
                "confidence": "HIGH",
                "maturity": "experimental",
                "proof_type": "passive",
                "verification_state": "candidate",
            },
        )
        object.__setattr__(canonical_finding, "dedup_key", "finding-v1:" + "3" * 64)
        for record in (
            result_asset,
            delivery_module,
            runtime_module,
            delivery_observation,
            delivery_artifact,
            finding_observation,
            finding_artifact,
            response_artifact,
            proof_artifact,
            canonical_finding,
        ):
            store.insert(record)
        for manifest, artifact, observation, role, sequence in (
            (
                delivery_manifest,
                delivery_artifact,
                delivery_observation,
                "primary",
                0,
            ),
            (
                request_manifest,
                finding_artifact,
                finding_observation,
                "primary",
                0,
            ),
            (
                response_manifest,
                response_artifact,
                finding_observation,
                "supporting",
                1,
            ),
            (
                proof_manifest,
                proof_artifact,
                finding_observation,
                "supporting",
                2,
            ),
        ):
            store.persist_artifact_manifest(
                manifest,
                custody_store=custody,
                artifact=artifact,
                observation=observation,
                role=role,
                sequence=sequence,
            )
        stamp = NOW.isoformat()
        session.connection().exec_driver_sql(
            """
            INSERT INTO canonical_finding_observations(
                tenant_id,finding_id,observation_id,artifact_id,identity_key,
                first_seen_at,last_seen_at,created_at,metadata_json
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                env.tenant_id,
                canonical_finding.id,
                finding_observation.id,
                finding_artifact.id,
                canonical_finding.dedup_key,
                stamp,
                stamp,
                stamp,
                "{}",
            ),
        )
        session.commit()

        run_truth_id = f"{link.run_id}:webforge"
        append_finding_run_snapshot(
            session,
            tenant_id=env.tenant_id,
            run_id=run_truth_id,
            snapshot={
                "id": (
                    "finding-task106-missing"
                    if fault == "signed_member"
                    else canonical_finding.id
                ),
                "tenant_id": env.tenant_id,
                "title": canonical_finding.title,
                "severity": canonical_finding.severity.value,
                "dedup_key": "3" * 64,
            },
        )
        signer = Ed25519PrivateKey.generate()
        policy = replace(
            RUN_TRUTH_POLICY,
            issuer_public_key=base64.b64encode(
                signer.public_key().public_bytes_raw()
            ).decode("ascii"),
        )
        monkeypatch.setattr(run_truth_module, "RUN_TRUTH_POLICY", policy)
        truth = RunCollectionTruth(
            run_id=run_truth_id,
            authorization_run_id=link.run_id,
            job_id=link.job_id,
            tenant_id=env.tenant_id,
            framework="webforge",
            scope_binding="sha256:" + "4" * 64,
            target_binding=str(stored_job["payload"]["target_digest"]),
            collection_status=RunCollectionStatus.SUCCESS,
            coverage_complete=True,
            coverage_identity="sha256:" + "5" * 64,
            finding_set_identity=finding_set_identity(
                session,
                tenant_id=env.tenant_id,
                run_id=run_truth_id,
            ),
            predecessor_run_id="",
            run_sequence=1,
            completed_at=NOW.isoformat(),
            authorization_decision_id=approval.id,
            authorization_binding=(
                "sha256:" + "9" * 64
                if fault == "wrong_authorization_binding"
                else approval.envelope_digest
            ),
            authority_id="task106-inert-run-authority",
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
        append_run_collection_truth(session, truth, policy=policy)
        session.close()

        inspected = env.jobs.inspect_run_truth(
            attempt_id,
            lease_token,
            run_truth_id,
            tenant_id=env.tenant_id,
            worker_id="worker-task106",
        )
        env.jobs.record_run_truth(
            attempt_id,
            lease_token,
            run_truth_id,
            tenant_id=env.tenant_id,
            worker_id="worker-task106",
        )
        env.jobs.record_result(
            attempt_id,
            lease_token,
            delivery_key=str(attempt["delivery_idempotency_key"]),
            tenant_id=env.tenant_id,
            receipt=ObservationReceipt(
                tenant_id=env.tenant_id,
                job_id=link.job_id,
                attempt_id=attempt_id,
                observation_id=delivery_observation.id,
                artifact_id=delivery_artifact.id,
                result_ref=delivery_artifact.reference,
                manifest_digest=delivery_manifest.manifest_digest,
            ),
            outcome="success",
            work=inspected["work"],
            run_truths=(inspected["receipt"],),
            worker_id="worker-task106",
        )
        env.jobs.finish_attempt(
            attempt_id,
            lease_token=lease_token,
            tenant_id=env.tenant_id,
            worker_id="worker-task106",
        )

        custody_root = env.database.parent / "evidence-custody"
        custody_modes_before = {
            str(path.relative_to(custody_root)): path.stat().st_mode & 0o777
            for path in (custody_root, *custody_root.rglob("*"))
        }
        audit_before = env.jobs.conn.execute(
            "SELECT COUNT(*) FROM canonical_evidence_access_audit"
        ).fetchone()[0]
        resolved = validated_job_success(
            env.jobs,
            database_path=env.database,
            tenant_id=env.tenant_id,
            job_id=link.job_id,
        )
        assert {
            str(path.relative_to(custody_root)): path.stat().st_mode & 0o777
            for path in (custody_root, *custody_root.rglob("*"))
        } == custody_modes_before
        assert env.jobs.conn.execute(
            "SELECT COUNT(*) FROM canonical_evidence_access_audit"
        ).fetchone()[0] == audit_before
        if fault != "none":
            assert resolved is None
            return
        assert resolved is not None
        assert resolved["canonical_plan_id"] == node.plan_id
        assert resolved["canonical_node_id"] == node.id
        assert resolved["canonical_action_id"] == link.action_id
        assert resolved["canonical_capability_id"] == "webforge:header_audit"
        assert resolved["canonical_capability_version"] == "1.0.0"
        assert resolved["canonical_module_id"] == "header_audit"
        assert resolved["canonical_runtime_module_version"] == VERSION
        exact_finding = next(
            item
            for item in resolved["canonical_lineage"]
            if item["finding_id"] == canonical_finding.id
        )
        assert exact_finding["observation_id"] == finding_observation.id
        assert exact_finding["finding_status"] == "open"
        assert exact_finding["verification_state"] == "candidate"
        assert exact_finding["proof_type"] == "passive"
        assert exact_finding["proof_policy"] == "header-audit-csp-proof-v1"
        assert env.service.reconcile(node).outcome == "success"

        proof_derivative = custody._derivative_path(proof_artifact.id)
        proof_derivative.write_bytes(proof_derivative.read_bytes() + b"tampered")
        assert validated_job_success(
            env.jobs,
            database_path=env.database,
            tenant_id=env.tenant_id,
            job_id=link.job_id,
        ) is None
    finally:
        env.close()


def test_readonly_custody_open_never_creates_or_changes_namespace(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing-custody"
    with pytest.raises(
        ArtifactBoundaryError,
        match="creation requires namespace tightening",
    ):
        open_private_directory(missing, create=True, tighten=False)
    assert not missing.exists()
    with pytest.raises(CustodyError):
        EvidenceCustodyStore(missing, "tenant-a", create=False)
    assert not missing.exists()

    real = tmp_path / "real-custody"
    EvidenceCustodyStore(real, "tenant-a")
    before = {
        str(path.relative_to(real)): (path.stat().st_mode & 0o777)
        for path in (real, *real.rglob("*"))
    }
    EvidenceCustodyStore(real, "tenant-a", create=False)
    assert {
        str(path.relative_to(real)): (path.stat().st_mode & 0o777)
        for path in (real, *real.rglob("*"))
    } == before

    alias = tmp_path / "custody-alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(CustodyError):
        EvidenceCustodyStore(alias, "tenant-a", create=False)
    assert alias.is_symlink()
    assert {
        str(path.relative_to(real)): (path.stat().st_mode & 0o777)
        for path in (real, *real.rglob("*"))
    } == before


def test_unapproved_request_never_reaches_job_factory(tmp_path: Path) -> None:
    env = _environment(tmp_path)
    try:
        node = _node(env)
        decision = env.service.policy(node, allowed_scope=(TARGET,))
        context = env.service.action_context(
            node,
            decision,
            operator_id="operator-fixture",
            operator_role=OperatorRole.OPERATOR,
            allowed_scope=(TARGET,),
        )
        with pytest.raises(BoundaryDenied, match="policy_not_allowed"):
            env.service.action_context(
                node,
                replace(decision, policy_digest="sha256:" + "0" * 64),
                operator_id="operator-fixture",
                operator_role=OperatorRole.OPERATOR,
                allowed_scope=(TARGET,),
            )
        fake = ApprovalReference(
            id="approval-unrecorded",
            tenant_id=env.tenant_id,
            engagement_id=env.engagement_id,
            plan_id=node.plan_id,
            node_id=node.id,
            action_id=context.job_id,
            job_id=context.job_id,
            operator_id="operator-fixture",
            operator_role="operator",
            target_digest=node.request_digest,
            capability_id=node.capability_id,
            capability_version=node.capability_version,
            safety_mode="passive",
            parameter_digest=node.parameter_digest,
            envelope_digest="sha256:" + "0" * 64,
            expires_at=NOW.isoformat(),
            nonce="nonce",
            idempotency_key=node.idempotency_key,
        )
        with pytest.raises(BoundaryDenied):
            env.service.create_action(node, fake)
        assert env.factory.calls == []
    finally:
        env.close()


def test_stale_denied_wrong_operator_and_cross_target_approvals_fail_closed(
    tmp_path: Path,
) -> None:
    env = _environment(tmp_path)
    try:
        node = _node(env)
        decision = env.service.policy(node, allowed_scope=(TARGET,))
        session, context, issued = _issue(env, node, decision)
        env.clock.value += 301
        with pytest.raises(BoundaryDenied, match="authorization_denied"):
            env.service.bind_approval(
                node,
                decision,
                session=session,
                envelope=issued.envelope,
                expected=context,
                nonce="stale-nonce",
            )
        session.close()
        assert env.factory.calls == []
    finally:
        env.close()

    denied_root = tmp_path / "denied"
    denied_root.mkdir()
    env = _environment(denied_root)
    try:
        node = _node(env)
        decision = env.service.policy(node, allowed_scope=(TARGET,))
        session, context, issued = _issue(env, node, decision, confirmed=False)
        with pytest.raises(BoundaryDenied):
            env.service.bind_approval(
                node,
                decision,
                session=session,
                envelope=issued.envelope,
                expected=context,
                nonce="denied-nonce",
            )
        session.close()
        assert env.factory.calls == []
    finally:
        env.close()

    wrong_root = tmp_path / "wrong"
    wrong_root.mkdir()
    env = _environment(wrong_root)
    try:
        node = _node(env)
        decision = env.service.policy(node, allowed_scope=(TARGET,))
        session, _context, issued = _issue(env, node, decision)
        wrong_operator = env.service.action_context(
            node,
            decision,
            operator_id="different-operator",
            operator_role=OperatorRole.OPERATOR,
            allowed_scope=(TARGET,),
        )
        with pytest.raises(BoundaryDenied, match="approval_binding_mismatch"):
            env.service.bind_approval(
                node,
                decision,
                session=session,
                envelope=issued.envelope,
                expected=wrong_operator,
                nonce="wrong-operator",
            )
        wrong_job = replace(_context, job_id="job-wrong-binding")
        with pytest.raises(BoundaryDenied, match="approval_binding_mismatch"):
            env.service.bind_approval(
                node,
                decision,
                session=session,
                envelope=issued.envelope,
                expected=wrong_job,
                nonce="wrong-job",
            )
        for label, wrong_context in (
            ("wrong-run", replace(_context, run_id="run-wrong-binding")),
            (
                "wrong-action",
                replace(_context, action_kind="forgebrain.other_action"),
            ),
        ):
            with pytest.raises(BoundaryDenied, match="approval_binding_mismatch"):
                env.service.bind_approval(
                    node,
                    decision,
                    session=session,
                    envelope=issued.envelope,
                    expected=wrong_context,
                    nonce=label,
                )
        session.close()
        changed = _node(env, target="https://other.example/", revision=2)
        fake = ApprovalReference(
            id=issued.envelope.decision_id,
            tenant_id=env.tenant_id,
            engagement_id=env.engagement_id,
            plan_id=node.plan_id,
            node_id=node.id,
            action_id=issued.envelope.action_id,
            job_id=issued.envelope.job_id,
            operator_id=issued.envelope.operator_id,
            operator_role=issued.envelope.operator_role,
            target_digest=issued.envelope.resolved_target,
            capability_id=node.capability_id,
            capability_version=node.capability_version,
            safety_mode="passive",
            parameter_digest=node.parameter_digest,
            envelope_digest=issued.envelope.binding_digest,
            expires_at=issued.envelope.expires_at,
            nonce="wrong-target",
            idempotency_key=node.idempotency_key,
        )
        with pytest.raises(BoundaryDenied):
            env.service.create_action(changed, fake)
        assert env.factory.calls == []
    finally:
        env.close()


def test_wrong_action_boundary_never_consumes_or_creates_job(tmp_path: Path) -> None:
    env = _environment(tmp_path)
    try:
        node = _node(env)
        decision = env.service.policy(node, allowed_scope=(TARGET,))
        session, context, issued = _issue(env, node, decision)
        try:
            with pytest.raises(BoundaryDenied, match="action_boundary_mismatch"):
                env.service.bind_approval(
                    node,
                    decision,
                    session=session,
                    envelope=issued.envelope,
                    expected=context,
                    nonce="wrong-boundary",
                    boundary="other.boundary",
                )
        finally:
            session.close()
        assert env.factory.calls == []
        assert env.jobs.list_jobs(tenant_id=env.tenant_id) == []
    finally:
        env.close()


def test_preoccupied_canonical_job_identity_is_never_adopted(tmp_path: Path) -> None:
    env = _environment(tmp_path)
    try:
        node = _node(env)
        decision = env.service.policy(node, allowed_scope=(TARGET,))
        approval = _approve(env, node, decision)
        env.jobs.create_job(
            payload={"reference_slice": "different"},
            tenant_id=env.tenant_id,
            job_id=approval.job_id,
            engagement_id=env.engagement_id,
            run_id="wrong-run",
            job_kind="different.kind",
            target="different.invalid",
            authorization_decision_id=approval.id,
            authorization_action_id=approval.action_id,
            idempotency_key="different-idempotency-key",
            state=JobState.PLANNED,
        )
        with pytest.raises(BoundaryConflict, match="canonical_job_identity_conflict"):
            env.service.create_action(node, approval)
        assert env.factory.calls == []
        row = env.jobs.conn.execute(
            "SELECT action_id,job_id FROM canonical_advisory_nodes "
            "WHERE tenant_id=? AND id=?",
            (env.tenant_id, node.id),
        ).fetchone()
        assert tuple(row) == (None, None)
    finally:
        env.close()


@pytest.mark.parametrize(
    ("state", "signed", "evidence", "expected"),
    [
        ("completed", "success", ("artifact:one",), "success"),
        ("completed", "success", (), "inconclusive"),
        ("completed", "failure", ("artifact:one",), "inconclusive"),
        ("failed", "", (), "failed"),
        ("partial", "", (), "partial"),
        ("canceled", "", (), "canceled"),
        ("expired", "", (), "timeout"),
        ("orphaned", "", (), "inconclusive"),
        ("running", "", (), "inconclusive"),
    ],
)
def test_terminal_outcome_classification_is_exact(
    state: str, signed: str, evidence: tuple[str, ...], expected: str
) -> None:
    outcome, _reason = classify_terminal_outcome(
        state, signed_outcome=signed, evidence_refs=evidence
    )
    assert outcome.value == expected


def test_advisory_simulation_unsupported_and_queued_never_become_success(
    tmp_path: Path,
) -> None:
    env = _environment(tmp_path)
    try:
        advisory = _node(env)
        assert env.service.reconcile(advisory).outcome == "advisory"
        simulation = _node(
            env,
            state="simulation",
            target="https://simulation.example/",
            revision=2,
        )
        assert env.service.reconcile(simulation).outcome == "simulation"
        unsupported = _node(
            env,
            target="https://unsupported.example/",
            capability_id="unknown:fixture",
            capability_version="1.0.0",
            revision=3,
        )
        assert env.service.reconcile(unsupported).outcome == "unsupported"
        node = _node(env, target="https://queued.example/", revision=4)
        decision = env.service.policy(node, allowed_scope=("https://queued.example/",))
        approval = _approve(env, node, decision)
        env.service.create_action(node, approval)
        assert env.service.reconcile(node).outcome == "inconclusive"
    finally:
        env.close()


@pytest.mark.parametrize("failpoint", ["after_intent", "after_consume"])
def test_restart_before_job_creation_resumes_exact_intent_once(
    tmp_path: Path, failpoint: str
) -> None:
    fired = False

    def hook(name: str) -> None:
        nonlocal fired
        if name == failpoint and not fired:
            fired = True
            raise RuntimeError("synthetic crash")

    env = _environment(tmp_path, failure_hook=hook)
    node = _node(env)
    decision = env.service.policy(node, allowed_scope=(TARGET,))
    session, context, issued = _issue(env, node, decision)
    with pytest.raises(RuntimeError, match="synthetic crash"):
        env.service.bind_approval(
            node,
            decision,
            session=session,
            envelope=issued.envelope,
            expected=context,
            nonce="restart-nonce",
        )
    session.close()
    env.service.close()
    env.jobs.close()

    jobs = JobStateService(env.database, clock=env.clock)
    factory = RecordingJobFactory(jobs)
    service = ForgeBrainTruthBoundary(
        database_path=env.database,
        tenant_id=env.tenant_id,
        clock=env.clock,
        job_service=jobs,
        job_factory=factory,
    )
    session = create_db(env.database)
    try:
        approval = service.bind_approval(
            node,
            decision,
            session=session,
            envelope=issued.envelope,
            expected=context,
            nonce="restart-nonce",
        )
        service.create_action(node, approval)
        assert len(factory.calls) == 1
    finally:
        session.close()
        service.close()
        jobs.close()


@pytest.mark.parametrize("failpoint", ["after_job_create", "after_link"])
def test_restart_after_job_creation_never_duplicates_job(
    tmp_path: Path, failpoint: str
) -> None:
    fired = False

    def hook(name: str) -> None:
        nonlocal fired
        if name == failpoint and not fired:
            fired = True
            raise RuntimeError("synthetic crash")

    env = _environment(tmp_path, failure_hook=hook)
    node = _node(env)
    decision = env.service.policy(node, allowed_scope=(TARGET,))
    approval = _approve(env, node, decision)
    with pytest.raises(RuntimeError, match="synthetic crash"):
        env.service.create_action(node, approval)
    assert len(env.factory.calls) == 1
    env.service.close()
    env.jobs.close()

    jobs = JobStateService(env.database, clock=env.clock)
    factory = RecordingJobFactory(jobs)
    service = ForgeBrainTruthBoundary(
        database_path=env.database,
        tenant_id=env.tenant_id,
        clock=env.clock,
        job_service=jobs,
        job_factory=factory,
    )
    try:
        link = service.create_action(node, approval)
        assert jobs.get_job(link.job_id, tenant_id=env.tenant_id) is not None
        assert factory.calls == []
    finally:
        service.close()
        jobs.close()


def test_narrative_is_read_only_and_cannot_rescue_action_contract(tmp_path: Path) -> None:
    env = _environment(tmp_path)
    try:
        node = _node(env)
        env.service.reconcile(node)
        narrative = env.service.narrative(node)
        assert isinstance(narrative, NarrativeProjection)
        before = env.jobs.list_jobs(tenant_id=env.tenant_id)
        rendered = json.dumps(narrative.to_dict())
        assert "password" not in rendered.lower()
        assert narrative.outcome == "advisory"
        assert env.jobs.list_jobs(tenant_id=env.tenant_id) == before
        action_contract_pass = False
        narrative_quality = 1.0
        assert action_contract_pass is False and narrative_quality == 1.0
    finally:
        env.close()


def test_model_projection_memory_cache_request_and_response_exclude_canary() -> None:
    canary = corpus()["secrets"]["canary"]
    register_sensitive_values([canary])

    class Response:
        content = [type("Block", (), {"text": json.dumps({"reasoning": canary})})()]

    class Messages:
        def __init__(self) -> None:
            self.requests: list[dict[str, Any]] = []

        async def create(self, **kwargs: Any) -> Any:
            self.requests.append(kwargs)
            return Response()

    class Client:
        def __init__(self) -> None:
            self.messages = Messages()

    try:
        projection = project_model_input(
            {
                "finding_id": "finding-a",
                "title": "Fixture",
                "password": canary,
                "credential_reference": "cred:fixture:opaque",
            },
            tenant_id="tenant-a",
            engagement_id="engagement-a",
        )
        assert canary not in json.dumps(projection)
        key_a = model_cache_key(
            projection, provider="fake", model="fixture", system_version="v1"
        )
        key_b = model_cache_key(
            dict(projection, tenant_id="tenant-b"),
            provider="fake",
            model="fixture",
            system_version="v1",
        )
        assert key_a != key_b and canary not in key_a + key_b

        brain = ForgeBrain(api_key="", tenant_id="tenant-a", engagement_id="engagement-a")
        client = Client()
        brain._client = client
        brain.memory.add("finding", "webforge", {"title": "Fixture", "password": canary})
        prompt = json.dumps({"password": canary})
        with pytest.raises(RuntimeError, match="raw_model_adapter_disabled"):
            asyncio.run(brain._call(prompt))
        with pytest.raises(RuntimeError, match="raw_model_adapter_disabled"):
            asyncio.run(brain._call(prompt))
        assert canary not in json.dumps(client.messages.requests)
        assert client.messages.requests == []
        assert canary not in json.dumps(brain.memory.get_context())
        assert canary not in json.dumps(brain._cache._cache)
    finally:
        clear_sensitive_values()


def test_legacy_credential_migration_purges_database_wal_backup_and_exports(
    tmp_path: Path,
) -> None:
    canary = corpus()["secrets"]["canary"]
    database = tmp_path / "legacy-engagement.db"
    conn = sqlite3.connect(database)
    conn.executescript(
        """
        CREATE TABLE credentials(
          id TEXT PRIMARY KEY,framework TEXT NOT NULL,host TEXT,service TEXT,
          username TEXT,password TEXT,hash_value TEXT,hash_type TEXT,domain TEXT,
          source TEXT,data_json TEXT,created_at TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO credentials VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "legacy-row", "webforge", "fixture", "https", "operator",
            canary, canary, "synthetic", "fixture", "test",
            json.dumps({"nested_token": canary}), NOW.isoformat(),
        ),
    )
    conn.commit()
    conn.close()

    bus = EngagementBus(
        db_path=str(database), tenant_id="tenant-a", engagement_id="engagement-a"
    )
    try:
        marker = bus._store._connection.execute(
            "SELECT tenant_id,engagement_id,credential_state FROM credential_refs WHERE id='legacy-row'"
        ).fetchone()
        assert tuple(marker) == (
            "legacy-unattributed",
            "legacy-unattributed",
            "purged_legacy",
        )
        raw = bus._store._connection.execute(
            "SELECT password,hash_value,data_json FROM credentials WHERE id='legacy-row'"
        ).fetchone()
        assert tuple(raw) == ("", "", "{}")
        asyncio.run(bus.publish_credential("webforge", {"password": canary}))
        assert canary not in json.dumps(bus.get_credentials())
        backup = tmp_path / "legacy-backup.db"
        bus._store.safe_backup(backup)
        assert backup.stat().st_mode & 0o777 == 0o600
    finally:
        bus.close()
    for candidate in (
        database,
        Path(str(database) + "-wal"),
        Path(str(database) + "-shm"),
        backup,
    ):
        if candidate.exists():
            assert canary.encode() not in candidate.read_bytes()


def test_engagement_bus_accepts_only_canonical_protected_references() -> None:
    bus = EngagementBus(
        db_path=":memory:", tenant_id="tenant-a", engagement_id="engagement-a"
    )
    try:
        asyncio.run(
            bus.publish_credential(
                "webforge", {"credential_reference": "cred:bad:slash/value"}
            )
        )
        asyncio.run(
            bus.publish_credential(
                "webforge", {"credential_reference": "cred:fixture:opaque_ref"}
            )
        )
        states = [item["credential_state"] for item in bus.get_credentials()]
        assert sorted(states) == ["protected_reference", "purged_legacy"]
    finally:
        bus.close()


def test_legacy_database_and_backup_paths_reject_symlinks(tmp_path: Path) -> None:
    victim = tmp_path / "victim.db"
    victim.write_bytes(b"TASK106_VICTIM")
    database_link = tmp_path / "engagement-link.db"
    database_link.symlink_to(victim)
    with pytest.raises(ValueError, match="database path is unsafe"):
        EngagementBus(db_path=str(database_link))

    bus = EngagementBus(db_path=str(tmp_path / "safe.db"))
    backup_link = tmp_path / "backup-link.db"
    backup_link.symlink_to(victim)
    try:
        with pytest.raises(ValueError, match="backup destination is unsafe"):
            bus._store.safe_backup(backup_link)
    finally:
        bus.close()
    assert victim.read_bytes() == b"TASK106_VICTIM"


def test_legacy_credential_migration_replays_applying_journal_idempotently(
    tmp_path: Path,
) -> None:
    canary = corpus()["secrets"]["canary"]
    database = tmp_path / "legacy-replay.db"
    bus = EngagementBus(
        db_path=str(database), tenant_id="tenant-a", engagement_id="engagement-a"
    )
    bus._store._connection.execute(
        "INSERT INTO credentials(id,framework,password,hash_value,data_json,created_at) VALUES(?,?,?,?,?,?)",
        ("interrupted-row", "webforge", canary, canary, json.dumps({"token": canary}), NOW.isoformat()),
    )
    bus._store._connection.execute(
        "UPDATE engagement_migration_journal SET state='applying',completed_at=NULL"
    )
    bus._store._connection.commit()
    bus.close()

    for _iteration in range(2):
        bus = EngagementBus(
            db_path=str(database), tenant_id="tenant-a", engagement_id="engagement-a"
        )
        row = bus._store._connection.execute(
            "SELECT password,hash_value,data_json FROM credentials WHERE id='interrupted-row'"
        ).fetchone()
        assert tuple(row) == ("", "", "{}")
        assert bus._store._connection.execute(
            "SELECT COUNT(*) FROM credential_refs WHERE id='interrupted-row'"
        ).fetchone()[0] == 1
        assert bus._store._connection.execute(
            "SELECT state FROM engagement_migration_journal"
        ).fetchone()[0] == "applied"
        bus.close()
    assert canary.encode() not in database.read_bytes()


def test_legacy_finding_and_chain_rows_are_quarantined_without_tenant_guessing(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy-scope.db"
    conn = sqlite3.connect(database)
    conn.executescript(
        """
        CREATE TABLE findings(
          id TEXT PRIMARY KEY,framework TEXT NOT NULL,title TEXT NOT NULL,
          severity TEXT,target TEXT,module TEXT,description TEXT,remediation TEXT,
          confidence TEXT,data_json TEXT,created_at TEXT,brain_verdict TEXT,
          brain_confidence TEXT,brain_reasoning TEXT
        );
        CREATE TABLE chain_actions(
          id TEXT PRIMARY KEY,chain_type TEXT NOT NULL,source_finding TEXT NOT NULL,
          source_framework TEXT NOT NULL,target_framework TEXT NOT NULL,
          target_module TEXT NOT NULL,target TEXT,rationale TEXT,
          auto_execute INTEGER,executed INTEGER,triggered_at TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "legacy-finding", "webforge", "Legacy", "High", "fixture", "legacy",
            "", "", "LOW", "{}", NOW.isoformat(), "", "", "",
        ),
    )
    conn.execute(
        "INSERT INTO chain_actions VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (
            "legacy-chain", "legacy", "legacy-finding", "webforge", "netforge",
            "legacy-module", "fixture", "legacy", 1, 1, NOW.isoformat(),
        ),
    )
    conn.commit()
    conn.close()
    bus = EngagementBus(
        db_path=str(database), tenant_id="tenant-a", engagement_id="engagement-a"
    )
    try:
        assert bus.get_all_findings() == []
        assert bus.get_chain_actions() == []
        scoped = bus._store._connection.execute(
            "SELECT tenant_id,engagement_id FROM findings WHERE id='legacy-finding'"
        ).fetchone()
        chain = bus._store._connection.execute(
            "SELECT tenant_id,engagement_id,auto_execute,executed FROM chain_actions WHERE id='legacy-chain'"
        ).fetchone()
        assert tuple(scoped) == ("legacy-unattributed", "legacy-unattributed")
        assert tuple(chain) == (
            "legacy-unattributed", "legacy-unattributed", 0, 0
        )
    finally:
        bus.close()


def test_scheduler_history_backup_is_private_and_redacted(tmp_path: Path) -> None:
    canary = corpus()["secrets"]["canary"]
    register_sensitive_values([canary])
    try:
        scheduler = EngagementScheduler(
            ScheduleConfig(), results_dir=tmp_path / "scheduler"
        )
        scheduler._runs.append(
            EngagementRun(
                run_id=1,
                status="failed",
                error=f"provider failure password={canary}",
            )
        )
        scheduler._save_history()
        assert scheduler._history_file is not None
        payload = scheduler._history_file.read_bytes()
        assert canary.encode() not in payload
        assert scheduler._history_file.stat().st_mode & 0o777 == 0o600
    finally:
        clear_sensitive_values()


def test_session_import_drops_secret_bearing_context_and_payload_libraries() -> None:
    canary = corpus()["secrets"]["canary"]
    register_sensitive_values([canary])
    brain = ForgeBrain(
        api_key="", tenant_id="tenant-a", engagement_id="engagement-a"
    )
    bus = EngagementBus(
        db_path=":memory:",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        brain=brain,
    )
    try:
        summary = asyncio.run(
            bus.load_engagement_session(
                {
                    "export_metadata": {"target_summary": canary},
                    "credentials": [{"password": canary}],
                    "target_context": {"cookie": canary},
                    "payloads_library": [{"payload": canary}],
                    "error_signatures": [{"response": canary}],
                    "attack_chains": [{"rationale": canary}],
                }
            )
        )
        rendered = json.dumps(
            {
                "summary": summary,
                "credentials": bus.get_credentials(),
                "memory": brain.memory.get_context(),
                "intel": bus.get_intel().to_dict(),
            },
            default=str,
        )
        assert canary not in rendered
    finally:
        bus.close()
        clear_sensitive_values()


def test_two_tenants_share_no_plan_snapshot_job_outcome_or_narrative(
    tmp_path: Path,
) -> None:
    database = tmp_path / "two-tenant.db"
    env_a = _environment(tmp_path, suffix="a", database=database)
    env_b = _environment(tmp_path, suffix="b", database=database)
    try:
        node_a = _node(env_a)
        node_b = _node(env_b)
        assert node_a.id != node_b.id
        decision_a = env_a.service.policy(node_a, allowed_scope=(TARGET,))
        approval_a = _approve(env_a, node_a, decision_a)
        env_a.service.create_action(node_a, approval_a)
        with pytest.raises(BoundaryDenied, match="cross_tenant"):
            env_b.service.create_action(node_a, approval_a)
        with pytest.raises(BoundaryDenied, match="cross_tenant"):
            env_b.service.narrative(node_a)
        assert len(env_a.jobs.list_jobs(tenant_id=env_a.tenant_id)) == 1
        assert env_b.jobs.list_jobs(tenant_id=env_b.tenant_id) == []
        rows = env_a.jobs.conn.execute(
            "SELECT tenant_id,COUNT(*) FROM canonical_advisory_plans GROUP BY tenant_id"
        ).fetchall()
        assert {tuple(row) for row in rows} == {
            (env_a.tenant_id, 1), (env_b.tenant_id, 1)
        }
    finally:
        env_a.close()
        env_b.close()


def test_migration_upgrade_interruption_replay_and_empty_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "migration.db"
    session = create_db(database)
    engine = session.get_bind()
    assert engine is not None
    manager = MigrationManager(engine)
    assert BRAIN_TRUTH_SCHEMA_VERSION in manager.versions
    manager.downgrade(REFERENCE_SLICE_SCHEMA_VERSION)
    with pytest.raises(MigrationInterruptedError):
        manager.upgrade(BRAIN_TRUTH_SCHEMA_VERSION, fail_after=1)
    assert manager.recover() is not None
    assert manager.journal()[-1]["version"] == BRAIN_TRUTH_SCHEMA_VERSION
    assert manager.journal()[-1]["state"] == "applied"
    assert manager.downgrade(REFERENCE_SLICE_SCHEMA_VERSION) is not None
    tables = {
        str(row[0])
        for row in session.connection().exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "canonical_advisory_plans" not in tables
    session.close()


def test_migration_refuses_downgrade_with_retained_advisory_history(
    tmp_path: Path,
) -> None:
    env = _environment(tmp_path)
    try:
        _node(env)
        engine = env.jobs._bootstrap_session.get_bind()
        assert engine is not None
        with pytest.raises(MigrationError, match="retained history"):
            MigrationManager(engine).downgrade(REFERENCE_SLICE_SCHEMA_VERSION)
    finally:
        env.close()
