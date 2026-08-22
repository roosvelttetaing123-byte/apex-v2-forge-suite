from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import DatabaseError

from common.action_authorization import (
    AUTHORIZATION_SCHEMA_VERSION,
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    AuthorizationOutcome,
    AuthorizationPersistenceError,
    AuthorizationReason,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    authorize_and_link_scan_job,
    claim_consumed_authorization_execution,
    compute_envelope_digest,
    consume_authorization,
    derive_authorization,
    default_authorization_db_path,
    execute_authorized,
    issue_authorization,
    load_authorization_envelopes,
    normalize_agent_authorization,
    normalize_cli_authorization,
    normalize_dashboard_authorization,
    open_authorization_session,
    redact_authorization_value,
    record_boundary_denial,
    validate_consumed_authorization,
)
from common.confirm_gate import ActionConfirmation
from common.canonical import MissingCanonicalContextError
from common.db import (
    AuthorizationConsumptionModel,
    AuthorizationDecisionModel,
    AuthorizationExecutionClaimModel,
    ScanJobModel,
    create_db,
    list_authorization_decisions,
    save_scan_job,
    update_scan_job,
)
from common.dashboard.event_bus import Event, EventType


NOW = datetime(2026, 7, 22, 16, 0, tzinfo=timezone.utc)
LAB_URL = "http://127.0.0.1:8080/fixture"
LAB_SCOPE = ["127.0.0.1/32"]


def _context(**overrides: object) -> AuthorizationContext:
    values: dict[str, object] = {
        "tenant_id": "tenant-lab",
        "engagement_id": "engagement-lab",
        "run_id": "run-lab",
        "job_id": "job-lab",
        "operator_id": "operator-lab",
        "operator_role": OperatorRole.OPERATOR,
        "action_kind": "module.execute",
        "engine": "webforge",
        "module_id": "sqli_scanner",
        "requested_target": LAB_URL,
        "resolved_target": LAB_URL,
        "allowed_scope": LAB_SCOPE,
        "excluded_scope": [],
        "scope_policy_version": "scope-policy-v1",
        "safety_mode": SafetyMode.ACTIVE,
        "credential_approval_required": False,
        "network_escalation_approval_required": False,
        "high_risk_approval_required": False,
        "confirmation_method": ConfirmationMethod.CLI_PROMPT,
        "confirmed_by": "operator-lab",
        "credential_reference": "",
        "parent_decision_id": "",
    }
    values.update(overrides)
    return AuthorizationContext(**values)


def _confirmation(context: AuthorizationContext | None = None, **overrides: object) -> ActionConfirmation:
    context = context or _context()
    values: dict[str, object] = {
        "job_id": context.job_id,
        "target": context.resolved_target,
        "engine": context.engine,
        "action": context.action_kind,
        "issued_at": NOW,
    }
    values.update(overrides)
    return ActionConfirmation.create(**values)


def _issue(session, context: AuthorizationContext | None = None, **overrides: object):
    context = context or _context()
    values: dict[str, object] = {
        "session": session,
        "context": context,
        "confirmation": _confirmation(context),
        "now": NOW,
    }
    values.update(overrides)
    return issue_authorization(**values)


def test_complete_matching_envelope_authorizes_one_exact_action(tmp_path) -> None:
    session = create_db(tmp_path / "authorization.db")
    issued = _issue(session)
    calls: list[str] = []

    decision, result = execute_authorized(
        session=session,
        envelope=issued.envelope,
        expected=_context(),
        boundary="module.execute",
        now=NOW,
        executor=lambda action_id: calls.append(action_id) or "executed",
    )

    assert decision.allowed is True
    assert decision.reason_code == AuthorizationReason.ALLOWED.value
    assert result == "executed"
    assert calls == [issued.envelope.action_id]
    assert session.query(AuthorizationConsumptionModel).count() == 1

    replay = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=_context(),
        boundary="module.execute",
        now=NOW,
    )
    assert replay.allowed is False
    assert replay.reason_code == AuthorizationReason.ALREADY_CONSUMED.value
    assert calls == [issued.envelope.action_id]
    session.close()


@pytest.mark.parametrize("missing_field", ActionAuthorizationEnvelope.required_fields())
def test_each_required_envelope_field_missing_denies_and_audits(
    tmp_path,
    missing_field: str,
) -> None:
    session = create_db(tmp_path / f"missing-{missing_field}.db")
    issued = _issue(session)
    malformed = issued.envelope.to_dict()
    malformed.pop(missing_field)
    before = session.query(AuthorizationDecisionModel).count()

    denied = consume_authorization(
        session=session,
        envelope=malformed,
        expected=_context(),
        boundary="module.execute",
        now=NOW,
    )

    assert denied.allowed is False
    assert denied.reason_code == AuthorizationReason.MISSING_REQUIRED_FIELD.value
    assert session.query(AuthorizationDecisionModel).count() == before + 1
    latest = list_authorization_decisions(session)[-1]
    assert latest["decision_outcome"] == AuthorizationOutcome.DENY.value
    assert latest["reason_code"] == AuthorizationReason.MISSING_REQUIRED_FIELD.value
    assert latest["detail"] == {"field": missing_field}
    session.close()


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("tenant_id", "tenant-other", AuthorizationReason.TENANT_MISMATCH),
        ("engagement_id", "engagement-other", AuthorizationReason.ENGAGEMENT_MISMATCH),
        ("run_id", "run-other", AuthorizationReason.RUN_MISMATCH),
        ("job_id", "job-other", AuthorizationReason.JOB_MISMATCH),
        ("operator_id", "operator-other", AuthorizationReason.OPERATOR_MISMATCH),
        ("operator_role", OperatorRole.ADMIN, AuthorizationReason.ROLE_MISMATCH),
        ("engine", "netforge", AuthorizationReason.ENGINE_MISMATCH),
        ("module_id", "xss_scanner", AuthorizationReason.MODULE_MISMATCH),
        ("action_kind", "engine.execute", AuthorizationReason.ACTION_MISMATCH),
        ("requested_target", "http://127.0.0.2:8080/fixture", AuthorizationReason.REQUESTED_TARGET_MISMATCH),
        ("resolved_target", "http://127.0.0.2:8080/fixture", AuthorizationReason.RESOLVED_TARGET_MISMATCH),
        ("credential_reference", "cred:other", AuthorizationReason.APPROVAL_MISMATCH),
        ("confirmation_method", ConfirmationMethod.DASHBOARD, AuthorizationReason.APPROVAL_MISMATCH),
        ("confirmed_by", "operator-other", AuthorizationReason.APPROVAL_MISMATCH),
    ],
)
def test_exact_binding_mismatches_deny_and_audit(
    tmp_path,
    field: str,
    value: object,
    reason: AuthorizationReason,
) -> None:
    session = create_db(tmp_path / f"mismatch-{field}.db")
    issued = _issue(session)
    expected = replace(_context(), **{field: value})

    denied = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=expected,
        boundary="module.execute",
        now=NOW,
    )

    assert denied.allowed is False
    assert denied.reason_code == reason.value
    assert list_authorization_decisions(session)[-1]["reason_code"] == reason.value
    assert session.query(AuthorizationConsumptionModel).count() == 0
    session.close()


def test_expired_future_modified_replayed_and_consumed_envelopes_fail(tmp_path) -> None:
    session = create_db(tmp_path / "negative-time-replay.db")

    expired = _issue(session)
    expired_result = consume_authorization(
        session=session,
        envelope=expired.envelope,
        expected=_context(),
        boundary="expired",
        now=NOW + timedelta(minutes=6),
    )
    assert expired_result.reason_code == AuthorizationReason.EXPIRED.value

    future = _issue(
        session,
        now=NOW + timedelta(minutes=2),
        confirmation=_confirmation(issued_at=NOW + timedelta(minutes=2)),
    )
    future_result = consume_authorization(
        session=session,
        envelope=future.envelope,
        expected=_context(),
        boundary="future",
        now=NOW,
    )
    assert future_result.reason_code == AuthorizationReason.FUTURE_ISSUED.value

    modified_context = replace(
        _context(),
        job_id="job-modified-envelope",
        run_id="run-modified-envelope",
    )
    modified = _issue(
        session,
        context=modified_context,
        confirmation=_confirmation(modified_context),
    )
    modified_value = modified.envelope.to_dict()
    modified_value["module_id"] = "xss_scanner"
    mutation_result = consume_authorization(
        session=session,
        envelope=modified_value,
        expected=modified_context,
        boundary="mutation",
        now=NOW,
    )
    assert mutation_result.reason_code == AuthorizationReason.INTEGRITY_MISMATCH.value

    recomputed = modified.envelope.to_dict()
    recomputed["module_id"] = "xss_scanner"
    recomputed["binding_digest"] = compute_envelope_digest(recomputed)
    stored_mismatch = consume_authorization(
        session=session,
        envelope=recomputed,
        expected=replace(modified_context, module_id="xss_scanner"),
        boundary="stored-mutation",
        now=NOW,
    )
    assert stored_mismatch.reason_code == AuthorizationReason.INTEGRITY_MISMATCH.value

    consumed_context = replace(
        _context(),
        job_id="job-consumed-envelope",
        run_id="run-consumed-envelope",
    )
    consumed = _issue(
        session,
        context=consumed_context,
        confirmation=_confirmation(consumed_context),
    )
    first = consume_authorization(
        session=session,
        envelope=consumed.envelope,
        expected=consumed_context,
        boundary="first-boundary",
        now=NOW,
    )
    second_boundary = consume_authorization(
        session=session,
        envelope=consumed.envelope,
        expected=consumed_context,
        boundary="different-boundary",
        now=NOW,
    )
    assert first.allowed is True
    assert second_boundary.reason_code == AuthorizationReason.REPLAYED.value
    session.close()


def test_authorization_ttl_cannot_extend_an_old_confirmation(tmp_path) -> None:
    session = create_db(tmp_path / "confirmation-age.db")
    context = _context()
    confirmation = _confirmation(
        context,
        issued_at=NOW - timedelta(seconds=299),
    )
    issued = _issue(
        session,
        context=context,
        confirmation=confirmation,
        now=NOW,
    )

    assert issued.allowed is True
    expires_at = datetime.fromisoformat(issued.envelope.expires_at.replace("Z", "+00:00"))
    assert expires_at <= NOW + timedelta(seconds=1)
    expired = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=context,
        boundary="module.execute",
        now=NOW + timedelta(seconds=2),
    )
    assert expired.allowed is False
    assert expired.reason_code == AuthorizationReason.EXPIRED.value
    session.close()


def test_one_confirmation_cannot_mint_multiple_root_authorizations(tmp_path) -> None:
    session = create_db(tmp_path / "confirmation-replay.db")
    context = _context()
    confirmation = _confirmation(context)

    first = _issue(
        session,
        context=context,
        confirmation=confirmation,
        now=NOW,
    )
    replay = _issue(
        session,
        context=context,
        confirmation=confirmation,
        now=NOW,
    )

    assert first.allowed is True
    assert replay.allowed is False
    assert replay.reason_code == AuthorizationReason.REPLAYED.value
    allowed_roots = (
        session.query(AuthorizationDecisionModel)
        .filter_by(
            parent_decision_id=None,
            decision_outcome=AuthorizationOutcome.ALLOW.value,
        )
        .all()
    )
    assert [row.decision_id for row in allowed_roots] == [first.envelope.decision_id]
    assert consume_authorization(
        session=session,
        envelope=first.envelope,
        expected=context,
        boundary="module.execute",
        now=NOW,
    ).allowed
    session.close()


def test_secret_bearing_target_values_remain_exact_opaque_bindings(tmp_path) -> None:
    session = create_db(tmp_path / "exact-secret-target.db")
    target_a = "https://127.0.0.1/fixture?token=CANARY_TOKEN_A"
    target_b = "https://127.0.0.1/fixture?token=CANARY_TOKEN_B"
    context = _context(requested_target=target_a, resolved_target=target_a)
    issued = _issue(
        session,
        context=context,
        confirmation=ActionConfirmation.create(
            job_id=context.job_id,
            target=target_a,
            engine=context.engine,
            action=context.action_kind,
            issued_at=NOW,
        ),
    )

    denied = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=replace(context, requested_target=target_b, resolved_target=target_b),
        boundary="exact-secret-target",
        now=NOW,
    )

    assert denied.allowed is False
    assert denied.reason_code == AuthorizationReason.REQUESTED_TARGET_MISMATCH.value
    rendered = issued.envelope.to_json()
    assert "CANARY_TOKEN_A" not in rendered
    assert "CANARY_TOKEN_B" not in rendered
    session.close()


def test_consumed_capability_validation_requires_exact_persisted_consumption(tmp_path) -> None:
    db_path = tmp_path / "consumed-capability.db"
    session = create_db(db_path)
    issued = _issue(session)

    missing = validate_consumed_authorization(
        session=session,
        envelope=issued.envelope,
        expected=_context(),
        boundary="module.execute",
        now=NOW,
    )
    assert missing.allowed is False
    assert missing.reason_code == AuthorizationReason.NOT_CONSUMED.value

    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=_context(),
        boundary="module.execute",
        now=NOW,
    )
    assert consumed.allowed is True
    verified = validate_consumed_authorization(
        session=session,
        envelope=issued.envelope,
        expected=_context(),
        boundary="module.execute",
        now=NOW,
    )
    wrong_boundary = validate_consumed_authorization(
        session=session,
        envelope=issued.envelope,
        expected=_context(),
        boundary="other.execute",
        now=NOW,
    )
    assert verified.allowed is True
    assert wrong_boundary.allowed is False
    assert wrong_boundary.reason_code == AuthorizationReason.INTEGRITY_MISMATCH.value

    first = claim_consumed_authorization_execution(
        session=session,
        envelope=issued.envelope,
        expected=_context(),
        boundary="module.execute",
        now=NOW,
    )
    repeated = claim_consumed_authorization_execution(
        session=session,
        envelope=issued.envelope,
        expected=_context(),
        boundary="module.execute",
        now=NOW,
    )
    assert first.allowed is True
    assert repeated.allowed is False
    assert repeated.reason_code == AuthorizationReason.ALREADY_CONSUMED.value
    assert session.query(AuthorizationExecutionClaimModel).count() == 1
    session.close()

    reconstructed = create_db(db_path)
    replay = claim_consumed_authorization_execution(
        session=reconstructed,
        envelope=issued.envelope,
        expected=_context(),
        boundary="module.execute",
        now=NOW,
    )
    assert replay.allowed is False
    assert replay.reason_code == AuthorizationReason.ALREADY_CONSUMED.value
    assert reconstructed.query(AuthorizationExecutionClaimModel).count() == 1
    reconstructed.close()

    race_db_path = tmp_path / "execution-claim-race.db"
    issuer = create_db(race_db_path)
    race_context = _context(job_id="job-claim-race", run_id="run-claim-race")
    race_issued = _issue(issuer, context=race_context)
    assert consume_authorization(
        session=issuer,
        envelope=race_issued.envelope,
        expected=race_context,
        boundary="module.execute",
        now=NOW,
    ).allowed
    issuer.close()

    sessions = [create_db(race_db_path), create_db(race_db_path)]
    barrier = threading.Barrier(2)

    def attempt(session) -> bool:
        barrier.wait()
        return claim_consumed_authorization_execution(
            session=session,
            envelope=race_issued.envelope,
            expected=race_context,
            boundary="module.execute",
            now=NOW,
        ).allowed

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, sessions))
        assert sorted(results) == [False, True]
        assert sessions[0].query(AuthorizationExecutionClaimModel).count() == 1
    finally:
        for session in sessions:
            session.close()


def test_parent_derivation_is_bounded_typed_single_use_and_non_broadening(tmp_path) -> None:
    session = create_db(tmp_path / "derivation-lineage.db")
    root = _context(
        action_kind="scan",
        module_id="",
        safety_mode=SafetyMode.ACTIVE,
    )
    issued = _issue(session, context=root, confirmation=_confirmation(root))
    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=root,
        boundary="cli.launch",
        now=NOW,
    )
    assert consumed.allowed is True
    child_context = replace(
        root,
        action_kind="engine.execute",
        parent_decision_id=issued.envelope.decision_id,
        confirmation_method=ConfirmationMethod.INHERITED,
    )

    child = derive_authorization(
        session=session,
        parent_envelope=issued.envelope,
        context=child_context,
        parent_boundary="cli.launch",
        now=NOW,
    )
    duplicate = derive_authorization(
        session=session,
        parent_envelope=issued.envelope,
        context=child_context,
        parent_boundary="cli.launch",
        now=NOW,
    )
    broadened_action = derive_authorization(
        session=session,
        parent_envelope=issued.envelope,
        context=replace(child_context, action_kind="module.execute", module_id="probe"),
        parent_boundary="cli.launch",
        now=NOW,
    )

    assert child.allowed is True
    assert child.envelope.expires_at <= issued.envelope.expires_at
    assert duplicate.allowed is False
    assert duplicate.reason_code == AuthorizationReason.ALREADY_DERIVED.value
    assert broadened_action.allowed is False
    assert broadened_action.reason_code == AuthorizationReason.PARENT_NOT_AUTHORIZED.value

    other_root = replace(root, job_id="job-expired-parent", run_id="run-expired-parent")
    other_issued = _issue(
        session,
        context=other_root,
        confirmation=_confirmation(other_root),
    )
    assert consume_authorization(
        session=session,
        envelope=other_issued.envelope,
        expected=other_root,
        boundary="cli.launch",
        now=NOW,
    ).allowed
    expired_child = derive_authorization(
        session=session,
        parent_envelope=other_issued.envelope,
        context=replace(
            other_root,
            action_kind="engine.execute",
            parent_decision_id=other_issued.envelope.decision_id,
            confirmation_method=ConfirmationMethod.INHERITED,
        ),
        parent_boundary="cli.launch",
        now=NOW + timedelta(minutes=6),
    )
    assert expired_child.allowed is False
    assert expired_child.reason_code == AuthorizationReason.EXPIRED.value

    mismatch_root = replace(root, job_id="job-safety-parent", run_id="run-safety-parent")
    mismatch_issued = _issue(
        session,
        context=mismatch_root,
        confirmation=_confirmation(mismatch_root),
    )
    assert consume_authorization(
        session=session,
        envelope=mismatch_issued.envelope,
        expected=mismatch_root,
        boundary="cli.launch",
        now=NOW,
    ).allowed
    safety_broadening = derive_authorization(
        session=session,
        parent_envelope=mismatch_issued.envelope,
        context=replace(
            mismatch_root,
            action_kind="engine.execute",
            safety_mode=SafetyMode.HIGH_RISK,
            parent_decision_id=mismatch_issued.envelope.decision_id,
            confirmation_method=ConfirmationMethod.INHERITED,
        ),
        parent_boundary="cli.launch",
        now=NOW,
    )
    assert safety_broadening.allowed is False
    assert safety_broadening.reason_code == AuthorizationReason.PARENT_NOT_AUTHORIZED.value
    session.close()


def test_parent_derivation_requires_the_exact_consumption_boundary(tmp_path) -> None:
    session = create_db(tmp_path / "derivation-parent-boundary.db")
    root = _context(action_kind="scan", module_id="", safety_mode=SafetyMode.ACTIVE)
    issued = _issue(session, context=root, confirmation=_confirmation(root))
    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=root,
        boundary="unrelated.component",
        now=NOW,
    )
    assert consumed.allowed is True

    child = derive_authorization(
        session=session,
        parent_envelope=issued.envelope,
        context=replace(
            root,
            action_kind="engine.execute",
            parent_decision_id=issued.envelope.decision_id,
            confirmation_method=ConfirmationMethod.INHERITED,
        ),
        parent_boundary="cli.launch",
        now=NOW,
    )

    assert child.allowed is False
    assert child.reason_code == AuthorizationReason.PARENT_NOT_AUTHORIZED.value
    latest = list_authorization_decisions(session)[-1]
    assert latest["decision_outcome"] == AuthorizationOutcome.DENY.value
    assert latest["parent_decision_id"] == issued.envelope.decision_id
    session.close()


def test_exact_engine_module_binding_cannot_be_broadened(tmp_path) -> None:
    session = create_db(tmp_path / "derivation-module-binding.db")
    root = _context(
        action_kind="scan",
        module_id="allowed_module",
        safety_mode=SafetyMode.ACTIVE,
    )
    issued = _issue(session, context=root, confirmation=_confirmation(root))
    assert consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=root,
        boundary="cli.launch",
        now=NOW,
    ).allowed
    engine_context = replace(
        root,
        action_kind="engine.execute",
        parent_decision_id=issued.envelope.decision_id,
        confirmation_method=ConfirmationMethod.INHERITED,
    )
    engine = derive_authorization(
        session=session,
        parent_envelope=issued.envelope,
        context=engine_context,
        parent_boundary="cli.launch",
        now=NOW,
    )
    assert engine.allowed
    assert consume_authorization(
        session=session,
        envelope=engine.envelope,
        expected=engine_context,
        boundary="engine.execute",
        now=NOW,
    ).allowed
    broadened = derive_authorization(
        session=session,
        parent_envelope=engine.envelope,
        context=replace(
            engine_context,
            action_kind="module.execute",
            module_id="forbidden_module",
            parent_decision_id=engine.envelope.decision_id,
        ),
        parent_boundary="engine.execute",
        now=NOW,
    )
    assert broadened.allowed is False
    assert broadened.reason_code == AuthorizationReason.PARENT_NOT_AUTHORIZED.value
    session.close()


def test_derive_commit_false_stages_allow_and_denial_for_caller_transaction(
    tmp_path,
) -> None:
    db_path = tmp_path / "derivation-transaction.db"
    session = create_db(db_path)
    root = _context(action_kind="scan", module_id="", safety_mode=SafetyMode.ACTIVE)
    issued = _issue(session, context=root, confirmation=_confirmation(root))
    assert consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=root,
        boundary="cli.launch",
        now=NOW,
    ).allowed
    child_context = replace(
        root,
        action_kind="engine.execute",
        parent_decision_id=issued.envelope.decision_id,
        confirmation_method=ConfirmationMethod.INHERITED,
    )

    child = derive_authorization(
        session=session,
        parent_envelope=issued.envelope,
        context=child_context,
        parent_boundary="cli.launch",
        now=NOW,
        commit=False,
    )
    assert child.allowed is True
    assert session.query(AuthorizationDecisionModel).count() == 2
    connection = sqlite3.connect(db_path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM authorization_decisions"
        ).fetchone()[0] == 1
    finally:
        connection.close()
    session.rollback()

    denied = derive_authorization(
        session=session,
        parent_envelope=issued.envelope,
        context=replace(child_context, action_kind="module.execute", module_id="probe"),
        parent_boundary="cli.launch",
        now=NOW,
        commit=False,
    )
    assert denied.allowed is False
    assert denied.reason_code == AuthorizationReason.PARENT_NOT_AUTHORIZED.value
    connection = sqlite3.connect(db_path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM authorization_decisions"
        ).fetchone()[0] == 1
    finally:
        connection.close()
    session.rollback()
    session.close()


def test_denial_is_committed_before_boundary_and_boundary_is_never_called(tmp_path) -> None:
    session = create_db(tmp_path / "deny-before-boundary.db")
    denied_issue = issue_authorization(
        session=session,
        context=_context(),
        confirmation=None,
        now=NOW,
    )
    called = False

    def boundary(_action_id: str) -> None:
        nonlocal called
        called = True

    decision, result = execute_authorized(
        session=session,
        envelope=denied_issue.envelope,
        expected=_context(),
        boundary="module.execute",
        now=NOW,
        executor=boundary,
    )

    assert decision.allowed is False
    assert result is None
    assert called is False
    rows = list_authorization_decisions(session)
    assert rows[0]["decision_outcome"] == AuthorizationOutcome.DENY.value
    assert rows[0]["reason_code"] == "missing_confirmation"
    session.close()


def test_allow_uses_server_ids_and_links_job_action_without_client_outcome(tmp_path) -> None:
    session = create_db(tmp_path / "trusted-link.db")
    body = {
        "tenant_id": "attacker-tenant",
        "operator_id": "attacker",
        "operator_role": "admin",
        "decision_outcome": "allow",
        "decision_id": "client-decision",
        "action_id": "client-action",
        "issued_at": "1999-01-01T00:00:00Z",
        "job_id": "client-job",
        "target": LAB_URL,
    }
    context = normalize_dashboard_authorization(
        body,
        tenant_id="tenant-lab",
        operator_id="operator-lab",
        operator_role=OperatorRole.OPERATOR,
        engagement_id="engagement-lab",
        run_id="run-lab",
        job_id="server-job",
        action_kind="module.execute",
        engine="webforge",
        module_id="sqli_scanner",
        requested_target=LAB_URL,
        resolved_target=LAB_URL,
        allowed_scope=LAB_SCOPE,
        excluded_scope=[],
        safety_mode=SafetyMode.ACTIVE,
        confirmation_method=ConfirmationMethod.DASHBOARD,
        confirmed_by="operator-lab",
    )
    confirmation = ActionConfirmation.create(
        job_id=context.job_id,
        target=context.resolved_target,
        engine=context.engine,
        action=context.action_kind,
        issued_at=NOW,
    )
    with pytest.raises(MissingCanonicalContextError):
        authorize_and_link_scan_job(
            session=session,
            context=context,
            confirmation=confirmation,
            boundary="dashboard.launch",
            job_record={
                "id": "client-job",
                "status": "pending",
                "target": LAB_URL,
                "frameworks": ["webforge"],
                "modules": ["sqli_scanner"],
            },
            now=NOW,
        )
    assert session.query(AuthorizationConsumptionModel).count() == 0
    assert session.get(ScanJobModel, "server-job") is None
    assert session.get(ScanJobModel, "client-job") is None
    session.close()


def test_cli_dashboard_and_agent_adapters_normalize_equivalently(tmp_path) -> None:
    untrusted = {
        "tenant_id": "ignored",
        "operator_id": "ignored",
        "operator_role": "admin",
        "decision_outcome": "allow",
        "issued_at": "ignored",
    }
    common = {
        "tenant_id": "tenant-lab",
        "operator_id": "operator-lab",
        "operator_role": OperatorRole.OPERATOR,
        "engagement_id": "engagement-lab",
        "run_id": "run-lab",
        "job_id": "job-lab",
        "action_kind": "module.execute",
        "engine": "webforge",
        "module_id": "sqli_scanner",
        "requested_target": LAB_URL,
        "resolved_target": LAB_URL,
        "allowed_scope": LAB_SCOPE,
        "excluded_scope": [],
        "safety_mode": SafetyMode.ACTIVE,
        "confirmation_method": ConfirmationMethod.INHERITED,
        "confirmed_by": "operator-lab",
    }

    cli = normalize_cli_authorization(untrusted, **common)
    dashboard = normalize_dashboard_authorization(untrusted, **common)
    agent = normalize_agent_authorization(untrusted, **common)

    assert cli == dashboard == agent
    issued = []
    for index, context in enumerate((cli, dashboard, agent)):
        session = create_db(tmp_path / f"adapter-{index}.db")
        decision = issue_authorization(
            session=session,
            context=context,
            confirmation=_confirmation(context),
            now=NOW,
        )
        issued.append(decision)
        session.close()
    assert [item.allowed for item in issued] == [True, True, True]
    assert [item.reason_code for item in issued] == ["allowed", "allowed", "allowed"]
    projections = []
    for item in issued:
        value = item.envelope.to_dict()
        for generated in ("decision_id", "action_id", "binding_digest"):
            value.pop(generated)
        projections.append(value)
    assert projections[0] == projections[1] == projections[2]


def test_authorization_records_are_append_only_ordered_and_attributable(tmp_path) -> None:
    session = create_db(tmp_path / "immutable.db")
    first = _issue(session, context=_context(job_id="job-one"))
    second_context = _context(job_id="job-two")
    second = _issue(
        session,
        context=second_context,
        confirmation=_confirmation(second_context),
        now=NOW + timedelta(seconds=1),
    )

    rows = list_authorization_decisions(session)
    assert [row["decision_id"] for row in rows] == [
        first.envelope.decision_id,
        second.envelope.decision_id,
    ]
    assert [row["operator_id"] for row in rows] == ["operator-lab", "operator-lab"]
    rows[0]["operator_id"] = "mutated-copy"
    assert list_authorization_decisions(session)[0]["operator_id"] == "operator-lab"

    with pytest.raises(DatabaseError):
        session.connection().exec_driver_sql(
            "UPDATE authorization_decisions SET operator_id='changed'"
        )
    session.rollback()
    with pytest.raises(DatabaseError):
        session.connection().exec_driver_sql("DELETE FROM authorization_decisions")
    session.rollback()
    claimed_context = _context(job_id="job-claim")
    claimed = _issue(
        session,
        context=claimed_context,
        confirmation=_confirmation(claimed_context),
    )
    assert consume_authorization(
        session=session,
        envelope=claimed.envelope,
        expected=claimed_context,
        boundary="module.execute",
        now=NOW,
    ).allowed
    assert claim_consumed_authorization_execution(
        session=session,
        envelope=claimed.envelope,
        expected=claimed_context,
        boundary="module.execute",
        now=NOW,
    ).allowed
    with pytest.raises(DatabaseError):
        session.connection().exec_driver_sql(
            "UPDATE authorization_execution_claims SET boundary='changed'"
        )
    session.rollback()
    with pytest.raises(DatabaseError):
        session.connection().exec_driver_sql(
            "DELETE FROM authorization_execution_claims"
        )
    session.rollback()
    session.close()


def test_canary_secrets_never_serialize_log_or_enter_audit_detail(tmp_path, caplog) -> None:
    canaries = [
        "CANARY_PASSWORD_002",
        "Bearer CANARY_TOKEN_002",
        "Cookie: session=CANARY_COOKIE_002",
        "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef",
        "AKIAIOSFODNN7EXAMPLE",
        "-----BEGIN PRIVATE KEY-----CANARY_PRIVATE_KEY_002",
    ]
    secret_target = (
        "https://127.0.0.1/path?password=CANARY_PASSWORD_002&token=CANARY_TOKEN_002"
    )
    context = _context(requested_target=secret_target, resolved_target=secret_target)
    session = create_db(tmp_path / "redaction.db")
    issued = issue_authorization(
        session=session,
        context=context,
        confirmation=ActionConfirmation.create(
            job_id=context.job_id,
            target=secret_target,
            engine=context.engine,
            action=context.action_kind,
            issued_at=NOW,
        ),
        now=NOW,
        detail={
            "password": canaries[0],
            "nested": {"value": canaries[1], "cookie": canaries[2]},
            "hash": canaries[3],
            "api_key": canaries[4],
            "pem": canaries[5],
        },
    )

    rendered = json.dumps(issued.envelope.to_dict(), sort_keys=True)
    event = Event(
        event_type=EventType.CONTROL_COMMAND,
        source="authorization-test",
        data={"authorization": issued.envelope.to_event_payload()},
    )
    rendered += event.to_json()
    rendered += json.dumps(list_authorization_decisions(session), sort_keys=True)
    rendered += json.dumps(redact_authorization_value({"values": canaries}), sort_keys=True)
    malformed = issued.envelope.to_dict()
    malformed["module_id"] = canaries[1]
    with pytest.raises(Exception) as exc_info:
        ActionAuthorizationEnvelope.from_value(malformed)
    rendered += str(exc_info.value)
    caplog.set_level("WARNING")
    assert load_authorization_envelopes(
        {"FORGE_ACTION_AUTHORIZATIONS": json.dumps({"secret": canaries[0]})}
    ) == []
    rendered += caplog.text
    for canary in canaries:
        assert canary not in rendered
    assert "CANARY_PASSWORD_002" not in str(issued)
    session.close()


def test_legacy_scan_job_defaults_to_unknown_not_authorized(tmp_path) -> None:
    db_path = tmp_path / "legacy.db"
    connection = sqlite3.connect(db_path)
    connection.execute(
        "CREATE TABLE scan_jobs (id VARCHAR(36) PRIMARY KEY, status VARCHAR(20), target VARCHAR(500))"
    )
    connection.execute(
        "INSERT INTO scan_jobs (id, status, target) VALUES (?, ?, ?)",
        ("legacy-job", "pending", LAB_URL),
    )
    connection.commit()
    connection.close()

    session = create_db(db_path)
    legacy = session.get(ScanJobModel, "legacy-job")

    assert legacy is not None
    assert legacy.authorization_state == AuthorizationOutcome.UNKNOWN_NOT_AUTHORIZED.value
    assert legacy.authorization_decision_id is None
    assert legacy.authorization_action_id is None

    denied = consume_authorization(
        session=session,
        envelope=None,
        expected=_context(job_id="legacy-job"),
        boundary="legacy.launch",
        now=NOW,
    )
    assert denied.allowed is False
    assert denied.reason_code == AuthorizationReason.LEGACY_NOT_AUTHORIZED.value
    session.close()


def test_schema_version_is_present_from_first_record(tmp_path) -> None:
    session = create_db(tmp_path / "schema.db")
    issued = _issue(session)
    row = session.query(AuthorizationDecisionModel).one()

    assert issued.envelope.schema_version == AUTHORIZATION_SCHEMA_VERSION
    assert row.schema_version == AUTHORIZATION_SCHEMA_VERSION
    session.close()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unknown_field": "ambiguous"}),
        lambda value: value.update({"single_use": 1}),
        lambda value: value.update({"credential_approval_required": 0}),
    ],
)
def test_unknown_keys_and_truthy_non_booleans_deny_strictly(tmp_path, mutation) -> None:
    session = create_db(tmp_path / f"strict-{uuid.uuid4().hex}.db")
    issued = _issue(session)
    value = issued.envelope.to_dict()
    mutation(value)

    denied = consume_authorization(
        session=session,
        envelope=value,
        expected=_context(),
        boundary="strict.parser",
        now=NOW,
    )

    assert denied.allowed is False
    assert denied.reason_code in {
        AuthorizationReason.MALFORMED_FIELD.value,
        AuthorizationReason.INTEGRITY_MISMATCH.value,
    }
    assert session.query(AuthorizationConsumptionModel).count() == 0
    session.close()


def test_audit_persistence_failure_fails_closed_before_executor(
    tmp_path,
    monkeypatch,
) -> None:
    session = create_db(tmp_path / "audit-failure.db")
    called = False

    def fail_append(*args, **kwargs):
        raise OSError("CANARY_PASSWORD_MUST_NOT_LEAK")

    monkeypatch.setattr(
        "common.action_authorization.append_authorization_decision",
        fail_append,
    )

    with pytest.raises(AuthorizationPersistenceError) as exc_info:
        issue_authorization(
            session=session,
            context=_context(),
            confirmation=_confirmation(),
            now=NOW,
        )
    assert called is False
    assert "CANARY_PASSWORD_MUST_NOT_LEAK" not in str(exc_info.value)
    session.close()


def test_malformed_boundary_denial_is_audited_with_opaque_values(tmp_path) -> None:
    session = create_db(tmp_path / "malformed-boundary.db")
    secret = "CANARY_MALFORMED_TARGET_SECRET_002"

    denied = record_boundary_denial(
        session=session,
        reason_code="malformed_target",
        action_kind={"not": "a-string"},
        engine="webforge",
        target=f"https://operator:{secret}@127.0.0.1/",
        allowed_scope=None,
        job_id={"not": "a-job"},
        operator_id="operator with spaces",
    )

    assert denied.allowed is False
    assert denied.reason_code == "malformed_target"
    rendered = json.dumps(list_authorization_decisions(session), sort_keys=True)
    assert secret not in rendered
    assert session.query(AuthorizationDecisionModel).count() == 1
    session.close()


def test_authorization_database_preserves_caller_owned_parent_mode(tmp_path) -> None:
    import stat

    shared = tmp_path / "caller-owned"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    db_path = shared / "authorization.db"

    session = open_authorization_session(db_path)
    try:
        assert stat.S_IMODE(shared.stat().st_mode) == 0o755
        for artifact in (
            db_path,
            db_path.with_suffix(".db.schema.lock"),
            shared / "authorization.db-wal",
            shared / "authorization.db-shm",
        ):
            assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    finally:
        session.close()


def test_configured_authorization_database_path_does_not_resolve_symlink(
    tmp_path,
) -> None:
    import os

    victim = tmp_path / "victim.db"
    connection = sqlite3.connect(victim)
    connection.execute("CREATE TABLE victim_canary (value TEXT)")
    connection.commit()
    connection.close()
    victim.chmod(0o644)
    original = victim.read_bytes()
    destination = tmp_path / "authorization.db"
    destination.symlink_to(victim)

    selected = default_authorization_db_path(
        {"FORGE_AUTHORIZATION_DB": os.fspath(destination)}
    )
    assert selected == destination.absolute()
    assert selected.is_symlink()
    with pytest.raises(ValueError, match="database artifact is unavailable"):
        open_authorization_session(selected)
    assert victim.read_bytes() == original
    assert (victim.stat().st_mode & 0o777) == 0o644
