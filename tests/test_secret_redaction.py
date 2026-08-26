"""Central secret-redaction and protected-artifact regression tests."""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import stat
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import Any

import pytest

from common.action_authorization import (
    AuthorizationContext,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    issue_authorization,
    redact_authorization_value,
)
from common.config import BaseForgeConfig
from common.confirm_gate import ActionConfirmation
from common.db import (
    AuditLogModel,
    FindingModel,
    create_db,
    save_audit_log,
    save_finding,
)
from common.evidence import Evidence, save_http_evidence
from common.finding import Finding, Severity
from common.logger import JsonlFileHandler, get_logger
from common.dashboard.event_bus import Event, EventBus, EventType
from common.redaction import redact_exception, redaction_filter
from common.reporter import BaseReporter
from common.scope import Scope
from leak_intel.parsers.credential_tester import CredentialPair, CredentialTester
from netforge.core.cred_engine import CredEngine


CANARIES = {
    "password": "CANARY_PASSWORD_42",
    "bearer": "BEARER_CANARY_TOKEN_42",
    "api_key": "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB",
    "cookie": "SESSION_COOKIE_CANARY_42",
    "ntlm": "8846f7eaee8fb117ad06bdd830b7586c",
    "connection": "postgresql://dbuser:dbpass@example.test/db?token=querysecret",
    "private_key": (
        "-----BEGIN PRIVATE KEY-----\n"
        "PRIVATE_KEY_CANARY_42\n"
        "-----END PRIVATE KEY-----"
    ),
}


@dataclass
class SecretObject:
    username: str
    password: str


class ReprObject:
    def __repr__(self) -> str:
        return "ReprObject(token=CANARY_REPR_TOKEN_42)"


def _render(value: object) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def test_redaction_handles_nested_dataclasses_objects_headers_urls_and_multiline() -> None:
    original = {
        "nested": [
            SecretObject("operator", CANARIES["password"]),
            ReprObject(),
            {"headers": {"Authorization": f"Bearer {CANARIES['bearer']}"}},
        ],
        "url": CANARIES["connection"],
        "cookie_line": f"Cookie: session={CANARIES['cookie']}",
        "hash": CANARIES["ntlm"],
        "private_material": CANARIES["private_key"],
        "api_value": CANARIES["api_key"],
    }

    rendered = _render(redact_authorization_value(original))

    for canary in CANARIES.values():
        assert canary not in rendered
    assert "dbpass" not in rendered
    assert "querysecret" not in rendered
    assert "CANARY_REPR_TOKEN_42" not in rendered


def test_truncated_private_key_redacts_body_after_header() -> None:
    from common.redaction import redact_text

    truncated = "-----BEGIN PRIVATE KEY-----\nTRUNCATED_PRIVATE_KEY_CANARY_42"
    rendered = redact_text(truncated)

    assert "TRUNCATED_PRIVATE_KEY_CANARY_42" not in rendered
    assert rendered == "<redacted>"


def test_redacted_exception_respects_suppressed_context() -> None:
    outside_canary = "/private/outside/location/SUPPRESSED_CONTEXT_VALUE"
    try:
        try:
            raise RuntimeError(outside_canary)
        except RuntimeError:
            raise ValueError("source_root is unavailable") from None
    except ValueError as exc:
        rendered = redact_exception(exc)

    assert rendered == "source_root is unavailable"
    assert outside_canary not in rendered


def test_exception_chain_is_redacted() -> None:
    try:
        try:
            raise ValueError(f"password={CANARIES['password']}")
        except ValueError as exc:
            raise RuntimeError(f"Bearer {CANARIES['bearer']}") from exc
    except RuntimeError as exc:
        rendered = str(redact_authorization_value(exc))

    assert CANARIES["password"] not in rendered
    assert CANARIES["bearer"] not in rendered


def test_event_subscriber_failures_never_log_exception_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sync_canary = "Bearer EVENT_SYNC_EXCEPTION_CANARY_007"
    async_canary = "Bearer EVENT_ASYNC_EXCEPTION_CANARY_007"

    def fail_sync(_event: Event) -> None:
        raise RuntimeError(sync_canary)

    async def unused_async(_event: Event) -> None:
        return None

    class FailingLoop:
        @staticmethod
        def is_closed() -> bool:
            return False

        @staticmethod
        def call_soon_threadsafe(*_args: object) -> None:
            raise ValueError(async_canary)

    bus = EventBus(run_id="subscriber-failure-redaction")
    bus.subscribe(EventType.HEARTBEAT, fail_sync)
    bus.async_subscribe(EventType.HEARTBEAT, unused_async)
    bus._loop = FailingLoop()  # type: ignore[assignment]
    bus._running = True
    bus._queue.put(
        Event(
            event_type=EventType.HEARTBEAT,
            data={},
            source="fixture",
        )
    )
    bus._queue.put(None)

    caplog.set_level(logging.ERROR, logger="forge.dashboard.events")
    bus._dispatch_loop()

    assert "Subscriber callback failed on heartbeat" in caplog.text
    assert "Async subscriber callback failed on heartbeat" in caplog.text
    assert sync_canary not in caplog.text
    assert async_canary not in caplog.text


def test_async_event_subscriber_task_failure_is_observed_without_secret_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = "Bearer ASYNC_SUBSCRIBER_TASK_CANARY_007"
    derived_canaries = (
        "ASYNC_SUBSCRIBER_TASK_CANARY_007",
        "SUBSCRIBER_TASK_CANARY_007",
    )

    async def exercise() -> tuple[list[dict[str, object]], int, int, list[Event]]:
        loop = asyncio.get_running_loop()
        loop_failures: list[dict[str, object]] = []
        failing_callback_started = asyncio.Event()
        peer_callback_started = asyncio.Event()
        peer_calls = 0
        previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(
            lambda _loop, context: loop_failures.append(dict(context))
        )

        async def fail(_event: Event) -> None:
            failing_callback_started.set()
            raise RuntimeError(canary)

        async def succeed(_event: Event) -> None:
            nonlocal peer_calls
            peer_calls += 1
            peer_callback_started.set()

        bus = EventBus(run_id="async-subscriber-task-redaction")
        bus.async_subscribe(EventType.HEARTBEAT, fail)
        bus.async_subscribe(EventType.HEARTBEAT, succeed)
        bus.start(loop)
        try:
            bus.emit(
                Event(
                    event_type=EventType.HEARTBEAT,
                    data={},
                    source="fixture",
                )
            )
            await asyncio.wait_for(failing_callback_started.wait(), timeout=1.0)
            await asyncio.wait_for(peer_callback_started.wait(), timeout=1.0)
            for _ in range(4):
                await asyncio.sleep(0)
            event_count = bus.event_count
            history = bus.get_history(EventType.HEARTBEAT)
        finally:
            bus.stop()
            loop.set_exception_handler(previous_handler)
        return loop_failures, peer_calls, event_count, history

    caplog.set_level(logging.ERROR, logger="forge.dashboard.events")
    loop_failures, peer_calls, event_count, history = asyncio.run(exercise())

    assert loop_failures == []
    assert peer_calls == 1
    assert event_count == 1
    assert len(history) == 1
    assert history[0].event_type == EventType.HEARTBEAT
    fixed_message = "Async subscriber callback failed on heartbeat"
    assert caplog.messages.count(fixed_message) == 1
    assert canary not in caplog.text
    assert canary not in repr(loop_failures)
    for fragment in derived_canaries:
        assert fragment not in caplog.text
        assert fragment not in repr(loop_failures)
    assert "Task exception was never retrieved" not in caplog.text
    assert "was never awaited" not in caplog.text


def test_async_event_subscriber_task_creation_failure_closes_awaitable(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "Bearer ASYNC_TASK_CREATION_CANARY_007"

    class TrackedAwaitable:
        def __init__(self) -> None:
            self.closed = False

        def __await__(self):
            if False:
                yield None
            return None

        def close(self) -> None:
            self.closed = True

    awaitable = TrackedAwaitable()

    def callback(_event: Event) -> TrackedAwaitable:
        return awaitable

    def fail_task_creation(_awaitable: object) -> None:
        raise RuntimeError(canary)

    monkeypatch.setattr(asyncio, "ensure_future", fail_task_creation)
    caplog.set_level(logging.ERROR, logger="forge.dashboard.events")
    bus = EventBus(run_id="async-task-creation-redaction")
    bus._schedule_async_subscriber(
        callback,  # type: ignore[arg-type]
        Event(event_type=EventType.HEARTBEAT, data={}, source="fixture"),
    )

    assert awaitable.closed is True
    assert caplog.messages.count(
        "Async subscriber callback failed on heartbeat"
    ) == 1
    assert canary not in caplog.text
    assert "ASYNC_TASK_CREATION_CANARY_007" not in caplog.text


def test_authorization_identifier_is_preserved_only_in_bound_identifier_fields() -> None:
    from common.redaction import redact_text, redact_value

    job_id = "job-2747325f3f684457b96ec4a6fcd6235d"
    run_id = "run-0123456789abcdef0123456789abcdef"
    authorization_id = "authz-16cc68fe2e954f5e99641c721a6372a8"
    assert redact_text(job_id) == job_id
    assert redact_text(run_id) == run_id
    assert redact_value(
        {"high_risk_child_decision_id": authorization_id}
    ) == {"high_risk_child_decision_id": authorization_id}
    assert redact_value(
        {"authorization_decision_id": authorization_id}
    ) == {"authorization_decision_id": authorization_id}
    assert redact_text(authorization_id) == "authz-<redacted>"
    assert redact_value({"detail": authorization_id}) == {"detail": "authz-<redacted>"}
    assert CANARIES["ntlm"] not in redact_text(CANARIES["ntlm"])


def test_authorization_prompt_does_not_render_target_query_secrets(
    monkeypatch,
    capsys,
) -> None:
    from common.auth_prompt import require_authorization

    canary = "CANARY_PROMPT_TOKEN_001"
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    require_authorization(
        f"https://127.0.0.1/path?token={canary}",
        "WebForge",
    )

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert canary not in rendered
    assert "127.0.0.1" in rendered


def test_evidence_serialization_and_artifacts_redact_before_write(tmp_path: Path) -> None:
    evidence = Evidence(
        request_raw=f"Authorization: Bearer {CANARIES['bearer']}",
        response_raw=f"Set-Cookie: session={CANARIES['cookie']}",
        extra={"password": CANARIES["password"]},
    )
    serialized = _render(evidence.to_dict())
    assert all(canary not in serialized for canary in CANARIES.values())

    saved = save_http_evidence(
        f"Authorization: Bearer {CANARIES['bearer']}",
        f"password={CANARIES['password']}",
        tmp_path / "evidence",
        "finding-1",
    )
    request_path = tmp_path / "evidence" / "finding-1_request.txt"
    response_path = tmp_path / "evidence" / "finding-1_response.txt"
    combined = request_path.read_text() + response_path.read_text() + _render(saved.to_dict())
    assert CANARIES["bearer"] not in combined
    assert CANARIES["password"] not in combined
    assert stat.S_IMODE(request_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(response_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(request_path.parent.stat().st_mode) == 0o700


def test_credential_export_contains_reference_not_ciphertext_or_plaintext(tmp_path: Path) -> None:
    engine = CredEngine()
    engine.add(
        "127.0.0.1",
        "ssh",
        "operator",
        password=CANARIES["password"],
        nt_hash=CANARIES["ntlm"],
        source="fake-fixture",
    )
    path = tmp_path / "protected" / "credential_references.json"

    rendered = engine.export_json(path)

    assert CANARIES["password"] not in rendered
    assert CANARIES["ntlm"] not in rendered
    assert "enc_password" not in rendered
    assert "credential_reference" in rendered
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    try:
        engine.export_plaintext(tmp_path / "plaintext.json")
    except RuntimeError as exc:
        assert "disabled" in str(exc)
    else:
        raise AssertionError("plaintext credential export must remain disabled")


def _credential_tester(tmp_path: Path, policy: object | None = None) -> CredentialTester:
    cfg = BaseForgeConfig(target="https://example.test")
    run_id = f"run-{uuid.uuid4().hex}"
    cfg.extra["job_id"] = f"job-{run_id}"
    cfg.extra["authorization_runtime"] = {
        "tenant_id": "tenant-leak-fixture",
        "engagement_id": "engagement-leak-fixture",
        "run_id": run_id,
        "operator_id": "operator-leak-fixture",
        "operator_role": OperatorRole.OPERATOR.value,
        "scope_policy_version": "scope-policy-v1",
        "safety_mode": SafetyMode.CREDENTIAL.value,
    }
    if policy is not None:
        cfg.extra["credential_validation_policy"] = policy
    return CredentialTester(
        cfg,
        Scope(["example.test"]),
        create_db(tmp_path / "leak-intel.db"),
        tmp_path / "results",
        run_id=run_id,
    )


def _authorize_credential_validation(tester: CredentialTester, reference) -> str:
    """Issue and consume the exact canonical fixture authorization."""
    now = datetime.now(timezone.utc)
    context = AuthorizationContext(
        tenant_id="tenant-leak-fixture",
        engagement_id="engagement-leak-fixture",
        run_id=tester.run_id,
        job_id=f"job-{tester.run_id}",
        operator_id="operator-leak-fixture",
        operator_role=OperatorRole.OPERATOR,
        action_kind="credential.validate",
        engine="leak_intel",
        module_id=f"{tester.NAME}:{reference.provider}",
        requested_target=tester.config.target,
        resolved_target=tester.config.target,
        allowed_scope=tester.scope.targets,
        excluded_scope=tester.scope.excluded,
        scope_policy_version="scope-policy-v1",
        safety_mode=SafetyMode.CREDENTIAL,
        credential_approval_required=True,
        network_escalation_approval_required=False,
        high_risk_approval_required=False,
        confirmation_method=ConfirmationMethod.CLI_PROMPT,
        confirmed_by="operator-leak-fixture",
        credential_reference=reference.value,
    )
    confirmation = ActionConfirmation.create(
        job_id=context.job_id,
        target=context.resolved_target,
        engine=context.engine,
        action=context.action_kind,
        issued_at=now,
    )
    issued = issue_authorization(
        session=tester.db,
        context=context,
        confirmation=confirmation,
        now=now,
    )
    assert issued.allowed is True
    tester.config.extra["credential_validation_authorization"] = issued.envelope
    return issued.envelope.decision_id


def test_leak_validation_makes_zero_provider_calls_by_default(tmp_path: Path) -> None:
    calls: list[object] = []
    tester = _credential_tester(tmp_path)
    tester.config.extra["credential_validation_fake_provider"] = lambda **kwargs: calls.append(kwargs)
    tester.add_credential(CredentialPair(username="operator", password=CANARIES["password"]))

    result = asyncio.run(tester._run_impl())

    assert result.skipped is True
    assert calls == []


def test_leak_validation_requires_every_authorization_component(tmp_path: Path) -> None:
    calls: list[object] = []
    fields = (
        "enabled", "provider", "target", "allowed_scope",
        "credential_reference", "credential_use_approved",
        "credential_use_approval_id", "audit_enabled", "max_attempts",
        "rate_per_second",
    )
    for missing in fields:
        tester = _credential_tester(tmp_path)
        reference = tester.add_credential(
            CredentialPair(password=CANARIES["password"])
        )
        policy = {
            "enabled": True,
            "provider": "fake-safe-provider",
            "target": "example.test",
            "allowed_scope": ["example.test"],
            "credential_reference": reference.value,
            "credential_use_approved": True,
            "credential_use_approval_id": "approval-fixture",
            "audit_enabled": True,
            "max_attempts": 1,
            "rate_per_second": 1,
        }
        del policy[missing]
        tester.config.extra["credential_validation_policy"] = policy
        tester.config.extra["safe_credential_validation_providers"] = ["fake-safe-provider"]
        tester.config.extra["credential_validation_fake_provider"] = lambda **kwargs: calls.append(kwargs)
        result = asyncio.run(tester._run_impl())
        assert result.skipped is True
    assert calls == []


def test_authorized_fake_provider_is_bounded_and_audit_is_redacted(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    async def fake_provider(**kwargs):
        calls.append(kwargs)
        return {"success": False, "detail": f"password={CANARIES['password']}"}

    tester = _credential_tester(tmp_path)
    reference = tester.add_credential(
        CredentialPair(username="first", password=CANARIES["password"])
    )
    tester.add_credential(
        CredentialPair(username="second", password="SECOND_PASSWORD_CANARY")
    )
    approval_id = _authorize_credential_validation(tester, reference)
    policy = {
        "enabled": True,
        "provider": reference.provider,
        "target": tester.config.target,
        "allowed_scope": ["example.test"],
        "credential_reference": reference.value,
        "credential_use_approved": True,
        "credential_use_approval_id": approval_id,
        "audit_enabled": True,
        "max_attempts": 1,
        "rate_per_second": 1,
    }
    tester.config.extra["credential_validation_policy"] = policy
    tester.config.extra["safe_credential_validation_providers"] = [reference.provider]
    tester.config.extra["credential_validation_fake_provider"] = fake_provider

    result = asyncio.run(tester._run_impl())

    assert result.skipped is False
    assert len(calls) == 1
    assert CANARIES["password"] not in _render(tester._audit_log)
    assert tester._audit_log[0]["credential_reference"] == reference.value


def test_leak_provider_exception_wipes_transient_credentials_and_audit(tmp_path: Path) -> None:
    captured: list[dict[str, str]] = []

    async def failing_provider(**kwargs):
        credential = kwargs["credential"]
        captured.append(credential)
        raise RuntimeError(f"password={CANARIES['password']}")

    tester = _credential_tester(tmp_path)
    reference = tester.add_credential(
        CredentialPair(username="operator", password=CANARIES["password"])
    )
    approval_id = _authorize_credential_validation(tester, reference)
    tester.config.extra["credential_validation_policy"] = {
        "enabled": True,
        "provider": reference.provider,
        "target": tester.config.target,
        "allowed_scope": ["example.test"],
        "credential_reference": reference.value,
        "credential_use_approved": True,
        "credential_use_approval_id": approval_id,
        "audit_enabled": True,
        "max_attempts": 1,
        "rate_per_second": 1,
    }
    tester.config.extra["safe_credential_validation_providers"] = [
        reference.provider
    ]
    tester.config.extra["credential_validation_fake_provider"] = failing_provider

    result = asyncio.run(tester._run_impl())

    assert result.skipped is False
    assert captured == [{}]
    assert CANARIES["password"] not in _render(tester._audit_log)


def test_leak_validation_denies_out_of_scope_target_before_provider_call(
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []
    tester = _credential_tester(tmp_path)
    reference = tester.add_credential(CredentialPair(password="opaque-fixture-value"))
    approval_id = _authorize_credential_validation(tester, reference)
    tester.config.extra["credential_validation_policy"] = {
        "enabled": True,
        "provider": reference.provider,
        "target": "https://outside.test",
        "allowed_scope": ["outside.test"],
        "credential_reference": reference.value,
        "credential_use_approved": True,
        "credential_use_approval_id": approval_id,
        "audit_enabled": True,
        "max_attempts": 1,
        "rate_per_second": 1,
    }
    tester.config.extra["safe_credential_validation_providers"] = [
        reference.provider
    ]
    tester.config.extra["credential_validation_fake_provider"] = (
        lambda **kwargs: calls.append(kwargs)
    )

    result = asyncio.run(tester._run_impl())

    assert result.skipped is True
    assert calls == []
    assert tester._secret_provider.resolve_calls == 0


@pytest.mark.parametrize(
    ("field", "other_value"),
    [
        ("tenant_id", "tenant-other"),
        ("engagement_id", "engagement-other"),
        ("run_id", "run-other"),
        ("job_id", "job-other"),
        ("operator_id", "operator-other"),
        ("operator_role", OperatorRole.ADMIN.value),
        ("scope_policy_version", "scope-policy-other"),
        ("safety_mode", SafetyMode.ACTIVE.value),
    ],
)
def test_leak_validation_binds_envelope_to_current_module_context(
    tmp_path: Path,
    field: str,
    other_value: str,
) -> None:
    calls: list[dict[str, object]] = []
    tester = _credential_tester(tmp_path)
    reference = tester.add_credential(CredentialPair(password="opaque-fixture-value"))
    approval_id = _authorize_credential_validation(tester, reference)
    if field == "job_id":
        tester.config.extra["job_id"] = other_value
    else:
        runtime = dict(tester.config.extra["authorization_runtime"])
        runtime[field] = other_value
        tester.config.extra["authorization_runtime"] = runtime
    tester.config.extra["credential_validation_policy"] = {
        "enabled": True,
        "provider": reference.provider,
        "target": tester.config.target,
        "allowed_scope": list(tester.scope.targets),
        "credential_reference": reference.value,
        "credential_use_approved": True,
        "credential_use_approval_id": approval_id,
        "audit_enabled": True,
        "max_attempts": 1,
        "rate_per_second": 1,
    }
    tester.config.extra["safe_credential_validation_providers"] = [
        reference.provider
    ]
    tester.config.extra["credential_validation_fake_provider"] = (
        lambda **kwargs: calls.append(kwargs)
    )

    result = asyncio.run(tester._run_impl())

    assert result.skipped is True
    assert calls == []
    assert tester._secret_provider.resolve_calls == 0


def test_leak_validation_rejects_valid_other_tenant_job_run_envelope(
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []
    tester = _credential_tester(tmp_path)
    reference = tester.add_credential(CredentialPair(password="opaque-fixture-value"))
    now = datetime.now(timezone.utc)
    other_context = AuthorizationContext(
        tenant_id="tenant-other",
        engagement_id="engagement-other",
        run_id=tester.run_id,
        job_id="job-other",
        operator_id="operator-other",
        operator_role=OperatorRole.OPERATOR,
        action_kind="credential.validate",
        engine="leak_intel",
        module_id=f"{tester.NAME}:{reference.provider}",
        requested_target=tester.config.target,
        resolved_target=tester.config.target,
        allowed_scope=tester.scope.targets,
        excluded_scope=tester.scope.excluded,
        scope_policy_version="scope-policy-v1",
        safety_mode=SafetyMode.CREDENTIAL,
        credential_approval_required=True,
        confirmation_method=ConfirmationMethod.CLI_PROMPT,
        confirmed_by="operator-other",
        credential_reference=reference.value,
    )
    issued = issue_authorization(
        session=tester.db,
        context=other_context,
        confirmation=ActionConfirmation.create(
            job_id=other_context.job_id,
            target=other_context.resolved_target,
            engine=other_context.engine,
            action=other_context.action_kind,
            issued_at=now,
        ),
        now=now,
    )
    assert issued.allowed is True
    tester.config.extra["job_id"] = other_context.job_id
    tester.config.extra["authorization_runtime"] = {
        "tenant_id": other_context.tenant_id,
        "engagement_id": other_context.engagement_id,
        "run_id": tester.run_id,
        "operator_id": other_context.operator_id,
        "operator_role": OperatorRole.OPERATOR.value,
        "scope_policy_version": "scope-policy-v1",
        "safety_mode": SafetyMode.CREDENTIAL.value,
    }
    tester.config.extra["credential_validation_authorization"] = issued.envelope
    tester.config.extra["credential_validation_policy"] = {
        "enabled": True,
        "provider": reference.provider,
        "target": tester.config.target,
        "allowed_scope": list(tester.scope.targets),
        "credential_reference": reference.value,
        "credential_use_approved": True,
        "credential_use_approval_id": issued.envelope.decision_id,
        "audit_enabled": True,
        "max_attempts": 1,
        "rate_per_second": 1,
    }
    tester.config.extra["safe_credential_validation_providers"] = [
        reference.provider
    ]
    tester.config.extra["credential_validation_fake_provider"] = (
        lambda **kwargs: calls.append(kwargs)
    )

    result = asyncio.run(tester._run_impl())

    assert result.skipped is True
    assert calls == []
    assert tester._secret_provider.resolve_calls == 0


def test_leak_provider_secret_echo_and_derived_fragments_are_removed_everywhere(
    tmp_path: Path,
) -> None:
    secret = "opaquef7b1bfe95f364fc48fda270b76a7d998"
    fragment = secret[:10]
    tester = _credential_tester(tmp_path)
    reference = tester.add_credential(CredentialPair(password=secret))
    approval_id = _authorize_credential_validation(tester, reference)

    async def echo_provider(**_kwargs):
        return {"success": False, "detail": f"{secret} derived={fragment}"}

    tester.config.extra["credential_validation_policy"] = {
        "enabled": True,
        "provider": reference.provider,
        "target": tester.config.target,
        "allowed_scope": ["example.test"],
        "credential_reference": reference.value,
        "credential_use_approved": True,
        "credential_use_approval_id": approval_id,
        "audit_enabled": True,
        "max_attempts": 1,
        "rate_per_second": 1,
    }
    tester.config.extra["safe_credential_validation_providers"] = [
        reference.provider
    ]
    tester.config.extra["credential_validation_fake_provider"] = echo_provider

    result = asyncio.run(tester._run_impl())
    persisted_audit = tester.db.query(AuditLogModel).all()

    assert result.skipped is False
    assert secret not in _render(tester._results)
    assert fragment not in _render(tester._results)
    assert secret not in _render(tester._audit_log)
    assert fragment not in _render(tester._audit_log)
    assert secret not in _render(
        [
            {
                "action": row.action,
                "object_id": row.object_id,
                "detail": row.detail,
            }
            for row in persisted_audit
        ]
    )
    assert fragment not in _render(
        [
            {
                "action": row.action,
                "object_id": row.object_id,
                "detail": row.detail,
            }
            for row in persisted_audit
        ]
    )
    assert tester._secret_provider.resolve_calls == 1


def test_bruteforce_logs_and_raw_findings_use_only_protected_references(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from netforge.modules.bruteforce.cred_spray import CredSpray
    from netforge.modules.bruteforce.hydra_wrap import HydraWrap

    secret = "OPAQUE_BRUTE_SECRET_7f62c851"
    cfg = BaseForgeConfig(target="127.0.0.1")
    cfg.extra.update(
        {
            "cred_engine": CredEngine(),
            "live_hosts": ["127.0.0.1"],
            "spray_users": ["operator"],
            "spray_passwords": [secret],
            "spray_delay_seconds": 0,
            "allow_legacy_compat": True,
        }
    )
    scope = Scope(["127.0.0.1"])
    spray = CredSpray(
        cfg,
        scope,
        create_db(tmp_path / "spray.db"),
        tmp_path / "spray-results",
    )
    hydra = HydraWrap(
        cfg,
        scope,
        create_db(tmp_path / "hydra.db"),
        tmp_path / "hydra-results",
    )

    async def no_match(*_args, **_kwargs):
        return False

    monkeypatch.setattr(spray, "_try_ssh", no_match)
    monkeypatch.setattr(spray, "_try_smb", no_match)
    with caplog.at_level(logging.INFO):
        asyncio.run(spray.run())

    spray._report_success("127.0.0.1", 22, "ssh", "operator", secret)
    hydra._report_success("127.0.0.1", 22, "ssh", "operator", secret)

    rendered_log = caplog.text
    assert secret not in rendered_log
    assert secret[:3] not in rendered_log
    for module in (spray, hydra):
        assert len(module.findings) == 1
        raw_finding = repr(module.findings[0])
        serialized_payload = module.findings[0].to_dict()
        serialized = _render(serialized_payload)
        for rendered in (raw_finding, serialized):
            assert secret not in rendered
            assert secret[:8] not in rendered
            assert secret[-4:] not in rendered
        # The in-memory finding retains the opaque protected reference, while
        # ordinary evidence serialization intentionally carries only capture
        # shape/state and never mutable credential metadata or raw inputs.
        assert "credential_reference" in raw_finding
        assert "cred:sha256:" in raw_finding
        evidence_payload = serialized_payload["evidence"]
        assert "credential_reference" not in evidence_payload
        assert "request_raw" not in evidence_payload
        assert "response_raw" not in evidence_payload
        assert "Credential reference:" in serialized


def test_bruteforce_metadata_cannot_disclose_a_password_fragment(
    tmp_path: Path,
) -> None:
    from netforge.modules.bruteforce.cred_spray import CredSpray
    from netforge.modules.bruteforce.hydra_wrap import HydraWrap
    from netforge.modules.bruteforce.native_brute import NativeBrute

    secret = "z4n8c2v6b0m5-long-password"
    fragment = secret[:8]
    config = BaseForgeConfig(target="127.0.0.1")
    config.extra["allow_legacy_compat"] = True
    scope = Scope(["127.0.0.1"])
    modules = (
        CredSpray(
            config,
            scope,
            create_db(tmp_path / "spray-fragment.db"),
            tmp_path / "spray-fragment-results",
        ),
        HydraWrap(
            config,
            scope,
            create_db(tmp_path / "hydra-fragment.db"),
            tmp_path / "hydra-fragment-results",
        ),
        NativeBrute(
            config,
            scope,
            create_db(tmp_path / "native-fragment.db"),
            tmp_path / "native-fragment-results",
        ),
    )

    modules[0]._report_success("127.0.0.1", 22, "ssh", fragment, secret)
    modules[1]._report_success("127.0.0.1", 22, "ssh", fragment, secret)
    modules[2]._report_hit("127.0.0.1", 22, "ssh", fragment, secret)

    for module in modules:
        rendered = repr(module.findings[0]) + _render(module.findings[0].to_dict())
        assert fragment not in rendered
        assert secret not in rendered
        assert "credential_reference" in rendered


def test_logs_events_findings_database_audit_reports_and_exports_redact_before_boundary(
    tmp_path: Path,
) -> None:
    secret = CANARIES["password"]
    bearer = CANARIES["bearer"]
    cookie = CANARIES["cookie"]

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("forge.wp007.boundary-test")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.info(
        "password=%s Authorization: Bearer %s Cookie: session=%s",
        secret,
        bearer,
        cookie,
    )
    assert secret not in stream.getvalue()
    assert bearer not in stream.getvalue()
    assert cookie not in stream.getvalue()

    event = Event(
        event_type=EventType.FINDING_NEW,
        source=f"password={secret}",
        data={
            "headers": {"Authorization": f"Bearer {bearer}"},
            "cookie": cookie,
        },
    )
    assert secret not in event.to_json()
    assert bearer not in event.to_json()
    assert cookie not in event.to_json()

    finding = Finding(
        title=f"password={secret}",
        severity=Severity.HIGH,
        target="https://example.test",
        module="fixture",
        description=f"Authorization: Bearer {bearer}",
        reproduction_steps=[f"Cookie: session={cookie}"],
        remediation="Rotate the affected fixture value.",
        references=[],
        evidence=Evidence(
            request_raw=f"Authorization: Bearer {bearer}",
            response_raw=f"Set-Cookie: session={cookie}",
            extra={"password": secret},
        ),
    )
    finding_dict = finding.to_dict()
    assert secret not in _render(finding_dict)
    assert bearer not in _render(finding_dict)
    assert cookie not in _render(finding_dict)

    db_path = tmp_path / "ordinary.db"
    session = create_db(db_path)
    save_finding(
        session,
        finding_dict,
        run_id="run-wp007",
        allow_legacy_compat=True,
    )
    save_audit_log(
        session,
        {
            "action": "fixture.audit",
            "object_id": f"password={secret}",
            "detail": {
                "Authorization": f"Bearer {bearer}",
                "cookie": cookie,
            },
        },
    )
    persisted = repr(session.query(FindingModel).all()) + repr(
        session.query(AuditLogModel).all()
    )
    persisted += "".join(
        str(getattr(row, column.name, ""))
        for row in session.query(FindingModel).all()
        for column in FindingModel.__table__.columns
    )
    persisted += "".join(
        str(getattr(row, column.name, ""))
        for row in session.query(AuditLogModel).all()
        for column in AuditLogModel.__table__.columns
    )
    session.close()
    assert secret not in persisted
    assert bearer not in persisted
    assert cookie not in persisted

    report_dir = tmp_path / "reports"
    reporter = BaseReporter(
        findings=[{
            **finding_dict,
            "title": f"password={secret}",
            "description": f"Bearer {bearer}",
            "reproduction_steps": [f"Cookie: session={cookie}"],
        }],
        results_dir=report_dir,
        engagement=f"password={secret}",
        target=f"https://operator:{secret}@example.test/?token={bearer}",
        formats=["json", "csv", "html"],
    )
    paths = reporter.generate_all()
    rendered_reports = "".join(
        Path(path).read_text(encoding="utf-8", errors="replace")
        for path in paths.values()
        if Path(path).suffix.lower() != ".pdf"
    )
    assert secret not in rendered_reports
    assert bearer not in rendered_reports
    assert cookie not in rendered_reports
    for path in paths.values():
        assert stat.S_IMODE(Path(path).stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "route",
    ("late_source", "propagated_root", "direct_root", "last_resort"),
)
def test_unfiltered_logging_routes_redact_before_handler_dispatch(route: str) -> None:
    """Every stdlib dispatch route is protected without handler-local filters."""
    secret = CANARIES["password"]
    bearer = CANARIES["bearer"]
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s|%(credential_context)s"))
    assert handler.filters == []

    root = logging.getLogger()
    root_handlers = list(root.handlers)
    root_level = root.level
    prior_last_resort = logging.lastResort
    logger = logging.getLogger(f"forge.wp007.raw-dispatch.{route}")
    logger_handlers = list(logger.handlers)
    logger_level = logger.level
    logger_propagate = logger.propagate
    try:
        root.setLevel(logging.INFO)
        logger.setLevel(logging.INFO)
        extra = {
            "credential_context": {
                "password": secret,
                "nested": {"Authorization": f"Bearer {bearer}"},
            }
        }
        if route == "late_source":
            configured = get_logger(logger.name, quiet=True)
            configured.handlers = [handler]
            configured.propagate = False
            configured.info("password=%s bearer=%s", secret, bearer, extra=extra)
        elif route == "propagated_root":
            root.handlers = [handler]
            logger.handlers = []
            logger.propagate = True
            logger.info("password=%s bearer=%s", secret, bearer, extra=extra)
        elif route == "direct_root":
            root.handlers = [handler]
            root.info("password=%s bearer=%s", secret, bearer, extra=extra)
        else:
            root.handlers = []
            logger.handlers = []
            logger.propagate = True
            logging.lastResort = handler
            logger.info("password=%s bearer=%s", secret, bearer, extra=extra)

        rendered = stream.getvalue()
        assert secret not in rendered
        assert bearer not in rendered
        assert "<redacted>" in rendered
        assert handler.filters == []
    finally:
        logger.handlers = logger_handlers
        logger.setLevel(logger_level)
        logger.propagate = logger_propagate
        root.handlers = root_handlers
        root.setLevel(root_level)
        logging.lastResort = prior_last_resort
        handler.close()


def test_stealth_log_redacts_before_sqlite_and_legacy_export_under_open_umask(
    tmp_path: Path,
) -> None:
    import sqlite3

    import netforge.core.stealth_log as stealth

    secret = CANARIES["password"]
    bearer = CANARIES["bearer"]
    db_path = tmp_path / "private" / "nested" / "stealth.db"
    export_path = tmp_path / "clear" / "nested" / "stealth.json"
    key = stealth._generate_session_key()

    previous_umask = os.umask(0o002)
    try:
        handler = stealth.StealthLogHandler(db_path, key)
    finally:
        os.umask(previous_umask)
    retained_key_alias = handler._key
    record = logging.LogRecord(
        name="forge.netforge.fixture",
        level=logging.WARNING,
        pathname="",
        lineno=0,
        msg="password=%s Authorization: Bearer %s",
        args=(secret, bearer),
        exc_info=None,
    )
    record.credential_context = {
        "password": secret,
        "nested": {"Authorization": f"Bearer {bearer}"},
    }
    # Direct emit bypasses both Logger.callHandlers and Handler.handle.  The
    # persistence boundary must still protect the complete entry itself.
    handler.emit(record)
    handler.flush()

    connection = sqlite3.connect(str(db_path))
    encrypted = connection.execute(
        "SELECT payload FROM stealth_log ORDER BY id LIMIT 1"
    ).fetchone()[0]
    stored_plaintext = stealth._decrypt(encrypted, key)
    assert secret not in stored_plaintext
    assert bearer not in stored_plaintext
    handler.close()
    assert retained_key_alias == bytearray()

    # A pre-hardening row is deliberately encrypted without redaction.  Dumping
    # must reapply the policy before returning or writing it.
    legacy = json.dumps(
        {
            "ts": "fixture",
            "level": "WARNING",
            "message": f"password={secret}",
            "extra": {"Authorization": f"Bearer {bearer}"},
        }
    )
    connection.execute(
        "INSERT INTO stealth_log (ts, level, payload) VALUES (?, ?, ?)",
        ("fixture", "WARNING", stealth._encrypt(legacy, key)),
    )
    connection.commit()
    connection.close()

    previous_umask = os.umask(0o002)
    try:
        records = stealth.dump_stealth_log(db_path, key, output_path=export_path)
    finally:
        os.umask(previous_umask)

    rendered = repr(records) + export_path.read_text(encoding="utf-8")
    assert secret not in rendered
    assert bearer not in rendered
    assert stat.S_IMODE((tmp_path / "private").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "private" / "nested").stat().st_mode) == 0o700
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "clear").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "clear" / "nested").stat().st_mode) == 0o700
    assert stat.S_IMODE(export_path.stat().st_mode) == 0o600
    assert key == bytearray()


def test_stealth_setup_tightens_preexisting_results_and_pcaps_before_db(
    tmp_path: Path,
) -> None:
    import netforge.core.stealth_log as stealth
    from netforge.netforge import setup_results

    results_dir = tmp_path / "existing-results"
    pcaps_dir = results_dir / "pcaps"
    previous_umask = os.umask(0o002)
    try:
        results_dir.mkdir(mode=0o777)
        pcaps_dir.mkdir(mode=0o777)
        assert stat.S_IMODE(results_dir.stat().st_mode) == 0o775
        assert stat.S_IMODE(pcaps_dir.stat().st_mode) == 0o775

        prepared = setup_results("fixture", "fixture", str(results_dir))
        key = stealth.install_stealth_logging(prepared)
    finally:
        os.umask(previous_umask)

    try:
        assert prepared == results_dir
        assert stat.S_IMODE(results_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(pcaps_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE((results_dir / "stealth.db").stat().st_mode) == 0o600
    finally:
        stealth.finalize_stealth_logging(results_dir / "stealth.db")
    assert key == bytearray()


def test_netforge_dry_run_and_result_names_do_not_retain_target_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import argparse

    import netforge.netforge as netforge

    secret = "CANARY_NETFORGE_RESULTS_SECRET_42"
    target = f"https://operator:{secret}@fixture.invalid/admin?token={secret}"
    cfg = BaseForgeConfig(target=target)
    args = argparse.Namespace(
        modules=None,
        skip_modules="",
        mode="external",
        red_team=False,
    )

    plan = asyncio.run(netforge.dry_run_plan(cfg, args))
    assert secret not in repr(plan)
    assert target not in repr(plan)
    assert plan["plan"]["target"] == "<invalid-target>"

    monkeypatch.setattr(netforge, "__file__", str(tmp_path / "netforge.py"))
    previous_umask = os.umask(0o002)
    try:
        results_dir = netforge.setup_results(
            f"../../token={secret}",
            target,
            None,
        )
    finally:
        os.umask(previous_umask)

    assert results_dir.is_relative_to(tmp_path / "results")
    assert secret not in str(results_dir)
    assert ".." not in results_dir.name
    assert stat.S_IMODE(results_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((results_dir / "pcaps").stat().st_mode) == 0o700


def _freeze_netforge_result_namespace(
    monkeypatch: pytest.MonkeyPatch,
    netforge: Any,
) -> None:
    """Force one timestamp and deterministic unique suffixes for collision tests."""

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:
            fixed = cls(2026, 8, 2, 12, 34, 56, tzinfo=timezone.utc)
            return fixed if tz is not None else fixed.replace(tzinfo=None)

    suffix_lock = threading.Lock()
    suffix_number = 0

    def deterministic_uuid4() -> uuid.UUID:
        nonlocal suffix_number
        with suffix_lock:
            suffix_number += 1
            value = suffix_number
        return uuid.UUID(hex=f"{value:08x}" + "0" * 24)

    monkeypatch.setattr(netforge, "datetime", FixedDateTime)
    monkeypatch.setattr(netforge.uuid, "uuid4", deterministic_uuid4)


def test_netforge_same_second_result_directories_are_unique_sequentially(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netforge.netforge as netforge

    monkeypatch.setattr(netforge, "__file__", str(tmp_path / "netforge.py"))
    _freeze_netforge_result_namespace(monkeypatch, netforge)

    first = netforge.setup_results("fixture", "fixture", None)
    second = netforge.setup_results("fixture", "fixture", None)

    base_name = "fixture_fixture_20260802_123456"
    assert first.name == base_name
    assert second.name == f"{base_name}_00000001"
    assert first != second
    assert (first.stat().st_dev, first.stat().st_ino) != (
        second.stat().st_dev,
        second.stat().st_ino,
    )
    for path in (first, second):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
        assert stat.S_IMODE((path / "pcaps").stat().st_mode) == 0o700


def test_netforge_same_second_result_directories_are_unique_concurrently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netforge.netforge as netforge

    monkeypatch.setattr(netforge, "__file__", str(tmp_path / "netforge.py"))
    _freeze_netforge_result_namespace(monkeypatch, netforge)
    worker_count = 8
    start = threading.Barrier(worker_count)
    allocated: list[Path | None] = [None] * worker_count

    def allocate(index: int) -> None:
        start.wait(timeout=10)
        path = netforge.setup_results("fixture", "fixture", None)
        (path / f"worker-{index}.marker").write_text("isolated\n", encoding="utf-8")
        allocated[index] = path

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(allocate, index) for index in range(worker_count)]
        for future in futures:
            future.result(timeout=15)

    paths = [path for path in allocated if path is not None]
    assert len(paths) == worker_count
    assert len(set(paths)) == worker_count
    assert (
        len({(path.stat().st_dev, path.stat().st_ino) for path in paths})
        == worker_count
    )
    for index, path in enumerate(allocated):
        assert path is not None
        assert {marker.name for marker in path.glob("*.marker")} == {
            f"worker-{index}.marker"
        }
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
        assert stat.S_IMODE((path / "pcaps").stat().st_mode) == 0o700


def test_stealth_corrupt_row_metadata_is_redacted_before_return(
    tmp_path: Path,
) -> None:
    import sqlite3

    import netforge.core.stealth_log as stealth

    db_path = tmp_path / "corrupt" / "stealth.db"
    key = stealth._generate_session_key()
    handler = stealth.StealthLogHandler(db_path, key)
    handler.close()
    secret = CANARIES["password"]
    metadata = f"password={secret}"
    connection = sqlite3.connect(str(db_path))
    connection.execute(
        "INSERT INTO stealth_log (ts, level, payload) VALUES (?, ?, ?)",
        (metadata, metadata, "not-a-fernet-token"),
    )
    connection.commit()
    connection.close()

    records = stealth.dump_stealth_log(db_path, key)

    assert secret not in repr(records)
    assert metadata not in repr(records)
    assert records[-1]["ts"] == "password=<redacted>"
    assert records[-1]["level"] == "password=<redacted>"
    assert key == bytearray()


def test_installed_stealth_log_flushes_tail_once_detaches_and_wipes_key(
    tmp_path: Path,
) -> None:
    import netforge.core.stealth_log as stealth

    results_dir = tmp_path / "installed" / "session"
    db_path = results_dir / "stealth.db"
    export_path = results_dir / "tail.json"
    key = stealth.install_stealth_logging(results_dir)
    root = logging.getLogger()
    handlers = [
        handler
        for handler in root.handlers
        if isinstance(handler, stealth.StealthLogHandler)
    ]
    assert len(handlers) == 1
    handler = handlers[0]
    retained_key_alias = handler._key
    logger = logging.getLogger("forge.netforge.tail-fixture")
    assert handler not in logger.handlers
    try:
        logger.warning("tail marker password=%s", CANARIES["password"])
        records = stealth.dump_stealth_log(
            db_path,
            key,
            output_path=export_path,
        )
    finally:
        stealth.finalize_stealth_logging(db_path)

    tail = [record for record in records if "tail marker" in str(record.get("message"))]
    assert len(tail) == 1
    assert CANARIES["password"] not in repr(records)
    assert retained_key_alias == bytearray()
    assert key == bytearray()
    assert handler not in root.handlers
    assert stat.S_IMODE(results_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(export_path.stat().st_mode) == 0o600


def test_netforge_exceptional_lifecycle_finalizes_active_stealth_session(
    tmp_path: Path,
) -> None:
    import netforge.core.stealth_log as stealth
    from netforge.netforge import _NetForgeResourceLifecycle

    results_dir = tmp_path / "lifecycle" / "session"
    db_path = results_dir / "stealth.db"
    key = stealth.install_stealth_logging(results_dir)
    root = logging.getLogger()
    handler = next(
        item for item in root.handlers if isinstance(item, stealth.StealthLogHandler)
    )
    retained_key_alias = handler._key
    lifecycle = _NetForgeResourceLifecycle(results_dir)
    lifecycle.stealth_db_path = db_path
    lifecycle.stealth_session_key = key

    class FailingTransport:
        async def close_all(self) -> None:
            raise RuntimeError("CANARY_STEALTH_LIFECYCLE_FAILURE")

    lifecycle.transport_manager = FailingTransport()
    try:
        asyncio.run(lifecycle.cleanup())
        asyncio.run(lifecycle.cleanup())
    finally:
        stealth.finalize_stealth_logging(db_path)

    assert retained_key_alias == bytearray()
    assert key == bytearray()
    assert lifecycle.stealth_session_key is None
    assert handler not in root.handlers


def test_stealth_finalize_waits_for_inflight_emit_and_preserves_tail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    import netforge.core.stealth_log as stealth

    results_dir = tmp_path / "inflight" / "session"
    db_path = results_dir / "stealth.db"
    key = stealth.install_stealth_logging(results_dir)
    root = logging.getLogger()
    handler = next(
        item for item in root.handlers if isinstance(item, stealth.StealthLogHandler)
    )
    retained_key_alias = handler._key
    baseline = handler._conn.execute("SELECT COUNT(*) FROM stealth_log").fetchone()[0]
    entered = threading.Event()
    release = threading.Event()
    finalize_started = threading.Event()
    finalized = threading.Event()
    errors: list[BaseException] = []
    real_encrypt = stealth._encrypt

    def blocked_encrypt(data: str, key_alias: bytes | bytearray) -> str:
        entered.set()
        if not release.wait(timeout=5):
            raise RuntimeError("fixture release timed out")
        return real_encrypt(data, key_alias)

    def emit_tail() -> None:
        try:
            handler.handle(
                logging.LogRecord(
                    name="forge.netforge.inflight",
                    level=logging.ERROR,
                    pathname="",
                    lineno=0,
                    msg="inflight tail marker",
                    args=(),
                    exc_info=None,
                )
            )
        except BaseException as exc:
            errors.append(exc)

    def finalize() -> None:
        finalize_started.set()
        try:
            assert stealth.finalize_stealth_logging(db_path) is True
        except BaseException as exc:
            errors.append(exc)
        finally:
            finalized.set()

    monkeypatch.setattr(stealth, "_encrypt", blocked_encrypt)
    emit_thread = threading.Thread(target=emit_tail)
    finalize_thread = threading.Thread(target=finalize)
    try:
        emit_thread.start()
        assert entered.wait(timeout=5)
        finalize_thread.start()
        assert finalize_started.wait(timeout=5)
        assert finalized.wait(timeout=0.05) is False
        release.set()
        emit_thread.join(timeout=5)
        finalize_thread.join(timeout=5)
    finally:
        release.set()
        emit_thread.join(timeout=5)
        finalize_thread.join(timeout=5)
        stealth.finalize_stealth_logging(db_path)

    assert errors == []
    assert emit_thread.is_alive() is False
    assert finalize_thread.is_alive() is False
    assert finalized.is_set()
    connection = sqlite3.connect(str(db_path))
    try:
        count = connection.execute("SELECT COUNT(*) FROM stealth_log").fetchone()[0]
    finally:
        connection.close()
    assert count == baseline + 1
    assert retained_key_alias == bytearray()
    assert key == bytearray()
    assert handler not in root.handlers


def test_stealth_concurrent_installs_are_single_global_session_and_restore_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netforge.core.stealth_log as stealth

    root = logging.getLogger()
    logger = logging.getLogger("forge.netforge.concurrent-install")
    prior_propagate = logger.propagate
    console_handler = logging.StreamHandler(io.StringIO())
    root.addHandler(console_handler)
    logger.propagate = False
    closed_key_aliases: list[bytearray] = []
    real_close = stealth.StealthLogHandler.close

    def tracked_close(handler: stealth.StealthLogHandler) -> None:
        alias = handler._key
        real_close(handler)
        closed_key_aliases.append(alias)

    monkeypatch.setattr(stealth.StealthLogHandler, "close", tracked_close)

    def concurrent_install(paths: dict[str, Path]) -> tuple[dict[str, bytearray], list[BaseException]]:
        barrier = threading.Barrier(len(paths) + 1)
        results: dict[str, bytearray] = {}
        errors: list[BaseException] = []

        def worker(label: str, path: Path) -> None:
            try:
                barrier.wait(timeout=5)
                results[label] = stealth.install_stealth_logging(path)
            except BaseException as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(label, path))
            for label, path in paths.items()
        ]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=5)
        assert all(thread.is_alive() is False for thread in threads)
        return results, errors

    try:
        same_dir = tmp_path / "same" / "session"
        same_keys, same_errors = concurrent_install({"one": same_dir, "two": same_dir})
        assert same_errors == []
        assert set(same_keys) == {"one", "two"}
        assert same_keys["one"] is same_keys["two"]
        assert len(stealth._ACTIVE_SESSIONS) == 1
        assert len(
            [item for item in root.handlers if isinstance(item, stealth.StealthLogHandler)]
        ) == 1
        assert console_handler not in root.handlers
        assert logger.propagate is True

        assert stealth.finalize_stealth_logging(same_dir / "stealth.db") is True
        assert same_keys["one"] == bytearray()
        assert console_handler in root.handlers
        assert logger.propagate is False

        different = {
            "left": tmp_path / "different" / "left",
            "right": tmp_path / "different" / "right",
        }
        different_keys, different_errors = concurrent_install(different)
        assert different_errors == []
        assert set(different_keys) == {"left", "right"}
        assert len(stealth._ACTIVE_SESSIONS) == 1
        active_session = next(iter(stealth._ACTIVE_SESSIONS.values()))
        active_handlers = [
            item for item in root.handlers if isinstance(item, stealth.StealthLogHandler)
        ]
        assert active_handlers == [active_session.handler]
        assert sum(bool(key) for key in different_keys.values()) == 1
        assert active_session.caller_key in different_keys.values()
        assert console_handler not in root.handlers
        assert logger.propagate is True

        assert stealth.finalize_stealth_logging(active_session.db_path) is True
        assert all(key == bytearray() for key in different_keys.values())
        assert len(stealth._ACTIVE_SESSIONS) == 0
        assert not any(
            isinstance(item, stealth.StealthLogHandler) for item in root.handlers
        )
        assert root.handlers.count(console_handler) == 1
        assert logger.propagate is False
        assert closed_key_aliases
        assert all(alias == bytearray() for alias in closed_key_aliases)
    finally:
        for session in list(stealth._ACTIVE_SESSIONS.values()):
            stealth.finalize_stealth_logging(session.db_path)
        root.removeHandler(console_handler)
        console_handler.close()
        logger.propagate = prior_propagate


def test_stealth_handler_initialization_failure_wipes_internal_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netforge.core.stealth_log as stealth

    wiped: list[bytes] = []
    original_wipe = stealth._wipe_bytearray

    def track_wipe(value: bytearray) -> None:
        original_wipe(value)
        wiped.append(bytes(value))

    def fail_connect(*_args: object, **_kwargs: object) -> object:
        raise stealth.StealthLogError("stealth log is unavailable")

    monkeypatch.setattr(stealth, "_wipe_bytearray", track_wipe)
    monkeypatch.setattr(stealth, "_connect_owner_only_database", fail_connect)
    key = stealth._generate_session_key()
    with pytest.raises(stealth.StealthLogError, match="^stealth log is unavailable$"):
        stealth.StealthLogHandler(
            tmp_path / "failure" / "stealth.db",
            key,
        )

    assert wiped and wiped[-1] == b""
    assert key == bytearray()


def test_stealth_dump_failure_is_fixed_wipes_local_key_and_leaves_no_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netforge.core.stealth_log as stealth
    from common.artifact_io import ArtifactBoundaryError

    db_path = tmp_path / "failure" / "stealth.db"
    export_path = tmp_path / "failure-export" / "clear.json"
    key = stealth._generate_session_key()
    handler = stealth.StealthLogHandler(db_path, key)
    handler.emit(
        logging.LogRecord(
            name="forge.failure",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="password=%s",
            args=(CANARIES["password"],),
            exc_info=None,
        )
    )
    handler.close()

    wiped: list[bytes] = []
    original_wipe = stealth._wipe_bytearray

    def track_wipe(value: bytearray) -> None:
        original_wipe(value)
        wiped.append(bytes(value))

    def fail_write(*_args: object, **_kwargs: object) -> Path:
        raise ArtifactBoundaryError("CANARY_WRITE_FAILURE")

    monkeypatch.setattr(stealth, "_wipe_bytearray", track_wipe)
    monkeypatch.setattr(stealth, "atomic_write_bytes", fail_write)
    with pytest.raises(stealth.StealthLogError) as caught:
        stealth.dump_stealth_log(db_path, key, output_path=export_path)

    assert str(caught.value) == "stealth log is unavailable"
    assert CANARIES["password"] not in str(caught.value)
    assert not export_path.exists()
    assert wiped and wiped[-1] == b""
    assert key == bytearray()


def test_jsonl_log_preserves_shared_parent_and_is_owner_only(tmp_path: Path) -> None:
    shared = tmp_path / "caller-owned"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    log_path = shared / "audit.jsonl"

    handler = JsonlFileHandler(log_path, module_name="fixture")
    try:
        assert stat.S_IMODE(shared.stat().st_mode) == 0o755
        assert stat.S_IMODE(log_path.stat().st_mode) == 0o600
    finally:
        handler.close()


def test_jsonl_log_creates_missing_parent_owner_only_under_open_umask(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "private" / "nested"
    previous_umask = os.umask(0)
    try:
        handler = JsonlFileHandler(parent / "audit.jsonl", module_name="fixture")
    finally:
        os.umask(previous_umask)
    try:
        assert stat.S_IMODE(parent.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(parent.stat().st_mode) == 0o700
        assert stat.S_IMODE((parent / "audit.jsonl").stat().st_mode) == 0o600
    finally:
        handler.close()


def test_jsonl_log_rejects_world_writable_destination_namespace(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "unmanaged-log-root"
    parent.mkdir(mode=0o700)
    parent.chmod(0o777)

    with pytest.raises(ValueError, match="log destination is unavailable"):
        JsonlFileHandler(parent / "audit.jsonl", module_name="fixture")

    assert list(parent.iterdir()) == []
    assert stat.S_IMODE(parent.stat().st_mode) == 0o777


def test_jsonl_log_rejects_symlink_without_touching_victim(tmp_path: Path) -> None:
    victim = tmp_path / "victim.log"
    victim.write_text("LOG_CANARY_UNCHANGED", encoding="utf-8")
    victim.chmod(0o644)
    destination = tmp_path / "audit.jsonl"
    destination.symlink_to(victim)

    with pytest.raises(ValueError, match="log destination is unavailable"):
        JsonlFileHandler(destination, module_name="fixture")

    assert destination.is_symlink()
    assert victim.read_text(encoding="utf-8") == "LOG_CANARY_UNCHANGED"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644


def test_jsonl_log_rejects_symlink_parent_without_creating_artifact(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="log destination is unavailable"):
        JsonlFileHandler(linked_parent / "audit.jsonl", module_name="fixture")

    assert list(real_parent.iterdir()) == []


def test_jsonl_log_pins_parent_across_ancestor_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import common.artifact_io as artifact_io_module

    original_root = tmp_path / "original-root"
    original_parent = original_root / "nested"
    original_parent.mkdir(parents=True)
    original_root.chmod(0o755)
    original_parent.chmod(0o755)
    detached_root = tmp_path / "detached-root"
    redirected_root = tmp_path / "redirected-root"
    redirected_parent = redirected_root / "nested"
    redirected_parent.mkdir(parents=True)
    redirected_root.chmod(0o755)
    redirected_parent.chmod(0o755)
    victim = redirected_parent / "audit.jsonl"
    victim.write_text("REDIRECTED_LOG_CANARY_007\n", encoding="utf-8")
    victim.chmod(0o644)
    real_open_private_directory = artifact_io_module.open_private_directory
    swapped = False

    def open_then_replace_ancestor(
        directory: str | os.PathLike[str],
        *,
        create: bool = True,
    ) -> int:
        nonlocal swapped
        descriptor = real_open_private_directory(directory, create=create)
        if Path(directory) == original_parent and not swapped:
            swapped = True
            original_root.rename(detached_root)
            original_root.symlink_to(redirected_root, target_is_directory=True)
        return descriptor

    monkeypatch.setattr(
        artifact_io_module,
        "open_private_directory",
        open_then_replace_ancestor,
    )
    handler = JsonlFileHandler(
        original_parent / "audit.jsonl",
        module_name="fixture",
    )
    record = logging.LogRecord(
        name="fixture",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="PINNED_LOG_WRITE_007",
        args=(),
        exc_info=None,
    )
    try:
        handler.emit(record)
    finally:
        handler.close()

    assert swapped is True
    assert victim.read_text(encoding="utf-8") == "REDIRECTED_LOG_CANARY_007\n"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    pinned_log = detached_root / "nested" / "audit.jsonl"
    assert handler.path == pinned_log
    assert "PINNED_LOG_WRITE_007" in pinned_log.read_text(encoding="utf-8")
    assert stat.S_IMODE(pinned_log.stat().st_mode) == 0o600


def test_jsonl_log_rejects_hardlink_without_mutating_alias(tmp_path: Path) -> None:
    victim = tmp_path / "hardlink-victim.log"
    victim.write_text("LOG_HARDLINK_CANARY", encoding="utf-8")
    victim.chmod(0o644)
    destination = tmp_path / "audit.jsonl"
    os.link(victim, destination)

    with pytest.raises(ValueError, match="log destination is unavailable"):
        JsonlFileHandler(destination, module_name="fixture")

    assert victim.read_text(encoding="utf-8") == "LOG_HARDLINK_CANARY"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    assert victim.stat().st_nlink == 2


def test_jsonl_log_rejects_leaf_rename_during_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import common.logger as logger_module

    destination = tmp_path / "audit.jsonl"
    renamed = tmp_path / "attacker-selected.jsonl"
    real_open = logger_module.open_owner_only_file
    raced = False

    def rename_after_open(*args: object, **kwargs: object) -> tuple[Path, int]:
        nonlocal raced
        candidate, descriptor = real_open(*args, **kwargs)  # type: ignore[arg-type]
        candidate.rename(renamed)
        raced = True
        return candidate, descriptor

    monkeypatch.setattr(logger_module, "open_owner_only_file", rename_after_open)

    with pytest.raises(ValueError, match="log destination is unavailable"):
        JsonlFileHandler(destination, module_name="fixture")

    assert raced is True
    assert destination.exists() is False
    assert renamed.read_bytes() == b""
    assert stat.S_IMODE(renamed.stat().st_mode) == 0o600


def test_jsonl_log_stops_before_writing_new_hardlink_alias(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    alias = tmp_path / "late-alias.log"
    handler = JsonlFileHandler(log_path, module_name="fixture")
    os.link(log_path, alias)
    record = logging.LogRecord(
        name="fixture",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="MUST_NOT_REACH_ALIAS",
        args=(),
        exc_info=None,
    )

    try:
        handler.emit(record)
    finally:
        handler.close()

    assert alias.read_text(encoding="utf-8") == ""
    assert log_path.stat().st_nlink == 2


def test_jsonl_log_rolls_back_leaf_transfer_after_final_prewrite_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import common.logger as logger_module

    log_path = tmp_path / "audit.jsonl"
    alias = tmp_path / "post-check-alias.log"
    handler = JsonlFileHandler(log_path, module_name="fixture")
    real_check = logger_module._log_namespace_is_safe
    calls = 0

    def transfer_leaf_after_final_prewrite_check(
        *args: object,
        **kwargs: object,
    ) -> bool:
        nonlocal calls
        calls += 1
        result = real_check(*args, **kwargs)  # type: ignore[arg-type]
        if calls == 3 and result:
            os.link(log_path, alias)
            log_path.unlink()
        return result

    record = logging.LogRecord(
        name="fixture",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="PRIVATE_LOG_EVENT_MUST_BE_ROLLED_BACK_007",
        args=(),
        exc_info=None,
    )
    try:
        monkeypatch.setattr(
            logger_module,
            "_log_namespace_is_safe",
            transfer_leaf_after_final_prewrite_check,
        )
        handler.emit(record)
    finally:
        handler.close()

    assert calls >= 4
    assert alias.read_text(encoding="utf-8") == ""
    assert alias.stat().st_nlink == 1
    assert log_path.exists() is False


@pytest.mark.parametrize("operation", ["fstat", "fchmod"])
def test_jsonl_log_normalizes_generic_artifact_helper_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    import common.logger as logger_module

    def fail_helper(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("CANARY_LOG_HELPER_FAILURE")

    monkeypatch.setattr(logger_module.os, operation, fail_helper)
    with pytest.raises(ValueError) as exc_info:
        JsonlFileHandler(tmp_path / "audit.jsonl", module_name="fixture")
    rendered = "".join(
        traceback.format_exception(
            type(exc_info.value),
            exc_info.value,
            exc_info.value.__traceback__,
        )
    )
    assert "CANARY_LOG_HELPER_FAILURE" not in rendered
    assert exc_info.value.__suppress_context__ is True
