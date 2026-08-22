from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

from common.action_authorization import (
    AUTHORIZATION_DB_ENV,
    AuthorizationContext,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    consume_authorization,
    issue_authorization,
)
from common.config import BaseForgeConfig
from common.confirm_gate import ActionConfirmation
from common.db import create_db
from common.outbound_policy import MemoryOutboundAuditSink, OutboundReason
from common.scope import Scope
from netforge.modules.compliance.cis_benchmark import CisBenchmark, CisBenchmarkEvaluator


class _Db:
    def add(self, _obj):
        return None

    def commit(self):
        return None

    def rollback(self):
        return None


def _authorized_config(
    tmp_path: Path,
    monkeypatch,
    *,
    target: str,
    extra: dict | None = None,
) -> tuple[BaseForgeConfig, str]:
    authorization_db = tmp_path / "cis-authorization.db"
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(authorization_db))
    session = create_db(authorization_db)
    now = datetime.now(timezone.utc)
    run_id = "run-cis-fixture"
    allowed_scope = [target]
    context = AuthorizationContext(
        tenant_id="tenant-cis-fixture",
        engagement_id="engagement-cis-fixture",
        run_id=run_id,
        job_id="job-cis-fixture",
        operator_id="operator-cis-fixture",
        operator_role=OperatorRole.OPERATOR,
        action_kind="module.execute",
        engine="netforge",
        module_id="cis_benchmark",
        requested_target=target,
        resolved_target=target,
        allowed_scope=allowed_scope,
        excluded_scope=[],
        scope_policy_version="scope-policy-v1",
        safety_mode=SafetyMode.ACTIVE,
        confirmation_method=ConfirmationMethod.CLI_PROMPT,
        confirmed_by="operator-cis-fixture",
    )
    issued = issue_authorization(
        session=session,
        context=context,
        confirmation=ActionConfirmation.create(
            job_id=context.job_id,
            target=context.resolved_target,
            engine=context.engine,
            action=context.action_kind,
            issued_at=now,
        ),
        now=now,
    )
    assert issued.allowed
    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=context,
        boundary="netforge.module",
        now=now,
    )
    assert consumed.allowed
    config = BaseForgeConfig(
        target=target,
        extra={
            **(extra or {}),
            "allowed_scope": allowed_scope,
            "excluded_scope": [],
            # The fixture exercises CIS evaluation with a lightweight in-memory
            # database and intentionally has no canonical asset graph.
            "allow_legacy_compat": True,
            "authorized_module_envelopes": {
                "cis_benchmark": issued.envelope,
            },
        },
    )
    session.close()
    return config, run_id


def test_linux_fact_evaluation_includes_level_two_when_requested():
    evaluator = CisBenchmarkEvaluator(level=2)

    results = evaluator.evaluate_host(
        {
            "host": "linux01",
            "platform": "ubuntu",
            "facts": {
                "kernel_modules": {"cramfs": {"disabled": True}},
                "mounts": {"/tmp": {"separate": True, "options": ["rw", "nodev", "nosuid"]}},
                "sysctl": {"net": {"ipv4": {"ip_forward": 0}}},
                "packages": {"auditd": {"installed": True}},
                "password_policy": {"max_days": 99999, "min_days": 0},
                "ssh": {"permit_root_login": True},
            },
        }
    )

    by_id = {result.check.check_id: result for result in results}
    assert by_id["linux-1.1.1.1"].status == "pass"
    assert by_id["linux-5.4.1.1"].status == "fail"
    assert by_id["linux-5.4.1.2"].status == "fail"
    assert by_id["linux-5.6.1"].status == "fail"


def test_windows_command_output_evaluation_is_deterministic():
    evaluator = CisBenchmarkEvaluator(level=1)

    results = evaluator.evaluate_host(
        {
            "host": "win01",
            "platform": "windows-server-2022",
            "command_outputs": {
                "net accounts": """
Minimum password length: 8
Length of password history maintained: 12
Lockout threshold: Never
""",
                "Get-SmbServerConfiguration | Select RequireSecuritySignature": "RequireSecuritySignature : False",
                "Get-NetFirewallProfile -Profile Domain": "Enabled : True",
                "Get-MpPreference": "DisableRealtimeMonitoring : True",
                "Get-LocalUser Guest": "Enabled : False",
            },
        }
    )

    failed = {result.check.check_id for result in results if result.status == "fail"}
    passed = {result.check.check_id for result in results if result.status == "pass"}
    assert {"windows-1.1.1", "windows-1.1.4", "windows-1.2.1", "windows-2.3.9.4", "windows-18.9.45.4.1"} <= failed
    assert {"windows-2.3.1.2", "windows-9.1.1"} <= passed


def test_cis_benchmark_module_skips_without_supplied_facts(
    tmp_path: Path,
    monkeypatch,
):
    config, run_id = _authorized_config(
        tmp_path,
        monkeypatch,
        target="example.internal",
    )
    module = CisBenchmark(
        config=config,
        scope=Scope(["example.internal"]),
        db_session=_Db(),
        results_dir=tmp_path,
        run_id=run_id,
    )

    result = asyncio.run(module.run())

    assert result.skipped is True
    assert "no supplied CIS facts" in result.skip_reason
    assert result.findings == []


def test_cis_benchmark_module_emits_findings_from_supplied_facts(
    tmp_path: Path,
    monkeypatch,
):
    config, run_id = _authorized_config(
        tmp_path,
        monkeypatch,
        target="linux01",
        extra={
            "cis_level": 1,
            "cis_hosts": [
                {
                    "host": "linux01",
                    "platform": "linux",
                    "facts": {
                        "kernel_modules": {"cramfs": {"disabled": False}},
                        "mounts": {"/tmp": {"separate": True, "options": ["rw"]}},
                        "sysctl": {"net": {"ipv4": {"ip_forward": 1}}},
                        "packages": {"auditd": {"installed": False}},
                        "password_policy": {"max_days": 99999},
                        "ssh": {"permit_root_login": True},
                    },
                }
            ],
        },
    )
    module = CisBenchmark(
        config=config,
        scope=Scope(["linux01"]),
        db_session=_Db(),
        results_dir=tmp_path,
        run_id=run_id,
    )

    result = asyncio.run(module.run())

    assert result.skipped is False
    assert len(result.findings) >= 5
    assert all(finding.service == "local-facts" for finding in result.findings)
    assert all(finding.evidence.extra["network_activity"] == "none" for finding in result.findings)


@pytest.mark.parametrize(
    "mutation",
    [
        "audit_sink",
        "attempt_limiter",
        "cancellation_check",
        "policy_clock",
        "rate_zero",
        "rate_negative",
        "rate_extreme",
    ],
)
def test_cis_benchmark_denies_in_place_outbound_control_mutation(
    tmp_path: Path,
    monkeypatch,
    mutation: str,
) -> None:
    config, run_id = _authorized_config(
        tmp_path,
        monkeypatch,
        target="linux01",
        extra={"cis_hosts": [{"host": "linux01", "platform": "linux"}]},
    )
    module = CisBenchmark(
        config=config,
        scope=Scope(["linux01"]),
        db_session=_Db(),
        results_dir=tmp_path,
        run_id=run_id,
    )
    assert module.outbound_policy is not None
    context = module.outbound_policy.context
    delegate_calls: list[str] = []

    def host_inputs():
        delegate_calls.append("host_inputs")
        return []

    monkeypatch.setattr(module, "_host_inputs", host_inputs)
    if mutation == "audit_sink":
        object.__setattr__(context, "audit_sink", MemoryOutboundAuditSink())
    elif mutation == "attempt_limiter":
        object.__setattr__(context, "attempt_limiter", None)
    elif mutation == "cancellation_check":
        object.__setattr__(context, "cancellation_check", lambda: False)
    elif mutation == "policy_clock":
        module.outbound_policy._clock = lambda: datetime.now(timezone.utc)
    elif mutation == "rate_zero":
        module.config.rate.requests_per_second = 0
    elif mutation == "rate_negative":
        module.config.rate.requests_per_second = -1
    else:
        module.config.rate.requests_per_second = 1_000_000

    result = asyncio.run(module.run())

    assert result.skipped is True
    assert result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value
    assert delegate_calls == []


def test_canonical_audit_sink_methods_cannot_be_shadowed_or_replaced(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from common.outbound_policy import AuthorizationDatabaseOutboundAuditSink

    config, run_id = _authorized_config(
        tmp_path,
        monkeypatch,
        target="linux01",
    )
    module = CisBenchmark(
        config=config,
        scope=Scope(["linux01"]),
        db_session=_Db(),
        results_dir=tmp_path,
        run_id=run_id,
    )
    assert module.outbound_policy is not None
    sink = module.outbound_policy.context.audit_sink
    assert type(sink) is AuthorizationDatabaseOutboundAuditSink
    method_names = (
        "append_decision",
        "append_route_health",
        "route_health_is_current",
        "invalidate_route_health",
    )
    for method_name in method_names:
        with pytest.raises(AttributeError):
            setattr(sink, method_name, lambda *_args, **_kwargs: None)

    delegate_calls: list[str] = []
    monkeypatch.setattr(
        module,
        "_host_inputs",
        lambda: delegate_calls.append("host_inputs") or [],
    )
    for method_name in method_names:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                AuthorizationDatabaseOutboundAuditSink,
                method_name,
                lambda *_args, **_kwargs: None,
            )
            result = asyncio.run(module.run())
            assert result.skipped is True
            assert result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value
    legitimate = asyncio.run(module.run())
    assert "no supplied CIS facts" in legitimate.skip_reason
    assert delegate_calls == ["host_inputs"]


def test_in_place_sink_and_policy_code_mutation_invalidates_runtime_binding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from common.outbound_policy import (
        AuthorizationDatabaseOutboundAuditSink,
        OutboundPolicy,
    )
    import common.outbound_policy as outbound_module

    config, run_id = _authorized_config(
        tmp_path,
        monkeypatch,
        target="linux01",
    )
    module = CisBenchmark(
        config=config,
        scope=Scope(["linux01"]),
        db_session=_Db(),
        results_dir=tmp_path,
        run_id=run_id,
    )
    delegate_calls: list[str] = []
    monkeypatch.setattr(
        module,
        "_host_inputs",
        lambda: delegate_calls.append("host_inputs") or [],
    )

    def no_op_sink(self, record):
        return None

    sink_code = AuthorizationDatabaseOutboundAuditSink.append_decision.__code__
    try:
        AuthorizationDatabaseOutboundAuditSink.append_decision.__code__ = (
            no_op_sink.__code__
        )
        sink_result = asyncio.run(module.run())
    finally:
        AuthorizationDatabaseOutboundAuditSink.append_decision.__code__ = sink_code
    assert sink_result.skipped is True
    assert sink_result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value

    def no_op_prepare(self, *args, **kwargs):
        return None

    policy_code = OutboundPolicy.prepare_destination.__code__
    try:
        OutboundPolicy.prepare_destination.__code__ = no_op_prepare.__code__
        policy_result = asyncio.run(module.run())
    finally:
        OutboundPolicy.prepare_destination.__code__ = policy_code
    assert policy_result.skipped is True
    assert policy_result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value

    def no_op_append(session, record, *, commit=True):
        return None

    append_code = outbound_module.append_outbound_decision.__code__
    try:
        outbound_module.append_outbound_decision.__code__ = no_op_append.__code__
        global_result = asyncio.run(module.run())
    finally:
        outbound_module.append_outbound_decision.__code__ = append_code
    assert global_result.skipped is True
    assert global_result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value

    legitimate = asyncio.run(module.run())
    assert "no supplied CIS facts" in legitimate.skip_reason
    assert delegate_calls == ["host_inputs"]


def test_consumed_context_cannot_be_replayed_across_module_instances(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, run_id = _authorized_config(
        tmp_path,
        monkeypatch,
        target="linux01",
    )
    first = CisBenchmark(
        config=config,
        scope=Scope(["linux01"]),
        db_session=_Db(),
        results_dir=tmp_path / "first",
        run_id=run_id,
    )
    second = CisBenchmark(
        config=config,
        scope=Scope(["linux01"]),
        db_session=_Db(),
        results_dir=tmp_path / "second",
        run_id=run_id,
    )
    calls: list[str] = []
    monkeypatch.setattr(
        first,
        "_host_inputs",
        lambda: calls.append("first") or [],
    )
    monkeypatch.setattr(
        second,
        "_host_inputs",
        lambda: calls.append("second") or [],
    )
    for name in (
        "outbound_policy",
        "_authorized_outbound_policy",
        "_authorized_outbound_context",
        "_authorized_outbound_policy_binding",
        "_authorized_outbound_context_binding",
        "authorization_decision_id",
        "authorization_envelope",
        "authorization_context",
        "authorization_boundary",
    ):
        setattr(second, name, getattr(first, name))

    first_result = asyncio.run(first.run())
    second_result = asyncio.run(second.run())

    assert "no supplied CIS facts" in first_result.skip_reason
    assert second_result.skipped is True
    assert second_result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value
    assert calls == ["first"]


def test_netforge_maps_cis_benchmark_module():
    from netforge.netforge import MODULE_MAP, PHASES, load_module

    phase_five_modules = next(modules for number, _name, modules in PHASES if number == 5)
    assert "cis_benchmark" in phase_five_modules
    assert MODULE_MAP["cis_benchmark"] == "netforge.modules.compliance.cis_benchmark"
    assert load_module("cis_benchmark") is CisBenchmark
