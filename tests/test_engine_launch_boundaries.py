from __future__ import annotations

import asyncio
import os
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from common.action_authorization import (
    AUTHORIZATION_DB_ENV,
    AuthorizationContext,
    AuthorizationReason,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    authorization_runtime_environment,
    consume_authorization,
    derive_authorization,
    issue_authorization,
    load_authorization_runtime_facts,
    module_set_binding,
    protected_credential_reference,
)
from common.base_module import ModuleResult
from common.base_module import BaseModule
from common.config import BaseForgeConfig
from common.confirm_gate import ActionConfirmation, set_auto_confirm
from common.db import AuthorizationDecisionModel, create_db as create_authorization_db
from common.scope import Scope, ScopeReason
from common.target_manager import TargetManager
from adforge import adforge
from aiforge import aiforge
from netforge import netforge
from webforge import webforge


LAB_WEB_TARGET = "http://127.0.0.1:8080/fixture"
LAB_NET_TARGET = "127.0.0.1"
LAB_SCOPE = ["127.0.0.1/32"]


@pytest.fixture(autouse=True)
def _isolated_engine_authorization_db(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(
        AUTHORIZATION_DB_ENV,
        str(tmp_path / "engine-boundary-authorization.db"),
    )


def _confirmation(target: str, engine: str, action: str = "scan") -> ActionConfirmation:
    return ActionConfirmation.create(
        job_id=f"job-{engine}-loopback",
        target=target,
        engine=engine,
        action=action,
    )


def _web_args(**overrides: object) -> Namespace:
    values: dict[str, object] = {
        "control_file": None,
        "scope": list(LAB_SCOPE),
        "exclude": [],
        "dry_run": False,
        "mode": "blackbox",
        "modules": "probe",
        "skip_modules": None,
        "username": None,
        "password": None,
        "token": None,
        "session": None,
        "sso": False,
        "auth_state": None,
        "login_script": None,
        "login_url": None,
        "report_format": "json",
    }
    values.update(overrides)
    return Namespace(**values)


def _net_args(**overrides: object) -> Namespace:
    values: dict[str, object] = {
        "control_file": None,
        "scope": list(LAB_SCOPE),
        "exclude": [],
        "dry_run": False,
        "mode": "full",
        "modules": "probe",
        "skip_modules": None,
        "stealth": False,
        "opsec": "normal",
        "red_team": False,
        "ssh_user": None,
        "snmp_user": None,
        "winrm_user": None,
        "attacker_ip": None,
        "report_format": "json",
    }
    values.update(overrides)
    return Namespace(**values)


def _ad_args(**overrides: object) -> Namespace:
    values: dict[str, object] = {
        "dc": LAB_NET_TARGET,
        "domain": "lab.test",
        "scope": list(LAB_SCOPE),
        "exclude": [],
        "dry_run": False,
        "mode": "unauth",
        "modules": "probe",
        "skip_modules": None,
        "dcsync": False,
        "bloodhound": False,
        "report_format": "json",
    }
    values.update(overrides)
    return Namespace(**values)


def _ai_args(**overrides: object) -> Namespace:
    values: dict[str, object] = {
        "target": LAB_WEB_TARGET,
        "scope": list(LAB_SCOPE),
        "exclude": [],
        "dry_run": False,
        "mode": "blackbox",
        "api_type": "custom",
        "modules": "probe",
        "skip_modules": None,
        "no_dos": False,
        "no_destructive": False,
        "allow_destructive": False,
        "report_format": "json",
    }
    values.update(overrides)
    return Namespace(**values)


def _programmatic_args(engine: str, tmp_path: Path) -> Namespace:
    if engine == "webforge":
        return _web_args(
            engagement="pytest",
            tester="boundary-tests",
            resume=None,
            output=str(tmp_path / "web-results"),
            config=None,
            rate=1.0,
            workers=1,
            verbose=False,
            quiet=True,
            proxy=None,
        )
    if engine == "netforge":
        return _net_args(
            engagement="pytest",
            tester="boundary-tests",
            resume=None,
            output=None,
            rate=1.0,
            workers=1,
            bf_delay=0.0,
            bf_max=1,
            bf_timeout=1.0,
            interface=None,
            capture=False,
        )
    if engine == "adforge":
        return _ad_args(
            engagement="pytest",
            tester="boundary-tests",
            resume=None,
            spray_delay=0.0,
            spray_max_rounds=1,
            username=None,
            password=None,
            hash=None,
            ticket=None,
        )
    if engine == "aiforge":
        return _ai_args(
            engagement="pytest",
            tester="boundary-tests",
            config=None,
            rate=1.0,
            verbose=False,
            quiet=True,
            proxy=None,
            api_key=None,
            model_name=None,
            max_tokens=8,
            temperature=0.0,
        )
    raise AssertionError(f"unsupported test engine: {engine}")


class _FakeDB:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def add(self, value: object) -> None:
        self.calls.append("db_add")

    def commit(self) -> None:
        self.calls.append("db_commit")

    def close(self) -> None:
        self.calls.append("db_close")


class _FakeReporter:
    def __init__(self, calls: list[str], **kwargs: object) -> None:
        self.calls = calls

    def generate_all(self) -> dict[str, Path]:
        self.calls.append("report")
        return {}


def _configured(target: str, confirmation: ActionConfirmation | None = None) -> BaseForgeConfig:
    cfg = BaseForgeConfig(
        target=target,
        engagement="pytest",
        tester="boundary-tests",
        mode="full",
    )
    cfg.workers = 1
    cfg.extra["allowed_scope"] = list(LAB_SCOPE)
    cfg.extra["excluded_scope"] = []
    if confirmation is not None:
        cfg.extra["job_id"] = confirmation.job_id
        cfg.extra["launch_action"] = confirmation.action
        cfg.extra["launch_confirmation"] = confirmation
    return cfg


def _authorized_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    engine: str,
    confirmation: ActionConfirmation,
    modules: list[str] | None = None,
    credential_reference: str = "",
) -> BaseForgeConfig:
    db_path = tmp_path / f"{engine}-authorization.db"
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(db_path))
    session = create_authorization_db(db_path)
    base = AuthorizationContext(
        tenant_id="tenant-lab",
        engagement_id="pytest",
        run_id=f"run-{engine}-loopback",
        job_id=confirmation.job_id,
        operator_id="operator-lab",
        operator_role=OperatorRole.OPERATOR,
        action_kind=confirmation.action,
        engine=engine,
        module_id=module_set_binding(modules),
        requested_target=target,
        resolved_target=target,
        allowed_scope=LAB_SCOPE,
        excluded_scope=[],
        safety_mode=(
            SafetyMode.HIGH_RISK if engine == "aiforge" else SafetyMode.ACTIVE
        ),
        credential_approval_required=bool(credential_reference),
        high_risk_approval_required=(engine == "aiforge"),
        confirmation_method=ConfirmationMethod.CLI_PROMPT,
        confirmed_by="operator-lab",
        credential_reference=credential_reference,
    )
    issued = issue_authorization(
        session=session,
        context=base,
        confirmation=confirmation,
    )
    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=base,
        boundary="test.parent",
    )
    assert consumed.allowed
    engine_context = AuthorizationContext(
        **{
            **base.__dict__,
            "action_kind": "engine.execute",
            "parent_decision_id": issued.envelope.decision_id,
            "confirmation_method": ConfirmationMethod.INHERITED,
        }
    )
    child = derive_authorization(
        session=session,
        parent_envelope=issued.envelope,
        context=engine_context,
        parent_boundary="test.parent",
    )
    session.close()
    assert child.allowed
    cfg = _configured(target, confirmation)
    cfg.extra["authorization_envelope"] = child.envelope
    cfg.extra["authorized_requested_modules"] = list(modules or [])
    cfg.extra["authorization_module_binding"] = module_set_binding(modules)
    cfg.extra["authorization_runtime"] = load_authorization_runtime_facts(
        authorization_runtime_environment(child.envelope)
    )
    cfg.extra["runtime_credential_reference"] = credential_reference
    return cfg


_PROGRAMMATIC_ENGINE_CASES = [
    (webforge, "webforge", LAB_WEB_TARGET, "setup_results_dir"),
    (netforge, "netforge", LAB_NET_TARGET, "setup_results"),
    (adforge, "adforge", LAB_NET_TARGET, "setup_results"),
    (aiforge, "aiforge", LAB_WEB_TARGET, "setup_results_dir"),
]


def _attach_engine_authorization(
    args: Namespace,
    engine: str,
    cfg: BaseForgeConfig,
) -> None:
    envelope = cfg.extra["authorization_envelope"]
    args._authorization_runtime = dict(cfg.extra["authorization_runtime"])
    if engine == "webforge":
        args._authorization_envelopes = [envelope]
    else:
        args._authorization_envelope = envelope


@pytest.mark.parametrize(
    ("engine_module", "engine", "target", "setup_name"),
    _PROGRAMMATIC_ENGINE_CASES,
)
@pytest.mark.parametrize("failure_mode", ["missing", "already_consumed"])
def test_programmatic_engine_envelope_denial_precedes_results_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    engine_module: object,
    engine: str,
    target: str,
    setup_name: str,
    failure_mode: str,
) -> None:
    confirmation = _confirmation(target, engine)
    args = _programmatic_args(engine, tmp_path)
    args._launch_confirmations = [confirmation]
    args._launch_job_id = confirmation.job_id
    args._launch_action = confirmation.action
    monkeypatch.delenv("FORGE_ACTION_AUTHORIZATIONS", raising=False)

    if failure_mode == "already_consumed":
        source_cfg = _authorized_config(
            tmp_path,
            monkeypatch,
            target,
            engine,
            confirmation,
            modules=["probe"],
        )
        _attach_engine_authorization(args, engine, source_cfg)
        consumed = engine_module._consume_engine_authorization(source_cfg)  # type: ignore[attr-defined]
        assert consumed.allowed is True

    calls: list[str] = []
    original_consume = engine_module._consume_engine_authorization  # type: ignore[attr-defined]

    def _tracked_consume(cfg: BaseForgeConfig):
        decision = original_consume(cfg)
        calls.append(f"consume:{decision.allowed}")
        return decision

    async def _unexpected_run(*items: object, **kwargs: object):
        pytest.fail("denied engine envelope reached run_scan")

    monkeypatch.setattr(engine_module, "_consume_engine_authorization", _tracked_consume)
    monkeypatch.setattr(
        engine_module,
        setup_name,
        lambda *items, **kwargs: pytest.fail(
            "results directory was created before engine authorization"
        ),
    )
    monkeypatch.setattr(engine_module, "run_scan", _unexpected_run)

    result = asyncio.run(
        engine_module.run_for_target(  # type: ignore[attr-defined]
            SimpleNamespace(target=target, options={}),
            args,
        )
    )

    assert result["status"] == "not_authorized"
    assert calls == ["consume:False"]
    expected_reason = (
        AuthorizationReason.LEGACY_NOT_AUTHORIZED.value
        if failure_mode == "missing"
        else AuthorizationReason.ALREADY_CONSUMED.value
    )
    assert result["reason_code"] == expected_reason


@pytest.mark.parametrize("failure_mode", ["missing", "already_consumed"])
@pytest.mark.parametrize("preexisting_results_base", [False, True])
def test_webforge_multitarget_engine_denial_creates_no_shared_results_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
    preexisting_results_base: bool,
) -> None:
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text(f"{LAB_WEB_TARGET}\n", encoding="utf-8")
    results_base = tmp_path / "multi-results"
    confirmation = _confirmation(LAB_WEB_TARGET, "webforge")
    args = _programmatic_args("webforge", tmp_path)
    args.target = None
    args.targets = str(targets_file)
    args.output = str(results_base)
    args.parallel = 1
    args.list_modules = False
    args.list_profiles = False
    args.auto_confirm = True
    args.no_screenshot = True
    args._launch_job_id = confirmation.job_id
    args._launch_action = confirmation.action

    prepared_authorizations = []
    if failure_mode == "already_consumed":
        source_cfg = _authorized_config(
            tmp_path,
            monkeypatch,
            LAB_WEB_TARGET,
            "webforge",
            confirmation,
            modules=["probe"],
        )
        _attach_engine_authorization(args, "webforge", source_cfg)
        consumed = webforge._consume_engine_authorization(source_cfg)
        assert consumed.allowed is True
        prepared_authorizations = [source_cfg.extra["authorization_envelope"]]
    if preexisting_results_base:
        results_base.mkdir(parents=True)

    monkeypatch.delenv("FORGE_ACTION_AUTHORIZATIONS", raising=False)
    monkeypatch.setattr(webforge, "parse_args", lambda: args)
    monkeypatch.setattr(
        webforge,
        "_prepare_cli_confirmations",
        lambda *_items, **_kwargs: (
            SimpleNamespace(allowed=True),
            [confirmation],
        ),
    )
    monkeypatch.setattr(
        webforge,
        "_prepare_engine_authorizations",
        lambda *_items, **_kwargs: (
            SimpleNamespace(allowed=True),
            prepared_authorizations,
        ),
    )
    monkeypatch.setattr(webforge, "set_auto_confirm", lambda *_items: None)
    monkeypatch.setattr(
        TargetManager,
        "enable_progress_persistence",
        lambda *_items: pytest.fail(
            "denied engine authorization enabled shared progress persistence"
        ),
    )
    monkeypatch.setattr(
        webforge,
        "setup_results_dir",
        lambda *_items, **_kwargs: pytest.fail(
            "denied engine authorization reached per-target results setup"
        ),
    )

    asyncio.run(webforge.main())

    assert results_base.exists() is preexisting_results_base
    assert not (results_base / "target_progress.json").exists()


def test_target_manager_deferred_results_persist_only_after_non_denied_callback(
    tmp_path: Path,
) -> None:
    results_base = tmp_path / "multi-results"
    manager = TargetManager(
        max_parallel=1,
        results_dir=results_base,
        defer_results_setup=True,
    )
    assert manager.add_target(LAB_WEB_TARGET)

    async def _authorized_fixture(_entry: object) -> dict[str, object]:
        manager.enable_progress_persistence()
        return {"status": "completed", "findings": 0, "errors": []}

    summary = asyncio.run(manager.run_all(_authorized_fixture))

    assert summary["states"]["completed"] == 1
    assert (results_base / "target_progress.json").is_file()


@pytest.mark.parametrize(
    ("returned_status", "expected_state"),
    [
        ("completed", "failed"),
        ("failed", "failed"),
        ("not_authorized", "not_authorized"),
        ("aborted", "aborted"),
    ],
)
def test_target_manager_normalizes_terminal_status_and_redacts_errors(
    tmp_path: Path,
    returned_status: str,
    expected_state: str,
) -> None:
    manager = TargetManager(
        max_parallel=1,
        results_dir=tmp_path / returned_status,
    )
    assert manager.add_target(LAB_WEB_TARGET)

    async def callback(_entry: object) -> dict[str, object]:
        return {
            "status": returned_status,
            "findings": 0,
            "errors": ["password=CANARY_TARGET_MANAGER_RESULT"],
        }

    summary = asyncio.run(manager.run_all(callback))
    target = summary["targets"][0]

    assert target["state"] == expected_state
    assert "CANARY_TARGET_MANAGER_RESULT" not in repr(summary)
    assert "<redacted>" in repr(summary)


@pytest.mark.parametrize(
    ("state_key", "surface"),
    [
        ("schema_outbound_state", "schema"),
        ("collab_outbound_state", "collab"),
    ],
)
def test_webforge_unsupported_requested_outbound_surface_fails_terminal_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state_key: str,
    surface: str,
) -> None:
    calls: list[str] = []
    events: list[str] = []
    confirmation = _confirmation(LAB_WEB_TARGET, "webforge")
    cfg = _authorized_config(
        tmp_path,
        monkeypatch,
        LAB_WEB_TARGET,
        "webforge",
        confirmation,
        modules=[],
    )
    cfg.extra[state_key] = "outbound_policy_unsupported"

    monkeypatch.setattr(webforge, "get_phases", lambda *args, **kwargs: [])
    monkeypatch.setattr(webforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(
        webforge,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )
    monkeypatch.setattr(webforge, "_get_eng_bus", lambda: None)
    monkeypatch.setattr(
        webforge,
        "_emit",
        lambda _b, _e, _t, etype, **_data: events.append(etype),
    )

    result = asyncio.run(
        webforge.run_scan(
            cfg,
            _web_args(modules=[]),
            tmp_path,
            event_bus=object(),
        )
    )

    assert result["status"] == "failed"
    assert result["errors"] == [f"{surface}: outbound_policy_unsupported"]
    assert "scan_interrupted" in events
    assert "scan_complete" not in events
    assert webforge._summary_exit_code(result) == 1


def test_target_manager_redacts_callback_exception_in_progress_state(
    tmp_path: Path,
) -> None:
    manager = TargetManager(max_parallel=1, results_dir=tmp_path / "exception")
    assert manager.add_target(LAB_WEB_TARGET)
    entry = next(iter(manager._targets.values()))
    entry.max_retries = 0

    async def callback(_entry: object) -> dict[str, object]:
        raise RuntimeError("token=CANARY_TARGET_MANAGER_EXCEPTION")

    summary = asyncio.run(manager.run_all(callback))

    assert summary["states"]["failed"] == 1
    assert "CANARY_TARGET_MANAGER_EXCEPTION" not in repr(summary)
    assert "<redacted>" in repr(summary)


def test_webforge_multitarget_dry_run_enables_deferred_progress_without_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results_base = tmp_path / "multi-results"
    args = _programmatic_args("webforge", tmp_path)
    args.dry_run = True
    args.output = str(results_base)
    args._launch_confirmations = []
    args._launch_job_id = "job-webforge-dry-run"
    args._launch_action = "scan"
    calls: list[str] = []
    manager = TargetManager(
        max_parallel=1,
        results_dir=results_base,
        defer_results_setup=True,
    )
    assert manager.add_target(LAB_WEB_TARGET)

    def _ready() -> None:
        calls.append("ready")
        manager.enable_progress_persistence()

    def _setup_results(*_items: object, **_kwargs: object) -> Path:
        calls.append("results")
        result = results_base / "dry-run-target"
        result.mkdir(parents=True)
        return result

    async def _run(*_items: object, **_kwargs: object) -> dict[str, object]:
        calls.append("run")
        return {
            "status": "completed",
            "authorized": False,
            "findings": 0,
            "errors": [],
        }

    monkeypatch.setattr(
        webforge,
        "_consume_engine_authorization",
        lambda *_items, **_kwargs: pytest.fail(
            "dry-run must not consume an active engine envelope"
        ),
    )
    monkeypatch.setattr(webforge, "setup_results_dir", _setup_results)
    monkeypatch.setattr(webforge, "run_scan", _run)

    summary = asyncio.run(
        manager.run_all(
            lambda entry: webforge.run_for_target(
                entry,
                args,
                on_results_ready=_ready,
            )
        )
    )

    assert summary["states"]["completed"] == 1
    assert calls == ["ready", "results", "run"]
    assert (results_base / "target_progress.json").is_file()


@pytest.mark.parametrize(
    ("engine_module", "engine", "target", "setup_name"),
    _PROGRAMMATIC_ENGINE_CASES,
)
def test_programmatic_engine_results_setup_follows_authorization_consumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    engine_module: object,
    engine: str,
    target: str,
    setup_name: str,
) -> None:
    confirmation = _confirmation(target, engine)
    source_cfg = _authorized_config(
        tmp_path,
        monkeypatch,
        target,
        engine,
        confirmation,
        modules=["probe"],
    )
    args = _programmatic_args(engine, tmp_path)
    args._launch_confirmations = [confirmation]
    args._launch_job_id = confirmation.job_id
    args._launch_action = confirmation.action
    _attach_engine_authorization(args, engine, source_cfg)
    monkeypatch.delenv("FORGE_ACTION_AUTHORIZATIONS", raising=False)

    calls: list[str] = []
    expected_results = tmp_path / f"{engine}-results"
    envelope = source_cfg.extra["authorization_envelope"]
    original_consume = engine_module._consume_engine_authorization  # type: ignore[attr-defined]

    def _tracked_consume(cfg: BaseForgeConfig):
        decision = original_consume(cfg)
        assert decision.allowed is True
        calls.append("consume")
        return decision

    def _setup(*items: object, **kwargs: object) -> Path:
        calls.append("results")
        return expected_results

    async def _run(
        cfg: BaseForgeConfig,
        run_args: Namespace,
        results_dir: Path,
        *items: object,
        **kwargs: object,
    ) -> dict[str, object]:
        calls.append("run")
        assert cfg.extra["consumed_engine_authorization"] == envelope.decision_id
        assert results_dir == expected_results
        return {"status": "completed"}

    async def _noop_web_preparation(*items: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(engine_module, "_consume_engine_authorization", _tracked_consume)
    monkeypatch.setattr(engine_module, setup_name, _setup)
    monkeypatch.setattr(engine_module, "run_scan", _run)
    if engine == "webforge":
        monkeypatch.setattr(
            engine_module,
            "prepare_browser_context",
            _noop_web_preparation,
        )
        monkeypatch.setattr(
            engine_module,
            "prepare_api_schema_context",
            _noop_web_preparation,
        )

    run_kwargs: dict[str, object] = {}
    if engine == "webforge":
        run_kwargs["on_results_ready"] = lambda: calls.append("ready")
    result = asyncio.run(
        engine_module.run_for_target(  # type: ignore[attr-defined]
            SimpleNamespace(target=target, options={}),
            args,
            **run_kwargs,
        )
    )

    assert result["status"] == "completed"
    if engine == "webforge":
        expected_calls = ["consume", "ready", "results", "run"]
    else:
        expected_calls = ["consume", "results", "run"]
    assert calls == expected_calls


@pytest.mark.parametrize(
    ("engine_module", "engine", "target"),
    [
        (webforge, "webforge", LAB_WEB_TARGET),
        (netforge, "netforge", LAB_NET_TARGET),
        (adforge, "adforge", LAB_NET_TARGET),
        (aiforge, "aiforge", LAB_WEB_TARGET),
    ],
)
def test_bound_module_set_allows_only_requested_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    engine_module: object,
    engine: str,
    target: str,
) -> None:
    confirmation = _confirmation(target, engine)
    cfg = _authorized_config(
        tmp_path,
        monkeypatch,
        target,
        engine,
        confirmation,
        modules=["probe"],
    )
    engine_decision = engine_module._consume_engine_authorization(cfg)  # type: ignore[attr-defined]
    assert engine_decision.allowed

    allowed = engine_module._authorize_module_execution(  # type: ignore[attr-defined]
        cfg,
        engine_decision.envelope,
        "probe",
    )
    denied = engine_module._authorize_module_execution(  # type: ignore[attr-defined]
        cfg,
        engine_decision.envelope,
        "different_module",
    )

    assert allowed.allowed
    assert denied.allowed is False
    assert denied.reason_code == AuthorizationReason.MODULE_MISMATCH.value


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("tenant_id", "tenant-other", AuthorizationReason.TENANT_MISMATCH),
        (
            "engagement_id",
            "engagement-other",
            AuthorizationReason.ENGAGEMENT_MISMATCH,
        ),
        ("run_id", "run-other", AuthorizationReason.RUN_MISMATCH),
        ("operator_id", "operator-other", AuthorizationReason.OPERATOR_MISMATCH),
        ("operator_role", "admin", AuthorizationReason.ROLE_MISMATCH),
        (
            "scope_policy_version",
            "scope-policy-other",
            AuthorizationReason.SCOPE_POLICY_MISMATCH,
        ),
        ("safety_mode", "passive", AuthorizationReason.SAFETY_MODE_MISMATCH),
    ],
)
def test_engine_rejects_runtime_facts_that_differ_from_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    reason: AuthorizationReason,
) -> None:
    confirmation = _confirmation(LAB_NET_TARGET, "netforge")
    cfg = _authorized_config(
        tmp_path,
        monkeypatch,
        LAB_NET_TARGET,
        "netforge",
        confirmation,
    )
    runtime = dict(cfg.extra["authorization_runtime"])
    runtime[field] = value
    cfg.extra["authorization_runtime"] = runtime

    denied = netforge._consume_engine_authorization(cfg)

    assert denied.allowed is False
    assert denied.reason_code == reason.value


def test_engine_binds_actual_credential_reference_without_serializing_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "CANARY_RUNTIME_PASSWORD_002"
    credential_reference = protected_credential_reference({"password": secret})
    confirmation = _confirmation(LAB_WEB_TARGET, "webforge")
    cfg = _authorized_config(
        tmp_path,
        monkeypatch,
        LAB_WEB_TARGET,
        "webforge",
        confirmation,
        credential_reference=credential_reference,
    )

    allowed = webforge._consume_engine_authorization(cfg)

    assert allowed.allowed is True
    assert secret not in allowed.envelope.to_json()

    other_confirmation = ActionConfirmation.create(
        job_id="job-webforge-credential-mutation",
        target=LAB_WEB_TARGET,
        engine="webforge",
        action="scan",
    )
    mutated = _authorized_config(
        tmp_path,
        monkeypatch,
        LAB_WEB_TARGET,
        "webforge",
        other_confirmation,
        credential_reference=credential_reference,
    )
    mutated.extra["runtime_credential_reference"] = protected_credential_reference(
        {"password": "different-fixture-value"}
    )

    denied = webforge._consume_engine_authorization(mutated)

    assert denied.allowed is False
    assert denied.reason_code == AuthorizationReason.APPROVAL_MISMATCH.value


@pytest.mark.parametrize(
    ("engine_module", "engine", "target", "action", "args"),
    [
        (webforge, "webforge", LAB_WEB_TARGET, "retest", _web_args()),
        (netforge, "netforge", LAB_NET_TARGET, "retest", _net_args()),
        (netforge, "netforge", LAB_NET_TARGET, "web_to_network", _net_args()),
    ],
)
def test_trusted_nondefault_actions_are_revalidated_at_engine_boundary(
    engine_module: object,
    engine: str,
    target: str,
    action: str,
    args: Namespace,
) -> None:
    confirmation = _confirmation(target, engine, action)
    cfg = _configured(target, confirmation)

    decision = engine_module._launch_decision(cfg, args)  # type: ignore[attr-defined]

    assert decision.allowed is True
    assert decision.reason_code == ScopeReason.ALLOWED.value


def test_webforge_missing_confirmation_stops_before_any_execution_resource(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        webforge,
        "_get_event_bus",
        lambda *args, **kwargs: pytest.fail("denial must precede event resources"),
    )
    monkeypatch.setattr(
        webforge,
        "create_db",
        lambda *args, **kwargs: pytest.fail("denial must precede database resources"),
    )
    monkeypatch.setattr(
        webforge,
        "load_module_class",
        lambda *args, **kwargs: pytest.fail("denial must precede module loading"),
    )

    result = asyncio.run(webforge.run_scan(_configured(LAB_WEB_TARGET), _web_args(), tmp_path))

    assert result["status"] == "not_authorized"
    assert result["reason_code"] == ScopeReason.MISSING_CONFIRMATION.value


def test_webforge_programmatic_target_missing_scope_stops_before_results_or_browser(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    entry = SimpleNamespace(target=LAB_WEB_TARGET, options={})
    args = _web_args(scope=[])
    monkeypatch.setattr(
        webforge,
        "setup_results_dir",
        lambda *args, **kwargs: pytest.fail("denial must precede results setup"),
    )
    monkeypatch.setattr(
        webforge,
        "prepare_browser_context",
        lambda *args, **kwargs: pytest.fail("denial must precede browser setup"),
    )

    result = asyncio.run(webforge.run_for_target(entry, args))

    assert result["status"] == "not_authorized"
    assert result["reason_code"] == ScopeReason.MISSING_SCOPE.value
    session = create_authorization_db(
        Path(os.environ[AUTHORIZATION_DB_ENV])
    )
    try:
        rows = session.query(AuthorizationDecisionModel).all()
        assert len(rows) == 1
        assert rows[0].reason_code == ScopeReason.MISSING_SCOPE.value
    finally:
        session.close()


def test_webforge_per_target_options_cannot_clear_base_exclusion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(
        target=LAB_WEB_TARGET,
        options={
            "scope": ["0.0.0.0/0"],
            "exclude": [],
            "target": "http://127.0.0.2:8080/fixture",
            "dry_run": False,
        },
    )
    args = _web_args(
        scope=["127.0.0.0/8"],
        exclude=["127.0.0.1/32"],
        dry_run=True,
    )
    monkeypatch.setattr(
        webforge,
        "setup_results_dir",
        lambda *args, **kwargs: pytest.fail("protected options must deny before results setup"),
    )

    result = asyncio.run(webforge.run_for_target(entry, args))

    assert result["status"] == "not_authorized"
    assert result["reason_code"] == ScopeReason.EXCLUDED.value


def test_webforge_scoped_dry_run_is_nonexecuting_and_not_authorized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = SimpleNamespace(number=1, name="fixture", modules=["probe"])
    monkeypatch.setattr(webforge, "get_phases", lambda *args, **kwargs: [phase])
    monkeypatch.setattr(
        webforge,
        "_get_event_bus",
        lambda *args, **kwargs: pytest.fail("dry-run must not create event resources"),
    )
    monkeypatch.setattr(
        webforge,
        "create_db",
        lambda *args, **kwargs: pytest.fail("dry-run must not create a scan database"),
    )
    monkeypatch.setattr(
        webforge,
        "load_module_class",
        lambda *args, **kwargs: pytest.fail("dry-run must not load modules"),
    )

    result = asyncio.run(
        webforge.run_scan(
            _configured(LAB_WEB_TARGET),
            _web_args(dry_run=True),
            tmp_path,
        )
    )

    assert result["status"] == "completed"
    assert result["dry_run"] is True
    assert result["authorized"] is False
    assert result["plan"]["authorized"] is False


def test_webforge_whitebox_modules_run_through_normal_authorized_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    confirmation = _confirmation(LAB_WEB_TARGET, "webforge")
    modules = ["secret_scan", "dep_audit"]
    source_root = tmp_path / "approved-source"
    source_root.mkdir()
    (source_root / "settings.py").write_text(
        'password="CANARY_WHITEBOX_DISPATCH_SECRET_007"\n',
        encoding="utf-8",
    )
    (source_root / "requirements.txt").write_text(
        "fixture==1.0\n",
        encoding="utf-8",
    )
    cfg = _authorized_config(
        tmp_path,
        monkeypatch,
        LAB_WEB_TARGET,
        "webforge",
        confirmation,
        modules=modules,
    )
    cfg.mode = "whitebox"
    cfg.extra["source_root"] = str(source_root.resolve())

    monkeypatch.setattr(webforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(
        webforge,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )
    monkeypatch.setattr(webforge, "_get_eng_bus", lambda: None)

    loaded: list[str] = []
    instances: dict[str, BaseModule] = {}
    original_loader = webforge.load_module_class
    original_base_init = BaseModule.__init__

    def tracked_base_init(self: BaseModule, *items: object, **kwargs: object) -> None:
        original_base_init(self, *items, **kwargs)  # type: ignore[arg-type]
        if self.NAME in modules:
            instances[self.NAME] = self

    def tracked_loader(module_name: str):
        loaded.append(module_name)
        return original_loader(module_name)

    monkeypatch.setattr(BaseModule, "__init__", tracked_base_init)
    monkeypatch.setattr(webforge, "load_module_class", tracked_loader)

    result = asyncio.run(
        webforge.run_scan(
            cfg,
            _web_args(mode="whitebox", modules=",".join(modules)),
            tmp_path,
        )
    )

    assert result["status"] == "completed"
    assert result["errors"] == []
    assert loaded == modules
    assert set(instances) == set(modules)
    for module_name in modules:
        instance = instances[module_name]
        assert instance.authorization_envelope is not None
        assert instance.authorization_context is not None
        assert instance.authorization_context.action_kind == "module.execute"
        assert instance.authorization_context.module_id == module_name
        assert instance.authorization_boundary == "webforge.module"
        assert instance.outbound_policy is None
    assert calls.count("db_add") >= 1
    assert calls.count("report") == 1
    from webforge.modules.whitebox import dep_audit, secret_scan

    def replay_reached_body(value: object) -> object:
        pytest.fail(f"replayed local module reached original body: {value!r}")

    monkeypatch.setattr(secret_scan, "require_approved_source_root", replay_reached_body)
    monkeypatch.setattr(dep_audit, "require_approved_source_root", replay_reached_body)
    for module_name in modules:
        instance = instances[module_name]
        replay_dir = tmp_path / f"replay-{module_name}"
        reconstructed = type(instance)(
            config=instance.config,
            scope=instance.scope,
            db_session=_FakeDB([]),  # type: ignore[arg-type]
            results_dir=replay_dir,
            run_id=instance.run_id,
        )
        repeated_result = asyncio.run(instance.run())
        reconstructed_result = asyncio.run(reconstructed.run())
        for denied in (repeated_result, reconstructed_result):
            assert denied.skipped is True
            assert denied.skip_reason == "authorization_invalid"
            assert denied.errors == ["authorization_invalid"]
        assert replay_dir.exists() is False


def test_webforge_exact_loopback_confirmation_reaches_mocked_module_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    confirmation = _confirmation(LAB_WEB_TARGET, "webforge")
    phase = SimpleNamespace(number=1, name="fixture", modules=["probe"])

    class FakeModule:
        def __init__(self, **kwargs: object) -> None:
            calls.append("module_init")

        async def run(self) -> ModuleResult:
            calls.append("module_run")
            return ModuleResult("probe")

    monkeypatch.setattr(webforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(webforge, "get_phases", lambda *args, **kwargs: [phase])
    monkeypatch.setattr(webforge, "load_module_class", lambda name: FakeModule)
    monkeypatch.setattr(
        webforge,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )
    monkeypatch.setattr(webforge, "_get_eng_bus", lambda: None)

    result = asyncio.run(
        webforge.run_scan(
            _authorized_config(
                tmp_path,
                monkeypatch,
                LAB_WEB_TARGET,
                "webforge",
                confirmation,
            ),
            _web_args(),
            tmp_path,
        )
    )

    assert result["status"] == "completed"
    assert calls.count("module_init") == 1
    assert calls.count("module_run") == 1


def test_webforge_module_result_errors_fail_terminal_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    events: list[str] = []
    confirmation = _confirmation(LAB_WEB_TARGET, "webforge")
    phase = SimpleNamespace(number=1, name="fixture", modules=["probe"])

    class ErrorResultModule:
        def __init__(self, **kwargs: object) -> None:
            pass

        async def run(self) -> ModuleResult:
            return ModuleResult(
                "probe",
                errors=["token=CANARY_WEBFORGE_RESULT_ERROR"],
            )

    monkeypatch.setattr(webforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(webforge, "get_phases", lambda *args, **kwargs: [phase])
    monkeypatch.setattr(webforge, "load_module_class", lambda name: ErrorResultModule)
    monkeypatch.setattr(
        webforge,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )
    monkeypatch.setattr(webforge, "_get_eng_bus", lambda: None)
    monkeypatch.setattr(
        webforge,
        "_emit",
        lambda _b, _e, _t, etype, **_data: events.append(etype),
    )

    result = asyncio.run(
        webforge.run_scan(
            _authorized_config(
                tmp_path,
                monkeypatch,
                LAB_WEB_TARGET,
                "webforge",
                confirmation,
                modules=["probe"],
            ),
            _web_args(),
            tmp_path,
            event_bus=object(),
        )
    )

    assert result["status"] == "failed"
    assert "CANARY_WEBFORGE_RESULT_ERROR" not in repr(result)
    assert "<redacted>" in repr(result)
    assert "scan_interrupted" in events
    assert "scan_complete" not in events


def test_webforge_abort_reaches_running_module_outbound_callback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    confirmation = _confirmation(LAB_WEB_TARGET, "webforge")
    phase = SimpleNamespace(number=1, name="fixture", modules=["probe"])
    control = webforge.ScanControl()
    entered = asyncio.Event()

    class FakeModule:
        def __init__(self, **kwargs: object) -> None:
            config = kwargs["config"]
            assert isinstance(config, BaseForgeConfig)
            callback = config.extra.get("outbound_cancellation_check")
            assert callable(callback)
            self.cancelled = callback
            calls.append("module_init")

        async def run(self) -> ModuleResult:
            calls.append("module_run")
            entered.set()
            while not self.cancelled():
                await asyncio.sleep(0)
            calls.append("module_cancelled")
            return ModuleResult("probe")

    monkeypatch.setattr(webforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(webforge, "get_phases", lambda *args, **kwargs: [phase])
    monkeypatch.setattr(webforge, "load_module_class", lambda name: FakeModule)
    monkeypatch.setattr(
        webforge,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )
    monkeypatch.setattr(webforge, "_get_eng_bus", lambda: None)

    async def exercise() -> dict[str, object]:
        task = asyncio.create_task(
            webforge.run_scan(
                _authorized_config(
                    tmp_path,
                    monkeypatch,
                    LAB_WEB_TARGET,
                    "webforge",
                    confirmation,
                ),
                _web_args(),
                tmp_path,
                scan_control=control,
            )
        )
        await asyncio.wait_for(entered.wait(), timeout=1.0)
        control.abort()
        return await asyncio.wait_for(task, timeout=1.0)

    result = asyncio.run(exercise())

    assert result["status"] == "aborted"
    assert result["errors"] == []
    assert calls.count("module_init") == 1
    assert calls.count("module_run") == 1
    assert calls.count("module_cancelled") == 1


def test_netforge_missing_scope_stops_before_opsec_event_db_or_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _configured(LAB_NET_TARGET, _confirmation(LAB_NET_TARGET, "netforge"))
    cfg.extra["allowed_scope"] = []
    monkeypatch.setattr(
        netforge,
        "_get_event_bus",
        lambda *args, **kwargs: pytest.fail("denial must precede event resources"),
    )
    monkeypatch.setattr(
        netforge,
        "_import_opsec",
        lambda: pytest.fail("denial must precede OpSec creation"),
    )
    monkeypatch.setattr(
        netforge,
        "create_db",
        lambda *args, **kwargs: pytest.fail("denial must precede database resources"),
    )
    monkeypatch.setattr(
        netforge,
        "load_module",
        lambda *args, **kwargs: pytest.fail("denial must precede module loading"),
    )

    result = asyncio.run(netforge.run_scan(cfg, _net_args(scope=[]), tmp_path))

    assert result["status"] == "not_authorized"
    assert result["reason_code"] == ScopeReason.MISSING_SCOPE.value


def test_netforge_programmatic_target_missing_scope_stops_before_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(target=LAB_NET_TARGET, options={})
    args = _net_args(scope=[])
    monkeypatch.setattr(
        netforge,
        "setup_results",
        lambda *args, **kwargs: pytest.fail("denial must precede results setup"),
    )

    result = asyncio.run(netforge.run_for_target(entry, args))

    assert result["status"] == "not_authorized"
    assert result["reason_code"] == ScopeReason.MISSING_SCOPE.value


def test_netforge_per_target_options_cannot_clear_base_exclusion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(
        target=LAB_NET_TARGET,
        options={
            "scope": ["0.0.0.0/0"],
            "exclude": [],
            "target": "127.0.0.2",
            "dry_run": False,
        },
    )
    args = _net_args(
        scope=["127.0.0.0/8"],
        exclude=["127.0.0.1/32"],
        dry_run=True,
    )
    monkeypatch.setattr(
        netforge,
        "setup_results",
        lambda *args, **kwargs: pytest.fail("protected options must deny before results setup"),
    )

    result = asyncio.run(netforge.run_for_target(entry, args))

    assert result["status"] == "not_authorized"
    assert result["reason_code"] == ScopeReason.EXCLUDED.value


def test_netforge_scoped_dry_run_creates_no_active_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(netforge, "PHASES", [(1, "fixture", ["probe"])])
    monkeypatch.setattr(
        netforge,
        "_get_event_bus",
        lambda *args, **kwargs: pytest.fail("dry-run must not create event resources"),
    )
    monkeypatch.setattr(
        netforge,
        "_import_opsec",
        lambda: pytest.fail("dry-run must not create OpSec resources"),
    )
    monkeypatch.setattr(
        netforge,
        "create_db",
        lambda *args, **kwargs: pytest.fail("dry-run must not create a scan database"),
    )
    monkeypatch.setattr(
        netforge,
        "load_module",
        lambda *args, **kwargs: pytest.fail("dry-run must not load modules"),
    )
    monkeypatch.setattr(
        netforge,
        "BaseReporter",
        lambda *args, **kwargs: pytest.fail("dry-run must not generate reports"),
    )

    result = asyncio.run(
        netforge.run_scan(
            _configured(LAB_NET_TARGET),
            _net_args(dry_run=True),
            tmp_path,
        )
    )

    assert result["status"] == "completed"
    assert result["dry_run"] is True
    assert result["authorized"] is False
    assert result["plan"]["authorized"] is False


def test_netforge_exact_loopback_confirmation_reaches_mocked_module_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    confirmation = _confirmation(LAB_NET_TARGET, "netforge")

    class FakeOpsec:
        level = SimpleNamespace(value="normal")
        max_threads = 1
        suppress_console = False
        stats = {"requests": 0, "decoys_injected": 0}

        def shuffle_modules(self, modules: list[str]) -> list[str]:
            return modules

        async def maybe_inject_decoy(self) -> None:
            calls.append("opsec_decoy_gate")

        async def jitter(self) -> None:
            calls.append("opsec_jitter_gate")

    class FakeModule:
        def __init__(self, **kwargs: object) -> None:
            calls.append("module_init")

        async def run(self) -> ModuleResult:
            calls.append("module_run")
            return ModuleResult("probe")

    monkeypatch.setattr(netforge, "PHASES", [(1, "fixture", ["probe"])])
    monkeypatch.setattr(netforge, "load_module", lambda name: FakeModule)
    monkeypatch.setattr(netforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(netforge, "_import_opsec", lambda: (lambda level: FakeOpsec()))
    monkeypatch.setattr(netforge, "_import_stealth", lambda: (None, None))
    monkeypatch.setattr(netforge, "_import_cred_engine", lambda: None)
    monkeypatch.setattr(netforge, "_import_attack_chain", lambda: None)
    monkeypatch.setattr(netforge, "_import_transport_manager", lambda: None)
    monkeypatch.setattr(netforge, "_import_session_cleanup", lambda: None)
    monkeypatch.setattr(netforge, "_get_eng_bus", lambda: None)
    monkeypatch.setattr(
        netforge,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )

    result = asyncio.run(
        netforge.run_scan(
            _authorized_config(
                tmp_path,
                monkeypatch,
                LAB_NET_TARGET,
                "netforge",
                confirmation,
            ),
            _net_args(),
            tmp_path,
        )
    )

    assert result["findings"] == 0
    assert calls.count("module_init") == 1
    assert calls.count("module_run") == 1


def test_netforge_manual_auto_confirm_only_synthesizes_scan_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _net_args(
        target=LAB_NET_TARGET,
        auto_confirm=True,
    )
    monkeypatch.delenv("FORGE_LAUNCH_CONFIRMATIONS", raising=False)

    decision, confirmations = netforge._prepare_cli_confirmation(args)

    assert decision.allowed is True
    assert len(confirmations) == 1
    assert confirmations[0].action == "scan"
    assert confirmations[0].action != "web_to_network"


def test_netforge_inherited_confirmation_uses_independent_expected_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from common.confirm_gate import (
        LAUNCH_ACTION_ENV,
        LAUNCH_CONFIRMATIONS_ENV,
        LAUNCH_JOB_ID_ENV,
        encode_launch_confirmations,
    )

    confirmation = ActionConfirmation.create(
        job_id="confirmed-job",
        target=LAB_NET_TARGET,
        engine="netforge",
        action="scan",
    )
    monkeypatch.setenv(
        LAUNCH_CONFIRMATIONS_ENV,
        encode_launch_confirmations([confirmation]),
    )
    monkeypatch.setenv(LAUNCH_JOB_ID_ENV, "different-job")
    monkeypatch.setenv(LAUNCH_ACTION_ENV, "scan")
    args = _net_args(target=LAB_NET_TARGET)

    decision, confirmations = netforge._prepare_cli_confirmation(args)

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.JOB_MISMATCH.value
    assert confirmations == []


@pytest.mark.parametrize(
    ("engine_module", "engine", "target", "args"),
    [
        (adforge, "adforge", LAB_NET_TARGET, _ad_args()),
        (aiforge, "aiforge", LAB_WEB_TARGET, _ai_args()),
    ],
)
def test_ad_and_ai_missing_envelope_stop_before_execution_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    engine_module: object,
    engine: str,
    target: str,
    args: Namespace,
) -> None:
    confirmation = _confirmation(target, engine)
    cfg = _configured(target, confirmation)
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(tmp_path / f"{engine}-missing.db"))
    monkeypatch.setattr(
        engine_module,
        "_get_event_bus",
        lambda *items, **kwargs: pytest.fail("denial must precede event resources"),
    )
    monkeypatch.setattr(
        engine_module,
        "create_db",
        lambda *items, **kwargs: pytest.fail("denial must precede scan database"),
    )

    result = asyncio.run(engine_module.run_scan(cfg, args, tmp_path))  # type: ignore[attr-defined]

    assert result["status"] == "not_authorized"
    assert result["reason_code"] == "legacy_not_authorized"


def test_adforge_exact_envelope_reaches_one_mocked_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    confirmation = _confirmation(LAB_NET_TARGET, "adforge")

    class FakeModule:
        def __init__(self, **kwargs: object) -> None:
            calls.append("module_init")

        async def run(self) -> ModuleResult:
            calls.append("module_run")
            return ModuleResult("probe")

    monkeypatch.setattr(adforge, "PHASES", [(1, "fixture", ["probe"], ["unauth"])])
    monkeypatch.setattr(adforge, "load_module", lambda name: FakeModule)
    monkeypatch.setattr(adforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(adforge, "_get_eng_bus", lambda: None)
    monkeypatch.setattr(
        adforge,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )

    result = asyncio.run(
        adforge.run_scan(
            _authorized_config(
                tmp_path,
                monkeypatch,
                LAB_NET_TARGET,
                "adforge",
                confirmation,
            ),
            _ad_args(),
            tmp_path,
        )
    )

    assert result["findings"] == 0
    assert calls.count("module_init") == 1
    assert calls.count("module_run") == 1


def test_aiforge_exact_envelope_reaches_one_mocked_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    confirmation = _confirmation(LAB_WEB_TARGET, "aiforge")

    class FakeModule:
        def __init__(self, **kwargs: object) -> None:
            calls.append("module_init")

        async def run(self) -> ModuleResult:
            calls.append("module_run")
            return ModuleResult("probe")

    monkeypatch.setattr(
        aiforge,
        "PHASES",
        [{"number": 1, "name": "fixture", "modules": ["probe"]}],
    )
    monkeypatch.setattr(aiforge, "load_module_class", lambda name: FakeModule)
    monkeypatch.setattr(aiforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(
        aiforge,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )

    result = asyncio.run(
        aiforge.run_scan(
            _authorized_config(
                tmp_path,
                monkeypatch,
                LAB_WEB_TARGET,
                "aiforge",
                confirmation,
            ),
            _ai_args(),
            tmp_path,
        )
    )

    assert result["findings"] == 0
    assert calls.count("module_init") == 1
    assert calls.count("module_run") == 1


def test_netforge_report_failure_cleans_resources_and_preserves_primary_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    confirmation = _confirmation(LAB_NET_TARGET, "netforge")

    class FakeOpsec:
        level = SimpleNamespace(value="normal")
        max_threads = 1
        suppress_console = False
        stats = {"requests": 0, "decoys_injected": 0}

        def shuffle_modules(self, modules: list[str]) -> list[str]:
            return modules

    class FakeCredentialEngine:
        def __len__(self) -> int:
            return 0

        def wipe_all(self) -> None:
            calls.append("cred_wipe")
            if calls.count("cred_wipe") == 1:
                raise RuntimeError("credential cleanup failure")

    class FakeTransport:
        async def close_all(self) -> None:
            calls.append("transport_close")
            raise RuntimeError("transport cleanup failure")

        def add_ssh_creds(self, **kwargs: object) -> None:
            calls.append("transport_configured")

    class FailingReporter:
        def __init__(self, **kwargs: object) -> None:
            pass

        def generate_all(self) -> dict[str, Path]:
            raise RuntimeError("primary report failure")

    async def _session_cleanup() -> None:
        calls.append("session_close")
        raise RuntimeError("session cleanup failure")

    monkeypatch.setattr(netforge, "PHASES", [])
    monkeypatch.setattr(netforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(netforge, "_import_opsec", lambda: (lambda level: FakeOpsec()))
    monkeypatch.setattr(netforge, "_import_stealth", lambda: (None, None))
    monkeypatch.setattr(netforge, "_import_cred_engine", lambda: FakeCredentialEngine)
    monkeypatch.setattr(netforge, "_import_attack_chain", lambda: None)
    monkeypatch.setattr(netforge, "_import_transport_manager", lambda: FakeTransport)
    monkeypatch.setattr(netforge, "_import_session_cleanup", lambda: _session_cleanup)
    monkeypatch.setattr(netforge, "_get_eng_bus", lambda: None)
    monkeypatch.setattr(netforge, "BaseReporter", FailingReporter)

    args = _net_args(ssh_user="fixture-operator", ssh_pass=None)
    with pytest.raises(RuntimeError, match="primary report failure"):
        asyncio.run(
            netforge.run_scan(
                _authorized_config(
                    tmp_path,
                    monkeypatch,
                    LAB_NET_TARGET,
                    "netforge",
                    confirmation,
                    modules=["probe"],
                ),
                args,
                tmp_path,
            )
        )

    assert "transport_close" in calls
    assert "session_close" in calls
    assert "cred_wipe" in calls
    assert "db_close" in calls


def test_netforge_cancellation_cleans_resources_and_propagates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    confirmation = _confirmation(LAB_NET_TARGET, "netforge")

    class FakeOpsec:
        level = SimpleNamespace(value="normal")
        max_threads = 1
        suppress_console = False
        stats = {"requests": 0, "decoys_injected": 0}

        def shuffle_modules(self, modules: list[str]) -> list[str]:
            return modules

    class CancellingModule:
        def __init__(self, **kwargs: object) -> None:
            pass

        async def run(self) -> ModuleResult:
            raise asyncio.CancelledError

    monkeypatch.setattr(netforge, "PHASES", [(1, "fixture", ["probe"])])
    monkeypatch.setattr(netforge, "load_module", lambda name: CancellingModule)
    monkeypatch.setattr(netforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(netforge, "_import_opsec", lambda: (lambda level: FakeOpsec()))
    monkeypatch.setattr(netforge, "_import_stealth", lambda: (None, None))
    monkeypatch.setattr(netforge, "_import_cred_engine", lambda: None)
    monkeypatch.setattr(netforge, "_import_attack_chain", lambda: None)
    monkeypatch.setattr(netforge, "_import_transport_manager", lambda: None)
    monkeypatch.setattr(netforge, "_import_session_cleanup", lambda: None)
    monkeypatch.setattr(netforge, "_get_eng_bus", lambda: None)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            netforge.run_scan(
                _authorized_config(
                    tmp_path,
                    monkeypatch,
                    LAB_NET_TARGET,
                    "netforge",
                    confirmation,
                    modules=["probe"],
                ),
                _net_args(),
                tmp_path,
            )
        )
    assert calls.count("db_close") == 1


def test_adforge_report_failure_closes_database_and_preserves_primary_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    confirmation = _confirmation(LAB_NET_TARGET, "adforge")

    class FailingReporter:
        def __init__(self, **kwargs: object) -> None:
            pass

        def generate_all(self) -> dict[str, Path]:
            raise RuntimeError("primary AD report failure")

    monkeypatch.setattr(adforge, "PHASES", [])
    monkeypatch.setattr(adforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(adforge, "_get_eng_bus", lambda: None)
    monkeypatch.setattr(adforge, "BaseReporter", FailingReporter)

    with pytest.raises(RuntimeError, match="primary AD report failure"):
        asyncio.run(
            adforge.run_scan(
                _authorized_config(
                    tmp_path,
                    monkeypatch,
                    LAB_NET_TARGET,
                    "adforge",
                    confirmation,
                    modules=["probe"],
                ),
                _ad_args(),
                tmp_path,
            )
        )
    assert calls.count("db_close") == 1


def test_adforge_main_stops_event_bus_on_failure_without_masking_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeEventBus:
        def __init__(self, run_id: str) -> None:
            calls.append("event_init")

        def start(self) -> None:
            calls.append("event_start")

        def stop(self) -> None:
            calls.append("event_stop")
            raise RuntimeError("event cleanup failure")

    args = _programmatic_args("adforge", tmp_path)
    args.dashboard_url = None
    args.auto_confirm = True
    args.autopilot = True
    args.verbose = False

    async def _fail_scan(*items: object, **kwargs: object) -> dict[str, Any]:
        raise RuntimeError("primary AD scan failure")

    monkeypatch.setattr(adforge, "parse_args", lambda: args)
    monkeypatch.setattr(
        adforge,
        "_prepare_cli_confirmation",
        lambda _args: (SimpleNamespace(allowed=True), []),
    )
    monkeypatch.setattr(
        adforge,
        "_prepare_engine_authorization",
        lambda *_items: (SimpleNamespace(allowed=True), object()),
    )
    monkeypatch.setattr(adforge, "_apply_launch_context", lambda *items: None)
    monkeypatch.setattr(
        adforge,
        "_consume_engine_authorization",
        lambda _cfg: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(adforge, "setup_results", lambda *items: tmp_path)
    monkeypatch.setattr(adforge, "run_scan", _fail_scan)
    monkeypatch.setattr("common.dashboard.event_bus.EventBus", FakeEventBus)

    with pytest.raises(RuntimeError, match="primary AD scan failure"):
        asyncio.run(adforge.main())
    assert calls == ["event_init", "event_start", "event_stop"]


@pytest.mark.parametrize(
    "engine_module",
    [webforge, netforge, aiforge, adforge],
)
@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("completed", 0),
        ("failed", 1),
        ("not_authorized", 1),
        ("aborted", 1),
    ],
)
def test_engine_cli_exit_code_tracks_terminal_summary(
    engine_module: object,
    status: str,
    expected: int,
) -> None:
    assert engine_module._summary_exit_code({"status": status}) == expected  # type: ignore[attr-defined]


@pytest.mark.parametrize("failure_mode", ["exception", "result_errors"])
def test_netforge_failed_module_emits_interrupted_not_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    calls: list[str] = []
    events: list[str] = []
    confirmation = _confirmation(LAB_NET_TARGET, "netforge")

    class FakeOpsec:
        level = SimpleNamespace(value="normal")
        max_threads = 1
        suppress_console = False
        stats = {"requests": 0, "decoys_injected": 0}

        def shuffle_modules(self, modules: list[str]) -> list[str]:
            return modules

        async def maybe_inject_decoy(self) -> None:
            return None

        async def jitter(self) -> None:
            return None

    class FailingModule:
        def __init__(self, **kwargs: object) -> None:
            pass

        async def run(self) -> ModuleResult:
            if failure_mode == "exception":
                raise RuntimeError("password=CANARY_NETFORGE_MODULE_ERROR")
            return ModuleResult(
                "probe",
                errors=["password=CANARY_NETFORGE_MODULE_ERROR"],
            )

    monkeypatch.setattr(netforge, "PHASES", [(1, "fixture", ["probe"])])
    monkeypatch.setattr(netforge, "load_module", lambda name: FailingModule)
    monkeypatch.setattr(netforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(netforge, "_import_opsec", lambda: (lambda level: FakeOpsec()))
    monkeypatch.setattr(netforge, "_import_stealth", lambda: (None, None))
    monkeypatch.setattr(netforge, "_import_cred_engine", lambda: None)
    monkeypatch.setattr(netforge, "_import_attack_chain", lambda: None)
    monkeypatch.setattr(netforge, "_import_transport_manager", lambda: None)
    monkeypatch.setattr(netforge, "_import_session_cleanup", lambda: None)
    monkeypatch.setattr(netforge, "_get_eng_bus", lambda: None)
    monkeypatch.setattr(netforge, "_emit", lambda _b, _e, _t, etype, **_data: events.append(etype))
    monkeypatch.setattr(
        netforge,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )

    result = asyncio.run(
        netforge.run_scan(
            _authorized_config(
                tmp_path,
                monkeypatch,
                LAB_NET_TARGET,
                "netforge",
                confirmation,
                modules=["probe"],
            ),
            _net_args(),
            tmp_path,
            event_bus=object(),
        )
    )

    assert result["status"] == "failed"
    assert "CANARY_NETFORGE_MODULE_ERROR" not in repr(result)
    assert "<redacted>" in repr(result)
    assert "scan_interrupted" in events
    assert "scan_complete" not in events


@pytest.mark.parametrize("failure_mode", ["exception", "result_errors"])
@pytest.mark.parametrize(
    ("engine_module", "engine", "target", "args", "phases", "loader_name"),
    [
        (
            aiforge,
            "aiforge",
            LAB_WEB_TARGET,
            _ai_args(),
            [{"number": 1, "name": "fixture", "modules": ["probe"]}],
            "load_module_class",
        ),
        (
            adforge,
            "adforge",
            LAB_NET_TARGET,
            _ad_args(),
            [(1, "fixture", ["probe"], ["unauth"])],
            "load_module",
        ),
    ],
)
def test_ai_and_ad_failed_module_emit_interrupted_not_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    engine_module: object,
    engine: str,
    target: str,
    args: Namespace,
    phases: object,
    loader_name: str,
    failure_mode: str,
) -> None:
    calls: list[str] = []
    events: list[str] = []
    confirmation = _confirmation(target, engine)

    class FailingModule:
        def __init__(self, **kwargs: object) -> None:
            pass

        async def run(self) -> ModuleResult:
            if failure_mode == "exception":
                raise RuntimeError("token=CANARY_ENGINE_MODULE_ERROR")
            return ModuleResult(
                "probe",
                errors=["token=CANARY_ENGINE_MODULE_ERROR"],
            )

    monkeypatch.setattr(engine_module, "PHASES", phases)
    monkeypatch.setattr(engine_module, loader_name, lambda name: FailingModule)
    monkeypatch.setattr(engine_module, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(
        engine_module,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )
    monkeypatch.setattr(
        engine_module,
        "_emit",
        lambda _b, _e, _t, etype, **_data: events.append(etype),
    )
    if engine == "adforge":
        monkeypatch.setattr(adforge, "_get_eng_bus", lambda: None)

    result = asyncio.run(
        engine_module.run_scan(  # type: ignore[attr-defined]
            _authorized_config(
                tmp_path,
                monkeypatch,
                target,
                engine,
                confirmation,
                modules=["probe"],
            ),
            args,
            tmp_path,
            event_bus=object(),
        )
    )

    assert result["status"] == "failed"
    assert "CANARY_ENGINE_MODULE_ERROR" not in repr(result)
    assert "<redacted>" in repr(result)
    assert "scan_interrupted" in events
    assert "scan_complete" not in events


def test_netforge_abort_emits_only_aborted_terminal_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    events: list[str] = []
    confirmation = _confirmation(LAB_NET_TARGET, "netforge")

    class FakeOpsec:
        level = SimpleNamespace(value="normal")
        max_threads = 1
        suppress_console = False
        stats = {"requests": 0, "decoys_injected": 0}

        def shuffle_modules(self, modules: list[str]) -> list[str]:
            return modules

    control = netforge.ScanControl()
    control.abort()
    monkeypatch.setattr(netforge, "PHASES", [(1, "fixture", ["probe"])])
    monkeypatch.setattr(netforge, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(netforge, "_import_opsec", lambda: (lambda level: FakeOpsec()))
    monkeypatch.setattr(netforge, "_import_stealth", lambda: (None, None))
    monkeypatch.setattr(netforge, "_import_cred_engine", lambda: None)
    monkeypatch.setattr(netforge, "_import_attack_chain", lambda: None)
    monkeypatch.setattr(netforge, "_import_transport_manager", lambda: None)
    monkeypatch.setattr(netforge, "_import_session_cleanup", lambda: None)
    monkeypatch.setattr(netforge, "_get_eng_bus", lambda: None)
    monkeypatch.setattr(netforge, "_emit", lambda _b, _e, _t, etype, **_data: events.append(etype))
    monkeypatch.setattr(
        netforge,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )

    result = asyncio.run(
        netforge.run_scan(
            _authorized_config(
                tmp_path,
                monkeypatch,
                LAB_NET_TARGET,
                "netforge",
                confirmation,
                modules=["probe"],
            ),
            _net_args(),
            tmp_path,
            event_bus=object(),
            scan_control=control,
        )
    )

    assert result["status"] == "aborted"
    assert "scan_aborted" in events
    assert "scan_complete" not in events
    assert "scan_interrupted" not in events
    assert netforge._summary_exit_code(result) == 1


@pytest.mark.parametrize(
    ("engine_module", "engine", "target", "args", "phases"),
    [
        (
            aiforge,
            "aiforge",
            LAB_WEB_TARGET,
            _ai_args(),
            [{"number": 1, "name": "fixture", "modules": ["probe"]}],
        ),
        (
            adforge,
            "adforge",
            LAB_NET_TARGET,
            _ad_args(),
            [(1, "fixture", ["probe"], ["unauth"])],
        ),
    ],
)
def test_ai_and_ad_abort_emit_only_aborted_terminal_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    engine_module: object,
    engine: str,
    target: str,
    args: Namespace,
    phases: object,
) -> None:
    calls: list[str] = []
    events: list[str] = []
    confirmation = _confirmation(target, engine)
    control = engine_module.ScanControl()  # type: ignore[attr-defined]
    control.abort()
    monkeypatch.setattr(engine_module, "PHASES", phases)
    monkeypatch.setattr(engine_module, "create_db", lambda path: _FakeDB(calls))
    monkeypatch.setattr(
        engine_module,
        "BaseReporter",
        lambda **kwargs: _FakeReporter(calls, **kwargs),
    )
    monkeypatch.setattr(
        engine_module,
        "_emit",
        lambda _b, _e, _t, etype, **_data: events.append(etype),
    )
    if engine == "adforge":
        monkeypatch.setattr(adforge, "_get_eng_bus", lambda: None)

    result = asyncio.run(
        engine_module.run_scan(  # type: ignore[attr-defined]
            _authorized_config(
                tmp_path,
                monkeypatch,
                target,
                engine,
                confirmation,
                modules=["probe"],
            ),
            args,
            tmp_path,
            event_bus=object(),
            scan_control=control,
        )
    )

    assert result["status"] == "aborted"
    assert "scan_aborted" in events
    assert "scan_complete" not in events
    assert "scan_interrupted" not in events
    assert engine_module._summary_exit_code(result) == 1  # type: ignore[attr-defined]


def test_webforge_consumes_engine_envelope_before_browser_or_schema_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    confirmation = _confirmation(LAB_WEB_TARGET, "webforge")
    args = _web_args(
        target=LAB_WEB_TARGET,
        engagement="pytest",
        tester="boundary-tests",
        resume=None,
        output=str(tmp_path / "results"),
        config=None,
        rate=1.0,
        workers=1,
        verbose=False,
        quiet=True,
        proxy=None,
    )
    args._launch_confirmations = [confirmation]
    args._launch_job_id = confirmation.job_id
    args._launch_action = confirmation.action
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(tmp_path / "web-preflight.db"))
    monkeypatch.setattr(
        webforge,
        "prepare_browser_context",
        lambda *items, **kwargs: pytest.fail("browser I/O preceded authorization"),
    )
    monkeypatch.setattr(
        webforge,
        "prepare_api_schema_context",
        lambda *items, **kwargs: pytest.fail("schema I/O preceded authorization"),
    )

    entry = SimpleNamespace(target=LAB_WEB_TARGET, options={})
    result = asyncio.run(webforge.run_for_target(entry, args))

    assert result["status"] == "not_authorized"
    assert result["reason_code"] == "legacy_not_authorized"


def test_raw_module_decision_string_cannot_authorize_sensitive_prompt(
    tmp_path: Path,
) -> None:
    class ProbeModule(BaseModule):
        NAME = "probe"

        async def run(self) -> ModuleResult:
            return ModuleResult(self.NAME)

    cfg = _configured(LAB_NET_TARGET)
    cfg.extra["authorized_module_decisions"] = {"probe": "forged-decision-id"}
    set_auto_confirm(True)
    try:
        module = ProbeModule(
            config=cfg,
            scope=Scope(LAB_SCOPE),
            db_session=_FakeDB([]),  # type: ignore[arg-type]
            results_dir=tmp_path,
            run_id="run-forged-marker",
        )

        assert module.confirm_action(
            action="sensitive fixture",
            target=LAB_NET_TARGET,
            risk="fixture",
        ) is False
    finally:
        set_auto_confirm(False)


def test_direct_legacy_modules_are_denied_before_raw_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aiohttp

    from leak_intel.scanners.crtsh_scanner import CrtshScanner
    from netforge.modules.discovery.port_scanner import PortScanner
    from webforge.core.source_root import canonical_source_root
    from webforge.modules.headers import cors_check
    from webforge.modules.recon.link_crawler import LinkCrawler
    from webforge.modules.whitebox import dep_audit, secret_scan

    calls: list[str] = []

    def forbidden_open_connection(*_args: object, **_kwargs: object) -> None:
        calls.append("open_connection")
        pytest.fail("direct legacy NetForge transport reached")

    def forbidden_client_session(*_args: object, **_kwargs: object) -> None:
        calls.append("client_session")
        pytest.fail("direct legacy WebForge transport reached")

    monkeypatch.setattr(asyncio, "open_connection", forbidden_open_connection)
    monkeypatch.setattr(
        aiohttp,
        "ClientSession",
        forbidden_client_session,
    )

    def forbidden_source_read(*_args: object, **_kwargs: object) -> None:
        calls.append("source_read")
        pytest.fail("direct local whitebox module reached its original run body")

    monkeypatch.setattr(secret_scan, "require_approved_source_root", forbidden_source_read)
    monkeypatch.setattr(dep_audit, "require_approved_source_root", forbidden_source_read)

    net_config = _configured(LAB_NET_TARGET)
    net_config.extra["live_hosts"] = ["192.0.2.123"]
    net_module = PortScanner(
        config=net_config,
        scope=Scope(LAB_SCOPE),
        db_session=_FakeDB([]),  # type: ignore[arg-type]
        results_dir=tmp_path / "net-direct",
    )
    net_result = asyncio.run(net_module.run())

    web_module = cors_check.CorsCheck(
        config=_configured(LAB_WEB_TARGET),
        scope=Scope(LAB_SCOPE),
        db_session=_FakeDB([]),  # type: ignore[arg-type]
        results_dir=tmp_path / "web-direct",
    )
    web_result = asyncio.run(web_module.run())

    supported_without_context = LinkCrawler(
        config=_configured(LAB_WEB_TARGET),
        scope=Scope(LAB_SCOPE),
        db_session=_FakeDB([]),  # type: ignore[arg-type]
        results_dir=tmp_path / "web-supported-direct",
    )
    supported_result = asyncio.run(supported_without_context.run())

    leak_module = CrtshScanner(
        config=_configured("https://fixture.invalid"),
        scope=Scope(["fixture.invalid"]),
        db_session=_FakeDB([]),  # type: ignore[arg-type]
        results_dir=tmp_path / "leak-direct",
    )
    leak_result = asyncio.run(leak_module.run())

    approved = tmp_path / "approved-source"
    approved.mkdir()
    (approved / "settings.py").write_text(
        'password="APPROVED_ROOT_ALONE_IS_NOT_AUTHORIZATION"\n',
        encoding="utf-8",
    )
    whitebox_config = _configured(LAB_WEB_TARGET)
    whitebox_config.mode = "whitebox"
    whitebox_config.extra["source_root"] = canonical_source_root(approved)
    secret_module = secret_scan.SecretScan(
        config=whitebox_config,
        scope=Scope(LAB_SCOPE),
        db_session=_FakeDB(calls),  # type: ignore[arg-type]
        results_dir=tmp_path / "secret-direct",
    )
    secret_result = asyncio.run(secret_module.run())
    dependency_module = dep_audit.DepAudit(
        config=whitebox_config,
        scope=Scope(LAB_SCOPE),
        db_session=_FakeDB(calls),  # type: ignore[arg-type]
        results_dir=tmp_path / "dependency-direct",
    )
    dependency_result = asyncio.run(dependency_module.run())

    assert net_module.authorization_envelope is None
    assert net_module.outbound_policy is None
    assert web_module.authorization_envelope is None
    assert web_module.outbound_policy is None
    assert supported_without_context.authorization_envelope is None
    assert supported_without_context.outbound_policy is None
    assert leak_module.authorization_envelope is None
    assert leak_module.outbound_policy is None
    assert secret_module.authorization_envelope is None
    assert secret_module.authorization_context is None
    assert secret_module.outbound_policy is None
    assert dependency_module.authorization_envelope is None
    assert dependency_module.authorization_context is None
    assert dependency_module.outbound_policy is None
    assert net_result.skipped is True
    assert web_result.skipped is True
    assert net_result.skip_reason == "outbound_policy_unsupported"
    assert web_result.skip_reason == "outbound_policy_unsupported"
    assert supported_result.skipped is True
    assert supported_result.skip_reason == "authorization_invalid"
    assert leak_result.skipped is True
    assert leak_result.skip_reason == "outbound_policy_unsupported"
    assert secret_result.skipped is True
    assert secret_result.skip_reason == "authorization_invalid"
    assert secret_result.errors == ["authorization_invalid"]
    assert dependency_result.skipped is True
    assert dependency_result.skip_reason == "authorization_invalid"
    assert dependency_result.errors == ["authorization_invalid"]
    assert (tmp_path / "secret-direct").exists() is False
    assert (tmp_path / "dependency-direct").exists() is False
    assert calls == []


def test_unknown_basemodule_engine_is_default_denied_before_run(tmp_path: Path) -> None:
    calls: list[str] = []

    async def fixture_run(self: BaseModule) -> ModuleResult:
        calls.append("run")
        return ModuleResult(self.NAME)

    unknown_module = type(
        "UnknownModule",
        (BaseModule,),
        {
            "__module__": "fixture_engine.modules.unknown",
            "NAME": "unknown",
            "run": fixture_run,
        },
    )
    instance = unknown_module(
        config=_configured(LAB_NET_TARGET),
        scope=Scope(LAB_SCOPE),
        db_session=_FakeDB([]),  # type: ignore[arg-type]
        results_dir=tmp_path / "unknown-engine",
    )

    result = asyncio.run(instance.run())

    assert result.skipped is True
    assert result.skip_reason == "outbound_policy_unsupported"
    assert calls == []
