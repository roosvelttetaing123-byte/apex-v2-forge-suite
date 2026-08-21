from __future__ import annotations

import argparse
import ast
import secrets
from pathlib import Path

import pytest

import forge
import common.action_authorization as action_authorization_module
from common.action_authorization import (
    AUTHORIZATION_DB_ENV,
    AUTHORIZATION_ENGAGEMENT_ENV,
    AUTHORIZATION_OPERATOR_ENV,
    AUTHORIZATION_ROLE_ENV,
    AUTHORIZATION_RUN_ENV,
    AUTHORIZATION_SAFETY_MODE_ENV,
    AUTHORIZATION_SCOPE_POLICY_ENV,
    AUTHORIZATION_TENANT_ENV,
    AuthorizationOutcome,
    AuthorizationPersistenceError,
    AuthorizationReason,
    load_authorization_envelopes,
)
from common.confirm_gate import (
    LAUNCH_ACTION_ENV,
    LAUNCH_JOB_ID_ENV,
    load_launch_confirmations,
)
from common.credential_boundary import resolved_process_credentials
from common.scope import ScopeReason, canonical_target
from common.db import (
    AuthorizationConsumptionModel,
    AuthorizationDecisionModel,
    create_db,
)


@pytest.fixture(autouse=True)
def _isolated_forge_authorization_db(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(
        AUTHORIZATION_DB_ENV,
        str(tmp_path / "forge-cli-authorization.db"),
    )


def test_port_accepts_valid_range() -> None:
    assert forge._port("1") == 1
    assert forge._port("65535") == 65535


def test_port_rejects_invalid_range() -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        forge._port("0")
    with pytest.raises(argparse.ArgumentTypeError):
        forge._port("65536")


def test_forwarded_option_allowlists_match_engine_parsers() -> None:
    engine_sources = {
        "web": Path("webforge/webforge.py"),
        "net": Path("netforge/netforge.py"),
        "ai": Path("aiforge/aiforge.py"),
        "ad": Path("adforge/adforge.py"),
    }
    root_parser = forge.build_parser()
    subparsers = next(
        action for action in root_parser._actions if action.dest == "command"
    ).choices

    for framework_key, relative_path in engine_sources.items():
        tree = ast.parse((forge.BASE_DIR / relative_path).read_text(encoding="utf-8"))
        parse_args = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "parse_args"
        )
        child_options = {
            argument.value
            for node in ast.walk(parse_args)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
            for argument in node.args
            if isinstance(argument, ast.Constant)
            and isinstance(argument.value, str)
            and argument.value.startswith("-")
        }
        parent_options = {
            option
            for action in subparsers[framework_key]._actions
            for option in action.option_strings
        }
        expected = (child_options - parent_options) | {"--help", "-h"}
        actual = set(
            forge._FORWARDED_VALUE_OPTIONS_BY_FRAMEWORK[framework_key]
        ) | set(forge._FORWARDED_FLAG_OPTIONS_BY_FRAMEWORK[framework_key])

        assert actual == expected


def test_target_file_ignores_comments_and_blanks(tmp_path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("\n# comment\nhttps://example.com\n10.0.0.1\n", encoding="utf-8")

    assert forge._read_targets_file(str(target_file)) == ["https://example.com", "10.0.0.1"]


def test_scan_input_requires_one_target_source(tmp_path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("https://example.com\n", encoding="utf-8")
    args = argparse.Namespace(
        target="https://example.com",
        targets=str(target_file),
        resume=None,
        parallel=3,
    )

    with pytest.raises(ValueError, match="only one"):
        forge._validate_common_scan_inputs(args)


def test_scan_input_rejects_empty_target_file(tmp_path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("\n# no targets\n", encoding="utf-8")
    args = argparse.Namespace(target=None, targets=str(target_file), resume=None, parallel=3)

    with pytest.raises(ValueError, match="no usable targets"):
        forge._validate_common_scan_inputs(args)


def test_scan_input_rejects_bad_url_scheme() -> None:
    args = argparse.Namespace(target="ftp://example.com", targets=None, resume=None, parallel=3)

    with pytest.raises(ValueError, match="unsupported URL scheme"):
        forge._validate_common_scan_inputs(args)


def test_high_risk_requires_flag_and_environment(monkeypatch) -> None:
    args = argparse.Namespace(red_team=True)

    monkeypatch.delenv("FORGE_ENABLE_HIGH_RISK", raising=False)
    assert forge._is_high_risk_enabled(args) is False

    monkeypatch.setenv("FORGE_ENABLE_HIGH_RISK", "1")
    assert forge._is_high_risk_enabled(args) is True


def test_payload_evasion_defaults_are_disabled() -> None:
    parser = forge.build_parser()
    args = parser.parse_args([
        "payload",
        "--red-team",
        "--lhost",
        "127.0.0.1",
    ])

    assert args.sandbox_detect is False
    assert args.amsi_bypass is False
    assert args.etw_bypass is False


def test_dashboard_no_auth_requires_loopback() -> None:
    assert forge._launch_web_dashboard(host="0.0.0.0", port=1337, auth=False) == 1


def test_dashboard_launchers_bind_state_to_resolved_tenant_without_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from common.dashboard import event_bus as event_bus_module
    from common.dashboard import server as server_module
    from common.dashboard import state_store as state_store_module
    from common.dashboard.tui import war_room_tui as tui_module

    buses: list[object] = []
    stores: list[object] = []
    servers: list[object] = []
    tui_launches: list[tuple[object, object]] = []
    asyncio_inputs: list[object] = []

    class FixtureEventBus:
        def __init__(self, *, run_id: str) -> None:
            self.run_id = run_id
            buses.append(self)

    class FixtureStateStore:
        def __init__(
            self,
            event_bus: object,
            *,
            framework: str,
            target: str,
            tenant_id: str,
        ) -> None:
            self.event_bus = event_bus
            self.framework = framework
            self.target = target
            self.tenant_id = tenant_id
            stores.append(self)

    class FixtureDashboardServer:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs
            servers.append(self)

        async def start(self) -> None:
            pytest.fail("dashboard regression started a server")

    def record_tui_launch(*, event_bus: object, state_store: object) -> None:
        tui_launches.append((event_bus, state_store))

    def suppress_server_start(awaitable: object) -> None:
        asyncio_inputs.append(awaitable)
        getattr(awaitable, "close")()

    monkeypatch.setenv("FORGE_TENANT_ID", " tenant-a ")
    monkeypatch.setattr(event_bus_module, "EventBus", FixtureEventBus)
    monkeypatch.setattr(state_store_module, "StateStore", FixtureStateStore)
    monkeypatch.setattr(server_module, "DashboardServer", FixtureDashboardServer)
    monkeypatch.setattr(tui_module, "launch_tui", record_tui_launch)
    monkeypatch.setattr(forge.asyncio, "run", suppress_server_start)
    monkeypatch.setattr(
        forge.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("dashboard regression launched a process"),
    )
    monkeypatch.setattr(
        forge.socket,
        "create_connection",
        lambda *args, **kwargs: pytest.fail("dashboard regression opened a network connection"),
    )

    assert forge._launch_web_dashboard() == 0
    assert forge._launch_tui_dashboard() == 0

    assert [getattr(bus, "run_id") for bus in buses] == ["dashboard", "tui"]
    assert [getattr(store, "tenant_id") for store in stores] == ["tenant-a", "tenant-a"]
    assert all(getattr(store, "framework") == "forge" for store in stores)
    assert all(getattr(store, "target") == "" for store in stores)
    assert getattr(stores[0], "event_bus") is buses[0]
    assert getattr(stores[1], "event_bus") is buses[1]
    server_kwargs = getattr(servers[0], "kwargs")
    assert server_kwargs["event_bus"] is buses[0]
    assert server_kwargs["state_store"] is stores[0]
    assert len(asyncio_inputs) == 1
    assert tui_launches == [(buses[1], stores[1])]


def test_kill_date_validation() -> None:
    forge._validate_kill_date("2026-06-23")

    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        forge._validate_kill_date("06/23/2026")


def test_scan_launch_missing_scope_reaches_no_process_or_dashboard(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path,
) -> None:
    args = forge.build_parser().parse_args([
        "web", "--target", "http://127.0.0.1:8080/fixture", "--auto-confirm",
    ])
    monkeypatch.delenv("FORGE_LAUNCH_CONFIRMATIONS", raising=False)
    db_path = tmp_path / "missing-scope-audit.db"
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(db_path))
    monkeypatch.setattr(
        forge.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("scope denial must precede subprocess creation"),
    )
    monkeypatch.setattr(
        forge,
        "_launch_dashboard_background",
        lambda *args, **kwargs: pytest.fail("scope denial must precede dashboard creation"),
    )

    assert forge.handle_scan(args, "web") == 1
    assert "missing_scope" in capsys.readouterr().out
    session = create_db(db_path)
    try:
        rows = session.query(AuthorizationDecisionModel).all()
        assert len(rows) == 1
        assert rows[0].reason_code == "missing_scope"
    finally:
        session.close()


def test_scoped_dry_run_is_local_and_not_authorized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = forge.build_parser().parse_args([
        "web",
        "--target", "http://127.0.0.1:8080/fixture",
        "--scope", "127.0.0.1/32",
        "--dry-run",
        "--dashboard",
    ])
    monkeypatch.setattr(
        forge.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("dry-run must not create a subprocess"),
    )
    monkeypatch.setattr(
        forge,
        "_launch_dashboard_background",
        lambda *args, **kwargs: pytest.fail("dry-run must not create a dashboard"),
    )

    assert forge.handle_scan(args, "web") == 0
    output = capsys.readouterr().out
    assert "no subprocess created" in output
    assert "Authorized: false" in output


def test_scoped_loopback_active_launch_passes_exact_confirmation_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = "http://127.0.0.1:8080/fixture"
    args = forge.build_parser().parse_args([
        "web",
        "--target", target,
        "--scope", "127.0.0.1/32",
        "--auto-confirm",
    ])
    calls: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(cmd: list[str], *, cwd: str, env: dict[str, str]):
        calls.append((cmd, env))
        return argparse.Namespace(returncode=0)

    monkeypatch.delenv("FORGE_LAUNCH_CONFIRMATIONS", raising=False)
    monkeypatch.setattr(forge.subprocess, "run", fake_run)

    assert forge.handle_scan(args, "web") == 0
    assert len(calls) == 1
    cmd, env = calls[0]
    assert ["--scope", "127.0.0.1/32"] == cmd[cmd.index("--scope"):cmd.index("--scope") + 2]
    confirmations = load_launch_confirmations(env)
    assert len(confirmations) == 1
    assert confirmations[0].target == canonical_target(target)
    for key in (
        AUTHORIZATION_TENANT_ENV,
        AUTHORIZATION_ENGAGEMENT_ENV,
        AUTHORIZATION_RUN_ENV,
        AUTHORIZATION_OPERATOR_ENV,
        AUTHORIZATION_ROLE_ENV,
        AUTHORIZATION_SCOPE_POLICY_ENV,
        AUTHORIZATION_SAFETY_MODE_ENV,
    ):
        assert env[key]
    assert confirmations[0].engine == "webforge"
    assert confirmations[0].action == "scan"
    assert env[LAUNCH_JOB_ID_ENV] == confirmations[0].job_id
    assert env[LAUNCH_ACTION_ENV] == "scan"


def test_unified_cli_binds_forwarded_credentials_without_logging_secret(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path,
) -> None:
    target = "http://127.0.0.1:8080/fixture"
    secret = "CANARY_FORGE_CLI_PASSWORD_002"
    args = forge.build_parser().parse_args(
        [
            "web",
            "--target",
            target,
            "--scope",
            "127.0.0.1/32",
            "--auto-confirm",
        ]
    )
    calls: list[dict[str, object]] = []

    def fake_run(cmd, *, cwd, env, pass_fds):
        child_env = dict(env)
        with resolved_process_credentials(child_env) as values:
            assert values == {"password": secret}
        calls.append({
            "cmd": list(cmd),
            "env": dict(env),
            "pass_fds": tuple(pass_fds),
        })
        return argparse.Namespace(returncode=0)

    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(tmp_path / "credential-cli.db"))
    monkeypatch.setattr(forge.subprocess, "run", fake_run)

    result = forge.handle_scan(
        args,
        "web",
        [
            "--auth-type",
            "form",
            "--username",
            "operator",
            "--password",
            secret,
        ],
    )

    assert result == 0
    envelopes = load_authorization_envelopes(calls[0]["env"])
    assert len(envelopes) == 1
    assert envelopes[0].credential_approval_required is True
    assert envelopes[0].credential_reference.startswith("cred:pipe:")
    assert secret not in envelopes[0].to_json()
    assert secret not in " ".join(calls[0]["cmd"])
    assert secret not in repr(calls[0]["env"])
    assert calls[0]["pass_fds"]
    assert secret not in capsys.readouterr().out


def test_unified_cli_rejects_inline_proxy_credentials_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = "http://127.0.0.1:8080/fixture"
    secret = "CANARY_FORGE_PROXY_PASSWORD"
    proxy = f"http://operator:{secret}@127.0.0.1:18080"
    calls: list[list[str]] = []
    args = forge.build_parser().parse_args(
        [
            "web",
            "--target",
            target,
            "--scope",
            "127.0.0.1/32",
            "--auto-confirm",
        ]
    )
    def fake_run(command: list[str], **_kwargs: object) -> argparse.Namespace:
        calls.append(list(command))
        return argparse.Namespace(returncode=0)

    monkeypatch.setattr(forge.subprocess, "run", fake_run)

    result = forge.handle_scan(args, "web", ["--proxy", proxy])
    output = capsys.readouterr().out

    assert result == 1
    assert calls == []
    assert secret not in output
    assert proxy not in output
    assert "inline credentials" in output
    assert secret not in forge._safe_command_display(
        ["python", "webforge.py", f"--https-proxy={proxy}"]
    )


def test_unified_cli_rejects_abbreviated_proxy_credentials_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = "http://127.0.0.1:8080/fixture"
    secret = "CANARY_ABBREVIATED_PROXY_PASSWORD"
    proxy = f"http://operator:{secret}@127.0.0.1:18080"
    calls: list[list[str]] = []
    args = forge.build_parser().parse_args(
        [
            "web",
            "--target",
            target,
            "--scope",
            "127.0.0.1/32",
            "--auto-confirm",
        ]
    )
    def fake_run(command: list[str], **_kwargs: object) -> argparse.Namespace:
        calls.append(list(command))
        return argparse.Namespace(returncode=0)

    monkeypatch.setattr(forge.subprocess, "run", fake_run)

    result = forge.handle_scan(args, "web", [f"--prox={proxy}"])
    output = capsys.readouterr().out

    assert result == 1
    assert calls == []
    assert "inline credentials" in output
    assert secret not in output
    assert proxy not in output
    assert secret not in forge._safe_command_display(
        ["python", "webforge.py", f"--prox={proxy}"]
    )


@pytest.mark.parametrize(
    "forwarded",
    [
        ["--proxyx={proxy}"],
        ["--proxyx", "{proxy}"],
        ["--route-url={proxy}"],
    ],
)
def test_unified_cli_rejects_proxy_credential_lookalikes_before_subprocess(
    forwarded: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = "http://127.0.0.1:8080/fixture"
    # Avoid relying on the broad CANARY_* scrubber: proxy-specific admission
    # and display handling must protect an otherwise ordinary marker.
    secret = f"SYNTHETIC_PROXY_MARKER_{secrets.token_hex(12)}"
    proxy = f"http://operator:{secret}@127.0.0.1:18080"
    arguments = [item.format(proxy=proxy) for item in forwarded]
    calls: list[list[str]] = []
    args = forge.build_parser().parse_args(
        [
            "web",
            "--target",
            target,
            "--scope",
            "127.0.0.1/32",
            "--auto-confirm",
        ]
    )
    def fake_run(command: list[str], **_kwargs: object) -> argparse.Namespace:
        calls.append(list(command))
        return argparse.Namespace(returncode=0)

    monkeypatch.setattr(forge.subprocess, "run", fake_run)

    result = forge.handle_scan(args, "web", arguments)
    output = capsys.readouterr().out

    assert result == 1
    assert calls == []
    assert "inline credentials" in output
    assert secret not in output
    assert proxy not in output
    safe_display = forge._safe_command_display(
        ["python", "webforge.py", *arguments]
    )
    assert secret not in safe_display
    assert proxy not in safe_display


def test_unified_cli_rejects_unknown_forwarded_option_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = forge.build_parser().parse_args(
        [
            "web",
            "--target",
            "http://127.0.0.1:8080/fixture",
            "--scope",
            "127.0.0.1/32",
            "--auto-confirm",
        ]
    )
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> argparse.Namespace:
        calls.append(list(command))
        return argparse.Namespace(returncode=0)

    monkeypatch.setattr(forge.subprocess, "run", fake_run)

    result = forge.handle_scan(args, "web", ["--unknown-child-option=value"])
    output = capsys.readouterr().out

    assert result == 1
    assert calls == []
    assert "unsupported" in output


def test_unified_cli_scrubs_ambient_proxy_environment_from_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = "http://127.0.0.1:8080/fixture"
    secret = "CANARY_AMBIENT_PROXY_PASSWORD"
    args = forge.build_parser().parse_args(
        [
            "web",
            "--target",
            target,
            "--scope",
            "127.0.0.1/32",
            "--auto-confirm",
        ]
    )
    captured: list[dict[str, str]] = []

    def fake_run(cmd, *, cwd, env):
        captured.append(env)
        return argparse.Namespace(returncode=0)

    monkeypatch.setenv(
        "HTTPS_PROXY",
        f"http://operator:{secret}@127.0.0.1:18080",
    )
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("THIRD_PARTY_PASSWORD", "AMBIENT_PROVIDER_SECRET")
    monkeypatch.setattr(forge.subprocess, "run", fake_run)

    assert forge.handle_scan(args, "web") == 0
    rendered = repr(captured[0])
    assert "HTTPS_PROXY" not in captured[0]
    assert "NO_PROXY" not in captured[0]
    assert "THIRD_PARTY_PASSWORD" not in captured[0]
    assert secret not in rendered


def test_background_dashboard_uses_explicit_environment_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    process = argparse.Namespace()

    def fake_popen(command, **kwargs):
        captured["command"] = list(command)
        captured["environment"] = dict(kwargs.get("env") or {})
        return process

    monkeypatch.delenv("FORGE_DASHBOARD_PASSWORD", raising=False)
    monkeypatch.setenv("FORGE_DASHBOARD_PASSWORD_HASH", "fixture-password-hash")
    monkeypatch.setenv("THIRD_PARTY_PASSWORD", "AMBIENT_PROVIDER_SECRET")
    monkeypatch.setattr(forge.subprocess, "Popen", fake_popen)

    assert forge._launch_dashboard_background(port=1337) is process
    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert environment["FORGE_DASHBOARD_PASSWORD_HASH"] == "fixture-password-hash"
    assert "THIRD_PARTY_PASSWORD" not in environment


def test_background_dashboard_launch_failure_logs_only_exception_type(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    exception_secret = "opaque-dashboard-launch-exception-5e794e6b"

    def fail_popen(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(exception_secret)

    monkeypatch.delenv("FORGE_DASHBOARD_PASSWORD", raising=False)
    monkeypatch.setenv("FORGE_DASHBOARD_PASSWORD_HASH", "fixture-password-hash")
    monkeypatch.setattr(forge.subprocess, "Popen", fail_popen)
    caplog.set_level(logging.WARNING, logger="forge")

    assert forge._launch_dashboard_background(port=1337) is None
    assert exception_secret not in caplog.text
    assert "RuntimeError" in caplog.text


def test_web_bare_hostname_is_normalized_before_parent_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = forge.build_parser().parse_args([
        "web",
        "--target", "app.example.test",
        "--scope", "example.test",
        "--auto-confirm",
    ])
    calls = []

    def fake_run(cmd, *, cwd, env):
        calls.append((cmd, env))
        return argparse.Namespace(returncode=0)

    monkeypatch.delenv("FORGE_LAUNCH_CONFIRMATIONS", raising=False)
    monkeypatch.setattr(forge.subprocess, "run", fake_run)

    assert forge.handle_scan(args, "web") == 0
    cmd, env = calls[0]
    child_target = cmd[cmd.index("--target") + 1]
    confirmation = load_launch_confirmations(env)[0]
    assert child_target == "https://app.example.test"
    assert confirmation.target == canonical_target(child_target)


def test_excluded_loopback_launch_reaches_no_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = forge.build_parser().parse_args([
        "net",
        "--target", "127.0.0.1",
        "--scope", "127.0.0.0/8",
        "--exclude", "127.0.0.1/32",
        "--auto-confirm",
    ])
    monkeypatch.setattr(
        forge.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("excluded target must not launch"),
    )

    assert forge.handle_scan(args, "net") == 1
    assert "excluded" in capsys.readouterr().out


def test_multi_target_prevalidation_rolls_back_entire_authorization_batch(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_file = tmp_path / "loopback-targets.txt"
    target_file.write_text("127.0.0.1\n127.0.0.2\n", encoding="utf-8")
    db_path = tmp_path / "multi-target-authorization.db"
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(db_path))
    args = forge.build_parser().parse_args(
        [
            "net",
            "--targets",
            str(target_file),
            "--scope",
            "127.0.0.1/32",
            "--auto-confirm",
        ]
    )
    subprocess_calls: list[str] = []

    def unexpected_subprocess(*args, **kwargs):
        subprocess_calls.append("called")
        pytest.fail("a partially valid target batch must not launch")

    monkeypatch.setattr(forge.subprocess, "run", unexpected_subprocess)
    monkeypatch.setattr(forge.subprocess, "Popen", unexpected_subprocess)

    assert forge.handle_scan(args, "net") == 1
    assert subprocess_calls == []

    session = create_db(db_path)
    try:
        decisions = session.query(AuthorizationDecisionModel).all()
        assert [row.decision_outcome for row in decisions] == [
            AuthorizationOutcome.DENY.value
        ]
        assert decisions[0].reason_code == ScopeReason.TARGET_MISMATCH.value
        assert decisions[0].requested_target == canonical_target("127.0.0.2")
        assert session.query(AuthorizationConsumptionModel).count() == 0
    finally:
        session.close()


def test_multi_target_persistence_failure_rolls_back_staged_authorizations(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_file = tmp_path / "allowed-loopback-targets.txt"
    target_file.write_text("127.0.0.1\n127.0.0.2\n", encoding="utf-8")
    db_path = tmp_path / "failed-batch-authorization.db"
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(db_path))
    args = forge.build_parser().parse_args(
        [
            "net",
            "--targets",
            str(target_file),
            "--scope",
            "127.0.0.0/30",
            "--auto-confirm",
        ]
    )
    subprocess_calls: list[str] = []

    def unexpected_subprocess(*args, **kwargs):
        subprocess_calls.append("called")
        pytest.fail("authorization persistence failure must prevent launch")

    real_append = action_authorization_module.append_authorization_decision
    append_calls = 0

    def fail_second_child(*args, **kwargs):
        nonlocal append_calls
        append_calls += 1
        if append_calls == 4:
            raise OSError("deterministic authorization persistence failure")
        return real_append(*args, **kwargs)

    monkeypatch.setattr(
        action_authorization_module,
        "append_authorization_decision",
        fail_second_child,
    )
    monkeypatch.setattr(forge.subprocess, "run", unexpected_subprocess)
    monkeypatch.setattr(forge.subprocess, "Popen", unexpected_subprocess)

    with pytest.raises(AuthorizationPersistenceError):
        forge.handle_scan(args, "net")
    assert subprocess_calls == []

    session = create_db(db_path)
    try:
        assert session.query(AuthorizationDecisionModel).count() == 0
        assert session.query(AuthorizationConsumptionModel).count() == 0
    finally:
        session.close()


def test_intel_sync_is_audited_and_denied_before_network_work(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from common.intel.intel_engine import IntelEngine

    db_path = tmp_path / "platform-authorization.db"
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(db_path))
    monkeypatch.setattr(
        IntelEngine,
        "sync",
        lambda *args, **kwargs: pytest.fail("legacy intel sync must not reach network work"),
    )
    args = forge.build_parser().parse_args(["intel", "sync", "--all"])

    assert forge.handle_intel(args) == 1

    session = create_db(db_path)
    try:
        record = session.query(AuthorizationDecisionModel).one()
        assert record.action_kind == "intel.sync"
        assert record.decision_outcome == AuthorizationOutcome.UNKNOWN_NOT_AUTHORIZED.value
        assert record.reason_code == AuthorizationReason.LEGACY_NOT_AUTHORIZED.value
    finally:
        session.close()


def test_payload_high_risk_booleans_cannot_replace_envelope(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge_payload.payload_factory import PayloadFactory

    db_path = tmp_path / "payload-authorization.db"
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(db_path))
    monkeypatch.setenv("FORGE_ENABLE_HIGH_RISK", "1")
    monkeypatch.setattr(
        PayloadFactory,
        "generate",
        lambda *args, **kwargs: pytest.fail("payload generation must remain blocked"),
    )
    args = forge.build_parser().parse_args(
        ["payload", "--red-team", "--lhost", "127.0.0.1"]
    )

    assert forge.handle_payload(args) == 1

    session = create_db(db_path)
    try:
        record = session.query(AuthorizationDecisionModel).one()
        assert record.action_kind == "payload.generate"
        assert record.reason_code == AuthorizationReason.LEGACY_NOT_AUTHORIZED.value
    finally:
        session.close()


def test_local_intel_search_remains_available(monkeypatch: pytest.MonkeyPatch) -> None:
    from common.intel.intel_engine import IntelEngine

    monkeypatch.setattr(IntelEngine, "search", lambda *args, **kwargs: ["fixture-result"])
    args = forge.build_parser().parse_args(["intel", "search", "fixture"])

    assert forge.handle_intel(args) == 0
