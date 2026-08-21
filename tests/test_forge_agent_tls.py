from __future__ import annotations

import argparse
import io
import ssl
from datetime import datetime, timedelta, timezone
from urllib import error as urllib_error

import pytest

import forge
import forge_agent
from webforge import webforge
from common.action_authorization import (
    AUTHORIZATION_DB_ENV,
    AUTHORIZATION_ENVELOPES_ENV,
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
)
from common.confirm_gate import (
    ActionConfirmation,
    LAUNCH_ACTION_ENV,
    LAUNCH_CONFIRMATIONS_ENV,
    LAUNCH_JOB_ID_ENV,
)
from common.db import AuthorizationDecisionModel, create_db
from common.scope import ScopeReason


@pytest.fixture(autouse=True)
def _isolated_authorization_db(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(
        AUTHORIZATION_DB_ENV,
        str(tmp_path / "forge-agent-test-authorization.db"),
    )


class _Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class _FakeContext:
    def __init__(self) -> None:
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED
        self.loaded_cert_chain = None

    def load_cert_chain(self, certfile, keyfile=None) -> None:
        self.loaded_cert_chain = (certfile, keyfile)


def _agent_args(**overrides) -> argparse.Namespace:
    args = {
        "dashboard_url": "https://dashboard.local:1337",
        "agent_id": "agent-1",
        "name": "",
        "engines": "webforge,netforge",
        "scope": "10.0.0.0/24",
        "exclude": [],
        "token": "",
        "interval": 5.0,
        "once": True,
        "allow_active_scans": False,
        "mtls_subject": "",
        "client_cert": "",
        "client_key": "",
        "ca_cert": "",
        "insecure_tls": False,
    }
    args.update(overrides)
    return argparse.Namespace(**args)


def test_agent_json_request_is_inert_without_control_plane_policy(monkeypatch) -> None:
    calls = []

    def fake_urlopen(req, **kwargs):
        calls.append((req, kwargs))
        return _Response(b"{}")

    monkeypatch.setattr(forge_agent.request, "urlopen", fake_urlopen)

    with pytest.raises(forge_agent.OutboundDenied) as denied:
        forge_agent._json_request("http://dashboard.local", "/api/v1/ping")

    assert denied.value.reason_code == "outbound_policy_unsupported"
    assert calls == []


def test_agent_json_request_never_opens_remote_error_body(monkeypatch) -> None:
    def fail_urlopen(req, **kwargs):
        raise urllib_error.HTTPError(
            req.full_url,
            403,
            "forbidden",
            {},
            io.BytesIO(b"Bearer CANARY_HTTP_ERROR_TOKEN_002"),
        )

    monkeypatch.setattr(forge_agent.request, "urlopen", fail_urlopen)

    with pytest.raises(forge_agent.OutboundDenied) as exc_info:
        forge_agent._json_request("http://dashboard.local", "/api/v1/ping")

    assert exc_info.value.reason_code == "outbound_policy_unsupported"
    assert "CANARY_HTTP_ERROR_TOKEN_002" not in str(exc_info.value)


def test_https_client_certificate_context_is_passed_to_urlopen(monkeypatch) -> None:
    loaded = {}
    context = _FakeContext()

    def fake_create_default_context(cafile=None):
        loaded["cafile"] = cafile
        return context

    monkeypatch.setattr(forge_agent.ssl, "create_default_context", fake_create_default_context)

    args = _agent_args(
        client_cert="/tmp/agent.crt",
        client_key="/tmp/agent.key",
        ca_cert="/tmp/lab-ca.pem",
    )

    built = forge_agent._build_ssl_context(args.dashboard_url, args)

    assert built is context
    assert loaded == {"cafile": "/tmp/lab-ca.pem"}
    assert context.loaded_cert_chain == ("/tmp/agent.crt", "/tmp/agent.key")

    calls = []

    def fake_urlopen(req, **kwargs):
        calls.append(kwargs)
        return _Response(b'{"ok": true}')

    monkeypatch.setattr(forge_agent.request, "urlopen", fake_urlopen)

    with pytest.raises(forge_agent.OutboundDenied):
        forge_agent._json_request(
            args.dashboard_url,
            "/api/v1/ping",
            ssl_context=built,
        )
    assert calls == []


def test_insecure_tls_disables_verification_for_https(monkeypatch) -> None:
    context = _FakeContext()
    monkeypatch.setattr(forge_agent.ssl, "create_default_context", lambda cafile=None: context)

    built = forge_agent._build_ssl_context(
        "https://dashboard.local",
        _agent_args(insecure_tls=True),
    )

    assert built is context
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_client_key_without_client_cert_is_rejected() -> None:
    args = _agent_args(client_key="/tmp/agent.key")

    with pytest.raises(ValueError, match="--client-key requires --client-cert"):
        forge_agent._build_ssl_context(args.dashboard_url, args)


def test_run_agent_stops_before_control_plane_network(monkeypatch) -> None:
    context = _FakeContext()
    calls = []

    monkeypatch.setattr(forge_agent, "_build_ssl_context", lambda base_url, args: context)

    def fake_json_request(base_url, path, **kwargs):
        calls.append((path, kwargs.get("ssl_context")))
        if path.endswith("/register"):
            return {"agent": {"id": "agent-1"}}
        return {"job": None}

    monkeypatch.setattr(forge_agent, "_json_request", fake_json_request)

    assert forge_agent.run_agent(_agent_args(once=True)) == 2
    assert calls == []


def test_scanner_process_renews_lease_while_running(monkeypatch) -> None:
    heartbeats = []

    class _Process:
        returncode = 0

        def __init__(self):
            self.calls = 0

        def communicate(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise forge_agent.subprocess.TimeoutExpired(["scanner"], timeout)
            return ("fixture complete\n", None)

        def poll(self):
            return None if self.calls < 2 else self.returncode

        def terminate(self):
            raise AssertionError("a valid renewed lease must not terminate the process")

    process = _Process()
    monkeypatch.setattr(forge_agent.subprocess, "Popen", lambda *args, **kwargs: process)

    result = forge_agent._run_with_lease_heartbeat(
        ["scanner"],
        cwd="/tmp",
        env={},
        heartbeat=lambda: heartbeats.append("renewed"),
        heartbeat_interval=0.25,
        timeout=5.0,
    )

    assert result.returncode == 0
    assert result.stdout == "fixture complete\n"
    assert heartbeats == ["renewed"]


def test_scanner_process_is_terminated_when_lease_renewal_fails(monkeypatch) -> None:
    terminated = []

    class _Process:
        returncode = -15

        def communicate(self, timeout=None):
            if terminated:
                return ("stopped\n", None)
            raise forge_agent.subprocess.TimeoutExpired(["scanner"], timeout)

        def poll(self):
            return self.returncode if terminated else None

        def terminate(self):
            terminated.append(True)

        def kill(self):
            raise AssertionError("graceful termination should be sufficient")

    monkeypatch.setattr(
        forge_agent.subprocess,
        "Popen",
        lambda *args, **kwargs: _Process(),
    )

    with pytest.raises(forge_agent.LeaseHeartbeatLost):
        forge_agent._run_with_lease_heartbeat(
            ["scanner"],
            cwd="/tmp",
            env={},
            heartbeat=lambda: (_ for _ in ()).throw(RuntimeError("revoked")),
            heartbeat_interval=0.25,
            timeout=5.0,
        )

    assert terminated == [True]


def test_forge_agent_subcommand_exposes_tls_flags() -> None:
    parser = forge.build_parser()
    args = parser.parse_args(
        [
            "agent",
            "--dashboard-url",
            "https://dashboard.local",
            "--scope",
            "10.0.0.0/24",
            "--client-cert",
            "agent.crt",
            "--client-key",
            "agent.key",
            "--ca-cert",
            "ca.pem",
            "--insecure-tls",
        ]
    )

    assert args.client_cert == "agent.crt"
    assert args.client_key == "agent.key"
    assert args.ca_cert == "ca.pem"
    assert args.insecure_tls is True


def _active_job(**overrides):
    target = "http://127.0.0.1:8080/fixture"
    job_id = "agent-local-active"
    values = {
        "id": job_id,
        "engine": "webforge",
        "target": target,
        "scope": ["127.0.0.1/32"],
        "excluded_scope": ["127.0.0.2/32"],
        "modules": ["header_audit"],
        "action": "scan",
        "safety_mode": "active",
        "dry_run": False,
        "confirmation": ActionConfirmation.create(
            job_id=job_id,
            target=target,
            engine="webforge",
            action="scan",
        ).to_dict(),
    }
    values.update(overrides)
    return values


def _authorized_active_job(tmp_path, monkeypatch, **overrides):
    job = _active_job(**overrides)
    db_path = tmp_path / "agent-authorization.db"
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(db_path))
    session = create_db(db_path)
    confirmation = ActionConfirmation.from_value(job["confirmation"])
    modules = job.get("modules") or []
    module_binding = module_set_binding(modules)
    base = AuthorizationContext(
        tenant_id="tenant-lab",
        engagement_id="engagement-agent-lab",
        run_id="run-agent-lab",
        job_id=job["id"],
        operator_id="operator-lab",
        operator_role=OperatorRole.OPERATOR,
        action_kind="scan",
        engine=job["engine"],
        module_id=module_binding,
        requested_target=job["target"].strip(),
        resolved_target=job["target"].strip(),
        allowed_scope=job["scope"],
        excluded_scope=job["excluded_scope"],
        safety_mode=SafetyMode.ACTIVE,
        confirmation_method=ConfirmationMethod.AGENT_JOB,
        confirmed_by="operator-lab",
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
        boundary="dashboard.agent_lease",
    )
    assert consumed.allowed
    agent_context = AuthorizationContext(
        **{
            **base.__dict__,
            "action_kind": "agent.execute",
            "parent_decision_id": issued.envelope.decision_id,
            "confirmation_method": ConfirmationMethod.INHERITED,
        }
    )
    child = derive_authorization(
        session=session,
        parent_envelope=issued.envelope,
        context=agent_context,
        parent_boundary="dashboard.agent_lease",
    )
    session.close()
    assert child.allowed
    job["authorization_envelope"] = child.envelope.to_dict()
    job["runtime_context"] = load_authorization_runtime_facts(
        authorization_runtime_environment(child.envelope)
    )
    job["authorization_db"] = str(db_path)
    return job


def _execute_job(job, *, allow_active_scans=True, local_scope=None, local_excluded=None):
    return forge_agent._safe_job_result(
        job,
        allow_active_scans,
        local_scope=["127.0.0.0/8"] if local_scope is None else local_scope,
        local_excluded_scope=[] if local_excluded is None else local_excluded,
    )


def test_agent_rejects_empty_scope_before_any_dashboard_request(monkeypatch, capsys) -> None:
    calls = []
    monkeypatch.setattr(forge_agent, "_json_request", lambda *args, **kwargs: calls.append(args))

    result = forge_agent.run_agent(_agent_args(scope=" "))

    assert result == 2
    assert calls == []
    assert ScopeReason.MISSING_SCOPE.value in capsys.readouterr().out
    session = create_db(
        forge_agent.default_authorization_db_path()
        if not forge_agent.os.environ.get(AUTHORIZATION_DB_ENV)
        else forge_agent.Path(forge_agent.os.environ[AUTHORIZATION_DB_ENV])
    )
    try:
        rows = session.query(AuthorizationDecisionModel).all()
        assert len(rows) == 1
        assert rows[0].reason_code == ScopeReason.MISSING_SCOPE.value
    finally:
        session.close()


def test_agent_dry_run_validates_scope_without_process_or_authorization(monkeypatch) -> None:
    def forbidden_run(*args, **kwargs):
        raise AssertionError("dry-run must not create a subprocess")

    monkeypatch.setattr(forge_agent.subprocess, "run", forbidden_run)
    job = _active_job(dry_run=True, confirmation=None)

    result = _execute_job(job)

    assert result["status"] == "completed"
    assert result["result"]["dry_run"] is True
    assert result["result"]["authorized"] is False
    assert result["result"]["scope_decision"]["reason_code"] == ScopeReason.SCOPE_MATCHED.value


def test_agent_rejects_non_boolean_dry_run_before_subprocess(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(forge_agent.subprocess, "run", lambda *args, **kwargs: calls.append(args))
    job = _active_job()
    job["dry_run"] = 0

    result = _execute_job(job)

    assert result["status"] == "failed"
    assert result["error"] == ScopeReason.INVALID_CONFIRMATION.value
    assert result["result"]["authorized"] is False
    assert calls == []


def test_agent_active_job_revalidates_and_passes_exact_child_context(
    tmp_path,
    monkeypatch,
) -> None:
    calls = []

    class _Process:
        returncode = 0
        stdout = "mocked scanner complete\n"

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        module_value = command[command.index("--modules") + 1]
        target_value = command[command.index("--target") + 1]
        monkeypatch.setenv(
            AUTHORIZATION_ENVELOPES_ENV,
            kwargs["env"][AUTHORIZATION_ENVELOPES_ENV],
        )
        engine_args = argparse.Namespace(
            _launch_job_id=kwargs["env"][LAUNCH_JOB_ID_ENV],
            modules=module_value,
        )
        engine_decision, envelopes = webforge._prepare_engine_authorizations(
            engine_args,
            [target_value],
            [],
        )
        assert engine_decision.allowed
        assert len(envelopes) == 1
        assert envelopes[0].module_id == module_set_binding(module_value.split(","))
        return _Process()

    monkeypatch.setattr(forge_agent.subprocess, "run", fake_run)
    monkeypatch.setenv("FORGE_PASSWORD", "AMBIENT_PASSWORD_MUST_NOT_REACH_CHILD")
    monkeypatch.setenv(
        "HTTPS_PROXY",
        "http://operator:CANARY_AGENT_PROXY@127.0.0.1:18080",
    )
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")

    result = _execute_job(_authorized_active_job(tmp_path, monkeypatch))

    assert result["status"] == "completed"
    assert result["result"]["authorized"] is True
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert "--auto-confirm" not in command
    assert command[command.index("--scope"):command.index("--scope") + 2] == [
        "--scope",
        "127.0.0.1/32",
    ]
    assert command[command.index("--exclude"):command.index("--exclude") + 2] == [
        "--exclude",
        "127.0.0.2/32",
    ]
    assert LAUNCH_CONFIRMATIONS_ENV in kwargs["env"]
    assert kwargs["env"][LAUNCH_JOB_ID_ENV] == "agent-local-active"
    assert kwargs["env"][LAUNCH_ACTION_ENV] == "scan"
    assert "FORGE_PASSWORD" not in kwargs["env"]
    assert "HTTPS_PROXY" not in kwargs["env"]
    assert "NO_PROXY" not in kwargs["env"]
    assert "CANARY_AGENT_PROXY" not in repr(kwargs["env"])
    assert kwargs["stdin"] is forge_agent.subprocess.DEVNULL


def test_agent_rejects_module_set_mutation_before_subprocess(
    tmp_path,
    monkeypatch,
) -> None:
    calls = []
    monkeypatch.setattr(
        forge_agent.subprocess,
        "run",
        lambda *args, **kwargs: calls.append(args),
    )
    job = _authorized_active_job(tmp_path, monkeypatch)
    job["modules"] = ["sqli_scanner"]

    result = _execute_job(job)

    assert result["status"] == "failed"
    assert result["error"] == AuthorizationReason.MODULE_MISMATCH.value
    assert calls == []


def test_agent_enforces_immutable_local_scope_before_subprocess(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(forge_agent.subprocess, "run", lambda *args, **kwargs: calls.append(args))

    result = _execute_job(
        _active_job(),
        local_scope=["127.0.0.2/32"],
    )

    assert result["status"] == "failed"
    assert result["error"] == ScopeReason.TARGET_MISMATCH.value
    assert calls == []


def test_agent_rejects_mutated_action_before_subprocess(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(forge_agent.subprocess, "run", lambda *args, **kwargs: calls.append(args))
    job = _active_job(action="retest")

    result = _execute_job(job)

    assert result["status"] == "failed"
    assert result["error"] == ScopeReason.ACTION_MISMATCH.value
    assert calls == []


def test_agent_builds_argv_from_normalized_target(tmp_path, monkeypatch) -> None:
    calls = []

    class _Process:
        returncode = 0
        stdout = ""

    monkeypatch.setattr(
        forge_agent.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command) or _Process(),
    )
    job = _authorized_active_job(tmp_path, monkeypatch)
    expected = job["target"]
    job["target"] = f"  {expected}  "

    result = _execute_job(job)

    assert result["status"] == "completed"
    assert len(calls) == 1
    command = calls[0]
    assert command[command.index("--target") + 1] == expected


@pytest.mark.parametrize(
    ("mutate", "expected_reason"),
    [
        (lambda job: job.update(scope=[]), ScopeReason.MISSING_SCOPE),
        (lambda job: job.update(scope=[None]), ScopeReason.MALFORMED_SCOPE),
        (lambda job: job.update(target=None), ScopeReason.MALFORMED_TARGET),
        (
            lambda job: job.update(
                confirmation=ActionConfirmation.create(
                    job_id=job["id"],
                    target=job["target"],
                    engine=job["engine"],
                    action="scan",
                    issued_at=datetime.now(timezone.utc) - timedelta(minutes=10),
                ).to_dict()
            ),
            ScopeReason.STALE_CONFIRMATION,
        ),
        (
            lambda job: job["confirmation"].update(job_id="forged-job"),
            ScopeReason.INVALID_CONFIRMATION,
        ),
    ],
)
def test_agent_denials_never_reach_subprocess(monkeypatch, mutate, expected_reason) -> None:
    calls = []
    monkeypatch.setattr(forge_agent.subprocess, "run", lambda *args, **kwargs: calls.append(args))
    job = _active_job()
    mutate(job)

    result = _execute_job(job)

    assert result["status"] == "failed"
    assert result["error"] == expected_reason.value
    assert calls == []
