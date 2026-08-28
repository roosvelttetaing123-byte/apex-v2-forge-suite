from __future__ import annotations

import io
import importlib
import json
import logging
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

import pytest

from common import artifact_io as artifact_io_module
from common.dashboard import server as server_module
from common.dashboard import credential_analysis as credential_analysis_module
from common.dashboard.server import DashboardArtifactError, DashboardServer


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _caller_directory(tmp_path: Path, name: str = "caller") -> Path:
    directory = tmp_path / name
    directory.mkdir()
    directory.chmod(0o755)
    return directory


def _scan_jobs_fixture(
    path: Path,
    *,
    scan_id: str,
    target: str = "https://fixture.test",
) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE scan_jobs ("
            "id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, status TEXT, "
            "target TEXT, frameworks TEXT, modules TEXT, logs TEXT, created_at TEXT"
            ")"
        )
        connection.execute(
            "INSERT INTO scan_jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                "default",
                "completed",
                target,
                '["webforge"]',
                '["headers"]',
                '{}',
                "2026-07-31T12:00:00+00:00",
            ),
        )
        connection.commit()
    finally:
        connection.close()


def test_credential_analysis_parse_failure_uses_fixed_safe_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exception_secret = "opaque-credential-parser-exception-007"

    def fail_parse(_raw: bytes) -> list[dict[str, str]]:
        raise RuntimeError(exception_secret)

    monkeypatch.setattr(credential_analysis_module, "_extract_json", fail_parse)
    _rows, notes = credential_analysis_module.extract_records("fixture.json", b"{}")

    rendered = repr(notes)
    assert notes == ["Structured parse failed; scanned as text fallback."]
    assert exception_secret not in rendered


def test_plugin_discovery_omits_exception_text_from_logs_and_state(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = DashboardServer(auth=False)
    exception_secret = "opaque-plugin-import-exception-05b473fa"
    registry_modules = {
        "webforge.webforge",
        "netforge.netforge",
        "adforge.adforge",
    }
    real_import = importlib.import_module

    def fake_import(name: str, package: str | None = None) -> object:
        if name in registry_modules:
            return SimpleNamespace(
                MODULE_MAP={"fixture": "fixture.secret_bearing_module"},
                CLASS_NAME_MAP={"fixture": "FixtureModule"},
                PHASES=[],
            )
        if name == "webforge.core.mode_engine":
            return SimpleNamespace(PHASES=[])
        if name == "fixture.secret_bearing_module":
            raise RuntimeError(exception_secret)
        return real_import(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import)
    caplog.set_level(logging.DEBUG, logger="forge.dashboard.server")

    plugins = server._discover_plugins()

    assert len(plugins) == 3
    assert all(plugin["error"] == "RuntimeError" for plugin in plugins)
    assert exception_secret not in repr(plugins)
    assert exception_secret not in caplog.text


@pytest.mark.parametrize("reader_name", ["bytes", "tail"])
def test_dashboard_read_discards_bytes_after_late_hardlink_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reader_name: str,
) -> None:
    source = tmp_path / "dashboard-artifact.bin"
    original = b"ORIGINAL_DASHBOARD_BYTES_007"
    injected = b"INJECTED_DASHBOARD_BYTES_007"
    assert len(original) == len(injected)
    source.write_bytes(original)
    source.chmod(0o600)
    outside_alias = tmp_path / "late-dashboard-alias.bin"
    real_read = server_module.os.read
    raced = False

    def add_alias_and_mutate(descriptor: int, count: int) -> bytes:
        nonlocal raced
        if not raced:
            raced = True
            os.link(source, outside_alias)
            write_descriptor = os.open(outside_alias, os.O_WRONLY | os.O_TRUNC)
            try:
                os.write(write_descriptor, injected)
            finally:
                os.close(write_descriptor)
        return real_read(descriptor, count)

    monkeypatch.setattr(server_module.os, "read", add_alias_and_mutate)

    with pytest.raises(DashboardArtifactError, match="changed during read"):
        if reader_name == "bytes":
            server_module._read_artifact_bytes(source, required_mode=0o600)
        else:
            server_module._read_artifact_tail(source, max_bytes=len(original))

    assert raced is True
    assert source.read_bytes() == injected
    assert source.stat().st_nlink == 2


def test_history_replaces_link_redacts_and_preserves_caller_directory(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    victim = tmp_path / "history-victim.json"
    victim.write_text("victim-content", encoding="utf-8")
    victim.chmod(0o640)
    victim_before = victim.read_bytes()
    history_path = caller / "history.json"
    history_path.symlink_to(victim)
    canary = "CANARY_DASHBOARD_HISTORY_PASSWORD_007"

    with patch.object(
        DashboardServer,
        "_history_path",
        new_callable=PropertyMock,
        return_value=history_path,
    ):
        server._write_scan_history(
            scan_id="scan-artifact-007",
            target=f"https://operator:{canary}@127.0.0.1/",
            scan_type="web",
            mode="greybox",
            engagement=f"engagement {canary}",
            frameworks=["webforge"],
            scan_options={"password": canary, "note": canary},
            control={"operator_note": canary},
            process_ids=["scan-artifact-007_web"],
        )

    assert not history_path.is_symlink()
    assert history_path.is_file()
    assert _mode(history_path) == 0o600
    assert _mode(caller) == 0o755
    assert victim.read_bytes() == victim_before
    assert _mode(victim) == 0o640
    rendered = history_path.read_text(encoding="utf-8")
    assert canary not in rendered
    assert "<redacted>" in rendered
    assert not list(caller.glob(".history.json.*.tmp"))


def test_history_replaces_hardlink_without_mutating_victim(tmp_path: Path) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    victim = tmp_path / "hardlink-history-victim.json"
    victim.write_text('[{"scan_id": "victim-record"}]', encoding="utf-8")
    victim.chmod(0o640)
    victim_before = victim.read_bytes()
    history_path = caller / "history.json"
    os.link(victim, history_path)

    with patch.object(
        DashboardServer,
        "_history_path",
        new_callable=PropertyMock,
        return_value=history_path,
    ):
        server._write_scan_history(
            scan_id="scan-hardlink-007",
            target="127.0.0.1",
            scan_type="web",
            mode="blackbox",
            engagement="fixture",
            frameworks=["webforge"],
        )

    assert history_path.stat().st_ino != victim.stat().st_ino
    assert _mode(history_path) == 0o600
    assert victim.read_bytes() == victim_before
    assert _mode(victim) == 0o640
    assert _mode(caller) == 0o755


def test_nested_template_store_is_private_and_atomic_failure_preserves_old_file(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    templates_path = caller / "managed" / "tenant" / "templates.json"
    canary = "CANARY_DASHBOARD_TEMPLATE_SECRET_007"

    with patch.object(
        DashboardServer,
        "_templates_path",
        new_callable=PropertyMock,
        return_value=templates_path,
    ):
        server._write_scan_templates(
            [{"name": "fixture", "config": {"password": canary, "note": canary}}]
        )

    assert _mode(caller) == 0o755
    assert _mode(caller / "managed") == 0o700
    assert _mode(caller / "managed" / "tenant") == 0o700
    assert _mode(templates_path) == 0o600
    assert canary not in templates_path.read_text(encoding="utf-8")

    old_payload = templates_path.read_bytes()
    old_mode = _mode(templates_path)
    failure_canary = "CANARY_DASHBOARD_ATOMIC_REPLACE_007"
    caplog.set_level(logging.WARNING, logger="forge.dashboard.server")
    with (
        patch.object(
            DashboardServer,
            "_templates_path",
            new_callable=PropertyMock,
            return_value=templates_path,
        ),
        patch.object(server_module.os, "replace", side_effect=OSError(failure_canary)),
        pytest.raises(DashboardArtifactError) as raised,
    ):
        server._write_scan_templates([{"name": "replacement"}])

    assert templates_path.read_bytes() == old_payload
    assert _mode(templates_path) == old_mode
    assert _mode(caller) == 0o755
    assert not list((caller / "managed" / "tenant").glob(".templates.json.*.tmp"))
    assert failure_canary not in str(raised.value)
    assert failure_canary not in caplog.text


def test_control_and_kill_switch_replace_links_without_mutating_victims(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)

    control_victim = tmp_path / "control-victim.json"
    control_victim.write_text("control-victim", encoding="utf-8")
    control_victim.chmod(0o644)
    control_before = control_victim.read_bytes()
    control_path = caller / "control.json"
    control_path.symlink_to(control_victim)
    server._write_control_file(control_path, paused=True, aborted=False)
    assert not control_path.is_symlink()
    assert _mode(control_path) == 0o600
    assert control_victim.read_bytes() == control_before
    assert _mode(control_victim) == 0o644

    kill_victim = tmp_path / "kill-victim.json"
    kill_victim.write_text('{"enabled": false}', encoding="utf-8")
    kill_victim.chmod(0o640)
    kill_before = kill_victim.read_bytes()
    kill_path = caller / "kill.json"
    kill_path.symlink_to(kill_victim)
    reason_canary = "CANARY_DASHBOARD_KILL_REASON_007"
    with patch.object(
        DashboardServer,
        "_kill_switch_path",
        new_callable=PropertyMock,
        return_value=kill_path,
    ):
        # A linked control state is unreadable and therefore fail-closed.
        assert server._kill_switch_active() is True
        state = server._set_kill_switch(
            True,
            reason=reason_canary,
            operator=reason_canary,
        )

    assert state["enabled"] is True
    assert reason_canary not in json.dumps(state)
    assert not kill_path.is_symlink()
    assert _mode(kill_path) == 0o600
    assert kill_victim.read_bytes() == kill_before
    assert _mode(kill_victim) == 0o640
    assert _mode(caller) == 0o755


def test_legacy_agent_cache_symlink_is_ignored_without_mutation(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    victim = tmp_path / "agent-victim.json"
    victim.write_text('{"agents": {}, "jobs": []}', encoding="utf-8")
    victim.chmod(0o640)
    victim_before = victim.read_bytes()
    agents_path = caller / "agents.json"
    agents_path.symlink_to(victim)
    with (
        patch.object(
            DashboardServer,
            "_agents_path",
            new_callable=PropertyMock,
            return_value=agents_path,
        ),
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=tmp_path / "legacy-symlink.db",
        ),
    ):
        durable = server._durable_job_state()

    assert durable.list_agents(tenant_id=server.tenant_id) == []
    assert durable.list_jobs(tenant_id=server.tenant_id) == []
    assert victim.read_bytes() == victim_before
    assert _mode(victim) == 0o640
    assert agents_path.is_symlink()
    assert agents_path.stat().st_ino == victim.stat().st_ino
    assert _mode(caller) == 0o755
    assert not list(caller.glob(".*.tmp"))


def test_legacy_agent_cache_import_is_one_time_canceled_and_tenant_bound(
    tmp_path: Path,
) -> None:
    """Legacy JSON may seed history, but never lease or execution authority."""

    server = DashboardServer(auth=False)
    state_path = tmp_path / "agents.json"
    database = tmp_path / "legacy-import.db"

    def agent_record(
        *,
        tenant_id: str = "default",
        revoked: bool = False,
        suffix: str = "fixture",
    ) -> dict:
        return {
            "tenant_id": tenant_id,
            "credential_digest": f"{suffix}-credential-digest",
            "key_id": f"{suffix}-key",
            "scope": ["fixture.local"],
            "engines": ["netforge"],
            "capabilities": ["scan"],
            "excluded_scope": ["excluded.fixture.local"],
            "name": "Legacy fixture agent",
            "host": "fixture-host",
            "platform": "fixture-platform",
            "version": "fixture-version",
            "active_scan_enabled": False,
            "revoked": revoked,
        }

    with (
        patch.object(
            DashboardServer,
            "_agents_path",
            new_callable=PropertyMock,
            return_value=state_path,
        ),
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=database,
        ),
    ):
        durable = server._durable_job_state()
        durable.register_agent(
            "existing-agent",
            tenant_id=server.tenant_id,
            key_id="existing-key",
            credential_digest="existing-digest",
            engines=("netforge",),
            capabilities=("scan",),
            scope=("fixture.local",),
        )
        durable.create_job(
            {"source": "preexisting"},
            tenant_id=server.tenant_id,
            job_id="existing-job",
            assigned_agent_id="existing-agent",
            state="planned",
            work_items=("existing-work",),
        )
        payload = {
            "agents": {
                "bad-shape": [],
                "wrong-tenant": agent_record(tenant_id="tenant-b"),
                "incomplete": {"tenant_id": "default"},
                "existing-agent": agent_record(),
                "new-agent": agent_record(suffix="new"),
                "revoked-agent": agent_record(revoked=True, suffix="revoked"),
            },
            "jobs": [
                "bad-shape",
                {"tenant_id": "tenant-b", "agent_id": "new-agent"},
                {"id": "unknown-agent-job", "agent_id": "missing-agent"},
                {
                    "id": "existing-job",
                    "agent_id": "existing-agent",
                    "modules": ["existing-work"],
                },
                {
                    "id": "invalid id with spaces",
                    "agent_id": "new-agent",
                    "engine": "netforge",
                    "target": "fixture.local",
                    "modules": ["module-one"],
                    "result": {"token": "must-not-survive"},
                },
                {
                    "id": "legacy-valid-job",
                    "agent_id": "new-agent",
                    "engine": "netforge",
                    "target": "fixture.local",
                    "modules": [],
                },
            ],
        }
        serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
        state_path.write_bytes(serialized)
        state_path.chmod(0o600)
        server._import_legacy_agent_cache(durable)

        agents = {
            row["id"]: row
            for row in durable.list_agents(tenant_id=server.tenant_id)
        }
        jobs = durable.list_jobs(tenant_id=server.tenant_id, limit=100)
        imported_jobs = [
            row for row in jobs if row["id"] != "existing-job"
        ]
        before_repeat = (
            len(agents),
            len(jobs),
            sum(
                len(durable.list_attempts(row["id"], tenant_id=server.tenant_id))
                for row in jobs
            ),
        )
        server._import_legacy_agent_cache(durable)

    assert set(agents) == {"existing-agent", "new-agent", "revoked-agent"}
    assert agents["revoked-agent"]["revoked"] is True
    assert len(imported_jobs) == 2
    assert {row["state"] for row in imported_jobs} == {"canceled"}
    assert all(row["terminal_reason"] for row in imported_jobs)
    assert all(
        durable.list_attempts(row["id"], tenant_id=server.tenant_id) == []
        for row in imported_jobs
    )
    assert before_repeat == (3, 3, 0)
    assert len(durable.list_agents(tenant_id=server.tenant_id)) == 3
    assert len(durable.list_jobs(tenant_id=server.tenant_id, limit=100)) == 3
    assert state_path.read_bytes() == serialized
    assert _mode(state_path) == 0o600
    durable.close()


@pytest.mark.parametrize(
    ("payload_json", "expected_frameworks", "expected_modules"),
    [
        ("not-json", [], []),
        ("[]", [], []),
        ('{"frameworks": {}, "modules": "bad"}', [], []),
        ('{"frameworks": ["webforge"], "modules": ["headers"]}', ["webforge"], ["headers"]),
    ],
)
def test_durable_scan_projection_fails_closed_for_malformed_payload_shapes(
    payload_json: str,
    expected_frameworks: list[str],
    expected_modules: list[str],
) -> None:
    row = {
        "id": "durable-projection",
        "state": None,
        "target": "fixture.local",
        "payload_json": payload_json,
        "engagement_id": None,
        "error_reason": None,
        "run_id": "run-fixture",
        "version": None,
    }

    projection = DashboardServer._durable_scan_job_mapping(row)

    assert projection["scan_id"] == "durable-projection"
    assert projection["status"] == "unknown"
    assert projection["frameworks"] == expected_frameworks
    assert projection["requested_modules"] == expected_modules
    assert projection["actual_modules"] == expected_modules
    assert projection["lifecycle_authority"] == "task103"
    assert projection["version"] == 0
    assert projection["required_work"] == 0


def test_agent_state_read_failure_is_opaque(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = DashboardServer(auth=False)
    state_path = tmp_path / "agents.json"
    state_path.write_text('{"agents": {}, "jobs": []}', encoding="utf-8")
    state_path.chmod(0o600)
    state_before = state_path.stat()
    state_bytes_before = state_path.read_bytes()
    canary = "CANARY_DASHBOARD_AGENT_READ_FAILURE_007"
    caplog.set_level(logging.WARNING, logger="forge.dashboard.server")

    with (
        patch.object(
            DashboardServer,
            "_agents_path",
            new_callable=PropertyMock,
            return_value=state_path,
        ),
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=tmp_path / "legacy-read-failure.db",
        ),
        patch(
            "common.dashboard.server._read_artifact_bytes",
            side_effect=OSError(canary),
        ),
    ):
        durable = server._durable_job_state()

    assert durable.list_agents(tenant_id=server.tenant_id) == []
    assert durable.list_jobs(tenant_id=server.tenant_id) == []
    assert canary not in caplog.text
    assert state_path.read_bytes() == state_bytes_before
    assert state_path.stat().st_ctime_ns == state_before.st_ctime_ns
    assert _mode(state_path) == 0o600


def test_managed_json_and_log_reads_reject_wrong_modes_without_mutation(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    state_path = caller / "agents.json"
    state_path.write_text('{"agents": {}, "jobs": []}', encoding="utf-8")
    state_path.chmod(0o644)
    log_path = caller / "scan-read_web.log"
    log_path.write_text("fixture log", encoding="utf-8")
    log_path.chmod(0o644)
    state_before = state_path.stat()
    log_before = log_path.stat()

    with (
        patch.object(
            DashboardServer,
            "_agents_path",
            new_callable=PropertyMock,
            return_value=state_path,
        ),
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=tmp_path / "legacy-wrong-mode.db",
        ),
    ):
        durable = server._durable_job_state()
    with pytest.raises(DashboardArtifactError, match="mode is invalid"):
        server_module._read_artifact_tail(log_path)
    assert server._tail_text(log_path) == ""

    assert durable.list_agents(tenant_id=server.tenant_id) == []
    assert durable.list_jobs(tenant_id=server.tenant_id) == []
    assert _mode(state_path) == 0o644
    assert _mode(log_path) == 0o644
    assert state_path.stat().st_ctime_ns == state_before.st_ctime_ns
    assert log_path.stat().st_ctime_ns == log_before.st_ctime_ns
    assert _mode(caller) == 0o755

    state_path.chmod(0o600)
    log_path.chmod(0o600)
    state_ready = state_path.stat()
    log_ready = log_path.stat()
    ready_server = DashboardServer(auth=False)
    with (
        patch.object(
            DashboardServer,
            "_agents_path",
            new_callable=PropertyMock,
            return_value=state_path,
        ),
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=tmp_path / "legacy-wrong-mode.db",
        ),
    ):
        ready_durable = ready_server._durable_job_state()
        assert ready_durable.list_agents(tenant_id=ready_server.tenant_id) == []
    with patch.object(server_module.os, "fchmod") as fchmod:
        assert ready_server._tail_text(log_path) == "fixture log"
    fchmod.assert_not_called()
    assert state_path.stat().st_ctime_ns == state_ready.st_ctime_ns
    assert log_path.stat().st_ctime_ns == log_ready.st_ctime_ns


def test_concurrent_dashboard_artifact_readers_do_not_invalidate_each_other(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "agents.json"
    payload = b'{"agents": {}, "jobs": []}'
    artifact.write_bytes(payload)
    artifact.chmod(0o600)
    before = artifact.stat()
    barrier = threading.Barrier(2)
    calls = 0
    calls_lock = threading.Lock()
    real_read = os.read

    def synchronized_read(descriptor: int, count: int) -> bytes:
        nonlocal calls
        wait = False
        with calls_lock:
            if calls < 2:
                calls += 1
                wait = True
        if wait:
            barrier.wait(timeout=5)
        return real_read(descriptor, count)

    monkeypatch.setattr(server_module.os, "read", synchronized_read)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                server_module._read_artifact_bytes,
                artifact,
                required_mode=0o600,
            )
            for _ in range(2)
        ]
        observed = [future.result(timeout=10) for future in futures]

    assert observed == [payload, payload]
    assert calls == 2
    after = artifact.stat()
    assert after.st_ctime_ns == before.st_ctime_ns
    assert _mode(artifact) == 0o600


@pytest.mark.parametrize("streaming", [False, True])
def test_dashboard_writers_reject_public_parent_and_wipe_late_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    streaming: bool,
) -> None:
    public = tmp_path / "public"
    public.mkdir()
    public.chmod(0o777)
    denied_path = public / "state.json"

    with pytest.raises(DashboardArtifactError):
        if streaming:
            server_module._atomic_write_text_stream(
                denied_path,
                lambda handle: handle.write("SENSITIVE_FIXTURE_BYTES"),
            )
        else:
            server_module._atomic_write_artifact(
                denied_path,
                b"SENSITIVE_FIXTURE_BYTES",
            )
    assert not denied_path.exists()
    assert _mode(public) == 0o777
    assert not list(public.glob(".*.tmp"))

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    destination = private / ("stream.log" if streaming else "state.json")
    alias = private / "late-alias"
    real_replace = artifact_io_module.os.replace

    def alias_after_replace(*args: object, **kwargs: object) -> None:
        real_replace(*args, **kwargs)  # type: ignore[arg-type]
        os.link(destination, alias)

    monkeypatch.setattr(artifact_io_module.os, "replace", alias_after_replace)
    with pytest.raises(DashboardArtifactError):
        if streaming:
            server_module._atomic_write_text_stream(
                destination,
                lambda handle: handle.write("SENSITIVE_FIXTURE_BYTES"),
            )
        else:
            server_module._atomic_write_artifact(
                destination,
                b"SENSITIVE_FIXTURE_BYTES",
            )

    assert not destination.exists()
    assert alias.read_bytes() == b""
    assert alias.stat().st_nlink == 1
    assert not list(private.glob(".*.tmp"))


def test_legacy_agent_cache_hardlink_is_ignored_without_victim_mutation(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    victim = tmp_path / "hardlink-agent-victim.json"
    victim.write_text('{"agents": {}, "jobs": []}', encoding="utf-8")
    victim.chmod(0o640)
    victim_before = victim.read_bytes()
    agents_path = caller / "agents.json"
    os.link(victim, agents_path)

    with (
        patch.object(
            DashboardServer,
            "_agents_path",
            new_callable=PropertyMock,
            return_value=agents_path,
        ),
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=tmp_path / "legacy-hardlink.db",
        ),
    ):
        durable = server._durable_job_state()

    assert durable.list_agents(tenant_id=server.tenant_id) == []
    assert durable.list_jobs(tenant_id=server.tenant_id) == []
    assert agents_path.stat().st_ino == victim.stat().st_ino
    assert victim.read_bytes() == victim_before
    assert _mode(victim) == 0o640
    assert _mode(caller) == 0o755


def test_agent_mtls_subject_is_exactly_bound_in_durable_db(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    agents_path = tmp_path / "agents.json"
    canary = "CANARY_DASHBOARD_AGENT_MTLS_SUBJECT_007"
    subject = f"commonName={canary}"

    with (
        patch.object(
            DashboardServer,
            "_agents_path",
            new_callable=PropertyMock,
            return_value=agents_path,
        ),
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=tmp_path / "agent-mtls.db",
        ),
    ):
        registration = server._register_scan_agent(
            {
                "engines": ["webforge"],
                "capabilities": ["dry_run"],
                "scope": ["127.0.0.1"],
            },
            object(),
            identity={"kind": "mtls", "peer_subject": subject},
        )

        class VerifiedTLS:
            @staticmethod
            def getpeercert() -> dict[str, object]:
                return {"subject": ((('commonName', canary),),)}

        request = type(
            "AgentRequest",
            (),
            {
                "headers": {
                    "X-Forge-Agent-Credential": registration["credential"],
                },
                "scope": {"ssl_object": VerifiedTLS()},
            },
        )()
        identity = server._require_agent_token(request, allow_bootstrap=False)
        durable = server._durable_job_state()
        stored_agent = durable.get_agent(
            registration["agent"]["id"],
            tenant_id=server.tenant_id,
        )

        class WrongVerifiedTLS:
            @staticmethod
            def getpeercert() -> dict[str, object]:
                return {"subject": ((('commonName', "different-agent"),),)}

        wrong_request = type(
            "WrongAgentRequest",
            (),
            {
                "headers": {
                    "X-Forge-Agent-Credential": registration["credential"],
                },
                "scope": {"ssl_object": WrongVerifiedTLS()},
            },
        )()
        with pytest.raises(server_module.HTTPException) as denied:
            server._require_agent_token(wrong_request, allow_bootstrap=False)

    assert identity["kind"] == "agent"
    assert identity["agent_id"] == registration["agent"]["id"]
    assert denied.value.status_code == 401
    assert denied.value.detail == {"reason_code": "agent_credential_invalid"}
    assert stored_agent is not None
    assert stored_agent["mtls_subject_digest"] == server._agent_subject_digest(subject)
    assert len(stored_agent["mtls_subject_digest"]) == 64
    assert subject not in json.dumps(stored_agent)
    assert "mtls_subject_digest" not in registration["agent"]
    assert not agents_path.exists()


def test_private_directory_setup_failure_cleans_new_chain(tmp_path: Path) -> None:
    caller = _caller_directory(tmp_path)
    destination = caller / "managed" / "tenant" / "artifact.json"
    canary = "CANARY_DASHBOARD_DIRECTORY_SETUP_007"

    with (
        patch.object(server_module.os, "fchmod", side_effect=OSError(canary)),
        pytest.raises(DashboardArtifactError) as raised,
    ):
        server_module._atomic_write_artifact(destination, b"{}")

    assert not (caller / "managed").exists()
    assert _mode(caller) == 0o755
    assert canary not in str(raised.value)

    real_open = os.open
    write_failure_canary = "CANARY_DASHBOARD_FILE_SETUP_007"

    def fail_artifact_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if str(path).startswith(".artifact.json."):
            raise OSError(write_failure_canary)
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    with (
        patch.object(server_module.os, "open", side_effect=fail_artifact_open),
        pytest.raises(DashboardArtifactError) as write_failure,
    ):
        server_module._atomic_write_artifact(destination, b"{}")

    assert not (caller / "managed").exists()
    assert _mode(caller) == 0o755
    assert write_failure_canary not in str(write_failure.value)


def test_artifact_identifiers_reject_traversal_and_globs_before_filesystem_access(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    server._scan_logs_dir = caller
    server._control_dir = caller
    unrelated = caller / "unrelated.log"
    unrelated.write_text("keep", encoding="utf-8")

    for invalid in ("../outside", "*", "[a-z]", "", ".hidden/child"):
        with pytest.raises(DashboardArtifactError):
            server._init_control_file(invalid)
        with pytest.raises(DashboardArtifactError):
            server._delete_scan_record(invalid)
        with pytest.raises(DashboardArtifactError):
            server._logs_for_scan(invalid)

    assert unrelated.read_text(encoding="utf-8") == "keep"
    assert list(caller.iterdir()) == [unrelated]


def test_log_cleanup_is_descriptor_anchored_and_prefix_exact(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    matching = logs / "scan1_web.log"
    adjacent = logs / "scan10_web.log"
    matching.write_text("remove", encoding="utf-8")
    adjacent.write_text("keep", encoding="utf-8")

    removed = server_module._unlink_matching_artifacts(
        logs,
        prefix="scan1_",
        suffix=".log",
    )
    assert removed == [matching]
    assert not matching.exists()
    assert adjacent.read_text(encoding="utf-8") == "keep"

    victim_directory = tmp_path / "victim-logs"
    victim_directory.mkdir()
    victim = victim_directory / "scan1_web.log"
    victim.write_text("victim", encoding="utf-8")
    for path in logs.iterdir():
        path.unlink()
    logs.rmdir()
    logs.symlink_to(victim_directory, target_is_directory=True)
    with pytest.raises(DashboardArtifactError):
        server_module._unlink_matching_artifacts(
            logs,
            prefix="scan1_",
            suffix=".log",
        )
    assert victim.read_text(encoding="utf-8") == "victim"


def test_scan_log_stream_replaces_link_redacts_and_rolls_back_on_failure(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    server._scan_logs_dir = caller
    canary = "CANARY_DASHBOARD_SCAN_LOG_007"

    victim = tmp_path / "log-victim.txt"
    victim.write_text("victim-log", encoding="utf-8")
    victim.chmod(0o640)
    victim_before = victim.read_bytes()
    log_path = caller / "scan-artifact_web.log"
    log_path.symlink_to(victim)

    class SuccessfulProcess:
        stdout = io.StringIO(
            f"password={canary}\n"
            "-----BEGIN PRIVATE KEY-----\n"
            f"{canary}\n"
            "-----END PRIVATE KEY-----\n"
        )
        pid = 7007

        @staticmethod
        def wait() -> int:
            return 0

        @staticmethod
        def poll() -> int:
            return 0

    info = {
        "proc": SuccessfulProcess(),
        "type": "web",
        "target": f"https://operator:{canary}@127.0.0.1/",
        "status": "running",
    }
    with (
        patch.object(server.event_bus, "emit_simple"),
        patch.object(server, "_update_scan_history_status"),
        patch.object(server, "_sync_scan_job_from_active"),
        patch.object(server, "_load_scan_job", return_value=None),
    ):
        server._track_scan_process("scan-artifact_web", info)
        deadline = time.monotonic() + 3
        while "returncode" not in info and time.monotonic() < deadline:
            time.sleep(0.01)

    assert info.get("returncode") == 0
    assert not log_path.is_symlink()
    assert _mode(log_path) == 0o600
    assert victim.read_bytes() == victim_before
    assert _mode(victim) == 0o640
    assert canary not in log_path.read_text(encoding="utf-8")
    assert "<redacted>" in log_path.read_text(encoding="utf-8")

    old_payload = b"previous-complete-log"
    failed_path = caller / "scan-failure_web.log"
    failed_path.write_bytes(old_payload)
    failed_path.chmod(0o600)
    failure_canary = "CANARY_DASHBOARD_SCAN_WAIT_FAILURE_007"

    class FailedProcess:
        stdout = io.StringIO(f"password={canary}\n")
        pid = 7008

        @staticmethod
        def wait() -> int:
            raise OSError(failure_canary)

        @staticmethod
        def poll() -> None:
            return None

    failed_info = {
        "proc": FailedProcess(),
        "type": "web",
        "target": "127.0.0.1",
        "status": "running",
    }
    caplog.set_level(logging.WARNING, logger="forge.dashboard.server")
    server._track_scan_process("scan-failure_web", failed_info)
    deadline = time.monotonic() + 3
    while "Scan monitor failed" not in caplog.text and time.monotonic() < deadline:
        time.sleep(0.01)

    assert failed_path.read_bytes() == old_payload
    assert failure_canary not in caplog.text
    assert not list(caller.glob(".scan-failure_web.log.*.tmp"))
    assert _mode(caller) == 0o755


def test_scan_log_write_failure_still_reconciles_durable_child_exit(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from common.job_state import process_identity

    server = DashboardServer(auth=False)
    server._scan_logs_dir = _caller_directory(tmp_path, "durable-log-failure")
    identity = process_identity(
        7010,
        start_token="fixture-start",
        command="inert-fixture-child",
        boot_id="fixture-boot",
        launch_nonce="fixture-nonce",
    )

    class CompletedProcess:
        stdout = io.StringIO("fixture output\n" * 20_000)
        pid = identity.pid

        @staticmethod
        def wait() -> int:
            return 0

    class FixtureService:
        exits: list[tuple[object, ...]] = []

        def record_process_exit(self, *args, **_kwargs):
            self.exits.append(args)

        @staticmethod
        def get_job(*_args, **_kwargs):
            return {"state": "completed"}

    service = FixtureService()
    info = {
        "proc": CompletedProcess(),
        "type": "web",
        "target": "127.0.0.1",
        "status": "running",
        "durable_attempt_id": "attempt-fixture",
        "durable_process_identity": identity.to_dict(),
        "durable_worker_id": "dashboard",
        "durable_control_boot_id": "fixture-boot",
    }
    caplog.set_level(logging.WARNING, logger="forge.dashboard.server")
    with (
        patch.object(
            server_module,
            "_atomic_write_text_stream",
            side_effect=OSError("opaque-log-write-failure"),
        ),
        patch.object(server, "_durable_job_state", return_value=service),
        patch.object(server, "_finalize_durable_scan_after_exit") as finalize,
        patch.object(server.event_bus, "emit_simple"),
        patch.object(server, "_update_scan_history_status"),
        patch.object(server, "_sync_scan_job_from_active"),
    ):
        server._track_scan_process("scan-durable_web", info)
        deadline = time.monotonic() + 3
        while not service.exits and time.monotonic() < deadline:
            time.sleep(0.01)

    assert info["returncode"] == 0
    assert info["status"] == "completed"
    assert len(service.exits) == 1
    assert service.exits[0][:2] == ("scan-durable", "attempt-fixture")
    finalize.assert_called_once_with("scan-durable")
    assert "opaque-log-write-failure" not in caplog.text


def test_configured_tls_preserves_caller_modes_and_rejects_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("cryptography")
    monkeypatch.delenv("FORGE_DASHBOARD_TLS_CERT", raising=False)
    monkeypatch.delenv("FORGE_DASHBOARD_TLS_KEY", raising=False)

    source = tmp_path / "generated-source"
    source_tls = source / ".tls"
    source_tls.mkdir(parents=True)
    source.chmod(0o755)
    source_tls.chmod(0o755)
    with patch.object(server_module, "_DASHBOARD_DIR", source):
        generated = DashboardServer(host="127.0.0.1")._create_ssl_context()
    assert generated is not None
    assert _mode(source_tls) == 0o755

    caller = _caller_directory(tmp_path, "tls-caller")
    cert_path = caller / "dashboard-cert.pem"
    key_path = caller / "dashboard-key.pem"
    cert_path.write_bytes(Path(generated["certfile"]).read_bytes())
    key_path.write_bytes(Path(generated["keyfile"]).read_bytes())
    cert_path.chmod(0o644)
    key_path.chmod(0o600)
    monkeypatch.setenv("FORGE_DASHBOARD_TLS_CERT", str(cert_path))
    monkeypatch.setenv("FORGE_DASHBOARD_TLS_KEY", str(key_path))

    configured = DashboardServer(host="127.0.0.1")._create_ssl_context()
    assert configured == {"certfile": str(cert_path), "keyfile": str(key_path)}
    assert _mode(caller) == 0o755
    assert _mode(cert_path) == 0o644
    assert _mode(key_path) == 0o600

    key_path.chmod(0o644)
    with pytest.raises(RuntimeError, match="owner-only"):
        DashboardServer(host="127.0.0.1")._create_ssl_context()
    assert _mode(key_path) == 0o644
    assert _mode(caller) == 0o755

    key_path.unlink()
    key_victim = tmp_path / "tls-key-victim.pem"
    key_victim.write_bytes(Path(generated["keyfile"]).read_bytes())
    key_victim.chmod(0o600)
    victim_before = key_victim.read_bytes()
    key_path.symlink_to(key_victim)
    with pytest.raises(RuntimeError, match="regular files"):
        DashboardServer(host="127.0.0.1")._create_ssl_context()
    assert key_path.is_symlink()
    assert key_victim.read_bytes() == victim_before
    assert _mode(key_victim) == 0o600
    assert _mode(caller) == 0o755

    key_path.unlink()
    os.link(key_victim, key_path)
    hardlink_before = key_victim.read_bytes()
    with pytest.raises(RuntimeError, match="hard-linked"):
        DashboardServer(host="127.0.0.1")._create_ssl_context()
    assert key_path.stat().st_ino == key_victim.stat().st_ino
    assert key_victim.read_bytes() == hardlink_before
    assert _mode(key_victim) == 0o600
    assert _mode(caller) == 0o755


def test_generated_tls_failure_removes_partial_material_and_new_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("cryptography")
    monkeypatch.delenv("FORGE_DASHBOARD_TLS_CERT", raising=False)
    monkeypatch.delenv("FORGE_DASHBOARD_TLS_KEY", raising=False)
    tls_root = tmp_path / "failed-generated-tls"
    canary = "CANARY_DASHBOARD_TLS_CERT_WRITE_007"
    real_atomic_write = server_module._atomic_write_artifact

    def fail_certificate(path: Path, payload: bytes, **kwargs: object) -> None:
        if path.name == "forge_cert.pem":
            raise OSError(canary)
        real_atomic_write(path, payload, **kwargs)  # type: ignore[arg-type]

    with (
        patch.object(server_module, "_DASHBOARD_DIR", tls_root),
        patch.object(server_module, "_atomic_write_artifact", side_effect=fail_certificate),
        pytest.raises(RuntimeError) as raised,
    ):
        DashboardServer(host="127.0.0.1")._create_ssl_context()

    assert str(raised.value) == "dashboard TLS generation failed"
    assert canary not in str(raised.value)
    assert not tls_root.exists()


def test_scan_jobs_read_only_uses_pinned_descriptor_without_side_effects(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    database = caller / "scan_jobs.db"
    _scan_jobs_fixture(database, scan_id="trusted-scan-job")
    database.chmod(0o640)
    database_mode = _mode(database)
    caller_mode = _mode(caller)
    observed_descriptors: list[int] = []
    real_connect = sqlite3.connect

    class TrackingConnection:
        def __init__(self, connection: sqlite3.Connection, descriptor: int) -> None:
            self._connection = connection
            self._descriptor = descriptor

        @property
        def row_factory(self) -> object:
            return self._connection.row_factory

        @row_factory.setter
        def row_factory(self, value: object) -> None:
            self._connection.row_factory = value  # type: ignore[assignment]

        def execute(self, *args: object, **kwargs: object) -> sqlite3.Cursor:
            os.fstat(self._descriptor)
            return self._connection.execute(*args, **kwargs)  # type: ignore[arg-type]

        def close(self) -> None:
            os.fstat(self._descriptor)
            self._connection.close()

    def tracked_connect(
        database_uri: str,
        *,
        uri: bool = False,
        timeout: float = 0.0,
        **kwargs: object,
    ) -> TrackingConnection:
        assert database_uri.startswith(("file:/proc/self/fd/", "file:/dev/fd/"))
        assert database_uri.endswith("/scan_jobs.db?mode=ro")
        assert "immutable=1" not in database_uri
        assert uri is True
        descriptor = int(database_uri.partition("?")[0].rsplit("/", 2)[1])
        os.fstat(descriptor)
        observed_descriptors.append(descriptor)
        connection = real_connect(
            database_uri,
            uri=uri,
            timeout=timeout,
            **kwargs,
        )
        return TrackingConnection(connection, descriptor)

    with (
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=database,
        ),
        patch.object(server_module.sqlite3, "connect", side_effect=tracked_connect),
    ):
        rows = server._load_scan_jobs_read_only()

    assert [row["scan_id"] for row in rows] == ["trusted-scan-job"]
    assert observed_descriptors
    with pytest.raises(OSError):
        os.fstat(observed_descriptors[0])
    assert _mode(database) == database_mode
    assert _mode(caller) == caller_mode
    assert not any(
        (caller / f"scan_jobs.db{suffix}").exists()
        for suffix in ("-wal", "-shm", "-journal")
    )


def test_scan_jobs_read_only_includes_committed_live_wal_rows(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    database = caller / "scan_jobs.db"
    _scan_jobs_fixture(database, scan_id="checkpointed-scan-job")
    writer = sqlite3.connect(database)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(
            "INSERT INTO scan_jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "committed-wal-scan-job",
                "default",
                "running",
                "https://wal.fixture.test",
                '["webforge"]',
                '["headers"]',
                '{}',
                "2026-07-31T12:01:00+00:00",
            ),
        )
        writer.commit()
        assert writer.execute(
            "SELECT id FROM scan_jobs WHERE id='committed-wal-scan-job'"
        ).fetchone() == ("committed-wal-scan-job",)
        assert Path(f"{database}-wal").is_file()

        with patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=database,
        ):
            rows = server._load_scan_jobs_read_only()
    finally:
        writer.close()

    assert {row["scan_id"] for row in rows} == {
        "checkpointed-scan-job",
        "committed-wal-scan-job",
    }


def test_scan_jobs_read_only_rejects_transient_wal_alias(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    database = caller / "scan_jobs.db"
    _scan_jobs_fixture(database, scan_id="checkpointed-scan-job")
    writer = sqlite3.connect(database)
    alias = caller / "transient-wal-alias"
    real_connect = sqlite3.connect
    linked = False
    rows: list[dict[str, object]] = []
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(
            "INSERT INTO scan_jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "committed-wal-scan-job",
                "default",
                "running",
                "https://wal.fixture.test",
                '["webforge"]',
                '["headers"]',
                '{}',
                "2026-07-31T12:01:00+00:00",
            ),
        )
        writer.commit()
        wal = Path(f"{database}-wal")
        assert wal.is_file()

        def alias_then_connect(
            *args: object,
            **kwargs: object,
        ) -> sqlite3.Connection:
            nonlocal linked
            os.link(wal, alias)
            alias.unlink()
            linked = True
            return real_connect(*args, **kwargs)  # type: ignore[arg-type]

        with (
            patch.object(
                DashboardServer,
                "_scan_jobs_db_path",
                new_callable=PropertyMock,
                return_value=database,
            ),
            patch.object(
                server_module.sqlite3,
                "connect",
                side_effect=alias_then_connect,
            ),
        ):
            rows = server._load_scan_jobs_read_only()
    finally:
        writer.close()

    assert linked is True
    assert rows == []
    assert not alias.exists()


def test_scan_jobs_read_only_discards_rows_after_transient_hardlink(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    database = caller / "scan_jobs.db"
    _scan_jobs_fixture(database, scan_id="transient-hardlink-row")
    database.chmod(0o600)
    alias = tmp_path / "transient-hardlink-alias.db"
    real_connect = sqlite3.connect
    linked = False

    def link_then_connect(
        *args: object,
        **kwargs: object,
    ) -> sqlite3.Connection:
        nonlocal linked
        os.link(database, alias)
        alias.unlink()
        linked = True
        return real_connect(*args, **kwargs)  # type: ignore[arg-type]

    with (
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=database,
        ),
        patch.object(
            server_module.sqlite3,
            "connect",
            side_effect=link_then_connect,
        ),
    ):
        rows = server._load_scan_jobs_read_only()

    assert linked is True
    assert rows == []
    assert database.stat().st_nlink == 1
    assert not alias.exists()


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_scan_jobs_read_only_rejects_links_without_reading_or_mutating_victim(
    tmp_path: Path,
    link_kind: str,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    victim = tmp_path / f"{link_kind}-victim.db"
    _scan_jobs_fixture(victim, scan_id=f"{link_kind}-victim-row")
    victim.chmod(0o640)
    victim_before = victim.read_bytes()
    victim_mode = _mode(victim)
    database = caller / "scan_jobs.db"
    if link_kind == "symlink":
        database.symlink_to(victim)
    else:
        os.link(victim, database)

    with (
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=database,
        ),
        patch.object(
            server_module.sqlite3,
            "connect",
            side_effect=AssertionError("unsafe database reached SQLite"),
        ),
    ):
        assert server._load_scan_jobs_read_only() == []

    assert victim.read_bytes() == victim_before
    assert _mode(victim) == victim_mode
    assert _mode(caller) == 0o755
    if link_kind == "symlink":
        assert database.is_symlink()
    else:
        assert database.stat().st_ino == victim.stat().st_ino
        assert victim.stat().st_nlink == 2


def test_scan_jobs_read_only_rejects_intermediate_directory_link(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    real_parent = tmp_path / "real-parent"
    nested = real_parent / "nested"
    nested.mkdir(parents=True)
    nested.chmod(0o755)
    victim = nested / "scan_jobs.db"
    _scan_jobs_fixture(victim, scan_id="intermediate-link-victim-row")
    victim.chmod(0o640)
    victim_before = victim.read_bytes()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    database = linked_parent / "nested" / "scan_jobs.db"

    with (
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=database,
        ),
        patch.object(
            server_module.sqlite3,
            "connect",
            side_effect=AssertionError("linked directory reached SQLite"),
        ),
    ):
        assert server._load_scan_jobs_read_only() == []

    assert linked_parent.is_symlink()
    assert victim.read_bytes() == victim_before
    assert _mode(victim) == 0o640
    assert _mode(nested) == 0o755


def test_scan_jobs_read_only_rejects_non_owner_without_mode_mutation(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    database = caller / "scan_jobs.db"
    _scan_jobs_fixture(database, scan_id="foreign-owner-row")
    database.chmod(0o644)
    actual_uid = os.getuid()

    with (
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=database,
        ),
        patch.object(server_module.os, "getuid", return_value=actual_uid + 1),
        patch.object(
            server_module.sqlite3,
            "connect",
            side_effect=AssertionError("foreign database reached SQLite"),
        ),
    ):
        assert server._load_scan_jobs_read_only() == []

    assert _mode(database) == 0o644
    assert _mode(caller) == 0o755


def test_scan_jobs_read_only_discards_rows_after_directory_entry_swap(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    database = caller / "scan_jobs.db"
    replacement = caller / "replacement.db"
    pinned_original = caller / "pinned-original.db"
    _scan_jobs_fixture(database, scan_id="original-row")
    _scan_jobs_fixture(replacement, scan_id="replacement-row")
    real_connect = sqlite3.connect
    swapped = False

    def swap_then_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        nonlocal swapped
        database.rename(pinned_original)
        replacement.rename(database)
        swapped = True
        return real_connect(*args, **kwargs)  # type: ignore[arg-type]

    with (
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=database,
        ),
        patch.object(
            server_module.sqlite3,
            "connect",
            side_effect=swap_then_connect,
        ),
    ):
        rows = server._load_scan_jobs_read_only()

    assert swapped is True
    assert rows == []
    assert database.is_file()
    assert pinned_original.is_file()


def test_scan_jobs_read_only_discards_rows_after_ancestor_directory_swap(
    tmp_path: Path,
) -> None:
    server = DashboardServer(auth=False)
    caller = _caller_directory(tmp_path)
    database = caller / "scan_jobs.db"
    _scan_jobs_fixture(database, scan_id="detached-original-row")
    replacement_parent = _caller_directory(tmp_path, "replacement-parent")
    replacement_database = replacement_parent / "scan_jobs.db"
    _scan_jobs_fixture(replacement_database, scan_id="ancestor-replacement-row")
    detached_parent = tmp_path / "detached-parent"
    real_connect = sqlite3.connect
    swapped = False

    def swap_parent_then_connect(
        *args: object,
        **kwargs: object,
    ) -> sqlite3.Connection:
        nonlocal swapped
        caller.rename(detached_parent)
        replacement_parent.rename(caller)
        swapped = True
        return real_connect(*args, **kwargs)  # type: ignore[arg-type]

    with (
        patch.object(
            DashboardServer,
            "_scan_jobs_db_path",
            new_callable=PropertyMock,
            return_value=database,
        ),
        patch.object(
            server_module.sqlite3,
            "connect",
            side_effect=swap_parent_then_connect,
        ),
    ):
        rows = server._load_scan_jobs_read_only()

    assert swapped is True
    assert rows == []
    assert (detached_parent / "scan_jobs.db").is_file()
    assert database.is_file()
