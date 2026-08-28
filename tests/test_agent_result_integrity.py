from __future__ import annotations

import copy
import json
import sqlite3
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import PropertyMock, patch

import httpx
import anyio
import pytest

from common.action_authorization import module_set_binding
from common.canonical_evidence import CanonicalEvidenceService
from common.dashboard.auth import Role, issue_identity_token
from common.dashboard.server import DashboardServer
from common.db import AuditLogModel, create_db
from common.job_state import JobStateError, JobStateService, LeaseError


@pytest.fixture(autouse=True)
def _agent_env(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGE_AGENT_REGISTRATION_TOKEN", "bootstrap-secret")
    monkeypatch.setenv(
        "FORGE_DASHBOARD_STATE_DIR",
        str(tmp_path / "dashboard-state"),
    )
    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda self: tmp_path / "agent-integrity.db"),
    )
    # The JSON path is retained only as an import input.  It must never be
    # created or consulted as lifecycle authority by these tests.
    monkeypatch.setattr(
        DashboardServer,
        "_agents_path",
        property(lambda self: tmp_path / "legacy-agents.json"),
    )


@pytest.fixture
def anyio_backend():
    """WP005 exercises one deterministic ASGI backend; Trio is not required."""
    return "asyncio"


def _client(app, token="bootstrap-secret"):
    headers = {
        "Authorization": f"Bearer {issue_identity_token('integrity-test', Role.ADMIN)}",
    }
    if token:
        headers["X-Forge-Agent-Token"] = token
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
        headers=headers,
    )


async def _register(client, agent_id="agent-hint", **overrides):
    body = {
        "agent_id": agent_id,
        "engines": ["webforge"],
        "capabilities": ["dry_run", "scoped_jobs"],
        "scope": ["example.test"],
    }
    body.update(overrides)
    response = await client.post("/api/v1/agents/register", json=body)
    if response.status_code == 200:
        client.headers.pop("X-Forge-Agent-Token", None)
        client.headers["X-Forge-Agent-Credential"] = response.json()["credential"]
        client.forge_agent_id = response.json()["agent"]["id"]
    return response


def _agent_id(client) -> str:
    return str(client.forge_agent_id)


def _legacy_path(srv: DashboardServer) -> Path:
    return srv._agents_path


def _durable_snapshot(srv: DashboardServer, tenant_id: str | None = None) -> str:
    """Canonical, tenant-bound snapshot for no-mutation assertions.

    Include the durable agent/job/attempt/lease/event/delivery/work rows and
    Task 102 observation/custody rows.  Secrets are intentionally represented
    only by their stored digests/identities, never by JSON authority bytes.
    """
    tenant = tenant_id or srv.tenant_id
    conn = srv._durable_job_state().conn
    tables = [
        "durable_job_state_agents",
        "durable_job_state_agent_engines",
        "durable_job_state_agent_capabilities",
        "durable_job_state_agent_scope",
        "durable_job_state_jobs",
        "durable_job_state_job_authorizations",
        "durable_job_state_attempts",
        "durable_job_state_leases",
        "durable_job_state_events",
        "durable_job_state_logs",
        "durable_job_state_work_plan",
        "durable_job_state_work_items",
        "durable_job_state_deliveries",
        "durable_job_state_terminal_proofs",
        "durable_job_state_child_processes",
        "durable_job_state_launch_intents",
        "canonical_observations",
        "canonical_artifact_refs",
        "canonical_artifact_manifests",
        "authorization_decisions",
        "authorization_consumptions",
    ]
    snapshot: dict[str, list[dict[str, Any]]] = {}
    for table in tables:
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if exists is None:
            continue
        columns = [str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")]
        if "tenant_id" not in columns:
            continue
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE tenant_id=? ORDER BY rowid", (tenant,)
        ).fetchall()
        snapshot[table] = [dict(row) for row in rows]
    return json.dumps(snapshot, sort_keys=True, default=str, separators=(",", ":"))


def _assert_legacy_untouched(srv: DashboardServer, before: bytes | None = None) -> None:
    """The legacy JSON path is import-only and must remain absent/byte-stable."""
    path = _legacy_path(srv)
    if before is None:
        assert not path.exists()
    else:
        assert path.exists()
        assert path.read_bytes() == before


def _control_mutation_snapshot(srv: DashboardServer) -> str:
    """Rows whose mutation constitutes an agent-control-plane write."""
    full = json.loads(_durable_snapshot(srv))
    keep = {
        key: full.get(key, [])
        for key in (
            "durable_job_state_agents",
            "durable_job_state_agent_engines",
            "durable_job_state_agent_capabilities",
            "durable_job_state_agent_scope",
            "durable_job_state_jobs",
            "durable_job_state_attempts",
            "durable_job_state_leases",
            "durable_job_state_deliveries",
            "canonical_observations",
            "canonical_artifact_refs",
            "canonical_artifact_manifests",
        )
    }
    return json.dumps(keep, sort_keys=True, separators=(",", ":"), default=str)


def _result_custody_state(srv: DashboardServer, job_id: str) -> dict[str, Any]:
    """Return result-delivery/custody rows and files for one isolated job."""

    conn = srv._durable_job_state().conn
    counts: dict[str, int] = {}
    for table in (
        "durable_job_state_deliveries",
        "canonical_observations",
        "canonical_artifact_refs",
        "canonical_artifact_manifests",
        "canonical_observation_artifacts",
    ):
        columns = [str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")]
        if "job_id" in columns:
            counts[table] = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE tenant_id=? AND job_id=?",
                    (srv.tenant_id, job_id),
                ).fetchone()[0]
            )
        else:
            counts[table] = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE tenant_id=?",
                    (srv.tenant_id,),
                ).fetchone()[0]
            )
    custody_root = srv._scan_results_dir / job_id
    counts["custody_files"] = (
        sum(1 for path in custody_root.rglob("*") if path.is_file())
        if custody_root.exists()
        else 0
    )
    return counts


def _agent_path(client, suffix: str = "") -> str:
    return f"/api/v1/agents/{_agent_id(client)}{suffix}"


async def _queue_and_lease(client, agent_id=None):
    agent_id = agent_id or _agent_id(client)
    created = await client.post(
        "/api/v1/agents/jobs",
        json={
            "job_id": "integrity-dry-run",
            "agent_id": agent_id,
            "engine": "webforge",
            "target": "http://example.test/fixture",
            "scope": ["example.test"],
            "modules": ["header_audit"],
        },
    )
    assert created.status_code == 200, created.text
    leased = await client.get(f"/api/v1/agents/{agent_id}/jobs/next")
    assert leased.status_code == 200, leased.text
    return leased.json()["job"]


def _result(job, **overrides):
    value = {
        "lease_token": job["lease_token"],
        "delivery_idempotency_key": job["delivery_idempotency_key"],
        "outcome": "success",
        "tenant_id": job["tenant_id"],
        "job_id": job["id"],
        "agent_id": job["agent_id"],
        "attempt_id": job["attempt_id"],
        "run_id": job["run_id"],
        "engine": job["engine"],
        "capability": job["capability"],
        "module_binding": module_set_binding(job["modules"]),
        "target": job["target"],
        "authorization_id": job["authorization_id"],
        "result": {"findings": []},
    }
    value.update(overrides)
    return value


class _FakeTLSObject:
    def __init__(self, common_name: str) -> None:
        self._common_name = common_name

    def getpeercert(self):
        return {"subject": ((("commonName", self._common_name),),)}


class _FakeTLSRequest:
    def __init__(self, common_name: str, headers: dict[str, str] | None = None) -> None:
        self.scope = {"ssl_object": _FakeTLSObject(common_name)}
        self.headers = headers or {}


@pytest.mark.anyio
async def test_registration_requires_valid_bootstrap_without_state_mutation(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app(), token="") as client:
            missing = await client.post(
                "/api/v1/agents/register",
                json={"agent_id": "missing-agent", "scope": ["example.test"]},
            )
            client.headers["X-Forge-Agent-Token"] = "invalid-bootstrap"
            invalid = await client.post(
                "/api/v1/agents/register",
                json={"agent_id": "invalid-agent", "scope": ["example.test"]},
            )
    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert not path.exists()


@pytest.mark.anyio
async def test_registration_authentication_precedes_json_parsing(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app(), token="") as client:
            response = await client.post(
                "/api/v1/agents/register",
                content=b'{"agent_id":',
                headers={"Content-Type": "application/json"},
            )
    assert response.status_code == 401
    assert response.json()["detail"]["reason_code"] == "agent_auth_required"
    assert not path.exists()


def test_verified_tls_peer_identity_is_stable_and_body_or_proxy_headers_are_inert(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    request = _FakeTLSRequest(
        "agent-peer-1",
        headers={
            "X-Forwarded-Client-Cert": "By=attacker;Subject=CN=forged",
            "X-Forge-Agent-Token": "bootstrap-secret",
        },
    )
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        first = srv._register_scan_agent(
            {
                "agent_id": "body-forged-id",
                "mtls_subject": "commonName=body-forged",
                "engines": ["webforge"],
                "capabilities": ["dry_run"],
                "scope": ["example.test"],
            },
            request,
        )
        before = _durable_snapshot(srv)
        with pytest.raises(Exception) as duplicate:
            srv._register_scan_agent(
                {
                    "agent_id": "different-body-id",
                    "engines": ["webforge"],
                    "capabilities": ["dry_run"],
                    "scope": ["example.test"],
                },
                request,
            )
    expected_id = f"agent-{srv._agent_digest('commonName=agent-peer-1')[:24]}"
    state = srv._durable_job_state().get_agent(first["agent"]["id"], tenant_id=srv.tenant_id)
    assert first["agent"]["id"] == expected_id
    assert getattr(duplicate.value, "status_code", None) == 409
    assert duplicate.value.detail["reason_code"] == "agent_already_registered"
    assert _durable_snapshot(srv) == before
    assert state["mtls_subject_digest"] == srv._agent_subject_digest("commonName=agent-peer-1")
    assert state["id"] == expected_id
    assert "forged" not in _durable_snapshot(srv)
    _assert_legacy_untouched(srv)


@pytest.mark.anyio
async def test_bootstrap_body_hint_cannot_replace_existing_agent_identity(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as first_client:
            first = await _register(first_client, agent_id="agent-victim", name="Victim")
            original_credential = first.json()["credential"]
            first_id = first.json()["agent"]["id"]
            before = _durable_snapshot(srv)
            async with _client(srv.create_app()) as takeover_client:
                takeover = await _register(
                    takeover_client,
                    agent_id="agent-victim",
                    name="Replacement",
                )
            after_takeover = _durable_snapshot(srv)
            valid = await first_client.get(f"/api/v1/agents/{first_id}/jobs/next")
    assert first.status_code == 200
    assert takeover.status_code == 409
    assert takeover.json()["detail"]["reason_code"] == "agent_already_registered"
    assert first_id != "agent-victim"
    assert srv._agent_digest(original_credential) in after_takeover
    assert after_takeover == before
    assert srv._durable_job_state().get_agent(first_id, tenant_id=srv.tenant_id)["display_name"] == "Victim"
    assert valid.status_code == 200


@pytest.mark.anyio
async def test_concurrent_bootstrap_registration_has_one_server_identity(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        responses: list[httpx.Response] = []

        async def register() -> None:
            async with _client(srv.create_app()) as client:
                responses.append(await _register(client, agent_id="agent-race"))

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(register)
            tasks.start_soon(register)
    assert sorted(response.status_code for response in responses) == [200, 409]
    accepted = next(response for response in responses if response.status_code == 200)
    issued_id = accepted.json()["agent"]["id"]
    assert issued_id != "agent-race"
    assert [agent["id"] for agent in srv._durable_job_state().list_agents(tenant_id=srv.tenant_id)] == [issued_id]


def test_revoked_verified_tls_peer_cannot_reregister(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    request = _FakeTLSRequest("revoked-peer")
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        first = srv._register_scan_agent(
            {
                "engines": ["webforge"],
                "capabilities": ["dry_run"],
                "scope": ["example.test"],
            },
            request,
        )
        agent_id = first["agent"]["id"]
        srv._durable_job_state().revoke_agent(agent_id, tenant_id=srv.tenant_id)
        before = _durable_snapshot(srv)
        with pytest.raises(Exception) as raised:
            srv._register_scan_agent(
                {
                    "engines": ["webforge"],
                    "capabilities": ["dry_run"],
                    "scope": ["example.test"],
                },
                request,
            )
    assert getattr(raised.value, "status_code", None) == 401
    assert raised.value.detail["reason_code"] == "agent_revoked"
    assert _durable_snapshot(srv) == before


@pytest.mark.anyio
async def test_two_pollers_racing_for_one_attempt_create_one_lease(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            registration = await _register(client)
            created = await client.post(
                "/api/v1/agents/jobs",
                json={
                    "job_id": "race-dry-run",
                    "agent_id": _agent_id(client),
                    "engine": "webforge",
                    "target": "http://example.test/fixture",
                    "scope": ["example.test"],
                    "modules": ["header_audit"],
                },
            )
            assert created.status_code == 200, created.text
            headers = {
                "Authorization": client.headers["Authorization"],
                "X-Forge-Agent-Credential": registration.json()["credential"],
            }
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=srv.create_app()),
                base_url="http://testserver",
                headers=headers,
            ) as first_client, httpx.AsyncClient(
                transport=httpx.ASGITransport(app=srv.create_app()),
                base_url="http://testserver",
                headers=headers,
            ) as second_client:
                responses: list[httpx.Response] = []
                agent_id = _agent_id(client)

                async def poll(client):
                    responses.append(
                        await client.get(f"/api/v1/agents/{agent_id}/jobs/next")
                    )

                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(poll, first_client)
                    tasks.start_soon(poll, second_client)
                first, second = responses
    leased = [response.json()["job"] for response in (first, second) if response.json()["job"]]
    service = srv._durable_job_state()
    rows = service.conn.execute(
        "SELECT state,lease_generation FROM durable_job_state_attempts "
        "WHERE tenant_id=? ORDER BY number", (srv.tenant_id,)
    ).fetchall()
    assert len(leased) == 1
    assert len({job["lease_token"] for job in leased}) == 1
    assert rows[0]["state"] == "running"
    assert rows[0]["lease_generation"] == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", "tenant-forged"),
        ("job_id", "job-forged"),
        ("agent_id", "agent-forged"),
        ("attempt_id", "attempt-forged"),
        ("run_id", "run-forged"),
        ("engine", "netforge"),
        ("capability", "active_scan"),
        ("module_binding", "module-set-forged"),
        ("target", "http://outside.test"),
        ("authorization_id", "authorization-forged"),
    ],
)
async def test_exact_result_assignment_mismatch_has_zero_mutation(tmp_path, field, value):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            job = await _queue_and_lease(client)
            before = _durable_snapshot(srv)
            response = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=_result(job, **{field: value}),
            )
    assert response.status_code == 409
    assert response.json()["detail"]["reason_code"] == "result_assignment_mismatch"
    assert _durable_snapshot(srv) == before


@pytest.mark.anyio
async def test_renewal_uses_fake_clock_and_preserves_exact_assignment(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    clock = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    srv._agent_now = lambda: clock[0]
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            srv._durable_job_state().clock = lambda: clock[0].timestamp()
            job = await _queue_and_lease(client)
            preserved = {
                key: job[key]
                for key in (
                    "agent_id", "tenant_id", "id", "run_id", "attempt_id", "engine",
                    "capability", "modules", "target", "authorization_id",
                )
            }
            clock[0] += timedelta(seconds=5)
            renewed = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/lease/renew"),
                json={"lease_token": job["lease_token"]},
            )
    assert renewed.status_code == 200, renewed.text
    rotated = renewed.json()["job"]
    assert rotated["id"] == job["id"]
    assert rotated["attempt_id"] == job["attempt_id"]
    assert rotated["lease_token"] != job["lease_token"]
    assert rotated["lease_generation"] == 2
    assert rotated["lease_expires_at"] == pytest.approx(
        clock[0].timestamp() + srv._agent_lease_seconds()
    )
    stored = srv._durable_job_state().get_job(job["id"], tenant_id=srv.tenant_id)
    assert stored["run_id"] == job["run_id"]
    assert stored["payload"]["target"] == job["target"]


@pytest.mark.anyio
async def test_registration_credential_is_hashed_and_body_mtls_is_ignored(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            response = await _register(client, mtls_subject="CN=forged")
            credential = response.json()["credential"]
    state_text = _durable_snapshot(srv)
    agent = srv._durable_job_state().get_agent(_agent_id(client), tenant_id=srv.tenant_id)
    assert response.status_code == 200
    assert credential not in state_text
    assert agent["credential_digest"]
    assert agent["mtls_subject_digest"] is None
    assert "credential_digest" not in response.text
    assert not _legacy_path(srv).exists()


@pytest.mark.anyio
async def test_missing_invalid_and_wrong_path_credentials_do_not_mutate(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            registration = await _register(client)
            before = _durable_snapshot(srv)
            client.headers.pop("X-Forge-Agent-Credential")
            missing = await client.get(_agent_path(client, "/jobs/next"))
            client.headers["X-Forge-Agent-Credential"] = "wrong-secret"
            invalid = await client.get(_agent_path(client, "/jobs/next"))
            client.headers["X-Forge-Agent-Credential"] = registration.json()["credential"]
            wrong_path = await client.get("/api/v1/agents/agent-2/jobs/next")
            client.headers.pop("X-Forge-Agent-Credential")
            client.headers["X-Forge-Agent-Token"] = registration.json()["credential"]
            legacy_header = await client.get(_agent_path(client, "/jobs/next"))
            after = _durable_snapshot(srv)
    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert wrong_path.status_code == 403
    assert legacy_header.status_code == 401
    assert before == after
    _assert_legacy_untouched(srv)


@pytest.mark.anyio
@pytest.mark.parametrize("endpoint_kind", ["renew", "result"])
@pytest.mark.parametrize("credential_kind", ["missing", "invalid", "wrong_path"])
async def test_renew_and_result_credentials_fail_before_state_mutation(
    tmp_path,
    endpoint_kind,
    credential_kind,
):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            registration = await _register(client)
            job = await _queue_and_lease(client)
            before = _durable_snapshot(srv)
            agent_id = _agent_id(client)
            if credential_kind == "missing":
                client.headers.pop("X-Forge-Agent-Credential")
            elif credential_kind == "invalid":
                client.headers["X-Forge-Agent-Credential"] = "invalid-agent-credential"
            else:
                client.headers["X-Forge-Agent-Credential"] = registration.json()["credential"]
                agent_id = "agent-2"
            endpoint = f"/api/v1/agents/{agent_id}/jobs/{job['id']}"
            if endpoint_kind == "renew":
                response = await client.post(
                    f"{endpoint}/lease/renew",
                    json={"lease_token": job["lease_token"]},
                )
            else:
                response = await client.post(f"{endpoint}/result", json=_result(job))
    assert response.status_code in {401, 403}
    assert _durable_snapshot(srv) == before


@pytest.mark.anyio
async def test_renew_rotates_lease_and_old_token_fails(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    clock = [datetime.now(timezone.utc)]
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            srv._durable_job_state().clock = lambda: clock[0].timestamp()
            job = await _queue_and_lease(client)
            renewed = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/lease/renew"),
                json={"lease_token": job["lease_token"]},
            )
            assert renewed.status_code == 200, renewed.text
            rotated = renewed.json()["job"]
            assert rotated["lease_token"] != job["lease_token"]
            accepted = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=_result({**job, **rotated, "authorization_id": job["authorization_id"]}),
            )
            rejected = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=_result(job),
            )
    assert accepted.status_code == 200, accepted.text
    assert rejected.status_code == 409


@pytest.mark.anyio
async def test_renewal_is_bounded_by_original_deadline(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGE_AGENT_LEASE_SECONDS", "15")
    monkeypatch.setenv("FORGE_AGENT_LEASE_MAX_SECONDS", "20")
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    clock = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    srv._agent_now = lambda: clock[0]
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            srv._durable_job_state().clock = lambda: clock[0].timestamp()
            job = await _queue_and_lease(client)
            original_expiry = job["lease_expires_at"]
            clock[0] += timedelta(seconds=10)
            renewed = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/lease/renew"),
                json={"lease_token": job["lease_token"]},
            )
            rotated = renewed.json()["job"]
            stale = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/lease/renew"),
                json={"lease_token": job["lease_token"]},
            )
            clock[0] += timedelta(seconds=10)
            exhausted = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/lease/renew"),
                json={"lease_token": rotated["lease_token"]},
            )
    assert renewed.status_code == 200, renewed.text
    base_timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    assert original_expiry == pytest.approx(base_timestamp + 15)
    assert rotated["lease_expires_at"] == pytest.approx(
        base_timestamp + 20
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["reason_code"] == "durable_lease_renewal_failed"
    assert exhausted.status_code == 409
    assert srv._durable_job_state().get_job(
        job["id"], tenant_id=srv.tenant_id
    )["state"] == "running"
    srv._durable_job_state().reconcile(tenant_id=srv.tenant_id)
    stored = srv._durable_job_state().get_job(
        job["id"],
        tenant_id=srv.tenant_id,
    )
    assert stored["state"] == "expired"
    assert stored["terminal_at"] is None


@pytest.mark.anyio
async def test_result_assignment_mismatch_has_zero_mutation_and_server_owns_status(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            job = await _queue_and_lease(client)
            before = _durable_snapshot(srv)
            forged = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=_result(job, target="http://outside.test", status="completed", verified=True),
            )
            assert forged.status_code == 409
            assert _durable_snapshot(srv) == before
            accepted = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=_result(
                    job,
                    outcome="failure",
                    status="completed",
                    operator="attacker",
                    severity="Critical",
                    verified=True,
                ),
            )
    assert accepted.status_code == 200, accepted.text
    stored = srv._durable_job_state().get_job(job["id"], tenant_id=srv.tenant_id)
    assert stored["state"] == "failed"
    assert stored["tenant_id"] == srv.tenant_id
    assert "verified" not in json.dumps(stored)


@pytest.mark.anyio
async def test_nested_result_claims_cannot_override_server_truth(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    canary = "CANARY_NESTED_AGENT_RESULT_005"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            job = await _queue_and_lease(client)
            response = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=_result(
                    job,
                    outcome="failure",
                    result={
                        "observation": {
                            "status": "completed",
                            "verified": True,
                            "tenant_id": "tenant-forged",
                            "operator": "attacker",
                            "severity": "Critical",
                            "authorization": {"decision_id": "forged"},
                            "lineage": {"job_id": "forged"},
                            "detail": "bounded observation",
                            "secret": canary,
                        }
                    },
                ),
            )
    assert response.status_code == 200, response.text
    returned = response.json()["job"]
    assert returned["status"] == "failed"
    assert returned["tenant_id"] == "default"
    assert returned["result"] == {
        "observation": {"detail": "bounded observation", "secret": "<redacted>"}
    }
    persisted = _durable_snapshot(srv)
    assert canary not in persisted
    assert "tenant-forged" not in persisted


@pytest.mark.anyio
async def test_redacted_result_differences_conflict_and_keys_are_redacted(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    key_canary = "CANARY_RESULT_KEY_005"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            job = await _queue_and_lease(client)
            first_payload = _result(
                job,
                result={"secret": "first-secret", key_canary: "visible"},
            )
            first = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=first_payload,
            )
            conflict_payload = copy.deepcopy(first_payload)
            conflict_payload["result"]["secret"] = "second-secret"
            before_conflict = _durable_snapshot(srv)
            conflict = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=conflict_payload,
            )
    assert first.status_code == 200, first.text
    assert first.json()["job"]["result"] == {
        "secret": "<redacted>",
        "<redacted>": "visible",
    }
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["reason_code"] == "result_delivery_conflict"
    assert _durable_snapshot(srv) == before_conflict
    persisted = _durable_snapshot(srv)
    assert key_canary not in persisted
    assert "first-secret" not in persisted
    assert "second-secret" not in persisted


@pytest.mark.anyio
async def test_identical_duplicate_is_idempotent_and_conflict_is_rejected_and_audited(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    canary = "CANARY_CONFLICT_RESULT_SECRET_005"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            job = await _queue_and_lease(client)
            payload = _result(job)
            first = await client.post(_agent_path(client, f"/jobs/{job['id']}/result"), json=payload)
            after_first = _durable_snapshot(srv)
            duplicate = await client.post(_agent_path(client, f"/jobs/{job['id']}/result"), json=payload)
            conflicting_payload = copy.deepcopy(payload)
            conflicting_payload["result"] = {"findings": [{"id": "different", "secret": canary}]}
            before_conflict = _durable_snapshot(srv)
            conflict = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=conflicting_payload,
            )
            wrong_lease_payload = copy.deepcopy(payload)
            wrong_lease_payload["lease_token"] = "forged-replay-token"
            wrong_lease = await client.post(_agent_path(client, f"/jobs/{job['id']}/result"), json=wrong_lease_payload)
    session = create_db(srv._scan_jobs_db_path)
    try:
        audit_rows = session.query(AuditLogModel).all()
        audit_text = "\n".join(
            f"{row.action} {row.object_id} {row.detail}"
            for row in audit_rows
        )
    finally:
        session.close()
    assert first.status_code == 200
    assert duplicate.status_code == 200
    assert duplicate.json()["status"] == "duplicate"
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["reason_code"] == "result_delivery_conflict"
    assert _durable_snapshot(srv) == before_conflict
    assert wrong_lease.status_code == 409
    service = srv._durable_job_state()
    assert service.conn.execute(
        "SELECT COUNT(*) FROM durable_job_state_deliveries WHERE tenant_id=? AND job_id=?",
        (srv.tenant_id, job["id"]),
    ).fetchone()[0] == 1
    assert service.conn.execute(
        "SELECT COUNT(*) FROM canonical_observations WHERE tenant_id=? AND job_id=?",
        (srv.tenant_id, job["id"]),
    ).fetchone()[0] == 1
    assert "agent.result.conflict" not in audit_text
    assert canary not in audit_text
    assert job["lease_token"] not in audit_text


@pytest.mark.anyio
async def test_expiry_and_revocation_never_complete_work(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    clock = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    srv._agent_now = lambda: clock[0]
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            srv._durable_job_state().clock = lambda: clock[0].timestamp()
            job = await _queue_and_lease(client)
            srv._durable_job_state().clock = lambda: clock[0].timestamp()
            clock[0] += timedelta(minutes=10)
            assert srv._durable_job_state().clock() == clock[0].timestamp()
            expired = await client.post(_agent_path(client, f"/jobs/{job['id']}/result"), json=_result(job))
    assert expired.status_code == 409, expired.text
    # A rejected client call never drives lifecycle recovery. The server-owned
    # reconciler expires the lease independently.
    assert srv._durable_job_state().get_job(
        job["id"], tenant_id=srv.tenant_id
    )["state"] == "running"
    srv._durable_job_state().reconcile(tenant_id=srv.tenant_id)
    stored = srv._durable_job_state().get_job(job["id"], tenant_id=srv.tenant_id)
    assert stored["state"] == "expired"
    assert stored["terminal_at"] is None
    assert set(_result_custody_state(srv, job["id"]).values()) == {0}


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("boundary", "reason_code"),
    [
        ("rotated", "durable_result_rejected"),
        ("revoked", "durable_result_rejected"),
        ("invalid_run_truth", "signed_run_truth_invalid"),
    ],
)
async def test_rejected_result_boundaries_leave_zero_canonical_custody(
    tmp_path,
    monkeypatch,
    boundary,
    reason_code,
):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(
        DashboardServer,
        "_agents_path",
        new_callable=PropertyMock,
        return_value=path,
    ):
        async with _client(srv.create_app()) as client:
            await _register(client)
            job = await _queue_and_lease(client)
            durable = srv._durable_job_state()
            payload = _result(job)
            if boundary == "rotated":
                renewed = await client.post(
                    _agent_path(client, f"/jobs/{job['id']}/lease/renew"),
                    json={"lease_token": job["lease_token"]},
                )
                assert renewed.status_code == 200, renewed.text
            elif boundary == "revoked":
                assert durable.revoke_lease(
                    job["attempt_id"],
                    tenant_id=srv.tenant_id,
                    reason="fixture revocation",
                ) is True
            else:
                real_get_job = durable.get_job

                def active_job(*args, **kwargs):
                    stored = real_get_job(*args, **kwargs)
                    assert stored is not None
                    result = copy.deepcopy(stored)
                    result["payload"]["dry_run"] = False
                    return result

                monkeypatch.setattr(durable, "get_job", active_job)
                payload["run_truth_id"] = "missing-run-truth"
            response = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=payload,
            )

    assert response.status_code == 409, response.text
    assert response.json()["detail"]["reason_code"] == reason_code
    assert set(_result_custody_state(srv, job["id"]).values()) == {0}


@pytest.mark.anyio
async def test_custodied_delivery_recovers_exactly_once_after_acceptance_crash(
    tmp_path,
):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(
        DashboardServer,
        "_agents_path",
        new_callable=PropertyMock,
        return_value=path,
    ):
        async with _client(srv.create_app()) as client:
            await _register(client)
            job = await _queue_and_lease(client)
            payload = _result(job)
            with patch.object(
                JobStateService,
                "record_result",
                side_effect=LeaseError("fixture post-custody crash"),
            ):
                interrupted = await client.post(
                    _agent_path(client, f"/jobs/{job['id']}/result"),
                    json=payload,
                )
            staged = _result_custody_state(srv, job["id"])
            assert srv._job_state_service is not None
            srv._job_state_service.close()
            unavailable = await client.get(
                f"/api/v1/agents/{_agent_id(client)}/jobs/next"
            )
            assert unavailable.status_code == 503, unavailable.text
            assert unavailable.json()["detail"]["reason_code"] == (
                "agent_control_plane_unavailable"
            )
            with pytest.raises(
                JobStateError,
                match="durable job authority changed or closed",
            ):
                srv._durable_job_state()
            srv._job_state_service = None
            srv._job_state_service_path = None
            restarted = srv._initialize_durable_job_state()
            assert restarted.get_job(
                job["id"], tenant_id=srv.tenant_id
            )["state"] == "completed"
            assert restarted.conn.execute(
                "SELECT state FROM durable_job_state_deliveries "
                "WHERE tenant_id=? AND job_id=?",
                (srv.tenant_id, job["id"]),
            ).fetchone()["state"] == "accepted"
            recovered = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=payload,
            )

    assert interrupted.status_code == 409, interrupted.text
    assert interrupted.json()["detail"]["reason_code"] == "durable_result_rejected"
    assert staged["durable_job_state_deliveries"] == 1
    assert staged["canonical_observations"] == 1
    assert staged["canonical_artifact_refs"] == 1
    assert staged["canonical_artifact_manifests"] == 1
    assert staged["canonical_observation_artifacts"] == 1
    assert staged["custody_files"] > 0
    assert recovered.status_code == 200, recovered.text
    final = _result_custody_state(srv, job["id"])
    assert final == staged
    delivery = srv._durable_job_state().conn.execute(
        "SELECT state FROM durable_job_state_deliveries "
        "WHERE tenant_id=? AND job_id=?",
        (srv.tenant_id, job["id"]),
    ).fetchone()
    assert delivery["state"] == "accepted"


@pytest.mark.anyio
async def test_custodied_delivery_survives_cancel_race_without_terminal_mutation(
    tmp_path,
):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(
        DashboardServer,
        "_agents_path",
        new_callable=PropertyMock,
        return_value=path,
    ):
        async with _client(srv.create_app()) as client:
            await _register(client)
            job = await _queue_and_lease(client)
            payload = _result(job)
            original_record = JobStateService.record_result

            def cancel_then_accept(service, *args, **kwargs):
                service.cancel_job(
                    job["id"],
                    tenant_id=srv.tenant_id,
                    reason="fixture cancel after custody reservation",
                    sla_seconds=0,
                )
                return original_record(service, *args, **kwargs)

            with patch.object(
                JobStateService,
                "record_result",
                new=cancel_then_accept,
            ):
                response = await client.post(
                    _agent_path(client, f"/jobs/{job['id']}/result"),
                    json=payload,
                )

    assert response.status_code == 409, response.text
    assert response.json()["detail"]["reason_code"] == "durable_result_rejected"
    stored = srv._durable_job_state().get_job(job["id"], tenant_id=srv.tenant_id)
    assert stored["state"] == "canceled"
    assert stored["completed_work"] == 0
    state = _result_custody_state(srv, job["id"])
    assert state["canonical_observations"] == 1
    assert state["durable_job_state_deliveries"] == 1
    delivery = srv._durable_job_state().conn.execute(
        "SELECT state FROM durable_job_state_deliveries "
        "WHERE tenant_id=? AND job_id=?",
        (srv.tenant_id, job["id"]),
    ).fetchone()
    assert delivery["state"] == "custodied"
    srv._durable_job_state().reconcile(tenant_id=srv.tenant_id)
    recovered = srv._durable_job_state().conn.execute(
        "SELECT state FROM durable_job_state_deliveries "
        "WHERE tenant_id=? AND job_id=?",
        (srv.tenant_id, job["id"]),
    ).fetchone()
    assert recovered["state"] == "accepted"
    final = srv._durable_job_state().get_job(job["id"], tenant_id=srv.tenant_id)
    assert final["state"] == "canceled"
    assert final["completed_work"] == 0


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("truth_status", "coverage_complete", "expected_job_state"),
    [
        ("success", True, "completed"),
        ("failed", False, "failed"),
    ],
)
async def test_active_agent_result_binds_signed_truth_and_canonical_custody(
    tmp_path,
    monkeypatch,
    truth_status,
    coverage_complete,
    expected_job_state,
):
    """An active agent claim completes only through signed truth plus custody."""

    import base64
    from dataclasses import replace

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    import common.run_truth as run_truth_module
    from common.action_authorization import (
        ActionAuthorizationEnvelope,
        AuthorizationContext,
        ConfirmationMethod,
        derive_authorization,
        consume_authorization,
    )
    from common.confirm_gate import ActionConfirmation
    from common.db import append_run_collection_truth, finding_set_identity
    from common.run_truth import (
        RUN_TRUTH_POLICY,
        RunCollectionStatus,
        RunCollectionTruth,
        run_collection_truth_attestation_payload,
    )

    target = "http://127.0.0.1:8080/fixture"
    srv = DashboardServer(auth=False)
    async with _client(srv.create_app()) as client:
        registered = await _register(
            client,
            scope=["127.0.0.0/8"],
            active_scan_enabled=True,
        )
        assert registered.status_code == 200, registered.text
        created = await client.post(
            "/api/v1/agents/jobs",
            json={
                "job_id": "active-custodied-result",
                "agent_id": _agent_id(client),
                "engine": "webforge",
                "target": target,
                "scope": ["127.0.0.1/32"],
                "modules": ["header_audit"],
                "dry_run": False,
                "confirmation": ActionConfirmation.create(
                    job_id="active-custodied-result",
                    target=target,
                    engine="webforge",
                    action="scan",
                ).to_dict(),
            },
        )
        assert created.status_code == 200, created.text
        leased = await client.get(f"/api/v1/agents/{_agent_id(client)}/jobs/next")
        assert leased.status_code == 200, leased.text
        job = leased.json()["job"]

        authorization = ActionAuthorizationEnvelope.from_value(
            job["authorization_envelope"]
        )
        authorization_context = AuthorizationContext(
            tenant_id=authorization.tenant_id,
            engagement_id=authorization.engagement_id,
            run_id=authorization.run_id,
            job_id=authorization.job_id,
            operator_id=authorization.operator_id,
            operator_role=authorization.operator_role,
            action_kind="agent.execute",
            engine=job["engine"],
            module_id=module_set_binding(job["modules"]),
            requested_target=job["target"],
            resolved_target=job["target"],
            allowed_scope=job["scope"],
            excluded_scope=job["excluded_scope"],
            scope_policy_version=authorization.scope_policy_version,
            safety_mode=authorization.safety_mode,
            credential_approval_required=(
                authorization.credential_approval_required
            ),
            network_escalation_approval_required=(
                authorization.network_escalation_approval_required
            ),
            high_risk_approval_required=authorization.high_risk_approval_required,
            confirmation_method=ConfirmationMethod.INHERITED,
            confirmed_by=authorization.operator_id,
            credential_reference=authorization.credential_reference,
            parent_decision_id=authorization.decision_id,
        )
        authorization_session = create_db(srv._scan_jobs_db_path)
        try:
            consumed_agent = consume_authorization(
                session=authorization_session,
                envelope=authorization,
                expected=authorization_context,
                boundary="agent.execute",
            )
            assert consumed_agent.allowed
            engine_context = AuthorizationContext(
                **{
                    **authorization_context.__dict__,
                    "action_kind": "engine.execute",
                    "parent_decision_id": authorization.decision_id,
                }
            )
            derived = derive_authorization(
                session=authorization_session,
                parent_envelope=authorization,
                context=engine_context,
                parent_boundary="agent.execute",
            )
            assert derived.allowed
            consumed_engine = consume_authorization(
                session=authorization_session,
                envelope=derived.envelope,
                expected=engine_context,
                boundary="webforge.engine",
            )
            assert consumed_engine.allowed
            engine_authorization = derived.envelope
        finally:
            authorization_session.close()

        signer = Ed25519PrivateKey.generate()
        policy = replace(
            RUN_TRUTH_POLICY,
            issuer_public_key=base64.b64encode(
                signer.public_key().public_bytes_raw()
            ).decode("ascii"),
        )
        monkeypatch.setattr(run_truth_module, "RUN_TRUTH_POLICY", policy)
        session = create_db(srv._scan_jobs_db_path)
        try:
            run_truth_id = f"{job['run_id']}:webforge"
            truth = RunCollectionTruth(
                run_id=run_truth_id,
                authorization_run_id=job["run_id"],
                job_id=job["id"],
                tenant_id=job["tenant_id"],
                framework="webforge",
                scope_binding="sha256:" + "a" * 64,
                target_binding="sha256:" + "b" * 64,
                collection_status=RunCollectionStatus(truth_status),
                coverage_complete=coverage_complete,
                coverage_identity="sha256:" + "c" * 64,
                finding_set_identity=finding_set_identity(
                    session,
                    tenant_id=job["tenant_id"],
                    run_id=run_truth_id,
                ),
                predecessor_run_id="",
                run_sequence=1,
                completed_at="2026-08-27T00:00:00+00:00",
                authorization_decision_id=engine_authorization.decision_id,
                authorization_binding=engine_authorization.binding_digest,
                authority_id="fixture-run-authority",
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
        finally:
            session.close()

        inspected = srv._durable_job_state().inspect_run_truth(
            job["attempt_id"],
            job["lease_token"],
            run_truth_id,
            tenant_id=srv.tenant_id,
            worker_id=_agent_id(client),
        )
        assert inspected["outcome"] == (
            "success" if truth_status == "success" else "failure"
        )
        submitted = await client.post(
            _agent_path(client, f"/jobs/{job['id']}/result"),
            json={**_result(job), "run_truth_id": run_truth_id},
        )

    assert submitted.status_code == 200, submitted.text
    assert submitted.json()["job"]["status"] == expected_job_state
    stored = srv._durable_job_state().get_job(job["id"], tenant_id=srv.tenant_id)
    assert stored["state"] == expected_job_state
    coverage = srv._durable_job_state().coverage_snapshot(
        job["id"], tenant_id=srv.tenant_id
    )
    assert coverage["completed"] == (1 if truth_status == "success" else 0)
    assert coverage["failed"] == (1 if truth_status == "failed" else 0)
    conn = srv._durable_job_state().conn
    assert conn.execute(
        "SELECT COUNT(*) FROM durable_job_state_terminal_proofs "
        "WHERE tenant_id=? AND job_id=?",
        (srv.tenant_id, job["id"]),
    ).fetchone()[0] == 2
    assert _result_custody_state(srv, job["id"])["canonical_observations"] == 1


@pytest.mark.anyio
async def test_revocation_invalidates_credential_and_active_lease(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            job = await _queue_and_lease(client)
            revoked = await client.post(_agent_path(client, "/revoke"), json={})
            submit = await client.post(_agent_path(client, f"/jobs/{job['id']}/result"), json=_result(job))
    assert revoked.status_code == 200
    assert submit.status_code == 401
    stored_agent = srv._durable_job_state().get_agent(_agent_id(client), tenant_id=srv.tenant_id)
    stored_job = srv._durable_job_state().get_job(job["id"], tenant_id=srv.tenant_id)
    assert stored_agent["revoked"] is True
    assert stored_job["state"] == "canceled"
    assert stored_job["terminal_at"] is not None


@pytest.mark.anyio
@pytest.mark.parametrize(
    "operation",
    ["registration", "job_creation", "lease", "renewal", "revocation", "result"],
)
async def test_agent_mutations_fail_closed_when_state_persistence_fails(
    tmp_path,
    operation,
):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    canary = "CANARY_AGENT_PERSISTENCE_005"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            job = None
            if operation != "registration":
                registered = await _register(client)
                assert registered.status_code == 200
            if operation in {"lease", "renewal", "revocation", "result"}:
                created = await client.post(
                    "/api/v1/agents/jobs",
                    json={
                        "job_id": f"persist-{operation}",
                        "agent_id": _agent_id(client),
                        "engine": "webforge",
                        "target": "http://example.test/fixture",
                        "scope": ["example.test"],
                        "modules": ["header_audit"],
                    },
                )
                assert created.status_code == 200
            if operation in {"renewal", "revocation", "result"}:
                leased = await client.get(_agent_path(client, "/jobs/next"))
                assert leased.status_code == 200
                job = leased.json()["job"]
            before = _control_mutation_snapshot(srv)
            original_tx = JobStateService._tx

            @contextmanager
            def failing_tx(service):
                # Fail at the durable transaction boundary; JobStateService
                # must roll back all writes before exposing the error.
                with original_tx(service):
                    yield
                    raise sqlite3.OperationalError(canary)

            try:
                failure_patch = (
                    patch.object(
                        CanonicalEvidenceService,
                        "persist_job_observation",
                        side_effect=OSError(canary),
                    )
                    if operation == "result"
                    else patch.object(JobStateService, "_tx", failing_tx)
                )
                with failure_patch:
                    if operation == "registration":
                        response = await _register(client, agent_id="agent-write-failure")
                    elif operation == "job_creation":
                        response = await client.post(
                            "/api/v1/agents/jobs",
                            json={
                                "job_id": "persist-create",
                                "agent_id": _agent_id(client),
                                "engine": "webforge",
                                "target": "http://example.test/fixture",
                                "scope": ["example.test"],
                                "modules": ["header_audit"],
                            },
                        )
                    elif operation == "lease":
                        response = await client.get(_agent_path(client, "/jobs/next"))
                    elif operation == "renewal":
                        assert job is not None
                        response = await client.post(
                            _agent_path(client, f"/jobs/{job['id']}/lease/renew"),
                            json={"lease_token": job["lease_token"]},
                        )
                    elif operation == "revocation":
                        response = await client.post(_agent_path(client, "/revoke"), json={})
                    else:
                        assert job is not None
                        response = await client.post(
                            _agent_path(client, f"/jobs/{job['id']}/result"),
                            json=_result(job, error=canary),
                        )
            except BaseException as failure:
                # ASGITransport propagates an unhandled SQLite boundary error;
                # either way, no successful mutation may be observed.
                assert canary in str(failure)
                response = None
    # The operation fails at SQLite commit and the ASGI boundary surfaces the
    # failure without a success response; the durable snapshot is unchanged.
    if response is not None:
        assert response.status_code == 503
    assert _control_mutation_snapshot(srv) == before
    assert not _legacy_path(srv).exists()


@pytest.mark.anyio
@pytest.mark.parametrize("state_bytes", [b"{malformed", b"[]", b'{"agents": [], "jobs": {}}'])
async def test_agent_state_corruption_fails_closed_and_recovers(
    tmp_path,
    caplog,
    state_bytes,
):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    path.write_bytes(state_bytes)
    before = path.read_bytes()
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            recovered = await _register(client, agent_id="agent-corrupt")
            assert recovered.status_code == 200
            assert path.read_bytes() == before
    assert recovered.status_code == 200
    assert "malformed" not in caplog.text
    assert state_bytes.decode("utf-8", errors="ignore") not in caplog.text


@pytest.mark.anyio
async def test_agent_state_read_error_fails_closed_without_secret_logging(
    tmp_path,
    caplog,
):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    path.write_text('{"agents": {}, "jobs": []}', encoding="utf-8")
    before = path.read_bytes()
    canary = "CANARY_AGENT_STATE_READ_005"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        with patch("common.dashboard.server._read_artifact_bytes", side_effect=OSError(canary)):
            async with _client(srv.create_app()) as client:
                denied = await _register(client, agent_id="agent-read-failure")
    assert denied.status_code == 200
    assert path.read_bytes() == before
    assert canary not in denied.text
    assert canary not in caplog.text


def test_agent_state_and_job_creation_are_tenant_isolated(tmp_path):
    shared_path = tmp_path / "agents.json"
    tenant_a = DashboardServer(auth=False)
    tenant_b = DashboardServer(auth=False)
    tenant_a.tenant_id = "tenant-a"
    tenant_b.tenant_id = "tenant-b"
    request = type(
        "BootstrapRequest",
        (),
        {
            "scope": {},
            "headers": {"X-Forge-Agent-Token": "bootstrap-secret"},
        },
    )()
    with patch.object(
        DashboardServer,
        "_agents_path",
        new_callable=PropertyMock,
        return_value=shared_path,
    ):
        registration = tenant_a._register_scan_agent(
            {
                "agent_id": "tenant-a-hint",
                "engines": ["webforge"],
                "capabilities": ["dry_run"],
                "scope": ["example.test"],
            },
            request,
        )
        before = _durable_snapshot(tenant_a)
        assert tenant_b._agent_state()["agents"] == []
        with pytest.raises(Exception) as denied:
            tenant_b._create_agent_job(
                {
                    "job_id": "cross-tenant-job",
                    "agent_id": registration["agent"]["id"],
                    "engine": "webforge",
                    "target": "http://example.test/fixture",
                    "scope": ["example.test"],
                },
                None,
            )
        with pytest.raises(Exception) as credential_reuse:
            tenant_b._register_scan_agent(
                {
                    "agent_id": registration["agent"]["id"],
                    "engines": ["webforge"],
                    "capabilities": ["dry_run"],
                    "scope": ["example.test"],
                },
                request,
                identity={
                    "kind": "agent",
                    "agent_id": registration["agent"]["id"],
                    "tenant_id": "tenant-a",
                    "key_id": registration["agent"]["key_id"],
                    "peer_subject": "",
                },
            )
    assert getattr(denied.value, "status_code", None) == 404
    assert getattr(credential_reuse.value, "status_code", None) == 403
    assert _durable_snapshot(tenant_a) == before
    assert _durable_snapshot(tenant_b) != before
    assert not shared_path.exists()


@pytest.mark.anyio
async def test_concurrent_job_creation_serializes_without_lost_update(tmp_path):
    srv = DashboardServer(auth=False)
    async with _client(srv.create_app()) as owner:
        registered = await _register(owner)
        assert registered.status_code == 200
        agent_id = _agent_id(owner)

    def create(client_job_id: str) -> dict[str, Any]:
        return srv._create_agent_job(
            {
                "job_id": client_job_id,
                "agent_id": agent_id,
                "engine": "webforge",
                "target": "http://example.test/fixture",
                "scope": ["example.test"],
                "modules": ["header_audit"],
            },
            None,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(create, job_id)
            for job_id in ("concurrent-job-a", "concurrent-job-b")
        ]
        responses = [future.result(timeout=10) for future in futures]

    stored_ids = [
        str(job["id"])
        for job in srv._durable_job_state().list_jobs(tenant_id=srv.tenant_id)
        if job.get("assigned_agent_id") == agent_id
    ]
    response_ids = [str(response["id"]) for response in responses]
    assert len(stored_ids) == 2
    assert sorted(stored_ids) == sorted(response_ids)
    assert len(set(stored_ids)) == 2
    assert not _legacy_path(srv).exists()
