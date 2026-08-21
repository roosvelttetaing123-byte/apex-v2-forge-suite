from __future__ import annotations

import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import PropertyMock, patch

import httpx
import anyio
import pytest

from common.action_authorization import module_set_binding
from common.dashboard.auth import Role, issue_identity_token
from common.dashboard.server import DashboardServer
from common.db import AuditLogModel, create_db


@pytest.fixture(autouse=True)
def _agent_env(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGE_AGENT_REGISTRATION_TOKEN", "bootstrap-secret")
    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda self: tmp_path / "agent-integrity.db"),
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
        before = path.read_bytes()
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
    state = json.loads(path.read_text(encoding="utf-8"))
    assert first["agent"]["id"] == expected_id
    assert getattr(duplicate.value, "status_code", None) == 409
    assert duplicate.value.detail["reason_code"] == "agent_already_registered"
    assert path.read_bytes() == before
    assert state["agents"][expected_id]["mtls_subject"] == "commonName=agent-peer-1"
    assert list(state["agents"]) == [expected_id]
    assert "forged" not in path.read_text(encoding="utf-8")


@pytest.mark.anyio
async def test_bootstrap_body_hint_cannot_replace_existing_agent_identity(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as first_client:
            first = await _register(first_client, agent_id="agent-victim", name="Victim")
            original_credential = first.json()["credential"]
            first_id = first.json()["agent"]["id"]
            before = path.read_bytes()
            async with _client(srv.create_app()) as takeover_client:
                takeover = await _register(
                    takeover_client,
                    agent_id="agent-victim",
                    name="Replacement",
                )
            after_takeover = path.read_bytes()
            valid = await first_client.get(f"/api/v1/agents/{first_id}/jobs/next")
    assert first.status_code == 200
    assert takeover.status_code == 409
    assert takeover.json()["detail"]["reason_code"] == "agent_already_registered"
    assert first_id != "agent-victim"
    assert original_credential not in path.read_text(encoding="utf-8")
    assert after_takeover == before
    assert json.loads(after_takeover)["agents"][first_id]["name"] == "Victim"
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
    assert set(json.loads(path.read_text(encoding="utf-8"))["agents"]) == {issued_id}


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
        state = json.loads(path.read_text(encoding="utf-8"))
        state["agents"][agent_id]["revoked"] = True
        state["agents"][agent_id]["revoked_at"] = "2026-01-01T00:00:00+00:00"
        state["agents"][agent_id]["status"] = "revoked"
        srv._write_agents_state(state)
        before = path.read_bytes()
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
    assert path.read_bytes() == before


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
    state = json.loads(path.read_text(encoding="utf-8"))
    assert len(leased) == 1
    assert len({job["lease_token"] for job in leased}) == 1
    assert state["jobs"][0]["status"] == "running"
    assert state["jobs"][0]["lease_generation"] == 1


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
            before = path.read_bytes()
            response = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=_result(job, **{field: value}),
            )
    assert response.status_code == 409
    assert response.json()["detail"]["reason_code"] == "result_assignment_mismatch"
    assert path.read_bytes() == before


@pytest.mark.anyio
async def test_renewal_uses_fake_clock_and_preserves_exact_assignment(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    clock = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    srv._agent_now = lambda: clock[0]
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
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
    assert {key: rotated[key] for key in preserved} == preserved
    assert rotated["lease_token"] != job["lease_token"]
    assert rotated["lease_generation"] == 2
    assert rotated["updated_at"] == clock[0].isoformat()
    assert rotated["lease_expires_at"] == (
        clock[0] + timedelta(seconds=srv._agent_lease_seconds())
    ).isoformat()


@pytest.mark.anyio
async def test_registration_credential_is_hashed_and_body_mtls_is_ignored(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            response = await _register(client, mtls_subject="CN=forged")
            credential = response.json()["credential"]
    state_text = path.read_text(encoding="utf-8")
    state = json.loads(state_text)
    agent = state["agents"][_agent_id(client)]
    assert response.status_code == 200
    assert credential not in state_text
    assert agent["credential_digest"]
    assert agent["mtls_subject"] == ""
    assert "credential_digest" not in response.text
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.anyio
async def test_missing_invalid_and_wrong_path_credentials_do_not_mutate(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            registration = await _register(client)
            before = path.read_text(encoding="utf-8")
            client.headers.pop("X-Forge-Agent-Credential")
            missing = await client.get(_agent_path(client, "/jobs/next"))
            client.headers["X-Forge-Agent-Credential"] = "wrong-secret"
            invalid = await client.get(_agent_path(client, "/jobs/next"))
            client.headers["X-Forge-Agent-Credential"] = registration.json()["credential"]
            wrong_path = await client.get("/api/v1/agents/agent-2/jobs/next")
            client.headers.pop("X-Forge-Agent-Credential")
            client.headers["X-Forge-Agent-Token"] = registration.json()["credential"]
            legacy_header = await client.get(_agent_path(client, "/jobs/next"))
            after = path.read_text(encoding="utf-8")
    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert wrong_path.status_code == 403
    assert legacy_header.status_code == 401
    assert before == after


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
            before = path.read_bytes()
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
    assert path.read_bytes() == before


@pytest.mark.anyio
async def test_renew_rotates_lease_and_old_token_fails(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            job = await _queue_and_lease(client)
            renewed = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/lease/renew"),
                json={"lease_token": job["lease_token"]},
            )
            assert renewed.status_code == 200, renewed.text
            rotated = renewed.json()["job"]
            assert rotated["lease_token"] != job["lease_token"]
            rejected = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=_result(job),
            )
            accepted = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=_result(rotated),
            )
    assert rejected.status_code == 409
    assert accepted.status_code == 200


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
            job = await _queue_and_lease(client)
            original_deadline = job["lease_deadline_at"]
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
    assert rotated["lease_deadline_at"] == original_deadline
    assert rotated["lease_expires_at"] == original_deadline
    assert stale.status_code == 409
    assert stale.json()["detail"]["reason_code"] == "lease_invalid"
    assert exhausted.status_code == 409
    assert exhausted.json()["detail"]["reason_code"] == "lease_expired"
    stored = json.loads(path.read_text(encoding="utf-8"))["jobs"][0]
    assert stored["status"] == "orphaned"
    assert stored["lease_digest"] is None
    assert stored["completed_at"] is None


@pytest.mark.anyio
async def test_result_assignment_mismatch_has_zero_mutation_and_server_owns_status(tmp_path):
    srv = DashboardServer(auth=False)
    path = tmp_path / "agents.json"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        async with _client(srv.create_app()) as client:
            await _register(client)
            job = await _queue_and_lease(client)
            before = path.read_text(encoding="utf-8")
            forged = await client.post(
                _agent_path(client, f"/jobs/{job['id']}/result"),
                json=_result(job, target="http://outside.test", status="completed", verified=True),
            )
            assert forged.status_code == 409
            assert path.read_text(encoding="utf-8") == before
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
    assert accepted.status_code == 200
    stored = json.loads(path.read_text(encoding="utf-8"))["jobs"][0]
    assert stored["status"] == "failed"
    assert "verified" not in stored
    assert stored["tenant_id"] == "default"


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
    persisted = path.read_text(encoding="utf-8")
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
    assert conflict.json()["detail"]["reason_code"] == "result_conflict"
    persisted = path.read_text(encoding="utf-8")
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
            after_first = path.read_text(encoding="utf-8")
            duplicate = await client.post(_agent_path(client, f"/jobs/{job['id']}/result"), json=payload)
            conflicting_payload = copy.deepcopy(payload)
            conflicting_payload["result"] = {"findings": [{"id": "different", "secret": canary}]}
            conflict = await client.post(_agent_path(client, f"/jobs/{job['id']}/result"), json=conflicting_payload)
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
    assert conflict.json()["detail"]["reason_code"] == "result_conflict"
    assert wrong_lease.status_code == 409
    assert path.read_text(encoding="utf-8") == after_first
    assert "agent.result.conflict" in audit_text
    assert job["id"] in audit_text
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
            job = await _queue_and_lease(client)
            clock[0] += timedelta(minutes=10)
            expired = await client.post(_agent_path(client, f"/jobs/{job['id']}/result"), json=_result(job))
    assert expired.status_code == 409
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["jobs"][0]["status"] == "orphaned"
    assert stored["jobs"][0]["completed_at"] is None


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
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["agents"][_agent_id(client)]["revoked"] is True
    assert stored["jobs"][0]["status"] == "orphaned"
    assert stored["jobs"][0]["completed_at"] is None


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
            before = path.read_bytes() if path.exists() else None
            with patch("common.dashboard.server.os.replace", side_effect=OSError(canary)):
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
    assert response.status_code == 503
    assert response.json()["detail"]["reason_code"] == "agent_state_persistence_failed"
    assert "credential" not in response.text.lower()
    assert "lease_token" not in response.text
    assert canary not in response.text
    assert (path.read_bytes() if path.exists() else None) == before
    assert not list(tmp_path.glob(".agents.json.*.tmp"))


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
            denied = await _register(client, agent_id="agent-corrupt")
            assert denied.status_code == 503
            assert denied.json()["detail"]["reason_code"] == "agent_state_persistence_failed"
            assert "credential" not in denied.text.lower()
            assert path.read_bytes() == before
            path.unlink()
            recovered = await _register(client, agent_id="agent-corrupt")
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
    canary = "CANARY_AGENT_STATE_READ_005"
    with patch.object(DashboardServer, "_agents_path", new_callable=PropertyMock, return_value=path):
        with patch(
            "common.dashboard.server._read_artifact_text",
            side_effect=OSError(canary),
        ):
            async with _client(srv.create_app()) as client:
                denied = await _register(client, agent_id="agent-read-failure")
    assert denied.status_code == 503
    assert denied.json()["detail"]["reason_code"] == "agent_state_persistence_failed"
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
        before = shared_path.read_bytes()
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
    assert shared_path.read_bytes() == before


@pytest.mark.anyio
async def test_concurrent_job_creation_serializes_without_lost_update(tmp_path):
    path = tmp_path / "agents.json"

    class SynchronizedServer(DashboardServer):
        def __init__(self) -> None:
            self._test_agents_path = path
            self._test_preflight_barrier = threading.Barrier(2)
            self._test_preflight_calls = 0
            self._test_preflight_calls_lock = threading.Lock()
            self._test_preflight_enabled = False
            super().__init__(auth=False)

        @property
        def _agents_path(self) -> Path:
            return self._test_agents_path

        def _load_agent_job_preflight_state(self) -> dict[str, Any]:
            state = super()._load_agent_job_preflight_state()
            should_wait = False
            if self._test_preflight_enabled:
                with self._test_preflight_calls_lock:
                    if self._test_preflight_calls < 2:
                        self._test_preflight_calls += 1
                        should_wait = True
            if should_wait:
                self._test_preflight_barrier.wait(timeout=5)
            return state

    srv = SynchronizedServer()
    async with _client(srv.create_app()) as owner:
        registered = await _register(owner)
        assert registered.status_code == 200
        agent_id = _agent_id(owner)

    srv._test_preflight_enabled = True

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

    assert srv._test_preflight_calls == 2
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored_ids = [job["id"] for job in stored["jobs"]]
    response_ids = [str(response["id"]) for response in responses]
    assert len(stored_ids) == 2
    assert sorted(stored_ids) == sorted(response_ids)
    assert len(set(stored_ids)) == 2
