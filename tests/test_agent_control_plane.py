from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import PropertyMock, patch

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from common.action_authorization import SafetyMode, module_set_binding
from common.confirm_gate import ActionConfirmation
from common.scope import ScopeReason


@pytest.fixture(autouse=True)
def _isolated_dashboard_authorization_db(tmp_path, monkeypatch) -> None:
    from common.dashboard.server import DashboardServer

    monkeypatch.setenv("FORGE_AGENT_REGISTRATION_TOKEN", "task004-agent-token")
    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda self: tmp_path / "agent-control-plane.db"),
    )


def _make_async_client(app):
    from common.dashboard.auth import Role, issue_identity_token

    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={
            "Authorization": f"Bearer {issue_identity_token('agent-test', Role.ADMIN)}",
            "X-Forge-Agent-Token": "task004-agent-token",
        },
    )


async def _register_agent(client, payload):
    response = await client.post("/api/v1/agents/register", json=payload)
    if response.status_code == 200:
        client.headers.pop("X-Forge-Agent-Token", None)
        client.headers["X-Forge-Agent-Credential"] = response.json()["credential"]
        client.forge_agent_id = response.json()["agent"]["id"]
    return response


def _confirmation(
    job_id: str,
    target: str,
    engine: str = "webforge",
    action: str = "scan",
    **kwargs,
) -> dict[str, object]:
    return ActionConfirmation.create(
        job_id=job_id,
        target=target,
        engine=engine,
        action=action,
        **kwargs,
    ).to_dict()


class TestAgentControlPlane(unittest.IsolatedAsyncioTestCase):
    async def test_agent_registers_leases_and_submits_redacted_result(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with tempfile.TemporaryDirectory() as tmpdir:
            agents_path = Path(tmpdir) / "agents.json"
            with patch.object(
                DashboardServer,
                "_agents_path",
                new_callable=PropertyMock,
                return_value=agents_path,
            ):
                async with _make_async_client(app) as client:
                    register = await _register_agent(
                        client,
                        {
                            "agent_id": "agent-1",
                            "name": "Lab Agent",
                            "engines": ["webforge", "netforge"],
                            "scope": ["10.0.0.0/24", "example.test"],
                            "active_scan_enabled": False,
                            "mtls_subject": "CN=agent-1",
                        },
                    )
                    agent_id = register.json()["agent"]["id"]
                    create = await client.post(
                        "/api/v1/agents/jobs",
                        json={
                            "job_id": "agent-dry-1",
                            "agent_id": agent_id,
                            "engine": "webforge",
                            "target": "http://example.test/login",
                            "scope": ["example.test"],
                            "modules": ["header_audit"],
                        },
                    )
                    job_id = create.json()["job"]["id"]
                    lease = await client.get(f"/api/v1/agents/{agent_id}/jobs/next")
                    leased_job = lease.json()["job"]
                    submission = {
                        "lease_token": leased_job["lease_token"],
                        "delivery_idempotency_key": leased_job[
                            "delivery_idempotency_key"
                        ],
                        "outcome": "success",
                        "tenant_id": leased_job["tenant_id"],
                        "job_id": leased_job["id"],
                        "agent_id": leased_job["agent_id"],
                        "attempt_id": leased_job["attempt_id"],
                        "run_id": leased_job["run_id"],
                        "engine": leased_job["engine"],
                        "capability": leased_job["capability"],
                        "module_binding": module_set_binding(leased_job["modules"]),
                        "target": leased_job["target"],
                        "authorization_id": leased_job["authorization_id"],
                        "status": "failed",
                        "error": "Bearer CANARY_AGENT_ERROR_002",
                        "result": {
                            "findings": [],
                            "token": "must-not-persist",
                            "nested": {"password": "must-not-persist"},
                        },
                    }
                    submit = await client.post(
                        f"/api/v1/agents/{agent_id}/jobs/{job_id}/result",
                        json=submission,
                    )
                    replay = await client.post(
                        f"/api/v1/agents/{agent_id}/jobs/{job_id}/result",
                        json=submission,
                    )
                    state = await client.get("/api/v1/agents")

        self.assertEqual(register.status_code, 200, register.text)
        self.assertEqual(create.status_code, 200, create.text)
        self.assertEqual(lease.status_code, 200, lease.text)
        self.assertEqual(submit.status_code, 200, submit.text)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["status"], "duplicate")
        self.assertEqual(state.status_code, 200, state.text)
        self.assertEqual(lease.json()["job"]["id"], job_id)
        redacted = submit.json()["job"]["result"]
        self.assertEqual(redacted["token"], "<redacted>")
        self.assertEqual(redacted["nested"]["password"], "<redacted>")
        self.assertNotIn("CANARY_AGENT_ERROR_002", submit.text)
        self.assertNotIn("CANARY_AGENT_ERROR_002", state.text)
        self.assertFalse(agents_path.exists())
        stored = srv._durable_job_state().get_job(
            job_id,
            tenant_id=srv.tenant_id,
        )
        self.assertIsNotNone(stored)
        self.assertNotIn("CANARY_AGENT_ERROR_002", json.dumps(stored))
        self.assertEqual(
            srv._durable_job_state().conn.execute(
                "SELECT COUNT(*) FROM canonical_observations "
                "WHERE tenant_id=? AND job_id=? AND attempt_id=?",
                (srv.tenant_id, job_id, leased_job["attempt_id"]),
            ).fetchone()[0],
            1,
        )
        self.assertEqual(state.json()["counts"]["completed_jobs"], 1)

    async def test_agent_retry_preserves_both_attempt_observations_and_evidence(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        async with _make_async_client(app) as client:
            register = await _register_agent(
                client,
                {
                    "agent_id": "agent-retry",
                    "engines": ["webforge"],
                    "scope": ["retry.example.test"],
                },
            )
            agent_id = register.json()["agent"]["id"]
            create = await client.post(
                "/api/v1/agents/jobs",
                json={
                    "job_id": "agent-retry-job",
                    "agent_id": agent_id,
                    "engine": "webforge",
                    "target": "https://retry.example.test/fixture",
                    "scope": ["retry.example.test"],
                    "modules": ["header_audit"],
                    "max_attempts": 2,
                },
            )
            job_id = create.json()["job"]["id"]

            async def submit_attempt(outcome: str) -> tuple[dict, httpx.Response]:
                lease = await client.get(
                    f"/api/v1/agents/{agent_id}/jobs/next"
                )
                assert lease.status_code == 200, lease.text
                assignment = lease.json()["job"]
                submission = {
                    "lease_token": assignment["lease_token"],
                    "delivery_idempotency_key": assignment[
                        "delivery_idempotency_key"
                    ],
                    "outcome": outcome,
                    "tenant_id": assignment["tenant_id"],
                    "job_id": assignment["id"],
                    "agent_id": assignment["agent_id"],
                    "attempt_id": assignment["attempt_id"],
                    "run_id": assignment["run_id"],
                    "engine": assignment["engine"],
                    "capability": assignment["capability"],
                    "module_binding": module_set_binding(
                        assignment["modules"]
                    ),
                    "target": assignment["target"],
                    "authorization_id": assignment["authorization_id"],
                    "error": (
                        "fixture first-attempt failure"
                        if outcome == "failure"
                        else None
                    ),
                    "result": {"attempt_outcome": outcome},
                }
                return assignment, await client.post(
                    f"/api/v1/agents/{agent_id}/jobs/{job_id}/result",
                    json=submission,
                )

            first, first_result = await submit_attempt("failure")
            second, second_result = await submit_attempt("success")

        self.assertEqual(create.status_code, 200, create.text)
        self.assertEqual(first_result.status_code, 200, first_result.text)
        self.assertEqual(first_result.json()["job"]["status"], "queued")
        self.assertEqual(second_result.status_code, 200, second_result.text)
        self.assertEqual(second_result.json()["job"]["status"], "completed")
        self.assertNotEqual(first["attempt_id"], second["attempt_id"])
        service = srv._durable_job_state()
        self.assertEqual(
            [
                attempt["state"]
                for attempt in service.list_attempts(
                    job_id,
                    tenant_id=srv.tenant_id,
                )
            ],
            ["failed", "completed"],
        )
        observations = service.conn.execute(
            "SELECT attempt_id,id FROM canonical_observations "
            "WHERE tenant_id=? AND job_id=? ORDER BY created_at",
            (srv.tenant_id, job_id),
        ).fetchall()
        self.assertEqual(
            {str(row["attempt_id"]) for row in observations},
            {first["attempt_id"], second["attempt_id"]},
        )
        self.assertEqual(len(observations), 2)
        self.assertEqual(
            service.conn.execute(
                "SELECT COUNT(*) FROM canonical_artifact_manifests "
                "WHERE tenant_id=? AND observation_id IN (?,?)",
                (
                    srv.tenant_id,
                    str(observations[0]["id"]),
                    str(observations[1]["id"]),
                ),
            ).fetchone()[0],
            2,
        )

    async def test_agent_job_rejects_scope_escape_and_secret_fields(self):
        from common.dashboard.server import DashboardServer
        from common.db import AuthorizationDecisionModel, create_db

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with tempfile.TemporaryDirectory() as tmpdir:
            agents_path = Path(tmpdir) / "agents.json"
            with patch.object(
                DashboardServer,
                "_agents_path",
                new_callable=PropertyMock,
                return_value=agents_path,
            ):
                async with _make_async_client(app) as client:
                    registration = await _register_agent(
                        client,
                        {
                            "agent_id": "agent-1",
                            "engines": ["webforge"],
                            "scope": ["example.test"],
                        },
                    )
                    agent_id = registration.json()["agent"]["id"]
                    out_of_scope = await client.post(
                        "/api/v1/agents/jobs",
                        json={
                            "job_id": "agent-outside",
                            "agent_id": agent_id,
                            "engine": "webforge",
                            "target": "http://outside.test",
                            "scope": ["outside.test"],
                        },
                    )
                    secret_field = await client.post(
                        "/api/v1/agents/jobs",
                        json={
                            "job_id": "agent-secret",
                            "agent_id": agent_id,
                            "engine": "webforge",
                            "target": "http://example.test",
                            "scope": ["example.test"],
                            "password": "nope",
                        },
                    )

        self.assertEqual(out_of_scope.status_code, 403)
        self.assertEqual(
            out_of_scope.json()["detail"]["reason_code"],
            ScopeReason.TARGET_MISMATCH.value,
        )
        self.assertEqual(secret_field.status_code, 400)
        self.assertIn("may not contain secrets", secret_field.json()["detail"])
        session = create_db(srv._scan_jobs_db_path)
        try:
            rows = session.query(AuthorizationDecisionModel).all()
        finally:
            session.close()
        reasons = [row.reason_code for row in rows]
        self.assertIn(ScopeReason.TARGET_MISMATCH.value, reasons)
        self.assertIn(ScopeReason.INVALID_CONFIRMATION.value, reasons)
        self.assertTrue(all(row.job_id.startswith("job-") for row in rows))
        self.assertNotIn("agent-outside", {row.job_id for row in rows})
        self.assertNotIn("agent-secret", {row.job_id for row in rows})

    async def test_agent_registration_rejects_empty_and_malformed_scope_before_state_write(self):
        from common.dashboard.server import DashboardServer
        from common.db import AuthorizationDecisionModel, create_db

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with tempfile.TemporaryDirectory() as tmpdir:
            agents_path = Path(tmpdir) / "agents.json"
            with patch.object(
                DashboardServer,
                "_agents_path",
                new_callable=PropertyMock,
                return_value=agents_path,
            ):
                async with _make_async_client(app) as client:
                    empty = await _register_agent(
                        client,
                        {"agent_id": "empty-agent", "scope": []},
                    )
                    malformed = await _register_agent(
                        client,
                        {"agent_id": "bad-agent", "scope": ["10.0.0.1/999"]},
                    )

            self.assertFalse(agents_path.exists())

        self.assertEqual(empty.status_code, 403)
        self.assertEqual(empty.json()["detail"]["reason_code"], ScopeReason.MISSING_SCOPE.value)
        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(malformed.json()["detail"]["reason_code"], ScopeReason.MALFORMED_SCOPE.value)
        session = create_db(srv._scan_jobs_db_path)
        try:
            reasons = [
                row.reason_code
                for row in session.query(AuthorizationDecisionModel).all()
            ]
        finally:
            session.close()
        self.assertEqual(
            reasons,
            [ScopeReason.MISSING_SCOPE.value, ScopeReason.MALFORMED_SCOPE.value],
        )

    async def test_agent_registration_rejects_truthy_non_boolean_active_flag(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with tempfile.TemporaryDirectory() as tmpdir:
            agents_path = Path(tmpdir) / "agents.json"
            with patch.object(
                DashboardServer,
                "_agents_path",
                new_callable=PropertyMock,
                return_value=agents_path,
            ):
                async with _make_async_client(app) as client:
                    response = await _register_agent(
                        client,
                        {
                            "agent_id": "bad-active-flag",
                            "scope": ["127.0.0.1/32"],
                            "active_scan_enabled": "false",
                        },
                    )

            self.assertFalse(agents_path.exists())

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json()["detail"]["reason_code"],
            ScopeReason.INVALID_CONFIRMATION.value,
        )

    async def test_active_agent_job_requires_exact_confirmation_and_revalidates_at_lease(self):
        from common.dashboard.server import DashboardServer

        target = "http://127.0.0.1:8080/fixture"
        job_id = "agent-active-loopback"
        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with tempfile.TemporaryDirectory() as tmpdir:
            agents_path = Path(tmpdir) / "agents.json"
            with patch.object(
                DashboardServer,
                "_agents_path",
                new_callable=PropertyMock,
                return_value=agents_path,
            ):
                async with _make_async_client(app) as client:
                    register = await _register_agent(
                        client,
                        {
                            "agent_id": "agent-active",
                            "engines": ["webforge"],
                            "scope": ["127.0.0.0/8"],
                            "excluded_scope": ["127.0.0.2/32"],
                            "active_scan_enabled": True,
                        },
                    )
                    agent_id = register.json()["agent"]["id"]
                    create = await client.post(
                        "/api/v1/agents/jobs",
                        json={
                            "job_id": job_id,
                            "agent_id": agent_id,
                            "engine": "webforge",
                            "target": target,
                            "scope": ["127.0.0.1/32"],
                            "exclude": [],
                            "dry_run": False,
                            "max_attempts": 2,
                            "safety_mode": "passive",
                            "confirmation": _confirmation(job_id, target),
                        },
                    )
                    lease = await client.get(f"/api/v1/agents/{agent_id}/jobs/next")
                    leased_for_result = lease.json().get("job", {})
                    submit = await client.post(
                        f"/api/v1/agents/{agent_id}/jobs/"
                        f"{leased_for_result.get('id')}/result",
                        json={
                            "lease_token": leased_for_result.get("lease_token"),
                            "delivery_idempotency_key": leased_for_result.get(
                                "delivery_idempotency_key"
                            ),
                            "outcome": "success",
                            "tenant_id": leased_for_result.get("tenant_id"),
                            "job_id": leased_for_result.get("id"),
                            "agent_id": leased_for_result.get("agent_id"),
                            "attempt_id": leased_for_result.get("attempt_id"),
                            "run_id": leased_for_result.get("run_id"),
                            "engine": leased_for_result.get("engine"),
                            "capability": leased_for_result.get("capability"),
                            "module_binding": module_set_binding(
                                leased_for_result.get("modules") or []
                            ),
                            "target": leased_for_result.get("target"),
                            "authorization_id": leased_for_result.get(
                                "authorization_id"
                            ),
                            "result": {"return_code": 0},
                        },
                    )
                    retry_without_authorization = await client.get(
                        f"/api/v1/agents/{agent_id}/jobs/next"
                    )

        self.assertEqual(register.status_code, 200, register.text)
        self.assertEqual(create.status_code, 200, create.text)
        self.assertEqual(lease.status_code, 200, lease.text)
        self.assertEqual(submit.status_code, 200, submit.text)
        self.assertEqual(
            retry_without_authorization.status_code,
            200,
            retry_without_authorization.text,
        )
        self.assertIsNone(retry_without_authorization.json()["job"])
        leased_job = lease.json()["job"]
        self.assertEqual(leased_job["client_job_id"], job_id)
        self.assertEqual(leased_job["id"], create.json()["job"]["id"])
        self.assertTrue(leased_job["id"].startswith("job-"))
        self.assertTrue(leased_job["authorized"])
        self.assertEqual(leased_job["safety_mode"], SafetyMode.ACTIVE.value)
        self.assertEqual(
            leased_job["authorization_envelope"]["safety_mode"],
            SafetyMode.ACTIVE.value,
        )
        self.assertEqual(leased_job["scope_decision"]["reason_code"], ScopeReason.ALLOWED.value)
        self.assertEqual(
            submit.json()["job"]["status"],
            "pending_approval",
        )
        durable = srv._durable_job_state().get_job(
            leased_job["id"],
            tenant_id=srv.tenant_id,
        )
        self.assertEqual(durable["state"], "pending_approval")
        self.assertIsNone(durable["terminal_at"])
        self.assertEqual(
            srv._durable_job_state().list_events(
                leased_job["id"],
                tenant_id=srv.tenant_id,
            )[-1]["reason_code"],
            "active_retry_requires_fresh_authorization",
        )

    async def test_agent_job_rejects_excluded_stale_mismatched_and_forged_confirmations(self):
        from common.dashboard.server import DashboardServer

        target = "http://127.0.0.1:8080/fixture"
        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with tempfile.TemporaryDirectory() as tmpdir:
            agents_path = Path(tmpdir) / "agents.json"
            with patch.object(
                DashboardServer,
                "_agents_path",
                new_callable=PropertyMock,
                return_value=agents_path,
            ):
                async with _make_async_client(app) as client:
                    registration = await _register_agent(
                        client,
                        {
                            "agent_id": "agent-negative",
                            "engines": ["webforge", "netforge"],
                            "scope": ["127.0.0.0/8"],
                            "active_scan_enabled": True,
                        },
                    )
                    agent_id = registration.json()["agent"]["id"]
                    stale = _confirmation(
                        "stale-job",
                        target,
                        issued_at=datetime.now(timezone.utc) - timedelta(minutes=10),
                    )
                    forged = _confirmation("forged-job", target)
                    forged["target"] = "http://127.0.0.2:8080/fixture"
                    cases = [
                        (
                            "excluded-job",
                            _confirmation("excluded-job", target),
                            ["127.0.0.1/32"],
                            ScopeReason.EXCLUDED,
                        ),
                        ("stale-job", stale, [], ScopeReason.STALE_CONFIRMATION),
                        (
                            "wrong-job",
                            _confirmation("another-job", target),
                            [],
                            ScopeReason.JOB_MISMATCH,
                        ),
                        (
                            "wrong-engine",
                            _confirmation("wrong-engine", target, engine="netforge"),
                            [],
                            ScopeReason.ENGINE_MISMATCH,
                        ),
                        (
                            "wrong-target",
                            _confirmation("wrong-target", "http://127.0.0.2:8080/fixture"),
                            [],
                            ScopeReason.TARGET_MISMATCH,
                        ),
                        ("forged-job", forged, [], ScopeReason.INVALID_CONFIRMATION),
                    ]
                    responses = []
                    for case_job_id, confirmation, excluded, reason in cases:
                        response = await client.post(
                            "/api/v1/agents/jobs",
                            json={
                                "job_id": case_job_id,
                                "agent_id": agent_id,
                                "engine": "webforge",
                                "target": target,
                                "scope": ["127.0.0.0/8"],
                                "exclude": excluded,
                                "dry_run": False,
                                "confirmation": confirmation,
                            },
                        )
                        responses.append((response, reason))

        for response, reason in responses:
            self.assertIn(response.status_code, {400, 403}, response.text)
            self.assertEqual(response.json()["detail"]["reason_code"], reason.value)

    async def test_agent_scope_change_invalidates_queued_job_before_lease(self):
        from common.dashboard.server import DashboardServer

        target = "http://127.0.0.1:8080/fixture"
        job_id = "agent-stale-scope"
        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with tempfile.TemporaryDirectory() as tmpdir:
            agents_path = Path(tmpdir) / "agents.json"
            with patch.object(
                DashboardServer,
                "_agents_path",
                new_callable=PropertyMock,
                return_value=agents_path,
            ):
                async with _make_async_client(app) as client:
                    registration = await _register_agent(
                        client,
                        {
                            "agent_id": "agent-stale",
                            "engines": ["webforge"],
                            "scope": ["127.0.0.0/8"],
                            "active_scan_enabled": True,
                        },
                    )
                    agent_id = registration.json()["agent"]["id"]
                    created = await client.post(
                        "/api/v1/agents/jobs",
                        json={
                            "job_id": job_id,
                            "agent_id": agent_id,
                            "engine": "webforge",
                            "target": target,
                            "scope": ["127.0.0.0/8"],
                            "dry_run": False,
                            "confirmation": _confirmation(job_id, target),
                        },
                    )
                    await _register_agent(
                        client,
                        {
                            "agent_id": agent_id,
                            "engines": ["webforge"],
                            "scope": ["127.0.0.2/32"],
                            "active_scan_enabled": True,
                        },
                    )
                    lease = await client.get(f"/api/v1/agents/{agent_id}/jobs/next")

        self.assertEqual(created.status_code, 200, created.text)
        self.assertEqual(lease.status_code, 403, lease.text)
        server_job_id = created.json()["job"]["id"]
        job = srv._durable_job_state().get_job(
            server_job_id,
            tenant_id=srv.tenant_id,
        )
        self.assertIsNotNone(job)
        self.assertEqual(job["payload"]["client_job_id"], job_id)
        self.assertEqual(job["state"], "canceled")
        self.assertEqual(job["terminal_reason"], ScopeReason.TARGET_MISMATCH.value)
        self.assertEqual(
            srv._durable_job_state().list_attempts(
                server_job_id,
                tenant_id=srv.tenant_id,
            ),
            [],
        )
        self.assertFalse(agents_path.exists())


class TestFindingStatusPersistence(unittest.IsolatedAsyncioTestCase):
    async def test_dashboard_status_patch_updates_persisted_finding(self):
        from common.dashboard.server import DashboardServer
        from common.db import create_db
        from sqlalchemy import text
        from tests.test_scanbuilder_module_mapping import (
            _seed_canonical_dashboard_finding,
        )

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "scan_jobs.db"

            with patch.object(
                DashboardServer,
                "_scan_jobs_db_path",
                new_callable=PropertyMock,
                return_value=db_path,
            ):
                canonical_id = _seed_canonical_dashboard_finding(
                    srv,
                    db_path,
                    tmp_path,
                    finding_id="finding-1",
                    module="header_audit",
                    target="https://example.test/",
                    title="Stored Finding",
                )
                async with _make_async_client(app) as client:
                    resp = await client.patch(
                        f"/api/v1/findings/{canonical_id}/status",
                        json={
                            "expected_version": 0,
                            "status": "False Positive",
                        },
                    )
                canonical_db = srv._canonical_database_paths(
                    srv._canonical_result_roots()[0]
                )[0]
                session = create_db(canonical_db)
                try:
                    persisted_status = session.execute(
                        text(
                            "SELECT status FROM canonical_finding_review_current "
                            "WHERE tenant_id=:tenant_id AND finding_id=:finding_id"
                        ),
                        {
                            "tenant_id": srv.tenant_id,
                            "finding_id": canonical_id,
                        },
                    ).scalar_one()
                    session.rollback()
                finally:
                    session.close()

        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(resp.json()["persisted"])
        self.assertEqual(resp.json()["review"]["status"], "false_positive")
        self.assertEqual(resp.json()["review"]["version"], 1)
        self.assertEqual(persisted_status, "false_positive")


class TestBrainAndChainDashboardEvents(unittest.TestCase):
    def test_state_store_tracks_brain_verdict_and_chain_action(self):
        from common.dashboard.event_bus import EventBus, EventType
        from common.dashboard.state_store import StateStore

        bus = EventBus()
        bus.start()
        store = StateStore(bus, framework="forge", target="https://example.test")

        bus.emit_simple(
            EventType.FINDING_NEW,
            source="sqli_scanner",
            id="finding-1",
            title="SQL Injection",
            severity="Critical",
            module="sqli_scanner",
            target="https://example.test",
            confidence="HIGH",
        )
        bus.emit_simple(
            EventType.BRAIN_VERDICT,
            source="brain",
            finding_id="finding-1",
            verdict="CONFIRMED",
            confidence="HIGH",
            reasoning="FPReducer supplied two confirming probes",
        )
        bus.emit_simple(
            EventType.CHAIN_ACTION_NEW,
            source="engagement_bus",
            chain_type="sqli_to_cred_spray",
            source_finding="finding-1",
            source_framework="webforge",
            target_framework="netforge",
            target_module="cred_spray",
            rationale="Verified SQLi can expose reusable credentials",
        )

        import time as _time
        _time.sleep(0.3)
        bus.stop()

        snap = store.snapshot()
        self.assertEqual(snap["brain_verdicts"][0]["finding"], "SQL Injection")
        self.assertEqual(snap["brain_verdicts"][0]["confidence"], "HIGH")
        self.assertEqual(snap["chain_actions"][0]["target_module"], "cred_spray")
        self.assertTrue(
            any(item["type"] == "chain_action" for item in snap["timeline"])
        )

    def test_engagement_bus_emits_first_class_brain_and_chain_events(self):
        from common.brain.engagement_bus import EngagementBus
        from common.dashboard.event_bus import EventBus, EventType

        class RuleBrain:
            available = True

            async def analyze_finding(self, finding):
                class Result:
                    class Value:
                        def __init__(self, value):
                            self.value = value

                    verdict = Value("CONFIRMED")
                    confidence = Value("HIGH")
                    reasoning = "Rule-based test verdict"

                return Result()

        with tempfile.TemporaryDirectory() as tmpdir:
            events = EventBus()
            seen = []
            events.subscribe(None, lambda event: seen.append(event.event_type))
            events.start()
            bus = EngagementBus(
                db_path=str(Path(tmpdir) / "engagement.db"),
                brain=RuleBrain(),
                event_bus=events,
            )
            try:
                import asyncio

                async def publish_and_wait():
                    await bus.publish("webforge", {
                        "id": "finding-1",
                        "title": "SQL Injection in id",
                        "severity": "Critical",
                        "target": "https://example.test/item?id=1",
                        "module": "sqli_scanner",
                        "confidence": "HIGH",
                    })
                    await asyncio.sleep(0.2)

                asyncio.run(publish_and_wait())
                import time as _time
                _time.sleep(0.3)
            finally:
                bus.close()
                events.stop()

        self.assertIn(EventType.FINDING_NEW, seen)
        self.assertIn(EventType.CHAIN_ACTION_NEW, seen)
        self.assertIn(EventType.BRAIN_VERDICT, seen)


if __name__ == "__main__":
    unittest.main()
