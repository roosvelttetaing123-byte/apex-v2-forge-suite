import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import httpx

from common.confirm_gate import ActionConfirmation

sys.path.insert(0, str(Path(__file__).parent.parent))


def _make_async_client(app):
    from common.dashboard.auth import Role, issue_identity_token

    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {issue_identity_token('scanbuilder-test', Role.ADMIN)}"},
    )


def _web_launch_contract(job_id: str, target: str = "http://127.0.0.1:8080") -> dict:
    return {
        "job_id": job_id,
        "scope": ["127.0.0.1/32"],
        "exclude": [],
        "confirmation": ActionConfirmation.create(
            job_id=job_id,
            target=target,
            engine="webforge",
            action="scan",
        ).to_dict(),
    }


def _seed_canonical_dashboard_finding(
    server,
    scan_jobs_db: Path,
    tmp_path: Path,
    *,
    finding_id: str,
    module: str,
    target: str,
    title: str,
    credential_reference: str = "",
) -> str:
    from common.action_authorization import (
        AuthorizationContext,
        ConfirmationMethod,
        OperatorRole,
        SafetyMode,
        consume_authorization,
        issue_authorization,
    )
    from common.canonical_evidence import (
        CanonicalEvidenceContext,
        CanonicalEvidenceService,
    )
    from common.db import ScanJobModel, create_db
    from common.evidence import Evidence
    from common.finding import Finding, Severity
    from common.job_state import JobState, JobStateService

    scan_id = f"canonical-source-{finding_id}"
    server._scan_results_dir = tmp_path / "scan-results"
    server._scan_results_dir.mkdir(mode=0o700)
    result_root = server._allocate_scan_results_dir(scan_id)
    authorization_context = AuthorizationContext(
        tenant_id=server.tenant_id,
        engagement_id="engagement-retest-fixture",
        run_id="run-retest-fixture",
        job_id=scan_id,
        operator_id="operator-retest-fixture",
        operator_role=OperatorRole.OPERATOR,
        engine="webforge",
        module_id=module,
        action_kind="module.execute",
        requested_target=target,
        resolved_target=target,
        allowed_scope=[target],
        excluded_scope=[],
        scope_policy_version="scope-policy-v1",
        safety_mode=SafetyMode.ACTIVE,
        credential_approval_required=bool(credential_reference),
        credential_reference=credential_reference,
        confirmation_method=ConfirmationMethod.CLI_PROMPT,
        confirmed_by="operator-retest-fixture",
    )
    scan_session = create_db(scan_jobs_db)
    try:
        issued = issue_authorization(
            session=scan_session,
            context=authorization_context,
            confirmation=ActionConfirmation.create(
                job_id=scan_id,
                target=target,
                engine="webforge",
                action="module.execute",
            ),
        )
        assert issued.allowed is True
        consumed = consume_authorization(
            session=scan_session,
            envelope=issued.envelope,
            expected=authorization_context,
            boundary="webforge.module",
        )
        assert consumed.allowed is True
        scan_session.add(
            ScanJobModel(
                id=scan_id,
                tenant_id=server.tenant_id,
                status="completed",
                target=target,
                frameworks=json.dumps(["webforge"]),
                modules=json.dumps([module]),
                results_dir=str(result_root),
                logs=json.dumps({}),
                authorization_state="allow",
                authorization_decision_id=issued.envelope.decision_id,
                authorization_action_id=issued.envelope.action_id,
            )
        )
        scan_session.commit()
    finally:
        scan_bind = scan_session.bind
        scan_session.close()
        if scan_bind is not None:
            scan_bind.dispose()
    result_jobs = JobStateService(
        result_root / "webforge.db",
        authorization_checker=lambda *_args: True,
    )
    result_jobs.create_job(
        tenant_id=server.tenant_id,
        job_id=issued.envelope.job_id,
        engagement_id=issued.envelope.engagement_id,
        run_id=issued.envelope.run_id,
        job_kind="webforge",
        target=target,
        authorization_decision_id=issued.envelope.decision_id,
        authorization_action_id=issued.envelope.action_id,
        state=JobState.QUEUED,
        work_items=(module,),
    )
    original_attempt = result_jobs.acquire_lease(
        issued.envelope.job_id,
        "fixture-worker",
        tenant_id=server.tenant_id,
        attempt_id=f"attempt-{finding_id}",
        idempotency_key=f"attempt-{finding_id}",
    )
    result_jobs.start_attempt(
        str(original_attempt["id"]),
        str(original_attempt["lease_token"]),
        tenant_id=server.tenant_id,
        worker_id="fixture-worker",
    )
    context = CanonicalEvidenceContext.from_authorization(
        issued.envelope,
        attempt_id=str(original_attempt["id"]),
    )
    finding_session = create_db(result_root / "webforge.db")
    try:
        projection = CanonicalEvidenceService(
            finding_session,
            result_root / "evidence-custody",
            context,
        ).persist_finding(
            Finding(
                id=finding_id,
                title=title,
                severity=Severity.HIGH,
                target=target,
                url=target,
                module=module,
                description="Persisted canonical retest fixture.",
                reproduction_steps=["Inspect the deterministic fixture."],
                remediation="Apply the fixture remediation.",
                references=[],
                confidence="HIGH",
                proof_type="passive",
                verification_state="verified",
                evidence=Evidence(
                    request_raw="GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n",
                    response_raw="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
                    extra={
                        "route": "/",
                        "check_id": module,
                        "header": "Content-Security-Policy",
                        "value": None,
                        "issue": "Missing",
                    }
                ),
            )
        )
    finally:
        finding_bind = finding_session.bind
        finding_session.close()
        if finding_bind is not None:
            finding_bind.dispose()
        result_jobs.close()

    connection = sqlite3.connect(scan_jobs_db)
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("PRAGMA journal_mode=DELETE")
    finally:
        connection.close()
    assert server._canonical_result_roots() == [result_root]
    canonical_id = str(projection["id"])
    assert server._find_finding_metadata(
        canonical_id,
        actor_id="scanbuilder-test",
    ) is not None
    return canonical_id


class TestScanBuilderModuleMapping(unittest.IsolatedAsyncioTestCase):
    async def test_unsupported_module_rejected_without_launch(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with patch("subprocess.Popen") as mock_popen:
            async with _make_async_client(app) as client:
                resp = await client.post(
                    "/api/v1/scans/launch",
                    json={
                        "target": "http://example.com",
                        "mode": "blackbox",
                        "modules": ["sqli", "not-a-module"],
                    },
                )

        self.assertEqual(resp.status_code, 400)
        self.assertIn("Unsupported ScanBuilder module ID", resp.json()["detail"])
        self.assertIn("not-a-module", resp.json()["detail"])
        mock_popen.assert_not_called()

    async def test_launch_without_canonical_lineage_fails_closed(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        history_directory = tempfile.TemporaryDirectory()
        self.addCleanup(history_directory.cleanup)
        history_path = Path(history_directory.name) / "scan-history.json"

        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.wait.return_value = 0
        mock_proc.stdout = []

        with (
            patch.object(
                DashboardServer,
                "_history_path",
                new_callable=PropertyMock,
                return_value=history_path,
            ),
            patch.object(DashboardServer, "_track_scan_process"),
            patch("subprocess.Popen", return_value=mock_proc) as mock_popen,
        ):
            async with _make_async_client(app) as client:
                resp = await client.post(
                    "/api/v1/scans/launch",
                    json={
                        "target": "http://127.0.0.1:8080",
                        "mode": "blackbox",
                        "modules": ["sqli", "xss", "jwt"],
                        **_web_launch_contract("scanbuilder-modules"),
                    },
                )

        self.assertEqual(resp.status_code, 500, resp.text)
        self.assertEqual(
            resp.json()["detail"],
            "Authorization handoff persistence failed; execution denied",
        )
        self.assertFalse(history_path.exists())
        mock_popen.assert_not_called()

    async def test_launch_without_canonical_lineage_does_not_persist_job(self):
        from common.dashboard.server import DashboardServer
        from common.db import ScanJobModel, create_db

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        history_directory = tempfile.TemporaryDirectory()
        self.addCleanup(history_directory.cleanup)
        history_path = Path(history_directory.name) / "scan-history.json"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            scan_jobs_db = tmp_path / "scan_jobs.db"
            logs_dir = tmp_path / "logs"
            controls_dir = tmp_path / "controls"
            logs_dir.mkdir()
            controls_dir.mkdir()
            srv._scan_logs_dir = logs_dir
            srv._control_dir = controls_dir

            mock_proc = MagicMock()
            mock_proc.pid = 4321
            mock_proc.poll.return_value = None
            mock_proc.stdout = []

            with (
                patch.object(
                    DashboardServer,
                    "_history_path",
                    new_callable=PropertyMock,
                    return_value=history_path,
                ),
                patch.object(
                    DashboardServer,
                    "_scan_jobs_db_path",
                    new_callable=PropertyMock,
                    return_value=scan_jobs_db,
                ),
                patch.object(DashboardServer, "_track_scan_process"),
                patch("subprocess.Popen", return_value=mock_proc) as mock_popen,
            ):
                async with _make_async_client(app) as client:
                    resp = await client.post(
                        "/api/v1/scans/launch",
                        json={
                            "target": "http://127.0.0.1:8080",
                            "mode": "blackbox",
                            "modules": ["sqli"],
                            **_web_launch_contract("scanbuilder-durable"),
                        },
                    )

            self.assertEqual(resp.status_code, 503, resp.text)
            self.assertEqual(
                resp.json()["detail"]["reason_code"],
                "mutation_audit_unavailable",
            )
            self.assertFalse(history_path.exists())
            self.assertFalse(any(logs_dir.iterdir()))
            mock_popen.assert_not_called()
            session = create_db(scan_jobs_db)
            try:
                self.assertEqual(session.query(ScanJobModel).count(), 0)
            finally:
                session.close()

    async def test_retest_dry_run_plans_without_legacy_row_or_subprocess(self):
        from common.dashboard.server import DashboardServer
        from common.db import FindingRetestModel, create_db

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            scan_jobs_db = tmp_path / "scan_jobs.db"
            logs_dir = tmp_path / "logs"
            controls_dir = tmp_path / "controls"
            logs_dir.mkdir()
            controls_dir.mkdir()
            srv._scan_logs_dir = logs_dir
            srv._control_dir = controls_dir

            mock_proc = MagicMock()
            mock_proc.pid = 9876
            mock_proc.poll.return_value = None
            mock_proc.stdout = []

            with (
                patch.object(
                    DashboardServer,
                    "_scan_jobs_db_path",
                    new_callable=PropertyMock,
                    return_value=scan_jobs_db,
                ),
                patch.object(DashboardServer, "_track_scan_process"),
                patch("subprocess.Popen", return_value=mock_proc) as mock_popen,
            ):
                canonical_id = _seed_canonical_dashboard_finding(
                    srv,
                    scan_jobs_db,
                    tmp_path,
                    finding_id="finding-123",
                    module="sqli_scanner",
                    target="http://127.0.0.1:8080/login?id=1",
                    title="SQL Injection",
                )
                async with _make_async_client(app) as client:
                    resp = await client.post(
                        f"/api/v1/findings/{canonical_id}/retest",
                        json={
                            "job_id": "retest-dry-plan",
                            "scope": ["127.0.0.1/32"],
                            "exclude": [],
                        },
                    )

            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertEqual(resp.json()["state"], "planned")
            self.assertIsNone(resp.json()["retest_verdict"])
            mock_popen.assert_not_called()

            session = create_db(scan_jobs_db)
            try:
                self.assertEqual(session.query(FindingRetestModel).count(), 0)
            finally:
                session.close()

    async def test_active_header_retest_uses_canonical_verifier_without_subprocess(self):
        from common.dashboard.server import DashboardServer
        from common.retest import HeaderResponse

        target = "http://127.0.0.1:8080/"
        job_id = "retest-active"
        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            srv._scan_logs_dir = tmp_path / "logs"
            srv._control_dir = tmp_path / "controls"
            srv._scan_logs_dir.mkdir()
            srv._control_dir.mkdir()
            process = MagicMock(pid=8765, stdout=[])
            process.poll.return_value = None
            async def fetch_headers(target_url, *_args):
                return HeaderResponse(200, {}, target_url)
            with (
                patch.object(
                    DashboardServer,
                    "_scan_jobs_db_path",
                    new_callable=PropertyMock,
                    return_value=tmp_path / "scan_jobs.db",
                ),
                patch.object(DashboardServer, "_track_scan_process"),
                patch("subprocess.Popen", return_value=process) as popen,
                patch("common.retest._governed_header_fetch", new=fetch_headers),
            ):
                canonical_id = _seed_canonical_dashboard_finding(
                    srv,
                    tmp_path / "scan_jobs.db",
                    tmp_path,
                    finding_id="finding-active-retest",
                    module="header_audit",
                    target=target,
                    title="Header Missing",
                )
                async with _make_async_client(app) as client:
                    response = await client.post(
                        f"/api/v1/findings/{canonical_id}/retest",
                        json={
                            "job_id": job_id,
                            "scope": ["127.0.0.1/32"],
                            "exclude": [],
                            "dry_run": False,
                            "confirmation": ActionConfirmation.create(
                                job_id=job_id,
                                target=target,
                                engine="webforge",
                                action="retest",
                            ).to_dict(),
                        },
                    )
                    refreshed = await client.get("/api/v1/findings?limit=20")
                    exported = await client.post(
                        "/api/v1/findings/export",
                        json={"finding_ids": [canonical_id]},
                    )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["retest_verdict"], "still_vulnerable")
        self.assertEqual(response.json()["state"], "terminal")
        self.assertEqual(refreshed.status_code, 200, refreshed.text)
        persisted = next(
            item
            for item in refreshed.json()["findings"]
            if item["id"] == canonical_id
        )
        self.assertEqual(persisted["retest_verdict"], "still_vulnerable")
        self.assertEqual(persisted["retest_status"], "still_vulnerable")
        self.assertEqual(persisted["status"], "open")
        self.assertTrue(any(
            artifact.get("capture_kind") == "retest_proof"
            for observation in persisted["evidence"]["observations"]
            for artifact in observation["artifacts"]
        ))
        self.assertEqual(exported.status_code, 200, exported.text)
        self.assertEqual(
            exported.json()["findings"][0]["retest_verdict"],
            "still_vulnerable",
        )
        popen.assert_not_called()

    async def test_active_authenticated_header_retest_resolves_only_original_protected_reference(self):
        from contextlib import contextmanager

        from common.credential_boundary import (
            CredentialUseApproval,
            InMemorySecretProvider,
        )
        from common.dashboard.server import DashboardServer
        from common.retest import HeaderResponse

        secret = "DASHBOARD_RETEST_SESSION_SECRET_CANARY"
        provider = InMemorySecretProvider()
        reference = provider.put({"Authorization": f"Bearer {secret}"})

        class Resolver:
            @contextmanager
            def resolve(
                self,
                reference_value,
                *,
                approval: CredentialUseApproval,
                target: str,
            ):
                with provider.resolve(
                    reference_value,
                    approval=approval,
                    target=target,
                ) as values:
                    yield {"headers": values}

        target = "http://127.0.0.1:8080/"
        job_id = "retest-active-authenticated"
        srv = DashboardServer(auth=False, retest_session_resolver=Resolver())
        app = srv.create_app()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            srv._scan_logs_dir = tmp_path / "logs"
            srv._control_dir = tmp_path / "controls"
            srv._scan_logs_dir.mkdir()
            srv._control_dir.mkdir()
            process = MagicMock(pid=8766, stdout=[])
            process.poll.return_value = None
            fetch_calls = 0

            async def fetch_headers(target_url, _policy, headers, cookies):
                nonlocal fetch_calls
                fetch_calls += 1
                self.assertEqual(headers["Authorization"], f"Bearer {secret}")
                self.assertEqual(cookies, {})
                return HeaderResponse(200, {}, target_url)

            with (
                patch.object(
                    DashboardServer,
                    "_scan_jobs_db_path",
                    new_callable=PropertyMock,
                    return_value=tmp_path / "scan_jobs.db",
                ),
                patch.object(DashboardServer, "_track_scan_process"),
                patch("subprocess.Popen", return_value=process) as popen,
                patch("common.retest._governed_header_fetch", new=fetch_headers),
            ):
                canonical_id = _seed_canonical_dashboard_finding(
                    srv,
                    tmp_path / "scan_jobs.db",
                    tmp_path,
                    finding_id="finding-active-authenticated-retest",
                    module="header_audit",
                    target=target,
                    title="Authenticated Header Missing",
                    credential_reference=reference.value,
                )
                async with _make_async_client(app) as client:
                    response = await client.post(
                        f"/api/v1/findings/{canonical_id}/retest",
                        json={
                            "job_id": job_id,
                            "scope": ["127.0.0.1/32"],
                            "exclude": [],
                            "dry_run": False,
                            "confirmation": ActionConfirmation.create(
                                job_id=job_id,
                                target=target,
                                engine="webforge",
                                action="retest",
                            ).to_dict(),
                            "credential_reference": "cred:memory:CLIENT_SUBSTITUTION",
                            "session": secret,
                        },
                    )

            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["retest_verdict"], "still_vulnerable")
            self.assertNotIn(secret, response.text)
            self.assertEqual(fetch_calls, 1)
            self.assertEqual(provider.resolve_calls, 1)
            popen.assert_not_called()
            persisted = b"".join(
                path.read_bytes()
                for path in tmp_path.rglob("*")
                if path.is_file()
            )
            self.assertNotIn(secret.encode("utf-8"), persisted)
        provider.discard_all()

    async def test_active_unregistered_retest_returns_unsupported_without_generic_launch(self):
        from common.dashboard.server import DashboardServer

        target = "http://127.0.0.1:8080/"
        job_id = "retest-active-unsupported"
        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            srv._scan_logs_dir = tmp_path / "logs"
            srv._control_dir = tmp_path / "controls"
            srv._scan_logs_dir.mkdir()
            srv._control_dir.mkdir()
            process = MagicMock(pid=8767, stdout=[])
            process.poll.return_value = None
            with (
                patch.object(
                    DashboardServer,
                    "_scan_jobs_db_path",
                    new_callable=PropertyMock,
                    return_value=tmp_path / "scan_jobs.db",
                ),
                patch.object(DashboardServer, "_track_scan_process"),
                patch("subprocess.Popen", return_value=process) as popen,
                patch(
                    "common.retest._governed_header_fetch",
                    side_effect=AssertionError("unsupported verifier opened a connection"),
                ) as fetch,
            ):
                canonical_id = _seed_canonical_dashboard_finding(
                    srv,
                    tmp_path / "scan_jobs.db",
                    tmp_path,
                    finding_id="finding-active-unsupported-retest",
                    module="sqli_scanner",
                    target=target,
                    title="Unsupported Retest Family",
                )
                async with _make_async_client(app) as client:
                    response = await client.post(
                        f"/api/v1/findings/{canonical_id}/retest",
                        json={
                            "job_id": job_id,
                            "scope": ["127.0.0.1/32"],
                            "exclude": [],
                            "dry_run": False,
                            "confirmation": ActionConfirmation.create(
                                job_id=job_id,
                                target=target,
                                engine="webforge",
                                action="retest",
                            ).to_dict(),
                        },
                    )

            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["retest_verdict"], "unsupported")
            self.assertEqual(response.json()["state"], "terminal")
            fetch.assert_not_called()
            popen.assert_not_called()

    def test_legacy_retest_row_is_fixture_only_and_has_no_dashboard_completion_authority(self):
        from common.dashboard.server import DashboardServer
        from common.db import FindingRetestModel, create_db, save_finding_retest

        srv = DashboardServer(auth=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            scan_jobs_db = tmp_path / "scan_jobs.db"
            with patch.object(
                DashboardServer,
                "_scan_jobs_db_path",
                new_callable=PropertyMock,
                return_value=scan_jobs_db,
            ):
                session = create_db(scan_jobs_db)
                try:
                    save_finding_retest(
                        session,
                        {
                            "id": "rt-1",
                            "finding_id": "finding-123",
                            "status": "running",
                            "module": "sqli_scanner",
                            "target": "http://example.com",
                        },
                        allow_legacy_compat=True,
                    )
                finally:
                    session.close()

                self.assertFalse(hasattr(srv, "_complete_finding_retest"))
                self.assertFalse(hasattr(srv, "_launch_finding_retest_job"))

                session = create_db(scan_jobs_db)
                try:
                    retest = session.query(FindingRetestModel).filter_by(id="rt-1").one()
                    self.assertEqual(retest.status, "running")
                    self.assertIsNone(retest.still_vulnerable)
                    self.assertIsNone(retest.confidence)
                    evidence = json.loads(retest.evidence)
                    self.assertEqual(evidence, {})
                    self.assertIsNone(retest.retested_at)
                finally:
                    session.close()
