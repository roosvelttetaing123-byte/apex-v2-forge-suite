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
    context = CanonicalEvidenceContext.from_authorization(issued.envelope)
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
                evidence=Evidence(
                    extra={
                        "route": "/",
                        "check_id": module,
                    }
                ),
            )
        )
    finally:
        finding_bind = finding_session.bind
        finding_session.close()
        if finding_bind is not None:
            finding_bind.dispose()

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

            self.assertEqual(resp.status_code, 500, resp.text)
            self.assertEqual(
                resp.json()["detail"],
                "Authorization handoff persistence failed; execution denied",
            )
            self.assertFalse(history_path.exists())
            self.assertFalse(any(logs_dir.iterdir()))
            mock_popen.assert_not_called()
            session = create_db(scan_jobs_db)
            try:
                self.assertEqual(session.query(ScanJobModel).count(), 0)
            finally:
                session.close()

    async def test_retest_finding_without_canonical_lineage_fails_before_dry_run_persistence(self):
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

            self.assertEqual(resp.status_code, 500, resp.text)
            self.assertEqual(
                resp.json()["detail"],
                "Canonical retest context is required; persistence denied",
            )
            mock_popen.assert_not_called()

            session = create_db(scan_jobs_db)
            try:
                self.assertEqual(session.query(FindingRetestModel).count(), 0)
            finally:
                session.close()

    async def test_active_retest_without_canonical_lineage_fails_closed(self):
        from common.dashboard.server import DashboardServer

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
            with (
                patch.object(
                    DashboardServer,
                    "_scan_jobs_db_path",
                    new_callable=PropertyMock,
                    return_value=tmp_path / "scan_jobs.db",
                ),
                patch.object(DashboardServer, "_track_scan_process"),
                patch("subprocess.Popen", return_value=process) as popen,
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

        self.assertEqual(response.status_code, 500, response.text)
        self.assertEqual(
            response.json()["detail"],
            "Authorization handoff persistence failed; execution denied",
        )
        popen.assert_not_called()

    def test_retest_completion_without_canonical_lineage_leaves_legacy_record_unchanged(self):
        from common.dashboard.server import DashboardServer
        from common.db import FindingRetestModel, create_db, save_finding_retest

        srv = DashboardServer(auth=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            scan_jobs_db = tmp_path / "scan_jobs.db"
            logs_dir = tmp_path / "logs"
            logs_dir.mkdir()
            srv._scan_logs_dir = logs_dir
            log_path = logs_dir / "retest-rt-1_web.log"
            log_path.write_text("dry run complete\n", encoding="utf-8")
            log_path.chmod(0o600)

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

                srv._complete_finding_retest(
                    {"retest_id": "rt-1"},
                    "retest-rt-1_web",
                    0,
                    log_path,
                )

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
