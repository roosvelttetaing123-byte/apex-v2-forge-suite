import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import httpx

from common.action_authorization import (
    AUTHORIZATION_ENVELOPES_ENV,
    load_authorization_envelopes,
    module_set_binding,
)
from common.confirm_gate import ActionConfirmation, LAUNCH_CONFIRMATIONS_ENV

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
                patch("subprocess.Popen", return_value=mock_proc),
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
            mock_proc.assert_not_called()
            session = create_db(scan_jobs_db)
            try:
                self.assertEqual(session.query(ScanJobModel).count(), 0)
            finally:
                session.close()

    async def test_retest_finding_persists_plan_without_spawning_dry_run_job(self):
        from common.dashboard.event_bus import Event, EventType
        from common.dashboard.server import DashboardServer
        from common.db import FindingRetestModel, create_db

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        srv.state_store._on_finding(
            Event(
                EventType.FINDING_NEW,
                source="sqli_scanner",
                data={
                    "id": "finding-123",
                    "title": "SQL Injection",
                    "severity": "High",
                    "module": "sqli_scanner",
                    "target": "http://127.0.0.1:8080",
                    "url": "http://127.0.0.1:8080/login?id=1",
                    "description": "Time delay observed",
                    "confidence": "HIGH",
                    "evidence": {"request_raw": "GET /login?id=1"},
                    "verification": {"param": "id", "payload_class": "time-based-sqli"},
                },
            )
        )

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
                async with _make_async_client(app) as client:
                    resp = await client.post(
                        "/api/v1/findings/finding-123/retest",
                        json={
                            "job_id": "retest-dry-plan",
                            "scope": ["127.0.0.1/32"],
                            "exclude": [],
                        },
                    )

            self.assertEqual(resp.status_code, 200, resp.text)
            body = resp.json()
            self.assertEqual(body["status"], "planned")
            self.assertTrue(body["dry_run"])
            self.assertEqual(body["module"], "sqli_scanner")
            self.assertEqual(body["client_job_id"], "retest-dry-plan")
            self.assertTrue(body["job_id"].startswith("job-"))
            mock_popen.assert_not_called()

            session = create_db(scan_jobs_db)
            try:
                retest = session.query(FindingRetestModel).filter_by(id=body["retest_id"]).one()
                self.assertEqual(retest.finding_id, "finding-123")
                self.assertEqual(retest.module, "sqli_scanner")
                self.assertEqual(retest.target, "http://127.0.0.1:8080")
                self.assertEqual(retest.status, "planned")
                self.assertEqual(retest.job_id, body["job_id"])
                self.assertEqual(retest.param, "id")
                self.assertEqual(retest.payload_class, "time-based-sqli")
                evidence = json.loads(retest.evidence)
                self.assertTrue(evidence["dry_run"])
                self.assertFalse(evidence["authorized"])
            finally:
                session.close()

    async def test_active_retest_without_canonical_lineage_fails_closed(self):
        from common.dashboard.event_bus import Event, EventType
        from common.dashboard.server import DashboardServer

        target = "http://127.0.0.1:8080"
        job_id = "retest-active"
        srv = DashboardServer(auth=False)
        app = srv.create_app()
        srv.state_store._on_finding(
            Event(
                EventType.FINDING_NEW,
                source="header_audit",
                data={
                    "id": "finding-active-retest",
                    "title": "Header Missing",
                    "severity": "Low",
                    "module": "header_audit",
                    "target": target,
                },
            )
        )

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
                async with _make_async_client(app) as client:
                    response = await client.post(
                        "/api/v1/findings/finding-active-retest/retest",
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

    def test_retest_completion_updates_persisted_record(self):
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
                    self.assertEqual(retest.status, "completed")
                    self.assertIsNone(retest.still_vulnerable)
                    self.assertEqual(retest.confidence, "UNVERIFIED")
                    evidence = json.loads(retest.evidence)
                    self.assertEqual(evidence["return_code"], 0)
                    self.assertIn("dry run complete", evidence["log_tail"])
                    self.assertIsNotNone(retest.retested_at)
                finally:
                    session.close()
