from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import PropertyMock, patch

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))


def _make_async_client(app):
    from common.dashboard.auth import Role, issue_identity_token

    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {issue_identity_token('fingerprint-test', Role.OPERATOR)}"},
    )


class TestScanFingerprintApi(unittest.IsolatedAsyncioTestCase):
    async def test_dashboard_plans_records_and_adapts_incremental_scan_state(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "scan_fingerprints.json"
            with patch.object(
                DashboardServer,
                "_scan_fingerprint_path",
                new_callable=PropertyMock,
                return_value=state_path,
            ):
                async with _make_async_client(app) as client:
                    first_plan = await client.post(
                        "/api/v1/scans/fingerprints/plan",
                        json={
                            "targets": [
                                {
                                    "host": "https://APP.example.test/login",
                                    "service": "https",
                                    "port": 443,
                                    "attributes": {"title": "Portal", "status": 200},
                                }
                            ]
                        },
                    )
                    record = await client.post(
                        "/api/v1/scans/fingerprints/record",
                        json={
                            "scanned_at": "2026-06-30T12:00:00Z",
                            "targets": [
                                {
                                    "host": "app.example.test",
                                    "service": "https",
                                    "port": 443,
                                    "attributes": {"status": 200, "title": "Portal"},
                                }
                            ],
                        },
                    )
                    second_plan = await client.post(
                        "/api/v1/scans/fingerprints/plan",
                        json={
                            "targets": [
                                {
                                    "host": "APP.EXAMPLE.TEST",
                                    "service": "HTTPS",
                                    "port": "443",
                                    "attributes": {"title": "Portal", "status": 200},
                                },
                                {
                                    "host": "api.example.test",
                                    "service": "https",
                                    "port": 443,
                                    "attributes": {"title": "API", "status": 200},
                                },
                            ]
                        },
                    )
                    rate = await client.post(
                        "/api/v1/scans/rate-adapt",
                        json={
                            "host": "api.example.test",
                            "service": "https",
                            "port": 443,
                            "signal": "timeout",
                            "policy": {"initial_rate": 12.0, "min_rate": 1.0},
                        },
                    )

        self.assertEqual(first_plan.status_code, 200, first_plan.text)
        self.assertEqual(first_plan.json()["decisions"][0]["reason"], "new")
        self.assertEqual(record.status_code, 200, record.text)
        self.assertEqual(record.json()["recorded"], 1)
        self.assertEqual(second_plan.status_code, 200, second_plan.text)
        self.assertEqual(
            [decision["reason"] for decision in second_plan.json()["decisions"]],
            ["unchanged", "new"],
        )
        self.assertEqual(rate.status_code, 200, rate.text)
        self.assertEqual(rate.json()["action"], "backoff_timeout")
        self.assertEqual(rate.json()["current_rate"], 6.0)

    async def test_dashboard_rejects_invalid_rate_signal(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(
                DashboardServer,
                "_scan_fingerprint_path",
                new_callable=PropertyMock,
                return_value=Path(tmpdir) / "scan_fingerprints.json",
            ):
                async with _make_async_client(app) as client:
                    resp = await client.post(
                        "/api/v1/scans/rate-adapt",
                        json={
                            "host": "api.example.test",
                            "service": "https",
                            "port": 443,
                            "signal": "not-real",
                        },
                    )

        self.assertEqual(resp.status_code, 400)
        self.assertIn("Unsupported rate signal", resp.json()["error"])


if __name__ == "__main__":
    unittest.main()
