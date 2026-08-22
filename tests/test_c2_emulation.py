from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))


def _make_async_client(app):
    from common.dashboard.auth import Role, issue_identity_token

    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {issue_identity_token('c2-emulation-test', Role.VIEWER)}"},
    )


class TestC2EmulationSafety(unittest.IsolatedAsyncioTestCase):
    def test_process_injection_plan_is_inert(self):
        from forge_c2.emulation import build_process_injection_emulation_plan

        plan = build_process_injection_emulation_plan(
            "early_bird_apc",
            beacon_id="beacon-1",
            target_process="notepad.exe",
            operator="tester",
        )

        self.assertEqual(plan["safety_mode"], "dry_run_emulation")
        self.assertEqual(plan["verification_state"], "simulation")
        self.assertEqual(plan["proof_type"], "simulation")
        self.assertEqual(plan["maturity"], "simulation")
        self.assertIn("process injection", plan["forbidden_actions"])
        self.assertEqual(plan["technique"]["safety"], "metadata_only_no_injection")

        with self.assertRaises(ValueError):
            build_process_injection_emulation_plan(
                "early_bird_apc",
                beacon_id="beacon-1",
                dry_run=False,
            )

    def test_simulation_serialization_rejects_forbidden_outcomes(self):
        from forge_c2.emulation import validate_simulation_serialization

        for outcome in ("success", "exploited", "still_vulnerable", "fixed", "verified"):
            with self.subTest(outcome=outcome):
                with self.assertRaises(ValueError):
                    validate_simulation_serialization({"status": outcome})
                with self.assertRaises(ValueError):
                    validate_simulation_serialization({outcome: True})

        safe = validate_simulation_serialization(
            {"status": "emulated", "verification_state": "simulation"}
        )
        self.assertEqual(safe["status"], "emulated")
        self.assertEqual(safe["verification_state"], "simulation")

    def test_p2p_topology_updates_metadata_only(self):
        from forge_c2.beacon.beacon_core import BeaconRegistry
        from forge_c2.emulation import P2PTopology

        registry = BeaconRegistry()
        parent = registry.register({"hostname": "parent"})
        child = registry.register({"hostname": "child"})
        parent.checkin()
        child.checkin()

        link = P2PTopology(registry).link(parent.beacon_id, child.beacon_id, transport="tcp")

        self.assertEqual(link.status, "emulated")
        self.assertEqual(child.parent_beacon, parent.beacon_id)
        self.assertIn(child.beacon_id, parent.child_beacons)
        self.assertEqual(parent.task_queue, [])
        self.assertEqual(child.task_queue, [])
        self.assertTrue(child.transport.startswith("p2p:tcp"))

    async def test_team_server_emulation_commands_do_not_queue_tasks(self):
        from forge_c2.server import OperatorRole, TeamServer

        old_password = os.environ.get("FORGE_C2_ADMIN_PW")
        os.environ["FORGE_C2_ADMIN_PW"] = "test-password"
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                server = TeamServer(data_dir=Path(tmpdir))
                server.operators.add_operator("op", "pw", OperatorRole.OPERATOR)
                op = server.operators.authenticate("op", "pw")
                self.assertIsNotNone(op)
                beacon = server.registry.register({"hostname": "lab"})
                beacon.checkin()

                result = await server._handle_operator_command(
                    "process_injection_plan",
                    {
                        "technique_id": "module_stomping",
                        "beacon_id": beacon.beacon_id,
                    },
                    op.session_token if op else "",
                    "127.0.0.1",
                )

                self.assertEqual(result["status"], "ok")
                self.assertEqual(beacon.task_queue, [])
                self.assertEqual(server.router.task_history, [])
                self.assertEqual(server.status()["emulation_events_total"], 1)
        finally:
            if old_password is None:
                os.environ.pop("FORGE_C2_ADMIN_PW", None)
            else:
                os.environ["FORGE_C2_ADMIN_PW"] = old_password

    async def test_dashboard_c2_emulation_api(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        async with _make_async_client(app) as client:
            listing = await client.get("/api/v1/c2/emulation/process-injection")
            plan = await client.post(
                "/api/v1/c2/emulation/process-injection/plan",
                json={
                    "technique_id": "ntqueueapcthread",
                    "beacon_id": "beacon-1",
                    "target_process": "calc.exe",
                },
            )
            rejected = await client.post(
                "/api/v1/c2/emulation/process-injection/plan",
                json={
                    "technique_id": "ntqueueapcthread",
                    "beacon_id": "beacon-1",
                    "dry_run": False,
                },
            )
            p2p = await client.get("/api/v1/c2/emulation/p2p")

        self.assertEqual(listing.status_code, 200)
        self.assertGreaterEqual(listing.json()["total"], 5)
        self.assertEqual(plan.status_code, 200)
        self.assertEqual(plan.json()["plan"]["safety_mode"], "dry_run_emulation")
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(p2p.status_code, 200)
        self.assertIn("tcp", p2p.json()["transports"])
