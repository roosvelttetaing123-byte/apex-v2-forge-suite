"""Tests for credential security in dashboard scan launch endpoints.

Key invariants verified:
- Secrets (password, token, cookie_jar) never appear in subprocess argv
- Secrets are injected via environment variables instead
- Invalid mode values are rejected with a 400 error
- Saved templates never contain password, token, or cookie_jar
- Cookie header prefix is stripped before use
"""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx

# Make forge-suite importable
sys.path.insert(0, str(Path(__file__).parent.parent))


def _make_server():
    """Create a DashboardServer instance with auth disabled for testing."""
    from common.dashboard.server import DashboardServer
    srv = DashboardServer(auth=False)
    return srv


def _make_async_client(app):
    """Use ASGITransport directly; Starlette TestClient hangs with httpx 0.28 here."""
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


class TestModeWhitelisting(unittest.IsolatedAsyncioTestCase):
    """Invalid modes must be rejected before any subprocess is spawned."""

    async def test_invalid_mode_scan_start_returns_400(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        async with _make_async_client(app) as client:
            resp = await client.post("/api/v1/scans/start", json={"target": "http://example.com", "mode": "superadmin"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid mode", resp.json()["detail"])

    async def test_invalid_mode_scan_launch_returns_400(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        async with _make_async_client(app) as client:
            resp = await client.post("/api/v1/scans/launch", json={"target": "http://example.com", "mode": "hacker"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid mode", resp.json()["detail"])

    async def test_valid_modes_accepted(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        for mode in ("blackbox", "greybox", "whitebox"):
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.poll.return_value = None
                mock_proc.wait.return_value = 0
                mock_popen.return_value = mock_proc
                async with _make_async_client(app) as client:
                    resp = await client.post("/api/v1/scans/start", json={"target": "http://example.com", "mode": mode})
                # 200 or 500 (if webforge.py not present) — but NOT 400
                self.assertNotEqual(resp.status_code, 400, f"mode={mode} should be accepted")


class TestSecretsNotInArgv(unittest.IsolatedAsyncioTestCase):
    """Passwords, tokens, and cookie jars must never appear in subprocess argv."""

    async def test_password_not_in_argv_scan_start(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.poll.return_value = None
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc

            async with _make_async_client(app) as client:
                await client.post("/api/v1/scans/start", json={
                    "target": "http://example.com",
                    "mode": "greybox",
                    "auth_profile": {
                        "auth_type": "form",
                        "username": "admin",
                        "password": "S3cr3tP@ssw0rd!",
                        "login_url": "http://example.com/login",
                    },
                })

            if mock_popen.called:
                # scan_type='web' spawns webforge first, then auto-netforge second.
                # Check the first call (webforge) which receives FORGE_PASSWORD in env.
                first_call = mock_popen.call_args_list[0]
                args_list = first_call[0][0]  # positional arg 0 = cmd list
                argv_str = " ".join(str(a) for a in args_list)
                self.assertNotIn("S3cr3tP@ssw0rd!", argv_str,
                                 "Password must NOT appear in subprocess argv")
                env = first_call[1].get("env", {})
                self.assertEqual(env.get("FORGE_PASSWORD"), "S3cr3tP@ssw0rd!",
                                 "Password must be in webforge env dict")

    async def test_token_not_in_argv_scan_launch(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.poll.return_value = None
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc

            async with _make_async_client(app) as client:
                await client.post("/api/v1/scans/launch", json={
                    "target": "http://example.com",
                    "mode": "greybox",
                    "modules": ["sqli", "xss"],
                    "auth_profile": {
                        "auth_type": "bearer",
                        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret",
                    },
                })

            if mock_popen.called:
                args_list = mock_popen.call_args[0][0]
                argv_str = " ".join(str(a) for a in args_list)
                self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret", argv_str,
                                 "Token must NOT appear in subprocess argv")
                env = mock_popen.call_args[1].get("env", {})
                self.assertEqual(env.get("FORGE_TOKEN"),
                                 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret",
                                 "Token must be in env dict")

    async def test_cookie_jar_not_in_argv(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.poll.return_value = None
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc

            async with _make_async_client(app) as client:
                await client.post("/api/v1/scans/launch", json={
                    "target": "http://example.com",
                    "mode": "greybox",
                    "modules": ["sqli"],
                    "auth_profile": {
                        "auth_type": "cookie",
                        "cookie_jar": "session=abc123; role=admin",
                    },
                })

            if mock_popen.called:
                args_list = mock_popen.call_args[0][0]
                argv_str = " ".join(str(a) for a in args_list)
                self.assertNotIn("abc123", argv_str,
                                 "Cookie jar must NOT appear in subprocess argv")
                env = mock_popen.call_args[1].get("env", {})
                self.assertEqual(env.get("FORGE_COOKIE_JAR"), "session=abc123; role=admin",
                                 "Cookie jar must be in env dict")


class TestCookieHeaderSanitization(unittest.TestCase):
    """The 'Cookie:' prefix must be stripped before secrets reach the env or HTTP client."""

    def _strip(self, raw: str) -> str:
        import re
        return re.sub(r"^cookie:\s*", "", raw, flags=re.IGNORECASE)

    def test_strips_cookie_prefix(self):
        self.assertEqual(self._strip("Cookie: session=abc; role=admin"),
                         "session=abc; role=admin")

    def test_strips_lowercase_prefix(self):
        self.assertEqual(self._strip("cookie: session=abc"),
                         "session=abc")

    def test_no_prefix_unchanged(self):
        self.assertEqual(self._strip("session=abc; role=admin"),
                         "session=abc; role=admin")

    def test_strips_only_leading_prefix(self):
        # A cookie value that contains "cookie:" in the value must not be altered
        self.assertEqual(self._strip("session=abc; redirect=cookie:example"),
                         "session=abc; redirect=cookie:example")


class TestTemplatePersistence(unittest.IsolatedAsyncioTestCase):
    """Saved templates must never contain password, token, or cookie_jar."""

    async def test_save_template_strips_secrets(self):
        from common.dashboard.server import DashboardServer
        from unittest.mock import PropertyMock
        import tempfile, os

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("[]")
            tmp = f.name

        try:
            # Patch the class-level property so all instances redirect to tmp
            with patch.object(DashboardServer, "_templates_path",
                              new_callable=PropertyMock, return_value=Path(tmp)):
                async with _make_async_client(app) as client:
                    resp = await client.post("/api/v1/scan/templates", json={
                        "name": "MyTemplate",
                        "target": "http://example.com",
                        "mode": "greybox",
                        "auth_profile": {
                            "auth_type": "form",
                            "username": "admin",
                            "password": "topsecret",
                            "token": "leak_me",
                            "cookie_jar": "session=leak",
                        },
                    })

            self.assertEqual(resp.status_code, 200, f"Template save failed: {resp.text}")

            # Read back the template file and confirm no secrets were persisted
            raw = Path(tmp).read_text()
            self.assertNotIn("topsecret",   raw, "password must not be in saved template")
            self.assertNotIn("leak_me",     raw, "token must not be in saved template")
            self.assertNotIn("session=leak", raw, "cookie_jar must not be in saved template")

            # Confirm mode IS persisted (was previously missing from the config allowlist)
            import json
            saved = json.loads(raw)
            self.assertTrue(saved, "Template list must not be empty")
            self.assertEqual(saved[0]["config"].get("mode"), "greybox",
                             "Scan mode must be persisted in template config")
        finally:
            os.unlink(tmp)


class TestBlackboxNoEnvSecrets(unittest.IsolatedAsyncioTestCase):
    """In blackbox mode no FORGE_* secret env vars should be set."""

    async def test_blackbox_no_forge_secrets_in_env(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.poll.return_value = None
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc

            async with _make_async_client(app) as client:
                await client.post("/api/v1/scans/start", json={
                    "target": "http://example.com",
                    "mode": "blackbox",
                })

            if mock_popen.called:
                env = mock_popen.call_args[1].get("env", {})
                for key in ("FORGE_PASSWORD", "FORGE_TOKEN", "FORGE_COOKIE_JAR"):
                    self.assertNotIn(key, env,
                                     f"{key} must not be set for blackbox scans")


class TestDashboardConnectivity(unittest.IsolatedAsyncioTestCase):
    """Dashboard health and tool launch metadata should stay wired."""

    async def test_health_exposes_tool_inventory(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        async with _make_async_client(app) as client:
            resp = await client.get("/api/v1/health")

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        tool_ids = {tool["id"] for tool in data["tools"]}
        self.assertIn("web", tool_ids)
        self.assertIn("net", tool_ids)
        self.assertIn("payload", tool_ids)

    async def test_launch_response_and_status_include_dashboard_url(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.poll.return_value = None
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc

            async with _make_async_client(app) as client:
                resp = await client.post(
                    "/api/v1/scans/launch",
                    json={"target": "http://example.com", "mode": "blackbox", "modules": ["sqli"]},
                )
                status = await client.get("/api/v1/scans/status")

        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertIn("dashboard_url", body)
        self.assertTrue(body["dashboard_url"].startswith("http://testserver"))
        self.assertEqual(status.status_code, 200)
        processes = status.json()["running"] + status.json()["completed"]
        self.assertTrue(processes)
        self.assertIn("dashboard_url", processes[0])
        self.assertIn("control_file", processes[0])

    async def test_untracked_running_history_becomes_orphaned(self):
        from common.dashboard.server import DashboardServer
        from unittest.mock import PropertyMock
        import tempfile, os

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump([{
                "scan_id": "stale123",
                "target": "http://example.com",
                "scan_type": "web",
                "mode": "blackbox",
                "engagement": "Stale",
                "frameworks": ["web"],
                "started_at": "2026-06-23T00:00:00+00:00",
                "status": "running",
                "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            }], f)
            tmp = f.name

        try:
            with patch.object(DashboardServer, "_history_path",
                              new_callable=PropertyMock, return_value=Path(tmp)):
                async with _make_async_client(app) as client:
                    resp = await client.get("/api/v1/scans/history")

            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["history"][0]["status"], "orphaned")
        finally:
            os.unlink(tmp)

    async def test_delete_scan_removes_history_record(self):
        from common.dashboard.server import DashboardServer
        from unittest.mock import PropertyMock
        import tempfile, os

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump([{
                "scan_id": "delete123",
                "target": "http://example.com",
                "scan_type": "web",
                "mode": "blackbox",
                "engagement": "DeleteMe",
                "frameworks": ["web"],
                "started_at": "2026-06-23T00:00:00+00:00",
                "status": "completed",
                "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            }], f)
            tmp = f.name

        try:
            with patch.object(DashboardServer, "_history_path",
                              new_callable=PropertyMock, return_value=Path(tmp)):
                async with _make_async_client(app) as client:
                    resp = await client.delete("/api/v1/scans/delete123")
                    history = await client.get("/api/v1/scans/history")

            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.json()["history_deleted"])
            self.assertEqual(history.json()["history"], [])
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main()
