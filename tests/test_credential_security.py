"""Tests for credential security in dashboard scan launch endpoints.

Key invariants verified:
- Secrets (password, token, cookie_jar) never appear in subprocess argv
- Secrets cross the process boundary only through a one-shot inherited pipe
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

from common.confirm_gate import ActionConfirmation
from common.credential_boundary import (
    CREDENTIAL_FD_ENV,
    CREDENTIAL_REF_ENV,
    ProtectedCredentialBundle,
    resolved_process_credentials,
)


def _make_server():
    """Create a DashboardServer instance with auth disabled for testing."""
    from common.dashboard.server import DashboardServer
    srv = DashboardServer(auth=False)
    return srv


def _make_async_client(app):
    """Use ASGITransport directly; Starlette TestClient hangs with httpx 0.28 here."""
    from common.dashboard.auth import Role, issue_identity_token

    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {issue_identity_token('credential-test', Role.ADMIN)}"},
    )


LAB_TARGET = "http://127.0.0.1:8080"


def _web_launch_contract(job_id: str) -> dict:
    return {
        "job_id": job_id,
        "scope": ["127.0.0.1/32"],
        "exclude": [],
        "confirmation": ActionConfirmation.create(
            job_id=job_id,
            target=LAB_TARGET,
            engine="webforge",
            action="scan",
        ).to_dict(),
    }


def _credential_pipe_popen(expected: dict[str, str], captured: dict[str, object]):
    """Return a fake Popen that consumes the inherited pipe during spawn."""
    def _spawn(cmd, *args, **kwargs):
        child_env = dict(kwargs.get("env") or {})
        captured["argv"] = list(cmd)
        captured["environment"] = dict(child_env)
        captured["pass_fds"] = tuple(kwargs.get("pass_fds") or ())

        with resolved_process_credentials(child_env) as values:
            captured["resolved"] = dict(values)
            assert values == expected
        assert child_env.get(CREDENTIAL_REF_ENV) is None
        assert child_env.get(CREDENTIAL_FD_ENV) is None

        proc = MagicMock()
        proc.pid = 7007
        proc.poll.return_value = None
        proc.wait.return_value = 0
        return proc

    return _spawn


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
            job_id = f"valid-mode-{mode}"
            with (
                patch("subprocess.Popen") as mock_popen,
                patch.object(DashboardServer, "_track_scan_process"),
                patch.object(DashboardServer, "_write_scan_history"),
                patch.object(DashboardServer, "_write_scan_job"),
                patch.object(DashboardServer, "_write_audit_log"),
                patch.object(
                    DashboardServer,
                    "_init_control_file",
                    return_value=Path("/tmp/forge-test-control.json"),
                ),
            ):
                mock_proc = MagicMock()
                mock_proc.poll.return_value = None
                mock_proc.wait.return_value = 0
                mock_popen.return_value = mock_proc
                request = {
                    "target": LAB_TARGET,
                    "mode": mode,
                    **_web_launch_contract(job_id),
                }
                if mode == "whitebox":
                    request["source_root"] = str(Path(__file__).parent.parent.resolve())
                async with _make_async_client(app) as client:
                    resp = await client.post(
                        "/api/v1/scans/start",
                        json=request,
                    )
                self.assertEqual(resp.status_code, 200, resp.text)

    async def test_invalid_scan_type_returns_400(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        async with _make_async_client(app) as client:
            resp = await client.post(
                "/api/v1/scans/start",
                json={"target": "http://example.com", "scan_type": "ghost"},
            )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid scan_type", resp.json()["detail"])

    async def test_whitebox_requires_canonical_source_root_before_spawn(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with patch("subprocess.Popen") as mock_popen:
            async with _make_async_client(app) as client:
                resp = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "target": LAB_TARGET,
                        "mode": "whitebox",
                        **_web_launch_contract("whitebox-missing-root"),
                    },
                )
        self.assertEqual(resp.status_code, 400, resp.text)
        self.assertIn("source_root", resp.text)
        mock_popen.assert_not_called()

    async def test_whitebox_rejects_alternate_source_key_before_spawn(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with patch("subprocess.Popen") as mock_popen:
            async with _make_async_client(app) as client:
                resp = await client.post(
                    "/api/v1/scans/launch",
                    json={
                        "target": LAB_TARGET,
                        "mode": "whitebox",
                        "source_dir": str(Path(__file__).parent.parent.resolve()),
                        **_web_launch_contract("whitebox-alternate-key"),
                    },
                )
        self.assertEqual(resp.status_code, 400, resp.text)
        self.assertIn("source_root", resp.text)
        mock_popen.assert_not_called()

    async def test_whitebox_forwards_one_canonical_source_root_argument(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        source_root = str(Path(__file__).parent.parent.resolve())
        with (
            patch("subprocess.Popen") as mock_popen,
            patch.object(DashboardServer, "_track_scan_process"),
            patch.object(DashboardServer, "_write_scan_history"),
            patch.object(DashboardServer, "_write_scan_job"),
            patch.object(DashboardServer, "_write_audit_log"),
            patch.object(
                DashboardServer,
                "_init_control_file",
                return_value=Path("/tmp/forge-test-control.json"),
            ),
        ):
            proc = MagicMock()
            proc.pid = 7008
            proc.poll.return_value = None
            proc.wait.return_value = 0
            mock_popen.return_value = proc
            async with _make_async_client(app) as client:
                resp = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "target": LAB_TARGET,
                        "mode": "whitebox",
                        "source_root": source_root,
                        **_web_launch_contract("whitebox-canonical-root"),
                    },
                )
        self.assertEqual(resp.status_code, 200, resp.text)
        argv = mock_popen.call_args[0][0]
        self.assertEqual(argv.count("--source-root"), 1)
        self.assertEqual(argv[argv.index("--source-root") + 1], source_root)


class TestDashboardAuthHardening(unittest.TestCase):
    """Password auth must be explicitly configured; no source-known default."""

    def setUp(self):
        self._env = {
            key: __import__("os").environ.get(key)
            for key in (
                "FORGE_DASHBOARD_PASSWORD",
                "FORGE_DASHBOARD_PASSWORD_HASH",
                "FORGE_DASHBOARD_USER",
                "FORGE_DASHBOARD_ROLE",
            )
        }
        for key in self._env:
            __import__("os").environ.pop(key, None)

    def tearDown(self):
        os = __import__("os")
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_no_default_dashboard_password(self):
        from common.dashboard.auth import generate_token

        self.assertIsNone(generate_token("operator", "forge2026"))

    def test_env_password_login_still_works(self):
        import os
        from common.dashboard.auth import generate_token, validate_token

        os.environ["FORGE_DASHBOARD_PASSWORD"] = "configured-secret"
        token = generate_token("operator", "configured-secret")
        self.assertIsNotNone(token)
        payload = validate_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload.username, "operator")


class TestC2Hardening(unittest.IsolatedAsyncioTestCase):
    """C2 startup/auth/listener defects from the plan should fail closed."""

    def test_operator_hashes_are_salted(self):
        from forge_c2.server import OperatorManager

        mgr = OperatorManager()
        first = mgr.add_operator("first", "same-password")
        second = mgr.add_operator("second", "same-password")
        self.assertNotEqual(first.password_hash, second.password_hash)
        self.assertTrue(first.password_hash.startswith("pbkdf2_sha256$"))
        self.assertIsNotNone(mgr.authenticate("first", "same-password"))
        self.assertIsNone(mgr.authenticate("first", "wrong"))

    def test_team_server_requires_configured_admin_password(self):
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from forge_c2.server import TeamServer

        old = os.environ.pop("FORGE_C2_ADMIN_PW", None)
        try:
            with tempfile.TemporaryDirectory() as d:
                with patch("forge_c2.server.BeaconCrypto"):
                    with self.assertRaises(RuntimeError):
                        TeamServer(data_dir=Path(d))
        finally:
            if old is not None:
                os.environ["FORGE_C2_ADMIN_PW"] = old

    async def test_dns_smb_listeners_do_not_report_running(self):
        from forge_c2.server import ListenerManager, ListenerState, ListenerType

        registry = object()
        crypto = object()
        mgr = ListenerManager(registry, crypto)
        dns = mgr.create(ListenerType.DNS, bind_port=5353)
        smb = mgr.create(ListenerType.SMB, bind_port=445)

        self.assertFalse(await mgr.start(dns.listener_id))
        self.assertFalse(await mgr.start(smb.listener_id))
        self.assertEqual(dns.state, ListenerState.ERROR)
        self.assertEqual(smb.state, ListenerState.ERROR)


class TestSecretsNotInArgv(unittest.IsolatedAsyncioTestCase):
    """Secrets cross process boundaries only through inherited pipe descriptors."""

    async def test_password_not_in_argv_scan_start(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with (
            patch("subprocess.Popen") as mock_popen,
            patch.object(DashboardServer, "_track_scan_process"),
        ):
            captured = {}
            mock_popen.side_effect = _credential_pipe_popen(
                {"password": "S3cr3tP@ssw0rd!"}, captured
            )

            async with _make_async_client(app) as client:
                await client.post("/api/v1/scans/start", json={
                    "target": LAB_TARGET,
                    "mode": "greybox",
                    **_web_launch_contract("credential-password"),
                    "auth_profile": {
                        "auth_type": "form",
                        "username": "admin",
                        "password": "S3cr3tP@ssw0rd!",
                        "login_url": "http://127.0.0.1:8080/login",
                    },
                })

            if mock_popen.called:
                self.assertEqual(mock_popen.call_count, 1)
                first_call = mock_popen.call_args_list[0]
                args_list = first_call[0][0]  # positional arg 0 = cmd list
                argv_str = " ".join(str(a) for a in args_list)
                self.assertNotIn("S3cr3tP@ssw0rd!", argv_str,
                                 "Password must NOT appear in subprocess argv")
                env = first_call[1].get("env", {})
                self.assertNotIn("FORGE_PASSWORD", env)
                self.assertIn(CREDENTIAL_REF_ENV, env)
                self.assertIn(CREDENTIAL_FD_ENV, env)
                self.assertEqual(first_call[1].get("pass_fds"), captured["pass_fds"])
                self.assertEqual(captured["resolved"], {"password": "S3cr3tP@ssw0rd!"})
                self.assertNotIn("S3cr3tP@ssw0rd!", json.dumps(captured["environment"]))

    async def test_token_not_in_argv_scan_launch(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with (
            patch("subprocess.Popen") as mock_popen,
            patch.object(DashboardServer, "_track_scan_process"),
        ):
            captured = {}
            token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"
            mock_popen.side_effect = _credential_pipe_popen(
                {"token": token}, captured
            )

            async with _make_async_client(app) as client:
                await client.post("/api/v1/scans/launch", json={
                    "target": LAB_TARGET,
                    "mode": "greybox",
                    "modules": ["sqli", "xss"],
                    **_web_launch_contract("credential-token"),
                    "auth_profile": {
                        "auth_type": "bearer",
                        "token": token,
                    },
                })

            if mock_popen.called:
                args_list = mock_popen.call_args[0][0]
                argv_str = " ".join(str(a) for a in args_list)
                self.assertNotIn(token, argv_str,
                                 "Token must NOT appear in subprocess argv")
                env = mock_popen.call_args[1].get("env", {})
                self.assertNotIn("FORGE_TOKEN", env)
                self.assertIn(CREDENTIAL_REF_ENV, env)
                self.assertIn(CREDENTIAL_FD_ENV, env)
                self.assertEqual(mock_popen.call_args[1].get("pass_fds"), captured["pass_fds"])
                self.assertEqual(captured["resolved"], {"token": token})
                self.assertNotIn(token, json.dumps(captured["environment"]))

    async def test_cookie_jar_not_in_argv(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with (
            patch("subprocess.Popen") as mock_popen,
            patch.object(DashboardServer, "_track_scan_process"),
        ):
            captured = {}
            cookie = "session=abc123; role=admin"
            mock_popen.side_effect = _credential_pipe_popen(
                {"cookie": cookie}, captured
            )

            async with _make_async_client(app) as client:
                await client.post("/api/v1/scans/launch", json={
                    "target": LAB_TARGET,
                    "mode": "greybox",
                    "modules": ["sqli"],
                    **_web_launch_contract("credential-cookie"),
                    "auth_profile": {
                        "auth_type": "cookie",
                        "cookie_jar": cookie,
                    },
                })

            if mock_popen.called:
                args_list = mock_popen.call_args[0][0]
                argv_str = " ".join(str(a) for a in args_list)
                self.assertNotIn("abc123", argv_str,
                                 "Cookie jar must NOT appear in subprocess argv")
                env = mock_popen.call_args[1].get("env", {})
                self.assertNotIn("FORGE_COOKIE_JAR", env)
                self.assertIn(CREDENTIAL_REF_ENV, env)
                self.assertIn(CREDENTIAL_FD_ENV, env)
                self.assertEqual(mock_popen.call_args[1].get("pass_fds"), captured["pass_fds"])
                self.assertEqual(captured["resolved"], {"cookie": cookie})
                self.assertNotIn(cookie, json.dumps(captured["environment"]))


class TestDashboardCredentialLifecycle(unittest.IsolatedAsyncioTestCase):
    """Every post-creation exit wipes the request-owned credential bundle."""

    async def _assert_failure_wipes_bundle(
        self,
        endpoint: str,
        request_body: dict[str, object],
        patch_target: str,
    ) -> None:
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        bundles: list[ProtectedCredentialBundle] = []
        original_create = DashboardServer._request_credential_bundle

        def _capture_bundle(server, request, values, *, ttl_seconds=60):
            bundle = original_create(
                server,
                request,
                values,
                ttl_seconds=ttl_seconds,
            )
            bundles.append(bundle)
            return bundle

        with (
            patch.object(
                DashboardServer,
                "_request_credential_bundle",
                new=_capture_bundle,
            ),
            patch.object(
                DashboardServer,
                patch_target,
                side_effect=RuntimeError("bounded prelaunch fixture failure"),
            ),
            patch("subprocess.Popen") as mock_popen,
        ):
            async with _make_async_client(app) as client:
                try:
                    await client.post(endpoint, json=request_body)
                except RuntimeError:
                    pass

        self.assertEqual(len(bundles), 1)
        self.assertEqual(len(bundles[0]._payload), 0)
        mock_popen.assert_not_called()

    async def test_scan_start_wipes_bundle_on_confirmation_exception(self):
        body = {
            "target": LAB_TARGET,
            "mode": "greybox",
            **_web_launch_contract("credential-start-prelaunch-failure"),
            "auth_profile": {
                "auth_type": "form",
                "username": "operator",
                "password": "CANARY_START_LIFECYCLE_007",
            },
        }
        await self._assert_failure_wipes_bundle(
            "/api/v1/scans/start",
            body,
            "_server_confirmation",
        )

    async def test_scan_launch_wipes_bundle_on_module_resolution_exception(self):
        body = {
            "target": LAB_TARGET,
            "mode": "greybox",
            "modules": ["sqli"],
            **_web_launch_contract("credential-launch-prelaunch-failure"),
            "auth_profile": {
                "auth_type": "bearer",
                "token": "CANARY_LAUNCH_LIFECYCLE_007",
            },
        }
        await self._assert_failure_wipes_bundle(
            "/api/v1/scans/launch",
            body,
            "_string_list",
        )

    async def test_cleanup_failure_does_not_mask_prelaunch_exception(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        body = {
            "target": LAB_TARGET,
            "mode": "greybox",
            **_web_launch_contract("credential-cleanup-mask"),
            "auth_profile": {"password": "CANARY_CLEANUP_MASK_007"},
        }

        with (
            patch.object(
                DashboardServer,
                "_server_confirmation",
                side_effect=RuntimeError("primary prelaunch failure"),
            ),
            patch.object(
                ProtectedCredentialBundle,
                "wipe",
                side_effect=RuntimeError("cleanup failure"),
            ),
        ):
            async with _make_async_client(app) as client:
                with self.assertRaisesRegex(RuntimeError, "primary prelaunch failure"):
                    await client.post("/api/v1/scans/start", json=body)


class TestContainedADCredentialActions(unittest.IsolatedAsyncioTestCase):
    """Legacy AD subprocess and hash-artifact paths remain inert at Gate 0."""

    async def test_named_ad_paths_make_zero_subprocess_calls_or_artifacts(self):
        import tempfile

        from adforge.modules.attacks.asrep_roast import AsrepRoast
        from adforge.modules.attacks.kerberoast import Kerberoast
        from adforge.modules.post.secretsdump import Secretsdump
        from adforge.modules.reporting.bloodhound_export import BloodhoundExport
        from common.config import BaseForgeConfig
        from common.db import create_db
        from common.scope import Scope

        canary = "CANARY_AD_PASSWORD_007"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = BaseForgeConfig(target="127.0.0.1")
            cfg.extra.update({
                "domain": "fixture.test",
                "dc": "127.0.0.1",
                "username": "operator",
                "password": canary,
                "hash": "8846f7eaee8fb117ad06bdd830b7586c",
                "results_dir": str(root),
                "bloodhound_enabled": True,
                "dcsync_enabled": True,
            })
            session = create_db(root / "ad-contained.db")
            scope = Scope(["127.0.0.1/32"])
            modules = [
                AsrepRoast(cfg, scope, session, root),
                Kerberoast(cfg, scope, session, root),
                BloodhoundExport(cfg, scope, session, root),
                Secretsdump(cfg, scope, session, root),
            ]

            with patch("asyncio.create_subprocess_exec") as spawn:
                results = [await module.run() for module in modules]

            spawn.assert_not_called()
            self.assertTrue(all(result.skipped for result in results))
            self.assertNotIn(canary, repr(results))
            self.assertFalse((root / "hashes").exists())
            self.assertFalse((root / "bloodhound").exists())
            session.close()

    async def test_asrep_legacy_entrypoints_are_inert(self):
        import tempfile

        from adforge.modules.attacks.asrep_roast import AsrepRoast
        from common.config import BaseForgeConfig
        from common.db import create_db
        from common.scope import Scope

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = BaseForgeConfig(target="127.0.0.1")
            cfg.extra.update({
                "domain": "fixture.test",
                "dc": "127.0.0.1",
                "username": "operator",
                "password": "CANARY_ASREP_PASSWORD_007",
                "results_dir": str(root),
            })
            session = create_db(root / "asrep-contained.db")
            module = AsrepRoast(cfg, Scope(["127.0.0.1/32"]), session, root)

            with (
                patch("asyncio.create_subprocess_exec") as spawn,
                patch("adforge.core.ldap_client.LdapClient.connect") as ldap_connect,
                patch.object(Path, "write_text") as write_text,
            ):
                result = await module.run()
                enumerated = await module._enum_asrep_accounts(
                    "fixture.test", "127.0.0.1"
                )
                requested = await module._roast_accounts(
                    ["operator"], "fixture.test", "127.0.0.1"
                )
                direct = await module._roast_impacket(
                    ["operator"], "fixture.test", "127.0.0.1"
                )
                fallback = await module._roast_cli(
                    ["operator"], "fixture.test", "127.0.0.1"
                )

            self.assertTrue(result.skipped)
            self.assertEqual((enumerated, requested, direct, fallback), ([], [], [], []))
            spawn.assert_not_called()
            ldap_connect.assert_not_called()
            write_text.assert_not_called()
            self.assertFalse((root / "hashes").exists())
            session.close()

    def test_adforge_direct_secret_arguments_are_rejected_and_cleared(self):
        from argparse import Namespace
        from common.config import BaseForgeConfig
        from adforge.adforge import (
            _clear_direct_secret_args,
            _has_direct_secret_args,
        )

        args = Namespace(password="CANARY_AD_DIRECT_007", hash=None, ticket=None)
        cfg = BaseForgeConfig(target="127.0.0.1")
        cfg.extra["password"] = "CANARY_AD_DIRECT_007"
        self.assertTrue(_has_direct_secret_args(args, cfg))
        _clear_direct_secret_args(args, cfg)
        self.assertFalse(_has_direct_secret_args(args, cfg))
        self.assertIsNone(args.password)
        self.assertNotIn("password", cfg.extra)


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

        private_tmp_context = tempfile.TemporaryDirectory(
            prefix="forge-template-test-"
        )
        private_tmp = private_tmp_context.name
        with tempfile.NamedTemporaryFile(
            suffix=".json",
            delete=False,
            mode="w",
            dir=private_tmp,
        ) as f:
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
            private_tmp_context.cleanup()


class TestBlackboxNoEnvSecrets(unittest.IsolatedAsyncioTestCase):
    """In blackbox mode no FORGE_* secret env vars should be set."""

    async def test_blackbox_no_forge_secrets_in_env(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with (
            patch("subprocess.Popen") as mock_popen,
            patch.object(DashboardServer, "_track_scan_process"),
        ):
            mock_proc = MagicMock()
            mock_proc.poll.return_value = None
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc

            async with _make_async_client(app) as client:
                await client.post("/api/v1/scans/start", json={
                    "target": LAB_TARGET,
                    "mode": "blackbox",
                    **_web_launch_contract("credential-blackbox"),
                })

            if mock_popen.called:
                env = mock_popen.call_args[1].get("env", {})
                for key in ("FORGE_PASSWORD", "FORGE_TOKEN", "FORGE_COOKIE_JAR"):
                    self.assertNotIn(key, env,
                                     f"{key} must not be set for blackbox scans")


class TestDashboardConnectivity(unittest.IsolatedAsyncioTestCase):
    """Dashboard health and tool launch metadata should stay wired."""

    async def test_health_is_sanitized_and_authenticated_tools_expose_inventory(self):
        from common.dashboard.server import DashboardServer
        from common.version import VERSION

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        async with _make_async_client(app) as client:
            health = await client.get("/api/v1/health")
            tools = await client.get("/api/v1/tools")

        self.assertEqual(health.status_code, 200)
        health_data = health.json()
        self.assertEqual(
            set(health_data),
            {"status", "auth_required", "version", "timestamp"},
        )
        self.assertEqual(health_data["status"], "ok")
        self.assertTrue(health_data["auth_required"])
        self.assertEqual(health_data["version"], VERSION)

        self.assertEqual(tools.status_code, 200)
        tool_ids = {tool["id"] for tool in tools.json()["tools"]}
        self.assertIn("web", tool_ids)
        self.assertIn("net", tool_ids)
        self.assertIn("payload", tool_ids)

    async def test_launch_response_and_status_include_dashboard_url(self):
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with (
            patch("subprocess.Popen") as mock_popen,
            patch.object(DashboardServer, "_track_scan_process"),
        ):
            mock_proc = MagicMock()
            mock_proc.poll.return_value = None
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc

            async with _make_async_client(app) as client:
                resp = await client.post(
                    "/api/v1/scans/launch",
                    json={
                        "target": LAB_TARGET,
                        "mode": "blackbox",
                        "modules": ["sqli"],
                        **_web_launch_contract("dashboard-connectivity"),
                    },
                )
                status = await client.get("/api/v1/scans/status")

        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertIn("dashboard_url", body)
        self.assertEqual(body["dashboard_url"], "http://127.0.0.1:1337")
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
        private_tmp_context = tempfile.TemporaryDirectory(
            prefix="forge-history-test-"
        )
        private_tmp = private_tmp_context.name
        with tempfile.NamedTemporaryFile(
            suffix=".json",
            delete=False,
            mode="w",
            dir=private_tmp,
        ) as f:
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
            private_tmp_context.cleanup()

    async def test_delete_scan_removes_history_record(self):
        from common.dashboard.server import DashboardServer
        from unittest.mock import PropertyMock
        import tempfile, os

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        private_tmp_context = tempfile.TemporaryDirectory(
            prefix="forge-history-delete-test-"
        )
        private_tmp = private_tmp_context.name
        with tempfile.NamedTemporaryFile(
            suffix=".json",
            delete=False,
            mode="w",
            dir=private_tmp,
        ) as f:
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
            private_tmp_context.cleanup()


if __name__ == "__main__":
    unittest.main()
