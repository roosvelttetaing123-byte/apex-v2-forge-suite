from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import httpx
import pytest
from fastapi import HTTPException

from common.confirm_gate import (
    ActionConfirmation,
    LAUNCH_ACTION_ENV,
    LAUNCH_CONFIRMATIONS_ENV,
    LAUNCH_JOB_ID_ENV,
    decide_action,
    load_launch_confirmations,
)
from common.scope import ScopeReason


def _make_async_client(app, *, role="admin", authenticated=True):
    transport = httpx.ASGITransport(app=app)
    headers = {}
    if authenticated:
        from common.dashboard.auth import issue_identity_token
        headers["Authorization"] = f"Bearer {issue_identity_token('task004-test', role)}"
    return httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers=headers,
    )


LAB_URL = "http://127.0.0.1:8080/fixture"


def test_scan_fingerprint_validation_errors_are_fixed_and_opaque(
    tmp_path: Path,
) -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=False)
    app = server.create_app()
    fingerprint_secret = "opaque-fingerprint-validator-input-8f34b0"
    rate_secret = "opaque-rate-validator-input-71d4"

    async def exercise() -> tuple[list[httpx.Response], httpx.Response, httpx.Response]:
        with patch.object(
            DashboardServer,
            "_scan_fingerprint_path",
            new_callable=PropertyMock,
            return_value=tmp_path / "scan-fingerprints.json",
        ):
            async with _make_async_client(app, role="operator") as client:
                fingerprint_responses = [
                    await client.post(
                        "/api/v1/scans/fingerprints/plan",
                        json={
                            "host": "api.example.test",
                            "service": "https",
                            "port": supplied,
                        },
                    )
                    for supplied in (fingerprint_secret, fingerprint_secret[:12])
                ]
                non_object_response = await client.post(
                    "/api/v1/scans/fingerprints/plan",
                    json=["opaque-non-object-input-4c21"],
                )
                rate_response = await client.post(
                    "/api/v1/scans/rate-adapt",
                    json={
                        "host": "api.example.test",
                        "service": "https",
                        "port": 443,
                        "signal": rate_secret,
                    },
                )
        return fingerprint_responses, non_object_response, rate_response

    fingerprint_responses, non_object_response, rate_response = asyncio.run(
        exercise()
    )

    for response, supplied in zip(
        fingerprint_responses,
        (fingerprint_secret, fingerprint_secret[:12]),
    ):
        assert response.status_code == 400
        assert response.json() == {
            "detail": {"reason_code": "scan_fingerprint_input_invalid"}
        }
        assert supplied not in response.text
    assert non_object_response.status_code == 400
    assert non_object_response.json() == {
        "detail": {"reason_code": "scan_fingerprint_input_invalid"}
    }
    assert "opaque-non-object-input-4c21" not in non_object_response.text
    assert rate_response.status_code == 400
    assert rate_response.json()["reason_code"] == "scan_rate_input_invalid"
    assert rate_secret not in rate_response.text
    assert rate_secret[:12] not in rate_response.text


@pytest.fixture(autouse=True)
def _isolated_dashboard_job_db(tmp_path, monkeypatch) -> None:
    from common.dashboard.server import DashboardServer

    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda self: tmp_path / "dashboard-hardening.db"),
    )


def _confirmation(
    job_id: str,
    target: str = LAB_URL,
    engine: str = "webforge",
    action: str = "scan",
) -> dict[str, object]:
    return ActionConfirmation.create(
        job_id=job_id,
        target=target,
        engine=engine,
        action=action,
    ).to_dict()


def test_dashboard_confirmation_bundle_matches_single_web_launch_contract() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer.__new__(DashboardServer)
    bundle = server._prepare_dashboard_confirmation_bundle(
        {
            "intent": "scan.start",
            "target": "127.0.0.1:8080",
            "scope": ["127.0.0.1/32"],
            "exclude": [],
            "scan_type": "web",
        }
    )

    assert bundle["authorized"] is False
    assert bundle["scope"] == ["127.0.0.1/32"]
    assert len(bundle["confirmations"]) == 1
    confirmation = ActionConfirmation.from_value(bundle["confirmation"])
    decision = decide_action(
        target="https://127.0.0.1:8080",
        allowed_scope=bundle["scope"],
        excluded_scope=bundle["exclude"],
        confirmation=confirmation,
        job_id=bundle["job_id"],
        engine="webforge",
        action="scan",
    )
    assert decision.allowed is True


def test_dashboard_confirmation_bundle_requires_separate_vapt_network_scope() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer.__new__(DashboardServer)
    request = {
        "intent": "scan.launch",
        "target": LAB_URL,
        # The broad primary scope already contains the network target.  Mixed
        # launches must still supply and validate a separate network scope.
        "scope": ["127.0.0.0/8"],
        "exclude": [],
        "modules": ["sqli", "portscan"],
        "network_target": "127.0.0.2",
    }
    with pytest.raises(HTTPException) as denied:
        server._prepare_dashboard_confirmation_bundle(request)
    assert denied.value.detail["reason_code"] == ScopeReason.MISSING_SCOPE.value

    with pytest.raises(HTTPException) as broad_denied:
        server._prepare_dashboard_confirmation_bundle(
            {**request, "network_scope": ["127.0.0.0/8"]}
        )
    assert broad_denied.value.detail["reason_code"] == (
        ScopeReason.TARGET_MISMATCH.value
    )

    bundle = server._prepare_dashboard_confirmation_bundle(
        {**request, "network_scope": ["127.0.0.2/32"]}
    )
    assert bundle["scope"] == ["127.0.0.0/8", "127.0.0.2/32"]
    assert bundle["web_scope"] == ["127.0.0.0/8"]
    assert bundle["network_scope"] == ["127.0.0.2/32"]
    assert bundle["network_target"] == "127.0.0.2"
    assert [item["scope"] for item in bundle["actions"]] == [
        ["127.0.0.0/8"],
        ["127.0.0.2/32"],
    ]
    assert [
        (item["engine"], item["action"])
        for item in bundle["confirmations"]
    ] == [
        ("webforge", "scan"),
        ("netforge", "web_to_network"),
    ]


def test_dashboard_confirmation_bundle_derives_retest_target_and_engine() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer.__new__(DashboardServer)
    server._find_finding_metadata = lambda _finding_id: {
        "id": "finding-1",
        "module": "port_scanner",
        "target": "192.0.2.0/24",
    }
    server._netforge_module_names = lambda: {"port_scanner"}

    bundle = server._prepare_dashboard_confirmation_bundle(
        {
            "intent": "finding.retest",
            "finding_id": "finding-1",
            "scope": ["192.0.2.0/24"],
            "exclude": [],
        }
    )

    confirmation = ActionConfirmation.from_value(bundle["confirmation"])
    assert confirmation.engine == "netforge"
    assert confirmation.action == "retest"


def test_dashboard_confirmation_bundle_rejects_empty_scanbuilder_plan() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer.__new__(DashboardServer)
    with pytest.raises(HTTPException) as denied:
        server._prepare_dashboard_confirmation_bundle(
            {
                "intent": "scan.launch",
                "target": LAB_URL,
                "scope": ["127.0.0.1/32"],
                "exclude": [],
                "modules": [],
            }
        )
    assert denied.value.detail["reason_code"] == (
        ScopeReason.INVALID_CONFIRMATION.value
    )


def test_dashboard_confirmation_bundle_validates_whitebox_source_root(
    tmp_path: Path,
) -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer.__new__(DashboardServer)
    request = {
        "intent": "scan.start",
        "target": LAB_URL,
        "scope": ["127.0.0.1/32"],
        "exclude": [],
        "scan_type": "web",
        "mode": "whitebox",
    }
    with pytest.raises(HTTPException) as denied:
        server._prepare_dashboard_confirmation_bundle(request)
    assert denied.value.status_code == 400
    assert denied.value.detail == "source_root is required"

    bundle = server._prepare_dashboard_confirmation_bundle(
        {**request, "source_root": str(tmp_path)}
    )
    assert bundle["authorized"] is False


def test_dashboard_ipv6_escalation_resolution_uses_exact_getaddrinfo_answer() -> None:
    import socket

    from common.dashboard.server import DashboardServer

    answers = [
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("2001:db8::10", 0, 0, 0),
        )
    ]
    with (
        patch("common.dashboard.server.socket.gethostbyname") as ipv4_resolver,
        patch(
            "common.dashboard.server.socket.getaddrinfo",
            return_value=answers,
        ) as ipv6_resolver,
    ):
        assert DashboardServer._hostname_resolves_to_exact_ip(
            "app.example.test",
            "2001:db8::10",
        )
        assert not DashboardServer._hostname_resolves_to_exact_ip(
            "app.example.test",
            "2001:db8::11",
        )

    ipv4_resolver.assert_not_called()
    assert ipv6_resolver.call_count == 2
    ipv6_resolver.assert_called_with(
        "app.example.test",
        None,
        socket.AF_INET6,
        socket.SOCK_STREAM,
    )

    server = DashboardServer.__new__(DashboardServer)
    scope, decision = server._exact_network_scope_inputs(
        "[2001:db8::10]",
        ["[2001:db8::10]"],
        [],
    )
    assert decision.allowed is True
    assert scope == ["2001:db8::10/128"]


class _Attr:
    def __init__(self, value, raw_values=None) -> None:
        self.value = value
        self.raw_values = raw_values or []


class _Entry:
    entry_dn = "CN=Test,DC=example,DC=test"
    nTSecurityDescriptor = _Attr("<string descriptor>", [b"\x01\x00raw-sd"])


class _Connection:
    entries = [_Entry()]

    def search(self, **kwargs) -> None:
        self.kwargs = kwargs


def test_ldap_client_preserves_raw_security_descriptor_bytes() -> None:
    from adforge.core.ldap_client import LdapClient

    client = LdapClient("127.0.0.1", "example.test")
    conn = _Connection()
    client._conn = conn
    client._base_dn = "DC=example,DC=test"

    rows = client.search("(objectClass=*)", ["nTSecurityDescriptor"], controls=["sd-control"])

    assert conn.kwargs["controls"] == ["sd-control"]
    assert rows[0]["nTSecurityDescriptor"] == b"\x01\x00raw-sd"
    assert rows[0]["nTSecurityDescriptor_raw"] == b"\x01\x00raw-sd"


def test_asrep_rc4_hash_uses_trailing_checksum() -> None:
    from adforge.modules.attacks.asrep_roast import format_asrep_hash

    cipher = bytes(range(1, 33))
    formatted = format_asrep_hash("alice", "corp.local", 23, cipher)

    assert formatted == (
        "$krb5asrep$23$alice@CORP.LOCAL:"
        "1112131415161718191a1b1c1d1e1f20$"
        "0102030405060708090a0b0c0d0e0f10"
    )


def test_audit_log_model_round_trips(tmp_path: Path) -> None:
    from common.db import AuditLogModel, audit_log_to_dict, create_db, save_audit_log

    session = create_db(tmp_path / "audit.db")
    try:
        row = save_audit_log(
            session,
            {
                "tenant_id": "tenant-a",
                "operator": "alice",
                "role": "admin",
                "ip": "127.0.0.1",
                "action": "scan.launch",
                "object_id": "scan-1",
                "status": "ok",
                "detail": {"target": "example.test"},
            },
        )
        loaded = session.query(AuditLogModel).filter_by(id=row.id).one()
        data = audit_log_to_dict(loaded)
    finally:
        session.close()

    assert data["tenant_id"] == "tenant-a"
    assert data["action"] == "scan.launch"
    assert data["detail"] == {"target": "example.test"}


def test_dashboard_scan_job_reads_and_deletes_are_tenant_filtered(
    tmp_path: Path,
) -> None:
    from common.dashboard.server import DashboardServer
    from common.db import create_db, get_scan_job, save_scan_job

    db_path = tmp_path / "tenant-dashboard-jobs.db"
    session = create_db(db_path)
    try:
        for tenant in ("tenant-a", "tenant-b"):
            save_scan_job(
                session,
                {
                    "id": f"job-{tenant}",
                    "tenant_id": tenant,
                    "status": "pending",
                    "target": LAB_URL,
                },
                allow_legacy_compat=True,
            )
    finally:
        session.close()

    server = DashboardServer(auth=False)
    server.tenant_id = "tenant-a"
    with patch.object(
        DashboardServer,
        "_scan_jobs_db_path",
        new_callable=PropertyMock,
        return_value=db_path,
    ):
        assert server._load_scan_job("job-tenant-a") is not None
        assert server._load_scan_job("job-tenant-b") is None
        assert [row["scan_id"] for row in server._load_scan_jobs()] == [
            "job-tenant-a"
        ]
        server._delete_scan_job("job-tenant-b")

    session = create_db(db_path)
    try:
        assert get_scan_job(
            session,
            "job-tenant-b",
            tenant_id="tenant-b",
        ) is not None
    finally:
        session.close()

def test_state_store_sqlite_backend_restores_tenant_and_findings(tmp_path: Path) -> None:
    from common.dashboard.event_bus import Event, EventBus, EventType
    from common.dashboard.state_store import StateStore
    from common.db import create_db

    session = create_db(tmp_path / "state.db")
    bus = EventBus()
    bus.start()
    try:
        store = StateStore(
            bus,
            framework="webforge",
            run_id="run-1",
            target="https://example.test",
            persist_db=session,
            tenant_id="tenant-a",
        )
        bus.emit(Event(
            event_type=EventType.FINDING_NEW,
            data={
                "id": "finding-1",
                "title": "Header Missing",
                "severity": "Low",
                "module": "header_audit",
                "target": "https://example.test",
            },
            source="header_audit",
        ))
        time.sleep(0.2)
        store.stop()
        restored = StateStore.restore_from_db(
            session,
            "run-1",
            bus,
            tenant_id="tenant-a",
        )
    finally:
        bus.stop()
        session.close()

    assert restored is not None
    snap = restored.snapshot()
    assert snap["tenant_id"] == "tenant-a"
    assert snap["findings"][0]["id"] == "finding-1"


def test_state_store_sqlite_backend_isolates_same_run_across_tenants(
    tmp_path: Path,
) -> None:
    from common.dashboard.state_store import SQLiteStateBackend
    from common.db import DashboardStateModel, create_db

    session = create_db(tmp_path / "tenant-state.db")
    try:
        tenant_a = SQLiteStateBackend(session, tenant_id="tenant-a")
        tenant_b = SQLiteStateBackend(session, tenant_id="tenant-b")
        tenant_a.save("shared-run", {"tenant_id": "tenant-a", "marker": "a"})
        tenant_b.save("shared-run", {"tenant_id": "tenant-b", "marker": "b"})

        assert tenant_a.load("shared-run") == {"tenant_id": "tenant-a", "marker": "a"}
        assert tenant_b.load("shared-run") == {"tenant_id": "tenant-b", "marker": "b"}
        assert session.query(DashboardStateModel).filter_by(run_id="shared-run").count() == 2
    finally:
        session.close()


def test_state_store_sqlite_id_binds_adversarial_tenant_run_tuples(
    tmp_path: Path,
) -> None:
    from common.dashboard.state_store import SQLiteStateBackend
    from common.db import DashboardStateModel, create_db

    session = create_db(tmp_path / "tenant-state-tuple-binding.db")
    try:
        colon_in_tenant = SQLiteStateBackend(session, tenant_id="a:b")
        colon_in_run = SQLiteStateBackend(session, tenant_id="a")
        colon_in_tenant.save("c", {"marker": "tenant-colon"})
        colon_in_run.save("b:c", {"marker": "run-colon"})

        assert colon_in_tenant.load("c") == {"marker": "tenant-colon"}
        assert colon_in_run.load("b:c") == {"marker": "run-colon"}
        rows = session.query(DashboardStateModel).all()
        assert len(rows) == 2
        assert {row.id for row in rows} == {
            "30fa3a05-6fbd-5cb5-af77-d9e7448a43be",
            "90aea80d-7aaa-5fa2-b7f5-55409b517f45",
        }
        assert {(row.tenant_id, row.run_id) for row in rows} == {
            ("a:b", "c"),
            ("a", "b:c"),
        }
    finally:
        session.close()


def test_state_store_redis_backend_isolates_same_run_across_tenants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hashlib
    import sys

    from common.dashboard.state_store import (
        RedisStateBackend,
        make_state_backend,
    )

    values: dict[str, str] = {
        "forge:dashboard:state:legacy-run": json.dumps({"marker": "legacy"}),
    }
    redis_client = MagicMock()
    redis_client.set.side_effect = lambda key, value: values.__setitem__(key, value)
    redis_client.get.side_effect = values.get
    redis_module = MagicMock()
    redis_module.from_url.return_value = redis_client
    monkeypatch.setitem(sys.modules, "redis", redis_module)

    tenant_a = RedisStateBackend("redis://fixture", tenant_id="tenant-a")
    tenant_b = RedisStateBackend("redis://fixture", tenant_id="tenant-b")
    tenant_a.save("shared-run", {"tenant_id": "tenant-a", "marker": "a"})
    tenant_b.save("shared-run", {"tenant_id": "tenant-b", "marker": "b"})

    tenant_a_digest = hashlib.sha256(b"tenant-a").hexdigest()
    tenant_b_digest = hashlib.sha256(b"tenant-b").hexdigest()
    run_digest = hashlib.sha256(b"shared-run").hexdigest()
    assert tenant_a._key("shared-run") == (
        "forge:dashboard:state:tenant-sha256:"
        f"{tenant_a_digest}:run-sha256:{run_digest}"
    )
    assert tenant_b._key("shared-run") == (
        "forge:dashboard:state:tenant-sha256:"
        f"{tenant_b_digest}:run-sha256:{run_digest}"
    )
    assert tenant_a._key("shared-run") != tenant_b._key("shared-run")
    assert tenant_a.load("shared-run") == {"tenant_id": "tenant-a", "marker": "a"}
    assert tenant_b.load("shared-run") == {"tenant_id": "tenant-b", "marker": "b"}
    assert tenant_a.load("legacy-run") is None

    factory_backend = make_state_backend(
        "redis",
        redis_url="redis://fixture",
        tenant_id="tenant-a",
    )
    assert isinstance(factory_backend, RedisStateBackend)
    assert factory_backend.tenant_id == "tenant-a"
    assert factory_backend._key("shared-run") == tenant_a._key("shared-run")

    connection_calls = redis_module.from_url.call_count
    with pytest.raises(ValueError, match="invalid dashboard state tenant identifier"):
        make_state_backend(
            "redis",
            redis_url="redis://fixture",
            tenant_id="../tenant-b",
        )
    assert redis_module.from_url.call_count == connection_calls


def test_auth_lockout_and_totp(monkeypatch) -> None:
    from common.dashboard import auth

    monkeypatch.setenv("FORGE_DASHBOARD_PASSWORD", "configured-secret")
    monkeypatch.setenv("FORGE_DASHBOARD_LOCKOUT_ATTEMPTS", "2")
    monkeypatch.setenv("FORGE_DASHBOARD_LOCKOUT_SECONDS", "60")
    monkeypatch.setenv("FORGE_DASHBOARD_TOTP_SECRET", "JBSWY3DPEHPK3PXP")
    auth._clear_auth_failures("operator")
    try:
        assert auth.generate_token("operator", "configured-secret") is None
        code = auth._totp_code("JBSWY3DPEHPK3PXP", int(time.time() // 30))
        assert auth.generate_token("operator", "configured-secret", totp_code=code) is not None
        assert auth.generate_token("operator", "wrong") is None
        assert auth.generate_token("operator", "wrong") is None
        assert auth.generate_token("operator", "configured-secret", totp_code=code) is None
    finally:
        auth._clear_auth_failures("operator")


class TestDashboardHardeningApi(unittest.IsolatedAsyncioTestCase):
    async def test_action_confirmation_endpoint_only_prepares_exact_contract(self) -> None:
        from common.dashboard.server import DashboardServer
        from common.db import AuthorizationDecisionModel, ScanJobModel, create_db

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch.object(DashboardServer, "_init_control_file") as control,
        ):
            async with _make_async_client(app, role="operator") as client:
                response = await client.post(
                    "/api/v1/action-confirmations",
                    json={
                        "intent": "scan.start",
                        "target": "localhost",
                        "scan_type": "net",
                        "scope": ["localhost"],
                        "exclude": [],
                    },
                )

        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["authorized"] is False
        assert payload["actions"][0]["engine"] == "netforge"
        assert payload["actions"][0]["action"] == "scan"
        confirmation = ActionConfirmation.from_value(payload["confirmation"])
        assert confirmation.job_id == payload["job_id"]
        assert confirmation.engine == "netforge"
        popen.assert_not_called()
        control.assert_not_called()

        session = create_db(srv._scan_jobs_db_path)
        try:
            assert session.query(ScanJobModel).count() == 0
            assert session.query(AuthorizationDecisionModel).count() == 0
        finally:
            session.close()

    async def test_dashboard_audit_logs_and_kill_switch_are_exposed(self) -> None:
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "scan_jobs.db"
            kill_path = Path(tmpdir) / "kill.json"
            with (
                patch.object(DashboardServer, "_scan_jobs_db_path", new_callable=PropertyMock, return_value=db_path),
                patch.object(DashboardServer, "_kill_switch_path", new_callable=PropertyMock, return_value=kill_path),
            ):
                async with _make_async_client(app) as client:
                    kill = await client.post("/api/v1/control/kill-switch", json={"enabled": True, "reason": "test"})
                    blocked = await client.post("/api/v1/scans/launch", json={"target": "http://example.test", "modules": ["sqli"]})
                    logs = await client.get("/api/v1/audit-logs")
                    supervisor = await client.get("/api/v1/supervisor")

        assert kill.status_code == 200
        assert kill.json()["status"] == "enabled"
        assert blocked.status_code == 423
        assert logs.status_code == 200
        assert any(item["action"] == "control.kill_switch" for item in logs.json()["audit_logs"])
        assert supervisor.status_code == 200
        assert supervisor.json()["kill_switch_active"] is True

    async def test_missing_scope_denies_before_every_launch_side_effect(self) -> None:
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch("common.dashboard.server.socket.gethostbyname") as resolve,
            patch.object(DashboardServer, "_init_control_file") as control,
            patch.object(DashboardServer, "_track_scan_process") as track,
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": "missing-scope",
                        "target": LAB_URL,
                        "confirmation": _confirmation("missing-scope"),
                    },
                )

        assert response.status_code == 403
        assert response.json()["detail"]["reason_code"] == ScopeReason.MISSING_SCOPE.value
        popen.assert_not_called()
        resolve.assert_not_called()
        control.assert_not_called()
        track.assert_not_called()

    async def test_non_string_target_and_scope_deny_without_coercion_or_side_effects(self) -> None:
        from common.dashboard.server import DashboardServer
        from common.db import AuthorizationDecisionModel, create_db

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        forged_job_id = "job-" + ("a" * 32)
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch("common.dashboard.server.socket.gethostbyname") as resolve,
            patch.object(DashboardServer, "_init_control_file") as control,
        ):
            async with _make_async_client(app) as client:
                bad_target = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": forged_job_id,
                        "target": None,
                        "scope": ["127.0.0.1/32"],
                    },
                )
                bad_scope = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": "bad-scope-type",
                        "target": LAB_URL,
                        "scope": [None],
                        "confirmation": _confirmation("bad-scope-type"),
                    },
                )

        assert bad_target.status_code == 400
        assert bad_target.json()["detail"]["reason_code"] == ScopeReason.MALFORMED_TARGET.value
        assert bad_scope.status_code == 400
        assert bad_scope.json()["detail"]["reason_code"] == ScopeReason.MALFORMED_SCOPE.value
        popen.assert_not_called()
        resolve.assert_not_called()
        control.assert_not_called()
        session = create_db(srv._scan_jobs_db_path)
        try:
            rows = session.query(AuthorizationDecisionModel).all()
        finally:
            session.close()
        reasons = [row.reason_code for row in rows]
        assert reasons == [
            ScopeReason.MALFORMED_TARGET.value,
            ScopeReason.MALFORMED_SCOPE.value,
        ]
        assert rows[0].job_id.startswith("job-")
        assert rows[0].job_id != forged_job_id
        assert rows[1].job_id.startswith("job-")
        assert rows[1].job_id != "bad-scope-type"

    async def test_malformed_boolean_and_bracketed_ip_deny_before_side_effects(self) -> None:
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch("common.dashboard.server.socket.gethostbyname") as resolve,
            patch.object(DashboardServer, "_init_control_file") as control,
        ):
            async with _make_async_client(app) as client:
                malformed_boolean = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": "bad-dry-run-type",
                        "target": LAB_URL,
                        "scope": ["127.0.0.1/32"],
                        "dry_run": 0,
                        "confirmation": _confirmation("bad-dry-run-type"),
                    },
                )
                malformed_ip = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": "bad-bracketed-ip",
                        "target": "[[127.0.0.1]]",
                        "scan_type": "net",
                        "scope": ["127.0.0.1/32"],
                        "confirmation": _confirmation(
                            "bad-bracketed-ip",
                            "127.0.0.1",
                            engine="netforge",
                        ),
                    },
                )

        assert malformed_boolean.status_code == 400
        assert malformed_boolean.json()["detail"]["reason_code"] == ScopeReason.INVALID_CONFIRMATION.value
        assert malformed_ip.status_code == 400
        assert malformed_ip.json()["detail"]["reason_code"] == ScopeReason.MALFORMED_TARGET.value
        popen.assert_not_called()
        resolve.assert_not_called()
        control.assert_not_called()

    async def test_scanbuilder_missing_confirmation_denies_before_side_effects(self) -> None:
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch("common.dashboard.server.socket.gethostbyname") as resolve,
            patch.object(DashboardServer, "_init_control_file") as control,
            patch.object(DashboardServer, "_track_scan_process") as track,
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/launch",
                    json={
                        "job_id": "scanbuilder-unconfirmed",
                        "target": LAB_URL,
                        "scope": ["127.0.0.1/32"],
                        "exclude": [],
                        "modules": ["sqli"],
                    },
                )

        assert response.status_code == 403
        assert response.json()["detail"]["reason_code"] == ScopeReason.MISSING_CONFIRMATION.value
        popen.assert_not_called()
        resolve.assert_not_called()
        control.assert_not_called()
        track.assert_not_called()

    async def test_scanbuilder_empty_module_plan_denies_before_side_effects(self) -> None:
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch.object(DashboardServer, "_init_control_file") as control,
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/launch",
                    json={
                        "job_id": "empty-plan",
                        "target": LAB_URL,
                        "scope": ["127.0.0.1/32"],
                        "exclude": [],
                        "modules": [],
                    },
                )

        assert response.status_code == 400
        assert response.json()["detail"] == (
            "Select at least one implemented module before launch."
        )
        popen.assert_not_called()
        control.assert_not_called()

    async def test_exclusion_denies_without_process_dns_or_control_file(self) -> None:
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch("common.dashboard.server.socket.gethostbyname") as resolve,
            patch.object(DashboardServer, "_init_control_file") as control,
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": "excluded-target",
                        "target": LAB_URL,
                        "scope": ["127.0.0.0/8"],
                        "exclude": ["127.0.0.1/32"],
                        "confirmation": _confirmation("excluded-target"),
                    },
                )

        assert response.status_code == 403
        assert response.json()["detail"]["reason_code"] == ScopeReason.EXCLUDED.value
        popen.assert_not_called()
        resolve.assert_not_called()
        control.assert_not_called()

    async def test_dry_run_is_scope_plan_not_authorization_and_has_no_side_effects(self) -> None:
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch("common.dashboard.server.socket.gethostbyname") as resolve,
            patch.object(DashboardServer, "_init_control_file") as control,
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": "dry-plan",
                        "target": LAB_URL,
                        "scope": ["127.0.0.1/32"],
                        "exclude": [],
                        "dry_run": True,
                    },
                )

        assert response.status_code == 200, response.text
        assert response.json()["status"] == "planned"
        assert response.json()["authorized"] is False
        popen.assert_not_called()
        resolve.assert_not_called()
        control.assert_not_called()

    async def test_plain_web_launch_without_canonical_lineage_fails_closed(self) -> None:
        from common.dashboard.server import DashboardServer
        from common.db import (
            AuthorizationConsumptionModel,
            AuthorizationDecisionModel,
            ScanJobModel,
            create_db,
        )

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        process = MagicMock(pid=4242, stdout=[])
        process.poll.return_value = None
        with (
            patch("common.dashboard.server.subprocess.Popen", return_value=process) as popen,
            patch("common.dashboard.server.socket.gethostbyname") as resolve,
            patch.dict(
                os.environ,
                {
                    "FORGE_PASSWORD": "AMBIENT_PASSWORD_MUST_NOT_REACH_CHILD",
                    "FORGE_AGENT_REGISTRATION_TOKEN": "AMBIENT_AGENT_TOKEN",
                    "THIRD_PARTY_PASSWORD": "AMBIENT_PROVIDER_SECRET",
                },
            ),
            patch.object(
                DashboardServer,
                "_init_control_file",
                return_value=Path("/tmp/forge-web-control.json"),
            ) as control,
            patch.object(DashboardServer, "_track_scan_process"),
            patch.object(DashboardServer, "_write_scan_history"),
            patch.object(DashboardServer, "_write_scan_job"),
            patch.object(DashboardServer, "_write_audit_log"),
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": "web-only",
                        "target": LAB_URL,
                        "scope": ["127.0.0.1/32"],
                        "exclude": ["127.0.0.2/32"],
                        "confirmation": _confirmation("web-only"),
                    },
                )

        assert response.status_code == 500, response.text
        assert response.json()["detail"] == (
            "Authorization handoff persistence failed; execution denied"
        )
        popen.assert_not_called()
        resolve.assert_not_called()
        control.assert_not_called()
        session = create_db(srv._scan_jobs_db_path)
        try:
            assert session.query(ScanJobModel).count() == 0
            assert session.query(AuthorizationDecisionModel).filter_by(
                decision_outcome="allow"
            ).count() == 0
            assert session.query(AuthorizationConsumptionModel).count() == 0
        finally:
            session.close()

    async def test_direct_net_launch_without_canonical_lineage_fails_closed(self) -> None:
        from common.dashboard.server import DashboardServer

        cases = (
            ("net-hostname", "localhost", ["localhost"]),
            ("net-cidr", "127.0.0.0/30", ["127.0.0.0/30"]),
        )
        for job_id, target, scope in cases:
            with self.subTest(target=target):
                srv = DashboardServer(auth=False)
                app = srv.create_app()
                process = MagicMock(pid=4343, stdout=[])
                process.poll.return_value = None
                with (
                    patch(
                        "common.dashboard.server.subprocess.Popen",
                        return_value=process,
                    ) as popen,
                    patch("common.dashboard.server.socket.gethostbyname") as resolve,
                    patch.object(
                        DashboardServer,
                        "_init_control_file",
                        return_value=Path("/tmp/forge-net-control.json"),
                    ),
                    patch.object(DashboardServer, "_track_scan_process"),
                    patch.object(DashboardServer, "_write_scan_history"),
                    patch.object(DashboardServer, "_write_scan_job"),
                    patch.object(DashboardServer, "_write_audit_log"),
                ):
                    async with _make_async_client(app) as client:
                        response = await client.post(
                            "/api/v1/scans/start",
                            json={
                                "job_id": job_id,
                                "target": target,
                                "scan_type": "net",
                                "scope": scope,
                                "exclude": [],
                                "confirmation": _confirmation(
                                    job_id,
                                    target,
                                    engine="netforge",
                                ),
                            },
                        )

                assert response.status_code == 500, response.text
                assert response.json()["detail"] == (
                    "Authorization handoff persistence failed; execution denied"
                )
                resolve.assert_not_called()
                popen.assert_not_called()

    async def test_pending_authorization_handoff_failure_blocks_subprocess(self) -> None:
        from common.dashboard.server import DashboardServer
        from common.db import (
            AuthorizationConsumptionModel,
            AuthorizationDecisionModel,
            ScanJobModel,
            create_db,
        )

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch.object(
                DashboardServer,
                "_init_control_file",
                return_value=Path("/tmp/forge-pending-failure.json"),
            ),
            patch(
                "common.dashboard.server.save_scan_job",
                side_effect=RuntimeError("forced pending write failure"),
            ),
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": "pending-write-failure",
                        "target": LAB_URL,
                        "scope": ["127.0.0.1/32"],
                        "exclude": [],
                        "confirmation": _confirmation("pending-write-failure"),
                    },
                )

        assert response.status_code == 500
        assert response.json()["detail"] == (
            "Authorization handoff persistence failed; execution denied"
        )
        popen.assert_not_called()
        session = create_db(srv._scan_jobs_db_path)
        try:
            rows = session.query(AuthorizationDecisionModel).all()
            consumptions = session.query(AuthorizationConsumptionModel).count()
            jobs = session.query(ScanJobModel).count()
        finally:
            session.close()
        assert [row.reason_code for row in rows] == ["handoff_persistence_failed"]
        assert (consumptions, jobs) == (0, 0)

    async def test_vapt_missing_second_confirmation_commits_no_partial_allow(self) -> None:
        from common.dashboard.server import DashboardServer
        from common.db import (
            AuthorizationConsumptionModel,
            AuthorizationDecisionModel,
            ScanJobModel,
            create_db,
        )

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        web_target = "http://app.example.test:8080/fixture"
        with patch("common.dashboard.server.subprocess.Popen") as popen:
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": "partial-vapt",
                        "target": web_target,
                        "scan_type": "vapt",
                        "network_target": "127.0.0.1",
                        "scope": ["app.example.test", "127.0.0.1/32"],
                        "web_scope": ["app.example.test"],
                        "network_scope": ["127.0.0.1/32"],
                        "web_confirmation": _confirmation(
                            "partial-vapt",
                            web_target,
                        ),
                    },
                )

        assert response.status_code == 403
        assert response.json()["detail"]["reason_code"] == (
            ScopeReason.MISSING_CONFIRMATION.value
        )
        popen.assert_not_called()
        session = create_db(srv._scan_jobs_db_path)
        try:
            allows = session.query(AuthorizationDecisionModel).filter_by(
                decision_outcome="allow"
            ).count()
            denials = session.query(AuthorizationDecisionModel).filter_by(
                decision_outcome="deny"
            ).all()
            consumptions = session.query(AuthorizationConsumptionModel).count()
            jobs = session.query(ScanJobModel).count()
        finally:
            session.close()
        assert [row.reason_code for row in denials] == [
            ScopeReason.MISSING_CONFIRMATION.value
        ]
        assert (allows, consumptions, jobs) == (0, 0, 0)

    async def test_separately_approved_escalation_without_canonical_lineage_fails_closed(self) -> None:
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        web_target = "http://app.example.test:8080/fixture"
        network_target = "127.0.0.1"
        processes = [MagicMock(pid=5001, stdout=[]), MagicMock(pid=5002, stdout=[])]
        for process in processes:
            process.poll.return_value = None
        with (
            patch(
                "common.dashboard.server.subprocess.Popen",
                side_effect=processes,
            ) as popen,
            patch(
                "common.dashboard.server.socket.gethostbyname",
                return_value=network_target,
            ) as resolve,
            patch.object(
                DashboardServer,
                "_init_control_file",
                return_value=Path("/tmp/forge-vapt-control.json"),
            ),
            patch.object(DashboardServer, "_track_scan_process"),
            patch.object(DashboardServer, "_write_scan_history"),
            patch.object(DashboardServer, "_write_scan_job"),
            patch.object(DashboardServer, "_write_audit_log"),
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": "approved-escalation",
                        "target": web_target,
                        "scan_type": "vapt",
                        "network_target": network_target,
                        "scope": ["app.example.test", "127.0.0.1/32"],
                        "web_scope": ["app.example.test"],
                        "network_scope": ["127.0.0.1/32"],
                        "exclude": [],
                        "web_confirmation": _confirmation(
                            "approved-escalation",
                            web_target,
                        ),
                        "network_confirmation": _confirmation(
                            "approved-escalation",
                            network_target,
                            engine="netforge",
                            action="web_to_network",
                        ),
                    },
                )

        assert response.status_code == 500, response.text
        assert response.json()["detail"] == (
            "Authorization handoff persistence failed; execution denied"
        )
        assert popen.call_count == 0
        resolve.assert_called_once_with("app.example.test")

    async def test_changed_dns_answer_denies_combined_launch_before_any_process(self) -> None:
        from common.dashboard.server import DashboardServer
        from common.db import (
            AuthorizationConsumptionModel,
            AuthorizationDecisionModel,
            ScanJobModel,
            create_db,
        )

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        web_target = "https://app.example.test"
        approved_ip = "192.0.2.10"
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch(
                "common.dashboard.server.socket.gethostbyname",
                return_value="192.0.2.11",
            ) as resolve,
            patch.object(DashboardServer, "_init_control_file") as control,
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/start",
                    json={
                        "job_id": "changed-dns",
                        "target": web_target,
                        "scan_type": "vapt",
                        "network_target": approved_ip,
                        "scope": ["app.example.test", f"{approved_ip}/32"],
                        "web_scope": ["app.example.test"],
                        "network_scope": [f"{approved_ip}/32"],
                        "exclude": [],
                        "web_confirmation": _confirmation("changed-dns", web_target),
                        "network_confirmation": _confirmation(
                            "changed-dns",
                            approved_ip,
                            engine="netforge",
                            action="web_to_network",
                        ),
                    },
                )

        assert response.status_code == 403
        assert response.json()["detail"]["reason_code"] == ScopeReason.TARGET_MISMATCH.value
        resolve.assert_called_once_with("app.example.test")
        popen.assert_not_called()
        control.assert_not_called()
        session = create_db(srv._scan_jobs_db_path)
        try:
            allows = session.query(AuthorizationDecisionModel).filter_by(
                decision_outcome="allow"
            ).count()
            denials = session.query(AuthorizationDecisionModel).filter_by(
                decision_outcome="deny"
            ).all()
            consumptions = session.query(AuthorizationConsumptionModel).count()
            jobs = session.query(ScanJobModel).count()
        finally:
            session.close()
        assert [row.reason_code for row in denials] == [
            "resolved_target_mismatch"
        ]
        assert (allows, consumptions, jobs) == (0, 0, 0)

    async def test_scanbuilder_changed_dns_denies_all_requested_processes(self) -> None:
        from common.dashboard.server import DashboardServer
        from common.db import (
            AuthorizationConsumptionModel,
            AuthorizationDecisionModel,
            ScanJobModel,
            create_db,
        )

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        web_target = "https://builder.example.test"
        approved_ip = "192.0.2.20"
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch(
                "common.dashboard.server.socket.gethostbyname",
                return_value="192.0.2.21",
            ) as resolve,
            patch.object(DashboardServer, "_init_control_file") as control,
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/launch",
                    json={
                        "job_id": "builder-changed-dns",
                        "target": web_target,
                        "network_target": approved_ip,
                        "modules": ["sqli", "portscan"],
                        "scope": ["builder.example.test", f"{approved_ip}/32"],
                        "web_scope": ["builder.example.test"],
                        "network_scope": [f"{approved_ip}/32"],
                        "exclude": [],
                        "web_confirmation": _confirmation(
                            "builder-changed-dns",
                            web_target,
                        ),
                        "network_confirmation": _confirmation(
                            "builder-changed-dns",
                            approved_ip,
                            engine="netforge",
                            action="web_to_network",
                        ),
                    },
                )

        assert response.status_code == 403
        assert response.json()["detail"]["reason_code"] == ScopeReason.TARGET_MISMATCH.value
        resolve.assert_called_once_with("builder.example.test")
        popen.assert_not_called()
        control.assert_not_called()
        session = create_db(srv._scan_jobs_db_path)
        try:
            allows = session.query(AuthorizationDecisionModel).filter_by(
                decision_outcome="allow"
            ).count()
            denials = session.query(AuthorizationDecisionModel).filter_by(
                decision_outcome="deny"
            ).all()
            consumptions = session.query(AuthorizationConsumptionModel).count()
            jobs = session.query(ScanJobModel).count()
        finally:
            session.close()
        assert [row.reason_code for row in denials] == [
            "resolved_target_mismatch"
        ]
        assert (allows, consumptions, jobs) == (0, 0, 0)

    async def test_denial_detail_does_not_echo_url_credentials(self) -> None:
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        password = "CANARY_PASSWORD_DASHBOARD"
        token = "CANARY_TOKEN_DASHBOARD"
        submitted = f"https://operator:{password}@outside.test/path?token={token}"
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch("common.dashboard.server.socket.gethostbyname") as resolve,
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/start",
                    json={"job_id": "redacted-denial", "target": submitted},
                )

        rendered = response.text
        assert response.status_code == 403
        assert password not in rendered
        assert token not in rendered
        popen.assert_not_called()
        resolve.assert_not_called()

    async def test_scanbuilder_denial_never_logs_raw_target_credentials(self) -> None:
        from common.dashboard.server import DashboardServer

        srv = DashboardServer(auth=False)
        app = srv.create_app()
        password = "CANARY_SCANBUILDER_PASSWORD"
        token = "CANARY_SCANBUILDER_TOKEN"
        submitted = f"https://operator:{password}@outside.test/path?token={token}"
        with (
            patch("common.dashboard.server.subprocess.Popen") as popen,
            patch("common.dashboard.server.socket.gethostbyname") as resolve,
            patch("common.dashboard.server.log.info") as info_log,
        ):
            async with _make_async_client(app) as client:
                response = await client.post(
                    "/api/v1/scans/launch",
                    json={
                        "job_id": "redacted-scanbuilder-denial",
                        "target": submitted,
                        "modules": ["sqli"],
                    },
                )

        rendered_logs = str(info_log.call_args_list)
        assert response.status_code in {400, 403}
        assert password not in rendered_logs
        assert token not in rendered_logs
        popen.assert_not_called()
        resolve.assert_not_called()


def test_plugin_discovery_returns_multiple_frameworks() -> None:
    from common.dashboard.server import DashboardServer

    plugins = DashboardServer(auth=False)._discover_plugins()
    frameworks = {plugin["framework"] for plugin in plugins}

    assert "webforge" in frameworks
    assert "netforge" in frameworks
    assert any(plugin["name"] == "sqli_scanner" for plugin in plugins)


def test_dashboard_subprocess_output_is_redacted_before_disk_tail_and_event(
    tmp_path: Path,
) -> None:
    import io

    from common.dashboard.server import DashboardServer

    canaries = [
        "CANARY_PASSWORD_DASH_LOG_002",
        "Bearer CANARY_BEARER_DASH_LOG_002",
        "Cookie: session=CANARY_COOKIE_DASH_LOG_002",
        "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef",
        "AKIAIOSFODNN7EXAMPLE",
        "MIIE-private-key-body-not-a-generic-secret-pattern",
    ]
    output = "\n".join(
        [
            f"password={canaries[0]}",
            canaries[1],
            canaries[2],
            canaries[3],
            canaries[4],
            "-----BEGIN PRIVATE KEY-----",
            canaries[5],
            "-----END PRIVATE KEY-----",
        ]
    ) + "\n"

    class FakeProcess:
        stdout = io.StringIO(output)
        pid = 4242

        @staticmethod
        def wait() -> int:
            return 0

        @staticmethod
        def poll() -> int:
            return 0

    server = DashboardServer(auth=False)
    server._scan_logs_dir = tmp_path
    info = {
        "proc": FakeProcess(),
        "type": "web",
        "target": (
            "https://operator:CANARY_EVENT_PASSWORD_002@127.0.0.1/"
            "?token=CANARY_EVENT_TOKEN_002"
        ),
        "status": "running",
    }
    with (
        patch.object(server.event_bus, "emit_simple") as emit,
        patch.object(server, "_update_scan_history_status"),
        patch.object(server, "_sync_scan_job_from_active"),
        patch.object(server, "_load_scan_job", return_value=None),
    ):
        server._track_scan_process("scan-redact_web", info)
        deadline = time.time() + 2
        log_path = tmp_path / "scan-redact_web.log"
        while time.time() < deadline and "returncode" not in info:
            time.sleep(0.01)

        persisted = log_path.read_text(encoding="utf-8")
        tail = server._tail_text(log_path)
        log_payload = json.dumps(server._logs_for_scan("scan-redact"))
        event_payload = str(emit.call_args_list)

    rendered = persisted + tail + log_payload + event_payload
    for canary in [
        *canaries,
        "CANARY_EVENT_PASSWORD_002",
        "CANARY_EVENT_TOKEN_002",
    ]:
        assert canary not in rendered
    assert "<redacted>" in persisted


def test_dashboard_nonzero_engine_exit_remains_failed_and_interrupted(
    tmp_path: Path,
) -> None:
    import io

    from common.dashboard.event_bus import EventType
    from common.dashboard.server import DashboardServer

    class FakeProcess:
        stdout = io.StringIO("")
        pid = 4243

        @staticmethod
        def wait() -> int:
            return 1

        @staticmethod
        def poll() -> int:
            return 1

    server = DashboardServer(auth=False)
    server._scan_logs_dir = tmp_path
    info = {
        "proc": FakeProcess(),
        "type": "web",
        "target": LAB_URL,
        "status": "running",
    }
    with (
        patch.object(server.event_bus, "emit_simple") as emit,
        patch.object(server, "_update_scan_history_status") as update_history,
        patch.object(server, "_sync_scan_job_from_active") as sync_job,
        patch.object(server, "_load_scan_job", return_value=None),
    ):
        server._track_scan_process("scan-failed_web", info)
        deadline = time.time() + 2
        while time.time() < deadline and not (
            "returncode" in info
            and update_history.call_count == 1
            and sync_job.call_count == 1
        ):
            time.sleep(0.01)

    assert info["returncode"] == 1
    assert info["status"] == "failed"
    assert emit.call_args.args[0] is EventType.SCAN_INTERRUPTED
    update_history.assert_called_once_with("scan-failed", "failed")
    sync_job.assert_called_once_with("scan-failed", fallback="failed")


def test_dashboard_supervisor_metadata_redacts_proxy_credentials() -> None:
    from common.dashboard.server import DashboardServer

    canary = "CANARY_PROXY_METADATA_PASSWORD"
    proxy_url = f"http://operator:{canary}@127.0.0.1:18080"

    class FakeProcess:
        pid = 4244

        @staticmethod
        def poll() -> None:
            return None

    server = DashboardServer(auth=False)
    server._active_scans["scan-proxy_web"] = {
        "proc": FakeProcess(),
        "type": "web",
        "target": LAB_URL,
        "status": "running",
        "command": server._sanitize_cmd(
            [
                "python",
                "webforge.py",
                "--proxy",
                proxy_url,
                f"--https-proxy={proxy_url}",
            ]
        ),
        "child_env_keys": ["FORGE_ROUTE_PROXY_CREDENTIAL_REFERENCE"],
    }

    rendered = json.dumps(server._supervisor_snapshot())

    assert canary not in rendered
    assert proxy_url not in rendered
    assert rendered.count("<redacted>") == 2
    assert "FORGE_ROUTE_PROXY_CREDENTIAL_REFERENCE" not in rendered
