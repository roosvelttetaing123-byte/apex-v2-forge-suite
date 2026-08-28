from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Callable, Coroutine
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, ParamSpec, TypeVar
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import httpx
import pytest

from common.action_authorization import (
    AuthorizationContext,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    compute_envelope_digest,
    issue_authorization,
)
from common.confirm_gate import ActionConfirmation
from common.dashboard.auth import Role, TokenPayload, issue_identity_token, validate_token
from common.dashboard.event_bus import (
    REMOTE_EVENT_SCHEMA_VERSION,
    Event,
    EventAdmissionError,
    EventCredentialRegistry,
    EventType,
    RemoteEventBus,
)
from common.dashboard.state_store import CredentialEntry, FindingEntry
from common.db import create_db, get_authorization_decision


TARGET = "http://127.0.0.1:8080/fixture"
NOW = datetime(2026, 7, 27, 2, 45, tzinfo=timezone.utc)
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_P = ParamSpec("_P")
_R = TypeVar("_R")


def _async_test(
    function: Callable[_P, Coroutine[Any, Any, _R]],
) -> Callable[_P, _R]:
    """Run an async test without requiring a pytest event-loop plugin."""

    @wraps(function)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        return asyncio.run(function(*args, **kwargs))

    return wrapper


def _client(app: Any, *, role: Role | None = None) -> httpx.AsyncClient:
    headers: dict[str, str] = {}
    if role is not None:
        token = issue_identity_token(f"task004-{role.value}", role)
        headers["Authorization"] = f"Bearer {token}"
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
        headers=headers,
    )


async def _raw_asgi_http_request(
    app: Any,
    *,
    method: str,
    path: str,
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"",
) -> tuple[int, bytes, int]:
    """Issue one inert ASGI request with exact caller-controlled headers."""
    sent: list[dict[str, Any]] = []
    received = False
    receive_calls = 0

    async def receive() -> dict[str, Any]:
        nonlocal receive_calls, received
        receive_calls += 1
        if not received:
            received = True
            return {
                "type": "http.request",
                "body": body,
                "more_body": False,
            }
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": headers or [],
            "client": ("127.0.0.1", 45000),
            "server": ("testserver", 80),
            "root_path": "",
        },
        receive,
        send,
    )
    status = next(
        int(message["status"])
        for message in sent
        if message["type"] == "http.response.start"
    )
    rendered = b"".join(
        bytes(message.get("body", b""))
        for message in sent
        if message["type"] == "http.response.body"
    )
    return status, rendered, receive_calls


def _authorization(tmp_path: Path, *, now: datetime = NOW):
    session = create_db(tmp_path / "event-authorization.db")
    context = AuthorizationContext(
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        run_id="run-a",
        job_id="job-a",
        operator_id="operator-a",
        operator_role=OperatorRole.OPERATOR,
        action_kind="scan",
        engine="webforge",
        module_id="header_audit",
        requested_target=TARGET,
        resolved_target=TARGET,
        allowed_scope=("127.0.0.1/32",),
        excluded_scope=(),
        safety_mode=SafetyMode.ACTIVE,
        confirmation_method=ConfirmationMethod.DASHBOARD,
        confirmed_by="operator-a",
    )
    confirmation = ActionConfirmation.create(
        job_id="job-a",
        target=TARGET,
        engine="webforge",
        action="scan",
        issued_at=now,
    )
    try:
        decision = issue_authorization(
            session=session,
            context=context,
            confirmation=confirmation,
            now=now,
            ttl_seconds=300,
        )
        assert decision.allowed
        return decision.envelope
    finally:
        session.close()


def _issued_registry(tmp_path: Path):
    clock = [NOW]
    job_status = ["running"]
    authorization = _authorization(tmp_path)
    session = create_db(tmp_path / "event-authorization.db")
    try:
        row = get_authorization_decision(session, authorization.decision_id)
        assert row is not None
        persisted_authorization = json.loads(str(row.envelope_json))
    finally:
        session.close()

    def resolve_authorization(decision_id: str):
        if decision_id != authorization.decision_id:
            return None
        return persisted_authorization

    registry = EventCredentialRegistry(
        clock=lambda: clock[0],
        authorization_resolver=resolve_authorization,
        job_state_resolver=lambda _binding: job_status[0],
    )
    issued = registry.issue(
        authorization=authorization,
        module_id="header_audit",
        target=TARGET,
        sender_id="worker-a",
        allowed_event_types=[
            EventType.MODULE_START,
            EventType.MODULE_PROGRESS,
            EventType.MODULE_FAIL,
            EventType.MODULE_SKIP,
        ],
        ttl_seconds=120,
        max_events=8,
    )
    return registry, issued, clock, job_status


def _submission(
    *,
    event_type: EventType = EventType.MODULE_START,
    sequence: int = 1,
    nonce: str = "nonce_task004_0001",
    data: dict[str, Any] | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    if data is None:
        if event_type is EventType.MODULE_START:
            data = {"name": "header_audit", "phase": 1}
        elif event_type is EventType.MODULE_PROGRESS:
            data = {"name": "header_audit", "progress": 50}
        else:
            data = {"name": "header_audit", "reason_code": "fixture_failure"}
    result: dict[str, Any] = {
        "schema_version": REMOTE_EVENT_SCHEMA_VERSION,
        "tenant_id": "tenant-a",
        "engagement_id": "engagement-a",
        "run_id": "run-a",
        "job_id": "job-a",
        "engine": "webforge",
        "module_id": "header_audit",
        "target": TARGET,
        "event_type": event_type.value,
        "sequence": sequence,
        "nonce": nonce,
        "sender_id": "worker-a",
        "data": data,
    }
    result.update(overrides)
    return result


def _concrete_path(path: str) -> str:
    values = {
        "{scan_id}": "scan-fixture",
        "{template_id}": "template-fixture",
        "{finding_id}": "finding-fixture",
        "{agent_id}": "agent-fixture",
        "{job_id}": "job-fixture",
        "{name}": "whoami",
    }
    for marker, value in values.items():
        path = path.replace(marker, value)
    return path


def test_event_credential_admits_one_canonical_bound_event(tmp_path: Path) -> None:
    registry, issued, _clock, _job_status = _issued_registry(tmp_path)

    admitted = registry.admit(issued.token, _submission())

    assert admitted.sequence == 1
    assert admitted.event.event_type is EventType.MODULE_START
    assert admitted.event.source == "header_audit"
    assert admitted.event.run_id == "run-a"
    assert admitted.event.data["tenant_id"] == "tenant-a"
    assert admitted.event.data["engagement_id"] == "engagement-a"
    assert admitted.event.data["job_id"] == "job-a"
    assert admitted.event.data["engine"] == "webforge"
    assert admitted.event.data["module_id"] == "header_audit"
    assert admitted.event.data["sender_id"] == "worker-a"
    assert admitted.event.data["sequence"] == 1
    assert "target" not in admitted.event.data
    assert "nonce_task004_0001" not in json.dumps(admitted.event.data)
    assert issued.token not in repr(issued)


def test_event_credential_requires_the_exact_persisted_authorization(
    tmp_path: Path,
) -> None:
    authorization = _authorization(tmp_path)
    registry = EventCredentialRegistry(
        clock=lambda: NOW,
        authorization_resolver=lambda decision_id: (
            authorization if decision_id == authorization.decision_id else None
        ),
    )
    forged = authorization.to_dict()
    forged["tenant_id"] = "tenant-b"
    forged["binding_digest"] = compute_envelope_digest(forged)

    with pytest.raises(EventAdmissionError) as denial:
        registry.issue(
            authorization=forged,
            module_id="header_audit",
            target=TARGET,
            sender_id="worker-a",
            allowed_event_types=[EventType.MODULE_START],
        )
    assert denial.value.reason_code == "unrecorded_event_authorization"

    without_resolver = EventCredentialRegistry(clock=lambda: NOW)
    with pytest.raises(EventAdmissionError) as missing_resolver:
        without_resolver.issue(
            authorization=authorization,
            module_id="header_audit",
            target=TARGET,
            sender_id="worker-a",
            allowed_event_types=[EventType.MODULE_START],
        )
    assert missing_resolver.value.reason_code == "unrecorded_event_authorization"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("tenant_id", "tenant-b", "event_tenant_mismatch"),
        ("engagement_id", "engagement-b", "event_engagement_mismatch"),
        ("run_id", "run-b", "event_run_mismatch"),
        ("job_id", "job-b", "event_job_mismatch"),
        ("engine", "netforge", "event_engine_mismatch"),
        ("module_id", "other_module", "event_module_mismatch"),
        ("target", "http://127.0.0.2:8080/fixture", "event_target_mismatch"),
        ("sender_id", "worker-b", "event_sender_mismatch"),
    ],
)
def test_event_binding_mismatches_reject_without_consuming_sequence(
    tmp_path: Path,
    field: str,
    value: str,
    reason: str,
) -> None:
    registry, issued, _clock, _job_status = _issued_registry(tmp_path)
    with pytest.raises(EventAdmissionError) as denied:
        registry.admit(issued.token, _submission(**{field: value}))
    assert denied.value.reason_code == reason

    # A rejected mutation did not consume the valid next sequence.
    assert registry.admit(issued.token, _submission()).sequence == 1


def test_forged_expired_replayed_and_out_of_order_events_fail_closed(tmp_path: Path) -> None:
    registry, issued, clock, _job_status = _issued_registry(tmp_path)
    forged = issued.token[:-1] + ("A" if issued.token[-1] != "A" else "B")
    with pytest.raises(EventAdmissionError) as forged_denial:
        registry.admit(forged, _submission())
    assert forged_denial.value.reason_code == "forged_event_credential"

    first = _submission()
    assert registry.admit(issued.token, first).sequence == 1
    with pytest.raises(EventAdmissionError) as replay:
        registry.admit(issued.token, first)
    assert replay.value.reason_code == "event_replayed"

    with pytest.raises(EventAdmissionError) as out_of_order:
        registry.admit(
            issued.token,
            _submission(sequence=3, nonce="nonce_task004_0003"),
        )
    assert out_of_order.value.reason_code == "event_out_of_order"

    clock[0] = NOW + timedelta(seconds=121)
    with pytest.raises(EventAdmissionError) as expired:
        registry.admit(
            issued.token,
            _submission(sequence=2, nonce="nonce_task004_0002"),
        )
    assert expired.value.reason_code == "expired_event_credential"

    exact_registry, exact_issued, exact_clock, _job_status = _issued_registry(
        tmp_path / "exact-expiry",
    )
    exact_clock[0] = NOW + timedelta(seconds=120)
    with pytest.raises(EventAdmissionError) as exact_expiry:
        exact_registry.admit(exact_issued.token, _submission())
    assert exact_expiry.value.reason_code == "expired_event_credential"


def test_credential_rotation_cannot_reset_or_duplicate_one_event_stream(
    tmp_path: Path,
) -> None:
    registry, first, _clock, _job_status = _issued_registry(tmp_path)
    session = create_db(tmp_path / "event-authorization.db")
    try:
        row = get_authorization_decision(
            session,
            first.binding.authorization_decision_id,
        )
        assert row is not None
        authorization = json.loads(str(row.envelope_json))
    finally:
        session.close()

    def rotate():
        return registry.issue(
            authorization=authorization,
            module_id="header_audit",
            target=TARGET,
            sender_id="worker-a",
            allowed_event_types=[EventType.MODULE_START, EventType.MODULE_PROGRESS],
            ttl_seconds=120,
            max_events=8,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        rotations = list(pool.map(lambda _index: rotate(), range(2)))

    # Concurrent rotations are linearized: exactly one token remains active and
    # exactly one copy of the first logical delivery can be admitted.
    active = None
    denials: list[str] = []
    for candidate in [first, *rotations]:
        try:
            assert registry.admit(candidate.token, _submission()).sequence == 1
            active = candidate
        except EventAdmissionError as exc:
            denials.append(exc.reason_code)
    assert active is not None
    assert denials == ["forged_event_credential", "forged_event_credential"]

    replacement = registry.issue(
        authorization=authorization,
        module_id="header_audit",
        target=TARGET,
        sender_id="worker-a",
        allowed_event_types=[EventType.MODULE_START, EventType.MODULE_PROGRESS],
        ttl_seconds=120,
        max_events=8,
    )

    # Rotation retains the stream ledger: neither the old token nor the new
    # token can replay sequence/nonce 1, and the next exact delivery is 2.
    with pytest.raises(EventAdmissionError) as old_token:
        registry.admit(
            active.token,
            _submission(sequence=2, nonce="nonce_task004_0002"),
        )
    assert old_token.value.reason_code == "forged_event_credential"
    with pytest.raises(EventAdmissionError) as reset_replay:
        registry.admit(replacement.token, _submission())
    assert reset_replay.value.reason_code == "event_replayed"
    admitted = registry.admit(
        replacement.token,
        _submission(
            event_type=EventType.MODULE_PROGRESS,
            sequence=2,
            nonce="nonce_task004_0002",
        ),
    )
    assert admitted.sequence == 2


def test_dashboard_identity_token_expires_at_the_exact_boundary() -> None:
    payload = TokenPayload(
        username="viewer",
        role=Role.VIEWER,
        issued_at=99.0,
        expires_at=100.0,
        session_id="fixture",
        tenant_id="default",
    )
    with patch("common.dashboard.auth.time.time", return_value=100.0):
        assert payload.is_expired() is True


def test_dashboard_identity_empty_environment_tenant_matches_server_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORGE_TENANT_ID", "   ")
    token = issue_identity_token("viewer", Role.VIEWER)
    payload = validate_token(token)
    assert payload is not None
    assert payload.tenant_id == "default"


def test_event_credential_revokes_when_bound_job_becomes_terminal(
    tmp_path: Path,
) -> None:
    registry, issued, _clock, job_status = _issued_registry(tmp_path)
    assert registry.admit(issued.token, _submission()).sequence == 1
    job_status[0] = "completed"

    with pytest.raises(EventAdmissionError) as terminal:
        registry.admit(
            issued.token,
            _submission(sequence=2, nonce="nonce_task004_0002"),
        )
    assert terminal.value.reason_code == "event_job_not_active"

    job_status[0] = "running"
    with pytest.raises(EventAdmissionError) as revoked:
        registry.admit(
            issued.token,
            _submission(sequence=2, nonce="nonce_task004_0002"),
        )
    assert revoked.value.reason_code == "forged_event_credential"


@pytest.mark.parametrize(
    "payload",
    [
        _submission(event_type=EventType.SCAN_COMPLETE),
        _submission(data={"name": "header_audit", "phase": 1, "severity": "Critical"}),
        _submission(data={"name": "header_audit", "phase": 1, "verified": True}),
        _submission(data={"name": "header_audit", "phase": 1, "completed": True}),
        _submission(data={"name": "header_audit", "phase": 1, "tenant_id": "tenant-b"}),
    ],
)
def test_terminal_and_server_owned_payload_overrides_are_rejected(
    tmp_path: Path,
    payload: dict[str, Any],
) -> None:
    registry, issued, _clock, _job_status = _issued_registry(tmp_path)
    with pytest.raises(EventAdmissionError) as denied:
        registry.admit(issued.token, payload)
    assert denied.value.reason_code in {
        "event_type_not_authorized",
        "event_payload_forbidden",
    }


@_async_test
async def test_http_event_ingress_is_disabled_before_body_bus_or_state_mutation(
    tmp_path: Path,
) -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=False)
    app = server.create_app()
    canary = "CANARY_EVENT_TOKEN_TASK004"
    before = server.state_store.snapshot()
    audit: list[dict[str, Any]] = []

    def record_audit(**kwargs: Any) -> bool:
        audit.append(kwargs)
        return True

    with (
        patch.object(server, "_write_audit_log", side_effect=record_audit),
        patch.object(server.event_bus, "emit") as emit,
    ):
        async with _client(app) as client:
            response = await client.post(
                "/api/v1/events/emit",
                content=f'not-json-{canary}',
                headers={"X-Forge-Event-Credential": canary},
            )

    assert response.status_code == 503
    assert response.json() == {
        "status": "disabled",
        "reason_code": "remote_event_transport_disabled",
    }
    assert canary not in response.text
    assert canary not in json.dumps(audit)
    assert audit[0]["detail"]["reason_code"] == "remote_event_transport_disabled"
    assert server.state_store.snapshot() == before
    emit.assert_not_called()


@_async_test
async def test_runtime_endpoint_matrix_has_no_unclassified_state_mutation() -> None:
    from common.dashboard.server import (
        DASHBOARD_API_ROUTE_POLICY,
        DashboardServer,
        classify_dashboard_api_route,
    )

    server = DashboardServer(auth=False)
    app = server.create_app()
    matrix: list[tuple[str, str, str]] = []
    for route in app.routes:
        path = getattr(route, "path", "")
        for method in sorted(getattr(route, "methods", set()) or set()):
            if path.startswith("/api/v1/"):
                matrix.append((method, path, classify_dashboard_api_route(method, path)))

    state_rows = [row for row in matrix if row[0] in STATE_CHANGING_METHODS]
    assert state_rows
    assert {(method, path) for method, path, _ in matrix} == set(DASHBOARD_API_ROUTE_POLICY)
    assert all(row[2] in {"dashboard_identity", "service_credential", "public_bootstrap"} for row in state_rows)
    assert {
        (method, path)
        for method, path, auth_class in state_rows
        if auth_class == "public_bootstrap"
    } == {
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/sso/exchange"),
    }

    # Every ordinary mutation is denied centrally before endpoint body parsing.
    with patch.object(server, "_write_audit_log", return_value=True):
        async with _client(app) as client:
            for method, path, auth_class in state_rows:
                if auth_class != "dashboard_identity":
                    continue
                response = await client.request(
                    method,
                    _concrete_path(path),
                    json={"canary": "MUST_NOT_REACH_ENDPOINT"},
                )
                assert response.status_code == 401, (method, path, response.text)
                assert response.json()["detail"]["reason_code"] == "dashboard_auth_required"


@_async_test
async def test_legacy_no_auth_mode_cannot_read_tenant_state_or_launch() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=False)
    app = server.create_app()
    with (
        patch.object(server, "_write_audit_log", return_value=True),
        patch("common.dashboard.server.subprocess.Popen") as popen,
    ):
        async with _client(app) as client:
            state = await client.get("/api/v1/state")
            launch = await client.post("/api/v1/scans/launch", json={})
    assert state.status_code == 401
    assert launch.status_code == 401
    assert server.auth_enabled is True
    assert server.auth_disable_requested is True
    popen.assert_not_called()


@_async_test
async def test_dashboard_query_tokens_are_not_authentication() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    token = issue_identity_token("query-viewer", Role.VIEWER)
    async with _client(app) as client:
        response = await client.get("/api/v1/state", params={"token": token})
    assert response.status_code == 401
    assert token not in response.text


@_async_test
async def test_public_health_is_sanitized_side_effect_free_and_rate_limited() -> None:
    from common.dashboard.server import DashboardServer
    from common.version import VERSION

    server = DashboardServer(auth=True)
    app = server.create_app()
    process = MagicMock()
    server._active_scans["hidden"] = {"proc": process}
    with patch.object(server, "_tool_inventory") as inventory:
        async with _client(app) as client:
            responses = [await client.get("/api/v1/health") for _ in range(31)]
    assert all(response.status_code == 200 for response in responses[:30])
    assert responses[30].status_code == 429
    body = responses[0].json()
    assert set(body) == {"status", "auth_required", "version", "timestamp"}
    assert body["auth_required"] is True
    assert body["version"] == VERSION
    inventory.assert_not_called()
    process.poll.assert_not_called()


@_async_test
async def test_public_bootstrap_allowlist_reaches_no_dashboard_or_host_mutation() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    before = server.state_store.snapshot()
    canary = "CANARY_BOOTSTRAP_SECRET_TASK004"
    audits: list[dict[str, Any]] = []
    with (
        patch.object(
            server,
            "_write_audit_log",
            side_effect=lambda **item: audits.append(item) or True,
        ),
        patch.object(server.event_bus, "emit") as emit,
        patch.object(server.event_bus, "emit_simple") as emit_simple,
        patch.object(server, "_tool_inventory") as inventory,
        patch.object(server, "_discover_plugins") as discover,
        patch("common.dashboard.server.subprocess.Popen") as popen,
        patch("common.dashboard.server.socket.gethostbyname") as resolve,
    ):
        async with _client(app) as client:
            responses = [
                await client.post(
                    "/api/v1/auth/login",
                    json={"username": f"Bearer {canary}", "password": canary},
                ),
                await client.get("/api/v1/auth/sso/config"),
                await client.get(
                    "/api/v1/auth/sso/start",
                    params={"next": f"/{canary}"},
                ),
                await client.get(
                    "/api/v1/auth/sso/callback",
                    params={"code": canary, "state": canary},
                ),
                await client.post(
                    "/api/v1/auth/sso/exchange",
                    content=canary,
                ),
                await client.get("/api/v1/health"),
            ]

    assert [response.status_code for response in responses] == [401, 200, 503, 503, 503, 200]
    rendered = "".join(response.text for response in responses) + json.dumps(audits)
    assert canary not in rendered
    assert server.state_store.snapshot() == before
    emit.assert_not_called()
    emit_simple.assert_not_called()
    inventory.assert_not_called()
    discover.assert_not_called()
    popen.assert_not_called()
    resolve.assert_not_called()


@_async_test
async def test_public_static_mount_roots_are_classified_and_rate_limited() -> None:
    from common.dashboard.server import DashboardServer, classify_public_ui_route

    assert classify_public_ui_route("/assets") == "public_static_asset"
    assert classify_public_ui_route("/assets/") == "public_static_asset"
    assert classify_public_ui_route("/static") == "public_static_asset"
    assert classify_public_ui_route("/src") == "public_static_asset"
    assert classify_public_ui_route("/login/") == "public_spa_shell"
    assert classify_public_ui_route("/scans/fixture/") == "public_spa_shell"

    server = DashboardServer(auth=True)
    app = server.create_app()
    runtime_public = {
        getattr(route, "path", "")
        for route in app.routes
        if getattr(route, "path", "")
        and not getattr(route, "path", "").startswith("/api/v1/")
        and getattr(route, "path", "") != "/ws/dashboard"
    }
    assert runtime_public
    assert all(classify_public_ui_route(path) is not None for path in runtime_public)
    async with _client(app) as client:
        responses = [await client.get("/assets", follow_redirects=False) for _ in range(301)]
        aliases = [await client.get("/login/", follow_redirects=False) for _ in range(31)]
    assert all(response.status_code != 429 for response in responses[:300])
    assert responses[300].status_code == 429
    assert all(response.status_code != 429 for response in aliases[:30])
    assert aliases[30].status_code == 429


@_async_test
async def test_http_host_boundary_precedes_routes_bodies_state_and_host_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from common.dashboard.server import DashboardServer, Request

    monkeypatch.delenv("FORGE_DASHBOARD_PUBLIC_HOST", raising=False)
    monkeypatch.delenv("FORGE_DASHBOARD_ALLOWED_HOSTS", raising=False)
    server = DashboardServer(auth=True)
    app = server.create_app()
    before = server.state_store.snapshot()
    endpoint_guards: dict[str, AsyncMock] = {}
    for route in app.routes:
        path = getattr(route, "path", "")
        if path not in {"/", "/api/v1/auth/login", "/api/v1/state"}:
            continue
        guard = AsyncMock(side_effect=AssertionError(f"endpoint reached: {path}"))
        route.dependant.call = guard
        endpoint_guards[path] = guard
    assert set(endpoint_guards) == {
        "/",
        "/api/v1/auth/login",
        "/api/v1/state",
    }

    canary = b"CANARY_FOREIGN_HOST_BODY_TASK004"
    token = issue_identity_token("host-boundary-viewer", Role.VIEWER)
    authorization = (b"authorization", f"Bearer {token}".encode("ascii"))
    foreign_host = (b"host", b"foreign.invalid")
    requests = [
        ("GET", "/", [foreign_host], b""),
        ("GET", "/", [], b""),
        (
            "POST",
            "/api/v1/auth/login",
            [foreign_host, (b"content-type", b"application/json")],
            canary,
        ),
        (
            "POST",
            "/api/v1/auth/login",
            [(b"content-type", b"application/json")],
            canary,
        ),
        ("GET", "/api/v1/state", [foreign_host, authorization], b""),
        ("GET", "/api/v1/state", [authorization], b""),
        (
            "GET",
            "/api/v1/state",
            [(b"host", b"testserver"), foreign_host, authorization],
            b"",
        ),
        (
            "GET",
            "/api/v1/state",
            [(b"host", b"user@testserver"), authorization],
            b"",
        ),
        (
            "GET",
            "/api/v1/state",
            [(b"host", b"testserver:not-a-port"), authorization],
            b"",
        ),
    ]

    with ExitStack() as stack:
        guards: dict[str, MagicMock] = {
            "request_json": stack.enter_context(
                patch.object(Request, "json")
            ),
            "request_body": stack.enter_context(
                patch.object(Request, "body")
            ),
            "route_classification": stack.enter_context(
                patch("common.dashboard.server.classify_public_ui_route")
            ),
            "api_classification": stack.enter_context(
                patch("common.dashboard.server.classify_dashboard_api_route")
            ),
            "api_policy": stack.enter_context(
                patch("common.dashboard.server.dashboard_api_route_policy")
            ),
            "token_validation": stack.enter_context(
                patch("common.dashboard.server.validate_token")
            ),
            "rate_limit": stack.enter_context(
                patch.object(server, "_consume_public_rate_limit")
            ),
            "public_snapshot": stack.enter_context(
                patch.object(server, "_public_state_snapshot")
            ),
            "state_snapshot": stack.enter_context(
                patch.object(server.state_store, "snapshot")
            ),
            "audit": stack.enter_context(
                patch.object(server, "_write_audit_log")
            ),
            "event_emit": stack.enter_context(
                patch.object(server.event_bus, "emit")
            ),
            "event_emit_simple": stack.enter_context(
                patch.object(server.event_bus, "emit_simple")
            ),
            "popen": stack.enter_context(
                patch("common.dashboard.server.subprocess.Popen")
            ),
            "process_run": stack.enter_context(
                patch("common.dashboard.server.subprocess.run")
            ),
            "resolve": stack.enter_context(
                patch("common.dashboard.server.socket.getaddrinfo")
            ),
            "connect": stack.enter_context(
                patch("common.dashboard.server.socket.create_connection")
            ),
            "sqlite_connect": stack.enter_context(
                patch("common.dashboard.server.sqlite3.connect")
            ),
            "path_exists": stack.enter_context(patch.object(Path, "exists")),
            "path_open": stack.enter_context(patch.object(Path, "open")),
            "path_read_text": stack.enter_context(patch.object(Path, "read_text")),
            "path_read_bytes": stack.enter_context(patch.object(Path, "read_bytes")),
            "path_write_text": stack.enter_context(patch.object(Path, "write_text")),
            "path_write_bytes": stack.enter_context(patch.object(Path, "write_bytes")),
            "path_mkdir": stack.enter_context(patch.object(Path, "mkdir")),
        }
        responses = [
            await _raw_asgi_http_request(
                app,
                method=method,
                path=path,
                headers=headers,
                body=body,
            )
            for method, path, headers, body in requests
        ]

    assert [status for status, _body, _calls in responses] == [403] * len(requests)
    assert all(
        json.loads(body) == {
            "detail": {"reason_code": "dashboard_host_forbidden"}
        }
        for _status, body, _calls in responses
    )
    assert all(calls == 0 for _status, _body, calls in responses)
    assert canary not in b"".join(body for _status, body, _calls in responses)
    assert all(guard.call_count == 0 for guard in endpoint_guards.values())
    for name, guard in guards.items():
        assert guard.call_count == 0, f"foreign Host reached {name}"
    assert server.state_store.snapshot() == before
    assert server._public_rate_events == {}


@_async_test
async def test_http_host_boundary_accepts_normalized_public_and_explicit_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from common.dashboard.server import DashboardServer

    monkeypatch.setenv(
        "FORGE_DASHBOARD_PUBLIC_HOST",
        "  Dashboard.Example.Test.  ",
    )
    monkeypatch.setenv(
        "FORGE_DASHBOARD_ALLOWED_HOSTS",
        "  Alias.Example.Test.  ",
    )
    server = DashboardServer(host="0.0.0.0", auth=True)
    app = server.create_app()
    token = issue_identity_token("public-host-viewer", Role.VIEWER)

    with patch.object(server, "_write_audit_log", return_value=True):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            spa = await client.get(
                "/",
                headers={"Host": "DASHBOARD.EXAMPLE.TEST.:8443"},
            )
            login = await client.post(
                "/api/v1/auth/login",
                headers={"Host": "dashboard.example.test.:8443"},
                json={},
            )
            state = await client.get(
                "/api/v1/state",
                headers={
                    "Host": "dashboard.example.test.:8443",
                    "Authorization": f"Bearer {token}",
                },
            )
            alias_state = await client.get(
                "/api/v1/state",
                headers={
                    "Host": "ALIAS.EXAMPLE.TEST.:8443",
                    "Authorization": f"Bearer {token}",
                },
            )

    assert spa.status_code == 200
    assert login.status_code == 401
    assert login.json() == {"detail": "Invalid credentials"}
    assert state.status_code == 200
    assert alias_state.status_code == 200


@_async_test
async def test_agent_registration_is_inert_without_configured_header_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from common.dashboard.server import DashboardServer

    monkeypatch.delenv("FORGE_AGENT_REGISTRATION_TOKEN", raising=False)
    server = DashboardServer(auth=True)
    agents_path = tmp_path / "agents.json"
    app = server.create_app()
    canary = "CANARY_AGENT_BODY_TOKEN_TASK004"
    with patch.object(
        DashboardServer,
        "_agents_path",
        new_callable=PropertyMock,
        return_value=agents_path,
    ):
        async with _client(app) as client:
            missing_config = await client.post(
                "/api/v1/agents/register",
                json={"agent_id": "agent-a", "registration_token": canary},
            )
    assert missing_config.status_code == 503
    assert missing_config.json()["detail"]["reason_code"] == "agent_auth_not_configured"
    assert canary not in missing_config.text
    assert not agents_path.exists()


@_async_test
async def test_service_denials_are_pre_body_and_rate_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from common.dashboard.server import DashboardServer, Request

    monkeypatch.delenv("FORGE_AGENT_REGISTRATION_TOKEN", raising=False)
    server = DashboardServer(auth=True)
    app = server.create_app()
    audits: list[dict[str, Any]] = []

    with (
        patch.object(Request, "json", side_effect=AssertionError("body parser reached")),
        patch.object(Request, "body", side_effect=AssertionError("body reader reached")),
        patch.object(server, "_write_audit_log", side_effect=lambda **item: audits.append(item) or True),
    ):
        async with _client(app) as client:
            event_responses = [
                await client.post(
                    "/api/v1/events/emit",
                    content="CANARY_EVENT_BODY_TASK004",
                )
                for _ in range(31)
            ]
            agent_responses = [
                await client.post(
                    "/api/v1/agents/register",
                    content="CANARY_AGENT_BODY_TASK004",
                )
                for _ in range(31)
            ]

    assert [item.status_code for item in event_responses[:30]] == [503] * 30
    assert event_responses[30].status_code == 429
    assert [item.status_code for item in agent_responses[:30]] == [503] * 30
    assert agent_responses[30].status_code == 429
    rendered = json.dumps(audits)
    assert "CANARY_EVENT_BODY_TASK004" not in rendered
    assert "CANARY_AGENT_BODY_TASK004" not in rendered
    assert sum(item["action"] == "event.admission" for item in audits) == 30
    assert sum(item["action"] == "agent.api.denied" for item in audits) == 30


@_async_test
async def test_viewer_cannot_reach_dashboard_host_side_effect_factories() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    routes = [
        ("POST", "/api/v1/credentials/analyze"),
        ("POST", "/api/v1/agents/jobs"),
        ("POST", "/api/v1/auth/test"),
        ("POST", "/api/v1/control/pause"),
        ("POST", "/api/v1/control/resume"),
        ("POST", "/api/v1/control/abort"),
        ("POST", "/api/v1/control/kill-switch"),
        ("POST", "/api/v1/control/skip-module"),
        ("POST", "/api/v1/scans/start"),
        ("POST", "/api/v1/scans/stop"),
        ("POST", "/api/v1/scans/fingerprints/plan"),
        ("POST", "/api/v1/scans/fingerprints/record"),
        ("POST", "/api/v1/scans/rate-adapt"),
        ("DELETE", "/api/v1/scans/scan-a"),
        ("POST", "/api/v1/scan/templates"),
        ("DELETE", "/api/v1/scan/templates/template-a"),
        ("PATCH", "/api/v1/findings/finding-a/status"),
        ("POST", "/api/v1/findings/finding-a/retest"),
        ("POST", "/api/v1/scans/launch"),
        ("POST", "/api/v1/c2/bofs/whoami/execute"),
    ]
    with (
        patch.object(server, "_write_audit_log", return_value=True),
        patch.object(server, "_write_all_control_files") as control_files,
        patch.object(server, "_terminate_active_scans") as terminate,
        patch.object(server, "_init_control_file") as init_control,
        patch.object(server, "_scan_fingerprint_store") as fingerprints,
        patch.object(server, "_save_scan_template") as save_template,
        patch.object(server, "_write_scan_templates") as write_templates,
        patch("common.dashboard.server.subprocess.Popen") as popen,
    ):
        async with _client(app, role=Role.VIEWER) as client:
            for method, path in routes:
                response = await client.request(method, path, json={})
                assert response.status_code == 403, (method, path, response.text)
    control_files.assert_not_called()
    terminate.assert_not_called()
    init_control.assert_not_called()
    fingerprints.assert_not_called()
    save_template.assert_not_called()
    write_templates.assert_not_called()
    popen.assert_not_called()


@_async_test
async def test_viewer_tool_plugin_and_report_inputs_fail_before_host_access() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    with (
        patch.object(server, "_tool_inventory") as inventory,
        patch.object(server, "_discover_plugins") as discover,
        patch.object(Path, "exists", side_effect=AssertionError("filesystem probe reached")),
        patch.object(Path, "rglob", side_effect=AssertionError("filesystem traversal reached")),
    ):
        async with _client(app, role=Role.VIEWER) as client:
            tools = await client.get("/api/v1/tools")
            plugins = await client.get("/api/v1/plugins")
            traversal = await client.get(
                "/api/v1/reports",
                params={"framework": "../../", "fmt": "*"},
            )
            invalid_latest = await client.get(
                "/api/v1/reports/latest",
                params={"fmt": "*"},
            )
    assert tools.status_code == 403
    assert plugins.status_code == 403
    assert traversal.status_code == 400
    assert invalid_latest.status_code == 400
    inventory.assert_not_called()
    discover.assert_not_called()

    fixture_tools = [
        {
            "id": "web",
            "name": "WebForge",
            "path": "webforge/webforge.py",
            "ready": True,
            "dashboard_launch": True,
        }
    ]
    with patch.object(server, "_tool_inventory", return_value=fixture_tools) as inventory:
        async with _client(app, role=Role.OPERATOR) as operator:
            allowed = await operator.get("/api/v1/tools")
    assert allowed.status_code == 200
    assert allowed.json() == {"tools": fixture_tools, "ready": True}
    inventory.assert_called_once_with()


@_async_test
async def test_viewer_scan_gets_are_read_only(
    tmp_path: Path,
) -> None:
    from common.dashboard.server import DashboardServer

    history_path = tmp_path / "history.json"
    history_path.write_text(json.dumps([{
        "scan_id": "scan-read-only",
        "tenant_id": "default",
        "target": TARGET,
        "scan_type": "web",
        "mode": "blackbox",
        "engagement": "fixture",
        "frameworks": ["web"],
        "started_at": NOW.isoformat(),
        "status": "running",
    }]), encoding="utf-8")
    history_path.chmod(0o600)
    before = history_path.read_bytes()
    db_path = tmp_path / "must-not-be-created.db"
    server = DashboardServer(auth=True)
    process = MagicMock(pid=4242)
    server._scan_logs_dir = tmp_path / "logs"
    server._scan_logs_dir.mkdir()
    cross_tenant_canary = "CANARY_OTHER_TENANT_LOG_TASK004"
    (server._scan_logs_dir / "other-tenant_web.log").write_text(
        cross_tenant_canary,
        encoding="utf-8",
    )
    server._active_scans["scan-read-only_web"] = {
        "proc": process,
        "type": "web",
        "target": TARGET,
        "engagement": "fixture",
        "started_at": 1.0,
        "started_dt": NOW.isoformat(),
        "status": "running",
    }
    app = server.create_app()
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
            return_value=db_path,
        ),
        patch.object(server, "_sync_scan_job_from_active") as sync,
        patch.object(server, "_write_scan_history_records") as write_history,
        patch.object(
            server,
            "_with_scan_jobs_session",
            side_effect=AssertionError("write-capable database session reached"),
        ),
    ):
        async with _client(app, role=Role.VIEWER) as client:
            history = await client.get("/api/v1/scans/history")
            status = await client.get("/api/v1/scans/status")
            detail = await client.get("/api/v1/scans/scan-read-only")
            logs = await client.get("/api/v1/scans/scan-read-only/logs")
            unknown_logs = await client.get("/api/v1/scans/other-tenant/logs")
    assert history.status_code == 200
    assert status.status_code == 200
    assert detail.status_code == 200
    assert logs.status_code == 200
    assert unknown_logs.status_code == 404
    assert cross_tenant_canary not in unknown_logs.text
    assert history.json()["history"][0]["status"] == "orphaned"
    assert history_path.read_bytes() == before
    assert not db_path.exists()
    sync.assert_not_called()
    write_history.assert_not_called()
    process.poll.assert_not_called()
    process.wait.assert_not_called()
    process.terminate.assert_not_called()


@_async_test
async def test_dashboard_identity_is_tenant_bound_and_login_canary_is_opaque(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    canary = "Bearer CANARY_LOGIN_SECRET_TASK004"
    audits: list[dict[str, Any]] = []
    caplog.set_level("WARNING")
    with patch.object(
        server,
        "_write_audit_log",
        side_effect=lambda **item: audits.append(item) or True,
    ):
        async with _client(app) as anonymous:
            login = await anonymous.post(
                "/api/v1/auth/login",
                json={"username": canary, "password": "fixture"},
            )
        wrong_token = issue_identity_token(
            "tenant-b-viewer",
            Role.VIEWER,
            tenant_id="tenant-b",
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
            headers={"Authorization": f"Bearer {wrong_token}"},
        ) as wrong_tenant:
            state = await wrong_tenant.get("/api/v1/state")

    assert login.status_code == 401
    assert state.status_code == 403
    assert state.json()["detail"]["reason_code"] == "dashboard_tenant_forbidden"
    rendered = login.text + json.dumps(audits) + caplog.text
    assert canary not in rendered
    assert audits[0]["object_id"].startswith("identity:")


@_async_test
async def test_successful_login_fails_closed_when_audit_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from common.dashboard.server import DashboardServer

    monkeypatch.setenv("FORGE_DASHBOARD_USER", "task004-audited-user")
    monkeypatch.setenv("FORGE_DASHBOARD_PASSWORD", "fixture-password")
    server = DashboardServer(auth=True)
    app = server.create_app()
    with patch.object(server, "_write_audit_log", return_value=False):
        async with _client(app) as client:
            response = await client.post(
                "/api/v1/auth/login",
                json={
                    "username": "task004-audited-user",
                    "password": "fixture-password",
                },
            )
    assert response.status_code == 503
    assert response.json()["detail"]["reason_code"] == "mutation_audit_unavailable"
    assert "token" not in response.json()


def test_dashboard_tls_material_is_loopback_scoped_and_owner_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("cryptography")
    from common.dashboard import server as server_module

    monkeypatch.delenv("FORGE_DASHBOARD_TLS_CERT", raising=False)
    monkeypatch.delenv("FORGE_DASHBOARD_TLS_KEY", raising=False)
    with patch.object(server_module, "_DASHBOARD_DIR", tmp_path):
        loopback = server_module.DashboardServer(host="127.0.0.1")
        previous_umask = os.umask(0o077)
        try:
            material = loopback._create_ssl_context()
        finally:
            os.umask(previous_umask)
        assert material is not None
        cert_path = Path(material["certfile"])
        key_path = Path(material["keyfile"])
        assert cert_path.is_file() and not cert_path.is_symlink()
        assert key_path.is_file() and not key_path.is_symlink()
        assert key_path.stat().st_mode & 0o777 == 0o600
        assert cert_path.stat().st_mode & 0o777 == 0o644
        assert key_path.parent.stat().st_mode & 0o777 == 0o700

        exposed = server_module.DashboardServer(host="0.0.0.0")
        assert exposed._create_ssl_context() is None


def test_configured_dashboard_tls_requires_matching_key_and_host_san(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from common.dashboard.server import DashboardServer
    import ipaddress

    cert_path = tmp_path / "dashboard-cert.pem"
    key_path = tmp_path / "dashboard-key.pem"

    certificate_now = datetime.now(timezone.utc)

    def write_pair(san_ip: str, *, key: Any = None) -> Any:
        private_key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(certificate_now - timedelta(minutes=1))
            .not_valid_after(certificate_now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.IPAddress(ipaddress.ip_address(san_ip)),
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        key_path.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.chmod(0o600)
        cert_path.chmod(0o644)
        return private_key

    write_pair("192.0.2.10")
    monkeypatch.setenv("FORGE_DASHBOARD_TLS_CERT", str(cert_path))
    monkeypatch.setenv("FORGE_DASHBOARD_TLS_KEY", str(key_path))
    server = DashboardServer(host="192.0.2.10")
    assert server._create_ssl_context() == {
        "certfile": str(cert_path),
        "keyfile": str(key_path),
    }

    unrelated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path.write_bytes(unrelated_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    key_path.chmod(0o600)
    with pytest.raises(RuntimeError, match="certificate/key mismatch"):
        server._create_ssl_context()

    write_pair("192.0.2.11")
    with pytest.raises(RuntimeError, match="SAN does not cover"):
        server._create_ssl_context()


def test_finding_database_lookups_are_tenant_filtered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from common.dashboard.server import DashboardServer
    from common.db import FindingModel, create_db

    db_path = tmp_path / "tenant-findings.db"
    session = create_db(db_path)
    try:
        session.add(FindingModel(
            id="tenant-b-finding",
            tenant_id="tenant-b",
            title="Tenant B",
            severity="High",
            target=TARGET,
            module="header_audit",
            description="fixture",
            status="open",
        ))
        session.commit()
    finally:
        session.close()

    monkeypatch.setenv("FORGE_TENANT_ID", "tenant-a")
    server = DashboardServer(auth=True)
    with patch.object(
        DashboardServer,
        "_scan_jobs_db_path",
        new_callable=PropertyMock,
        return_value=db_path,
    ):
        assert server._persist_finding_status("tenant-b-finding", "Fixed") is False
        assert server._find_finding_metadata("tenant-b-finding") is None

    session = create_db(db_path)
    try:
        row = session.query(FindingModel).filter_by(id="tenant-b-finding").one()
        assert row.status == "open"
    finally:
        session.close()


@_async_test
async def test_mutation_audit_distinguishes_authorization_from_rejection() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    audits: list[dict[str, Any]] = []
    with patch.object(
        server,
        "_write_audit_log",
        side_effect=lambda **item: audits.append(item) or True,
    ):
        async with _client(app, role=Role.OPERATOR) as client:
            response = await client.post("/api/v1/scan/templates", json={})
    assert response.status_code == 400
    assert any(
        item["action"] == "api.mutation.authorization"
        and item["status"] == "authorized"
        for item in audits
    )
    assert any(
        item["action"] == "api.mutation.result"
        and item["status"] == "rejected"
        and item["detail"]["http_status"] == 400
        for item in audits
    )


@_async_test
async def test_bof_execute_is_disabled_for_every_identity_before_import_or_body() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    audits: list[dict[str, Any]] = []

    def record_audit(**kwargs: Any) -> bool:
        audits.append(kwargs)
        return True

    with patch.object(server, "_write_audit_log", side_effect=record_audit):
        async with _client(app) as anonymous:
            no_auth = await anonymous.post(
                "/api/v1/c2/bofs/whoami/execute",
                content="body-must-not-be-read",
            )
        async with _client(app, role=Role.VIEWER) as viewer:
            viewer_denied = await viewer.post("/api/v1/c2/bofs/whoami/execute", content="not-json")
        async with _client(app, role=Role.OPERATOR) as operator:
            operator_denied = await operator.post("/api/v1/c2/bofs/whoami/execute", content="not-json")
        async with _client(app, role=Role.ADMIN) as admin:
            admin_disabled = await admin.post("/api/v1/c2/bofs/whoami/execute", content="not-json")
            listing = await admin.get("/api/v1/c2/bofs")

    assert no_auth.status_code == 401
    assert viewer_denied.status_code == 403
    assert operator_denied.status_code == 403
    assert admin_disabled.status_code == 403
    assert admin_disabled.json()["reason_code"] == "local_bof_execution_disabled"
    assert listing.status_code == 200
    assert listing.json()["enabled"] is False
    assert listing.json()["bofs"] == []
    assert audits
    assert all(
        item["object_id"] in {"disabled", "/api/v1/c2/bofs/{name}/execute"}
        for item in audits
    )
    assert "whoami" not in json.dumps(audits)


@_async_test
async def test_viewer_c2_profiles_are_static_and_side_effect_free() -> None:
    from common.dashboard.server import DashboardServer
    from forge_c2.profiles.profile_parser import (
        BUILTIN_PROFILES,
        get_builtin_profile,
    )

    expected_listing = [
        {
            "name": name,
            "description": data.get("description", ""),
            "author": data.get("author", ""),
            "source": "built-in",
        }
        for name, data in BUILTIN_PROFILES.items()
    ]
    expected_detail = get_builtin_profile("office365").to_dict()
    missing_canary = "CANARY_PROFILE_NAME_TASK004"
    server = DashboardServer(auth=True)
    app = server.create_app()

    with (
        patch(
            "forge_c2.profiles.profile_parser.list_profiles",
            side_effect=AssertionError("custom profile discovery reached"),
        ) as discover_profiles,
        patch.object(Path, "exists") as path_exists,
        patch.object(Path, "iterdir") as path_iterdir,
        patch.object(Path, "open") as path_open,
        patch("common.dashboard.server.sqlite3.connect") as sqlite_connect,
        patch("common.dashboard.server.subprocess.Popen") as popen,
        patch("common.dashboard.server.subprocess.run") as process_run,
        patch("common.dashboard.server.socket.getaddrinfo") as resolve,
        patch("common.dashboard.server.socket.create_connection") as connect,
    ):
        async with _client(app, role=Role.VIEWER) as viewer:
            listing_one = await viewer.get("/api/v1/c2/profiles")
            detail_one = await viewer.get("/api/v1/c2/profiles/office365")
            missing_one = await viewer.get(f"/api/v1/c2/profiles/{missing_canary}")
            listing_two = await viewer.get("/api/v1/c2/profiles")
            detail_two = await viewer.get("/api/v1/c2/profiles/office365")
            missing_two = await viewer.get(f"/api/v1/c2/profiles/{missing_canary}")

    assert listing_one.status_code == 200
    assert listing_one.json() == {
        "profiles": expected_listing,
        "total": len(expected_listing),
    }
    assert listing_two.json() == listing_one.json()
    assert detail_one.status_code == 200
    assert detail_one.json() == {"profile": expected_detail}
    assert detail_two.json() == detail_one.json()
    assert missing_one.status_code == 404
    assert missing_one.json() == {
        "error": "Profile not found",
        "reason_code": "c2_profile_not_found",
    }
    assert missing_two.json() == missing_one.json()
    assert missing_canary not in missing_one.text
    discover_profiles.assert_not_called()
    path_exists.assert_not_called()
    path_iterdir.assert_not_called()
    path_open.assert_not_called()
    sqlite_connect.assert_not_called()
    popen.assert_not_called()
    process_run.assert_not_called()
    resolve.assert_not_called()
    connect.assert_not_called()


@_async_test
async def test_c2_emulation_plan_binds_operator_to_viewer_without_host_side_effects() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    invalid_canary = "CANARY_C2_TECHNIQUE_TASK004"
    with (
        patch.object(server, "_write_audit_log", return_value=True),
        patch("common.dashboard.server.subprocess.Popen") as popen,
        patch("common.dashboard.server.subprocess.run") as process_run,
        patch("common.dashboard.server.socket.getaddrinfo") as resolve,
        patch("common.dashboard.server.socket.create_connection") as connect,
        patch("common.dashboard.server.sqlite3.connect") as sqlite_connect,
        patch.object(Path, "open") as path_open,
        patch.object(Path, "write_text") as path_write_text,
        patch.object(Path, "write_bytes") as path_write_bytes,
        patch.object(Path, "mkdir") as path_mkdir,
    ):
        async with _client(app, role=Role.VIEWER) as viewer:
            response = await viewer.post(
                "/api/v1/c2/emulation/process-injection/plan",
                json={
                    "technique_id": "ntqueueapcthread",
                    "beacon_id": "beacon-1",
                    "target_process": "fixture.exe",
                    "operator": "admin",
                },
            )
            non_object = await viewer.post(
                "/api/v1/c2/emulation/process-injection/plan",
                json=["operator", "admin"],
            )
            invalid = await viewer.post(
                "/api/v1/c2/emulation/process-injection/plan",
                json={"technique_id": invalid_canary, "operator": "admin"},
            )

    assert response.status_code == 200
    assert response.json()["plan"]["operator"] == "task004-viewer"
    assert response.json()["plan"]["operator"] != "admin"
    assert non_object.status_code == 400
    assert non_object.json() == {"error": "JSON body must be an object"}
    assert invalid.status_code == 400
    assert invalid.json() == {
        "error": "Process-injection emulation plan rejected",
        "reason_code": "c2_emulation_plan_rejected",
    }
    assert invalid_canary not in invalid.text
    popen.assert_not_called()
    process_run.assert_not_called()
    resolve.assert_not_called()
    connect.assert_not_called()
    sqlite_connect.assert_not_called()
    path_open.assert_not_called()
    path_write_text.assert_not_called()
    path_write_bytes.assert_not_called()
    path_mkdir.assert_not_called()


def test_remote_event_bus_stays_inert_without_task003_control_plane_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import urllib.request

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: pytest.fail("remote event traffic escaped"),
    )
    bus = RemoteEventBus("https://127.0.0.1:1337", run_id="run-a")
    assert bus.start() is False
    assert bus.disabled_reason == "remote_event_destination_not_authorized"
    assert bus._thread is None
    assert bus._running is False


class _FakeWebSocket:
    def __init__(
        self,
        auth_message: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
        client_ip: str | None = "127.0.0.1",
    ) -> None:
        self.auth_message = auth_message or {}
        self.headers = {"host": "testserver", **(headers or {})}
        self.client = (
            type("Client", (), {"host": client_ip})()
            if client_ip is not None
            else None
        )
        self.sent_json: list[dict[str, Any]] = []
        self.sent_text: list[str] = []
        self.close_code: int | None = None
        self.accepted = False
        self.accept_calls = 0
        self.receive_json_calls = 0
        self.receive_text_calls = 0

    async def accept(self) -> None:
        self.accepted = True
        self.accept_calls += 1

    async def receive_json(self) -> dict[str, Any]:
        self.receive_json_calls += 1
        return self.auth_message

    async def receive_text(self) -> str:
        from common.dashboard.server import WebSocketDisconnect

        self.receive_text_calls += 1
        raise WebSocketDisconnect()

    async def send_json(self, value: dict[str, Any]) -> None:
        self.sent_json.append(value)

    async def send_text(self, value: str) -> None:
        self.sent_text.append(value)

    async def close(self, code: int = 1000) -> None:
        self.close_code = code


class _PendingAuthWebSocket(_FakeWebSocket):
    def __init__(self, release: asyncio.Event, *, client_ip: str) -> None:
        super().__init__(client_ip=client_ip)
        self._release = release
        self.receive_started = asyncio.Event()

    async def receive_json(self) -> dict[str, Any]:
        from common.dashboard.server import WebSocketDisconnect

        self.receive_json_calls += 1
        self.receive_started.set()
        await self._release.wait()
        raise WebSocketDisconnect()


def _install_websocket_inert_guards(
    stack: ExitStack,
    server: Any,
) -> dict[str, MagicMock]:
    """Fail evidence if a rejected handshake reaches state or host boundaries."""
    return {
        "public_snapshot": stack.enter_context(
            patch.object(server, "_public_state_snapshot")
        ),
        "state_snapshot": stack.enter_context(
            patch.object(server.state_store, "snapshot")
        ),
        "audit": stack.enter_context(patch.object(server, "_write_audit_log")),
        "event_emit": stack.enter_context(patch.object(server.event_bus, "emit")),
        "event_emit_simple": stack.enter_context(
            patch.object(server.event_bus, "emit_simple")
        ),
        "popen": stack.enter_context(
            patch("common.dashboard.server.subprocess.Popen")
        ),
        "process_run": stack.enter_context(
            patch("common.dashboard.server.subprocess.run")
        ),
        "resolve": stack.enter_context(
            patch("common.dashboard.server.socket.getaddrinfo")
        ),
        "connect": stack.enter_context(
            patch("common.dashboard.server.socket.create_connection")
        ),
        "sqlite_connect": stack.enter_context(
            patch("common.dashboard.server.sqlite3.connect")
        ),
        "thread": stack.enter_context(
            patch("common.dashboard.server.threading.Thread")
        ),
        "path_open": stack.enter_context(patch.object(Path, "open")),
        "path_write_text": stack.enter_context(patch.object(Path, "write_text")),
        "path_write_bytes": stack.enter_context(patch.object(Path, "write_bytes")),
        "path_mkdir": stack.enter_context(patch.object(Path, "mkdir")),
    }


def _assert_websocket_guards_inert(guards: dict[str, MagicMock]) -> None:
    for name, guard in guards.items():
        assert guard.call_count == 0, f"rejected WebSocket reached {name}"


@_async_test
async def test_websocket_rejects_disallowed_origin_before_accept_or_state_access() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", "") == "/ws/dashboard"
    )
    websocket = _FakeWebSocket(
        {"token": "CANARY_ORIGIN_TOKEN_MUST_NOT_BE_READ"},
        headers={"origin": "https://disallowed.invalid"},
    )

    with ExitStack() as stack:
        guards = _install_websocket_inert_guards(stack, server)
        await endpoint(websocket)

    assert websocket.close_code == 4403
    assert websocket.accept_calls == 0
    assert websocket.receive_json_calls == 0
    assert websocket.sent_json == []
    assert server._ws_clients == {}
    assert server._websocket_reservation_count() == 0
    _assert_websocket_guards_inert(guards)


@_async_test
async def test_websocket_normalizes_public_host_and_rejects_evil_or_missing_origin_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from common.dashboard.server import DashboardServer

    monkeypatch.setenv(
        "FORGE_DASHBOARD_PUBLIC_HOST",
        "  Dashboard.Example.Test.  ",
    )
    monkeypatch.delenv("FORGE_DASHBOARD_ALLOWED_HOSTS", raising=False)
    server = DashboardServer(host="0.0.0.0", auth=True)
    app = server.create_app()
    endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", "") == "/ws/dashboard"
    )
    same_origin = _FakeWebSocket(
        {"token": "CANARY_INVALID_WS_TOKEN"},
        headers={
            "host": "DASHBOARD.EXAMPLE.TEST.:8443",
            "origin": "https://dashboard.example.test.:8443",
        },
        client_ip="192.0.2.10",
    )
    evil_origin = _FakeWebSocket(
        {"token": "CANARY_EVIL_ORIGIN_TOKEN_MUST_NOT_BE_READ"},
        headers={
            "host": "dashboard.example.test:8443",
            "origin": "https://evil.invalid",
        },
        client_ip="192.0.2.11",
    )
    missing_host = _FakeWebSocket(
        {"token": "CANARY_MISSING_HOST_TOKEN_MUST_NOT_BE_READ"},
        headers={"host": ""},
        client_ip="192.0.2.12",
    )

    with ExitStack() as stack:
        guards = _install_websocket_inert_guards(stack, server)
        await endpoint(same_origin)
        await endpoint(evil_origin)
        await endpoint(missing_host)

    assert same_origin.accept_calls == 1
    assert same_origin.receive_json_calls == 1
    assert same_origin.close_code == 4001
    for rejected in (evil_origin, missing_host):
        assert rejected.close_code == 4403
        assert rejected.accept_calls == 0
        assert rejected.receive_json_calls == 0
        assert rejected.sent_json == []
    assert server._ws_clients == {}
    assert server._websocket_reservation_count() == 0
    _assert_websocket_guards_inert(guards)


@_async_test
async def test_websocket_invalid_headers_cannot_poison_valid_quota_or_use_duplicates() -> None:
    from starlette.datastructures import Headers

    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", "") == "/ws/dashboard"
    )
    client_ip = "192.0.2.50"
    foreign = [
        _FakeWebSocket(
            {"token": "CANARY_FOREIGN_WS_TOKEN"},
            headers={"host": "foreign.invalid"},
            client_ip=client_ip,
        )
        for _ in range(30)
    ]
    duplicate_host = _FakeWebSocket(client_ip="192.0.2.51")
    duplicate_host.headers = Headers(raw=[
        (b"host", b"testserver"),
        (b"host", b"foreign.invalid"),
    ])
    duplicate_origin = _FakeWebSocket(client_ip="192.0.2.52")
    duplicate_origin.headers = Headers(raw=[
        (b"host", b"testserver"),
        (b"origin", b"https://testserver"),
        (b"origin", b"https://foreign.invalid"),
    ])
    valid = _FakeWebSocket(
        {"token": "CANARY_INVALID_WS_TOKEN"},
        client_ip=client_ip,
    )

    with ExitStack() as stack:
        guards = _install_websocket_inert_guards(stack, server)
        stack.enter_context(
            patch("common.dashboard.server.time.monotonic", return_value=10_000.0)
        )
        for websocket in foreign:
            await endpoint(websocket)
        await endpoint(duplicate_host)
        await endpoint(duplicate_origin)
        await endpoint(valid)

    assert all(websocket.close_code == 4403 for websocket in foreign)
    assert all(websocket.accept_calls == 0 for websocket in foreign)
    for duplicate in (duplicate_host, duplicate_origin):
        assert duplicate.close_code == 4403
        assert duplicate.accept_calls == 0
        assert duplicate.receive_json_calls == 0
        assert duplicate.sent_json == []
    assert valid.accept_calls == 1
    assert valid.receive_json_calls == 1
    assert valid.close_code == 4001
    assert len(server._public_rate_events[(
        "websocket-invalid-host-origin",
        client_ip,
    )]) == 30
    assert len(server._public_rate_events[("websocket-handshake", client_ip)]) == 1
    assert server._websocket_reservation_count() == 0
    _assert_websocket_guards_inert(guards)


@_async_test
async def test_websocket_failed_handshake_rate_limit_rejects_thirty_first_pre_accept() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", "") == "/ws/dashboard"
    )
    attempts = [
        _FakeWebSocket({"token": "CANARY_INVALID_WS_TOKEN"})
        for _ in range(31)
    ]

    with ExitStack() as stack:
        guards = _install_websocket_inert_guards(stack, server)
        stack.enter_context(
            patch("common.dashboard.server.time.monotonic", return_value=10_000.0)
        )
        for websocket in attempts:
            await endpoint(websocket)

    assert all(websocket.close_code == 4001 for websocket in attempts[:30])
    assert all(websocket.accept_calls == 1 for websocket in attempts[:30])
    assert attempts[30].close_code == 4429
    assert attempts[30].accept_calls == 0
    assert attempts[30].receive_json_calls == 0
    assert attempts[30].sent_json == []
    assert server._ws_clients == {}
    assert len(
        server._public_rate_events[("websocket-handshake", "127.0.0.1")]
    ) == 30
    assert server._websocket_reservation_count() == 0
    _assert_websocket_guards_inert(guards)


@_async_test
async def test_websocket_capacity_atomically_counts_pending_and_releases_every_slot() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", "") == "/ws/dashboard"
    )
    release = asyncio.Event()
    pending = [
        _PendingAuthWebSocket(release, client_ip=f"192.0.2.{index}")
        for index in range(1, 65)
    ]
    overflow = _FakeWebSocket(
        {"token": "CANARY_CAPACITY_TOKEN_MUST_NOT_BE_READ"},
        client_ip="192.0.2.65",
    )
    tasks: list[asyncio.Task[None]] = []
    results: list[Any] = []

    with ExitStack() as stack:
        guards = _install_websocket_inert_guards(stack, server)
        try:
            tasks = [asyncio.create_task(endpoint(websocket)) for websocket in pending]
            await asyncio.wait_for(
                asyncio.gather(
                    *(websocket.receive_started.wait() for websocket in pending)
                ),
                timeout=2.0,
            )
            assert server._websocket_reservation_count() == 64
            await endpoint(overflow)
            assert server._websocket_reservation_count() == 64
            assert overflow.close_code == 4429
            assert overflow.accept_calls == 0
            assert overflow.receive_json_calls == 0
            assert overflow.sent_json == []
        finally:
            release.set()
            results = list(await asyncio.gather(*tasks, return_exceptions=True))

    assert results == [None] * 64
    assert all(websocket.accept_calls == 1 for websocket in pending)
    assert all(websocket.receive_json_calls == 1 for websocket in pending)
    assert all(websocket.close_code == 4002 for websocket in pending)
    assert server._ws_clients == {}
    assert server._websocket_reservation_count() == 0
    assert overflow not in server._ws_reservations
    _assert_websocket_guards_inert(guards)


@_async_test
async def test_websocket_expired_handshake_emits_no_state_and_releases_capacity() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", "") == "/ws/dashboard"
    )
    expired = TokenPayload(
        username="expired-handshake",
        role=Role.ADMIN,
        issued_at=0.0,
        expires_at=0.0,
        session_id="expired-handshake",
        tenant_id=server.tenant_id,
    )
    websocket = _FakeWebSocket({"token": "CANARY_EXPIRED_HANDSHAKE_TOKEN"})

    with ExitStack() as stack:
        guards = _install_websocket_inert_guards(stack, server)
        stack.enter_context(
            patch("common.dashboard.server.validate_token", return_value=expired)
        )
        await endpoint(websocket)

    assert websocket.accept_calls == 1
    assert websocket.receive_json_calls == 1
    assert websocket.close_code == 4001
    assert websocket.sent_json == []
    assert server._ws_clients == {}
    assert server._websocket_reservation_count() == 0
    _assert_websocket_guards_inert(guards)


@_async_test
async def test_websocket_expired_session_cannot_command_or_receive_broadcast() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    expired = TokenPayload(
        username="expired-session",
        role=Role.ADMIN,
        issued_at=0.0,
        expires_at=0.0,
        session_id="expired-session",
        tenant_id=server.tenant_id,
    )
    command_ws = _FakeWebSocket()
    broadcast_ws = _FakeWebSocket()
    assert server._reserve_websocket(command_ws)
    assert server._reserve_websocket(broadcast_ws)
    server._ws_clients[command_ws] = expired
    server._ws_clients[broadcast_ws] = expired

    with ExitStack() as stack:
        guards = _install_websocket_inert_guards(stack, server)
        await server._handle_ws_command({"action": "get_state"}, command_ws)
        assert server._websocket_reservation_count() == 1
        await server._broadcast_event(Event(
            event_type=EventType.MODULE_PROGRESS,
            source="expiry-fixture",
            data={
                "tenant_id": server.tenant_id,
                "name": "header_audit",
                "progress": 50,
            },
        ))

    assert command_ws.close_code == 4001
    assert command_ws.sent_json == [{
        "type": "error",
        "reason_code": "dashboard_session_expired",
    }]
    assert broadcast_ws.close_code == 4001
    assert broadcast_ws.sent_text == []
    assert broadcast_ws.sent_json == [{
        "type": "error",
        "reason_code": "dashboard_session_expired",
    }]
    assert server._ws_clients == {}
    assert server._websocket_reservation_count() == 0
    _assert_websocket_guards_inert(guards)


@_async_test
async def test_websocket_authenticates_tenant_before_redacted_snapshot() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    app = server.create_app()
    endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", "") == "/ws/dashboard"
    )

    invalid = _FakeWebSocket({"token": "CANARY_INVALID_WS_TOKEN"})
    await endpoint(invalid)
    assert invalid.close_code == 4001
    assert all(item.get("type") != "state_snapshot" for item in invalid.sent_json)
    assert "CANARY_INVALID_WS_TOKEN" not in json.dumps(invalid.sent_json)

    wrong_tenant = _FakeWebSocket({
        "token": issue_identity_token(
            "tenant-b-viewer",
            Role.VIEWER,
            tenant_id="tenant-b",
        ),
    })
    await endpoint(wrong_tenant)
    assert wrong_tenant.close_code == 4403
    assert all(item.get("type") != "state_snapshot" for item in wrong_tenant.sent_json)

    valid = _FakeWebSocket({
        "token": issue_identity_token(
            "tenant-a-viewer",
            Role.VIEWER,
            tenant_id=server.tenant_id,
        ),
    })
    await endpoint(valid)
    assert [item["type"] for item in valid.sent_json[:2]] == [
        "auth_ack",
        "state_snapshot",
    ]
    assert valid.sent_json[0]["tenant_id"] == server.tenant_id
    assert server._ws_clients == {}
    assert server._websocket_reservation_count() == 0


def test_public_state_snapshot_ignores_transient_findings_and_omits_secrets() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    canary = "CANARY_WEBSOCKET_SECRET_TASK004"
    server.state_store.findings.append(FindingEntry(
        id="finding-a",
        title="Fixture finding",
        severity="High",
        module="header_audit",
        target=TARGET,
        evidence={"password": canary},
        verification={"raw_proof": canary},
    ))
    server.state_store.credentials.append(CredentialEntry(
        cred_type="API_KEY",
        account="fixture",
        secret=canary,
        target=TARGET,
    ))

    viewer = server._public_state_snapshot(Role.VIEWER)
    operator = server._public_state_snapshot(Role.OPERATOR)
    rendered = json.dumps({"viewer": viewer, "operator": operator})
    assert canary not in rendered
    assert viewer["findings"] == []
    assert operator["findings"] == []
    assert viewer["credentials"] == []
    assert "secret" not in operator["credentials"][0]


def test_state_store_rejects_explicit_cross_tenant_events() -> None:
    from common.dashboard.event_bus import EventBus
    from common.dashboard.state_store import StateStore

    bus = EventBus(run_id="tenant-run")
    store = StateStore(bus, tenant_id="tenant-a")
    bus.start()
    try:
        bus.emit(Event(
            event_type=EventType.FINDING_NEW,
            source="fixture",
            data={
                "tenant_id": "tenant-b",
                "id": "cross-tenant",
                "title": "must not appear",
                "severity": "High",
            },
        ))
        bus.emit(Event(
            event_type=EventType.FINDING_NEW,
            source="fixture",
            data={
                "tenant_id": "tenant-a",
                "id": "same-tenant",
                "title": "fixture",
                "severity": "Low",
            },
        ))
        deadline = time.monotonic() + 1.0
        while len(store.findings) < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        bus.stop()
    assert [finding.id for finding in store.findings] == ["same-tenant"]


@_async_test
async def test_websocket_event_tenant_filter_and_canary_redaction() -> None:
    from common.dashboard.server import DashboardServer

    server = DashboardServer(auth=True)
    viewer = _FakeWebSocket()
    operator = _FakeWebSocket()
    viewer_payload = validate_token(issue_identity_token("viewer", Role.VIEWER))
    operator_payload = validate_token(issue_identity_token("operator", Role.OPERATOR))
    assert viewer_payload is not None and operator_payload is not None
    server._ws_clients[viewer] = viewer_payload
    server._ws_clients[operator] = operator_payload
    canary = "CANARY_EVENT_SECRET_TASK004"

    await server._broadcast_event(Event(
        event_type=EventType.CREDENTIAL_FOUND,
        source="credential-fixture",
        data={
            "tenant_id": server.tenant_id,
            "type": "API_KEY",
            "account": "fixture",
            "secret": canary,
        },
    ))
    assert viewer.sent_text == []
    assert len(operator.sent_text) == 1
    assert canary not in operator.sent_text[0]
    assert "secret" not in json.loads(operator.sent_text[0])["data"]

    before = len(operator.sent_text)
    await server._broadcast_event(Event(
        event_type=EventType.MODULE_PROGRESS,
        source="header_audit",
        data={
            "tenant_id": "tenant-b",
            "name": "header_audit",
            "progress": 50,
        },
    ))
    assert len(operator.sent_text) == before

    await server._broadcast_event(Event(
        event_type=EventType.FINDING_NEW,
        source="untrusted-fixture",
        data={
            "tenant_id": server.tenant_id,
            "id": "fabricated-verified",
            "title": "Fabricated verified claim",
            "severity": "Critical",
            "status": "verified",
            "verification_state": "verified",
            "proof_type": "active",
            "maturity": "verified",
        },
    ))
    public_finding = json.loads(operator.sent_text[-1])["data"]
    assert public_finding["status"] == "open"
    assert public_finding["verification_state"] != "verified"
    assert public_finding["maturity"] == "experimental"

    await server._handle_ws_command({"action": "get_findings", "limit": 201}, operator)
    assert operator.sent_json[-1]["reason_code"] == "websocket_limit_invalid"


def test_c2_ui_truthfully_removes_local_bof_run_control() -> None:
    source = Path("apex-ui/src/pages/C2Console.jsx").read_text(encoding="utf-8")
    assert "Dashboard-host BOF execution is disabled" in source
    assert "local_bof_execution_disabled" in source
    assert "/execute`" not in source
    assert "click RUN" not in source
    assert "Built-in BOFs execute locally" not in source
