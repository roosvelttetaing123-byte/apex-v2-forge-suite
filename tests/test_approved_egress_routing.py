from __future__ import annotations

import asyncio
import json
import sys
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import common.outbound_policy as outbound_policy_module
from common.action_authorization import SafetyMode
from common.db import (
    append_route_health_evidence,
    create_db,
    list_outbound_decisions,
    list_route_health_evidence,
)
from common.outbound_policy import (
    AiohttpPinnedTransport,
    ApprovedEgressRoute,
    AuthorizationDatabaseOutboundAuditSink,
    DatabaseOutboundAuditSink,
    DnsMode,
    HttpTransportRequest,
    OutboundContext,
    OutboundDenied,
    OutboundPolicy,
    OutboundReason,
    PolicyHttpClient,
    PolicyBoundTransport,
    ROUTE_HEALTH_SCHEMA_VERSION,
    RouteVerificationPolicy,
    TransportResponse,
    _normalized_proxy_origin,
    approved_route_configuration_digest,
    evaluate_transport_compatibility,
    evaluate_module_outbound_support,
    intrinsically_local_modules,
    normalize_destination,
    outbound_context_claim_is_valid,
    policy_supported_modules,
)
from tests.test_outbound_policy import (
    NOW,
    TARGET,
    _authorization_context,
    _consumed_envelope,
    _policy,
)


def _route(**overrides: object) -> ApprovedEgressRoute:
    values: dict[str, object] = {
        "schema_version": "forge-approved-egress-route-v1",
        "route_id": "route-loopback",
        "tenant_id": "tenant-lab",
        "engagement_id": "engagement-lab",
        "action_id": "action-fixture",
        "operator_id": "operator-lab",
        "dns_mode": DnsMode.LOCAL_PINNED,
        "allowed_protocols": ("http", "https"),
        "allowed_tools": ("aiohttp",),
        "verification_policy": RouteVerificationPolicy.REQUIRED,
        "verification_endpoint": "https://127.0.0.1:8443/egress",
        "proxy_url": "http://127.0.0.1:18080",
        "proxy_credential_reference": "",
        "required": True,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(overrides)
    values.setdefault(
        "configuration_digest",
        approved_route_configuration_digest(
            schema_version=str(values["schema_version"]),
            route_id=str(values["route_id"]),
            tenant_id=str(values["tenant_id"]),
            engagement_id=str(values["engagement_id"]),
            action_id=str(values["action_id"]),
            operator_id=str(values["operator_id"]),
            dns_mode=values["dns_mode"],  # type: ignore[arg-type]
            allowed_protocols=values["allowed_protocols"],  # type: ignore[arg-type]
            allowed_tools=values["allowed_tools"],  # type: ignore[arg-type]
            verification_policy=values["verification_policy"],  # type: ignore[arg-type]
            verification_endpoint=str(values["verification_endpoint"]),
            proxy_url=str(values["proxy_url"]),
            proxy_credential_reference=str(values["proxy_credential_reference"]),
            required=bool(values["required"]),
            issued_at=values["issued_at"],  # type: ignore[arg-type]
            expires_at=values["expires_at"],  # type: ignore[arg-type]
        ),
    )
    return ApprovedEgressRoute(**values)


@pytest.mark.parametrize(
    "proxy_url",
    [
        "http://127.0.0.1:0",
        "http://127.0.0.1:",
        "http://[::1]:0",
        "http://[::1]:",
    ],
)
def test_proxy_origin_rejects_zero_or_empty_explicit_port(proxy_url: str) -> None:
    with pytest.raises(ValueError, match="port"):
        _normalized_proxy_origin(proxy_url)
    with pytest.raises(ValueError, match="port"):
        _route(proxy_url=proxy_url)


@pytest.mark.parametrize(
    "proxy_url",
    [
        " http://127.0.0.1:18080",
        "http://127.0.0.1:18080 ",
        "\x00http://127.0.0.1:18080",
        "http://127.0.0.1\n:18080",
        "http://127.0.0.1:\t18080",
        "http://127.0.0.1.:18080",
        "http://127.0.0.1..:18080",
        "http://[::1%25lo]:18080",
    ],
)
def test_proxy_origin_rejects_hidden_or_ambiguous_authority(proxy_url: str) -> None:
    with pytest.raises(ValueError):
        _normalized_proxy_origin(proxy_url)
    with pytest.raises(ValueError):
        _route(proxy_url=proxy_url)


def _preflight(
    policy: OutboundPolicy,
    *,
    observed_egress: str = "127.0.0.1",
    route_identity: str = "loopback-proxy-fixture",
):
    async def resolver(host: str, port: int) -> list[str]:
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        assert request.route is not None
        return TransportResponse(
            status=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(
                {
                    "observed_egress": observed_egress,
                    "route_identity": route_identity,
                }
            ).encode(),
        )

    return asyncio.run(policy.preflight_route(resolver=resolver, transport=transport))


async def _async_addresses(address: str) -> list[str]:
    return [address]


async def _async_route_health_response(
    observed_egress: str,
    route_identity: str,
) -> TransportResponse:
    return TransportResponse(
        status=200,
        headers={"Content-Type": "application/json"},
        body=json.dumps(
            {
                "observed_egress": observed_egress,
                "route_identity": route_identity,
            }
        ).encode(),
    )


def test_required_route_has_no_direct_fallback_when_unhealthy(tmp_path) -> None:
    route = _route()
    policy, session = _policy(tmp_path, route=route, now=NOW)
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolve")
        return ["127.0.0.1"]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return TransportResponse(status=200, headers={}, body=b"ok")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(policy, resolver=resolver, transport=transport).get(TARGET)
        )
    assert denied.value.reason_code == OutboundReason.ROUTE_PREFLIGHT_FAILED.value
    assert calls == ["resolve", "resolve", "transport"]
    session.close()


def test_future_dated_route_denies_before_preflight_io_or_health(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(outbound_policy_module, "_system_utc_now", lambda: NOW)
    route = _route(
        issued_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=6),
    )
    policy, session = _policy(tmp_path, route=route, now=NOW)
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolver")
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return await _async_route_health_response("127.0.0.1", "future-route")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            policy.preflight_route(
                resolver=resolver,
                transport=transport,
            )
        )

    assert denied.value.reason_code == OutboundReason.ROUTE_NOT_YET_VALID.value
    assert calls == []
    assert list_route_health_evidence(session) == []
    session.close()


def test_route_health_integrity_binds_subsecond_expiry(tmp_path) -> None:
    current = NOW + timedelta(microseconds=100_000)
    policy, session = _policy(tmp_path, route=_route(), now=current)
    health = policy._record_route_health(
        observed_egress="127.0.0.1",
        endpoint=policy.context.route.verification_endpoint,  # type: ignore[union-attr]
        route_identity="subsecond-health",
        now=current,
    )
    assert policy.route_health_is_current() is True

    policy._route_health_state.evidence = replace(
        health,
        expires_at=health.expires_at.replace(microsecond=999_999),
    )

    assert policy.route_health_is_current() is False
    session.close()


@pytest.mark.parametrize(
    "destination",
    [
        "https://127.0.0.2:8443/excluded",
        "https://127.0.0.1:8443/%zz malformed",
    ],
)
def test_invalid_initial_destination_precedes_required_route_preflight(
    tmp_path,
    destination: str,
) -> None:
    policy, session = _policy(
        tmp_path,
        route=_route(),
        allowed_scope=["127.0.0.0/8", TARGET],
        excluded_scope=["127.0.0.2/32"],
        now=NOW,
    )
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolve")
        return ["127.0.0.1"]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return await _async_route_health_response("127.0.0.1", "identity-one")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(destination)
        )

    expected = (
        OutboundReason.EXCLUDED.value
        if "127.0.0.2" in destination
        else OutboundReason.MALFORMED_DESTINATION.value
    )
    assert denied.value.reason_code == expected
    assert calls == []
    session.close()


@pytest.mark.parametrize(
    "target_addresses",
    [
        ["127.0.0.2"],
        ["127.0.0.1", "127.0.0.2"],
    ],
)
def test_invalid_initial_dns_precedes_required_route_transport(
    tmp_path,
    target_addresses: list[str],
) -> None:
    target = "https://allowed.test:8443/start"
    policy, session = _policy(
        tmp_path,
        target=target,
        route=_route(),
        allowed_scope=[
            "allowed.test",
            "127.0.0.1/32",
            "https://allowed.test:8443",
            "https://127.0.0.1:8443",
        ],
        now=NOW,
    )
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append(f"resolve:{host}")
        if host == "allowed.test":
            return target_addresses
        return ["127.0.0.1"]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return await _async_route_health_response("127.0.0.1", "identity-one")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(target)
        )

    assert denied.value.reason_code == OutboundReason.RESOLVED_IP_OUT_OF_SCOPE.value
    assert calls == ["resolve:allowed.test"]
    session.close()


def test_required_route_success_uses_exact_approved_proxy(tmp_path) -> None:
    route = _route()
    policy, session = _policy(tmp_path, route=route, now=NOW)
    _preflight(policy)
    requests: list[HttpTransportRequest] = []

    async def resolver(host: str, port: int) -> list[str]:
        return ["127.0.0.1"]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        requests.append(request)
        return TransportResponse(status=200, headers={}, body=b"ok")

    response = asyncio.run(
        PolicyHttpClient(policy, resolver=resolver, transport=transport).get(TARGET)
    )
    assert response.status == 200
    assert requests[0].route is not None
    assert requests[0].route.route_id == route.route_id
    assert requests[0].route.proxy_url == "http://127.0.0.1:18080"
    assert list_route_health_evidence(session)[-1]["observed_egress"] == "127.0.0.1"
    session.close()


def test_real_loopback_proxy_uses_permit_ip_sni_and_has_no_direct_fallback(
    tmp_path,
    monkeypatch,
) -> None:
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    async def exercise() -> None:
        certificate_now = datetime.now(timezone.utc)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "allowed.test")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(certificate_now - timedelta(days=1))
            .not_valid_after(certificate_now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("allowed.test")]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        cert_path = tmp_path / "route-target-cert.pem"
        key_path = tmp_path / "route-target-key.pem"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        monkeypatch.setenv("SSL_CERT_FILE", str(cert_path))

        target_peers: list[str] = []
        target_hosts: list[str] = []
        observed_sni: list[str] = []
        proxy_connects: list[str] = []

        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)
        server_context.set_servername_callback(
            lambda _ssl, server_name, _ctx: observed_sni.append(server_name or "")
        )

        async def target_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            peer = writer.get_extra_info("peername")
            target_peers.append(str(peer[0]))
            request = await reader.readuntil(b"\r\n\r\n")
            lines = request.decode("latin-1").split("\r\n")
            path = lines[0].split(" ", 2)[1]
            host = next(
                (line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("host:")),
                "",
            )
            target_hosts.append(host)
            if path == "/egress":
                body = json.dumps(
                    {
                        "observed_egress": "127.0.0.1",
                        "route_identity": "real-loopback-proxy-v1",
                    }
                ).encode()
                content_type = b"Content-Type: application/json\r\n"
            else:
                body = b"ok"
                content_type = b""
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                + content_type
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        target_server = await asyncio.start_server(
            target_handler,
            "127.0.0.1",
            0,
            ssl=server_context,
        )
        target_port = int(target_server.sockets[0].getsockname()[1])

        async def relay(
            source: asyncio.StreamReader,
            destination: asyncio.StreamWriter,
        ) -> None:
            try:
                while data := await source.read(65536):
                    destination.write(data)
                    await destination.drain()
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                destination.close()

        async def proxy_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            request = await reader.readuntil(b"\r\n\r\n")
            first_line = request.decode("latin-1").split("\r\n", 1)[0]
            proxy_connects.append(first_line)
            assert first_line == f"CONNECT 127.0.0.1:{target_port} HTTP/1.1"
            upstream_reader, upstream_writer = await asyncio.open_connection(
                "127.0.0.1",
                target_port,
                local_addr=("127.0.0.2", 0),
            )
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(
                relay(reader, upstream_writer),
                relay(upstream_reader, writer),
            )

        proxy_server = await asyncio.start_server(
            proxy_handler,
            "127.0.0.1",
            0,
        )
        proxy_port = int(proxy_server.sockets[0].getsockname()[1])
        target = f"https://allowed.test:{target_port}/start"
        verification_endpoint = f"https://allowed.test:{target_port}/egress"
        route = _route(
            verification_endpoint=verification_endpoint,
            proxy_url=f"http://127.0.0.1:{proxy_port}",
        )
        policy, session = _policy(
            tmp_path / "real-proxy",
            target=target,
            allowed_scope=["allowed.test", "127.0.0.1/32", target],
            route=route,
            now=NOW,
        )

        async def resolver(host: str, port: int) -> list[str]:
            assert host == "allowed.test"
            assert port == target_port
            return ["127.0.0.1"]

        try:
            response = await PolicyHttpClient(policy, resolver=resolver).get(target)
            assert response.status == 200
            assert await response.text() == "ok"
            assert proxy_connects == [
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1",
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1",
            ]
            assert target_peers == ["127.0.0.2", "127.0.0.2"]
            assert observed_sni == ["allowed.test", "allowed.test"]
            assert target_hosts == [
                f"allowed.test:{target_port}",
                f"allowed.test:{target_port}",
            ]

            proxy_server.close()
            await proxy_server.wait_closed()
            before = len(target_peers)
            with pytest.raises(OutboundDenied) as unavailable:
                await PolicyHttpClient(policy, resolver=resolver).get(target)
            assert unavailable.value.reason_code == OutboundReason.CONNECTION_FAILED.value
            assert len(target_peers) == before
        finally:
            if proxy_server.is_serving():
                proxy_server.close()
                await proxy_server.wait_closed()
            target_server.close()
            await target_server.wait_closed()
            session.close()

    asyncio.run(exercise())


def test_route_restart_requires_new_preflight_and_changed_identity_pauses(tmp_path) -> None:
    route = _route()
    first, session = _policy(tmp_path, route=route, runtime_id="runtime-one", now=NOW)
    evidence = _preflight(first, route_identity="identity-one")
    assert first.route_health is evidence

    restarted = OutboundPolicy(
        first.context,
        runtime_id="runtime-two",
        prior_route_health=evidence,
    )
    with pytest.raises(OutboundDenied) as stale:
        restarted.prepare_destination(TARGET, action_kind="http.request")
    assert stale.value.reason_code == OutboundReason.ROUTE_HEALTH_REQUIRED.value

    with pytest.raises(OutboundDenied) as restart_changed:
        asyncio.run(
            restarted.preflight_route(
                resolver=lambda host, port: _async_addresses("127.0.0.1"),
                transport=lambda request: _async_route_health_response(
                    "127.0.0.2", "identity-two"
                ),
            )
        )
    assert restart_changed.value.reason_code == OutboundReason.ROUTE_IDENTITY_CHANGED.value

    with pytest.raises(OutboundDenied) as changed:
        asyncio.run(
            first.preflight_route(
                resolver=lambda host, port: _async_addresses("127.0.0.1"),
                transport=lambda request: _async_route_health_response(
                    "127.0.0.2", "identity-two"
                ),
            )
        )
    assert changed.value.reason_code == OutboundReason.ROUTE_IDENTITY_CHANGED.value
    session.close()


def test_protected_route_health_store_rejects_fresh_runtime_drift(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("FORGE_AUTHORIZATION_DB", str(tmp_path / "route-health.db"))
    session = create_db(tmp_path / "seed-authorization.db")
    expected = _authorization_context()
    envelope = _consumed_envelope(session, expected)
    route = _route(action_id=envelope.action_id)
    context = OutboundContext.from_consumed_authorization(
        session=session,
        envelope=envelope,
        expected=expected,
        boundary="webforge.module",
        authorized_target=TARGET,
        allowed_scope=expected.allowed_scope,
        excluded_scope=expected.excluded_scope,
        audit_sink=AuthorizationDatabaseOutboundAuditSink(),
        route=route,
    )
    first = OutboundPolicy(context, runtime_id="runtime-one")
    _preflight(first, route_identity="identity-one")

    same_identity = OutboundPolicy(
        context,
        runtime_id="runtime-two",
    )
    asyncio.run(
        same_identity.preflight_route(
            resolver=lambda host, port: _async_addresses("127.0.0.1"),
            transport=lambda request: _async_route_health_response(
                "127.0.0.1", "identity-one"
            ),
        )
    )
    assert first.route_health_is_current()
    assert same_identity.route_health_is_current()

    failed_destination = first.prepare_destination(
        TARGET,
        action_kind="http.request",
    )
    first.record_terminal_failure(
        prepared=failed_destination,
        reason=OutboundReason.CONNECTION_FAILED,
        stage="transport",
    )
    assert first.route_health_is_current() is False
    assert (
        same_identity.route_health_is_current()
        is False
    )

    recovered = OutboundPolicy(
        context,
        runtime_id="runtime-recovered",
    )
    asyncio.run(
        recovered.preflight_route(
            resolver=lambda host, port: _async_addresses("127.0.0.1"),
            transport=lambda request: _async_route_health_response(
                "127.0.0.1", "identity-one"
            ),
        )
    )
    assert same_identity.route_health_is_current()

    changed_identity = OutboundPolicy(
        context,
        runtime_id="runtime-three",
    )
    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            changed_identity.preflight_route(
                resolver=lambda host, port: _async_addresses("127.0.0.1"),
                transport=lambda request: _async_route_health_response(
                    "127.0.0.2", "identity-two"
                ),
            )
        )

    assert denied.value.reason_code == OutboundReason.ROUTE_IDENTITY_CHANGED.value

    changed_expected = _authorization_context(
        run_id="run-route-configuration",
        job_id="job-route-configuration",
    )
    changed_envelope = _consumed_envelope(session, changed_expected)
    baseline_route = _route(action_id=changed_envelope.action_id)
    changed_route = _route(
        action_id=changed_envelope.action_id,
        proxy_url="http://127.0.0.1:18081",
    )
    health_session = create_db(tmp_path / "route-health.db")
    append_route_health_evidence(
        health_session,
        {
            "evidence_id": "route-health-baseline-configuration",
            "schema_version": ROUTE_HEALTH_SCHEMA_VERSION,
            "route_id": baseline_route.route_id,
            "tenant_id": baseline_route.tenant_id,
            "engagement_id": baseline_route.engagement_id,
            "action_id": baseline_route.action_id,
            "configuration_digest": baseline_route.configuration_digest,
            "runtime_id": "runtime-baseline-configuration",
            "dns_mode": baseline_route.dns_mode.value,
            "verification_endpoint_ref": normalize_destination(
                baseline_route.verification_endpoint
            ).destination_ref,
            "observed_egress": "127.0.0.1",
            "route_identity": "identity-one",
            "verified_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
            "binding_digest": "sha256:" + "a" * 64,
            "recorded_at": NOW.isoformat(),
        },
    )
    health_session.close()
    changed_configuration = OutboundPolicy(
        OutboundContext.from_consumed_authorization(
            session=session,
            envelope=changed_envelope,
            expected=changed_expected,
            boundary="webforge.module",
            authorized_target=TARGET,
            allowed_scope=changed_expected.allowed_scope,
            excluded_scope=changed_expected.excluded_scope,
            audit_sink=AuthorizationDatabaseOutboundAuditSink(),
            route=changed_route,
        ),
        runtime_id="runtime-four",
    )
    with pytest.raises(OutboundDenied) as configuration_denied:
        asyncio.run(
            changed_configuration.preflight_route(
                resolver=lambda host, port: _async_addresses("127.0.0.1"),
                transport=lambda request: _async_route_health_response(
                    "127.0.0.1", "identity-one"
                ),
            )
        )
    assert (
        configuration_denied.value.reason_code
        == OutboundReason.ROUTE_CONFIGURATION_CHANGED.value
    )
    session.close()


@pytest.mark.parametrize(
    "failure_reason",
    [
        OutboundReason.CONNECTION_FAILED,
        OutboundReason.TLS_VERIFICATION_FAILED,
    ],
)
def test_route_transport_failure_forces_preflight_before_next_target_request(
    tmp_path,
    failure_reason: OutboundReason,
) -> None:
    policy, session = _policy(tmp_path, route=_route(), now=NOW)
    _preflight(policy, route_identity="identity-one")

    async def failed_transport(request: HttpTransportRequest) -> TransportResponse:
        raise OutboundDenied(failure_reason)

    with pytest.raises(OutboundDenied) as failed:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses("127.0.0.1"),
                transport=failed_transport,
            ).get(TARGET)
        )
    assert failed.value.reason_code == failure_reason.value
    assert policy.route_health_is_current() is False

    actions: list[str] = []

    async def recovered_transport(
        request: HttpTransportRequest,
    ) -> TransportResponse:
        actions.append(request.prepared.action_kind)
        if request.prepared.action_kind == "route.preflight":
            return await _async_route_health_response("127.0.0.1", "identity-one")
        return TransportResponse(status=200, headers={}, body=b"ok")

    response = asyncio.run(
        PolicyHttpClient(
            policy,
            resolver=lambda host, port: _async_addresses("127.0.0.1"),
            transport=recovered_transport,
        ).get(TARGET)
    )

    assert response.status == 200
    assert actions == ["route.preflight", "http.request"]
    session.close()


def test_sibling_policy_clients_share_route_health_and_identity(tmp_path) -> None:
    policy, session = _policy(tmp_path, route=_route(), now=NOW)
    first = policy.fork()
    second = policy.fork()

    _preflight(first, route_identity="shared-identity")
    assert policy.route_health_is_current()
    assert second.route_health_is_current()

    with pytest.raises(OutboundDenied) as changed:
        asyncio.run(
            second.preflight_route(
                resolver=lambda host, port: _async_addresses("127.0.0.1"),
                transport=lambda request: _async_route_health_response(
                    "127.0.0.2", "changed-identity"
                ),
            )
        )
    assert changed.value.reason_code == OutboundReason.ROUTE_IDENTITY_CHANGED.value
    session.close()


def test_inflight_response_is_rejected_after_sibling_route_invalidation(tmp_path) -> None:
    policy, session = _policy(tmp_path, route=_route(), now=NOW)
    first = policy.fork()
    second = policy.fork()
    _preflight(first, route_identity="shared-identity")
    released: list[str] = []

    async def exercise() -> None:
        entered = asyncio.Event()
        release = asyncio.Event()

        async def blocked_transport(
            request: HttpTransportRequest,
        ) -> TransportResponse:
            entered.set()
            await release.wait()
            return TransportResponse(
                status=200,
                headers={},
                body=b"ok",
                release_callback=lambda: released.append("released"),
            )

        async def failed_transport(
            request: HttpTransportRequest,
        ) -> TransportResponse:
            raise OutboundDenied(OutboundReason.TLS_VERIFICATION_FAILED)

        first_task = asyncio.create_task(
            PolicyHttpClient(
                first,
                resolver=lambda host, port: _async_addresses("127.0.0.1"),
                transport=blocked_transport,
            ).get(TARGET)
        )
        await asyncio.wait_for(entered.wait(), timeout=1.0)

        with pytest.raises(OutboundDenied) as sibling_failure:
            await PolicyHttpClient(
                second,
                resolver=lambda host, port: _async_addresses("127.0.0.1"),
                transport=failed_transport,
            ).get(TARGET)
        assert (
            sibling_failure.value.reason_code
            == OutboundReason.TLS_VERIFICATION_FAILED.value
        )
        release.set()

        with pytest.raises(OutboundDenied) as inflight:
            await first_task
        assert inflight.value.reason_code == OutboundReason.ROUTE_HEALTH_REQUIRED.value

    asyncio.run(exercise())

    assert released == ["released"]
    assert first.route_health_is_current() is False
    session.close()


def test_pinned_transport_rejects_tampered_prepared_state_without_socket(tmp_path) -> None:
    policy, session = _policy(tmp_path, now=NOW)
    prepared = policy.prepare_destination(TARGET, action_kind="http.request")
    permit = policy.authorize_resolution(prepared, ["127.0.0.1"])
    request = HttpTransportRequest(
        method="GET",
        url=TARGET,
        headers={},
        permit=permit,
        prepared=replace(prepared, verify_tls=False, tls_mode="lab_only_insecure"),
        route=None,
        timeout_seconds=1.0,
        max_response_bytes=1024,
    )

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(AiohttpPinnedTransport(policy)(request))

    assert denied.value.reason_code == OutboundReason.PERMIT_MISMATCH.value
    session.close()


def test_policy_bound_transport_consumes_permit_once_before_delegate(tmp_path) -> None:
    policy, session = _policy(tmp_path, now=NOW)
    prepared = policy.prepare_destination(TARGET, action_kind="http.request")
    permit = policy.authorize_resolution(prepared, ["127.0.0.1"])
    request = HttpTransportRequest(
        method="GET",
        url=TARGET,
        headers={},
        permit=permit,
        prepared=prepared,
        route=None,
        timeout_seconds=1.0,
        max_response_bytes=1024,
    )
    calls: list[str] = []

    async def delegate(admitted: HttpTransportRequest) -> TransportResponse:
        calls.append(admitted.permit.permit_id)
        return TransportResponse(status=200, headers={}, body=b"ok")

    bound = PolicyBoundTransport(policy, delegate)
    first = asyncio.run(bound(request))
    assert first.status == 200
    with pytest.raises(OutboundDenied) as replayed:
        asyncio.run(bound(request))

    assert replayed.value.reason_code == OutboundReason.PERMIT_REPLAYED.value
    assert calls == [permit.permit_id]
    session.close()


def test_policy_bound_transport_strips_all_caller_headers_cross_origin(tmp_path) -> None:
    secondary = "https://127.0.0.2:8443/secondary"
    policy, session = _policy(
        tmp_path,
        allowed_scope=["127.0.0.0/8", TARGET, secondary],
        now=NOW,
    )
    prepared = policy.prepare_destination(
        secondary,
        action_kind="http.request",

    )
    permit = policy.authorize_resolution(prepared, ["127.0.0.2"])
    received_headers: list[dict[str, str]] = []

    async def delegate(admitted: HttpTransportRequest) -> TransportResponse:
        received_headers.append(dict(admitted.headers))
        return TransportResponse(status=200, headers={}, body=b"ok")

    request = HttpTransportRequest(
        method="GET",
        url=secondary,
        headers={
            "Authorization": "Bearer CANARY_DIRECT_AUTH",
            "Cookie": "session=CANARY_DIRECT_COOKIE",
            "Accept": "CANARY_DIRECT_CREDENTIAL_CARRIER",
            "Host": "attacker.invalid",
        },
        permit=permit,
        prepared=prepared,
        route=None,
        timeout_seconds=1.0,
        max_response_bytes=1024,
    )

    response = asyncio.run(PolicyBoundTransport(policy, delegate)(request))

    assert response.status == 200
    assert received_headers == [{"Host": "127.0.0.2:8443"}]
    session.close()


def test_policy_bound_transport_denies_cross_origin_body_before_delegate(tmp_path) -> None:
    secondary = "https://127.0.0.2:8443/secondary"
    policy, session = _policy(
        tmp_path,
        allowed_scope=["127.0.0.0/8", TARGET, secondary],
        now=NOW,
    )
    prepared = policy.prepare_destination(
        secondary,
        action_kind="http.request",

    )
    permit = policy.authorize_resolution(prepared, ["127.0.0.2"])
    calls: list[str] = []

    async def delegate(admitted: HttpTransportRequest) -> TransportResponse:
        calls.append("delegate")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    request = HttpTransportRequest(
        method="POST",
        url=secondary,
        headers={},
        permit=permit,
        prepared=prepared,
        route=None,
        timeout_seconds=1.0,
        max_response_bytes=1024,
        options={"data": {"access_token": "CANARY_DIRECT_BODY"}},
    )
    bound = PolicyBoundTransport(policy, delegate)

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(bound(request))

    assert denied.value.reason_code == OutboundReason.CROSS_ORIGIN_BODY_NOT_AUTHORIZED.value
    assert calls == []
    clean = replace(request, method="GET", options={})
    assert asyncio.run(bound(clean)).status == 200
    assert calls == ["delegate"]
    session.close()


def test_policy_bound_transport_denies_invalidated_health_before_delegate(tmp_path) -> None:
    policy, session = _policy(tmp_path, route=_route(), now=NOW)
    _preflight(policy, route_identity="shared-identity")
    prepared = policy.prepare_destination(TARGET, action_kind="http.request")
    permit = policy.authorize_resolution(prepared, ["127.0.0.1"])
    policy.record_terminal_failure(
        prepared=prepared,
        reason=OutboundReason.TLS_VERIFICATION_FAILED,
        stage="fixture_sibling_failure",
    )
    calls: list[str] = []

    async def delegate(request: HttpTransportRequest) -> TransportResponse:
        calls.append("delegate")
        return TransportResponse(status=200, headers={}, body=b"ok")

    request = HttpTransportRequest(
        method="GET",
        url=TARGET,
        headers={},
        permit=permit,
        prepared=prepared,
        route=prepared.route,
        timeout_seconds=1.0,
        max_response_bytes=1024,
    )
    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(PolicyBoundTransport(policy, delegate)(request))

    assert denied.value.reason_code == OutboundReason.ROUTE_HEALTH_REQUIRED.value
    assert calls == []
    session.close()


@pytest.mark.parametrize(
    ("protocol", "tool"),
    [
        ("raw_tcp", "scapy"),
        ("icmp", "ping"),
        ("udp", "snmp"),
        ("packet_capture", "tcpdump"),
    ],
)
def test_incompatible_raw_udp_icmp_and_capture_are_unsupported_without_traffic(
    protocol: str,
    tool: str,
) -> None:
    decision = evaluate_transport_compatibility(
        route=_route(),
        protocol=protocol,
        tool=tool,
    )
    assert decision.supported is False
    assert decision.reason_code == OutboundReason.UNSUPPORTED_ROUTE_TRANSPORT.value
    assert decision.outcome == "not_tested"


def test_route_declarations_cannot_claim_unimplemented_raw_adapter_support() -> None:
    route = _route(
        allowed_protocols=("raw_tcp",),
        allowed_tools=("scapy",),
    )
    decision = evaluate_transport_compatibility(
        route=route,
        protocol="raw_tcp",
        tool="scapy",
    )
    assert decision.supported is False
    assert decision.reason_code == OutboundReason.UNSUPPORTED_ROUTE_TRANSPORT.value


def test_unmigrated_known_modules_default_to_not_tested() -> None:
    for engine, module_id in (
        ("netforge", "host_discover"),
        ("netforge", "port_scanner"),
        ("netforge", "cred_spray"),
        ("netforge", "hydra_wrap"),
        ("netforge", "native_brute"),
        ("webforge", "http_smuggling"),
        ("webforge", "login_brute"),
        ("adforge", "ldap_enum"),
    ):
        decision = evaluate_module_outbound_support(
            engine=engine,
            module_id=module_id,
        )
        assert decision.supported is False
        assert decision.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value
        assert decision.outcome == "not_tested"


def test_module_names_and_helpers_cannot_create_no_context_exceptions(
    tmp_path,
) -> None:
    from common.base_module import BaseModule, ModuleResult
    from common.config import BaseForgeConfig
    from common.scope import Scope
    from netforge.modules.compliance.cis_benchmark import CisBenchmark
    from netforge.modules.reporting.html_report import HtmlReport

    delegate_calls: list[str] = []

    def original_run(module_class: type[BaseModule]):
        return module_class.__dict__["run"]

    def alternate_host_inputs(_self: BaseModule) -> list[dict[str, object]]:
        delegate_calls.append("cis_benchmark.helper")
        return []

    def alternate_make_result(
        self: BaseModule,
        *_args: object,
        **_kwargs: object,
    ) -> ModuleResult:
        delegate_calls.append("html_report.helper")
        return ModuleResult(self.NAME)

    assert intrinsically_local_modules("netforge") == frozenset()
    foreign_policy, foreign_session = _policy(tmp_path / "foreign-policy")
    for module_id, real_class, alternate_name, alternate in (
        ("cis_benchmark", CisBenchmark, "_host_inputs", alternate_host_inputs),
        ("html_report", HtmlReport, "_make_result", alternate_make_result),
    ):
        unbound = type(
            real_class.__name__,
            (BaseModule,),
            {
                "__module__": real_class.__module__,
                "NAME": module_id,
                "run": original_run(real_class),
                alternate_name: alternate,
            },
        )
        loaded_module = sys.modules[real_class.__module__]
        original_export = getattr(loaded_module, real_class.__name__)
        setattr(loaded_module, real_class.__name__, unbound)
        try:
            for supplied_policy in (
                None,
                SimpleNamespace(last_denial_reason=""),
                object.__new__(OutboundPolicy),
                foreign_policy,
            ):
                instance = unbound(
                    config=BaseForgeConfig(
                        target="127.0.0.1",
                        scope=["127.0.0.1/32"],
                    ),
                    scope=Scope(["127.0.0.1/32"]),
                    db_session=SimpleNamespace(),
                    results_dir=tmp_path / module_id,
                )
                instance.outbound_policy = supplied_policy
                result = asyncio.run(instance.run())
                assert result.skipped is True
                assert (
                    result.skip_reason
                    == OutboundReason.AUTHORIZATION_INVALID.value
                )

            missing_policy = unbound(
                config=BaseForgeConfig(
                    target="127.0.0.1",
                    scope=["127.0.0.1/32"],
                ),
                scope=Scope(["127.0.0.1/32"]),
                db_session=SimpleNamespace(),
                results_dir=tmp_path / f"{module_id}-missing-policy",
            )
            del missing_policy.outbound_policy
            missing_result = asyncio.run(missing_policy.run())
            assert missing_result.skipped is True
            assert (
                missing_result.skip_reason
                == OutboundReason.AUTHORIZATION_INVALID.value
            )

            original_module_path = unbound.__module__
            for runtime_module_value in ("fixture_unmanaged", None, 7):
                metadata_changed = unbound(
                    config=BaseForgeConfig(
                        target="127.0.0.1",
                        scope=["127.0.0.1/32"],
                    ),
                    scope=Scope(["127.0.0.1/32"]),
                    db_session=SimpleNamespace(),
                    results_dir=tmp_path / f"{module_id}-metadata-changed",
                )
                setattr(unbound, "__module__", runtime_module_value)
                try:
                    metadata_result = asyncio.run(metadata_changed.run())
                finally:
                    setattr(unbound, "__module__", original_module_path)
                assert metadata_result.skipped is True
                assert (
                    metadata_result.skip_reason
                    == OutboundReason.AUTHORIZATION_INVALID.value
                )
        finally:
            setattr(loaded_module, real_class.__name__, original_export)
    foreign_session.close()
    assert delegate_calls == []


def test_caller_supplied_guard_marker_cannot_skip_module_guard(tmp_path) -> None:
    from common.base_module import BaseModule, ModuleResult
    from common.config import BaseForgeConfig
    from common.scope import Scope
    from netforge.modules.reporting.html_report import HtmlReport

    delegate_calls: list[str] = []

    async def caller_run(self: BaseModule) -> ModuleResult:
        delegate_calls.append("run")
        return ModuleResult(self.NAME)

    setattr(caller_run, "_forge_outbound_guarded", True)
    spoofed = type(
        "HtmlReport",
        (BaseModule,),
        {
            "__module__": HtmlReport.__module__,
            "NAME": "html_report",
            "run": caller_run,
        },
    )
    instance = spoofed(
        config=BaseForgeConfig(
            target="127.0.0.1",
            scope=["127.0.0.1/32"],
        ),
        scope=Scope(["127.0.0.1/32"]),
        db_session=SimpleNamespace(),
        results_dir=tmp_path,
    )

    result = asyncio.run(instance.run())

    assert result.skipped is True
    assert result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value
    assert delegate_calls == []


def test_intermediate_subclass_hook_cannot_suppress_module_guard(tmp_path) -> None:
    from common.base_module import BaseModule, ModuleResult
    from common.config import BaseForgeConfig
    from common.scope import Scope
    from webforge.modules.recon.tech_detect import TechDetect

    delegate_calls: list[str] = []

    class Intermediate(BaseModule):
        def __init_subclass__(cls, **_kwargs: object) -> None:
            return None

    async def caller_run(self: BaseModule) -> ModuleResult:
        delegate_calls.append("run")
        return ModuleResult(self.NAME)

    descendant = type(
        "TechDetect",
        (Intermediate,),
        {
            "__module__": TechDetect.__module__,
            "NAME": "tech_detect",
            "run": caller_run,
        },
    )
    instance = descendant(
        config=BaseForgeConfig(
            target="127.0.0.1",
            scope=["127.0.0.1/32"],
        ),
        scope=Scope(["127.0.0.1/32"]),
        db_session=SimpleNamespace(),
        results_dir=tmp_path,
    )

    result = asyncio.run(instance.run())

    assert result.skipped is True
    assert result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value
    assert delegate_calls == []


def test_module_run_boundary_rejects_class_and_instance_replacement(tmp_path) -> None:
    from common.base_module import BaseModule, ModuleResult
    from common.config import BaseForgeConfig
    from common.scope import Scope
    from webforge.modules.recon.tech_detect import TechDetect

    delegate_calls: list[str] = []

    async def original(self: BaseModule) -> ModuleResult:
        delegate_calls.append("original")
        return ModuleResult(self.NAME)

    async def replacement(self: BaseModule) -> ModuleResult:
        delegate_calls.append("replacement")
        return ModuleResult(self.NAME)

    managed = type(
        "TechDetect",
        (BaseModule,),
        {
            "__module__": TechDetect.__module__,
            "NAME": "tech_detect",
            "run": original,
        },
    )
    instance = managed(
        config=BaseForgeConfig(
            target="127.0.0.1",
            scope=["127.0.0.1/32"],
        ),
        scope=Scope(["127.0.0.1/32"]),
        db_session=SimpleNamespace(),
        results_dir=tmp_path,
    )

    with pytest.raises(AttributeError, match="cannot be replaced"):
        setattr(managed, "run", replacement)
    with pytest.raises(AttributeError, match="cannot be replaced"):
        setattr(instance, "run", replacement)

    result = asyncio.run(instance.run())

    assert result.skipped is True
    assert result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value
    assert delegate_calls == []


def test_inherited_module_run_boundary_rejects_replacement(tmp_path) -> None:
    from common.base_module import BaseModule, ModuleResult
    from common.config import BaseForgeConfig
    from common.scope import Scope
    from webforge.modules.recon.tech_detect import TechDetect

    delegate_calls: list[str] = []

    async def original(self: BaseModule) -> ModuleResult:
        delegate_calls.append("original")
        return ModuleResult(self.NAME)

    async def replacement(self: BaseModule) -> ModuleResult:
        delegate_calls.append("replacement")
        return ModuleResult(self.NAME)

    parent = type(
        "TechDetectParent",
        (BaseModule,),
        {
            "__module__": TechDetect.__module__,
            "NAME": "tech_detect",
            "run": original,
        },
    )
    child = type(
        "TechDetect",
        (parent,),
        {
            "__module__": TechDetect.__module__,
            "NAME": "tech_detect",
        },
    )

    with pytest.raises(AttributeError, match="cannot be replaced"):
        setattr(child, "run", replacement)

    instance = child(
        config=BaseForgeConfig(
            target="127.0.0.1",
            scope=["127.0.0.1/32"],
        ),
        scope=Scope(["127.0.0.1/32"]),
        db_session=SimpleNamespace(),
        results_dir=tmp_path,
    )
    result = asyncio.run(instance.run())

    assert result.skipped is True
    assert result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value
    assert delegate_calls == []


def test_non_plain_async_run_declarations_fail_closed(tmp_path) -> None:
    from common.base_module import BaseModule, ModuleResult
    from common.config import BaseForgeConfig
    from common.scope import Scope
    from webforge.modules.recon.tech_detect import TechDetect

    delegate_calls: list[str] = []

    async def async_run(self: BaseModule) -> ModuleResult:
        delegate_calls.append("async")
        return ModuleResult(self.NAME)

    def sync_run(self: BaseModule) -> ModuleResult:
        delegate_calls.append("sync")
        return ModuleResult(self.NAME)

    def property_run(self: BaseModule):
        delegate_calls.append("property")
        return async_run

    run_values = (
        classmethod(async_run),
        staticmethod(async_run),
        property(property_run),
        sync_run,
    )
    for index, run_value in enumerate(run_values):
        managed = type(
            f"TechDetectInvalid{index}",
            (BaseModule,),
            {
                "__module__": TechDetect.__module__,
                "NAME": "tech_detect",
                "run": run_value,
            },
        )
        instance = managed(
            config=BaseForgeConfig(
                target="127.0.0.1",
                scope=["127.0.0.1/32"],
            ),
            scope=Scope(["127.0.0.1/32"]),
            db_session=SimpleNamespace(),
            results_dir=tmp_path / str(index),
        )
        result = asyncio.run(instance.run())
        assert result.skipped is True
        assert result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value
    assert delegate_calls == []


def test_module_run_descriptor_mutation_cannot_change_guard_identity(tmp_path) -> None:
    from common.base_module import BaseModule, ModuleResult
    from common.config import BaseForgeConfig
    from common.scope import Scope
    from webforge.modules.recon.tech_detect import TechDetect

    delegate_calls: list[str] = []

    async def original(self: BaseModule) -> ModuleResult:
        delegate_calls.append("original")
        return ModuleResult(self.NAME)

    async def replacement(self: BaseModule) -> ModuleResult:
        delegate_calls.append("replacement")
        return ModuleResult(self.NAME)

    managed = type(
        "TechDetect",
        (BaseModule,),
        {
            "__module__": TechDetect.__module__,
            "NAME": "tech_detect",
            "run": original,
        },
    )
    descriptor = managed.__dict__["run"]
    with pytest.raises(AttributeError, match="metadata is immutable"):
        descriptor._declared_engine = "fixture_unmanaged"
    object.__setattr__(descriptor, "_declared_engine", "fixture_unmanaged")
    instance = managed(
        config=BaseForgeConfig(
            target="127.0.0.1",
            scope=["127.0.0.1/32"],
        ),
        scope=Scope(["127.0.0.1/32"]),
        db_session=SimpleNamespace(),
        results_dir=tmp_path,
    )

    result = asyncio.run(instance.run())

    assert result.skipped is True
    assert result.skip_reason == OutboundReason.AUTHORIZATION_INVALID.value
    assert delegate_calls == []


def test_module_subclasses_cannot_override_attribute_lookup() -> None:
    from common.base_module import BaseModule, ModuleResult
    from webforge.modules.recon.tech_detect import TechDetect

    async def caller_run(self: BaseModule) -> ModuleResult:
        return ModuleResult(self.NAME)

    def alternate_lookup(self: BaseModule, name: str):
        return object.__getattribute__(self, name)

    with pytest.raises(TypeError, match="cannot override __getattribute__"):
        type(
            "TechDetect",
            (BaseModule,),
            {
                "__module__": TechDetect.__module__,
                "NAME": "tech_detect",
                "run": caller_run,
                "__getattribute__": alternate_lookup,
            },
        )


def test_context_claim_revalidates_in_place_route_configuration_mutation(
    tmp_path,
) -> None:
    policy, session = _policy(tmp_path, route=_route(), now=NOW)
    expected = _authorization_context()
    assert outbound_context_claim_is_valid(
        session=session,
        context=policy.context,
        expected=expected,
        boundary="webforge.module",
    )
    route = policy.context.route
    assert route is not None

    object.__setattr__(route, "proxy_url", "http://127.0.0.1:18081")

    assert outbound_context_claim_is_valid(
        session=session,
        context=policy.context,
        expected=expected,
        boundary="webforge.module",
    ) is False
    session.close()


def test_remote_dns_route_and_proxy_userinfo_are_rejected() -> None:
    with pytest.raises(ValueError, match="proxy URL userinfo"):
        _route(proxy_url="http://user:CANARY_PROXY_PASSWORD@127.0.0.1:18080")

    decision = evaluate_transport_compatibility(
        route=_route(dns_mode=DnsMode.REMOTE_UNVERIFIED),
        protocol="https",
        tool="aiohttp",
    )
    assert decision.supported is False
    assert decision.reason_code == OutboundReason.DNS_LEAK_UNVERIFIABLE.value

    with pytest.raises(ValueError, match="verification endpoint must use HTTPS"):
        _route(verification_endpoint="http://127.0.0.1:8443/egress")


def test_route_expiry_config_drift_and_cancellation_deny_before_resolution(
    tmp_path,
    monkeypatch,
) -> None:
    clock = [NOW]
    monkeypatch.setattr(
        outbound_policy_module,
        "_system_utc_now",
        lambda: clock[0],
    )
    route = _route(expires_at=NOW + timedelta(seconds=1))
    policy, session = _policy(tmp_path, route=route, now=NOW)
    _preflight(policy, route_identity="fixture")
    clock[0] = NOW + timedelta(seconds=2)
    with pytest.raises(OutboundDenied) as expired:
        policy.prepare_destination(TARGET, action_kind="http.request")
    assert expired.value.reason_code == OutboundReason.ROUTE_EXPIRED.value

    clock[0] = NOW
    slow_route = _route(expires_at=NOW + timedelta(seconds=1))
    slow_policy, slow_session = _policy(
        tmp_path / "slow-route",
        route=slow_route,
        now=NOW,
    )
    _preflight(slow_policy, route_identity="slow-fixture")
    prepared = slow_policy.prepare_destination(TARGET, action_kind="http.request")
    clock[0] = NOW + timedelta(seconds=2)
    with pytest.raises(OutboundDenied) as slow_dns:
        slow_policy.authorize_resolution(prepared, ["127.0.0.1"])
    assert slow_dns.value.reason_code == OutboundReason.ROUTE_EXPIRED.value
    slow_session.close()

    route_values = route.to_dict()
    route_values["proxy_url"] = "http://127.0.0.1:18081"
    with pytest.raises(ValueError, match="digest does not match"):
        ApprovedEgressRoute.from_value(route_values)
    session.close()


def test_route_preflight_honors_cancellation_without_target_transport(tmp_path) -> None:
    cancelled = True
    policy, session = _policy(
        tmp_path,
        route=_route(),
        now=NOW,
        cancellation_check=lambda: cancelled,
    )
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolver")
        await asyncio.Event().wait()
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return TransportResponse(status=200, headers={}, body=b"{}")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(TARGET)
        )
    assert denied.value.reason_code == OutboundReason.CANCELLED.value
    assert "transport" not in calls
    session.close()


def test_route_preflight_uses_one_cumulative_timeout_budget(
    tmp_path,
    monkeypatch,
) -> None:
    policy, session = _policy(
        tmp_path,
        route=_route(),
        now=NOW,
        # Leave deterministic headroom for persisted authority checks while
        # the hanging transport still proves one cumulative request budget.
        timeout_seconds=0.25,
    )
    resolve_calls = 0
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        nonlocal resolve_calls
        resolve_calls += 1
        calls.append(f"resolve:{resolve_calls}")
        if resolve_calls == 2:
            await asyncio.sleep(0.05)
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append(f"transport:{request.prepared.action_kind}")
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.ROUTE_PREFLIGHT_FAILED.value
    assert policy.last_denial_reason == OutboundReason.ROUTE_PREFLIGHT_FAILED.value
    assert calls == [
        "resolve:1",
        "resolve:2",
        "transport:route.preflight",
    ]
    session.close()

    ordering_root = tmp_path / "resolver-evaluation-order"
    ordering_root.mkdir()
    ordering_policy, ordering_session = _policy(
        ordering_root,
        route=_route(),
        now=NOW,
        timeout_seconds=0.1,
    )
    resolver_calls: list[tuple[str, int]] = []
    clock_values = iter((0.0, 1.0))

    async def addresses(host: str) -> list[str]:
        return [host]

    def resolver(host: str, port: int):
        resolver_calls.append((host, port))
        return addresses(host)

    async def exercise() -> None:
        real_get_running_loop = asyncio.get_running_loop
        fake_loop = SimpleNamespace(time=lambda: next(clock_values, 1.0))
        monkeypatch.setattr(
            outbound_policy_module.asyncio,
            "get_running_loop",
            lambda: fake_loop,
        )
        try:
            with pytest.raises(OutboundDenied) as denied:
                await ordering_policy.preflight_route(resolver=resolver)
        finally:
            monkeypatch.setattr(
                outbound_policy_module.asyncio,
                "get_running_loop",
                real_get_running_loop,
            )
        assert denied.value.reason_code == OutboundReason.ROUTE_PREFLIGHT_FAILED.value

    asyncio.run(exercise())
    assert resolver_calls == []
    ordering_session.close()


def test_route_preflight_rejects_and_releases_late_timeout_response(
    tmp_path,
    monkeypatch,
) -> None:
    policy, session = _policy(
        tmp_path,
        route=_route(),
        now=NOW,
        # The wait fixture below injects timeout immediately after transport
        # entry. This setup headroom prevents an overloaded test host from
        # expiring before reaching the cleanup branch under test.
        timeout_seconds=10.0,
    )
    released: list[str] = []
    entered = asyncio.Event()
    timeout_started: list[float] = []
    real_wait = asyncio.wait
    wait_calls = 0
    contended_cleanup_waits = 0

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        response = await _async_route_health_response("127.0.0.1", "late")
        response.release_callback = lambda: released.append("released")
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                return response

    async def deterministic_wait(
        futures,
        *,
        timeout=None,
        return_when=asyncio.ALL_COMPLETED,
    ):
        nonlocal wait_calls, contended_cleanup_waits
        wait_calls += 1
        if wait_calls == 2:
            # Make this a late-response timeout test even when a loaded test
            # host would otherwise exhaust the setup budget before
            # the resolver or transport receives its first scheduler turn.
            await entered.wait()
            timeout_started.append(time.monotonic())
            return set(), set(futures)
        if (
            timeout is not None
            and timeout <= 0.01
            and contended_cleanup_waits < 2
        ):
            # Model the exact contention window that defeated the old fixed
            # two-wait cleanup: these waits expire without yielding to the
            # cancellation-resistant transport.
            contended_cleanup_waits += 1
            return set(), set(futures)
        return await real_wait(
            futures,
            timeout=timeout,
            return_when=return_when,
        )

    async def exercise() -> None:
        monkeypatch.setattr(
            outbound_policy_module.asyncio,
            "wait",
            deterministic_wait,
        )
        try:
            with pytest.raises(OutboundDenied) as denied:
                await policy.preflight_route(
                    resolver=lambda host, port: _async_addresses("127.0.0.1"),
                    transport=transport,
                )
            assert denied.value.reason_code == OutboundReason.ROUTE_PREFLIGHT_FAILED.value
            assert released == ["released"]
            assert policy.route_health is None
            assert contended_cleanup_waits == 1
            assert len(timeout_started) == 1
            assert time.monotonic() - timeout_started[0] < 0.5
        finally:
            monkeypatch.setattr(
                outbound_policy_module.asyncio,
                "wait",
                real_wait,
            )

    asyncio.run(exercise())
    session.close()


def test_route_preflight_releases_malformed_response_before_failure(tmp_path) -> None:
    policy, session = _policy(tmp_path, route=_route(), now=NOW)
    released: list[str] = []

    class BrokenBody:
        def __len__(self) -> int:
            raise RuntimeError("fixture body length failed")

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        return TransportResponse(
            status=200,
            headers={},
            body=BrokenBody(),  # type: ignore[arg-type]
            release_callback=lambda: released.append("released"),
        )

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            policy.preflight_route(
                resolver=lambda host, port: _async_addresses("127.0.0.1"),
                transport=transport,
            )
        )

    assert denied.value.reason_code == OutboundReason.ROUTE_PREFLIGHT_FAILED.value
    assert released == ["released"]
    assert policy.route_health is None
    session.close()


def test_route_preflight_release_callback_failure_is_typed_and_audited(
    tmp_path,
) -> None:
    policy, session = _policy(tmp_path, route=_route(), now=NOW)
    released: list[str] = []

    def broken_release() -> None:
        released.append("released")
        raise RuntimeError("fixture preflight cleanup failed")

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        response = await _async_route_health_response("127.0.0.1", "fixture")
        response.release_callback = broken_release
        return response

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            policy.preflight_route(
                resolver=lambda host, port: _async_addresses("127.0.0.1"),
                transport=transport,
            )
        )

    assert denied.value.reason_code == OutboundReason.TRANSPORT_CLEANUP_FAILED.value
    assert released == ["released"]
    assert policy.route_health is None
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["stage"] == "route_preflight"
    assert (
        decisions[-1]["reason_code"]
        == OutboundReason.TRANSPORT_CLEANUP_FAILED.value
    )
    session.close()


def test_route_preflight_revalidates_live_expiry_after_transport(
    tmp_path,
    monkeypatch,
) -> None:
    route = _route(expires_at=NOW + timedelta(seconds=1))
    initial_policy, session = _policy(tmp_path, route=route, now=NOW)
    clock = [NOW]
    monkeypatch.setattr(
        outbound_policy_module,
        "_system_utc_now",
        lambda: clock[0],
    )
    policy = OutboundPolicy(initial_policy.context)

    async def resolver(host: str, port: int) -> list[str]:
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        clock[0] = NOW + timedelta(seconds=2)
        return await _async_route_health_response("127.0.0.1", "expired-identity")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            policy.preflight_route(
                resolver=resolver,
                transport=transport,
            )
        )

    assert denied.value.reason_code == OutboundReason.ROUTE_EXPIRED.value
    assert policy.route_health is None
    assert list_route_health_evidence(session) == []
    session.close()


def test_proxy_credential_canary_never_appears_in_serialized_route_or_audit(tmp_path) -> None:
    route = _route(proxy_credential_reference="cred:fixture-proxy")
    policy, session = _policy(
        tmp_path,
        route=route,
        context_overrides={"safety_mode": SafetyMode.LOCAL_LAB},
        now=NOW,
    )
    decision = evaluate_transport_compatibility(
        route=policy.context.route,
        protocol="https",
        tool="aiohttp",
    )
    assert decision.supported is False

    rendered = str(route.to_safe_dict()) + str(list_route_health_evidence(session))
    assert "CANARY" not in rendered
    assert "proxy_credential_reference" not in route.to_safe_dict()
    assert "cred:fixture-proxy" not in rendered
    session.close()


def test_route_parser_rejects_unknown_fields_and_preserves_exact_version() -> None:
    route = _route()
    serialized = route.to_dict()
    parsed = ApprovedEgressRoute.from_value(serialized)
    assert parsed == route

    serialized["unknown"] = "value"
    with pytest.raises(ValueError, match="incomplete or unknown"):
        ApprovedEgressRoute.from_value(serialized)

    wrong_version = route.to_dict()
    wrong_version["schema_version"] = "latest"
    with pytest.raises(ValueError, match="unsupported approved route schema"):
        ApprovedEgressRoute.from_value(wrong_version)


def test_browser_route_is_unsupported_before_browser_or_navigation(tmp_path) -> None:
    from webforge.core.browser_engine import BrowserEngine

    route = _route(allowed_tools=("aiohttp", "playwright"))
    policy, session = _policy(
        tmp_path,
        route=route,
        allowed_scope=["127.0.0.0/8", "https://127.0.0.1:8443"],
        excluded_scope=["127.0.0.2/32"],
        now=NOW,
    )
    engine = BrowserEngine(tmp_path, outbound_policy=policy)
    with pytest.raises(OutboundDenied) as denied:
        engine._prepare_browser_policy()
    assert denied.value.reason_code == OutboundReason.UNSUPPORTED_ROUTE_TRANSPORT.value
    session.close()


def test_ssh_unknown_host_keys_are_rejected_and_ambient_keys_are_disabled(monkeypatch) -> None:
    from netforge.core.cred_transport import SSHTransport, ScanCredential

    calls: dict[str, object] = {}

    class RejectPolicy:
        pass

    class FakeClient:
        def load_system_host_keys(self) -> None:
            calls["loaded"] = True

        def set_missing_host_key_policy(self, policy: object) -> None:
            calls["policy"] = policy

        def connect(self, **kwargs: object) -> None:
            calls["connect"] = kwargs

    fake_paramiko = SimpleNamespace(
        SSHClient=FakeClient,
        RejectPolicy=RejectPolicy,
        RSAKey=SimpleNamespace(),
        Ed25519Key=SimpleNamespace(),
        ECDSAKey=SimpleNamespace(),
        SSHException=RuntimeError,
    )
    monkeypatch.setitem(sys.modules, "paramiko", fake_paramiko)

    transport = SSHTransport()
    _client, connect = transport._build_connect_plan(
        "127.0.0.1",
        22,
        ScanCredential(
            transport="ssh",
            username="fixture",
            password="CANARY_SSH_PASSWORD",
            host_pattern="127.0.0.1",
        ),
        fake_paramiko,
    )

    assert calls["loaded"] is True
    assert isinstance(calls["policy"], RejectPolicy)
    assert connect["allow_agent"] is False
    assert connect["look_for_keys"] is False
    assert "connect" not in calls

    with pytest.raises(OutboundDenied) as denied:
        transport._connect_sync(
            "127.0.0.1",
            22,
            ScanCredential(
                transport="ssh",
                username="fixture",
                password="CANARY_SSH_PASSWORD",
                host_pattern="127.0.0.1",
            ),
        )
    assert denied.value.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value
    assert "connect" not in calls


def test_winrm_requires_https_and_certificate_validation(monkeypatch) -> None:
    from netforge.core.cred_transport import ScanCredential, WinRMTransport

    captured: dict[str, object] = {}

    class FakeResult:
        status_code = 0
        std_err = b""

    class FakeSession:
        def __init__(self, endpoint: str, **kwargs: object) -> None:
            captured["endpoint"] = endpoint
            captured.update(kwargs)

        def run_ps(self, command: str) -> FakeResult:
            captured["command"] = command
            return FakeResult()

    monkeypatch.setitem(sys.modules, "winrm", SimpleNamespace(Session=FakeSession))
    credential = ScanCredential(
        transport="winrm",
        username="fixture",
        password="CANARY_WINRM_PASSWORD",
        port=5986,
        host_pattern="127.0.0.1",
    )

    transport = WinRMTransport()
    endpoint, username, session_kwargs = transport._build_session_plan(
        "127.0.0.1",
        5986,
        credential,
    )
    assert endpoint == "https://127.0.0.1:5986/wsman"
    assert username == "fixture"
    assert session_kwargs["server_cert_validation"] == "validate"
    assert captured == {}

    with pytest.raises(OutboundDenied) as denied:
        transport._connect_sync("127.0.0.1", 5986, credential)
    assert denied.value.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value
    assert captured == {}

    with pytest.raises(RuntimeError, match="HTTPS port 5986"):
        transport._build_session_plan("127.0.0.1", 5985, credential)


def test_legacy_credential_transports_are_inert_at_every_delegate_boundary(
    monkeypatch,
) -> None:
    from netforge.core.cred_transport import (
        SSHTransport,
        SNMPv3Transport,
        ScanCredential,
        TransportManager,
        WinRMTransport,
    )

    delegate_calls: list[str] = []

    class FakeDelegate:
        def connect(self, **_kwargs: object) -> None:
            delegate_calls.append("ssh.connect")

        def exec_command(self, *_args: object, **_kwargs: object) -> object:
            delegate_calls.append("ssh.exec_command")
            return object()

        def open_sftp(self) -> object:
            delegate_calls.append("ssh.open_sftp")
            return object()

        def run_ps(self, _command: str) -> object:
            delegate_calls.append("winrm.run_ps")
            return object()

        def run_cmd(self, _command: str) -> object:
            delegate_calls.append("winrm.run_cmd")
            return object()

        def close(self) -> None:
            delegate_calls.append("cleanup.close")

    class RejectPolicy:
        pass

    fake_paramiko = SimpleNamespace(
        SSHClient=FakeDelegate,
        RejectPolicy=RejectPolicy,
        RSAKey=SimpleNamespace(),
        Ed25519Key=SimpleNamespace(),
        ECDSAKey=SimpleNamespace(),
        SSHException=RuntimeError,
    )

    def fake_winrm_session(*_args: object, **_kwargs: object) -> FakeDelegate:
        delegate_calls.append("winrm.Session")
        return FakeDelegate()

    monkeypatch.setitem(sys.modules, "paramiko", fake_paramiko)
    monkeypatch.setitem(
        sys.modules,
        "winrm",
        SimpleNamespace(Session=fake_winrm_session),
    )

    ssh_credential = ScanCredential(
        transport="ssh",
        username="fixture",
        password="SYNTHETIC_SSH_SECRET",
        host_pattern="192.0.2.44",
    )
    snmp_credential = ScanCredential(
        transport="snmpv3",
        username="fixture",
        auth_passphrase="SYNTHETIC_SNMP_AUTH",
        priv_passphrase="SYNTHETIC_SNMP_PRIV",
        host_pattern="192.0.2.44",
    )
    winrm_credential = ScanCredential(
        transport="winrm",
        username="fixture",
        password="SYNTHETIC_WINRM_SECRET",
        port=5986,
        host_pattern="192.0.2.44",
    )

    def assert_denied(call) -> None:
        with pytest.raises(OutboundDenied) as denied:
            call()
        assert denied.value.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value

    async def exercise() -> None:
        manager = TransportManager()
        manager.add_credential(ssh_credential)
        manager.add_credential(snmp_credential)
        manager.add_credential(winrm_credential)

        for operation in (
            manager.get_ssh_session("192.0.2.44", 22),
            manager.get_snmpv3_session("192.0.2.44", 161),
            manager.get_winrm_session("192.0.2.44", 5986),
        ):
            with pytest.raises(OutboundDenied) as denied:
                await operation
            assert denied.value.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value

        ssh = SSHTransport()
        snmp = SNMPv3Transport()
        winrm = WinRMTransport()
        async_operations = (
            ssh.connect("198.51.100.9", ssh_credential, 22),
            ssh.execute({"client": FakeDelegate(), "host": "198.51.100.9"}, "id"),
            ssh.read_file({"client": FakeDelegate()}, "/etc/hosts"),
            snmp.connect("198.51.100.9", snmp_credential, 161),
            snmp.execute({"host": "198.51.100.9"}, "fixture"),
            snmp.snmp_get({"host": "198.51.100.9"}, "1.3.6.1"),
            snmp.snmp_walk({"host": "198.51.100.9"}, "1.3.6.1"),
            snmp.read_file({"host": "198.51.100.9"}, "/fixture"),
            winrm.connect("198.51.100.9", winrm_credential, 5986),
            winrm.execute({"session": FakeDelegate()}, "$true"),
            winrm.execute_cmd({"session": FakeDelegate()}, "whoami"),
            winrm.read_file({"session": FakeDelegate()}, "C:\\fixture"),
        )
        for operation in async_operations:
            with pytest.raises(OutboundDenied) as denied:
                await operation
            assert denied.value.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value

        await manager.close_all()

    asyncio.run(exercise())

    ssh = SSHTransport()
    snmp = SNMPv3Transport()
    winrm = WinRMTransport()
    delegate = FakeDelegate()
    assert_denied(lambda: ssh._connect_sync("198.51.100.9", 22, ssh_credential))
    assert_denied(lambda: ssh._exec_sync(delegate, "id"))
    assert_denied(lambda: ssh._read_file_sync(delegate, "/etc/hosts"))
    assert_denied(lambda: snmp._snmp_get_sync({"host": "198.51.100.9"}, "1.3.6.1"))
    assert_denied(
        lambda: snmp._snmp_walk_sync(
            {"host": "198.51.100.9"},
            "1.3.6.1",
            10,
        )
    )
    assert_denied(lambda: winrm._connect_sync("198.51.100.9", 5986, winrm_credential))
    assert_denied(lambda: winrm._exec_sync(delegate, "$true"))
    assert_denied(lambda: winrm._exec_cmd_sync(delegate, "whoami"))
    assert delegate_calls == []


def test_nuclei_remote_update_helpers_are_inert_before_url_or_token_use(
    monkeypatch,
) -> None:
    import urllib.request

    from common.intel.nuclei_sync import (
        NucleiSync,
        _fetch_raw_content,
        _github_api,
    )

    delegate_calls: list[object] = []

    def fake_urlopen(*args: object, **kwargs: object) -> object:
        delegate_calls.append((args, kwargs))
        raise AssertionError("remote update delegate must remain unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    async def exercise() -> None:
        operations = (
            _github_api("/fixture", token="SYNTHETIC_GITHUB_SECRET"),
            _fetch_raw_content(
                "https://raw.githubusercontent.test/fixture",
                token="SYNTHETIC_GITHUB_SECRET",
            ),
            NucleiSync()._sync_github(),
            NucleiSync().sync(object()),  # type: ignore[arg-type]
        )
        for operation in operations:
            with pytest.raises(OutboundDenied) as denied:
                await operation
            assert denied.value.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value

    asyncio.run(exercise())
    assert delegate_calls == []


def test_legacy_netforge_cve_updaters_are_inert_before_network_or_storage(
    monkeypatch,
    tmp_path,
) -> None:
    import aiohttp

    from netforge.data.cve_db import CVEDatabase, update_cve_db

    delegate_calls: list[object] = []

    class FailClientSession:
        def __init__(self, *args: object, **kwargs: object) -> None:
            delegate_calls.append((args, kwargs))
            raise AssertionError("legacy CVE updater must remain unreachable")

    monkeypatch.setattr(aiohttp, "ClientSession", FailClientSession)
    db_path = tmp_path / "local-cve-cache.db"

    async def exercise() -> None:
        db = CVEDatabase(db_path)
        try:
            with pytest.raises(OutboundDenied) as denied:
                await db.update(
                    api_key="SYNTHETIC_NVD_SECRET",
                    years=[2026],
                )
            assert denied.value.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value
        finally:
            db.close()
        with pytest.raises(OutboundDenied) as denied:
            await update_cve_db(
                api_key="SYNTHETIC_NVD_SECRET",
                db_path=str(db_path),
                years=[2026],
            )
        assert denied.value.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value

    asyncio.run(exercise())
    assert delegate_calls == []


def test_wildcard_credential_bindings_are_rejected() -> None:
    from netforge.core.cred_transport import ScanCredential, TransportManager

    with pytest.raises(ValueError, match="exact authorized host"):
        TransportManager().add_credential(
            ScanCredential(
                transport="ssh",
                username="fixture",
                password="CANARY_PASSWORD",
                host_pattern="*",
            )
        )


def test_supported_module_manifest_contains_no_direct_client_bypass() -> None:
    from aiforge.aiforge import MODULE_MAP as AI_MODULES
    from netforge.netforge import MODULE_MAP as NET_MODULES
    from webforge.webforge import MODULE_MAP as WEB_MODULES

    root = Path(__file__).resolve().parents[1]
    maps = {
        "aiforge": AI_MODULES,
        "netforge": NET_MODULES,
        "webforge": WEB_MODULES,
    }
    forbidden = (
        "aiohttp.ClientSession(",
        "requests.get(",
        "requests.post(",
        "requests.request(",
        "httpx.Client(",
        "httpx.AsyncClient(",
        "urllib.request.urlopen(",
        "socket.create_connection(",
        "socket.socket(",
        "asyncio.open_connection(",
        "paramiko.AutoAddPolicy(",
        # FPReducer's active re-probes still use its legacy urllib helpers.
        # A module may retain non-network confidence helpers, but it must not
        # be advertised as policy-supported while invoking that path.
        "self._fp.verify(",
    )
    for engine, module_map in maps.items():
        validated_modules = policy_supported_modules(
            engine
        ) | intrinsically_local_modules(engine)
        for module_id in validated_modules:
            module_path = module_map.get(module_id)
            assert module_path, f"supported module missing from registry: {engine}:{module_id}"
            path = root / (module_path.replace(".", "/") + ".py")
            source = path.read_text(encoding="utf-8")
            for pattern in forbidden:
                assert pattern not in source, f"{engine}:{module_id} bypasses policy via {pattern}"
