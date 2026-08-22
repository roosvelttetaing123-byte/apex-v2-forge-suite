from __future__ import annotations

import asyncio
import gc
import ipaddress
import inspect
import ssl
import time
import weakref
from collections.abc import ItemsView
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

import common.outbound_policy as outbound_policy_module
from common.action_authorization import (
    DEFAULT_AUTHORIZATION_TTL_SECONDS,
    MAX_FUTURE_SKEW_SECONDS,
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    consume_authorization,
    derive_authorization,
    issue_authorization,
)
from common.confirm_gate import ActionConfirmation
from common.db import append_outbound_decision, create_db, list_outbound_decisions
from common.outbound_policy import (
    CredentialBinding,
    DatabaseOutboundAuditSink,
    HttpTransportRequest,
    MAX_OUTBOUND_RESPONSE_BYTES,
    OutboundContext,
    OutboundDenied,
    OutboundPolicy,
    OutboundReason,
    PolicyBoundTransport,
    PolicyHttpClient,
    PolicyResponse,
    TransportResponse,
    _PinnedResolver,
    _OUTBOUND_CONTEXT_PROVENANCE,
    _OUTBOUND_POLICY_PROVENANCE,
    _outbound_context_claim_record,
    _persist_outbound_context_claim,
    cookie_provenance_matches_destination,
    normalize_destination,
    outbound_context_claim_is_valid,
    strip_origin_bound_secrets,
)


NOW = datetime.now(timezone.utc).replace(microsecond=0)
TARGET = "https://127.0.0.1:8443/start"
ALLOWED_SCOPE = ["127.0.0.1/32", "https://127.0.0.1:8443"]


def test_test_harness_blocks_non_loopback_socket_attempts() -> None:
    import socket

    with pytest.raises(AssertionError, match="non-loopback socket"):
        socket.create_connection(("192.0.2.10", 443), timeout=0.01)


def test_test_harness_blocks_libc_dns_and_udp_sendmsg() -> None:
    import socket

    with pytest.raises(AssertionError, match="DNS/network access"):
        socket.gethostbyname("fixture.invalid")
    with pytest.raises(AssertionError, match="DNS/network access"):
        socket.gethostbyname_ex("fixture.invalid")
    with pytest.raises(AssertionError, match="non-loopback socket"):
        socket.gethostbyaddr("192.0.2.10")
    with pytest.raises(AssertionError, match="non-loopback socket"):
        socket.getnameinfo(("192.0.2.10", 443), socket.NI_NUMERICHOST)
    if hasattr(socket.socket, "sendmsg"):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
            with pytest.raises(AssertionError, match="non-loopback socket"):
                datagram.sendmsg([b"fixture"], [], 0, ("192.0.2.10", 9))


def test_outbound_context_rejects_unbounded_response_limit(tmp_path) -> None:
    with pytest.raises(ValueError, match="outside the supported bound"):
        _policy(
            tmp_path,
            max_response_bytes=MAX_OUTBOUND_RESPONSE_BYTES + 1,
        )


@pytest.mark.parametrize(
    "malformed_field",
    ["host_only", "secure"],
)
def test_malformed_cookie_provenance_flags_fail_closed(malformed_field: str) -> None:
    provenance: dict[str, object] = {
        "origin": "https://app.example.com:443",
        "domain": "app.example.com",
        "host_only": True,
        "path": "/",
        "secure": True,
    }
    provenance[malformed_field] = "true"

    assert cookie_provenance_matches_destination(
        provenance,
        "https://app.example.com/",
    ) is False

    for submitted, wire_url in (
        (
            "https://127.0.0.1:8443/admin/../public",
            "https://127.0.0.1:8443/public",
        ),
        (
            "https://127.0.0.1:8443/admin/%2e%2e/public",
            "https://127.0.0.1:8443/public",
        ),
        (
            "https://127.0.0.1:8443/admin/%2E%2E/public",
            "https://127.0.0.1:8443/public",
        ),
        (
            "https://127.0.0.1:8443/admin/%2e./public",
            "https://127.0.0.1:8443/public",
        ),
        (
            "https://127.0.0.1:8443/admin/.%2e/public",
            "https://127.0.0.1:8443/public",
        ),
        (
            "https://127.0.0.1:8443/a%2fb?marker=%7e&slash=%2f",
            "https://127.0.0.1:8443/a%2Fb?marker=~&slash=/",
        ),
        (
            "https://127.0.0.1:8443/public?marker=%ZZ",
            "https://127.0.0.1:8443/public?marker=%25ZZ",
        ),
    ):
        normalized = normalize_destination(submitted)
        assert normalized.url == wire_url
        assert normalized.destination_ref == normalize_destination(wire_url).destination_ref


def test_explicitly_protected_safe_header_is_stripped_cross_origin() -> None:
    binding = CredentialBinding.for_origin(
        "https://app.example.com",
        protected_headers=("accept",),
    )

    retained = strip_origin_bound_secrets(
        {
            "Accept": "Bearer CANARY_EXPLICIT_SECRET",
            "User-Agent": "Forge fixture",
        },
        destination_origin=normalize_destination("https://api.example.com").origin,
        binding=binding,
    )

    assert retained == {}


def test_caller_cannot_rebind_credential_origin(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolver")
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    binding = CredentialBinding.for_origin("https://127.0.0.2:8443/")
    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(
                TARGET,
                headers={"Authorization": "Bearer CANARY_REBIND"},
                credential_binding=binding,
            )
        )

    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    assert calls == []
    session.close()


def _authorization_context(**overrides: object) -> AuthorizationContext:
    values: dict[str, object] = {
        "tenant_id": "tenant-lab",
        "engagement_id": "engagement-lab",
        "run_id": "run-outbound",
        "job_id": "job-outbound",
        "operator_id": "operator-lab",
        "operator_role": OperatorRole.OPERATOR,
        "action_kind": "module.execute",
        "engine": "webforge",
        "module_id": "fixture_module",
        "requested_target": TARGET,
        "resolved_target": TARGET,
        "allowed_scope": ALLOWED_SCOPE,
        "excluded_scope": [],
        "scope_policy_version": "scope-policy-v1",
        "safety_mode": SafetyMode.ACTIVE,
        "confirmation_method": ConfirmationMethod.CLI_PROMPT,
        "confirmed_by": "operator-lab",
    }
    values.update(overrides)
    return AuthorizationContext(**values)


def _consumed_envelope(session, context: AuthorizationContext) -> ActionAuthorizationEnvelope:
    issued = issue_authorization(
        session=session,
        context=context,
        confirmation=ActionConfirmation.create(
            job_id=context.job_id,
            target=context.resolved_target,
            engine=context.engine,
            action=context.action_kind,
            issued_at=NOW,
        ),
        now=NOW,
    )
    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=context,
        boundary="webforge.module",
        now=NOW,
    )
    assert consumed.allowed
    return issued.envelope


def _forged_outbound_context(
    *,
    envelope: ActionAuthorizationEnvelope,
    audit_sink: DatabaseOutboundAuditSink,
    **overrides: object,
) -> OutboundContext:
    """Build an adversarial object without invoking the protected factory."""
    context = object.__new__(OutboundContext)
    values: dict[str, object] = {
        "envelope": envelope,
        "authorized_target": TARGET,
        "allowed_scope": tuple(ALLOWED_SCOPE),
        "excluded_scope": (),
        "audit_sink": audit_sink,
        "route": None,
        "transport_tool": "aiohttp",
        "max_redirects": 5,
        "max_retries": 2,
        "timeout_seconds": 30.0,
        "max_response_bytes": 10 * 1024 * 1024,
        "permit_ttl_seconds": 15,
        "cancellation_check": None,
        "attempt_limiter": None,
        "lab_only_insecure_tls": False,
        "insecure_tls_target": "",
        "insecure_tls_authorization": None,
    }
    values.update(overrides)
    for name, value in values.items():
        object.__setattr__(context, name, value)
    return context


def test_outbound_context_rejects_public_and_unconsumed_construction(tmp_path) -> None:
    import common.outbound_policy as outbound_module

    session = create_db(tmp_path / "unconsumed-context.db")
    context = _authorization_context()
    issued = issue_authorization(
        session=session,
        context=context,
        confirmation=ActionConfirmation.create(
            job_id=context.job_id,
            target=context.resolved_target,
            engine=context.engine,
            action=context.action_kind,
            issued_at=NOW,
        ),
        now=NOW,
    )
    sink = DatabaseOutboundAuditSink(session)
    assert not hasattr(outbound_module, "_issue_outbound_context_nonce")
    assert not hasattr(outbound_module, "_consume_outbound_context_nonce")

    with pytest.raises(OutboundDenied) as direct:
        OutboundContext(
            envelope=issued.envelope,
            authorized_target=TARGET,
            allowed_scope=tuple(ALLOWED_SCOPE),
            excluded_scope=(),
            audit_sink=sink,
            _construction_nonce="caller-supplied-proof",
        )
    assert direct.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value

    with pytest.raises(OutboundDenied) as unconsumed:
        OutboundContext.from_consumed_authorization(
            session=session,
            envelope=issued.envelope,
            expected=context,
            boundary="webforge.module",
            authorized_target=TARGET,
            allowed_scope=ALLOWED_SCOPE,
            excluded_scope=[],
            audit_sink=sink,
        )
    assert unconsumed.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    session.close()


@pytest.mark.parametrize("consume_envelope", [False, True])
def test_policy_rejects_forged_context_without_factory_claim_before_callbacks(
    tmp_path,
    consume_envelope: bool,
) -> None:
    session = create_db(tmp_path / f"forged-policy-{consume_envelope}.db")
    expected = _authorization_context()
    issued = issue_authorization(
        session=session,
        context=expected,
        confirmation=ActionConfirmation.create(
            job_id=expected.job_id,
            target=expected.resolved_target,
            engine=expected.engine,
            action=expected.action_kind,
            issued_at=NOW,
        ),
        now=NOW,
    )
    if consume_envelope:
        consumed = consume_authorization(
            session=session,
            envelope=issued.envelope,
            expected=expected,
            boundary="webforge.module",
            now=NOW,
        )
        assert consumed.allowed
    forged = _forged_outbound_context(
        envelope=issued.envelope,
        audit_sink=DatabaseOutboundAuditSink(session),
    )
    assert not outbound_context_claim_is_valid(
        session=session,
        context=forged,
        expected=expected,
        boundary="webforge.module",
    )
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append(f"resolver:{host}:{port}")
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append(f"transport:{request.url}")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    with pytest.raises(OutboundDenied) as denied:
        policy = OutboundPolicy(forged)
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    assert calls == []
    session.close()


def test_policy_context_replacement_is_denied_before_callbacks(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    forged = _forged_outbound_context(
        envelope=policy.context.envelope,
        audit_sink=policy.context.audit_sink,
    )
    policy.context = forged
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append(f"resolver:{host}:{port}")
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append(f"transport:{request.url}")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    assert calls == []
    session.close()


def test_policy_rechecks_authority_after_limiter_and_resolution(tmp_path) -> None:
    calls: list[str] = []
    policy_holder: dict[str, OutboundPolicy] = {}
    forged_holder: dict[str, OutboundContext] = {}

    async def limiter() -> None:
        calls.append("limiter")
        policy_holder["policy"].context = forged_holder["context"]

    policy, session = _policy(tmp_path, attempt_limiter=limiter)
    policy_holder["policy"] = policy
    forged_holder["context"] = _forged_outbound_context(
        envelope=policy.context.envelope,
        audit_sink=policy.context.audit_sink,
        attempt_limiter=limiter,
    )

    async def resolver(host: str, port: int) -> list[str]:
        calls.append(f"resolver:{host}:{port}")
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append(f"transport:{request.url}")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    client = PolicyHttpClient(policy, resolver=resolver, transport=transport)
    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(client.get(TARGET))

    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    assert calls == ["limiter"]
    session.close()


def test_policy_rechecks_authority_after_resolver_before_transport(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    forged = _forged_outbound_context(
        envelope=policy.context.envelope,
        audit_sink=policy.context.audit_sink,
    )
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append(f"resolver:{host}:{port}")
        policy.context = forged
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append(f"transport:{request.url}")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    client = PolicyHttpClient(policy, resolver=resolver, transport=transport)
    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(client.get(TARGET))

    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    assert calls == ["resolver:127.0.0.1:8443"]
    session.close()


def test_private_claim_persistence_rejects_issued_but_unconsumed_context(
    tmp_path,
) -> None:
    session = create_db(tmp_path / "unconsumed-private-claim.db")
    expected = _authorization_context()
    issued = issue_authorization(
        session=session,
        context=expected,
        confirmation=ActionConfirmation.create(
            job_id=expected.job_id,
            target=expected.resolved_target,
            engine=expected.engine,
            action=expected.action_kind,
            issued_at=NOW,
        ),
        now=NOW,
    )
    forged = _forged_outbound_context(
        envelope=issued.envelope,
        audit_sink=DatabaseOutboundAuditSink(session),
    )

    with pytest.raises(OutboundDenied) as denied:
        _persist_outbound_context_claim(
            session=session,
            context=forged,
            expected=expected,
            boundary="webforge.module",
            now=NOW,
        )

    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    assert list_outbound_decisions(session) == []
    session.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_redirects", 999),
        ("max_response_bytes", MAX_OUTBOUND_RESPONSE_BYTES + 1),
    ],
)
def test_private_claim_persistence_rejects_forged_unbounded_context(
    tmp_path,
    field: str,
    value: int,
) -> None:
    session = create_db(tmp_path / f"forged-{field}-claim.db")
    expected = _authorization_context()
    envelope = _consumed_envelope(session, expected)
    forged = _forged_outbound_context(
        envelope=envelope,
        audit_sink=DatabaseOutboundAuditSink(session),
        **{field: value},
    )

    with pytest.raises(OutboundDenied) as denied:
        _persist_outbound_context_claim(
            session=session,
            context=forged,
            expected=expected,
            boundary="webforge.module",
            now=NOW,
        )

    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    assert list_outbound_decisions(session) == []
    assert outbound_context_claim_is_valid(
        session=session,
        context=forged,
        expected=expected,
        boundary="webforge.module",
    ) is False
    session.close()


def test_private_claim_persistence_does_not_register_forged_consumed_context(
    tmp_path,
) -> None:
    session = create_db(tmp_path / "forged-consumed-private-claim.db")
    expected = _authorization_context()
    envelope = _consumed_envelope(session, expected)
    forged = _forged_outbound_context(
        envelope=envelope,
        audit_sink=DatabaseOutboundAuditSink(session),
    )

    _persist_outbound_context_claim(
        session=session,
        context=forged,
        expected=expected,
        boundary="webforge.module",
        now=NOW,
    )

    assert len(list_outbound_decisions(session)) == 1
    assert outbound_context_claim_is_valid(
        session=session,
        context=forged,
        expected=expected,
        boundary="webforge.module",
    ) is False
    session.close()


def test_private_claim_and_registration_helpers_cannot_mint_forged_context(
    tmp_path,
) -> None:
    session = create_db(tmp_path / "forged-private-registration.db")
    expected = _authorization_context()
    envelope = _consumed_envelope(session, expected)
    forged = _forged_outbound_context(
        envelope=envelope,
        audit_sink=DatabaseOutboundAuditSink(session),
    )

    _persist_outbound_context_claim(
        session=session,
        context=forged,
        expected=expected,
        boundary="webforge.module",
        now=NOW,
    )

    # Context provenance is minted only inside the two class operations that
    # create a root or a narrowed context.  Persisting the canonical claim
    # leaves this caller-created object untrusted, and there is no separate
    # callable that can register it afterward.
    assert not hasattr(outbound_policy_module, "_register_outbound_context")
    assert not hasattr(
        outbound_policy_module,
        "_register_narrowed_outbound_context",
    )
    assert outbound_context_claim_is_valid(
        session=session,
        context=forged,
        expected=expected,
        boundary="webforge.module",
    ) is False
    with pytest.raises(OutboundDenied) as denied:
        OutboundPolicy(forged)

    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    session.close()


def test_caller_inserted_claim_cannot_become_valid_after_later_consumption(
    tmp_path,
) -> None:
    session = create_db(tmp_path / "preinserted-context-claim.db")
    expected = _authorization_context()
    issued = issue_authorization(
        session=session,
        context=expected,
        confirmation=ActionConfirmation.create(
            job_id=expected.job_id,
            target=expected.resolved_target,
            engine=expected.engine,
            action=expected.action_kind,
            issued_at=NOW,
        ),
        now=NOW,
    )
    forged = _forged_outbound_context(
        envelope=issued.envelope,
        audit_sink=DatabaseOutboundAuditSink(session),
    )
    append_outbound_decision(
        session,
        _outbound_context_claim_record(
            context=forged,
            boundary="webforge.module",
            now=NOW,
        ),
    )
    assert outbound_context_claim_is_valid(
        session=session,
        context=forged,
        expected=expected,
        boundary="webforge.module",
    ) is False

    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=expected,
        boundary="webforge.module",
        now=NOW,
    )
    assert consumed.allowed
    assert outbound_context_claim_is_valid(
        session=session,
        context=forged,
        expected=expected,
        boundary="webforge.module",
    ) is False
    session.close()


def test_outbound_context_claim_is_single_use_and_timeout_clone_is_bound(
    tmp_path,
) -> None:
    session = create_db(tmp_path / "single-context-claim.db")
    expected = _authorization_context()
    envelope = _consumed_envelope(session, expected)
    common = {
        "session": session,
        "envelope": envelope,
        "expected": expected,
        "boundary": "webforge.module",
        "authorized_target": TARGET,
        "allowed_scope": ALLOWED_SCOPE,
        "excluded_scope": [],
        "audit_sink": DatabaseOutboundAuditSink(session),
    }

    context = OutboundContext.from_consumed_authorization(**common)
    assert outbound_context_claim_is_valid(
        session=session,
        context=context,
        expected=expected,
        boundary="webforge.module",
    )
    with pytest.raises(OutboundDenied) as replayed:
        OutboundContext.from_consumed_authorization(**common)
    assert replayed.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value

    with pytest.raises(OutboundDenied) as replaced:
        replace(context, authorized_target="https://127.0.0.1:9443/other")
    assert replaced.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value

    narrowed = context.with_timeout_seconds(10.0)
    assert narrowed is not context
    assert narrowed.envelope is context.envelope
    assert narrowed.authorized_target == context.authorized_target
    assert narrowed.allowed_scope == context.allowed_scope
    assert narrowed.excluded_scope == context.excluded_scope
    assert narrowed.audit_sink is context.audit_sink
    assert narrowed.route is context.route
    assert narrowed.insecure_tls_authorization is context.insecure_tls_authorization
    assert narrowed.timeout_seconds == 10.0
    assert outbound_context_claim_is_valid(
        session=session,
        context=narrowed,
        expected=expected,
        boundary="webforge.module",
    )
    narrowed_policy = OutboundPolicy(narrowed)
    assert narrowed_policy.fork(narrowed).context is narrowed
    with pytest.raises(ValueError, match="cannot broaden"):
        narrowed.with_timeout_seconds(context.timeout_seconds)

    claims = [
        record
        for record in list_outbound_decisions(session)
        if record["stage"] == "context_construction"
    ]
    assert len(claims) == 1
    assert claims[0]["authorization_decision_id"] == envelope.decision_id
    assert claims[0]["reason_code"] == OutboundReason.ALLOWED.value
    session.close()


def test_policy_rejects_unrelated_valid_context_lineage(tmp_path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first, first_session = _policy(first_root)
    second, second_session = _policy(second_root)

    with pytest.raises(OutboundDenied) as denied:
        first.fork(second.context)

    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    first_session.close()
    second_session.close()


def test_policy_rejects_object_new_policy_at_client_boundary(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    forged = object.__new__(OutboundPolicy)
    for name in OutboundPolicy.__slots__:
        if name != "__weakref__":
            object.__setattr__(forged, name, getattr(policy, name))

    with pytest.raises(OutboundDenied) as denied:
        PolicyHttpClient(forged)

    assert not hasattr(outbound_policy_module, "_register_outbound_policy")
    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    session.close()


def test_context_and_policy_authority_registries_do_not_retain_instances(
    tmp_path,
) -> None:
    policy, session = _policy(tmp_path)
    context_reference = weakref.ref(policy.context)
    policy_reference = weakref.ref(policy)
    context_id = id(policy.context)
    policy_id = id(policy)
    assert context_id in _OUTBOUND_CONTEXT_PROVENANCE
    assert policy_id in _OUTBOUND_POLICY_PROVENANCE

    del policy
    gc.collect()

    assert policy_reference() is None
    assert context_reference() is None
    assert policy_id not in _OUTBOUND_POLICY_PROVENANCE
    assert context_id not in _OUTBOUND_CONTEXT_PROVENANCE
    session.close()


def test_policy_context_claim_survives_factory_session_close(tmp_path) -> None:
    session = create_db(tmp_path / "closed-factory-session.db")
    expected = _authorization_context()
    envelope = _consumed_envelope(session, expected)
    context = OutboundContext.from_consumed_authorization(
        session=session,
        envelope=envelope,
        expected=expected,
        boundary="webforge.module",
        authorized_target=TARGET,
        allowed_scope=ALLOWED_SCOPE,
        excluded_scope=[],
        audit_sink=DatabaseOutboundAuditSink(session),
    )
    session.close()

    policy = OutboundPolicy(context)
    assert policy.context is context


def test_outbound_context_rejects_wrong_consumption_boundary(tmp_path) -> None:
    session = create_db(tmp_path / "wrong-boundary-context.db")
    context = _authorization_context()
    issued = issue_authorization(
        session=session,
        context=context,
        confirmation=ActionConfirmation.create(
            job_id=context.job_id,
            target=context.resolved_target,
            engine=context.engine,
            action=context.action_kind,
            issued_at=NOW,
        ),
        now=NOW,
    )
    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=context,
        boundary="wrong.module",
        now=NOW,
    )
    assert consumed.allowed

    with pytest.raises(OutboundDenied) as denied:
        OutboundContext.from_consumed_authorization(
            session=session,
            envelope=issued.envelope,
            expected=context,
            boundary="webforge.module",
            authorized_target=TARGET,
            allowed_scope=ALLOWED_SCOPE,
            excluded_scope=[],
            audit_sink=DatabaseOutboundAuditSink(session),
        )
    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    session.close()


def test_outbound_context_rejects_stale_and_replay_denial_envelopes(
    tmp_path,
    monkeypatch,
) -> None:
    session = create_db(tmp_path / "stale-replay-context.db")
    context = _authorization_context()
    issued = issue_authorization(
        session=session,
        context=context,
        confirmation=ActionConfirmation.create(
            job_id=context.job_id,
            target=context.resolved_target,
            engine=context.engine,
            action=context.action_kind,
            issued_at=NOW,
        ),
        now=NOW,
    )
    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=context,
        boundary="webforge.module",
        now=NOW,
    )
    assert consumed.allowed
    replay = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=context,
        boundary="webforge.module",
        now=NOW,
    )
    assert replay.allowed is False

    common = {
        "session": session,
        "expected": context,
        "boundary": "webforge.module",
        "authorized_target": TARGET,
        "allowed_scope": ALLOWED_SCOPE,
        "excluded_scope": [],
        "audit_sink": DatabaseOutboundAuditSink(session),
    }
    with pytest.raises(OutboundDenied) as replayed:
        OutboundContext.from_consumed_authorization(
            envelope=replay.envelope,
            **common,
        )
    assert replayed.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value

    monkeypatch.setattr(
        outbound_policy_module,
        "_system_utc_now",
        lambda: NOW + timedelta(seconds=DEFAULT_AUTHORIZATION_TTL_SECONDS + 1),
    )
    with pytest.raises(OutboundDenied) as stale:
        OutboundContext.from_consumed_authorization(
            envelope=issued.envelope,
            **common,
        )
    assert stale.value.reason_code == OutboundReason.AUTHORIZATION_INVALID.value
    session.close()


def _policy(
    tmp_path,
    *,
    target: str = TARGET,
    allowed_scope: list[str] | None = None,
    excluded_scope: list[str] | None = None,
    context_overrides: dict[str, object] | None = None,
    **outbound_overrides: Any,
) -> tuple[OutboundPolicy, Any]:
    validation_now = outbound_overrides.pop("now", NOW)
    runtime_id = outbound_overrides.pop("runtime_id", None)
    authorize_insecure_tls = bool(
        outbound_overrides.pop("authorize_insecure_tls", False)
    )
    insecure_tls_ttl_seconds = int(
        outbound_overrides.pop(
            "insecure_tls_ttl_seconds",
            DEFAULT_AUTHORIZATION_TTL_SECONDS,
        )
    )
    session = create_db(tmp_path / "outbound.db")
    auth_context = _authorization_context(
        requested_target=target,
        resolved_target=target,
        allowed_scope=allowed_scope or ALLOWED_SCOPE,
        excluded_scope=excluded_scope or [],
        **(context_overrides or {}),
    )
    envelope = _consumed_envelope(session, auth_context)
    insecure_envelope = None
    insecure_expected = None
    if authorize_insecure_tls:
        insecure_expected = replace(
            auth_context,
            action_kind="outbound.insecure_tls",
            parent_decision_id=envelope.decision_id,
            confirmation_method=ConfirmationMethod.INHERITED,
        )
        derived = derive_authorization(
            session=session,
            parent_envelope=envelope,
            context=insecure_expected,
            parent_boundary="webforge.module",
            now=validation_now,
            ttl_seconds=insecure_tls_ttl_seconds,
        )
        assert derived.allowed
        consumed_insecure = consume_authorization(
            session=session,
            envelope=derived.envelope,
            expected=insecure_expected,
            boundary="outbound.insecure_tls",
            now=validation_now,
        )
        assert consumed_insecure.allowed
        insecure_envelope = derived.envelope
    route = outbound_overrides.pop("route", None)
    if route is not None:
        route = route.with_action_id(envelope.action_id)
    outbound = OutboundContext.from_consumed_authorization(
        session=session,
        envelope=envelope,
        expected=auth_context,
        boundary="webforge.module",
        authorized_target=target,
        allowed_scope=allowed_scope or ALLOWED_SCOPE,
        excluded_scope=excluded_scope or [],
        audit_sink=DatabaseOutboundAuditSink(session),
        route=route,
        insecure_tls_authorization=insecure_envelope,
        insecure_tls_expected=insecure_expected,
        **outbound_overrides,
    )
    return OutboundPolicy(outbound, runtime_id=runtime_id), session


def test_excluded_initial_target_is_denied_before_resolver_or_transport(tmp_path) -> None:
    policy, session = _policy(
        tmp_path,
        allowed_scope=["127.0.0.0/8", "https://127.0.0.1:8443"],
        excluded_scope=["127.0.0.2/32"],
    )
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append(f"resolve:{host}:{port}")
        return ["127.0.0.1"]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return TransportResponse(status=200, headers={}, body=b"ok")

    client = PolicyHttpClient(policy, resolver=resolver, transport=transport)
    with pytest.raises(OutboundDenied) as exc_info:
        asyncio.run(client.get("https://127.0.0.2/blocked"))

    assert exc_info.value.reason_code == OutboundReason.EXCLUDED.value
    assert calls == []
    assert list_outbound_decisions(session)[-1]["stage"] == "pre_resolution"
    session.close()


def test_mixed_and_unapproved_dns_answers_fail_closed(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    mixed_prepared = policy.prepare_destination(
        TARGET,
        action_kind="http.request",

    )

    with pytest.raises(OutboundDenied) as mixed:
        policy.authorize_resolution(
            mixed_prepared,
            ["127.0.0.1", "192.0.2.10"],

        )
    assert mixed.value.reason_code == OutboundReason.RESOLVED_IP_OUT_OF_SCOPE.value

    unapproved_prepared = policy.prepare_destination(
        TARGET,
        action_kind="http.request",

    )
    with pytest.raises(OutboundDenied) as unapproved:
        policy.authorize_resolution(
            unapproved_prepared,
            ["192.0.2.10"],

        )
    assert unapproved.value.reason_code == OutboundReason.RESOLVED_IP_OUT_OF_SCOPE.value
    session.close()


@pytest.mark.parametrize(
    ("target", "allowed_scope", "answer"),
    [
        (
            "https://127.0.0.1:8443/start",
            ["127.0.0.0/8", "https://127.0.0.1:8443"],
            "127.0.0.2",
        ),
        (
            "https://127.0.0.1:8443/start",
            ["127.0.0.0/8", "https://127.0.0.1:8443"],
            "::ffff:127.0.0.2",
        ),
        (
            "https://[::1]:8443/start",
            ["::/126", "https://[::1]:8443"],
            "::2",
        ),
    ],
)
def test_ip_literal_resolution_cannot_rebind_socket_destination(
    tmp_path,
    target: str,
    allowed_scope: list[str],
    answer: str,
) -> None:
    policy, session = _policy(
        tmp_path,
        target=target,
        allowed_scope=allowed_scope,
    )
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolver")
        return [answer]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(target)
        )

    assert denied.value.reason_code == OutboundReason.LITERAL_ADDRESS_MISMATCH.value
    assert calls == ["resolver"]
    session.close()


def test_ip_literal_accepts_only_its_canonical_mapped_alias(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    prepared = policy.prepare_destination(TARGET, action_kind="http.request")

    permit = policy.authorize_resolution(
        prepared,
        ["::ffff:127.0.0.1"],

    )

    assert permit.addresses == ("127.0.0.1",)
    session.close()


@pytest.mark.parametrize(
    "destination",
    [
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://[::ffff:100.100.100.200]/latest/meta-data/",
    ],
)
def test_ipv4_mapped_metadata_aliases_require_delegated_authorization(
    tmp_path,
    destination: str,
) -> None:
    policy, session = _policy(
        tmp_path,
        allowed_scope=["127.0.0.0/8", TARGET, destination],
    )

    with pytest.raises(OutboundDenied) as denied:
        policy.prepare_destination(destination, action_kind="http.request")

    assert (
        denied.value.reason_code
        == OutboundReason.DELEGATED_DESTINATION_NOT_AUTHORIZED.value
    )
    session.close()


@pytest.mark.parametrize(
    "metadata_address",
    [
        "169.254.169.254",
        "169.254.170.2",
        "169.254.170.23",
        "fd00:ec2::23",
    ],
)
def test_hostname_resolution_to_metadata_is_denied_before_transport(
    tmp_path,
    metadata_address: str,
) -> None:
    target = "http://allowed.test/start"
    policy, session = _policy(
        tmp_path,
        target=target,
        allowed_scope=["allowed.test", "0.0.0.0/0", "http://allowed.test:80"],
    )
    transports: list[str] = []

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        transports.append(request.url)
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(
                    metadata_address
                ),
                transport=transport,
            ).get(target)
        )

    assert (
        denied.value.reason_code
        == OutboundReason.DELEGATED_DESTINATION_NOT_AUTHORIZED.value
    )
    assert transports == []
    session.close()


def test_dns_answer_is_pinned_and_change_is_rejected(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    request_id = "request-dns-change-fixture"
    prepared = policy.prepare_destination(
        TARGET,
        action_kind="http.request",
        request_id=request_id,

    )
    permit = policy.authorize_resolution(prepared, ["127.0.0.1"])

    assert permit.addresses == ("127.0.0.1",)
    assert permit.host == "127.0.0.1"
    assert permit.port == 8443

    changed_prepared = policy.prepare_destination(
        TARGET,
        action_kind="http.request",
        request_id=request_id,

    )
    with pytest.raises(OutboundDenied) as changed:
        policy.authorize_resolution(
            changed_prepared,
            ["127.0.0.1", "127.0.0.2"],

        )
    assert changed.value.reason_code == OutboundReason.DNS_ANSWER_CHANGED.value

    policy.consume_connection_permit(permit, TARGET)
    with pytest.raises(OutboundDenied) as replayed:
        policy.consume_connection_permit(permit, TARGET)
    assert replayed.value.reason_code == OutboundReason.PERMIT_REPLAYED.value
    session.close()


def test_prepared_destination_cannot_issue_multiple_permits(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    prepared = policy.prepare_destination(
        TARGET,
        action_kind="http.request",
    )

    first = policy.authorize_resolution(prepared, ["127.0.0.1"])
    delegate_calls: list[str] = []

    async def delegate(request: HttpTransportRequest) -> TransportResponse:
        delegate_calls.append(request.permit.permit_id)
        return TransportResponse(status=200, headers={}, body=b"ok")

    asyncio.run(
        PolicyBoundTransport(policy, delegate)(
            HttpTransportRequest(
                method="GET",
                url=TARGET,
                headers={},
                permit=first,
                prepared=prepared,
                route=None,
                timeout_seconds=1.0,
                max_response_bytes=1024,
            )
        )
    )
    with pytest.raises(OutboundDenied) as replayed:
        policy.authorize_resolution(prepared, ["127.0.0.1"])

    assert first.decision_id == prepared.decision_id
    assert replayed.value.reason_code == OutboundReason.PERMIT_REPLAYED.value
    assert delegate_calls == [first.permit_id]
    session.close()


def test_denied_resolution_consumes_prepared_destination(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    prepared = policy.prepare_destination(
        TARGET,
        action_kind="http.request",

    )

    with pytest.raises(OutboundDenied) as out_of_scope:
        policy.authorize_resolution(prepared, ["192.0.2.10"])
    assert (
        out_of_scope.value.reason_code
        == OutboundReason.RESOLVED_IP_OUT_OF_SCOPE.value
    )

    with pytest.raises(OutboundDenied) as replayed:
        policy.authorize_resolution(prepared, ["127.0.0.1"])
    assert replayed.value.reason_code == OutboundReason.PERMIT_REPLAYED.value
    session.close()


def test_pinned_hostname_resolver_uses_immutable_trusted_clock(
    tmp_path,
    monkeypatch,
) -> None:
    clock = [NOW]
    monkeypatch.setattr(
        outbound_policy_module,
        "_system_utc_now",
        lambda: clock[0],
    )
    target = "https://allowed.test:8443/start"
    policy, session = _policy(
        tmp_path,
        target=target,
        allowed_scope=["allowed.test", "127.0.0.0/8", "https://allowed.test:8443"],
    )
    prepared = policy.prepare_destination(
        target,
        action_kind="http.request",
    )
    permit = policy.authorize_resolution(prepared, ["127.0.0.1"])
    resolver = _PinnedResolver(permit)

    records = asyncio.run(resolver.resolve("allowed.test", 8443))

    assert [record["host"] for record in records] == ["127.0.0.1"]
    with pytest.raises(AttributeError):
        resolver._clock = lambda: NOW  # type: ignore[attr-defined]
    clock[0] = permit.expires_at + timedelta(seconds=1)
    with pytest.raises(OSError, match="expired"):
        asyncio.run(resolver.resolve("allowed.test", 8443))
    session.close()


def test_connection_permit_integrity_rejects_substituted_addresses(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    prepared = policy.prepare_destination(TARGET, action_kind="http.request")
    permit = policy.authorize_resolution(prepared, ["127.0.0.1"])
    tampered = replace(
        permit,
        addresses=("127.0.0.2",),
        address_digest="sha256:" + "0" * 64,
    )

    with pytest.raises(OutboundDenied) as denied:
        policy.consume_connection_permit(tampered, TARGET)
    assert denied.value.reason_code == OutboundReason.PERMIT_MISMATCH.value
    session.close()


def test_clock_rollback_cannot_predate_parent_prepared_or_permit(
    tmp_path,
    monkeypatch,
) -> None:
    rollback = NOW - timedelta(seconds=MAX_FUTURE_SKEW_SECONDS + 1)
    clock = [NOW]
    monkeypatch.setattr(
        outbound_policy_module,
        "_system_utc_now",
        lambda: clock[0],
    )
    policy, session = _policy(tmp_path, now=NOW)
    clock[0] = rollback
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolver")
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    with pytest.raises(OutboundDenied) as parent_denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(TARGET)
        )
    assert (
        parent_denied.value.reason_code
        == OutboundReason.AUTHORIZATION_NOT_YET_VALID.value
    )
    assert calls == []

    with pytest.raises(TypeError):
        OutboundPolicy(policy.context, clock=lambda: NOW)  # type: ignore[call-arg]

    prepared = policy._prepare_destination(
        TARGET,
        action_kind="http.request",
        now=NOW,
        require_route_health=True,
    )
    with pytest.raises(OutboundDenied) as prepared_denied:
        policy._authorize_resolution(
            prepared,
            ["127.0.0.1"],
            now=rollback,
            require_route_health=True,
        )
    assert (
        prepared_denied.value.reason_code
        == OutboundReason.PERMIT_NOT_YET_VALID.value
    )

    permit = policy._authorize_resolution(
        prepared,
        ["127.0.0.1"],
        now=NOW,
        require_route_health=True,
    )
    with pytest.raises(OutboundDenied) as permit_denied:
        policy._validate_connection_permit(
            permit,
            TARGET,
            now=rollback,
            require_route_health=True,
        )
    assert (
        permit_denied.value.reason_code
        == OutboundReason.PERMIT_NOT_YET_VALID.value
    )
    session.close()


def test_policy_uses_trusted_live_clock_and_denies_expired_context(
    tmp_path,
    monkeypatch,
) -> None:
    clock = [NOW]
    monkeypatch.setattr(
        outbound_policy_module,
        "_system_utc_now",
        lambda: clock[0],
    )
    policy, session = _policy(tmp_path, now=NOW)
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolver")
        return [host]

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    clock[0] = NOW + timedelta(seconds=DEFAULT_AUTHORIZATION_TTL_SECONDS + 1)
    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.AUTHORIZATION_EXPIRED.value
    assert calls == []
    session.close()


def test_transport_admission_rejects_caller_time_and_live_expired_permit(
    tmp_path,
    monkeypatch,
) -> None:
    clock = [NOW]
    monkeypatch.setattr(
        outbound_policy_module,
        "_system_utc_now",
        lambda: clock[0],
    )
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
    clock[0] = permit.expires_at + timedelta(seconds=1)

    with pytest.raises(TypeError):
        policy.admit_transport_request(  # type: ignore[call-arg]
            request,
            now=permit.issued_at,
        )
    with pytest.raises(OutboundDenied) as denied:
        policy.admit_transport_request(request)

    assert denied.value.reason_code == OutboundReason.PERMIT_EXPIRED.value
    session.close()


def test_target_affecting_public_boundaries_expose_no_caller_time_source() -> None:
    for value in (
        OutboundContext.from_consumed_authorization,
        outbound_context_claim_is_valid,
        OutboundPolicy,
        OutboundPolicy.prepare_destination,
        OutboundPolicy.prepare_delegated_destination,
        OutboundPolicy.authorize_resolution,
        OutboundPolicy.validate_connection_permit,
        OutboundPolicy.consume_connection_permit,
        OutboundPolicy.route_health_is_current,
        OutboundPolicy.preflight_route,
        OutboundPolicy.admit_transport_request,
        OutboundPolicy.validate_transport_boundary,
        PolicyBoundTransport,
        outbound_policy_module.AiohttpPinnedTransport,
        _PinnedResolver,
    ):
        parameters = inspect.signature(value).parameters
        assert "clock" not in parameters
        assert "now" not in parameters


def test_subsecond_expiry_tampering_breaks_prepared_and_permit_integrity(tmp_path) -> None:
    current = NOW + timedelta(microseconds=100_000)
    policy, session = _policy(tmp_path, now=current)
    prepared = policy.prepare_destination(
        TARGET,
        action_kind="http.request",

    )
    tampered_prepared = replace(
        prepared,
        expires_at=prepared.expires_at.replace(microsecond=999_999),
    )
    after_original_expiry = prepared.expires_at + timedelta(microseconds=100_000)

    with pytest.raises(OutboundDenied) as prepared_denied:
        policy.authorize_resolution(
            tampered_prepared,
            ["127.0.0.1"],

        )
    assert prepared_denied.value.reason_code == OutboundReason.PERMIT_MISMATCH.value

    permit = policy.authorize_resolution(prepared, ["127.0.0.1"])
    tampered_permit = replace(
        permit,
        expires_at=permit.expires_at.replace(microsecond=999_999),
    )
    with pytest.raises(OutboundDenied) as permit_denied:
        policy.validate_connection_permit(
            tampered_permit,
            TARGET,

        )
    assert permit_denied.value.reason_code == OutboundReason.PERMIT_MISMATCH.value
    session.close()


def test_same_origin_redirect_succeeds_and_cross_scope_redirect_stops_before_dns(tmp_path) -> None:
    policy, session = _policy(tmp_path, max_redirects=2)
    resolved: list[str] = []
    sent: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        resolved.append(f"{host}:{port}")
        return ["127.0.0.1"]

    async def same_origin_transport(request: HttpTransportRequest) -> TransportResponse:
        sent.append(request.url)
        if len(sent) == 1:
            return TransportResponse(
                status=302,
                headers={"Location": "/next"},
                body=b"",
            )
        return TransportResponse(status=200, headers={}, body=b"ok")

    response = asyncio.run(
        PolicyHttpClient(policy, resolver=resolver, transport=same_origin_transport).get(TARGET)
    )
    assert response.status == 200
    assert sent == [TARGET, "https://127.0.0.1:8443/next"]

    sent.clear()
    resolved.clear()

    async def cross_scope_transport(request: HttpTransportRequest) -> TransportResponse:
        sent.append(request.url)
        return TransportResponse(
            status=302,
            headers={"Location": "https://192.0.2.10/escape"},
            body=b"",
        )

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(policy, resolver=resolver, transport=cross_scope_transport).get(TARGET)
        )
    assert denied.value.reason_code == OutboundReason.HOST_OUT_OF_SCOPE.value
    assert sent == [TARGET]
    assert resolved == ["127.0.0.1:8443"]
    session.close()


def test_malformed_redirect_is_typed_audited_and_stops_before_second_attempt(
    tmp_path,
) -> None:
    policy, session = _policy(tmp_path, max_redirects=2)
    resolved: list[str] = []
    requests: list[HttpTransportRequest] = []

    async def resolver(host: str, port: int) -> list[str]:
        resolved.append(f"{host}:{port}")
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        requests.append(request)
        return TransportResponse(
            status=302,
            headers={"Location": "http://[::1"},
            body=b"",
        )

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.MALFORMED_DESTINATION.value
    assert policy.last_denial_reason == OutboundReason.MALFORMED_DESTINATION.value
    assert resolved == ["127.0.0.1:8443"]
    assert [request.url for request in requests] == [TARGET]
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["outcome"] == "deny"
    assert decisions[-1]["reason_code"] == OutboundReason.MALFORMED_DESTINATION.value
    assert decisions[-1]["stage"] == "redirect"
    assert decisions[-1]["detail"] == {"hop": 1}
    assert "http://[::1" not in str(decisions)
    session.close()


def test_redirect_bound_and_secret_stripping_on_allowed_origin_change(tmp_path) -> None:
    target = "https://127.0.0.1:8443/start"
    scope = [
        "127.0.0.0/8",
        "https://127.0.0.1:8443",
        "https://127.0.0.2:8443",
    ]
    policy, session = _policy(tmp_path, target=target, allowed_scope=scope, max_redirects=1)
    requests: list[HttpTransportRequest] = []

    async def resolver(host: str, port: int) -> list[str]:
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        requests.append(request)
        if len(requests) == 1:
            return TransportResponse(
                status=302,
                headers={"Location": "https://127.0.0.2:8443/next"},
                body=b"",
            )
        return TransportResponse(
            status=302,
            headers={"Location": "https://127.0.0.1:8443/again"},
            body=b"",
        )

    headers = {
        "Authorization": "Bearer CANARY_AUTH_003",
        "Cookie": "session=CANARY_COOKIE_003",
        "Proxy-Authorization": "Basic CANARY_PROXY_003",
        "X-API-Key": "CANARY_API_KEY_003",
        "Private-Token": "CANARY_PRIVATE_TOKEN_003",
        "Accept": "Bearer CANARY_ACCEPT_003",
    }
    binding = CredentialBinding.for_origin(
        target,
        protected_headers=("authorization", "cookie", "x-api-key"),
    )

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(policy, resolver=resolver, transport=transport).get(
                target,
                headers=headers,
                credential_binding=binding,
            )
        )

    assert denied.value.reason_code == OutboundReason.REDIRECT_LIMIT_EXCEEDED.value
    assert requests[0].headers["Authorization"] == "Bearer CANARY_AUTH_003"
    assert requests[0].headers["Cookie"] == "session=CANARY_COOKIE_003"
    assert requests[0].headers["X-API-Key"] == "CANARY_API_KEY_003"
    assert "Proxy-Authorization" not in requests[0].headers
    assert requests[1].headers == {"Host": "127.0.0.2:8443"}
    assert "CANARY" not in str(list_outbound_decisions(session))
    session.close()


def test_default_port_and_scheme_transitions_need_explicit_origin_scope(tmp_path) -> None:
    policy, session = _policy(
        tmp_path,
        allowed_scope=["127.0.0.1/32", TARGET],
    )
    for destination in (
        "https://127.0.0.1/other-port",
        "http://127.0.0.1/downgrade",
    ):
        with pytest.raises(OutboundDenied) as denied:
            policy.prepare_destination(destination, action_kind="http.request")
        assert denied.value.reason_code == OutboundReason.PORT_NOT_AUTHORIZED.value
    session.close()


@pytest.mark.parametrize(
    "invalid_scope_entry",
    [
        "https://127.0.0.2:0",
        "https://127.0.0.2:",
    ],
)
def test_invalid_explicit_scope_port_cannot_authorize_default_port(
    tmp_path,
    invalid_scope_entry: str,
) -> None:
    policy, session = _policy(
        tmp_path,
        allowed_scope=["127.0.0.0/8", TARGET, invalid_scope_entry],
    )
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolver")
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get("https://127.0.0.2/child")
        )

    assert denied.value.reason_code == OutboundReason.PORT_NOT_AUTHORIZED.value
    assert calls == []
    session.close()


def test_request_transport_overrides_are_denied_before_resolution(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolver")
        return [host]

    for option in (
        {"ssl": False},
        {"auth": object()},
        {"proxy_auth": object()},
        {"server_hostname": "outside.test"},
        {"fingerprint": b"x"},
    ):
        with pytest.raises(OutboundDenied) as denied:
            asyncio.run(PolicyHttpClient(policy, resolver=resolver).get(TARGET, **option))
        assert denied.value.reason_code == OutboundReason.REQUEST_OPTION_NOT_ALLOWED.value
    assert calls == []
    session.close()


def test_host_and_authority_headers_are_canonicalized_for_each_origin(tmp_path) -> None:
    target = "https://127.0.0.1:8443/start"
    policy, session = _policy(
        tmp_path,
        target=target,
        allowed_scope=[
            "127.0.0.0/8",
            "https://127.0.0.1:8443",
            "https://127.0.0.2:8443",
        ],
    )
    requests: list[HttpTransportRequest] = []

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        requests.append(request)
        if len(requests) == 1:
            return TransportResponse(
                status=302,
                headers={"Location": "https://127.0.0.2:8443/next"},
                body=b"",
            )
        return TransportResponse(status=200, headers={}, body=b"ok")

    response = asyncio.run(
        PolicyHttpClient(
            policy,
            resolver=lambda host, port: _async_addresses_for_test(host),
            transport=transport,
        ).get(
            target,
            headers={
                "Host": "out-of-scope.invalid",
                ":authority": "out-of-scope.invalid",
                "Authorization": "Bearer CANARY_HOST_003",
            },
        )
    )

    assert response.status == 200
    assert requests[0].headers == {
        "Authorization": "Bearer CANARY_HOST_003",
        "Host": "127.0.0.1:8443",
    }
    assert requests[1].headers == {"Host": "127.0.0.2:8443"}
    assert "out-of-scope.invalid" not in str(requests)
    session.close()


def test_top_level_cross_origin_request_does_not_rebind_session_credentials(tmp_path) -> None:
    scope = ["127.0.0.0/8", TARGET, "https://127.0.0.2:8443"]
    policy, session = _policy(tmp_path, allowed_scope=scope)
    requests: list[HttpTransportRequest] = []

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        requests.append(request)
        return TransportResponse(status=200, headers={}, body=b"ok")

    response = asyncio.run(
        PolicyHttpClient(
            policy,
            resolver=lambda host, port: _async_addresses_for_test(host),
            transport=transport,
            headers={
                "Authorization": "Bearer CANARY",
                "Private-Token": "CANARY_PRIVATE",
                "Accept": "application/json",
            },
            cookies={"session": "CANARY_COOKIE"},
        ).get("https://127.0.0.2:8443/child")
    )
    assert response.status == 200
    assert requests[0].headers == {"Host": "127.0.0.2:8443"}
    session.close()


def test_top_level_cross_origin_request_body_is_denied_before_resolution(tmp_path) -> None:
    scope = ["127.0.0.0/8", TARGET, "https://127.0.0.2:8443"]
    policy, session = _policy(tmp_path, allowed_scope=scope)
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolver")
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).post(
                "https://127.0.0.2:8443/form-action",
                data={"access_token": "CANARY_TOP_LEVEL_BODY"},
            )
        )

    assert denied.value.reason_code == OutboundReason.CROSS_ORIGIN_BODY_NOT_AUTHORIZED.value
    assert calls == []
    session.close()


def test_imported_cookie_path_is_revalidated_on_same_origin_redirect(tmp_path) -> None:
    async def exercise() -> None:
        wire_requests: list[str] = []

        async def handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            try:
                wire_requests.append(
                    (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
                )
                if len(wire_requests) == 1:
                    writer.write(
                        b"HTTP/1.1 302 Found\r\n"
                        b"Location: /admin/%2e%2e/public\r\n"
                        b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                else:
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Length: 2\r\nConnection: close\r\n\r\nok"
                    )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = int(server.sockets[0].getsockname()[1])
        origin = f"http://127.0.0.1:{port}"
        target = f"{origin}/admin/start"
        policy, session = _policy(
            tmp_path,
            target=target,
            allowed_scope=["127.0.0.1/32", origin],
        )
        try:
            client = PolicyHttpClient(
                policy,
                cookies={"admin_session": "CANARY_ADMIN_COOKIE"},
                cookie_provenance={
                    "admin_session": {
                        "origin": origin,
                        "domain": "127.0.0.1",
                        "host_only": True,
                        "path": "/admin",
                        "secure": False,
                    }
                },
            )
            response = await client.get(target)
            top_level = f"{origin}/admin/%2e%2e/public"
            top_response = await client.get(top_level)
            assert response.status == 200
            assert top_response.status == 200
            assert wire_requests[0].startswith("GET /admin/start HTTP/1.1\r\n")
            assert "\r\nCookie: admin_session=CANARY_ADMIN_COOKIE\r\n" in wire_requests[0]
            assert wire_requests[1].startswith("GET /public HTTP/1.1\r\n")
            assert "\r\nCookie:" not in wire_requests[1]
            assert wire_requests[2].startswith("GET /public HTTP/1.1\r\n")
            assert "\r\nCookie:" not in wire_requests[2]
        finally:
            session.close()
            server.close()
            await server.wait_closed()

    asyncio.run(exercise())


async def _async_addresses_for_test(host: str) -> list[str]:
    return [host]


def test_cross_origin_307_does_not_replay_request_body(tmp_path) -> None:
    scope = ["127.0.0.0/8", TARGET, "https://127.0.0.2:8443"]
    policy, session = _policy(tmp_path, allowed_scope=scope)
    sends: list[str] = []

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        sends.append(request.url)
        return TransportResponse(
            status=307,
            headers={"Location": "https://127.0.0.2:8443/receive"},
            body=b"",
        )

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).post(TARGET, json={"password": "CANARY_BODY_SECRET"})
        )
    assert denied.value.reason_code == OutboundReason.CROSS_ORIGIN_BODY_NOT_AUTHORIZED.value
    assert sends == [TARGET]
    session.close()


def test_attempt_limiter_runs_for_every_redirect_and_retry(tmp_path) -> None:
    limiter_calls: list[str] = []

    async def limiter() -> None:
        limiter_calls.append("limit")

    policy, session = _policy(
        tmp_path,
        max_retries=1,
        max_redirects=1,
        attempt_limiter=limiter,
    )
    sends = 0

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        nonlocal sends
        sends += 1
        if sends == 1:
            return TransportResponse(status=302, headers={"Location": "/next"}, body=b"")
        if sends == 2:
            return TransportResponse(status=429, headers={"Retry-After": "0"}, body=b"")
        return TransportResponse(status=200, headers={}, body=b"ok")

    response = asyncio.run(
        PolicyHttpClient(
            policy,
            resolver=lambda host, port: _async_addresses_for_test(host),
            transport=transport,
            sleeper=lambda delay: _async_noop(),
        ).get(TARGET)
    )
    assert response.status == 200
    assert limiter_calls == ["limit", "limit", "limit"]
    session.close()


async def _async_noop() -> None:
    return None


def test_429_retry_releases_response_rechecks_policy_and_is_bounded(tmp_path) -> None:
    policy, session = _policy(tmp_path, max_retries=1)
    calls: list[str] = []
    released: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolve")
        return ["127.0.0.1"]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("send")
        if calls.count("send") == 1:
            return TransportResponse(
                status=429,
                headers={"Retry-After": "0"},
                body=b"retry",
                release_callback=lambda: released.append("released"),
            )
        return TransportResponse(status=200, headers={}, body=b"ok")

    async def no_sleep(_: float) -> None:
        calls.append("sleep")

    response = asyncio.run(
        PolicyHttpClient(
            policy,
            resolver=resolver,
            transport=transport,
            sleeper=no_sleep,
        ).get(TARGET)
    )

    assert response.status == 200
    assert calls.count("resolve") == 2
    assert calls.count("send") == 2
    assert released == ["released"]

    with pytest.raises(OutboundDenied) as non_idempotent:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=lambda request: _async_response(429),
                sleeper=no_sleep,
            ).post(TARGET, data=b"mutation")
        )
    assert non_idempotent.value.reason_code == OutboundReason.RETRY_NOT_IDEMPOTENT.value
    session.close()


def test_buffered_success_releases_transport_response_exactly_once(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    released: list[str] = []

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        return TransportResponse(
            status=200,
            headers={},
            body=b"buffered",
            release_callback=lambda: released.append("released"),
        )

    response = asyncio.run(
        PolicyHttpClient(
            policy,
            resolver=lambda host, port: _async_addresses_for_test(host),
            transport=transport,
        ).get(TARGET)
    )

    assert response.body == b"buffered"
    assert released == ["released"]
    response.release()
    response.release()
    assert released == ["released"]
    session.close()


def test_buffered_success_contains_and_records_release_callback_exception(
    tmp_path,
    caplog,
) -> None:
    policy, session = _policy(tmp_path)
    released: list[str] = []
    raw_responses: list[TransportResponse] = []

    def broken_release() -> None:
        released.append("released")
        raise RuntimeError("fixture cleanup secret must not be logged")

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        response = TransportResponse(
            status=200,
            headers={},
            body=b"buffered",
            release_callback=broken_release,
        )
        raw_responses.append(response)
        return response

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.TRANSPORT_CLEANUP_FAILED.value
    assert released == ["released"]
    assert raw_responses[0].released is True
    assert raw_responses[0].release_error == "callback_failed"
    assert "Transport response release callback failed" in caplog.text
    assert "fixture cleanup secret" not in caplog.text
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["stage"] == "transport_cleanup"
    assert (
        decisions[-1]["reason_code"]
        == OutboundReason.TRANSPORT_CLEANUP_FAILED.value
    )
    session.close()


def test_external_cancellation_drains_and_releases_late_transport_response(
    tmp_path,
) -> None:
    policy, session = _policy(tmp_path)
    released: list[str] = []

    async def exercise() -> None:
        entered = asyncio.Event()
        finished = asyncio.Event()

        async def transport(_request: HttpTransportRequest) -> TransportResponse:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await asyncio.sleep(0)
                finished.set()
                return TransportResponse(
                    status=200,
                    headers={},
                    body=b"late",
                    release_callback=lambda: released.append("released"),
                )

        request = asyncio.ensure_future(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )
        await entered.wait()
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request

        assert finished.is_set()

    asyncio.run(exercise())
    assert released == ["released"]
    session.close()


def test_external_cancellation_survives_release_callback_exception(
    tmp_path,
    caplog,
) -> None:
    policy, session = _policy(tmp_path)
    released: list[str] = []
    late_responses: list[TransportResponse] = []

    def broken_release() -> None:
        released.append("released")
        raise RuntimeError("fixture late cleanup failed")

    async def exercise() -> None:
        entered = asyncio.Event()

        async def transport(_request: HttpTransportRequest) -> TransportResponse:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                response = TransportResponse(
                    status=200,
                    headers={},
                    body=b"late",
                    release_callback=broken_release,
                )
                late_responses.append(response)
                return response

        request = asyncio.create_task(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )
        await entered.wait()
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        pending = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ]
        assert pending == []

    asyncio.run(exercise())
    assert released == ["released"]
    assert late_responses[0].released is True
    assert late_responses[0].release_error == "callback_failed"
    assert "Transport response release callback failed" in caplog.text
    session.close()


def test_timeout_survives_late_release_callback_exception(tmp_path) -> None:
    policy, session = _policy(tmp_path, timeout_seconds=0.05)
    released: list[str] = []
    late_responses: list[TransportResponse] = []

    def broken_release() -> None:
        released.append("released")
        raise RuntimeError("fixture timeout cleanup failed")

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            response = TransportResponse(
                status=200,
                headers={},
                body=b"late",
                release_callback=broken_release,
            )
            late_responses.append(response)
            return response

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )

    # Timeout already has the canonical connection-failed terminal reason;
    # cleanup diagnostics must not replace it with a raw callback exception.
    assert denied.value.reason_code == OutboundReason.CONNECTION_FAILED.value
    assert released == ["released"]
    assert late_responses[0].release_error == "callback_failed"
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["stage"] == "transport"
    assert decisions[-1]["reason_code"] == OutboundReason.CONNECTION_FAILED.value
    session.close()


def test_cancellation_suppressing_delegate_release_error_stays_cancelled(
    tmp_path,
) -> None:
    policy, session = _policy(tmp_path)
    released: list[str] = []
    late_responses: list[TransportResponse] = []

    def broken_release() -> None:
        released.append("released")
        raise RuntimeError("fixture repeated cancellation cleanup failed")

    async def exercise() -> None:
        entered = asyncio.Event()

        async def transport(_request: HttpTransportRequest) -> TransportResponse:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    response = TransportResponse(
                        status=200,
                        headers={},
                        body=b"late",
                        release_callback=broken_release,
                    )
                    late_responses.append(response)
                    return response

        request = asyncio.create_task(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )
        await entered.wait()
        request.cancel()
        await asyncio.sleep(0.01)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        pending = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ]
        assert pending == []

    asyncio.run(exercise())
    assert released == ["released"]
    assert late_responses[0].release_error == "callback_failed"
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["reason_code"] == OutboundReason.CANCELLED.value
    session.close()


def test_release_diagnostic_never_introspects_or_logs_callback_exception(
    caplog,
) -> None:
    released: list[str] = []

    class HostileExceptionType(type):
        def __getattribute__(cls, name: str) -> Any:
            if name == "__name__":
                raise RuntimeError("CANARY_RAW_CLASS_NAME")
            return super().__getattribute__(name)

    class CANARY_SECRET_EXCEPTION(
        Exception,
        metaclass=HostileExceptionType,
    ):
        pass

    def broken_release() -> None:
        released.append("released")
        raise CANARY_SECRET_EXCEPTION("CANARY_RAW_MESSAGE")

    response = TransportResponse(
        status=200,
        headers={},
        body=b"fixture",
        release_callback=broken_release,
    )
    response.release()
    response.release()

    assert released == ["released"]
    assert response.released is True
    assert response.release_error == "callback_failed"
    assert "Transport response release callback failed" in caplog.text
    assert "CANARY" not in caplog.text


def test_transport_response_release_override_is_contained_and_audited(
    tmp_path,
    caplog,
) -> None:
    policy, session = _policy(tmp_path)
    override_calls: list[str] = []
    callback_calls: list[str] = []
    raw_responses: list[TransportResponse] = []

    class ThrowingReleaseResponse(TransportResponse):
        def release(self) -> bool:
            override_calls.append("override")
            raise RuntimeError("CANARY_SUBCLASS_RELEASE")

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        response = ThrowingReleaseResponse(
            status=200,
            headers={},
            body=b"buffered",
            release_callback=lambda: callback_calls.append("callback"),
        )
        raw_responses.append(response)
        return response

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.TRANSPORT_CLEANUP_FAILED.value
    assert override_calls == []
    assert callback_calls == ["callback"]
    assert raw_responses[0].released is True
    assert raw_responses[0].release_error == "callback_failed"
    assert "Transport response release callback failed" in caplog.text
    assert "CANARY" not in caplog.text
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["stage"] == "transport_cleanup"
    session.close()


def test_cancellation_survives_transport_response_release_override(
    tmp_path,
) -> None:
    policy, session = _policy(tmp_path)
    override_calls: list[str] = []
    callback_calls: list[str] = []

    class ThrowingReleaseResponse(TransportResponse):
        def release(self) -> bool:
            override_calls.append("override")
            raise RuntimeError("fixture subclass cleanup failed")

    async def exercise() -> None:
        entered = asyncio.Event()

        async def transport(_request: HttpTransportRequest) -> TransportResponse:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                return ThrowingReleaseResponse(
                    status=200,
                    headers={},
                    body=b"late",
                    release_callback=lambda: callback_calls.append("callback"),
                )

        request = asyncio.create_task(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )
        await entered.wait()
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        pending = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ]
        assert pending == []

    asyncio.run(exercise())
    assert override_calls == []
    assert callback_calls == ["callback"]
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["reason_code"] == OutboundReason.CANCELLED.value
    session.close()


def test_transport_response_subtype_cannot_forge_release_postcondition(
    tmp_path,
) -> None:
    policy, session = _policy(tmp_path)
    override_calls: list[str] = []
    callback_calls: list[str] = []

    class LyingReleaseResponse(TransportResponse):
        def release(self) -> bool:
            override_calls.append("override")
            self.released = True
            self.release_error = ""
            return True

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        return LyingReleaseResponse(
            status=200,
            headers={},
            body=b"buffered",
            release_callback=lambda: callback_calls.append("callback"),
        )

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.TRANSPORT_CLEANUP_FAILED.value
    assert override_calls == []
    assert callback_calls == ["callback"]
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["stage"] == "transport_cleanup"
    session.close()


def test_pre_released_transport_response_cannot_forge_cleanup_completion(
    tmp_path,
) -> None:
    policy, session = _policy(tmp_path)
    callback_calls: list[str] = []

    with pytest.raises(TypeError):
        TransportResponse(  # type: ignore[call-arg]
            status=200,
            headers={},
            body=b"forged",
            released=True,
        )

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        response = TransportResponse(
            status=200,
            headers={},
            body=b"forged",
            release_callback=lambda: callback_calls.append("callback"),
        )
        response.released = True
        return response

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.TRANSPORT_CLEANUP_FAILED.value
    assert callback_calls == []
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["stage"] == "transport_cleanup"
    session.close()


def test_release_callback_cannot_forge_cleanup_postcondition(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    raw_responses: list[TransportResponse] = []

    def corrupt_release_state() -> None:
        raw_responses[0].released = 1  # type: ignore[assignment]
        raw_responses[0].release_error = ""

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        response = TransportResponse(
            status=200,
            headers={},
            body=b"forged",
            release_callback=corrupt_release_state,
        )
        raw_responses.append(response)
        return response

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.TRANSPORT_CLEANUP_FAILED.value
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["stage"] == "transport_cleanup"
    session.close()


def test_release_callback_cannot_change_sealed_response_type(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    raw_responses: list[TransportResponse] = []

    class MutatedTransportResponse(TransportResponse):
        pass

    def mutate_response_type() -> None:
        raw_responses[0].__class__ = MutatedTransportResponse

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        response = TransportResponse(
            status=200,
            headers={},
            body=b"mutated",
            release_callback=mutate_response_type,
        )
        raw_responses.append(response)
        return response

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.TRANSPORT_CLEANUP_FAILED.value
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["stage"] == "transport_cleanup"
    session.close()


def test_out_of_contract_response_class_probe_is_contained(tmp_path) -> None:
    policy, session = _policy(tmp_path)

    class HostileDuckResponse:
        status = 200
        headers: dict[str, str] = {}
        body = b"duck"
        url = TARGET

        @property
        def __class__(self) -> type[Any]:
            raise RuntimeError("CANARY_DUCK_CLASS")

    async def transport(_request: HttpTransportRequest) -> Any:
        return HostileDuckResponse()

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,  # type: ignore[arg-type]
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.TRANSPORT_CLEANUP_FAILED.value
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["stage"] == "transport_cleanup"
    session.close()


def test_cancellation_late_duck_class_probe_is_contained(tmp_path) -> None:
    policy, session = _policy(tmp_path)

    class HostileDuckResponse:
        @property
        def __class__(self) -> type[Any]:
            raise RuntimeError("CANARY_LATE_DUCK_CLASS")

    async def exercise() -> None:
        entered = asyncio.Event()

        async def transport(_request: HttpTransportRequest) -> Any:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                return HostileDuckResponse()

        request = asyncio.create_task(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,  # type: ignore[arg-type]
            ).get(TARGET)
        )
        await entered.wait()
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        pending = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ]
        assert pending == []

    asyncio.run(exercise())
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["reason_code"] == OutboundReason.CANCELLED.value
    session.close()


def test_repeated_external_cancellation_cannot_interrupt_child_cleanup(
    tmp_path,
    monkeypatch,
) -> None:
    policy, session = _policy(tmp_path)
    released: list[str] = []

    async def exercise() -> None:
        entered = asyncio.Event()

        async def transport(_request: HttpTransportRequest) -> TransportResponse:
            response = TransportResponse(
                status=200,
                headers={},
                body=b"late",
                release_callback=lambda: released.append("released"),
            )
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    return response

        request = asyncio.ensure_future(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )
        await entered.wait()
        request.cancel()
        await asyncio.sleep(0.01)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        pending = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ]
        assert pending == []

    asyncio.run(exercise())
    assert released == ["released"]
    contended_releases: list[str] = []
    contended_cancellations: list[int] = []

    async def exercise_contention() -> None:
        entered = asyncio.Event()
        response = TransportResponse(
            status=200,
            headers={},
            body=b"late",
            release_callback=lambda: contended_releases.append("released"),
        )

        async def transport() -> TransportResponse:
            entered.set()
            for attempt in range(2):
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    contended_cancellations.append(attempt)
            return response

        task = asyncio.create_task(transport())
        await entered.wait()
        real_wait = asyncio.wait
        contended_waits = 0

        async def contended_wait(
            futures,
            *,
            timeout=None,
            return_when=asyncio.ALL_COMPLETED,
        ):
            nonlocal contended_waits
            if timeout is not None and timeout <= 0.01 and contended_waits < 2:
                # Model two scheduler-contention windows in which the cleanup
                # wait expires before the child receives a queued cancel().
                contended_waits += 1
                return set(), set(futures)
            return await real_wait(
                futures,
                timeout=timeout,
                return_when=return_when,
            )

        monkeypatch.setattr(outbound_policy_module.asyncio, "wait", contended_wait)
        started = time.monotonic()
        try:
            await outbound_policy_module._cancel_task_with_transport_cleanup(
                task,
                late_result_cleanup=outbound_policy_module._release_transport_response,
            )
            elapsed = time.monotonic() - started
            assert task.done()
            assert task.result() is response
            assert contended_cancellations == [0, 1]
            # The old fixed two-wait implementation consumes both simulated
            # contention windows before the child sees either cancellation;
            # the corrected handshake needs only the first window.
            assert contended_waits == 1
            assert contended_releases == ["released"]
            assert response.released is True
            assert elapsed < 0.25
        finally:
            monkeypatch.setattr(outbound_policy_module.asyncio, "wait", real_wait)
            for _ in range(4):
                if task.done():
                    break
                task.cancel()
                await asyncio.sleep(0)
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise_contention())
    eventual_releases: list[str] = []
    non_cooperative_cancellations: list[int] = []

    async def exercise_non_cooperative_cleanup() -> None:
        entered = asyncio.Event()
        finish = asyncio.Event()
        response = TransportResponse(
            status=200,
            headers={},
            body=b"eventual",
            release_callback=lambda: eventual_releases.append("released"),
        )

        async def transport() -> TransportResponse:
            entered.set()
            while not finish.is_set():
                try:
                    await finish.wait()
                except asyncio.CancelledError:
                    non_cooperative_cancellations.append(
                        len(non_cooperative_cancellations)
                    )
            return response

        task = asyncio.create_task(transport())
        await entered.wait()
        cleanup_budget = 0.02
        monkeypatch.setattr(
            outbound_policy_module,
            "_TRANSPORT_CLEANUP_BUDGET_SECONDS",
            cleanup_budget,
        )
        monkeypatch.setattr(
            outbound_policy_module,
            "_TRANSPORT_CLEANUP_POLL_SECONDS",
            0.002,
        )

        started = time.monotonic()
        try:
            await outbound_policy_module._cancel_task_with_transport_cleanup(
                task,
                late_result_cleanup=outbound_policy_module._release_transport_response,
            )
            elapsed = time.monotonic() - started
            assert task.done() is False
            assert non_cooperative_cancellations
            assert elapsed >= cleanup_budget
            assert elapsed < 0.25
            assert eventual_releases == []
        finally:
            finish.set()
            result = await asyncio.wait_for(asyncio.shield(task), timeout=0.25)

        assert result is response
        assert eventual_releases == ["released"]
        assert response.released is True

    asyncio.run(exercise_non_cooperative_cleanup())
    session.close()


def test_cancellation_check_exception_drains_late_transport_response(
    tmp_path,
) -> None:
    entered = False
    released: list[str] = []

    def cancellation_check() -> bool:
        if entered:
            raise RuntimeError("fixture cancellation check failed")
        return False

    policy, session = _policy(tmp_path, cancellation_check=cancellation_check)

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        nonlocal entered
        entered = True
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            return TransportResponse(
                status=200,
                headers={},
                body=b"late",
                release_callback=lambda: released.append("released"),
            )

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.CONNECTION_FAILED.value
    assert released == ["released"]
    session.close()


def test_malformed_transport_headers_release_raw_response(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    released: list[str] = []

    class BrokenHeaders(dict[str, str]):
        def items(self) -> ItemsView[str, str]:
            raise RuntimeError("fixture headers failed")

    async def transport(_request: HttpTransportRequest) -> TransportResponse:
        return TransportResponse(
            status=200,
            headers=BrokenHeaders(),
            body=b"malformed",
            release_callback=lambda: released.append("released"),
        )

    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.CONNECTION_FAILED.value
    assert released == ["released"]
    session.close()


async def _async_response(status: int) -> TransportResponse:
    return TransportResponse(status=status, headers={}, body=b"")


def test_cancellation_and_expired_permit_stop_before_transport(
    tmp_path,
    monkeypatch,
) -> None:
    cancelled = False
    clock = [NOW]
    monkeypatch.setattr(
        outbound_policy_module,
        "_system_utc_now",
        lambda: clock[0],
    )
    policy, session = _policy(
        tmp_path,
        cancellation_check=lambda: cancelled,
        permit_ttl_seconds=1,
    )
    prepared = policy.prepare_destination(TARGET, action_kind="http.request")
    permit = policy.authorize_resolution(prepared, ["127.0.0.1"])
    clock[0] = NOW + timedelta(seconds=2)
    with pytest.raises(OutboundDenied) as expired:
        policy.validate_connection_permit(permit, TARGET)
    assert expired.value.reason_code == OutboundReason.PERMIT_EXPIRED.value

    cancelled = True
    with pytest.raises(OutboundDenied) as denied:
        policy.prepare_destination(TARGET, action_kind="http.request")
    assert denied.value.reason_code == OutboundReason.CANCELLED.value
    session.close()


def test_resolution_timeout_is_bounded_and_records_failure(
    tmp_path,
    monkeypatch,
    caplog,
) -> None:
    policy, session = _policy(tmp_path, timeout_seconds=0.05)
    transports: list[str] = []
    resolver_cancellations: list[int] = []
    cleanup_handlers: list[Any] = []
    real_cleanup = outbound_policy_module._cancel_task_with_transport_cleanup

    async def record_cleanup_handler(
        task,
        *,
        late_result_cleanup,
    ) -> None:
        cleanup_handlers.append(late_result_cleanup)
        await real_cleanup(
            task,
            late_result_cleanup=late_result_cleanup,
        )

    monkeypatch.setattr(
        outbound_policy_module,
        "_cancel_task_with_transport_cleanup",
        record_cleanup_handler,
    )

    async def resolver(host: str, port: int) -> list[str]:
        for attempt in range(2):
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                resolver_cancellations.append(attempt)
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        transports.append(request.url)
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    async def exercise_resolution_timeout() -> OutboundDenied:
        with pytest.raises(OutboundDenied) as denied:
            await PolicyHttpClient(
                policy,
                resolver=resolver,
                transport=transport,
            ).get(TARGET)
        pending = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ]
        assert pending == []
        return denied.value

    denied = asyncio.run(exercise_resolution_timeout())

    assert denied.reason_code == OutboundReason.CONNECTION_FAILED.value
    assert transports == []
    assert resolver_cancellations == [0, 1]
    assert cleanup_handlers == [None]
    assert "Transport response release callback failed" not in caplog.text
    decisions = list_outbound_decisions(session)
    assert decisions[-1]["stage"] == "resolution"
    assert decisions[-1]["reason_code"] == OutboundReason.CONNECTION_FAILED.value
    session.close()

    transport_root = tmp_path / "late-transport"
    transport_root.mkdir()
    transport_policy, transport_session = _policy(
        transport_root,
        timeout_seconds=0.05,
    )
    released: list[str] = []
    late_responses: list[TransportResponse] = []

    async def late_transport(
        _request: HttpTransportRequest,
    ) -> TransportResponse:
        response = TransportResponse(
            status=200,
            headers={},
            body=b"late",
            release_callback=lambda: released.append("released"),
        )
        late_responses.append(response)
        for _attempt in range(2):
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                pass
        return response

    async def exercise_transport_timeout() -> OutboundDenied:
        with pytest.raises(OutboundDenied) as denied:
            await PolicyHttpClient(
                transport_policy,
                resolver=lambda host, port: _async_addresses_for_test(host),
                transport=late_transport,
            ).get(TARGET)
        pending = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ]
        assert pending == []
        return denied.value

    transport_denied = asyncio.run(exercise_transport_timeout())
    assert transport_denied.reason_code == OutboundReason.CONNECTION_FAILED.value
    assert cleanup_handlers == [
        None,
        outbound_policy_module._release_transport_response,
    ]
    assert released == ["released"]
    assert len(late_responses) == 1
    assert late_responses[0].released is True
    assert "Transport response release callback failed" not in caplog.text
    transport_session.close()


def test_delegated_metadata_oob_decoy_and_update_destinations_need_exact_authorization(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    destinations = [
        ("http://169.254.169.254/latest/meta-data", "metadata"),
        ("https://127.0.0.1:9443/callback", "oob"),
        ("https://127.0.0.2:8443/cover", "decoy"),
        ("https://127.0.0.1:9443/update", "update"),
    ]
    for destination, action_kind in destinations:
        with pytest.raises(OutboundDenied) as denied:
            policy.prepare_delegated_destination(
                destination,
                action_kind=action_kind,
            )
        assert denied.value.reason_code == OutboundReason.DELEGATED_DESTINATION_NOT_AUTHORIZED.value
    session.close()


@pytest.mark.parametrize(
    "target",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.170.2/v2/credentials/fixture",
        "http://169.254.170.23/v1/credentials",
        "http://[fd00:ec2::23]/v1/credentials",
    ],
)
def test_metadata_address_cannot_use_ordinary_http_action_even_in_broad_scope(
    tmp_path,
    target: str,
) -> None:
    host = normalize_destination(target).host
    network = f"{host}/128" if ":" in host else f"{host}/32"
    with pytest.raises(OutboundDenied) as denied:
        policy, session = _policy(
            tmp_path,
            target=target,
            allowed_scope=[network, target],
        )
        try:
            policy.prepare_destination(target, action_kind="http.request")
        finally:
            session.close()
    assert denied.value.reason_code == OutboundReason.DELEGATED_DESTINATION_NOT_AUTHORIZED.value


def test_insecure_tls_requires_local_lab_target_binding_and_audit(tmp_path) -> None:
    with pytest.raises(OutboundDenied) as denied:
        _policy(
            tmp_path / "active",
            lab_only_insecure_tls=True,
            insecure_tls_target=TARGET,
        )
    assert denied.value.reason_code == OutboundReason.INSECURE_TLS_NOT_AUTHORIZED.value

    lab_policy, lab_session = _policy(
        tmp_path / "lab",
        context_overrides={
            "safety_mode": SafetyMode.LOCAL_LAB,
            "high_risk_approval_required": True,
        },
        lab_only_insecure_tls=True,
        insecure_tls_target=TARGET,
        authorize_insecure_tls=True,
    )
    prepared = lab_policy.prepare_destination(TARGET, action_kind="http.request")
    assert prepared.verify_tls is False
    assert list_outbound_decisions(lab_session)[-1]["tls_mode"] == "lab_only_insecure"

    with pytest.raises(OutboundDenied):
        replace(
            lab_policy.context,
            insecure_tls_target="https://127.0.0.2:8443/",
        )
    lab_session.close()


def test_insecure_tls_context_rejects_unconsumed_and_wrong_boundary_child(
    tmp_path,
) -> None:
    session = create_db(tmp_path / "insecure-child-consumption.db")
    parent_expected = _authorization_context(
        safety_mode=SafetyMode.LOCAL_LAB,
        high_risk_approval_required=True,
    )
    parent = _consumed_envelope(session, parent_expected)
    child_expected = replace(
        parent_expected,
        action_kind="outbound.insecure_tls",
        parent_decision_id=parent.decision_id,
        confirmation_method=ConfirmationMethod.INHERITED,
    )
    child = derive_authorization(
        session=session,
        parent_envelope=parent,
        context=child_expected,
        parent_boundary="webforge.module",
        now=NOW,
    )
    assert child.allowed

    common = {
        "session": session,
        "envelope": parent,
        "expected": parent_expected,
        "boundary": "webforge.module",
        "authorized_target": TARGET,
        "allowed_scope": ALLOWED_SCOPE,
        "excluded_scope": [],
        "audit_sink": DatabaseOutboundAuditSink(session),
        "lab_only_insecure_tls": True,
        "insecure_tls_target": TARGET,
        "insecure_tls_authorization": child.envelope,
        "insecure_tls_expected": child_expected,
    }
    with pytest.raises(OutboundDenied) as unconsumed:
        OutboundContext.from_consumed_authorization(**common)
    assert (
        unconsumed.value.reason_code
        == OutboundReason.INSECURE_TLS_NOT_AUTHORIZED.value
    )

    wrong_boundary = consume_authorization(
        session=session,
        envelope=child.envelope,
        expected=child_expected,
        boundary="wrong.insecure_tls",
        now=NOW,
    )
    assert wrong_boundary.allowed
    with pytest.raises(OutboundDenied) as wrong:
        OutboundContext.from_consumed_authorization(**common)
    assert wrong.value.reason_code == OutboundReason.INSECURE_TLS_NOT_AUTHORIZED.value
    session.close()


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://user:password@127.0.0.1/", OutboundReason.USERINFO_NOT_ALLOWED),
        ("https://127.0.0.1\\@outside.test/", OutboundReason.MALFORMED_DESTINATION),
        ("http://2130706433/", OutboundReason.MALFORMED_DESTINATION),
        ("http://[fe80::1%25eth0]/", OutboundReason.MALFORMED_DESTINATION),
        ("https://faß.de/", OutboundReason.MALFORMED_DESTINATION),
        ("https://ｅxample.com/", OutboundReason.MALFORMED_DESTINATION),
        ("https://example.com../", OutboundReason.MALFORMED_DESTINATION),
        ("https://example.com:/", OutboundReason.MALFORMED_DESTINATION),
        (" https://127.0.0.1/", OutboundReason.MALFORMED_DESTINATION),
        ("https://127.0.0.1/ ", OutboundReason.MALFORMED_DESTINATION),
        ("\x00https://127.0.0.1/", OutboundReason.MALFORMED_DESTINATION),
        ("https://127.0.0.1\n/", OutboundReason.MALFORMED_DESTINATION),
        ("https://127.0.0.1\t/", OutboundReason.MALFORMED_DESTINATION),
        ("ftp://127.0.0.1/file", OutboundReason.UNSUPPORTED_SCHEME),
    ],
)
def test_ambiguous_destination_forms_are_rejected(url: str, reason: OutboundReason) -> None:
    with pytest.raises(OutboundDenied) as denied:
        normalize_destination(url)
    assert denied.value.reason_code == reason.value


def test_outbound_decisions_are_append_only(tmp_path) -> None:
    policy, session = _policy(tmp_path)
    policy.prepare_destination(TARGET, action_kind="http.request")

    with pytest.raises(DatabaseError):
        session.execute(text("UPDATE outbound_decisions SET outcome='allow'"))
        session.commit()
    session.rollback()
    with pytest.raises(DatabaseError):
        session.execute(text("DELETE FROM outbound_decisions"))
        session.commit()
    session.rollback()
    session.close()


def test_scan_time_connectivity_check_is_inert(monkeypatch) -> None:
    import socket
    import urllib.request
    from common import netcheck

    netcheck.reset_internet_decision()
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *args, **kwargs: pytest.fail("connectivity check opened a socket"),
    )
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: pytest.fail("connectivity check opened HTTP"),
    )

    assert netcheck.check_internet() is False
    assert netcheck.ask_internet_permission("scan-time fixture", force=True) is False


def test_module_output_merge_cannot_mutate_authorization_or_route_state() -> None:
    from common.base_module import merge_module_output_extra

    shared = {
        "allowed_scope": ["127.0.0.1/32"],
        "excluded_scope": [],
        "approved_egress_route": "trusted-route",
        "tenant_id": "tenant-a",
        "operator_id": "operator-a",
        "safety_mode": "active",
        "proxy": "http://127.0.0.1:18080",
    }
    isolated = {
        **shared,
        "allowed_scope": ["*"],
        "excluded_scope": [""],
        "approved_egress_route": "attacker-route",
        "tenant_id": "tenant-b",
        "operator_id": "operator-b",
        "safety_mode": "local_lab",
        "proxy": "http://127.0.0.1:1",
        "crawled_urls": ["https://127.0.0.1/child"],
    }

    merge_module_output_extra(shared, isolated)

    assert shared["allowed_scope"] == ["127.0.0.1/32"]
    assert shared["excluded_scope"] == []
    assert shared["approved_egress_route"] == "trusted-route"
    assert shared["tenant_id"] == "tenant-a"
    assert shared["operator_id"] == "operator-a"
    assert shared["safety_mode"] == "active"
    assert shared["proxy"] == "http://127.0.0.1:18080"
    assert shared["crawled_urls"] == ["https://127.0.0.1/child"]


def test_policy_response_exposes_aiohttp_compatible_content_type() -> None:
    response = PolicyResponse(
        status=200,
        headers={"Content-Type": "application/json; charset=utf-8"},
        body=b"{}",
        url=TARGET,
    )
    assert response.content_type == "application/json"


def test_schema_merge_handles_forms_without_endpoints() -> None:
    from common.config import BaseForgeConfig
    from webforge.webforge import _merge_schema_result

    cfg = BaseForgeConfig(target=TARGET)
    cfg.extra["allowed_scope"] = ["127.0.0.1/32", TARGET]
    result = SimpleNamespace(
        endpoints=[],
        forms=[{"action": TARGET, "method": "POST", "inputs": []}],
        auth_schemes=[],
        to_dict=lambda: {"endpoints": [], "forms": 1},
    )

    _merge_schema_result(cfg, result)

    assert cfg.extra["api_endpoints"] == []
    assert cfg.extra["found_forms"] == result.forms


def test_policy_forks_share_denial_truth_for_module_outcomes(tmp_path) -> None:
    policy, session = _policy(
        tmp_path,
        allowed_scope=["127.0.0.0/8", TARGET],
        excluded_scope=["127.0.0.2/32"],
    )
    child = policy.fork()

    with pytest.raises(OutboundDenied):
        child.prepare_destination(
            "https://127.0.0.2:8443/excluded",
            action_kind="http.request",

        )

    assert policy.last_denial_reason == OutboundReason.EXCLUDED.value
    session.close()


def test_untrusted_tls_fails_by_default_and_exact_lab_mode_is_audited(tmp_path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "fixture-cert.pem"
    key_path = tmp_path / "fixture-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    async def exercise() -> None:
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await reader.read(4096)
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(
            handler,
            "127.0.0.1",
            0,
            ssl=server_context,
        )
        port = int(server.sockets[0].getsockname()[1])
        target = f"https://127.0.0.1:{port}/"
        scope = ["127.0.0.1/32", target]
        try:
            verified_policy, verified_session = _policy(
                tmp_path / "verified",
                target=target,
                allowed_scope=scope,
            )
            with pytest.raises(OutboundDenied) as tls_denied:
                await PolicyHttpClient(verified_policy).get(target)
            assert tls_denied.value.reason_code == OutboundReason.TLS_VERIFICATION_FAILED.value
            verified_session.close()

            lab_policy, lab_session = _policy(
                tmp_path / "lab-tls",
                target=target,
                allowed_scope=scope,
                context_overrides={
                    "safety_mode": SafetyMode.LOCAL_LAB,
                    "high_risk_approval_required": True,
                },
                    lab_only_insecure_tls=True,
                    insecure_tls_target=target,
                    authorize_insecure_tls=True,
                )
            response = await PolicyHttpClient(lab_policy).get(target)
            assert response.status == 200
            assert await response.text() == "ok"
            assert any(
                item["tls_mode"] == "lab_only_insecure"
                for item in list_outbound_decisions(lab_session)
            )
            lab_session.close()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(exercise())


def test_lab_tls_child_expiry_is_live_bounded_and_audited(
    tmp_path,
    monkeypatch,
) -> None:
    clock = [NOW]
    monkeypatch.setattr(
        outbound_policy_module,
        "_system_utc_now",
        lambda: clock[0],
    )
    policy, session = _policy(
        tmp_path,
        context_overrides={
            "safety_mode": SafetyMode.LOCAL_LAB,
            "high_risk_approval_required": True,
        },
        lab_only_insecure_tls=True,
        insecure_tls_target=TARGET,
        authorize_insecure_tls=True,
        insecure_tls_ttl_seconds=1,
    )
    child = policy.context.insecure_tls_authorization
    assert child is not None

    prepared = policy.prepare_destination(TARGET, action_kind="http.request")
    permit = policy.authorize_resolution(prepared, ["127.0.0.1"])

    assert prepared.verify_tls is False
    assert prepared.expires_at == NOW + timedelta(seconds=1)
    assert permit.expires_at == NOW + timedelta(seconds=1)
    lab_records = [
        record
        for record in list_outbound_decisions(session)
        if record["tls_mode"] == "lab_only_insecure"
    ]
    assert lab_records
    assert all(
        record["detail"]["high_risk_child_decision_id"]
        == child.decision_id
        for record in lab_records
    )

    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append("resolver")
        return [host]

    async def transport(request: HttpTransportRequest) -> TransportResponse:
        calls.append("transport")
        return TransportResponse(status=200, headers={}, body=b"unexpected")

    late_request = HttpTransportRequest(
        method="GET",
        url=TARGET,
        headers={},
        permit=permit,
        prepared=prepared,
        route=None,
        timeout_seconds=1.0,
        max_response_bytes=1024,
    )
    clock[0] = NOW + timedelta(seconds=2)
    with pytest.raises(OutboundDenied) as transport_denied:
        asyncio.run(
            PolicyBoundTransport(policy, transport)(late_request)
        )
    assert (
        transport_denied.value.reason_code
        == OutboundReason.INSECURE_TLS_NOT_AUTHORIZED.value
    )
    assert calls == []

    late_policy = OutboundPolicy(policy.context)
    with pytest.raises(OutboundDenied) as denied:
        asyncio.run(
            PolicyHttpClient(
                late_policy,
                resolver=resolver,
                transport=transport,
            ).get(TARGET)
        )

    assert denied.value.reason_code == OutboundReason.INSECURE_TLS_NOT_AUTHORIZED.value
    assert calls == []
    session.close()


def test_trusted_certificate_with_wrong_hostname_fails_closed(
    tmp_path,
    monkeypatch,
) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Forge Test CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong.test")])
    leaf_certificate = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("wrong.test")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "trusted-ca.pem"
    cert_path = tmp_path / "wrong-host-cert.pem"
    key_path = tmp_path / "wrong-host-key.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf_certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    async def exercise() -> None:
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)

        async def handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            try:
                await reader.read(4096)
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(
            handler,
            "127.0.0.1",
            0,
            ssl=server_context,
        )
        port = int(server.sockets[0].getsockname()[1])
        target = f"https://allowed.test:{port}/"
        policy, session = _policy(
            tmp_path / "wrong-host",
            target=target,
            allowed_scope=["allowed.test", "127.0.0.1/32", target],
        )
        client_context = ssl.create_default_context(cafile=str(ca_path))
        monkeypatch.setattr(
            "common.outbound_policy.ssl.create_default_context",
            lambda: client_context,
        )
        try:
            with pytest.raises(OutboundDenied) as denied:
                await PolicyHttpClient(
                    policy,
                    resolver=lambda host, port: _async_addresses_for_test(
                        "127.0.0.1"
                    ),
                ).get(target)
            assert denied.value.reason_code == OutboundReason.TLS_VERIFICATION_FAILED.value
        finally:
            session.close()
            server.close()
            await server.wait_closed()

    asyncio.run(exercise())


def test_delayed_response_chunks_cannot_bypass_body_limit(tmp_path) -> None:
    async def exercise() -> None:
        async def handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            try:
                await reader.readuntil(b"\r\n\r\n")
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 110\r\n"
                    b"Connection: close\r\n\r\n"
                    + b"A" * 10
                )
                await writer.drain()
                await asyncio.sleep(0.03)
                writer.write(b"B" * 100)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = int(server.sockets[0].getsockname()[1])
        target = f"http://127.0.0.1:{port}/slow"
        policy, session = _policy(
            tmp_path,
            target=target,
            allowed_scope=["127.0.0.1/32", target],
            max_response_bytes=50,
        )
        try:
            with pytest.raises(OutboundDenied) as denied:
                await PolicyHttpClient(policy).get(target)
            assert denied.value.reason_code == OutboundReason.RESPONSE_TOO_LARGE.value
        finally:
            session.close()
            server.close()
            await server.wait_closed()

    asyncio.run(exercise())


def test_metadata_oob_and_decoy_surfaces_make_zero_unapproved_calls(
    tmp_path,
    monkeypatch,
) -> None:
    import socket
    import aiohttp

    from common.config import BaseForgeConfig
    from common.scope import Scope
    from netforge.core.opsec import OpSecLevel, OpSecProfile
    from netforge.modules.services.cloud_metadata import CloudMetadata
    from webforge.modules.injection.log4shell_scanner import Log4ShellScanner

    monkeypatch.setattr(
        aiohttp,
        "ClientSession",
        lambda *args, **kwargs: pytest.fail("unapproved client was created"),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda *args, **kwargs: pytest.fail("unapproved decoy DNS was sent"),
    )
    config = BaseForgeConfig(target="127.0.0.1")
    scope = Scope(["127.0.0.1/32"])
    session = create_db(tmp_path / "special-destinations.db")
    try:
        metadata = CloudMetadata(config, scope, session, tmp_path)
        metadata_result = asyncio.run(metadata.run())
        assert metadata_result.skipped is True
        assert metadata_result.skip_reason == "outbound_policy_unsupported"

        web_config = BaseForgeConfig(target="http://127.0.0.1")
        log4shell = Log4ShellScanner(web_config, scope, session, tmp_path)
        oob_result = asyncio.run(log4shell.run())
        assert oob_result.skipped is True
        assert oob_result.skip_reason == "outbound_policy_unsupported"

        profile = OpSecProfile(
            level=OpSecLevel.STEALTH,
            inject_decoys=True,
            decoy_ratio=1.0,
        )
        asyncio.run(profile.maybe_inject_decoy())
        assert profile.stats["decoys_injected"] == 0
    finally:
        session.close()


def test_remote_event_bus_is_disabled_without_control_plane_authorization(monkeypatch) -> None:
    import urllib.request
    from common.dashboard.event_bus import Event, EventType, RemoteEventBus

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: pytest.fail("remote event traffic was sent"),
    )
    bus = RemoteEventBus("https://127.0.0.1:1337", run_id="fixture")
    started = bus.start()
    bus.emit(Event(event_type=EventType.SCAN_START, data={}, source="fixture"))
    bus.stop()

    assert started is False
    assert bus.disabled_reason == "remote_event_destination_not_authorized"
    assert bus._thread is None
