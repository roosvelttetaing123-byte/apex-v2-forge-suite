"""Fail-closed outbound destination, resolution, TLS, redirect, and route policy.

The Work Package 001 scope decision and Work Package 002 consumed action
authorization remain authoritative.  This module binds each outbound attempt
to that retained authorization, decides the logical destination before DNS,
then validates and pins every resolved address before a transport may connect.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
from http.cookies import SimpleCookie
import ipaddress
import json
import logging
import math
import re
import secrets
import socket
import ssl
import uuid
import weakref
from collections.abc import Awaitable, Callable, Coroutine, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import FunctionType
from typing import Any, Protocol, cast
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult
from yarl import URL
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from common.action_authorization import (
    MAX_FUTURE_SKEW_SECONDS,
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    SafetyMode,
    open_authorization_session,
    redact_authorization_value,
    validate_consumed_authorization,
)
from common.db import (
    RouteHealthConfigurationChangedError,
    RouteHealthIdentityChangedError,
    append_outbound_decision,
    append_route_health_evidence,
    append_route_health_invalidation,
    get_outbound_decision,
    outbound_decision_to_dict,
    route_health_store_is_current,
)
from common.scope import ScopeReason, canonical_target, decide_scope


_LOGGER = logging.getLogger(__name__)
OUTBOUND_SCHEMA_VERSION = "forge-outbound-decision-v1"
ROUTE_SCHEMA_VERSION = "forge-approved-egress-route-v1"
ROUTE_HEALTH_SCHEMA_VERSION = "forge-route-health-evidence-v1"
ROUTE_HEALTH_INVALIDATION_SCHEMA_VERSION = "forge-route-health-invalidation-v1"
ROUTE_HEALTH_TTL_SECONDS = 300
MAX_OUTBOUND_RESPONSE_BYTES = 64 * 1024 * 1024
_SHA256_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,199}$")
_AMBIGUOUS_IPV4 = re.compile(
    r"^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$",
    re.IGNORECASE,
)
_SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "api-key",
    }
)
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_RETRY_STATUSES = frozenset({429, 502, 503, 504})
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
_SAFE_REQUEST_OPTIONS = frozenset({"data", "json"})
_FIXED_METADATA_NAMES = frozenset({"metadata.google.internal"})
_FIXED_METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "169.254.170.23",
        "100.100.100.200",
        "fd00:ec2::23",
        "fd00:ec2::254",
    }
)
_PROXY_ENVIRONMENT_KEYS = frozenset(
    {"http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy"}
)


class OutboundReason(str, Enum):
    ALLOWED = "allowed"
    MALFORMED_DESTINATION = "malformed_destination"
    UNSUPPORTED_SCHEME = "unsupported_scheme"
    USERINFO_NOT_ALLOWED = "userinfo_not_allowed"
    HOST_OUT_OF_SCOPE = "host_out_of_scope"
    EXCLUDED = "excluded"
    PORT_NOT_AUTHORIZED = "port_not_authorized"
    EMPTY_DNS_ANSWER = "empty_dns_answer"
    MALFORMED_DNS_ANSWER = "malformed_dns_answer"
    RESOLVED_IP_OUT_OF_SCOPE = "resolved_ip_out_of_scope"
    DNS_ANSWER_CHANGED = "dns_answer_changed"
    PERMIT_EXPIRED = "permit_expired"
    PERMIT_NOT_YET_VALID = "permit_not_yet_valid"
    PERMIT_MISMATCH = "permit_mismatch"
    PERMIT_REPLAYED = "permit_replayed"
    REDIRECT_LIMIT_EXCEEDED = "redirect_limit_exceeded"
    RETRY_LIMIT_EXCEEDED = "retry_limit_exceeded"
    RETRY_NOT_IDEMPOTENT = "retry_not_idempotent"
    RESPONSE_TOO_LARGE = "response_too_large"
    CANCELLED = "cancelled"
    AUTHORIZATION_INVALID = "authorization_invalid"
    AUTHORIZATION_NOT_YET_VALID = "authorization_not_yet_valid"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    AUDIT_PERSISTENCE_FAILED = "audit_persistence_failed"
    INSECURE_TLS_NOT_AUTHORIZED = "insecure_tls_not_authorized"
    TLS_VERIFICATION_FAILED = "tls_verification_failed"
    CONNECTION_FAILED = "connection_failed"
    TRANSPORT_CLEANUP_FAILED = "transport_cleanup_failed"
    DELEGATED_DESTINATION_NOT_AUTHORIZED = "delegated_destination_not_authorized"
    ROUTE_REQUIRED = "route_required"
    ROUTE_NOT_YET_VALID = "route_not_yet_valid"
    ROUTE_EXPIRED = "route_expired"
    ROUTE_BINDING_MISMATCH = "route_binding_mismatch"
    ROUTE_HEALTH_REQUIRED = "route_health_required"
    ROUTE_IDENTITY_CHANGED = "route_identity_changed"
    ROUTE_CONFIGURATION_CHANGED = "route_configuration_changed"
    UNSUPPORTED_ROUTE_TRANSPORT = "unsupported_route_transport"
    DNS_LEAK_UNVERIFIABLE = "dns_leak_unverifiable"
    OUTBOUND_POLICY_UNSUPPORTED = "outbound_policy_unsupported"
    REQUEST_OPTION_NOT_ALLOWED = "request_option_not_allowed"
    CROSS_ORIGIN_BODY_NOT_AUTHORIZED = "cross_origin_body_not_authorized"
    ROUTE_PREFLIGHT_FAILED = "route_preflight_failed"
    LITERAL_ADDRESS_MISMATCH = "literal_address_mismatch"


_REASON_TEXT: dict[OutboundReason, str] = {
    OutboundReason.ALLOWED: "The exact outbound destination and resolved addresses are authorized.",
    OutboundReason.MALFORMED_DESTINATION: "The outbound destination is malformed or ambiguous.",
    OutboundReason.UNSUPPORTED_SCHEME: "The outbound destination scheme is unsupported.",
    OutboundReason.USERINFO_NOT_ALLOWED: "Credentials in destination URLs are prohibited.",
    OutboundReason.HOST_OUT_OF_SCOPE: "The logical destination host is outside the effective scope.",
    OutboundReason.EXCLUDED: "The logical destination intersects an explicit exclusion.",
    OutboundReason.PORT_NOT_AUTHORIZED: "The destination port is not authorized for this origin.",
    OutboundReason.EMPTY_DNS_ANSWER: "DNS returned no usable destination address.",
    OutboundReason.MALFORMED_DNS_ANSWER: "DNS returned a malformed or ambiguous address.",
    OutboundReason.RESOLVED_IP_OUT_OF_SCOPE: "At least one resolved address is outside the effective scope.",
    OutboundReason.DNS_ANSWER_CHANGED: "The DNS answer changed during the authorized connection attempt.",
    OutboundReason.PERMIT_EXPIRED: "The pinned connection permit expired before use.",
    OutboundReason.PERMIT_NOT_YET_VALID: "The pinned connection permit predates its valid clock window.",
    OutboundReason.PERMIT_MISMATCH: "The connection does not match its pinned permit.",
    OutboundReason.PERMIT_REPLAYED: "The one-use connection permit was replayed.",
    OutboundReason.REDIRECT_LIMIT_EXCEEDED: "The redirect chain exceeded its configured bound.",
    OutboundReason.RETRY_LIMIT_EXCEEDED: "The request retry count exceeded its configured bound.",
    OutboundReason.RETRY_NOT_IDEMPOTENT: "The operation is not safe to retry without an idempotency contract.",
    OutboundReason.RESPONSE_TOO_LARGE: "The response exceeded its configured size bound.",
    OutboundReason.CANCELLED: "The outbound operation was canceled before connection.",
    OutboundReason.AUTHORIZATION_INVALID: "The retained action authorization is invalid for outbound use.",
    OutboundReason.AUTHORIZATION_NOT_YET_VALID: "The retained action authorization is not yet valid.",
    OutboundReason.AUTHORIZATION_EXPIRED: "The retained action authorization expired.",
    OutboundReason.AUDIT_PERSISTENCE_FAILED: "The outbound audit could not be persisted; connection was denied.",
    OutboundReason.INSECURE_TLS_NOT_AUTHORIZED: "Lab-only insecure TLS lacks exact high-risk authorization.",
    OutboundReason.TLS_VERIFICATION_FAILED: "TLS certificate or host identity verification failed.",
    OutboundReason.CONNECTION_FAILED: "The authorized outbound connection failed.",
    OutboundReason.TRANSPORT_CLEANUP_FAILED: "The outbound transport response could not be released cleanly.",
    OutboundReason.DELEGATED_DESTINATION_NOT_AUTHORIZED: "The delegated destination lacks its own exact authorization.",
    OutboundReason.ROUTE_REQUIRED: "The action requires an approved egress route.",
    OutboundReason.ROUTE_NOT_YET_VALID: "The approved egress route is not yet valid.",
    OutboundReason.ROUTE_EXPIRED: "The approved egress route expired.",
    OutboundReason.ROUTE_BINDING_MISMATCH: "The approved egress route does not match this action.",
    OutboundReason.ROUTE_HEALTH_REQUIRED: "A fresh route-health preflight is required before connection.",
    OutboundReason.ROUTE_IDENTITY_CHANGED: "The observed egress route identity changed; execution is paused.",
    OutboundReason.ROUTE_CONFIGURATION_CHANGED: "The approved route configuration changed; execution is paused.",
    OutboundReason.UNSUPPORTED_ROUTE_TRANSPORT: "The required route cannot safely carry this protocol or tool.",
    OutboundReason.DNS_LEAK_UNVERIFIABLE: "The route DNS behavior cannot prove destination enforcement.",
    OutboundReason.OUTBOUND_POLICY_UNSUPPORTED: "The module has an unmigrated outbound path and was not tested.",
    OutboundReason.REQUEST_OPTION_NOT_ALLOWED: "A request option could bypass the outbound transport policy.",
    OutboundReason.CROSS_ORIGIN_BODY_NOT_AUTHORIZED: "A request body cannot be replayed to a different origin without separate authorization.",
    OutboundReason.ROUTE_PREFLIGHT_FAILED: "The approved route preflight did not produce valid health evidence.",
    OutboundReason.LITERAL_ADDRESS_MISMATCH: "The resolved socket address does not match the authorized IP literal.",
}


class DnsMode(str, Enum):
    LOCAL_PINNED = "local_pinned"
    ROUTE_VERIFIED = "route_verified"
    REMOTE_UNVERIFIED = "remote_unverified"


class RouteVerificationPolicy(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"


class OutboundDenied(RuntimeError):
    """Safe policy denial that never reflects submitted URLs or secrets."""

    def __init__(self, reason: OutboundReason | str) -> None:
        code = reason.value if isinstance(reason, OutboundReason) else str(reason)
        self.reason_code = code
        try:
            message = _REASON_TEXT[OutboundReason(code)]
        except (KeyError, ValueError):
            message = "The outbound action was denied."
        super().__init__(f"{code}: {message}")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _system_utc_now() -> datetime:
    """Return the process wall clock used at target-affecting boundaries."""
    return datetime.now(timezone.utc)


def _trusted_utc_now() -> datetime:
    """Stable indirection for factory provenance and live wall-clock checks."""
    return _system_utc_now()


def _now(value: datetime | None) -> datetime:
    return _system_utc_now() if value is None else _utc(value)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _integrity_timestamp(value: datetime) -> str:
    """Serialize the full datetime precision used by integrity bindings."""
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _before_valid_window(current: datetime, issued_at: datetime) -> bool:
    return current < issued_at - timedelta(seconds=MAX_FUTURE_SKEW_SECONDS)


def _parse_timestamp(value: str) -> datetime:
    return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _digest(value: Mapping[str, Any] | Iterable[Any] | str) -> str:
    if isinstance(value, str):
        material = value
    else:
        material = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"sha256:{hashlib.sha256(material.encode('utf-8', 'replace')).hexdigest()}"


def _hmac_digest(key: bytes, value: Mapping[str, Any]) -> str:
    material = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8", "replace")
    return f"hmac-sha256:{hmac.new(key, material, hashlib.sha256).hexdigest()}"


def _safe_identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _SAFE_IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{field_name} is malformed")
    return value.strip()


def _scope_snapshot(allowed: Iterable[str], excluded: Iterable[str]) -> str:
    return _digest(
        {
            "allowed": sorted(str(item).strip() for item in allowed),
            "excluded": sorted(str(item).strip() for item in excluded),
        }
    )


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _canonical_ip_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Collapse IPv4-mapped IPv6 aliases before scope or metadata decisions."""
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _format_host(host: str) -> str:
    try:
        address = _canonical_ip_address(host)
    except ValueError:
        return host
    return f"[{address}]" if address.version == 6 else str(address)


def _normalize_host_value(host_value: str) -> str:
    if not host_value or "%" in host_value or host_value.endswith("."):
        raise ValueError("host is malformed")
    try:
        return str(_canonical_ip_address(host_value))
    except ValueError:
        if not host_value.isascii():
            raise ValueError("host must use canonical ASCII labels")
        lowered = host_value.lower()
        if not lowered or _AMBIGUOUS_IPV4.fullmatch(lowered):
            raise ValueError("host is ambiguous")
        labels = lowered.split(".")
        if (
            len(lowered) > 253
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not re.fullmatch(r"[a-z0-9-]+", label)
                for label in labels
            )
        ):
            raise ValueError("host labels are malformed")
        return lowered


def _canonical_host_header(destination: "NormalizedDestination") -> str:
    value = _format_host(destination.host)
    if destination.port != _default_port(destination.scheme):
        value = f"{value}:{destination.port}"
    return value


def _headers_with_canonical_host(
    headers: Mapping[str, str],
    destination: "NormalizedDestination",
) -> dict[str, str]:
    result = {
        str(key): str(value)
        for key, value in headers.items()
        if str(key).strip().lower() not in {"host", ":authority"}
    }
    result["Host"] = _canonical_host_header(destination)
    return result


def _is_fixed_metadata_destination(host: str) -> bool:
    if host in _FIXED_METADATA_NAMES:
        return True
    try:
        return str(_canonical_ip_address(host)) in _FIXED_METADATA_ADDRESSES
    except ValueError:
        return False


@dataclass(frozen=True)
class NormalizedDestination:
    url: str
    scheme: str
    host: str
    port: int
    origin: str
    destination_ref: str


def normalize_destination(url: str) -> NormalizedDestination:
    """Strictly normalize an HTTP(S) destination without resolving it."""
    if not isinstance(url, str):
        raise OutboundDenied(OutboundReason.MALFORMED_DESTINATION)
    raw = url
    if (
        not raw
        or raw != raw.strip()
        or "\\" in raw
        or any(ord(char) < 32 for char in raw)
        or any(char.isspace() for char in raw)
    ):
        raise OutboundDenied(OutboundReason.MALFORMED_DESTINATION)
    try:
        parsed = urlsplit(raw)
        port_value = parsed.port
    except ValueError as exc:
        raise OutboundDenied(OutboundReason.MALFORMED_DESTINATION) from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise OutboundDenied(OutboundReason.UNSUPPORTED_SCHEME)
    if parsed.username is not None or parsed.password is not None:
        raise OutboundDenied(OutboundReason.USERINFO_NOT_ALLOWED)
    if parsed.netloc.endswith(":"):
        raise OutboundDenied(OutboundReason.MALFORMED_DESTINATION)
    try:
        host = _normalize_host_value(parsed.hostname or "")
    except ValueError:
        # Gate 0 accepts canonical ASCII DNS labels/A-labels only.  This
        # avoids transitional-IDNA and Unicode-dot host aliasing until a
        # pinned IDNA2008 implementation is part of the contract.
        raise OutboundDenied(OutboundReason.MALFORMED_DESTINATION)
    port = _default_port(scheme) if port_value is None else port_value
    if port < 1 or port > 65535:
        raise OutboundDenied(OutboundReason.MALFORMED_DESTINATION)
    formatted_host = _format_host(host)
    default_port = _default_port(scheme)
    netloc = formatted_host if port_value is None or port == default_port else f"{formatted_host}:{port}"
    # Match the URL canonicalization performed by aiohttp's yarl-backed
    # transport.  Policy checks (including cookie path provenance) must use
    # the path/query that will actually reach the server, rather than a raw
    # dot-segment or percent-encoded spelling supplied by the caller.
    canonical_input = urlunsplit(
        (scheme, netloc, parsed.path or "/", parsed.query, "")
    )
    try:
        normalized_url = str(URL(canonical_input))
    except (TypeError, ValueError) as exc:
        raise OutboundDenied(OutboundReason.MALFORMED_DESTINATION) from exc
    origin = f"{scheme}://{formatted_host}:{port}"
    return NormalizedDestination(
        url=normalized_url,
        scheme=scheme,
        host=host,
        port=port,
        origin=origin,
        destination_ref=canonical_target(normalized_url),
    )


@dataclass(frozen=True)
class CredentialBinding:
    """Origin and protected names for credentials assembled per request."""

    origin: str
    protected_headers: tuple[str, ...] = (
        "authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
        "api-key",
    )

    @classmethod
    def for_origin(
        cls,
        url: str,
        *,
        protected_headers: Iterable[str] | None = None,
    ) -> "CredentialBinding":
        destination = normalize_destination(url)
        names = cls.__dataclass_fields__["protected_headers"].default
        if protected_headers is not None:
            names = tuple(sorted({str(item).strip().lower() for item in protected_headers if str(item).strip()}))
        return cls(origin=destination.origin, protected_headers=cast(tuple[str, ...], names))

    def __post_init__(self) -> None:
        normalized = normalize_destination(self.origin)
        if normalized.url.split("?", 1)[0].rstrip("/") != normalized.origin:
            object.__setattr__(self, "origin", normalized.origin)
        object.__setattr__(
            self,
            "protected_headers",
            tuple(sorted({item.strip().lower() for item in self.protected_headers if item.strip()})),
        )


def strip_origin_bound_secrets(
    headers: Mapping[str, str] | None,
    *,
    destination_origin: str,
    binding: CredentialBinding,
) -> dict[str, str]:
    """Build per-hop headers; proxy auth is never accepted as a target header."""
    same_origin = hmac.compare_digest(destination_origin, binding.origin)
    result: dict[str, str] = {}
    for raw_name, raw_value in (headers or {}).items():
        name = str(raw_name)
        lower_name = name.strip().lower()
        if lower_name == "proxy-authorization":
            continue
        if not same_origin:
            # Caller/session header values have no trustworthy provenance.
            # Even a nominal metadata header (Accept, Content-Type, etc.) can
            # be configured as the credential carrier, so retain none across
            # an origin change.  Transport-owned Host/SNI are regenerated
            # after this boundary.
            continue
        result[name] = str(raw_value)
    return result


def cookie_path_matches(request_path: str, cookie_path: str) -> bool:
    """Apply RFC 6265 path-match semantics for retained browser cookies."""
    if not cookie_path.startswith("/"):
        return False
    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or request_path[len(cookie_path):].startswith("/")


def cookie_provenance_matches_destination(
    provenance: Mapping[str, Any] | None,
    destination_url: str,
) -> bool:
    """Revalidate imported browser-cookie origin/domain/path/Secure scope."""
    if not isinstance(provenance, Mapping):
        return False
    try:
        destination = normalize_destination(destination_url)
    except OutboundDenied:
        return False
    if not hmac.compare_digest(
        str(provenance.get("origin", "")),
        destination.origin,
    ):
        return False
    domain = str(provenance.get("domain", ""))
    if not domain:
        return False
    host_only = provenance.get("host_only")
    secure = provenance.get("secure")
    if type(host_only) is not bool or type(secure) is not bool:
        return False
    if host_only:
        if destination.host != domain:
            return False
    elif not (
        destination.host == domain
        or destination.host.endswith(f".{domain}")
    ):
        return False
    request_path = urlsplit(destination.url).path or "/"
    if not cookie_path_matches(request_path, str(provenance.get("path", ""))):
        return False
    if secure and destination.scheme != "https":
        return False
    return True


def _normalized_proxy_origin(proxy_url: str) -> str:
    if not proxy_url:
        return ""
    if (
        not isinstance(proxy_url, str)
        or proxy_url != proxy_url.strip()
        or "\\" in proxy_url
        or any(ord(char) < 32 for char in proxy_url)
        or any(char.isspace() for char in proxy_url)
    ):
        raise ValueError("proxy URL is malformed")
    try:
        proxy = urlsplit(proxy_url)
        proxy_port = proxy.port
    except ValueError as exc:
        raise ValueError("proxy URL is malformed") from exc
    if proxy.username is not None or proxy.password is not None:
        raise ValueError("proxy URL userinfo is prohibited")
    if proxy.netloc.endswith(":"):
        raise ValueError("proxy URL port is malformed")
    scheme = proxy.scheme.lower()
    if scheme not in {"http", "https", "socks5", "socks5h"}:
        raise ValueError("proxy URL is unsupported")
    try:
        host = _normalize_host_value(proxy.hostname or "")
    except ValueError as exc:
        raise ValueError("proxy URL host is malformed") from exc
    if proxy.path not in {"", "/"} or proxy.query or proxy.fragment:
        raise ValueError("proxy URL must contain only an origin")
    port = ({
        "http": 80,
        "https": 443,
        "socks5": 1080,
        "socks5h": 1080,
    }[scheme] if proxy_port is None else proxy_port)
    if not 1 <= port <= 65535:
        raise ValueError("proxy URL port is invalid")
    return f"{scheme}://{_format_host(host)}:{port}"


def scrub_proxy_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Remove ambient proxy routing and credentials from child environments."""
    return {
        str(key): str(value)
        for key, value in environment.items()
        if str(key).lower() not in _PROXY_ENVIRONMENT_KEYS
    }


def approved_route_configuration_digest(
    *,
    schema_version: str,
    route_id: str,
    tenant_id: str,
    engagement_id: str,
    action_id: str,
    operator_id: str,
    dns_mode: DnsMode | str,
    allowed_protocols: Iterable[str],
    allowed_tools: Iterable[str],
    verification_policy: RouteVerificationPolicy | str,
    verification_endpoint: str,
    proxy_url: str,
    proxy_credential_reference: str,
    required: bool,
    issued_at: datetime,
    expires_at: datetime,
) -> str:
    """Digest every non-secret route field so a caller cannot mask drift."""
    return _digest(
        {
            "schema_version": str(schema_version),
            "route_id": str(route_id),
            "tenant_id": str(tenant_id),
            "engagement_id": str(engagement_id),
            "action_id": str(action_id),
            "operator_id": str(operator_id),
            "dns_mode": DnsMode(dns_mode).value,
            "allowed_protocols": sorted(
                {str(item).strip().lower() for item in allowed_protocols if str(item).strip()}
            ),
            "allowed_tools": sorted(
                {str(item).strip().lower() for item in allowed_tools if str(item).strip()}
            ),
            "verification_policy": RouteVerificationPolicy(verification_policy).value,
            "verification_endpoint_ref": normalize_destination(
                verification_endpoint
            ).destination_ref,
            "proxy_origin": _normalized_proxy_origin(proxy_url),
            "proxy_credential_reference_digest": (
                _digest(proxy_credential_reference)
                if proxy_credential_reference
                else ""
            ),
            "required": bool(required),
            "issued_at": _integrity_timestamp(issued_at),
            "expires_at": _integrity_timestamp(expires_at),
        }
    )


@dataclass(frozen=True)
class ApprovedEgressRoute:
    schema_version: str
    route_id: str
    tenant_id: str
    engagement_id: str
    action_id: str
    operator_id: str
    configuration_digest: str
    dns_mode: DnsMode | str
    allowed_protocols: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    verification_policy: RouteVerificationPolicy | str
    verification_endpoint: str
    proxy_url: str
    proxy_credential_reference: str
    required: bool
    issued_at: datetime
    expires_at: datetime

    @classmethod
    def from_value(
        cls,
        value: "ApprovedEgressRoute | Mapping[str, Any]",
    ) -> "ApprovedEgressRoute":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise ValueError("approved route must be a mapping")
        fields = tuple(cls.__dataclass_fields__)
        if set(value) != set(fields):
            raise ValueError("approved route fields are incomplete or unknown")
        values = dict(value)
        for name in ("issued_at", "expires_at"):
            raw = values[name]
            if isinstance(raw, str):
                values[name] = _parse_timestamp(raw)
            elif not isinstance(raw, datetime):
                raise ValueError(f"{name} must be a timestamp")
        for name in ("allowed_protocols", "allowed_tools"):
            raw = values[name]
            if isinstance(raw, str) or not isinstance(raw, (list, tuple)):
                raise ValueError(f"{name} must be a list")
            values[name] = tuple(raw)
        if type(values["required"]) is not bool:
            raise ValueError("route required must be boolean")
        return cls(**values)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "route_id": self.route_id,
            "tenant_id": self.tenant_id,
            "engagement_id": self.engagement_id,
            "action_id": self.action_id,
            "operator_id": self.operator_id,
            "configuration_digest": self.configuration_digest,
            "dns_mode": cast(DnsMode, self.dns_mode).value,
            "allowed_protocols": list(self.allowed_protocols),
            "allowed_tools": list(self.allowed_tools),
            "verification_policy": cast(RouteVerificationPolicy, self.verification_policy).value,
            "verification_endpoint": self.verification_endpoint,
            "proxy_url": self.proxy_url,
            "proxy_credential_reference": self.proxy_credential_reference,
            "required": self.required,
            "issued_at": _integrity_timestamp(self.issued_at),
            "expires_at": _integrity_timestamp(self.expires_at),
        }

    def __post_init__(self) -> None:
        if self.schema_version != ROUTE_SCHEMA_VERSION:
            raise ValueError("unsupported approved route schema")
        for name in ("route_id", "tenant_id", "engagement_id", "action_id", "operator_id"):
            _safe_identifier(str(getattr(self, name)), name)
        if not _SHA256_REF.fullmatch(self.configuration_digest):
            raise ValueError("route configuration digest is malformed")
        object.__setattr__(self, "dns_mode", DnsMode(self.dns_mode))
        object.__setattr__(self, "verification_policy", RouteVerificationPolicy(self.verification_policy))
        object.__setattr__(
            self,
            "allowed_protocols",
            tuple(sorted({str(item).strip().lower() for item in self.allowed_protocols if str(item).strip()})),
        )
        object.__setattr__(
            self,
            "allowed_tools",
            tuple(sorted({str(item).strip().lower() for item in self.allowed_tools if str(item).strip()})),
        )
        if type(self.required) is not bool:
            raise ValueError("route required must be boolean")
        issued_at = _utc(self.issued_at)
        expires_at = _utc(self.expires_at)
        if expires_at <= issued_at:
            raise ValueError("route expiry must follow issue time")
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)
        verification = normalize_destination(self.verification_endpoint)
        if verification.scheme != "https":
            raise ValueError("route verification endpoint must use HTTPS")
        object.__setattr__(self, "verification_endpoint", verification.url)
        object.__setattr__(self, "proxy_url", _normalized_proxy_origin(self.proxy_url))
        if self.proxy_credential_reference and (
            not self.proxy_credential_reference.startswith("cred:")
            or any(char.isspace() for char in self.proxy_credential_reference)
        ):
            raise ValueError("proxy credential must be an opaque reference")
        expected_digest = approved_route_configuration_digest(
            schema_version=self.schema_version,
            route_id=self.route_id,
            tenant_id=self.tenant_id,
            engagement_id=self.engagement_id,
            action_id=self.action_id,
            operator_id=self.operator_id,
            dns_mode=cast(DnsMode, self.dns_mode),
            allowed_protocols=self.allowed_protocols,
            allowed_tools=self.allowed_tools,
            verification_policy=cast(RouteVerificationPolicy, self.verification_policy),
            verification_endpoint=self.verification_endpoint,
            proxy_url=self.proxy_url,
            proxy_credential_reference=self.proxy_credential_reference,
            required=self.required,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
        )
        if not hmac.compare_digest(self.configuration_digest, expected_digest):
            raise ValueError("route configuration digest does not match route fields")

    def with_action_id(self, action_id: str) -> "ApprovedEgressRoute":
        values = self.to_dict()
        values["action_id"] = action_id
        values["configuration_digest"] = approved_route_configuration_digest(
            schema_version=str(values["schema_version"]),
            route_id=str(values["route_id"]),
            tenant_id=str(values["tenant_id"]),
            engagement_id=str(values["engagement_id"]),
            action_id=str(values["action_id"]),
            operator_id=str(values["operator_id"]),
            dns_mode=str(values["dns_mode"]),
            allowed_protocols=cast(Iterable[str], values["allowed_protocols"]),
            allowed_tools=cast(Iterable[str], values["allowed_tools"]),
            verification_policy=str(values["verification_policy"]),
            verification_endpoint=str(values["verification_endpoint"]),
            proxy_url=str(values["proxy_url"]),
            proxy_credential_reference=str(values["proxy_credential_reference"]),
            required=bool(values["required"]),
            issued_at=_parse_timestamp(str(values["issued_at"])),
            expires_at=_parse_timestamp(str(values["expires_at"])),
        )
        return ApprovedEgressRoute.from_value(values)

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "route_id": self.route_id,
            "tenant_id": self.tenant_id,
            "engagement_id": self.engagement_id,
            "action_id": self.action_id,
            "operator_id": self.operator_id,
            "configuration_digest": self.configuration_digest,
            "dns_mode": cast(DnsMode, self.dns_mode).value,
            "allowed_protocols": list(self.allowed_protocols),
            "allowed_tools": list(self.allowed_tools),
            "verification_policy": cast(RouteVerificationPolicy, self.verification_policy).value,
            "verification_endpoint_ref": canonical_target(self.verification_endpoint),
            "proxy_origin_ref": _digest(self.proxy_url) if self.proxy_url else "",
            "requires_proxy_credentials": bool(self.proxy_credential_reference),
            "required": self.required,
            "issued_at": _integrity_timestamp(self.issued_at),
            "expires_at": _integrity_timestamp(self.expires_at),
        }


@dataclass(frozen=True)
class TransportCompatibilityDecision:
    supported: bool
    reason_code: str
    outcome: str


def evaluate_transport_compatibility(
    *,
    route: ApprovedEgressRoute | None,
    protocol: str,
    tool: str,
) -> TransportCompatibilityDecision:
    if route is None:
        return TransportCompatibilityDecision(True, OutboundReason.ALLOWED.value, "supported")
    normalized_protocol = str(protocol).strip().lower()
    normalized_tool = str(tool).strip().lower()
    if normalized_protocol not in {"http", "https"} or normalized_tool != "aiohttp":
        return TransportCompatibilityDecision(
            False,
            OutboundReason.UNSUPPORTED_ROUTE_TRANSPORT.value,
            "not_tested",
        )
    if cast(DnsMode, route.dns_mode) is not DnsMode.LOCAL_PINNED:
        return TransportCompatibilityDecision(
            False,
            OutboundReason.DNS_LEAK_UNVERIFIABLE.value,
            "not_tested",
        )
    if (
        normalized_protocol not in route.allowed_protocols
        or normalized_tool not in route.allowed_tools
    ):
        return TransportCompatibilityDecision(
            False,
            OutboundReason.UNSUPPORTED_ROUTE_TRANSPORT.value,
            "not_tested",
        )
    if route.required and not route.proxy_url:
        return TransportCompatibilityDecision(
            False,
            OutboundReason.ROUTE_REQUIRED.value,
            "not_tested",
        )
    if route.proxy_url and normalized_protocol in {"http", "https"}:
        proxy = urlsplit(route.proxy_url)
        proxy_host = proxy.hostname or ""
        try:
            loopback_proxy = ipaddress.ip_address(proxy_host).is_loopback
        except ValueError:
            loopback_proxy = False
        if (
            not loopback_proxy
            or proxy.scheme.lower() != "http"
            or route.proxy_credential_reference
        ):
            return TransportCompatibilityDecision(
                False,
                OutboundReason.UNSUPPORTED_ROUTE_TRANSPORT.value,
                "not_tested",
            )
    return TransportCompatibilityDecision(True, OutboundReason.ALLOWED.value, "supported")


_POLICY_SUPPORTED_MODULES: dict[str, frozenset[str]] = {
    "webforge": frozenset(
        {
            "tech_detect",
            "link_crawler",
            "header_audit",
            "jwt_audit",
            "idor_scanner",
            "mass_assignment",
            "open_redirect",
            "price_tamper",
            "workflow_bypass",
            "race_condition",
            "secret_scan",
            "dep_audit",
        }
    ),
    # The provider client is policy-bound, but existing modules still convert
    # transport denials into assessment output.  Keep them not-tested until
    # structured error propagation is migrated end to end.
    "aiforge": frozenset(),
    "netforge": frozenset(
        {
            "cis_benchmark",
            "html_report",
            "pdf_report",
            "json_export",
            "csv_export",
            "network_diagram",
        }
    ),
    "adforge": frozenset(),
    # Cloud modules do not yet have an engine-level consumed-envelope handoff.
    # Their BaseModule helpers fail closed, and direct module execution remains
    # compatibility-gated until that canonical launch path exists.
    "cloud": frozenset(),
    # Existing leak-intelligence scanners contain direct provider clients.
    # Until their engine has the canonical consumed-envelope handoff, guard
    # every BaseModule entry and report the path as unsupported with no I/O.
    "leak_intel": frozenset(),
}

# A caller-mutable class name or module export is not execution authority.
# Local whitebox analyzers remain authorization-bound but do not require a
# network transport context after their canonical source root is approved.
_POLICY_LOCAL_ONLY_MODULES: dict[str, frozenset[str]] = {
    "webforge": frozenset({"secret_scan", "dep_audit"}),
}
# There are no no-authorization direct-execution exceptions.  BaseModule must
# still receive the exact consumed Task 002 context for every module.
_INTRINSICALLY_LOCAL_MODULES: dict[str, frozenset[str]] = {}


def evaluate_module_outbound_support(
    *,
    engine: str,
    module_id: str,
) -> TransportCompatibilityDecision:
    """Default-deny known modules until every outbound path is migrated."""
    supported = module_id.strip().lower() in _POLICY_SUPPORTED_MODULES.get(
        engine.strip().lower(),
        frozenset(),
    )
    return TransportCompatibilityDecision(
        supported=supported,
        reason_code=(
            OutboundReason.ALLOWED.value
            if supported
            else OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value
        ),
        outcome="supported" if supported else "not_tested",
    )


def policy_supported_modules(engine: str) -> frozenset[str]:
    """Expose the versioned allow-set for validation and operator reporting."""
    return _POLICY_SUPPORTED_MODULES.get(engine.strip().lower(), frozenset())


def policy_manages_engine(engine: str) -> bool:
    """Return whether module execution is governed by the outbound allow-set."""
    return engine.strip().lower() in _POLICY_SUPPORTED_MODULES


def module_requires_outbound_context(*, engine: str, module_id: str) -> bool:
    """Return whether a supported module must hold a validated policy context."""
    normalized_engine = engine.strip().lower()
    normalized_module = module_id.strip().lower()
    return (
        normalized_module in _POLICY_SUPPORTED_MODULES.get(
            normalized_engine,
            frozenset(),
        )
        and normalized_module
        not in _POLICY_LOCAL_ONLY_MODULES.get(normalized_engine, frozenset())
    )


def module_is_intrinsically_local(
    *,
    engine: str,
    module_id: str,
    module_class: type[Any] | None = None,
) -> bool:
    """Return whether a no-context exception exists (none are authorized)."""
    return module_id.strip().lower() in _INTRINSICALLY_LOCAL_MODULES.get(
        engine.strip().lower(),
        frozenset(),
    )


def intrinsically_local_modules(engine: str) -> frozenset[str]:
    """Expose local-only exceptions for static bypass validation."""
    return _INTRINSICALLY_LOCAL_MODULES.get(engine.strip().lower(), frozenset())


@dataclass(frozen=True)
class RouteHealthEvidence:
    evidence_id: str
    route_id: str
    configuration_digest: str
    runtime_id: str
    dns_mode: str
    verification_endpoint_ref: str
    observed_egress: str
    route_identity: str
    verified_at: datetime
    expires_at: datetime
    binding_digest: str

    def binding_values(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "route_id": self.route_id,
            "configuration_digest": self.configuration_digest,
            "runtime_id": self.runtime_id,
            "dns_mode": self.dns_mode,
            "verification_endpoint_ref": self.verification_endpoint_ref,
            "observed_egress": self.observed_egress,
            "route_identity": self.route_identity,
            "verified_at": _integrity_timestamp(self.verified_at),
            "expires_at": _integrity_timestamp(self.expires_at),
        }

    def to_record(self, route: ApprovedEgressRoute) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "schema_version": ROUTE_HEALTH_SCHEMA_VERSION,
            "route_id": self.route_id,
            "tenant_id": route.tenant_id,
            "engagement_id": route.engagement_id,
            "action_id": route.action_id,
            "configuration_digest": self.configuration_digest,
            "runtime_id": self.runtime_id,
            "dns_mode": self.dns_mode,
            "verification_endpoint_ref": self.verification_endpoint_ref,
            "observed_egress": self.observed_egress,
            "route_identity": self.route_identity,
            "verified_at": _integrity_timestamp(self.verified_at),
            "expires_at": _integrity_timestamp(self.expires_at),
            "binding_digest": self.binding_digest,
            "recorded_at": _integrity_timestamp(self.verified_at),
        }


@dataclass
class _RouteHealthState:
    evidence: RouteHealthEvidence | None = None


@dataclass
class _OutboundRuntimeState:
    last_denial_reason: str = ""


class OutboundAuditSink(Protocol):
    def append_decision(self, record: dict[str, Any]) -> None: ...

    def append_route_health(self, record: dict[str, Any]) -> None: ...

    def route_health_is_current(self, record: dict[str, Any]) -> bool: ...

    def invalidate_route_health(self, record: dict[str, Any]) -> None: ...


class DatabaseOutboundAuditSink:
    """Append outbound evidence to the same protected authorization database."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def append_decision(self, record: dict[str, Any]) -> None:
        append_outbound_decision(self.session, record)

    def append_route_health(self, record: dict[str, Any]) -> None:
        append_route_health_evidence(self.session, record)

    def route_health_is_current(self, record: dict[str, Any]) -> bool:
        session = Session(bind=self.session.get_bind())
        try:
            return route_health_store_is_current(session, record)
        finally:
            session.close()

    def invalidate_route_health(self, record: dict[str, Any]) -> None:
        session = Session(bind=self.session.get_bind())
        try:
            append_route_health_invalidation(session, record)
        finally:
            session.close()


class AuthorizationDatabaseOutboundAuditSink:
    """Short-lived protected DB sessions for module-owned outbound evidence."""

    __slots__ = ()

    def append_decision(self, record: dict[str, Any]) -> None:
        session = open_authorization_session()
        try:
            append_outbound_decision(session, record)
        finally:
            session.close()

    def append_route_health(self, record: dict[str, Any]) -> None:
        session = open_authorization_session()
        try:
            append_route_health_evidence(session, record)
        finally:
            session.close()

    def route_health_is_current(self, record: dict[str, Any]) -> bool:
        session = open_authorization_session()
        try:
            return route_health_store_is_current(session, record)
        finally:
            session.close()

    def invalidate_route_health(self, record: dict[str, Any]) -> None:
        session = open_authorization_session()
        try:
            append_route_health_invalidation(session, record)
        finally:
            session.close()


@dataclass
class MemoryOutboundAuditSink:
    decisions: list[dict[str, Any]] = field(default_factory=list)
    route_health: list[dict[str, Any]] = field(default_factory=list)
    route_health_invalidations: list[dict[str, Any]] = field(default_factory=list)

    def append_decision(self, record: dict[str, Any]) -> None:
        self.decisions.append(dict(record))

    def append_route_health(self, record: dict[str, Any]) -> None:
        for existing in self.route_health:
            same_binding = all(
                existing.get(name) == record.get(name)
                for name in ("route_id", "tenant_id", "engagement_id", "action_id")
            )
            if not same_binding:
                continue
            if existing.get("configuration_digest") != record.get(
                "configuration_digest"
            ):
                raise RouteHealthConfigurationChangedError(
                    "approved route configuration changed"
                )
            if (
                existing.get("observed_egress") != record.get("observed_egress")
                or existing.get("route_identity") != record.get("route_identity")
            ):
                raise RouteHealthIdentityChangedError(
                    "approved route identity changed"
                )
        self.route_health.append(dict(record))

    def route_health_is_current(self, record: dict[str, Any]) -> bool:
        matching = [
            (sequence, item)
            for sequence, item in enumerate(self.route_health, start=1)
            if all(
                item.get(name) == record.get(name)
                for name in (
                    "route_id",
                    "tenant_id",
                    "engagement_id",
                    "action_id",
                    "configuration_digest",
                )
            )
        ]
        if not matching:
            return False
        latest_sequence, latest = matching[-1]
        if (
            latest.get("observed_egress") != record.get("observed_egress")
            or latest.get("route_identity") != record.get("route_identity")
        ):
            return False
        invalidated_through = max(
            (
                int(item["health_sequence"])
                for item in self.route_health_invalidations
                if all(
                    item.get(name) == latest.get(name)
                    for name in (
                        "route_id",
                        "tenant_id",
                        "engagement_id",
                        "action_id",
                        "configuration_digest",
                    )
                )
            ),
            default=0,
        )
        return latest_sequence > invalidated_through

    def invalidate_route_health(self, record: dict[str, Any]) -> None:
        matching = [
            (sequence, item)
            for sequence, item in enumerate(self.route_health, start=1)
            if all(
                item.get(name) == record.get(name)
                for name in ("route_id", "tenant_id", "engagement_id", "action_id")
            )
        ]
        if not matching:
            return
        health_sequence, latest = matching[-1]
        self.route_health_invalidations.append(
            {
                **dict(record),
                "configuration_digest": latest["configuration_digest"],
                "health_sequence": health_sequence,
            }
        )


@dataclass(frozen=True, init=False)
class OutboundContext:
    envelope: ActionAuthorizationEnvelope
    authorized_target: str
    allowed_scope: tuple[str, ...]
    excluded_scope: tuple[str, ...]
    audit_sink: OutboundAuditSink
    route: ApprovedEgressRoute | None = None
    transport_tool: str = "aiohttp"
    max_redirects: int = 5
    max_retries: int = 2
    timeout_seconds: float = 30.0
    max_response_bytes: int = 10 * 1024 * 1024
    permit_ttl_seconds: int = 15
    cancellation_check: Callable[[], bool] | None = None
    attempt_limiter: Callable[[], Awaitable[None]] | None = None
    lab_only_insecure_tls: bool = False
    insecure_tls_target: str = ""
    insecure_tls_authorization: ActionAuthorizationEnvelope | None = None

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        """Reject direct construction; use the consumed-authorization factory."""
        raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)

    def _validate(self) -> None:
        object.__setattr__(self, "allowed_scope", tuple(self.allowed_scope))
        object.__setattr__(self, "excluded_scope", tuple(self.excluded_scope))
        if type(self.envelope) is not ActionAuthorizationEnvelope:
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        if (
            type(self.transport_tool) is not str
            or not self.transport_tool
            or self.transport_tool != self.transport_tool.strip()
        ):
            raise ValueError("transport_tool is malformed")
        if type(self.lab_only_insecure_tls) is not bool:
            raise ValueError("lab_only_insecure_tls must be boolean")
        if type(self.insecure_tls_target) is not str:
            raise ValueError("insecure_tls_target must be text")
        if self.cancellation_check is not None and not callable(
            self.cancellation_check
        ):
            raise ValueError("cancellation_check must be callable")
        if self.attempt_limiter is not None and not callable(self.attempt_limiter):
            raise ValueError("attempt_limiter must be callable")
        for method_name in (
            "append_decision",
            "append_route_health",
            "route_health_is_current",
            "invalidate_route_health",
        ):
            if not callable(getattr(self.audit_sink, method_name, None)):
                raise ValueError("audit_sink does not implement the outbound contract")
        if (
            type(self.max_redirects) is not int
            or self.max_redirects < 0
            or self.max_redirects > 20
        ):
            raise ValueError("max_redirects is outside the supported bound")
        if (
            type(self.max_retries) is not int
            or self.max_retries < 0
            or self.max_retries > 10
        ):
            raise ValueError("max_retries is outside the supported bound")
        if (
            type(self.timeout_seconds) not in {int, float}
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or self.timeout_seconds > 600
        ):
            raise ValueError("timeout_seconds is outside the supported bound")
        if (
            type(self.max_response_bytes) is not int
            or self.max_response_bytes <= 0
            or self.max_response_bytes > MAX_OUTBOUND_RESPONSE_BYTES
        ):
            raise ValueError("max_response_bytes is outside the supported bound")
        if (
            type(self.permit_ttl_seconds) is not int
            or self.permit_ttl_seconds <= 0
            or self.permit_ttl_seconds > 60
        ):
            raise ValueError("permit_ttl_seconds is outside the supported bound")
        if self.envelope.decision_outcome != "allow":
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        if self.envelope.resolved_target != canonical_target(self.authorized_target):
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        if self.envelope.scope_snapshot != _scope_snapshot(
            self.allowed_scope,
            self.excluded_scope,
        ):
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        if self.route is not None:
            if type(self.route) is not ApprovedEgressRoute:
                raise OutboundDenied(OutboundReason.ROUTE_BINDING_MISMATCH)
            try:
                ApprovedEgressRoute.__post_init__(self.route)
            except Exception as exc:
                raise OutboundDenied(
                    OutboundReason.ROUTE_BINDING_MISMATCH
                ) from exc
            if (
                self.route.tenant_id != self.envelope.tenant_id
                or self.route.engagement_id != self.envelope.engagement_id
                or self.route.action_id != self.envelope.action_id
                or self.route.operator_id != self.envelope.operator_id
            ):
                raise OutboundDenied(OutboundReason.ROUTE_BINDING_MISMATCH)
        if self.lab_only_insecure_tls:
            child = self.insecure_tls_authorization
            target = normalize_destination(self.insecure_tls_target)
            if (
                child is None
                or child.decision_outcome != "allow"
                or child.action_kind != "outbound.insecure_tls"
                or child.parent_decision_id != self.envelope.decision_id
                or child.tenant_id != self.envelope.tenant_id
                or child.engagement_id != self.envelope.engagement_id
                or child.run_id != self.envelope.run_id
                or child.job_id != self.envelope.job_id
                or child.operator_id != self.envelope.operator_id
                or child.engine != self.envelope.engine
                or child.module_id != self.envelope.module_id
                or child.safety_mode != SafetyMode.LOCAL_LAB.value
                or not child.high_risk_approval_required
                or child.resolved_target != target.destination_ref
            ):
                raise OutboundDenied(OutboundReason.INSECURE_TLS_NOT_AUTHORIZED)

    def with_timeout_seconds(self, timeout_seconds: float) -> "OutboundContext":
        """Return the same validated authority with a no-weaker timeout bound."""
        if not _outbound_context_authority_is_valid(self):
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        if type(timeout_seconds) not in {int, float}:
            raise ValueError("timeout_seconds cannot broaden the validated context")
        requested = float(timeout_seconds)
        if (
            not math.isfinite(requested)
            or requested <= 0
            or requested > self.timeout_seconds
        ):
            raise ValueError("timeout_seconds cannot broaden the validated context")
        clone = object.__new__(OutboundContext)
        for name in (
            "envelope",
            "authorized_target",
            "allowed_scope",
            "excluded_scope",
            "audit_sink",
            "route",
            "transport_tool",
            "max_redirects",
            "max_retries",
            "timeout_seconds",
            "max_response_bytes",
            "permit_ttl_seconds",
            "cancellation_check",
            "attempt_limiter",
            "lab_only_insecure_tls",
            "insecure_tls_target",
            "insecure_tls_authorization",
        ):
            object.__setattr__(clone, name, getattr(self, name))
        object.__setattr__(clone, "timeout_seconds", requested)
        OutboundContext._validate(clone)
        # Keep provenance minting inside the only public operation that is
        # allowed to derive a context.  A module-level registration helper
        # would let a caller bless an ``object.__new__`` lookalike after
        # copying the root fields.
        source_provenance = _validated_outbound_context_provenance(self)
        if source_provenance is None:
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        claim_context = _claim_context(source_provenance)
        if claim_context is None:
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        clone_id = id(clone)

        def forget_context(reference: weakref.ReferenceType[OutboundContext]) -> None:
            current = _OUTBOUND_CONTEXT_PROVENANCE.get(clone_id)
            if current is not None and current.reference is reference:
                _OUTBOUND_CONTEXT_PROVENANCE.pop(clone_id, None)

        reference = weakref.ref(clone, forget_context)
        _OUTBOUND_CONTEXT_PROVENANCE[clone_id] = _OutboundContextProvenance(
            reference=reference,
            runtime_binding=_outbound_context_runtime_binding(clone),
            lineage_binding=source_provenance.lineage_binding,
            timeout_ceiling=float(clone.timeout_seconds),
            expected=source_provenance.expected,
            boundary=source_provenance.boundary,
            bind=source_provenance.bind,
            claim_recorded_at=source_provenance.claim_recorded_at,
            claim_reference=source_provenance.claim_reference,
            claim_owner=claim_context,
            lineage_id=source_provenance.lineage_id,
        )
        return clone

    @classmethod
    def from_consumed_authorization(
        cls,
        *,
        session: Session,
        envelope: ActionAuthorizationEnvelope | Mapping[str, Any],
        expected: AuthorizationContext,
        boundary: str,
        authorized_target: str,
        allowed_scope: Iterable[str],
        excluded_scope: Iterable[str],
        audit_sink: OutboundAuditSink,
        route: ApprovedEgressRoute | None = None,
        insecure_tls_authorization: ActionAuthorizationEnvelope | Mapping[str, Any] | None = None,
        insecure_tls_expected: AuthorizationContext | None = None,
        **kwargs: Any,
    ) -> "OutboundContext":
        current = _now(_trusted_utc_now())
        verified = validate_consumed_authorization(
            session=session,
            envelope=envelope,
            expected=expected,
            boundary=boundary,
            now=current,
        )
        if not verified.allowed:
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        record = verified.envelope
        allowed_values = tuple(str(item).strip() for item in allowed_scope)
        excluded_values = tuple(str(item).strip() for item in excluded_scope)
        if (
            record.resolved_target != canonical_target(authorized_target)
            or record.scope_snapshot != _scope_snapshot(allowed_values, excluded_values)
        ):
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        if current > _parse_timestamp(record.expires_at):
            raise OutboundDenied(OutboundReason.AUTHORIZATION_EXPIRED)
        if route is not None:
            if (
                route.tenant_id != record.tenant_id
                or route.engagement_id != record.engagement_id
                or route.operator_id != record.operator_id
                or route.action_id != record.action_id
            ):
                raise OutboundDenied(OutboundReason.ROUTE_BINDING_MISMATCH)
        insecure_record: ActionAuthorizationEnvelope | None = None
        if bool(kwargs.get("lab_only_insecure_tls", False)):
            if insecure_tls_authorization is None or insecure_tls_expected is None:
                raise OutboundDenied(OutboundReason.INSECURE_TLS_NOT_AUTHORIZED)
            insecure_verified = validate_consumed_authorization(
                session=session,
                envelope=insecure_tls_authorization,
                expected=insecure_tls_expected,
                boundary="outbound.insecure_tls",
                now=current,
            )
            if not insecure_verified.allowed:
                raise OutboundDenied(OutboundReason.INSECURE_TLS_NOT_AUTHORIZED)
            insecure_record = insecure_verified.envelope
        supported_options = {
            "transport_tool",
            "max_redirects",
            "max_retries",
            "timeout_seconds",
            "max_response_bytes",
            "permit_ttl_seconds",
            "cancellation_check",
            "attempt_limiter",
            "lab_only_insecure_tls",
            "insecure_tls_target",
        }
        unexpected = sorted(set(kwargs) - supported_options)
        if unexpected:
            raise TypeError(
                "unexpected OutboundContext option(s): " + ", ".join(unexpected)
            )
        context = object.__new__(OutboundContext)
        values: dict[str, Any] = {
            "envelope": record,
            "authorized_target": authorized_target,
            "allowed_scope": allowed_values,
            "excluded_scope": excluded_values,
            "audit_sink": audit_sink,
            "route": route,
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
            "insecure_tls_authorization": insecure_record,
        }
        values.update(kwargs)
        for name, value in values.items():
            object.__setattr__(context, name, value)
        OutboundContext._validate(context)
        _persist_outbound_context_claim(
            session=session,
            context=context,
            expected=expected,
            boundary=boundary,
            now=current,
        )
        # Provenance registration deliberately stays in this factory body.
        # Persisting an otherwise valid claim is not itself proof that the
        # caller used this factory, so no callable registration primitive is
        # exposed at module scope.
        context_id = id(context)
        boundary_value = _safe_identifier(boundary, "boundary")

        def forget_context(reference: weakref.ReferenceType[OutboundContext]) -> None:
            registered = _OUTBOUND_CONTEXT_PROVENANCE.get(context_id)
            if registered is not None and registered.reference is reference:
                _OUTBOUND_CONTEXT_PROVENANCE.pop(context_id, None)

        reference = weakref.ref(context, forget_context)
        _OUTBOUND_CONTEXT_PROVENANCE[context_id] = _OutboundContextProvenance(
            reference=reference,
            runtime_binding=_outbound_context_runtime_binding(context),
            lineage_binding=_outbound_context_lineage_binding(context),
            timeout_ceiling=float(context.timeout_seconds),
            expected=replace(expected),
            boundary=boundary_value,
            bind=_session_engine(session),
            claim_recorded_at=current,
            claim_reference=reference,
            claim_owner=None,
            lineage_id=f"outctx-lineage-{secrets.token_hex(32)}",
        )
        return context


def _stable_runtime_type_name(value: Any) -> str:
    value_type = type(value)
    module = str(getattr(value_type, "__module__", ""))
    qualname = str(getattr(value_type, "__qualname__", value_type.__name__))
    return f"{module}.{qualname}" if module else qualname


def _runtime_value_binding(value: Any) -> Any:
    if value is None or type(value) in {bool, int, float, str, bytes}:
        return (type(value).__name__, value)
    if isinstance(value, tuple):
        return ("tuple", tuple(_runtime_value_binding(item) for item in value))
    if isinstance(value, dict):
        return (
            "dict",
            tuple(
                sorted(
                    (str(key), _runtime_value_binding(item))
                    for key, item in value.items()
                )
            ),
        )
    return (_stable_runtime_type_name(value), id(value))


def _callable_behavior_binding(
    value: Any,
    *,
    depth: int = 0,
    seen: frozenset[int] = frozenset(),
) -> Any:
    if isinstance(value, (staticmethod, classmethod)):
        return (
            type(value).__name__,
            _callable_behavior_binding(value.__func__, depth=depth, seen=seen),
        )
    if isinstance(value, property):
        return (
            "property",
            _callable_behavior_binding(value.fget, depth=depth, seen=seen),
            _callable_behavior_binding(value.fset, depth=depth, seen=seen),
            _callable_behavior_binding(value.fdel, depth=depth, seen=seen),
        )
    if type(value) is FunctionType:
        code = value.__code__
        if id(value) in seen:
            return ("function-reference", id(value), id(code))
        next_seen = seen | {id(value)}
        code_material = repr(
            (
                code.co_argcount,
                code.co_posonlyargcount,
                code.co_kwonlyargcount,
                code.co_flags,
                code.co_code,
                code.co_consts,
                code.co_names,
                code.co_varnames,
                code.co_freevars,
                code.co_cellvars,
            )
        ).encode("utf-8", "replace")
        closure = value.__closure__ or ()
        global_bindings: tuple[Any, ...] = ()
        if depth < 1:
            bound_globals: list[Any] = []
            for name in sorted(set(code.co_names)):
                if name not in value.__globals__:
                    continue
                global_value = value.__globals__[name]
                if type(global_value) is FunctionType:
                    binding = _callable_behavior_binding(
                        global_value,
                        depth=depth + 1,
                        seen=next_seen,
                    )
                else:
                    binding = (
                        _stable_runtime_type_name(global_value),
                        id(global_value),
                    )
                bound_globals.append((name, binding))
            global_bindings = tuple(bound_globals)
        return (
            "function",
            id(value),
            id(code),
            hashlib.sha256(code_material).hexdigest(),
            _runtime_value_binding(value.__defaults__),
            _runtime_value_binding(value.__kwdefaults__),
            tuple(
                id(cell.cell_contents) if cell.cell_contents is not None else 0
                for cell in closure
            ),
            global_bindings,
        )
    return (_stable_runtime_type_name(value), id(value))


def _class_behavior_binding(value_type: type[Any]) -> tuple[tuple[str, Any], ...]:
    """Bind class behavior, including in-place function-code replacement."""
    return tuple(
        sorted(
            (str(name), _callable_behavior_binding(value))
            for name, value in vars(value_type).items()
            if name not in {"__dict__", "__weakref__"}
        )
    )


def _outbound_context_security_values(context: OutboundContext) -> dict[str, Any]:
    """Return every creation-time control that can change outbound behavior."""
    route = context.route
    cancellation = context.cancellation_check
    limiter = context.attempt_limiter
    child = context.insecure_tls_authorization
    return {
        "authorization_decision_id": context.envelope.decision_id,
        "authorization_binding_digest": context.envelope.binding_digest,
        "authorized_target": canonical_target(context.authorized_target),
        "allowed_scope": context.allowed_scope,
        "excluded_scope": context.excluded_scope,
        "audit_sink_type": _stable_runtime_type_name(context.audit_sink),
        "route_type": _stable_runtime_type_name(route) if route else "",
        "route_id": route.route_id if route else "",
        "route_configuration_digest": route.configuration_digest if route else "",
        "transport_tool": context.transport_tool,
        "max_redirects": context.max_redirects,
        "max_retries": context.max_retries,
        "timeout_seconds": context.timeout_seconds,
        "max_response_bytes": context.max_response_bytes,
        "permit_ttl_seconds": context.permit_ttl_seconds,
        "cancellation_check_bound": cancellation is not None,
        "cancellation_check_type": (
            _stable_runtime_type_name(cancellation) if cancellation else ""
        ),
        "attempt_limiter_bound": limiter is not None,
        "attempt_limiter_type": _stable_runtime_type_name(limiter) if limiter else "",
        "lab_only_insecure_tls": context.lab_only_insecure_tls,
        "insecure_tls_target": context.insecure_tls_target,
        "insecure_tls_decision_id": child.decision_id if child else "",
    }


def _outbound_context_runtime_binding(
    context: OutboundContext,
) -> tuple[Any, ...]:
    """Seal persisted controls plus in-process capability identities."""
    if type(context) is not OutboundContext:
        raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
    OutboundContext._validate(context)
    return (
        _digest(_outbound_context_security_values(context)),
        _class_behavior_binding(OutboundContext),
        id(context.envelope),
        id(context.audit_sink),
        _class_behavior_binding(type(context.audit_sink)),
        id(context.route) if context.route is not None else 0,
        (
            _class_behavior_binding(type(context.route))
            if context.route is not None
            else ()
        ),
        id(context.cancellation_check) if context.cancellation_check is not None else 0,
        id(context.attempt_limiter) if context.attempt_limiter is not None else 0,
        (
            id(context.insecure_tls_authorization)
            if context.insecure_tls_authorization is not None
            else 0
        ),
    )


def _outbound_context_lineage_binding(context: OutboundContext) -> tuple[Any, ...]:
    """Bind every authority field except the deliberately narrowed timeout."""
    return (
        id(context.envelope),
        context.authorized_target,
        context.allowed_scope,
        context.excluded_scope,
        id(context.audit_sink),
        id(context.route) if context.route is not None else 0,
        context.transport_tool,
        context.max_redirects,
        context.max_retries,
        context.max_response_bytes,
        context.permit_ttl_seconds,
        id(context.cancellation_check) if context.cancellation_check is not None else 0,
        id(context.attempt_limiter) if context.attempt_limiter is not None else 0,
        context.lab_only_insecure_tls,
        context.insecure_tls_target,
        (
            id(context.insecure_tls_authorization)
            if context.insecure_tls_authorization is not None
            else 0
        ),
    )


@dataclass(frozen=True)
class _OutboundContextProvenance:
    reference: weakref.ReferenceType[OutboundContext]
    runtime_binding: tuple[Any, ...]
    lineage_binding: tuple[Any, ...]
    timeout_ceiling: float
    expected: AuthorizationContext
    boundary: str
    bind: Any
    claim_recorded_at: datetime
    claim_reference: weakref.ReferenceType[OutboundContext]
    claim_owner: OutboundContext | None
    lineage_id: str


_OUTBOUND_CONTEXT_PROVENANCE: dict[int, _OutboundContextProvenance] = {}


def _session_engine(session: Session) -> Any:
    bind = session.get_bind()
    return getattr(bind, "engine", bind)


def _claim_context(
    provenance: _OutboundContextProvenance,
) -> OutboundContext | None:
    return provenance.claim_owner or provenance.claim_reference()


def _validated_outbound_context_provenance(
    context: OutboundContext,
) -> _OutboundContextProvenance | None:
    try:
        if type(context) is not OutboundContext:
            return None
        provenance = _OUTBOUND_CONTEXT_PROVENANCE.get(id(context))
        if (
            provenance is None
            or provenance.reference() is not context
            or provenance.runtime_binding != _outbound_context_runtime_binding(context)
            or provenance.lineage_binding != _outbound_context_lineage_binding(context)
            or type(provenance.timeout_ceiling) is not float
            or context.timeout_seconds > provenance.timeout_ceiling
            or _claim_context(provenance) is None
        ):
            return None
        return provenance
    except Exception:
        return None


def _outbound_context_claim_id(
    authorization_decision_id: str,
    boundary: str,
) -> str:
    boundary_value = _safe_identifier(boundary, "boundary")
    claim_key = f"{authorization_decision_id}\x00{boundary_value}".encode("utf-8")
    return "outctx-" + hashlib.sha256(claim_key).hexdigest()[:57]


def _outbound_context_claim_record(
    *,
    context: OutboundContext,
    boundary: str,
    now: datetime,
) -> dict[str, Any]:
    """Build the exact immutable record that seals a validated context."""
    boundary_value = _safe_identifier(boundary, "boundary")
    record = context.envelope
    route = context.route
    claim: dict[str, Any] = {
        "decision_id": _outbound_context_claim_id(record.decision_id, boundary_value),
        "schema_version": OUTBOUND_SCHEMA_VERSION,
        "authorization_decision_id": record.decision_id,
        "action_id": record.action_id,
        "tenant_id": record.tenant_id,
        "engagement_id": record.engagement_id,
        "run_id": record.run_id,
        "job_id": record.job_id,
        "engine": record.engine,
        "module_id": record.module_id,
        "action_kind": "outbound.context",
        "stage": "context_construction",
        "destination_ref": record.resolved_target,
        "scheme": "",
        "host": "",
        "port": None,
        "resolved_addresses": [],
        "outcome": "allow",
        "reason_code": OutboundReason.ALLOWED.value,
        "route_id": route.route_id if route else "",
        "route_configuration_digest": route.configuration_digest if route else "",
        "tls_mode": (
            "lab_only_insecure" if context.lab_only_insecure_tls else "verify"
        ),
        "detail": {
            "boundary": boundary_value,
            "scope_snapshot": record.scope_snapshot,
            "high_risk_child_decision_id": (
                context.insecure_tls_authorization.decision_id
                if context.lab_only_insecure_tls
                and context.insecure_tls_authorization is not None
                else ""
            ),
            "runtime_binding": {
                key: value
                for key, value in _outbound_context_security_values(context).items()
                if key
                in {
                    "audit_sink_type",
                    "route_type",
                    "cancellation_check_bound",
                    "cancellation_check_type",
                    "attempt_limiter_bound",
                    "attempt_limiter_type",
                }
            },
            "context_binding_digest": _digest(
                _outbound_context_security_values(context)
            ),
        },
        "recorded_at": _timestamp(now),
    }
    claim["binding_digest"] = _digest(claim)
    return claim


def _persist_outbound_context_claim(
    *,
    session: Session,
    context: OutboundContext,
    expected: AuthorizationContext,
    boundary: str,
    now: datetime,
) -> dict[str, Any]:
    """Atomically claim the one context allowed by a consumed authorization."""
    if type(context) is not OutboundContext:
        raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
    try:
        OutboundContext._validate(context)
    except OutboundDenied:
        raise
    except Exception as exc:
        raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID) from exc
    verified = validate_consumed_authorization(
        session=session,
        envelope=context.envelope,
        expected=expected,
        boundary=boundary,
        now=now,
    )
    if not verified.allowed or verified.envelope != context.envelope:
        raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
    claim = _outbound_context_claim_record(
        context=context,
        boundary=boundary,
        now=now,
    )
    try:
        append_outbound_decision(session, claim)
    except IntegrityError as exc:
        session.rollback()
        raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID) from exc
    except Exception as exc:
        session.rollback()
        raise OutboundDenied(OutboundReason.AUDIT_PERSISTENCE_FAILED) from exc
    return claim


def _outbound_context_claim_is_valid_at(
    *,
    session: Session,
    context: OutboundContext,
    expected: AuthorizationContext,
    boundary: str,
    current: datetime,
) -> bool:
    """Verify one persisted context claim at a trusted internal instant."""
    try:
        provenance = _validated_outbound_context_provenance(context)
        boundary_value = _safe_identifier(boundary, "boundary")
        if (
            provenance is None
            or provenance.expected != expected
            or provenance.boundary != boundary_value
        ):
            return False
        claim_context = _claim_context(provenance)
        if claim_context is None:
            return False
        claim_provenance = _validated_outbound_context_provenance(claim_context)
        if (
            claim_provenance is None
            or claim_provenance.claim_owner is not None
            or claim_provenance.claim_reference() is not claim_context
            or claim_provenance.lineage_id != provenance.lineage_id
            or claim_provenance.lineage_binding != provenance.lineage_binding
            or claim_provenance.expected != provenance.expected
            or claim_provenance.boundary != provenance.boundary
            or claim_provenance.bind is not provenance.bind
            or context.timeout_seconds > claim_context.timeout_seconds
        ):
            return False
        verified = validate_consumed_authorization(
            session=session,
            envelope=claim_context.envelope,
            expected=expected,
            boundary=boundary_value,
            now=current,
        )
        if not verified.allowed or verified.envelope != claim_context.envelope:
            return False
        decision_id = _outbound_context_claim_id(
            claim_context.envelope.decision_id,
            boundary_value,
        )
        model = get_outbound_decision(session, decision_id)
        if model is None or model.recorded_at is None:
            return False
        recorded_at = cast(datetime, model.recorded_at)
        if recorded_at.tzinfo is None:
            recorded_at = recorded_at.replace(tzinfo=timezone.utc)
        expected_claim = _outbound_context_claim_record(
            context=claim_context,
            boundary=boundary_value,
            now=_now(recorded_at),
        )
        actual = outbound_decision_to_dict(model)
        actual.pop("sequence", None)
        actual["recorded_at"] = _timestamp(recorded_at)
        return actual == expected_claim
    except Exception:
        return False


def outbound_context_claim_is_valid(
    *,
    session: Session,
    context: OutboundContext,
    expected: AuthorizationContext,
    boundary: str,
) -> bool:
    """Verify a context claim against the trusted process wall clock."""
    return _outbound_context_claim_is_valid_at(
        session=session,
        context=context,
        expected=expected,
        boundary=boundary,
        current=_now(_trusted_utc_now()),
    )


def _outbound_context_authority_is_valid(context: OutboundContext) -> bool:
    """Revalidate factory provenance, consumption, and the persisted root claim."""
    provenance = _validated_outbound_context_provenance(context)
    if provenance is None:
        return False
    session = Session(bind=provenance.bind)
    try:
        return _outbound_context_claim_is_valid_at(
            session=session,
            context=context,
            expected=provenance.expected,
            boundary=provenance.boundary,
            current=provenance.claim_recorded_at,
        )
    finally:
        session.close()


def _outbound_contexts_share_lineage(
    left: OutboundContext,
    right: OutboundContext,
) -> bool:
    left_provenance = _validated_outbound_context_provenance(left)
    right_provenance = _validated_outbound_context_provenance(right)
    return bool(
        left_provenance is not None
        and right_provenance is not None
        and left_provenance.lineage_id == right_provenance.lineage_id
        and left_provenance.lineage_binding == right_provenance.lineage_binding
    )


@dataclass(frozen=True)
class PreparedDestination:
    decision_id: str
    request_id: str
    authorization_decision_id: str
    action_kind: str
    destination: NormalizedDestination
    previous_origin: str
    hop: int
    attempt: int
    verify_tls: bool
    tls_mode: str
    route: ApprovedEgressRoute | None
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class ConnectionPermit:
    permit_id: str
    decision_id: str
    authorization_decision_id: str
    request_id: str
    scheme: str
    host: str
    port: int
    origin: str
    addresses: tuple[str, ...]
    address_digest: str
    route_id: str
    route_configuration_digest: str
    issued_at: datetime
    expires_at: datetime
    binding_digest: str


def _explicit_scope_port_matches(
    entries: Iterable[str],
    *,
    destination: NormalizedDestination,
) -> bool:
    for raw_entry in entries:
        entry = str(raw_entry)
        if (
            not entry
            or entry != entry.strip()
            or "\\" in entry
            or any(ord(char) < 32 for char in entry)
            or any(char.isspace() for char in entry)
        ):
            continue
        # Bare hosts/CIDRs authorize name/address membership only.  A scheme
        # or port transition requires an explicit URL-shaped scope entry so a
        # hostname allowlist cannot silently authorize HTTPS downgrade or a
        # different service port.
        if "://" not in entry:
            continue
        try:
            parsed = urlsplit(entry)
            if parsed.netloc.endswith(":"):
                continue
            if parsed.username is not None or parsed.password is not None:
                continue
            parsed_port = parsed.port
            explicit_port = (
                _default_port(parsed.scheme.lower())
                if parsed_port is None
                else parsed_port
            )
            entry_host = _normalize_host_value(parsed.hostname or "")
            entry_scheme = parsed.scheme.lower()
        except ValueError:
            continue
        if explicit_port != destination.port or entry_scheme != destination.scheme:
            continue
        try:
            entry_ip = _canonical_ip_address(entry_host)
            destination_ip = _canonical_ip_address(destination.host)
            if entry_ip == destination_ip:
                return True
        except ValueError:
            if destination.host == entry_host or destination.host.endswith(f".{entry_host}"):
                return True
    return False


class OutboundPolicy:
    """Stateful decision coordinator used by explicit outbound adapters."""

    __slots__ = (
        "context",
        "runtime_id",
        "_route_health_state",
        "_resolution_fingerprints",
        "_issued_prepared",
        "_used_prepared",
        "_used_permits",
        "_issued_permits",
        "_permit_integrity_key",
        "_route_health_integrity_key",
        "_runtime_state",
        "_clock",
        "__weakref__",
    )

    def __init__(
        self,
        context: OutboundContext,
        *,
        runtime_id: str | None = None,
        prior_route_health: RouteHealthEvidence | None = None,
        permit_integrity_key: bytes | None = None,
        route_health_integrity_key: bytes | None = None,
        route_health_state: _RouteHealthState | None = None,
        runtime_state: _OutboundRuntimeState | None = None,
    ) -> None:
        _OUTBOUND_POLICY_PROVENANCE.pop(id(self), None)
        if not _outbound_context_authority_is_valid(context):
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        self.context = context
        self.runtime_id = runtime_id or f"runtime-{uuid.uuid4().hex}"
        self._route_health_state = route_health_state or _RouteHealthState(
            prior_route_health
        )
        if (
            prior_route_health is not None
            and self._route_health_state.evidence is None
        ):
            self._route_health_state.evidence = prior_route_health
        self._resolution_fingerprints: dict[str, str] = {}
        self._issued_prepared: dict[str, str] = {}
        self._used_prepared: set[str] = set()
        self._used_permits: set[str] = set()
        self._issued_permits: dict[str, str] = {}
        self._permit_integrity_key = permit_integrity_key or secrets.token_bytes(32)
        self._route_health_integrity_key = (
            route_health_integrity_key or secrets.token_bytes(32)
        )
        self._runtime_state = runtime_state or _OutboundRuntimeState()
        # Expiry is always evaluated against the process wall clock.  A caller
        # must not be able to pin a policy to authorization issuance time.
        self._clock = _system_utc_now
        # Register only as the final step of the real constructor.  Keeping a
        # separate callable registration helper would allow a copied
        # ``object.__new__`` policy to acquire authority without running these
        # initialization checks.
        context_provenance = _validated_outbound_context_provenance(self.context)
        if (
            context_provenance is None
            or not _outbound_context_authority_is_valid(self.context)
        ):
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        policy_id = id(self)

        def forget_policy(reference: weakref.ReferenceType[OutboundPolicy]) -> None:
            current = _OUTBOUND_POLICY_PROVENANCE.get(policy_id)
            if current is not None and current.reference is reference:
                _OUTBOUND_POLICY_PROVENANCE.pop(policy_id, None)

        reference = weakref.ref(self, forget_policy)
        _OUTBOUND_POLICY_PROVENANCE[policy_id] = _OutboundPolicyProvenance(
            reference=reference,
            context_reference=weakref.ref(self.context),
            runtime_binding=_outbound_policy_runtime_binding(self),
            lineage_id=context_provenance.lineage_id,
        )

    @property
    def route_health(self) -> RouteHealthEvidence | None:
        return self._route_health_state.evidence

    @property
    def last_denial_reason(self) -> str:
        return self._runtime_state.last_denial_reason

    def _assert_authority(self) -> None:
        if not _outbound_policy_authority_is_valid(self):
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)

    def _route_store_record(
        self,
        *,
        health: RouteHealthEvidence | None = None,
        reason: OutboundReason | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        route = self.context.route
        if route is None:
            return {}
        record: dict[str, Any] = {
            "route_id": route.route_id,
            "tenant_id": route.tenant_id,
            "engagement_id": route.engagement_id,
            "action_id": route.action_id,
            "configuration_digest": route.configuration_digest,
            "runtime_id": self.runtime_id,
        }
        if health is not None:
            record.update(
                {
                    "observed_egress": health.observed_egress,
                    "route_identity": health.route_identity,
                }
            )
        if reason is not None:
            record.update(
                {
                    "invalidation_id": f"route-invalidation-{uuid.uuid4().hex}",
                    "schema_version": ROUTE_HEALTH_INVALIDATION_SCHEMA_VERSION,
                    "reason_code": reason.value,
                    "recorded_at": _timestamp(self._current(now)),
                }
            )
        return record

    def fork(self, context: OutboundContext | None = None) -> "OutboundPolicy":
        """Create a client-scoped policy sharing only trusted runtime health."""
        self._assert_authority()
        selected_context = context or self.context
        if not _outbound_contexts_share_lineage(self.context, selected_context):
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        return OutboundPolicy(
            selected_context,
            runtime_id=self.runtime_id,
            route_health_integrity_key=self._route_health_integrity_key,
            route_health_state=self._route_health_state,
            runtime_state=self._runtime_state,
        )

    def _cancelled(self) -> bool:
        check = self.context.cancellation_check
        return bool(check and check())

    def _current(self, value: datetime | None = None) -> datetime:
        return _now(self._clock() if value is None else value)

    def _prepared_binding_values(
        self,
        prepared: PreparedDestination,
    ) -> dict[str, Any]:
        return {
            "decision_id": prepared.decision_id,
            "request_id": prepared.request_id,
            "authorization_decision_id": prepared.authorization_decision_id,
            "action_kind": prepared.action_kind,
            "destination_url": prepared.destination.url,
            "destination_origin": prepared.destination.origin,
            "destination_ref": prepared.destination.destination_ref,
            "previous_origin": prepared.previous_origin,
            "hop": prepared.hop,
            "attempt": prepared.attempt,
            "verify_tls": prepared.verify_tls,
            "tls_mode": prepared.tls_mode,
            "route_id": prepared.route.route_id if prepared.route else "",
            "route_configuration_digest": (
                prepared.route.configuration_digest if prepared.route else ""
            ),
            "issued_at": _integrity_timestamp(prepared.issued_at),
            "expires_at": _integrity_timestamp(prepared.expires_at),
        }

    def _validate_prepared_destination(
        self,
        prepared: PreparedDestination,
        *,
        require_route_health: bool,
        consume: bool = False,
        stage: str = "transport_boundary",
        now: datetime | None = None,
    ) -> None:
        current = self._current(now)
        expected = self._issued_prepared.get(prepared.decision_id, "")
        actual = _hmac_digest(
            self._permit_integrity_key,
            self._prepared_binding_values(prepared),
        )
        if (
            not expected
            or not hmac.compare_digest(expected, actual)
            or prepared.authorization_decision_id
            != self.context.envelope.decision_id
        ):
            self._deny(
                OutboundReason.PERMIT_MISMATCH,
                action_kind=prepared.action_kind,
                stage=stage,
                destination=prepared.destination,
                tls_mode=prepared.tls_mode,
                now=current,
            )
        if _before_valid_window(current, prepared.issued_at):
            self._deny(
                OutboundReason.PERMIT_NOT_YET_VALID,
                action_kind=prepared.action_kind,
                stage=stage,
                destination=prepared.destination,
                tls_mode=prepared.tls_mode,
                now=current,
            )
        if consume:
            if prepared.decision_id in self._used_prepared:
                self._deny(
                    OutboundReason.PERMIT_REPLAYED,
                    action_kind=prepared.action_kind,
                    stage=stage,
                    destination=prepared.destination,
                    tls_mode=prepared.tls_mode,
                    now=current,
                )
            # Burn the logical decision before mutable route/cancellation/DNS
            # checks so every retry must obtain a fresh pre-resolution decision.
            self._used_prepared.add(prepared.decision_id)
        if prepared.tls_mode == "lab_only_insecure":
            self._validate_insecure_tls_authorization(
                prepared.destination,
                current,
                action_kind=prepared.action_kind,
                stage=stage,
            )
        self._validate_route(
            prepared.destination,
            current,
            require_health=require_route_health,
        )
        if current > prepared.expires_at:
            self._deny(
                OutboundReason.PERMIT_EXPIRED,
                action_kind=prepared.action_kind,
                stage=stage,
                destination=prepared.destination,
                tls_mode=prepared.tls_mode,
                now=current,
            )
        if self._cancelled():
            self._deny(
                OutboundReason.CANCELLED,
                action_kind=prepared.action_kind,
                stage=stage,
                destination=prepared.destination,
                tls_mode=prepared.tls_mode,
                now=current,
            )

    def _decision_record(
        self,
        *,
        decision_id: str,
        action_kind: str,
        stage: str,
        destination: NormalizedDestination | None,
        outcome: str,
        reason: OutboundReason,
        tls_mode: str,
        resolved_addresses: Iterable[str] = (),
        detail: Mapping[str, Any] | None = None,
        recorded_at: datetime | None = None,
    ) -> dict[str, Any]:
        route = self.context.route
        current = self._current(recorded_at)
        raw_detail = dict(detail or {})
        if (
            tls_mode == "lab_only_insecure"
            and self.context.insecure_tls_authorization is not None
        ):
            raw_detail["high_risk_child_decision_id"] = (
                self.context.insecure_tls_authorization.decision_id
            )
        safe_detail = redact_authorization_value(raw_detail)
        values: dict[str, Any] = {
            "decision_id": decision_id,
            "schema_version": OUTBOUND_SCHEMA_VERSION,
            "authorization_decision_id": self.context.envelope.decision_id,
            "action_id": self.context.envelope.action_id,
            "tenant_id": self.context.envelope.tenant_id,
            "engagement_id": self.context.envelope.engagement_id,
            "run_id": self.context.envelope.run_id,
            "job_id": self.context.envelope.job_id,
            "engine": self.context.envelope.engine,
            "module_id": self.context.envelope.module_id,
            "action_kind": action_kind,
            "stage": stage,
            "destination_ref": destination.destination_ref if destination else _digest("invalid"),
            "scheme": destination.scheme if destination else "",
            "host": destination.host if destination else "",
            "port": destination.port if destination else None,
            "resolved_addresses": tuple(resolved_addresses),
            "outcome": outcome,
            "reason_code": reason.value,
            "route_id": route.route_id if route else "",
            "route_configuration_digest": route.configuration_digest if route else "",
            "tls_mode": tls_mode,
            "detail": safe_detail,
            "recorded_at": _timestamp(current),
        }
        values["binding_digest"] = _digest(values)
        return values

    def _persist_decision(self, record: dict[str, Any]) -> None:
        try:
            self.context.audit_sink.append_decision(record)
        except Exception as exc:
            raise OutboundDenied(OutboundReason.AUDIT_PERSISTENCE_FAILED) from exc

    def _deny(
        self,
        reason: OutboundReason,
        *,
        action_kind: str,
        stage: str,
        destination: NormalizedDestination | None = None,
        tls_mode: str = "verify",
        decision_id: str | None = None,
        detail: Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> None:
        self._runtime_state.last_denial_reason = reason.value
        record = self._decision_record(
            decision_id=decision_id or f"outbound-{uuid.uuid4().hex}",
            action_kind=action_kind,
            stage=stage,
            destination=destination,
            outcome="deny",
            reason=reason,
            tls_mode=tls_mode,
            detail=detail,
            recorded_at=now,
        )
        self._persist_decision(record)
        raise OutboundDenied(reason)

    def record_terminal_failure(
        self,
        *,
        prepared: PreparedDestination,
        reason: OutboundReason | str,
        stage: str,
    ) -> None:
        self._assert_authority()
        try:
            normalized = OutboundReason(
                reason.value if isinstance(reason, OutboundReason) else str(reason)
            )
        except ValueError:
            normalized = OutboundReason.CONNECTION_FAILED
        self._runtime_state.last_denial_reason = normalized.value
        if self.context.route is not None and normalized in {
            OutboundReason.CONNECTION_FAILED,
            OutboundReason.TRANSPORT_CLEANUP_FAILED,
            OutboundReason.TLS_VERIFICATION_FAILED,
            OutboundReason.ROUTE_PREFLIGHT_FAILED,
            OutboundReason.ROUTE_IDENTITY_CHANGED,
            OutboundReason.ROUTE_CONFIGURATION_CHANGED,
        }:
            # A required-route connection failure makes the short-lived health
            # observation stale for every sibling policy.  The next attempt
            # must re-preflight and compare against the protected baseline.
            self._route_health_state.evidence = None
            try:
                self.context.audit_sink.invalidate_route_health(
                    self._route_store_record(reason=normalized)
                )
            except Exception as exc:
                self._runtime_state.last_denial_reason = (
                    OutboundReason.AUDIT_PERSISTENCE_FAILED.value
                )
                raise OutboundDenied(
                    OutboundReason.AUDIT_PERSISTENCE_FAILED
                ) from exc
        self._persist_decision(
            self._decision_record(
                decision_id=f"outbound-{uuid.uuid4().hex}",
                action_kind=prepared.action_kind,
                stage=stage,
                destination=prepared.destination,
                outcome="deny",
                reason=normalized,
                tls_mode=prepared.tls_mode,
            )
        )

    def _validate_insecure_tls_authorization(
        self,
        destination: NormalizedDestination,
        current: datetime,
        *,
        action_kind: str,
        stage: str,
    ) -> ActionAuthorizationEnvelope:
        child = self.context.insecure_tls_authorization
        insecure_target = (
            normalize_destination(self.context.insecure_tls_target)
            if self.context.insecure_tls_target
            else None
        )
        if (
            child is None
            or self.context.envelope.safety_mode != SafetyMode.LOCAL_LAB.value
            or not self.context.envelope.high_risk_approval_required
            or child.decision_outcome != "allow"
            or child.action_kind != "outbound.insecure_tls"
            or child.parent_decision_id != self.context.envelope.decision_id
            or child.tenant_id != self.context.envelope.tenant_id
            or child.engagement_id != self.context.envelope.engagement_id
            or child.run_id != self.context.envelope.run_id
            or child.job_id != self.context.envelope.job_id
            or child.operator_id != self.context.envelope.operator_id
            or child.engine != self.context.envelope.engine
            or child.module_id != self.context.envelope.module_id
            or child.safety_mode != SafetyMode.LOCAL_LAB.value
            or not child.high_risk_approval_required
            or insecure_target is None
            or insecure_target.origin != destination.origin
            or child.resolved_target != insecure_target.destination_ref
            or _before_valid_window(current, _parse_timestamp(child.issued_at))
            or current > _parse_timestamp(child.expires_at)
        ):
            self._deny(
                OutboundReason.INSECURE_TLS_NOT_AUTHORIZED,
                action_kind=action_kind,
                stage=stage,
                destination=destination,
                tls_mode="lab_only_insecure",
                now=current,
            )
        assert child is not None
        return child

    def _validate_route(
        self,
        destination: NormalizedDestination,
        current: datetime,
        *,
        require_health: bool = True,
    ) -> None:
        route = self.context.route
        if route is None:
            return
        if current < route.issued_at:
            self._deny(
                OutboundReason.ROUTE_NOT_YET_VALID,
                action_kind="route.validate",
                stage="pre_resolution",
                destination=destination,
                now=current,
            )
        if current > route.expires_at:
            self._deny(
                OutboundReason.ROUTE_EXPIRED,
                action_kind="route.validate",
                stage="pre_resolution",
                destination=destination,
                now=current,
            )
        if (
            route.tenant_id != self.context.envelope.tenant_id
            or route.engagement_id != self.context.envelope.engagement_id
            or route.action_id != self.context.envelope.action_id
            or route.operator_id != self.context.envelope.operator_id
        ):
            self._deny(
                OutboundReason.ROUTE_BINDING_MISMATCH,
                action_kind="route.validate",
                stage="pre_resolution",
                destination=destination,
                now=current,
            )
        compatibility = evaluate_transport_compatibility(
            route=route,
            protocol=destination.scheme,
            tool=self.context.transport_tool,
        )
        if not compatibility.supported:
            self._deny(
                OutboundReason(compatibility.reason_code),
                action_kind="route.validate",
                stage="pre_resolution",
                destination=destination,
                now=current,
            )
        if require_health and (
            route.verification_policy is RouteVerificationPolicy.REQUIRED
            or route.required
        ) and not self._route_health_is_current(now=current):
                self._deny(
                    OutboundReason.ROUTE_HEALTH_REQUIRED,
                    action_kind="route.validate",
                    stage="pre_resolution",
                    destination=destination,
                    now=current,
                )

    def route_health_is_current(self) -> bool:
        """Check route health against the trusted process wall clock."""
        return self._route_health_is_current(now=self._current())

    def _route_health_is_current(self, *, now: datetime) -> bool:
        self._assert_authority()
        route = self.context.route
        health = self._route_health_state.evidence
        if route is None or health is None:
            return False
        current = self._current(now)
        locally_current = not (
            health.runtime_id != self.runtime_id
            or health.route_id != route.route_id
            or health.configuration_digest != route.configuration_digest
            or health.dns_mode != cast(DnsMode, route.dns_mode).value
            or health.verification_endpoint_ref
            != normalize_destination(route.verification_endpoint).destination_ref
            or current < route.issued_at
            or health.verified_at > current
            or current > health.expires_at
            or health.expires_at > route.expires_at
            or health.expires_at
            > health.verified_at + timedelta(seconds=ROUTE_HEALTH_TTL_SECONDS)
            or not hmac.compare_digest(
                health.binding_digest,
                _hmac_digest(
                    self._route_health_integrity_key,
                    health.binding_values(),
                ),
            )
        )
        if not locally_current:
            return False
        try:
            return self.context.audit_sink.route_health_is_current(
                self._route_store_record(health=health)
            )
        except Exception:
            return False

    def prepare_destination(
        self,
        url: str,
        *,
        action_kind: str,
        previous_origin: str = "",
        hop: int = 0,
        attempt: int = 0,
        request_id: str | None = None,
    ) -> PreparedDestination:
        return self._prepare_destination(
            url,
            action_kind=action_kind,
            previous_origin=previous_origin,
            hop=hop,
            attempt=attempt,
            request_id=request_id,
            now=self._current(),
            require_route_health=True,
        )

    def _prepare_destination(
        self,
        url: str,
        *,
        action_kind: str,
        previous_origin: str = "",
        hop: int = 0,
        attempt: int = 0,
        request_id: str | None = None,
        now: datetime | None = None,
        require_route_health: bool,
    ) -> PreparedDestination:
        """Decide logical scheme/host/port before any DNS or connection call."""
        self._assert_authority()
        current = self._current(now)
        action = _safe_identifier(action_kind, "action_kind")
        if self._cancelled():
            self._deny(
                OutboundReason.CANCELLED,
                action_kind=action,
                stage="pre_resolution",
                now=current,
            )
        if _before_valid_window(
            current,
            _parse_timestamp(self.context.envelope.issued_at),
        ):
            self._deny(
                OutboundReason.AUTHORIZATION_NOT_YET_VALID,
                action_kind=action,
                stage="pre_resolution",
                now=current,
            )
        if current > _parse_timestamp(self.context.envelope.expires_at):
            self._deny(
                OutboundReason.AUTHORIZATION_EXPIRED,
                action_kind=action,
                stage="pre_resolution",
                now=current,
            )
        if hop > self.context.max_redirects:
            self._deny(
                OutboundReason.REDIRECT_LIMIT_EXCEEDED,
                action_kind=action,
                stage="pre_resolution",
                now=current,
            )
        if attempt > self.context.max_retries:
            self._deny(
                OutboundReason.RETRY_LIMIT_EXCEEDED,
                action_kind=action,
                stage="pre_resolution",
                now=current,
            )
        try:
            destination = normalize_destination(url)
        except OutboundDenied as exc:
            reason = OutboundReason(exc.reason_code)
            self._deny(
                reason,
                action_kind=action,
                stage="pre_resolution",
                now=current,
            )
            raise AssertionError("unreachable")

        if _is_fixed_metadata_destination(destination.host):
            self._deny(
                OutboundReason.DELEGATED_DESTINATION_NOT_AUTHORIZED,
                action_kind=action,
                stage="pre_resolution",
                destination=destination,
                now=current,
            )

        scope = decide_scope(
            destination.host,
            self.context.allowed_scope,
            self.context.excluded_scope,
        )
        if not scope.allowed:
            reason = (
                OutboundReason.EXCLUDED
                if scope.reason_code == ScopeReason.EXCLUDED.value
                else OutboundReason.HOST_OUT_OF_SCOPE
            )
            self._deny(
                reason,
                action_kind=action,
                stage="pre_resolution",
                destination=destination,
                now=current,
            )

        authorized_origin = normalize_destination(self.context.authorized_target).origin
        if (
            destination.origin != authorized_origin
            and not _explicit_scope_port_matches(
                self.context.allowed_scope,
                destination=destination,
            )
        ):
            self._deny(
                OutboundReason.PORT_NOT_AUTHORIZED,
                action_kind=action,
                stage="pre_resolution",
                destination=destination,
                now=current,
            )

        verify_tls = True
        insecure_child_expiry: datetime | None = None
        tls_mode = "verify" if destination.scheme == "https" else "not_applicable"
        if self.context.lab_only_insecure_tls and destination.scheme == "https":
            child = self._validate_insecure_tls_authorization(
                destination,
                current,
                action_kind=action,
                stage="pre_resolution",
            )
            insecure_child_expiry = _parse_timestamp(child.expires_at)
            verify_tls = False
            tls_mode = "lab_only_insecure"

        self._validate_route(
            destination,
            current,
            require_health=require_route_health,
        )
        decision_id = f"outbound-{uuid.uuid4().hex}"
        self._persist_decision(
            self._decision_record(
                decision_id=decision_id,
                action_kind=action,
                stage="pre_resolution",
                destination=destination,
                outcome="allow",
                reason=OutboundReason.ALLOWED,
                tls_mode=tls_mode,
                detail={
                    "hop": hop,
                    "attempt": attempt,
                    "origin_changed": bool(previous_origin and previous_origin != destination.origin),
                },
                recorded_at=current,
            )
        )
        envelope_expiry = _parse_timestamp(self.context.envelope.expires_at)
        expiry_candidates = [
            envelope_expiry,
            current + timedelta(seconds=self.context.permit_ttl_seconds),
        ]
        if self.context.route is not None:
            expiry_candidates.append(self.context.route.expires_at)
            if (
                require_route_health
                and self._route_health_state.evidence is not None
            ):
                expiry_candidates.append(
                    self._route_health_state.evidence.expires_at
                )
        if insecure_child_expiry is not None:
            expiry_candidates.append(insecure_child_expiry)
        prepared = PreparedDestination(
            decision_id=decision_id,
            request_id=request_id or f"request-{uuid.uuid4().hex}",
            authorization_decision_id=self.context.envelope.decision_id,
            action_kind=action,
            destination=destination,
            previous_origin=previous_origin,
            hop=hop,
            attempt=attempt,
            verify_tls=verify_tls,
            tls_mode=tls_mode,
            route=self.context.route,
            issued_at=current,
            expires_at=min(expiry_candidates),
        )
        self._issued_prepared[decision_id] = _hmac_digest(
            self._permit_integrity_key,
            self._prepared_binding_values(prepared),
        )
        return prepared

    def prepare_delegated_destination(
        self,
        url: str,
        *,
        action_kind: str,
    ) -> PreparedDestination:
        """Deny delegated egress until a separate consumed envelope exists."""
        try:
            destination = normalize_destination(url)
        except OutboundDenied:
            self._deny(
                OutboundReason.DELEGATED_DESTINATION_NOT_AUTHORIZED,
                action_kind=action_kind,
                stage="delegated_destination",
            )
            raise AssertionError("unreachable")
        self._deny(
            OutboundReason.DELEGATED_DESTINATION_NOT_AUTHORIZED,
            action_kind=action_kind,
            stage="delegated_destination",
            destination=destination,
        )
        raise AssertionError("unreachable")

    def record_credential_transition(
        self,
        prepared: PreparedDestination,
        original: Mapping[str, str],
        sanitized: Mapping[str, str],
    ) -> None:
        self._assert_authority()
        removed = sorted(
            name.lower()
            for name in original
            if name not in sanitized
            and name.lower() in (_SENSITIVE_HEADER_NAMES | {"proxy-authorization"})
        )
        if not removed:
            return
        self._persist_decision(
            self._decision_record(
                decision_id=f"outbound-{uuid.uuid4().hex}",
                action_kind=prepared.action_kind,
                stage="credential_binding",
                destination=prepared.destination,
                outcome="allow",
                reason=OutboundReason.ALLOWED,
                tls_mode=prepared.tls_mode,
                detail={"removed_header_names": removed},
            )
        )

    def authorize_resolution(
        self,
        prepared: PreparedDestination,
        addresses: Iterable[str],
    ) -> ConnectionPermit:
        return self._authorize_resolution(
            prepared,
            addresses,
            now=self._current(),
            require_route_health=True,
        )

    def _authorize_resolution(
        self,
        prepared: PreparedDestination,
        addresses: Iterable[str],
        *,
        now: datetime | None = None,
        require_route_health: bool,
    ) -> ConnectionPermit:
        """Validate the entire DNS answer and issue a short-lived pinned permit."""
        self._assert_authority()
        current = self._current(now)
        destination = prepared.destination
        self._validate_prepared_destination(
            prepared,
            require_route_health=require_route_health,
            consume=True,
            stage="post_resolution",
            now=current,
        )
        if self._cancelled():
            self._deny(
                OutboundReason.CANCELLED,
                action_kind=prepared.action_kind,
                stage="post_resolution",
                destination=destination,
                tls_mode=prepared.tls_mode,
                now=current,
            )
        if (
            prepared.authorization_decision_id != self.context.envelope.decision_id
            or current > prepared.expires_at
        ):
            self._deny(
                OutboundReason.PERMIT_EXPIRED,
                action_kind=prepared.action_kind,
                stage="post_resolution",
                destination=destination,
                tls_mode=prepared.tls_mode,
                now=current,
            )
        rendered = tuple(str(item).strip() for item in addresses)
        if not rendered or len(rendered) > 32:
            self._deny(
                OutboundReason.EMPTY_DNS_ANSWER,
                action_kind=prepared.action_kind,
                stage="post_resolution",
                destination=destination,
                tls_mode=prepared.tls_mode,
                now=current,
            )
        canonical_addresses: list[str] = []
        try:
            for raw in rendered:
                if "%" in raw:
                    raise ValueError("zone-scoped address")
                canonical_addresses.append(str(_canonical_ip_address(raw)))
        except ValueError:
            self._deny(
                OutboundReason.MALFORMED_DNS_ANSWER,
                action_kind=prepared.action_kind,
                stage="post_resolution",
                destination=destination,
                tls_mode=prepared.tls_mode,
                now=current,
            )
        ordered = tuple(sorted(set(canonical_addresses), key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item)))))
        fingerprint = _digest(ordered)
        resolution_key = _digest(
            {
                "request_id": prepared.request_id,
                "hop": prepared.hop,
                "url": destination.url,
            }
        )
        previous = self._resolution_fingerprints.get(resolution_key)
        if previous is not None and not hmac.compare_digest(previous, fingerprint):
            self._deny(
                OutboundReason.DNS_ANSWER_CHANGED,
                action_kind=prepared.action_kind,
                stage="post_resolution",
                destination=destination,
                tls_mode=prepared.tls_mode,
                now=current,
            )
        if any(_is_fixed_metadata_destination(address) for address in ordered):
            self._deny(
                OutboundReason.DELEGATED_DESTINATION_NOT_AUTHORIZED,
                action_kind=prepared.action_kind,
                stage="post_resolution",
                destination=destination,
                tls_mode=prepared.tls_mode,
                now=current,
            )
        for address in ordered:
            scope = decide_scope(address, self.context.allowed_scope, self.context.excluded_scope)
            if not scope.allowed:
                self._deny(
                    OutboundReason.RESOLVED_IP_OUT_OF_SCOPE,
                    action_kind=prepared.action_kind,
                    stage="post_resolution",
                    destination=destination,
                    tls_mode=prepared.tls_mode,
                    detail={"address_family": ipaddress.ip_address(address).version},
                    now=current,
                )
        try:
            literal_address = str(_canonical_ip_address(destination.host))
        except ValueError:
            literal_address = ""
        if literal_address and any(
            not hmac.compare_digest(address, literal_address)
            for address in ordered
        ):
            self._deny(
                OutboundReason.LITERAL_ADDRESS_MISMATCH,
                action_kind=prepared.action_kind,
                stage="post_resolution",
                destination=destination,
                tls_mode=prepared.tls_mode,
                now=current,
            )
        self._resolution_fingerprints[resolution_key] = fingerprint
        permit_id = f"permit-{uuid.uuid4().hex}"
        permit_values = {
            "permit_id": permit_id,
            "decision_id": prepared.decision_id,
            "authorization_decision_id": self.context.envelope.decision_id,
            "request_id": prepared.request_id,
            "scheme": destination.scheme,
            "host": destination.host,
            "port": destination.port,
            "origin": destination.origin,
            "addresses": ordered,
            "address_digest": fingerprint,
            "route_id": prepared.route.route_id if prepared.route else "",
            "route_configuration_digest": (
                prepared.route.configuration_digest if prepared.route else ""
            ),
            "issued_at": _integrity_timestamp(current),
            "expires_at": _integrity_timestamp(
                min(
                    prepared.expires_at,
                    current + timedelta(seconds=self.context.permit_ttl_seconds),
                )
            ),
        }
        binding_digest = _hmac_digest(self._permit_integrity_key, permit_values)
        permit = ConnectionPermit(
            permit_id=permit_id,
            decision_id=prepared.decision_id,
            authorization_decision_id=self.context.envelope.decision_id,
            request_id=prepared.request_id,
            scheme=destination.scheme,
            host=destination.host,
            port=destination.port,
            origin=destination.origin,
            addresses=ordered,
            address_digest=fingerprint,
            route_id=prepared.route.route_id if prepared.route else "",
            route_configuration_digest=(
                prepared.route.configuration_digest if prepared.route else ""
            ),
            issued_at=current,
            expires_at=min(
                prepared.expires_at,
                current + timedelta(seconds=self.context.permit_ttl_seconds),
            ),
            binding_digest=binding_digest,
        )
        self._issued_permits[permit.permit_id] = binding_digest
        self._persist_decision(
            self._decision_record(
                decision_id=f"outbound-{uuid.uuid4().hex}",
                action_kind=prepared.action_kind,
                stage="post_resolution",
                destination=destination,
                outcome="allow",
                reason=OutboundReason.ALLOWED,
                tls_mode=prepared.tls_mode,
                resolved_addresses=ordered,
                detail={"permit_id": permit.permit_id},
                recorded_at=current,
            )
        )
        return permit

    def validate_connection_permit(
        self,
        permit: ConnectionPermit,
        url: str,
    ) -> None:
        self._validate_connection_permit(
            permit,
            url,
            now=self._current(),
            require_route_health=True,
        )

    def _validate_connection_permit(
        self,
        permit: ConnectionPermit,
        url: str,
        *,
        now: datetime | None = None,
        require_route_health: bool,
    ) -> None:
        self._assert_authority()
        current = self._current(now)
        destination = normalize_destination(url)
        self._validate_route(
            destination,
            current,
            require_health=require_route_health,
        )
        if _before_valid_window(current, permit.issued_at):
            self._deny(
                OutboundReason.PERMIT_NOT_YET_VALID,
                action_kind="connection.permit",
                stage="connection_permit",
                destination=destination,
                now=current,
            )
        if current > permit.expires_at:
            self._deny(
                OutboundReason.PERMIT_EXPIRED,
                action_kind="connection.permit",
                stage="connection_permit",
                destination=destination,
                now=current,
            )
        permit_values = {
            "permit_id": permit.permit_id,
            "decision_id": permit.decision_id,
            "authorization_decision_id": permit.authorization_decision_id,
            "request_id": permit.request_id,
            "scheme": permit.scheme,
            "host": permit.host,
            "port": permit.port,
            "origin": permit.origin,
            "addresses": permit.addresses,
            "address_digest": permit.address_digest,
            "route_id": permit.route_id,
            "route_configuration_digest": permit.route_configuration_digest,
            "issued_at": _integrity_timestamp(permit.issued_at),
            "expires_at": _integrity_timestamp(permit.expires_at),
        }
        expected_binding = _hmac_digest(self._permit_integrity_key, permit_values)
        issued_binding = self._issued_permits.get(permit.permit_id, "")
        if (
            not hmac.compare_digest(permit.binding_digest, expected_binding)
            or not issued_binding
            or not hmac.compare_digest(issued_binding, permit.binding_digest)
            or permit.authorization_decision_id != self.context.envelope.decision_id
            or permit.scheme != destination.scheme
            or permit.host != destination.host
            or permit.port != destination.port
            or permit.origin != destination.origin
            or not permit.addresses
            or not hmac.compare_digest(permit.address_digest, _digest(permit.addresses))
        ):
            self._deny(
                OutboundReason.PERMIT_MISMATCH,
                action_kind="connection.permit",
                stage="connection_permit",
                destination=destination,
                now=current,
            )
        for address in permit.addresses:
            try:
                canonical = str(_canonical_ip_address(address))
            except ValueError:
                self._deny(
                    OutboundReason.PERMIT_MISMATCH,
                    action_kind="connection.permit",
                    stage="connection_permit",
                    destination=destination,
                    now=current,
                )
            if _is_fixed_metadata_destination(canonical):
                self._deny(
                    OutboundReason.PERMIT_MISMATCH,
                    action_kind="connection.permit",
                    stage="connection_permit",
                    destination=destination,
                    now=current,
                )
            if not decide_scope(
                canonical,
                self.context.allowed_scope,
                self.context.excluded_scope,
            ).allowed:
                self._deny(
                    OutboundReason.PERMIT_MISMATCH,
                    action_kind="connection.permit",
                    stage="connection_permit",
                    destination=destination,
                    now=current,
                )
        route = self.context.route
        if route is None:
            if permit.route_id or permit.route_configuration_digest:
                self._deny(
                    OutboundReason.PERMIT_MISMATCH,
                    action_kind="connection.permit",
                    stage="connection_permit",
                    destination=destination,
                    now=current,
                )
        elif (
            permit.route_id != route.route_id
            or permit.route_configuration_digest != route.configuration_digest
        ):
            self._deny(
                OutboundReason.PERMIT_MISMATCH,
                action_kind="connection.permit",
                stage="connection_permit",
                destination=destination,
                now=current,
            )

    def consume_connection_permit(
        self,
        permit: ConnectionPermit,
        url: str,
    ) -> None:
        self._consume_connection_permit(
            permit,
            url,
            now=self._current(),
            require_route_health=True,
        )

    def _validate_transport_request(
        self,
        request: HttpTransportRequest,
        *,
        require_route_health: bool,
        require_consumed: bool,
        now: datetime | None = None,
    ) -> None:
        self._assert_authority()
        prepared = request.prepared
        destination = prepared.destination
        self._validate_prepared_destination(
            prepared,
            require_route_health=require_route_health,
            now=now,
        )
        if (
            prepared.decision_id not in self._used_prepared
            or request.url != destination.url
            or request.permit.decision_id != prepared.decision_id
            or request.permit.request_id != prepared.request_id
            or request.route != prepared.route
            or request.route != self.context.route
            or not re.fullmatch(r"[A-Z]+", request.method)
            or not math.isfinite(request.timeout_seconds)
            or request.timeout_seconds <= 0
            or request.timeout_seconds > self.context.timeout_seconds
            or request.max_response_bytes <= 0
            or request.max_response_bytes > self.context.max_response_bytes
            or set(request.options) - _SAFE_REQUEST_OPTIONS
        ):
            self._deny(
                OutboundReason.PERMIT_MISMATCH,
                action_kind=prepared.action_kind,
                stage="transport_boundary",
                destination=destination,
                tls_mode=prepared.tls_mode,
                now=now,
            )
        self._validate_connection_permit(
            request.permit,
            request.url,
            now=now,
            require_route_health=require_route_health,
        )
        if require_consumed and request.permit.permit_id not in self._used_permits:
            self._deny(
                OutboundReason.PERMIT_MISMATCH,
                action_kind="connection.permit",
                stage="transport_boundary",
                destination=destination,
                now=now,
            )

    def admit_transport_request(
        self,
        request: HttpTransportRequest,
        *,
        require_route_health: bool = True,
    ) -> HttpTransportRequest:
        """Consume one issued permit immediately before a transport delegate."""
        current = self._current()
        self._validate_transport_request(
            request,
            require_route_health=require_route_health,
            require_consumed=False,
            now=current,
        )
        credential_binding = CredentialBinding.for_origin(
            self.context.authorized_target
        )
        if (
            not hmac.compare_digest(
                request.prepared.destination.origin,
                credential_binding.origin,
            )
            and any(name in request.options for name in ("data", "json"))
        ):
            self._deny(
                OutboundReason.CROSS_ORIGIN_BODY_NOT_AUTHORIZED,
                action_kind=request.prepared.action_kind,
                stage="transport_boundary",
                destination=request.prepared.destination,
                now=current,
            )
        sanitized_headers = strip_origin_bound_secrets(
            request.headers,
            destination_origin=request.prepared.destination.origin,
            binding=credential_binding,
        )
        self.record_credential_transition(
            request.prepared,
            request.headers,
            sanitized_headers,
        )
        canonical_headers = _headers_with_canonical_host(
            sanitized_headers,
            request.prepared.destination,
        )
        self._consume_connection_permit(
            request.permit,
            request.url,
            now=current,
            require_route_health=require_route_health,
        )
        return replace(request, headers=canonical_headers)

    def validate_transport_boundary(
        self,
        request: HttpTransportRequest,
        *,
        require_route_health: bool = True,
    ) -> None:
        """Revalidate current policy state for an admitted in-flight request."""
        self._validate_transport_request(
            request,
            require_route_health=require_route_health,
            require_consumed=True,
            now=self._current(),
        )

    def _consume_connection_permit(
        self,
        permit: ConnectionPermit,
        url: str,
        *,
        now: datetime | None = None,
        require_route_health: bool,
    ) -> None:
        self._assert_authority()
        self._validate_connection_permit(
            permit,
            url,
            now=now,
            require_route_health=require_route_health,
        )
        if permit.permit_id in self._used_permits:
            self._deny(
                OutboundReason.PERMIT_REPLAYED,
                action_kind="connection.permit",
                stage="connection_permit",
                destination=normalize_destination(url),
                now=now,
            )
        self._used_permits.add(permit.permit_id)

    async def preflight_route(
        self,
        *,
        resolver: ResolverCallable | None = None,
        transport: TransportCallable | None = None,
    ) -> RouteHealthEvidence:
        """Verify the configured route through its exact approved endpoint."""
        self._assert_authority()
        route = self.context.route
        current = self._current()
        if route is None:
            raise OutboundDenied(OutboundReason.ROUTE_REQUIRED)
        prepared = self._prepare_destination(
            route.verification_endpoint,
            action_kind="route.preflight",
            request_id=f"route-preflight-{uuid.uuid4().hex}",
            now=current,
            require_route_health=False,
        )
        resolve = resolver or resolve_system_addresses
        send: TransportCallable = (
            PolicyBoundTransport(
                self,
                transport,
                require_route_health=False,
            )
            if transport is not None
            else AiohttpPinnedTransport(
                self,
                require_route_health=False,
            )
        )
        preflight_timeout = min(10.0, self.context.timeout_seconds)
        deadline = asyncio.get_running_loop().time() + preflight_timeout

        def remaining_timeout() -> float:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            return remaining

        try:
            self._assert_authority()
            resolution_timeout = remaining_timeout()
            addresses = await _await_with_bounded_cleanup(
                resolve(
                    prepared.destination.host,
                    prepared.destination.port,
                ),
                late_result_cleanup=None,
                timeout_seconds=resolution_timeout,
            )
            permit = self._authorize_resolution(
                prepared,
                addresses,
                now=self._current(),
                require_route_health=False,
            )
            transport_timeout = remaining_timeout()
            self._assert_authority()
            response = await _await_with_bounded_cleanup(
                send(
                    HttpTransportRequest(
                        method="GET",
                        url=prepared.destination.url,
                        headers={"Accept": "application/json"},
                        permit=permit,
                        prepared=prepared,
                        route=route,
                        timeout_seconds=transport_timeout,
                        max_response_bytes=min(65536, self.context.max_response_bytes),
                    )
                ),
                late_result_cleanup=_release_transport_response,
                timeout_seconds=transport_timeout,
            )
            raw_response = response
            try:
                response_status = raw_response.status
                response_body = bytes(raw_response.body)
            finally:
                # The preflight owns every successful transport result.  Keep
                # cleanup around the raw-object copy so malformed runtime
                # values cannot strand a connection before validation.
                release_succeeded = _release_transport_response(raw_response)
            if not release_succeeded:
                raise OutboundDenied(OutboundReason.TRANSPORT_CLEANUP_FAILED)
            if response_status != 200 or len(response_body) > 65536:
                raise OutboundDenied(OutboundReason.ROUTE_PREFLIGHT_FAILED)
            try:
                payload = json.loads(response_body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise OutboundDenied(OutboundReason.ROUTE_PREFLIGHT_FAILED) from exc
            if not isinstance(payload, dict) or set(payload) != {
                "observed_egress",
                "route_identity",
            }:
                raise OutboundDenied(OutboundReason.ROUTE_PREFLIGHT_FAILED)
            return self._record_route_health(
                observed_egress=str(payload["observed_egress"]),
                endpoint=route.verification_endpoint,
                route_identity=str(payload["route_identity"]),
                now=self._current(),
            )
        except OutboundDenied as exc:
            self.record_terminal_failure(
                prepared=prepared,
                reason=exc.reason_code,
                stage="route_preflight",
            )
            raise
        except asyncio.CancelledError:
            self.record_terminal_failure(
                prepared=prepared,
                reason=OutboundReason.CANCELLED,
                stage="route_preflight",
            )
            raise
        except (asyncio.TimeoutError, Exception) as exc:
            self.record_terminal_failure(
                prepared=prepared,
                reason=OutboundReason.ROUTE_PREFLIGHT_FAILED,
                stage="route_preflight",
            )
            raise OutboundDenied(OutboundReason.ROUTE_PREFLIGHT_FAILED) from exc

    def _record_route_health(
        self,
        *,
        observed_egress: str,
        endpoint: str,
        route_identity: str,
        now: datetime | None = None,
    ) -> RouteHealthEvidence:
        self._assert_authority()
        route = self.context.route
        current = self._current(now)
        if route is None:
            raise OutboundDenied(OutboundReason.ROUTE_REQUIRED)
        if current < route.issued_at:
            raise OutboundDenied(OutboundReason.ROUTE_NOT_YET_VALID)
        if current > route.expires_at:
            raise OutboundDenied(OutboundReason.ROUTE_EXPIRED)
        endpoint_destination = normalize_destination(endpoint)
        if endpoint_destination.url != route.verification_endpoint:
            raise OutboundDenied(OutboundReason.ROUTE_BINDING_MISMATCH)
        try:
            egress = str(_canonical_ip_address(observed_egress))
        except ValueError as exc:
            raise OutboundDenied(OutboundReason.ROUTE_BINDING_MISMATCH) from exc
        identity = _safe_identifier(route_identity, "route_identity")
        existing = self._route_health_state.evidence
        if existing is not None:
            if existing.configuration_digest != route.configuration_digest:
                raise OutboundDenied(OutboundReason.ROUTE_CONFIGURATION_CHANGED)
            if existing.observed_egress != egress or existing.route_identity != identity:
                raise OutboundDenied(OutboundReason.ROUTE_IDENTITY_CHANGED)
        evidence_id = f"route-health-{uuid.uuid4().hex}"
        expires_at = min(
            route.expires_at,
            current + timedelta(seconds=ROUTE_HEALTH_TTL_SECONDS),
        )
        unsigned = RouteHealthEvidence(
            evidence_id=evidence_id,
            route_id=route.route_id,
            configuration_digest=route.configuration_digest,
            runtime_id=self.runtime_id,
            dns_mode=cast(DnsMode, route.dns_mode).value,
            verification_endpoint_ref=endpoint_destination.destination_ref,
            observed_egress=egress,
            route_identity=identity,
            verified_at=current,
            expires_at=expires_at,
            binding_digest="",
        )
        evidence = replace(
            unsigned,
            binding_digest=_hmac_digest(
                self._route_health_integrity_key,
                unsigned.binding_values(),
            ),
        )
        try:
            self.context.audit_sink.append_route_health(evidence.to_record(route))
        except RouteHealthConfigurationChangedError as exc:
            raise OutboundDenied(OutboundReason.ROUTE_CONFIGURATION_CHANGED) from exc
        except RouteHealthIdentityChangedError as exc:
            raise OutboundDenied(OutboundReason.ROUTE_IDENTITY_CHANGED) from exc
        except Exception as exc:
            raise OutboundDenied(OutboundReason.AUDIT_PERSISTENCE_FAILED) from exc
        self._route_health_state.evidence = evidence
        return evidence


def _outbound_policy_runtime_binding(policy: OutboundPolicy) -> tuple[Any, ...]:
    """Seal immutable policy controls while allowing ordinary runtime state."""
    if type(policy) is not OutboundPolicy:
        raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
    if (
        type(policy.runtime_id) is not str
        or not policy.runtime_id
        or not callable(policy._clock)
        or type(policy._permit_integrity_key) is not bytes
        or type(policy._route_health_integrity_key) is not bytes
    ):
        raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
    return (
        _class_behavior_binding(OutboundPolicy),
        id(policy.context),
        policy.runtime_id,
        id(policy._route_health_state),
        id(policy._runtime_state),
        id(policy._resolution_fingerprints),
        id(policy._issued_prepared),
        id(policy._used_prepared),
        id(policy._used_permits),
        id(policy._issued_permits),
        policy._permit_integrity_key,
        policy._route_health_integrity_key,
        id(policy._clock),
    )


@dataclass(frozen=True)
class _OutboundPolicyProvenance:
    reference: weakref.ReferenceType[OutboundPolicy]
    context_reference: weakref.ReferenceType[OutboundContext]
    runtime_binding: tuple[Any, ...]
    lineage_id: str


_OUTBOUND_POLICY_PROVENANCE: dict[int, _OutboundPolicyProvenance] = {}


def _outbound_policy_authority_is_valid(policy: OutboundPolicy) -> bool:
    try:
        if type(policy) is not OutboundPolicy:
            return False
        provenance = _OUTBOUND_POLICY_PROVENANCE.get(id(policy))
        if (
            provenance is None
            or provenance.reference() is not policy
            or provenance.context_reference() is not policy.context
            or provenance.runtime_binding != _outbound_policy_runtime_binding(policy)
        ):
            return False
        context_provenance = _validated_outbound_context_provenance(policy.context)
        return bool(
            context_provenance is not None
            and context_provenance.lineage_id == provenance.lineage_id
            and _outbound_context_authority_is_valid(policy.context)
        )
    except Exception:
        return False


@dataclass(frozen=True)
class HttpTransportRequest:
    method: str
    url: str
    headers: dict[str, str]
    permit: ConnectionPermit
    prepared: PreparedDestination
    route: ApprovedEgressRoute | None
    timeout_seconds: float
    max_response_bytes: int
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str = ""
    release_callback: Callable[[], None] | None = None
    released: bool = field(default=False, init=False)
    release_error: str = field(default="", init=False)

    def release(self) -> bool:
        if self.released:
            return not self.release_error
        self.released = True
        if self.release_callback is not None:
            try:
                self.release_callback()
            except BaseException:
                # Cleanup hooks are transport-owned and best effort.  Record a
                # redacted diagnostic, but never let a hook replace the
                # request's success, timeout, or cancellation outcome.
                # Do not inspect or serialize the exception: hostile exception
                # metaclasses can make even ``type(exc).__name__`` raise, and
                # class/message text is not trusted evidence.
                self.release_error = "callback_failed"
                _log_transport_release_failure()
                return False
        return True


def _log_transport_release_failure() -> None:
    try:
        _LOGGER.warning("Transport response release callback failed")
    except BaseException:
        # A caller-installed logging handler is not cleanup authority either.
        pass


def _release_transport_response(response: Any) -> bool:
    """Release through sealed base behavior and reject response subtypes."""
    response_type = type(response)
    exact_type = response_type is TransportResponse
    if not exact_type:
        try:
            is_response_subtype = issubclass(response_type, TransportResponse)
        except BaseException:
            is_response_subtype = False
    else:
        is_response_subtype = True
    if not is_response_subtype:
        _log_transport_release_failure()
        return False
    try:
        pristine_state = (
            type(response.released) is bool
            and response.released is False
            and type(response.release_error) is str
            and response.release_error == ""
        )
    except BaseException:
        pristine_state = False
    if not pristine_state:
        _log_transport_release_failure()
        return False
    try:
        result = TransportResponse.release(response)
    except BaseException:
        try:
            object.__setattr__(response, "released", True)
            object.__setattr__(response, "release_error", "callback_failed")
        except BaseException:
            pass
        _log_transport_release_failure()
        return False
    if not exact_type:
        # A subtype can override release or forge mutable postconditions.
        # Base cleanup above still owns the declared callback, but the
        # response is rejected rather than trusting subtype behavior.
        try:
            object.__setattr__(response, "release_error", "callback_failed")
        except BaseException:
            pass
        _log_transport_release_failure()
        return False
    try:
        released = response.released
        release_error = response.release_error
        return (
            type(response) is TransportResponse
            and type(released) is bool
            and released is True
            and type(release_error) is str
            and release_error == ""
            and result is True
        )
    except BaseException:
        _log_transport_release_failure()
        return False


_LateResultCleanup = Callable[[Any], object]


def _completed_result_consumer(
    late_result_cleanup: _LateResultCleanup | None,
) -> Callable[[asyncio.Future[Any]], None]:
    """Consume one terminal result and run only its explicitly bound cleanup."""

    def consume(completed: asyncio.Future[Any]) -> None:
        try:
            result = completed.result()
        except BaseException:
            return
        if late_result_cleanup is not None:
            late_result_cleanup(result)

    return consume


_TRANSPORT_CLEANUP_BUDGET_SECONDS = 0.1
_TRANSPORT_CLEANUP_POLL_SECONDS = 0.01


async def _cancel_task_with_transport_cleanup(
    task: asyncio.Future[Any],
    *,
    late_result_cleanup: _LateResultCleanup | None,
) -> None:
    """Bound cancellation and retain ownership of an eventual late result."""
    consume_completed_result = _completed_result_consumer(late_result_cleanup)
    if task.done():
        consume_completed_result(task)
        return

    loop = asyncio.get_running_loop()
    deadline = loop.time() + _TRANSPORT_CLEANUP_BUDGET_SECONDS
    cancellation_turns = 0
    try:
        while not task.done():
            task.cancel()
            # A timeout alone does not prove that the child received the
            # cancellation: under scheduler contention, multiple cancel()
            # calls can be queued before the child gets one execution turn.
            # Yield once per request so cancellation-resistant transports can
            # finish their bounded cleanup and return a response we still own.
            await asyncio.sleep(0)
            cancellation_turns += 1
            if task.done():
                break
            remaining = deadline - loop.time()
            # Deliver two cancellation turns even if the scheduler consumed
            # the nominal grace budget between turns. This preserves the
            # existing repeated-cancellation contract without allowing an
            # unbounded cleanup loop.
            if remaining <= 0 and cancellation_turns >= 2:
                break
            if remaining <= 0:
                continue
            await asyncio.wait(
                {task},
                timeout=min(_TRANSPORT_CLEANUP_POLL_SECONDS, remaining),
            )
    finally:
        if task.done():
            consume_completed_result(task)
        else:
            # A genuinely non-cooperative task cannot make the caller's
            # cleanup unbounded. Retain eventual-result ownership through the
            # same explicit consumer used for immediate completion.
            task.add_done_callback(consume_completed_result)


async def _await_with_bounded_cleanup(
    awaitable: Awaitable[Any],
    *,
    late_result_cleanup: _LateResultCleanup | None,
    timeout_seconds: float,
) -> Any:
    """Await one side-effect task without accepting a late timeout result."""
    task = asyncio.ensure_future(awaitable)
    try:
        done, _ = await asyncio.wait({task}, timeout=timeout_seconds)
        if not done:
            raise asyncio.TimeoutError
        return await task
    except BaseException as original:
        cleanup = asyncio.create_task(
            _cancel_task_with_transport_cleanup(
                task,
                late_result_cleanup=late_result_cleanup,
            )
        )
        cancelled_during_cleanup = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled_during_cleanup = True
        cleanup.result()
        if cancelled_during_cleanup and not isinstance(
            original,
            asyncio.CancelledError,
        ):
            raise asyncio.CancelledError from original
        raise


@dataclass
class PolicyResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str
    history: tuple[str, ...] = ()
    released: bool = False
    cookies: SimpleCookie = field(default_factory=SimpleCookie)

    def __post_init__(self) -> None:
        for name, value in self.headers.items():
            if name.lower() == "set-cookie":
                self.cookies.load(value)

    @property
    def content_type(self) -> str:
        value = next(
            (
                header_value
                for name, header_value in self.headers.items()
                if name.lower() == "content-type"
            ),
            "",
        )
        return value.split(";", 1)[0].strip().lower()

    async def read(self) -> bytes:
        return self.body

    async def text(self, encoding: str | None = None, errors: str = "strict") -> str:
        selected = encoding or "utf-8"
        return self.body.decode(selected, errors=errors)

    async def json(self, **kwargs: Any) -> Any:
        kwargs.pop("content_type", None)
        text = self.body.decode(kwargs.pop("encoding", "utf-8"), errors="strict")
        try:
            return json.loads(text, **kwargs)
        except (TypeError, ValueError) as exc:
            raise ValueError("response JSON was malformed") from exc

    def release(self) -> None:
        self.released = True

    async def __aenter__(self) -> "PolicyResponse":
        return self

    async def __aexit__(self, *_: Any) -> None:
        self.release()


class _PolicyRequestContextManager(Coroutine[Any, Any, PolicyResponse]):
    def __init__(self, coroutine: Awaitable[PolicyResponse]) -> None:
        self._coroutine = coroutine
        self._response: PolicyResponse | None = None

    def __await__(self):  # type: ignore[no-untyped-def]
        return self._coroutine.__await__()

    def send(self, value: Any) -> Any:
        return cast(Any, self._coroutine).send(value)

    def throw(self, typ: Any, val: Any = None, tb: Any = None) -> Any:
        if val is None and tb is None:
            return cast(Any, self._coroutine).throw(typ)
        if isinstance(typ, BaseException):
            exc = typ
        elif isinstance(val, BaseException):
            exc = val
        else:
            exc = typ(val)
        if tb is not None:
            exc = exc.with_traceback(tb)
        return cast(Any, self._coroutine).throw(exc)

    def close(self) -> None:
        cast(Any, self._coroutine).close()

    async def __aenter__(self) -> PolicyResponse:
        self._response = await self._coroutine
        return self._response

    async def __aexit__(self, *_: Any) -> None:
        if self._response is not None:
            self._response.release()


ResolverCallable = Callable[[str, int], Awaitable[Iterable[str]]]
TransportCallable = Callable[[HttpTransportRequest], Awaitable[TransportResponse]]


async def resolve_system_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        loop = asyncio.get_running_loop()
        records = await loop.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        return tuple(record[4][0] for record in records)
    return (str(address),)


class _PinnedResolver(AbstractResolver):
    __slots__ = ("permit",)

    def __init__(
        self,
        permit: ConnectionPermit,
    ) -> None:
        self.permit = permit

    def __setattr__(self, name: str, value: Any) -> None:
        if name != "permit" or hasattr(self, "permit"):
            raise AttributeError("pinned resolver authority is immutable")
        object.__setattr__(self, name, value)

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[ResolveResult]:
        current = _now(_system_utc_now())
        if (
            _before_valid_window(current, self.permit.issued_at)
            or current > self.permit.expires_at
        ):
            raise OSError("pinned destination permit expired")
        normalized_host = str(ipaddress.ip_address(host)) if _is_ip(host) else host.lower().rstrip(".")
        if normalized_host != self.permit.host or port != self.permit.port:
            raise OSError("pinned destination mismatch")
        return [
            ResolveResult(
                hostname=host,
                host=address,
                port=port,
                family=socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET,
                proto=socket.IPPROTO_TCP,
                flags=socket.AI_NUMERICHOST,
            )
            for address in self.permit.addresses
        ]

    async def close(self) -> None:
        return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class PolicyBoundTransport:
    """Admit injected transports through the issuing policy immediately before use."""

    def __init__(
        self,
        policy: OutboundPolicy,
        delegate: TransportCallable,
        *,
        require_route_health: bool = True,
    ) -> None:
        policy._assert_authority()
        self.policy = policy
        self.delegate = delegate
        self.require_route_health = require_route_health

    async def __call__(self, request: HttpTransportRequest) -> TransportResponse:
        admitted = self.policy.admit_transport_request(
            request,
            require_route_health=self.require_route_health,
        )
        response: TransportResponse | None = None
        try:
            response = await self.delegate(admitted)
            self.policy.validate_transport_boundary(
                admitted,
                require_route_health=self.require_route_health,
            )
            return response
        except BaseException:
            if response is not None:
                _release_transport_response(response)
            raise


class AiohttpPinnedTransport:
    """Policy-bound one-request aiohttp transport using pinned addresses only."""

    def __init__(
        self,
        policy: OutboundPolicy,
        *,
        require_route_health: bool = True,
    ) -> None:
        policy._assert_authority()
        self.policy = policy
        self.require_route_health = require_route_health

    async def __call__(self, request: HttpTransportRequest) -> TransportResponse:
        admitted = self.policy.admit_transport_request(
            request,
            require_route_health=self.require_route_health,
        )
        if self.policy._current() > admitted.permit.expires_at:
            raise OutboundDenied(OutboundReason.PERMIT_EXPIRED)
        request_headers = admitted.headers
        ssl_context = ssl.create_default_context()
        if not admitted.prepared.verify_tls:
            # This branch is reachable only after the audited LOCAL_LAB policy
            # decision in ``prepare_destination``.
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        if admitted.route is None:
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                resolver=_PinnedResolver(admitted.permit),
                use_dns_cache=False,
                limit=1,
            )
            proxy = None
            request_url = admitted.url
            server_hostname = None
        else:
            compatibility = evaluate_transport_compatibility(
                route=admitted.route,
                protocol=admitted.prepared.destination.scheme,
                tool="aiohttp",
            )
            if not compatibility.supported:
                raise OutboundDenied(compatibility.reason_code)
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                use_dns_cache=False,
                limit=1,
            )
            proxy = admitted.route.proxy_url
            # A generic proxy must never re-resolve the authorized hostname.
            # Address the CONNECT/absolute-form request to the exact permit IP,
            # while preserving the original Host header and TLS SNI/identity.
            pinned_address = admitted.permit.addresses[0]
            parsed = urlsplit(admitted.url)
            pinned_netloc = f"{_format_host(pinned_address)}:{admitted.permit.port}"
            request_url = urlunsplit(
                (parsed.scheme, pinned_netloc, parsed.path, parsed.query, "")
            )
            server_hostname = (
                admitted.prepared.destination.host
                if admitted.prepared.destination.scheme == "https"
                else None
            )
        timeout = aiohttp.ClientTimeout(total=admitted.timeout_seconds)
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                cookie_jar=aiohttp.DummyCookieJar(),
                trust_env=False,
            ) as session:
                self.policy.validate_transport_boundary(
                    admitted,
                    require_route_health=self.require_route_health,
                )
                async with session.request(
                    admitted.method,
                    request_url,
                    headers=request_headers,
                    proxy=proxy,
                    allow_redirects=False,
                    server_hostname=server_hostname,
                    **admitted.options,
                ) as response:
                    body = bytearray()
                    while True:
                        remaining = admitted.max_response_bytes + 1 - len(body)
                        chunk = await response.content.read(min(65536, remaining))
                        if not chunk:
                            break
                        body.extend(chunk)
                        if len(body) > admitted.max_response_bytes:
                            raise OutboundDenied(OutboundReason.RESPONSE_TOO_LARGE)
                    self.policy.validate_transport_boundary(
                        admitted,
                        require_route_health=self.require_route_health,
                    )
                    return TransportResponse(
                        status=response.status,
                        headers=dict(response.headers),
                        body=bytes(body),
                        url=admitted.url,
                    )
        except asyncio.CancelledError:
            raise
        except OutboundDenied:
            raise
        except (aiohttp.ClientConnectorCertificateError, aiohttp.ClientSSLError, ssl.SSLError) as exc:
            raise OutboundDenied(OutboundReason.TLS_VERIFICATION_FAILED) from exc
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            raise OutboundDenied(OutboundReason.CONNECTION_FAILED) from exc


class PolicyHttpClient:
    """aiohttp-compatible, buffered client with explicit per-hop authorization."""

    def __init__(
        self,
        policy: OutboundPolicy,
        *,
        resolver: ResolverCallable | None = None,
        transport: TransportCallable | None = None,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
        headers: Mapping[str, str] | None = None,
        cookies: Mapping[str, str] | None = None,
        cookie_provenance: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        policy._assert_authority()
        self.policy = policy
        self.resolver = resolver or resolve_system_addresses
        self._transport_delegate = transport
        self.transport: TransportCallable = (
            PolicyBoundTransport(policy, transport)
            if transport is not None
            else AiohttpPinnedTransport(policy)
        )
        self.sleeper = sleeper
        self.base_headers = dict(headers or {})
        self.base_cookies = dict(cookies or {})
        self.base_cookie_provenance = {
            str(name): dict(provenance)
            for name, provenance in (cookie_provenance or {}).items()
            if isinstance(provenance, Mapping)
        }
        self.closed = False

    async def __aenter__(self) -> "PolicyHttpClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def close(self) -> None:
        self.closed = True

    def update_headers(self, headers: Mapping[str, str]) -> None:
        self.base_headers.update({str(key): str(value) for key, value in headers.items()})

    def update_cookies(
        self,
        cookies: Mapping[str, str],
        *,
        cookie_provenance: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        self.base_cookies.update({str(key): str(value) for key, value in cookies.items()})
        if cookie_provenance:
            self.base_cookie_provenance.update(
                {
                    str(name): dict(provenance)
                    for name, provenance in cookie_provenance.items()
                    if isinstance(provenance, Mapping)
                }
            )

    def request(self, method: str, url: str, **kwargs: Any) -> _PolicyRequestContextManager:
        return _PolicyRequestContextManager(self._request(method, url, **kwargs))

    def get(self, url: str, **kwargs: Any) -> _PolicyRequestContextManager:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> _PolicyRequestContextManager:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> _PolicyRequestContextManager:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> _PolicyRequestContextManager:
        return self.request("DELETE", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> _PolicyRequestContextManager:
        return self.request("PATCH", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> _PolicyRequestContextManager:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> _PolicyRequestContextManager:
        return self.request("OPTIONS", url, **kwargs)

    async def _await_cancellable(
        self,
        awaitable: Awaitable[Any],
        *,
        late_result_cleanup: _LateResultCleanup | None,
        timeout_seconds: float | None = None,
    ) -> Any:
        task = asyncio.ensure_future(awaitable)

        deadline = (
            asyncio.get_running_loop().time() + timeout_seconds
            if timeout_seconds is not None
            else None
        )
        try:
            while not task.done():
                if self.policy._cancelled():
                    raise OutboundDenied(OutboundReason.CANCELLED)
                wait_seconds = 0.05
                if deadline is not None:
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        raise asyncio.TimeoutError
                    wait_seconds = min(wait_seconds, remaining)
                done, _ = await asyncio.wait({task}, timeout=wait_seconds)
                if done:
                    break
            return await task
        except BaseException as original:
            cleanup = asyncio.create_task(
                _cancel_task_with_transport_cleanup(
                    task,
                    late_result_cleanup=late_result_cleanup,
                )
            )
            cancelled_during_cleanup = False
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    # Repeated caller cancellation must not interrupt resource
                    # ownership transfer.  Cleanup itself is bounded above.
                    cancelled_during_cleanup = True
            cleanup.result()
            if cancelled_during_cleanup and not isinstance(
                original,
                asyncio.CancelledError,
            ):
                raise asyncio.CancelledError from original
            raise

    async def _request(self, method: str, url: str, **kwargs: Any) -> PolicyResponse:
        if self.closed:
            raise RuntimeError("outbound client is closed")
        self.policy._assert_authority()
        current_method = str(method).upper().strip()
        if not current_method or not re.fullmatch(r"[A-Z]+", current_method):
            raise ValueError("HTTP method is malformed")
        allow_redirects = bool(kwargs.pop("allow_redirects", True))
        caller_headers = kwargs.pop("headers", None) or {}
        caller_cookies = kwargs.pop("cookies", None) or {}
        credential_binding = kwargs.pop("credential_binding", None)
        if credential_binding is not None and not isinstance(credential_binding, CredentialBinding):
            raise TypeError("credential_binding must be a CredentialBinding")
        authorized_origin = normalize_destination(
            self.policy.context.authorized_target
        ).origin
        if (
            credential_binding is not None
            and not hmac.compare_digest(credential_binding.origin, authorized_origin)
        ):
            self.policy._deny(
                OutboundReason.AUTHORIZATION_INVALID,
                action_kind="http.request",
                stage="credential_binding",
            )
        timeout_value = kwargs.pop("timeout", self.policy.context.timeout_seconds)
        if isinstance(timeout_value, aiohttp.ClientTimeout):
            timeout_seconds = float(timeout_value.total or self.policy.context.timeout_seconds)
        else:
            timeout_seconds = float(timeout_value)
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            self.policy._deny(
                OutboundReason.REQUEST_OPTION_NOT_ALLOWED,
                action_kind="http.request",
                stage="request_options",
                detail={"option_names": ["timeout"]},
            )
        timeout_seconds = min(timeout_seconds, self.policy.context.timeout_seconds)
        requested_retries = int(kwargs.pop("retries", self.policy.context.max_retries))
        requested_redirects = int(
            kwargs.pop("max_redirects", self.policy.context.max_redirects)
        )
        if requested_retries < 0 or requested_redirects < 0:
            self.policy._deny(
                OutboundReason.REQUEST_OPTION_NOT_ALLOWED,
                action_kind="http.request",
                stage="request_options",
                detail={"option_names": ["retries", "max_redirects"]},
            )
        retries = min(requested_retries, self.policy.context.max_retries)
        max_redirects = min(requested_redirects, self.policy.context.max_redirects)
        params = kwargs.pop("params", None)
        unknown_options = sorted(set(kwargs) - _SAFE_REQUEST_OPTIONS)
        if unknown_options:
            self.policy._deny(
                OutboundReason.REQUEST_OPTION_NOT_ALLOWED,
                action_kind="http.request",
                stage="request_options",
                detail={"option_names": unknown_options},
            )
        if params is not None:
            try:
                url = append_query_parameters(url, cast(Any, params))
            except (TypeError, ValueError):
                self.policy._deny(
                    OutboundReason.MALFORMED_DESTINATION,
                    action_kind="http.request",
                    stage="request_options",
                )
        try:
            initial = normalize_destination(url)
        except OutboundDenied:
            # Route malformed input through the audited pre-resolution path.
            self.policy.prepare_destination(url, action_kind="http.request")
            raise AssertionError("unreachable")
        binding = credential_binding or CredentialBinding.for_origin(
            self.policy.context.authorized_target
        )
        if (
            not hmac.compare_digest(initial.origin, binding.origin)
            and any(name in kwargs for name in ("data", "json"))
        ):
            self.policy._deny(
                OutboundReason.CROSS_ORIGIN_BODY_NOT_AUTHORIZED,
                action_kind="http.request",
                stage="initial_destination",
                destination=initial,
            )
        original_headers = dict(self.base_headers)
        original_headers.update({str(key): str(value) for key, value in caller_headers.items()})
        cookies = dict(self.base_cookies)
        for header_name in list(original_headers):
            if header_name.strip().lower() != "cookie":
                continue
            parsed_cookies = SimpleCookie()
            parsed_cookies.load(original_headers.pop(header_name))
            cookies.update(
                {name: morsel.value for name, morsel in parsed_cookies.items()}
            )
        cookies.update({str(key): str(value) for key, value in caller_cookies.items()})
        audit_original_headers = dict(original_headers)
        if cookies:
            audit_original_headers["Cookie"] = "<origin-bound>"
        request_id = f"request-{uuid.uuid4().hex}"
        route = self.policy.context.route
        if (
            route is not None
            and (
                route.required
                or route.verification_policy is RouteVerificationPolicy.REQUIRED
            )
            and not self.policy.route_health_is_current()
        ):
            # Validate the caller's actual destination and request contract
            # before any route-verification traffic.  Route health is the only
            # check deferred here; the normal attempt repeats the full decision
            # after a successful preflight.
            initial_prepared = self.policy._prepare_destination(
                initial.url,
                action_kind="http.request",
                request_id=request_id,
                require_route_health=False,
            )
            try:
                self.policy._assert_authority()
                initial_addresses = await self._await_cancellable(
                    self.resolver(
                        initial_prepared.destination.host,
                        initial_prepared.destination.port,
                    ),
                    late_result_cleanup=None,
                    timeout_seconds=timeout_seconds,
                )
            except asyncio.CancelledError:
                self.policy.record_terminal_failure(
                    prepared=initial_prepared,
                    reason=OutboundReason.CANCELLED,
                    stage="initial_resolution",
                )
                raise
            except OutboundDenied as exc:
                self.policy.record_terminal_failure(
                    prepared=initial_prepared,
                    reason=exc.reason_code,
                    stage="initial_resolution",
                )
                raise
            except Exception as exc:
                self.policy.record_terminal_failure(
                    prepared=initial_prepared,
                    reason=OutboundReason.CONNECTION_FAILED,
                    stage="initial_resolution",
                )
                raise OutboundDenied(OutboundReason.CONNECTION_FAILED) from exc
            # Prove the complete initial DNS answer is in scope before the
            # first route-verification connection.  The normal attempt resolves
            # again with the same request/hop key, so changed answers fail as
            # DNS_ANSWER_CHANGED before target transport.
            self.policy._authorize_resolution(
                initial_prepared,
                initial_addresses,
                require_route_health=False,
            )
            try:
                await self._await_cancellable(
                    self.policy.preflight_route(
                        resolver=self.resolver,
                        transport=self._transport_delegate,
                    ),
                    late_result_cleanup=None,
                    timeout_seconds=None,
                )
            except OutboundDenied as exc:
                if (
                    exc.reason_code == OutboundReason.CANCELLED.value
                    and not self.policy.last_denial_reason
                ):
                    self.policy._deny(
                        OutboundReason.CANCELLED,
                        action_kind="route.preflight",
                        stage="route_preflight",
                    )
                raise
        current_url = initial.url
        previous_origin = ""
        hop = 0
        attempt = 0
        history: list[str] = []
        while True:
            self.policy._assert_authority()
            attempt_limiter = self.policy.context.attempt_limiter
            if attempt_limiter is not None:
                try:
                    await self._await_cancellable(
                        attempt_limiter(),
                        late_result_cleanup=None,
                        timeout_seconds=timeout_seconds,
                    )
                except OutboundDenied as exc:
                    self.policy._deny(
                        OutboundReason(exc.reason_code),
                        action_kind="http.request",
                        stage="rate_limit",
                    )
                except Exception:
                    self.policy._deny(
                        OutboundReason.CONNECTION_FAILED,
                        action_kind="http.request",
                        stage="rate_limit",
                    )
                self.policy._assert_authority()
            prepared = self.policy.prepare_destination(
                current_url,
                action_kind="http.request",
                previous_origin=previous_origin,
                hop=hop,
                attempt=attempt,
                request_id=request_id,
            )
            try:
                self.policy._assert_authority()
                addresses = await self._await_cancellable(
                    self.resolver(
                        prepared.destination.host,
                        prepared.destination.port,
                    ),
                    late_result_cleanup=None,
                    timeout_seconds=timeout_seconds,
                )
            except asyncio.CancelledError:
                self.policy.record_terminal_failure(
                    prepared=prepared,
                    reason=OutboundReason.CANCELLED,
                    stage="resolution",
                )
                raise
            except OutboundDenied as exc:
                self.policy.record_terminal_failure(
                    prepared=prepared,
                    reason=exc.reason_code,
                    stage="resolution",
                )
                raise
            except Exception as exc:
                self.policy.record_terminal_failure(
                    prepared=prepared,
                    reason=OutboundReason.CONNECTION_FAILED,
                    stage="resolution",
                )
                raise OutboundDenied(OutboundReason.CONNECTION_FAILED) from exc
            permit = self.policy.authorize_resolution(prepared, addresses)
            hop_headers = strip_origin_bound_secrets(
                original_headers,
                destination_origin=prepared.destination.origin,
                binding=binding,
            )
            hop_headers = _headers_with_canonical_host(
                hop_headers,
                prepared.destination,
            )
            if hmac.compare_digest(prepared.destination.origin, binding.origin):
                hop_cookies = {
                    name: value
                    for name, value in cookies.items()
                    if name not in self.base_cookie_provenance
                    or cookie_provenance_matches_destination(
                        self.base_cookie_provenance[name],
                        prepared.destination.url,
                    )
                }
                if hop_cookies:
                    hop_headers["Cookie"] = "; ".join(
                        f"{name}={value}"
                        for name, value in sorted(hop_cookies.items())
                    )
            self.policy.record_credential_transition(
                prepared,
                audit_original_headers,
                hop_headers,
            )
            transport_request = HttpTransportRequest(
                method=current_method,
                url=prepared.destination.url,
                headers=hop_headers,
                permit=permit,
                prepared=prepared,
                route=prepared.route,
                timeout_seconds=timeout_seconds,
                max_response_bytes=self.policy.context.max_response_bytes,
                options=dict(kwargs),
            )
            response: TransportResponse | None = None
            try:
                self.policy._assert_authority()
                response = await self._await_cancellable(
                    self.transport(transport_request),
                    late_result_cleanup=_release_transport_response,
                    timeout_seconds=timeout_seconds,
                )
            except asyncio.CancelledError:
                if response is not None:
                    _release_transport_response(response)
                self.policy.record_terminal_failure(
                    prepared=prepared,
                    reason=OutboundReason.CANCELLED,
                    stage="transport",
                )
                raise
            except OutboundDenied as exc:
                if response is not None:
                    _release_transport_response(response)
                self.policy.record_terminal_failure(
                    prepared=prepared,
                    reason=exc.reason_code,
                    stage="transport",
                )
                raise
            except Exception as exc:
                if response is not None:
                    _release_transport_response(response)
                self.policy.record_terminal_failure(
                    prepared=prepared,
                    reason=OutboundReason.CONNECTION_FAILED,
                    stage="transport",
                )
                raise OutboundDenied(OutboundReason.CONNECTION_FAILED) from exc
            assert response is not None
            raw_response = response
            try:
                # Copy every value needed by the buffered client while the
                # raw delegate response is owned by this scope.  Even a
                # malformed mapping/attribute releases exactly once.
                response = TransportResponse(
                    status=raw_response.status,
                    headers={
                        str(key): str(value)
                        for key, value in raw_response.headers.items()
                    },
                    body=bytes(raw_response.body),
                    url=raw_response.url,
                )
            except Exception as exc:
                self.policy.record_terminal_failure(
                    prepared=prepared,
                    reason=OutboundReason.CONNECTION_FAILED,
                    stage="transport_response",
                )
                raise OutboundDenied(OutboundReason.CONNECTION_FAILED) from exc
            finally:
                release_succeeded = _release_transport_response(raw_response)
            if not release_succeeded:
                self.policy.record_terminal_failure(
                    prepared=prepared,
                    reason=OutboundReason.TRANSPORT_CLEANUP_FAILED,
                    stage="transport_cleanup",
                )
                raise OutboundDenied(OutboundReason.TRANSPORT_CLEANUP_FAILED)
            if len(response.body) > self.policy.context.max_response_bytes:
                _release_transport_response(response)
                self.policy.record_terminal_failure(
                    prepared=prepared,
                    reason=OutboundReason.RESPONSE_TOO_LARGE,
                    stage="transport",
                )
                raise OutboundDenied(OutboundReason.RESPONSE_TOO_LARGE)
            location = next(
                (value for key, value in response.headers.items() if str(key).lower() == "location"),
                "",
            )
            if allow_redirects and response.status in _REDIRECT_STATUSES and location:
                _release_transport_response(response)
                if hop >= max_redirects:
                    self.policy._deny(
                        OutboundReason.REDIRECT_LIMIT_EXCEEDED,
                        action_kind="http.request",
                        stage="redirect",
                        destination=prepared.destination,
                        tls_mode=prepared.tls_mode,
                    )
                try:
                    next_url = urljoin(prepared.destination.url, str(location))
                except (TypeError, ValueError):
                    # ``urljoin`` parses absolute/scheme-relative locations and
                    # can reject malformed authority syntax before the normal
                    # destination validator runs.  Keep those redirect
                    # failures on the same typed, audited fail-closed path.
                    self.policy._deny(
                        OutboundReason.MALFORMED_DESTINATION,
                        action_kind="http.request",
                        stage="redirect",
                        tls_mode=prepared.tls_mode,
                        detail={"hop": hop + 1},
                    )
                    raise AssertionError("unreachable")
                try:
                    next_destination = normalize_destination(next_url)
                except OutboundDenied:
                    self.policy.prepare_destination(
                        next_url,
                        action_kind="http.request",
                        previous_origin=prepared.destination.origin,
                        hop=hop + 1,
                        attempt=0,
                        request_id=request_id,
                    )
                    raise AssertionError("unreachable")
                changes_to_get = response.status == 303 or (
                    response.status in {301, 302} and current_method == "POST"
                )
                if (
                    next_destination.origin != prepared.destination.origin
                    and any(name in kwargs for name in ("data", "json"))
                    and not changes_to_get
                ):
                    self.policy._deny(
                        OutboundReason.CROSS_ORIGIN_BODY_NOT_AUTHORIZED,
                        action_kind="http.request",
                        stage="redirect",
                        destination=next_destination,
                    )
                history.append(prepared.destination.url)
                previous_origin = prepared.destination.origin
                current_url = next_destination.url
                hop += 1
                attempt = 0
                if changes_to_get:
                    current_method = "GET"
                    kwargs.pop("data", None)
                    kwargs.pop("json", None)
                continue
            if response.status in _RETRY_STATUSES:
                if current_method not in _IDEMPOTENT_METHODS and not any(
                    key.lower() == "idempotency-key" for key in hop_headers
                ):
                    _release_transport_response(response)
                    self.policy._deny(
                        OutboundReason.RETRY_NOT_IDEMPOTENT,
                        action_kind="http.request",
                        stage="retry",
                        destination=prepared.destination,
                        tls_mode=prepared.tls_mode,
                    )
                if attempt >= retries:
                    _release_transport_response(response)
                    self.policy._deny(
                        OutboundReason.RETRY_LIMIT_EXCEEDED,
                        action_kind="http.request",
                        stage="retry",
                        destination=prepared.destination,
                        tls_mode=prepared.tls_mode,
                    )
                _release_transport_response(response)
                retry_after = next(
                    (value for key, value in response.headers.items() if str(key).lower() == "retry-after"),
                    "",
                )
                try:
                    delay = max(0.0, min(float(retry_after), 30.0)) if retry_after else min(2.0 ** attempt, 30.0)
                except ValueError:
                    delay = min(2.0 ** attempt, 30.0)
                try:
                    await self._await_cancellable(
                        self.sleeper(delay),
                        late_result_cleanup=None,
                        timeout_seconds=timeout_seconds,
                    )
                except OutboundDenied:
                    self.policy.record_terminal_failure(
                        prepared=prepared,
                        reason=OutboundReason.CANCELLED,
                        stage="retry_backoff",
                    )
                    raise
                except Exception as exc:
                    self.policy.record_terminal_failure(
                        prepared=prepared,
                        reason=OutboundReason.CONNECTION_FAILED,
                        stage="retry_backoff",
                    )
                    raise OutboundDenied(OutboundReason.CONNECTION_FAILED) from exc
                attempt += 1
                continue
            try:
                return PolicyResponse(
                    status=response.status,
                    headers={
                        str(key): str(value)
                        for key, value in response.headers.items()
                    },
                    body=bytes(response.body),
                    url=response.url or prepared.destination.url,
                    history=tuple(history),
                )
            finally:
                # PolicyResponse is fully buffered; ownership of any delegate
                # resource ends before the wrapper is returned.
                _release_transport_response(response)


class DeniedPolicyHttpClient:
    """Compatibility-shaped inert client for unauthorized direct module use."""

    def __init__(
        self,
        reason: OutboundReason = OutboundReason.AUTHORIZATION_INVALID,
        on_deny: Callable[[str], None] | None = None,
    ) -> None:
        self.reason = reason
        self.on_deny = on_deny
        self.closed = False

    async def __aenter__(self) -> "DeniedPolicyHttpClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def close(self) -> None:
        self.closed = True

    def _request(self) -> _PolicyRequestContextManager:
        async def denied() -> PolicyResponse:
            if self.on_deny is not None:
                self.on_deny(self.reason.value)
            raise OutboundDenied(self.reason)

        return _PolicyRequestContextManager(denied())

    def request(self, *_: Any, **__: Any) -> _PolicyRequestContextManager:
        return self._request()

    def get(self, *_: Any, **__: Any) -> _PolicyRequestContextManager:
        return self._request()

    def post(self, *_: Any, **__: Any) -> _PolicyRequestContextManager:
        return self._request()

    def put(self, *_: Any, **__: Any) -> _PolicyRequestContextManager:
        return self._request()

    def delete(self, *_: Any, **__: Any) -> _PolicyRequestContextManager:
        return self._request()

    def patch(self, *_: Any, **__: Any) -> _PolicyRequestContextManager:
        return self._request()

    def head(self, *_: Any, **__: Any) -> _PolicyRequestContextManager:
        return self._request()

    def options(self, *_: Any, **__: Any) -> _PolicyRequestContextManager:
        return self._request()


def append_query_parameters(url: str, params: Mapping[str, Any] | Iterable[tuple[str, Any]]) -> str:
    """Deterministically add query parameters before policy evaluation."""
    destination = normalize_destination(url)
    parsed = urlsplit(destination.url)
    encoded = urlencode(cast(Any, params), doseq=True)
    query = "&".join(part for part in (parsed.query, encoded) if part)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
