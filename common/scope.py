"""Pure, fail-closed scope decisions for every active Forge boundary."""
from __future__ import annotations

import ipaddress
import hashlib
import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

log = logging.getLogger(__name__)

_IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_HOST_LABEL = re.compile(r"^[a-z0-9_-]+$", re.IGNORECASE)
_AMBIGUOUS_IPV4 = re.compile(
    r"^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$",
    re.IGNORECASE,
)


class ScopeReason(str, Enum):
    """Stable reason codes shared by launchers and the future envelope."""

    ALLOWED = "allowed"
    SCOPE_MATCHED = "scope_matched"
    MISSING_SCOPE = "missing_scope"
    MALFORMED_SCOPE = "malformed_scope"
    MALFORMED_TARGET = "malformed_target"
    EXCLUDED = "excluded"
    TARGET_MISMATCH = "target_mismatch"
    MISSING_CONFIRMATION = "missing_confirmation"
    INVALID_CONFIRMATION = "invalid_confirmation"
    STALE_CONFIRMATION = "stale_confirmation"
    JOB_MISMATCH = "job_mismatch"
    ENGINE_MISMATCH = "engine_mismatch"
    ACTION_MISMATCH = "action_mismatch"


_REASONS: dict[ScopeReason, str] = {
    ScopeReason.ALLOWED: "The submitted target matches the effective scope.",
    ScopeReason.SCOPE_MATCHED: "The submitted target matches scope; no action was authorized.",
    ScopeReason.MISSING_SCOPE: "An explicit, non-empty effective scope is required.",
    ScopeReason.MALFORMED_SCOPE: "The effective scope contains a malformed or ambiguous entry.",
    ScopeReason.MALFORMED_TARGET: "The submitted target is malformed or ambiguous.",
    ScopeReason.EXCLUDED: "The submitted target intersects an explicit exclusion.",
    ScopeReason.TARGET_MISMATCH: "The submitted target does not match the approved target or scope.",
    ScopeReason.MISSING_CONFIRMATION: "This active action requires explicit operator confirmation.",
    ScopeReason.INVALID_CONFIRMATION: "The supplied confirmation is malformed or has invalid integrity data.",
    ScopeReason.STALE_CONFIRMATION: "The supplied confirmation is stale or has an invalid timestamp.",
    ScopeReason.JOB_MISMATCH: "The confirmation is bound to a different job.",
    ScopeReason.ENGINE_MISMATCH: "The confirmation is bound to a different engine.",
    ScopeReason.ACTION_MISMATCH: "The confirmation is bound to a different action.",
}


@dataclass(frozen=True)
class ScopeDecision:
    """Narrow serializable result for scope and launch-boundary decisions."""

    allowed: bool
    reason_code: str
    reason: str
    normalized_target: str = ""
    matched_scope: str = ""

    def to_dict(self) -> dict[str, object]:
        """Return only non-secret decision metadata."""
        result: dict[str, object] = {
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "reason": self.reason,
        }
        if self.normalized_target:
            result["normalized_target"] = self.normalized_target
        return result


@dataclass(frozen=True)
class _ParsedScopeValue:
    normalized: str
    network: _IpNetwork | None = None
    domain: str = ""


class ScopeViolation(Exception):
    """Raised when a target is denied by the effective scope."""

    def __init__(self, decision: ScopeDecision) -> None:
        self.decision = decision
        super().__init__(f"{decision.reason_code}: {decision.reason}")


def _decision(
    reason: ScopeReason,
    *,
    normalized_target: str = "",
    matched_scope: str = "",
) -> ScopeDecision:
    return ScopeDecision(
        allowed=reason in {ScopeReason.ALLOWED, ScopeReason.SCOPE_MATCHED},
        reason_code=reason.value,
        reason=_REASONS[reason],
        normalized_target=normalized_target,
        matched_scope=matched_scope,
    )


def decision_for_reason(
    reason: ScopeReason,
    *,
    normalized_target: str = "",
    matched_scope: str = "",
) -> ScopeDecision:
    """Build a decision while keeping stable reason text in one module."""
    return _decision(
        reason,
        normalized_target=normalized_target,
        matched_scope=matched_scope,
    )


def _entries(values: Iterable[str] | str | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    normalized: list[str] = []
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise ValueError("scope must be a string or iterable of strings") from exc
    for value in iterator:
        if not isinstance(value, str):
            raise ValueError("scope entries must be strings")
        normalized.append(value.strip())
    return normalized


def _normalize_domain(host: str, *, allow_wildcard: bool) -> str:
    value = host.strip().strip("[]").lower().rstrip(".")
    if allow_wildcard and value.startswith("*."):
        value = value[2:]
    if not value or value == "*" or len(value) > 253:
        raise ValueError("invalid hostname")
    if _AMBIGUOUS_IPV4.fullmatch(value):
        raise ValueError("ambiguous IPv4-like hostname")
    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not _HOST_LABEL.fullmatch(label)
        for label in labels
    ):
        raise ValueError("invalid hostname")
    return value


def _url_host(value: str) -> tuple[str, int | None]:
    if "\\" in value:
        raise ValueError("backslashes are ambiguous in URLs")
    parsed = urlsplit(value)
    try:
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid URL authority") from exc
    if not parsed.scheme or not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("URL requires a scheme and hostname")
    return host, port


def _bare_host(value: str) -> tuple[str, int | None]:
    """Parse a bare host[:port] without URL parser authority ambiguities."""
    if any(marker in value for marker in ("@", "?", "#")):
        raise ValueError("bare targets cannot contain userinfo, query, or fragment data")
    authority = value[:-1] if value.endswith("/") else value
    if not authority or "/" in authority:
        raise ValueError("invalid bare target")
    if "[" in authority or "]" in authority:
        if not re.fullmatch(r"\[[^\[\]]+\](?::[0-9]+)?", authority):
            raise ValueError("invalid bracketed host")
    elif authority.count(":") > 1:
        try:
            address = ipaddress.ip_address(authority)
        except ValueError as exc:
            raise ValueError("invalid unbracketed IPv6 target") from exc
        if not isinstance(address, ipaddress.IPv6Address):
            raise ValueError("invalid bare target")
        return str(address), None

    try:
        parsed = urlsplit(f"scope://{authority}")
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid host or port") from exc
    if (
        not host
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("invalid bare target")
    return host, port


def _literal_candidate(value: str) -> str | None:
    """Return an exact IP/CIDR literal candidate, rejecting malformed brackets."""
    if "[" not in value and "]" not in value:
        return value
    if value.count("[") == 1 and value.count("]") == 1 and value.startswith("[") and value.endswith("]"):
        return value[1:-1]
    if re.fullmatch(r"\[[^\[\]]+\]:[0-9]+/?", value):
        return None
    raise ValueError("invalid bracketed target")


def _parse_scope_value(value: str, *, scope_entry: bool) -> _ParsedScopeValue:
    raw = value.strip()
    if not raw or any(char.isspace() for char in raw) or "\\" in raw:
        raise ValueError("empty or whitespace-containing value")

    if "://" not in raw:
        candidate = _literal_candidate(raw)
        if candidate is not None:
            try:
                network = ipaddress.ip_network(candidate, strict=False)
                return _ParsedScopeValue(normalized=str(network), network=network)
            except ValueError:
                if "/" in raw:
                    raise ValueError("invalid network")

    if "://" in raw:
        host, _ = _url_host(raw)
    else:
        host, _ = _bare_host(raw)

    try:
        network = ipaddress.ip_network(host, strict=False)
        return _ParsedScopeValue(normalized=str(network), network=network)
    except ValueError:
        domain = _normalize_domain(host, allow_wildcard=scope_entry)
        return _ParsedScopeValue(normalized=domain, domain=domain)


def _canonical_target_material(target: str) -> str:
    if not isinstance(target, str):
        raise ValueError("target must be a string")
    raw = target.strip()
    if not raw or any(char.isspace() for char in raw) or "\\" in raw:
        raise ValueError("invalid target")
    if "://" not in raw:
        candidate = _literal_candidate(raw)
        if candidate is not None:
            try:
                network = ipaddress.ip_network(candidate, strict=False)
                return str(network) if "/" in raw else str(network.network_address)
            except ValueError:
                if "/" in raw:
                    raise ValueError("invalid network")
        host, port = _bare_host(raw)
        try:
            address = ipaddress.ip_address(host)
            canonical_host = f"[{address}]" if address.version == 6 else str(address)
        except ValueError:
            canonical_host = _normalize_domain(host, allow_wildcard=False)
        return canonical_host if port is None else f"{canonical_host}:{port}"

    parsed = urlsplit(raw)
    host, port = _url_host(raw)
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        canonical_host = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        canonical_host = _normalize_domain(host, allow_wildcard=False)
    netloc = canonical_host if port is None else f"{canonical_host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "", parsed.query, parsed.fragment))


def canonical_target(target: str) -> str:
    """Return an opaque SHA-256 binding for the exact submitted target."""
    material = _canonical_target_material(target)
    return f"sha256:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


def safe_target_display(target: str) -> str:
    """Return host/network-only target metadata safe for logs and responses."""
    try:
        return _parse_scope_value(target, scope_entry=False).normalized
    except (TypeError, ValueError):
        return "<invalid-target>"


def _network_representations(network: _IpNetwork) -> list[_IpNetwork]:
    representations: list[_IpNetwork] = [network]
    if isinstance(network, ipaddress.IPv6Network):
        mapped_prefix = ipaddress.IPv6Network("::ffff:0:0/96")
        if network.subnet_of(mapped_prefix):
            mapped_address = network.network_address.ipv4_mapped
            if mapped_address is not None:
                representations.append(
                    ipaddress.IPv4Network((mapped_address, network.prefixlen - 96), strict=False)
                )
    return representations


def _same_family_subnet(candidate: _IpNetwork, allowed: _IpNetwork) -> bool:
    if isinstance(candidate, ipaddress.IPv4Network) and isinstance(allowed, ipaddress.IPv4Network):
        return candidate.subnet_of(allowed)
    if isinstance(candidate, ipaddress.IPv6Network) and isinstance(allowed, ipaddress.IPv6Network):
        return candidate.subnet_of(allowed)
    return False


def _network_matches(candidate: _IpNetwork, allowed: _IpNetwork) -> bool:
    return any(
        _same_family_subnet(candidate_value, allowed_value)
        for candidate_value in _network_representations(candidate)
        for allowed_value in _network_representations(allowed)
    )


def _same_family_overlap(candidate: _IpNetwork, excluded: _IpNetwork) -> bool:
    if isinstance(candidate, ipaddress.IPv4Network) and isinstance(excluded, ipaddress.IPv4Network):
        return candidate.overlaps(excluded)
    if isinstance(candidate, ipaddress.IPv6Network) and isinstance(excluded, ipaddress.IPv6Network):
        return candidate.overlaps(excluded)
    return False


def _network_intersects(candidate: _IpNetwork, excluded: _IpNetwork) -> bool:
    if any(
        _same_family_overlap(candidate_value, excluded_value)
        for candidate_value in _network_representations(candidate)
        for excluded_value in _network_representations(excluded)
    ):
        return True

    mapped_base = int(ipaddress.IPv6Address("::ffff:0:0"))

    def mapped_network(value: ipaddress.IPv4Network) -> ipaddress.IPv6Network:
        return ipaddress.IPv6Network(
            (mapped_base + int(value.network_address), value.prefixlen + 96),
            strict=False,
        )

    if isinstance(candidate, ipaddress.IPv6Network) and isinstance(excluded, ipaddress.IPv4Network):
        return candidate.overlaps(mapped_network(excluded))
    if isinstance(candidate, ipaddress.IPv4Network) and isinstance(excluded, ipaddress.IPv6Network):
        return mapped_network(candidate).overlaps(excluded)
    return False


def _domain_matches(candidate: str, allowed: str) -> bool:
    return candidate == allowed or candidate.endswith(f".{allowed}")


def decide_scope(
    target: str,
    allowed: Iterable[str] | str | None,
    excluded: Iterable[str] | str | None = None,
) -> ScopeDecision:
    """Purely decide whether a URL, host, IP, or CIDR is in effective scope."""
    try:
        allow_values = _entries(allowed)
        exclude_values = _entries(excluded)
    except ValueError:
        return _decision(ScopeReason.MALFORMED_SCOPE)
    if not allow_values or not any(allow_values):
        return _decision(ScopeReason.MISSING_SCOPE)

    try:
        parsed_allowed = [
            _parse_scope_value(value, scope_entry=True)
            for value in allow_values
        ]
        parsed_excluded = [
            _parse_scope_value(value, scope_entry=True)
            for value in exclude_values
        ]
    except ValueError:
        return _decision(ScopeReason.MALFORMED_SCOPE)

    try:
        if not isinstance(target, str):
            raise ValueError("target must be a string")
        candidate = _parse_scope_value(target, scope_entry=False)
    except (TypeError, ValueError):
        return _decision(ScopeReason.MALFORMED_TARGET)

    for entry in parsed_excluded:
        if candidate.network is not None and entry.network is not None:
            if _network_intersects(candidate.network, entry.network):
                return _decision(
                    ScopeReason.EXCLUDED,
                    normalized_target=candidate.normalized,
                    matched_scope=entry.normalized,
                )
        elif candidate.domain and entry.domain and _domain_matches(candidate.domain, entry.domain):
            return _decision(
                ScopeReason.EXCLUDED,
                normalized_target=candidate.normalized,
                matched_scope=entry.normalized,
            )

    for entry in parsed_allowed:
        if candidate.network is not None and entry.network is not None:
            if _network_matches(candidate.network, entry.network):
                return _decision(
                    ScopeReason.ALLOWED,
                    normalized_target=candidate.normalized,
                    matched_scope=entry.normalized,
                )
        elif candidate.domain and entry.domain and _domain_matches(candidate.domain, entry.domain):
            return _decision(
                ScopeReason.ALLOWED,
                normalized_target=candidate.normalized,
                matched_scope=entry.normalized,
            )

    return _decision(
        ScopeReason.TARGET_MISMATCH,
        normalized_target=candidate.normalized,
    )


class Scope:
    """Compatibility adapter around the pure fail-closed scope decision."""

    def __init__(
        self,
        targets: Iterable[str] | str | None,
        excluded: Iterable[str] | str | None = None,
        strict: bool = True,
    ) -> None:
        self.strict = strict
        try:
            self.targets = _entries(targets)
            self.excluded = _entries(excluded)
            self._invalid_configuration = False
        except ValueError:
            self.targets = []
            self.excluded = []
            self._invalid_configuration = True

    def decision(self, target: str) -> ScopeDecision:
        if self._invalid_configuration:
            return _decision(ScopeReason.MALFORMED_SCOPE)
        return decide_scope(target, self.targets, self.excluded)

    def check(self, target: str) -> bool:
        decision = self.decision(target)
        if decision.allowed:
            return True
        log.warning(
            "SCOPE_DENIED: %s",
            decision.reason_code,
            extra={
                "reason_code": decision.reason_code,
                "target": decision.normalized_target,
            },
        )
        if self.strict:
            raise ScopeViolation(decision)
        return False

    def check_url(self, url: str) -> bool:
        return self.check(url)

    def check_ip(self, ip: str) -> bool:
        return self.check(ip)


class TestScope:
    """Unit tests retained for production-package collection checks."""

    def test_cidr_in_scope(self) -> None:
        scope = Scope(["10.0.0.0/24"])
        assert scope.check("10.0.0.1") is True
        assert scope.check("10.0.0.255") is True

    def test_cidr_out_of_scope(self) -> None:
        scope = Scope(["10.0.0.0/24"], strict=False)
        assert scope.check("10.0.1.1") is False

    def test_domain_in_scope(self) -> None:
        scope = Scope(["example.com"])
        assert scope.check("example.com") is True
        assert scope.check("sub.example.com") is True

    def test_domain_out_of_scope(self) -> None:
        scope = Scope(["example.com"], strict=False)
        assert scope.check("evil.com") is False

    def test_exclusion(self) -> None:
        scope = Scope(["10.0.0.0/24"], excluded=["10.0.0.1"], strict=False)
        assert scope.check("10.0.0.1") is False
        assert scope.check("10.0.0.2") is True

    def test_strict_raises(self) -> None:
        scope = Scope(["10.0.0.0/24"], strict=True)
        try:
            scope.check("192.168.1.1")
            assert False, "Should have raised"
        except ScopeViolation:
            pass

    def test_empty_scope_denies(self) -> None:
        scope = Scope([], strict=False)
        assert scope.check("1.2.3.4") is False
