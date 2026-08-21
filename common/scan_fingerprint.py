"""Passive scan fingerprint state and adaptive rate helpers.

This module is intentionally deterministic and side-effect light: it never
opens sockets or probes targets. Callers provide observed host/service facts
and request outcomes; this helper turns those facts into stable fingerprints,
rescan decisions, and persisted per-service rate state.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


STATE_VERSION = 1
DEFAULT_HASH_ALGORITHM = "sha256"


class ScanFingerprintStateError(ValueError):
    """Raised when a persisted scan fingerprint state file is invalid."""


class RateSignal(str, Enum):
    """Passive request outcome signals used by the rate adapter."""

    SUCCESS = "success"
    CONNECTION_DROP = "connection_drop"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"


_RATE_SIGNAL_ALIASES: dict[str, RateSignal] = {
    "ok": RateSignal.SUCCESS,
    "success": RateSignal.SUCCESS,
    "succeeded": RateSignal.SUCCESS,
    "2xx": RateSignal.SUCCESS,
    "3xx": RateSignal.SUCCESS,
    "connection_drop": RateSignal.CONNECTION_DROP,
    "connection_dropped": RateSignal.CONNECTION_DROP,
    "connection_reset": RateSignal.CONNECTION_DROP,
    "connection_error": RateSignal.CONNECTION_DROP,
    "disconnect": RateSignal.CONNECTION_DROP,
    "eof": RateSignal.CONNECTION_DROP,
    "timeout": RateSignal.TIMEOUT,
    "timed_out": RateSignal.TIMEOUT,
    "read_timeout": RateSignal.TIMEOUT,
    "connect_timeout": RateSignal.TIMEOUT,
    "rate_limit": RateSignal.RATE_LIMIT,
    "rate_limited": RateSignal.RATE_LIMIT,
    "too_many_requests": RateSignal.RATE_LIMIT,
    "429": RateSignal.RATE_LIMIT,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonicalize(value: Any) -> Any:
    """Convert supported Python values into deterministic JSON-compatible data."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _canonicalize(dataclasses.asdict(value))
    if isinstance(value, Mapping):
        normalized: list[tuple[str, Any]] = []
        seen_keys: set[str] = set()
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if key in seen_keys:
                raise ValueError(f"Duplicate canonical JSON object key: {key!r}")
            seen_keys.add(key)
            normalized.append((key, _canonicalize(raw_value)))
        return {key: val for key, val in sorted(normalized, key=lambda item: item[0])}
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_canonicalize(item) for item in value]
        return sorted(
            items,
            key=lambda item: json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ),
        )
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite floats cannot be fingerprinted")
        return value
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise TypeError(f"Unsupported value for stable JSON hashing: {type(value).__name__}")


def stable_json_dumps(value: Any) -> str:
    """Return a canonical compact JSON string for hashing and state files."""
    return json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def stable_json_hash(value: Any, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """Hash a value using canonical JSON serialization."""
    digest = hashlib.new(algorithm)
    digest.update(stable_json_dumps(value).encode("utf-8"))
    return digest.hexdigest()


def normalize_host(host: str) -> str:
    """Normalize a host or URL into a lowercase host identity."""
    raw = str(host or "").strip()
    if not raw:
        raise ValueError("host is required")

    if "://" not in raw and "/" not in raw and raw.count(":") > 1 and not raw.startswith("["):
        return raw.lower().rstrip(".")

    candidate = raw if "://" in raw else f"//{raw}"
    try:
        parsed = urlsplit(candidate, allow_fragments=False)
        hostname = parsed.hostname
    except ValueError:
        hostname = None

    if not hostname:
        without_path = raw.split("/", 1)[0].split("@")[-1]
        if without_path.startswith("[") and "]" in without_path:
            hostname = without_path[1:without_path.index("]")]
        elif without_path.count(":") == 1:
            hostname = without_path.rsplit(":", 1)[0]
        else:
            hostname = without_path

    normalized = hostname.strip().strip("[]").lower().rstrip(".")
    if not normalized:
        raise ValueError("host is required")
    return normalized


def normalize_service(service: str | None, port: int | str | None = None) -> str:
    """Normalize service labels while keeping unknown services explicit."""
    if service is not None and str(service).strip():
        return str(service).strip().lower()
    if port is not None and str(port).strip():
        return f"port-{int(port)}"
    return "unknown"


def normalize_protocol(protocol: str | None = "tcp") -> str:
    normalized = str(protocol or "tcp").strip().lower()
    if not normalized:
        raise ValueError("protocol is required")
    return normalized


def normalize_port(port: int | str | None) -> int | None:
    if port is None or str(port).strip() == "":
        return None
    normalized = int(port)
    if normalized < 1 or normalized > 65535:
        raise ValueError(f"port out of range: {port!r}")
    return normalized


def service_key(
    host: str,
    service: str | None = None,
    port: int | str | None = None,
    protocol: str | None = "tcp",
) -> str:
    """Return a stable host/service key for state lookups."""
    norm_port = normalize_port(port)
    return "|".join(
        (
            normalize_host(host),
            normalize_protocol(protocol),
            str(norm_port) if norm_port is not None else "-",
            normalize_service(service, norm_port),
        )
    )


@dataclass(frozen=True)
class ScanFingerprint:
    """Stable fingerprint for one host/service target."""

    key: str
    host: str
    service: str
    port: int | None
    protocol: str
    digest: str
    fingerprint: dict[str, Any] = field(repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "host": self.host,
            "service": self.service,
            "port": self.port,
            "protocol": self.protocol,
            "digest": self.digest,
            "fingerprint": _canonicalize(self.fingerprint),
        }

    def to_record(
        self,
        *,
        scanned_at: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        previous: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        timestamp = scanned_at or _utc_now()
        previous_count = int((previous or {}).get("scan_count", 0) or 0)
        return {
            **self.to_dict(),
            "first_scanned_at": (previous or {}).get("first_scanned_at") or timestamp,
            "last_scanned_at": timestamp,
            "scan_count": previous_count + 1,
            "metadata": _canonicalize(metadata or {}),
        }


def build_scan_fingerprint(
    host: str,
    service: str | None = None,
    *,
    port: int | str | None = None,
    protocol: str | None = "tcp",
    attributes: Mapping[str, Any] | None = None,
) -> ScanFingerprint:
    """Build a deterministic fingerprint from observed passive target facts."""
    norm_host = normalize_host(host)
    norm_port = normalize_port(port)
    norm_protocol = normalize_protocol(protocol)
    norm_service = normalize_service(service, norm_port)
    identity = {
        "host": norm_host,
        "service": norm_service,
        "port": norm_port,
        "protocol": norm_protocol,
    }
    payload = {
        "identity": identity,
        "attributes": _canonicalize(attributes or {}),
    }
    return ScanFingerprint(
        key=service_key(norm_host, norm_service, norm_port, norm_protocol),
        host=norm_host,
        service=norm_service,
        port=norm_port,
        protocol=norm_protocol,
        digest=stable_json_hash(payload),
        fingerprint=payload,
    )


@dataclass(frozen=True)
class RescanDecision:
    """Decision for one candidate host/service fingerprint."""

    fingerprint: ScanFingerprint
    should_rescan: bool
    reason: str
    current_digest: str
    previous_digest: str | None = None

    @property
    def key(self) -> str:
        return self.fingerprint.key

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "should_rescan": self.should_rescan,
            "reason": self.reason,
            "current_digest": self.current_digest,
            "previous_digest": self.previous_digest,
        }


@dataclass(frozen=True)
class RescanPlan:
    """Collection of rescan decisions preserving caller input order."""

    decisions: tuple[RescanDecision, ...]

    @property
    def targets_to_scan(self) -> list[ScanFingerprint]:
        return [decision.fingerprint for decision in self.decisions if decision.should_rescan]

    @property
    def changed_keys(self) -> list[str]:
        return [decision.key for decision in self.decisions if decision.should_rescan]

    @property
    def unchanged_keys(self) -> list[str]:
        return [decision.key for decision in self.decisions if not decision.should_rescan]

    def to_dict(self) -> dict[str, Any]:
        return {
            "targets_to_scan": self.changed_keys,
            "unchanged": self.unchanged_keys,
            "decisions": [decision.to_dict() for decision in self.decisions],
        }


@dataclass(frozen=True)
class RatePolicy:
    """Parameters for deterministic per-service request-rate adaptation."""

    initial_rate: float = 10.0
    min_rate: float = 0.1
    max_rate: float | None = None
    drop_factor: float = 0.5
    timeout_factor: float = 0.5
    rate_limit_factor: float = 0.25
    recovery_factor: float = 1.1
    recovery_successes: int = 3

    def __post_init__(self) -> None:
        max_rate = self.initial_rate if self.max_rate is None else self.max_rate
        if self.initial_rate <= 0:
            raise ValueError("initial_rate must be positive")
        if self.min_rate <= 0:
            raise ValueError("min_rate must be positive")
        if max_rate < self.min_rate:
            raise ValueError("max_rate must be >= min_rate")
        for name in ("drop_factor", "timeout_factor", "rate_limit_factor"):
            value = getattr(self, name)
            if value <= 0 or value >= 1:
                raise ValueError(f"{name} must be greater than 0 and less than 1")
        if self.recovery_factor <= 1:
            raise ValueError("recovery_factor must be greater than 1")
        if self.recovery_successes < 1:
            raise ValueError("recovery_successes must be >= 1")
        object.__setattr__(self, "initial_rate", float(self.initial_rate))
        object.__setattr__(self, "min_rate", float(self.min_rate))
        object.__setattr__(self, "max_rate", float(max_rate))


@dataclass(frozen=True)
class RateAdaptation:
    """Result of applying one passive rate signal."""

    key: str
    signal: RateSignal
    previous_rate: float
    current_rate: float
    action: str
    success_streak: int
    backoff_streak: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "signal": self.signal.value,
            "previous_rate": self.previous_rate,
            "current_rate": self.current_rate,
            "action": self.action,
            "success_streak": self.success_streak,
            "backoff_streak": self.backoff_streak,
        }


def _empty_state() -> dict[str, Any]:
    return {"version": STATE_VERSION, "targets": {}, "rates": {}}


def _round_rate(value: float) -> float:
    return round(float(value), 6)


def _normalize_rate_signal(signal: RateSignal | str) -> RateSignal:
    if isinstance(signal, RateSignal):
        return signal
    normalized = str(signal).strip().lower().replace("-", "_").replace(" ", "_")
    try:
        return _RATE_SIGNAL_ALIASES[normalized]
    except KeyError as exc:
        raise ValueError(f"Unsupported rate signal: {signal!r}") from exc


def _coerce_key(target: ScanFingerprint | Mapping[str, Any] | str) -> str:
    if isinstance(target, ScanFingerprint):
        return target.key
    if isinstance(target, str):
        return target
    if "key" in target:
        return str(target["key"])
    return service_key(
        str(target["host"]),
        str(target.get("service") or "") or None,
        target.get("port"),
        str(target.get("protocol") or "tcp"),
    )


def _load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty_state()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScanFingerprintStateError(f"Invalid scan fingerprint state JSON: {path}") from exc
    if not isinstance(raw, Mapping):
        raise ScanFingerprintStateError("Scan fingerprint state must be a JSON object")
    if int(raw.get("version", 0) or 0) != STATE_VERSION:
        raise ScanFingerprintStateError(
            f"Unsupported scan fingerprint state version: {raw.get('version')!r}"
        )
    state = _empty_state()
    targets = raw.get("targets", {})
    rates = raw.get("rates", {})
    if not isinstance(targets, Mapping) or not isinstance(rates, Mapping):
        raise ScanFingerprintStateError("Scan fingerprint state targets/rates must be objects")
    state["targets"] = _canonicalize(targets)
    state["rates"] = _canonicalize(rates)
    if "updated_at" in raw:
        state["updated_at"] = str(raw["updated_at"])
    return state


def _write_state_atomic(path: Path, state: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = stable_json_dumps(state) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


class ScanFingerprintStore:
    """State store for last-scan fingerprints and adaptive request rates."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._state = _load_state(self.path)

    @property
    def state(self) -> dict[str, Any]:
        return _canonicalize(self._state)

    def save(self) -> None:
        _write_state_atomic(self.path, self._state)

    def get_record(self, target: ScanFingerprint | Mapping[str, Any] | str) -> dict[str, Any] | None:
        key = _coerce_key(target)
        record = self._state["targets"].get(key)
        return _canonicalize(record) if record else None

    def record_scan(
        self,
        fingerprint: ScanFingerprint,
        *,
        scanned_at: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        previous = self._state["targets"].get(fingerprint.key)
        record = fingerprint.to_record(
            scanned_at=scanned_at,
            metadata=metadata,
            previous=previous,
        )
        self._state["targets"][fingerprint.key] = record
        self._state["updated_at"] = record["last_scanned_at"]
        return _canonicalize(record)

    def plan_rescan(self, fingerprints: Iterable[ScanFingerprint]) -> RescanPlan:
        decisions: list[RescanDecision] = []
        for fingerprint in fingerprints:
            previous = self._state["targets"].get(fingerprint.key)
            previous_digest = str(previous.get("digest")) if previous else None
            if previous is None:
                reason = "new"
                should_rescan = True
            elif previous_digest != fingerprint.digest:
                reason = "changed"
                should_rescan = True
            else:
                reason = "unchanged"
                should_rescan = False
            decisions.append(
                RescanDecision(
                    fingerprint=fingerprint,
                    should_rescan=should_rescan,
                    reason=reason,
                    current_digest=fingerprint.digest,
                    previous_digest=previous_digest,
                )
            )
        return RescanPlan(tuple(decisions))

    def rate_state(self, target: ScanFingerprint | Mapping[str, Any] | str) -> dict[str, Any] | None:
        key = _coerce_key(target)
        state = self._state["rates"].get(key)
        return _canonicalize(state) if state else None

    def current_rate(
        self,
        target: ScanFingerprint | Mapping[str, Any] | str,
        *,
        default: float | None = None,
    ) -> float | None:
        state = self.rate_state(target)
        if not state:
            return default
        return float(state["current_rate"])

    def adapt_rate(
        self,
        target: ScanFingerprint | Mapping[str, Any] | str,
        signal: RateSignal | str,
        *,
        policy: RatePolicy | None = None,
        updated_at: str | None = None,
    ) -> RateAdaptation:
        key = _coerce_key(target)
        policy = policy or RatePolicy()
        norm_signal = _normalize_rate_signal(signal)
        existing = self._state["rates"].get(key, {})

        max_rate = float(policy.max_rate or policy.initial_rate)
        base_rate = float(existing.get("base_rate", policy.initial_rate))
        previous_rate = _round_rate(float(existing.get("current_rate", base_rate)))
        previous_rate = min(max(previous_rate, policy.min_rate), max_rate)
        success_streak = int(existing.get("success_streak", 0) or 0)
        backoff_streak = int(existing.get("backoff_streak", 0) or 0)

        current_rate = previous_rate
        action = "hold"
        if norm_signal == RateSignal.SUCCESS:
            backoff_streak = 0
            if previous_rate < max_rate:
                success_streak += 1
                if success_streak >= policy.recovery_successes:
                    current_rate = min(max_rate, previous_rate * policy.recovery_factor)
                    current_rate = _round_rate(current_rate)
                    success_streak = 0
                    action = "recover" if current_rate > previous_rate else "hold"
            else:
                success_streak = 0
        else:
            success_streak = 0
            backoff_streak += 1
            if norm_signal == RateSignal.RATE_LIMIT:
                current_rate = previous_rate * policy.rate_limit_factor
                action = "backoff_rate_limit"
            elif norm_signal == RateSignal.TIMEOUT:
                current_rate = previous_rate * policy.timeout_factor
                action = "backoff_timeout"
            else:
                current_rate = previous_rate * policy.drop_factor
                action = "backoff_connection_drop"
            current_rate = _round_rate(max(policy.min_rate, current_rate))

        current_rate = _round_rate(current_rate)
        rate_state: dict[str, Any] = {
            "base_rate": _round_rate(base_rate),
            "current_rate": current_rate,
            "min_rate": _round_rate(policy.min_rate),
            "max_rate": _round_rate(max_rate),
            "success_streak": success_streak,
            "backoff_streak": backoff_streak,
            "last_signal": norm_signal.value,
            "updated_at": updated_at or _utc_now(),
        }
        self._state["rates"][key] = rate_state
        self._state["updated_at"] = rate_state["updated_at"]
        return RateAdaptation(
            key=key,
            signal=norm_signal,
            previous_rate=previous_rate,
            current_rate=current_rate,
            action=action,
            success_streak=success_streak,
            backoff_streak=backoff_streak,
        )
