"""Canonical, tenant-scoped Forge data contracts.

Task 101 keeps the domain contract independent from engine and dashboard
objects.  The models in this module are deliberately small immutable-ish
dataclasses: they validate the values that cross a process boundary while
``CanonicalStore`` persists only their normalized relationships.  Raw
artifact bytes and durable job/retest behaviour remain owned by later work
packages; this store records references and lineage only.
"""
from __future__ import annotations

import json
import hashlib
import re
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Iterable, Mapping, TypeVar, cast
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import text
from sqlalchemy.orm import Session

from common.evidence_custody import ArtifactManifest
from common.redaction import redact_text, redact_value


CANONICAL_SCHEMA_VERSION = "forge-canonical-v1"
SCHEMA_VERSION = CANONICAL_SCHEMA_VERSION
CURRENT_CONTRACT_VERSION = CANONICAL_SCHEMA_VERSION
MAX_METADATA_BYTES = 16_384
MAX_METADATA_DEPTH = 4
MAX_METADATA_ITEMS = 64
MAX_METADATA_STRING = 1_024

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REFERENCE_RE = re.compile(
    r"^(?:credential|cred|artifact|secret|source):[A-Za-z0-9._:+/\-]{1,240}$"
)
_AUTHORIZATION_REF_RE = re.compile(
    r"^(?:authz|authorization):[A-Za-z0-9._:@/+\-]{1,240}$"
)
_RELATIONSHIP_KEYS = {
    "tenant_id",
    "client_id",
    "project_id",
    "engagement_id",
    "operator_id",
    "role_id",
    "scope_decision_id",
    "job_id",
    "action_id",
    "authorization_decision_id",
    "run_id",
    "execution_id",
    "attempt_id",
    "module_version_id",
    "module_execution_id",
    "intelligence_snapshot_id",
    "feed_snapshot_id",
    "check_pack_snapshot_id",
    "asset_id",
    "source_asset_id",
    "observation_id",
    "source_observation_id",
    "artifact_id",
    "finding_id",
    "retest_id",
    "report_id",
    "export_id",
    "source_id",
    "provenance_id",
    "manifest_id",
    "actor_id",
    "created_by",
    "parent_id",
}


def _is_relationship_metadata_key(key: str) -> bool:
    """Recognize relationship-shaped metadata keys across casing styles."""
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).replace("-", "_").lower()
    # Any ``*_id`` value is structurally relationship-shaped.  Keeping a
    # short explicit set is useful for non-suffixed historical names, but the
    # suffix guard prevents new contracts (attempt_id, execution_id,
    # manifest_id, check_id, etc.) from silently becoming JSON-only links.
    return normalized in _RELATIONSHIP_KEYS or normalized.endswith("_id")
_SECRET_KEYS = re.compile(
    r"(?:password|passwd|pwd|secret|token|cookie|credential|private[_-]?key|"
    r"api[_-]?key|access[_-]?key|passphrase|hash(?:es)?|authorization)",
    re.IGNORECASE,
)


class CanonicalContractError(ValueError):
    """A contract value is malformed or outside its bounded envelope."""


class MissingCanonicalContextError(CanonicalContractError):
    """An adapter attempted to persist a graph without trusted context."""


CanonicalContextError = MissingCanonicalContextError


class CanonicalTenantMismatchError(CanonicalContractError):
    """A graph contains records from more than one tenant."""


class CanonicalLineageError(CanonicalContractError):
    """A required lineage link is absent or inconsistent."""


class CanonicalSerializationError(CanonicalContractError):
    """A contract cannot be represented safely at a process boundary."""


class ScopeOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


class EngagementStatus(str, Enum):
    PLANNED = "planned"
    ACTIVE = "active"
    CLOSED = "closed"
    UNKNOWN = "unknown"


class AssetKind(str, Enum):
    HOST = "host"
    URL = "url"
    SERVICE = "service"
    APPLICATION = "application"
    ACCOUNT = "account"
    DOMAIN_OBJECT = "domain_object"
    CLOUD_RESOURCE = "cloud_resource"
    MODEL_ENDPOINT = "model_endpoint"
    BEACON = "beacon"


class JobStatus(str, Enum):
    PLANNED = "planned"
    PENDING_APPROVAL = "pending_approval"
    QUEUED = "queued"
    RUNNING = "running"
    UNKNOWN_NOT_AUTHORIZED = "unknown_not_authorized"
    FAILED = "failed"
    PARTIAL = "partial"
    COMPLETED = "completed"


class ModuleExecutionStatus(str, Enum):
    PLANNED = "planned"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELED = "canceled"


class ReportStatus(str, Enum):
    DRAFT = "draft"
    FINAL = "final"
    ARCHIVED = "archived"


class ExportStatus(str, Enum):
    CREATED = "created"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELED = "canceled"


class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ObservationStatus(str, Enum):
    OBSERVED = "observed"
    NO_FINDING = "no_finding"
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELED = "canceled"
    NOT_AUTHORIZED = "not_authorized"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(str, Enum):
    OPEN = "open"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    UNKNOWN = "unknown"


class RetestStatus(str, Enum):
    NOT_RUN = "not_run"
    FIXED = "fixed"
    STILL_VULNERABLE = "still_vulnerable"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    NOT_AUTHORIZED = "not_authorized"
    UNSUPPORTED = "unsupported"


class RedactionState(str, Enum):
    REDACTED = "redacted"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class CollectionStatus(str, Enum):
    """Collection truth for one immutable observation."""

    COLLECTED = "collected"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_TESTED = "not_tested"
    CANCELED = "canceled"
    NOT_AUTHORIZED = "not_authorized"
    UNKNOWN = "unknown"


class ArtifactIntegrityState(str, Enum):
    VERIFIED = "sha256_verified"
    UNKNOWN = "unknown"
    FAILED = "failed"


class ProvenanceSourceType(str, Enum):
    """Supported normalized provenance source kinds.

    Keeping this as an enum prevents a free-form ``source_type`` plus ID from
    becoming an unchecked polymorphic relationship at the contract boundary.
    The ``legacy`` value is intentionally limited to the reduced Gate 0
    archive and is not treated as executable evidence.
    """

    INTELLIGENCE_SOURCE = "intelligence_source"
    FEED_SNAPSHOT = "feed_snapshot"
    CHECK_PACK_SNAPSHOT = "check_pack_snapshot"
    LEGACY = "legacy"


class _Contract:
    """Shared validation/serialization behavior for all public contracts."""

    _relationship_fields: ClassVar[frozenset[str]] = frozenset()

    def _validate_common(self) -> None:
        identifier = getattr(self, "id", None)
        if not isinstance(identifier, str) or not _ID_RE.fullmatch(identifier):
            raise CanonicalContractError("id must be a bounded server identifier")
        if _SECRET_KEYS.search(identifier) or re.search(r"(?i)canary", identifier):
            raise CanonicalContractError("id may not contain secret-like material")
        version = getattr(self, "schema_version", None)
        if version != CANONICAL_SCHEMA_VERSION:
            raise CanonicalContractError("unsupported canonical schema version")
        created = getattr(self, "created_at", None)
        if isinstance(created, datetime):
            # Store one canonical representation at the contract boundary;
            # callers may supply an aware offset, but persisted/serialized
            # values are always UTC and never a naive local timestamp.
            object.__setattr__(self, "created_at", ensure_utc(created))
        for name in ("observed_at", "collected_at", "decided_at", "created_at"):
            value = getattr(self, name, None)
            if value is None:
                continue
            if not isinstance(value, datetime):
                raise CanonicalContractError(f"{name} must be a timezone-aware datetime")
            object.__setattr__(self, name, ensure_utc(value))
        metadata = getattr(self, "metadata", None)
        if metadata is not None:
            object.__setattr__(self, "metadata", bounded_metadata(metadata))

    def to_dict(self) -> dict[str, Any]:
        if not is_dataclass(self):
            raise CanonicalSerializationError("contract is not a dataclass")
        result = _serialize_value(asdict(self))
        if not isinstance(result, dict):
            raise CanonicalSerializationError("contract did not serialize to an object")
        # Structural identities are not content and must not be redacted by a
        # broad hash/canary rule in ordinary metadata.
        for name in _structural_keys(result):
            original = getattr(self, name, None)
            if isinstance(original, Enum):
                original = original.value
            if isinstance(original, datetime):
                original = isoformat_utc(original)
            # Optional relationship IDs are structural too: preserve an
            # explicit ``None`` instead of allowing the generic redactor to
            # turn a sensitive-looking field name into ``<redacted>``.
            # Non-null IDs were validated as opaque, secret-free handles by
            # the contract constructor.
            result[name] = original
        # Artifact references are opaque handles, not arbitrary content.  A
        # valid artifact/sha256 handle can safely round-trip through the
        # central redactor even when its suffix is short (the ordinary
        # redaction policy deliberately requires longer credential handles).
        reference = getattr(self, "reference", None)
        # ``redact_value`` intentionally preserves syntactically valid opaque
        # references.  Sanitize those handles once first so a registered
        # canary embedded in an otherwise valid ``*_ref``/artifact reference
        # cannot bypass the secret-safe serialization boundary.
        sanitized = _sanitize_reference_canaries(result)
        redacted = cast(dict[str, Any], _restore_opaque_references(result, redact_value(sanitized)))
        # The generic redactor treats sensitive-looking field names as
        # secret-bearing even when their value is ``None``. Restore the
        # already-validated structural values after redaction so optional
        # relationship IDs remain a faithful round-trip.
        for name in _structural_keys(result):
            redacted[name] = result[name]
        if isinstance(reference, str) and (
            _REFERENCE_RE.fullmatch(reference) or _DIGEST_RE.fullmatch(reference)
        ) and redacted.get("reference") == reference:
            redacted["reference"] = reference
        return redacted

    def serialize(self) -> str:
        return serialize_contract(self)

    @classmethod
    def from_dict(cls: type["_Contract"], value: Mapping[str, Any]) -> "_Contract":
        if not isinstance(value, Mapping):
            raise CanonicalSerializationError("contract payload must be an object")
        payload = dict(value)
        for item in fields(cls):  # type: ignore[arg-type]
            if item.name not in payload:
                continue
            raw = payload[item.name]
            if item.name.endswith("_at") and isinstance(raw, str):
                payload[item.name] = parse_utc(raw)
            if isinstance(raw, str) and item.name in {
                "kind",
                "outcome",
                "status",
                "severity",
                "redaction_state",
                "collection_status",
                "integrity_state",
                "level",
            }:
                enum_type = _enum_type_for_name(item.name)
                if item.name == "status":
                    enum_type = cast(type[Enum] | None, {
                        "Engagement": EngagementStatus,
                        "Job": JobStatus,
                        "ModuleExecution": ModuleExecutionStatus,
                        "Finding": FindingStatus,
                        "Retest": RetestStatus,
                        "Report": ReportStatus,
                        "Export": ExportStatus,
                    }.get(cls.__name__))
                if item.name == "level":
                    enum_type = LogLevel
                if enum_type is not None:
                    payload[item.name] = enum_type(raw)
        return cls(**payload)  # type: ignore[arg-type,call-arg]


def server_id() -> str:
    """Return a new opaque server-generated identifier."""
    return str(uuid.uuid4())


def ensure_utc(value: datetime) -> datetime:
    """Reject naive/ambiguous timestamps and return the UTC instant."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise CanonicalContractError("timestamps must be timezone-aware UTC values")
    # A fold of either 0 or 1 can be valid for an explicitly supplied aware
    # instant.  The important boundary is that it carries a concrete offset;
    # normalizing here removes local/ambiguous representation differences.
    return value.astimezone(timezone.utc)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_utc(value: datetime) -> str:
    return ensure_utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise CanonicalContractError("timestamp must be an ISO-8601 string")
    try:
        return ensure_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (TypeError, ValueError) as exc:
        raise CanonicalContractError("timestamp must be an ISO-8601 string") from exc


def _enum_value(value: Enum | str, enum_type: type[Enum]) -> str:
    try:
        return (value.value if isinstance(value, Enum) else enum_type(value)).value
    except (TypeError, ValueError) as exc:
        raise CanonicalContractError(f"invalid {enum_type.__name__}") from exc


def _identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value.strip()):
        raise CanonicalContractError(f"{field_name} must be a bounded identifier")
    rendered = value.strip()
    # IDs are server-generated opaque handles, never a place to echo
    # caller-controlled credential material.  Legacy migration code derives
    # tenant-bound opaque IDs before constructing contracts, while a direct
    # contract boundary rejects obvious canaries/secret-bearing labels.
    if _SECRET_KEYS.search(rendered) or re.search(r"(?i)canary", rendered):
        raise CanonicalContractError(f"{field_name} may not contain secret-like material")
    return rendered


def _text(value: Any, field_name: str, *, max_length: int = 2_000, required: bool = True) -> str:
    if not isinstance(value, str):
        raise CanonicalContractError(f"{field_name} must be text")
    rendered = redact_text(value.strip())
    if required and not rendered:
        raise CanonicalContractError(f"{field_name} is required")
    if len(rendered) > max_length:
        raise CanonicalContractError(f"{field_name} exceeds its bound")
    return rendered


def _optional_text(value: Any, field_name: str, *, max_length: int = 300) -> str | None:
    if value is None:
        return None
    return _text(value, field_name, max_length=max_length)


def _authorization_ref(value: Any, field_name: str = "authorization_ref") -> str | None:
    """Validate an opaque protected-original authorization handle.

    Authorization references are deliberately narrower than generic IDs.  A
    caller may provide a handle such as ``authorization:review-123`` but not
    a free-form role, token, path, or explanatory text that could be replayed
    or echoed into an audit row.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise CanonicalContractError(f"{field_name} must be an opaque authorization reference")
    # Authorization handles are typed opaque bindings, not request/response
    # text.  Running them through the emergency redactor would turn a valid
    # ``authorization:review-1`` binding into ``authorization:<redacted>`` and
    # make protected-original manifests impossible to reopen.
    rendered = value.strip()
    if not rendered or len(rendered) > 300:
        raise CanonicalContractError(f"{field_name} must be an opaque authorization reference")
    if not _AUTHORIZATION_REF_RE.fullmatch(rendered):
        raise CanonicalContractError(f"{field_name} must be an opaque authorization reference")
    return rendered


def _optional_digest(value: Any, field_name: str, *, allow_unknown: bool = False) -> str | None:
    if value is None:
        if allow_unknown:
            return None
        raise CanonicalContractError(f"{field_name} is required")
    if not isinstance(value, str):
        raise CanonicalContractError(f"{field_name} must be sha256:<hex>")
    rendered = value.strip().lower()
    if not _DIGEST_RE.fullmatch(rendered):
        raise CanonicalContractError(f"{field_name} must be sha256:<hex>")
    return rendered


def _enum_type_for_name(name: str) -> type[Enum] | None:
    return {
        "kind": AssetKind,
        "outcome": ScopeOutcome,
        "status": None,
        "severity": FindingSeverity,
        "redaction_state": RedactionState,
        "collection_status": CollectionStatus,
        "integrity_state": ArtifactIntegrityState,
        "source_type": ProvenanceSourceType,
    }.get(name)


def _serialize_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return isoformat_utc(value)
    if isinstance(value, Mapping):
        return {str(k): _serialize_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_serialize_value(v) for v in value]
    return value


def _structural_keys(value: Mapping[str, Any]) -> set[str]:
    return {
        key
        for key in value
        if key == "id" or key.endswith("_id") or key in {"schema_version", "tenant_id"}
    }


def _restore_opaque_references(original: Any, redacted: Any) -> Any:
    """Keep opaque ``*_ref`` handles while never restoring secret values."""
    if isinstance(original, Mapping) and isinstance(redacted, Mapping):
        output = dict(redacted)
        for key, value in original.items():
            if isinstance(value, str) and str(key).lower().endswith("_ref") and (
                _REFERENCE_RE.fullmatch(value) or _DIGEST_RE.fullmatch(value)
            ) and redacted.get(key) == value:
                # Restore only a clean opaque handle.  A registered canary or
                # redaction-pattern match must remain redacted even if its
                # shape resembles a credential/artifact reference.
                output[str(key)] = value
            elif key in output:
                output[str(key)] = _restore_opaque_references(value, output[key])
        return output
    if isinstance(original, list) and isinstance(redacted, list):
        return [_restore_opaque_references(item, redacted[index]) if index < len(redacted) else item for index, item in enumerate(original)]
    return redacted


def _sanitize_reference_canaries(value: Any) -> Any:
    """Redact canaries before the generic redactor preserves opaque handles."""
    if isinstance(value, Mapping):
        return {
            str(key): (
                redact_text(item)
                if isinstance(item, str)
                and (str(key).lower().endswith("_ref") or str(key).lower() == "reference")
                else _sanitize_reference_canaries(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_reference_canaries(item) for item in value]
    return value


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth > MAX_METADATA_DEPTH:
        raise CanonicalContractError("metadata nesting exceeds its bound")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return redact_text(value)[:MAX_METADATA_STRING]
    if isinstance(value, Mapping):
        if len(value) > MAX_METADATA_ITEMS:
            raise CanonicalContractError("metadata contains too many keys")
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key).strip()
            if not key or len(key) > 64:
                raise CanonicalContractError("metadata key is invalid")
            if _is_relationship_metadata_key(key):
                raise CanonicalContractError(
                    f"metadata cannot carry normalized relationship {key}"
                )
            if _SECRET_KEYS.search(key):
                if key.lower().endswith("_ref") and isinstance(item, str) and (
                    _REFERENCE_RE.fullmatch(item) or _DIGEST_RE.fullmatch(item)
                ):
                    # Opaque references are normally safe handles, but a
                    # registered runtime canary can be embedded in an
                    # otherwise valid-looking handle.  Run the same
                    # redaction boundary used by serialization before the
                    # value is retained in bounded metadata, because this
                    # representation is also written directly to the
                    # canonical metadata_json column.
                    sanitized = redact_text(item)
                    result[key] = sanitized if sanitized != item else item
                else:
                    result[key] = "<redacted>"
            else:
                result[key] = _bounded(item, depth + 1)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        if len(value) > MAX_METADATA_ITEMS:
            raise CanonicalContractError("metadata list exceeds its bound")
        return [_bounded(item, depth + 1) for item in value]
    raise CanonicalContractError(f"unsupported metadata value {type(value).__name__}")


def bounded_metadata(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise CanonicalContractError("metadata must be an object")
    result = cast(dict[str, Any], _bounded(value))
    rendered = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(rendered.encode("utf-8")) > MAX_METADATA_BYTES:
        raise CanonicalContractError("metadata exceeds its byte bound")
    return result


def serialize_contract(contract: _Contract) -> str:
    """Serialize one contract with stable ordering and secret redaction."""
    payload = contract.to_dict()
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


TContract = TypeVar("TContract", bound=_Contract)


@dataclass(frozen=True)
class Tenant(_Contract):
    name: str
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, "name", max_length=300))
        self._validate_common()


@dataclass(frozen=True)
class Client(_Contract):
    tenant_id: str
    name: str
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "name", _text(self.name, "name", max_length=300))
        self._validate_common()


@dataclass(frozen=True)
class Project(_Contract):
    tenant_id: str
    client_id: str
    name: str
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "client_id", _identifier(self.client_id, "client_id"))
        object.__setattr__(self, "name", _text(self.name, "name", max_length=300))
        self._validate_common()


@dataclass(frozen=True)
class Engagement(_Contract):
    tenant_id: str
    name: str
    project_id: str | None = None
    status: EngagementStatus = EngagementStatus.PLANNED
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "name", _text(self.name, "name", max_length=300))
        if self.project_id is not None:
            object.__setattr__(self, "project_id", _identifier(self.project_id, "project_id"))
        object.__setattr__(self, "status", EngagementStatus(self.status))
        self._validate_common()


@dataclass(frozen=True)
class Operator(_Contract):
    tenant_id: str
    display_name: str
    external_ref: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "display_name", _text(self.display_name, "display_name"))
        if self.external_ref is not None:
            object.__setattr__(self, "external_ref", _text(self.external_ref, "external_ref"))
        self._validate_common()


@dataclass(frozen=True)
class Role(_Contract):
    tenant_id: str
    name: str
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "name", _text(self.name, "name", max_length=100))
        self._validate_common()


@dataclass(frozen=True)
class ScopeDecision(_Contract):
    tenant_id: str
    engagement_id: str
    operator_id: str
    outcome: ScopeOutcome
    policy_version: str
    decision_reason: str = ""
    role_id: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    decided_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("tenant_id", "engagement_id", "operator_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(self, "outcome", ScopeOutcome(self.outcome))
        object.__setattr__(self, "policy_version", _text(self.policy_version, "policy_version", max_length=100))
        object.__setattr__(self, "decision_reason", _text(self.decision_reason, "decision_reason", required=False))
        if self.role_id is not None:
            object.__setattr__(self, "role_id", _identifier(self.role_id, "role_id"))
        self._validate_common()


@dataclass(frozen=True)
class Job(_Contract):
    tenant_id: str
    engagement_id: str
    job_kind: str
    status: JobStatus = JobStatus.PLANNED
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("tenant_id", "engagement_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(self, "job_kind", _text(self.job_kind, "job_kind", max_length=100))
        object.__setattr__(self, "status", JobStatus(self.status))
        self._validate_common()


@dataclass(frozen=True)
class Action(_Contract):
    tenant_id: str
    engagement_id: str
    job_id: str
    action_kind: str
    authorization_decision_id: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("tenant_id", "engagement_id", "job_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(self, "action_kind", _text(self.action_kind, "action_kind", max_length=100))
        if self.authorization_decision_id is not None:
            object.__setattr__(self, "authorization_decision_id", _identifier(self.authorization_decision_id, "authorization_decision_id"))
        self._validate_common()


@dataclass(frozen=True)
class IntelligenceSource(_Contract):
    tenant_id: str
    name: str
    source_kind: str
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "name", _text(self.name, "name", max_length=300))
        object.__setattr__(self, "source_kind", _text(self.source_kind, "source_kind", max_length=100))
        self._validate_common()


@dataclass(frozen=True)
class Provenance(_Contract):
    tenant_id: str
    source_type: ProvenanceSourceType
    source_id: str
    digest: str
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "source_type", ProvenanceSourceType(self.source_type))
        object.__setattr__(self, "source_id", _identifier(self.source_id, "source_id"))
        if not _DIGEST_RE.fullmatch(self.digest):
            raise CanonicalContractError("provenance digest must be sha256:<hex>")
        self._validate_common()


@dataclass(frozen=True)
class FeedSnapshot(_Contract):
    tenant_id: str
    source_id: str
    version: str
    digest: str
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("tenant_id", "source_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(self, "version", _text(self.version, "version", max_length=100))
        if not _DIGEST_RE.fullmatch(self.digest):
            raise CanonicalContractError("feed snapshot digest must be sha256:<hex>")
        self._validate_common()


@dataclass(frozen=True)
class CheckPackSnapshot(FeedSnapshot):
    """Executable check-pack snapshot; separate type keeps provenance explicit."""


@dataclass(frozen=True)
class ModuleVersion(_Contract):
    tenant_id: str
    module_id: str
    version: str
    module_kind: str = "check"
    manifest_digest: str | None = None
    policy_version: str | None = None
    intelligence_snapshot_id: str | None = None
    check_pack_snapshot_id: str | None = None
    provenance_id: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "module_id", _text(self.module_id, "module_id", max_length=200))
        object.__setattr__(self, "version", _text(self.version, "version", max_length=100))
        object.__setattr__(self, "module_kind", _text(self.module_kind, "module_kind", max_length=40))
        for name in ("intelligence_snapshot_id", "check_pack_snapshot_id", "provenance_id"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _identifier(value, name))
        if self.manifest_digest is not None and not _DIGEST_RE.fullmatch(self.manifest_digest):
            raise CanonicalContractError("manifest_digest must be sha256:<hex>")
        if self.policy_version is not None:
            object.__setattr__(self, "policy_version", _text(self.policy_version, "policy_version", max_length=100))
        self._validate_common()


@dataclass(frozen=True)
class ModuleExecution(_Contract):
    tenant_id: str
    job_id: str
    module_version_id: str
    status: ModuleExecutionStatus = ModuleExecutionStatus.PLANNED
    intelligence_snapshot_id: str | None = None
    check_pack_snapshot_id: str | None = None
    provenance_id: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("tenant_id", "job_id", "module_version_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(self, "status", ModuleExecutionStatus(self.status))
        for name in ("intelligence_snapshot_id", "check_pack_snapshot_id", "provenance_id"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _identifier(value, name))
        self._validate_common()


def normalize_asset_identity(kind: AssetKind | str, identity_key: str) -> tuple[AssetKind, str]:
    """Normalize identity keys without conflating display labels."""
    try:
        asset_kind = kind if isinstance(kind, AssetKind) else AssetKind(kind)
    except (TypeError, ValueError) as exc:
        raise CanonicalContractError("unsupported asset kind") from exc
    key = _text(identity_key, "identity_key", max_length=1_000)
    if asset_kind is AssetKind.URL:
        parsed = urlsplit(key)
        if not parsed.scheme or not parsed.netloc:
            raise CanonicalContractError("URL asset identity must include scheme and host")
        host = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError as exc:
            raise CanonicalContractError("URL asset port is invalid") from exc
        netloc = host.lower()
        if parsed.username or parsed.password:
            raise CanonicalContractError("URL identity may not contain credentials")
        if port is not None:
            netloc += f":{port}"
        key = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
    elif asset_kind in {AssetKind.HOST, AssetKind.SERVICE, AssetKind.CLOUD_RESOURCE, AssetKind.MODEL_ENDPOINT}:
        key = key.lower()
    return asset_kind, key


@dataclass(frozen=True)
class Asset(_Contract):
    tenant_id: str
    kind: AssetKind
    identity_key: str
    display_name: str
    canonical_uri: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        normalized_kind, normalized_key = normalize_asset_identity(self.kind, self.identity_key)
        object.__setattr__(self, "kind", normalized_kind)
        object.__setattr__(self, "identity_key", normalized_key)
        object.__setattr__(self, "display_name", _text(self.display_name, "display_name"))
        if self.canonical_uri is not None:
            object.__setattr__(self, "canonical_uri", _text(self.canonical_uri, "canonical_uri", max_length=2_000))
        self._validate_common()


@dataclass(frozen=True)
class Observation(_Contract):
    tenant_id: str
    engagement_id: str
    job_id: str
    module_version_id: str
    asset_id: str
    status: ObservationStatus = ObservationStatus.OBSERVED
    module_execution_id: str | None = None
    action_id: str | None = None
    intelligence_snapshot_id: str | None = None
    provenance_id: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    observed_at: datetime = field(default_factory=utc_now)
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    proof_type: str = "unknown"
    collection_status: CollectionStatus = CollectionStatus.UNKNOWN
    check_id: str | None = None
    route: str | None = None
    parameter: str | None = None
    location: str | None = None
    identity_ref: str | None = None

    def __post_init__(self) -> None:
        for name in ("tenant_id", "engagement_id", "job_id", "module_version_id", "asset_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(self, "status", ObservationStatus(self.status))
        for name in ("module_execution_id", "action_id", "intelligence_snapshot_id", "provenance_id"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _identifier(value, name))
        object.__setattr__(self, "proof_type", _text(self.proof_type, "proof_type", max_length=100))
        object.__setattr__(self, "collection_status", CollectionStatus(self.collection_status))
        for name in ("check_id", "route", "parameter", "location", "identity_ref"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _text(value, name, max_length=1_000))
        self._validate_common()


@dataclass(frozen=True)
class ArtifactReference(_Contract):
    tenant_id: str
    observation_id: str
    reference: str
    digest: str | None
    media_type: str
    size: int
    redaction_state: RedactionState = RedactionState.REDACTED
    encryption_state: str = "reference_only"
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    collected_at: datetime = field(default_factory=utc_now)
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    collector_id: str = "unknown"
    collector_version: str = "unknown"
    source_target: str = "unknown"
    source_asset_id: str | None = None
    redaction_version: str = "unknown"
    protection_state: str = "reference_only"
    signer_state: str = "unsigned"
    integrity_state: ArtifactIntegrityState = ArtifactIntegrityState.VERIFIED
    retention_class: str = "default"
    retention_expires_at: datetime | None = None
    protected_original_authorization_ref: str | None = None
    derivative_reference: str | None = None
    manifest_digest: str | None = None

    def __post_init__(self) -> None:
        for name in ("tenant_id", "observation_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        reference = _text(self.reference, "reference", max_length=2_000)
        if not (_REFERENCE_RE.fullmatch(reference) or _DIGEST_RE.fullmatch(reference)):
            raise CanonicalContractError("artifact reference must be an opaque handle")
        object.__setattr__(self, "reference", reference)
        if self.digest is not None:
            object.__setattr__(self, "digest", self.digest.strip().lower())
        if self.digest is None:
            if self.integrity_state not in {ArtifactIntegrityState.UNKNOWN, "unknown"}:
                raise CanonicalContractError("artifact digest is required when integrity is verified")
        elif not _DIGEST_RE.fullmatch(self.digest):
            raise CanonicalContractError("artifact digest must be sha256:<hex>")
        object.__setattr__(self, "media_type", _text(self.media_type, "media_type", max_length=200))
        if not isinstance(self.size, int) or self.size < 0 or self.size > 2**63 - 1:
            raise CanonicalContractError("artifact size is invalid")
        object.__setattr__(self, "redaction_state", RedactionState(self.redaction_state))
        object.__setattr__(self, "encryption_state", _text(self.encryption_state, "encryption_state", max_length=40))
        for name in ("collector_id", "collector_version", "source_target", "redaction_version", "protection_state", "signer_state", "retention_class"):
            object.__setattr__(self, name, _text(getattr(self, name), name, max_length=300))
        integrity_value = self.integrity_state.value if isinstance(self.integrity_state, ArtifactIntegrityState) else str(self.integrity_state)
        # The filesystem custody manifest uses the human-readable
        # ``verified`` state; canonical artifact references retain the more
        # explicit wire value.  Accept the former at this adapter boundary so
        # callers cannot accidentally downgrade a verified artifact to
        # ``unknown`` merely while translating the manifest.
        if integrity_value == "verified":
            integrity_value = ArtifactIntegrityState.VERIFIED.value
        object.__setattr__(self, "integrity_state", ArtifactIntegrityState(integrity_value))
        for name in ("source_asset_id",):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _identifier(value, name))
        if self.retention_expires_at is not None:
            object.__setattr__(self, "retention_expires_at", ensure_utc(self.retention_expires_at))
        if self.protected_original_authorization_ref is not None:
            object.__setattr__(
                self,
                "protected_original_authorization_ref",
                _authorization_ref(
                    self.protected_original_authorization_ref,
                    "protected_original_authorization_ref",
                ),
            )
        if self.derivative_reference is not None:
            ref = _text(self.derivative_reference, "derivative_reference", max_length=2_000).lower()
            if not (_REFERENCE_RE.fullmatch(ref) or _DIGEST_RE.fullmatch(ref)):
                raise CanonicalContractError("derivative reference must be an opaque handle")
            object.__setattr__(self, "derivative_reference", ref)
        if self.manifest_digest is not None:
            object.__setattr__(self, "manifest_digest", _optional_digest(self.manifest_digest, "manifest_digest"))
        self._validate_common()


@dataclass(frozen=True)
class Finding(_Contract):
    tenant_id: str
    observation_id: str
    artifact_id: str
    title: str
    severity: FindingSeverity
    description: str
    status: FindingStatus = FindingStatus.OPEN
    finding_key: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    dedup_key: str | None = None

    def __post_init__(self) -> None:
        for name in ("tenant_id", "observation_id", "artifact_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(self, "title", _text(self.title, "title", max_length=500))
        object.__setattr__(self, "severity", FindingSeverity(self.severity))
        object.__setattr__(self, "description", _text(self.description, "description", max_length=8_000))
        object.__setattr__(self, "status", FindingStatus(self.status))
        if self.finding_key is not None:
            object.__setattr__(self, "finding_key", _text(self.finding_key, "finding_key", max_length=300))
        if self.dedup_key is not None:
            dedup = _text(self.dedup_key, "dedup_key", max_length=300)
            if not re.fullmatch(r"finding-v[0-9]+:[0-9a-f]{64}", dedup):
                raise CanonicalContractError("dedup_key must be finding-vN:<64 lowercase hex>")
            object.__setattr__(self, "dedup_key", dedup)
        self._validate_common()


@dataclass(frozen=True)
class Retest(_Contract):
    tenant_id: str
    finding_id: str
    source_observation_id: str
    status: RetestStatus = RetestStatus.NOT_RUN
    job_id: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("tenant_id", "finding_id", "source_observation_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        if self.job_id is not None:
            object.__setattr__(self, "job_id", _identifier(self.job_id, "job_id"))
        object.__setattr__(self, "status", RetestStatus(self.status))
        self._validate_common()


@dataclass(frozen=True)
class Report(_Contract):
    tenant_id: str
    name: str
    version: int = 1
    status: ReportStatus = ReportStatus.DRAFT
    created_by: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "name", _text(self.name, "name", max_length=300))
        if not isinstance(self.version, int) or self.version < 1:
            raise CanonicalContractError("report version must be positive")
        object.__setattr__(self, "status", ReportStatus(self.status))
        if self.created_by is not None:
            object.__setattr__(self, "created_by", _identifier(self.created_by, "created_by"))
        self._validate_common()


@dataclass(frozen=True)
class ReportMembership(_Contract):
    tenant_id: str
    report_id: str
    finding_id: str
    observation_id: str
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("tenant_id", "report_id", "finding_id", "observation_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        self._validate_common()


@dataclass(frozen=True)
class Export(_Contract):
    tenant_id: str
    finding_id: str
    source_observation_id: str
    format: str
    status: ExportStatus = ExportStatus.CREATED
    report_id: str | None = None
    provenance_id: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("tenant_id", "finding_id", "source_observation_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        for name in ("report_id", "provenance_id"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _identifier(value, name))
        object.__setattr__(self, "format", _text(self.format, "format", max_length=60))
        object.__setattr__(self, "status", ExportStatus(self.status))
        self._validate_common()


@dataclass(frozen=True)
class Event(_Contract):
    tenant_id: str
    job_id: str
    event_type: str
    level: LogLevel = LogLevel.INFO
    actor_id: str | None = None
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "job_id", _identifier(self.job_id, "job_id"))
        object.__setattr__(self, "event_type", _text(self.event_type, "event_type", max_length=160))
        object.__setattr__(self, "level", LogLevel(self.level))
        if self.actor_id is not None:
            object.__setattr__(self, "actor_id", _identifier(self.actor_id, "actor_id"))
        self._validate_common()


@dataclass(frozen=True)
class Log(_Contract):
    tenant_id: str
    job_id: str
    message: str
    level: LogLevel = LogLevel.INFO
    id: str = field(default_factory=server_id)
    schema_version: str = CANONICAL_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "job_id", _identifier(self.job_id, "job_id"))
        object.__setattr__(self, "message", _text(self.message, "message", max_length=8_000))
        object.__setattr__(self, "level", LogLevel(self.level))
        self._validate_common()


_TABLE_TYPES: dict[type[_Contract], str] = {
    Tenant: "canonical_tenants",
    Client: "canonical_clients",
    Project: "canonical_projects",
    Engagement: "canonical_engagements",
    Operator: "canonical_operators",
    Role: "canonical_roles",
    ScopeDecision: "canonical_scope_decisions",
    Job: "canonical_jobs",
    Action: "canonical_actions",
    IntelligenceSource: "canonical_intelligence_sources",
    Provenance: "canonical_provenance",
    FeedSnapshot: "canonical_feed_snapshots",
    CheckPackSnapshot: "canonical_check_pack_snapshots",
    ModuleVersion: "canonical_module_versions",
    ModuleExecution: "canonical_module_executions",
    Asset: "canonical_assets",
    Observation: "canonical_observations",
    ArtifactReference: "canonical_artifact_refs",
    Finding: "canonical_findings",
    Retest: "canonical_retests",
    Report: "canonical_reports",
    ReportMembership: "canonical_report_memberships",
    Export: "canonical_exports",
    Event: "canonical_events",
    Log: "canonical_logs",
}


def _metadata_json(value: Mapping[str, Any]) -> str:
    return json.dumps(bounded_metadata(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _iso(value: datetime) -> str:
    return isoformat_utc(value)


def finding_identity_key(
    *,
    tenant_id: str,
    module_version_id: str,
    asset_id: str,
    finding_key: str | None = None,
    title: str = "",
    route: str | None = None,
    parameter: str | None = None,
    location: str | None = None,
    identity_ref: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> str:
    """Return the versioned, explainable identity used for finding grouping.

    Run/job/observation IDs are intentionally excluded: repeated executions
    append source observations to the same mutable workflow summary while all
    proof remains attached to the immutable source rows.  Tenant, check/module,
    asset, and family-specific route/parameter/location/identity dimensions are
    mandatory parts of the key so title/host-only collisions cannot merge
    unrelated findings.
    """
    tenant = _identifier(tenant_id, "tenant_id")
    module = _identifier(module_version_id, "module_version_id")
    asset = _identifier(asset_id, "asset_id")
    metadata_map = dict(metadata or {})
    def _dimension(name: str, explicit: str | None) -> str:
        value = explicit if explicit is not None else metadata_map.get(name)
        return str(value or "").strip()
    material = {
        "version": "finding-v1",
        "tenant_id": tenant,
        "module_version_id": module,
        "asset_id": asset,
        "check_identity": str(finding_key or metadata_map.get("check_id") or title or "").strip().lower(),
        "route": _dimension("route", route),
        "path": _dimension("path", None),
        "parameter": _dimension("parameter", parameter),
        "location": _dimension("location", location),
        "identity_ref": _dimension("identity_ref", identity_ref),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "finding-v1:" + hashlib.sha256(canonical).hexdigest()


class CanonicalStore:
    """Transactional repository for the normalized canonical graph."""

    def __init__(self, session: Session):
        self.session = session

    @contextmanager
    def _atomic(self):
        if self.session.in_transaction():
            with self.session.begin_nested():
                yield
        else:
            with self.session.begin():
                yield

    @staticmethod
    def _tenant_of(record: _Contract) -> str | None:
        if isinstance(record, Tenant):
            return record.id
        return cast(str | None, getattr(record, "tenant_id", None))

    def _assert_same_tenant(self, records: Iterable[_Contract]) -> str:
        tenant_ids = {self._tenant_of(record) for record in records if self._tenant_of(record)}
        if len(tenant_ids) != 1:
            raise CanonicalTenantMismatchError("canonical graph records must share one tenant")
        tenant_id = next(iter(tenant_ids))
        if tenant_id is None:
            raise CanonicalTenantMismatchError("canonical graph records require a tenant")
        return tenant_id

    def _insert(self, record: _Contract, *, ignore: bool = False) -> None:
        table = _TABLE_TYPES.get(type(record))
        if table is None:
            raise CanonicalContractError(f"unsupported canonical record {type(record).__name__}")
        params = self._record_params(record)
        columns = ", ".join(params)
        placeholders = ", ".join(f":{name}" for name in params)
        prefix = "INSERT OR IGNORE" if ignore else "INSERT"
        self.session.execute(
            text(f"{prefix} INTO {table} ({columns}) VALUES ({placeholders})"),
            params,
        )

    def _insert_or_validate_existing(self, record: _Contract) -> None:
        """Insert a graph node, reusing an identical already-persisted node.

        Adapters commonly resolve the tenant/engagement/job/module/asset
        context before emitting a new observation.  Re-inserting those
        context rows would otherwise fail on their stable primary keys.  We
        allow exact identity reuse while still rejecting an ID that is bound
        to another tenant or carries conflicting relationship/identity data.
        ``insert()`` remains strict for callers that explicitly request one
        row insertion.
        """
        table = _TABLE_TYPES.get(type(record))
        if table is None:
            raise CanonicalContractError(f"unsupported canonical record {type(record).__name__}")
        existing = self.session.execute(
            text(f"SELECT * FROM {table} WHERE id=:id"), {"id": cast(str, getattr(record, "id"))}
        ).mappings().first()
        if existing is None:
            self._insert(record)
            return
        expected = self._record_params(record)
        # A stable ID is an identity assertion, not an upsert instruction.
        # Every persisted field represented by the contract must match before
        # a context node can be reused.  This catches altered names, statuses,
        # schema versions, timestamps, metadata, and optional provenance links
        # instead of allowing a caller to smuggle a second object under an
        # existing server ID.
        # Creation timestamps are generated by the server and are not the
        # identity of an already persisted context row.  Compare all other
        # contract fields exactly; an altered timestamp alone should not turn
        # a context re-use into a false lineage conflict.
        for name, value in expected.items():
            if name == "created_at":
                continue
            if existing.get(name) != value:
                raise CanonicalLineageError(
                    f"existing {table} record {cast(str, getattr(record, 'id'))} conflicts on {name}"
                )

    def _record_params(self, record: _Contract) -> dict[str, Any]:
        base = {
            "id": cast(str, getattr(record, "id")),
            "schema_version": cast(str, getattr(record, "schema_version")),
            "created_at": _iso(getattr(record, "created_at", utc_now())),
            "metadata_json": _metadata_json(getattr(record, "metadata", {})),
            "tenant_id": self._tenant_of(record),
        }
        if isinstance(record, Tenant):
            return {"id": record.id, "schema_version": record.schema_version, "name": record.name, "created_at": _iso(record.created_at), "metadata_json": _metadata_json(record.metadata)}
        if isinstance(record, Client):
            return base | {"name": record.name}
        if isinstance(record, Project):
            return base | {"client_id": record.client_id, "name": record.name}
        if isinstance(record, Engagement):
            return base | {"project_id": record.project_id, "name": record.name, "status": record.status.value}
        if isinstance(record, Operator):
            return base | {"display_name": record.display_name, "external_ref": record.external_ref}
        if isinstance(record, Role):
            return base | {"name": record.name}
        if isinstance(record, ScopeDecision):
            return base | {"engagement_id": record.engagement_id, "operator_id": record.operator_id, "role_id": record.role_id, "outcome": record.outcome.value, "policy_version": record.policy_version, "decision_reason": record.decision_reason, "decided_at": _iso(record.decided_at)}
        if isinstance(record, Job):
            return base | {"engagement_id": record.engagement_id, "job_kind": record.job_kind, "status": record.status.value}
        if isinstance(record, Action):
            return base | {"engagement_id": record.engagement_id, "job_id": record.job_id, "action_kind": record.action_kind, "authorization_decision_id": record.authorization_decision_id}
        if isinstance(record, IntelligenceSource):
            return base | {"name": record.name, "source_kind": record.source_kind}
        if isinstance(record, Provenance):
            return base | {"source_type": record.source_type.value, "source_id": record.source_id, "digest": record.digest}
        if isinstance(record, (FeedSnapshot, CheckPackSnapshot)):
            return base | {"source_id": record.source_id, "version": record.version, "digest": record.digest}
        if isinstance(record, ModuleVersion):
            return base | {"module_id": record.module_id, "version": record.version, "module_kind": record.module_kind, "manifest_digest": record.manifest_digest, "policy_version": record.policy_version, "intelligence_snapshot_id": record.intelligence_snapshot_id, "check_pack_snapshot_id": record.check_pack_snapshot_id, "provenance_id": record.provenance_id}
        if isinstance(record, ModuleExecution):
            return base | {"job_id": record.job_id, "module_version_id": record.module_version_id, "status": record.status.value, "intelligence_snapshot_id": record.intelligence_snapshot_id, "check_pack_snapshot_id": record.check_pack_snapshot_id, "provenance_id": record.provenance_id}
        if isinstance(record, Asset):
            return base | {"kind": record.kind.value, "identity_key": record.identity_key, "display_name": record.display_name, "canonical_uri": record.canonical_uri}
        if isinstance(record, Observation):
            return base | {"engagement_id": record.engagement_id, "job_id": record.job_id, "module_version_id": record.module_version_id, "module_execution_id": record.module_execution_id, "asset_id": record.asset_id, "action_id": record.action_id, "intelligence_snapshot_id": record.intelligence_snapshot_id, "provenance_id": record.provenance_id, "status": record.status.value, "observed_at": _iso(record.observed_at), "proof_type": record.proof_type, "collection_status": record.collection_status.value, "check_id": record.check_id, "route": record.route, "parameter": record.parameter, "location": record.location, "identity_ref": record.identity_ref}
        if isinstance(record, ArtifactReference):
            return base | {"observation_id": record.observation_id, "reference": record.reference, "digest": record.digest, "media_type": record.media_type, "size": record.size, "redaction_state": record.redaction_state.value, "encryption_state": record.encryption_state, "collected_at": _iso(record.collected_at), "collector_id": record.collector_id, "collector_version": record.collector_version, "source_target": record.source_target, "source_asset_id": record.source_asset_id, "redaction_version": record.redaction_version, "protection_state": record.protection_state, "signer_state": record.signer_state, "integrity_state": record.integrity_state.value, "retention_class": record.retention_class, "retention_expires_at": _iso(record.retention_expires_at) if record.retention_expires_at else None, "protected_original_authorization_ref": record.protected_original_authorization_ref, "derivative_reference": record.derivative_reference, "manifest_digest": record.manifest_digest}
        if isinstance(record, Finding):
            return base | {"observation_id": record.observation_id, "artifact_id": record.artifact_id, "title": record.title, "severity": record.severity.value, "description": record.description, "status": record.status.value, "finding_key": record.finding_key, "dedup_key": record.dedup_key}
        if isinstance(record, Retest):
            return base | {"finding_id": record.finding_id, "source_observation_id": record.source_observation_id, "job_id": record.job_id, "status": record.status.value}
        if isinstance(record, Report):
            return base | {"name": record.name, "version": record.version, "status": record.status.value, "created_by": record.created_by}
        if isinstance(record, ReportMembership):
            return base | {"report_id": record.report_id, "finding_id": record.finding_id, "observation_id": record.observation_id}
        if isinstance(record, Export):
            return base | {"finding_id": record.finding_id, "source_observation_id": record.source_observation_id, "format": record.format, "status": record.status.value, "report_id": record.report_id, "provenance_id": record.provenance_id}
        if isinstance(record, Event):
            return base | {"job_id": record.job_id, "event_type": record.event_type, "level": record.level.value, "actor_id": record.actor_id}
        if isinstance(record, Log):
            return base | {"job_id": record.job_id, "message": record.message, "level": record.level.value}
        raise CanonicalContractError(f"unsupported canonical record {type(record).__name__}")

    def insert(self, record: _Contract) -> _Contract:
        """Insert one validated record and commit only this operation."""
        with self._atomic():
            self._insert(record)
        return record

    def ensure_tenant(self, tenant_id: str, *, name: str | None = None) -> Tenant:
        tenant_id = _identifier(tenant_id, "tenant_id")
        with self._atomic():
            row = self.session.execute(text("SELECT id, schema_version, name, created_at, metadata_json FROM canonical_tenants WHERE id=:id"), {"id": tenant_id}).mappings().first()
            if row is not None:
                return Tenant(id=str(row["id"]), name=str(row["name"]), schema_version=str(row["schema_version"]), created_at=parse_utc(str(row["created_at"])), metadata=json.loads(str(row["metadata_json"])))
            tenant = Tenant(id=tenant_id, name=name or tenant_id)
            self._insert(tenant)
            return tenant

    def get_or_create_asset(
        self,
        *,
        tenant_id: str,
        kind: AssetKind | str,
        identity_key: str,
        display_name: str | None = None,
        canonical_uri: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Asset:
        tenant_id = _identifier(tenant_id, "tenant_id")
        asset_kind, normalized_key = normalize_asset_identity(kind, identity_key)
        with self._atomic():
            row = self.session.execute(
                text("SELECT * FROM canonical_assets WHERE tenant_id=:tenant_id AND kind=:kind AND identity_key=:identity_key"),
                {"tenant_id": tenant_id, "kind": asset_kind.value, "identity_key": normalized_key},
            ).mappings().first()
            if row is not None:
                return _asset_from_row(cast(Mapping[str, Any], row))
            asset = Asset(tenant_id=tenant_id, kind=asset_kind, identity_key=normalized_key, display_name=display_name or normalized_key, canonical_uri=canonical_uri, metadata=metadata or {})
            self._insert(asset)
            return asset

    def create_lineage(
        self,
        *,
        tenant: Tenant,
        client: Client | None = None,
        project: Project | None = None,
        engagement: Engagement,
        job: Job,
        module_version: ModuleVersion,
        asset: Asset,
        observation: Observation,
        artifact: ArtifactReference,
        finding: Finding,
        module_execution: ModuleExecution | None = None,
        action: Action | None = None,
        intelligence_source: IntelligenceSource | None = None,
        provenance: Provenance | None = None,
        feed_snapshot: FeedSnapshot | None = None,
        check_pack_snapshot: CheckPackSnapshot | None = None,
        retest: Retest | None = None,
        report: Report | None = None,
        report_membership: ReportMembership | None = None,
        export: Export | None = None,
    ) -> dict[str, _Contract]:
        records: list[_Contract] = [tenant, engagement, job, module_version, asset, observation, artifact, finding]
        records.extend(record for record in (client, project) if record is not None)
        records.extend(record for record in (module_execution, action, intelligence_source, provenance, feed_snapshot, check_pack_snapshot, retest, report, report_membership, export) if record is not None)
        tenant_id = self._assert_same_tenant(records)
        if project is not None and client is not None and project.client_id != client.id:
            raise CanonicalLineageError("project client link is inconsistent")
        if engagement.project_id is not None and project is not None and engagement.project_id != project.id:
            raise CanonicalLineageError("engagement project link is inconsistent")
        expected_links = {
            "observation tenant": (observation.tenant_id, tenant_id),
            "observation engagement": (observation.engagement_id, engagement.id),
            "observation job": (observation.job_id, job.id),
            "observation module version": (observation.module_version_id, module_version.id),
            "observation asset": (observation.asset_id, asset.id),
            "job engagement": (job.engagement_id, engagement.id),
            "finding observation": (finding.observation_id, observation.id),
            "finding artifact": (finding.artifact_id, artifact.id),
            "artifact observation": (artifact.observation_id, observation.id),
        }
        for label, (actual, expected) in expected_links.items():
            if actual != expected:
                raise CanonicalLineageError(f"{label} link is inconsistent")
        # The workflow summary identity intentionally excludes this run's
        # observation/job IDs.  Populate it once at the canonical boundary so
        # every downstream reader has the same explainable grouping key.
        dedup_key = finding.dedup_key or finding_identity_key(
            tenant_id=tenant_id,
            module_version_id=module_version.id,
            asset_id=asset.id,
            finding_key=finding.finding_key,
            title=finding.title,
            route=observation.route,
            parameter=observation.parameter,
            location=observation.location,
            identity_ref=observation.identity_ref,
            metadata=finding.metadata,
        )
        object.__setattr__(finding, "dedup_key", dedup_key)
        if module_execution is not None:
            if observation.module_execution_id != module_execution.id:
                raise CanonicalLineageError("observation module execution link is inconsistent")
            if module_execution.job_id != job.id or module_execution.module_version_id != module_version.id:
                raise CanonicalLineageError("module execution lineage is inconsistent")
        elif observation.module_execution_id is not None:
            raise CanonicalLineageError("observation references an unprovided module execution")
        if action is not None:
            if observation.action_id != action.id:
                raise CanonicalLineageError("observation action link is inconsistent")
            if action.engagement_id != engagement.id or action.job_id != job.id:
                raise CanonicalLineageError("action lineage is inconsistent")
        elif observation.action_id is not None:
            raise CanonicalLineageError("observation references an unprovided action")
        if retest is not None and (retest.finding_id != finding.id or retest.source_observation_id != observation.id):
            raise CanonicalLineageError("retest finding/source observation link is inconsistent")
        if retest is not None and retest.job_id is not None and retest.job_id != job.id:
            raise CanonicalLineageError("retest job link is inconsistent")
        if report_membership is not None and report is None:
            raise CanonicalLineageError("report membership requires its report context")
        if report_membership is not None and (report_membership.finding_id != finding.id or report_membership.observation_id != observation.id):
            raise CanonicalLineageError("report membership finding/observation link is inconsistent")
        if report_membership is not None and report_membership.report_id != cast(Report, report).id:
            raise CanonicalLineageError("report membership report link is inconsistent")
        if export is not None and (export.finding_id != finding.id or export.source_observation_id != observation.id):
            raise CanonicalLineageError("export finding/source observation link is inconsistent")
        if export is not None and export.report_id is not None:
            if report is None or export.report_id != report.id:
                raise CanonicalLineageError("export report link is inconsistent")
        if export is not None and export.provenance_id is not None:
            if provenance is None or export.provenance_id != provenance.id:
                raise CanonicalLineageError("export provenance link is inconsistent")
        if module_version.intelligence_snapshot_id is not None:
            if feed_snapshot is None or module_version.intelligence_snapshot_id != feed_snapshot.id:
                raise CanonicalLineageError("module intelligence snapshot link is inconsistent")
        if module_version.check_pack_snapshot_id is not None:
            if check_pack_snapshot is None or module_version.check_pack_snapshot_id != check_pack_snapshot.id:
                raise CanonicalLineageError("module check-pack snapshot link is inconsistent")
        if module_version.provenance_id is not None:
            if provenance is None or module_version.provenance_id != provenance.id:
                raise CanonicalLineageError("module provenance link is inconsistent")
        if module_execution is not None:
            if module_execution.intelligence_snapshot_id is not None and (
                feed_snapshot is None or module_execution.intelligence_snapshot_id != feed_snapshot.id
            ):
                raise CanonicalLineageError("module execution intelligence snapshot link is inconsistent")
            if module_execution.check_pack_snapshot_id is not None and (
                check_pack_snapshot is None or module_execution.check_pack_snapshot_id != check_pack_snapshot.id
            ):
                raise CanonicalLineageError("module execution check-pack snapshot link is inconsistent")
            if module_execution.provenance_id is not None and (
                provenance is None or module_execution.provenance_id != provenance.id
            ):
                raise CanonicalLineageError("module execution provenance link is inconsistent")
        with self._atomic():
            # Context rows may already exist when an adapter emits an
            # observation.  Reuse them only after checking tenant and
            # relationship identity; new observation/artifact/finding and
            # downstream records remain strict inserts so seeded constraint
            # failures roll back the complete write.
            for record in (tenant, client, project, engagement, job,
                           action, intelligence_source, feed_snapshot,
                           check_pack_snapshot, provenance, module_version,
                           module_execution, asset, report):
                if record is not None:
                    self._insert_or_validate_existing(record)
            # Observations and artifacts are the immutable source records.  A
            # finding summary is resolved/created before inserting any
            # downstream retest/report/export rows because those rows carry a
            # foreign key to the finding identity.
            for source_record in (observation, artifact):
                if source_record is not None:
                    self._insert(source_record)
            existing_finding = self.session.execute(
                text("SELECT id FROM canonical_findings WHERE tenant_id=:tenant_id AND dedup_key=:dedup_key ORDER BY created_at, id LIMIT 1"),
                {"tenant_id": tenant_id, "dedup_key": dedup_key},
            ).scalar_one_or_none()
            if existing_finding is None:
                self._insert(finding)
                existing_finding = finding.id
            else:
                # Findings are mutable workflow summaries.  Updating their
                # presentation/status is allowed, but the original source
                # observation and artifact remain untouched in their own
                # append-only rows.
                self.session.execute(
                    text("UPDATE canonical_findings SET title=:title, severity=:severity, description=:description, status=:status WHERE tenant_id=:tenant_id AND id=:id"),
                    {"tenant_id": tenant_id, "id": existing_finding, "title": finding.title, "severity": finding.severity.value, "description": finding.description, "status": finding.status.value},
                )
                # The caller's Finding object represents the workflow summary
                # returned by this operation.  Keep its identity aligned with
                # the deduplicated row rather than returning an unpersisted
                # synthetic ID.
                object.__setattr__(finding, "id", existing_finding)
            link_time = _iso(utc_now())
            # Include every append-only source dimension.  The earlier
            # six-column insert was silently ignored by SQLite once the v2
            # table added NOT NULL identity/first/last-seen fields, dropping
            # the very lineage Task 102 is meant to preserve.
            self.session.execute(
                text(
                    "INSERT OR IGNORE INTO canonical_finding_observations "
                    "(tenant_id,finding_id,observation_id,artifact_id,identity_key,"
                    "first_seen_at,last_seen_at,created_at,metadata_json) "
                    "VALUES (:tenant_id,:finding_id,:observation_id,:artifact_id,:identity_key,"
                    ":first_seen_at,:last_seen_at,:created_at,:metadata_json)"
                ),
                {
                    "tenant_id": tenant_id,
                    "finding_id": existing_finding,
                    "observation_id": observation.id,
                    "artifact_id": artifact.id,
                    "identity_key": dedup_key,
                    "first_seen_at": _iso(observation.observed_at),
                    "last_seen_at": _iso(observation.observed_at),
                    "created_at": link_time,
                    "metadata_json": _metadata_json({"identity_version": "finding-v1"}),
                },
            )
            # Keep a normalized observation-to-artifact set even when future
            # collectors attach supporting artifacts.  The primary artifact
            # link is idempotent and remains immutable after insertion.
            self.session.execute(
                text(
                    "INSERT OR IGNORE INTO canonical_observation_artifacts "
                    "(tenant_id,observation_id,artifact_id,role,sequence,created_at,metadata_json) "
                    "VALUES (:tenant_id,:observation_id,:artifact_id,'primary',0,:created_at,:metadata_json)"
                ),
                {
                    "tenant_id": tenant_id,
                    "observation_id": observation.id,
                    "artifact_id": artifact.id,
                    "created_at": link_time,
                    "metadata_json": _metadata_json({"source": "canonical_lineage"}),
                },
            )
            for downstream_record in (retest, report_membership, export):
                if downstream_record is not None:
                    self._insert(downstream_record)
        result: dict[str, _Contract] = {"tenant": tenant, "engagement": engagement, "job": job, "module_version": module_version, "asset": asset, "observation": observation, "artifact": artifact, "finding": finding}
        if client is not None:
            result["client"] = client
        if project is not None:
            result["project"] = project
        optional_records: tuple[tuple[str, _Contract | None], ...] = (("action", action), ("module_execution", module_execution), ("intelligence_source", intelligence_source), ("provenance", provenance), ("feed_snapshot", feed_snapshot), ("check_pack_snapshot", check_pack_snapshot), ("retest", retest), ("report", report), ("report_membership", report_membership), ("export", export))
        for name, optional_record in optional_records:
            if optional_record is not None:
                result[name] = optional_record
        return result

    def resolve_finding_lineage(self, finding_id: str, tenant_id: str) -> dict[str, Any] | None:
        finding_id = _identifier(finding_id, "finding_id")
        tenant_id = _identifier(tenant_id, "tenant_id")
        row = self.session.execute(
            text(
                "SELECT f.id AS finding_id, f.tenant_id, f.observation_id, f.artifact_id, "
                "o.engagement_id, o.job_id, o.module_version_id, o.asset_id, "
                "o.module_execution_id, a.reference AS artifact_reference, "
                "a.digest AS artifact_digest "
                "FROM canonical_findings f "
                "JOIN canonical_observations o ON o.tenant_id=f.tenant_id AND o.id=f.observation_id "
                "JOIN canonical_artifact_refs a ON a.tenant_id=f.tenant_id AND a.id=f.artifact_id "
                "WHERE f.tenant_id=:tenant_id AND f.id=:finding_id"
            ),
            {"tenant_id": tenant_id, "finding_id": finding_id},
        ).mappings().first()
        if row is None:
            return None
        result = dict(row)
        # The legacy primary observation/artifact columns remain for
        # compatibility, while consumers that need evidence history receive
        # the complete append-only source set as a deterministic child list.
        result["source_observations"] = self.list_finding_observations(finding_id, tenant_id)
        return result

    def list_finding_observations(self, finding_id: str, tenant_id: str) -> list[dict[str, Any]]:
        """Return every immutable observation/artifact linked to a summary."""
        finding_id = _identifier(finding_id, "finding_id")
        tenant_id = _identifier(tenant_id, "tenant_id")
        rows = self.session.execute(
            text(
                "SELECT fo.finding_id, fo.observation_id, fo.artifact_id, fo.created_at, "
                "o.engagement_id, o.job_id, o.module_version_id, o.asset_id, "
                "o.proof_type, o.collection_status, o.check_id, o.route, o.parameter, "
                "o.location, o.identity_ref, a.reference, a.digest, a.size, "
                "a.media_type, a.redaction_state, a.integrity_state, a.manifest_digest "
                "FROM canonical_finding_observations fo "
                "JOIN canonical_observations o ON o.tenant_id=fo.tenant_id AND o.id=fo.observation_id "
                "JOIN canonical_artifact_refs a ON a.tenant_id=fo.tenant_id AND a.id=fo.artifact_id "
                "WHERE fo.tenant_id=:tenant_id AND fo.finding_id=:finding_id "
                "ORDER BY fo.created_at, fo.observation_id"
            ),
            {"tenant_id": tenant_id, "finding_id": finding_id},
        ).mappings().all()
        return [dict(row) for row in rows]

    def persist_artifact_manifest(
        self,
        manifest: ArtifactManifest | Mapping[str, Any],
        *,
        custody_store: Any | None = None,
        artifact: ArtifactReference | None = None,
        observation: Observation | None = None,
        role: str = "primary",
        sequence: int = 0,
    ) -> None:
        """Persist one verified custody manifest and its source link.

        Bytes remain in :mod:`common.evidence_custody`; this method stores
        only the normalized, tenant-bound manifest metadata.  A custody store
        is mandatory so this persistence boundary cannot register metadata
        for bytes that were never verified on disk. Mapping inputs are
        accepted only as a wire-format convenience and are reconstructed
        through ``ArtifactManifest.from_dict`` so every field and the
        manifest digest are verified before anything reaches the database.
        """
        if custody_store is None:
            raise CanonicalContractError(
                "custody_store is required to persist an artifact manifest"
            )
        try:
            if isinstance(manifest, ArtifactManifest):
                typed_manifest = manifest
                typed_manifest.verify()
            elif isinstance(manifest, Mapping):
                typed_manifest = ArtifactManifest.from_dict(manifest)
            else:
                raise CanonicalContractError("artifact manifest must be an ArtifactManifest object")
            verifier = getattr(custody_store, "verify", None)
            if not callable(verifier):
                raise CanonicalContractError("custody store does not expose verification")
            verified = verifier(typed_manifest.artifact_id)
            if not isinstance(verified, ArtifactManifest) or verified.manifest_digest != typed_manifest.manifest_digest:
                raise CanonicalContractError("custody manifest does not match stored artifact")
        except CanonicalContractError:
            raise
        except Exception as exc:
            raise CanonicalContractError("artifact manifest failed integrity verification") from exc
        values = typed_manifest.to_dict()
        tenant_id = _identifier(typed_manifest.tenant_id, "tenant_id")
        artifact_id = _identifier(typed_manifest.artifact_id, "artifact_id")
        observation_id = _identifier(typed_manifest.source_observation_id, "source_observation_id")
        if artifact is not None and (artifact.id != artifact_id or artifact.observation_id != observation_id or artifact.tenant_id != tenant_id):
            raise CanonicalLineageError("artifact manifest lineage is inconsistent")
        if observation is not None and (observation.id != observation_id or observation.tenant_id != tenant_id):
            raise CanonicalLineageError("artifact manifest observation is inconsistent")
        if typed_manifest.protection_state == "protected_original" and typed_manifest.protected_original_authorization_ref is None:
            raise CanonicalContractError("protected original manifests require an authorization reference")
        protected_authorization_ref = _authorization_ref(
            typed_manifest.protected_original_authorization_ref,
            "protected_original_authorization_ref",
        )
        if role not in {"primary", "supporting", "derivative", "legacy"}:
            raise CanonicalContractError("unsupported artifact manifest link role")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise CanonicalContractError("artifact manifest link sequence must be a non-negative integer")
        # Bind the custody manifest to the canonical artifact reference before
        # opening the write transaction. This prevents a valid manifest for a
        # different byte stream from being attached to an immutable reference
        # merely because both identifiers happen to be well formed.
        artifact_row = self.session.execute(
            text(
                "SELECT observation_id, digest, media_type, size, source_target, "
                "source_asset_id, manifest_digest FROM canonical_artifact_refs "
                "WHERE tenant_id=:tenant_id AND id=:artifact_id"
            ),
            {"tenant_id": tenant_id, "artifact_id": artifact_id},
        ).mappings().first()
        if artifact_row is None:
            raise CanonicalLineageError(
                "artifact manifest requires a persisted canonical artifact reference"
            )
        observation_row = self.session.execute(
            text(
                "SELECT asset_id FROM canonical_observations "
                "WHERE tenant_id=:tenant_id AND id=:observation_id"
            ),
            {"tenant_id": tenant_id, "observation_id": observation_id},
        ).mappings().first()
        if observation_row is None:
            raise CanonicalLineageError(
                "artifact manifest requires a persisted source observation"
            )
        if str(artifact_row["observation_id"]) != observation_id:
            raise CanonicalLineageError("artifact manifest observation does not match artifact reference")
        if artifact_row["digest"] != typed_manifest.sha256 or int(artifact_row["size"]) != typed_manifest.byte_size:
            raise CanonicalLineageError("artifact manifest bytes do not match artifact reference")
        if str(artifact_row["media_type"]) != typed_manifest.media_type:
            raise CanonicalLineageError("artifact manifest media type does not match artifact reference")
        if artifact_row["source_target"] != typed_manifest.source_target:
            raise CanonicalLineageError("artifact manifest source target does not match artifact reference")
        if artifact_row["source_asset_id"] != typed_manifest.source_asset_id:
            raise CanonicalLineageError("artifact manifest source asset does not match artifact reference")
        if typed_manifest.source_asset_id is not None and str(observation_row["asset_id"]) != typed_manifest.source_asset_id:
            raise CanonicalLineageError("artifact manifest source asset is inconsistent with observation")
        if artifact_row["manifest_digest"] is not None and artifact_row["manifest_digest"] != typed_manifest.manifest_digest:
            raise CanonicalLineageError("artifact manifest digest conflicts with artifact reference")
        with self._atomic():
            existing_row = self.session.execute(
                text(
                    "SELECT * FROM canonical_artifact_manifests "
                    "WHERE tenant_id=:tenant_id AND artifact_id=:artifact_id"
                ),
                {"tenant_id": tenant_id, "artifact_id": artifact_id},
            ).mappings().first()
            if existing_row is not None:
                existing_manifest = _artifact_manifest_from_row(cast(Mapping[str, Any], existing_row))
                if existing_manifest.to_dict() != typed_manifest.to_dict():
                    raise CanonicalContractError("artifact manifest identity is immutable")
            self.session.execute(
                text(
                    "INSERT OR IGNORE INTO canonical_artifact_manifests "
                    "(id,tenant_id,artifact_id,observation_id,schema_version,sha256,byte_size,"
                    "media_type,collected_at,collector_id,source_target,source_asset_id,"
                    "redaction_state,redaction_version,protection_state,encryption_state,"
                    "signer_state,integrity_state,retention_class,retention_expires_at,"
                    "protected_original_authorization_ref,original_relative_path,"
                    "derivative_relative_path,derivative_artifact_id,derivative_sha256,"
                    "derivative_size,manifest_digest,created_at,metadata_json) VALUES "
                    "(:id,:tenant_id,:artifact_id,:observation_id,:schema_version,:sha256,:byte_size,"
                    ":media_type,:collected_at,:collector_id,:source_target,:source_asset_id,"
                    ":redaction_state,:redaction_version,:protection_state,:encryption_state,"
                    ":signer_state,:integrity_state,:retention_class,:retention_expires_at,"
                    ":protected_original_authorization_ref,:original_relative_path,"
                    ":derivative_relative_path,:derivative_artifact_id,:derivative_sha256,"
                    ":derivative_size,:manifest_digest,:created_at,:metadata_json)"
                ),
                {
                    "id": artifact_id,
                    "tenant_id": tenant_id,
                    "artifact_id": artifact_id,
                    "observation_id": observation_id,
                    "schema_version": typed_manifest.schema_version,
                    "sha256": typed_manifest.sha256,
                    "byte_size": typed_manifest.byte_size,
                    "media_type": typed_manifest.media_type,
                    "collected_at": typed_manifest.collected_at,
                    "collector_id": typed_manifest.collector_id,
                    "source_target": typed_manifest.source_target,
                    "source_asset_id": typed_manifest.source_asset_id,
                    "redaction_state": typed_manifest.redaction_state,
                    "redaction_version": typed_manifest.redaction_version,
                    "protection_state": typed_manifest.protection_state,
                    "encryption_state": typed_manifest.encryption_state,
                    "signer_state": typed_manifest.signer_state,
                    "integrity_state": typed_manifest.integrity_state,
                    "retention_class": typed_manifest.retention_class,
                    "retention_expires_at": typed_manifest.retention_expires_at,
                    "protected_original_authorization_ref": protected_authorization_ref,
                    "original_relative_path": typed_manifest.original_relative_path,
                    "derivative_relative_path": typed_manifest.derivative_relative_path,
                    "derivative_artifact_id": typed_manifest.derivative_artifact_id,
                    "derivative_sha256": typed_manifest.derivative_sha256,
                    "derivative_size": typed_manifest.derivative_size,
                    "manifest_digest": typed_manifest.manifest_digest,
                    "created_at": typed_manifest.collected_at,
                    "metadata_json": _metadata_json(cast(Mapping[str, Any], values["metadata"])),
                },
            )
            # Bind the immutable manifest digest back to the canonical artifact
            # reference.  The v2 custody trigger permits exactly one
            # NULL -> sha256 binding and rejects every later identity change.
            if artifact_row["manifest_digest"] is None:
                self.session.execute(
                    text(
                        "UPDATE canonical_artifact_refs "
                        "SET manifest_digest=:manifest_digest "
                        "WHERE tenant_id=:tenant_id AND id=:artifact_id"
                    ),
                    {
                        "manifest_digest": typed_manifest.manifest_digest,
                        "tenant_id": tenant_id,
                        "artifact_id": artifact_id,
                    },
                )
            self.session.execute(
                text(
                    "INSERT OR IGNORE INTO canonical_observation_artifacts "
                    "(tenant_id,observation_id,artifact_id,role,sequence,created_at,metadata_json) "
                    "VALUES (:tenant_id,:observation_id,:artifact_id,:role,:sequence,:created_at,:metadata_json)"
                ),
                {
                    "tenant_id": tenant_id,
                    "observation_id": observation_id,
                    "artifact_id": artifact_id,
                    "role": role,
                    "sequence": sequence,
                    "created_at": typed_manifest.collected_at,
                    "metadata_json": _metadata_json({"manifest_digest": typed_manifest.manifest_digest}),
                },
            )

    def persist_custodied_manifest(
        self,
        manifest: ArtifactManifest | Mapping[str, Any],
        *,
        custody_store: Any,
        artifact: ArtifactReference | None = None,
        observation: Observation | None = None,
        role: str = "primary",
        sequence: int = 0,
        rollback_on_failure: bool = True,
    ) -> ArtifactManifest:
        """Bridge one newly stored file artifact into canonical storage.

        The custody store is verified before the database write, and a failed
        database transaction compensates the exact newly staged artifact when
        ``rollback_on_failure`` is enabled.  Callers that are reopening an
        already-committed artifact can disable compensation explicitly; new
        ``store_artifact`` writes should leave it enabled.
        """
        try:
            typed_manifest = (
                manifest
                if isinstance(manifest, ArtifactManifest)
                else ArtifactManifest.from_dict(manifest)
            )
            typed_manifest.verify()
            verifier = getattr(custody_store, "verify", None)
            if not callable(verifier):
                raise CanonicalContractError("custody store does not expose verification")
            verified = verifier(typed_manifest.artifact_id)
            if not isinstance(verified, ArtifactManifest) or verified.manifest_digest != typed_manifest.manifest_digest:
                raise CanonicalContractError("custody manifest does not match stored artifact")
        except CanonicalContractError:
            raise
        except Exception as exc:
            raise CanonicalContractError("custody artifact verification failed") from exc

        try:
            self.persist_artifact_manifest(
                typed_manifest,
                custody_store=custody_store,
                artifact=artifact,
                observation=observation,
                role=role,
                sequence=sequence,
            )
        except Exception as exc:
            if rollback_on_failure:
                rollback = getattr(custody_store, "rollback_artifact", None)
                if not callable(rollback):
                    raise CanonicalContractError(
                        "database transaction failed and custody rollback is unavailable"
                    ) from exc
                try:
                    rollback(
                        typed_manifest.artifact_id,
                        expected_manifest_digest=typed_manifest.manifest_digest,
                    )
                except Exception as rollback_exc:
                    raise CanonicalContractError(
                        "database transaction failed and custody rollback did not complete"
                    ) from rollback_exc
            raise
        return typed_manifest

    def record_evidence_access(
        self,
        *,
        tenant_id: str,
        artifact_id: str,
        observation_id: str,
        access_kind: str,
        authorization_ref: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        """Append one tenant-bound redacted/original access audit row."""
        tenant_id = _identifier(tenant_id, "tenant_id")
        artifact_id = _identifier(artifact_id, "artifact_id")
        observation_id = _identifier(observation_id, "observation_id")
        if access_kind not in {"redacted_derivative", "protected_original"}:
            raise CanonicalContractError("unsupported evidence access kind")
        authorization_ref = _authorization_ref(authorization_ref)
        if access_kind == "protected_original" and authorization_ref is None:
            raise CanonicalContractError("protected original access requires an authorization reference")
        manifest_ref = self.session.execute(
            text(
                "SELECT protected_original_authorization_ref "
                "FROM canonical_artifact_manifests "
                "WHERE tenant_id=:tenant_id AND artifact_id=:artifact_id "
                "AND observation_id=:observation_id"
            ),
            {
                "tenant_id": tenant_id,
                "artifact_id": artifact_id,
                "observation_id": observation_id,
            },
        ).scalar_one_or_none()
        if access_kind == "protected_original":
            if manifest_ref is None:
                raise CanonicalContractError(
                    "protected original access requires a persisted protected manifest"
                )
            if manifest_ref != authorization_ref:
                raise CanonicalContractError("authorization reference does not match the artifact manifest")
        elif manifest_ref is None:
            # Redacted access is also an append-only read of a canonical
            # artifact; do not create audit rows for an unbound artifact ID.
            artifact_exists = self.session.execute(
                text(
                    "SELECT 1 FROM canonical_artifact_refs "
                    "WHERE tenant_id=:tenant_id AND id=:artifact_id "
                    "AND observation_id=:observation_id"
                ),
                {
                    "tenant_id": tenant_id,
                    "artifact_id": artifact_id,
                    "observation_id": observation_id,
                },
            ).scalar_one_or_none()
            if artifact_exists is None:
                raise CanonicalContractError(
                    "evidence access requires a persisted canonical artifact"
                )
        audit_id = server_id()
        with self._atomic():
            self.session.execute(
                text(
                    "INSERT INTO canonical_evidence_access_audit "
                    "(id,tenant_id,artifact_id,observation_id,access_kind,authorization_ref,accessed_at,metadata_json) "
                    "VALUES (:id,:tenant_id,:artifact_id,:observation_id,:access_kind,:authorization_ref,:accessed_at,:metadata_json)"
                ),
                {
                    "id": audit_id,
                    "tenant_id": tenant_id,
                    "artifact_id": artifact_id,
                    "observation_id": observation_id,
                    "access_kind": access_kind,
                    "authorization_ref": authorization_ref,
                    "accessed_at": _iso(utc_now()),
                    "metadata_json": _metadata_json(metadata or {}),
                },
            )
        return audit_id

    def get_observation(self, observation_id: str, tenant_id: str) -> Observation | None:
        observation_id = _identifier(observation_id, "observation_id")
        tenant_id = _identifier(tenant_id, "tenant_id")
        row = self.session.execute(
            text("SELECT * FROM canonical_observations WHERE tenant_id=:tenant_id AND id=:id"),
            {"tenant_id": tenant_id, "id": observation_id},
        ).mappings().first()
        return cast(Observation | None, _contract_from_row(Observation, cast(Mapping[str, Any], row))) if row else None

    def get_artifact(self, artifact_id: str, tenant_id: str) -> ArtifactReference | None:
        artifact_id = _identifier(artifact_id, "artifact_id")
        tenant_id = _identifier(tenant_id, "tenant_id")
        row = self.session.execute(
            text("SELECT * FROM canonical_artifact_refs WHERE tenant_id=:tenant_id AND id=:id"),
            {"tenant_id": tenant_id, "id": artifact_id},
        ).mappings().first()
        return cast(ArtifactReference | None, _contract_from_row(ArtifactReference, cast(Mapping[str, Any], row))) if row else None

    def get_artifact_manifest(self, artifact_id: str, tenant_id: str) -> ArtifactManifest | None:
        """Return one verified manifest only within the requested tenant."""
        artifact_id = _identifier(artifact_id, "artifact_id")
        tenant_id = _identifier(tenant_id, "tenant_id")
        row = self.session.execute(
            text(
                "SELECT * FROM canonical_artifact_manifests "
                "WHERE tenant_id=:tenant_id AND artifact_id=:artifact_id"
            ),
            {"tenant_id": tenant_id, "artifact_id": artifact_id},
        ).mappings().first()
        if row is None:
            return None
        return _artifact_manifest_from_row(cast(Mapping[str, Any], row))

    def list_artifact_manifests(
        self,
        tenant_id: str,
        observation_id: str | None = None,
    ) -> list[ArtifactManifest]:
        """List verified manifests scoped to one tenant and optional observation."""
        tenant_id = _identifier(tenant_id, "tenant_id")
        params: dict[str, Any] = {"tenant_id": tenant_id}
        clause = ""
        if observation_id is not None:
            observation_id = _identifier(observation_id, "observation_id")
            clause = " AND observation_id=:observation_id"
            params["observation_id"] = observation_id
        rows = self.session.execute(
            text(
                "SELECT * FROM canonical_artifact_manifests "
                "WHERE tenant_id=:tenant_id" + clause + " ORDER BY collected_at, artifact_id"
            ),
            params,
        ).mappings().all()
        return [_artifact_manifest_from_row(cast(Mapping[str, Any], row)) for row in rows]

    # Compatibility names used by custody/database adapters.
    get_manifest = get_artifact_manifest
    list_manifests = list_artifact_manifests

    # Explicit aliases keep the append-only boundary discoverable to existing
    # adapters without creating a second persistence schema.
    append_observation = create_lineage
    persist_observation = create_lineage

    def count(self, table: str, *, tenant_id: str | None = None) -> int:
        if not re.fullmatch(r"canonical_[a-z_]+", table):
            raise CanonicalContractError("invalid canonical table")
        clause = " WHERE tenant_id=:tenant_id" if tenant_id is not None and table != "canonical_tenants" else ""
        params = {"tenant_id": tenant_id} if clause else {}
        return int(self.session.execute(text(f"SELECT COUNT(*) FROM {table}{clause}"), params).scalar_one())

    def list_legacy_records(self, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
        clause = " WHERE tenant_id=:tenant_id" if tenant_id else ""
        rows = self.session.execute(text(f"SELECT * FROM canonical_legacy_records{clause} ORDER BY sequence"), {"tenant_id": tenant_id} if tenant_id else {}).mappings().all()
        return [dict(row) for row in rows]


class CanonicalAdapter:
    """Narrow adapter boundary for existing module/finding outputs."""

    def __init__(self, store: CanonicalStore, context: "CanonicalContext | None"):
        self.store = store
        self.context = context

    def require_context(self) -> "CanonicalContext":
        if self.context is None:
            raise MissingCanonicalContextError("tenant, engagement, job, module version, and asset context are required")
        self.context.validate()
        return self.context

    def persist_finding(
        self,
        *,
        title: str,
        severity: FindingSeverity | str,
        description: str,
        artifact_reference: str,
        artifact_digest: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, _Contract]:
        context = self.require_context()
        tenant_id = cast(str, context.tenant_id)
        engagement_id = cast(str, context.engagement_id)
        job_id = cast(str, context.job_id)
        module_version_id = cast(str, context.module_version_id)
        asset_id = cast(str, context.asset_id)
        action_id = cast(str | None, context.action_id)
        tenant_row = self.store.session.execute(
            text("SELECT id FROM canonical_tenants WHERE id=:tenant_id"),
            {"tenant_id": tenant_id},
        ).first()
        if tenant_row is None:
            raise MissingCanonicalContextError("canonical tenant context is not persisted")
        tenant = cast(Tenant, _contract_from_row(
            Tenant,
            cast(Mapping[str, Any], self.store.session.execute(
                text("SELECT * FROM canonical_tenants WHERE id=:tenant_id"),
                {"tenant_id": tenant_id},
            ).mappings().one()),
        ))
        engagement = self._existing(Engagement, engagement_id, tenant_id)
        job = self._existing(Job, job_id, tenant_id)
        module_version = self._existing(ModuleVersion, module_version_id, tenant_id)
        asset = self._existing(Asset, asset_id, tenant_id)
        action = self._existing(Action, action_id, tenant_id) if action_id else None
        if action_id and action is None:
            raise MissingCanonicalContextError("canonical action context is not persisted")
        if not all((engagement, job, module_version, asset)):
            raise MissingCanonicalContextError("canonical context references must already exist")
        observation = Observation(tenant_id=tenant_id, engagement_id=engagement_id, job_id=job_id, module_version_id=module_version_id, asset_id=asset_id, action_id=action_id, metadata=metadata or {})
        artifact = ArtifactReference(tenant_id=tenant_id, observation_id=observation.id, reference=artifact_reference, digest=artifact_digest, media_type="application/json", size=0)
        finding = Finding(tenant_id=tenant_id, observation_id=observation.id, artifact_id=artifact.id, title=title, severity=FindingSeverity(severity), description=description, metadata=metadata or {})
        return self.store.create_lineage(tenant=tenant, engagement=cast(Engagement, engagement), job=cast(Job, job), module_version=cast(ModuleVersion, module_version), asset=cast(Asset, asset), observation=observation, artifact=artifact, finding=finding, action=cast(Action | None, action))

    def _existing(self, cls: type[TContract], identifier: str, tenant_id: str) -> TContract | None:
        table = _TABLE_TYPES[cls]
        row = self.store.session.execute(text(f"SELECT * FROM {table} WHERE tenant_id=:tenant_id AND id=:id"), {"tenant_id": tenant_id, "id": identifier}).mappings().first()
        if row is None:
            return None
        return cast(TContract, _contract_from_row(cls, cast(Mapping[str, Any], row)))


@dataclass(frozen=True)
class CanonicalContext:
    tenant_id: str | None
    engagement_id: str | None
    job_id: str | None
    module_version_id: str | None
    asset_id: str | None
    action_id: str | None = None

    def validate(self) -> None:
        missing = [name for name in ("tenant_id", "engagement_id", "job_id", "module_version_id", "asset_id") if not getattr(self, name)]
        if missing:
            raise MissingCanonicalContextError("missing canonical context: " + ", ".join(missing))
        for name in ("tenant_id", "engagement_id", "job_id", "module_version_id", "asset_id", "action_id"):
            value = getattr(self, name)
            if value is not None:
                _identifier(value, name)


def _row_metadata(row: Mapping[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(str(row.get("metadata_json") or "{}"))
    except (TypeError, json.JSONDecodeError):
        value = {}
    return bounded_metadata(value if isinstance(value, Mapping) else {})


def _artifact_manifest_from_row(row: Mapping[str, Any]) -> ArtifactManifest:
    """Rebuild and verify a custody manifest read from canonical storage."""
    if str(row.get("id") or "") != str(row.get("artifact_id") or ""):
        raise CanonicalContractError("artifact manifest identity is inconsistent")
    try:
        metadata_value = json.loads(str(row.get("metadata_json") or "{}"))
    except (TypeError, json.JSONDecodeError) as exc:
        raise CanonicalContractError("artifact manifest metadata is malformed") from exc
    if not isinstance(metadata_value, Mapping):
        raise CanonicalContractError("artifact manifest metadata must be an object")
    values: dict[str, Any] = {
        "artifact_id": row.get("artifact_id"),
        "tenant_id": row.get("tenant_id"),
        "source_observation_id": row.get("observation_id"),
        "schema_version": row.get("schema_version"),
        "sha256": row.get("sha256"),
        "byte_size": row.get("byte_size"),
        "media_type": row.get("media_type"),
        "collected_at": row.get("collected_at"),
        "collector_id": row.get("collector_id"),
        "source_target": row.get("source_target"),
        "source_asset_id": row.get("source_asset_id"),
        "redaction_state": row.get("redaction_state"),
        "redaction_version": row.get("redaction_version"),
        "protection_state": row.get("protection_state"),
        "encryption_state": row.get("encryption_state"),
        "signer_state": row.get("signer_state"),
        "integrity_state": row.get("integrity_state"),
        "retention_class": row.get("retention_class"),
        "retention_expires_at": row.get("retention_expires_at"),
        "protected_original_authorization_ref": row.get("protected_original_authorization_ref"),
        "original_relative_path": row.get("original_relative_path"),
        "derivative_relative_path": row.get("derivative_relative_path"),
        "derivative_artifact_id": row.get("derivative_artifact_id"),
        "derivative_sha256": row.get("derivative_sha256"),
        "derivative_size": row.get("derivative_size"),
        "manifest_digest": row.get("manifest_digest"),
        "metadata": dict(metadata_value),
    }
    try:
        manifest = ArtifactManifest.from_dict(values)
        if manifest.protection_state == "protected_original" and manifest.protected_original_authorization_ref is None:
            raise CanonicalContractError("protected original manifests require an authorization reference")
        _authorization_ref(
            manifest.protected_original_authorization_ref,
            "protected_original_authorization_ref",
        )
        return manifest
    except Exception as exc:
        raise CanonicalContractError("artifact manifest failed integrity verification") from exc


def _asset_from_row(row: Mapping[str, Any]) -> Asset:
    return Asset(id=str(row["id"]), tenant_id=str(row["tenant_id"]), kind=AssetKind(str(row["kind"])), identity_key=str(row["identity_key"]), display_name=str(row["display_name"]), canonical_uri=row.get("canonical_uri"), schema_version=str(row["schema_version"]), created_at=parse_utc(str(row["created_at"])), metadata=_row_metadata(row))


def _contract_from_row(cls: type[_Contract], row: Mapping[str, Any]) -> _Contract:
    common: dict[str, Any] = {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "schema_version": str(row["schema_version"]),
        "created_at": parse_utc(str(row["created_at"])),
        "metadata": _row_metadata(row),
    }
    if cls is Asset:
        return _asset_from_row(cast(Mapping[str, Any], row))
    if cls is Tenant:
        return Tenant(
            id=str(row["id"]),
            name=str(row["name"]),
            schema_version=str(row["schema_version"]),
            created_at=parse_utc(str(row["created_at"])),
            metadata=_row_metadata(row),
        )
    if cls is Client:
        return Client(name=str(row["name"]), **common)
    if cls is Project:
        return Project(client_id=str(row["client_id"]), name=str(row["name"]), **common)
    if cls is Engagement:
        return Engagement(project_id=row.get("project_id"), name=str(row["name"]), status=EngagementStatus(str(row["status"])), **common)
    if cls is ScopeDecision:
        return ScopeDecision(
            engagement_id=str(row["engagement_id"]),
            operator_id=str(row["operator_id"]),
            role_id=row.get("role_id"),
            outcome=ScopeOutcome(str(row["outcome"])),
            policy_version=str(row["policy_version"]),
            decision_reason=str(row.get("decision_reason") or ""),
            decided_at=parse_utc(str(row["decided_at"])),
            **common,
        )
    if cls is Job:
        return Job(engagement_id=str(row["engagement_id"]), job_kind=str(row["job_kind"]), status=JobStatus(str(row["status"])), **common)
    if cls is Action:
        return Action(engagement_id=str(row["engagement_id"]), job_id=str(row["job_id"]), action_kind=str(row["action_kind"]), authorization_decision_id=row.get("authorization_decision_id"), **common)
    if cls is IntelligenceSource:
        return IntelligenceSource(name=str(row["name"]), source_kind=str(row["source_kind"]), **common)
    if cls is Provenance:
        return Provenance(source_type=ProvenanceSourceType(str(row["source_type"])), source_id=str(row["source_id"]), digest=str(row["digest"]), **common)
    if cls in (FeedSnapshot, CheckPackSnapshot):
        snapshot = {"source_id": str(row["source_id"]), "version": str(row["version"]), "digest": str(row["digest"]), **common}
        return cls(**snapshot)  # type: ignore[call-arg]
    if cls is ModuleVersion:
        return ModuleVersion(module_id=str(row["module_id"]), version=str(row["version"]), module_kind=str(row["module_kind"]), manifest_digest=row.get("manifest_digest"), policy_version=row.get("policy_version"), intelligence_snapshot_id=row.get("intelligence_snapshot_id"), check_pack_snapshot_id=row.get("check_pack_snapshot_id"), provenance_id=row.get("provenance_id"), **common)
    if cls is ModuleExecution:
        return ModuleExecution(job_id=str(row["job_id"]), module_version_id=str(row["module_version_id"]), status=ModuleExecutionStatus(str(row["status"])), intelligence_snapshot_id=row.get("intelligence_snapshot_id"), check_pack_snapshot_id=row.get("check_pack_snapshot_id"), provenance_id=row.get("provenance_id"), **common)
    if cls is Observation:
        return Observation(
            engagement_id=str(row["engagement_id"]),
            job_id=str(row["job_id"]),
            module_version_id=str(row["module_version_id"]),
            module_execution_id=row.get("module_execution_id"),
            asset_id=str(row["asset_id"]),
            action_id=row.get("action_id"),
            intelligence_snapshot_id=row.get("intelligence_snapshot_id"),
            provenance_id=row.get("provenance_id"),
            status=ObservationStatus(str(row["status"])),
            observed_at=parse_utc(str(row["observed_at"])),
            proof_type=str(row.get("proof_type") or "unknown"),
            collection_status=CollectionStatus(str(row.get("collection_status") or "unknown")),
            check_id=row.get("check_id"),
            route=row.get("route"),
            parameter=row.get("parameter"),
            location=row.get("location"),
            identity_ref=row.get("identity_ref"),
            **common,
        )
    if cls is ArtifactReference:
        retention = row.get("retention_expires_at")
        return ArtifactReference(
            observation_id=str(row["observation_id"]),
            reference=str(row["reference"]),
            digest=row.get("digest"),
            media_type=str(row["media_type"]),
            size=int(row["size"]),
            redaction_state=RedactionState(str(row.get("redaction_state") or "unknown")),
            encryption_state=str(row.get("encryption_state") or "reference_only"),
            collected_at=parse_utc(str(row["collected_at"])),
            collector_id=str(row.get("collector_id") or "unknown"),
            collector_version=str(row.get("collector_version") or "unknown"),
            source_target=str(row.get("source_target") or "unknown"),
            source_asset_id=row.get("source_asset_id"),
            redaction_version=str(row.get("redaction_version") or "unknown"),
            protection_state=str(row.get("protection_state") or "reference_only"),
            signer_state=str(row.get("signer_state") or "unsigned"),
            integrity_state=ArtifactIntegrityState(str(row.get("integrity_state") or ("unknown" if row.get("digest") is None else "sha256_verified"))),
            retention_class=str(row.get("retention_class") or "default"),
            retention_expires_at=parse_utc(str(retention)) if retention else None,
            protected_original_authorization_ref=row.get("protected_original_authorization_ref"),
            derivative_reference=row.get("derivative_reference"),
            manifest_digest=row.get("manifest_digest"),
            **common,
        )
    if cls is Finding:
        return Finding(
            observation_id=str(row["observation_id"]),
            artifact_id=str(row["artifact_id"]),
            title=str(row["title"]),
            severity=FindingSeverity(str(row["severity"])),
            description=str(row["description"]),
            status=FindingStatus(str(row["status"])),
            finding_key=row.get("finding_key"),
            dedup_key=row.get("dedup_key"),
            **common,
        )
    raise CanonicalContractError(f"row conversion for {cls.__name__} is not exposed")


def deserialize_contract(payload: str | Mapping[str, Any], cls: type[TContract]) -> TContract:
    if isinstance(payload, str):
        try:
            value = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise CanonicalSerializationError("invalid contract JSON") from exc
    else:
        value = payload
    if not isinstance(value, Mapping):
        raise CanonicalSerializationError("contract payload must be an object")
    return cast(TContract, cls.from_dict(value))


# Friendly compatibility aliases for adapters and tests that use repository
# terminology rather than the implementation's ``Store`` name.
CanonicalRepository = CanonicalStore
CanonicalContracts = CanonicalStore
AssetIdentity = Asset
ArtifactRef = ArtifactReference
ModuleCheckVersion = ModuleVersion
MissingContextError = MissingCanonicalContextError
TenantMismatchError = CanonicalTenantMismatchError
OrphanRecordError = CanonicalLineageError
SchemaVersionError = CanonicalContractError
NaiveTimestampError = CanonicalContractError
serialize = serialize_contract
deserialize = deserialize_contract


def create_canonical_lineage(store: CanonicalStore, **kwargs: Any) -> dict[str, _Contract]:
    return store.create_lineage(**kwargs)


def resolve_lineage(store: CanonicalStore, finding_id: str, tenant_id: str) -> dict[str, Any] | None:
    return store.resolve_finding_lineage(finding_id, tenant_id)


__all__ = [
    "Action", "ArtifactReference", "ArtifactRef", "Asset", "AssetIdentity", "AssetKind",
    "CanonicalAdapter", "CanonicalContext", "CanonicalContractError", "CanonicalContracts",
    "CanonicalLineageError", "CanonicalRepository", "CanonicalSerializationError",
    "CanonicalStore", "CanonicalTenantMismatchError", "CheckPackSnapshot", "Client",
    "CURRENT_CONTRACT_VERSION", "CANONICAL_SCHEMA_VERSION", "Engagement", "EngagementStatus", "Event", "Export",
    "ExportStatus", "FeedSnapshot", "Finding", "FindingSeverity", "FindingStatus", "IntelligenceSource", "Job",
    "JobStatus", "Log", "LogLevel", "MissingCanonicalContextError", "ModuleExecution", "ModuleExecutionStatus", "ModuleVersion",
    "ModuleCheckVersion", "Observation", "ObservationStatus", "Operator", "Project", "Provenance",
    "ProvenanceSourceType", "RedactionState", "Report", "ReportMembership", "ReportStatus", "Retest", "RetestStatus", "Role",
    "ScopeDecision", "ScopeOutcome", "SCHEMA_VERSION", "Tenant", "bounded_metadata", "deserialize_contract",
    "ensure_utc", "isoformat_utc", "normalize_asset_identity", "parse_utc", "serialize_contract",
    "server_id", "utc_now",
    "MissingContextError", "TenantMismatchError", "OrphanRecordError", "SchemaVersionError",
    "NaiveTimestampError", "serialize", "deserialize", "create_canonical_lineage", "resolve_lineage",
    "CanonicalContextError",
]
