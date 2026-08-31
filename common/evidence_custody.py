"""Append-only evidence artifact custody for Forge observations.

This module is deliberately independent from the legacy :class:`Evidence`
dataclass.  Legacy evidence is a presentation-shaped bundle containing raw
request/response fields and filesystem paths; custody needs a server-owned
artifact namespace, a signed-by-integrity (not cryptographic signing) manifest,
and two explicit read paths: a redacted derivative for ordinary consumers and
an exact, audited protected-original path.

The implementation is local-filesystem only.  It uses the descriptor-backed
artifact boundary already used by Forge, writes every object atomically, and
verifies both the manifest and bytes on every read.  A database adapter can
store the returned manifest in the canonical v2 tables, but the files remain
the source of artifact bytes and never live in mutable finding rows.
"""
from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import secrets
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping

from common.artifact_io import (
    ArtifactBoundaryError,
    atomic_write_bytes,
    ensure_private_directory,
    read_verified_regular_file,
    validate_private_directory_readonly,
)
from common.redaction import redact_text, redact_value


EVIDENCE_SCHEMA_VERSION = "forge-evidence-v1"
REDACTION_VERSION = "forge-redaction-v1"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127}$")
# Artifact identifiers are used as one filesystem path component. Other
# custody identifiers may retain the historical slash-compatible grammar,
# but an artifact id must never create a caller-controlled directory tree.
_ARTIFACT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_AUTHORIZATION_REF_RE = re.compile(
    r"^(?:authz|authorization):[A-Za-z0-9][A-Za-z0-9._:@/+\-]{1,240}$"
)
_SHA256_PREFIX = "sha256:"
_MAX_METADATA_BYTES = 16_384
_MAX_TEXT = 2_000


class CustodyError(ValueError):
    """Base class for a fail-closed custody failure."""


class ArtifactNotFound(CustodyError):
    """The requested artifact or manifest is absent."""


class ArtifactIntegrityError(CustodyError):
    """Stored bytes or manifest metadata do not match their integrity data."""


class ArtifactAccessDenied(CustodyError):
    """The caller did not present the exact protected-original authorization."""


class ArtifactScopeError(CustodyError):
    """The requested artifact is not owned by the store's tenant."""


class ArtifactTransactionError(CustodyError):
    """A manifest transaction failed and all newly-created files were removed."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CustodyError("timestamp must be ISO-8601") from exc
    else:
        parsed = value
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CustodyError("timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value.strip()):
        raise CustodyError(f"{field_name} must be a bounded identifier")
    rendered = value.strip()
    if ".." in rendered or "\\" in rendered:
        raise CustodyError(f"{field_name} contains a path traversal component")
    if re.search(r"(?i)(?:password|secret|token|canary|private[_-]?key)", rendered):
        raise CustodyError(f"{field_name} contains secret-like material")
    return rendered


def _artifact_id(value: str, field_name: str = "artifact_id") -> str:
    """Validate an artifact id as a single safe filesystem path component."""
    if not isinstance(value, str):
        raise CustodyError(f"{field_name} must be a bounded identifier")
    rendered = value.strip()
    if not _ARTIFACT_ID_RE.fullmatch(rendered) or ".." in rendered:
        raise CustodyError(f"{field_name} must not contain path separators or traversal")
    if re.search(r"(?i)(?:password|secret|token|canary|private[_-]?key)", rendered):
        raise CustodyError(f"{field_name} contains secret-like material")
    return rendered


def _authorization_ref(value: str, field_name: str = "authorization_ref") -> str:
    """Validate a typed, opaque protected-original authorization handle."""
    if not isinstance(value, str):
        raise CustodyError(f"{field_name} must be text")
    rendered = value.strip()
    if not _AUTHORIZATION_REF_RE.fullmatch(rendered):
        raise CustodyError(
            f"{field_name} must be a typed authz:/authorization: reference"
        )
    if re.search(r"(?i)(?:password|secret|token|canary|private[_-]?key)", rendered):
        raise CustodyError(f"{field_name} contains secret-like material")
    return rendered


def _relative_artifact_path(
    value: str | None,
    *,
    tenant_id: str,
    artifact_id: str,
    filename: str,
    required: bool,
) -> str | None:
    """Validate the exact server-generated relative path for one artifact."""
    if value is None:
        if required:
            raise CustodyError(f"{filename} relative path is required")
        return None
    if not isinstance(value, str) or not value or "\\" in value:
        raise CustodyError(f"{filename} relative path is unsafe")
    path = PurePosixPath(value)
    expected = (
        "tenants",
        hashlib.sha256(tenant_id.encode("utf-8")).hexdigest(),
        "artifacts",
        artifact_id,
        filename,
    )
    if path.is_absolute() or path.parts != expected:
        raise CustodyError(f"{filename} relative path is outside custody namespace")
    return value


def _text(value: str | None, field_name: str, *, required: bool = False, limit: int = _MAX_TEXT) -> str | None:
    if value is None:
        if required:
            raise CustodyError(f"{field_name} is required")
        return None
    if not isinstance(value, str):
        raise CustodyError(f"{field_name} must be text")
    rendered = redact_text(value.strip())
    if required and not rendered:
        raise CustodyError(f"{field_name} is required")
    if len(rendered) > limit:
        raise CustodyError(f"{field_name} exceeds its bound")
    return rendered


def _digest(payload: bytes) -> str:
    return _SHA256_PREFIX + hashlib.sha256(payload).hexdigest()


def _metadata(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise CustodyError("metadata must be an object")
    rendered = redact_value(dict(value))
    if not isinstance(rendered, dict):
        raise CustodyError("metadata must be an object")
    encoded = json.dumps(rendered, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(encoded.encode("utf-8")) > _MAX_METADATA_BYTES:
        raise CustodyError("metadata exceeds its byte bound")
    return rendered


def _canonical_manifest_payload(values: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact manifest payload covered by ``manifest_digest``."""
    result = {str(key): values[key] for key in values if key != "manifest_digest"}
    return json.loads(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _manifest_digest(values: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        _canonical_manifest_payload(values),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return _digest(encoded)


@dataclass(frozen=True)
class ProtectedOriginalAuthorization:
    """Single-use-style authorization descriptor for an original read.

    The store does not infer authorization from a role, a finding, or a
    caller-supplied boolean.  The authorization reference must exactly match
    the manifest binding, and the tenant/artifact tuple is checked again.
    """

    tenant_id: str
    artifact_id: str
    authorization_ref: str
    operator_id: str
    reason: str
    expires_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _id(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "artifact_id", _artifact_id(self.artifact_id))
        object.__setattr__(
            self,
            "authorization_ref",
            _authorization_ref(self.authorization_ref, "authorization_ref"),
        )
        object.__setattr__(self, "operator_id", _id(self.operator_id, "operator_id"))
        object.__setattr__(self, "reason", _text(self.reason, "reason", required=True, limit=500) or "")
        object.__setattr__(self, "expires_at", _iso(self.expires_at))

    def valid_now(self) -> bool:
        if self.expires_at is None:
            return True
        expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        return _utc_now() < expiry


@dataclass(frozen=True)
class ArtifactManifest:
    """Tamper-evident metadata for one original and its derivative."""

    artifact_id: str
    tenant_id: str
    source_observation_id: str
    sha256: str
    byte_size: int
    media_type: str
    collected_at: str
    collector_id: str
    source_target: str | None
    source_asset_id: str | None
    redaction_state: str
    redaction_version: str
    protection_state: str
    encryption_state: str
    signer_state: str
    integrity_state: str
    retention_class: str
    retention_expires_at: str | None
    protected_original_authorization_ref: str | None
    original_relative_path: str | None
    derivative_relative_path: str
    derivative_artifact_id: str
    derivative_sha256: str
    derivative_size: int
    manifest_digest: str
    schema_version: str = EVIDENCE_SCHEMA_VERSION
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_id", _artifact_id(self.artifact_id))
        object.__setattr__(self, "tenant_id", _id(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "source_observation_id", _id(self.source_observation_id, "source_observation_id"))
        object.__setattr__(self, "collector_id", _id(self.collector_id, "collector_id"))
        if self.source_asset_id is not None:
            object.__setattr__(self, "source_asset_id", _id(self.source_asset_id, "source_asset_id"))
        if not _DIGEST_RE.fullmatch(self.sha256):
            raise CustodyError("sha256 must be sha256:<64 lowercase hex>")
        if not _DIGEST_RE.fullmatch(self.derivative_sha256):
            raise CustodyError("derivative_sha256 must be sha256:<64 lowercase hex>")
        if not isinstance(self.byte_size, int) or self.byte_size < 0:
            raise CustodyError("byte_size must be a non-negative integer")
        if not isinstance(self.derivative_size, int) or self.derivative_size < 0:
            raise CustodyError("derivative_size must be a non-negative integer")
        object.__setattr__(self, "media_type", _text(self.media_type, "media_type", required=True, limit=200) or "")
        object.__setattr__(self, "source_target", _text(self.source_target, "source_target", limit=2_000))
        object.__setattr__(self, "collected_at", _iso(self.collected_at) or "")
        for name in ("redaction_state", "redaction_version", "protection_state", "encryption_state", "signer_state", "integrity_state", "retention_class"):
            object.__setattr__(self, name, _text(str(getattr(self, name)), name, required=True, limit=100) or "")
        object.__setattr__(self, "retention_expires_at", _iso(self.retention_expires_at))
        if self.protected_original_authorization_ref is not None:
            object.__setattr__(
                self,
                "protected_original_authorization_ref",
                _authorization_ref(
                    self.protected_original_authorization_ref,
                    "protected_original_authorization_ref",
                ),
            )
        object.__setattr__(self, "metadata", _metadata(self.metadata))
        if self.schema_version != EVIDENCE_SCHEMA_VERSION:
            raise CustodyError("unsupported evidence manifest schema version")
        object.__setattr__(self, "derivative_artifact_id", _artifact_id(self.derivative_artifact_id, "derivative_artifact_id"))
        object.__setattr__(
            self,
            "original_relative_path",
            _relative_artifact_path(
                self.original_relative_path,
                tenant_id=self.tenant_id,
                artifact_id=self.artifact_id,
                filename="original.bin",
                required=self.protection_state == "protected_original",
            ),
        )
        object.__setattr__(
            self,
            "derivative_relative_path",
            _relative_artifact_path(
                self.derivative_relative_path,
                tenant_id=self.tenant_id,
                artifact_id=self.artifact_id,
                filename="derivative.bin",
                required=True,
            ),
        )
        if self.protection_state == "protected_original":
            if self.original_relative_path is None or self.protected_original_authorization_ref is None:
                raise CustodyError(
                    "protected originals require an original path and authorization reference"
                )
        elif self.protection_state == "not_retained":
            if self.original_relative_path is not None or self.protected_original_authorization_ref is not None:
                raise CustodyError(
                    "non-retained artifacts cannot bind an original path or authorization"
                )
        elif self.protection_state != "legacy_unknown":
            raise CustodyError("unsupported protection state")
        if not _DIGEST_RE.fullmatch(self.manifest_digest):
            raise CustodyError("manifest_digest must be sha256:<64 lowercase hex>")

    def payload(self) -> dict[str, Any]:
        values = {
            "artifact_id": self.artifact_id,
            "tenant_id": self.tenant_id,
            "source_observation_id": self.source_observation_id,
            "sha256": self.sha256,
            "byte_size": self.byte_size,
            "media_type": self.media_type,
            "collected_at": self.collected_at,
            "collector_id": self.collector_id,
            "source_target": self.source_target,
            "source_asset_id": self.source_asset_id,
            "redaction_state": self.redaction_state,
            "redaction_version": self.redaction_version,
            "protection_state": self.protection_state,
            "encryption_state": self.encryption_state,
            "signer_state": self.signer_state,
            "integrity_state": self.integrity_state,
            "retention_class": self.retention_class,
            "retention_expires_at": self.retention_expires_at,
            "protected_original_authorization_ref": self.protected_original_authorization_ref,
            "original_relative_path": self.original_relative_path,
            "derivative_relative_path": self.derivative_relative_path,
            "derivative_artifact_id": self.derivative_artifact_id,
            "derivative_sha256": self.derivative_sha256,
            "derivative_size": self.derivative_size,
            "schema_version": self.schema_version,
            "metadata": dict(self.metadata),
        }
        return _canonical_manifest_payload(values)

    def to_dict(self) -> dict[str, Any]:
        values = self.payload()
        values["manifest_digest"] = self.manifest_digest
        return values

    def verify(self) -> None:
        if _manifest_digest(self.to_dict()) != self.manifest_digest:
            raise ArtifactIntegrityError("artifact manifest integrity check failed")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ArtifactManifest":
        if not isinstance(value, Mapping):
            raise ArtifactIntegrityError("artifact manifest must be an object")
        try:
            manifest = cls(**dict(value))
        except (TypeError, ValueError, KeyError) as exc:
            raise ArtifactIntegrityError("artifact manifest is malformed") from exc
        manifest.verify()
        return manifest


@dataclass(frozen=True)
class StoredArtifact:
    manifest: ArtifactManifest
    derivative: bytes


class EvidenceCustodyStore:
    """Tenant-contained, integrity-checked local artifact store."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        tenant_id: str = "default",
        *,
        audit_sink: Callable[[Mapping[str, Any]], None] | None = None,
        redaction_version: str = REDACTION_VERSION,
        redactor: Callable[[str], str] | None = None,
        create: bool = True,
    ) -> None:
        self.root = Path(root)
        self.tenant_id = _id(tenant_id, "tenant_id")
        self.redaction_version = _text(redaction_version, "redaction_version", required=True, limit=100) or REDACTION_VERSION
        self.audit_sink = audit_sink
        # Keep the hook for compatibility with existing adapters, but the
        # emergency redactor is always applied as the final pass below. A
        # custom hook may add masking; it cannot disable central masking.
        self.redactor = redactor or (lambda value: value)
        try:
            directory_boundary = (
                ensure_private_directory
                if create
                else validate_private_directory_readonly
            )
            directory_boundary(self.root)
            directory_boundary(self._tenant_root())
        except (ArtifactBoundaryError, OSError) as exc:
            raise CustodyError("artifact custody root is unavailable") from exc

    def _tenant_token(self) -> str:
        return hashlib.sha256(self.tenant_id.encode("utf-8")).hexdigest()

    def _tenant_root(self) -> Path:
        return self.root / "tenants" / self._tenant_token()

    def _artifact_dir(self, artifact_id: str) -> Path:
        # Artifact IDs are generated by this class; still validate every path
        # supplied by a caller so traversal cannot reach the filesystem.
        safe = _artifact_id(artifact_id)
        return self._tenant_root() / "artifacts" / safe

    def _manifest_path(self, artifact_id: str) -> Path:
        return self._artifact_dir(artifact_id) / "manifest.json"

    def _derivative_path(self, artifact_id: str) -> Path:
        return self._artifact_dir(artifact_id) / "derivative.bin"

    def _original_path(self, artifact_id: str) -> Path:
        return self._artifact_dir(artifact_id) / "original.bin"

    def _audit(self, event: str, manifest: ArtifactManifest, **extra: Any) -> None:
        if self.audit_sink is None:
            return
        payload: dict[str, Any] = {
            "event": event,
            "tenant_id": manifest.tenant_id,
            "artifact_id": manifest.artifact_id,
            "source_observation_id": manifest.source_observation_id,
            "manifest_digest": manifest.manifest_digest,
        }
        payload.update({str(key): redact_value(value) for key, value in extra.items()})
        self.audit_sink(payload)

    def _derivative(self, payload: bytes, media_type: str) -> bytes:
        """Generate a redacted derivative before ordinary access.

        Text and JSON are redacted as UTF-8.  Binary media is represented by a
        deterministic, content-free receipt.  Returning binary input as its
        own "derivative" would expose the protected bytes through the default
        read path.
        """
        normalized_media_type = media_type.split(";", 1)[0].strip().lower()
        if normalized_media_type.startswith("text/") or "json" in normalized_media_type or "xml" in normalized_media_type or "javascript" in normalized_media_type:
            candidate = self.redactor(payload.decode("utf-8", errors="replace"))
            # Work Package 007's emergency redaction remains mandatory,
            # including when a caller supplied a custom hook.
            return redact_text(candidate).encode("utf-8")
        withheld = {
            "byte_size": len(payload),
            "media_type": normalized_media_type or "application/octet-stream",
            "sha256": _digest(payload),
            "state": "binary_withheld",
        }
        return json.dumps(
            withheld,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    def _write_manifest(self, manifest: ArtifactManifest) -> None:
        encoded = json.dumps(manifest.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        atomic_write_bytes(self._manifest_path(manifest.artifact_id), encoded, mode=0o600)

    def _load_manifest(self, artifact_id: str) -> ArtifactManifest:
        try:
            raw = read_verified_regular_file(self._manifest_path(artifact_id), require_owner_only_mode=True)
        except (ArtifactBoundaryError, FileNotFoundError, OSError) as exc:
            raise ArtifactNotFound("artifact manifest is unavailable") from exc
        try:
            value = json.loads(raw.decode("utf-8"))
            manifest = ArtifactManifest.from_dict(value)
        except (UnicodeDecodeError, json.JSONDecodeError, CustodyError) as exc:
            raise ArtifactIntegrityError("artifact manifest failed verification") from exc
        if manifest.tenant_id != self.tenant_id or manifest.artifact_id != _artifact_id(artifact_id):
            raise ArtifactScopeError("artifact is outside the requested tenant")
        return manifest

    def _verify_bytes(self, path: Path, expected: str, expected_size: int, *, label: str) -> bytes:
        try:
            payload = read_verified_regular_file(path, require_owner_only_mode=True)
        except (ArtifactBoundaryError, FileNotFoundError, OSError) as exc:
            raise ArtifactIntegrityError(f"{label} artifact is unavailable") from exc
        if len(payload) != expected_size or _digest(payload) != expected:
            raise ArtifactIntegrityError(f"{label} artifact integrity check failed")
        return payload

    def store_artifact(
        self,
        content: bytes | bytearray | memoryview | str,
        *,
        source_observation_id: str,
        collector_id: str,
        media_type: str | None = None,
        source_target: str | None = None,
        source_asset_id: str | None = None,
        redaction_required: bool = True,
        retain_original: bool = False,
        protected_original_authorization_ref: str | None = None,
        retention_class: str = "standard",
        retention_expires_at: datetime | str | None = None,
        metadata: Mapping[str, Any] | None = None,
        artifact_id: str | None = None,
    ) -> ArtifactManifest:
        """Atomically store bytes and return an integrity-bound manifest."""
        payload = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        observation_id = _id(source_observation_id, "source_observation_id")
        collector = _id(collector_id, "collector_id")
        artifact = _artifact_id(artifact_id) if artifact_id is not None else "artifact:" + uuid.uuid4().hex
        media = _text(media_type or mimetypes.guess_type("artifact.bin")[0] or "application/octet-stream", "media_type", required=True, limit=200) or "application/octet-stream"
        # Keep the historical argument for source compatibility, but custody
        # never permits a caller to make raw bytes the ordinary derivative.
        # Text is centrally redacted and binary input becomes a content-free
        # receipt regardless of the legacy opt-out value.
        _ = redaction_required
        redaction_applied = True
        derivative = self._derivative(payload, media)
        if retain_original and not protected_original_authorization_ref:
            raise ArtifactAccessDenied(
                "retaining a protected original requires an explicit authorization reference"
            )
        if protected_original_authorization_ref is not None:
            protected_original_authorization_ref = _authorization_ref(
                protected_original_authorization_ref,
                "protected_original_authorization_ref",
            )
        original_path = self._original_path(artifact) if retain_original else None
        derivative_path = self._derivative_path(artifact)
        manifest_path = self._manifest_path(artifact)
        artifact_dir = self._artifact_dir(artifact)
        derivative_id = "artifact:" + uuid.uuid4().hex
        created: list[Path] = []
        try:
            # Artifact IDs are immutable namespace entries.  Never replace a
            # prior derivative/original/manifest when a caller retries with an
            # existing ID; a retry must use a new artifact identity.
            ensure_private_directory(artifact_dir.parent)
            if artifact_dir.exists():
                raise CustodyError("artifact identity already exists")
            artifact_dir.mkdir(mode=0o700)
            if retain_original:
                created.append(original_path)  # type: ignore[arg-type]
                atomic_write_bytes(original_path, payload, mode=0o400)  # type: ignore[arg-type]
            created.append(derivative_path)
            atomic_write_bytes(derivative_path, derivative, mode=0o600)
            primary_payload = payload if retain_original else derivative
            manifest_values: dict[str, Any] = {
                "artifact_id": artifact,
                "tenant_id": self.tenant_id,
                "source_observation_id": observation_id,
                # The primary digest always describes bytes that were actually
                # retained.  For a protected original it binds original.bin;
                # otherwise it binds the only retained bytes, derivative.bin.
                "sha256": _digest(primary_payload),
                "byte_size": len(primary_payload),
                "media_type": media,
                "collected_at": _iso(_utc_now()),
                "collector_id": collector,
                # ArtifactManifest applies the same mandatory redaction.  Use
                # the normalized value before hashing so secret-bearing
                # source metadata cannot invalidate its own manifest.
                "source_target": _text(source_target, "source_target", limit=2_000),
                "source_asset_id": source_asset_id,
                "redaction_state": "redacted" if redaction_applied else "not_applicable",
                "redaction_version": self.redaction_version,
                "protection_state": "protected_original" if retain_original else "not_retained",
                "encryption_state": "owner_only_local",
                "signer_state": "unsigned_integrity_digest",
                "integrity_state": "verified",
                "retention_class": retention_class,
                "retention_expires_at": _iso(retention_expires_at),
                "protected_original_authorization_ref": protected_original_authorization_ref,
                "original_relative_path": str(original_path.relative_to(self.root)) if original_path is not None else None,
                "derivative_relative_path": str(derivative_path.relative_to(self.root)),
                "derivative_artifact_id": derivative_id,
                "derivative_sha256": _digest(derivative),
                "derivative_size": len(derivative),
                "schema_version": EVIDENCE_SCHEMA_VERSION,
                "metadata": _metadata(metadata),
            }
            manifest_values["manifest_digest"] = _manifest_digest(manifest_values)
            manifest = ArtifactManifest(**manifest_values)
            created.append(manifest_path)
            self._write_manifest(manifest)
            # Read-back verification closes the write transaction from the
            # filesystem's perspective before the manifest is returned.
            self._load_manifest(artifact)
            self._verify_bytes(derivative_path, manifest.derivative_sha256, manifest.derivative_size, label="derivative")
            if retain_original:
                self._verify_bytes(original_path, manifest.sha256, manifest.byte_size, label="original")  # type: ignore[arg-type]
            return manifest
        except Exception as exc:
            for path in reversed(created):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            try:
                if artifact_dir.exists() and not any(artifact_dir.iterdir()):
                    artifact_dir.rmdir()
            except OSError:
                pass
            if isinstance(exc, CustodyError):
                raise
            if isinstance(exc, ArtifactBoundaryError):
                raise ArtifactTransactionError("artifact write failed; no orphan was retained") from exc
            raise ArtifactTransactionError("artifact write failed; no orphan was retained") from exc

    # Friendly names used by adapters and tests.
    put = store_artifact
    persist = store_artifact

    def get_manifest(self, artifact_id: str) -> ArtifactManifest:
        return self._load_manifest(artifact_id)

    def verify(self, artifact_id: str) -> ArtifactManifest:
        manifest = self._load_manifest(artifact_id)
        manifest.verify()
        self._verify_bytes(self._derivative_path(manifest.artifact_id), manifest.derivative_sha256, manifest.derivative_size, label="derivative")
        if manifest.original_relative_path is not None:
            self._verify_bytes(self._original_path(manifest.artifact_id), manifest.sha256, manifest.byte_size, label="original")
        return manifest

    verify_artifact = verify

    def read(
        self,
        artifact_id: str,
        *,
        include_original: bool = False,
        authorization: ProtectedOriginalAuthorization | None = None,
        actor_id: str | None = None,
    ) -> bytes:
        manifest = self.verify(artifact_id)
        if not include_original:
            payload = self._verify_bytes(self._derivative_path(manifest.artifact_id), manifest.derivative_sha256, manifest.derivative_size, label="derivative")
            self._audit("artifact.read.redacted", manifest, actor_id=actor_id)
            return payload
        if manifest.original_relative_path is None or manifest.protection_state != "protected_original":
            raise ArtifactAccessDenied("protected original is not retained")
        if self.audit_sink is None:
            raise ArtifactAccessDenied(
                "protected-original access requires an active audit sink"
            )
        authorized = bool(
            isinstance(authorization, ProtectedOriginalAuthorization)
            and authorization.tenant_id == self.tenant_id
            and authorization.artifact_id == manifest.artifact_id
            and authorization.authorization_ref
            == manifest.protected_original_authorization_ref
            and authorization.valid_now()
        )
        if not authorized:
            self._audit("artifact.read.original.denied", manifest, actor_id=actor_id)
            raise ArtifactAccessDenied("exact protected-original authorization is required")
        assert isinstance(authorization, ProtectedOriginalAuthorization)
        # Audit before releasing bytes.  Sink failures propagate so a caller
        # can never receive a protected original without a durable audit event.
        self._audit(
            "artifact.read.original.authorized",
            manifest,
            actor_id=authorization.operator_id,
            reason=authorization.reason,
        )
        payload = self._verify_bytes(self._original_path(manifest.artifact_id), manifest.sha256, manifest.byte_size, label="original")
        return payload

    read_artifact = read

    def export(self, artifact_id: str, *, authorization: ProtectedOriginalAuthorization | None = None) -> bytes:
        """Export follows the ordinary redacted path unless explicitly authorized."""
        return self.read(artifact_id, include_original=authorization is not None, authorization=authorization)

    def rollback_artifact(self, artifact_id: str, *, expected_manifest_digest: str) -> None:
        """Compensate a failed database transaction for one newly staged artifact.

        This is intentionally narrower than :meth:`delete`: the caller must
        present the exact manifest digest returned by the same write, and the
        manifest/bytes are verified before any path is removed.  It exists for
        the explicit filesystem-plus-canonical transaction adapter; ordinary
        callers still have no destructive delete path.
        """
        manifest = self.verify(artifact_id)
        if manifest.manifest_digest != expected_manifest_digest:
            raise ArtifactIntegrityError("rollback manifest binding does not match")
        artifact_dir = self._artifact_dir(manifest.artifact_id)
        paths = [self._manifest_path(manifest.artifact_id), self._derivative_path(manifest.artifact_id)]
        if manifest.original_relative_path is not None:
            paths.append(self._original_path(manifest.artifact_id))
        # Refuse to remove an unexpected entry or any symlink.  This keeps a
        # failed compensation fail-closed instead of broadening into a path
        # cleanup primitive.
        try:
            entries = list(artifact_dir.iterdir())
        except OSError as exc:
            raise ArtifactTransactionError("artifact rollback boundary is unavailable") from exc
        expected_paths = {path.resolve(strict=False) for path in paths}
        if any(entry.is_symlink() or entry.resolve(strict=False) not in expected_paths for entry in entries):
            raise ArtifactTransactionError("artifact rollback encountered an unexpected entry")
        self._audit("artifact.rollback", manifest)
        try:
            for path in paths:
                path.unlink(missing_ok=False)
            artifact_dir.rmdir()
        except (OSError, FileNotFoundError) as exc:
            raise ArtifactTransactionError("artifact rollback did not complete") from exc

    def delete(self, artifact_id: str, *, authorization: str | None = None) -> None:
        """Refuse destructive deletion; retention is an explicit DB workflow."""
        manifest = self._load_manifest(artifact_id)
        self._audit("artifact.delete.denied", manifest, authorization_ref=authorization)
        raise CustodyError("artifact deletion is unsupported; preserve lineage or use retention workflow")


def make_original_authorization(
    *,
    tenant_id: str,
    artifact_id: str,
    authorization_ref: str,
    operator_id: str,
    reason: str,
    expires_at: datetime | str | None = None,
) -> ProtectedOriginalAuthorization:
    return ProtectedOriginalAuthorization(
        tenant_id=tenant_id,
        artifact_id=artifact_id,
        authorization_ref=_authorization_ref(authorization_ref),
        operator_id=operator_id,
        reason=reason,
        expires_at=_iso(expires_at),
    )


__all__ = [
    "ArtifactAccessDenied",
    "ArtifactIntegrityError",
    "ArtifactManifest",
    "ArtifactNotFound",
    "ArtifactScopeError",
    "ArtifactTransactionError",
    "CustodyError",
    "EVIDENCE_SCHEMA_VERSION",
    "EvidenceCustodyStore",
    "ProtectedOriginalAuthorization",
    "REDACTION_VERSION",
    "StoredArtifact",
    "make_original_authorization",
]
