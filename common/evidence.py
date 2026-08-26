"""Evidence collection dataclass and helpers."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from common.artifact_io import (
    ArtifactBoundaryError,
    _unlink_if_descriptor_entry,
    _wipe_owned_descriptor,
    atomic_write_bytes,
    committed_file_is_stable,
    descriptor_entry_is_stable,
    directory_descriptor_is_owner_controlled,
    directory_descriptor_matches,
    ensure_private_directory,
    open_private_directory,
    prepare_owner_controlled_directory,
    read_verified_regular_file,
)
from common.redaction import redact_text

# Task 102 custody is kept in a focused module so legacy ``Evidence`` callers
# remain source-compatible.  Re-export the typed custody API here because
# existing engines import their evidence boundary from this module.
from common.evidence_custody import (  # noqa: E402
    ArtifactAccessDenied,
    ArtifactIntegrityError,
    ArtifactManifest,
    ArtifactNotFound,
    ArtifactScopeError,
    ArtifactTransactionError,
    CustodyError,
    EVIDENCE_SCHEMA_VERSION,
    EvidenceCustodyStore,
    ProtectedOriginalAuthorization,
    REDACTION_VERSION,
    make_original_authorization,
)

EvidenceAuthorizationError = ArtifactAccessDenied
EvidenceIntegrityError = ArtifactIntegrityError
EvidenceManifest = ArtifactManifest
EvidenceCustodyError = CustodyError
_SAFE_FINDING_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SAFE_SHA256_REFERENCE = re.compile(r"sha256:[0-9a-f]{64}")
_SAFE_DEDUP_KEY = re.compile(r"finding-v[0-9]+:[0-9a-f]{64}")
_MAX_ORDINARY_DERIVATIVE_CHARS = 20_000
_FORBIDDEN_ORDINARY_EVIDENCE_KEYS = frozenset(
    {
        "request_raw",
        "response_raw",
        "screenshot_path",
        "console_capture_path",
        "pcap_path",
        "original_relative_path",
        "derivative_relative_path",
    }
)
_ORDINARY_FINDING_FIELDS = frozenset(
    {
        "confidence",
        "cvss_score",
        "cvss_v31_score",
        "cvss_v31_vector",
        "cvss_v40_score",
        "cvss_v40_vector",
        "dedup_key",
        "description",
        "discovered_at",
        "finding_key",
        "id",
        "maturity",
        "mitre",
        "mitre_attack",
        "module",
        "operator_confirmed",
        "port",
        "proof_type",
        "references",
        "remediation",
        "reproduction_steps",
        "service",
        "severity",
        "status",
        "tags",
        "target",
        "timestamp",
        "title",
        "url",
        "verification_state",
        "vpr",
        "vpr_priority",
        "vpr_score",
    }
)


class EvidenceCaptureError(ValueError):
    """A transient evidence bundle could not be consumed safely."""


@dataclass(frozen=True)
class CapturedEvidenceArtifact:
    """One immutable artifact value produced by a one-shot capture.

    These values may only cross into the custody service.  They are never a
    finding, API, event, report, or export representation.
    """

    kind: str
    content: bytes
    media_type: str
    metadata: dict[str, Any] = field(default_factory=dict)


def ordinary_evidence_projection(value: Any) -> dict[str, Any]:
    """Return the only evidence shape ordinary consumers may render.

    Missing or legacy inline evidence becomes an explicit unavailable state.
    A value claiming to be persisted is validated strictly so a malformed or
    raw-bearing projection cannot be rendered as trusted custody output.
    """
    unavailable = {"observations": [], "state": "unavailable"}
    if not isinstance(value, Mapping) or value.get("state") != "persisted":
        return unavailable

    def _reject_forbidden(item: Any) -> None:
        pending = [item]
        visited: set[int] = set()
        inspected = 0
        while pending:
            current = pending.pop()
            if not isinstance(current, (Mapping, list, tuple)):
                continue
            identity = id(current)
            if identity in visited:
                continue
            visited.add(identity)
            inspected += 1
            if inspected > 25_000:
                raise EvidenceCaptureError(
                    "persisted evidence projection is too complex"
                )
            if isinstance(current, Mapping):
                for raw_key, child in current.items():
                    if str(raw_key) in _FORBIDDEN_ORDINARY_EVIDENCE_KEYS:
                        raise EvidenceCaptureError(
                            "persisted evidence projection contains raw or path data"
                        )
                    pending.append(child)
            else:
                pending.extend(current)

    def _text_value(
        item: Any,
        field_name: str,
        *,
        limit: int = 2_000,
        allow_empty: bool = False,
    ) -> str:
        if (
            not isinstance(item, str)
            or (not allow_empty and not item)
            or len(item) > limit
        ):
            raise EvidenceCaptureError(
                f"persisted evidence {field_name} is invalid"
            )
        return redact_text(item)

    def _digest_value(item: Any, field_name: str, *, optional: bool = False) -> str | None:
        if optional and item is None:
            return None
        if not isinstance(item, str) or _SAFE_SHA256_REFERENCE.fullmatch(item) is None:
            raise EvidenceCaptureError(
                f"persisted evidence {field_name} is invalid"
            )
        return item

    def _size_value(item: Any, field_name: str) -> int:
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise EvidenceCaptureError(
                f"persisted evidence {field_name} is invalid"
            )
        return item

    _reject_forbidden(value)
    finding_id = _text_value(value.get("finding_id"), "finding_id", limit=300)
    raw_observations = value.get("observations")
    if (
        not isinstance(raw_observations, list)
        or not raw_observations
        or len(raw_observations) > 10_000
    ):
        raise EvidenceCaptureError(
            "persisted evidence observations are invalid"
        )
    observations: list[dict[str, Any]] = []
    observation_fields = (
        "asset_id",
        "check_id",
        "collection_status",
        "engagement_id",
        "identity_ref",
        "job_id",
        "location",
        "module_execution_id",
        "observed_at",
        "parameter",
        "proof_type",
        "route",
    )
    for raw_observation in raw_observations:
        if not isinstance(raw_observation, Mapping):
            raise EvidenceCaptureError(
                "persisted evidence observation is invalid"
            )
        observation_id = _text_value(
            raw_observation.get("observation_id"),
            "observation_id",
            limit=300,
        )
        raw_artifacts = raw_observation.get("artifacts")
        if not isinstance(raw_artifacts, list) or not raw_artifacts or len(raw_artifacts) > 256:
            raise EvidenceCaptureError(
                "persisted evidence artifacts are invalid"
            )
        artifacts: list[dict[str, Any]] = []
        for raw_artifact in raw_artifacts:
            if not isinstance(raw_artifact, Mapping):
                raise EvidenceCaptureError(
                    "persisted evidence artifact is invalid"
                )
            artifacts.append(
                {
                    "artifact_id": _text_value(
                        raw_artifact.get("artifact_id"),
                        "artifact_id",
                        limit=300,
                    ),
                    "capture_kind": _text_value(
                        raw_artifact.get("capture_kind"),
                        "capture_kind",
                        limit=100,
                    ),
                    "derivative": redact_text(
                        _text_value(
                            raw_artifact.get("derivative"),
                            "derivative",
                            limit=_MAX_ORDINARY_DERIVATIVE_CHARS,
                            allow_empty=True,
                        )
                    ),
                    "derivative_sha256": _digest_value(
                        raw_artifact.get("derivative_sha256"),
                        "derivative_sha256",
                    ),
                    "derivative_size": _size_value(
                        raw_artifact.get("derivative_size"),
                        "derivative_size",
                    ),
                    "integrity_state": _text_value(
                        raw_artifact.get("integrity_state"),
                        "integrity_state",
                        limit=100,
                    ),
                    "manifest_digest": _digest_value(
                        raw_artifact.get("manifest_digest"),
                        "manifest_digest",
                    ),
                    "media_type": _text_value(
                        raw_artifact.get("media_type"),
                        "media_type",
                        limit=200,
                    ),
                    "primary_sha256": _digest_value(
                        raw_artifact.get("primary_sha256"),
                        "primary_sha256",
                        optional=True,
                    ),
                    "primary_size": _size_value(
                        raw_artifact.get("primary_size"),
                        "primary_size",
                    ),
                    "redaction_state": _text_value(
                        raw_artifact.get("redaction_state"),
                        "redaction_state",
                        limit=100,
                    ),
                    "role": _text_value(
                        raw_artifact.get("role"),
                        "role",
                        limit=100,
                    ),
                    "sequence": _size_value(
                        raw_artifact.get("sequence"),
                        "sequence",
                    ),
                }
            )
        observation: dict[str, Any] = {
            "artifacts": artifacts,
            "observation_id": observation_id,
        }
        for field_name in observation_fields:
            field_value = raw_observation.get(field_name)
            observation[field_name] = (
                None
                if field_value is None
                else _text_value(field_value, field_name, limit=1_000)
            )
        observations.append(observation)
    return {
        "finding_id": finding_id,
        "observations": observations,
        "state": "persisted",
    }


def ordinary_finding_projection(value: Any) -> dict[str, Any]:
    """Return a bounded finding projection for UI, report, and export use."""
    if not isinstance(value, Mapping):
        serializer = getattr(value, "to_dict", None)
        if not callable(serializer):
            raise EvidenceCaptureError(
                "ordinary finding projection must be an object"
            )
        value = serializer()
    if not isinstance(value, Mapping):
        raise EvidenceCaptureError("ordinary finding projection must be an object")
    evidence = ordinary_evidence_projection(value.get("evidence"))
    text_limits = {
        "confidence": 100,
        "cvss_v31_vector": 500,
        "cvss_v40_vector": 500,
        "description": 8_000,
        "discovered_at": 100,
        "finding_key": 300,
        "id": 300,
        "maturity": 100,
        "module": 300,
        "proof_type": 100,
        "remediation": 8_000,
        "service": 500,
        "status": 100,
        "target": 2_000,
        "timestamp": 100,
        "title": 500,
        "url": 2_000,
        "verification_state": 100,
        "vpr": 100,
        "vpr_priority": 100,
    }
    sequence_limits = {
        "mitre": (256, 500),
        "mitre_attack": (256, 500),
        "references": (256, 2_000),
        "reproduction_steps": (256, 4_000),
        "tags": (256, 500),
    }
    numeric_fields = {
        "cvss_score",
        "cvss_v31_score",
        "cvss_v40_score",
        "vpr_score",
    }
    rendered: dict[str, Any] = {}
    for key in sorted(_ORDINARY_FINDING_FIELDS):
        if key not in value or key in {"severity", "dedup_key"}:
            continue
        item = value[key]
        if key in text_limits:
            if item is None:
                rendered[key] = None
            elif not isinstance(item, str) or len(item) > text_limits[key]:
                raise EvidenceCaptureError(
                    f"ordinary finding {key} is invalid"
                )
            else:
                rendered[key] = redact_text(item)
        elif key in sequence_limits:
            max_items, max_item_length = sequence_limits[key]
            if item is None:
                rendered[key] = []
            elif (
                not isinstance(item, (list, tuple))
                or len(item) > max_items
                or any(
                    not isinstance(entry, str)
                    or len(entry) > max_item_length
                    for entry in item
                )
            ):
                raise EvidenceCaptureError(
                    f"ordinary finding {key} is invalid"
                )
            else:
                rendered[key] = [redact_text(entry) for entry in item]
        elif key in numeric_fields:
            if item is None:
                rendered[key] = None
            elif (
                isinstance(item, bool)
                or not isinstance(item, (int, float))
                or not math.isfinite(float(item))
            ):
                raise EvidenceCaptureError(
                    f"ordinary finding {key} is invalid"
                )
            else:
                rendered[key] = item
        elif key == "port":
            if item is None:
                rendered[key] = None
            elif (
                isinstance(item, bool)
                or not isinstance(item, int)
                or not 0 <= item <= 65_535
            ):
                raise EvidenceCaptureError("ordinary finding port is invalid")
            else:
                rendered[key] = item
        elif key == "operator_confirmed":
            if not isinstance(item, bool):
                raise EvidenceCaptureError(
                    "ordinary finding operator_confirmed is invalid"
                )
            rendered[key] = item
        else:
            raise EvidenceCaptureError(f"ordinary finding {key} is unsupported")

    if "dedup_key" in value:
        dedup_key = value.get("dedup_key")
        if dedup_key is None:
            rendered["dedup_key"] = None
        elif not isinstance(dedup_key, str) or _SAFE_DEDUP_KEY.fullmatch(
            dedup_key
        ) is None:
            raise EvidenceCaptureError("ordinary finding dedup_key is invalid")
        else:
            # A validated identity digest is a reference, not secret material.
            rendered["dedup_key"] = dedup_key
    if "severity" in value:
        raw_severity = value.get("severity")
        if not isinstance(raw_severity, str):
            raise EvidenceCaptureError("ordinary finding severity is invalid")
        severity = raw_severity.strip().lower()
        severity_labels = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "informational": "Informational",
            "info": "Informational",
        }
        if severity not in severity_labels:
            raise EvidenceCaptureError("ordinary finding severity is invalid")
        rendered["severity"] = severity_labels[severity]
    if evidence["state"] == "persisted" and rendered.get("id") != evidence.get(
        "finding_id"
    ):
        raise EvidenceCaptureError(
            "ordinary finding evidence belongs to another finding"
        )
    rendered["evidence"] = evidence
    return rendered


def ordinary_evidence_artifacts(value: Any) -> list[dict[str, Any]]:
    """Flatten verified derivative records for ordinary presentation."""
    projection = ordinary_evidence_projection(value)
    artifacts: list[dict[str, Any]] = []
    for observation in projection.get("observations", []):
        for artifact in observation.get("artifacts", []):
            artifacts.append(
                {
                    **artifact,
                    "observation_id": observation["observation_id"],
                }
            )
    return artifacts


def _ensure_artifact_directory(path: Path) -> None:
    """Validate/create a no-follow private directory chain."""
    ensure_private_directory(path)


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    written = 0
    try:
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("artifact write made no progress")
            written += count
    finally:
        view.release()


def _owner_only_write_bytes(path: Path, content: bytes) -> None:
    """Atomically replace one artifact through a pinned no-follow parent."""
    atomic_write_bytes(path, content, mode=0o600)


def _owner_only_write(path: Path, content: str) -> None:
    """Create or replace a text artifact with mode 0600."""
    _owner_only_write_bytes(path, content.encode("utf-8"))


_EVIDENCE_REF_PREFIX = "sha256:"
_EVIDENCE_OBJECT_SUFFIX = ".evidence"


def _evidence_digest(content: bytes) -> str:
    """Return the canonical content-addressed reference for evidence bytes."""
    return _EVIDENCE_REF_PREFIX + hashlib.sha256(content).hexdigest()


def _immutable_evidence_exists_at(
    directory_fd: int,
    object_name: str,
    evidence_ref: str,
) -> bool:
    """Validate one unaliased immutable object relative to a pinned store."""
    descriptor = -1
    payload = bytearray()
    try:
        descriptor = os.open(
            object_name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
            or stat.S_IMODE(metadata.st_mode) != stat.S_IRUSR
        ):
            return False
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            payload.extend(chunk)
        return (
            _evidence_digest(bytes(payload)) == evidence_ref
            and descriptor_entry_is_stable(
                descriptor,
                directory_fd,
                object_name,
                initial=metadata,
                expected_mode=stat.S_IRUSR,
                expected_size=len(payload),
            )
        )
    except OSError:
        return False
    finally:
        if payload:
            payload[:] = b"\x00" * len(payload)
            payload.clear()
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except Exception:
                pass


def persist_immutable_evidence(content: bytes | str, store_dir: Path) -> str:
    """Persist owner-only content-addressed evidence without replacing existing data."""
    payload = content.encode("utf-8") if isinstance(content, str) else bytes(content)
    evidence_ref = _evidence_digest(payload)
    digest = evidence_ref.removeprefix(_EVIDENCE_REF_PREFIX)
    object_name = f"{digest}{_EVIDENCE_OBJECT_SUFFIX}"
    directory_fd = -1
    temporary_name = f".forge-evidence-{secrets.token_hex(16)}"
    descriptor = -1
    object_created = False
    acknowledged = False
    try:
        directory_fd = open_private_directory(store_dir, create=True)
        if not prepare_owner_controlled_directory(directory_fd):
            raise ArtifactBoundaryError(
                "artifact directory must be owner-controlled"
            )
        descriptor = os.open(
            temporary_name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o400,
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            raise ArtifactBoundaryError(
                "evidence temporary must be one owner-controlled regular file"
            )
        _write_all(descriptor, payload)
        os.fchmod(descriptor, stat.S_IRUSR)
        os.fsync(descriptor)
        if (
            not directory_descriptor_is_owner_controlled(directory_fd)
            or not directory_descriptor_matches(directory_fd, store_dir)
        ):
            raise ArtifactBoundaryError("artifact directory changed during write")
        try:
            os.link(
                temporary_name,
                object_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            object_created = True
        except FileExistsError:
            if not _immutable_evidence_exists_at(
                directory_fd,
                object_name,
                evidence_ref,
            ):
                raise ValueError(
                    "existing evidence object failed content-address validation"
                ) from None
            # The descriptor is the inode created by this call with O_EXCL, so
            # it is safe to wipe even when a hardlink appeared after the
            # initial link-count check.  Reopen-by-name cleanup cannot make
            # that ownership claim and therefore remains more conservative.
            _wipe_owned_descriptor(descriptor)
            _unlink_if_descriptor_entry(
                directory_fd,
                temporary_name,
                descriptor,
            )
            try:
                os.close(descriptor)
            except Exception:
                pass
            descriptor = -1
            if (
                not directory_descriptor_is_owner_controlled(directory_fd)
                or not directory_descriptor_matches(directory_fd, store_dir)
                or not _immutable_evidence_exists_at(
                    directory_fd,
                    object_name,
                    evidence_ref,
                )
            ):
                raise ValueError(
                    "existing evidence object failed content-address validation"
                ) from None
        if object_created:
            _unlink_if_descriptor_entry(
                directory_fd,
                temporary_name,
                descriptor,
            )
        try:
            os.fsync(directory_fd)
        except Exception:
            # The immutable link has committed; directory fsync is not portable.
            pass
        if object_created and (
            not committed_file_is_stable(
                descriptor,
                directory_fd,
                object_name,
                store_dir,
                expected_mode=stat.S_IRUSR,
                expected_size=len(payload),
            )
            or not _immutable_evidence_exists_at(
                directory_fd,
                object_name,
                evidence_ref,
            )
            or not committed_file_is_stable(
                descriptor,
                directory_fd,
                object_name,
                store_dir,
                expected_mode=stat.S_IRUSR,
                expected_size=len(payload),
            )
        ):
            raise ArtifactBoundaryError("immutable evidence changed during commit")
        if not object_created and not _immutable_evidence_exists_at(
            directory_fd,
            object_name,
            evidence_ref,
        ):
            raise ValueError(
                "existing evidence object failed content-address validation"
            ) from None
        if (
            not directory_descriptor_is_owner_controlled(directory_fd)
            or not directory_descriptor_matches(directory_fd, store_dir)
        ):
            raise ArtifactBoundaryError("artifact directory changed during write")
        if not object_created and not _immutable_evidence_exists_at(
            directory_fd,
            object_name,
            evidence_ref,
        ):
            raise ValueError(
                "existing evidence object failed content-address validation"
            ) from None
        if (
            not directory_descriptor_is_owner_controlled(directory_fd)
            or not directory_descriptor_matches(directory_fd, store_dir)
        ):
            raise ArtifactBoundaryError("artifact directory changed during write")
        acknowledged = True
    except (ArtifactBoundaryError, ValueError):
        raise
    except Exception:
        raise ArtifactBoundaryError("immutable evidence write failed") from None
    finally:
        if not acknowledged and descriptor >= 0 and directory_fd >= 0:
            # This descriptor is always the O_EXCL temporary inode.  If link(2)
            # committed before a namespace or alias race was observed, wiping it
            # clears every surviving late alias before removing our entries.
            _wipe_owned_descriptor(descriptor)
            _unlink_if_descriptor_entry(
                directory_fd,
                temporary_name,
                descriptor,
            )
            _unlink_if_descriptor_entry(
                directory_fd,
                object_name,
                descriptor,
            )
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except Exception:
                pass
            descriptor = -1
        if directory_fd >= 0:
            try:
                os.close(directory_fd)
            except Exception:
                pass
    return evidence_ref


def immutable_evidence_exists(evidence_ref: str, store_dir: Path) -> bool:
    """Validate that a reference resolves to persisted bytes with the same digest."""
    normalized = str(evidence_ref or "").strip().lower()
    if not normalized.startswith(_EVIDENCE_REF_PREFIX) or len(normalized) != 71:
        return False
    digest = normalized.removeprefix(_EVIDENCE_REF_PREFIX)
    if any(char not in "0123456789abcdef" for char in digest):
        return False
    object_name = f"{digest}{_EVIDENCE_OBJECT_SUFFIX}"
    directory_fd = -1
    try:
        directory_fd = open_private_directory(
            store_dir,
            create=False,
        )
        return (
            _immutable_evidence_exists_at(
                directory_fd,
                object_name,
                normalized,
            )
            and directory_descriptor_matches(directory_fd, store_dir)
        )
    except (ArtifactBoundaryError, FileNotFoundError, OSError):
        return False
    finally:
        if directory_fd >= 0:
            try:
                os.close(directory_fd)
            except Exception:
                pass



# Friendly aliases used by adapters and acceptance fixtures.
# Keep the legacy ``Evidence`` dataclass in this module, but expose exactly one
# custody implementation.  The focused module owns tenant namespaces,
# append-only manifests, redacted/default reads, and protected-original
# authorization; the compatibility block above is intentionally not part of
# the public API.
EvidenceStore = EvidenceCustodyStore
verify_evidence_manifest = EvidenceCustodyStore.verify


@dataclass
class Evidence:
    """Source-compatible, one-shot input to canonical evidence custody."""
    request_raw:          str | None = None   # Raw HTTP request
    response_raw:         str | None = None   # Raw HTTP response
    screenshot_path:      str | None = None   # PNG screenshot path
    console_capture_path: str | None = None   # Rich HTML console export path
    pcap_path:            str | None = None   # PCAP file path
    extra:                dict[str, Any] = field(default_factory=dict)
    _consumed:            bool = field(default=False, init=False, repr=False)

    _CAPTURE_FIELDS = frozenset(
        {
            "request_raw",
            "response_raw",
            "screenshot_path",
            "console_capture_path",
            "pcap_path",
            "extra",
        }
    )

    def __setattr__(self, name: str, value: Any) -> None:
        if (
            name in self._CAPTURE_FIELDS
            and getattr(self, "_consumed", False)
        ):
            raise EvidenceCaptureError("evidence capture has already been consumed")
        object.__setattr__(self, name, value)

    def _pending_kinds(self) -> list[str]:
        kinds: list[str] = []
        if self.request_raw is not None:
            kinds.append("request")
        if self.response_raw is not None:
            kinds.append("response")
        if self.screenshot_path:
            kinds.append("screenshot")
        if self.console_capture_path:
            kinds.append("console_capture")
        if self.pcap_path:
            kinds.append("pcap")
        if self.extra:
            kinds.append("structured_proof")
        return kinds

    def to_dict(self) -> dict[str, Any]:
        """Return content-free capture state for non-custody consumers."""
        kinds = [] if self._consumed else self._pending_kinds()
        return {
            "artifact_count": len(kinds),
            "capture_kinds": kinds,
            "state": "consumed" if self._consumed else ("pending_custody" if kinds else "empty"),
        }

    def consume(self) -> tuple[CapturedEvidenceArtifact, ...]:
        """Read all capture inputs exactly once, then discard their references.

        Caller-controlled file paths are read only through Forge's verified
        regular-file boundary.  A supplied but unreadable path fails the whole
        capture; it is never silently omitted from canonical lineage.
        """
        if self._consumed:
            raise EvidenceCaptureError("evidence capture has already been consumed")
        artifacts: list[CapturedEvidenceArtifact] = []
        try:
            if self.request_raw is not None:
                artifacts.append(
                    CapturedEvidenceArtifact(
                        kind="request",
                        content=self.request_raw.encode("utf-8"),
                        media_type="text/http; msgtype=request",
                    )
                )
            if self.response_raw is not None:
                artifacts.append(
                    CapturedEvidenceArtifact(
                        kind="response",
                        content=self.response_raw.encode("utf-8"),
                        media_type="text/http; msgtype=response",
                    )
                )
            for kind, path, media_type in (
                ("screenshot", self.screenshot_path, "image/png"),
                ("console_capture", self.console_capture_path, "text/html"),
                ("pcap", self.pcap_path, "application/vnd.tcpdump.pcap"),
            ):
                if not path:
                    continue
                try:
                    content = read_verified_regular_file(path)
                except (ArtifactBoundaryError, FileNotFoundError, OSError) as exc:
                    raise EvidenceCaptureError(
                        f"{kind} source failed the verified file boundary"
                    ) from exc
                artifacts.append(
                    CapturedEvidenceArtifact(
                        kind=kind,
                        content=content,
                        media_type=media_type,
                    )
                )
            if self.extra:
                try:
                    structured = json.dumps(
                        self.extra,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("utf-8")
                except (TypeError, ValueError) as exc:
                    raise EvidenceCaptureError(
                        "structured evidence must be JSON serializable"
                    ) from exc
                artifacts.append(
                    CapturedEvidenceArtifact(
                        kind="structured_proof",
                        content=structured,
                        media_type="application/json",
                    )
                )
            return tuple(artifacts)
        finally:
            object.__setattr__(self, "request_raw", None)
            object.__setattr__(self, "response_raw", None)
            object.__setattr__(self, "screenshot_path", None)
            object.__setattr__(self, "console_capture_path", None)
            object.__setattr__(self, "pcap_path", None)
            for value in self.extra.values():
                if isinstance(value, bytearray):
                    value[:] = b"\x00" * len(value)
                    value.clear()
            self.extra.clear()
            object.__setattr__(self, "_consumed", True)

    def _legacy_custody_payload(self) -> dict[str, Any]:
        """Return transient inputs only for the explicit legacy custody writer.

        This is intentionally private and must never feed an event, report,
        API, UI, or export.  It preserves Gate-0 fixture compatibility while
        ordinary ``to_dict`` remains content-free.
        """
        if self._consumed:
            raise EvidenceCaptureError("evidence capture has already been consumed")
        return {
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
            "screenshot_path": self.screenshot_path,
            "console_capture_path": self.console_capture_path,
            "pcap_path": self.pcap_path,
            "extra": self.extra,
        }

    def screenshot_as_base64(self) -> str | None:
        """Disable pre-custody original previews for ordinary consumers."""
        return None

    def console_capture_as_html(self) -> str | None:
        """Disable pre-custody console previews for ordinary consumers."""
        return None

    def has_screenshot(self) -> bool:
        """Return True if a screenshot file exists."""
        if not self.screenshot_path:
            return False
        try:
            read_verified_regular_file(self.screenshot_path)
        except ArtifactBoundaryError:
            return False
        return True

    def copy_to(self, dest_dir: Path) -> "Evidence":
        """Preserve the legacy signature without copying pre-custody bytes."""
        _ensure_artifact_directory(dest_dir)
        return Evidence()


def save_http_evidence(
    request: str,
    response: str,
    evidence_dir: Path,
    finding_id: str,
) -> Evidence:
    """Save HTTP request/response as text files and return Evidence."""
    _ensure_artifact_directory(evidence_dir)
    if not _SAFE_FINDING_ID.fullmatch(str(finding_id)):
        raise ValueError("finding_id is not safe for evidence persistence")
    req_path = evidence_dir / f"{finding_id}_request.txt"
    resp_path = evidence_dir / f"{finding_id}_response.txt"
    safe_request = redact_text(request)
    safe_response = redact_text(response)
    _owner_only_write(req_path, safe_request)
    _owner_only_write(resp_path, safe_response)
    return Evidence(request_raw=safe_request, response_raw=safe_response)


class TestEvidence:
    """Unit tests for evidence module."""

    def test_evidence_creation(self) -> None:
        e = Evidence(request_raw="GET / HTTP/1.1", response_raw="HTTP/1.1 200 OK")
        assert e.request_raw == "GET / HTTP/1.1"
        assert not e.has_screenshot()

    def test_base64_no_path(self) -> None:
        e = Evidence()
        assert e.screenshot_as_base64() is None

    def test_copy_to(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        ss = src / "shot.png"
        ss.write_bytes(b"PNG")
        e = Evidence(screenshot_path=str(ss))
        dst = tmp_path / "dst"
        new_e = e.copy_to(dst)
        assert not new_e.has_screenshot()
        assert new_e.screenshot_path is None
        assert list(dst.iterdir()) == []
