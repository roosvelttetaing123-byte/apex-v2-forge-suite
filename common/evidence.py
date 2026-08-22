"""Evidence collection dataclass and helpers."""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
from common.redaction import redact_text, redact_value

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
    """Full evidence bundle attached to every finding."""
    request_raw:          str | None = None   # Raw HTTP request
    response_raw:         str | None = None   # Raw HTTP response
    screenshot_path:      str | None = None   # PNG screenshot path
    console_capture_path: str | None = None   # Rich HTML console export path
    pcap_path:            str | None = None   # PCAP file path
    extra:                dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize evidence for events, storage, and reports."""
        return redact_value({
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
            "screenshot_path": self.screenshot_path,
            "console_capture_path": self.console_capture_path,
            "pcap_path": self.pcap_path,
            "extra": self.extra,
        })

    def screenshot_as_base64(self) -> str | None:
        """Return screenshot as base64 data URI for HTML embedding."""
        if not self.screenshot_path:
            return None
        try:
            content = read_verified_regular_file(self.screenshot_path)
        except ArtifactBoundaryError:
            return None
        data = base64.b64encode(content).decode()
        return f"data:image/png;base64,{data}"

    def console_capture_as_html(self) -> str | None:
        """Return Rich console capture HTML content."""
        if not self.console_capture_path:
            return None
        try:
            content = read_verified_regular_file(self.console_capture_path)
        except ArtifactBoundaryError:
            return None
        return redact_text(content.decode("utf-8", errors="replace"))

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
        """Copy all evidence files to dest_dir and return updated Evidence."""
        _ensure_artifact_directory(dest_dir)
        new = Evidence(
            request_raw=redact_text(self.request_raw or "") or None,
            response_raw=redact_text(self.response_raw or "") or None,
            extra=redact_value(dict(self.extra)),
        )
        screenshot = self._read_source(self.screenshot_path)
        if screenshot is not None and self.screenshot_path:
            dst = dest_dir / Path(self.screenshot_path).name
            _owner_only_write_bytes(dst, screenshot)
            new.screenshot_path = str(dst)
        console_capture = self._read_source(self.console_capture_path)
        if console_capture is not None and self.console_capture_path:
            dst = dest_dir / Path(self.console_capture_path).name
            _owner_only_write_bytes(dst, console_capture)
            new.console_capture_path = str(dst)
        pcap = self._read_source(self.pcap_path)
        if pcap is not None and self.pcap_path:
            dst = dest_dir / Path(self.pcap_path).name
            _owner_only_write_bytes(dst, pcap)
            new.pcap_path = str(dst)
        return new

    @staticmethod
    def _read_source(path: str | None) -> bytes | None:
        """Return source bytes only through the descriptor-backed read boundary."""
        if not path:
            return None
        try:
            return read_verified_regular_file(path)
        except ArtifactBoundaryError:
            return None


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
        assert new_e.has_screenshot()
        assert new_e.screenshot_path is not None
        assert Path(new_e.screenshot_path).parent == dst
