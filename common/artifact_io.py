"""Descriptor-anchored boundaries for owner-only local artifacts.

The helpers in this module deliberately operate on lexical absolute paths and
walk every directory component relative to an already-open descriptor.  That
keeps a validated parent pinned across file creation and atomic replacement,
so an intermediate-directory rename or symlink swap cannot redirect a write.

Commit boundaries also require an owner-controlled final directory and remove
primary-group write before exposing a leaf.  Processes sharing the effective
UID are one trusted filesystem principal; POSIX permissions do not isolate
mutually hostile processes running as that same identity.
"""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing import Callable, Final, TextIO, TypeVar


_DIRECTORY_FLAGS: Final[int] = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_NOFOLLOW_FLAGS: Final[int] = (
    getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
)


class ArtifactBoundaryError(ValueError):
    """Fixed public failure for an unsafe or unavailable artifact path."""


T = TypeVar("T")


def _directory_entry_namespace_is_protected(
    parent: os.stat_result,
    entry: os.stat_result,
) -> bool:
    """Return whether untrusted identities cannot replace one child entry."""
    write_bits = stat.S_IMODE(parent.st_mode) & 0o022
    if not write_bits:
        return True
    if not stat.S_IMODE(parent.st_mode) & stat.S_ISVTX:
        return False
    if not hasattr(os, "getuid"):
        return False
    # Sticky namespaces such as /tmp permit only the directory owner, entry
    # owner, or a privileged identity to rename the owned child.
    return parent.st_uid == os.getuid() or entry.st_uid == os.getuid()


def _tighten_owner_primary_group_directory(descriptor: int) -> None:
    """Remove primary-group write before traversing an owner directory."""
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            stat.S_ISDIR(metadata.st_mode)
            and hasattr(os, "getuid")
            and metadata.st_uid == os.getuid()
            and hasattr(os, "getgid")
            and metadata.st_gid == os.getgid()
            and mode & stat.S_IWGRP
            and not mode & stat.S_IWOTH
        ):
            os.fchmod(descriptor, mode & ~stat.S_IWGRP)
    except Exception:
        pass


def absolute_lexical_path(path: str | os.PathLike[str]) -> Path:
    """Return an absolute path without resolving attacker-controlled links."""
    try:
        return Path(os.path.abspath(os.fspath(Path(path).expanduser())))
    except ArtifactBoundaryError:
        raise
    except Exception:
        raise ArtifactBoundaryError("artifact path is invalid") from None


def _safe_close(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except Exception:
        pass


def open_private_directory(
    directory: str | os.PathLike[str],
    *,
    create: bool = True,
    tighten: bool = True,
) -> int:
    """Open a no-follow directory chain, privately creating missing components.

    Safe existing directory modes remain unchanged.  Owner-primary-group write
    is removed before a component becomes an artifact namespace; components
    created by this boundary are tightened through their descriptors to
    ``0700`` independently of the process umask.
    """
    if create and not tighten:
        raise ArtifactBoundaryError(
            "directory creation requires namespace tightening"
        )
    candidate = absolute_lexical_path(directory)
    descriptor = -1
    try:
        anchor = candidate.anchor
        if not anchor:
            raise ArtifactBoundaryError("artifact directory is unavailable")
        descriptor = os.open(anchor, _DIRECTORY_FLAGS)
        for component in candidate.parts[1:]:
            if tighten:
                _tighten_owner_primary_group_directory(descriptor)
            created = False
            try:
                metadata = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                metadata = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )

            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ArtifactBoundaryError(
                    "artifact directory must be a real directory"
                )

            parent_metadata = os.fstat(descriptor)
            if not _directory_entry_namespace_is_protected(
                parent_metadata,
                metadata,
            ):
                raise ArtifactBoundaryError(
                    "artifact directory namespace is not private"
                )

            child_descriptor = -1
            try:
                child_descriptor = os.open(
                    component,
                    _DIRECTORY_FLAGS,
                    dir_fd=descriptor,
                )
                opened = os.fstat(child_descriptor)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                ):
                    raise ArtifactBoundaryError(
                        "artifact directory changed during traversal"
                    )
                if created:
                    os.fchmod(child_descriptor, 0o700)
                _safe_close(descriptor)
                descriptor = child_descriptor
                child_descriptor = -1
            finally:
                _safe_close(child_descriptor)

        result = descriptor
        descriptor = -1
        return result
    except ArtifactBoundaryError:
        raise
    except Exception:
        raise ArtifactBoundaryError("artifact directory is unavailable") from None
    finally:
        _safe_close(descriptor)


def ensure_private_directory(directory: str | os.PathLike[str]) -> None:
    """Validate/create a private directory chain and release its descriptor."""
    descriptor = -1
    try:
        descriptor = open_private_directory(directory, create=True)
    finally:
        _safe_close(descriptor)


def validate_private_directory_readonly(
    directory: str | os.PathLike[str],
) -> None:
    """Validate an existing private directory chain without changing it."""

    descriptor = -1
    try:
        descriptor = open_private_directory(
            directory,
            create=False,
            tighten=False,
        )
    finally:
        _safe_close(descriptor)


def directory_descriptor_matches(
    descriptor: int,
    directory: str | os.PathLike[str],
    *,
    readonly: bool = False,
) -> bool:
    """Return whether a lexical directory still names the pinned descriptor.

    A successful no-follow walk immediately before commit detects an ancestor
    rename or symlink swap.  The original descriptor remains the authority for
    cleanup, so a failed comparison never redirects removal to the replacement
    path.
    """
    comparison_descriptor = -1
    try:
        comparison_descriptor = (
            open_private_directory(
                directory,
                create=False,
                tighten=False,
            )
            if readonly
            else open_private_directory(directory, create=False)
        )
        pinned = os.fstat(descriptor)
        current = os.fstat(comparison_descriptor)
        return (
            stat.S_ISDIR(pinned.st_mode)
            and stat.S_ISDIR(current.st_mode)
            and pinned.st_dev == current.st_dev
            and pinned.st_ino == current.st_ino
        )
    except (ArtifactBoundaryError, FileNotFoundError, OSError):
        return False
    finally:
        _safe_close(comparison_descriptor)


def directory_descriptor_is_owner_controlled(descriptor: int) -> bool:
    """Return whether a directory namespace excludes untrusted writers.

    The final artifact namespace must exclude both group and world writers.
    """
    try:
        metadata = os.fstat(descriptor)
        return (
            stat.S_ISDIR(metadata.st_mode)
            and (not hasattr(os, "getuid") or metadata.st_uid == os.getuid())
            and not stat.S_IMODE(metadata.st_mode) & 0o022
        )
    except Exception:
        return False


def prepare_owner_controlled_directory(descriptor: int) -> bool:
    """Tighten an owner-primary-group directory, rejecting public writers."""
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
            or mode & stat.S_IWOTH
            or (
                mode & stat.S_IWGRP
                and (
                    not hasattr(os, "getgid")
                    or metadata.st_gid != os.getgid()
                )
            )
        ):
            return False
        if mode & stat.S_IWGRP:
            _tighten_owner_primary_group_directory(descriptor)
        return directory_descriptor_is_owner_controlled(descriptor)
    except Exception:
        return False


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    try:
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("artifact write made no progress")
            written += count
    finally:
        view.release()


def _metadata_is_owned_regular(
    metadata: os.stat_result,
    *,
    identity: tuple[int, int],
    expected_mode: int | None = None,
    expected_size: int | None = None,
) -> bool:
    """Return whether one snapshot describes the expected private inode."""
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and (not hasattr(os, "getuid") or metadata.st_uid == os.getuid())
        and (metadata.st_dev, metadata.st_ino) == identity
        and (
            expected_mode is None
            or stat.S_IMODE(metadata.st_mode) == expected_mode
        )
        and (expected_size is None or metadata.st_size == expected_size)
    )


def descriptor_entry_is_stable(
    descriptor: int,
    directory_descriptor: int,
    name: str,
    *,
    initial: os.stat_result | None = None,
    expected_mode: int | None = None,
    expected_size: int | None = None,
) -> bool:
    """Validate one committed descriptor against its pinned directory entry.

    Two descriptor snapshots bracket the entry lookup.  Link-count, identity,
    ownership, permissions, and mutation metadata must agree throughout, so a
    hardlink or leaf replacement introduced at commit time is never
    acknowledged as the caller's artifact.
    """
    try:
        before = initial if initial is not None else os.fstat(descriptor)
        entry = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino)
        snapshots = (before, entry, after)
        if not all(
            _metadata_is_owned_regular(
                metadata,
                identity=identity,
                expected_mode=expected_mode,
                expected_size=expected_size,
            )
            for metadata in snapshots
        ):
            return False
        stable_fields = (
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_mode",
            "st_uid",
            "st_gid",
        )
        return all(
            getattr(metadata, field) == getattr(before, field)
            for metadata in (entry, after)
            for field in stable_fields
        )
    except Exception:
        return False


def committed_file_is_stable(
    descriptor: int,
    directory_descriptor: int,
    name: str,
    directory: str | os.PathLike[str],
    *,
    expected_mode: int | None = None,
    expected_size: int | None = None,
) -> bool:
    """Validate inode, entry, and lexical ancestors after one file commit."""
    try:
        if (
            not directory_descriptor_is_owner_controlled(directory_descriptor)
            or not directory_descriptor_matches(directory_descriptor, directory)
        ):
            return False
        initial = os.fstat(descriptor)
        if not descriptor_entry_is_stable(
            descriptor,
            directory_descriptor,
            name,
            initial=initial,
            expected_mode=expected_mode,
            expected_size=expected_size,
        ):
            return False
        if (
            not directory_descriptor_is_owner_controlled(directory_descriptor)
            or not directory_descriptor_matches(directory_descriptor, directory)
        ):
            return False
        return (
            descriptor_entry_is_stable(
                descriptor,
                directory_descriptor,
                name,
                expected_mode=expected_mode,
                expected_size=expected_size,
            )
            and directory_descriptor_is_owner_controlled(directory_descriptor)
        )
    except Exception:
        return False


def _entry_names_descriptor(
    directory_descriptor: int,
    name: str,
    descriptor: int,
) -> bool:
    """Return whether a no-follow directory entry still names a descriptor."""
    try:
        opened = os.fstat(descriptor)
        entry = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        return (
            stat.S_ISREG(opened.st_mode)
            and stat.S_ISREG(entry.st_mode)
            and opened.st_dev == entry.st_dev
            and opened.st_ino == entry.st_ino
        )
    except Exception:
        return False


def _wipe_owned_descriptor(descriptor: int) -> None:
    """Best-effort wipe of a boundary-created inode, including late aliases."""
    try:
        metadata = os.fstat(descriptor)
        if (
            stat.S_ISREG(metadata.st_mode)
            and (not hasattr(os, "getuid") or metadata.st_uid == os.getuid())
        ):
            os.ftruncate(descriptor, 0)
            try:
                os.fsync(descriptor)
            except Exception:
                pass
    except Exception:
        pass


def _unlink_if_descriptor_entry(
    directory_descriptor: int,
    name: str,
    descriptor: int,
) -> None:
    """Best-effort unlink only while an entry names the boundary inode."""
    if not _entry_names_descriptor(directory_descriptor, name, descriptor):
        return
    try:
        os.unlink(name, dir_fd=directory_descriptor)
    except Exception:
        pass


def dispose_temporary_file(
    directory_descriptor: int,
    name: str,
    *,
    descriptor: int = -1,
) -> None:
    """Best-effort wipe and unlink of one boundary-owned temporary inode.

    When unlink is denied, truncation ensures the leftover owner-only file does
    not retain report or credential-derived content.  A closed temporary is
    reopened without following links and is wiped only when it is an unaliased,
    owner-controlled regular file.
    """
    owned_descriptor = descriptor
    try:
        if owned_descriptor < 0:
            try:
                owned_descriptor = os.open(
                    name,
                    os.O_WRONLY | _FILE_NOFOLLOW_FLAGS,
                    dir_fd=directory_descriptor,
                )
            except Exception:
                owned_descriptor = -1
        if owned_descriptor >= 0:
            try:
                metadata = os.fstat(owned_descriptor)
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and metadata.st_nlink == 1
                    and (
                        not hasattr(os, "getuid")
                        or metadata.st_uid == os.getuid()
                    )
                ):
                    os.ftruncate(owned_descriptor, 0)
                    try:
                        os.fsync(owned_descriptor)
                    except Exception:
                        pass
            except Exception:
                pass
    finally:
        _safe_close(owned_descriptor)
        try:
            os.unlink(name, dir_fd=directory_descriptor)
        except Exception:
            pass


def atomic_write_bytes(
    path: str | os.PathLike[str],
    payload: bytes,
    *,
    mode: int = 0o600,
) -> Path:
    """Atomically replace one artifact relative to a pinned no-follow parent."""
    candidate = absolute_lexical_path(path)
    if candidate.name in {"", ".", ".."}:
        raise ArtifactBoundaryError("artifact path is invalid")
    parent_descriptor = -1
    descriptor = -1
    temporary_name = f".{candidate.name}.{secrets.token_hex(16)}.tmp"
    replace_attempted = False
    acknowledged = False
    try:
        parent_descriptor = open_private_directory(candidate.parent, create=True)
        if not prepare_owner_controlled_directory(parent_descriptor):
            raise ArtifactBoundaryError(
                "artifact directory must be owner-controlled"
            )
        descriptor = os.open(
            temporary_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW_FLAGS,
            mode,
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            raise ArtifactBoundaryError(
                "artifact temporary must be one owner-controlled regular file"
            )
        os.fchmod(descriptor, mode)
        _write_all(descriptor, bytes(payload))
        os.fsync(descriptor)
        if not directory_descriptor_matches(parent_descriptor, candidate.parent):
            raise ArtifactBoundaryError(
                "artifact directory changed during write"
            )
        replace_attempted = True
        os.replace(
            temporary_name,
            candidate.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        try:
            os.fsync(parent_descriptor)
        except Exception:
            # Replacement has committed; directory fsync is not portable.
            pass
        if not committed_file_is_stable(
            descriptor,
            parent_descriptor,
            candidate.name,
            candidate.parent,
            expected_mode=mode,
            expected_size=len(payload),
        ):
            raise ArtifactBoundaryError("artifact changed during commit")
        acknowledged = True
        return candidate
    except ArtifactBoundaryError:
        raise
    except Exception:
        raise ArtifactBoundaryError("artifact write failed") from None
    finally:
        if not acknowledged and descriptor >= 0 and parent_descriptor >= 0:
            # The descriptor always belongs to the O_EXCL temporary inode.  If
            # replacement committed before a namespace/alias race was noticed,
            # wiping it also clears every late hardlink before we remove names
            # that still resolve to that inode.
            _wipe_owned_descriptor(descriptor)
            _unlink_if_descriptor_entry(
                parent_descriptor,
                temporary_name,
                descriptor,
            )
            if replace_attempted:
                _unlink_if_descriptor_entry(
                    parent_descriptor,
                    candidate.name,
                    descriptor,
                )
        _safe_close(descriptor)
        _safe_close(parent_descriptor)


def atomic_write_text_stream(
    path: str | os.PathLike[str],
    writer: Callable[[TextIO], T],
    *,
    mode: int = 0o600,
) -> T:
    """Atomically commit callback-produced text through a retained descriptor.

    The callback writes to the same O_EXCL inode that remains open across the
    final rename and post-commit validation.  A failed callback or commit wipes
    that inode before removing every entry that still names it, so a late
    hardlink cannot retain the produced text.
    """
    candidate = absolute_lexical_path(path)
    if candidate.name in {"", ".", ".."}:
        raise ArtifactBoundaryError("artifact path is invalid")
    parent_descriptor = -1
    descriptor = -1
    temporary_name = f".{candidate.name}.{secrets.token_hex(16)}.tmp"
    replace_attempted = False
    acknowledged = False
    try:
        parent_descriptor = open_private_directory(candidate.parent, create=True)
        if not prepare_owner_controlled_directory(parent_descriptor):
            raise ArtifactBoundaryError(
                "artifact directory must be owner-controlled"
            )
        descriptor = os.open(
            temporary_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW_FLAGS,
            mode,
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            raise ArtifactBoundaryError(
                "artifact temporary must be one owner-controlled regular file"
            )
        os.fchmod(descriptor, mode)
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            errors="replace",
            closefd=False,
        ) as handle:
            result = writer(handle)
            handle.flush()
        os.fsync(descriptor)
        expected_size = os.fstat(descriptor).st_size
        if not directory_descriptor_matches(parent_descriptor, candidate.parent):
            raise ArtifactBoundaryError(
                "artifact directory changed during write"
            )
        replace_attempted = True
        os.replace(
            temporary_name,
            candidate.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        try:
            os.fsync(parent_descriptor)
        except Exception:
            pass
        if not committed_file_is_stable(
            descriptor,
            parent_descriptor,
            candidate.name,
            candidate.parent,
            expected_mode=mode,
            expected_size=expected_size,
        ):
            raise ArtifactBoundaryError("artifact changed during commit")
        acknowledged = True
        return result
    except ArtifactBoundaryError:
        raise
    except Exception:
        raise ArtifactBoundaryError("artifact stream write failed") from None
    finally:
        if not acknowledged and descriptor >= 0 and parent_descriptor >= 0:
            _wipe_owned_descriptor(descriptor)
            _unlink_if_descriptor_entry(
                parent_descriptor,
                temporary_name,
                descriptor,
            )
            if replace_attempted:
                _unlink_if_descriptor_entry(
                    parent_descriptor,
                    candidate.name,
                    descriptor,
                )
        _safe_close(descriptor)
        _safe_close(parent_descriptor)


def open_owner_only_file(
    path: str | os.PathLike[str],
    *,
    flags: int,
    mode: int = 0o600,
) -> tuple[Path, int]:
    """Open one unaliased owner-controlled regular file via a pinned parent."""
    candidate = absolute_lexical_path(path)
    if candidate.name in {"", ".", ".."}:
        raise ArtifactBoundaryError("artifact path is invalid")
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = open_private_directory(candidate.parent, create=True)
        if not prepare_owner_controlled_directory(parent_descriptor):
            raise ArtifactBoundaryError(
                "artifact directory must be owner-controlled"
            )
        descriptor = os.open(
            candidate.name,
            flags | _FILE_NOFOLLOW_FLAGS,
            mode,
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            raise ArtifactBoundaryError(
                "artifact must be one owner-controlled regular file"
            )
        os.fchmod(descriptor, mode)
        adjusted = os.fstat(descriptor)
        if (
            not stat.S_ISREG(adjusted.st_mode)
            or adjusted.st_nlink != 1
            or (hasattr(os, "getuid") and adjusted.st_uid != os.getuid())
            or adjusted.st_dev != metadata.st_dev
            or adjusted.st_ino != metadata.st_ino
            or stat.S_IMODE(adjusted.st_mode) != mode
            or not directory_descriptor_is_owner_controlled(parent_descriptor)
        ):
            raise ArtifactBoundaryError(
                "artifact must be one owner-controlled regular file"
            )
        result = descriptor
        descriptor = -1
        return candidate, result
    except ArtifactBoundaryError:
        raise
    except Exception:
        raise ArtifactBoundaryError("artifact is unavailable") from None
    finally:
        _safe_close(descriptor)
        _safe_close(parent_descriptor)


def _open_verified_regular_file_for_read_pinned(
    path: str | os.PathLike[str],
    *,
    require_owner_only_mode: bool = False,
) -> tuple[Path, int, int, os.stat_result]:
    """Open a regular file while retaining its validated parent descriptor.

    This read boundary never creates directories, changes modes, or resolves a
    caller-controlled pathname.  The leaf identity is checked before and after
    ``open`` and every ancestor is traversed descriptor-relatively with
    ``O_NOFOLLOW``.  Callers that read security artifacts such as SQLite state
    may additionally require that no group/world permission bits are present.
    """
    candidate = absolute_lexical_path(path)
    if candidate.name in {"", ".", ".."}:
        raise ArtifactBoundaryError("artifact path is invalid")
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = open_private_directory(
            candidate.parent,
            create=False,
            tighten=False,
        )
        before = os.stat(
            candidate.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise ArtifactBoundaryError(
                "artifact must be one owner-controlled regular file"
            )
        descriptor = os.open(
            candidate.name,
            os.O_RDONLY | _FILE_NOFOLLOW_FLAGS,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        after = os.stat(
            candidate.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (hasattr(os, "getuid") and opened.st_uid != os.getuid())
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_dev != after.st_dev
            or opened.st_ino != after.st_ino
            or (
                require_owner_only_mode
                and stat.S_IMODE(opened.st_mode) & 0o077
            )
        ):
            raise ArtifactBoundaryError(
                "artifact must be one owner-controlled regular file"
            )
        if not directory_descriptor_matches(
            parent_descriptor,
            candidate.parent,
            readonly=True,
        ):
            raise ArtifactBoundaryError("artifact directory changed during read")
        result_descriptor = descriptor
        result_parent_descriptor = parent_descriptor
        descriptor = -1
        parent_descriptor = -1
        return (
            candidate,
            result_descriptor,
            result_parent_descriptor,
            opened,
        )
    except ArtifactBoundaryError:
        raise
    except Exception:
        raise ArtifactBoundaryError("artifact is unavailable") from None
    finally:
        _safe_close(descriptor)
        _safe_close(parent_descriptor)


def open_verified_regular_file_for_read(
    path: str | os.PathLike[str],
    *,
    require_owner_only_mode: bool = False,
) -> tuple[Path, int]:
    """Open an unaliased owner-controlled regular file for descriptor use.

    Callers that consume bytes should prefer :func:`read_verified_regular_file`,
    which retains and rechecks the parent, entry, link count, and metadata for
    the full read interval.
    """
    parent_descriptor = -1
    try:
        candidate, descriptor, parent_descriptor, _ = (
            _open_verified_regular_file_for_read_pinned(
                path,
                require_owner_only_mode=require_owner_only_mode,
            )
        )
        return candidate, descriptor
    finally:
        _safe_close(parent_descriptor)


def _read_snapshot_is_stable(
    initial: os.stat_result,
    final: os.stat_result,
    entry: os.stat_result,
    *,
    require_owner_only_mode: bool,
) -> bool:
    """Return whether one pinned inode stayed unaliased and unchanged."""
    initial_identity = (initial.st_dev, initial.st_ino)
    snapshots = (initial, final, entry)
    if any(
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        or (metadata.st_dev, metadata.st_ino) != initial_identity
        or (
            require_owner_only_mode
            and stat.S_IMODE(metadata.st_mode) & 0o077
        )
        for metadata in snapshots
    ):
        return False
    stable_fields = (
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_mode",
        "st_uid",
        "st_gid",
    )
    return all(
        getattr(final, field) == getattr(initial, field)
        and getattr(entry, field) == getattr(initial, field)
        for field in stable_fields
    )


def read_verified_regular_file(
    path: str | os.PathLike[str],
    *,
    require_owner_only_mode: bool = False,
) -> bytes:
    """Read bytes from one unchanged inode under a pinned lexical parent."""
    candidate: Path | None = None
    parent_descriptor = -1
    descriptor = -1
    payload = bytearray()
    try:
        candidate, descriptor, parent_descriptor, initial = (
            _open_verified_regular_file_for_read_pinned(
                path,
                require_owner_only_mode=require_owner_only_mode,
            )
        )
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            payload.extend(chunk)
        final = os.fstat(descriptor)
        entry = os.stat(
            candidate.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not _read_snapshot_is_stable(
            initial,
            final,
            entry,
            require_owner_only_mode=require_owner_only_mode,
        ) or not directory_descriptor_matches(
            parent_descriptor,
            candidate.parent,
            readonly=True,
        ):
            raise ArtifactBoundaryError("artifact changed during read")
        result = bytes(payload)
        payload[:] = b"\x00" * len(payload)
        payload.clear()
        return result
    except ArtifactBoundaryError:
        raise
    except Exception:
        raise ArtifactBoundaryError("artifact read failed") from None
    finally:
        if payload:
            payload[:] = b"\x00" * len(payload)
            payload.clear()
        _safe_close(descriptor)
        _safe_close(parent_descriptor)
