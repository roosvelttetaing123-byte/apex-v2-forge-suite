"""Canonical, fail-closed WebForge whitebox source-root handling."""
from __future__ import annotations

import errno
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, NoReturn, cast


class SourceRootError(ValueError):
    """Safe source-root validation failure without outside-path disclosure."""


_RootIdentity = tuple[int, int]
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _close_descriptor_quietly(descriptor: int) -> None:
    """Best-effort cleanup that never replaces an in-flight failure."""
    try:
        os.close(descriptor)
    except Exception:
        pass


def _close_descriptor_or_error(descriptor: int, message: str) -> None:
    """Close one owned descriptor or emit a fixed, non-disclosing error."""
    try:
        os.close(descriptor)
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError(message) from None


@contextmanager
def _managed_descriptor(
    descriptor: int,
    *,
    close_error: str,
) -> Iterator[int]:
    """Close a descriptor without allowing cleanup to mask a primary error."""
    try:
        yield descriptor
    except BaseException:
        _close_descriptor_quietly(descriptor)
        raise
    else:
        _close_descriptor_or_error(descriptor, close_error)


class _CanonicalSourceRootPath(type(Path())):  # type: ignore[misc]
    """Concrete ``Path`` carrying the inode approved at validation time.

    A path string alone is not a stable authorization fact: the whole root can
    be renamed and replaced after validation.  The identity travels with
    derived paths and is compared against every descriptor-relative walk/open.
    """

    __slots__ = ("_approved_identity",)
    _approved_identity: _RootIdentity | None

    def __new__(cls, *pathsegments: object) -> "_CanonicalSourceRootPath":
        instance = super().__new__(cls, *pathsegments)
        instance._approved_identity = None
        return instance

    def with_segments(self, *pathsegments: object) -> "_CanonicalSourceRootPath":
        child = type(self)(*pathsegments)
        child._approved_identity = self._approved_identity
        return child

    def _make_child(self, args: tuple[object, ...]) -> "_CanonicalSourceRootPath":
        """Preserve identity for the pathlib implementation used by Python 3.11."""
        legacy_make_child = getattr(super(), "_make_child", None)
        if legacy_make_child is None:  # pragma: no cover - 3.12+ uses with_segments
            return self.with_segments(self, *args)
        child = legacy_make_child(args)
        child._approved_identity = self._approved_identity
        return child

    def __copy__(self) -> "_CanonicalSourceRootPath":
        # Paths are immutable.  Returning this exact identity-bound instance is
        # safer than reconstructing it through ``PurePath.__reduce__``, which
        # retains only the pathname and silently drops the approved inode.
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "_CanonicalSourceRootPath":
        memo[id(self)] = self
        return self

    def __reduce__(self) -> NoReturn:
        # The inode approval is a live, process-local authorization fact.  Do
        # not serialize a pathname that could later be re-approved after the
        # directory has been replaced.
        raise TypeError("identity-bound source_root is not serializable")


def _identity(metadata: os.stat_result) -> _RootIdentity:
    return metadata.st_dev, metadata.st_ino


def _expected_identity(value: object) -> _RootIdentity | None:
    # Only the private concrete capability may carry approval.  Looking up an
    # arbitrary PathLike attribute can execute user code before normalization.
    if type(value) is not _CanonicalSourceRootPath:
        return None
    identity = value._approved_identity
    if (
        isinstance(identity, tuple)
        and len(identity) == 2
        and all(isinstance(item, int) for item in identity)
    ):
        return identity
    return None


def _open_root_directory(
    path: Path,
    *,
    expected: _RootIdentity | None,
    path_identity: _RootIdentity | None = None,
) -> tuple[int, _RootIdentity]:
    """Open and identity-check the root without disclosing its spelling."""
    try:
        descriptor = os.open(path, _DIRECTORY_FLAGS)
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError("source_root is unavailable or unsafe") from None
    try:
        metadata = os.fstat(descriptor)
        observed = _identity(metadata)
        if not stat.S_ISDIR(metadata.st_mode) or (
            expected is not None and observed != expected
        ) or (
            path_identity is not None and observed != path_identity
        ):
            raise SourceRootError("source_root identity changed after approval")
        # A second pathname identity check closes the interval between the
        # pre-open lstat and descriptor acquisition.  The descriptor itself is
        # retained after this point, so later renames cannot redirect reads.
        try:
            after = os.lstat(path)
        except OSError:
            raise SourceRootError(
                "source_root identity changed after approval"
            ) from None
        if not stat.S_ISDIR(after.st_mode) or _identity(after) != observed:
            raise SourceRootError("source_root identity changed after approval")
        return descriptor, observed
    except SourceRootError:
        _close_descriptor_quietly(descriptor)
        raise
    except Exception:
        _close_descriptor_quietly(descriptor)
        raise SourceRootError("source_root is unavailable or unsafe") from None
    except BaseException:
        _close_descriptor_quietly(descriptor)
        raise


def canonical_source_root(value: object) -> Path:
    """Return a canonical path bound to the approved directory inode."""
    try:
        return _canonical_source_root(value)
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError("source_root is unavailable") from None


def _canonical_source_root(value: object) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise SourceRootError("source_root is required")
    expected = _expected_identity(value)
    if type(value) is _CanonicalSourceRootPath and expected is None:
        raise SourceRootError("source_root approval is required")
    try:
        raw_value = os.fspath(value)
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError("source_root is unavailable") from None
    # ``Path`` accepts text paths only here.  Reject bytes and malformed
    # PathLike implementations rather than allowing a TypeError to escape the
    # engine boundary.
    if type(raw_value) is not str:
        raise SourceRootError("source_root is required")
    raw = str.strip(raw_value)
    if not raw:
        raise SourceRootError("source_root is required")
    try:
        candidate = Path(raw).expanduser()
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError("source_root is unavailable") from None
    if not candidate.is_absolute():
        raise SourceRootError("source_root must be an absolute path")
    try:
        if candidate.is_symlink():
            raise SourceRootError("source_root must not be a symlink")
        before = os.lstat(candidate)
        if not stat.S_ISDIR(before.st_mode):
            raise SourceRootError("source_root must be a directory")
        before_identity = _identity(before)
        resolved = candidate.resolve(strict=True)
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError("source_root is unavailable") from None
    if resolved != candidate:
        raise SourceRootError("source_root must already be canonical")
    if not resolved.is_dir():
        raise SourceRootError("source_root must be a directory")
    descriptor, observed = _open_root_directory(
        resolved,
        expected=expected,
        path_identity=before_identity,
    )
    with _managed_descriptor(
        descriptor,
        close_error="source_root is unavailable or unsafe",
    ):
        pass
    approved = _CanonicalSourceRootPath(resolved)
    approved._approved_identity = observed
    return approved


def require_approved_source_root(value: object) -> Path:
    """Validate and return an existing process-local source-root capability."""
    try:
        expected = _expected_identity(value)
        if expected is None:
            raise SourceRootError("source_root approval is required")
        approved = cast(Path, value)
        descriptor, _ = _open_root_directory(approved, expected=expected)
        with _managed_descriptor(
            descriptor,
            close_error="source_root is unavailable or unsafe",
        ):
            pass
        return approved
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError("source_root is unavailable or unsafe") from None


def _relative_parts(root: Path, candidate: Path) -> tuple[str, ...]:
    try:
        relative = candidate.relative_to(root)
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError("path is outside source_root") from None
    try:
        if not relative.parts or relative == Path("."):
            raise SourceRootError("path must identify a file below source_root")
        if any(part in {"", ".", ".."} for part in relative.parts):
            raise SourceRootError("path is not canonical below source_root")
        return relative.parts
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError("source entry is unavailable or unsafe") from None


def _source_candidate_path(value: object) -> Path:
    """Normalize one candidate without exposing malformed PathLike details."""
    try:
        raw_value = os.fspath(cast(str | os.PathLike[str], value))
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError("source entry is unavailable or unsafe") from None
    if type(raw_value) is not str:
        raise SourceRootError("source entry is unavailable or unsafe")
    try:
        return Path(raw_value)
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError("source entry is unavailable or unsafe") from None


def open_source_file(root: Path, candidate: Path, *, max_bytes: int) -> bytes:
    """Open a regular in-root file without following symlinks or path swaps."""
    try:
        if type(max_bytes) is not int or max_bytes < 0:
            raise SourceRootError("source entry is unavailable or unsafe")
        canonical_root = require_approved_source_root(root)
        expected = _expected_identity(canonical_root)
        if expected is None:
            raise SourceRootError("source_root approval is required")
        parts = _relative_parts(canonical_root, _source_candidate_path(candidate))
        root_fd, _ = _open_root_directory(canonical_root, expected=expected)
        with _managed_descriptor(
            root_fd,
            close_error="source entry could not be opened safely",
        ):
            current_fd = root_fd
            try:
                for part in parts[:-1]:
                    next_fd = os.open(
                        part,
                        _DIRECTORY_FLAGS,
                        dir_fd=current_fd,
                    )
                    if current_fd != root_fd:
                        previous_fd = current_fd
                        # Do not retry a close that reported failure: its state
                        # is unspecified and its numeric value may be reused.
                        current_fd = root_fd
                        try:
                            _close_descriptor_or_error(
                                previous_fd,
                                "source entry could not be opened safely",
                            )
                        except BaseException:
                            _close_descriptor_quietly(next_fd)
                            raise
                    current_fd = next_fd
            except BaseException:
                if current_fd != root_fd:
                    _close_descriptor_quietly(current_fd)
                raise

            if current_fd == root_fd:
                return _read_source_file(root_fd, parts[-1], max_bytes=max_bytes)
            with _managed_descriptor(
                current_fd,
                close_error="source entry could not be opened safely",
            ):
                return _read_source_file(
                    current_fd,
                    parts[-1],
                    max_bytes=max_bytes,
                )
    except SourceRootError:
        raise
    except ValueError:
        raise SourceRootError("source entry is unavailable or unsafe") from None
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT}:
            raise SourceRootError("source entry is unavailable or unsafe") from None
        raise SourceRootError("source entry could not be opened safely") from None
    except Exception:
        raise SourceRootError("source entry could not be opened safely") from None


def _read_source_file(directory_fd: int, name: str, *, max_bytes: int) -> bytes:
    """Read one descriptor-relative regular file under a validated root."""
    file_fd = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
    with _managed_descriptor(
        file_fd,
        close_error="source entry could not be opened safely",
    ):
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SourceRootError("source entry is not a regular file")
        if metadata.st_size > max_bytes:
            raise SourceRootError("source file exceeds the permitted size")
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(file_fd, min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > max_bytes:
            raise SourceRootError("source file exceeds the permitted size")
        return bytes(data)


def iter_source_files(
    root: Path,
    *,
    skip_directories: frozenset[str],
) -> Iterator[tuple[Path, str]]:
    """Yield files through one identity-bound descriptor-relative tree walk."""
    try:
        yield from _iter_source_files(
            root,
            skip_directories=skip_directories,
        )
    except SourceRootError:
        raise
    except Exception:
        raise SourceRootError(
            "source directory could not be read safely"
        ) from None


def _iter_source_files(
    root: Path,
    *,
    skip_directories: frozenset[str],
) -> Iterator[tuple[Path, str]]:
    canonical_root = require_approved_source_root(root)
    expected = _expected_identity(canonical_root)
    if expected is None:
        raise SourceRootError("source_root approval is required")
    root_fd, _ = _open_root_directory(
        canonical_root,
        expected=expected,
    )

    def walk(
        directory_fd: int,
        relative_parts: tuple[str, ...],
    ) -> Iterator[tuple[Path, str]]:
        try:
            with os.scandir(directory_fd) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except SourceRootError:
            raise
        except Exception:
            raise SourceRootError(
                "source directory could not be read safely"
            ) from None
        for entry in entries:
            name = entry.name
            if not name or name in {".", ".."}:
                continue
            try:
                if entry.is_symlink():
                    continue
                child_parts = (*relative_parts, name)
                if entry.is_dir(follow_symlinks=False):
                    if name in skip_directories:
                        continue
                    child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
                    with _managed_descriptor(
                        child_fd,
                        close_error="source tree changed during scan",
                    ):
                        metadata = os.fstat(child_fd)
                        if stat.S_ISDIR(metadata.st_mode):
                            yield from walk(child_fd, child_parts)
                elif entry.is_file(follow_symlinks=False):
                    relative = Path(*child_parts).as_posix()
                    yield canonical_root.joinpath(*child_parts), relative
            except SourceRootError:
                raise
            except Exception:
                raise SourceRootError(
                    "source tree changed during scan"
                ) from None

    with _managed_descriptor(
        root_fd,
        close_error="source directory could not be read safely",
    ):
        yield from walk(root_fd, ())
