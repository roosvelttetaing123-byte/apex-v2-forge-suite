"""Shared Rich-based logger for all forge-suite frameworks."""
from __future__ import annotations

import json
import logging
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

from common.artifact_io import (
    ArtifactBoundaryError,
    absolute_lexical_path,
    descriptor_entry_is_stable,
    directory_descriptor_is_owner_controlled,
    directory_descriptor_matches,
    open_owner_only_file,
    open_private_directory,
)
from common.redaction import redact_text, redact_value, redaction_filter

_THEME = Theme({
    "info":     "cyan",
    "warning":  "yellow",
    "error":    "bold red",
    "critical": "bold white on red",
    "success":  "bold green",
    "finding":  "bold magenta",
    "phase":    "bold cyan",
})

console = Console(theme=_THEME, highlight=True)
quiet_console = Console(quiet=True)

class _LogArtifactError(ValueError):
    """Fixed public failure for an unsafe log artifact path."""


_LOG_ARTIFACT_FAILURE = "log destination is unavailable"


def _safe_close_descriptor(descriptor: int) -> None:
    """Close a descriptor without masking the primary boundary result."""
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except Exception:
        pass


def _descriptor_backed_candidate(candidate: Path, descriptor: int) -> Path:
    """Prefer the kernel's live descriptor path after an ancestor rename."""
    try:
        rendered = os.readlink(f"/proc/self/fd/{descriptor}")
        if not rendered.startswith("/") or rendered.endswith(" (deleted)"):
            return candidate
        live_candidate = absolute_lexical_path(rendered)
        if live_candidate.name != candidate.name:
            return candidate
        return live_candidate
    except Exception:
        return candidate


def _open_owner_only_log(path: Path) -> tuple[Path, TextIO, int]:
    """Open one append-only log through a descriptor-pinned directory chain."""
    descriptor = -1
    parent_descriptor = -1
    try:
        candidate, descriptor = open_owner_only_file(
            path,
            flags=(
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | getattr(os, "O_NONBLOCK", 0)
            ),
            mode=0o600,
        )
        candidate = _descriptor_backed_candidate(candidate, descriptor)
        parent_descriptor = open_private_directory(
            candidate.parent,
            create=False,
        )
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        if not (
            directory_descriptor_is_owner_controlled(parent_descriptor)
            and directory_descriptor_matches(parent_descriptor, candidate.parent)
            and descriptor_entry_is_stable(
                descriptor,
                parent_descriptor,
                candidate.name,
                initial=metadata,
                expected_mode=0o600,
                expected_size=metadata.st_size,
            )
        ):
            raise ArtifactBoundaryError("artifact changed during log open")
        handle = os.fdopen(descriptor, "a", encoding="utf-8")
        descriptor = -1
        result_parent_descriptor = parent_descriptor
        parent_descriptor = -1
        return candidate, handle, result_parent_descriptor
    except ArtifactBoundaryError:
        raise _LogArtifactError(_LOG_ARTIFACT_FAILURE) from None
    except Exception:
        raise _LogArtifactError(_LOG_ARTIFACT_FAILURE) from None
    finally:
        _safe_close_descriptor(descriptor)
        _safe_close_descriptor(parent_descriptor)


def _log_snapshot_is_safe(
    metadata: os.stat_result,
    identity: tuple[int, int],
    *,
    expected_size: int | None = None,
) -> bool:
    """Return whether an append descriptor remains private and unaliased."""
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and (not hasattr(os, "getuid") or metadata.st_uid == os.getuid())
        and (metadata.st_dev, metadata.st_ino) == identity
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and (expected_size is None or metadata.st_size == expected_size)
    )


def _rollback_log_append(descriptor: int, size: int) -> None:
    """Remove a partial or alias-exposed append without leaking its contents."""
    try:
        os.ftruncate(descriptor, size)
        try:
            os.fsync(descriptor)
        except Exception:
            pass
    except Exception:
        pass


def _log_namespace_is_safe(
    descriptor: int,
    parent_descriptor: int,
    path: Path,
    identity: tuple[int, int],
    *,
    initial: os.stat_result | None = None,
    expected_size: int | None = None,
) -> bool:
    """Validate the live append inode, canonical entry, and pinned parent."""
    try:
        metadata = initial if initial is not None else os.fstat(descriptor)
        return (
            _log_snapshot_is_safe(
                metadata,
                identity,
                expected_size=expected_size,
            )
            and directory_descriptor_is_owner_controlled(parent_descriptor)
            and directory_descriptor_matches(parent_descriptor, path.parent)
            and descriptor_entry_is_stable(
                descriptor,
                parent_descriptor,
                path.name,
                initial=metadata,
                expected_mode=0o600,
                expected_size=expected_size,
            )
            and directory_descriptor_matches(parent_descriptor, path.parent)
        )
    except Exception:
        return False


class JsonlFileHandler(logging.Handler):
    """Writes every log record as a JSON line to a file for audit trail."""

    def __init__(self, path: Path, module_name: str = "") -> None:
        super().__init__()
        self.module_name = module_name
        self._fh: TextIO | None = None
        self._parent_descriptor = -1
        try:
            self.path, self._fh, self._parent_descriptor = _open_owner_only_log(path)
            metadata = os.fstat(self._fh.fileno())
            self._identity = (metadata.st_dev, metadata.st_ino)
            if not _log_namespace_is_safe(
                self._fh.fileno(),
                self._parent_descriptor,
                self.path,
                self._identity,
                initial=metadata,
                expected_size=metadata.st_size,
            ):
                raise _LogArtifactError(_LOG_ARTIFACT_FAILURE)
        except Exception:
            handle = self._fh
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
            self._fh = None
            _safe_close_descriptor(self._parent_descriptor)
            self._parent_descriptor = -1
            raise _LogArtifactError(_LOG_ARTIFACT_FAILURE) from None
        self._disabled = False
        self.addFilter(redaction_filter())

    def emit(self, record: logging.LogRecord) -> None:
        entry: dict[str, Any] = redact_value({
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": getattr(record, "forge_module", self.module_name),
            "event": record.getMessage(),
            "target": getattr(record, "target", ""),
            "detail": getattr(record, "detail", {}),
            "operator_confirmed": getattr(record, "operator_confirmed", None),
        })
        checkpoint_size: int | None = None
        try:
            if self._fh is None or self._disabled:
                return
            descriptor = self._fh.fileno()
            before = os.fstat(descriptor)
            if not _log_namespace_is_safe(
                descriptor,
                self._parent_descriptor,
                self.path,
                self._identity,
                initial=before,
                expected_size=before.st_size,
            ):
                self._disabled = True
                return
            checkpoint_size = before.st_size
            os.fchmod(descriptor, 0o600)

            # The mode adjustment is a deliberate test seam: a hardlink added
            # after the first fstat must be observed before any private event is
            # appended.  A second bracketing snapshot narrows the syscall gap.
            after_mode = os.fstat(descriptor)
            before_write = os.fstat(descriptor)
            if not (
                _log_namespace_is_safe(
                    descriptor,
                    self._parent_descriptor,
                    self.path,
                    self._identity,
                    initial=after_mode,
                    expected_size=checkpoint_size,
                )
                and _log_namespace_is_safe(
                    descriptor,
                    self._parent_descriptor,
                    self.path,
                    self._identity,
                    initial=before_write,
                    expected_size=checkpoint_size,
                )
                and _log_snapshot_is_safe(
                    after_mode,
                    self._identity,
                    expected_size=checkpoint_size,
                )
                and _log_snapshot_is_safe(
                    before_write,
                    self._identity,
                    expected_size=checkpoint_size,
                )
            ):
                self._disabled = True
                return

            line = json.dumps(entry, default=str) + "\n"
            expected_size = checkpoint_size + len(line.encode("utf-8"))
            self._fh.write(line)
            self._fh.flush()

            after_write = os.fstat(descriptor)
            final = os.fstat(descriptor)
            if not (
                _log_namespace_is_safe(
                    descriptor,
                    self._parent_descriptor,
                    self.path,
                    self._identity,
                    initial=after_write,
                    expected_size=expected_size,
                )
                and _log_namespace_is_safe(
                    descriptor,
                    self._parent_descriptor,
                    self.path,
                    self._identity,
                    initial=final,
                    expected_size=expected_size,
                )
                and _log_snapshot_is_safe(
                    after_write,
                    self._identity,
                    expected_size=expected_size,
                )
                and _log_snapshot_is_safe(
                    final,
                    self._identity,
                    expected_size=expected_size,
                )
            ):
                _rollback_log_append(descriptor, checkpoint_size)
                self._disabled = True
        except Exception:
            if self._fh is not None and checkpoint_size is not None:
                try:
                    _rollback_log_append(self._fh.fileno(), checkpoint_size)
                except Exception:
                    pass
            self._disabled = True

    def close(self) -> None:
        handle = getattr(self, "_fh", None)
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass
            self._fh = None
        _safe_close_descriptor(getattr(self, "_parent_descriptor", -1))
        self._parent_descriptor = -1
        super().close()


def get_logger(
    name: str,
    log_file: Path | None = None,
    quiet: bool = False,
    verbose: bool = False,
) -> logging.Logger:
    """Return a configured logger with Rich console + optional JSONL file output."""
    logger = logging.getLogger(name)
    if logger.handlers:
        for handler in logger.handlers:
            if redaction_filter() not in handler.filters:
                handler.addFilter(redaction_filter())
        return logger

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not quiet:
        rich_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
        )
        rich_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        rich_handler.addFilter(redaction_filter())
        logger.addHandler(rich_handler)

    if log_file:
        file_handler = JsonlFileHandler(log_file, module_name=name)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

    return logger


def phase_banner(number: int, total: int, name: str) -> None:
    """Print a phase separator banner to the Rich console."""
    console.print(f"\n[phase]{'═' * 60}[/phase]")
    console.print(f"[phase]  PHASE {number}/{total}: {redact_text(name).upper()}[/phase]")
    console.print(f"[phase]{'═' * 60}[/phase]\n")


def finding_banner(title: str, severity: str) -> None:
    """Print a finding alert to the Rich console."""
    color = {
        "Critical": "bold white on red",
        "High":     "bold red",
        "Medium":   "bold yellow",
        "Low":      "yellow",
        "Informational": "cyan",
    }.get(severity, "white")
    console.print(
        f"[{color}]  [FINDING] {severity.upper()}: {redact_text(title)}[/{color}]"
    )


class TestLogger:
    """Unit tests for logger module."""

    def test_get_logger_returns_logger(self) -> None:
        lg = get_logger("test.logger")
        assert isinstance(lg, logging.Logger)

    def test_get_logger_idempotent(self) -> None:
        lg1 = get_logger("test.idem")
        lg2 = get_logger("test.idem")
        assert lg1 is lg2

    def test_jsonl_handler_writes(self, tmp_path: Path) -> None:
        p = tmp_path / "test.log"
        lg = get_logger("test.jsonl", log_file=p, quiet=True)
        lg.info("hello")
        lines = p.read_text().strip().split("\n")
        assert len(lines) >= 1
        entry = json.loads(lines[0])
        assert entry["event"] == "hello"


if __name__ == "__main__":
    lg = get_logger("demo", verbose=True)
    phase_banner(1, 12, "Reconnaissance")
    lg.info("Logger working correctly")
    finding_banner("SQL Injection", "High")
