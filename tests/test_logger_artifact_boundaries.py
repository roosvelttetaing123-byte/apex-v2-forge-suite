"""Deterministic filesystem-boundary regressions for JSONL audit logs."""
from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path

import pytest

import common.artifact_io as artifact_io
import common.logger as logger_module
from common.logger import JsonlFileHandler


def _record(message: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="fixture",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg=message,
        args=(),
        exc_info=None,
    )


def test_logger_rejects_intermediate_directory_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    (real / "nested").mkdir(parents=True)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValueError, match="log destination is unavailable"):
        JsonlFileHandler(linked / "nested" / "audit.jsonl")

    assert list((real / "nested").iterdir()) == []


def test_logger_parent_swap_stays_on_pinned_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_root = tmp_path / "requested"
    requested_logs = requested_root / "logs"
    requested_logs.mkdir(parents=True)
    moved_root = tmp_path / "pinned-original"

    redirected_root = tmp_path / "redirected"
    redirected_logs = redirected_root / "logs"
    redirected_logs.mkdir(parents=True)
    victim = redirected_logs / "audit.jsonl"
    victim.write_text("VICTIM_CANARY_UNCHANGED", encoding="utf-8")
    victim.chmod(0o644)

    real_open = artifact_io.os.open
    swapped = False

    def swap_before_leaf_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and path == "audit.jsonl" and dir_fd is not None:
            requested_root.rename(moved_root)
            requested_root.symlink_to(redirected_root, target_is_directory=True)
            swapped = True
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(artifact_io.os, "open", swap_before_leaf_open)
    handler = JsonlFileHandler(requested_logs / "audit.jsonl", module_name="fixture")
    try:
        handler.emit(_record("PINNED_APPEND"))
    finally:
        handler.close()

    pinned_log = moved_root / "logs" / "audit.jsonl"
    assert swapped is True
    assert json.loads(pinned_log.read_text(encoding="utf-8"))["event"] == "PINNED_APPEND"
    assert victim.read_text(encoding="utf-8") == "VICTIM_CANARY_UNCHANGED"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644


def test_logger_preserves_existing_parent_and_privately_creates_descendants(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "caller-owned"
    existing.mkdir(mode=0o755)
    existing.chmod(0o755)
    nested = existing / "private" / "logs"

    previous_umask = os.umask(0)
    try:
        handler = JsonlFileHandler(nested / "audit.jsonl")
    finally:
        os.umask(previous_umask)
    try:
        assert stat.S_IMODE(existing.stat().st_mode) == 0o755
        assert stat.S_IMODE((existing / "private").stat().st_mode) == 0o700
        assert stat.S_IMODE(nested.stat().st_mode) == 0o700
        assert stat.S_IMODE((nested / "audit.jsonl").stat().st_mode) == 0o600
    finally:
        handler.close()


@pytest.mark.parametrize("alias_kind", ["symlink", "hardlink"])
def test_logger_rejects_linked_leaf_without_mutating_victim(
    tmp_path: Path,
    alias_kind: str,
) -> None:
    victim = tmp_path / "victim.jsonl"
    victim.write_text("LEAF_CANARY_UNCHANGED", encoding="utf-8")
    victim.chmod(0o644)
    destination = tmp_path / "audit.jsonl"
    if alias_kind == "symlink":
        destination.symlink_to(victim)
    else:
        os.link(victim, destination)

    with pytest.raises(ValueError, match="log destination is unavailable"):
        JsonlFileHandler(destination)

    assert victim.read_text(encoding="utf-8") == "LEAF_CANARY_UNCHANGED"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644


def test_logger_closes_descriptor_when_fdopen_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_boundary_open = logger_module.open_owner_only_file
    captured: dict[str, int] = {}

    def capture_boundary_descriptor(*args: object, **kwargs: object) -> tuple[Path, int]:
        candidate, descriptor = real_boundary_open(*args, **kwargs)
        captured["descriptor"] = descriptor
        return candidate, descriptor

    def fail_fdopen(*_args: object, **_kwargs: object) -> None:
        raise OSError("FDOPEN_CANARY")

    monkeypatch.setattr(
        logger_module,
        "open_owner_only_file",
        capture_boundary_descriptor,
    )
    monkeypatch.setattr(logger_module.os, "fdopen", fail_fdopen)

    with pytest.raises(ValueError, match="log destination is unavailable") as exc_info:
        JsonlFileHandler(tmp_path / "audit.jsonl")

    assert "FDOPEN_CANARY" not in str(exc_info.value)
    with pytest.raises(OSError):
        os.fstat(captured["descriptor"])
