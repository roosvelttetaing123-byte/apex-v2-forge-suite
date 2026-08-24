#!/usr/bin/env python3
"""Verify independently reviewed Bandit and detect-secrets baselines."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tomllib
from collections import Counter
from contextlib import contextmanager
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Mapping


ROOT = Path(__file__).resolve().parents[1]
TASK_ID = "008"
TASK_SHA256 = "ba38ababe417c56ebb1296b8e54a1877d27ace0da10e81b280a726ae900e5e15"
SECURITY_REVIEW = Path("config/security-review.toml")
BANDIT_BASELINE = Path("config/bandit-baseline.json")
SECRET_BASELINE = Path(".secrets.baseline")
SCANNER_CONTRACT = Path("scripts/verify_supply_chain.py")
DEVELOPMENT_LOCK = Path("requirements-dev.lock")
DOCKERFILE_CONTRACT = Path("Dockerfile")
DOCKERIGNORE_CONTRACT = Path(".dockerignore")
CONTEXT_INVENTORY_CONTRACT = "forge-filesystem-candidate-with-docker-context-v1"
BANDIT_SCHEMA = "forge-bandit-baseline-v2"
BANDIT_VERSION = "1.8.6"
DETECT_SECRETS_VERSION = "1.5.0"
PYTHON_VERSION = "3.13.9"
BANDIT_PATHS = (
    "common",
    "webforge",
    "netforge",
    "adforge",
    "aiforge",
    "forge_c2",
    "forge_collab",
    "forge_payload",
    "cloud",
    "leak_intel",
)
_NONCANDIDATE_DIRECTORY_NAMES = {
    ".tls",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "results",
}
_NONCANDIDATE_FILE_SUFFIXES = (".pyc", ".pyd", ".pyo")
_LOCAL_PRIVATE_FILE_SUFFIXES = (".key", ".pem")
_CANDIDATE_ROOT_FILES = (
    ".dockerignore",
    ".env.example",
    ".gitignore",
    "AGENTS.md",
    "ASSESSMENT_INPUT_MANIFEST.sha256",
    "COMMERCIAL_COMPARISON.md",
    "Dockerfile",
    "ENTERPRISE_MATURITY_ASSESSMENT.md",
    "HANDOFF.md",
    "Makefile",
    "README.md",
    "ROADMAP.md",
    "ROADMAP2ND.md",
    "VERSION",
    "docker-compose.yml",
    "forge.py",
    "forge_agent.py",
    "install.sh",
    "pyproject.toml",
    "redteaming-roadmap.txt",
    "requirements-dev.in",
    "requirements-dev.lock",
    "requirements.in",
    "requirements.lock",
    "requirements.txt",
    "scan_jobs.db.schema.lock",
    "skill.md",
)
_CANDIDATE_ROOT_DIRECTORIES = (
    ".github",
    "adforge",
    "aiforge",
    "apex-ui",
    "cloud",
    "common",
    "config",
    "contracts",
    "docs",
    "forge_c2",
    "forge_collab",
    "forge_payload",
    "leak_intel",
    "netforge",
    "scripts",
    "tests",
    "webforge",
)
_NONCANDIDATE_ROOT_FILES = {
    ".coverage",
    ".secrets.baseline",
    "APEX_Platform_Design_Spec.pptx",
    "coverage.xml",
    "dwf_5knhyr.html",
    "engagement.db",
    "engagement.db-journal",
    "engagement.db-shm",
    "engagement.db-wal",
    "scan_history.json",
    "scan_jobs.db",
    "scan_jobs.db-journal",
    "scan_jobs.db-shm",
    "scan_jobs.db-wal",
}
_NONCANDIDATE_ROOT_DIRECTORIES = {
    ".agents",
    ".codex",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "artifacts",
    "build",
    "c2_data",
    "coverage",
    "dist",
    "engagements",
    "evidence",
    "extracted_images",
    "htmlcov",
    "reports",
    "results",
    "secrets",
    "tmp",
    "venv",
}
_DOCKER_CONTEXT_CONTROL_FILES = (".dockerignore", "Dockerfile")
_DOCKER_CONTEXT_ROOT_FILES = (
    "VERSION",
    "forge.py",
    "forge_agent.py",
    "requirements.lock",
    "apex-ui/index.html",
    "apex-ui/package-lock.json",
    "apex-ui/package.json",
    "apex-ui/tsconfig.json",
    "apex-ui/vite.config.js",
)
_DOCKER_CONTEXT_ROOT_DIRECTORIES = (
    "common",
    "webforge",
    "netforge",
    "adforge",
    "aiforge",
    "forge_c2",
    "forge_collab",
    "forge_payload",
    "cloud",
    "leak_intel",
    "apex-ui/public",
    "apex-ui/src",
)
_DOCKER_CONTEXT_EXCLUDED_FILES = {
    "common/intel/forge_intel.db",
    "webforge/engagement.db",
}
_DOCKER_CONTEXT_ALLOWED_BINARY_FILES = {
    "apex-ui/src/assets/hero.png",
    "common/dashboard/web/static/images/cyber_demon_logo.png",
    "common/dashboard/web/static/images/forge_logo.png",
}
_CANDIDATE_ALLOWED_BINARY_FILES = {
    *_DOCKER_CONTEXT_ALLOWED_BINARY_FILES,
    "common/intel/forge_intel.db",
    "webforge/engagement.db",
}
_DOCKERIGNORE_PATTERNS = (
    "**",
    "!VERSION",
    "!requirements.lock",
    "!forge.py",
    "!forge_agent.py",
    "!common/",
    "!common/**",
    "!webforge/",
    "!webforge/**",
    "!netforge/",
    "!netforge/**",
    "!adforge/",
    "!adforge/**",
    "!aiforge/",
    "!aiforge/**",
    "!forge_c2/",
    "!forge_c2/**",
    "!forge_collab/",
    "!forge_collab/**",
    "!forge_payload/",
    "!forge_payload/**",
    "!cloud/",
    "!cloud/**",
    "!leak_intel/",
    "!leak_intel/**",
    "!apex-ui/",
    "apex-ui/*",
    "!apex-ui/package.json",
    "!apex-ui/package-lock.json",
    "!apex-ui/index.html",
    "!apex-ui/tsconfig.json",
    "!apex-ui/vite.config.js",
    "!apex-ui/public/",
    "!apex-ui/public/**",
    "!apex-ui/src/",
    "!apex-ui/src/**",
    "**/.env",
    "**/.env.*",
    "**/.tls/",
    "**/*.key",
    "**/*.pem",
    "**/__pycache__/",
    "**/.mypy_cache/",
    "**/.pytest_cache/",
    "**/.ruff_cache/",
    "**/build/",
    "**/dist/",
    "**/node_modules/",
    "**/results/",
    "**/*.pyc",
    "**/*.pyo",
    "**/*.pyd",
    "common/intel/forge_intel.db",
    "webforge/engagement.db",
)
_DOCKERFILE_COPY_INSTRUCTIONS = (
    "COPY apex-ui/package.json apex-ui/package-lock.json ./",
    "COPY VERSION /build/VERSION",
    "COPY apex-ui/index.html apex-ui/tsconfig.json apex-ui/vite.config.js ./",
    "COPY apex-ui/public ./public",
    "COPY apex-ui/src ./src",
    "COPY requirements.lock ./",
    "COPY --from=python-builder /install /usr/local",
    "COPY --chown=0:0 VERSION forge.py forge_agent.py ./",
    "COPY --chown=0:0 common ./common",
    "COPY --chown=0:0 webforge ./webforge",
    "COPY --chown=0:0 netforge ./netforge",
    "COPY --chown=0:0 adforge ./adforge",
    "COPY --chown=0:0 aiforge ./aiforge",
    "COPY --chown=0:0 forge_c2 ./forge_c2",
    "COPY --chown=0:0 forge_collab ./forge_collab",
    "COPY --chown=0:0 forge_payload ./forge_payload",
    "COPY --chown=0:0 cloud ./cloud",
    "COPY --chown=0:0 leak_intel ./leak_intel",
    "COPY --chown=0:0 --from=frontend-builder /build/apex-ui/dist ./apex-ui/dist",
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY_RE = re.compile(
    r"^(?:[a-z][a-z0-9+.-]*:[A-Za-z0-9._/@+-]{1,120}|"
    r"[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+)$"
)
_EVIDENCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{7,255}$")
_RECEIPT_TABLES = ("scanner_contract", "baseline_set", "bandit", "detect_secrets")
_RECEIPT_KEYS = {
    "schema_version",
    "receipt_type",
    "task_id",
    "task_sha256",
    "decision",
    "implementer_identity",
    "reviewer_identity",
    "implemented_on",
    "reviewed_on",
    "expires_on",
    "reviewed_contract_sha256",
    "proposal_manifest_sha256",
    "review_evidence_id",
    "review_evidence_sha256",
    *_RECEIPT_TABLES,
}
_RECEIPT_ROOT_ORDER = (
    "schema_version",
    "receipt_type",
    "task_id",
    "task_sha256",
    "decision",
    "implementer_identity",
    "reviewer_identity",
    "implemented_on",
    "reviewed_on",
    "expires_on",
    "reviewed_contract_sha256",
    "proposal_manifest_sha256",
    "review_evidence_id",
    "review_evidence_sha256",
)
_RECEIPT_TABLE_ORDER = {
    "scanner_contract": (
        "path",
        "sha256",
        "python_version",
        "development_lock",
        "development_lock_sha256",
        "context_inventory_contract",
        "dockerfile",
        "dockerfile_sha256",
        "dockerignore",
        "dockerignore_sha256",
    ),
    "baseline_set": ("sha256",),
    "bandit": (
        "baseline",
        "baseline_sha256",
        "finding_count",
        "scope",
        "config",
        "config_sha256",
        "scanner_version",
        "severity",
        "confidence",
    ),
    "detect_secrets": (
        "baseline",
        "baseline_sha256",
        "finding_count",
        "path_count",
        "paths_sha256",
        "docker_path_count",
        "docker_paths_sha256",
        "plugin_count",
        "plugins_sha256",
        "scanner_version",
    ),
}


class SupplyChainError(RuntimeError):
    """Raised when a security baseline or its independent receipt is invalid."""


_GIT_CONTROL_FILE_LIMIT = 4096


def _git_repository_environment() -> dict[str, str]:
    """Return an environment without caller-controlled Git repository selectors."""

    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }


def _read_git_control_file(
    path: Path,
    label: str,
) -> tuple[bytes, tuple[int, int, int, int, int, int]]:
    """Read one bounded Git control file without following links or accepting drift."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SupplyChainError(f"{label} is missing, unreadable, or a symlink") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SupplyChainError(f"{label} must be a regular file")
        if before.st_size > _GIT_CONTROL_FILE_LIMIT:
            raise SupplyChainError(f"{label} exceeds the bounded control-file size")
        content = os.read(descriptor, _GIT_CONTROL_FILE_LIMIT + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity or len(content) != after.st_size:
        raise SupplyChainError(f"{label} changed while it was being read")
    return content, after_identity


def _git_path_record(content: bytes, label: str, *, prefix: bytes = b"") -> str:
    """Decode one canonical LF-terminated UTF-8 Git path record."""

    if not content.endswith(b"\n") or content.count(b"\n") != 1 or b"\r" in content:
        raise SupplyChainError(f"{label} must contain exactly one LF-terminated record")
    record = content[:-1]
    if prefix:
        if not record.startswith(prefix):
            raise SupplyChainError(f"{label} has invalid record syntax")
        record = record[len(prefix) :]
    if not record or any(byte < 0x20 or byte == 0x7F for byte in record):
        raise SupplyChainError(f"{label} contains an empty or unsafe path")
    try:
        return record.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SupplyChainError(f"{label} path is not canonical UTF-8") from exc


def _canonical_absolute_path(raw: str, label: str) -> Path:
    """Resolve an absolute path while rejecting lexical aliases and symlink traversal."""

    path = Path(raw)
    if not path.is_absolute() or str(path) != raw:
        raise SupplyChainError(f"{label} path is not canonical and absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise SupplyChainError(f"{label} path cannot be resolved") from exc
    if resolved != path:
        raise SupplyChainError(f"{label} path traverses a symlink or lexical alias")
    return resolved


def _real_directory_identity(
    path: Path,
    label: str,
) -> tuple[int, int, int, int, int]:
    """Capture a real canonical directory identity for later drift detection."""

    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise SupplyChainError(f"{label} cannot be inspected") from exc
    if not stat.S_ISDIR(path_stat.st_mode):
        raise SupplyChainError(f"{label} must be a real directory")
    try:
        if path.resolve(strict=True) != path:
            raise SupplyChainError(f"{label} must not traverse a symlink")
    except OSError as exc:
        raise SupplyChainError(f"{label} cannot be resolved") from exc
    return (
        path_stat.st_dev,
        path_stat.st_ino,
        path_stat.st_mode,
        path_stat.st_mtime_ns,
        path_stat.st_ctime_ns,
    )


def _assert_linked_worktree_unchanged(
    control_files: tuple[
        tuple[Path, str, tuple[bytes, tuple[int, int, int, int, int, int]]], ...
    ],
    directories: tuple[tuple[Path, str, tuple[int, int, int, int, int]], ...],
) -> None:
    """Fail when a linked-worktree marker or administrative path drifted."""

    for path, label, expected in control_files:
        if _read_git_control_file(path, label) != expected:
            raise SupplyChainError(f"{label} changed during Git validation")
    for directory_path, directory_label, directory_expected in directories:
        if _real_directory_identity(directory_path, directory_label) != directory_expected:
            raise SupplyChainError(f"{directory_label} changed during Git validation")


def _validate_linked_worktree_gitfile(
    root: Path,
) -> tuple[
    tuple[tuple[Path, str, tuple[bytes, tuple[int, int, int, int, int, int]]], ...],
    tuple[tuple[Path, str, tuple[int, int, int, int, int]], ...],
]:
    """Validate a regular ``.git`` marker as this exact linked worktree."""

    root = root.resolve(strict=True)
    root_identity = _real_directory_identity(root, "candidate root")
    marker = root / ".git"
    marker_snapshot = _read_git_control_file(marker, "linked-worktree .git marker")
    admin_raw = _git_path_record(
        marker_snapshot[0],
        "linked-worktree .git marker",
        prefix=b"gitdir: ",
    )
    git_admin = _canonical_absolute_path(admin_raw, "linked-worktree Git admin")
    admin_identity = _real_directory_identity(git_admin, "linked-worktree Git admin")

    commondir_path = git_admin / "commondir"
    commondir_snapshot = _read_git_control_file(
        commondir_path,
        "linked-worktree commondir",
    )
    common_raw = _git_path_record(commondir_snapshot[0], "linked-worktree commondir")
    common_reference = Path(common_raw)
    if str(common_reference) != common_raw:
        raise SupplyChainError("linked-worktree commondir path is not canonical")
    try:
        common_dir = (
            common_reference
            if common_reference.is_absolute()
            else git_admin / common_reference
        ).resolve(strict=True)
    except OSError as exc:
        raise SupplyChainError("linked-worktree common directory cannot be resolved") from exc
    if common_reference.is_absolute() and common_dir != common_reference:
        raise SupplyChainError("linked-worktree commondir path traverses a symlink")
    common_identity = _real_directory_identity(
        common_dir,
        "linked-worktree common directory",
    )
    worktrees_dir = common_dir / "worktrees"
    worktrees_identity = _real_directory_identity(
        worktrees_dir,
        "linked-worktree administrative parent",
    )
    if git_admin.parent != worktrees_dir or not git_admin.name:
        raise SupplyChainError("linked-worktree Git admin has invalid common-dir topology")

    backlink_path = git_admin / "gitdir"
    backlink_snapshot = _read_git_control_file(
        backlink_path,
        "linked-worktree gitdir backlink",
    )
    backlink_raw = _git_path_record(
        backlink_snapshot[0],
        "linked-worktree gitdir backlink",
    )
    backlink = _canonical_absolute_path(backlink_raw, "linked-worktree gitdir backlink")
    if backlink != marker:
        raise SupplyChainError("linked-worktree gitdir backlink does not name this marker")

    control_files = (
        (marker, "linked-worktree .git marker", marker_snapshot),
        (commondir_path, "linked-worktree commondir", commondir_snapshot),
        (backlink_path, "linked-worktree gitdir backlink", backlink_snapshot),
    )
    directories = (
        (root, "candidate root", root_identity),
        (git_admin, "linked-worktree Git admin", admin_identity),
        (common_dir, "linked-worktree common directory", common_identity),
        (worktrees_dir, "linked-worktree administrative parent", worktrees_identity),
    )

    try:
        resolved = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "rev-parse",
                "--path-format=absolute",
                "--show-toplevel",
                "--git-dir",
                "--git-common-dir",
                "--is-inside-work-tree",
                "--is-bare-repository",
            ],
            check=False,
            capture_output=True,
            timeout=30,
            env=_git_repository_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SupplyChainError("linked-worktree Git identity cannot be resolved") from exc
    if resolved.returncode != 0:
        raise SupplyChainError("linked-worktree Git identity cannot be resolved")
    if (
        not resolved.stdout.endswith(b"\n")
        or b"\r" in resolved.stdout
        or resolved.stdout.count(b"\n") != 5
    ):
        raise SupplyChainError("linked-worktree Git identity is not canonical output")
    try:
        resolved_records = resolved.stdout[:-1].decode("utf-8").split("\n")
    except UnicodeDecodeError as exc:
        raise SupplyChainError("linked-worktree Git identity is not canonical UTF-8") from exc
    expected_paths = (root, git_admin, common_dir)
    for raw, expected, label in zip(
        resolved_records[:3],
        expected_paths,
        ("worktree root", "Git admin", "common directory"),
        strict=True,
    ):
        if _canonical_absolute_path(raw, f"Git-resolved {label}") != expected:
            raise SupplyChainError(f"Git-resolved {label} differs from linked-worktree metadata")
    if resolved_records[3:] != ["true", "false"]:
        raise SupplyChainError("Git identity is not a non-bare worktree")
    _assert_linked_worktree_unchanged(control_files, directories)
    return control_files, directories


def _is_local_private_file(name: str) -> bool:
    """Classify private-looking filenames excluded when they are machine-local."""

    return (
        name == ".env"
        or (name.startswith(".env.") and name != ".env.example")
        or name.endswith(_LOCAL_PRIVATE_FILE_SUFFIXES)
    )


def _is_local_private_path(relative: str) -> bool:
    """Return whether a path has a machine-local credential shape."""

    pure = PurePosixPath(relative)
    return ".tls" in pure.parts or _is_local_private_file(pure.name)


def _tracked_local_private_paths(root: Path) -> tuple[str, ...]:
    """Return private-shaped files explicitly tracked by this exact Git worktree.

    Untracked TLS and environment material remains outside the deterministic
    candidate and Docker inventories.  A force-added private-looking file is
    source, however, and must enter the secret scan instead of disappearing
    behind the machine-local exclusions.
    """

    git_marker = root / ".git"
    if not git_marker.exists() and not git_marker.is_symlink():
        return ()
    try:
        marker_stat = git_marker.lstat()
    except OSError as exc:
        raise SupplyChainError("Git worktree marker cannot be inspected") from exc
    if stat.S_ISLNK(marker_stat.st_mode) or not (
        stat.S_ISDIR(marker_stat.st_mode) or stat.S_ISREG(marker_stat.st_mode)
    ):
        raise SupplyChainError("Git worktree marker has an unsupported type")

    linked_snapshot = None
    if stat.S_ISREG(marker_stat.st_mode):
        linked_snapshot = _validate_linked_worktree_gitfile(root)

    try:
        top_level = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            timeout=30,
            env=_git_repository_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SupplyChainError("Git worktree identity cannot be resolved") from exc
    if top_level.returncode != 0:
        raise SupplyChainError("Git worktree identity cannot be resolved")
    try:
        resolved_top_level = Path(top_level.stdout.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as exc:
        raise SupplyChainError("Git worktree identity is not canonical UTF-8") from exc
    if resolved_top_level != root:
        raise SupplyChainError("Git worktree root differs from the candidate root")
    if linked_snapshot is not None:
        _assert_linked_worktree_unchanged(*linked_snapshot)

    try:
        tracked = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--"],
            check=False,
            capture_output=True,
            timeout=30,
            env=_git_repository_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SupplyChainError("tracked source inventory cannot be enumerated") from exc
    if tracked.returncode != 0:
        raise SupplyChainError("tracked source inventory cannot be enumerated")
    if linked_snapshot is not None:
        _assert_linked_worktree_unchanged(*linked_snapshot)

    private_paths: list[str] = []
    for encoded in tracked.stdout.split(b"\0"):
        if not encoded:
            continue
        try:
            relative = _safe_inventory_path(encoded.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise SupplyChainError("tracked source path is not canonical UTF-8") from exc
        if not _is_local_private_path(relative):
            continue
        path = root / relative
        try:
            path_stat = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SupplyChainError(
                f"tracked private path cannot be inspected: {relative}"
            ) from exc
        if stat.S_ISLNK(path_stat.st_mode):
            raise SupplyChainError(f"tracked private path must not be a symlink: {relative}")
        if not stat.S_ISREG(path_stat.st_mode):
            raise SupplyChainError(
                f"tracked private path must be a regular file: {relative}"
            )
        private_paths.append(relative)
    if linked_snapshot is not None:
        _assert_linked_worktree_unchanged(*linked_snapshot)
    return tuple(sorted(private_paths))


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _read_regular_bytes(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SupplyChainError(f"{label} is missing, unreadable, or a symlink: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SupplyChainError(f"{label} must be a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or sum(len(chunk) for chunk in chunks) != after.st_size:
        raise SupplyChainError(f"{label} changed while it was being read: {path}")
    return b"".join(chunks)


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sorted_nul_digest(values: Iterable[str]) -> str:
    ordered = sorted(values)
    payload = b"".join(value.encode("utf-8") + b"\0" for value in ordered)
    return _sha256_bytes(payload)


def _relative_filename(filename: str, root: Path) -> str:
    path = Path(filename)
    if not path.is_absolute():
        path = root / path
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _normalized_bandit_code(code: str) -> str:
    lines = []
    for line in code.splitlines():
        lines.append(re.sub(r"^\s*\d+\s+", "", line).rstrip())
    return "\n".join(lines).strip()


def scan_bandit(
    root: Path,
    paths: tuple[str, ...] = BANDIT_PATHS,
    config: Path | None = None,
) -> list[dict[str, Any]]:
    command = [
        sys.executable,
        "-m",
        "bandit",
        "-q",
        "-r",
        *paths,
        "-ll",
        "-ii",
        "-f",
        "json",
    ]
    if config is not None:
        command.extend(["-c", str(config)])
    completed = subprocess.run(
        command,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if completed.returncode not in (0, 1):
        raise SupplyChainError(
            f"Bandit execution failed with exit {completed.returncode}: {completed.stderr.strip()}"
        )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SupplyChainError("Bandit did not produce valid JSON") from exc

    provisional: list[dict[str, Any]] = []
    for finding in report.get("results", []):
        filename = _relative_filename(str(finding.get("filename", "")), root)
        normalized_code = _normalized_bandit_code(str(finding.get("code", "")))
        record = {
            "filename": filename,
            "test_id": str(finding.get("test_id", "")),
            "test_name": str(finding.get("test_name", "")),
            "severity": str(finding.get("issue_severity", "")).upper(),
            "confidence": str(finding.get("issue_confidence", "")).upper(),
            "issue": str(finding.get("issue_text", "")).strip(),
            "source_sha256": _sha256_bytes(normalized_code.encode("utf-8")),
            "line": int(finding.get("line_number") or 0),
        }
        fingerprint_input = {key: value for key, value in record.items() if key != "line"}
        # Preserve the reviewed v1 fingerprint encoding while moving approval
        # metadata out of the baseline document.
        fingerprint_bytes = json.dumps(fingerprint_input, sort_keys=True).encode("utf-8")
        record["base_fingerprint"] = _sha256_bytes(fingerprint_bytes)
        provisional.append(record)

    provisional.sort(key=lambda item: (item["base_fingerprint"], item["filename"], item["line"]))
    occurrences: Counter[str] = Counter()
    normalized: list[dict[str, Any]] = []
    for record in provisional:
        base_fingerprint = record.pop("base_fingerprint")
        record.pop("line")
        occurrences[base_fingerprint] += 1
        record["occurrence"] = occurrences[base_fingerprint]
        record["fingerprint"] = _sha256_bytes(
            f"{base_fingerprint}:{record['occurrence']}".encode("ascii")
        )
        normalized.append(record)
    return sorted(normalized, key=lambda item: item["fingerprint"])


def bandit_proposal_document(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Return unreviewed baseline bytes suitable only for an external proposal."""

    return {"schema_version": BANDIT_SCHEMA, "findings": findings}


def _safe_inventory_path(relative: str) -> str:
    pure = PurePosixPath(relative)
    if (
        not relative
        or pure.is_absolute()
        or ".." in pure.parts
        or pure.as_posix() != relative
        or any(character in relative for character in ("\x00", "\n", "\r"))
    ):
        raise SupplyChainError(f"candidate inventory contains an unsafe path: {relative!r}")
    try:
        relative.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SupplyChainError(
            f"candidate inventory path is not canonical UTF-8: {relative!r}"
        ) from exc
    return relative


def _walk_regular_files(
    root: Path,
    relative_directory: str,
    *,
    excluded_files: set[str],
) -> Iterator[str]:
    relative_directory = _safe_inventory_path(relative_directory)
    directory = root / relative_directory
    try:
        directory_stat = directory.lstat()
    except OSError as exc:
        raise SupplyChainError(
            f"required candidate directory is missing: {relative_directory}"
        ) from exc
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise SupplyChainError(
            f"required candidate directory is not a real directory: {relative_directory}"
        )

    def _walk(current: Path, current_relative: str) -> Iterator[str]:
        try:
            entries = sorted(os.scandir(current), key=lambda entry: os.fsencode(entry.name))
        except OSError as exc:
            raise SupplyChainError(
                f"candidate directory cannot be enumerated: {current_relative}"
            ) from exc
        for entry in entries:
            relative = _safe_inventory_path(f"{current_relative}/{entry.name}")
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise SupplyChainError(f"candidate path cannot be inspected: {relative}") from exc
            if stat.S_ISDIR(entry_stat.st_mode):
                if entry.name not in _NONCANDIDATE_DIRECTORY_NAMES:
                    yield from _walk(Path(entry.path), relative)
                continue
            if stat.S_ISLNK(entry_stat.st_mode):
                raise SupplyChainError(f"candidate path must not be a symlink: {relative}")
            if not stat.S_ISREG(entry_stat.st_mode):
                raise SupplyChainError(f"candidate path must be a regular file: {relative}")
            if (
                relative in excluded_files
                or relative.endswith(_NONCANDIDATE_FILE_SUFFIXES)
                or _is_local_private_file(entry.name)
            ):
                continue
            yield relative

    yield from _walk(directory, relative_directory)


def _regular_inventory_paths(
    root: Path,
    *,
    root_files: Iterable[str],
    root_directories: Iterable[str],
    excluded_files: set[str],
) -> tuple[str, ...]:
    paths: list[str] = []
    for relative in root_files:
        relative = _safe_inventory_path(relative)
        path = root / relative
        try:
            path_stat = path.lstat()
        except OSError as exc:
            raise SupplyChainError(f"required candidate file is missing: {relative}") from exc
        if not stat.S_ISREG(path_stat.st_mode):
            raise SupplyChainError(f"required candidate file is not regular: {relative}")
        if relative not in excluded_files and not relative.endswith(_NONCANDIDATE_FILE_SUFFIXES):
            paths.append(relative)
    for relative_directory in root_directories:
        paths.extend(
            _walk_regular_files(
                root,
                relative_directory,
                excluded_files=excluded_files,
            )
        )
    if len(paths) != len(set(paths)):
        raise SupplyChainError("candidate inventory roots overlap")
    return tuple(sorted(paths))


def _validate_top_level_classification(root: Path) -> None:
    candidate_files = set(_CANDIDATE_ROOT_FILES)
    candidate_directories = set(_CANDIDATE_ROOT_DIRECTORIES)
    unknown: list[str] = []
    try:
        entries = sorted(os.scandir(root), key=lambda entry: os.fsencode(entry.name))
    except OSError as exc:
        raise SupplyChainError("candidate root cannot be enumerated") from exc
    for entry in entries:
        name = _safe_inventory_path(entry.name)
        try:
            entry_stat = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise SupplyChainError(f"top-level candidate path cannot be inspected: {name}") from exc
        if stat.S_ISLNK(entry_stat.st_mode):
            raise SupplyChainError(f"top-level candidate path must not be a symlink: {name}")
        if stat.S_ISREG(entry_stat.st_mode):
            if name == ".git":
                _validate_linked_worktree_gitfile(root)
                continue
            if (
                name not in candidate_files
                and name not in _NONCANDIDATE_ROOT_FILES
                and not _is_local_private_file(name)
            ):
                unknown.append(name)
            continue
        if stat.S_ISDIR(entry_stat.st_mode):
            if name not in candidate_directories and name not in _NONCANDIDATE_ROOT_DIRECTORIES:
                unknown.append(name)
            continue
        raise SupplyChainError(f"top-level candidate path has unsupported type: {name}")
    if unknown:
        raise SupplyChainError(f"unclassified top-level candidate paths: {unknown[:3]}")


def _text_inventory(
    root: Path,
    paths: Iterable[str],
    *,
    allowed_binary_files: set[str],
) -> tuple[str, ...]:
    text_paths: list[str] = []
    for relative in paths:
        content = _read_regular_bytes(root / relative, f"candidate file {relative}")
        if b"\x00" in content:
            if relative not in allowed_binary_files:
                raise SupplyChainError(f"candidate contains an unreviewed binary file: {relative}")
            continue
        try:
            content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SupplyChainError(
                f"candidate file is neither NUL-marked binary nor UTF-8 text: {relative}"
            ) from exc
        text_paths.append(relative)
    return tuple(sorted(text_paths))


def _validate_dockerignore_contract(root: Path) -> bytes:
    content = _read_regular_bytes(root / DOCKERIGNORE_CONTRACT, "Docker ignore contract")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SupplyChainError(".dockerignore must be canonical UTF-8") from exc
    if not text.endswith("\n") or "\r" in text:
        raise SupplyChainError(".dockerignore must use canonical LF-terminated lines")
    patterns: list[str] = []
    for line in text.splitlines():
        if line != line.strip():
            raise SupplyChainError(".dockerignore patterns must not contain edge whitespace")
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    if tuple(patterns) != _DOCKERIGNORE_PATTERNS:
        raise SupplyChainError(
            ".dockerignore differs from the exact fail-closed build-context allowlist"
        )
    return content


def _validate_dockerfile_contract(root: Path) -> bytes:
    content = _read_regular_bytes(root / DOCKERFILE_CONTRACT, "Dockerfile contract")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SupplyChainError("Dockerfile must be canonical UTF-8") from exc
    if "\r" in text:
        raise SupplyChainError("Dockerfile must use LF line endings")
    instructions = tuple(
        line.strip() for line in text.splitlines() if re.match(r"(?i)^\s*(?:ADD|COPY)\s+", line)
    )
    if any(instruction.upper().startswith("ADD ") for instruction in instructions):
        raise SupplyChainError("Dockerfile ADD instructions are forbidden")
    if instructions != _DOCKERFILE_COPY_INSTRUCTIONS:
        raise SupplyChainError("Dockerfile local COPY allowlist changed")
    if re.search(r"(?im)^\s*RUN\s+--mount", text):
        raise SupplyChainError("Dockerfile context bind mounts are forbidden")
    return content


def docker_shipped_text_paths(root: Path) -> tuple[str, ...]:
    """Return every UTF-8 Docker control or COPY-accessible candidate file."""

    root = root.resolve(strict=True)
    _validate_dockerignore_contract(root)
    _validate_dockerfile_contract(root)
    regular_paths = _regular_inventory_paths(
        root,
        root_files=(*_DOCKER_CONTEXT_CONTROL_FILES, *_DOCKER_CONTEXT_ROOT_FILES),
        root_directories=_DOCKER_CONTEXT_ROOT_DIRECTORIES,
        excluded_files=_DOCKER_CONTEXT_EXCLUDED_FILES,
    )
    return _text_inventory(
        root,
        regular_paths,
        allowed_binary_files=_DOCKER_CONTEXT_ALLOWED_BINARY_FILES,
    )


def secret_scan_paths(root: Path) -> tuple[str, ...]:
    """Return the deterministic source inventory, including all Docker-shipped text."""

    root = root.resolve(strict=True)
    shipped_paths = set(docker_shipped_text_paths(root))
    _validate_top_level_classification(root)
    # These outputs recursively bind this inventory and therefore cannot scan
    # themselves.  The filesystem remains the primary inventory; Git is used
    # only to add back private-shaped paths that were explicitly force-tracked.
    excluded_files = {
        SECRET_BASELINE.as_posix(),
        BANDIT_BASELINE.as_posix(),
        SECURITY_REVIEW.as_posix(),
    }
    regular_paths = _regular_inventory_paths(
        root,
        root_files=_CANDIDATE_ROOT_FILES,
        root_directories=_CANDIDATE_ROOT_DIRECTORIES,
        excluded_files=excluded_files,
    )
    tracked_private_paths = _tracked_local_private_paths(root)
    candidate_paths = _text_inventory(
        root,
        sorted(set(regular_paths).union(tracked_private_paths)),
        allowed_binary_files=_CANDIDATE_ALLOWED_BINARY_FILES,
    )
    missing = sorted(shipped_paths.difference(candidate_paths))
    if missing:
        raise SupplyChainError(
            f"Docker-shipped text is outside the secret inventory: {missing[:3]}"
        )
    return candidate_paths


@contextmanager
def _detect_secrets_settings() -> Iterator[None]:
    try:
        from detect_secrets.settings import default_settings
    except ImportError as exc:
        raise SupplyChainError("detect-secrets is not installed from the development lock") from exc
    with default_settings():
        yield


def scan_secrets(root: Path, paths: tuple[str, ...] | None = None) -> dict[str, Any]:
    try:
        from detect_secrets.core import baseline as detect_baseline
        from detect_secrets.core.secrets_collection import SecretsCollection
    except ImportError as exc:
        raise SupplyChainError("detect-secrets is not installed from the development lock") from exc
    selected = paths if paths is not None else secret_scan_paths(root)
    with _detect_secrets_settings():
        collection = SecretsCollection(root=str(root))
        for relative_path in selected:
            collection.scan_file(relative_path)
        document = detect_baseline.format_for_output(collection, is_slim_mode=True)
    results = document.get("results", {})
    if not isinstance(results, dict):
        raise SupplyChainError("detect-secrets returned an invalid results object")
    for items in results.values():
        if not isinstance(items, list):
            raise SupplyChainError("detect-secrets returned an invalid finding list")
        for item in items:
            item.pop("filename", None)
        items.sort(key=lambda item: (str(item.get("type")), str(item.get("hashed_secret"))))
    document["results"] = dict(sorted(results.items()))
    return document


def secret_proposal_document(
    root: Path,
    paths: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Return an unreviewed detect-secrets proposal with no approval metadata."""

    return scan_secrets(root, paths=paths)


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    content = _read_regular_bytes(path, label)
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupplyChainError(f"{label} is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(document, dict):
        raise SupplyChainError(f"{label} must be a JSON object")
    return document, content


def _validate_bandit_baseline_document(document: Mapping[str, Any]) -> None:
    if set(document) != {"schema_version", "findings"}:
        raise SupplyChainError(
            "Bandit baseline must be an unreviewed v2 scan document; approval belongs only in "
            "config/security-review.toml"
        )
    if document.get("schema_version") != BANDIT_SCHEMA:
        raise SupplyChainError(f"Bandit baseline schema must be {BANDIT_SCHEMA}")
    findings = document.get("findings")
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise SupplyChainError("Bandit baseline findings must be a list of objects")
    fingerprints = [item.get("fingerprint") for item in findings]
    if any(not isinstance(value, str) or not _SHA256_RE.fullmatch(value) for value in fingerprints):
        raise SupplyChainError("Bandit baseline contains an invalid finding fingerprint")
    if len(set(fingerprints)) != len(fingerprints):
        raise SupplyChainError("Bandit baseline contains duplicate finding fingerprints")


def _load_bandit_baseline(path: Path) -> tuple[dict[str, Any], bytes]:
    document, content = _load_json(path, "Bandit baseline")
    _validate_bandit_baseline_document(document)
    return document, content


def _validate_secret_baseline_document(document: Mapping[str, Any]) -> None:
    required = {"version", "plugins_used", "filters_used", "results"}
    if set(document) != required:
        raise SupplyChainError(
            "detect-secrets baseline must contain only scanner output; approval belongs only in "
            "config/security-review.toml"
        )
    if document.get("version") != DETECT_SECRETS_VERSION:
        raise SupplyChainError(f"detect-secrets baseline version must be {DETECT_SECRETS_VERSION}")
    if not isinstance(document.get("plugins_used"), list) or not document["plugins_used"]:
        raise SupplyChainError("detect-secrets baseline plugins_used must be a non-empty list")
    if not all(isinstance(plugin, dict) for plugin in document["plugins_used"]):
        raise SupplyChainError("detect-secrets baseline plugins_used contains a non-object")
    if not isinstance(document.get("filters_used"), list):
        raise SupplyChainError("detect-secrets baseline filters_used must be a list")
    results = document.get("results")
    if not isinstance(results, dict):
        raise SupplyChainError("detect-secrets baseline results must be an object")
    if not all(
        isinstance(path, str) and isinstance(items, list) for path, items in results.items()
    ):
        raise SupplyChainError("detect-secrets baseline results contain an invalid entry")
    forbidden = {BANDIT_BASELINE.as_posix(), SECRET_BASELINE.as_posix(), SECURITY_REVIEW.as_posix()}
    if forbidden.intersection(results):
        raise SupplyChainError(
            "detect-secrets baseline recursively scans a bound baseline or receipt"
        )


def _load_secret_baseline(path: Path) -> tuple[dict[str, Any], bytes]:
    document, content = _load_json(path, "detect-secrets baseline")
    _validate_secret_baseline_document(document)
    return document, content


def _scanner_versions(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    if overrides is None:
        try:
            versions = {
                "bandit": importlib.metadata.version("bandit"),
                "detect-secrets": importlib.metadata.version("detect-secrets"),
            }
        except importlib.metadata.PackageNotFoundError as exc:
            raise SupplyChainError(
                "security scanners are not installed from the development lock"
            ) from exc
    else:
        versions = dict(overrides)
    expected = {"bandit": BANDIT_VERSION, "detect-secrets": DETECT_SECRETS_VERSION}
    if versions != expected:
        raise SupplyChainError(
            f"security scanner versions changed: expected={expected} actual={versions}"
        )
    return versions


def _validate_secret_path_inventory(paths: Iterable[str]) -> tuple[str, ...]:
    inventory = tuple(paths)
    if len(set(inventory)) != len(inventory):
        raise SupplyChainError("detect-secrets path inventory contains duplicates")
    forbidden = {BANDIT_BASELINE.as_posix(), SECRET_BASELINE.as_posix(), SECURITY_REVIEW.as_posix()}
    for path in inventory:
        pure = PurePosixPath(path)
        if (
            not path
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.as_posix() != path
            or path in forbidden
        ):
            raise SupplyChainError(
                f"detect-secrets path inventory contains an unsafe path: {path!r}"
            )
    return tuple(sorted(inventory))


def _security_review_context_from_documents(
    root: Path,
    *,
    bandit: Mapping[str, Any],
    bandit_bytes: bytes,
    secrets: Mapping[str, Any],
    secret_bytes: bytes,
    secret_paths: Iterable[str] | None = None,
    scanner_versions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    _validate_bandit_baseline_document(bandit)
    _validate_secret_baseline_document(secrets)
    versions = _scanner_versions(scanner_versions)
    if platform.python_version() != PYTHON_VERSION:
        raise SupplyChainError(
            f"security scanner Python changed: expected={PYTHON_VERSION} "
            f"actual={platform.python_version()}"
        )

    config_path = root / "pyproject.toml"
    config_bytes = _read_regular_bytes(config_path, "Bandit configuration")
    try:
        configuration = tomllib.loads(config_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SupplyChainError("Bandit configuration is missing or invalid") from exc
    bandit_config = configuration.get("tool", {}).get("bandit")
    if not isinstance(bandit_config, dict):
        raise SupplyChainError("pyproject.toml is missing [tool.bandit]")
    if bandit_config.get("severity") != "medium" or bandit_config.get("confidence") != "medium":
        raise SupplyChainError("Bandit severity/confidence must both remain medium")

    inventory = _validate_secret_path_inventory(
        secret_scan_paths(root) if secret_paths is None else secret_paths
    )
    docker_inventory = docker_shipped_text_paths(root)
    missing_docker_paths = sorted(set(docker_inventory).difference(inventory))
    if missing_docker_paths:
        raise SupplyChainError(
            f"reviewed inventory omits Docker-shipped text: {missing_docker_paths[:3]}"
        )
    secret_results = secrets["results"]
    result_paths_outside_inventory = sorted(set(secret_results).difference(inventory))
    if result_paths_outside_inventory:
        raise SupplyChainError(
            "detect-secrets result paths are outside the reviewed inventory: "
            f"{result_paths_outside_inventory[:3]}"
        )
    secret_findings = sum(len(items) for items in secret_results.values())
    scanner_contract_bytes = _read_regular_bytes(
        root / SCANNER_CONTRACT,
        "supply-chain scanner contract",
    )
    development_lock_bytes = _read_regular_bytes(
        root / DEVELOPMENT_LOCK,
        "development dependency lock",
    )
    dockerfile_bytes = _validate_dockerfile_contract(root)
    dockerignore_bytes = _validate_dockerignore_contract(root)
    bandit_sha256 = _sha256_bytes(bandit_bytes)
    secret_sha256 = _sha256_bytes(secret_bytes)
    baseline_rows = [
        {
            "finding_count": len(bandit["findings"]),
            "path": BANDIT_BASELINE.as_posix(),
            "sha256": bandit_sha256,
        },
        {
            "finding_count": secret_findings,
            "path": SECRET_BASELINE.as_posix(),
            "sha256": secret_sha256,
        },
    ]
    context: dict[str, Any] = {
        "scanner_contract": {
            "path": SCANNER_CONTRACT.as_posix(),
            "sha256": _sha256_bytes(scanner_contract_bytes),
            "python_version": PYTHON_VERSION,
            "development_lock": DEVELOPMENT_LOCK.as_posix(),
            "development_lock_sha256": _sha256_bytes(development_lock_bytes),
            "context_inventory_contract": CONTEXT_INVENTORY_CONTRACT,
            "dockerfile": DOCKERFILE_CONTRACT.as_posix(),
            "dockerfile_sha256": _sha256_bytes(dockerfile_bytes),
            "dockerignore": DOCKERIGNORE_CONTRACT.as_posix(),
            "dockerignore_sha256": _sha256_bytes(dockerignore_bytes),
        },
        "baseline_set": {"sha256": _sha256_bytes(_canonical_json_bytes(baseline_rows))},
        "bandit": {
            "baseline": BANDIT_BASELINE.as_posix(),
            "baseline_sha256": bandit_sha256,
            "finding_count": len(bandit["findings"]),
            "scope": list(BANDIT_PATHS),
            "config": "pyproject.toml",
            "config_sha256": _sha256_bytes(config_bytes),
            "scanner_version": versions["bandit"],
            "severity": "medium",
            "confidence": "medium",
        },
        "detect_secrets": {
            "baseline": SECRET_BASELINE.as_posix(),
            "baseline_sha256": secret_sha256,
            "finding_count": secret_findings,
            "path_count": len(inventory),
            "paths_sha256": _sorted_nul_digest(inventory),
            "docker_path_count": len(docker_inventory),
            "docker_paths_sha256": _sorted_nul_digest(docker_inventory),
            "plugin_count": len(secrets["plugins_used"]),
            "plugins_sha256": _sha256_bytes(_canonical_json_bytes(secrets["plugins_used"])),
            "scanner_version": versions["detect-secrets"],
        },
    }
    # This subject excludes the receipt and external review evidence, so the
    # reviewer can bind it before the final receipt names that evidence.
    subject = {"task_id": TASK_ID, "task_sha256": TASK_SHA256, **context}
    context["reviewed_contract_sha256"] = _sha256_bytes(_canonical_json_bytes(subject))
    proposal_manifest = _proposal_manifest(context, bandit_bytes, secret_bytes)
    context["proposal_manifest_sha256"] = _sha256_bytes(_proposal_bytes(proposal_manifest))
    return context


def security_review_context(
    root: Path,
    *,
    bandit_baseline_path: Path | None = None,
    secret_baseline_path: Path | None = None,
    secret_paths: Iterable[str] | None = None,
    scanner_versions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Compute the exact non-self-referential subject an independent review binds.

    Proposal paths may be supplied by review tooling outside the repository. The
    logical committed paths remain fixed in the returned contract.
    """

    root = root.resolve()
    bandit_path = bandit_baseline_path or root / BANDIT_BASELINE
    secret_path = secret_baseline_path or root / SECRET_BASELINE
    bandit, bandit_bytes = _load_bandit_baseline(bandit_path)
    secrets, secret_bytes = _load_secret_baseline(secret_path)
    return _security_review_context_from_documents(
        root,
        bandit=bandit,
        bandit_bytes=bandit_bytes,
        secrets=secrets,
        secret_bytes=secret_bytes,
        secret_paths=secret_paths,
        scanner_versions=scanner_versions,
    )


def _validate_identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTITY_RE.fullmatch(value):
        raise SupplyChainError(
            f"security review {label} must be an explicit scheme identity or email address"
        )
    if any(marker in value.casefold() for marker in ("placeholder", "unknown", "pending", "tbd")):
        raise SupplyChainError(f"security review {label} is provisional")
    return value


def _receipt_date(value: Any, label: str) -> date:
    if not isinstance(value, str):
        raise SupplyChainError(f"security review {label} must be a quoted YYYY-MM-DD date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise SupplyChainError(f"security review {label} is invalid") from exc


def validate_security_review_document(
    document: Mapping[str, Any],
    context: Mapping[str, Any],
    as_of: date,
) -> None:
    """Validate one independent LOCAL_UNSIGNED acceptance receipt."""

    if set(document) != _RECEIPT_KEYS:
        raise SupplyChainError("security review receipt fields differ from schema v2")
    if type(document.get("schema_version")) is not int or document["schema_version"] != 2:
        raise SupplyChainError("security review schema_version must be 2")
    if document.get("receipt_type") != "LOCAL_UNSIGNED":
        raise SupplyChainError("security review receipt_type must be LOCAL_UNSIGNED")
    if document.get("task_id") != TASK_ID or document.get("task_sha256") != TASK_SHA256:
        raise SupplyChainError("security review does not bind the exact Task 008 definition")
    if document.get("decision") != "ACCEPT":
        raise SupplyChainError("security review decision must be ACCEPT")

    implementer = _validate_identity(document.get("implementer_identity"), "implementer_identity")
    reviewer = _validate_identity(document.get("reviewer_identity"), "reviewer_identity")
    if implementer.casefold() == reviewer.casefold():
        raise SupplyChainError(
            "security review implementer and reviewer identities must be distinct"
        )

    implemented_on = _receipt_date(document.get("implemented_on"), "implemented_on")
    reviewed_on = _receipt_date(document.get("reviewed_on"), "reviewed_on")
    expires_on = _receipt_date(document.get("expires_on"), "expires_on")
    if not implemented_on <= reviewed_on <= as_of <= expires_on:
        raise SupplyChainError("security review dates are unordered, future, or expired")
    if (expires_on - reviewed_on).days > 120:
        raise SupplyChainError("security review validity exceeds 120 days")

    evidence_id = document.get("review_evidence_id")
    if (
        not isinstance(evidence_id, str)
        or not _EVIDENCE_ID_RE.fullmatch(evidence_id)
        or PurePosixPath(evidence_id).is_absolute()
        or ".." in PurePosixPath(evidence_id).parts
        or any(marker in evidence_id.casefold() for marker in ("placeholder", "pending", "tbd"))
    ):
        raise SupplyChainError("security review evidence ID is not an immutable opaque reference")
    evidence_sha256 = document.get("review_evidence_sha256")
    if (
        not isinstance(evidence_sha256, str)
        or not _SHA256_RE.fullmatch(evidence_sha256)
        or evidence_sha256 == "0" * 64
    ):
        raise SupplyChainError("security review evidence SHA-256 is invalid")

    expected_subject = context.get("reviewed_contract_sha256")
    if document.get("reviewed_contract_sha256") != expected_subject:
        raise SupplyChainError("security review does not bind the current reviewed contract")
    if document.get("proposal_manifest_sha256") != context.get("proposal_manifest_sha256"):
        raise SupplyChainError("security review does not bind the reviewed proposal manifest")
    for table in _RECEIPT_TABLES:
        if document.get(table) != context.get(table):
            raise SupplyChainError(f"security review {table} binding changed")


def _toml_value(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if type(value) is int:
        return str(value)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return "[" + ", ".join(json.dumps(item, ensure_ascii=False) for item in value) + "]"
    raise SupplyChainError("security review contains a value outside the canonical TOML schema")


def render_security_review_receipt(document: Mapping[str, Any]) -> bytes:
    """Render the sole accepted receipt syntax, excluding hidden comments/data."""

    lines = [f"{key} = {_toml_value(document[key])}" for key in _RECEIPT_ROOT_ORDER]
    for table in _RECEIPT_TABLES:
        value = document.get(table)
        if not isinstance(value, Mapping) or set(value) != set(_RECEIPT_TABLE_ORDER[table]):
            raise SupplyChainError(f"security review {table} fields differ from schema v2")
        lines.extend(("", f"[{table}]"))
        lines.extend(f"{key} = {_toml_value(value[key])}" for key in _RECEIPT_TABLE_ORDER[table])
    return ("\n".join(lines) + "\n").encode("utf-8")


def validate_security_review_bytes(
    content: bytes,
    context: Mapping[str, Any],
    as_of: date,
) -> dict[str, Any]:
    try:
        document = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SupplyChainError("security review receipt is not valid canonical TOML") from exc
    validate_security_review_document(document, context, as_of)
    if content != render_security_review_receipt(document):
        raise SupplyChainError(
            "security review receipt is not canonical; comments and trailing data are forbidden"
        )
    return document


def validate_security_review(
    root: Path,
    as_of: date,
    *,
    secret_paths: Iterable[str] | None = None,
) -> dict[str, Any]:
    canonical_paths = secret_scan_paths(root)
    if secret_paths is not None and tuple(secret_paths) != canonical_paths:
        raise SupplyChainError("security review path inventory is not the canonical candidate set")
    receipt_path = root / SECURITY_REVIEW
    receipt_bytes = _read_regular_bytes(receipt_path, "security review receipt")
    try:
        preliminary = tomllib.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SupplyChainError(
            f"security review receipt is missing or invalid: {receipt_path}"
        ) from exc
    if preliminary.get("schema_version") != 2:
        raise SupplyChainError("security review receipt must be migrated to schema v2")
    context = security_review_context(root, secret_paths=canonical_paths)
    validate_security_review_bytes(receipt_bytes, context, as_of)
    return context


def verify_bandit(root: Path, expected: Mapping[str, Any] | None = None) -> int:
    baseline, baseline_bytes = _load_bandit_baseline(root / BANDIT_BASELINE)
    if expected is not None:
        if _sha256_bytes(baseline_bytes) != expected.get("baseline_sha256"):
            raise SupplyChainError("Bandit baseline bytes changed after receipt validation")
        config_bytes = _read_regular_bytes(root / "pyproject.toml", "Bandit configuration")
        if _sha256_bytes(config_bytes) != expected.get("config_sha256"):
            raise SupplyChainError("Bandit configuration changed after receipt validation")
    observed = scan_bandit(root, config=root / "pyproject.toml")
    if expected is not None:
        config_bytes = _read_regular_bytes(root / "pyproject.toml", "Bandit configuration")
        if _sha256_bytes(config_bytes) != expected.get("config_sha256"):
            raise SupplyChainError("Bandit configuration changed during the scan")
    if baseline["findings"] != observed:
        expected = Counter(item.get("fingerprint") for item in baseline["findings"])
        actual = Counter(item["fingerprint"] for item in observed)
        added = sorted((actual - expected).elements())
        removed = sorted((expected - actual).elements())
        raise SupplyChainError(f"Bandit baseline drift: added={len(added)} removed={len(removed)}")
    return len(observed)


def verify_secrets(
    root: Path,
    *,
    paths: tuple[str, ...] | None = None,
    expected: Mapping[str, Any] | None = None,
) -> int:
    baseline, baseline_bytes = _load_secret_baseline(root / SECRET_BASELINE)
    if expected is not None and _sha256_bytes(baseline_bytes) != expected.get("baseline_sha256"):
        raise SupplyChainError("detect-secrets baseline bytes changed after receipt validation")
    observed = scan_secrets(root, paths=paths)
    if baseline != observed:
        raise SupplyChainError("detect-secrets baseline drift; review the exact hashed detections")
    return sum(len(items) for items in observed["results"].values())


def _proposal_bytes(document: Mapping[str, Any]) -> bytes:
    forbidden = {
        "forge_review",
        "reviewer_identity",
        "review_evidence_id",
        "review_evidence_sha256",
        "decision",
    }
    if forbidden.intersection(document):
        raise SupplyChainError("proposal document contains approval metadata")
    return json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _proposal_manifest(
    context: Mapping[str, Any],
    bandit_content: bytes,
    secret_content: bytes,
) -> dict[str, Any]:
    bandit = context["bandit"]
    secrets = context["detect_secrets"]
    if _sha256_bytes(bandit_content) != bandit["baseline_sha256"]:
        raise SupplyChainError("Bandit proposal bytes differ from the reviewed context")
    if _sha256_bytes(secret_content) != secrets["baseline_sha256"]:
        raise SupplyChainError("detect-secrets proposal bytes differ from the reviewed context")
    return {
        "schema_version": "forge-supply-chain-proposal-set-v1",
        "proposal_type": "UNREVIEWED",
        "task_id": TASK_ID,
        "task_sha256": TASK_SHA256,
        "reviewed_contract_sha256": context["reviewed_contract_sha256"],
        **{table: context[table] for table in _RECEIPT_TABLES},
        "files": [
            {
                "bytes": len(bandit_content),
                "committed_path": BANDIT_BASELINE.as_posix(),
                "finding_count": bandit["finding_count"],
                "kind": "bandit",
                "proposal_file": "bandit-baseline.proposal.json",
                "sha256": bandit["baseline_sha256"],
            },
            {
                "bytes": len(secret_content),
                "committed_path": SECRET_BASELINE.as_posix(),
                "finding_count": secrets["finding_count"],
                "kind": "detect-secrets",
                "proposal_file": "secrets-baseline.proposal.json",
                "sha256": secrets["baseline_sha256"],
            },
        ],
    }


def _proposal_directory(destination: Path, root: Path) -> Path:
    root = root.resolve(strict=True)
    requested = destination if destination.is_absolute() else Path.cwd() / destination
    try:
        parent = requested.parent.resolve(strict=True)
    except OSError as exc:
        raise SupplyChainError("proposal parent directory must already exist") from exc
    target = parent / requested.name
    if target == root or root in target.parents:
        raise SupplyChainError("proposal destination must be outside the repository")
    try:
        parent_stat = parent.stat()
    except OSError as exc:
        raise SupplyChainError("proposal parent directory is inaccessible") from exc
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise SupplyChainError("proposal parent is not a directory")
    if parent_stat.st_uid != os.geteuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077:
        raise SupplyChainError("proposal parent directory must be owner-private")
    if target.exists() or target.is_symlink():
        raise SupplyChainError("proposal set destination already exists; refusing overwrite")
    return target


def _write_exclusive_private(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise SupplyChainError("proposal file already exists; refusing overwrite") from exc
    except OSError as exc:
        raise SupplyChainError(f"cannot create proposal file: {exc}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        created = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_uid != os.geteuid()
            or stat.S_IMODE(created.st_mode) != 0o600
        ):
            raise SupplyChainError("proposal file is not owner-private regular file mode 0600")
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def write_baseline_set_proposal(
    destination: Path,
    bandit_document: Mapping[str, Any],
    secret_document: Mapping[str, Any],
    root: Path,
    *,
    secret_paths: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Create one complete unreviewed proposal set outside the repository."""

    target = _proposal_directory(destination, root)
    bandit_content = _proposal_bytes(bandit_document)
    secret_content = _proposal_bytes(secret_document)
    canonical_inventory = secret_scan_paths(root)
    if secret_paths is not None and tuple(secret_paths) != canonical_inventory:
        raise SupplyChainError("proposal path inventory is not the canonical candidate set")
    inventory = canonical_inventory
    context = _security_review_context_from_documents(
        root,
        bandit=bandit_document,
        bandit_bytes=bandit_content,
        secrets=secret_document,
        secret_bytes=secret_content,
        secret_paths=inventory,
    )
    manifest = _proposal_manifest(context, bandit_content, secret_content)
    outputs = {
        "bandit-baseline.proposal.json": bandit_content,
        "secrets-baseline.proposal.json": secret_content,
        "proposal-manifest.json": _proposal_bytes(manifest),
    }
    try:
        os.mkdir(target, mode=0o700)
    except FileExistsError as exc:
        raise SupplyChainError(
            "proposal set destination already exists; refusing overwrite"
        ) from exc
    except OSError as exc:
        raise SupplyChainError(f"cannot create proposal set directory: {exc}") from exc
    try:
        created_directory = target.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(created_directory.st_mode)
            or created_directory.st_uid != os.geteuid()
            or stat.S_IMODE(created_directory.st_mode) != 0o700
        ):
            raise SupplyChainError("proposal set directory is not owner-private mode 0700")
        # The manifest is intentionally written last. Its presence means both
        # proposal artifacts were created and hashed as one candidate set.
        for name in (
            "bandit-baseline.proposal.json",
            "secrets-baseline.proposal.json",
            "proposal-manifest.json",
        ):
            _write_exclusive_private(target / name, outputs[name])
    except Exception:
        for name in outputs:
            try:
                (target / name).unlink()
            except OSError:
                pass
        try:
            target.rmdir()
        except OSError:
            pass
        raise
    return manifest


def _proposal_static_hashes(root: Path) -> tuple[str, str, str, str, str]:
    return (
        _sha256_bytes(_read_regular_bytes(root / SCANNER_CONTRACT, "scanner contract")),
        _sha256_bytes(_read_regular_bytes(root / "pyproject.toml", "Bandit configuration")),
        _sha256_bytes(_read_regular_bytes(root / DEVELOPMENT_LOCK, "development lock")),
        _sha256_bytes(_validate_dockerfile_contract(root)),
        _sha256_bytes(_validate_dockerignore_contract(root)),
    )


def _parse_date(raw: str) -> date:
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("date must be YYYY-MM-DD") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--as-of",
        type=_parse_date,
        default=datetime.now(timezone.utc).date(),
        help="receipt date used for expiry enforcement (UTC today by default)",
    )
    parser.add_argument("--bandit-only", action="store_true")
    parser.add_argument("--secret-only", action="store_true")
    parser.add_argument(
        "--propose-baseline-set",
        type=Path,
        metavar="NEW_DIRECTORY",
        help="create one complete unreviewed proposal set outside the repository",
    )
    args = parser.parse_args(argv)
    if args.bandit_only and args.secret_only:
        parser.error("--bandit-only and --secret-only are mutually exclusive")
    if args.propose_baseline_set and (args.bandit_only or args.secret_only):
        parser.error("proposal destinations cannot be combined with verification selectors")
    root = args.root.resolve()
    try:
        if args.propose_baseline_set:
            _proposal_directory(args.propose_baseline_set, root)
            static_hashes = _proposal_static_hashes(root)
            proposal_secret_paths = secret_scan_paths(root)
            bandit_document = bandit_proposal_document(
                scan_bandit(root, config=root / "pyproject.toml")
            )
            secret_document = secret_proposal_document(root, paths=proposal_secret_paths)
            if (
                secret_scan_paths(root) != proposal_secret_paths
                or _proposal_static_hashes(root) != static_hashes
            ):
                raise SupplyChainError("proposal scanner inputs changed during generation")
            manifest = write_baseline_set_proposal(
                args.propose_baseline_set,
                bandit_document,
                secret_document,
                root,
                secret_paths=proposal_secret_paths,
            )
            manifest_sha256 = _sha256_bytes(_proposal_bytes(manifest))
            print(
                "PROPOSAL supply-chain kind=baseline-set status=UNREVIEWED "
                f"manifest_sha256={manifest_sha256} "
                f"baseline_set_sha256={manifest['baseline_set']['sha256']}"
            )
            return 0

        secret_paths = secret_scan_paths(root)
        context = validate_security_review(root, args.as_of, secret_paths=secret_paths)
        bandit_count = 0 if args.secret_only else verify_bandit(root, expected=context["bandit"])
        secret_count = (
            0
            if args.bandit_only
            else verify_secrets(
                root,
                paths=secret_paths,
                expected=context["detect_secrets"],
            )
        )
        final_secret_paths = secret_scan_paths(root)
        final_context = validate_security_review(
            root,
            args.as_of,
            secret_paths=final_secret_paths,
        )
        if final_secret_paths != secret_paths or final_context != context:
            raise SupplyChainError("reviewed scanner inputs changed during verification")
    except (OSError, SupplyChainError) as exc:
        print(f"FAIL supply-chain: {exc}", file=sys.stderr)
        return 1
    print(
        f"PASS supply-chain bandit_findings={bandit_count} "
        f"secret_detections={secret_count} as_of={args.as_of.isoformat()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
