#!/usr/bin/env python3
"""Fail-closed validation for Forge's reviewed Python dependency inputs and locks."""

from __future__ import annotations

import argparse
import importlib.metadata
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON = "3.13.9"
EXPECTED_PIP = "25.2"
EXPECTED_PIP_TOOLS = "7.5.0"
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})(?=\s|$)")


class LockValidationError(RuntimeError):
    """Raised when a dependency input or generated lock is not reproducible."""


@dataclass(frozen=True)
class LockedRequirement:
    name: str
    version: str
    hashes: tuple[str, ...]


COMPILE_COMMANDS = {
    "requirements.lock": (
        "python -m piptools compile --resolver=backtracking --generate-hashes "
        "--allow-unsafe --strip-extras requirements.in --output-file requirements.lock"
    ),
    "requirements-dev.lock": (
        "python -m piptools compile --resolver=backtracking --generate-hashes "
        "--allow-unsafe --strip-extras requirements-dev.in "
        "--output-file requirements-dev.lock"
    ),
}


def _exact_pin(text: str, label: str) -> tuple[str, str]:
    try:
        requirement = Requirement(text)
    except InvalidRequirement as exc:
        raise LockValidationError(f"{label}: invalid requirement: {text!r}") from exc
    if requirement.url or requirement.marker:
        raise LockValidationError(f"{label}: URLs and environment markers are not permitted")
    specifiers = list(requirement.specifier)
    if (
        len(specifiers) != 1
        or specifiers[0].operator != "=="
        or "*" in specifiers[0].version
    ):
        raise LockValidationError(f"{label}: dependency must use one exact == pin: {text!r}")
    return canonicalize_name(requirement.name), specifiers[0].version


def parse_input(path: Path) -> tuple[dict[str, str], tuple[str, ...]]:
    pins: dict[str, str] = {}
    includes: list[str] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")):
            parts = line.split()
            if len(parts) != 2:
                raise LockValidationError(f"{path.name}:{line_number}: malformed include")
            includes.append(parts[1])
            continue
        if line.startswith("-"):
            raise LockValidationError(
                f"{path.name}:{line_number}: unsupported resolver option {line!r}"
            )
        name, version = _exact_pin(line, f"{path.name}:{line_number}")
        if name in pins:
            raise LockValidationError(f"{path.name}:{line_number}: duplicate pin for {name}")
        pins[name] = version
    if not pins:
        raise LockValidationError(f"{path.name}: no exact dependency pins found")
    return pins, tuple(includes)


def _logical_lock_lines(text: str) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    fragments: list[str] = []
    start = 0
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        if not fragments and (not stripped or stripped.startswith("#")):
            continue
        if not fragments:
            start = line_number
        if stripped.startswith("#"):
            continue
        continued = stripped.endswith("\\")
        fragments.append(stripped[:-1].rstrip() if continued else stripped)
        if not continued:
            logical.append((start, " ".join(fragments)))
            fragments = []
    if fragments:
        raise LockValidationError("generated lock ends with an incomplete continuation")
    return logical


def parse_lock(path: Path) -> dict[str, LockedRequirement]:
    text = path.read_text(encoding="utf-8")
    locked: dict[str, LockedRequirement] = {}
    for line_number, logical in _logical_lock_lines(text):
        requirement_text = logical.split(None, 1)[0]
        name, version = _exact_pin(requirement_text, f"{path.name}:{line_number}")
        hashes = tuple(sorted(set(HASH_RE.findall(logical))))
        if not hashes:
            raise LockValidationError(
                f"{path.name}:{line_number}: {name} has no sha256 artifact hash"
            )
        if name in locked:
            raise LockValidationError(f"{path.name}:{line_number}: duplicate locked package {name}")
        locked[name] = LockedRequirement(name, version, hashes)
    if not locked:
        raise LockValidationError(f"{path.name}: no locked requirements found")
    return locked


def _require_matching_pins(
    pins: dict[str, str],
    locked: dict[str, LockedRequirement],
    label: str,
) -> None:
    for name, expected_version in sorted(pins.items()):
        requirement = locked.get(name)
        if requirement is None:
            raise LockValidationError(f"{label}: direct pin {name} is absent from the lock")
        if requirement.version != expected_version:
            raise LockValidationError(
                f"{label}: {name} input={expected_version} lock={requirement.version}"
            )


def validate_repository(root: Path = ROOT) -> dict[str, int]:
    runtime_input, runtime_includes = parse_input(root / "requirements.in")
    dev_input, dev_includes = parse_input(root / "requirements-dev.in")
    if runtime_includes:
        raise LockValidationError("requirements.in must not include another requirements file")
    if dev_includes != ("requirements.in",):
        raise LockValidationError(
            "requirements-dev.in must include exactly '-r requirements.in'"
        )

    compatibility_lines = [
        line.strip()
        for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if compatibility_lines != ["-r requirements.lock"]:
        raise LockValidationError(
            "requirements.txt must be only a compatibility include of requirements.lock"
        )

    runtime_lock = parse_lock(root / "requirements.lock")
    dev_lock = parse_lock(root / "requirements-dev.lock")
    _require_matching_pins(runtime_input, runtime_lock, "runtime lock")
    _require_matching_pins(runtime_input, dev_lock, "development lock runtime graph")
    _require_matching_pins(dev_input, dev_lock, "development lock tool graph")

    for name, requirement in sorted(runtime_lock.items()):
        dev_requirement = dev_lock.get(name)
        if dev_requirement is None or dev_requirement.version != requirement.version:
            raise LockValidationError(
                f"development lock does not preserve runtime resolution {name}=={requirement.version}"
            )

    for lock_name, command in COMPILE_COMMANDS.items():
        header = f"#    {command}"
        if header not in (root / lock_name).read_text(encoding="utf-8").splitlines():
            raise LockValidationError(
                f"{lock_name}: generator command header does not match the canonical command"
            )

    return {
        "runtime_direct": len(runtime_input),
        "runtime_locked": len(runtime_lock),
        "development_direct": len(dev_input),
        "development_locked": len(dev_lock),
    }


def validate_tool_environment() -> None:
    observed_python = platform.python_version()
    if observed_python != EXPECTED_PYTHON:
        raise LockValidationError(
            f"qualification requires CPython {EXPECTED_PYTHON}; found {observed_python}"
        )
    for distribution, expected in (("pip", EXPECTED_PIP), ("pip-tools", EXPECTED_PIP_TOOLS)):
        observed = importlib.metadata.version(distribution)
        if observed != expected:
            raise LockValidationError(
                f"qualification requires {distribution} {expected}; found {observed}"
            )


def compile_check(root: Path = ROOT) -> None:
    validate_tool_environment()
    for lock_name, command in COMPILE_COMMANDS.items():
        input_name = "requirements-dev.in" if "dev" in lock_name else "requirements.in"
        environment = os.environ.copy()
        environment["CUSTOM_COMPILE_COMMAND"] = command
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "piptools",
                "compile",
                "--resolver=backtracking",
                "--generate-hashes",
                "--allow-unsafe",
                "--strip-extras",
                input_name,
                "--output-file",
                lock_name,
                "--dry-run",
            ],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode:
            raise LockValidationError(
                f"{lock_name}: pip-compile dry-run failed:\n{completed.stdout}{completed.stderr}"
            )
        rendered = completed.stderr
        trailer = "\nDry-run, so nothing updated.\n"
        if not rendered.endswith(trailer):
            raise LockValidationError(
                f"{lock_name}: pip-compile emitted an unexpected dry-run trailer"
            )
        rendered = rendered[: -len(trailer)] + "\n"
        current = (root / lock_name).read_text(encoding="utf-8")
        if rendered != current:
            raise LockValidationError(
                f"{lock_name}: generated bytes drift; rerun its canonical pip-compile command"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--compile-check", action="store_true")
    parser.add_argument("--check-environment", action="store_true")
    args = parser.parse_args(argv)
    try:
        counts = validate_repository(args.root.resolve())
        if args.check_environment:
            validate_tool_environment()
        if args.compile_check:
            compile_check(args.root.resolve())
    except (OSError, LockValidationError, importlib.metadata.PackageNotFoundError) as exc:
        print(f"FAIL dependency-locks: {exc}", file=sys.stderr)
        return 1
    print("PASS dependency-locks " + " ".join(f"{key}={value}" for key, value in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
