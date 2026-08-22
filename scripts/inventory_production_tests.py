#!/usr/bin/env python3
"""Inventory and enforce normal pytest collection of production regressions.

The repository historically kept genuine ``Test*`` classes beside production
implementations.  They are not dead documentation: Task 008 makes every method
an explicit, normally collected pytest regression through
``tests/test_production_embedded_regressions.py``.  This command emits the
reviewable one-row-per-method inventory used as CI evidence and rejects broad
or stale safety exceptions.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import io
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config/production-test-classification.toml"
COLLECTOR = "tests/test_production_embedded_regressions.py"
PRODUCTION_ROOTS = (
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


@dataclass(frozen=True, order=True)
class ProductionRegression:
    path: str
    line: int
    class_name: str
    method_name: str
    source_sha256: str

    @property
    def source_node_id(self) -> str:
        return f"{self.path}::{self.class_name}::{self.method_name}"

    @property
    def collector_class(self) -> str:
        label = re.sub(r"[^A-Za-z0-9]+", "_", f"{self.path}_{self.class_name}")
        suffix = hashlib.sha256(
            f"{self.path}::{self.class_name}".encode("utf-8")
        ).hexdigest()[:10]
        return f"TestEmbedded_{label}_{suffix}"

    @property
    def pytest_node_id(self) -> str:
        return f"{COLLECTOR}::{self.collector_class}::{self.method_name}"


def _configuration() -> dict[str, object]:
    return tomllib.loads(CONFIG.read_text(encoding="utf-8"))


def inventory() -> tuple[list[ProductionRegression], list[str]]:
    rows: list[ProductionRegression] = []
    failures: list[str] = []
    for root in PRODUCTION_ROOTS:
        for path in sorted((ROOT / root).rglob("*.py")):
            relative = path.relative_to(ROOT).as_posix()
            try:
                source = path.read_bytes()
                tree = ast.parse(source.decode("utf-8-sig"), filename=relative)
            except (SyntaxError, UnicodeDecodeError) as exc:
                failures.append(f"{relative}: {type(exc).__name__}: {exc}")
                continue
            digest = hashlib.sha256(source).hexdigest()
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                    failures.append(f"{relative}:{node.lineno}: module-level {node.name} is not collected")
                if not isinstance(node, ast.ClassDef):
                    continue
                methods = [
                    child
                    for child in node.body
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.name.startswith("test_")
                ]
                if not methods:
                    continue
                if not node.name.startswith("Test"):
                    failures.append(
                        f"{relative}:{node.lineno}: test methods belong to non-Test class {node.name}"
                    )
                if any(
                    isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.name == "__init__"
                    for child in node.body
                ):
                    failures.append(
                        f"{relative}:{node.lineno}: {node.name} defines __init__ and is not pytest-collectable"
                    )
                for method in methods:
                    rows.append(
                        ProductionRegression(
                            path=relative,
                            line=method.lineno,
                            class_name=node.name,
                            method_name=method.name,
                            source_sha256=digest,
                        )
                    )

    duplicates: dict[str, int] = {}
    for row in rows:
        duplicates[row.source_node_id] = duplicates.get(row.source_node_id, 0) + 1
    failures.extend(
        f"duplicate production regression: {node_id}"
        for node_id, count in sorted(duplicates.items())
        if count != 1
    )
    return sorted(rows), failures


def validate_policy(rows: list[ProductionRegression]) -> list[str]:
    config = _configuration()
    execution = config.get("execution")
    if not isinstance(execution, dict):
        return ["classification config is missing [execution]"]
    failures: list[str] = []
    if execution.get("collector") != COLLECTOR:
        failures.append("classification collector does not match the enforced pytest collector")
    minimum = execution.get("minimum_regressions")
    if not isinstance(minimum, int) or len(rows) < minimum:
        failures.append(f"production regression count {len(rows)} is below reviewed minimum {minimum!r}")

    raw_exceptions = config.get("unsafe_exception", [])
    if not isinstance(raw_exceptions, list):
        return failures + ["unsafe_exception must be an array of exact tables"]
    known = {row.source_node_id for row in rows}
    seen: set[str] = set()
    required_fields = {"node_id", "owner", "reason", "risk", "expires"}
    for index, exception in enumerate(raw_exceptions):
        if not isinstance(exception, dict):
            failures.append(f"unsafe_exception[{index}] is not a table")
            continue
        missing = required_fields - set(exception)
        if missing:
            failures.append(f"unsafe_exception[{index}] missing {sorted(missing)}")
            continue
        node_id = exception["node_id"]
        if not isinstance(node_id, str) or node_id not in known:
            failures.append(f"unsafe_exception[{index}] has stale/unknown node_id {node_id!r}")
        elif node_id in seen:
            failures.append(f"duplicate unsafe exception: {node_id}")
        else:
            seen.add(node_id)
        for field in required_fields - {"node_id"}:
            if not isinstance(exception[field], str) or not exception[field].strip():
                failures.append(f"unsafe_exception[{index}] has empty {field}")
    allowed = execution.get("maximum_unsafe_exceptions")
    if not isinstance(allowed, int) or len(seen) > allowed:
        failures.append(
            f"unsafe exception count {len(seen)} exceeds reviewed maximum {allowed!r}"
        )
    return failures


def render(rows: list[ProductionRegression]) -> str:
    raw_exceptions = _configuration().get("unsafe_exception", [])
    if not isinstance(raw_exceptions, list):
        raise ValueError("unsafe_exception must be an array of exact tables")
    exceptions = {
        item["node_id"]: item
        for item in raw_exceptions
        if isinstance(item, dict) and isinstance(item.get("node_id"), str)
    }
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        (
            "source_node_id",
            "source_sha256",
            "line",
            "classification",
            "pytest_node_id",
            "ci_disposition",
            "review_reason",
        )
    )
    for row in rows:
        exception = exceptions.get(row.source_node_id)
        if exception is None:
            classification = "embedded_unit_regression"
            disposition = "COLLECT_AND_EXECUTE"
            reason = "genuine regression executed by normal pytest discovery"
        else:
            classification = "narrow_unsafe_exception"
            disposition = "DO_NOT_EXECUTE"
            reason = str(exception["reason"])
        writer.writerow(
            (
                row.source_node_id,
                row.source_sha256,
                row.line,
                classification,
                row.pytest_node_id,
                disposition,
                reason,
            )
        )
    return buffer.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "build/test-inventory.csv")
    args = parser.parse_args()
    rows, failures = inventory()
    failures.extend(validate_policy(rows))
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(rows), encoding="utf-8")
    if failures:
        print("\n".join(failures))
        return 1
    exception_count = sum(
        1 for row in render(rows).splitlines()[1:] if ",narrow_unsafe_exception," in row
    )
    print(
        f"PASS embedded_regressions={len(rows)} unsafe_exceptions={exception_count} "
        f"inventory={output.relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
