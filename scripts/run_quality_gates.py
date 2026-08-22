#!/usr/bin/env python3
"""Run the pinned Task 008 quality gates and verify the measured coverage report."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PYTHON_EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "apex-ui",
    "build",
    "engagements",
    "extracted_images",
    "node_modules",
    "results",
    "tmp",
}
WARNING_RECORD_FIELDS = {
    "category",
    "module",
    "message_prefix",
    "owner",
    "reason",
    "expires",
}
REVIEWABLE_WARNING_CATEGORIES = {
    "DeprecationWarning",
    "FutureWarning",
    "ImportWarning",
    "PendingDeprecationWarning",
    "ResourceWarning",
}
MODULE_NAME_RE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")
BROAD_MESSAGE_PATTERNS = {"*", ".*", ".+", "^.*", "^.*$", "(?s).*"}


class QualityGateError(RuntimeError):
    """Raised whenever an enforced gate cannot prove success."""


def _configuration(root: Path) -> dict[str, Any]:
    return tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))


def _python_files(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.py")
        if not any(part in PYTHON_EXCLUDED_PARTS for part in path.relative_to(root).parts)
    )


def _run(command: list[str], root: Path, log_path: Path) -> None:
    completed = subprocess.run(
        command,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    rendered = (
        f"$ {' '.join(command)}\n"
        f"exit={completed.returncode}\n"
        f"--- stdout ---\n{completed.stdout}"
        f"--- stderr ---\n{completed.stderr}"
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(rendered, encoding="utf-8")
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    if completed.returncode:
        raise QualityGateError(
            f"command failed with exit {completed.returncode}: {' '.join(command)}; log={log_path}"
        )


def _warning_filter(record: dict[str, str]) -> str:
    message = re.escape(record["message_prefix"])
    module = re.escape(record["module"])
    return f"ignore:^{message}:{record['category']}:^{module}$"


def validate_warning_policy_documents(
    configuration: dict[str, Any],
    warning_document: dict[str, Any],
    as_of: date,
) -> int:
    if warning_document.get("schema_version") != 2:
        raise QualityGateError("warning allowlist schema_version must be 2")
    records = warning_document.get("warning")
    if not isinstance(records, list) or not records:
        raise QualityGateError("warning allowlist must contain narrow reviewed records")
    reviewed_filters: list[str] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != WARNING_RECORD_FIELDS:
            raise QualityGateError(f"warning[{index}] fields differ from the reviewed schema")
        if any(
            not isinstance(record[field], str) or not record[field].strip()
            for field in WARNING_RECORD_FIELDS
        ):
            raise QualityGateError(f"warning[{index}] contains an empty field")
        category = record["category"]
        if category not in REVIEWABLE_WARNING_CATEGORIES:
            raise QualityGateError(f"warning[{index}] category is broad or unsupported: {category}")
        module = record["module"]
        if not MODULE_NAME_RE.fullmatch(module):
            raise QualityGateError(f"warning[{index}] module must be one exact dotted module")
        message_prefix = record["message_prefix"].strip()
        if (
            len(message_prefix) < 16
            or message_prefix in BROAD_MESSAGE_PATTERNS
            or message_prefix.startswith((".*", ".+", "^.*", "(?"))
            or any(character in message_prefix for character in "\r\n:\\")
        ):
            raise QualityGateError(f"warning[{index}] message prefix is broad or unsafe")
        try:
            expires = date.fromisoformat(record["expires"])
        except ValueError as exc:
            raise QualityGateError(f"warning[{index}] expiry is invalid") from exc
        if as_of > expires:
            raise QualityGateError(f"warning[{index}] review expired on {expires.isoformat()}")
        reviewed_filters.append(_warning_filter(record))

    if len(reviewed_filters) != len(set(reviewed_filters)):
        raise QualityGateError("warning allowlist contains duplicate pytest filters")

    filters = configuration["tool"]["pytest"]["ini_options"].get("filterwarnings", [])
    expected_filters = ["error", *reviewed_filters]
    if filters != expected_filters:
        raise QualityGateError(
            "pytest filterwarnings must exactly equal the ordered reviewed warning allowlist"
        )
    return len(records)


def validate_warning_policy(root: Path, as_of: date) -> int:
    configuration = _configuration(root)
    warning_path = root / configuration["tool"]["forge"]["qualification"]["warning_allowlist"]
    warning_document = tomllib.loads(warning_path.read_text(encoding="utf-8"))
    return validate_warning_policy_documents(configuration, warning_document, as_of)


def _coverage_percent(file_record: dict[str, Any]) -> float:
    try:
        return float(file_record["summary"]["percent_covered"])
    except (KeyError, TypeError, ValueError) as exc:
        raise QualityGateError("coverage JSON lacks a numeric percent_covered") from exc


def validate_coverage_report(
    report: dict[str, Any],
    qualification: dict[str, Any],
    configured_fail_under: float,
) -> dict[str, float]:
    threshold = float(qualification["coverage_total"])
    if threshold != float(configured_fail_under):
        raise QualityGateError(
            f"coverage command threshold {configured_fail_under} differs from qualification {threshold}"
        )
    try:
        measured = float(report["totals"]["percent_covered"])
    except (KeyError, TypeError, ValueError) as exc:
        raise QualityGateError("coverage JSON lacks totals.percent_covered") from exc
    if measured < threshold:
        raise QualityGateError(f"total coverage {measured:.3f}% is below {threshold:.3f}%")

    files = report.get("files")
    if not isinstance(files, dict):
        raise QualityGateError("coverage JSON lacks file records")
    measured_targets: dict[str, float] = {}
    for relative_path, required in qualification.get("coverage_targets", {}).items():
        record = files.get(relative_path)
        if not isinstance(record, dict):
            raise QualityGateError(f"targeted coverage file is absent: {relative_path}")
        percentage = _coverage_percent(record)
        measured_targets[relative_path] = percentage
        if percentage < float(required):
            raise QualityGateError(
                f"targeted coverage {relative_path}={percentage:.3f}% is below {float(required):.3f}%"
            )
    return {"total": measured, **measured_targets}


def run_static(root: Path, output_dir: Path, as_of: date) -> None:
    files = _python_files(root)
    if not files:
        raise QualityGateError("Python source inventory is empty")
    commands = [
        ("py-compile", [sys.executable, "-m", "py_compile", *files]),
        ("ruff", [sys.executable, "-m", "ruff", "check", "."]),
        ("mypy", [sys.executable, "-m", "mypy"]),
        (
            "dependency-locks",
            [
                sys.executable,
                "scripts/check_dependency_locks.py",
                "--check-environment",
                "--compile-check",
            ],
        ),
        ("product-version", [sys.executable, "scripts/check_product_version.py"]),
        ("module-mappings", [sys.executable, "scripts/verify_module_mappings.py"]),
        (
            "production-test-inventory",
            [
                sys.executable,
                "scripts/inventory_production_tests.py",
                "--output",
                str(output_dir / "production-test-inventory.csv"),
            ],
        ),
        (
            "frontend-contracts",
            [sys.executable, "scripts/generate_frontend_contracts.py", "--check"],
        ),
        ("ci-fail-closed", [sys.executable, "scripts/verify_ci_fail_closed.py"]),
        (
            "supply-chain",
            [sys.executable, "scripts/verify_supply_chain.py", "--as-of", as_of.isoformat()],
        ),
        (
            "static-sbom-generate",
            [sys.executable, "scripts/generate_sbom.py", "--output", str(output_dir / "static-sbom.cdx.json")],
        ),
        (
            "static-sbom-verify",
            [sys.executable, "scripts/verify_sbom.py", "--input", str(output_dir / "static-sbom.cdx.json")],
        ),
    ]
    for label, command in commands:
        _run(command, root, output_dir / f"{label}.log")
    warning_count = validate_warning_policy(root, as_of)
    (output_dir / "warning-policy.log").write_text(
        f"PASS warning-policy reviewed_records={warning_count} as_of={as_of.isoformat()}\n",
        encoding="utf-8",
    )
    print(f"PASS warning-policy reviewed_records={warning_count}")


def verify_coverage(root: Path, coverage_json: Path, output_dir: Path) -> None:
    configuration = _configuration(root)
    report = json.loads(coverage_json.read_text(encoding="utf-8"))
    measured = validate_coverage_report(
        report,
        configuration["tool"]["forge"]["qualification"],
        float(configuration["tool"]["coverage"]["report"]["fail_under"]),
    )
    rendered = "PASS coverage " + " ".join(
        f"{path}={percentage:.3f}" for path, percentage in measured.items()
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "coverage-gate.log").write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


def _parse_date(raw: str) -> date:
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("date must be YYYY-MM-DD") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gate", choices=("static", "coverage", "all"), nargs="?", default="static")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path, default=Path("build/quality"))
    parser.add_argument("--coverage-json", type=Path, default=Path("build/coverage.json"))
    parser.add_argument(
        "--as-of",
        type=_parse_date,
        default=datetime.now(timezone.utc).date(),
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    output_dir = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir
    coverage_json = args.coverage_json if args.coverage_json.is_absolute() else root / args.coverage_json
    try:
        if args.gate in {"static", "all"}:
            run_static(root, output_dir, args.as_of)
        if args.gate in {"coverage", "all"}:
            verify_coverage(root, coverage_json, output_dir)
    except (OSError, json.JSONDecodeError, subprocess.SubprocessError, tomllib.TOMLDecodeError, QualityGateError) as exc:
        print(f"FAIL quality-gates: {exc}", file=sys.stderr)
        return 1
    print(f"PASS quality-gates gate={args.gate} output={output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
