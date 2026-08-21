#!/usr/bin/env python3
"""Semantically prove that every required CI gate is pinned and fail closed."""

from __future__ import annotations

import argparse
import copy
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = Path(".github/workflows/ci.yml")
CHECKOUT = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
SETUP_PYTHON = "actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38"
SETUP_NODE = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"
UPLOAD_ARTIFACT = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
SHA_REF_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


class CiValidationError(RuntimeError):
    """Raised when CI contains a bypass or omits an enforced gate."""


class _WorkflowLoader(yaml.SafeLoader):
    """Safe YAML loader with GitHub-compatible booleans and unique keys."""


_WorkflowLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for _resolver_key, _resolvers in tuple(_WorkflowLoader.yaml_implicit_resolvers.items()):
    _WorkflowLoader.yaml_implicit_resolvers[_resolver_key] = [
        resolver for resolver in _resolvers if resolver[0] != "tag:yaml.org,2002:bool"
    ]
_WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def _construct_unique_mapping(
    loader: _WorkflowLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "workflow mapping key is not hashable",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate workflow key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_WorkflowLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class StepSpec:
    name: str
    uses: str | None = None
    run: str | None = None
    run_sha256: str | None = None
    working_directory: str | None = None
    condition: str | None = None
    with_values: dict[str, Any] | None = None


def _run(
    name: str,
    run_sha256: str,
    *,
    exact: str | None = None,
    working_directory: str | None = None,
    condition: str | None = None,
) -> StepSpec:
    return StepSpec(
        name=name,
        run=exact,
        run_sha256=run_sha256,
        working_directory=working_directory,
        condition=condition,
    )


def _uses(
    name: str,
    action: str,
    *,
    condition: str | None = None,
    with_values: dict[str, Any] | None = None,
) -> StepSpec:
    return StepSpec(
        name=name,
        uses=action,
        condition=condition,
        with_values=with_values,
    )


PYTHON_SETUP = {
    "python-version": "${{ env.PYTHON_VERSION }}",
    "cache": "pip",
    "cache-dependency-path": "requirements-dev.lock",
}
INSTALL_LOCK = "python -m pip install --require-hashes --requirement requirements-dev.lock"
PIP_CHECK = "python -m pip check"
STATIC_GATE = "python scripts/run_quality_gates.py static --output-dir build/quality"
COLLECTION_GATE = (
    "python -m pytest tests/ --collect-only -q --forge-qualification "
    "> build/test-results/collection.txt"
)
TEST_GATE = (
    "python -m pytest tests/ -v --tb=short --strict-markers --timeout=60 "
    "--forge-qualification --junitxml=build/test-results/pytest.xml "
    "--cov=common --cov=webforge/core --cov=netforge/data "
    "--cov-report=term-missing --cov-report=xml:build/coverage.xml "
    "--cov-report=json:build/coverage.json"
)
COVERAGE_GATE = (
    "python scripts/run_quality_gates.py coverage --coverage-json build/coverage.json "
    "--output-dir build/quality"
)


EXPECTED_JOB_META: dict[str, dict[str, Any]] = {
    "python-quality": {
        "name": "Python quality and supply chain",
        "runs-on": "ubuntu-24.04",
        "timeout-minutes": 35,
    },
    "python-tests": {
        "name": "Python tests and coverage",
        "runs-on": "ubuntu-24.04",
        "timeout-minutes": 35,
    },
    "frontend": {
        "name": "Frontend lock, contracts, types, tests, and build",
        "runs-on": "ubuntu-24.04",
        "timeout-minutes": 20,
    },
    "container-sbom": {
        "name": "Container, Compose, SBOM, and build identity",
        "runs-on": "ubuntu-24.04",
        "timeout-minutes": 35,
        "needs": ["python-quality", "python-tests", "frontend"],
    },
    "gate-0-baseline": {
        "name": "Required Gate 0 baseline",
        "runs-on": "ubuntu-24.04",
        "timeout-minutes": 5,
        "if": "always()",
        "needs": ["python-quality", "python-tests", "frontend", "container-sbom"],
    },
}


EXPECTED_STEPS: dict[str, tuple[StepSpec, ...]] = {
    "python-quality": (
        _uses("Check out the candidate", CHECKOUT),
        _uses("Install qualified Python", SETUP_PYTHON, with_values=PYTHON_SETUP),
        _run("Install the reviewed development graph", "1b03edea612053ded2143975fa748ef1ce4772ee74dedb9f84c126ed3dfdd94d", exact=INSTALL_LOCK),
        _run("Verify installed Python dependencies", "6eeb28200f23fe5677196410bc3248966febe63b086aab6118d5a1d7d3e479d8", exact=PIP_CHECK),
        _run("Run all static and supply-chain gates", "a228cdf404959b2d512c6d1fc4ce5805b199ec6d0b6bc35142f9547197bdbc06", exact=STATIC_GATE),
        _uses(
            "Publish quality evidence",
            UPLOAD_ARTIFACT,
            condition="always()",
            with_values={
                "name": "python-quality-${{ github.sha }}",
                "path": "build/quality",
                "if-no-files-found": "error",
                "retention-days": 30,
            },
        ),
    ),
    "python-tests": (
        _uses("Check out the candidate", CHECKOUT),
        _uses("Install qualified Python", SETUP_PYTHON, with_values=PYTHON_SETUP),
        _run("Install the reviewed development graph", "1b03edea612053ded2143975fa748ef1ce4772ee74dedb9f84c126ed3dfdd94d", exact=INSTALL_LOCK),
        _run("Verify installed Python dependencies", "6eeb28200f23fe5677196410bc3248966febe63b086aab6118d5a1d7d3e479d8", exact=PIP_CHECK),
        _run("Create test evidence paths", "7048da8c8ce1b837403cf5c78d1d918d06174fc433366d64fb012d921d14b89f", exact="mkdir -p build/test-results build/quality"),
        _run("Record the normal discovery inventory", "4d213d01329f798b347c505efde0841d38aa10992b3cc088ec260b147270922f", exact=COLLECTION_GATE),
        _run("Run the complete test and coverage gate", "ecfcf72a2390fb52bcfd67e9d62b612cb32a1393d4a38d8e8f7cad9baba52a39", exact=TEST_GATE),
        _run("Verify total and safety-critical coverage thresholds", "21f91ce0edc832f83d4dfb964ce85ddcb0842654037599022bb6ce1ccb90532f", exact=COVERAGE_GATE),
        _uses(
            "Publish test and coverage evidence",
            UPLOAD_ARTIFACT,
            condition="always()",
            with_values={
                "name": "python-tests-${{ github.sha }}",
                "path": "build/test-results\nbuild/coverage.xml\nbuild/coverage.json\nbuild/quality\n",
                "if-no-files-found": "error",
                "retention-days": 30,
            },
        ),
    ),
    "frontend": (
        _uses("Check out the candidate", CHECKOUT),
        _uses(
            "Install qualified Python for contract generation",
            SETUP_PYTHON,
            with_values={"python-version": "${{ env.PYTHON_VERSION }}"},
        ),
        _uses(
            "Install qualified Node",
            SETUP_NODE,
            with_values={
                "node-version": "${{ env.NODE_VERSION }}",
                "cache": "npm",
                "cache-dependency-path": "apex-ui/package-lock.json",
            },
        ),
        _run("Verify the qualified Node and npm pair", "518a474e6adb8611f7ddd3252139d89b0c380d37df653f04894fd767e011c18d"),
        _run("Create frontend evidence path", "3f1606dec1a0ba77f4a6cacf5bf2b05d4ca044394fdd7ee8be8e1d4ab48f804e"),
        _run("Install the exact frontend graph", "9514b3517c824a0127f135c25784c58557b6a032b154a5a28b501578c90fc70e", working_directory="apex-ui"),
        _run("Record the resolved frontend dependency graph", "323c20ed8b77ff8a0dbc136da0d2eab3454a6e1015b01e1c9b7fd200d654ff2e", working_directory="apex-ui"),
        _run("Verify generated API contracts", "8245cdea53c46362eb6a5b4adec8e2a5feb3da5fea144c98bec3adb53c1c3e7d", working_directory="apex-ui"),
        _run("Type-check every declared JavaScript, JSX, and TypeScript input", "2d1fcc97d154e96e870687f41b79be1beff32cf0020c310a9096ad070bb7f679", working_directory="apex-ui"),
        _run("Run operator workflow and negative type-contract tests", "aab7b6af98bdbf38f18c9ff02b3eb27a01d3031874b36cbf84bcf20530e0dddb", working_directory="apex-ui"),
        _run("Enforce the reviewed npm advisory disposition", "4dda87d097ade16bd32fda744dfbbda9f0cd6845b9e72b209e55273bdbdf197b", working_directory="apex-ui"),
        _run("Build the production frontend", "1e290d50cdc9c6038b9579faf5336e3b3bca9154fc3e271940cf916bcb47f520", working_directory="apex-ui"),
        _run("Hash the production frontend artifact", "81066b60a07c9304ac36f600144be558b63963b065ff5ecb54336f6e378878dd"),
        _uses(
            "Publish frontend evidence and build",
            UPLOAD_ARTIFACT,
            condition="always()",
            with_values={
                "name": "frontend-${{ github.sha }}",
                "path": "build/frontend\napex-ui/dist\n",
                "if-no-files-found": "error",
                "retention-days": 30,
            },
        ),
    ),
    "container-sbom": (
        _uses("Check out the candidate", CHECKOUT),
        _uses("Install qualified Python", SETUP_PYTHON, with_values=PYTHON_SETUP),
        _run("Install the reviewed development graph", "1b03edea612053ded2143975fa748ef1ce4772ee74dedb9f84c126ed3dfdd94d", exact=INSTALL_LOCK),
        _run("Verify installed Python dependencies", "6eeb28200f23fe5677196410bc3248966febe63b086aab6118d5a1d7d3e479d8", exact=PIP_CHECK),
        _run("Create container evidence path", "c11a87aae6de402033ada24c6633992a03664369cadae896fd41df9ae8b3551e"),
        _run("Build the immutable-input image", "12547c50e325187572f5487f3367ea6bde6e84bdf3c93489f2d88475d3855131"),
        _run("Validate secure Compose interpolation", "fa00bb8e2008c0ab15194165dbeadab40fa69148d259fdcc721cd00184085876"),
        _run("Prove authenticated TLS startup and health", "4dc346952dc67c3f839838a1dc6030284fced362fc6567a4e337a4009d58ca38"),
        _run("Inventory all installed image packages", "56fc91610ae5ee5e6edfbdcbaa465b64a39b7d0f99556fb84cdc2c55a2492227"),
        _run("Generate and verify the full build SBOM", "5978ee83a00c5ff3ec5dd6fc85125738393c3f4dd77b1c92465b68d4beb5f7f8"),
        _run("Generate exact tested-build identity", "d4958a035c940758cf23e24654f32913b583edddb98843a55ca5a5effd125a99"),
        _run("Remove ephemeral credential material from evidence", "c06eb1e7ddc4a79d63a6dec47b305189d188486bfa016ac1cae012b1654d7c1a", condition="always()"),
        _uses(
            "Publish container, SBOM, and build identity evidence",
            UPLOAD_ARTIFACT,
            condition="always()",
            with_values={
                "name": "container-sbom-${{ github.sha }}",
                "path": "build/container\nbuild/forge-sbom.cdx.json\nbuild/forge-build-manifest.json\n",
                "if-no-files-found": "error",
                "retention-days": 30,
            },
        ),
    ),
    "gate-0-baseline": (
        _run("Require every producer gate to succeed", "a787ebfefce155f0dd4b8e89ae17f35c80a8e7fbeb0dc626113bd1776cdd0edd"),
    ),
}


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CiValidationError(f"{label} must be a mapping")
    return value


def _load_workflow(text: str) -> dict[str, Any]:
    try:
        for event in yaml.parse(text, Loader=_WorkflowLoader):
            if isinstance(event, yaml.events.AliasEvent) or getattr(event, "anchor", None):
                raise CiValidationError("workflow YAML anchors and aliases are forbidden")
        document = yaml.load(text, Loader=_WorkflowLoader)
    except CiValidationError:
        raise
    except (yaml.YAMLError, ConstructorError) as exc:
        raise CiValidationError(f"workflow YAML is invalid: {exc}") from exc
    return _mapping(document, "workflow")


def _normalized_run(value: str) -> str:
    lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    # YAML block scalars differ only in whether they retain a final newline.
    # Preserve all commands, comments, indentation, and internal blank lines.
    return "\n".join(line.rstrip(" \t") for line in lines).rstrip("\n")


def _validate_step(job_name: str, step: Any, spec: StepSpec) -> tuple[int, int]:
    raw = _mapping(step, f"step {job_name}/{spec.name}")
    expected_keys = {"name"}
    if spec.uses is not None:
        expected_keys.add("uses")
    else:
        expected_keys.add("run")
    if spec.working_directory is not None:
        expected_keys.add("working-directory")
    if spec.condition is not None:
        expected_keys.add("if")
    if spec.with_values is not None:
        expected_keys.add("with")
    if set(raw) != expected_keys:
        raise CiValidationError(
            f"step {job_name}/{spec.name} keys changed: "
            f"expected={sorted(expected_keys)} actual={sorted(raw)}"
        )
    if raw.get("name") != spec.name:
        raise CiValidationError(f"job {job_name} step order/name changed; expected {spec.name!r}")
    if spec.condition is not None and raw.get("if") != spec.condition:
        raise CiValidationError(f"step {job_name}/{spec.name} condition changed")
    if spec.working_directory is not None and raw.get("working-directory") != spec.working_directory:
        raise CiValidationError(f"step {job_name}/{spec.name} working-directory changed")

    if spec.uses is not None:
        action = raw.get("uses")
        if action != spec.uses or not isinstance(action, str) or not SHA_REF_RE.fullmatch(action):
            raise CiValidationError(f"step {job_name}/{spec.name} action pin changed")
        if spec.with_values is not None and raw.get("with") != spec.with_values:
            raise CiValidationError(f"step {job_name}/{spec.name} action settings changed")
        return 1, int(action == UPLOAD_ARTIFACT)

    run = raw.get("run")
    if not isinstance(run, str):
        raise CiValidationError(f"step {job_name}/{spec.name} run command must be text")
    normalized = _normalized_run(run)
    if spec.run is not None and normalized != spec.run:
        raise CiValidationError(f"step {job_name}/{spec.name} required command changed")
    observed_digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if observed_digest != spec.run_sha256:
        raise CiValidationError(
            f"step {job_name}/{spec.name} run script changed: {observed_digest}"
        )
    return 0, 0


def validate_workflow_text(text: str) -> dict[str, int]:
    root = _load_workflow(text)
    expected_root_keys = {"name", "on", "permissions", "concurrency", "env", "jobs"}
    if set(root) != expected_root_keys:
        raise CiValidationError("workflow root keys changed")
    if root.get("name") != "Forge Gate 0 Baseline":
        raise CiValidationError("workflow name changed")
    if root.get("on") != {
        "push": {"branches": ["main", "master", "develop"]},
        "pull_request": {"branches": ["main", "master", "develop"]},
    }:
        raise CiValidationError("workflow triggers changed or include an unsafe trigger")
    if root.get("permissions") != {"contents": "read"}:
        raise CiValidationError("workflow permissions must be exactly contents: read")
    if root.get("concurrency") != {
        "group": "${{ github.workflow }}-${{ github.ref }}",
        "cancel-in-progress": True,
    }:
        raise CiValidationError("workflow concurrency policy changed")
    if root.get("env") != {
        "PYTHON_VERSION": "3.13.9",
        "NODE_VERSION": "20.19.5",
        "NPM_VERSION": "10.8.2",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PIP_PROGRESS_BAR": "off",
        "PYTHONDONTWRITEBYTECODE": "1",
    }:
        raise CiValidationError("workflow toolchain environment changed")

    jobs = _mapping(root.get("jobs"), "jobs")
    if set(jobs) != set(EXPECTED_JOB_META):
        raise CiValidationError(
            f"workflow jobs changed: expected={sorted(EXPECTED_JOB_META)} actual={sorted(jobs)}"
        )

    action_count = 0
    upload_count = 0
    for job_name, expected_meta in EXPECTED_JOB_META.items():
        job = _mapping(jobs[job_name], f"job {job_name}")
        expected_job_keys = {*expected_meta, "steps"}
        if set(job) != expected_job_keys:
            raise CiValidationError(f"job {job_name} keys changed")
        for key, value in expected_meta.items():
            if job.get(key) != value:
                raise CiValidationError(f"job {job_name} field {key} changed")
        raw_steps = job.get("steps")
        if not isinstance(raw_steps, list):
            raise CiValidationError(f"job {job_name} steps must be a list")
        specs = EXPECTED_STEPS[job_name]
        if len(raw_steps) != len(specs):
            raise CiValidationError(
                f"job {job_name} step count changed: expected={len(specs)} actual={len(raw_steps)}"
            )
        for raw_step, spec in zip(raw_steps, specs, strict=True):
            actions, uploads = _validate_step(job_name, raw_step, spec)
            action_count += actions
            upload_count += uploads

    if upload_count != 4:
        raise CiValidationError("each producer job must publish exactly one evidence artifact")
    return {"jobs": len(jobs), "actions": action_count, "artifact_uploads": upload_count}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    path = args.root.resolve() / WORKFLOW
    try:
        counts = validate_workflow_text(path.read_text(encoding="utf-8"))
    except (OSError, CiValidationError) as exc:
        print(f"FAIL ci-fail-closed: {exc}", file=sys.stderr)
        return 1
    print("PASS ci-fail-closed " + " ".join(f"{key}={value}" for key, value in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
