"""Seeded negative fixtures proving that every Task 008 gate fails closed."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tomllib
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import check_dependency_locks
from scripts import check_product_version
from scripts import generate_sbom
from scripts import run_quality_gates
from scripts import verify_ci_fail_closed
from scripts import verify_module_mappings
from scripts import verify_sbom
from scripts import verify_supply_chain


ROOT = Path(__file__).resolve().parents[1]
_CONFTEST_SPEC = importlib.util.spec_from_file_location(
    "forge_task008_conftest_contract",
    ROOT / "tests/conftest.py",
)
if _CONFTEST_SPEC is None or _CONFTEST_SPEC.loader is None:
    raise RuntimeError("could not load the Forge pytest qualification contract")
forge_conftest = importlib.util.module_from_spec(_CONFTEST_SPEC)
_CONFTEST_SPEC.loader.exec_module(forge_conftest)


def _qualification_policy(
    node_ids: list[str],
    *,
    minimum: int | None = None,
    reviewed_skips: list[str] | None = None,
) -> dict[str, object]:
    return {
        "expected_collection_minimum": len(node_ids) if minimum is None else minimum,
        "expected_collection_sha256": forge_conftest._collection_nodes_sha256(node_ids),
        "allowed_skip_node_ids": reviewed_skips or [],
    }


def test_qualification_rejects_truncated_collection_and_binds_sorted_nodes() -> None:
    nodes = ["tests/test_beta.py::test_b", "tests/test_alpha.py::test_a"]
    assert forge_conftest._collection_nodes_sha256(nodes) == forge_conftest._collection_nodes_sha256(
        reversed(nodes)
    )
    failures = forge_conftest._qualification_failures(
        node_ids=nodes,
        skipped_node_ids=set(),
        deselected_node_ids=set(),
        collectonly=True,
        policy=_qualification_policy(nodes, minimum=3),
    )
    assert any("below floor" in failure for failure in failures)


def test_qualification_rejects_deselection_and_reviewed_skip_drift() -> None:
    reviewed = "tests/test_lab.py::test_reviewed"
    nodes = [reviewed, "tests/test_unit.py::test_unit"]
    failures = forge_conftest._qualification_failures(
        node_ids=nodes,
        skipped_node_ids=set(),
        deselected_node_ids={"tests/test_other.py::test_other"},
        collectonly=False,
        policy=_qualification_policy(nodes, reviewed_skips=[reviewed]),
    )
    assert any("deselected nodes" in failure for failure in failures)
    assert any("skip set changed" in failure for failure in failures)


def test_canonical_full_tests_are_automatic_but_focused_selections_are_not() -> None:
    options = SimpleNamespace(
        keyword="",
        markexpr="",
        lf=False,
        failedfirst=False,
        newfirst=False,
        ignore=[],
        ignore_glob=[],
        deselect=[],
    )
    canonical = SimpleNamespace(args=[str(ROOT / "tests")], option=options)
    focused_path = SimpleNamespace(
        args=[str(ROOT / "tests/test_task008_negative_gates.py")],
        option=options,
    )
    focused_keyword = SimpleNamespace(
        args=[str(ROOT / "tests")],
        option=SimpleNamespace(**{**vars(options), "keyword": "qualification"}),
    )
    assert forge_conftest._is_canonical_full_tests_invocation(canonical)
    assert not forge_conftest._is_canonical_full_tests_invocation(focused_path)
    assert not forge_conftest._is_canonical_full_tests_invocation(focused_keyword)


def test_dependency_gate_rejects_ranges_and_unhashed_locks(tmp_path: Path) -> None:
    with pytest.raises(check_dependency_locks.LockValidationError, match="exact == pin"):
        check_dependency_locks._exact_pin("requests>=2.0", "seeded")

    lock = tmp_path / "requirements.lock"
    lock.write_text("requests==2.34.2\n", encoding="utf-8")
    with pytest.raises(check_dependency_locks.LockValidationError, match="no sha256"):
        check_dependency_locks.parse_lock(lock)


def test_version_gate_rejects_frontend_and_runtime_identity_drift(tmp_path: Path) -> None:
    surfaces = (
        "VERSION",
        "common/version.py",
        "common/brain/brain.py",
        "common/intel/technique_learner.py",
        "common/intel/nuclei_sync.py",
        "forge.py",
        "webforge/webforge.py",
        "netforge/netforge.py",
        "adforge/adforge.py",
        "aiforge/aiforge.py",
        "common/dashboard/server.py",
        "common/reporting/report_engine.py",
        "aiforge/modules/reporting/html_report.py",
        "aiforge/modules/reporting/pdf_report.py",
        "netforge/modules/reporting/html_report.py",
        "netforge/modules/reporting/pdf_report.py",
        "apex-ui/package.json",
        "apex-ui/package-lock.json",
        "apex-ui/vite.config.js",
        "apex-ui/src/App.jsx",
        "Dockerfile",
        "Makefile",
    )
    for relative_path in surfaces:
        destination = tmp_path / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(ROOT / relative_path)
    package_path = tmp_path / "apex-ui/package.json"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    package_path.unlink()
    package["version"] = "5.0.1"
    package_path.write_text(json.dumps(package), encoding="utf-8")
    with pytest.raises(check_product_version.VersionValidationError, match="package.json version"):
        check_product_version.validate_repository(tmp_path)

    package_path.unlink()
    package_path.symlink_to(ROOT / "apex-ui/package.json")
    hardcoded_identities = {
        "common/brain/brain.py": 'SEEDED_PRODUCT_IDENTITY = "Forge Suite v5.0.0"\n',
        "common/intel/technique_learner.py": (
            'SEEDED_PRODUCT_IDENTITY = "Forge-Suite/5.0.0"\n'
        ),
        "common/intel/nuclei_sync.py": 'SEEDED_PRODUCT_IDENTITY = "Forge-Suite/5"\n',
    }
    for relative_path, seeded_identity in hardcoded_identities.items():
        destination = tmp_path / relative_path
        destination.unlink()
        destination.write_text(
            (ROOT / relative_path).read_text(encoding="utf-8") + "\n" + seeded_identity,
            encoding="utf-8",
        )
        with pytest.raises(
            check_product_version.VersionValidationError,
            match="hardcoded product release identity",
        ):
            check_product_version.validate_repository(tmp_path)
        destination.unlink()
        destination.symlink_to(ROOT / relative_path)


def test_ci_gate_rejects_a_required_step_marked_continue_on_error() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    seeded = workflow.replace(
        "      - name: Run all static and supply-chain gates\n",
        "      - name: Run all static and supply-chain gates\n        continue-on-error: true\n",
        1,
    )
    with pytest.raises(verify_ci_fail_closed.CiValidationError, match="keys changed"):
        verify_ci_fail_closed.validate_workflow_text(seeded)


def test_ci_gate_rejects_comment_echo_noop_wrong_job_step_and_missing_qualification() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    static = "python scripts/run_quality_gates.py static --output-dir build/quality"
    coverage = (
        "python scripts/run_quality_gates.py coverage --coverage-json build/coverage.json "
        "--output-dir build/quality"
    )
    swapped = workflow.replace(static, "__STATIC_GATE_PLACEHOLDER__", 1)
    swapped = swapped.replace(coverage, static, 1).replace("__STATIC_GATE_PLACEHOLDER__", coverage, 1)
    seeded = {
        "comment": workflow.replace(
            f"        run: {static}\n",
            f"        run: echo static-gate-omitted\n        # {static}\n",
            1,
        ),
        "echo": workflow.replace(f"run: {static}", f"run: echo '{static}'", 1),
        "dead-noop": workflow.replace(
            f"        run: {static}\n",
            f"        run: |\n          if false; then {static}; fi\n",
            1,
        ),
        "wrong-job": swapped,
        "wrong-step": workflow.replace(
            "      - name: Run all static and supply-chain gates\n"
            f"        run: {static}\n",
            "      - name: Run all static and supply-chain gates\n"
            "        run: echo static-gate-omitted\n"
            "      - name: Decoy static command in the wrong step\n"
            "        if: ${{ false }}\n"
            f"        run: {static}\n",
            1,
        ),
        "missing-qualification": workflow.replace(" --forge-qualification", "", 1),
    }
    for label, candidate in seeded.items():
        with pytest.raises(verify_ci_fail_closed.CiValidationError, match="step") as caught:
            verify_ci_fail_closed.validate_workflow_text(candidate)
        assert label
        assert caught.value

    duplicate_key = workflow + "\npermissions:\n  contents: read\n"
    with pytest.raises(verify_ci_fail_closed.CiValidationError, match="duplicate workflow key"):
        verify_ci_fail_closed.validate_workflow_text(duplicate_key)
    anchored = workflow.replace(
        f"run: {static}",
        f"run: &static-gate {static}",
        1,
    )
    with pytest.raises(verify_ci_fail_closed.CiValidationError, match="anchors and aliases"):
        verify_ci_fail_closed.validate_workflow_text(anchored)


def test_ci_gate_ignores_forbidden_words_in_comments_but_rejects_executed_bypasses() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    verify_ci_fail_closed.validate_workflow_text(workflow + "\n# --exit-zero -p no:warnings\n")
    command = "python scripts/run_quality_gates.py static --output-dir build/quality"
    for bypass in ("--exit-zero", "-p no:warnings"):
        seeded = workflow.replace(command, f"{command} {bypass}", 1)
        with pytest.raises(verify_ci_fail_closed.CiValidationError, match="required command changed"):
            verify_ci_fail_closed.validate_workflow_text(seeded)


def test_warning_policy_rejects_broad_or_unreviewed_filters() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    warning_document = tomllib.loads(
        (ROOT / "config/warning-allowlist.toml").read_text(encoding="utf-8")
    )
    cases: list[tuple[dict[str, object], dict[str, object]]] = []

    broad_message = copy.deepcopy(warning_document)
    broad_message["warning"][0]["message_prefix"] = ".*"
    cases.append((configuration, broad_message))

    broad_category = copy.deepcopy(warning_document)
    broad_category["warning"][0]["category"] = "Warning"
    cases.append((configuration, broad_category))

    broad_module = copy.deepcopy(warning_document)
    broad_module["warning"][0]["module"] = ".*"
    cases.append((configuration, broad_module))

    extra_filter = copy.deepcopy(configuration)
    extra_filter["tool"]["pytest"]["ini_options"]["filterwarnings"].append(
        "ignore:.*:Warning:.*"
    )
    cases.append((extra_filter, warning_document))

    missing_filter = copy.deepcopy(configuration)
    missing_filter["tool"]["pytest"]["ini_options"]["filterwarnings"].pop()
    cases.append((missing_filter, warning_document))

    for candidate_configuration, candidate_allowlist in cases:
        with pytest.raises(run_quality_gates.QualityGateError):
            run_quality_gates.validate_warning_policy_documents(
                candidate_configuration,
                candidate_allowlist,
                date(2026, 8, 5),
            )


def test_coverage_gate_fails_one_point_below_configured_result() -> None:
    report = {"totals": {"percent_covered": 34.0}, "files": {}}
    qualification = {"coverage_total": 35.0, "coverage_targets": {}}
    with pytest.raises(run_quality_gates.QualityGateError, match="below 35"):
        run_quality_gates.validate_coverage_report(report, qualification, 35.0)


def test_mapping_gate_detects_duplicate_literal_ids_before_import() -> None:
    source = 'MODULE_MAP = {"duplicate": "one", "duplicate": "two"}\n'
    assert verify_module_mappings.duplicate_literal_keys(source, "MODULE_MAP") == ["duplicate"]


def test_ruff_gate_rejects_a_seeded_undefined_name(tmp_path: Path) -> None:
    fixture = tmp_path / "seeded_ruff.py"
    fixture.write_text("print(undefined_task008_symbol)\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--config",
            str(ROOT / "pyproject.toml"),
            str(fixture),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "F821" in result.stdout


def test_mypy_gate_rejects_a_seeded_return_type_error(tmp_path: Path) -> None:
    fixture = tmp_path / "seeded_mypy.py"
    fixture.write_text(
        'def typed_value() -> int:\n    return "not-an-integer"\n',
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--config-file",
            str(ROOT / "pyproject.toml"),
            str(fixture),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "return-value" in result.stdout


def test_bandit_gate_detects_a_seeded_shell_injection(tmp_path: Path) -> None:
    fixture = tmp_path / "seeded.py"
    fixture.write_text(
        "import subprocess\n"
        "def unsafe(user_input):\n"
        "    return subprocess.run(user_input, shell=True)\n",
        encoding="utf-8",
    )
    findings = verify_supply_chain.scan_bandit(tmp_path, ("seeded.py",))
    assert any(item["test_id"] == "B602" for item in findings)


def test_secret_gate_detects_a_seeded_credential(tmp_path: Path) -> None:
    fixture = tmp_path / "seeded.env"
    fixture.write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        encoding="utf-8",
    )
    report = verify_supply_chain.scan_secrets(tmp_path, ("seeded.env",))
    detections = [item for items in report["results"].values() for item in items]
    assert detections
    assert any(item["type"] in {"AWS Access Key", "Secret Keyword"} for item in detections)


def test_sbom_gate_rejects_a_missing_ecosystem() -> None:
    document = generate_sbom.build_sbom(ROOT)
    document = json.loads(json.dumps(document))
    document["components"] = [
        component
        for component in document["components"]
        if not any(
            prop.get("name") == "forge:ecosystem" and prop.get("value") == "node"
            for prop in component.get("properties", [])
        )
    ]
    with pytest.raises(verify_sbom.SbomValidationError, match="missing ecosystems"):
        verify_sbom.validate_document(document, ROOT)


def test_full_container_sbom_gate_rejects_declared_only_inventory() -> None:
    document = generate_sbom.build_sbom(ROOT)
    with pytest.raises(verify_sbom.SbomValidationError, match="built image package inventory"):
        verify_sbom.validate_document(document, ROOT, require_container_inventory=True)
