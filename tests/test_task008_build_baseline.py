"""Positive acceptance coverage for the Task 008 build and supply-chain gates."""

from __future__ import annotations

import hashlib
import json
import stat
from datetime import date
from pathlib import Path

import pytest

from scripts import check_dependency_locks
from scripts import check_product_version
from scripts import generate_sbom
from scripts import inventory_production_tests
from scripts import run_quality_gates
from scripts import verify_ci_fail_closed
from scripts import verify_module_mappings
from scripts import verify_sbom
from scripts import verify_supply_chain


ROOT = Path(__file__).resolve().parents[1]


def test_exact_hash_locks_cover_runtime_and_development_inputs() -> None:
    counts = check_dependency_locks.validate_repository(ROOT)
    assert counts["runtime_direct"] == 31
    assert counts["runtime_locked"] >= counts["runtime_direct"]
    assert counts["development_direct"] == 14
    assert counts["development_locked"] > counts["runtime_locked"]


def test_canonical_product_version_reaches_static_and_runtime_surfaces() -> None:
    version = check_product_version.validate_repository(ROOT)
    check_product_version.validate_runtime_outputs(ROOT, version)
    assert version == "5.0.0"


def test_registered_modules_load_and_every_other_file_is_classified() -> None:
    counts = verify_module_mappings.validate_repository(ROOT)
    assert counts == {
        "registered": 318,
        "unique_paths": 318,
        "classified_unregistered": 67,
    }


def test_production_regression_inventory_has_no_execution_exception() -> None:
    rows, failures = inventory_production_tests.inventory()
    failures.extend(inventory_production_tests.validate_policy(rows))
    rendered = inventory_production_tests.render(rows)
    assert not failures
    assert len(rows) == 1444
    assert rendered.count(",COLLECT_AND_EXECUTE,") == 1444
    assert ",DO_NOT_EXECUTE," not in rendered


def test_ci_is_pinned_fail_closed_and_publishes_each_evidence_family() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    counts = verify_ci_fail_closed.validate_workflow_text(workflow)
    assert counts["jobs"] == 5
    assert counts["artifact_uploads"] == 4


def test_static_sbom_is_deterministic_and_lock_complete() -> None:
    first = generate_sbom.build_sbom(ROOT)
    second = generate_sbom.build_sbom(ROOT)
    assert first == second
    counts = verify_sbom.validate_document(first, ROOT)
    assert counts["python"] == check_dependency_locks.validate_repository(ROOT)["runtime_locked"]
    assert counts["node"] >= 100
    assert counts["base-image"] == 2
    assert counts["debian"] >= 10


def test_built_image_sbom_requires_inventory_and_digest(tmp_path: Path) -> None:
    inventory = tmp_path / "packages.tsv"
    inventory.write_text(
        "".join(
            f"{name}\t{version}\tamd64\tii \n"
            for name, version, _architecture in generate_sbom._declared_debian_packages(
                ROOT,
                stage="runtime",
            )
        ),
        encoding="utf-8",
    )
    document = generate_sbom.build_sbom(
        ROOT,
        inventory,
        "forge-suite:5.0.0@sha256:" + "a" * 64,
    )
    counts = verify_sbom.validate_document(document, ROOT, require_container_inventory=True)
    assert counts["container-image"] == 1
    assert counts["debian"] == 8


def test_security_baselines_are_review_bound_and_nonrecursive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bandit = json.loads((ROOT / "config/bandit-baseline.json").read_text(encoding="utf-8"))
    secrets = json.loads((ROOT / ".secrets.baseline").read_text(encoding="utf-8"))
    bandit_proposal = verify_supply_chain.bandit_proposal_document(bandit["findings"])
    secret_proposal = {key: value for key, value in secrets.items() if key != "forge_review"}
    assert set(bandit_proposal) == {"schema_version", "findings"}
    assert bandit_proposal["schema_version"] == "forge-bandit-baseline-v2"
    assert "forge_review" not in bandit_proposal
    assert "forge_review" not in secret_proposal
    assert "config/bandit-baseline.json" not in secrets["results"]
    assert ".secrets.baseline" not in secrets["results"]
    assert "config/security-review.toml" not in secrets["results"]
    assert "scan_history.json" not in secrets["results"]
    paths = verify_supply_chain.secret_scan_paths(ROOT)
    shipped_paths = verify_supply_chain.docker_shipped_text_paths(ROOT)
    assert "config/bandit-baseline.json" not in paths
    assert ".secrets.baseline" not in paths
    assert "config/security-review.toml" not in paths
    assert ".env.example" in paths
    assert "common/dashboard/web/static/js/credentials.js" in paths
    assert "common/dashboard/web/static/js/credentials.js" in shipped_paths
    assert set(shipped_paths).issubset(paths)

    fixture_root = tmp_path / "fixture-repository"
    (fixture_root / "config").mkdir(parents=True)
    (fixture_root / "scripts").mkdir()
    (fixture_root / "config/bandit-baseline.json").write_text(
        json.dumps(bandit_proposal, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    fixture_secret_proposal = {**secret_proposal, "results": {}}
    (fixture_root / ".secrets.baseline").write_text(
        json.dumps(fixture_secret_proposal, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (fixture_root / "pyproject.toml").write_bytes((ROOT / "pyproject.toml").read_bytes())
    (fixture_root / "requirements-dev.lock").write_bytes(
        (ROOT / "requirements-dev.lock").read_bytes()
    )
    for relative in verify_supply_chain._DOCKER_CONTEXT_ROOT_FILES:
        path = fixture_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(f"fixture for {relative}\n", encoding="utf-8")
    for relative in verify_supply_chain._DOCKER_CONTEXT_ROOT_DIRECTORIES:
        (fixture_root / relative).mkdir(parents=True, exist_ok=True)
    (fixture_root / "Dockerfile").write_bytes((ROOT / "Dockerfile").read_bytes())
    (fixture_root / ".dockerignore").write_bytes((ROOT / ".dockerignore").read_bytes())
    (fixture_root / "scripts/verify_supply_chain.py").write_bytes(
        (ROOT / "scripts/verify_supply_chain.py").read_bytes()
    )
    fixture_secret_paths = verify_supply_chain.docker_shipped_text_paths(fixture_root)
    context = verify_supply_chain.security_review_context(
        fixture_root,
        secret_paths=fixture_secret_paths,
        scanner_versions={"bandit": "1.8.6", "detect-secrets": "1.5.0"},
    )
    fixture_manifest = verify_supply_chain._proposal_manifest(
        context,
        (fixture_root / "config/bandit-baseline.json").read_bytes(),
        (fixture_root / ".secrets.baseline").read_bytes(),
    )
    assert (
        hashlib.sha256(verify_supply_chain._proposal_bytes(fixture_manifest)).hexdigest()
        == (context["proposal_manifest_sha256"])
    )
    receipt = {
        "schema_version": 2,
        "receipt_type": "LOCAL_UNSIGNED",
        "task_id": "008",
        "task_sha256": verify_supply_chain.TASK_SHA256,
        "decision": "ACCEPT",
        "implementer_identity": "fixture:implementer",
        "reviewer_identity": "fixture:independent-reviewer",
        "implemented_on": "2026-08-05",
        "reviewed_on": "2026-08-05",
        "expires_on": "2026-11-01",
        "reviewed_contract_sha256": context["reviewed_contract_sha256"],
        "proposal_manifest_sha256": context["proposal_manifest_sha256"],
        "review_evidence_id": "fixture/task008/review-001",
        "review_evidence_sha256": "a" * 64,
        **{table: context[table] for table in verify_supply_chain._RECEIPT_TABLES},
    }
    verify_supply_chain.validate_security_review_document(receipt, context, date(2026, 8, 5))
    receipt_bytes = verify_supply_chain.render_security_review_receipt(receipt)
    verify_supply_chain.validate_security_review_bytes(
        receipt_bytes,
        context,
        date(2026, 8, 5),
    )
    with pytest.raises(
        verify_supply_chain.SupplyChainError,
        match="comments and trailing data are forbidden",
    ):
        verify_supply_chain.validate_security_review_bytes(
            receipt_bytes + b'# canary_secret = "forge-fixture-secret-value"\n',
            context,
            date(2026, 8, 5),
        )
    symlinked_bandit = tmp_path / "symlinked-bandit-baseline.json"
    symlinked_bandit.symlink_to(fixture_root / "config/bandit-baseline.json")
    with pytest.raises(
        verify_supply_chain.SupplyChainError,
        match="symlink",
    ):
        verify_supply_chain.security_review_context(
            fixture_root,
            bandit_baseline_path=symlinked_bandit,
            secret_paths=fixture_secret_paths,
            scanner_versions={"bandit": "1.8.6", "detect-secrets": "1.5.0"},
        )
    self_reviewed = {**receipt, "reviewer_identity": receipt["implementer_identity"]}
    with pytest.raises(
        verify_supply_chain.SupplyChainError,
        match="identities must be distinct",
    ):
        verify_supply_chain.validate_security_review_document(
            self_reviewed,
            context,
            date(2026, 8, 5),
        )

    proposal_parent = tmp_path / "private-proposals"
    proposal_parent.mkdir(mode=0o700)
    proposal_directory = proposal_parent / "candidate-set"
    monkeypatch.setattr(
        verify_supply_chain,
        "scan_bandit",
        lambda *_args, **_kwargs: bandit["findings"],
    )
    monkeypatch.setattr(
        verify_supply_chain,
        "secret_proposal_document",
        lambda *_args, **_kwargs: secret_proposal,
    )
    assert (
        verify_supply_chain.main(
            ["--root", str(ROOT), "--propose-baseline-set", str(proposal_directory)]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert output.startswith("PROPOSAL supply-chain kind=baseline-set status=UNREVIEWED")
    assert "PASS" not in output
    assert "reviewer" not in output.casefold()
    assert stat.S_IMODE(proposal_directory.stat().st_mode) == 0o700
    for name in (
        "bandit-baseline.proposal.json",
        "secrets-baseline.proposal.json",
        "proposal-manifest.json",
    ):
        assert stat.S_IMODE((proposal_directory / name).stat().st_mode) == 0o600
    assert "forge_review" not in json.loads(
        (proposal_directory / "bandit-baseline.proposal.json").read_text(encoding="utf-8")
    )
    proposal_manifest = json.loads(
        (proposal_directory / "proposal-manifest.json").read_text(encoding="utf-8")
    )
    assert proposal_manifest["proposal_type"] == "UNREVIEWED"
    assert len(proposal_manifest["reviewed_contract_sha256"]) == 64
    assert (
        proposal_manifest["scanner_contract"]["context_inventory_contract"]
        == "forge-filesystem-candidate-with-docker-context-v1"
    )
    assert proposal_manifest["scanner_contract"]["dockerfile"] == "Dockerfile"
    assert proposal_manifest["scanner_contract"]["dockerignore"] == ".dockerignore"
    assert proposal_manifest["detect_secrets"]["path_count"] == len(paths)
    assert proposal_manifest["detect_secrets"]["docker_path_count"] == len(shipped_paths)
    assert proposal_manifest["detect_secrets"][
        "docker_paths_sha256"
    ] == verify_supply_chain._sorted_nul_digest(shipped_paths)
    assert len(proposal_manifest["files"]) == 2
    manifest_text = json.dumps(proposal_manifest, sort_keys=True)
    for forbidden in (
        "proposal_manifest_sha256",
        "review_evidence",
        "reviewer_identity",
        "decision",
    ):
        assert forbidden not in manifest_text
    for entry in proposal_manifest["files"]:
        proposal_bytes = (proposal_directory / entry["proposal_file"]).read_bytes()
        assert hashlib.sha256(proposal_bytes).hexdigest() == entry["sha256"]
        assert len(proposal_bytes) == entry["bytes"]
    with pytest.raises(
        verify_supply_chain.SupplyChainError,
        match="outside the repository",
    ):
        verify_supply_chain.write_baseline_set_proposal(
            ROOT / "config/task008-proposal-set",
            bandit_proposal,
            secret_proposal,
            ROOT,
        )
    with pytest.raises(
        verify_supply_chain.SupplyChainError,
        match="refusing overwrite",
    ):
        verify_supply_chain.write_baseline_set_proposal(
            proposal_directory,
            bandit_proposal,
            secret_proposal,
            ROOT,
        )
    with pytest.raises(
        verify_supply_chain.SupplyChainError,
        match="path inventory is not the canonical candidate set",
    ):
        verify_supply_chain.write_baseline_set_proposal(
            proposal_parent / "truncated-set",
            bandit_proposal,
            secret_proposal,
            ROOT,
            secret_paths=paths[:-1],
        )

    incomplete_directory = proposal_parent / "incomplete-set"
    exclusive_writer = verify_supply_chain._write_exclusive_private

    def _fail_manifest_write(path: Path, content: bytes) -> None:
        if path.name == "proposal-manifest.json":
            raise verify_supply_chain.SupplyChainError("seeded manifest write failure")
        exclusive_writer(path, content)

    monkeypatch.setattr(
        verify_supply_chain,
        "_write_exclusive_private",
        _fail_manifest_write,
    )
    with pytest.raises(
        verify_supply_chain.SupplyChainError,
        match="seeded manifest write failure",
    ):
        verify_supply_chain.write_baseline_set_proposal(
            incomplete_directory,
            bandit_proposal,
            secret_proposal,
            ROOT,
            secret_paths=paths,
        )
    assert not incomplete_directory.exists()
    monkeypatch.setattr(
        verify_supply_chain,
        "_write_exclusive_private",
        exclusive_writer,
    )

    committed_before = {
        "bandit": (ROOT / "config/bandit-baseline.json").read_bytes(),
        "secrets": (ROOT / ".secrets.baseline").read_bytes(),
    }
    with pytest.raises(SystemExit):
        verify_supply_chain.main(["--write-bandit-baseline"])
    capsys.readouterr()
    assert (ROOT / "config/bandit-baseline.json").read_bytes() == committed_before["bandit"]
    assert (ROOT / ".secrets.baseline").read_bytes() == committed_before["secrets"]


def test_warning_policy_is_narrow_owned_and_unexpired() -> None:
    assert run_quality_gates.validate_warning_policy(ROOT, date(2026, 8, 5)) == 3
