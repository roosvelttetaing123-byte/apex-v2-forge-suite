"""Task 102 canonical evidence cross-surface acceptance fixtures.

These tests deliberately exercise the persisted canonical reader boundary before
passing data to ordinary exports and reports. They use only inert local
fixtures; no target activity or external resources are involved.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from common.canonical_evidence import (
    CanonicalEvidenceContext,
    CanonicalEvidenceError,
    CanonicalEvidenceReader,
    CanonicalEvidenceService,
)
from common.db import create_db
from common.evidence import Evidence
from common.evidence_custody import (
    ArtifactAccessDenied,
    ArtifactNotFound,
    ArtifactIntegrityError,
    ArtifactScopeError,
    ArtifactTransactionError,
    CustodyError,
    EvidenceCustodyStore,
    make_original_authorization,
)
from common.finding import Finding, Severity
from common.reporter import BaseReporter
from common.reporting.report_engine import ReportConfig, ReportEngine
from common.redaction import clear_sensitive_values, register_sensitive_values


_RAW_CANARY = "TASK102_INTEGRATION_RAW_CANARY"
_RESPONSE_CANARY = "TASK102_INTEGRATION_RESPONSE_CANARY"


@pytest.fixture
def registered_canaries() -> None:
    register_sensitive_values((_RAW_CANARY, _RESPONSE_CANARY))
    try:
        yield
    finally:
        clear_sensitive_values()


def _context(
    tenant_id: str,
    *,
    run_suffix: str = "default",
) -> CanonicalEvidenceContext:
    suffix = str(run_suffix)
    return CanonicalEvidenceContext(
        tenant_id=tenant_id,
        engagement_id=f"engagement-{tenant_id}",
        run_id=f"run-{tenant_id}-{suffix}",
        job_id=f"job-{tenant_id}-{suffix}",
        action_id=f"action-{tenant_id}-{suffix}",
        decision_id=f"decision-{tenant_id}-{suffix}",
        operator_id=f"operator-{tenant_id}",
        operator_role="operator",
        engine="fixture-engine",
        module_id="fixture.check",
        action_kind="fixture-observation",
        scope_policy_version="scope-policy-v1",
        scope_reason="local deterministic fixture",
    )


def _make_finding(
    *,
    tenant_id: str,
    host: str | None = None,
    route: str = "/items",
    parameter: str = "item",
    identity_ref: str | None = None,
    check_id: str = "fixture.check",
) -> Finding:
    identity = identity_ref or f"principal:{tenant_id}"
    normalized_route = route if route.startswith("/") else f"/{route}"
    target_host = host or f"{tenant_id}.fixture.invalid"
    return Finding(
        title="Persisted fixture finding",
        severity=Severity.HIGH,
        target=f"https://{target_host}{normalized_route}?{parameter}=1",
        url=f"https://{target_host}{normalized_route}?{parameter}=1",
        module="fixture.check",
        description="Persisted canonical fixture derivative.",
        reproduction_steps=["Review the local fixture."],
        remediation="Apply the fixture remediation.",
        references=["CWE-000"],
        confidence="HIGH",
        proof_type="deterministic_fixture",
        verification_state="verified",
        maturity="stable",
        evidence=Evidence(
            request_raw=(
                f"GET {normalized_route}?{parameter}=1 HTTP/1.1\n\n{_RAW_CANARY}"
            ),
            response_raw=f"HTTP/1.1 200 OK\n\n{_RESPONSE_CANARY}",
            extra={
                "route": normalized_route,
                "parameter": parameter,
                "location": "query",
                "identity_ref": identity,
                "check_id": check_id,
            },
        ),
    )


def _persist_fixture(
    session: Any,
    custody_root: Path,
    tenant_id: str,
    *,
    run_suffix: str = "default",
    host: str | None = None,
    route: str = "/items",
    parameter: str = "item",
    identity_ref: str | None = None,
    check_id: str = "fixture.check",
) -> dict[str, Any]:
    finding = _make_finding(
        tenant_id=tenant_id,
        host=host,
        route=route,
        parameter=parameter,
        identity_ref=identity_ref,
        check_id=check_id,
    )
    service = CanonicalEvidenceService(
        session,
        custody_root,
        _context(tenant_id, run_suffix=run_suffix),
    )
    projection = service.persist_finding(finding)
    artifact = projection["evidence"]["observations"][0]["artifacts"][0]
    return {
        "tenant_id": tenant_id,
        "finding_id": projection["id"],
        "projection": projection,
        "artifact_id": artifact["artifact_id"],
        "reader": CanonicalEvidenceReader(
            session,
            custody_root,
            tenant_id,
            audit_actor_id=f"operator-{tenant_id}",
            expected_original_operator_id=f"operator-{tenant_id}",
        ),
    }


def _assert_ordinary_payload(payload: str, derivative: str) -> None:
    assert derivative.splitlines()[0] in payload
    assert "<redacted>" in payload or "&lt;redacted&gt;" in payload
    assert _RAW_CANARY not in payload
    assert _RESPONSE_CANARY not in payload
    for forbidden in (
        "request_raw",
        "response_raw",
        "screenshot_path",
        "console_capture_path",
        "pcap_path",
        "original.bin",
    ):
        assert forbidden not in payload


def _report_input(projection: dict[str, Any]) -> dict[str, Any]:
    # Report constructors accept the persisted ordinary projection returned by
    # the canonical reader; no mutable finding or raw capture is introduced.
    return json.loads(json.dumps(projection))


_CANONICAL_LINEAGE_TABLES = (
    "canonical_tenants",
    "canonical_engagements",
    "canonical_operators",
    "canonical_roles",
    "canonical_scope_decisions",
    "canonical_jobs",
    "canonical_actions",
    "canonical_module_versions",
    "canonical_module_executions",
    "canonical_assets",
    "canonical_observations",
    "canonical_artifact_refs",
    "canonical_artifact_manifests",
    "canonical_observation_artifacts",
    "canonical_findings",
    "canonical_finding_observations",
)


def _tenant_lineage_counts(session: Any, tenant_id: str) -> dict[str, int]:
    return {
        table: int(
            session.execute(
                text(
                    f"SELECT COUNT(*) FROM {table} WHERE "
                    f"{'id' if table == 'canonical_tenants' else 'tenant_id'}=:tenant_id"
                ),
                {"tenant_id": tenant_id},
            ).scalar_one()
        )
        for table in _CANONICAL_LINEAGE_TABLES
    }


def _all_lineage_counts(session: Any) -> dict[str, int]:
    return {
        table: int(
            session.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one()
        )
        for table in _CANONICAL_LINEAGE_TABLES
    }


def _custody_files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.is_file()]


def test_one_finding_links_observations_from_separate_runs(
    tmp_path: Path,
    registered_canaries: None,
) -> None:
    session = create_db(tmp_path / "separate-runs.db")
    custody_root = tmp_path / "custody"
    custody_root.mkdir(mode=0o700)
    try:
        first = _persist_fixture(
            session,
            custody_root,
            "tenant-a",
            run_suffix="first",
        )
        second = _persist_fixture(
            session,
            custody_root,
            "tenant-a",
            run_suffix="second",
        )

        assert second["finding_id"] == first["finding_id"]
        projection = second["reader"].get_finding_projection(first["finding_id"])
        assert projection is not None
        observations = projection["evidence"]["observations"]
        assert len(observations) == 2
        assert len({item["observation_id"] for item in observations}) == 2
        assert len(
            {
                artifact["artifact_id"]
                for item in observations
                for artifact in item["artifacts"]
            }
        ) >= 2
        assert all(item["artifacts"] for item in observations)
        assert len({item["job_id"] for item in observations}) == 2
        assert _tenant_lineage_counts(session, "tenant-a")[
            "canonical_finding_observations"
        ] == 2
        assert _tenant_lineage_counts(session, "tenant-a")[
            "canonical_observation_artifacts"
        ] >= 2
    finally:
        session.close()


def test_rerun_cannot_mutate_first_observation_or_artifacts(
    tmp_path: Path,
    registered_canaries: None,
) -> None:
    session = create_db(tmp_path / "rerun-immutability.db")
    custody_root = tmp_path / "custody"
    custody_root.mkdir(mode=0o700)
    try:
        first = _persist_fixture(
            session,
            custody_root,
            "tenant-a",
            run_suffix="first",
        )
        first_observation_id = session.execute(
            text(
                "SELECT observation_id FROM canonical_artifact_refs "
                "WHERE tenant_id=:tenant_id AND id=:artifact_id"
            ),
            {"tenant_id": "tenant-a", "artifact_id": first["artifact_id"]},
        ).scalar_one()
        assert session.in_transaction()
        first_observation = dict(
            session.execute(
                text(
                    "SELECT job_id,module_version_id,asset_id,route,parameter,"
                    "location,identity_ref,metadata_json "
                    "FROM canonical_observations "
                    "WHERE tenant_id=:tenant_id AND id=:observation_id"
                ),
                {
                    "tenant_id": "tenant-a",
                    "observation_id": first_observation_id,
                },
            ).mappings().one()
        )
        first_artifact = dict(
            session.execute(
                text(
                    "SELECT observation_id,reference,digest,size,"
                    "integrity_state,metadata_json,manifest_digest "
                    "FROM canonical_artifact_refs "
                    "WHERE tenant_id=:tenant_id AND id=:artifact_id"
                ),
                {"tenant_id": "tenant-a", "artifact_id": first["artifact_id"]},
            ).mappings().one()
        )
        first_manifest = first["reader"].custody.get_manifest(first["artifact_id"])
        first_derivative = first["reader"].custody.read(first["artifact_id"])
        # Snapshot queries above open a SQLAlchemy read transaction.  Close
        # that caller-owned snapshot explicitly before starting the next
        # canonical write; persistence must never commit or roll it back
        # implicitly on the caller's behalf.
        session.rollback()

        second = _persist_fixture(
            session,
            custody_root,
            "tenant-a",
            run_suffix="second",
        )
        assert second["finding_id"] == first["finding_id"]

        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "UPDATE canonical_observations SET route='/mutated' "
                    "WHERE tenant_id=:tenant_id AND id=:observation_id"
                ),
                {
                    "tenant_id": "tenant-a",
                    "observation_id": first_observation_id,
                },
            )
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "UPDATE canonical_artifact_refs SET digest=:digest "
                    "WHERE tenant_id=:tenant_id AND id=:artifact_id"
                ),
                {
                    "digest": "sha256:" + "f" * 64,
                    "tenant_id": "tenant-a",
                    "artifact_id": first["artifact_id"],
                },
            )
            session.commit()
        session.rollback()
        with pytest.raises(CustodyError):
            first["reader"].custody.store_artifact(
                b"replacement-attempt",
                source_observation_id=str(second["artifact_id"]),
                collector_id="fixture-collector",
                artifact_id=first["artifact_id"],
            )

        assert dict(
            session.execute(
                text(
                    "SELECT job_id,module_version_id,asset_id,route,parameter,"
                    "location,identity_ref,metadata_json "
                    "FROM canonical_observations "
                    "WHERE tenant_id=:tenant_id AND id=:observation_id"
                ),
                {
                    "tenant_id": "tenant-a",
                    "observation_id": first_observation_id,
                },
            ).mappings().one()
        ) == first_observation
        assert dict(
            session.execute(
                text(
                    "SELECT observation_id,reference,digest,size,"
                    "integrity_state,metadata_json,manifest_digest "
                    "FROM canonical_artifact_refs "
                    "WHERE tenant_id=:tenant_id AND id=:artifact_id"
                ),
                {"tenant_id": "tenant-a", "artifact_id": first["artifact_id"]},
            ).mappings().one()
        ) == first_artifact
        assert first["reader"].custody.get_manifest(
            first["artifact_id"]
        ).manifest_digest == first_manifest.manifest_digest
        assert first["reader"].custody.read(first["artifact_id"]) == first_derivative
    finally:
        session.close()


def test_identity_dimensions_separate_route_parameter_identity_check_run_and_tenant(
    tmp_path: Path,
    registered_canaries: None,
) -> None:
    session = create_db(tmp_path / "identity-dimensions.db")
    custody_root = tmp_path / "custody"
    custody_root.mkdir(mode=0o700)
    try:
        baseline = _persist_fixture(
            session,
            custody_root,
            "tenant-a",
            run_suffix="baseline",
            host="shared.fixture.invalid",
            route="/items",
            parameter="item",
            identity_ref="principal:a",
            check_id="check-a",
        )
        assert (
            baseline["projection"]["target"].split("/", 3)[2]
            == "shared.fixture.invalid"
        )
        variants = (
            ("route", {"route": "/admin"}),
            ("parameter", {"parameter": "name"}),
            ("identity", {"identity_ref": "principal:b"}),
            ("check", {"check_id": "check-b"}),
        )
        variant_ids: set[str] = set()
        for suffix, updates in variants:
            variant = _persist_fixture(
                session,
                custody_root,
                "tenant-a",
                run_suffix=f"variant-{suffix}",
                host="shared.fixture.invalid",
                **updates,
            )
            assert (
                variant["projection"]["target"].split("/", 3)[2]
                == "shared.fixture.invalid"
            )
            variant_ids.add(variant["finding_id"])

        assert len(variant_ids) == len(variants)
        assert baseline["finding_id"] not in variant_ids

        rerun = _persist_fixture(
            session,
            custody_root,
            "tenant-a",
            run_suffix="rerun",
            host="shared.fixture.invalid",
            route="/items",
            parameter="item",
            identity_ref="principal:a",
            check_id="check-a",
        )
        assert rerun["finding_id"] == baseline["finding_id"]
        baseline_projection = rerun["reader"].get_finding_projection(
            baseline["finding_id"]
        )
        assert baseline_projection is not None
        assert len(baseline_projection["evidence"]["observations"]) == 2
        session.rollback()

        mapped_query_finding = _make_finding(
            tenant_id="tenant-a",
            host="shared.fixture.invalid",
            route="/items",
        )
        mapped_query_finding.evidence.extra.pop("parameter")
        mapped_query_finding.evidence.extra["query"] = {
            "page": {"nested": _RAW_CANARY},
            "search": _RESPONSE_CANARY,
        }
        mapped_query_projection = CanonicalEvidenceService(
            session,
            custody_root,
            _context("tenant-a", run_suffix="mapped-query"),
        ).persist_finding(mapped_query_finding)
        mapped_observation = mapped_query_projection["evidence"]["observations"][0]
        assert mapped_observation["parameter"] == "page,search"
        assert _RAW_CANARY not in json.dumps(mapped_query_projection)
        assert _RESPONSE_CANARY not in json.dumps(mapped_query_projection)

        tenant_b = _persist_fixture(
            session,
            custody_root,
            "tenant-b",
            run_suffix="baseline",
            host="shared.fixture.invalid",
            route="/items",
            parameter="item",
            identity_ref="principal:a",
            check_id="check-a",
        )
        assert (
            tenant_b["projection"]["target"].split("/", 3)[2]
            == "shared.fixture.invalid"
        )
        assert tenant_b["finding_id"] != baseline["finding_id"]
        assert {
            item["id"] for item in baseline["reader"].list_finding_projections()
        } == {
            baseline["finding_id"],
            mapped_query_projection["id"],
            *variant_ids,
        }
        assert {
            item["id"] for item in tenant_b["reader"].list_finding_projections()
        } == {tenant_b["finding_id"]}
    finally:
        session.close()


def test_intentional_dedup_retains_every_source_and_artifact(
    tmp_path: Path,
    registered_canaries: None,
) -> None:
    session = create_db(tmp_path / "dedup-lineage.db")
    custody_root = tmp_path / "custody"
    custody_root.mkdir(mode=0o700)
    try:
        first = _persist_fixture(
            session,
            custody_root,
            "tenant-a",
            run_suffix="first",
            route="/items",
            parameter="item",
            identity_ref="principal:a",
            check_id="check-a",
        )
        second = _persist_fixture(
            session,
            custody_root,
            "tenant-a",
            run_suffix="second",
            route="/items",
            parameter="item",
            identity_ref="principal:a",
            check_id="check-a",
        )
        assert second["finding_id"] == first["finding_id"]
        links = session.execute(
            text(
                "SELECT finding_id,observation_id,artifact_id,identity_key "
                "FROM canonical_finding_observations "
                "WHERE tenant_id=:tenant_id ORDER BY observation_id"
            ),
            {"tenant_id": "tenant-a"},
        ).mappings().all()
        assert len(links) == 2
        assert {row["finding_id"] for row in links} == {first["finding_id"]}
        assert len({row["observation_id"] for row in links}) == 2
        assert len({row["artifact_id"] for row in links}) == 2
        assert len({row["identity_key"] for row in links}) == 1
        artifact_links = session.execute(
            text(
                "SELECT observation_id,artifact_id,role,sequence "
                "FROM canonical_observation_artifacts "
                "WHERE tenant_id=:tenant_id ORDER BY observation_id"
            ),
            {"tenant_id": "tenant-a"},
        ).mappings().all()
        assert len(artifact_links) >= 2
        assert {row["observation_id"] for row in artifact_links} == {
            row["observation_id"] for row in links
        }
        assert {row["artifact_id"] for row in artifact_links} >= {
            row["artifact_id"] for row in links
        }
        assert all(
            any(
                row["observation_id"] == observation_id
                and row["role"] == "primary"
                and row["sequence"] == 0
                for row in artifact_links
            )
            for observation_id in {row["observation_id"] for row in links}
        )
        finding_row = session.execute(
            text(
                "SELECT dedup_key FROM canonical_findings "
                "WHERE tenant_id=:tenant_id AND id=:finding_id"
            ),
            {"tenant_id": "tenant-a", "finding_id": first["finding_id"]},
        ).scalar_one()
        assert finding_row == links[0]["identity_key"]
    finally:
        session.close()


def test_cross_tenant_read_link_dedup_export_and_artifact_path_fail(
    tmp_path: Path,
    registered_canaries: None,
) -> None:
    session = create_db(tmp_path / "canonical.db")
    custody_root = tmp_path / "custody"
    custody_root.mkdir(mode=0o700)
    try:
        tenant_a = _persist_fixture(session, custody_root, "tenant-a")
        tenant_b = _persist_fixture(session, custody_root, "tenant-b")
        derivative = tenant_a["projection"]["evidence"]["observations"][0]["artifacts"][0]["derivative"]

        reader_a = tenant_a["reader"]
        reader_b = tenant_b["reader"]
        assert reader_a.get_finding_projection(tenant_a["finding_id"]) is not None
        assert reader_b.get_finding_projection(tenant_a["finding_id"]) is None
        with pytest.raises(CanonicalEvidenceError):
            reader_b.export_finding(tenant_a["finding_id"])
        with pytest.raises((ArtifactNotFound, ArtifactScopeError)):
            reader_b.custody.get_manifest(tenant_a["artifact_id"])
        assert [item["id"] for item in reader_b.list_finding_projections()] == [
            tenant_b["finding_id"]
        ]
        tenant_a_observation = session.execute(
            text(
                "SELECT observation_id FROM canonical_artifact_refs "
                "WHERE tenant_id=:tenant_id AND id=:artifact_id"
            ),
            {
                "tenant_id": "tenant-a",
                "artifact_id": tenant_a["artifact_id"],
            },
        ).scalar_one()
        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "INSERT INTO canonical_finding_observations "
                    "(tenant_id,finding_id,observation_id,artifact_id,identity_key,"
                    "first_seen_at,last_seen_at,created_at,metadata_json) "
                    "VALUES (:tenant_id,:finding_id,:observation_id,:artifact_id,"
                    ":identity_key,:seen,:seen,:seen,'{}')"
                ),
                {
                    "tenant_id": "tenant-b",
                    "finding_id": tenant_b["finding_id"],
                    "observation_id": tenant_a_observation,
                    "artifact_id": tenant_a["artifact_id"],
                    "identity_key": "finding-v1:" + "1" * 64,
                    "seen": "2026-08-25T00:00:00Z",
                },
            )
            session.commit()
        session.rollback()

        backend_export = reader_a.export_finding(tenant_a["finding_id"])
        assert backend_export == reader_a.export_finding(tenant_a["finding_id"])
        _assert_ordinary_payload(backend_export.decode("utf-8"), derivative)

        base_dir = tmp_path / "base-report"
        base_paths = BaseReporter(
            [_report_input(tenant_a["projection"])],
            base_dir,
            formats=["json", "html"],
        )
        base_json = Path(base_paths.generate_json()).read_text(encoding="utf-8")
        base_html = Path(base_paths.generate_html()).read_text(encoding="utf-8")
        _assert_ordinary_payload(base_json, derivative)
        _assert_ordinary_payload(base_html, derivative)

        engine_dir = tmp_path / "engine-report"
        engine = ReportEngine(
            [_report_input(tenant_a["projection"])],
            ReportConfig(
                engagement="Task 102 fixture",
                target="local fixture",
                output_dir=str(engine_dir),
                formats=["json", "html"],
                include_exec_summary=False,
                include_unverified=True,
            ),
        )
        engine_paths = asyncio.run(engine.generate())
        engine_json = Path(engine_paths["json"]).read_text(encoding="utf-8")
        engine_html = Path(engine_paths["html"]).read_text(encoding="utf-8")
        _assert_ordinary_payload(engine_json, derivative)
        _assert_ordinary_payload(engine_html, derivative)

        tenant_b_report = BaseReporter(
            reader_b.list_finding_projections(),
            tmp_path / "tenant-b-report",
            formats=["json"],
        )
        tenant_b_json = Path(tenant_b_report.generate_json()).read_text(encoding="utf-8")
        assert tenant_a["finding_id"] not in tenant_b_json
        assert tenant_a["artifact_id"] not in tenant_b_json
        assert tenant_a["projection"]["target"] not in tenant_b_json
    finally:
        session.close()


def test_default_api_report_export_return_only_redacted_derivative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_task102_end_to_end import exercise_task102_end_to_end

    result = exercise_task102_end_to_end(tmp_path, monkeypatch)
    finding = result["api"]["findings"][0]
    artifacts = [
        artifact
        for observation in finding["evidence"]["observations"]
        for artifact in observation["artifacts"]
    ]
    derivatives = [artifact["derivative"] for artifact in artifacts]
    assert derivatives
    assert all(result["raw_marker"] not in value for value in derivatives)
    for rendered in (
        result["export"],
        *result["reports"].values(),
    ):
        assert any(
            derivative.splitlines()[0] in rendered
            or derivative.splitlines()[0]
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            in rendered
            for derivative in derivatives
        )
        assert result["raw_marker"] not in rendered


def test_redaction_canaries_absent_from_default_api_ui_report_export_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_task102_end_to_end import exercise_task102_end_to_end

    result = exercise_task102_end_to_end(tmp_path, monkeypatch)
    rendered_surfaces = json.dumps(
        {
            "api": result["api"],
            "event": result["event"],
            "export": result["export"],
            "reports": result["reports"],
            "logs": result["logs"],
        },
        sort_keys=True,
    )
    assert result["raw_marker"] not in rendered_surfaces
    for forbidden in (
        "request_raw",
        "response_raw",
        "original_relative_path",
        "derivative_relative_path",
    ):
        assert forbidden not in rendered_surfaces

    ui_regression = Path(
        "apex-ui/src/pages/__tests__/VulnerabilitiesTruth.test.jsx"
    ).read_text(encoding="utf-8")
    assert "renders persisted derivative evidence" in ui_regression
    assert "not.toHaveTextContent('IGNORED_LEGACY_RAW_CANARY')" in ui_regression


def test_artifact_and_manifest_tamper_fail_deterministically(
    tmp_path: Path,
    registered_canaries: None,
) -> None:
    for tamper_kind in ("bytes", "manifest"):
        case_root = tmp_path / tamper_kind
        case_root.mkdir(mode=0o700)
        session = create_db(case_root / "canonical.db")
        custody_root = case_root / "custody"
        custody_root.mkdir(mode=0o700)
        failed_export = case_root / "failed-export.json"
        try:
            fixture = _persist_fixture(session, custody_root, "tenant-a")
            reader = fixture["reader"]
            artifact_id = fixture["artifact_id"]
            if tamper_kind == "bytes":
                reader.custody._derivative_path(artifact_id).write_bytes(b"tampered")
            else:
                manifest_path = reader.custody._manifest_path(artifact_id)
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest["collector_id"] = "tampered-collector"
                manifest_path.write_text(
                    json.dumps(manifest, sort_keys=True), encoding="utf-8"
                )

            with pytest.raises((ArtifactIntegrityError, CanonicalEvidenceError)):
                reader.get_finding_projection(fixture["finding_id"])
            with pytest.raises((ArtifactIntegrityError, CanonicalEvidenceError)):
                failed_export.write_bytes(reader.export_finding(fixture["finding_id"]))
            assert not failed_export.exists()
        finally:
            session.close()


def test_missing_truncated_swapped_traversal_and_symlink_fail_closed(
    tmp_path: Path,
) -> None:
    for mutation in ("missing", "truncated", "swapped", "traversal", "symlink"):
        case_root = tmp_path / mutation
        case_root.mkdir(mode=0o700)
        custody_root = case_root / "custody"
        custody_root.mkdir(mode=0o700)
        store = EvidenceCustodyStore(custody_root, "tenant-a")
        first = store.store_artifact(
            b"first-artifact",
            source_observation_id="observation-first",
            collector_id="fixture-collector",
            media_type="text/plain",
        )
        second = store.store_artifact(
            b"second-artifact",
            source_observation_id="observation-second",
            collector_id="fixture-collector",
            media_type="text/plain",
        )
        first_path = store._derivative_path(first.artifact_id)
        second_path = store._derivative_path(second.artifact_id)

        if mutation == "missing":
            first_path.unlink()
        elif mutation == "truncated":
            first_path.write_bytes(b"first")
        elif mutation == "swapped":
            first_path.write_bytes(second_path.read_bytes())
        elif mutation == "symlink":
            first_path.unlink()
            first_path.symlink_to(second_path)
        else:
            with pytest.raises(CustodyError):
                store.get_manifest("../outside")
            with pytest.raises(CustodyError):
                store.store_artifact(
                    b"traversal-attempt",
                    source_observation_id="observation-traversal",
                    collector_id="fixture-collector",
                    artifact_id="artifact:nested/child",
                )
            assert not (case_root / "outside").exists()
            continue

        with pytest.raises(ArtifactIntegrityError):
            store.verify(first.artifact_id)


def test_protected_original_requires_exact_typed_authorization_and_audits(
    tmp_path: Path,
    registered_canaries: None,
) -> None:
    session = create_db(tmp_path / "protected.db")
    custody_root = tmp_path / "custody"
    custody_root.mkdir(mode=0o700)
    try:
        fixture_a = _persist_fixture(session, custody_root, "tenant-a")
        reader_a = fixture_a["reader"]
        artifact_id = fixture_a["artifact_id"]
        binding = session.execute(
            text(
                "SELECT protected_original_authorization_ref "
                "FROM canonical_artifact_refs "
                "WHERE tenant_id=:tenant_id AND id=:artifact_id"
            ),
            {"tenant_id": "tenant-a", "artifact_id": artifact_id},
        ).scalar_one()

        wrong_ref = make_original_authorization(
            tenant_id="tenant-a",
            artifact_id=artifact_id,
            authorization_ref="authorization:wrong-binding",
            operator_id="operator-tenant-a",
            reason="fixture denial",
        )
        with pytest.raises(ArtifactAccessDenied):
            reader_a.read_protected_original(artifact_id, wrong_ref)
        assert session.in_transaction()

        reader_b = CanonicalEvidenceReader(
            session,
            custody_root,
            "tenant-b",
            audit_actor_id="operator-tenant-b",
            expected_original_operator_id="operator-tenant-b",
        )
        wrong_tenant = make_original_authorization(
            tenant_id="tenant-b",
            artifact_id=artifact_id,
            authorization_ref=binding,
            operator_id="operator-tenant-b",
            reason="fixture cross-tenant denial",
        )
        with pytest.raises((ArtifactNotFound, ArtifactScopeError)):
            reader_b.read_protected_original(artifact_id, wrong_tenant)

        exact = make_original_authorization(
            tenant_id="tenant-a",
            artifact_id=artifact_id,
            authorization_ref=binding,
            operator_id="operator-tenant-a",
            reason="fixture exact authorization",
        )
        original = reader_a.read_protected_original(artifact_id, exact)
        assert _RAW_CANARY.encode("utf-8") in original
        assert session.in_transaction()
        session.rollback()
        audit_rows = session.execute(
            text(
                "SELECT access_kind,authorization_ref,metadata_json "
                "FROM canonical_evidence_access_audit "
                "WHERE tenant_id=:tenant_id AND artifact_id=:artifact_id "
                "ORDER BY accessed_at"
            ),
            {"tenant_id": "tenant-a", "artifact_id": artifact_id},
        ).mappings().all()
        assert audit_rows
        rendered_audit = json.dumps([dict(row) for row in audit_rows], sort_keys=True)
        assert _RAW_CANARY not in rendered_audit
        assert _RESPONSE_CANARY not in rendered_audit
        assert "original.bin" not in rendered_audit
        assert any(row["access_kind"] == "protected_original" for row in audit_rows)
    finally:
        session.close()


def test_retention_and_delete_preserve_lineage_or_reject(
    tmp_path: Path,
    registered_canaries: None,
) -> None:
    session = create_db(tmp_path / "destructive.db")
    custody_root = tmp_path / "custody"
    custody_root.mkdir(mode=0o700)
    try:
        fixture = _persist_fixture(session, custody_root, "tenant-a")
        tenant_id = fixture["tenant_id"]
        finding_id = fixture["finding_id"]
        artifact_id = fixture["artifact_id"]
        observation_id = session.execute(
            text(
                "SELECT observation_id FROM canonical_artifact_refs "
                "WHERE tenant_id=:tenant_id AND id=:artifact_id"
            ),
            {"tenant_id": tenant_id, "artifact_id": artifact_id},
        ).scalar_one()
        tables = (
            ("canonical_artifact_refs", "id", artifact_id),
            ("canonical_observations", "id", observation_id),
            ("canonical_findings", "id", finding_id),
        )
        before = {
            table: session.execute(
                text(f"SELECT COUNT(*) FROM {table} WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            ).scalar_one()
            for table, _column, _value in tables
        }
        manifest_digest = fixture["reader"].custody.get_manifest(artifact_id).manifest_digest

        for table, column, value in tables:
            with pytest.raises(IntegrityError):
                session.execute(
                    text(
                        f"DELETE FROM {table} "
                        f"WHERE tenant_id=:tenant_id AND {column}=:value"
                    ),
                    {"tenant_id": tenant_id, "value": value},
                )
                session.commit()
            session.rollback()
            assert {
                name: session.execute(
                    text(f"SELECT COUNT(*) FROM {name} WHERE tenant_id=:tenant_id"),
                    {"tenant_id": tenant_id},
                ).scalar_one()
                for name in before
            } == before
            assert fixture["reader"].custody.get_manifest(artifact_id).manifest_digest == manifest_digest
    finally:
        session.close()


def test_legacy_migration_preserves_available_bytes_and_marks_missing_unknown(
    tmp_path: Path,
) -> None:
    from common.canonical_evidence import CanonicalEvidenceReader
    from common.db import FindingModel
    from common.schema_migrations import (
        CURRENT_SCHEMA_VERSION,
        EVIDENCE_SCHEMA_VERSION,
        MigrationError,
        MigrationManager,
        _canonical_legacy_key,
    )

    request_marker = "TASK102_LEGACY_REQUEST_MARKER"
    response_marker = "TASK102_LEGACY_RESPONSE_MARKER"
    nested_marker = "TASK102_LEGACY_NESTED_MARKER"
    screenshot_bytes = b"TASK102_LEGACY_SCREENSHOT_BYTES"
    unavailable_bytes = b"TASK102_LEGACY_UNAVAILABLE_BYTES"
    register_sensitive_values(
        (request_marker, response_marker, nested_marker)
    )
    screenshot = tmp_path / "legacy-screenshot.bin"
    screenshot.write_bytes(screenshot_bytes)
    screenshot.chmod(0o600)
    outside = tmp_path / "legacy-outside.bin"
    outside.write_bytes(unavailable_bytes)
    outside.chmod(0o600)
    linked = tmp_path / "legacy-linked.bin"
    linked.symlink_to(outside)

    session = create_db(tmp_path / "legacy-migration.db")
    try:
        manager = MigrationManager(session.get_bind())
        assert manager.downgrade(target=CURRENT_SCHEMA_VERSION) == CURRENT_SCHEMA_VERSION
        session.add(
            FindingModel(
                id="legacy-evidence-finding",
                tenant_id="legacy-evidence-tenant",
                title="Legacy evidence",
                severity="High",
                target="fixture.invalid",
                module="legacy-module",
                description="Legacy evidence migration fixture",
                request_raw=f"GET /?q={request_marker} HTTP/1.1",
                response_raw=f"HTTP/1.1 200 OK\n\n{response_marker}",
                screenshot_path=str(screenshot),
                console_capture_path=str(tmp_path / "missing-console.html"),
                pcap_path=str(linked),
                verification=json.dumps(
                    {"nested": {"request_raw": nested_marker}}
                ),
            )
        )
        session.commit()

        assert manager.upgrade() == CURRENT_SCHEMA_VERSION
        mutable = session.execute(
            text(
                "SELECT request_raw,response_raw,screenshot_path,"
                "console_capture_path,pcap_path,verification FROM findings "
                "WHERE id='legacy-evidence-finding'"
            )
        ).mappings().one()
        assert all(
            mutable[field] is None
            for field in (
                "request_raw",
                "response_raw",
                "screenshot_path",
                "console_capture_path",
                "pcap_path",
            )
        )
        assert request_marker not in str(mutable["verification"])
        assert response_marker not in str(mutable["verification"])
        assert nested_marker not in str(mutable["verification"])

        tenant_id = _canonical_legacy_key(
            "legacy-evidence-tenant",
            kind="tenant",
            tenant_id="forge-legacy",
        )
        finding_id = _canonical_legacy_key(
            "legacy-evidence-finding",
            kind="finding",
            tenant_id=tenant_id,
        )
        counts = session.execute(
            text(
                "SELECT "
                "(SELECT COUNT(*) FROM canonical_artifact_refs WHERE tenant_id=:tenant_id) AS refs,"
                "(SELECT COUNT(*) FROM canonical_artifact_manifests WHERE tenant_id=:tenant_id) AS manifests,"
                "(SELECT COUNT(*) FROM canonical_observation_artifacts WHERE tenant_id=:tenant_id) AS links"
            ),
            {"tenant_id": tenant_id},
        ).mappings().one()
        assert counts == {"refs": 5, "manifests": 4, "links": 4}
        unknown = session.execute(
            text(
                "SELECT digest,size,integrity_state,protection_state "
                "FROM canonical_artifact_refs WHERE tenant_id=:tenant_id "
                "AND digest IS NULL"
            ),
            {"tenant_id": tenant_id},
        ).mappings().one()
        assert unknown == {
            "digest": None,
            "size": 0,
            "integrity_state": "unknown",
            "protection_state": "legacy_unknown",
        }

        custody_root = tmp_path / "evidence-custody"
        reader = CanonicalEvidenceReader(
            session,
            custody_root,
            tenant_id,
            audit_actor_id="operator:legacy-review",
            expected_original_operator_id="operator:legacy-review",
        )
        projection = reader.get_finding_projection(finding_id)
        assert projection is not None
        rendered = json.dumps(projection, sort_keys=True)
        assert request_marker not in rendered
        assert response_marker not in rendered
        assert nested_marker not in rendered
        assert unavailable_bytes.decode("ascii") not in rendered
        artifacts = projection["evidence"]["observations"][0]["artifacts"]
        assert len(artifacts) == 4
        assert all(
            artifact["derivative"]
            and artifact["derivative_sha256"].startswith("sha256:")
            for artifact in artifacts
        )
        for artifact in artifacts:
            assert reader.custody.verify(artifact["artifact_id"]).artifact_id == artifact[
                "artifact_id"
            ]

        screenshot_artifact = next(
            artifact
            for artifact in artifacts
            if artifact["capture_kind"] == "screenshot_path"
        )
        binding = session.execute(
            text(
                "SELECT protected_original_authorization_ref "
                "FROM canonical_artifact_refs "
                "WHERE tenant_id=:tenant_id AND id=:artifact_id"
            ),
            {"tenant_id": tenant_id, "artifact_id": screenshot_artifact["artifact_id"]},
        ).scalar_one()
        session.rollback()
        authorization = make_original_authorization(
            tenant_id=tenant_id,
            artifact_id=screenshot_artifact["artifact_id"],
            authorization_ref=binding,
            operator_id="operator:legacy-review",
            reason="verify available migrated bytes",
        )
        assert (
            reader.read_protected_original(
                screenshot_artifact["artifact_id"], authorization
            )
            == screenshot_bytes
        )

        assert manager.upgrade() == CURRENT_SCHEMA_VERSION
        repeated = session.execute(
            text(
                "SELECT "
                "(SELECT COUNT(*) FROM canonical_artifact_refs WHERE tenant_id=:tenant_id),"
                "(SELECT COUNT(*) FROM canonical_artifact_manifests WHERE tenant_id=:tenant_id),"
                "(SELECT COUNT(*) FROM canonical_observation_artifacts WHERE tenant_id=:tenant_id)"
            ),
            {"tenant_id": tenant_id},
        ).one()
        assert tuple(repeated) == (5, 4, 4)
        session.rollback()
        with pytest.raises(
            MigrationError,
            match="downgrade would break retained canonical lineage",
        ):
            manager.downgrade(target=CURRENT_SCHEMA_VERSION)
        assert session.execute(
            text(
                "SELECT state FROM canonical_migration_journal "
                "WHERE version=:version"
            ),
            {"version": EVIDENCE_SCHEMA_VERSION},
        ).scalar_one() == "applied"
    finally:
        clear_sensitive_values()
        session.close()


def test_each_transaction_failure_point_leaves_no_file_or_row(
    tmp_path: Path,
    registered_canaries: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import common.canonical_evidence as canonical_module
    import common.evidence_custody as custody_module

    failure_modes = (
        "filesystem_write",
        "manifest_write",
        "reference_build",
        "database_manifest",
        "database_after_first_manifest",
        "commit",
    )
    for failure_mode in failure_modes:
        case_root = tmp_path / failure_mode
        case_root.mkdir(mode=0o700)
        session = create_db(case_root / "canonical.db")
        custody_root = case_root / "custody"
        custody_root.mkdir(mode=0o700)
        service = CanonicalEvidenceService(
            session,
            custody_root,
            _context("tenant-a", run_suffix=failure_mode),
        )
        calls = 0
        try:
            with monkeypatch.context() as scoped:
                if failure_mode in {"filesystem_write", "manifest_write"}:
                    real_atomic_write = custody_module.atomic_write_bytes

                    def fail_atomic_write(*args: Any, **kwargs: Any) -> Any:
                        nonlocal calls
                        calls += 1
                        if failure_mode == "filesystem_write" or calls == 3:
                            raise OSError("injected custody write failure")
                        return real_atomic_write(*args, **kwargs)

                    scoped.setattr(
                        custody_module, "atomic_write_bytes", fail_atomic_write
                    )
                elif failure_mode == "reference_build":
                    def fail_artifact_reference(*args: Any, **kwargs: Any) -> Any:
                        nonlocal calls
                        calls += 1
                        raise RuntimeError("injected artifact-reference failure")

                    scoped.setattr(
                        canonical_module,
                        "ArtifactReference",
                        fail_artifact_reference,
                    )
                elif failure_mode in {
                    "database_manifest",
                    "database_after_first_manifest",
                }:
                    real_persist_manifest = service.store.persist_artifact_manifest

                    def fail_persist_manifest(*args: Any, **kwargs: Any) -> Any:
                        nonlocal calls
                        calls += 1
                        if (
                            failure_mode == "database_manifest"
                            or calls == 2
                        ):
                            raise RuntimeError("injected manifest database failure")
                        return real_persist_manifest(*args, **kwargs)

                    scoped.setattr(
                        service.store,
                        "persist_artifact_manifest",
                        fail_persist_manifest,
                    )
                else:
                    def fail_commit() -> None:
                        nonlocal calls
                        calls += 1
                        raise RuntimeError("injected commit failure")

                    scoped.setattr(session, "commit", fail_commit)

                expected = (
                    ArtifactTransactionError
                    if failure_mode in {"filesystem_write", "manifest_write"}
                    else RuntimeError
                )
                with pytest.raises(expected):
                    service.persist_finding(
                        _make_finding(
                            tenant_id="tenant-a",
                            route="/transaction",
                            parameter="fixture",
                            identity_ref="principal:transaction",
                            check_id="fixture.transaction",
                        )
                    )

            session.rollback()
            expected_calls = {
                "filesystem_write": 1,
                "manifest_write": 3,
                "reference_build": 1,
                "database_manifest": 1,
                "database_after_first_manifest": 2,
                "commit": 1,
            }
            assert calls == expected_calls[failure_mode]
            assert _all_lineage_counts(session) == {
                table: 0 for table in _CANONICAL_LINEAGE_TABLES
            }
            assert _custody_files(custody_root) == []
        finally:
            session.close()
