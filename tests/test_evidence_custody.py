"""Task 102 immutable observation and evidence-custody fixtures."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from common.canonical import (
    ArtifactReference,
    Asset,
    AssetKind,
    CanonicalContractError,
    CanonicalLineageError,
    CanonicalStore,
    Client,
    Engagement,
    Finding,
    FindingSeverity,
    Job,
    ModuleVersion,
    Observation,
    Tenant,
)
from common.db import create_db
from common.evidence_custody import (
    ArtifactAccessDenied,
    ArtifactIntegrityError,
    ArtifactTransactionError,
    ArtifactManifest,
    CustodyError,
    EvidenceCustodyStore,
    make_original_authorization,
)
from common.redaction import clear_sensitive_values, register_sensitive_values


def _lineage_graph(
    session,
    *,
    tenant: Tenant,
    route: str = "/health",
    client: Client | None = None,
    engagement: Engagement | None = None,
    module: ModuleVersion | None = None,
    asset: Asset | None = None,
):
    """Create one small canonical graph without running any target activity."""
    client = client or Client(tenant_id=tenant.id, name="fixture-client")
    engagement = engagement or Engagement(tenant_id=tenant.id, name="fixture-engagement")
    module = module or ModuleVersion(tenant_id=tenant.id, module_id="fixture.check", version="1")
    asset = asset or Asset(tenant_id=tenant.id, kind=AssetKind.HOST, identity_key="fixture.example", display_name="fixture")
    job = Job(tenant_id=tenant.id, engagement_id=engagement.id, job_kind="fixture")
    observation = Observation(
        tenant_id=tenant.id,
        engagement_id=engagement.id,
        job_id=job.id,
        module_version_id=module.id,
        asset_id=asset.id,
        check_id="fixture.check",
        route=route,
        parameter="q",
        location="query",
        identity_ref="identity-a",
    )
    artifact = ArtifactReference(
        tenant_id=tenant.id,
        observation_id=observation.id,
        reference="artifact:fixture-proof-" + observation.id,
        digest="sha256:" + "a" * 64,
        media_type="text/plain",
        size=8,
        source_target="fixture.example",
        source_asset_id=asset.id,
        collector_id="fixture-collector",
        redaction_version="forge-redaction-v1",
        protection_state="not_retained",
    )
    finding = Finding(
        tenant_id=tenant.id,
        observation_id=observation.id,
        artifact_id=artifact.id,
        title="Fixture finding",
        severity=FindingSeverity.MEDIUM,
        description="A deterministic fixture observation.",
        finding_key="fixture.check",
    )
    return {
        "tenant": tenant,
        "client": client,
        "engagement": engagement,
        "module": module,
        "asset": asset,
        "job": job,
        "observation": observation,
        "artifact": artifact,
        "finding": finding,
    }


def _persist_graph(store: CanonicalStore, graph: dict[str, object]) -> dict[str, object]:
    return store.create_lineage(
        tenant=graph["tenant"],
        client=graph["client"],
        engagement=graph["engagement"],
        job=graph["job"],
        module_version=graph["module"],
        asset=graph["asset"],
        observation=graph["observation"],
        artifact=graph["artifact"],
        finding=graph["finding"],
    )


def _bind_artifact_to_manifest(
    artifact: ArtifactReference,
    manifest: ArtifactManifest,
) -> ArtifactReference:
    return replace(
        artifact,
        digest=manifest.sha256,
        size=manifest.byte_size,
        media_type=manifest.media_type,
        collected_at=datetime.fromisoformat(
            manifest.collected_at.replace("Z", "+00:00")
        ),
        redaction_state=manifest.redaction_state,
        encryption_state=manifest.encryption_state,
        collector_id=manifest.collector_id,
        source_target=manifest.source_target or "unknown",
        source_asset_id=manifest.source_asset_id,
        redaction_version=manifest.redaction_version,
        protection_state=manifest.protection_state,
        signer_state=manifest.signer_state,
        integrity_state=manifest.integrity_state,
        retention_class=manifest.retention_class,
        retention_expires_at=(
            datetime.fromisoformat(
                manifest.retention_expires_at.replace("Z", "+00:00")
            )
            if manifest.retention_expires_at is not None
            else None
        ),
        protected_original_authorization_ref=(
            manifest.protected_original_authorization_ref
        ),
        derivative_reference=manifest.derivative_artifact_id,
    )


def _custodied_lineage_fixture(tmp_path: Path) -> dict[str, object]:
    """Stage one primary and one supporting artifact for lineage tests."""
    session = create_db(tmp_path / "canonical.db")
    canonical = CanonicalStore(session)
    tenant = Tenant(id="tenant-a", name="Task 102 tenant")
    graph = _lineage_graph(session, tenant=tenant)
    custody = EvidenceCustodyStore(tmp_path / "custody", tenant.id)

    primary = graph["artifact"]
    primary_manifest = custody.store_artifact(
        b"primary-custodied-proof",
        source_observation_id=graph["observation"].id,
        collector_id="fixture-primary",
        media_type="text/plain",
        source_target=primary.source_target,
        source_asset_id=primary.source_asset_id,
        artifact_id=primary.id,
    )
    primary = _bind_artifact_to_manifest(primary, primary_manifest)

    supporting_id = "artifact:supporting-" + graph["observation"].id
    supporting_manifest = custody.store_artifact(
        b"supporting-custodied-proof",
        source_observation_id=graph["observation"].id,
        collector_id="fixture-supporting",
        media_type="text/plain",
        source_target=primary.source_target,
        source_asset_id=primary.source_asset_id,
        artifact_id=supporting_id,
    )
    supporting = _bind_artifact_to_manifest(ArtifactReference(
        tenant_id=tenant.id,
        observation_id=graph["observation"].id,
        reference="artifact:supporting-proof-" + graph["observation"].id,
        digest=supporting_manifest.sha256,
        media_type=supporting_manifest.media_type,
        size=supporting_manifest.byte_size,
        source_target=supporting_manifest.source_target or "",
        source_asset_id=supporting_manifest.source_asset_id,
        id=supporting_id,
    ), supporting_manifest)
    graph["artifact"] = primary
    return {
        "session": session,
        "canonical": canonical,
        "custody": custody,
        "tenant": tenant,
        "graph": graph,
        "primary": primary,
        "supporting": supporting,
        "primary_manifest": primary_manifest,
        "supporting_manifest": supporting_manifest,
    }


def _assert_no_custodied_lineage_rows(session, tenant_id: str) -> None:
    tenant_columns = {
        "canonical_tenants": "id",
        "canonical_clients": "tenant_id",
        "canonical_engagements": "tenant_id",
        "canonical_jobs": "tenant_id",
        "canonical_module_versions": "tenant_id",
        "canonical_assets": "tenant_id",
        "canonical_observations": "tenant_id",
        "canonical_artifact_refs": "tenant_id",
        "canonical_findings": "tenant_id",
        "canonical_artifact_manifests": "tenant_id",
        "canonical_observation_artifacts": "tenant_id",
        "canonical_finding_observations": "tenant_id",
    }
    for table, tenant_column in tenant_columns.items():
        assert session.execute(
            text(f"SELECT COUNT(*) FROM {table} WHERE {tenant_column}=:tenant_id"),
            {"tenant_id": tenant_id},
        ).scalar_one() == 0


def test_redacted_default_and_exact_protected_original_access(tmp_path: Path) -> None:
    register_sensitive_values(["TASK102_CANARY_SECRET"])
    try:
        events: list[dict[str, object]] = []
        store = EvidenceCustodyStore(tmp_path, "tenant-a", audit_sink=events.append)
        manifest = store.store_artifact(
            "Authorization: Bearer TASK102_CANARY_SECRET\n",
            source_observation_id="observation-1",
            collector_id="collector-1",
            media_type="text/plain",
            retain_original=True,
            protected_original_authorization_ref="authorization:task102-original",
        )
        redacted = store.read(manifest.artifact_id)
        assert b"TASK102_CANARY_SECRET" not in redacted
        assert b"<redacted>" in redacted
        with pytest.raises(ArtifactAccessDenied):
            store.read(manifest.artifact_id, include_original=True)
        authorization = make_original_authorization(
            tenant_id="tenant-a",
            artifact_id=manifest.artifact_id,
            authorization_ref="authorization:task102-original",
            operator_id="operator-1",
            reason="Task 102 fixture access",
        )
        assert store.read(
            manifest.artifact_id,
            include_original=True,
            authorization=authorization,
        ) == b"Authorization: Bearer TASK102_CANARY_SECRET\n"
        assert [event["event"] for event in events] == [
            "artifact.read.redacted",
            "artifact.read.original.denied",
            "artifact.read.original.authorized",
        ]
    finally:
        clear_sensitive_values()


def test_binary_derivative_withholds_content_and_primary_digest_binds_stored_bytes(
    tmp_path: Path,
) -> None:
    store = EvidenceCustodyStore(tmp_path, "tenant-a")
    original = b"\x00TASK102_BINARY_CANARY\xff"
    manifest = store.store_artifact(
        original,
        source_observation_id="observation-1",
        collector_id="collector-1",
        media_type="application/octet-stream",
        redaction_required=False,
    )

    derivative = store.read(manifest.artifact_id)
    assert original not in derivative
    assert b"TASK102_BINARY_CANARY" not in derivative
    assert json.loads(derivative) == {
        "byte_size": len(original),
        "media_type": "application/octet-stream",
        "sha256": "sha256:" + hashlib.sha256(original).hexdigest(),
        "state": "binary_withheld",
    }
    assert manifest.sha256 == manifest.derivative_sha256
    assert manifest.byte_size == manifest.derivative_size


def test_protected_original_requires_typed_authorization_and_active_audit(
    tmp_path: Path,
) -> None:
    store = EvidenceCustodyStore(tmp_path, "tenant-a")
    manifest = store.store_artifact(
        b"protected",
        source_observation_id="observation-1",
        collector_id="collector-1",
        retain_original=True,
        protected_original_authorization_ref="authorization:task102-original",
    )
    typed = make_original_authorization(
        tenant_id="tenant-a",
        artifact_id=manifest.artifact_id,
        authorization_ref="authorization:task102-original",
        operator_id="operator-1",
        reason="Task 102 fixture access",
    )
    with pytest.raises(ArtifactAccessDenied, match="audit sink"):
        store.read(
            manifest.artifact_id,
            include_original=True,
            authorization=typed,
        )

    audited = EvidenceCustodyStore(tmp_path, "tenant-a", audit_sink=lambda _event: None)
    with pytest.raises(ArtifactAccessDenied, match="exact protected-original"):
        audited.read(
            manifest.artifact_id,
            include_original=True,
            authorization="authorization:task102-original",  # type: ignore[arg-type]
        )


def test_text_redaction_is_case_insensitive_and_cannot_be_disabled(tmp_path: Path) -> None:
    register_sensitive_values(["TASK102_UPPER_CANARY"])
    try:
        # An identity custom hook and the legacy opt-out flag must not bypass
        # the emergency redaction boundary for textual media.
        store = EvidenceCustodyStore(tmp_path, "tenant-a", redactor=lambda value: value)
        manifest = store.store_artifact(
            "Authorization: Bearer TASK102_UPPER_CANARY\n",
            source_observation_id="observation-1",
            collector_id="collector-1",
            media_type="TEXT/PLAIN; charset=utf-8",
            redaction_required=False,
        )
        assert b"TASK102_UPPER_CANARY" not in store.read(manifest.artifact_id)
        assert manifest.redaction_state == "redacted"
    finally:
        clear_sensitive_values()


def test_original_authorization_is_typed_and_source_target_is_hashed_after_redaction(
    tmp_path: Path,
) -> None:
    register_sensitive_values(["TASK102_SOURCE_CANARY"])
    try:
        store = EvidenceCustodyStore(tmp_path, "tenant-a")
        with pytest.raises(CustodyError):
            store.store_artifact(
                b"fixture",
                source_observation_id="observation-1",
                collector_id="collector-1",
                retain_original=True,
                protected_original_authorization_ref="admin",
            )
        manifest = store.store_artifact(
            b"fixture",
            source_observation_id="observation-1",
            collector_id="collector-1",
            source_target="https://TASK102_SOURCE_CANARY.example.test/path",
            retain_original=True,
            protected_original_authorization_ref="authorization:review-1",
        )
        assert "TASK102_SOURCE_CANARY" not in (manifest.source_target or "")
        assert manifest.source_target is not None
        assert manifest.manifest_digest == store.verify(manifest.artifact_id).manifest_digest
        with pytest.raises(CustodyError):
            make_original_authorization(
                tenant_id="tenant-a",
                artifact_id=manifest.artifact_id,
                authorization_ref="admin",
                operator_id="operator-1",
                reason="fixture",
            )
    finally:
        clear_sensitive_values()


def test_manifest_paths_are_server_bound(tmp_path: Path) -> None:
    store = EvidenceCustodyStore(tmp_path, "tenant-a")
    manifest = store.store_artifact(
        b"fixture",
        source_observation_id="observation-1",
        collector_id="collector-1",
        media_type="application/octet-stream",
    )
    with pytest.raises(CustodyError):
        replace(manifest, derivative_relative_path="../outside.bin")


def test_tenant_namespace_and_path_traversal_are_isolated(tmp_path: Path) -> None:
    store_a = EvidenceCustodyStore(tmp_path, "tenant-a")
    store_b = EvidenceCustodyStore(tmp_path, "tenant-b")
    manifest = store_a.store_artifact(
        b"fixture",
        source_observation_id="observation-a",
        collector_id="collector-a",
        media_type="application/octet-stream",
    )
    with pytest.raises((CustodyError, ArtifactIntegrityError)):
        store_b.get_manifest(manifest.artifact_id)
    with pytest.raises(CustodyError):
        store_a.get_manifest("../outside")
    with pytest.raises(CustodyError):
        store_a.store_artifact(
            b"fixture",
            source_observation_id="observation-a",
            collector_id="collector-a",
            artifact_id="artifact:nested/child",
        )
    assert manifest.tenant_id == "tenant-a"
    assert len(list((tmp_path / "tenants").iterdir())) == 2


@pytest.mark.parametrize("mutation", ["missing", "truncated", "swapped", "symlink"])
def test_bytes_tampering_fails_closed(tmp_path: Path, mutation: str) -> None:
    store = EvidenceCustodyStore(tmp_path, "tenant-a")
    first = store.store_artifact(
        b"first-artifact",
        source_observation_id="observation-1",
        collector_id="collector-1",
        media_type="text/plain",
    )
    second = store.store_artifact(
        b"second-artifact",
        source_observation_id="observation-2",
        collector_id="collector-1",
        media_type="text/plain",
    )
    path = store._derivative_path(first.artifact_id)
    if mutation == "missing":
        path.unlink()
    elif mutation == "truncated":
        path.write_bytes(b"first")
    elif mutation == "swapped":
        path.write_bytes(store._derivative_path(second.artifact_id).read_bytes())
    else:
        path.unlink()
        path.symlink_to(store._derivative_path(second.artifact_id))
    with pytest.raises(ArtifactIntegrityError):
        store.verify(first.artifact_id)


def test_manifest_tampering_is_detected(tmp_path: Path) -> None:
    store = EvidenceCustodyStore(tmp_path, "tenant-a")
    manifest = store.store_artifact(
        b"manifest-fixture",
        source_observation_id="observation-1",
        collector_id="collector-1",
        media_type="text/plain",
    )
    path = store._manifest_path(manifest.artifact_id)
    payload = json.loads(path.read_text())
    payload["collector_id"] = "tampered-collector"
    path.write_text(json.dumps(payload, sort_keys=True))
    with pytest.raises(ArtifactIntegrityError):
        store.get_manifest(manifest.artifact_id)


def test_failed_write_leaves_no_orphan_namespace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = EvidenceCustodyStore(tmp_path, "tenant-a")

    def fail(*_args: object, **_kwargs: object) -> object:
        raise OSError("injected write failure")

    monkeypatch.setattr("common.evidence_custody.atomic_write_bytes", fail)
    with pytest.raises(ArtifactTransactionError):
        store.store_artifact(
            b"transaction-fixture",
            source_observation_id="observation-1",
            collector_id="collector-1",
        )
    tenant_root = store._tenant_root()
    artifacts = tenant_root / "artifacts"
    assert not artifacts.exists() or not any(artifacts.iterdir())


def test_canonical_transaction_compensation_removes_new_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    custody = EvidenceCustodyStore(tmp_path / "custody", "tenant-a")
    manifest = custody.store_artifact(
        b"transaction-fixture",
        source_observation_id="observation-1",
        collector_id="collector-1",
        artifact_id="artifact:transaction-fixture",
    )
    session = create_db(tmp_path / "canonical.db")
    try:
        canonical = CanonicalStore(session)

        def fail(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("injected database failure")

        monkeypatch.setattr(canonical, "persist_artifact_manifest", fail)
        with pytest.raises(RuntimeError):
            canonical.persist_custodied_manifest(manifest, custody_store=custody)
        assert not custody._artifact_dir(manifest.artifact_id).exists()
    finally:
        session.close()


def test_persist_custodied_lineage_commits_complete_graph_and_reopens(
    tmp_path: Path,
) -> None:
    fixture = _custodied_lineage_fixture(tmp_path)
    session = fixture["session"]
    canonical = fixture["canonical"]
    custody = fixture["custody"]
    tenant = fixture["tenant"]
    graph = fixture["graph"]
    primary = fixture["primary"]
    supporting = fixture["supporting"]
    primary_manifest = fixture["primary_manifest"]
    supporting_manifest = fixture["supporting_manifest"]
    try:
        result = canonical.persist_custodied_lineage(
            custody_store=custody,
            manifests=[primary_manifest, supporting_manifest],
            tenant=tenant,
            client=graph["client"],
            engagement=graph["engagement"],
            job=graph["job"],
            module_version=graph["module"],
            asset=graph["asset"],
            observation=graph["observation"],
            primary_artifact=primary,
            supporting_artifacts=[supporting],
            finding=graph["finding"],
        )
        assert [item.id for item in result["artifacts"]] == [primary.id, supporting.id]
        assert [item.artifact_id for item in result["manifests"]] == [
            primary_manifest.artifact_id,
            supporting_manifest.artifact_id,
        ]

        refs = session.execute(
            text(
                "SELECT tenant_id,id,observation_id,digest,size,manifest_digest "
                "FROM canonical_artifact_refs WHERE tenant_id=:tenant_id "
                "ORDER BY id"
            ),
            {"tenant_id": tenant.id},
        ).mappings().all()
        assert refs == [
            {
                "tenant_id": tenant.id,
                "id": item.id,
                "observation_id": graph["observation"].id,
                "digest": item.digest,
                "size": item.size,
                "manifest_digest": manifest.manifest_digest,
            }
            for item, manifest in sorted(
                ((primary, primary_manifest), (supporting, supporting_manifest)),
                key=lambda pair: pair[0].id,
            )
        ]

        manifests = session.execute(
            text(
                "SELECT tenant_id,artifact_id,observation_id,sha256,byte_size,manifest_digest "
                "FROM canonical_artifact_manifests WHERE tenant_id=:tenant_id "
                "ORDER BY artifact_id"
            ),
            {"tenant_id": tenant.id},
        ).mappings().all()
        assert manifests == [
            {
                "tenant_id": tenant.id,
                "artifact_id": manifest.artifact_id,
                "observation_id": graph["observation"].id,
                "sha256": manifest.sha256,
                "byte_size": manifest.byte_size,
                "manifest_digest": manifest.manifest_digest,
            }
            for manifest in sorted(
                (primary_manifest, supporting_manifest), key=lambda item: item.artifact_id
            )
        ]

        links = session.execute(
            text(
                "SELECT tenant_id,observation_id,artifact_id,role,sequence "
                "FROM canonical_observation_artifacts WHERE tenant_id=:tenant_id "
                "ORDER BY sequence"
            ),
            {"tenant_id": tenant.id},
        ).mappings().all()
        assert links == [
            {
                "tenant_id": tenant.id,
                "observation_id": graph["observation"].id,
                "artifact_id": primary.id,
                "role": "primary",
                "sequence": 0,
            },
            {
                "tenant_id": tenant.id,
                "observation_id": graph["observation"].id,
                "artifact_id": supporting.id,
                "role": "supporting",
                "sequence": 1,
            },
        ]
        finding_links = session.execute(
            text(
                "SELECT tenant_id,finding_id,observation_id,artifact_id "
                "FROM canonical_finding_observations WHERE tenant_id=:tenant_id"
            ),
            {"tenant_id": tenant.id},
        ).mappings().all()
        assert finding_links == [
            {
                "tenant_id": tenant.id,
                "finding_id": graph["finding"].id,
                "observation_id": graph["observation"].id,
                "artifact_id": primary.id,
            }
        ]
        assert custody._artifact_dir(primary.id).is_dir()
        assert custody._artifact_dir(supporting.id).is_dir()
    finally:
        session.close()

    reopened = create_db(tmp_path / "canonical.db")
    try:
        assert reopened.execute(
            text(
                "SELECT COUNT(*) FROM canonical_artifact_refs "
                "WHERE tenant_id=:tenant_id"
            ),
            {"tenant_id": tenant.id},
        ).scalar_one() == 2
        reopened_store = CanonicalStore(reopened)
        assert reopened_store.get_artifact_manifest(primary.id, tenant.id) == primary_manifest
        assert reopened_store.get_artifact_manifest(supporting.id, tenant.id) == supporting_manifest
        assert custody.verify(primary.id).manifest_digest == primary_manifest.manifest_digest
        assert custody.verify(supporting.id).manifest_digest == supporting_manifest.manifest_digest
    finally:
        reopened.close()


def test_persist_custodied_lineage_rejects_caller_transaction_and_compensates_both(
    tmp_path: Path,
) -> None:
    fixture = _custodied_lineage_fixture(tmp_path)
    session = fixture["session"]
    canonical = fixture["canonical"]
    custody = fixture["custody"]
    tenant = fixture["tenant"]
    graph = fixture["graph"]
    primary = fixture["primary"]
    supporting = fixture["supporting"]
    primary_manifest = fixture["primary_manifest"]
    supporting_manifest = fixture["supporting_manifest"]
    try:
        session.execute(text("SELECT 1"))
        assert session.in_transaction()
        with pytest.raises(CanonicalContractError, match="idle database session"):
            canonical.persist_custodied_lineage(
                custody_store=custody,
                manifests=[primary_manifest, supporting_manifest],
                tenant=tenant,
                client=graph["client"],
                engagement=graph["engagement"],
                job=graph["job"],
                module_version=graph["module"],
                asset=graph["asset"],
                observation=graph["observation"],
                primary_artifact=primary,
                supporting_artifacts=[supporting],
                finding=graph["finding"],
            )
        assert not session.in_transaction()
        assert not custody._artifact_dir(primary.id).exists()
        assert not custody._artifact_dir(supporting.id).exists()
        _assert_no_custodied_lineage_rows(session, tenant.id)
    finally:
        session.close()


def test_persist_custodied_lineage_rejects_custody_attribute_mismatch(
    tmp_path: Path,
) -> None:
    fixture = _custodied_lineage_fixture(tmp_path)
    session = fixture["session"]
    canonical = fixture["canonical"]
    custody = fixture["custody"]
    tenant = fixture["tenant"]
    graph = fixture["graph"]
    primary = fixture["primary"]
    supporting = fixture["supporting"]
    primary_manifest = fixture["primary_manifest"]
    supporting_manifest = fixture["supporting_manifest"]
    mismatched_primary = replace(
        primary,
        derivative_reference="artifact:unrelated-derivative",
    )
    try:
        with pytest.raises(
            CanonicalLineageError,
            match="custody manifest does not match canonical artifact lineage",
        ):
            canonical.persist_custodied_lineage(
                custody_store=custody,
                manifests=[primary_manifest, supporting_manifest],
                tenant=tenant,
                client=graph["client"],
                engagement=graph["engagement"],
                job=graph["job"],
                module_version=graph["module"],
                asset=graph["asset"],
                observation=graph["observation"],
                primary_artifact=mismatched_primary,
                supporting_artifacts=[supporting],
                finding=graph["finding"],
            )
        assert not custody._artifact_dir(primary.id).exists()
        assert not custody._artifact_dir(supporting.id).exists()
        _assert_no_custodied_lineage_rows(session, tenant.id)
    finally:
        session.close()


def test_persist_custodied_lineage_database_failure_after_manifest_compensates_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _custodied_lineage_fixture(tmp_path)
    session = fixture["session"]
    canonical = fixture["canonical"]
    custody = fixture["custody"]
    tenant = fixture["tenant"]
    graph = fixture["graph"]
    primary = fixture["primary"]
    supporting = fixture["supporting"]
    primary_manifest = fixture["primary_manifest"]
    supporting_manifest = fixture["supporting_manifest"]
    calls: list[str] = []
    completed: list[str] = []
    real_persist = canonical.persist_artifact_manifest

    def fail_on_second_manifest(*args: object, **kwargs: object) -> object:
        manifest = args[0] if args else kwargs["manifest"]
        calls.append(manifest.artifact_id)
        if len(calls) == 2:
            raise RuntimeError("injected failure after first manifest")
        result = real_persist(*args, **kwargs)
        completed.append(manifest.artifact_id)
        return result

    monkeypatch.setattr(canonical, "persist_artifact_manifest", fail_on_second_manifest)
    try:
        with pytest.raises(RuntimeError, match="after first manifest"):
            canonical.persist_custodied_lineage(
                custody_store=custody,
                manifests=[primary_manifest, supporting_manifest],
                tenant=tenant,
                client=graph["client"],
                engagement=graph["engagement"],
                job=graph["job"],
                module_version=graph["module"],
                asset=graph["asset"],
                observation=graph["observation"],
                primary_artifact=primary,
                supporting_artifacts=[supporting],
                finding=graph["finding"],
            )
        assert calls == [primary.id, supporting.id]
        assert completed == [primary.id]
        assert not session.in_transaction()
        assert not custody._artifact_dir(primary.id).exists()
        assert not custody._artifact_dir(supporting.id).exists()
        _assert_no_custodied_lineage_rows(session, tenant.id)
    finally:
        session.close()


def test_delete_and_duplicate_identity_fail_closed(tmp_path: Path) -> None:
    store = EvidenceCustodyStore(tmp_path, "tenant-a")
    manifest = store.store_artifact(
        b"immutable",
        source_observation_id="observation-1",
        collector_id="collector-1",
        artifact_id="artifact:fixed-id",
    )
    with pytest.raises(CustodyError):
        store.store_artifact(
            b"replacement",
            source_observation_id="observation-2",
            collector_id="collector-1",
            artifact_id=manifest.artifact_id,
        )
    with pytest.raises(CustodyError):
        store.delete(manifest.artifact_id)


def test_dedup_preserves_each_run_and_identity_dimension(tmp_path: Path) -> None:
    session = create_db(tmp_path / "canonical.db")
    try:
        store = CanonicalStore(session)
        tenant = Tenant(name="tenant-a")
        first = _lineage_graph(session, tenant=tenant, route="/health")
        _persist_graph(store, first)
        first_observation = dict(
            session.execute(
                text(
                    "SELECT job_id,module_version_id,asset_id,observed_at,"
                    "route,parameter,location,identity_ref,metadata_json "
                    "FROM canonical_observations "
                    "WHERE tenant_id=:tenant_id AND id=:observation_id"
                ),
                {
                    "tenant_id": tenant.id,
                    "observation_id": first["observation"].id,
                },
            ).mappings().one()
        )
        first_artifact = dict(
            session.execute(
                text(
                    "SELECT observation_id,reference,digest,size,"
                    "integrity_state,metadata_json FROM canonical_artifact_refs "
                    "WHERE tenant_id=:tenant_id AND id=:artifact_id"
                ),
                {
                    "tenant_id": tenant.id,
                    "artifact_id": first["artifact"].id,
                },
            ).mappings().one()
        )
        session.rollback()

        second = _lineage_graph(
            session,
            tenant=tenant,
            route="/health",
            client=first["client"],
            engagement=first["engagement"],
            module=first["module"],
            asset=first["asset"],
        )
        _persist_graph(store, second)

        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "UPDATE canonical_observations SET route='/mutated' "
                    "WHERE tenant_id=:tenant_id AND id=:observation_id"
                ),
                {
                    "tenant_id": tenant.id,
                    "observation_id": first["observation"].id,
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
                    "digest": "sha256:" + "b" * 64,
                    "tenant_id": tenant.id,
                    "artifact_id": first["artifact"].id,
                },
            )
            session.commit()
        session.rollback()
        assert dict(
            session.execute(
                text(
                    "SELECT job_id,module_version_id,asset_id,observed_at,"
                    "route,parameter,location,identity_ref,metadata_json "
                    "FROM canonical_observations "
                    "WHERE tenant_id=:tenant_id AND id=:observation_id"
                ),
                {
                    "tenant_id": tenant.id,
                    "observation_id": first["observation"].id,
                },
            ).mappings().one()
        ) == first_observation
        assert dict(
            session.execute(
                text(
                    "SELECT observation_id,reference,digest,size,"
                    "integrity_state,metadata_json FROM canonical_artifact_refs "
                    "WHERE tenant_id=:tenant_id AND id=:artifact_id"
                ),
                {
                    "tenant_id": tenant.id,
                    "artifact_id": first["artifact"].id,
                },
            ).mappings().one()
        ) == first_artifact

        assert session.execute(text("SELECT COUNT(*) FROM canonical_findings WHERE tenant_id=:t"), {"t": tenant.id}).scalar_one() == 1
        assert session.execute(text("SELECT COUNT(*) FROM canonical_observations WHERE tenant_id=:t"), {"t": tenant.id}).scalar_one() == 2
        assert session.execute(text("SELECT COUNT(*) FROM canonical_finding_observations WHERE tenant_id=:t"), {"t": tenant.id}).scalar_one() == 2
        assert session.execute(text("SELECT COUNT(*) FROM canonical_observation_artifacts WHERE tenant_id=:t"), {"t": tenant.id}).scalar_one() == 2

        distinct_route = _lineage_graph(
            session,
            tenant=tenant,
            route="/admin",
            client=first["client"],
            engagement=first["engagement"],
            module=first["module"],
            asset=first["asset"],
        )
        _persist_graph(store, distinct_route)
        assert session.execute(text("SELECT COUNT(*) FROM canonical_findings WHERE tenant_id=:t"), {"t": tenant.id}).scalar_one() == 2
    finally:
        session.close()


def test_legacy_unknown_integrity_and_manifest_persistence(tmp_path: Path) -> None:
    session = create_db(tmp_path / "canonical.db")
    try:
        store = CanonicalStore(session)
        tenant = Tenant(name="tenant-a")
        graph = _lineage_graph(session, tenant=tenant)
        graph["artifact"] = ArtifactReference(
            id=graph["artifact"].id,
            tenant_id=tenant.id,
            observation_id=graph["observation"].id,
            reference="artifact:legacy-unknown",
            digest=None,
            media_type="application/octet-stream",
            size=0,
            integrity_state="unknown",
            redaction_state="unknown",
            protection_state="legacy_unknown",
        )
        graph["finding"] = Finding(
            id=graph["finding"].id,
            tenant_id=tenant.id,
            observation_id=graph["observation"].id,
            artifact_id=graph["artifact"].id,
            title="Legacy evidence",
            severity=FindingSeverity.INFORMATIONAL,
            description="Unknown legacy bytes.",
        )
        _persist_graph(store, graph)
        row = session.execute(text("SELECT digest, integrity_state, protection_state FROM canonical_artifact_refs WHERE id=:id"), {"id": graph["artifact"].id}).mappings().one()
        assert row["digest"] is None
        assert row["integrity_state"] == "unknown"
        assert row["protection_state"] == "legacy_unknown"
    finally:
        session.close()


def test_artifact_source_asset_is_tenant_bound_at_database_boundary(tmp_path: Path) -> None:
    session = create_db(tmp_path / "source-asset-lineage.db")
    try:
        store = CanonicalStore(session)
        tenant_a = Tenant(name="tenant-a")
        tenant_b = Tenant(name="tenant-b")
        graph_a = _lineage_graph(session, tenant=tenant_a)
        graph_b = _lineage_graph(session, tenant=tenant_b, route="/other")
        _persist_graph(store, graph_a)
        _persist_graph(store, graph_b)
        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "INSERT INTO canonical_artifact_refs "
                    "(id,tenant_id,observation_id,schema_version,reference,digest,media_type,size,"
                    "redaction_state,encryption_state,collected_at,created_at,source_asset_id) "
                    "VALUES (:id,:tenant_id,:observation_id,:schema_version,:reference,:digest,:media_type,:size,"
                    ":redaction_state,:encryption_state,:collected_at,:created_at,:asset_id)"
                ),
                {
                    "id": "artifact:cross-tenant-source",
                    "observation_id": graph_a["observation"].id,
                    "schema_version": "forge-canonical-v1",
                    "reference": "artifact:cross-tenant-source",
                    "digest": "sha256:" + "b" * 64,
                    "media_type": "text/plain",
                    "size": 1,
                    "redaction_state": "redacted",
                    "encryption_state": "reference_only",
                    "collected_at": "2026-01-01T00:00:00Z",
                    "created_at": "2026-01-01T00:00:00Z",
                    "asset_id": graph_b["asset"].id,
                    "tenant_id": tenant_a.id,
                },
            )
            session.commit()
        session.rollback()
    finally:
        session.close()


def test_canonical_manifest_round_trip_is_verified_and_tenant_scoped(tmp_path: Path) -> None:
    session = create_db(tmp_path / "canonical-manifest.db")
    try:
        store = CanonicalStore(session)
        tenant = Tenant(name="tenant-a")
        graph = _lineage_graph(session, tenant=tenant)
        custody = EvidenceCustodyStore(tmp_path / "custody", tenant.id)
        manifest = custody.store_artifact(
            b"canonical-proof",
            source_observation_id=graph["observation"].id,
            collector_id="fixture-collector",
            media_type="text/plain",
            source_target=graph["artifact"].source_target,
            source_asset_id=graph["artifact"].source_asset_id,
            artifact_id=graph["artifact"].id,
        )
        graph["artifact"] = _bind_artifact_to_manifest(
            graph["artifact"],
            manifest,
        )
        _persist_graph(store, graph)

        store.persist_artifact_manifest(
            manifest.to_dict(),
            custody_store=custody,
            artifact=graph["artifact"],
            observation=graph["observation"],
        )
        restored = store.get_artifact_manifest(manifest.artifact_id, tenant.id)
        assert restored is not None
        assert restored.manifest_digest == manifest.manifest_digest
        assert session.execute(
            text(
                "SELECT manifest_digest FROM canonical_artifact_refs "
                "WHERE tenant_id=:tenant_id AND id=:artifact_id"
            ),
            {"tenant_id": tenant.id, "artifact_id": graph["artifact"].id},
        ).scalar_one() == manifest.manifest_digest
        assert store.list_artifact_manifests(tenant.id) == [restored]
        assert store.get_artifact_manifest(manifest.artifact_id, "tenant-b") is None

        tampered = manifest.to_dict()
        tampered["collector_id"] = "tampered"
        with pytest.raises(CanonicalContractError):
            store.persist_artifact_manifest(tampered)
        with pytest.raises(CanonicalContractError):
            store.record_evidence_access(
                tenant_id=tenant.id,
                artifact_id=graph["artifact"].id,
                observation_id=graph["observation"].id,
                access_kind="protected_original",
                authorization_ref="not-an-authorization-handle",
            )
    finally:
        session.close()


def test_canonical_manifest_requires_custody_verification_and_binds_protected_auth(
    tmp_path: Path,
) -> None:
    session = create_db(tmp_path / "canonical-protected.db")
    try:
        canonical = CanonicalStore(session)
        tenant = Tenant(name="tenant-a")
        graph = _lineage_graph(session, tenant=tenant)
        custody = EvidenceCustodyStore(tmp_path / "custody", tenant.id)
        manifest = custody.store_artifact(
            b"protected-proof",
            source_observation_id=graph["observation"].id,
            collector_id="fixture-collector",
            media_type="text/plain",
            source_target=graph["artifact"].source_target,
            source_asset_id=graph["artifact"].source_asset_id,
            retain_original=True,
            protected_original_authorization_ref="authorization:review-1",
            artifact_id=graph["artifact"].id,
        )
        graph["artifact"] = _bind_artifact_to_manifest(
            graph["artifact"],
            manifest,
        )
        _persist_graph(canonical, graph)
        with pytest.raises(CanonicalContractError, match="custody_store"):
            canonical.persist_artifact_manifest(
                manifest,
                artifact=graph["artifact"],
                observation=graph["observation"],
            )
        canonical.persist_artifact_manifest(
            manifest,
            custody_store=custody,
            artifact=graph["artifact"],
            observation=graph["observation"],
        )
        assert canonical.get_artifact_manifest(manifest.artifact_id, tenant.id) is not None
        with pytest.raises(CanonicalContractError):
            canonical.record_evidence_access(
                tenant_id=tenant.id,
                artifact_id=manifest.artifact_id,
                observation_id=graph["observation"].id,
                access_kind="protected_original",
                authorization_ref="authorization:wrong",
            )
        audit_id = canonical.record_evidence_access(
            tenant_id=tenant.id,
            artifact_id=manifest.artifact_id,
            observation_id=graph["observation"].id,
            access_kind="protected_original",
            authorization_ref="authorization:review-1",
        )
        assert audit_id
    finally:
        session.close()
