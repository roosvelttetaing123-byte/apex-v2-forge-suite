"""Task 102 immutable observation and evidence-custody fixtures."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from sqlalchemy import text

from common.canonical import (
    ArtifactReference,
    Asset,
    AssetKind,
    CanonicalContractError,
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
    CustodyError,
    EvidenceCustodyStore,
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
        assert store.read(
            manifest.artifact_id,
            include_original=True,
            authorization="authorization:task102-original",
        ) == b"Authorization: Bearer TASK102_CANARY_SECRET\n"
        assert [event["event"] for event in events] == [
            "artifact.read.redacted",
            "artifact.read.original.denied",
            "artifact.read.original.authorized",
        ]
    finally:
        clear_sensitive_values()


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
            artifact_id=graph["artifact"].id,
        )
        graph["artifact"] = replace(
            graph["artifact"],
            digest=manifest.sha256,
            size=manifest.byte_size,
            media_type=manifest.media_type,
        )
        _persist_graph(store, graph)

        store.persist_artifact_manifest(
            manifest.to_dict(),
            artifact=graph["artifact"],
            observation=graph["observation"],
        )
        restored = store.get_artifact_manifest(manifest.artifact_id, tenant.id)
        assert restored is not None
        assert restored.manifest_digest == manifest.manifest_digest
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
