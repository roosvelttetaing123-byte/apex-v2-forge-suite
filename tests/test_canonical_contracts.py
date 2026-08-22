"""Deterministic Task 101 canonical-contract acceptance fixtures."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from common.canonical import (
    Action,
    ArtifactReference,
    Asset,
    AssetKind,
    CanonicalAdapter,
    CanonicalContext,
    CanonicalLineageError,
    MissingCanonicalContextError,
    CanonicalStore,
    CanonicalTenantMismatchError,
    CheckPackSnapshot,
    Client,
    Engagement,
    Export,
    FeedSnapshot,
    Finding,
    FindingSeverity,
    IntelligenceSource,
    Job,
    ModuleExecution,
    ModuleVersion,
    Observation,
    ObservationStatus,
    Operator,
    Project,
    Provenance,
    ProvenanceSourceType,
    Report,
    ReportMembership,
    Retest,
    RetestStatus,
    ScopeDecision,
    Tenant,
    deserialize_contract,
    serialize_contract,
)
from common.db import create_db
from common.redaction import clear_sensitive_values, register_sensitive_values


def _graph(tmp_path: Path):
    session = create_db(tmp_path / "canonical.db")
    store = CanonicalStore(session)
    tenant = Tenant(name="Tenant A")
    client = Client(tenant_id=tenant.id, name="Client A")
    project = Project(tenant_id=tenant.id, client_id=client.id, name="Project A")
    engagement = Engagement(tenant_id=tenant.id, project_id=project.id, name="Engagement A")
    job = Job(tenant_id=tenant.id, engagement_id=engagement.id, job_kind="fixture")
    module = ModuleVersion(tenant_id=tenant.id, module_id="web.headers", version="1.2.3")
    asset = Asset(
        tenant_id=tenant.id,
        kind=AssetKind.HOST,
        identity_key="APP.EXAMPLE.TEST",
        display_name="Application host",
    )
    observation = Observation(
        tenant_id=tenant.id,
        engagement_id=engagement.id,
        job_id=job.id,
        module_version_id=module.id,
        asset_id=asset.id,
        status=ObservationStatus.OBSERVED,
    )
    artifact = ArtifactReference(
        tenant_id=tenant.id,
        observation_id=observation.id,
        reference="artifact:fixture-observation",
        digest="sha256:" + "a" * 64,
        media_type="application/json",
        size=42,
    )
    finding = Finding(
        tenant_id=tenant.id,
        observation_id=observation.id,
        artifact_id=artifact.id,
        title="Missing security header",
        severity=FindingSeverity.MEDIUM,
        description="The inert fixture omitted a required response header.",
        finding_key="headers:x-content-type-options",
    )
    return session, store, {
        "tenant": tenant,
        "client": client,
        "project": project,
        "engagement": engagement,
        "job": job,
        "module": module,
        "asset": asset,
        "observation": observation,
        "artifact": artifact,
        "finding": finding,
    }


def test_complete_finding_resolves_mandatory_lineage(tmp_path: Path) -> None:
    session, store, graph = _graph(tmp_path)
    try:
        store.create_lineage(
            tenant=graph["tenant"],
            client=graph["client"],
            project=graph["project"],
            engagement=graph["engagement"],
            job=graph["job"],
            module_version=graph["module"],
            asset=graph["asset"],
            observation=graph["observation"],
            artifact=graph["artifact"],
            finding=graph["finding"],
        )
        lineage = store.resolve_finding_lineage(graph["finding"].id, graph["tenant"].id)
        assert lineage is not None
        assert lineage["engagement_id"] == graph["engagement"].id
        assert lineage["job_id"] == graph["job"].id
        assert lineage["module_version_id"] == graph["module"].id
        assert lineage["asset_id"] == graph["asset"].id
        assert lineage["observation_id"] == graph["observation"].id
        assert lineage["artifact_id"] == graph["artifact"].id
    finally:
        session.close()


def test_optional_intelligence_retest_report_export_links_share_finding(tmp_path: Path) -> None:
    session, store, graph = _graph(tmp_path)
    try:
        source = IntelligenceSource(tenant_id=graph["tenant"].id, name="fixture-feed", source_kind="feed")
        feed = FeedSnapshot(tenant_id=graph["tenant"].id, source_id=source.id, version="2026.08", digest="sha256:" + "b" * 64)
        checkpack = CheckPackSnapshot(tenant_id=graph["tenant"].id, source_id=source.id, version="pack-1", digest="sha256:" + "c" * 64)
        provenance = Provenance(tenant_id=graph["tenant"].id, source_type=ProvenanceSourceType.FEED_SNAPSHOT, source_id=feed.id, digest=feed.digest)
        graph["module"] = ModuleVersion(
            id=graph["module"].id,
            tenant_id=graph["tenant"].id,
            module_id="web.headers",
            version="1.2.3",
            intelligence_snapshot_id=feed.id,
            check_pack_snapshot_id=checkpack.id,
            provenance_id=provenance.id,
        )
        retest = Retest(tenant_id=graph["tenant"].id, finding_id=graph["finding"].id, source_observation_id=graph["observation"].id, status=RetestStatus.NOT_RUN, job_id=graph["job"].id)
        report = Report(tenant_id=graph["tenant"].id, name="fixture report")
        membership = ReportMembership(tenant_id=graph["tenant"].id, report_id=report.id, finding_id=graph["finding"].id, observation_id=graph["observation"].id)
        export = Export(tenant_id=graph["tenant"].id, finding_id=graph["finding"].id, source_observation_id=graph["observation"].id, format="json", report_id=report.id, provenance_id=provenance.id)
        result = store.create_lineage(
            tenant=graph["tenant"], client=graph["client"], project=graph["project"], engagement=graph["engagement"], job=graph["job"],
            intelligence_source=source, feed_snapshot=feed, check_pack_snapshot=checkpack, provenance=provenance,
            module_version=graph["module"], asset=graph["asset"], observation=graph["observation"], artifact=graph["artifact"], finding=graph["finding"],
            retest=retest, report=report, report_membership=membership, export=export,
        )
        assert result["retest"].finding_id == graph["finding"].id
        assert result["report_membership"].observation_id == graph["observation"].id
        assert result["export"].report_id == report.id
        assert session.execute(text("SELECT COUNT(*) FROM canonical_retests WHERE tenant_id=:t AND finding_id=:f"), {"t": graph["tenant"].id, "f": graph["finding"].id}).scalar_one() == 1
    finally:
        session.close()


def test_cross_tenant_and_orphan_links_fail_at_application_and_db_layers(tmp_path: Path) -> None:
    session, store, graph = _graph(tmp_path)
    try:
        with pytest.raises(CanonicalTenantMismatchError):
            store.create_lineage(
                tenant=Tenant(name="Tenant B"), client=graph["client"], project=graph["project"], engagement=graph["engagement"], job=graph["job"],
                module_version=graph["module"], asset=graph["asset"], observation=graph["observation"], artifact=graph["artifact"], finding=graph["finding"],
            )
        with pytest.raises(IntegrityError):
            session.execute(text("INSERT INTO canonical_observations (id,tenant_id,engagement_id,job_id,module_version_id,asset_id,schema_version,status,observed_at,created_at,metadata_json) VALUES ('orphan','no-tenant','e','j','m','a','forge-canonical-v1','observed','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','{}')"))
            session.commit()
        session.rollback()
        # A real parent in tenant A cannot be referenced by a tenant-B child;
        # the composite ownership FK must reject the link at the database
        # boundary even when application validation is bypassed.
        session.execute(text("INSERT INTO canonical_tenants(id,schema_version,name,created_at,metadata_json) VALUES ('tenant-a','forge-canonical-v1','A','2026-01-01T00:00:00Z','{}'),('tenant-b','forge-canonical-v1','B','2026-01-01T00:00:00Z','{}')"))
        session.execute(text("INSERT INTO canonical_clients(id,tenant_id,schema_version,name,created_at,metadata_json) VALUES ('client-a','tenant-a','forge-canonical-v1','A','2026-01-01T00:00:00Z','{}')"))
        with pytest.raises(IntegrityError):
            session.execute(text("INSERT INTO canonical_projects(id,tenant_id,client_id,schema_version,name,created_at,metadata_json) VALUES ('project-b','tenant-b','client-a','forge-canonical-v1','B','2026-01-01T00:00:00Z','{}')"))
            session.commit()
    finally:
        session.rollback()
        session.close()


def test_sha256_artifact_reference_round_trips_through_database(tmp_path: Path) -> None:
    session, store, graph = _graph(tmp_path)
    try:
        reference = "sha256:" + "d" * 64
        artifact = ArtifactReference(
            tenant_id=graph["tenant"].id,
            observation_id=graph["observation"].id,
            reference=reference,
            digest="sha256:" + "e" * 64,
            media_type="application/octet-stream",
            size=0,
        )
        finding = Finding(
            tenant_id=graph["tenant"].id,
            observation_id=graph["observation"].id,
            artifact_id=artifact.id,
            title="Digest reference",
            severity=FindingSeverity.LOW,
            description="An opaque digest reference is accepted by the canonical database guard.",
        )
        store.create_lineage(
            tenant=graph["tenant"],
            client=graph["client"],
            project=graph["project"],
            engagement=graph["engagement"],
            job=graph["job"],
            module_version=graph["module"],
            asset=graph["asset"],
            observation=graph["observation"],
            artifact=artifact,
            finding=finding,
        )
        session.commit()
        row = session.execute(
            text("SELECT reference FROM canonical_artifact_refs WHERE id=:id"),
            {"id": artifact.id},
        ).scalar_one()
        assert row == reference
    finally:
        session.rollback()
        session.close()


def test_orphan_artifact_finding_retest_membership_and_export_fail(tmp_path: Path) -> None:
    session, _store, graph = _graph(tmp_path)
    try:
        session.execute(text("INSERT INTO canonical_tenants(id,schema_version,name,created_at,metadata_json) VALUES ('t','forge-canonical-v1','T','2026-01-01T00:00:00Z','{}')"))
        statements = [
            "INSERT INTO canonical_artifact_refs(id,tenant_id,observation_id,schema_version,reference,digest,media_type,size,redaction_state,encryption_state,collected_at,created_at,metadata_json) VALUES ('a','t','missing','forge-canonical-v1','artifact:x','sha256:" + "a" * 64 + "','text/plain',0,'redacted','reference_only','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','{}')",
            "INSERT INTO canonical_findings(id,tenant_id,observation_id,artifact_id,schema_version,title,severity,description,status,created_at,metadata_json) VALUES ('f','t','missing','missing','forge-canonical-v1','x','high','x','open','2026-01-01T00:00:00Z','{}')",
            "INSERT INTO canonical_retests(id,tenant_id,finding_id,source_observation_id,schema_version,status,created_at,metadata_json) VALUES ('r','t','missing','missing','forge-canonical-v1','not_run','2026-01-01T00:00:00Z','{}')",
            "INSERT INTO canonical_report_memberships(id,tenant_id,report_id,finding_id,observation_id,schema_version,created_at,metadata_json) VALUES ('rm','t','missing','missing','missing','forge-canonical-v1','2026-01-01T00:00:00Z','{}')",
            "INSERT INTO canonical_exports(id,tenant_id,finding_id,source_observation_id,schema_version,format,status,created_at,metadata_json) VALUES ('e','t','missing','missing','forge-canonical-v1','json','created','2026-01-01T00:00:00Z','{}')",
        ]
        for statement in statements:
            with pytest.raises(IntegrityError):
                session.execute(text(statement))
                session.commit()
            session.rollback()
    finally:
        session.close()


def test_asset_identity_deduplicates_exact_key_but_not_display_labels(tmp_path: Path) -> None:
    session, store, graph = _graph(tmp_path)
    try:
        store.insert(graph["tenant"])
        first = store.get_or_create_asset(tenant_id=graph["tenant"].id, kind="host", identity_key="Host.Example", display_name="one")
        second = store.get_or_create_asset(tenant_id=graph["tenant"].id, kind="host", identity_key="host.example", display_name="different label")
        third = store.get_or_create_asset(tenant_id=graph["tenant"].id, kind="host", identity_key="host.example:443", display_name="same words, different identity")
        assert first.id == second.id
        assert third.id != first.id
        assert store.count("canonical_assets", tenant_id=graph["tenant"].id) == 2
    finally:
        session.close()


def test_relationship_ids_cannot_hide_in_metadata_and_secrets_are_redacted(tmp_path: Path) -> None:
    register_sensitive_values(["TASK101_CANARY_SECRET"])
    try:
        with pytest.raises(ValueError, match="relationship"):
            Tenant(name="x", metadata={"finding_id": "forged"})
        tenant = Tenant(name="x", metadata={"password": "TASK101_CANARY_SECRET", "credential_ref": "cred:fixture-12345678"})
        rendered = serialize_contract(tenant)
        assert "TASK101_CANARY_SECRET" not in rendered
        assert "cred:fixture-12345678" in rendered
    finally:
        clear_sensitive_values()


@pytest.mark.parametrize(
    "relationship_key",
    [
        "run_id",
        "execution_id",
        "attempt_id",
        "intelligence_snapshot_id",
        "check_pack_snapshot_id",
        "manifest_id",
        "source_observation_id",
        "source_asset_id",
        "authorization_decision_id",
    ],
)
def test_all_canonical_relationship_ids_are_rejected_from_metadata(
    relationship_key: str,
) -> None:
    with pytest.raises(ValueError, match="relationship"):
        Tenant(name="x", metadata={relationship_key: "forged"})


def test_registered_reference_canary_never_enters_canonical_metadata(tmp_path: Path) -> None:
    register_sensitive_values(["TASK101_CANARY_SECRET"])
    session = create_db(tmp_path / "metadata-redaction.db")
    try:
        tenant = Tenant(
            name="metadata fixture",
            metadata={"credential_ref": "cred:TASK101_CANARY_SECRET"},
        )
        CanonicalStore(session).insert(tenant)
        session.commit()
        stored = session.execute(
            text("SELECT metadata_json FROM canonical_tenants WHERE id=:id"),
            {"id": tenant.id},
        ).scalar_one()
        assert "TASK101_CANARY_SECRET" not in stored
        assert "<redacted>" in stored
    finally:
        session.rollback()
        session.close()
        clear_sensitive_values()


def test_lineage_constraint_failure_rolls_back_every_insert(tmp_path: Path) -> None:
    session, store, graph = _graph(tmp_path)
    try:
        store.create_lineage(tenant=graph["tenant"], client=graph["client"], project=graph["project"], engagement=graph["engagement"], job=graph["job"], module_version=graph["module"], asset=graph["asset"], observation=graph["observation"], artifact=graph["artifact"], finding=graph["finding"])
        before = {table: store.count(table, tenant_id=graph["tenant"].id) for table in ("canonical_engagements", "canonical_jobs", "canonical_observations", "canonical_artifact_refs", "canonical_findings")}
        duplicate_job = Job(id=graph["job"].id, tenant_id=graph["tenant"].id, engagement_id=graph["engagement"].id, job_kind="duplicate")
        with pytest.raises((IntegrityError, CanonicalLineageError)):
            store.create_lineage(tenant=graph["tenant"], client=graph["client"], project=graph["project"], engagement=graph["engagement"], job=duplicate_job, module_version=graph["module"], asset=graph["asset"], observation=graph["observation"], artifact=graph["artifact"], finding=graph["finding"])
        session.rollback()
        after = {table: store.count(table, tenant_id=graph["tenant"].id) for table in before}
        assert after == before
    finally:
        session.close()


def test_contract_round_trip_preserves_enum_timestamp_ids_relationships(tmp_path: Path) -> None:
    _session, _store, graph = _graph(tmp_path)
    finding = graph["finding"]
    offset_finding = Finding(
        id=finding.id, tenant_id=finding.tenant_id, observation_id=finding.observation_id, artifact_id=finding.artifact_id,
        title=finding.title, severity=FindingSeverity.HIGH, description=finding.description,
        created_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=-5))),
    )
    round_tripped = deserialize_contract(serialize_contract(offset_finding), Finding)
    assert round_tripped.id == finding.id
    assert round_tripped.severity is FindingSeverity.HIGH
    assert round_tripped.created_at.tzinfo == timezone.utc
    assert round_tripped.observation_id == finding.observation_id


def test_optional_relationship_none_and_registered_reference_canary_round_trip(tmp_path: Path) -> None:
    register_sensitive_values(["TASK101_CANARY_SECRET"])
    try:
        action = Action(
            tenant_id="tenant-a",
            engagement_id="eng-a",
            job_id="job-a",
            action_kind="fixture",
        )
        rendered = serialize_contract(action)
        assert '"authorization_decision_id":null' in rendered
        assert deserialize_contract(rendered, Action).authorization_decision_id is None

        tenant = Tenant(
            name="fixture",
            metadata={
                "credential_ref": "cred:TASK101_CANARY_SECRET",
                "artifact_ref": "artifact:TASK101_CANARY_SECRET",
            },
        )
        safe = serialize_contract(tenant)
        assert "TASK101_CANARY_SECRET" not in safe
    finally:
        clear_sensitive_values()


def test_missing_context_adapter_rejects_before_persistence(tmp_path: Path) -> None:
    session = create_db(tmp_path / "adapter.db")
    try:
        adapter = CanonicalAdapter(CanonicalStore(session), None)
        with pytest.raises(Exception) as exc_info:
            adapter.persist_finding(title="x", severity=FindingSeverity.LOW, description="x", artifact_reference="artifact:x", artifact_digest="sha256:" + "d" * 64)
        assert "context" in str(exc_info.value).lower()
        assert session.execute(text("SELECT COUNT(*) FROM canonical_tenants")).scalar_one() == 0
        context = CanonicalContext(None, "e", "j", "m", "a")
        with pytest.raises(Exception):
            CanonicalAdapter(CanonicalStore(session), context).require_context()
    finally:
        session.close()


def test_database_guards_immutable_provenance_authorization_and_schema_version(tmp_path: Path) -> None:
    session, store, graph = _graph(tmp_path)
    try:
        source = IntelligenceSource(tenant_id=graph["tenant"].id, name="source", source_kind="feed")
        feed = FeedSnapshot(tenant_id=graph["tenant"].id, source_id=source.id, version="v1", digest="sha256:" + "e" * 64)
        provenance = Provenance(
            tenant_id=graph["tenant"].id,
            source_type=ProvenanceSourceType.FEED_SNAPSHOT,
            source_id=feed.id,
            digest=feed.digest,
        )
        session.execute(text("INSERT INTO canonical_tenants(id,schema_version,name,created_at,metadata_json) VALUES (:id,:v,:n,:t,:m)"), {"id": "other", "v": "forge-canonical-v1", "n": "Other", "t": "2026-01-01T00:00:00Z", "m": "{}"})
        store.insert(graph["tenant"])
        store.insert(source)
        store.insert(feed)
        store.insert(provenance)
        session.commit()
        with pytest.raises(IntegrityError):
            session.execute(text("UPDATE canonical_provenance SET tenant_id='other' WHERE id=:id"), {"id": provenance.id})
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError):
            session.execute(text("UPDATE canonical_tenants SET schema_version='future' WHERE id=:id"), {"id": graph["tenant"].id})
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError):
            session.execute(text("INSERT INTO canonical_artifact_refs(id,tenant_id,observation_id,schema_version,reference,digest,media_type,size,redaction_state,encryption_state,collected_at,created_at,metadata_json) VALUES ('bad',:tenant,'missing','forge-canonical-v1','/tmp/plaintext','sha256:" + "a" * 64 + "','text/plain',0,'redacted','reference_only','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','{}')"), {"tenant": graph["tenant"].id})
            session.commit()
        session.rollback()
    finally:
        session.rollback()
        session.close()


def test_module_version_snapshot_identity_and_db_shapes_are_immutable(tmp_path: Path) -> None:
    session, store, graph = _graph(tmp_path)
    try:
        source = IntelligenceSource(tenant_id=graph["tenant"].id, name="source", source_kind="feed")
        feed_one = FeedSnapshot(
            tenant_id=graph["tenant"].id,
            source_id=source.id,
            version="v1",
            digest="sha256:" + "a" * 64,
        )
        feed_two = FeedSnapshot(
            tenant_id=graph["tenant"].id,
            source_id=source.id,
            version="v2",
            digest="sha256:" + "b" * 64,
        )
        provenance = Provenance(
            tenant_id=graph["tenant"].id,
            source_type=ProvenanceSourceType.FEED_SNAPSHOT,
            source_id=feed_one.id,
            digest=feed_one.digest,
        )
        module = ModuleVersion(
            id=graph["module"].id,
            tenant_id=graph["tenant"].id,
            module_id="fixture.module",
            version="1.0.0",
            intelligence_snapshot_id=feed_one.id,
            provenance_id=provenance.id,
        )
        execution = ModuleExecution(
            tenant_id=graph["tenant"].id,
            job_id=graph["job"].id,
            module_version_id=module.id,
            intelligence_snapshot_id=feed_one.id,
            provenance_id=provenance.id,
        )
        observation = Observation(
            tenant_id=graph["tenant"].id,
            engagement_id=graph["engagement"].id,
            job_id=graph["job"].id,
            module_version_id=module.id,
            module_execution_id=execution.id,
            asset_id=graph["asset"].id,
            status=ObservationStatus.OBSERVED,
        )
        artifact = ArtifactReference(
            tenant_id=graph["tenant"].id,
            observation_id=observation.id,
            reference="artifact:immutable-shape",
            digest="sha256:" + "c" * 64,
            media_type="application/json",
            size=0,
        )
        finding = Finding(
            tenant_id=graph["tenant"].id,
            observation_id=observation.id,
            artifact_id=artifact.id,
            title="fixture",
            severity=FindingSeverity.LOW,
            description="fixture",
        )
        store.create_lineage(
            tenant=graph["tenant"],
            client=graph["client"],
            project=graph["project"],
            engagement=graph["engagement"],
            job=graph["job"],
            module_version=module,
            asset=graph["asset"],
            observation=observation,
            artifact=artifact,
            finding=finding,
            module_execution=execution,
            intelligence_source=source,
            feed_snapshot=feed_one,
            provenance=provenance,
        )
        store.insert(feed_two)
        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "UPDATE canonical_module_versions "
                    "SET intelligence_snapshot_id=:feed_id WHERE id=:module_id"
                ),
                {"feed_id": feed_two.id, "module_id": module.id},
            )
            session.commit()
        session.rollback()
        assert session.execute(
            text("SELECT intelligence_snapshot_id FROM canonical_module_versions WHERE id=:id"),
            {"id": module.id},
        ).scalar_one() == feed_one.id

        with pytest.raises(IntegrityError):
            session.execute(
                text("UPDATE canonical_feed_snapshots SET digest='sha256:x' WHERE id=:id"),
                {"id": feed_one.id},
            )
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError):
            session.execute(
                text("UPDATE canonical_feed_snapshots SET version='v2' WHERE id=:id"),
                {"id": feed_one.id},
            )
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError):
            session.execute(
                text("UPDATE canonical_provenance SET digest='sha256:x' WHERE id=:id"),
                {"id": provenance.id},
            )
            session.commit()
        session.rollback()

        with pytest.raises(IntegrityError):
            session.execute(
                text("UPDATE canonical_artifact_refs SET digest='sha256:x' WHERE id=:id"),
                {"id": artifact.id},
            )
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError):
            session.execute(
                text("UPDATE canonical_artifact_refs SET reference='artifact:' WHERE id=:id"),
                {"id": artifact.id},
            )
            session.commit()
        session.rollback()

        with pytest.raises(IntegrityError):
            session.execute(
                text("UPDATE canonical_assets SET identity_key='other-host' WHERE id=:id"),
                {"id": graph["asset"].id},
            )
            session.commit()
        session.rollback()

        operator = Operator(tenant_id=graph["tenant"].id, display_name="fixture operator")
        decision = ScopeDecision(
            tenant_id=graph["tenant"].id,
            engagement_id=graph["engagement"].id,
            operator_id=operator.id,
            outcome="allow",
            policy_version="policy-v1",
        )
        store.insert(operator)
        store.insert(decision)
        session.commit()
        with pytest.raises(IntegrityError):
            session.execute(
                text("UPDATE canonical_scope_decisions SET outcome='deny' WHERE id=:id"),
                {"id": decision.id},
            )
            session.commit()
        session.rollback()
    finally:
        session.rollback()
        session.close()


def test_server_ids_reject_secret_like_caller_values(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="secret-like"):
        Tenant(id="TASK101_CANARY_SECRET", name="fixture")


def test_database_rejects_cross_engagement_authorization_decision(tmp_path: Path) -> None:
    session = create_db(tmp_path / "authorization-lineage.db")
    try:
        tenant = Tenant(id="tenant-a", name="Tenant A")
        engagement_a = Engagement(id="eng-a", tenant_id=tenant.id, name="A")
        engagement_b = Engagement(id="eng-b", tenant_id=tenant.id, name="B")
        operator = Operator(id="operator-a", tenant_id=tenant.id, display_name="Operator")
        job_a = Job(id="job-a", tenant_id=tenant.id, engagement_id=engagement_a.id, job_kind="fixture")
        decision_b = ScopeDecision(
            id="decision-b",
            tenant_id=tenant.id,
            engagement_id=engagement_b.id,
            operator_id=operator.id,
            outcome="allow",
            policy_version="policy-v1",
        )
        store = CanonicalStore(session)
        for record in (tenant, engagement_a, engagement_b, operator, job_a, decision_b):
            store.insert(record)
        session.commit()
        with pytest.raises(IntegrityError):
            session.execute(text(
                "INSERT INTO canonical_actions "
                "(id,tenant_id,engagement_id,job_id,schema_version,action_kind,authorization_decision_id,created_at,metadata_json) "
                "VALUES ('action-a',:tenant,'eng-a','job-a','forge-canonical-v1','scan','decision-b','2026-01-01T00:00:00Z','{}')"
            ), {"tenant": tenant.id})
            session.commit()
    finally:
        session.rollback()
        session.close()


def test_explicit_legacy_writer_context_is_typed_and_complete(tmp_path: Path) -> None:
    session = create_db(tmp_path / "legacy-adapter.db")
    try:
        from common.db import save_finding, save_scan_job

        with pytest.raises(MissingCanonicalContextError):
            save_scan_job(session, {"id": "job", "target": "fixture", "canonical_context": {"tenant_id": "t"}})
        with pytest.raises(MissingCanonicalContextError):
            save_finding(session, {"id": "finding", "title": "x", "target": "fixture", "module": "fixture", "description": "x", "canonical_context": object()})
        assert session.execute(text("SELECT COUNT(*) FROM scan_jobs WHERE id='job'")).scalar_one() == 0
        assert session.execute(text("SELECT COUNT(*) FROM findings WHERE id='finding'")).scalar_one() == 0
    finally:
        session.close()


def test_existing_legacy_writers_reject_explicit_partial_context(tmp_path: Path) -> None:
    """Legacy helpers fail closed whenever a caller opts into Task 101 context."""
    from common.db import FindingModel, ScanJobModel, save_finding, save_scan_job

    session = create_db(tmp_path / "legacy-adapters.db")
    try:
        with pytest.raises(Exception, match="canonical"):
            save_scan_job(
                session,
                {"id": "job-1", "target": "fixture", "canonical_context": {}},
            )
        with pytest.raises(Exception, match="canonical"):
            save_finding(
                session,
                {
                    "id": "finding-1",
                    "title": "fixture",
                    "target": "fixture",
                    "severity": "Low",
                    "module": "fixture",
                    "description": "fixture",
                    "canonical_context": {},
                },
            )
        assert session.query(ScanJobModel).count() == 0
        assert session.query(FindingModel).count() == 0
    finally:
        session.close()


def test_strict_legacy_writer_boundary_rejects_missing_context(tmp_path: Path) -> None:
    from common.db import FindingModel, ScanJobModel, save_finding, save_scan_job

    session = create_db(tmp_path / "strict-legacy-adapters.db")
    try:
        with pytest.raises(MissingCanonicalContextError):
            save_scan_job(
                session,
                {"id": "strict-job", "target": "fixture"},
            )
        with pytest.raises(MissingCanonicalContextError):
            save_finding(
                session,
                {
                    "id": "strict-finding",
                    "title": "fixture",
                    "target": "fixture",
                    "severity": "Low",
                    "module": "fixture",
                    "description": "fixture",
                },
            )
        assert session.query(ScanJobModel).count() == 0
        assert session.query(FindingModel).count() == 0
    finally:
        session.close()


def test_module_adapter_surfaces_typed_missing_context_before_legacy_persistence(tmp_path: Path) -> None:
    from common.base_module import BaseModule, ModuleResult
    from common.config import BaseForgeConfig
    from common.finding import Severity
    from common.scope import Scope

    class FixtureModule(BaseModule):
        NAME = "fixture"
        DESCRIPTION = "fixture"
        PHASE = 1

        async def run(self) -> ModuleResult:
            return ModuleResult(module_name=self.NAME)

    session = create_db(tmp_path / "module-adapter.db")
    try:
        config = BaseForgeConfig(target="fixture")
        config.extra["canonical_context_required"] = True
        module = FixtureModule(config, Scope(["fixture"]), session, tmp_path)
        with pytest.raises(MissingCanonicalContextError):
            module.new_finding(
                title="fixture",
                severity=Severity.LOW,
                description="fixture",
                reproduction_steps=[],
                remediation="fixture",
                references=[],
            )
        assert module.findings == []
        assert session.execute(text("SELECT COUNT(*) FROM findings")).scalar_one() == 0
    finally:
        session.close()


def test_legacy_writers_never_persist_a_marked_canonical_graph(tmp_path: Path) -> None:
    from common.db import FindingModel, ScanJobModel, save_finding, save_scan_job

    session = create_db(tmp_path / "marked-canonical-adapters.db")
    context = {
        "tenant_id": "tenant-a",
        "engagement_id": "eng-a",
        "job_id": "job-a",
        "module_version_id": "module-a",
        "asset_id": "asset-a",
    }
    try:
        with pytest.raises(MissingCanonicalContextError, match="CanonicalAdapter"):
            save_scan_job(
                session,
                {"id": "job-a", "target": "fixture", **context, "canonical_context": context},
            )
        with pytest.raises(MissingCanonicalContextError, match="CanonicalAdapter"):
            save_finding(
                session,
                {
                    "id": "finding-a",
                    "title": "fixture",
                    "target": "fixture",
                    "severity": "Low",
                    "module": "fixture",
                    "description": "fixture",
                    **context,
                    "canonical_context": context,
                },
            )
        assert session.query(ScanJobModel).count() == 0
        assert session.query(FindingModel).count() == 0
    finally:
        session.close()
