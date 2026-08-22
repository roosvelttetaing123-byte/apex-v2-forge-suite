"""Task 101 ordered migration, compatibility, and recovery fixtures."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import text

from common.db import AuthorizationDecisionModel, FindingModel, ScanJobModel, create_db
from common.schema_migrations import (
    CURRENT_SCHEMA_VERSION,
    MigrationInterruptedError,
    MigrationManager,
    downgrade,
    migration_versions,
    recover,
    upgrade,
)


def test_ordered_upgrade_downgrade_and_idempotence(tmp_path: Path) -> None:
    session = create_db(tmp_path / "migrations.db")
    try:
        manager = MigrationManager(session.get_bind())
        assert manager.versions == migration_versions()
        assert manager.current_version() == CURRENT_SCHEMA_VERSION
        assert manager.upgrade() == CURRENT_SCHEMA_VERSION
        assert manager.current_version() == CURRENT_SCHEMA_VERSION
        assert manager.downgrade() is None
        assert manager.current_version() is None
        assert manager.upgrade() == CURRENT_SCHEMA_VERSION
    finally:
        session.close()


def test_interrupted_migration_is_journaled_and_recoverable(tmp_path: Path) -> None:
    session = create_db(tmp_path / "interrupted.db")
    try:
        manager = MigrationManager(session.get_bind())
        assert manager.downgrade() is None
        with pytest.raises(MigrationInterruptedError):
            manager.upgrade(fail_after=0)
        states = {row["state"] for row in manager.journal() if row["version"] == CURRENT_SCHEMA_VERSION}
        assert states == {"failed"}
        assert manager.recover() == CURRENT_SCHEMA_VERSION
        assert manager.current_version() == CURRENT_SCHEMA_VERSION
    finally:
        session.close()


def test_legacy_gate0_records_migrate_to_unknown_reduced_claims(tmp_path: Path) -> None:
    session = create_db(tmp_path / "legacy.db")
    try:
        session.add(FindingModel(id="legacy-finding", tenant_id="legacy-tenant", title="old", severity="High", target="fixture", module="old", description="legacy"))
        session.add(ScanJobModel(id="legacy-job", tenant_id="legacy-tenant", target="fixture", status="completed"))
        session.add(AuthorizationDecisionModel(
            decision_id="legacy-auth", schema_version="legacy-v0", tenant_id="legacy-tenant", engagement_id="legacy-engagement", run_id="legacy-run", job_id="legacy-job", action_id="legacy-action", operator_id="legacy-operator", operator_role="operator", action_kind="scan", engine="fixture", requested_target="sha256:" + "a" * 64, resolved_target="sha256:" + "a" * 64, scope_snapshot="sha256:" + "b" * 64, scope_policy_version="legacy", scope_decision="allow", scope_reason_code="legacy", decision_outcome="allow", reason_code="allowed", issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc), expires_at=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc), binding_digest="sha256:" + "c" * 64, envelope_json=json.dumps({"password": "TASK101_CANARY_SECRET"}), detail="{}"
        ))
        session.commit()
        manager = MigrationManager(session.get_bind())
        manager.downgrade()
        manager.upgrade()
        rows = session.execute(text("SELECT record_kind,claim_state, payload_json FROM canonical_legacy_records ORDER BY record_kind")).mappings().all()
        assert {row["record_kind"] for row in rows} >= {"authorization", "finding", "job"}
        assert all(row["claim_state"] in {"unknown", "reduced", "not_authorized"} for row in rows)
        assert all("TASK101_CANARY_SECRET" not in row["payload_json"] for row in rows)
        # The migration materializes normalized control-plane rows while
        # retaining reduced/unknown claims.  A legacy finding without explicit
        # canonical observation/artifact authorization must not become an
        # observed or verified finding merely because display fields exist.
        normalized = session.execute(text(
            "SELECT outcome FROM canonical_scope_decisions"
        )).scalars().all()
        assert normalized == ["allow"]
        finding = session.execute(text(
            "SELECT status FROM canonical_findings WHERE id LIKE 'legacy-finding-%'"
        )).scalar_one()
        assert finding == "unknown"
        tenant_id = session.execute(text(
            "SELECT tenant_id FROM canonical_legacy_records "
            "WHERE record_kind='finding' LIMIT 1"
        )).scalar_one()
        observation = session.execute(text(
            "SELECT o.status FROM canonical_observations o "
            "JOIN canonical_findings f ON f.tenant_id=o.tenant_id AND f.observation_id=o.id "
            "WHERE f.id LIKE 'legacy-finding-%' AND f.tenant_id=:tenant_id"
        ), {"tenant_id": tenant_id}).scalar_one()
        assert observation == "not_authorized"
    finally:
        session.close()


def test_legacy_secret_bearing_keys_are_opaque_in_canonical_archive(tmp_path: Path) -> None:
    session = create_db(tmp_path / "legacy-keys.db")
    try:
        session.add(ScanJobModel(id="TASK101_CANARY_SECRET", tenant_id="TASK101_CANARY_SECRET", target="fixture", status="completed"))
        session.commit()
        manager = MigrationManager(session.get_bind())
        manager.downgrade()
        manager.upgrade()
        tenants = session.execute(text("SELECT id, name FROM canonical_tenants")).mappings().all()
        records = session.execute(text("SELECT tenant_id, legacy_id, payload_json FROM canonical_legacy_records")).mappings().all()
        assert tenants and records
        assert all("TASK101_CANARY_SECRET" not in str(value) for row in tenants for value in row.values())
        assert all("TASK101_CANARY_SECRET" not in str(value) for row in records for value in row.values())
        assert all(str(row["tenant_id"]).startswith("legacy-tenant-") for row in records)
        assert all(str(row["legacy_id"]).startswith("legacy-job-opaque-") for row in records)
    finally:
        session.close()


def test_contradictory_legacy_authorization_is_not_promoted_to_allow(tmp_path: Path) -> None:
    session = create_db(tmp_path / "legacy-contradiction.db")
    try:
        session.add(AuthorizationDecisionModel(
            decision_id="legacy-auth-contradictory",
            schema_version="legacy-v0",
            tenant_id="legacy-tenant",
            engagement_id="legacy-engagement",
            run_id="legacy-run",
            job_id="legacy-job",
            action_id="legacy-action",
            operator_id="legacy-operator",
            operator_role="operator",
            action_kind="scan",
            engine="fixture",
            requested_target="fixture",
            resolved_target="fixture",
            scope_snapshot="sha256:" + "b" * 64,
            scope_policy_version="legacy",
            scope_decision="deny",
            scope_reason_code="legacy",
            decision_outcome="allow",
            reason_code="contradictory",
            issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
            binding_digest="sha256:" + "c" * 64,
            envelope_json="{}",
            detail="{}",
        ))
        session.commit()
        manager = MigrationManager(session.get_bind())
        manager.downgrade()
        manager.upgrade()
        outcome = session.execute(text(
            "SELECT outcome FROM canonical_scope_decisions "
            "WHERE id LIKE 'legacy-scope-%'"
        )).scalar_one()
        assert outcome == "unknown"
        assert session.execute(text(
            "SELECT status FROM canonical_jobs WHERE id LIKE 'legacy-job-%'"
        )).scalar_one() == "unknown_not_authorized"
    finally:
        session.close()
