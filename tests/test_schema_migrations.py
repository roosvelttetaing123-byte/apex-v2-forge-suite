"""Task 101 ordered migration, compatibility, and recovery fixtures."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from common.action_authorization import (
    AUTHORIZATION_SCHEMA_VERSION,
    ActionAuthorizationEnvelope,
    compute_envelope_digest,
    module_set_binding,
)
from common.confirm_gate import ActionConfirmation
from common.db import (
    AuthorizationConsumptionModel,
    AuthorizationDecisionModel,
    AuthorizationExecutionClaimModel,
    FindingModel,
    ScanJobModel,
    create_db,
)
from common.schema_migrations import (
    CURRENT_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    JOB_STATE_SCHEMA_VERSION,
    MigrationError,
    MigrationInterruptedError,
    MigrationManager,
    _canonical_legacy_key,
    archive_legacy_records,
    downgrade,
    migration_versions,
    recover,
    upgrade,
)
from common.job_state import JobStateService


def _valid_legacy_authorization_model(
    *,
    module_id: str = "module-a",
) -> tuple[
    AuthorizationDecisionModel,
    dict[str, object],
]:
    issued_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    confirmation = ActionConfirmation.create(
        job_id="legacy-job",
        target="fixture",
        engine="fixture",
        action="scan",
        issued_at=issued_at,
    )
    envelope: dict[str, object] = {
        "schema_version": AUTHORIZATION_SCHEMA_VERSION,
        "decision_id": "authz-legacy-valid",
        "parent_decision_id": "",
        "tenant_id": "legacy-tenant",
        "engagement_id": "legacy-engagement",
        "run_id": "legacy-run",
        "job_id": "legacy-job",
        "action_id": "action-legacy-valid",
        "operator_id": "legacy-operator",
        "operator_role": "operator",
        "action_kind": "scan",
        "engine": "fixture",
        "module_id": module_id,
        "requested_target": confirmation.target,
        "resolved_target": confirmation.target,
        "scope_snapshot": "sha256:" + "b" * 64,
        "scope_policy_version": "scope-v1",
        "scope_decision": "allowed",
        "scope_reason_code": "allowed",
        "scope_reason": "target is in scope",
        "safety_mode": "active",
        "credential_approval_required": False,
        "network_escalation_approval_required": False,
        "high_risk_approval_required": False,
        "credential_reference": "",
        "confirmation_method": "cli_flag",
        "confirmed_by": "legacy-operator",
        "confirmed_at": confirmation.issued_at,
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued_at + timedelta(seconds=60)).isoformat().replace(
            "+00:00", "Z"
        ),
        "decision_outcome": "allow",
        "reason_code": "allowed",
        "decision_reason": "authorization granted",
        "single_use": True,
    }
    envelope["binding_digest"] = compute_envelope_digest(envelope)
    typed = ActionAuthorizationEnvelope.from_value(envelope)
    model = AuthorizationDecisionModel(
        decision_id=typed.decision_id,
        schema_version=typed.schema_version,
        parent_decision_id=None,
        tenant_id=typed.tenant_id,
        engagement_id=typed.engagement_id,
        run_id=typed.run_id,
        job_id=typed.job_id,
        action_id=typed.action_id,
        operator_id=typed.operator_id,
        operator_role=typed.operator_role,
        action_kind=typed.action_kind,
        engine=typed.engine,
        module_id=typed.module_id,
        requested_target=typed.requested_target,
        resolved_target=typed.resolved_target,
        scope_snapshot=typed.scope_snapshot,
        scope_policy_version=typed.scope_policy_version,
        scope_decision=typed.scope_decision,
        scope_reason_code=typed.scope_reason_code,
        decision_outcome=typed.decision_outcome,
        reason_code=typed.reason_code,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=60),
        binding_digest=typed.binding_digest,
        confirmation_digest=confirmation.binding_digest,
        envelope_json=typed.to_json(),
        detail="{}",
        recorded_at=issued_at,
    )
    return model, envelope


def _legacy_execution_records(
    model: AuthorizationDecisionModel,
) -> tuple[AuthorizationConsumptionModel, AuthorizationExecutionClaimModel]:
    boundary = "dashboard.launch"
    return (
        AuthorizationConsumptionModel(
            consumption_id="consume-legacy-valid",
            decision_id=model.decision_id,
            tenant_id=model.tenant_id,
            job_id=model.job_id,
            action_id=model.action_id,
            boundary=boundary,
            result_id=model.action_id,
            envelope_digest=model.binding_digest,
            consumed_at=model.issued_at,
        ),
        AuthorizationExecutionClaimModel(
            claim_id="execute-legacy-valid",
            decision_id=model.decision_id,
            tenant_id=model.tenant_id,
            job_id=model.job_id,
            action_id=model.action_id,
            boundary=boundary,
            envelope_digest=model.binding_digest,
            claimed_at=model.issued_at,
        ),
    )


def test_task103_migration_downgrades_only_when_history_is_empty(
    tmp_path: Path,
) -> None:
    empty = create_db(tmp_path / "empty-task103.db")
    try:
        manager = MigrationManager(empty.get_bind())
        manager.downgrade(target=EVIDENCE_SCHEMA_VERSION)
        tables = {
            str(row[0])
            for row in empty.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            ).all()
        }
        assert "durable_job_state_jobs" not in tables
        assert empty.execute(
            text(
                "SELECT COUNT(*) FROM canonical_migration_journal "
                "WHERE version=:version AND state='applied'"
            ),
            {"version": JOB_STATE_SCHEMA_VERSION},
        ).scalar_one() == 0
        manager.upgrade(target=JOB_STATE_SCHEMA_VERSION)
        assert empty.execute(
            text(
                "SELECT COUNT(*) FROM canonical_migration_journal "
                "WHERE version=:version AND state='applied'"
            ),
            {"version": JOB_STATE_SCHEMA_VERSION},
        ).scalar_one() == 1
        attempt_columns = {
            str(row[1])
            for row in empty.execute(
                text("PRAGMA table_info(durable_job_state_attempts)")
            ).all()
        }
        assert "control_boot_id" in attempt_columns
        delivery_columns = {
            str(row[1])
            for row in empty.execute(
                text("PRAGMA table_info(durable_job_state_deliveries)")
            ).all()
        }
        assert {
            "manifest_digest",
            "outcome",
            "work_json",
            "run_truth_json",
        } <= delivery_columns
    finally:
        empty.close()

    retained_path = tmp_path / "retained-task103.db"
    service = JobStateService(
        retained_path,
        authorization_checker=lambda *_args: True,
    )
    try:
        created = service.create_job(job_id="retained-job")
    finally:
        service.close()
    retained = create_db(retained_path)
    try:
        manager = MigrationManager(retained.get_bind())
        with pytest.raises(
            MigrationError,
            match="would destroy retained history",
        ):
            manager.downgrade(target=EVIDENCE_SCHEMA_VERSION)
        assert retained.execute(
            text(
                "SELECT COUNT(*) FROM durable_job_state_jobs "
                "WHERE tenant_id='default' AND id=:job_id"
            ),
            {"job_id": created["id"]},
        ).scalar_one() == 1
    finally:
        retained.close()


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

        now = "2026-01-01T00:00:00Z"
        session.execute(
            text(
                "INSERT INTO canonical_tenants "
                "(id,schema_version,name,created_at,metadata_json) "
                "VALUES ('tenant-a',:schema,'Tenant A',:now,'{}')"
            ),
            {"schema": CURRENT_SCHEMA_VERSION, "now": now},
        )
        session.execute(
            text(
                "INSERT INTO canonical_engagements "
                "(id,tenant_id,project_id,schema_version,name,status,created_at,metadata_json) "
                "VALUES ('engagement-a','tenant-a',NULL,:schema,'Engagement A',"
                "'planned',:now,'{}')"
            ),
            {"schema": CURRENT_SCHEMA_VERSION, "now": now},
        )
        session.execute(
            text(
                "INSERT INTO canonical_reports "
                "(id,tenant_id,schema_version,name,version,status,created_by,created_at,metadata_json) "
                "VALUES ('report-a','tenant-a',:schema,'Report A',1,'draft',NULL,:now,'{}')"
            ),
            {"schema": CURRENT_SCHEMA_VERSION, "now": now},
        )
        session.commit()

        for statement in (
            "INSERT INTO canonical_engagements "
            "(id,tenant_id,project_id,schema_version,name,status,created_at,metadata_json) "
            "VALUES ('ghost-engagement','ghost',NULL,'forge-canonical-v1','Ghost','planned',"
            "'2026-01-01T00:00:00Z','{}')",
            "INSERT INTO canonical_reports "
            "(id,tenant_id,schema_version,name,version,status,created_by,created_at,metadata_json) "
            "VALUES ('ghost-report','ghost','forge-canonical-v1','Ghost',1,'draft',NULL,"
            "'2026-01-01T00:00:00Z','{}')",
            "UPDATE canonical_engagements SET tenant_id='ghost' WHERE id='engagement-a'",
            "UPDATE canonical_reports SET tenant_id='ghost' WHERE id='report-a'",
        ):
            with pytest.raises(IntegrityError):
                session.execute(text(statement))
                session.commit()
            session.rollback()

        invalid_metadata = (
            "not-json",
            "[]",
            json.dumps({"nested": {"findingId": "forged"}}),
            json.dumps({"nested": {"finding@id": "forged"}}),
            json.dumps({"nested": {"tenant_id[]": "forged"}}),
            json.dumps(
                {"nested": {"ｆｉｎｄｉｎｇ＿ｉｄ": "forged"}},
                ensure_ascii=False,
            ),
            json.dumps(
                {"nested": {"𝐟𝐢𝐧𝐝𝐢𝐧𝐠_𝐢𝐝": "forged"}},
                ensure_ascii=False,
            ),
            json.dumps({"value": "x" * 16_384}),
        )
        for index, metadata in enumerate(invalid_metadata):
            with pytest.raises(IntegrityError, match="metadata"):
                session.execute(
                    text(
                        "INSERT INTO canonical_tenants "
                        "(id,schema_version,name,created_at,metadata_json) "
                        "VALUES (:id,:schema,'Invalid metadata',:now,:metadata)"
                    ),
                    {
                        "id": f"invalid-metadata-{index}",
                        "schema": CURRENT_SCHEMA_VERSION,
                        "now": now,
                        "metadata": metadata,
                    },
                )
                session.commit()
            session.rollback()
        for relationship_key in (
            "job-id",
            "finding@id",
            "tenant_id[]",
            "ｆｉｎｄｉｎｇ＿ｉｄ",
            "𝐟𝐢𝐧𝐝𝐢𝐧𝐠_𝐢𝐝",
        ):
            with pytest.raises(IntegrityError, match="metadata"):
                session.execute(
                    text(
                        "UPDATE canonical_tenants SET metadata_json=:metadata "
                        "WHERE id='tenant-a'"
                    ),
                    {
                        "metadata": json.dumps(
                            {"nested": {relationship_key: "forged"}},
                            ensure_ascii=False,
                        )
                    },
                )
                session.commit()
            session.rollback()

        session.execute(
            text(
                "INSERT INTO canonical_intelligence_sources "
                "(id,tenant_id,schema_version,name,source_kind,created_at,metadata_json) "
                "VALUES ('source-a','tenant-a',:schema,'Source','feed',:now,'{}')"
            ),
            {"schema": CURRENT_SCHEMA_VERSION, "now": now},
        )
        for snapshot_id, digest in (
            ("feed-a", "sha256:" + "a" * 64),
            ("feed-b", "sha256:" + "b" * 64),
        ):
            session.execute(
                text(
                    "INSERT INTO canonical_feed_snapshots "
                    "(id,tenant_id,source_id,schema_version,version,digest,created_at,metadata_json) "
                    "VALUES (:id,'tenant-a','source-a',:schema,:id,:digest,:now,'{}')"
                ),
                {
                    "id": snapshot_id,
                    "schema": CURRENT_SCHEMA_VERSION,
                    "digest": digest,
                    "now": now,
                },
            )
        session.execute(
            text(
                "INSERT INTO canonical_provenance "
                "(id,tenant_id,source_type,source_id,digest,schema_version,created_at,metadata_json) "
                "VALUES ('provenance-b','tenant-a','feed_snapshot','feed-b',:digest,:schema,:now,'{}')"
            ),
            {
                "digest": "sha256:" + "b" * 64,
                "schema": CURRENT_SCHEMA_VERSION,
                "now": now,
            },
        )
        session.commit()
        with pytest.raises(IntegrityError, match="provenance snapshot"):
            session.execute(
                text(
                    "INSERT INTO canonical_module_versions "
                    "(id,tenant_id,schema_version,module_id,version,module_kind,"
                    "intelligence_snapshot_id,provenance_id,created_at,metadata_json) "
                    "VALUES ('module-bad','tenant-a',:schema,'fixture','1','fixture',"
                    "'feed-a','provenance-b',:now,'{}')"
                ),
                {"schema": CURRENT_SCHEMA_VERSION, "now": now},
            )
            session.commit()
        session.rollback()
        session.execute(
            text(
                "INSERT INTO canonical_module_versions "
                "(id,tenant_id,schema_version,module_id,version,module_kind,"
                "intelligence_snapshot_id,provenance_id,created_at,metadata_json) "
                "VALUES ('module-good','tenant-a',:schema,'fixture','1','fixture',"
                "'feed-b','provenance-b',:now,'{}')"
            ),
            {"schema": CURRENT_SCHEMA_VERSION, "now": now},
        )
        session.commit()

        snapshot_triggers = {
            "canonical_module_execution_snapshot_guard_insert",
            "canonical_module_execution_snapshot_guard_update",
            "canonical_observation_snapshot_guard_insert",
            "canonical_observation_snapshot_guard_update",
        }
        for trigger in snapshot_triggers:
            session.execute(text(f"DROP TRIGGER {trigger}"))
        session.commit()
        assert manager.upgrade() == CURRENT_SCHEMA_VERSION
        assert snapshot_triggers <= {
            str(row[0])
            for row in session.execute(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='trigger' AND name LIKE "
                    "'canonical_%_snapshot_guard_%'"
                )
            ).all()
        }
        session.execute(
            text(
                "INSERT INTO canonical_jobs "
                "(id,tenant_id,engagement_id,schema_version,job_kind,status,"
                "created_at,metadata_json) VALUES ('snapshot-job','tenant-a',"
                "'engagement-a',:schema,'fixture','planned',:now,'{}')"
            ),
            {"schema": CURRENT_SCHEMA_VERSION, "now": now},
        )
        session.execute(
            text(
                "INSERT INTO canonical_assets "
                "(id,tenant_id,schema_version,kind,identity_key,display_name,"
                "created_at,metadata_json) VALUES ('snapshot-asset','tenant-a',"
                ":schema,'host','snapshot.example','Snapshot asset',:now,'{}')"
            ),
            {"schema": CURRENT_SCHEMA_VERSION, "now": now},
        )
        session.commit()
        with pytest.raises(IntegrityError, match="module execution snapshot"):
            session.execute(
                text(
                    "INSERT INTO canonical_module_executions "
                    "(id,tenant_id,job_id,module_version_id,schema_version,status,"
                    "intelligence_snapshot_id,provenance_id,created_at,metadata_json) "
                    "VALUES ('snapshot-execution-bad','tenant-a','snapshot-job',"
                    "'module-good',:schema,'planned','feed-a','provenance-b',:now,'{}')"
                ),
                {"schema": CURRENT_SCHEMA_VERSION, "now": now},
            )
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError, match="observation snapshot"):
            session.execute(
                text(
                    "INSERT INTO canonical_observations "
                    "(id,tenant_id,engagement_id,job_id,module_version_id,asset_id,"
                    "intelligence_snapshot_id,provenance_id,schema_version,status,"
                    "observed_at,created_at,metadata_json) VALUES ("
                    "'snapshot-observation-bad','tenant-a','engagement-a',"
                    "'snapshot-job','module-good','snapshot-asset','feed-a',"
                    "'provenance-b',:schema,'observed',:now,:now,'{}')"
                ),
                {"schema": CURRENT_SCHEMA_VERSION, "now": now},
            )
            session.commit()
        session.rollback()
        session.execute(
            text(
                "INSERT INTO canonical_module_executions "
                "(id,tenant_id,job_id,module_version_id,schema_version,status,"
                "intelligence_snapshot_id,provenance_id,created_at,metadata_json) "
                "VALUES ('snapshot-execution-good','tenant-a','snapshot-job',"
                "'module-good',:schema,'planned','feed-b','provenance-b',:now,'{}')"
            ),
            {"schema": CURRENT_SCHEMA_VERSION, "now": now},
        )
        session.execute(
            text(
                "INSERT INTO canonical_observations "
                "(id,tenant_id,engagement_id,job_id,module_version_id,asset_id,"
                "intelligence_snapshot_id,provenance_id,schema_version,status,"
                "observed_at,created_at,metadata_json) VALUES ("
                "'snapshot-observation-good','tenant-a','engagement-a',"
                "'snapshot-job','module-good','snapshot-asset','feed-b',"
                "'provenance-b',:schema,'observed',:now,:now,'{}')"
            ),
            {"schema": CURRENT_SCHEMA_VERSION, "now": now},
        )
        session.commit()
        for table, row_id in (
            ("canonical_module_executions", "snapshot-execution-good"),
            ("canonical_observations", "snapshot-observation-good"),
        ):
            with pytest.raises(IntegrityError, match="snapshot"):
                session.execute(
                    text(
                        f"UPDATE {table} SET intelligence_snapshot_id='feed-a' "
                        "WHERE id=:id"
                    ),
                    {"id": row_id},
                )
                session.commit()
            session.rollback()

        engine = session.get_bind()
        with engine.connect() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS borrowed_transaction_sentinel "
                "(value TEXT NOT NULL)"
            )
            connection.commit()
            borrowed_manager = MigrationManager(connection)
            assert not connection.in_transaction()
            assert borrowed_manager.current_version() == CURRENT_SCHEMA_VERSION
            assert not connection.in_transaction()
            assert borrowed_manager.journal()
            assert not connection.in_transaction()
            assert borrowed_manager.upgrade() == CURRENT_SCHEMA_VERSION
            assert not connection.in_transaction()

            transaction = connection.begin()
            connection.exec_driver_sql(
                "INSERT INTO borrowed_transaction_sentinel(value) VALUES ('pending')"
            )
            assert borrowed_manager.current_version() == CURRENT_SCHEMA_VERSION
            assert borrowed_manager.journal()
            assert connection.in_transaction()
            with pytest.raises(MigrationError, match="borrowed active transaction"):
                archive_legacy_records(connection)
            for operation in (
                borrowed_manager.upgrade,
                borrowed_manager.downgrade,
                borrowed_manager.recover,
            ):
                with pytest.raises(
                    MigrationError,
                    match="borrowed active transaction",
                ):
                    operation()
            assert connection.in_transaction()
            transaction.rollback()
            assert connection.exec_driver_sql(
                "SELECT COUNT(*) FROM borrowed_transaction_sentinel"
            ).scalar_one() == 0

        def seed_snapshot_context(invalid_session: object) -> None:
            execute = getattr(invalid_session, "execute")
            execute(
                text(
                    "INSERT INTO canonical_tenants "
                    "(id,schema_version,name,created_at,metadata_json) "
                    "VALUES ('audit-tenant','forge-canonical-v1','Audit tenant',"
                    "'2026-01-01T00:00:00Z','{}')"
                )
            )
            execute(
                text(
                    "INSERT INTO canonical_intelligence_sources "
                    "(id,tenant_id,schema_version,name,source_kind,created_at,metadata_json) "
                    "VALUES ('audit-source','audit-tenant','forge-canonical-v1',"
                    "'Audit source','feed','2026-01-01T00:00:00Z','{}')"
                )
            )
            for snapshot_id, digest in (
                ("audit-feed-a", "sha256:" + "a" * 64),
                ("audit-feed-b", "sha256:" + "b" * 64),
            ):
                execute(
                    text(
                        "INSERT INTO canonical_feed_snapshots "
                        "(id,tenant_id,source_id,schema_version,version,digest,"
                        "created_at,metadata_json) VALUES (:id,'audit-tenant',"
                        "'audit-source','forge-canonical-v1',:id,:digest,"
                        "'2026-01-01T00:00:00Z','{}')"
                    ),
                    {"id": snapshot_id, "digest": digest},
                )

        for violation in (
            "ghost_engagement",
            "ghost_report",
            "relationship_metadata",
            "module_provenance",
            "execution_snapshot",
        ):
            invalid_session = create_db(tmp_path / f"existing-{violation}.db")
            try:
                invalid_manager = MigrationManager(invalid_session.get_bind())
                assert invalid_manager.downgrade() is None
                assert (
                    invalid_manager.upgrade(target=CURRENT_SCHEMA_VERSION)
                    == CURRENT_SCHEMA_VERSION
                )
                if violation == "ghost_engagement":
                    invalid_session.execute(
                        text(
                            "DROP TRIGGER canonical_engagement_tenant_guard_insert"
                        )
                    )
                    invalid_session.commit()
                    invalid_session.execute(text("PRAGMA foreign_keys=OFF"))
                    invalid_session.execute(
                        text(
                            "INSERT INTO canonical_engagements "
                            "(id,tenant_id,project_id,schema_version,name,status,"
                            "created_at,metadata_json) VALUES ('ghost-engagement',"
                            "'ghost-tenant',NULL,'forge-canonical-v1','Ghost',"
                            "'planned','2026-01-01T00:00:00Z','{}')"
                        )
                    )
                elif violation == "ghost_report":
                    invalid_session.execute(
                        text("DROP TRIGGER canonical_report_tenant_guard_insert")
                    )
                    invalid_session.commit()
                    invalid_session.execute(text("PRAGMA foreign_keys=OFF"))
                    invalid_session.execute(
                        text(
                            "INSERT INTO canonical_reports "
                            "(id,tenant_id,schema_version,name,version,status,"
                            "created_by,created_at,metadata_json) VALUES ("
                            "'ghost-report','ghost-tenant','forge-canonical-v1',"
                            "'Ghost',1,'draft',NULL,'2026-01-01T00:00:00Z','{}')"
                        )
                    )
                elif violation == "relationship_metadata":
                    invalid_session.execute(
                        text(
                            "DROP TRIGGER "
                            "canonical_metadata_integrity_guard_insert_canonical_tenants"
                        )
                    )
                    invalid_session.execute(
                        text(
                            "INSERT INTO canonical_tenants "
                            "(id,schema_version,name,created_at,metadata_json) "
                            "VALUES ('bad-metadata','forge-canonical-v1','Bad',"
                            "'2026-01-01T00:00:00Z',:metadata)"
                        ),
                        {
                            "metadata": json.dumps(
                                {"nested": {"finding_id": "forged"}}
                            )
                        },
                    )
                elif violation == "module_provenance":
                    invalid_session.execute(
                        text(
                            "DROP TRIGGER "
                            "canonical_module_version_provenance_guard_insert"
                        )
                    )
                    seed_snapshot_context(invalid_session)
                    invalid_session.execute(
                        text(
                            "INSERT INTO canonical_provenance "
                            "(id,tenant_id,source_type,source_id,digest,"
                            "schema_version,created_at,metadata_json) VALUES ("
                            "'audit-provenance','audit-tenant','feed_snapshot',"
                            "'audit-feed-b',:digest,'forge-canonical-v1',"
                            "'2026-01-01T00:00:00Z','{}')"
                        ),
                        {"digest": "sha256:" + "b" * 64},
                    )
                    invalid_session.execute(
                        text(
                            "INSERT INTO canonical_module_versions "
                            "(id,tenant_id,schema_version,module_id,version,"
                            "module_kind,intelligence_snapshot_id,provenance_id,"
                            "created_at,metadata_json) VALUES ('audit-module',"
                            "'audit-tenant','forge-canonical-v1','audit.module','1',"
                            "'fixture','audit-feed-a','audit-provenance',"
                            "'2026-01-01T00:00:00Z','{}')"
                        )
                    )
                else:
                    invalid_session.execute(
                        text(
                            "DROP TRIGGER "
                            "canonical_module_execution_snapshot_guard_insert"
                        )
                    )
                    seed_snapshot_context(invalid_session)
                    invalid_session.execute(
                        text(
                            "INSERT INTO canonical_engagements "
                            "(id,tenant_id,project_id,schema_version,name,status,"
                            "created_at,metadata_json) VALUES ('audit-engagement',"
                            "'audit-tenant',NULL,'forge-canonical-v1','Audit',"
                            "'planned','2026-01-01T00:00:00Z','{}')"
                        )
                    )
                    invalid_session.execute(
                        text(
                            "INSERT INTO canonical_jobs "
                            "(id,tenant_id,engagement_id,schema_version,job_kind,"
                            "status,created_at,metadata_json) VALUES ('audit-job',"
                            "'audit-tenant','audit-engagement','forge-canonical-v1',"
                            "'fixture','planned','2026-01-01T00:00:00Z','{}')"
                        )
                    )
                    invalid_session.execute(
                        text(
                            "INSERT INTO canonical_module_versions "
                            "(id,tenant_id,schema_version,module_id,version,"
                            "module_kind,intelligence_snapshot_id,created_at,"
                            "metadata_json) VALUES ('audit-module','audit-tenant',"
                            "'forge-canonical-v1','audit.module','1','fixture',"
                            "'audit-feed-a','2026-01-01T00:00:00Z','{}')"
                        )
                    )
                    invalid_session.execute(
                        text(
                            "INSERT INTO canonical_module_executions "
                            "(id,tenant_id,job_id,module_version_id,schema_version,"
                            "status,intelligence_snapshot_id,created_at,metadata_json) "
                            "VALUES ('audit-execution','audit-tenant','audit-job',"
                            "'audit-module','forge-canonical-v1','planned',"
                            "'audit-feed-b','2026-01-01T00:00:00Z','{}')"
                        )
                    )
                invalid_session.commit()
                invalid_session.execute(text("PRAGMA foreign_keys=ON"))
                invalid_session.commit()
                with pytest.raises(MigrationError, match="existing canonical"):
                    invalid_manager.upgrade()
                assert invalid_manager.current_version() == CURRENT_SCHEMA_VERSION
                assert invalid_session.execute(
                    text(
                        "SELECT COUNT(*) FROM canonical_migration_journal "
                        "WHERE version=:version"
                    ),
                    {"version": EVIDENCE_SCHEMA_VERSION},
                ).scalar_one() == 0
                assert invalid_session.execute(
                    text(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
                        "AND name='canonical_artifact_manifests'"
                    )
                ).scalar_one() == 0
                assert "dedup_key" not in {
                    str(row[1])
                    for row in invalid_session.execute(
                        text("PRAGMA table_info(canonical_findings)")
                    ).all()
                }
            finally:
                invalid_session.close()
    finally:
        session.close()


def test_targeted_v1_upgrade_does_not_apply_later_evidence_schema(
    tmp_path: Path,
) -> None:
    session = create_db(tmp_path / "target-boundary.db")
    try:
        manager = MigrationManager(session.get_bind())
        assert manager.downgrade() is None
        assert manager.upgrade(target=CURRENT_SCHEMA_VERSION) == CURRENT_SCHEMA_VERSION
        tables = {
            str(row[0])
            for row in session.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            ).all()
        }
        assert "canonical_observations" in tables
        assert "canonical_finding_observations" not in tables
        assert "canonical_artifact_manifests" not in tables
        columns = {
            str(row[1])
            for row in session.execute(
                text("PRAGMA table_info(canonical_findings)")
            ).all()
        }
        assert "dedup_key" not in columns
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


def test_direct_recover_reconciles_v2_and_preflights_invalid_v1(
    tmp_path: Path,
) -> None:
    session = create_db(tmp_path / "recover-v2.db")
    try:
        manager = MigrationManager(session.get_bind())
        assert manager.downgrade() is None
        assert manager.upgrade(target=CURRENT_SCHEMA_VERSION) == CURRENT_SCHEMA_VERSION
        with pytest.raises(MigrationInterruptedError):
            manager.upgrade(fail_after=0)
        assert {
            row["state"]
            for row in manager.journal()
            if row["version"] == EVIDENCE_SCHEMA_VERSION
        } == {"failed"}
        evidence_journal_before = [
            row
            for row in manager.journal()
            if row["version"] == EVIDENCE_SCHEMA_VERSION
        ]
        finding_columns_before_target = {
            str(row[1])
            for row in session.execute(
                text("PRAGMA table_info(canonical_findings)")
            ).all()
        }
        tables_before_target = {
            str(row[0])
            for row in session.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            ).all()
        }
        assert manager.upgrade(target=CURRENT_SCHEMA_VERSION) == CURRENT_SCHEMA_VERSION
        assert [
            row
            for row in manager.journal()
            if row["version"] == EVIDENCE_SCHEMA_VERSION
        ] == evidence_journal_before
        assert {
            str(row[1])
            for row in session.execute(
                text("PRAGMA table_info(canonical_findings)")
            ).all()
        } == finding_columns_before_target
        assert {
            str(row[0])
            for row in session.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            ).all()
        } == tables_before_target
        assert manager.recover() == CURRENT_SCHEMA_VERSION
        assert {
            str(row[1])
            for row in session.execute(
                text("PRAGMA table_info(canonical_artifact_refs)")
            ).all()
        } >= {"collector_id", "integrity_state", "protection_state"}
        assert {
            row["state"]
            for row in manager.journal()
            if row["version"] == EVIDENCE_SCHEMA_VERSION
        } == {"applied"}
    finally:
        session.close()

    invalid = create_db(tmp_path / "recover-invalid-v1.db")
    try:
        manager = MigrationManager(invalid.get_bind())
        assert manager.downgrade() is None
        assert manager.upgrade(target=CURRENT_SCHEMA_VERSION) == CURRENT_SCHEMA_VERSION
        invalid.execute(
            text(
                "DROP TRIGGER "
                "canonical_metadata_integrity_guard_insert_canonical_tenants"
            )
        )
        invalid.execute(
            text(
                "INSERT INTO canonical_tenants "
                "(id,schema_version,name,created_at,metadata_json) VALUES "
                "('invalid-v1','forge-canonical-v1','Invalid',"
                "'2026-01-01T00:00:00Z',:metadata)"
            ),
            {"metadata": json.dumps({"nested": {"findingId": "forged"}})},
        )
        invalid.execute(
            text(
                "INSERT INTO canonical_migration_journal "
                "(version,state,started_at,detail) VALUES "
                "(:version,'failed','2026-01-01T00:00:00Z','{}')"
            ),
            {"version": EVIDENCE_SCHEMA_VERSION},
        )
        invalid.commit()
        with pytest.raises(MigrationError, match="existing canonical metadata"):
            manager.recover()
        assert invalid.execute(
            text(
                "SELECT state FROM canonical_migration_journal WHERE version=:version"
            ),
            {"version": EVIDENCE_SCHEMA_VERSION},
        ).scalar_one() == "failed"
        assert invalid.execute(
            text(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
                "AND name='canonical_artifact_manifests'"
            )
        ).scalar_one() == 0
        assert "dedup_key" not in {
            str(row[1])
            for row in invalid.execute(
                text("PRAGMA table_info(canonical_findings)")
            ).all()
        }
    finally:
        invalid.close()


def test_target_v1_ignores_stray_partial_v2_tables_for_legacy_finding(
    tmp_path: Path,
) -> None:
    session = create_db(tmp_path / "stray-v2.db")
    try:
        session.add(
            FindingModel(
                id="legacy-stray",
                tenant_id="legacy-tenant",
                title="legacy",
                severity="High",
                target="fixture",
                module="old",
                description="legacy",
            )
        )
        session.commit()
        manager = MigrationManager(session.get_bind())
        assert manager.downgrade() is None
        assert manager.upgrade(target=CURRENT_SCHEMA_VERSION) == CURRENT_SCHEMA_VERSION
        session.execute(
            text(
                "CREATE TABLE canonical_finding_observations ("
                "tenant_id TEXT,finding_id TEXT,observation_id TEXT,"
                "artifact_id TEXT,metadata_json TEXT NOT NULL DEFAULT '{}')"
            )
        )
        session.execute(
            text(
                "CREATE TABLE canonical_artifact_manifests ("
                "id TEXT,tenant_id TEXT,artifact_id TEXT,observation_id TEXT,"
                "source_asset_id TEXT,sha256 TEXT,derivative_sha256 TEXT,"
                "manifest_digest TEXT,metadata_json TEXT NOT NULL DEFAULT '{}')"
            )
        )
        session.commit()
        assert archive_legacy_records(session.get_bind()) == 0
        assert session.execute(
            text("SELECT COUNT(*) FROM canonical_findings")
        ).scalar_one() == 0
        assert manager.upgrade(target=CURRENT_SCHEMA_VERSION) == CURRENT_SCHEMA_VERSION
        assert session.execute(
            text("SELECT COUNT(*) FROM canonical_findings")
        ).scalar_one() == 0
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
        assert normalized == ["unknown"]
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

    valid_session = create_db(tmp_path / "valid-authorization.db")
    try:
        model, _envelope = _valid_legacy_authorization_model()
        valid_session.add(model)
        valid_session.add_all(_legacy_execution_records(model))
        valid_session.add(
            ScanJobModel(
                id="legacy-job",
                tenant_id="legacy-tenant",
                target="fixture",
                frameworks=json.dumps(["fixture"]),
                modules=json.dumps(["module-a"]),
                status="completed",
                authorization_state="allow",
                authorization_decision_id=model.decision_id,
                authorization_action_id=model.action_id,
            )
        )
        valid_session.commit()
        manager = MigrationManager(valid_session.get_bind())
        manager.downgrade()
        manager.upgrade()
        assert archive_legacy_records(valid_session.get_bind()) == 0
        assert archive_legacy_records(valid_session.get_bind()) == 0
        assert valid_session.execute(
            text("SELECT outcome FROM canonical_scope_decisions")
        ).scalar_one() == "allow"
        assert {
            row[0]
            for row in valid_session.execute(
                text(
                    "SELECT record_kind FROM canonical_legacy_records "
                    "WHERE record_kind LIKE 'authorization_%'"
                )
            ).all()
        } == {"authorization_consumption", "authorization_execution_claim"}
        assert valid_session.execute(
            text("SELECT status FROM canonical_jobs WHERE id LIKE 'legacy-job-%'")
        ).scalar_one() == "completed"
    finally:
        valid_session.close()

    module_set_session = create_db(tmp_path / "valid-module-set-authorization.db")
    try:
        model, _envelope = _valid_legacy_authorization_model(
            module_id=module_set_binding(["module-b", "module-a"])
        )
        module_set_session.add(model)
        module_set_session.add_all(_legacy_execution_records(model))
        module_set_session.add(
            ScanJobModel(
                id="legacy-job",
                tenant_id="legacy-tenant",
                target="fixture",
                frameworks=json.dumps(["fixture"]),
                modules=json.dumps(["module-a", "module-b"]),
                status="completed",
                authorization_state="allow",
                authorization_decision_id=model.decision_id,
                authorization_action_id=model.action_id,
            )
        )
        module_set_session.commit()
        manager = MigrationManager(module_set_session.get_bind())
        manager.downgrade()
        manager.upgrade()
        assert module_set_session.execute(
            text("SELECT outcome FROM canonical_scope_decisions")
        ).scalar_one() == "allow"
        assert module_set_session.execute(
            text("SELECT status FROM canonical_jobs WHERE id LIKE 'legacy-job-%'")
        ).scalar_one() == "completed"
    finally:
        module_set_session.close()

    for mutation in (
        "job_state",
        "job_decision",
        "job_action",
        "target",
        "module",
        "engine",
        "module_set_mismatch",
        "consumption_decision",
        "consumption_tenant",
        "consumption_job",
        "consumption_action",
        "consumption_digest",
        "consumption_boundary",
        "consumption_empty_boundary",
        "consumption_result",
        "consumption_before_issued",
        "consumption_after_expiry",
        "claim_decision",
        "claim_tenant",
        "claim_job",
        "claim_action",
        "claim_digest",
        "claim_boundary",
        "claim_empty_boundary",
        "claim_before_consumption",
        "claim_after_expiry",
        "missing_consumption",
        "missing_claim",
        "duplicate_consumption",
        "duplicate_claim",
    ):
        mismatch_session = create_db(tmp_path / f"legacy-mismatch-{mutation}.db")
        try:
            module_set_case = mutation == "module_set_mismatch"
            model, _envelope = _valid_legacy_authorization_model(
                module_id=(
                    module_set_binding(["module-a", "module-b"])
                    if module_set_case
                    else "module-a"
                )
            )
            consumption, claim = _legacy_execution_records(model)
            job_values: dict[str, object] = {
                "id": "legacy-job",
                "tenant_id": "legacy-tenant",
                "target": "fixture",
                "frameworks": json.dumps(["fixture"]),
                "modules": json.dumps(
                    ["module-a", "module-b"] if module_set_case else ["module-a"]
                ),
                "status": "completed",
                "authorization_state": "allow",
                "authorization_decision_id": model.decision_id,
                "authorization_action_id": model.action_id,
            }
            if mutation == "job_state":
                job_values["authorization_state"] = "unknown_not_authorized"
            elif mutation == "job_decision":
                job_values["authorization_decision_id"] = "other-decision"
            elif mutation == "job_action":
                job_values["authorization_action_id"] = "other-action"
            elif mutation == "target":
                job_values["target"] = "different.example"
            elif mutation == "module":
                job_values["modules"] = json.dumps(["module-b"])
            elif mutation == "engine":
                job_values["frameworks"] = json.dumps(["other-engine"])
            elif mutation == "module_set_mismatch":
                job_values["modules"] = json.dumps(["module-a", "module-c"])
            elif mutation == "consumption_decision":
                consumption.decision_id = "other-decision"
            elif mutation == "consumption_tenant":
                consumption.tenant_id = "other-tenant"
            elif mutation == "consumption_job":
                consumption.job_id = "other-job"
            elif mutation == "consumption_action":
                consumption.action_id = "other-action"
            elif mutation == "consumption_digest":
                consumption.envelope_digest = "sha256:" + "0" * 64
            elif mutation == "consumption_boundary":
                consumption.boundary = "other.boundary"
            elif mutation == "consumption_empty_boundary":
                consumption.boundary = ""
            elif mutation == "consumption_result":
                consumption.result_id = "other-result"
            elif mutation == "consumption_before_issued":
                consumption.consumed_at = model.issued_at - timedelta(seconds=1)
            elif mutation == "consumption_after_expiry":
                consumption.consumed_at = model.expires_at + timedelta(seconds=1)
                claim.claimed_at = consumption.consumed_at
            elif mutation == "claim_decision":
                claim.decision_id = "other-decision"
            elif mutation == "claim_tenant":
                claim.tenant_id = "other-tenant"
            elif mutation == "claim_job":
                claim.job_id = "other-job"
            elif mutation == "claim_action":
                claim.action_id = "other-action"
            elif mutation == "claim_digest":
                claim.envelope_digest = "sha256:" + "0" * 64
            elif mutation == "claim_boundary":
                claim.boundary = "other.boundary"
            elif mutation == "claim_empty_boundary":
                claim.boundary = ""
            elif mutation == "claim_before_consumption":
                consumption.consumed_at = model.issued_at + timedelta(seconds=1)
                claim.claimed_at = model.issued_at
            elif mutation == "claim_after_expiry":
                claim.claimed_at = model.expires_at + timedelta(seconds=1)

            mismatch_session.add(model)
            if mutation != "missing_consumption":
                mismatch_session.add(consumption)
            if mutation != "missing_claim":
                mismatch_session.add(claim)
            mismatch_session.add(ScanJobModel(**job_values))
            mismatch_session.commit()
            if mutation in {"duplicate_consumption", "duplicate_claim"}:
                if mutation == "duplicate_consumption":
                    table = "authorization_consumptions"
                    duplicate_id = "consume-legacy-duplicate"
                    columns = (
                        "sequence INTEGER PRIMARY KEY,consumption_id VARCHAR(64) NOT NULL,"
                        "decision_id VARCHAR(64) NOT NULL,tenant_id VARCHAR(100) NOT NULL,"
                        "job_id VARCHAR(160) NOT NULL,action_id VARCHAR(64) NOT NULL,"
                        "boundary VARCHAR(160) NOT NULL,result_id VARCHAR(160) NOT NULL,"
                        "envelope_digest VARCHAR(80) NOT NULL,consumed_at DATETIME NOT NULL"
                    )
                else:
                    table = "authorization_execution_claims"
                    duplicate_id = "execute-legacy-duplicate"
                    columns = (
                        "sequence INTEGER PRIMARY KEY,claim_id VARCHAR(64) NOT NULL,"
                        "decision_id VARCHAR(64) NOT NULL,tenant_id VARCHAR(100) NOT NULL,"
                        "job_id VARCHAR(160) NOT NULL,action_id VARCHAR(64) NOT NULL,"
                        "boundary VARCHAR(160) NOT NULL,envelope_digest VARCHAR(80) NOT NULL,"
                        "claimed_at DATETIME NOT NULL"
                    )
                source = f"{table}_source"
                mismatch_session.execute(
                    text(f"DROP TRIGGER IF EXISTS {table}_no_update")
                )
                mismatch_session.execute(
                    text(f"DROP TRIGGER IF EXISTS {table}_no_delete")
                )
                mismatch_session.execute(text(f"ALTER TABLE {table} RENAME TO {source}"))
                mismatch_session.execute(text(f"CREATE TABLE {table} ({columns})"))
                mismatch_session.execute(text(f"INSERT INTO {table} SELECT * FROM {source}"))
                mismatch_session.execute(
                    text(
                            f"INSERT INTO {table} SELECT NULL,:duplicate_id,"
                        + ",".join(
                            column
                            for column in (
                                "decision_id",
                                "tenant_id",
                                "job_id",
                                "action_id",
                                "boundary",
                                *(
                                    ("result_id",)
                                    if mutation == "duplicate_consumption"
                                    else ()
                                ),
                                "envelope_digest",
                                "consumed_at"
                                if mutation == "duplicate_consumption"
                                else "claimed_at",
                            )
                        )
                        + f" FROM {source} LIMIT 1"
                    ),
                    {"duplicate_id": duplicate_id},
                )
                mismatch_session.execute(text(f"DROP TABLE {source}"))
                mismatch_session.commit()
            manager = MigrationManager(mismatch_session.get_bind())
            manager.downgrade()
            manager.upgrade()
            assert mismatch_session.execute(
                text("SELECT status FROM canonical_jobs WHERE id LIKE 'legacy-job-%'")
            ).scalar_one() == "unknown_not_authorized"
            assert mismatch_session.execute(
                text("SELECT status FROM canonical_observations")
            ).scalar_one() == "not_authorized"
        finally:
            mismatch_session.close()

    archive_session = create_db(tmp_path / "finding-archive-only.db")
    try:
        archive_session.add(
            FindingModel(
                id="legacy-finding",
                tenant_id="legacy-tenant",
                title="old",
                severity="High",
                target="fixture",
                module="old",
                description="legacy",
            )
        )
        archive_session.commit()
        manager = MigrationManager(archive_session.get_bind())
        manager.downgrade()
        manager.upgrade(target=CURRENT_SCHEMA_VERSION)
        assert archive_session.execute(
            text(
                "SELECT COUNT(*) FROM canonical_legacy_records "
                "WHERE record_kind='finding' AND claim_state='reduced'"
            )
        ).scalar_one() == 1
        for table in (
            "canonical_jobs",
            "canonical_assets",
            "canonical_observations",
            "canonical_artifact_refs",
            "canonical_findings",
        ):
            assert archive_session.execute(
                text(f"SELECT COUNT(*) FROM {table}")
            ).scalar_one() == 0
        manager.upgrade()
        finding = archive_session.execute(
            text(
                "SELECT status,dedup_key FROM canonical_findings "
                "WHERE id LIKE 'legacy-finding-%'"
            )
        ).mappings().one()
        assert finding == {"status": "unknown", "dedup_key": None}
        artifact = archive_session.execute(
            text(
                "SELECT digest,integrity_state,protection_state "
                "FROM canonical_artifact_refs WHERE id LIKE 'legacy-artifact-%'"
            )
        ).mappings().one()
        assert artifact == {
            "digest": None,
            "integrity_state": "unknown",
            "protection_state": "legacy_unknown",
        }
        source_link = archive_session.execute(
            text(
                "SELECT identity_key,first_seen_at,last_seen_at,metadata_json "
                "FROM canonical_finding_observations"
            )
        ).mappings().one()
        assert source_link["identity_key"] == "finding-v1:legacy"
        assert source_link["first_seen_at"] == source_link["last_seen_at"]
        assert json.loads(source_link["metadata_json"])["legacy"] is True
        migrated_finding_id = archive_session.execute(
            text("SELECT id FROM canonical_findings")
        ).scalar_one()
        migrated_artifact_id = archive_session.execute(
            text("SELECT id FROM canonical_artifact_refs")
        ).scalar_one()
        manifest_digest = "sha256:" + "d" * 64
        with pytest.raises(IntegrityError):
            archive_session.execute(
                text(
                    "UPDATE canonical_artifact_refs SET manifest_digest=:digest "
                    "WHERE id=:id"
                ),
                {
                    "digest": "sha256:" + "g" * 64,
                    "id": migrated_artifact_id,
                },
            )
        archive_session.rollback()
        assert archive_session.execute(
            text(
                "SELECT manifest_digest FROM canonical_artifact_refs WHERE id=:id"
            ),
            {"id": migrated_artifact_id},
        ).scalar_one() is None
        archive_session.execute(
            text(
                "UPDATE canonical_findings SET title='Triaged title',"
                "severity='medium',description='Triaged description',status='open',"
                "metadata_json=:metadata WHERE id=:id"
            ),
            {"id": migrated_finding_id, "metadata": json.dumps({"triaged": True})},
        )
        archive_session.execute(
            text(
                "UPDATE canonical_artifact_refs SET manifest_digest=:digest "
                "WHERE id=:id"
            ),
            {"digest": manifest_digest, "id": migrated_artifact_id},
        )
        archive_session.commit()
        assert archive_legacy_records(archive_session.get_bind()) == 0
        replayed_finding = archive_session.execute(
            text(
                "SELECT title,severity,description,status,metadata_json "
                "FROM canonical_findings WHERE id=:id"
            ),
            {"id": migrated_finding_id},
        ).mappings().one()
        assert replayed_finding["title"] == "Triaged title"
        assert replayed_finding["severity"] == "medium"
        assert replayed_finding["description"] == "Triaged description"
        assert replayed_finding["status"] == "open"
        assert json.loads(replayed_finding["metadata_json"])["triaged"] is True
        assert archive_session.execute(
            text(
                "SELECT manifest_digest FROM canonical_artifact_refs WHERE id=:id"
            ),
            {"id": migrated_artifact_id},
        ).scalar_one() == manifest_digest
        archive_session.execute(
            text("DROP TRIGGER canonical_finding_observations_no_update")
        )
        archive_session.execute(
            text(
                "UPDATE canonical_finding_observations "
                "SET identity_key='triaged-link-mismatch'"
            )
        )
        archive_session.commit()
        with pytest.raises(MigrationError, match="finding (?:observation|source link)"):
            manager.upgrade()
        assert archive_session.execute(
            text("SELECT identity_key FROM canonical_finding_observations")
        ).scalar_one() == "triaged-link-mismatch"
    finally:
        archive_session.close()


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


def test_old_six_column_source_links_are_enriched_and_collision_checked(
    tmp_path: Path,
) -> None:
    session = create_db(tmp_path / "six-column-links.db")
    try:
        session.add(
            FindingModel(
                id="legacy-six-column",
                tenant_id="legacy-tenant",
                title="old",
                severity="High",
                target="fixture",
                module="old",
                description="legacy",
            )
        )
        session.commit()
        manager = MigrationManager(session.get_bind())
        assert manager.downgrade() is None
        assert manager.upgrade() == CURRENT_SCHEMA_VERSION
        original = session.execute(
            text(
                "SELECT tenant_id,finding_id,observation_id,artifact_id,"
                "created_at,metadata_json FROM canonical_finding_observations"
            )
        ).mappings().one()
        for trigger in (
            "canonical_finding_observations_no_update",
            "canonical_finding_observations_no_delete",
            "canonical_finding_observations_append_only_update",
            "canonical_finding_observations_append_only_delete",
        ):
            session.execute(text(f"DROP TRIGGER IF EXISTS {trigger}"))
        session.execute(text("DROP TABLE canonical_finding_observations"))
        session.execute(
            text(
                "CREATE TABLE canonical_finding_observations ("
                "tenant_id TEXT NOT NULL,finding_id TEXT NOT NULL,"
                "observation_id TEXT NOT NULL,artifact_id TEXT,"
                "created_at TEXT NOT NULL,metadata_json TEXT NOT NULL DEFAULT '{}',"
                "PRIMARY KEY(tenant_id,finding_id,observation_id))"
            )
        )
        session.execute(
            text(
                "INSERT INTO canonical_finding_observations "
                "(tenant_id,finding_id,observation_id,artifact_id,created_at,metadata_json) "
                "VALUES (:tenant_id,:finding_id,:observation_id,:artifact_id,"
                ":created_at,:metadata_json)"
            ),
            dict(original),
        )
        session.commit()
        assert manager.upgrade() == CURRENT_SCHEMA_VERSION
        enriched = session.execute(
            text(
                "SELECT artifact_id,identity_key,first_seen_at,last_seen_at,"
                "created_at,metadata_json FROM canonical_finding_observations"
            )
        ).mappings().one()
        assert enriched["artifact_id"] == original["artifact_id"]
        assert enriched["identity_key"] == "finding-v1:legacy"
        assert enriched["first_seen_at"] == original["created_at"]
        assert enriched["last_seen_at"] == original["created_at"]
        assert enriched["metadata_json"] == original["metadata_json"]

        session.execute(
            text("DROP TRIGGER canonical_finding_observations_no_update")
        )
        session.execute(
            text(
                "UPDATE canonical_finding_observations "
                "SET identity_key='preoccupied-mismatch'"
            )
        )
        session.commit()
        with pytest.raises(MigrationError, match="finding observation"):
            archive_legacy_records(session.get_bind())
        assert session.execute(
            text("SELECT identity_key FROM canonical_finding_observations")
        ).scalar_one() == "preoccupied-mismatch"
    finally:
        session.close()


def test_legacy_v2_identity_and_custody_collisions_fail_replay(
    tmp_path: Path,
) -> None:
    for mutation in ("finding_dedup", "observation_proof", "artifact_collector"):
        session = create_db(tmp_path / f"legacy-v2-collision-{mutation}.db")
        try:
            session.add(
                FindingModel(
                    id=f"legacy-{mutation}",
                    tenant_id="legacy-tenant",
                    title="old",
                    severity="High",
                    target="fixture",
                    module="old",
                    description="legacy",
                )
            )
            session.commit()
            manager = MigrationManager(session.get_bind())
            assert manager.downgrade() is None
            assert manager.upgrade() == CURRENT_SCHEMA_VERSION
            if mutation == "finding_dedup":
                session.execute(
                    text("DROP TRIGGER canonical_findings_identity_guard_update")
                )
                session.execute(
                    text("UPDATE canonical_findings SET dedup_key=:dedup_key"),
                    {"dedup_key": "finding-v1:" + "a" * 64},
                )
            elif mutation == "observation_proof":
                session.execute(
                    text(
                        "DROP TRIGGER "
                        "canonical_observations_append_only_update"
                    )
                )
                session.execute(
                    text(
                        "DROP TRIGGER "
                        "canonical_observations_custody_immutable_update"
                    )
                )
                session.execute(
                    text(
                        "UPDATE canonical_observations SET proof_type='verified'"
                    )
                )
            else:
                session.execute(
                    text(
                        "DROP TRIGGER "
                        "canonical_artifact_refs_append_only_update"
                    )
                )
                session.execute(
                    text(
                        "DROP TRIGGER "
                        "canonical_artifact_refs_custody_immutable_update"
                    )
                )
                session.execute(
                    text(
                        "UPDATE canonical_artifact_refs "
                        "SET collector_id='foreign-collector'"
                    )
                )
            session.commit()
            with pytest.raises(MigrationError, match="collides"):
                archive_legacy_records(session.get_bind())
        finally:
            session.close()



@pytest.mark.parametrize(
    "tampered_link_metadata",
    (
        {"legacy": 1, "integrity_state": "unknown"},
        {"integrity_state": "unknown"},
    ),
    ids=("boolean-to-integer", "marker-removed"),
)
def test_legacy_link_marker_type_confusion_fails_after_finding_triage(
    tmp_path: Path,
    tampered_link_metadata: dict[str, object],
) -> None:
    session = create_db(tmp_path / "legacy-link-marker-type.db")
    try:
        session.add(
            FindingModel(
                id="legacy-marker-type",
                tenant_id="legacy-tenant",
                title="old",
                severity="High",
                target="fixture",
                module="old",
                description="legacy",
            )
        )
        session.commit()
        manager = MigrationManager(session.get_bind())
        assert manager.downgrade() is None
        assert manager.upgrade() == CURRENT_SCHEMA_VERSION
        session.execute(
            text(
                "UPDATE canonical_findings SET metadata_json=:metadata"
            ),
            {"metadata": json.dumps({"triaged": True})},
        )
        session.execute(
            text("DROP TRIGGER canonical_finding_observations_no_update")
        )
        session.execute(
            text(
                "UPDATE canonical_finding_observations SET metadata_json=:metadata"
            ),
            {"metadata": json.dumps(tampered_link_metadata)},
        )
        session.commit()
        with pytest.raises(MigrationError, match="collides"):
            manager.upgrade()
        assert json.loads(
            session.execute(
                text(
                    "SELECT metadata_json FROM canonical_finding_observations"
                )
            ).scalar_one()
        ) == tampered_link_metadata
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


def test_task102_legacy_evidence_migrates_available_bytes_and_keeps_unknown_paths(
    tmp_path: Path,
) -> None:
    from common.canonical_evidence import CanonicalEvidenceReader
    from common.evidence_custody import make_original_authorization
    from common.redaction import clear_sensitive_values, register_sensitive_values

    request_canary = "CANARY_LEGACY_MIGRATION_REQUEST"
    response_canary = "CANARY_LEGACY_MIGRATION_RESPONSE"
    screenshot_canary = b"CANARY_LEGACY_MIGRATION_SCREENSHOT"
    nested_canary = "CANARY_LEGACY_MIGRATION_NESTED"
    unavailable_canary = b"CANARY_LEGACY_MIGRATION_UNAVAILABLE"
    register_sensitive_values(
        (request_canary, response_canary, nested_canary)
    )
    screenshot = tmp_path / "legacy-shot.png"
    screenshot.write_bytes(screenshot_canary)
    screenshot.chmod(0o600)
    outside = tmp_path / "legacy-outside.pcap"
    outside.write_bytes(unavailable_canary)
    outside.chmod(0o600)
    linked = tmp_path / "legacy-linked.pcap"
    linked.symlink_to(outside)

    session = create_db(tmp_path / "legacy-evidence.db")
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
                request_raw=f"GET /?password={request_canary} HTTP/1.1",
                response_raw=f"HTTP/1.1 200 OK\n\n{response_canary}",
                screenshot_path=str(screenshot),
                console_capture_path=str(tmp_path / "missing-console.html"),
                pcap_path=str(linked),
                verification=json.dumps(
                    {"nested": {"request_raw": nested_canary}}
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
        assert "CANARY" not in str(mutable["verification"])

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
        # One unknown placeholder plus four verifiably available payloads.
        assert counts == {"refs": 5, "manifests": 4, "links": 4}
        unknown = session.execute(
            text(
                "SELECT digest,integrity_state,protection_state "
                "FROM canonical_artifact_refs WHERE tenant_id=:tenant_id "
                "AND digest IS NULL"
            ),
            {"tenant_id": tenant_id},
        ).mappings().one()
        assert unknown == {
            "digest": None,
            "integrity_state": "unknown",
            "protection_state": "legacy_unknown",
        }

        reader = CanonicalEvidenceReader(
            session,
            tmp_path / "evidence-custody",
            tenant_id,
            audit_actor_id="operator:legacy-review",
            expected_original_operator_id="operator:legacy-review",
        )
        projection = reader.get_finding_projection(finding_id)
        assert projection is not None
        rendered = json.dumps(projection, sort_keys=True)
        assert request_canary not in rendered
        assert response_canary not in rendered
        assert nested_canary not in rendered
        assert unavailable_canary.decode("ascii") not in rendered
        artifacts = projection["evidence"]["observations"][0]["artifacts"]
        assert len(artifacts) == 4

        screenshot_artifact = next(
            artifact
            for artifact in artifacts
            if artifact["capture_kind"] == "screenshot_path"
        )
        binding = session.execute(
            text(
                "SELECT protected_original_authorization_ref "
                "FROM canonical_artifact_refs WHERE tenant_id=:tenant_id AND id=:artifact_id"
            ),
            {
                "tenant_id": tenant_id,
                "artifact_id": screenshot_artifact["artifact_id"],
            },
        ).scalar_one()
        session.rollback()
        authorization = make_original_authorization(
            tenant_id=tenant_id,
            artifact_id=screenshot_artifact["artifact_id"],
            authorization_ref=binding,
            operator_id="operator:legacy-review",
            reason="verify protected migration fixture",
        )
        assert reader.read_protected_original(
            screenshot_artifact["artifact_id"], authorization
        ) == screenshot_canary
        assert session.execute(
            text(
                "SELECT COUNT(*) FROM canonical_evidence_access_audit "
                "WHERE tenant_id=:tenant_id AND access_kind='protected_original'"
            ),
            {"tenant_id": tenant_id},
        ).scalar_one() == 1
        session.rollback()

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
        assert session.execute(
            text(
                "SELECT COUNT(*) FROM canonical_artifact_manifests "
                "WHERE tenant_id=:tenant_id"
            ),
            {"tenant_id": tenant_id},
        ).scalar_one() == 4
    finally:
        clear_sensitive_values()
        session.close()


def test_task102_legacy_evidence_database_failure_compensates_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import common.schema_migrations as migrations

    session = create_db(tmp_path / "legacy-compensation.db")
    try:
        manager = MigrationManager(session.get_bind())
        assert manager.downgrade(target=CURRENT_SCHEMA_VERSION) == CURRENT_SCHEMA_VERSION
        session.add(
            FindingModel(
                id="legacy-compensation-finding",
                tenant_id="legacy-compensation-tenant",
                title="Legacy compensation",
                severity="High",
                target="fixture.invalid",
                module="legacy-module",
                description="Legacy evidence compensation fixture",
                request_raw="CANARY_LEGACY_COMPENSATION",
            )
        )
        session.commit()

        original_insert = migrations._insert_or_validate_legacy

        def fail_manifest(*args, **kwargs):
            table = args[1] if len(args) > 1 else kwargs.get("table")
            if table == "canonical_artifact_manifests":
                raise MigrationError("injected legacy manifest failure")
            return original_insert(*args, **kwargs)

        with monkeypatch.context() as scoped:
            scoped.setattr(migrations, "_insert_or_validate_legacy", fail_manifest)
            with pytest.raises(MigrationError, match="injected legacy manifest"):
                manager.upgrade()

        session.rollback()
        assert session.execute(
            text(
                "SELECT request_raw FROM findings "
                "WHERE id='legacy-compensation-finding'"
            )
        ).scalar_one() == "CANARY_LEGACY_COMPENSATION"
        assert session.execute(
            text("SELECT COUNT(*) FROM canonical_artifact_manifests")
        ).scalar_one() == 0
        custody_files = [
            path
            for path in (tmp_path / "evidence-custody").rglob("*")
            if path.is_file()
        ]
        assert custody_files == []
        session.rollback()

        assert manager.upgrade() == CURRENT_SCHEMA_VERSION
        assert session.execute(
            text(
                "SELECT request_raw FROM findings "
                "WHERE id='legacy-compensation-finding'"
            )
        ).scalar_one() is None
        assert session.execute(
            text("SELECT COUNT(*) FROM canonical_artifact_manifests")
        ).scalar_one() == 1
    finally:
        session.close()


def test_task102_legacy_unavailable_evidence_has_read_only_projection(
    tmp_path: Path,
) -> None:
    from common.canonical_evidence import CanonicalEvidenceReader

    session = create_db(tmp_path / "legacy-unavailable-evidence.db")
    try:
        manager = MigrationManager(session.get_bind())
        assert manager.downgrade(target=CURRENT_SCHEMA_VERSION) == CURRENT_SCHEMA_VERSION
        session.add(
            FindingModel(
                id="legacy-unavailable-finding",
                tenant_id="legacy-unavailable-tenant",
                title="Legacy unavailable evidence",
                severity="Medium",
                target="fixture.invalid",
                module="legacy-module",
                description="Legacy finding without available evidence bytes",
            )
        )
        session.commit()

        assert manager.upgrade() == CURRENT_SCHEMA_VERSION
        tenant_id = _canonical_legacy_key(
            "legacy-unavailable-tenant",
            kind="tenant",
            tenant_id="forge-legacy",
        )
        finding_id = _canonical_legacy_key(
            "legacy-unavailable-finding",
            kind="finding",
            tenant_id=tenant_id,
        )
        custody_root = tmp_path / "evidence-custody"
        assert custody_root.is_dir()
        assert custody_root.stat().st_mode & 0o077 == 0

        projection = CanonicalEvidenceReader(
            session,
            custody_root,
            tenant_id,
        ).get_finding_projection(finding_id)
        assert projection is not None
        assert projection["evidence"] == {
            "observations": [],
            "state": "unavailable",
        }
    finally:
        session.close()


def test_legacy_authorization_mutations_and_collisions_fail_closed(
    tmp_path: Path,
) -> None:
    for mutation in (
        "extra_field",
        "binding_tamper",
        "ttl",
        "enum",
        "row_mismatch",
        "confirmation_tamper",
        "confirmation_stale",
        "confirmation_future",
        "authz_canary",
    ):
        invalid_session = create_db(
            tmp_path / f"invalid-authorization-{mutation}.db"
        )
        try:
            model, envelope = _valid_legacy_authorization_model()
            if mutation == "extra_field":
                envelope["password"] = "TASK101_CANARY_SECRET"
                envelope["binding_digest"] = compute_envelope_digest(envelope)
                model.binding_digest = str(envelope["binding_digest"])
            elif mutation == "binding_tamper":
                envelope["resolved_target"] = "sha256:" + "c" * 64
            elif mutation == "ttl":
                envelope["expires_at"] = (
                    datetime(2026, 1, 1, tzinfo=timezone.utc)
                    + timedelta(seconds=301)
                ).isoformat().replace("+00:00", "Z")
                envelope["binding_digest"] = compute_envelope_digest(envelope)
                model.expires_at = datetime(
                    2026, 1, 1, tzinfo=timezone.utc
                ) + timedelta(seconds=301)
                model.binding_digest = str(envelope["binding_digest"])
            elif mutation == "enum":
                envelope["safety_mode"] = "invented"
                envelope["binding_digest"] = compute_envelope_digest(envelope)
                model.binding_digest = str(envelope["binding_digest"])
            elif mutation == "row_mismatch":
                model.job_id = "different-job"
            elif mutation == "confirmation_tamper":
                model.confirmation_digest = "sha256:" + "0" * 64
            elif mutation in {"confirmation_stale", "confirmation_future"}:
                offset = -301 if mutation == "confirmation_stale" else 31
                confirmation = ActionConfirmation.create(
                    job_id=str(envelope["job_id"]),
                    target="fixture",
                    engine=str(envelope["engine"]),
                    action=str(envelope["action_kind"]),
                    issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc)
                    + timedelta(seconds=offset),
                )
                envelope["confirmed_at"] = confirmation.issued_at
                envelope["binding_digest"] = compute_envelope_digest(envelope)
                model.binding_digest = str(envelope["binding_digest"])
                model.confirmation_digest = confirmation.binding_digest
            elif mutation == "authz_canary":
                canary_decision_id = "authz-CANARY_AUTHORIZATION_HANDLE"
                envelope["decision_id"] = canary_decision_id
                envelope["binding_digest"] = compute_envelope_digest(envelope)
                model.decision_id = canary_decision_id
                model.binding_digest = str(envelope["binding_digest"])
            model.envelope_json = json.dumps(
                envelope,
                sort_keys=True,
                separators=(",", ":"),
            )
            invalid_session.add(model)
            invalid_session.commit()
            manager = MigrationManager(invalid_session.get_bind())
            manager.downgrade()
            manager.upgrade()
            assert invalid_session.execute(
                text("SELECT outcome FROM canonical_scope_decisions")
            ).scalar_one() == "unknown"
            assert "TASK101_CANARY_SECRET" not in "".join(
                invalid_session.execute(
                    text("SELECT payload_json FROM canonical_legacy_records")
                ).scalars().all()
            )
        finally:
            invalid_session.close()

    collision_session = create_db(tmp_path / "legacy-job-collision.db")
    try:
        tenant_id = _canonical_legacy_key(
            "legacy-tenant",
            kind="tenant",
            tenant_id="forge-legacy",
        )
        job_id = _canonical_legacy_key(
            "legacy-job",
            kind="job",
            tenant_id=tenant_id,
        )
        collision_session.execute(
            text(
                "INSERT INTO canonical_tenants "
                "(id,schema_version,name,created_at,metadata_json) "
                "VALUES (:tenant,'forge-canonical-v1','legacy-tenant',"
                "'2026-01-01T00:00:00Z',:metadata)"
            ),
            {"tenant": tenant_id, "metadata": json.dumps({"legacy": True})},
        )
        collision_session.execute(
            text(
                "INSERT INTO canonical_engagements "
                "(id,tenant_id,project_id,schema_version,name,status,created_at,metadata_json) "
                "VALUES ('canonical-engagement',:tenant,NULL,'forge-canonical-v1',"
                "'Canonical engagement','planned','2026-01-01T00:00:00Z','{}')"
            ),
            {"tenant": tenant_id},
        )
        collision_session.execute(
            text(
                "INSERT INTO canonical_jobs "
                "(id,tenant_id,engagement_id,schema_version,job_kind,status,created_at,metadata_json) "
                "VALUES (:job,:tenant,'canonical-engagement','forge-canonical-v1',"
                "'canonical','failed','2026-01-01T00:00:00Z','{\"owner\":\"canonical\"}')"
            ),
            {"job": job_id, "tenant": tenant_id},
        )
        collision_session.add(
            ScanJobModel(
                id="legacy-job",
                tenant_id="legacy-tenant",
                target="fixture",
                status="completed",
            )
        )
        collision_session.commit()

        with pytest.raises(MigrationError, match="collides"):
            archive_legacy_records(collision_session.get_bind())
        status, metadata_json = collision_session.execute(
            text(
                "SELECT status,metadata_json FROM canonical_jobs "
                "WHERE tenant_id=:tenant AND id=:job"
            ),
            {"tenant": tenant_id, "job": job_id},
        ).one()
        assert status == "failed"
        assert json.loads(metadata_json) == {"owner": "canonical"}
    finally:
        collision_session.close()

    asset_collision_session = create_db(tmp_path / "legacy-asset-collision.db")
    try:
        tenant_id = _canonical_legacy_key(
            "legacy-tenant",
            kind="tenant",
            tenant_id="forge-legacy",
        )
        asset_id = _canonical_legacy_key(
            "host:fixture",
            kind="asset",
            tenant_id=tenant_id,
        )
        asset_collision_session.execute(
            text(
                "INSERT INTO canonical_tenants "
                "(id,schema_version,name,created_at,metadata_json) "
                "VALUES (:tenant,'forge-canonical-v1','legacy-tenant',"
                "'2026-01-01T00:00:00Z',:metadata)"
            ),
            {"tenant": tenant_id, "metadata": json.dumps({"legacy": True})},
        )
        asset_collision_session.execute(
            text(
                "INSERT INTO canonical_assets "
                "(id,tenant_id,schema_version,kind,identity_key,display_name,"
                "canonical_uri,created_at,metadata_json) "
                "VALUES (:asset,:tenant,'forge-canonical-v1','host','wrong-host',"
                "'wrong-host',NULL,'2026-01-01T00:00:00Z',:metadata)"
            ),
            {
                "asset": asset_id,
                "tenant": tenant_id,
                "metadata": json.dumps({"legacy": True}),
            },
        )
        asset_collision_session.add(
            ScanJobModel(
                id="legacy-job",
                tenant_id="legacy-tenant",
                target="fixture",
                status="completed",
            )
        )
        asset_collision_session.commit()
        with pytest.raises(MigrationError, match="semantically different"):
            archive_legacy_records(asset_collision_session.get_bind())
        assert asset_collision_session.execute(
            text(
                "SELECT identity_key FROM canonical_assets "
                "WHERE tenant_id=:tenant AND id=:asset"
            ),
            {"tenant": tenant_id, "asset": asset_id},
        ).scalar_one() == "wrong-host"
    finally:
        asset_collision_session.close()

    operator_collision_session = create_db(
        tmp_path / "legacy-operator-collision.db"
    )
    try:
        model, _envelope = _valid_legacy_authorization_model()
        tenant_id = _canonical_legacy_key(
            model.tenant_id,
            kind="tenant",
            tenant_id="forge-legacy",
        )
        operator_id = _canonical_legacy_key(
            model.operator_id,
            kind="operator",
            tenant_id=tenant_id,
        )
        operator_collision_session.execute(
            text(
                "INSERT INTO canonical_tenants "
                "(id,schema_version,name,created_at,metadata_json) "
                "VALUES (:tenant,'forge-canonical-v1','legacy-tenant',"
                "'2026-01-01T00:00:00Z',:metadata)"
            ),
            {"tenant": tenant_id, "metadata": json.dumps({"legacy": True})},
        )
        operator_collision_session.execute(
            text(
                "INSERT INTO canonical_operators "
                "(id,tenant_id,schema_version,display_name,external_ref,"
                "created_at,metadata_json) VALUES (:operator,:tenant,"
                "'forge-canonical-v1','foreign operator',NULL,"
                "'2026-01-01T00:00:00Z',:metadata)"
            ),
            {
                "operator": operator_id,
                "tenant": tenant_id,
                "metadata": json.dumps({"legacy": True}),
            },
        )
        operator_collision_session.add(model)
        operator_collision_session.commit()
        with pytest.raises(MigrationError, match="semantically different"):
            archive_legacy_records(operator_collision_session.get_bind())
        assert operator_collision_session.execute(
            text(
                "SELECT display_name FROM canonical_operators "
                "WHERE tenant_id=:tenant AND id=:operator"
            ),
            {"tenant": tenant_id, "operator": operator_id},
        ).scalar_one() == "foreign operator"
    finally:
        operator_collision_session.close()
