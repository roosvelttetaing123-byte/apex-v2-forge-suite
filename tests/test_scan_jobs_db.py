"""Focused tests for durable scan job database storage."""
from __future__ import annotations

import base64
import json
import os
import sqlite3
import stat
import traceback
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pathlib import Path

import pytest


def test_scan_job_can_persist_and_update(tmp_path):
    from common.db import ScanJobModel, create_db, save_scan_job, update_scan_job

    session = create_db(tmp_path / "scan_jobs.db")
    started_at = datetime.now(timezone.utc)

    save_scan_job(
        session,
        {
            "id": "job-1",
            "status": "running",
            "target": "https://example.test",
            "frameworks": ["webforge", "netforge"],
            "modules": ["headers", "ssl"],
            "pid": 4242,
            "results_dir": tmp_path / "results" / "job-1",
            "logs": {"events": ["created", "started"]},
            "started_at": started_at,
        },
    )

    job = session.query(ScanJobModel).filter_by(id="job-1").one()
    assert job.status == "running"
    assert job.target == "https://example.test"
    assert json.loads(job.frameworks) == ["webforge", "netforge"]
    assert json.loads(job.modules) == ["headers", "ssl"]
    assert job.pid == 4242
    assert job.results_dir.endswith("results/job-1")
    assert json.loads(job.logs) == {"events": ["created", "started"]}
    assert job.return_code is None

    created_at = job.created_at
    first_updated_at = job.updated_at
    save_scan_job(
        session,
        {
            "id": "job-1",
            "target": "https://example.test",
            "status": "running",
            "pid": 5150,
        },
    )
    session.refresh(job)
    assert job.created_at == created_at
    assert job.updated_at >= first_updated_at
    assert job.pid == 5150
    assert json.loads(job.frameworks) == ["webforge", "netforge"]

    updated = update_scan_job(
        session,
        "job-1",
        status="completed",
        return_code=0,
        logs=["finished"],
        completed_at=datetime.now(timezone.utc),
    )

    assert updated is not None
    session.refresh(job)
    assert job.status == "completed"
    assert job.return_code == 0
    assert json.loads(job.logs) == ["finished"]
    assert job.completed_at is not None
    session.close()


def test_create_db_preserves_shared_parent_and_secures_sqlite_artifacts(
    tmp_path,
):
    from common.db import create_db

    shared = tmp_path / "caller-owned"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    db_path = shared / "protected.db"

    previous_umask = os.umask(0)
    try:
        session = create_db(db_path)
    finally:
        os.umask(previous_umask)

    try:
        assert stat.S_IMODE(shared.stat().st_mode) == 0o755
        for artifact in (
            db_path,
            db_path.with_suffix(".db.schema.lock"),
            shared / "protected.db-wal",
            shared / "protected.db-shm",
        ):
            assert artifact.is_file()
            assert not artifact.is_symlink()
            assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    finally:
        session.close()


def test_create_db_makes_each_missing_directory_owner_only(tmp_path):
    from common.db import create_db

    first = tmp_path / "first-private"
    second = first / "second-private"
    previous_umask = os.umask(0)
    try:
        session = create_db(second / "protected.db")
    finally:
        os.umask(previous_umask)

    try:
        assert stat.S_IMODE(first.stat().st_mode) == 0o700
        assert stat.S_IMODE(second.stat().st_mode) == 0o700
    finally:
        session.close()


def test_create_db_rejects_database_symlink_without_touching_victim(tmp_path):
    from common.db import create_db

    victim = tmp_path / "victim.db"
    connection = sqlite3.connect(victim)
    connection.execute("CREATE TABLE victim_canary (value TEXT)")
    connection.execute("INSERT INTO victim_canary VALUES ('unchanged')")
    connection.commit()
    connection.close()
    victim.chmod(0o644)
    original = victim.read_bytes()
    destination = tmp_path / "protected.db"
    destination.symlink_to(victim)

    with pytest.raises(ValueError, match="database artifact is unavailable"):
        create_db(destination)

    assert destination.is_symlink()
    assert victim.read_bytes() == original
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644


def test_create_db_rejects_schema_lock_symlink_without_touching_victim(tmp_path):
    from common.db import create_db

    victim = tmp_path / "lock-victim.txt"
    victim.write_text("LOCK_CANARY_UNCHANGED", encoding="utf-8")
    victim.chmod(0o644)
    db_path = tmp_path / "protected.db"
    lock_path = db_path.with_suffix(".db.schema.lock")
    lock_path.symlink_to(victim)

    with pytest.raises(ValueError, match="database artifact is unavailable"):
        create_db(db_path)

    assert lock_path.is_symlink()
    assert victim.read_text(encoding="utf-8") == "LOCK_CANARY_UNCHANGED"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    assert not db_path.exists()


def test_create_db_rejects_symlink_parent_without_creating_artifacts(tmp_path):
    from common.db import create_db

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="database directory must be a real directory"):
        create_db(linked_parent / "protected.db")

    assert list(real_parent.iterdir()) == []


def test_create_db_rejects_intermediate_directory_symlink_without_artifacts(tmp_path):
    from common.db import create_db

    real_parent = tmp_path / "real-parent"
    nested_parent = real_parent / "nested"
    nested_parent.mkdir(parents=True)
    nested_parent.chmod(0o755)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="database directory must be a real directory"):
        create_db(linked_parent / "nested" / "protected.db")

    assert list(nested_parent.iterdir()) == []
    assert stat.S_IMODE(nested_parent.stat().st_mode) == 0o755


def test_create_db_tightens_preexisting_sqlite_sidecars(tmp_path):
    from common.db import create_db

    db_path = tmp_path / "protected.db"
    first_session = create_db(db_path)
    wal_path = tmp_path / "protected.db-wal"
    shm_path = tmp_path / "protected.db-shm"
    wal_path.chmod(0o644)
    shm_path.chmod(0o666)

    second_session = create_db(db_path)
    try:
        assert stat.S_IMODE(wal_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(shm_path.stat().st_mode) == 0o600
    finally:
        second_engine = second_session.get_bind()
        first_engine = first_session.get_bind()
        second_session.close()
        first_session.close()
        second_engine.dispose()
        first_engine.dispose()


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_create_db_rejects_sqlite_sidecar_symlink_without_touching_victim(
    tmp_path,
    suffix,
):
    from common.db import create_db

    db_path = tmp_path / "protected.db"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE fixture (value TEXT)")
    connection.commit()
    connection.close()
    victim = tmp_path / f"victim{suffix}.txt"
    victim.write_text("SIDECAR_CANARY_UNCHANGED", encoding="utf-8")
    victim.chmod(0o644)
    sidecar = tmp_path / f"protected.db{suffix}"
    sidecar.symlink_to(victim)

    with pytest.raises(ValueError, match="database artifact is unavailable"):
        create_db(db_path)

    assert sidecar.is_symlink()
    assert victim.read_text(encoding="utf-8") == "SIDECAR_CANARY_UNCHANGED"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_create_db_rejects_sqlite_sidecar_hardlink_without_touching_victim(
    tmp_path,
    suffix,
):
    from common.db import create_db

    db_path = tmp_path / "protected.db"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE protected (value TEXT)")
    connection.commit()
    connection.close()
    victim = tmp_path / f"victim{suffix}.txt"
    victim.write_text("SIDECAR_HARDLINK_CANARY_UNCHANGED", encoding="utf-8")
    victim.chmod(0o644)
    original = victim.read_bytes()
    sidecar = tmp_path / f"protected.db{suffix}"
    os.link(victim, sidecar)

    with pytest.raises(ValueError, match="one unaliased regular file"):
        create_db(db_path)

    assert victim.read_bytes() == original
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    assert victim.stat().st_nlink == 2


def test_create_db_rejects_hardlink_without_mutating_alias(tmp_path):
    from common.db import create_db

    victim = tmp_path / "hardlink-victim.db"
    victim.write_bytes(b"DATABASE_HARDLINK_CANARY")
    victim.chmod(0o644)
    original = victim.read_bytes()
    destination = tmp_path / "protected.db"
    os.link(victim, destination)

    with pytest.raises(ValueError, match="one unaliased regular file"):
        create_db(destination)

    assert victim.read_bytes() == original
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    assert victim.stat().st_nlink == 2


def test_create_db_disposes_engine_and_normalizes_migration_failure(
    tmp_path,
    monkeypatch,
):
    import common.db as db_module

    db_path = tmp_path / "migration-failure.db"

    def fail_migration(_engine):
        raise RuntimeError("CANARY_MIGRATION_FAILURE_MUST_NOT_ESCAPE")

    monkeypatch.setattr(db_module, "_migrate_sqlite_schema", fail_migration)
    with pytest.raises(db_module.DatabaseInitializationError) as exc_info:
        db_module.create_db(db_path)

    rendered = "".join(
        traceback.format_exception(
            type(exc_info.value),
            exc_info.value,
            exc_info.value.__traceback__,
        )
    )
    assert "CANARY_MIGRATION_FAILURE_MUST_NOT_ESCAPE" not in rendered
    assert exc_info.value.__suppress_context__ is True
    leaked_descriptors = []
    descriptor_root = Path("/proc/self/fd")
    if descriptor_root.is_dir():
        for descriptor in descriptor_root.iterdir():
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            if os.fspath(db_path) in target:
                leaked_descriptors.append(target)
    assert leaked_descriptors == []


@pytest.mark.parametrize("operation", ["fstat", "fchmod"])
def test_create_db_normalizes_generic_artifact_helper_failures(
    tmp_path,
    monkeypatch,
    operation,
):
    import common.db as db_module

    def fail_helper(*_args, **_kwargs):
        raise RuntimeError("CANARY_DATABASE_HELPER_FAILURE")

    monkeypatch.setattr(db_module.os, operation, fail_helper)
    with pytest.raises(ValueError) as exc_info:
        db_module.create_db(tmp_path / "protected.db")
    rendered = "".join(
        traceback.format_exception(
            type(exc_info.value),
            exc_info.value,
            exc_info.value.__traceback__,
        )
    )
    assert "CANARY_DATABASE_HELPER_FAILURE" not in rendered
    assert exc_info.value.__suppress_context__ is True


def test_create_db_does_not_change_process_umask(tmp_path, monkeypatch):
    import common.db as db_module

    def reject_umask(*_args, **_kwargs):
        raise AssertionError("database boundary changed the process umask")

    monkeypatch.setattr(db_module.os, "umask", reject_umask)
    session = db_module.create_db(tmp_path / "protected.db")
    session.close()


def test_create_db_rejects_leaf_swap_without_mutating_symlink_victim(
    tmp_path,
    monkeypatch,
):
    import common.db as db_module

    db_path = tmp_path / "protected.db"
    victim = tmp_path / "swap-victim.db"
    connection = sqlite3.connect(victim)
    connection.execute("CREATE TABLE victim_canary (value TEXT)")
    connection.commit()
    connection.close()
    victim.chmod(0o644)
    original = victim.read_bytes()
    real_connect = db_module.sqlite3.connect
    swapped = False

    def swap_then_connect(path, *args, **kwargs):
        nonlocal swapped
        if not swapped:
            db_path.unlink()
            db_path.symlink_to(victim)
            swapped = True
        return real_connect(path, *args, **kwargs)

    monkeypatch.setattr(db_module.sqlite3, "connect", swap_then_connect)
    with pytest.raises(ValueError, match="changed during connection"):
        db_module.create_db(db_path)

    assert swapped is True
    assert db_path.is_symlink()
    assert victim.read_bytes() == original
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644


def test_create_db_rejects_inode_replacement_after_pool_disposal(tmp_path):
    from sqlalchemy import text

    from common.db import create_db

    db_path = tmp_path / "protected.db"
    original_path = tmp_path / "original.db"
    session = create_db(db_path)
    engine = session.get_bind()
    session.execute(text("CREATE TABLE lifetime_canary (value TEXT)"))
    session.execute(text("INSERT INTO lifetime_canary VALUES ('original')"))
    session.commit()
    session.close()
    engine.dispose()

    db_path.replace(original_path)
    replacement = sqlite3.connect(db_path)
    replacement.execute("CREATE TABLE replacement_canary (value TEXT)")
    replacement.execute(
        "INSERT INTO replacement_canary VALUES ('replacement')"
    )
    replacement.commit()
    replacement.close()
    db_path.chmod(0o644)
    replacement_bytes = db_path.read_bytes()

    try:
        with pytest.raises(ValueError, match="changed during connection"):
            with engine.connect() as connection:
                connection.exec_driver_sql(
                    "SELECT value FROM replacement_canary"
                ).scalar_one()
    finally:
        engine.dispose()

    assert db_path.read_bytes() == replacement_bytes
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o644
    original = sqlite3.connect(original_path)
    try:
        assert original.execute(
            "SELECT value FROM lifetime_canary"
        ).fetchone() == ("original",)
    finally:
        original.close()


def test_create_db_reconnect_does_not_recreate_missing_database(tmp_path):
    from sqlalchemy import text

    from common.db import create_db

    db_path = tmp_path / "protected.db"
    detached = tmp_path / "detached.db"
    session = create_db(db_path)
    engine = session.get_bind()
    session.execute(text("CREATE TABLE lifetime_canary (value TEXT)"))
    session.commit()
    session.close()
    engine.dispose()
    db_path.replace(detached)

    try:
        with pytest.raises(ValueError, match="changed during connection"):
            with engine.connect() as connection:
                connection.exec_driver_sql("SELECT 1").scalar_one()
    finally:
        engine.dispose()

    assert not db_path.exists()
    assert detached.is_file()


def test_scan_job_migration_adds_missing_columns(tmp_path):
    from common.db import ScanJobModel, create_db, save_scan_job

    db_path = tmp_path / "legacy_scan_jobs.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE scan_jobs (id VARCHAR(36) PRIMARY KEY)")
    conn.commit()
    conn.close()

    session = create_db(db_path)
    columns = {
        row[1]
        for row in session.connection()
        .exec_driver_sql("PRAGMA table_info(scan_jobs)")
        .fetchall()
    }

    assert {
        "id",
        "status",
        "target",
        "frameworks",
        "modules",
        "pid",
        "return_code",
        "results_dir",
        "logs",
    }.issubset(columns)

    save_scan_job(
        session,
        {
            "id": "job-legacy",
            "status": "pending",
            "target": "10.0.0.0/24",
            "frameworks": ["netforge"],
            "modules": [],
            "logs": {},
        },
    )

    job = session.query(ScanJobModel).filter_by(id="job-legacy").one()
    assert job.target == "10.0.0.0/24"
    assert json.loads(job.frameworks) == ["netforge"]
    session.close()


def test_update_scan_job_rejects_unknown_fields(tmp_path):
    from common.db import create_db, save_scan_job, update_scan_job

    session = create_db(tmp_path / "scan_jobs.db")
    save_scan_job(
        session,
        {
            "id": "job-1",
            "status": "pending",
            "target": "https://example.test",
        },
    )

    with pytest.raises(ValueError, match="unknown scan job fields"):
        update_scan_job(session, "job-1", unexpected=True)

    session.close()


def test_scan_job_tenant_linkage_filters_reads_and_updates(tmp_path):
    from common.db import create_db, get_scan_job, save_scan_job, update_scan_job

    session = create_db(tmp_path / "tenant-scan-jobs.db")
    save_scan_job(
        session,
        {
            "id": "job-tenant-a",
            "tenant_id": "tenant-a",
            "status": "pending",
            "target": "http://127.0.0.1:8080/fixture",
        },
    )

    assert get_scan_job(session, "job-tenant-a", tenant_id="tenant-a") is not None
    assert get_scan_job(session, "job-tenant-a", tenant_id="tenant-b") is None
    assert (
        update_scan_job(
            session,
            "job-tenant-a",
            tenant_id="tenant-b",
            status="completed",
        )
        is None
    )
    row = get_scan_job(session, "job-tenant-a", tenant_id="tenant-a")
    assert row is not None
    assert row.status == "pending"

    with pytest.raises(ValueError, match="tenant linkage is immutable"):
        save_scan_job(
            session,
            {
                "id": "job-tenant-a",
                "tenant_id": "tenant-b",
                "target": "http://127.0.0.1:8080/fixture",
            },
        )

    session.close()


def test_scan_job_cannot_claim_allow_without_consumed_authorization(tmp_path):
    from common.db import ScanJobModel, create_db, save_scan_job

    session = create_db(tmp_path / "unbacked-authorization.db")
    with pytest.raises(ValueError, match="authorization linkage is not valid"):
        save_scan_job(
            session,
            {
                "id": "client-job",
                "tenant_id": "tenant-lab",
                "target": "http://127.0.0.1/fixture",
                "authorization_state": "allow",
                "authorization_decision_id": "client-decision",
                "authorization_action_id": "client-action",
            },
        )
    assert session.query(ScanJobModel).filter_by(id="client-job").one_or_none() is None
    session.close()


def test_scan_job_migration_downgrades_unlinked_legacy_allow(tmp_path):
    from common.db import ScanJobModel, create_db

    db_path = tmp_path / "legacy-allow.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE scan_jobs ("
        "id VARCHAR(36) PRIMARY KEY, "
        "authorization_state VARCHAR(50), "
        "authorization_decision_id VARCHAR(64), "
        "authorization_action_id VARCHAR(64)"
        ")"
    )
    conn.execute(
        "INSERT INTO scan_jobs(id, authorization_state) VALUES (?, ?)",
        ("legacy-allow", "allow"),
    )
    conn.commit()
    conn.close()

    session = create_db(db_path)
    row = session.get(ScanJobModel, "legacy-allow")
    assert row is not None
    assert row.authorization_state == "unknown_not_authorized"
    assert row.authorization_decision_id is None
    assert row.authorization_action_id is None
    session.close()


def test_finding_retest_can_persist_and_update(tmp_path):
    from common.db import (
        FindingRetestModel,
        create_db,
        save_finding_retest,
        update_finding_retest,
    )

    session = create_db(tmp_path / "scan_jobs.db")
    save_finding_retest(
        session,
        {
            "id": "rt-1",
            "finding_id": "finding-1",
            "status": "pending",
            "module": "sqli_scanner",
            "target": "https://example.test",
            "url": "https://example.test/login?id=1",
            "param": "id",
            "payload_class": "sqli_scanner",
            "session_ref": "session.json",
            "evidence": {"proof_summary": "time delay"},
            "metadata_json": {"dry_run": True},
        },
    )

    retest = session.query(FindingRetestModel).filter_by(id="rt-1").one()
    assert retest.finding_id == "finding-1"
    assert retest.module == "sqli_scanner"
    assert retest.target == "https://example.test"
    assert json.loads(retest.evidence)["proof_summary"] == "time delay"
    assert json.loads(retest.metadata_json)["dry_run"] is True

    updated = update_finding_retest(
        session,
        "rt-1",
        status="completed",
        still_vulnerable=None,
        confidence="UNVERIFIED",
        evidence={"return_code": 0},
        retested_at=datetime.now(timezone.utc),
    )

    assert updated is not None
    session.refresh(retest)
    assert retest.status == "completed"
    assert retest.still_vulnerable is None
    assert retest.confidence == "UNVERIFIED"
    assert json.loads(retest.evidence)["return_code"] == 0
    assert retest.retested_at is not None
    session.close()


def test_finding_retest_redacts_every_ordinary_text_field_before_sqlite(
    tmp_path,
):
    from common.db import (
        FindingRetestModel,
        create_db,
        save_finding_retest,
        update_finding_retest,
    )

    db_path = tmp_path / "retest-redaction.db"
    session = create_db(db_path)
    save_canaries = {
        "target": "Bearer RETEST_SAVE_TARGET_CANARY_007",
        "url": (
            "https://operator:RETEST_SAVE_URL_CANARY_007@fixture.test/"
            "?token=RETEST_SAVE_QUERY_CANARY_007"
        ),
        "param": "password=RETEST_SAVE_PARAM_CANARY_007",
        "session_ref": "Cookie: session=RETEST_SAVE_SESSION_CANARY_007",
        "error": "Authorization: Bearer RETEST_SAVE_ERROR_CANARY_007",
    }
    save_secret_fragments = {
        "target": "RETEST_SAVE_TARGET_CANARY_007",
        "url": "RETEST_SAVE_URL_CANARY_007",
        "param": "RETEST_SAVE_PARAM_CANARY_007",
        "session_ref": "RETEST_SAVE_SESSION_CANARY_007",
        "error": "RETEST_SAVE_ERROR_CANARY_007",
    }
    save_finding_retest(
        session,
        {
            "id": "retest-redaction",
            "finding_id": "finding-redaction",
            "status": "pending",
            "module": "fixture",
            **save_canaries,
            "evidence": {"password": "RETEST_SAVE_EVIDENCE_CANARY_007"},
            "metadata_json": {"api_key": "RETEST_SAVE_METADATA_CANARY_007"},
        },
    )
    saved = session.get(FindingRetestModel, "retest-redaction")
    assert saved is not None
    for field, canary in save_secret_fragments.items():
        assert canary not in str(getattr(saved, field))

    update_canaries = {
        "target": "Bearer RETEST_UPDATE_TARGET_CANARY_007",
        "url": (
            "https://operator:RETEST_UPDATE_URL_CANARY_007@fixture.test/"
            "?token=RETEST_UPDATE_QUERY_CANARY_007"
        ),
        "param": "password=RETEST_UPDATE_PARAM_CANARY_007",
        "session_ref": "Cookie: session=RETEST_UPDATE_SESSION_CANARY_007",
        "error": "Authorization: Bearer RETEST_UPDATE_ERROR_CANARY_007",
    }
    update_secret_fragments = {
        "target": "RETEST_UPDATE_TARGET_CANARY_007",
        "url": "RETEST_UPDATE_URL_CANARY_007",
        "param": "RETEST_UPDATE_PARAM_CANARY_007",
        "session_ref": "RETEST_UPDATE_SESSION_CANARY_007",
        "error": "RETEST_UPDATE_ERROR_CANARY_007",
    }
    updated = update_finding_retest(
        session,
        "retest-redaction",
        **update_canaries,
        evidence={"password": "RETEST_UPDATE_EVIDENCE_CANARY_007"},
        metadata_json={"api_key": "RETEST_UPDATE_METADATA_CANARY_007"},
    )
    assert updated is not None
    for field, canary in update_secret_fragments.items():
        assert canary not in str(getattr(updated, field))
    session.close()

    raw = b"".join(
        path.read_bytes()
        for path in sorted(tmp_path.glob("retest-redaction.db*"))
        if path.is_file()
    )
    all_canaries = [
        *save_secret_fragments.values(),
        *update_secret_fragments.values(),
        "RETEST_SAVE_EVIDENCE_CANARY_007",
        "RETEST_SAVE_METADATA_CANARY_007",
        "RETEST_UPDATE_EVIDENCE_CANARY_007",
        "RETEST_UPDATE_METADATA_CANARY_007",
    ]
    for canary in all_canaries:
        assert canary.encode("utf-8") not in raw


def _finding(finding_id, title, target, *, port=443, severity="High", discovered_at=None):
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "target": target,
        "port": port,
        "service": "https",
        "module": "unit_scanner",
        "description": f"{title} found",
        "reproduction_steps": ["review local fixture"],
        "remediation": "Apply the documented remediation.",
        "references": ["CWE-000"],
        "confidence": "HIGH",
        "evidence": {"request_raw": "GET / HTTP/1.1"},
        "discovered_at": discovered_at,
    }


def test_finding_save_deduplicates_and_tracks_aging(tmp_path):
    from common.db import FindingModel, create_db, save_finding

    session = create_db(tmp_path / "findings.db")
    first_seen = datetime.now(timezone.utc) - timedelta(days=45)

    save_finding(
        session,
        _finding(
            "finding-old",
            "TLS Weak Cipher",
            "https://app.example.test",
            discovered_at=first_seen.isoformat(),
        ),
        run_id="run-previous",
    )
    save_finding(
        session,
        _finding(
            "finding-new",
            " tls   weak cipher ",
            "app.example.test/login",
            discovered_at=datetime.now(timezone.utc).isoformat(),
        ),
        run_id="run-current",
    )

    rows = session.query(FindingModel).all()
    assert len(rows) == 1
    finding = rows[0]
    assert finding.id == "finding-old"
    assert finding.times_seen == 2
    assert finding.last_seen_run == "run-current"
    assert finding.days_open >= 45
    assert finding.priority == "CRITICAL"
    assert finding.dedup_key
    session.close()


def test_concurrent_tenant_dedup_is_database_enforced_and_preserves_other_rows(
    tmp_path,
):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from sqlalchemy import text

    from common.db import FindingModel, ScanRunModel, create_db, save_finding

    db_path = tmp_path / "concurrent-finding-dedup.db"
    initial = create_db(db_path)
    initial_engine = initial.get_bind()
    initial.close()
    initial_engine.dispose()
    worker_count = 8
    barrier = threading.Barrier(worker_count)

    def save_once(index: int) -> None:
        session = create_db(db_path)
        engine = session.get_bind()
        try:
            session.execute(text("SELECT COUNT(*) FROM findings"))
            session.add(
                ScanRunModel(
                    id=f"unrelated-scan-{index}",
                    tenant_id="tenant-a",
                    framework="webforge",
                    target="fixture-target",
                )
            )
            barrier.wait(timeout=10)
            save_finding(
                session,
                {
                    **_finding(
                        f"finding-{index}",
                        "Concurrent finding",
                        "fixture-target",
                    ),
                    "tenant_id": "tenant-a",
                },
                run_id="run-a",
            )
        finally:
            session.close()
            engine.dispose()

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        list(executor.map(save_once, range(worker_count)))

    final = create_db(db_path)
    final_engine = final.get_bind()
    assert final.query(FindingModel).filter_by(tenant_id="tenant-a").count() == 1
    assert final.query(ScanRunModel).filter(
        ScanRunModel.id.like("unrelated-scan-%")
    ).count() == worker_count
    index = final.execute(
        text(
            "SELECT sql FROM sqlite_master WHERE type='index' "
            "AND name='uq_findings_tenant_dedup'"
        )
    ).scalar_one()
    assert "CREATE UNIQUE INDEX" in index.upper()
    final.close()
    final_engine.dispose()


def test_legacy_duplicate_findings_consolidate_once_before_unique_index(
    tmp_path,
):
    from common.db import FindingModel, create_db
    from sqlalchemy import text

    db_path = tmp_path / "legacy-duplicate-findings.db"
    session = create_db(db_path)
    session.execute(text("DROP INDEX uq_findings_tenant_dedup"))
    session.execute(
        text(
            "DELETE FROM schema_migrations "
            "WHERE version='wp006_tenant_finding_dedup_v1'"
        )
    )
    shared_key = "a" * 64
    first_seen = datetime(2026, 7, 1, tzinfo=timezone.utc)
    session.add_all(
        [
            FindingModel(
                id="duplicate-a",
                tenant_id="tenant-a",
                title="Duplicate finding",
                severity="High",
                target="fixture-target",
                module="fixture-module",
                description="first legacy row",
                dedup_key=shared_key,
                seen_runs=json.dumps(["run-a"]),
                times_seen=2,
                first_seen_at=first_seen,
                last_seen_at=first_seen,
                last_seen_run="run-a",
                days_open=10,
                priority="HIGH",
            ),
            FindingModel(
                id="duplicate-b",
                tenant_id="tenant-a",
                title="Duplicate finding",
                severity="High",
                target="fixture-target",
                module="fixture-module",
                description="second legacy row",
                dedup_key=shared_key,
                seen_runs=json.dumps(["run-b"]),
                times_seen=3,
                first_seen_at=first_seen + timedelta(days=1),
                last_seen_at=first_seen + timedelta(days=2),
                last_seen_run="run-b",
                days_open=12,
                priority="CRITICAL",
            ),
        ]
    )
    session.commit()
    engine = session.get_bind()
    session.close()
    engine.dispose()

    migrated = create_db(db_path)
    rows = migrated.query(FindingModel).filter_by(
        tenant_id="tenant-a", dedup_key=shared_key
    ).all()
    assert len(rows) == 1
    assert json.loads(rows[0].seen_runs) == ["run-a", "run-b"]
    assert rows[0].times_seen == 5
    assert rows[0].last_seen_run == "run-b"
    assert rows[0].priority == "CRITICAL"
    first_state = (
        rows[0].id,
        rows[0].seen_runs,
        rows[0].times_seen,
        rows[0].last_seen_run,
        rows[0].priority,
    )
    migrated_engine = migrated.get_bind()
    migrated.close()
    migrated_engine.dispose()

    reopened = create_db(db_path)
    row = reopened.query(FindingModel).filter_by(
        tenant_id="tenant-a", dedup_key=shared_key
    ).one()
    assert (
        row.id,
        row.seen_runs,
        row.times_seen,
        row.last_seen_run,
        row.priority,
    ) == first_state
    reopened_engine = reopened.get_bind()
    reopened.close()
    reopened_engine.dispose()


def _configured_run_truth_signer(monkeypatch):
    import common.run_truth as run_truth_module
    from common.run_truth import RUN_TRUTH_POLICY

    signer = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(
        signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    policy = replace(RUN_TRUTH_POLICY, issuer_public_key=public_key)
    monkeypatch.setattr(run_truth_module, "RUN_TRUTH_POLICY", policy)
    return policy, signer


def _signed_run_truth(
    run_id,
    *,
    session,
    policy,
    signer,
    status="success",
    coverage_complete=True,
    predecessor_run_id="",
    run_sequence=1,
):
    from common.db import finding_set_identity
    from common.run_truth import (
        RunCollectionStatus,
        RunCollectionTruth,
        run_collection_truth_attestation_payload,
    )

    record = RunCollectionTruth(
        run_id=run_id,
        authorization_run_id=f"authorization-{run_id}",
        job_id=f"job-{run_id}",
        tenant_id="default",
        framework="webforge",
        scope_binding="sha256:" + "a" * 64,
        target_binding="sha256:" + "b" * 64,
        collection_status=RunCollectionStatus(status),
        coverage_complete=coverage_complete,
        coverage_identity="sha256:" + "c" * 64,
        finding_set_identity=finding_set_identity(
            session,
            tenant_id="default",
            run_id=run_id,
        ),
        predecessor_run_id=predecessor_run_id,
        run_sequence=run_sequence,
        completed_at=f"2026-08-02T00:00:0{run_sequence}+00:00",
        authorization_decision_id=f"decision-{run_id}",
        authorization_binding="sha256:" + "d" * 64,
        authority_id="fixture-run-authority",
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        issuer_id=policy.issuer_id,
    )
    signature = signer.sign(run_collection_truth_attestation_payload(record))
    return replace(
        record,
        attestation=base64.b64encode(signature).decode("ascii"),
    )


def test_persisted_finding_delta_reports_new_fixed_remaining(
    tmp_path,
    monkeypatch,
):
    from common.db import append_run_collection_truth, create_db, save_finding
    from common.reporting.delta_report import build_persisted_finding_delta

    session = create_db(tmp_path / "delta.db")
    save_finding(session, _finding("fixed-1", "Exposed Admin", "10.0.0.10", port=8443), run_id="run-a")
    save_finding(session, _finding("remaining-1", "Missing HSTS", "10.0.0.11", port=443), run_id="run-a")
    save_finding(session, _finding("remaining-2", "Missing HSTS", "https://10.0.0.11", port=443), run_id="run-b")
    save_finding(session, _finding("new-1", "Default Credential", "10.0.0.12", port=22), run_id="run-b")
    policy, signer = _configured_run_truth_signer(monkeypatch)
    append_run_collection_truth(
        session,
        _signed_run_truth(
            "run-a", session=session, policy=policy, signer=signer
        ),
    )
    append_run_collection_truth(
        session,
        _signed_run_truth(
            "run-b",
            session=session,
            policy=policy,
            signer=signer,
            predecessor_run_id="run-a",
            run_sequence=2,
        ),
    )

    report = build_persisted_finding_delta(
        session,
        "run-a",
        "run-b",
        tenant_id="default",
        current_collection_status="failed",
        current_coverage_complete=False,
    )
    data = report.to_dict()

    assert data["summary"] == {
        "new": 1,
        "fixed": 1,
        "remaining": 1,
        "inconclusive": 0,
    }
    assert data["new"][0]["title"] == "Default Credential"
    assert data["fixed"][0]["title"] == "Exposed Admin"
    assert data["remaining"][0]["title"] == "Missing HSTS"
    session.close()


def test_failed_or_incomplete_delta_does_not_claim_fixed(
    tmp_path,
    monkeypatch,
):
    from common.db import append_run_collection_truth, create_db, save_finding
    from common.reporting.delta_report import (
        build_finding_delta,
        build_persisted_finding_delta,
    )

    session = create_db(tmp_path / "delta-failed.db")
    save_finding(
        session,
        _finding("previous", "Exposed Admin", "10.0.0.10"),
        run_id="run-a",
    )
    policy, signer = _configured_run_truth_signer(monkeypatch)
    append_run_collection_truth(
        session,
        _signed_run_truth(
            "run-a", session=session, policy=policy, signer=signer
        ),
    )

    persisted = build_persisted_finding_delta(
        session,
        "run-a",
        "missing-run",
        tenant_id="default",
        current_collection_status="success",
        current_coverage_complete=True,
    )
    persisted_data = persisted.to_dict()
    assert persisted_data["fixed"] == []
    assert persisted_data["summary"]["inconclusive"] == 1
    assert persisted_data["comparison_state"] == "inconclusive"
    assert (
        persisted_data["comparison_reason"]
        == "current_persisted_run_truth_missing"
    )
    invalid_identity = build_persisted_finding_delta(
        session,
        "",
        "run-a",
        tenant_id="default",
        current_collection_status="success",
        current_coverage_complete=True,
    ).to_dict()
    assert invalid_identity["fixed"] == []
    assert invalid_identity["comparison_reason"] == (
        "previous_persisted_run_truth_missing"
    )

    append_run_collection_truth(
        session,
        _signed_run_truth(
            "run-b",
            session=session,
            policy=policy,
            signer=signer,
            status="failed",
            predecessor_run_id="run-a",
            run_sequence=2,
        ),
    )
    failed = build_persisted_finding_delta(
        session,
        "run-a",
        "run-b",
        tenant_id="default",
        current_collection_status="success",
        current_coverage_complete=True,
    ).to_dict()
    assert failed["fixed"] == []
    assert failed["comparison_reason"] == "current_collection_failed"

    report = build_finding_delta(
        persisted.inconclusive,
        [],
        current_collection_status="failed",
        current_coverage_complete=False,
    )
    data = report.to_dict()
    assert data["fixed"] == []
    assert data["summary"]["inconclusive"] == 1
    assert data["comparison_state"] == "inconclusive"
    session.close()


def test_delta_export_is_detached_redacted_atomic_and_owner_only(
    tmp_path,
    monkeypatch,
):
    from common.reporting.delta_report import build_finding_delta

    secret = "opaque-6c242a8d-bbd0-40dc-87cb-a151745a7cb8"
    report = build_finding_delta(
        [],
        [
            {
                "id": "finding-delta-fixture",
                "title": "Synthetic finding",
                "target": "example.test",
                "severity": "High",
                "password": secret,
                "description": secret,
            }
        ],
        previous_run="run-old",
        current_run="run-new",
        current_collection_status="success",
        current_coverage_complete=True,
    )
    output = tmp_path / "delta-private" / "delta.json"
    output.parent.mkdir(parents=True)
    output.parent.chmod(0o755)
    output.write_text("incomplete", encoding="utf-8")
    output.chmod(0o666)

    replacements: list[tuple[str, str]] = []
    real_replace = os.replace

    def tracked_replace(
        source,
        destination,
        *,
        src_dir_fd,
        dst_dir_fd,
    ):
        assert source.startswith(f".{output.name}.")
        assert destination == output.name
        assert src_dir_fd == dst_dir_fd
        metadata = os.stat(
            source,
            dir_fd=src_dir_fd,
            follow_symlinks=False,
        )
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        replacements.append((str(source), str(destination)))
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr("common.artifact_io.os.replace", tracked_replace)

    written = report.write_json(output)
    rendered = written.read_text(encoding="utf-8")
    parsed = json.loads(rendered)

    assert replacements and len(replacements) == 1
    assert secret not in rendered
    assert parsed["new"][0]["password"] == "<redacted>"
    assert parsed["new"][0]["description"] == "<redacted>"
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    assert stat.S_IMODE(written.parent.stat().st_mode) == 0o755
    assert list(written.parent.glob(f".{written.name}.*.tmp")) == []


def test_delta_export_creates_private_parent_without_mutating_existing_parent(
    tmp_path,
):
    from common.reporting.delta_report import build_finding_delta

    report = build_finding_delta(
        [],
        [],
        previous_run="run-old",
        current_run="run-new",
        current_collection_status="success",
        current_coverage_complete=True,
    )
    new_output = tmp_path / "new-private" / "delta.json"
    written = report.write_json(new_output)
    assert stat.S_IMODE(written.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(written.stat().st_mode) == 0o600

    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    shared_output = report.write_json(shared / "delta.json")
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755
    assert stat.S_IMODE(shared_output.stat().st_mode) == 0o600
