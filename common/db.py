"""SQLAlchemy 2.0 ORM base models for forge-suite findings storage."""
from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import stat
import time
import weakref
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from common.confidence_policy import normalise_finding
from common.redaction import redact_text, redact_value
import common.run_truth as run_truth_module
from common.run_truth import (
    RunCollectionStatus,
    RunCollectionTruth,
    RunTruthPolicy,
    validate_run_collection_truth,
)

from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, Float, Integer, String, Text,
    Table, create_engine, UniqueConstraint, event, text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

fcntl: Any
try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None


_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_OPEN_FLAGS = (
    os.O_RDWR
    | os.O_CREAT
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_EXISTING_FILE_OPEN_FLAGS = (
    os.O_RDWR
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_SQLITE_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")
_ArtifactIdentity = tuple[int, int]


class _DatabaseArtifactError(ValueError):
    """Fixed public failure for an unsafe database artifact path."""


class DatabaseInitializationError(RuntimeError):
    """Fixed public failure for database schema initialization."""


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class RouteHealthConfigurationChangedError(RuntimeError):
    """A protected route baseline exists for a different configuration."""


class RouteHealthIdentityChangedError(RuntimeError):
    """A protected route baseline exists for a different egress identity."""


class PersistedRunTruthValidationError(ValueError):
    """A stored run-truth row is malformed or fails its configured signature."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"persisted run truth rejected: {reason}")


class FindingModel(Base):
    """ORM model for a security finding."""
    __tablename__ = "findings"

    id               = Column(String(36), primary_key=True)
    tenant_id        = Column(String(100), nullable=False, default="default")
    title            = Column(String(500), nullable=False)
    severity         = Column(String(20),  nullable=False)
    target           = Column(String(500), nullable=False)
    url              = Column(String(1000), nullable=True)
    port             = Column(Integer,     nullable=True)
    service          = Column(String(100), nullable=True)
    module           = Column(String(100), nullable=False)
    description      = Column(Text,        nullable=False)
    reproduction_steps = Column(Text,      nullable=True)   # JSON list
    remediation      = Column(Text,        nullable=True)
    references       = Column(Text,        nullable=True)   # JSON list
    cvss_v31_vector  = Column(String(200), nullable=True)
    cvss_v31_score   = Column(Float,       nullable=True)
    cvss_v40_vector  = Column(String(200), nullable=True)
    cvss_v40_score   = Column(Float,       nullable=True)
    mitre_attack     = Column(Text,        nullable=True)   # JSON list
    screenshot_path  = Column(String(500), nullable=True)
    request_raw      = Column(Text,        nullable=True)
    response_raw     = Column(Text,        nullable=True)
    console_capture_path = Column(String(500), nullable=True)
    pcap_path        = Column(String(500), nullable=True)
    operator_confirmed = Column(Boolean,   default=False)
    tags             = Column(Text,        nullable=True)   # JSON list
    confidence       = Column(String(20),  nullable=True)
    status           = Column(String(50),  nullable=True)
    vpr_score        = Column(Float,       nullable=True)
    vpr_priority     = Column(String(20),  nullable=True)
    verification     = Column(Text,        nullable=True)   # JSON dict
    verification_state = Column(String(30), nullable=False, default="unknown")
    proof_type       = Column(String(50),  nullable=False, default="unknown")
    maturity         = Column(String(30),  nullable=False, default="experimental")
    dedup_key        = Column(String(64),  nullable=True)
    first_seen_at    = Column(DateTime,    nullable=True)
    last_seen_at     = Column(DateTime,    nullable=True)
    last_seen_run    = Column(String(200), nullable=True)
    seen_runs        = Column(Text,        nullable=True)   # JSON list
    times_seen       = Column(Integer,     default=1)
    days_open        = Column(Integer,     default=0)
    priority         = Column(String(20),  nullable=True)
    discovered_at    = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
    engagement       = Column(String(200), nullable=True)
    tester           = Column(String(200), nullable=True)


class ScanRunModel(Base):
    """ORM model for a scan run / engagement metadata."""
    __tablename__ = "scan_runs"

    id         = Column(String(36), primary_key=True)
    tenant_id  = Column(String(100), nullable=True, default="default")
    framework  = Column(String(20),  nullable=False)  # webforge/netforge/adforge
    target     = Column(String(500), nullable=False)
    mode       = Column(String(50),  nullable=True)
    engagement = Column(String(200), nullable=True)
    tester     = Column(String(200), nullable=True)
    started_at = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
    ended_at   = Column(DateTime,    nullable=True)
    phase      = Column(Integer,     default=0)       # last completed phase index
    status     = Column(String(20),  default="running")  # running/completed/interrupted


class RunCollectionTruthModel(Base):
    """Immutable authority-attested collection truth for one scan run."""

    __tablename__ = "run_collection_truth"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "run_id",
            name="uq_run_collection_truth_tenant_run",
        ),
        UniqueConstraint(
            "tenant_id",
            "framework",
            "scope_binding",
            "target_binding",
            "run_sequence",
            name="uq_run_collection_truth_series_sequence",
        ),
        CheckConstraint(
            "coverage_complete IN (0, 1)",
            name="ck_run_collection_truth_coverage_complete",
        ),
        CheckConstraint(
            "collection_status IN ("
            "'success', 'partial', 'failed', 'canceled', 'unauthorized', "
            "'unsupported', 'collection_error')",
            name="ck_run_collection_truth_collection_status",
        ),
    )

    sequence = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(160), nullable=False)
    authorization_run_id = Column(String(160), nullable=False)
    job_id = Column(String(160), nullable=False)
    tenant_id = Column(String(100), nullable=False)
    framework = Column(String(100), nullable=False)
    scope_binding = Column(String(80), nullable=False)
    target_binding = Column(String(80), nullable=False)
    collection_status = Column(String(40), nullable=False)
    coverage_complete = Column(Boolean, nullable=False)
    coverage_identity = Column(String(80), nullable=False)
    finding_set_identity = Column(String(80), nullable=False)
    predecessor_run_id = Column(String(160), nullable=False, default="")
    run_sequence = Column(Integer, nullable=False)
    completed_at = Column(String(80), nullable=False)
    authorization_decision_id = Column(String(64), nullable=False)
    authorization_binding = Column(String(80), nullable=False)
    authority_id = Column(String(160), nullable=False)
    policy_id = Column(String(100), nullable=False)
    policy_version = Column(String(80), nullable=False)
    issuer_id = Column(String(160), nullable=False)
    attestation = Column(Text, nullable=False)
    recorded_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class FindingRunMembershipModel(Base):
    """Immutable tenant/run finding snapshot used by historical deltas."""

    __tablename__ = "finding_run_membership"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "run_id",
            "dedup_key",
            name="uq_finding_run_membership_identity",
        ),
    )

    sequence = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), nullable=False)
    run_id = Column(String(160), nullable=False)
    finding_id = Column(String(64), nullable=False)
    dedup_key = Column(String(64), nullable=False)
    snapshot_json = Column(Text, nullable=False)
    snapshot_identity = Column(String(80), nullable=False)
    recorded_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class PersistedFindingDeltaModel(Base):
    """Append-only authorization-bound rendering of one persisted delta."""

    __tablename__ = "finding_delta_reports"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "current_run_id",
            name="uq_finding_delta_tenant_current_run",
        ),
    )

    sequence = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), nullable=False)
    previous_run_id = Column(String(160), nullable=False, default="")
    current_run_id = Column(String(160), nullable=False)
    authorization_decision_id = Column(String(64), nullable=False)
    authorization_binding = Column(String(80), nullable=False)
    report_json = Column(Text, nullable=False)
    report_identity = Column(String(80), nullable=False)
    recorded_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class ScanJobModel(Base):
    """ORM model for durable dashboard-launched scan jobs."""
    __tablename__ = "scan_jobs"

    id          = Column(String(36), primary_key=True)
    tenant_id   = Column(String(100), nullable=False, default="default")
    status      = Column(String(20), nullable=False, default="pending")
    target      = Column(String(500), nullable=False)
    frameworks  = Column(Text, nullable=True)          # JSON list
    modules     = Column(Text, nullable=True)          # JSON list
    pid         = Column(Integer, nullable=True)
    return_code = Column(Integer, nullable=True)
    results_dir = Column(String(1000), nullable=True)
    logs        = Column(Text, nullable=True)          # JSON list/dict
    error       = Column(Text, nullable=True)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at  = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    started_at  = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    authorization_state = Column(
        String(50), nullable=False, default="unknown_not_authorized"
    )
    authorization_decision_id = Column(String(64), nullable=True)
    authorization_action_id = Column(String(64), nullable=True)


class AuthorizationDecisionModel(Base):
    """Immutable, append-only authorization decision and envelope record."""

    __tablename__ = "authorization_decisions"

    sequence = Column(Integer, primary_key=True, autoincrement=True)
    decision_id = Column(String(64), nullable=False, unique=True)
    schema_version = Column(String(80), nullable=False)
    parent_decision_id = Column(String(64), nullable=True)
    tenant_id = Column(String(100), nullable=False)
    engagement_id = Column(String(160), nullable=False)
    run_id = Column(String(160), nullable=False)
    job_id = Column(String(160), nullable=False)
    action_id = Column(String(64), nullable=False)
    operator_id = Column(String(200), nullable=False)
    operator_role = Column(String(50), nullable=False)
    action_kind = Column(String(100), nullable=False)
    engine = Column(String(100), nullable=False)
    module_id = Column(String(200), nullable=True)
    requested_target = Column(String(80), nullable=False)
    resolved_target = Column(String(80), nullable=False)
    scope_snapshot = Column(String(80), nullable=False)
    scope_policy_version = Column(String(100), nullable=False)
    scope_decision = Column(String(40), nullable=False)
    scope_reason_code = Column(String(100), nullable=False)
    decision_outcome = Column(String(50), nullable=False)
    reason_code = Column(String(100), nullable=False)
    issued_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    binding_digest = Column(String(80), nullable=False)
    confirmation_digest = Column(String(80), nullable=True)
    envelope_json = Column(Text, nullable=False)
    detail = Column(Text, nullable=False, default="{}")
    recorded_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class AuthorizationConsumptionModel(Base):
    """Immutable single-use link between an allow decision and one boundary."""

    __tablename__ = "authorization_consumptions"
    __table_args__ = (
        UniqueConstraint("decision_id", name="uq_authorization_consumption_decision"),
    )

    sequence = Column(Integer, primary_key=True, autoincrement=True)
    consumption_id = Column(String(64), nullable=False, unique=True)
    decision_id = Column(String(64), nullable=False)
    tenant_id = Column(String(100), nullable=False)
    job_id = Column(String(160), nullable=False)
    action_id = Column(String(64), nullable=False)
    boundary = Column(String(160), nullable=False)
    result_id = Column(String(160), nullable=False)
    envelope_digest = Column(String(80), nullable=False)
    consumed_at = Column(DateTime, nullable=False)


class AuthorizationExecutionClaimModel(Base):
    """Immutable one-shot claim that permits one consumed action to execute."""

    __tablename__ = "authorization_execution_claims"
    __table_args__ = (
        UniqueConstraint("decision_id", name="uq_authorization_execution_claim_decision"),
    )

    sequence = Column(Integer, primary_key=True, autoincrement=True)
    claim_id = Column(String(64), nullable=False, unique=True)
    decision_id = Column(String(64), nullable=False)
    tenant_id = Column(String(100), nullable=False)
    job_id = Column(String(160), nullable=False)
    action_id = Column(String(64), nullable=False)
    boundary = Column(String(160), nullable=False)
    envelope_digest = Column(String(80), nullable=False)
    claimed_at = Column(DateTime, nullable=False)


class OutboundDecisionModel(Base):
    """Immutable outbound destination and resolution policy decision."""

    __tablename__ = "outbound_decisions"

    sequence = Column(Integer, primary_key=True, autoincrement=True)
    decision_id = Column(String(64), nullable=False, unique=True)
    schema_version = Column(String(80), nullable=False)
    authorization_decision_id = Column(String(64), nullable=False)
    action_id = Column(String(64), nullable=False)
    tenant_id = Column(String(100), nullable=False)
    engagement_id = Column(String(160), nullable=False)
    run_id = Column(String(160), nullable=False)
    job_id = Column(String(160), nullable=False)
    engine = Column(String(100), nullable=False)
    module_id = Column(String(200), nullable=True)
    action_kind = Column(String(100), nullable=False)
    stage = Column(String(50), nullable=False)
    destination_ref = Column(String(80), nullable=False)
    scheme = Column(String(20), nullable=True)
    host = Column(String(300), nullable=True)
    port = Column(Integer, nullable=True)
    resolved_addresses = Column(Text, nullable=False, default="[]")
    outcome = Column(String(30), nullable=False)
    reason_code = Column(String(100), nullable=False)
    route_id = Column(String(100), nullable=True)
    route_configuration_digest = Column(String(80), nullable=True)
    tls_mode = Column(String(50), nullable=False)
    binding_digest = Column(String(80), nullable=False)
    detail = Column(Text, nullable=False, default="{}")
    recorded_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class RouteHealthEvidenceModel(Base):
    """Immutable approved-egress health and observed-identity evidence."""

    __tablename__ = "route_health_evidence"

    sequence = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String(64), nullable=False, unique=True)
    schema_version = Column(String(80), nullable=False)
    route_id = Column(String(100), nullable=False)
    tenant_id = Column(String(100), nullable=False)
    engagement_id = Column(String(160), nullable=False)
    action_id = Column(String(64), nullable=False)
    configuration_digest = Column(String(80), nullable=False)
    runtime_id = Column(String(100), nullable=False)
    dns_mode = Column(String(50), nullable=False)
    verification_endpoint_ref = Column(String(80), nullable=False)
    observed_egress = Column(String(100), nullable=False)
    route_identity = Column(String(200), nullable=False)
    verified_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    binding_digest = Column(String(80), nullable=False)
    detail = Column(Text, nullable=False, default="{}")
    recorded_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class RouteHealthInvalidationModel(Base):
    """Append-only generation marker that invalidates route health globally."""

    __tablename__ = "route_health_invalidations"

    sequence = Column(Integer, primary_key=True, autoincrement=True)
    invalidation_id = Column(String(64), nullable=False, unique=True)
    schema_version = Column(String(80), nullable=False)
    route_id = Column(String(100), nullable=False)
    tenant_id = Column(String(100), nullable=False)
    engagement_id = Column(String(160), nullable=False)
    action_id = Column(String(64), nullable=False)
    configuration_digest = Column(String(80), nullable=False)
    health_sequence = Column(Integer, nullable=False)
    runtime_id = Column(String(100), nullable=False)
    reason_code = Column(String(100), nullable=False)
    binding_digest = Column(String(80), nullable=False)
    recorded_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class FindingRetestModel(Base):
    """ORM model for finding retest attempts and evidence."""
    __tablename__ = "finding_retests"

    id               = Column(String(36), primary_key=True)
    finding_id       = Column(String(36), nullable=False)
    status           = Column(String(20), nullable=False, default="pending")
    module           = Column(String(100), nullable=False)
    target           = Column(String(500), nullable=False)
    url              = Column(String(1000), nullable=True)
    param            = Column(String(200), nullable=True)
    payload_class    = Column(String(100), nullable=True)
    session_ref      = Column(String(500), nullable=True)
    job_id           = Column(String(36), nullable=True)
    still_vulnerable = Column(Boolean, nullable=True)
    confidence       = Column(String(20), nullable=True)
    evidence         = Column(Text, nullable=True)       # JSON dict/list
    metadata_json    = Column(Text, nullable=True)       # JSON dict
    error            = Column(Text, nullable=True)
    created_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    retested_at      = Column(DateTime, nullable=True)


class EventModel(Base):
    """ORM model for audit log events."""
    __tablename__ = "events"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    ts         = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    level      = Column(String(10), nullable=False)
    module     = Column(String(100), nullable=True)
    event      = Column(Text, nullable=False)
    target     = Column(String(500), nullable=True)
    detail     = Column(Text, nullable=True)  # JSON
    run_id     = Column(String(36), nullable=True)


class AuditLogModel(Base):
    """Operator audit trail for dashboard/API actions."""
    __tablename__ = "audit_logs"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    timestamp  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    tenant_id  = Column(String(100), nullable=True, default="default")
    operator   = Column(String(200), nullable=True)
    role       = Column(String(50), nullable=True)
    ip         = Column(String(100), nullable=True)
    action     = Column(String(200), nullable=False)
    object_id  = Column(String(500), nullable=True)
    status     = Column(String(50), nullable=True)
    detail     = Column(Text, nullable=True)  # JSON


class DashboardStateModel(Base):
    """Persisted dashboard state for crash recovery / session attach."""
    __tablename__ = "dashboard_state"

    id         = Column(String(36), primary_key=True)
    tenant_id  = Column(String(100), nullable=True, default="default")
    run_id     = Column(String(36), nullable=False)
    state_json = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class CredentialModel(Base):
    """Discovered credentials — encrypted at rest via Fernet."""
    __tablename__ = "credentials"

    id            = Column(String(36), primary_key=True)
    cred_type     = Column(String(50), nullable=False)   # PLAINTEXT, NTLM_HASH, KERB_TICKET, API_KEY, SSH_KEY, JWT
    account       = Column(String(200), nullable=True)
    secret_enc    = Column(Text, nullable=True)          # Fernet-encrypted secret
    target        = Column(String(500), nullable=True)
    discovered_by = Column(String(100), nullable=True)
    run_id        = Column(String(36), nullable=True)
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class TargetStatusModel(Base):
    """Per-target compromise status."""
    __tablename__ = "target_status"

    id           = Column(String(36), primary_key=True)
    target       = Column(String(500), nullable=False)
    pwned        = Column(Boolean, default=False)
    shell        = Column(Boolean, default=False)
    access_level = Column(String(50), nullable=True)  # user, admin, SYSTEM, DA, root
    creds_count  = Column(Integer, default=0)
    run_id       = Column(String(36), nullable=True)
    updated_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc))


def _absolute_artifact_path(path: Path) -> Path:
    """Return an absolute lexical path without resolving filesystem links."""
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _safe_close_descriptor(descriptor: int) -> None:
    """Close a descriptor without masking the primary boundary result."""
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except Exception:
        pass


def _safe_dispose_engine(engine: Any) -> None:
    """Release pooled SQLite descriptors without leaking cleanup failures."""
    try:
        engine.dispose()
    except Exception:
        pass


class _EngineBoundSession(Session):
    """Dispose the private SQLite engine when its owning session closes."""

    def close(self) -> None:
        engine = self.info.pop("forge_private_engine", None)
        finalizer = self.info.pop("forge_private_engine_finalizer", None)
        try:
            super().close()
        finally:
            if engine is not None:
                _safe_dispose_engine(engine)
            if finalizer is not None and finalizer.alive:
                finalizer.detach()


class _ManagedSQLiteConnection(sqlite3.Connection):
    """Close an abandoned DB-API handle before Python can emit a leak warning.

    Explicit session/cache shutdown remains the normal lifecycle. This final
    boundary is needed because scanners and third-party integrations can retain
    a SQLAlchemy session until cyclic garbage collection, where Python 3.13
    otherwise reports the underlying SQLite handle before an engine finalizer
    has an opportunity to dispose it.
    """

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def _engine_bound_session(
    engine: Any,
    *,
    autocommit: bool = False,
    autoflush: bool = False,
) -> Session:
    """Return a session whose explicit close or collection releases SQLite."""

    factory = sessionmaker(
        bind=engine,
        class_=_EngineBoundSession,
        autocommit=autocommit,
        autoflush=autoflush,
    )
    session = factory()
    session.info["forge_private_engine"] = engine
    session.info["forge_private_engine_finalizer"] = weakref.finalize(
        session,
        _safe_dispose_engine,
        engine,
    )
    return session


def _artifact_identity(metadata: os.stat_result) -> _ArtifactIdentity:
    """Return the filesystem identity used to bind one database lifetime."""
    return metadata.st_dev, metadata.st_ino


def _open_private_directory(directory: Path) -> int:
    """Open a directory tree without following any component symlinks.

    Missing components are created descriptor-relatively as 0700. Existing
    caller-owned directory modes are preserved. Returning the final descriptor
    lets callers create artifacts relative to the exact tree that was checked,
    instead of re-traversing an attacker-swappable path string.
    """
    directory = _absolute_artifact_path(directory)
    descriptor = -1
    try:
        anchor = directory.anchor
        if not anchor:
            raise _DatabaseArtifactError("database directory is unavailable")
        descriptor = os.open(anchor, _DIRECTORY_OPEN_FLAGS)
        for component in directory.parts[1:]:
            created = False
            try:
                metadata = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                metadata = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise _DatabaseArtifactError(
                    "database directory must be a real directory"
                )

            child_descriptor = -1
            try:
                child_descriptor = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
                opened_metadata = os.fstat(child_descriptor)
                if (
                    not stat.S_ISDIR(opened_metadata.st_mode)
                    or opened_metadata.st_dev != metadata.st_dev
                    or opened_metadata.st_ino != metadata.st_ino
                ):
                    raise _DatabaseArtifactError(
                        "database directory changed during traversal"
                    )
                if created:
                    os.fchmod(child_descriptor, 0o700)
                _safe_close_descriptor(descriptor)
                descriptor = child_descriptor
                child_descriptor = -1
            finally:
                _safe_close_descriptor(child_descriptor)

        result = descriptor
        descriptor = -1
        return result
    except _DatabaseArtifactError:
        raise
    except Exception:
        raise _DatabaseArtifactError("database directory is unavailable") from None
    finally:
        _safe_close_descriptor(descriptor)


def _ensure_private_directory(directory: Path) -> None:
    """Create missing directory components as 0700 and preserve existing modes."""
    descriptor = -1
    try:
        descriptor = _open_private_directory(directory)
    finally:
        _safe_close_descriptor(descriptor)


def _open_owner_only_regular_file(
    path: Path,
    *,
    create: bool = True,
    expected_parent_identity: _ArtifactIdentity | None = None,
    expected_file_identity: _ArtifactIdentity | None = None,
) -> int:
    """Open one unaliased 0600 regular file without following symlinks."""
    path = _absolute_artifact_path(path)
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = _open_private_directory(path.parent)
        if (
            expected_parent_identity is not None
            and _artifact_identity(os.fstat(parent_descriptor))
            != expected_parent_identity
        ):
            raise _DatabaseArtifactError(
                "database artifact changed during connection"
            )
        flags = _FILE_OPEN_FLAGS if create else _EXISTING_FILE_OPEN_FLAGS
        try:
            descriptor = os.open(
                path.name,
                flags,
                0o600,
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            if not create:
                return -1
            raise
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise _DatabaseArtifactError(
                "database artifact must be one unaliased regular file"
            )
        if (
            expected_file_identity is not None
            and _artifact_identity(metadata) != expected_file_identity
        ):
            raise _DatabaseArtifactError(
                "database artifact changed during connection"
            )
        os.fchmod(descriptor, 0o600)
        result = descriptor
        descriptor = -1
        return result
    except _DatabaseArtifactError:
        raise
    except Exception:
        raise _DatabaseArtifactError("database artifact is unavailable") from None
    finally:
        _safe_close_descriptor(descriptor)
        _safe_close_descriptor(parent_descriptor)


def _secure_existing_sqlite_sidecars(
    db_path: Path,
    *,
    expected_parent_identity: _ArtifactIdentity | None = None,
) -> None:
    """Validate and tighten every existing SQLite journal sidecar."""
    for suffix in _SQLITE_SIDECAR_SUFFIXES:
        descriptor = _open_owner_only_regular_file(
            Path(f"{db_path}{suffix}"),
            create=False,
            expected_parent_identity=expected_parent_identity,
        )
        _safe_close_descriptor(descriptor)


def _verify_descriptor_path_identity(
    descriptor: int,
    path: Path,
    *,
    expected_parent_identity: _ArtifactIdentity | None = None,
    expected_file_identity: _ArtifactIdentity | None = None,
) -> None:
    """Fail if the database directory entry no longer names the opened inode."""
    parent_descriptor = -1
    try:
        path = _absolute_artifact_path(path)
        parent_descriptor = _open_private_directory(path.parent)
        parent_metadata = os.fstat(parent_descriptor)
        descriptor_metadata = os.fstat(descriptor)
        path_metadata = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or path_metadata.st_nlink != 1
            or (
                expected_parent_identity is not None
                and _artifact_identity(parent_metadata)
                != expected_parent_identity
            )
            or (
                expected_file_identity is not None
                and _artifact_identity(descriptor_metadata)
                != expected_file_identity
            )
            or descriptor_metadata.st_dev != path_metadata.st_dev
            or descriptor_metadata.st_ino != path_metadata.st_ino
        ):
            raise _DatabaseArtifactError(
                "database artifact changed during connection"
            )
    except _DatabaseArtifactError:
        raise
    except Exception:
        raise _DatabaseArtifactError("database artifact is unavailable") from None
    finally:
        _safe_close_descriptor(parent_descriptor)


def _capture_sqlite_lifetime_identity(
    db_path: Path,
) -> tuple[_ArtifactIdentity, _ArtifactIdentity]:
    """Create/open the database and bind its parent and inode for this engine."""
    descriptor = _open_owner_only_regular_file(db_path)
    parent_descriptor = -1
    try:
        parent_descriptor = _open_private_directory(db_path.parent)
        parent_identity = _artifact_identity(os.fstat(parent_descriptor))
        file_identity = _artifact_identity(os.fstat(descriptor))
        _verify_descriptor_path_identity(
            descriptor,
            db_path,
            expected_parent_identity=parent_identity,
            expected_file_identity=file_identity,
        )
        return parent_identity, file_identity
    finally:
        _safe_close_descriptor(parent_descriptor)
        _safe_close_descriptor(descriptor)


def _sqlite_descriptor_path(descriptor: int) -> str | None:
    """Return a stable descriptor-backed path on platforms that expose one."""
    for root in ("/proc/self/fd", "/dev/fd"):
        if os.path.isdir(root):
            return f"{root}/{descriptor}"
    return None


def _connect_sqlite_file(
    db_path: Path,
    parent_identity: _ArtifactIdentity | None = None,
    file_identity: _ArtifactIdentity | None = None,
) -> sqlite3.Connection:
    """Connect SQLite to a verified descriptor, keeping WAL artifacts private."""
    descriptor = _open_owner_only_regular_file(
        db_path,
        create=file_identity is None,
        expected_parent_identity=parent_identity,
        expected_file_identity=file_identity,
    )
    if descriptor < 0:
        raise _DatabaseArtifactError(
            "database artifact changed during connection"
        )
    connection: sqlite3.Connection | None = None
    try:
        _verify_descriptor_path_identity(
            descriptor,
            db_path,
            expected_parent_identity=parent_identity,
            expected_file_identity=file_identity,
        )
        _secure_existing_sqlite_sidecars(
            db_path,
            expected_parent_identity=parent_identity,
        )
        descriptor_path = _sqlite_descriptor_path(descriptor)
        if descriptor_path is None:
            raise _DatabaseArtifactError(
                "descriptor-backed database access is unavailable"
            )
        connection = sqlite3.connect(
            descriptor_path,
            check_same_thread=False,
            factory=_ManagedSQLiteConnection,
        )
        cursor = connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()
        _verify_descriptor_path_identity(
            descriptor,
            db_path,
            expected_parent_identity=parent_identity,
            expected_file_identity=file_identity,
        )
        _secure_existing_sqlite_sidecars(
            db_path,
            expected_parent_identity=parent_identity,
        )
        return connection
    except _DatabaseArtifactError:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        raise
    except Exception:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        raise DatabaseInitializationError("database connection failed") from None
    finally:
        _safe_close_descriptor(descriptor)


@contextmanager
def _db_schema_lock(db_path: Path):
    """Cross-process owner-only lock for SQLite schema setup."""
    lock_path = db_path.with_suffix(db_path.suffix + ".schema.lock")
    descriptor = _open_owner_only_regular_file(lock_path)
    try:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        else:
            # Fallback only protects against tight same-process timing on non-POSIX.
            time.sleep(0.05)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        _safe_close_descriptor(descriptor)


def create_db(db_path: Path) -> Session:
    """Create SQLite database, all tables, and return a session.

    Args:
        db_path: Path to the .db file. Created if not exists.

    Returns:
        SQLAlchemy Session bound to the database.
    """
    engine: Any | None = None
    try:
        db_path = _absolute_artifact_path(db_path)
        _ensure_private_directory(db_path.parent)
        with _db_schema_lock(db_path):
            parent_identity, file_identity = _capture_sqlite_lifetime_identity(
                db_path
            )
            engine = create_engine(
                URL.create("sqlite+pysqlite", database=os.fspath(db_path)),
                creator=lambda: _connect_sqlite_file(
                    db_path,
                    parent_identity,
                    file_identity,
                ),
                echo=False,
            )

            # WAL is selected in the descriptor-backed creator. Keep the event
            # for foreign-key enforcement on every pooled DB-API connection.
            @event.listens_for(engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):  # type: ignore
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

            Base.metadata.create_all(engine)
            _migrate_sqlite_schema(engine)
            # Task 101 canonical contracts are additive to the legacy ORM
            # tables.  Keep the migration runner separate so existing callers
            # retain their models while new adapters receive explicit
            # tenant-scoped foreign-key lineage and reversible schema state.
            from common.schema_migrations import MigrationManager

            MigrationManager(engine).upgrade()
        return _engine_bound_session(engine, autocommit=False, autoflush=False)
    except _DatabaseArtifactError:
        if engine is not None:
            _safe_dispose_engine(engine)
        raise
    except Exception:
        if engine is not None:
            _safe_dispose_engine(engine)
        raise DatabaseInitializationError("database initialization failed") from None


def _stable_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")


def _snapshot_identity(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_stable_json_bytes(value)).hexdigest()


def _legacy_finding_snapshot(row: Any) -> dict[str, Any]:
    """Build a conservative redacted snapshot while migrating ``seen_runs``."""

    def _value(name: str, default: Any = None) -> Any:
        try:
            value = row[name]
        except (KeyError, IndexError, TypeError):
            return default
        return default if value is None else value

    def _json(name: str, default: Any) -> Any:
        raw = _value(name)
        if isinstance(raw, (dict, list)):
            return raw
        try:
            decoded = json.loads(str(raw))
        except (TypeError, json.JSONDecodeError):
            return default
        return decoded if isinstance(decoded, type(default)) else default

    snapshot = {
        "id": str(_value("id", "")),
        "tenant_id": str(_value("tenant_id", "default") or "default"),
        "title": str(_value("title", "")),
        "severity": str(_value("severity", "informational")),
        "target": str(_value("target", "")),
        "url": _value("url"),
        "port": _value("port"),
        "service": _value("service"),
        "module": str(_value("module", "")),
        "description": str(_value("description", "")),
        "reproduction_steps": _json("reproduction_steps", []),
        "remediation": str(_value("remediation", "")),
        "references": _json("references", []),
        "cvss_v31_vector": _value("cvss_v31_vector"),
        "cvss_v31_score": _value("cvss_v31_score"),
        "cvss_v40_vector": _value("cvss_v40_vector"),
        "cvss_v40_score": _value("cvss_v40_score"),
        "mitre_attack": _json("mitre_attack", []),
        "operator_confirmed": bool(_value("operator_confirmed", False)),
        "tags": _json("tags", []),
        "confidence": str(_value("confidence", "UNVERIFIED")),
        "status": str(_value("status", "open")),
        "verification": _strip_legacy_raw_evidence(
            _json("verification", {})
        ),
        "verification_state": str(_value("verification_state", "unknown")),
        "proof_type": str(_value("proof_type", "unknown")),
        "maturity": str(_value("maturity", "experimental")),
        "dedup_key": str(_value("dedup_key", "")),
        "discovered_at": str(_value("discovered_at", "")),
        "first_seen_at": str(_value("first_seen_at", "")),
        "last_seen_at": str(_value("last_seen_at", "")),
        "last_seen_run": _value("last_seen_run"),
        "times_seen": int(_value("times_seen", 1) or 1),
        "days_open": int(_value("days_open", 0) or 0),
        "priority": _value("priority"),
        "evidence": {
            # Evidence bytes and caller-controlled paths are not part of an
            # immutable run-membership snapshot.  Legacy rows may still have
            # the historical columns while a database is being upgraded, but
            # snapshots must never copy those values into another mutable JSON
            # surface.  Canonical adapters attach custody manifest references
            # separately.
            "request_raw": None,
            "response_raw": None,
            "screenshot_path": None,
            "console_capture_path": None,
            "pcap_path": None,
        },
    }
    canonical_dedup = str(snapshot["dedup_key"] or "").strip().lower()
    if (
        len(canonical_dedup) != 64
        or any(
            character not in "0123456789abcdef"
            for character in canonical_dedup
        )
    ):
        canonical_dedup = finding_dedup_key(snapshot)
    snapshot["dedup_key"] = canonical_dedup
    safe = redact_value(snapshot)
    if not isinstance(safe, dict):
        return {}
    # These are opaque structural identities, not secret-bearing key values.
    # Restoring them prevents redaction from collapsing all migrated findings
    # for a run onto the literal ``<redacted>`` membership key.
    safe["id"] = snapshot["id"]
    safe["tenant_id"] = snapshot["tenant_id"]
    safe["dedup_key"] = canonical_dedup
    return safe


def _migrate_sqlite_schema(engine: Any) -> None:
    """Add nullable columns introduced after the initial findings table."""
    migrations = {
        "schema_migrations": {
            "version": "VARCHAR(100)",
            "applied_at": "DATETIME",
        },
        "findings": {
            "tenant_id": "VARCHAR(100)",
            "url": "VARCHAR(1000)",
            "confidence": "VARCHAR(20)",
            "status": "VARCHAR(50)",
            "vpr_score": "FLOAT",
            "vpr_priority": "VARCHAR(20)",
            "verification": "TEXT",
            "verification_state": "VARCHAR(30) NOT NULL DEFAULT 'unknown'",
            "proof_type": "VARCHAR(50) NOT NULL DEFAULT 'unknown'",
            "maturity": "VARCHAR(30) NOT NULL DEFAULT 'experimental'",
            "dedup_key": "VARCHAR(64)",
            "first_seen_at": "DATETIME",
            "last_seen_at": "DATETIME",
            "last_seen_run": "VARCHAR(200)",
            "seen_runs": "TEXT",
            "times_seen": "INTEGER",
            "days_open": "INTEGER",
            "priority": "VARCHAR(20)",
        },
        "run_collection_truth": {
            "run_id": "VARCHAR(160)",
            "authorization_run_id": "VARCHAR(160)",
            "job_id": "VARCHAR(160)",
            "tenant_id": "VARCHAR(100)",
            "framework": "VARCHAR(100)",
            "scope_binding": "VARCHAR(80)",
            "target_binding": "VARCHAR(80)",
            "collection_status": "VARCHAR(40)",
            "coverage_complete": "BOOLEAN",
            "coverage_identity": "VARCHAR(80)",
            "finding_set_identity": "VARCHAR(80)",
            "predecessor_run_id": "VARCHAR(160)",
            "run_sequence": "INTEGER",
            "completed_at": "VARCHAR(80)",
            "authorization_decision_id": "VARCHAR(64)",
            "authorization_binding": "VARCHAR(80)",
            "authority_id": "VARCHAR(160)",
            "policy_id": "VARCHAR(100)",
            "policy_version": "VARCHAR(80)",
            "issuer_id": "VARCHAR(160)",
            "attestation": "TEXT",
            "recorded_at": "DATETIME",
        },
        "finding_run_membership": {
            "tenant_id": "VARCHAR(100)",
            "run_id": "VARCHAR(160)",
            "finding_id": "VARCHAR(64)",
            "dedup_key": "VARCHAR(64)",
            "snapshot_json": "TEXT",
            "snapshot_identity": "VARCHAR(80)",
            "recorded_at": "DATETIME",
        },
        "finding_delta_reports": {
            "tenant_id": "VARCHAR(100)",
            "previous_run_id": "VARCHAR(160)",
            "current_run_id": "VARCHAR(160)",
            "authorization_decision_id": "VARCHAR(64)",
            "authorization_binding": "VARCHAR(80)",
            "report_json": "TEXT",
            "report_identity": "VARCHAR(80)",
            "recorded_at": "DATETIME",
        },
        "scan_jobs": {
            "tenant_id": "VARCHAR(100) NOT NULL DEFAULT 'default'",
            "status": "VARCHAR(20)",
            "target": "VARCHAR(500)",
            "frameworks": "TEXT",
            "modules": "TEXT",
            "pid": "INTEGER",
            "return_code": "INTEGER",
            "results_dir": "VARCHAR(1000)",
            "logs": "TEXT",
            "error": "TEXT",
            "created_at": "DATETIME",
            "updated_at": "DATETIME",
            "started_at": "DATETIME",
            "completed_at": "DATETIME",
            "authorization_state": (
                "VARCHAR(50) NOT NULL DEFAULT 'unknown_not_authorized'"
            ),
            "authorization_decision_id": "VARCHAR(64)",
            "authorization_action_id": "VARCHAR(64)",
        },
        "authorization_decisions": {
            "decision_id": "VARCHAR(64)",
            "schema_version": "VARCHAR(80)",
            "parent_decision_id": "VARCHAR(64)",
            "tenant_id": "VARCHAR(100)",
            "engagement_id": "VARCHAR(160)",
            "run_id": "VARCHAR(160)",
            "job_id": "VARCHAR(160)",
            "action_id": "VARCHAR(64)",
            "operator_id": "VARCHAR(200)",
            "operator_role": "VARCHAR(50)",
            "action_kind": "VARCHAR(100)",
            "engine": "VARCHAR(100)",
            "module_id": "VARCHAR(200)",
            "requested_target": "VARCHAR(80)",
            "resolved_target": "VARCHAR(80)",
            "scope_snapshot": "VARCHAR(80)",
            "scope_policy_version": "VARCHAR(100)",
            "scope_decision": "VARCHAR(40)",
            "scope_reason_code": "VARCHAR(100)",
            "decision_outcome": "VARCHAR(50)",
            "reason_code": "VARCHAR(100)",
            "issued_at": "DATETIME",
            "expires_at": "DATETIME",
            "binding_digest": "VARCHAR(80)",
            "confirmation_digest": "VARCHAR(80)",
            "envelope_json": "TEXT",
            "detail": "TEXT",
            "recorded_at": "DATETIME",
        },
        "authorization_consumptions": {
            "consumption_id": "VARCHAR(64)",
            "decision_id": "VARCHAR(64)",
            "tenant_id": "VARCHAR(100)",
            "job_id": "VARCHAR(160)",
            "action_id": "VARCHAR(64)",
            "boundary": "VARCHAR(160)",
            "result_id": "VARCHAR(160)",
            "envelope_digest": "VARCHAR(80)",
            "consumed_at": "DATETIME",
        },
        "authorization_execution_claims": {
            "claim_id": "VARCHAR(64)",
            "decision_id": "VARCHAR(64)",
            "tenant_id": "VARCHAR(100)",
            "job_id": "VARCHAR(160)",
            "action_id": "VARCHAR(64)",
            "boundary": "VARCHAR(160)",
            "envelope_digest": "VARCHAR(80)",
            "claimed_at": "DATETIME",
        },
        "outbound_decisions": {
            "decision_id": "VARCHAR(64)",
            "schema_version": "VARCHAR(80)",
            "authorization_decision_id": "VARCHAR(64)",
            "action_id": "VARCHAR(64)",
            "tenant_id": "VARCHAR(100)",
            "engagement_id": "VARCHAR(160)",
            "run_id": "VARCHAR(160)",
            "job_id": "VARCHAR(160)",
            "engine": "VARCHAR(100)",
            "module_id": "VARCHAR(200)",
            "action_kind": "VARCHAR(100)",
            "stage": "VARCHAR(50)",
            "destination_ref": "VARCHAR(80)",
            "scheme": "VARCHAR(20)",
            "host": "VARCHAR(300)",
            "port": "INTEGER",
            "resolved_addresses": "TEXT",
            "outcome": "VARCHAR(30)",
            "reason_code": "VARCHAR(100)",
            "route_id": "VARCHAR(100)",
            "route_configuration_digest": "VARCHAR(80)",
            "tls_mode": "VARCHAR(50)",
            "binding_digest": "VARCHAR(80)",
            "detail": "TEXT",
            "recorded_at": "DATETIME",
        },
        "route_health_evidence": {
            "evidence_id": "VARCHAR(64)",
            "schema_version": "VARCHAR(80)",
            "route_id": "VARCHAR(100)",
            "tenant_id": "VARCHAR(100)",
            "engagement_id": "VARCHAR(160)",
            "action_id": "VARCHAR(64)",
            "configuration_digest": "VARCHAR(80)",
            "runtime_id": "VARCHAR(100)",
            "dns_mode": "VARCHAR(50)",
            "verification_endpoint_ref": "VARCHAR(80)",
            "observed_egress": "VARCHAR(100)",
            "route_identity": "VARCHAR(200)",
            "verified_at": "DATETIME",
            "expires_at": "DATETIME",
            "binding_digest": "VARCHAR(80)",
            "detail": "TEXT",
            "recorded_at": "DATETIME",
        },
        "route_health_invalidations": {
            "invalidation_id": "VARCHAR(64)",
            "schema_version": "VARCHAR(80)",
            "route_id": "VARCHAR(100)",
            "tenant_id": "VARCHAR(100)",
            "engagement_id": "VARCHAR(160)",
            "action_id": "VARCHAR(64)",
            "configuration_digest": "VARCHAR(80)",
            "health_sequence": "INTEGER",
            "runtime_id": "VARCHAR(100)",
            "reason_code": "VARCHAR(100)",
            "binding_digest": "VARCHAR(80)",
            "recorded_at": "DATETIME",
        },
        "finding_retests": {
            "finding_id": "VARCHAR(36)",
            "status": "VARCHAR(20)",
            "module": "VARCHAR(100)",
            "target": "VARCHAR(500)",
            "url": "VARCHAR(1000)",
            "param": "VARCHAR(200)",
            "payload_class": "VARCHAR(100)",
            "session_ref": "VARCHAR(500)",
            "job_id": "VARCHAR(36)",
            "still_vulnerable": "BOOLEAN",
            "confidence": "VARCHAR(20)",
            "evidence": "TEXT",
            "metadata_json": "TEXT",
            "error": "TEXT",
            "created_at": "DATETIME",
            "retested_at": "DATETIME",
        },
        "scan_runs": {
            "tenant_id": "VARCHAR(100)",
        },
        "dashboard_state": {
            "tenant_id": "VARCHAR(100)",
        },
        "audit_logs": {
            "timestamp": "DATETIME",
            "tenant_id": "VARCHAR(100)",
            "operator": "VARCHAR(200)",
            "role": "VARCHAR(50)",
            "ip": "VARCHAR(100)",
            "action": "VARCHAR(200)",
            "object_id": "VARCHAR(500)",
            "status": "VARCHAR(50)",
            "detail": "TEXT",
        },
    }
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version VARCHAR(100) PRIMARY KEY, applied_at DATETIME NOT NULL)"
        )
        for table, columns in migrations.items():
            existing = {
                row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
            }
            for column, ddl in columns.items():
                if column not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

        # The preliminary WP006 table used a globally unique run_id and its
        # signature omitted predecessor, authorization, and finding-set
        # bindings. Preserve those rows as a fail-closed append-only archive and
        # create the tenant-scoped v3 authority table rather than pretending an
        # old signature attested fields it never covered.
        run_truth_v3 = "wp006_run_collection_truth_v3"
        run_truth_v3_applied = conn.exec_driver_sql(
            "SELECT 1 FROM schema_migrations WHERE version=?",
            (run_truth_v3,),
        ).fetchone()
        if run_truth_v3_applied is None:
            table_sql_row = conn.exec_driver_sql(
                "SELECT sql FROM sqlite_master "
                "WHERE type='table' AND name='run_collection_truth'"
            ).fetchone()
            table_sql = str(table_sql_row[0] if table_sql_row else "")
            current_shape = (
                "uq_run_collection_truth_tenant_run" in table_sql
                and "authorization_run_id" in table_sql
                and "finding_set_identity" in table_sql
                and "run_sequence" in table_sql
            )
            if not current_shape:
                conn.exec_driver_sql(
                    "DROP TRIGGER IF EXISTS run_collection_truth_no_update"
                )
                conn.exec_driver_sql(
                    "DROP TRIGGER IF EXISTS run_collection_truth_no_delete"
                )
                legacy_exists = conn.exec_driver_sql(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='run_collection_truth_legacy_v1'"
                ).fetchone()
                if legacy_exists is not None:
                    raise DatabaseInitializationError(
                        "legacy run truth archive already exists without migration marker"
                    )
                conn.exec_driver_sql(
                    "ALTER TABLE run_collection_truth "
                    "RENAME TO run_collection_truth_legacy_v1"
                )
                cast(Table, RunCollectionTruthModel.__table__).create(
                    bind=conn,
                    checkfirst=True,
                )
            conn.exec_driver_sql(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (run_truth_v3, datetime.now(timezone.utc)),
            )

        conn.exec_driver_sql(
            "UPDATE scan_jobs SET authorization_state='unknown_not_authorized' "
            "WHERE authorization_state IS NULL OR authorization_state=''"
        )
        conn.exec_driver_sql(
            "UPDATE scan_jobs SET tenant_id='default' "
            "WHERE tenant_id IS NULL OR tenant_id=''"
        )
        conn.exec_driver_sql(
            "UPDATE findings SET tenant_id='default' "
            "WHERE tenant_id IS NULL OR tenant_id=''"
        )
        # A persisted ``allow`` state is meaningful only when it points at the
        # exact immutable decision and its one-time consumption.  Older rows
        # (and rows written by untrusted callers) may contain a client-supplied
        # flag without either record; downgrade those rows before they can be
        # returned by dashboard authorization lookups.
        conn.exec_driver_sql(
            "UPDATE scan_jobs SET "
            "authorization_state='unknown_not_authorized', "
            "authorization_decision_id=NULL, "
            "authorization_action_id=NULL "
            "WHERE LOWER(COALESCE(authorization_state, ''))='allow' "
            "AND NOT EXISTS ("
            "SELECT 1 FROM authorization_decisions d "
            "JOIN authorization_consumptions c ON c.decision_id=d.decision_id "
            "WHERE d.decision_id=scan_jobs.authorization_decision_id "
            "AND d.decision_outcome='allow' "
            "AND d.job_id=scan_jobs.id "
            "AND d.tenant_id=COALESCE(scan_jobs.tenant_id, 'default') "
            "AND d.action_id=scan_jobs.authorization_action_id "
            "AND c.job_id=d.job_id "
            "AND c.action_id=d.action_id "
            "AND c.tenant_id=d.tenant_id "
            "AND c.envelope_digest=d.binding_digest"
            ") "
            "AND NOT EXISTS ("
            "SELECT 1 FROM authorization_decisions child "
            "JOIN authorization_decisions p ON p.decision_id=child.parent_decision_id "
            "JOIN authorization_consumptions pc ON pc.decision_id=p.decision_id "
            "WHERE child.decision_id=scan_jobs.authorization_decision_id "
            "AND child.decision_outcome='allow' "
            "AND p.decision_outcome='allow' "
            "AND p.job_id=scan_jobs.id "
            "AND p.tenant_id=COALESCE(scan_jobs.tenant_id, 'default') "
            "AND pc.job_id=p.job_id "
            "AND pc.action_id=p.action_id "
            "AND pc.tenant_id=p.tenant_id "
            "AND pc.envelope_digest=p.binding_digest"
            ")"
        )
        conn.exec_driver_sql(
            "UPDATE findings SET verification_state='unknown' "
            "WHERE verification_state IS NULL OR verification_state=''"
        )
        conn.exec_driver_sql(
            "UPDATE findings SET proof_type='unknown' "
            "WHERE proof_type IS NULL OR proof_type=''"
        )
        conn.exec_driver_sql(
            "UPDATE findings SET maturity='experimental' "
            "WHERE maturity IS NULL OR maturity=''"
        )
        legacy_truth_migration = "wp006_legacy_verification_truth_v1"
        already_applied = conn.exec_driver_sql(
            "SELECT 1 FROM schema_migrations WHERE version=?",
            (legacy_truth_migration,),
        ).fetchone()
        if already_applied is None:
            legacy_predicate = (
                "lower(COALESCE(status, ''))='verified' OR "
                "lower(COALESCE(verification_state, ''))='verified' OR "
                "(json_valid(verification)=1 AND ("
                "lower(COALESCE(json_extract(verification, '$.state'), ''))='verified' OR "
                "json_extract(verification, '$.verified')=1))"
            )
            lineage_predicate = (
                "json_valid(verification)=1 AND "
                "(COALESCE(json_extract(verification, '$.policy_id'), '')='forge-verification-policy' OR "
                "COALESCE(json_extract(verification, '$.policy_id'), '')='forge-active-proof-v1') AND "
                "COALESCE(json_extract(verification, '$.policy_version'), '')='1.0' AND "
                "COALESCE(json_extract(verification, '$.proof_policy_id'), '')='forge-active-proof-v1' AND "
                "COALESCE(json_extract(verification, '$.proof_policy_version'), '')='1.0' AND "
                "COALESCE(json_extract(verification, '$.capability_id'), '')='forge:active-proof-review' AND "
                "COALESCE(json_extract(verification, '$.capability_version'), '')='1.0'"
            )
            conn.exec_driver_sql(
                "UPDATE findings SET verification="
                "CASE "
                "WHEN verification IS NULL OR verification='' OR json_valid(verification)=0 "
                "THEN json_object('legacy_status', 'verified') "
                "ELSE json_set(verification, '$.legacy_status', 'verified') "
                "END WHERE (" + legacy_predicate + ") AND NOT (" + lineage_predicate + ")"
            )
            conn.exec_driver_sql(
                "UPDATE findings SET "
                "status=CASE WHEN status='verified' THEN 'open' ELSE status END, "
                "verification_state='unknown', proof_type='unknown', maturity='experimental' "
                "WHERE (" + legacy_predicate + ") AND NOT (" + lineage_predicate + ")"
            )
            conn.exec_driver_sql(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (legacy_truth_migration, datetime.now(timezone.utc)),
            )

        # V1 treated public policy metadata as if it could preserve a raw
        # verified claim.  Policy identifiers are public routing metadata, not
        # a trusted revalidation authority, so V2 conservatively downgrades
        # every historical verified shape while retaining its lineage JSON.
        legacy_truth_migration_v2 = "wp006_legacy_verification_truth_v2"
        v2_already_applied = conn.exec_driver_sql(
            "SELECT 1 FROM schema_migrations WHERE version=?",
            (legacy_truth_migration_v2,),
        ).fetchone()
        if v2_already_applied is None:
            legacy_verified_predicate_v2 = (
                "lower(trim(COALESCE(CAST(status AS TEXT), '')))='verified' OR "
                "lower(trim(COALESCE(CAST(verification_state AS TEXT), '')))="
                "'verified' OR "
                "lower(trim(COALESCE(CAST(maturity AS TEXT), '')))='verified' OR "
                "(json_valid(verification)=1 AND ("
                "lower(trim(COALESCE(CAST(json_extract(verification, "
                "'$.state') AS TEXT), '')))='verified' OR "
                "lower(trim(COALESCE(CAST(json_extract(verification, "
                "'$.verification_state') AS TEXT), '')))='verified' OR "
                "lower(trim(COALESCE(CAST(json_extract(verification, "
                "'$.status') AS TEXT), '')))='verified' OR "
                "lower(trim(COALESCE(CAST(json_extract(verification, "
                "'$.maturity') AS TEXT), '')))='verified' OR "
                "json_type(verification, '$.verified')='true' OR "
                "(json_type(verification, '$.verified') IN ('integer', 'real') "
                "AND CAST(json_extract(verification, '$.verified') AS REAL)<>0) OR "
                "(json_type(verification, '$.verified')='text' AND "
                "lower(trim(CAST(json_extract(verification, '$.verified') "
                "AS TEXT))) IN ('1', 'true', 'yes', 'verified'))))"
            )
            conn.exec_driver_sql(
                "UPDATE findings SET verification=CASE "
                "WHEN json_valid(verification)=1 "
                "AND json_type(verification)='object' THEN CASE "
                "WHEN json_type(verification, '$.legacy_status') IS NOT NULL "
                "THEN verification "
                "ELSE json_set(verification, '$.legacy_status', 'verified') END "
                "ELSE json_object('legacy_status', 'verified') END "
                "WHERE (" + legacy_verified_predicate_v2 + ")"
            )
            conn.exec_driver_sql(
                "UPDATE findings SET "
                "status=CASE WHEN "
                "lower(trim(COALESCE(CAST(status AS TEXT), '')))='verified' "
                "THEN 'open' ELSE status END, "
                "verification_state='unknown', proof_type='unknown', "
                "maturity='experimental' "
                "WHERE (" + legacy_verified_predicate_v2 + ")"
            )
            conn.exec_driver_sql(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (legacy_truth_migration_v2, datetime.now(timezone.utc)),
            )

        tenant_dedup_migration = "wp006_tenant_finding_dedup_v1"
        tenant_dedup_applied = conn.exec_driver_sql(
            "SELECT 1 FROM schema_migrations WHERE version=?",
            (tenant_dedup_migration,),
        ).fetchone()
        if tenant_dedup_applied is None:
            # Backfill a canonical key before enforcing uniqueness.  Historical
            # databases could contain multiple rows for the same tenant/key;
            # consolidate those rows deterministically while retaining their
            # run history and retest ownership instead of letting index creation
            # fail or silently selecting an arbitrary duplicate.
            finding_rows = conn.exec_driver_sql(
                "SELECT id, title, target, url, port, dedup_key FROM findings "
                "ORDER BY id"
            ).mappings().all()
            for row in finding_rows:
                candidate = str(row.get("dedup_key") or "").strip().lower()
                if (
                    len(candidate) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in candidate
                    )
                ):
                    candidate = finding_dedup_key(dict(row))
                    conn.exec_driver_sql(
                        "UPDATE findings SET dedup_key=? WHERE id=?",
                        (candidate, str(row["id"])),
                    )
            duplicate_groups = conn.exec_driver_sql(
                "SELECT tenant_id, dedup_key FROM findings "
                "WHERE dedup_key IS NOT NULL AND dedup_key<>'' "
                "GROUP BY tenant_id, dedup_key HAVING COUNT(*)>1 "
                "ORDER BY tenant_id, dedup_key"
            ).fetchall()
            priority_rank = {
                "CRITICAL": 4,
                "HIGH": 3,
                "MEDIUM": 2,
                "LOW": 1,
                "INFO": 0,
            }
            for tenant_id, dedup_key in duplicate_groups:
                duplicates = conn.exec_driver_sql(
                    "SELECT id, seen_runs, engagement, last_seen_run, "
                    "times_seen, first_seen_at, last_seen_at, discovered_at, "
                    "days_open, priority FROM findings WHERE tenant_id=? "
                    "AND dedup_key=? ORDER BY "
                    "COALESCE(first_seen_at, discovered_at) ASC, id ASC",
                    (tenant_id, dedup_key),
                ).mappings().all()
                if len(duplicates) < 2:
                    continue
                keeper_id = str(duplicates[0]["id"])
                seen_runs: list[str] = []
                timestamps: list[datetime] = []
                last_candidates: list[tuple[datetime, str]] = []
                times_seen = 0
                days_open = 0
                priority = "INFO"
                for duplicate in duplicates:
                    raw_seen_runs = duplicate.get("seen_runs")
                    try:
                        decoded_runs = json.loads(str(raw_seen_runs or "[]"))
                    except (TypeError, json.JSONDecodeError):
                        decoded_runs = []
                    if not isinstance(decoded_runs, list):
                        decoded_runs = []
                    for raw_run in (
                        *decoded_runs,
                        duplicate.get("engagement"),
                        duplicate.get("last_seen_run"),
                    ):
                        run = str(raw_run or "").strip()
                        if run and run not in seen_runs:
                            seen_runs.append(run)
                    times_seen += max(int(duplicate.get("times_seen") or 1), 1)
                    days_open = max(days_open, int(duplicate.get("days_open") or 0))
                    candidate_priority = str(duplicate.get("priority") or "INFO").upper()
                    if priority_rank.get(candidate_priority, 0) > priority_rank.get(priority, 0):
                        priority = candidate_priority
                    for field in ("first_seen_at", "discovered_at"):
                        parsed = _parse_datetime(duplicate.get(field))
                        if parsed is not None:
                            timestamps.append(parsed)
                    last_seen = _parse_datetime(duplicate.get("last_seen_at"))
                    if last_seen is not None:
                        last_candidates.append(
                            (last_seen, str(duplicate.get("last_seen_run") or ""))
                        )
                first_seen = min(timestamps) if timestamps else None
                last_seen, last_seen_run = (
                    max(last_candidates, key=lambda item: item[0])
                    if last_candidates
                    else (None, "")
                )
                conn.exec_driver_sql(
                    "UPDATE findings SET seen_runs=?, times_seen=?, "
                    "first_seen_at=?, last_seen_at=?, last_seen_run=?, "
                    "days_open=?, priority=? WHERE id=?",
                    (
                        json.dumps(seen_runs),
                        times_seen,
                        first_seen,
                        last_seen,
                        last_seen_run or None,
                        days_open,
                        priority,
                        keeper_id,
                    ),
                )
                for duplicate in duplicates[1:]:
                    duplicate_id = str(duplicate["id"])
                    conn.exec_driver_sql(
                        "UPDATE finding_retests SET finding_id=? WHERE finding_id=?",
                        (keeper_id, duplicate_id),
                    )
                    conn.exec_driver_sql(
                        "DELETE FROM findings WHERE id=?",
                        (duplicate_id,),
                    )
            conn.exec_driver_sql("DROP INDEX IF EXISTS ix_findings_tenant_dedup")
            conn.exec_driver_sql(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_tenant_dedup "
                "ON findings(tenant_id, dedup_key) "
                "WHERE dedup_key IS NOT NULL AND dedup_key<>''"
            )
            conn.exec_driver_sql(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (tenant_dedup_migration, datetime.now(timezone.utc)),
            )

        membership_migration = "wp006_finding_run_membership_v1"
        membership_applied = conn.exec_driver_sql(
            "SELECT 1 FROM schema_migrations WHERE version=?",
            (membership_migration,),
        ).fetchone()
        if membership_applied is None:
            rows = conn.exec_driver_sql("SELECT * FROM findings").mappings().all()
            for row in rows:
                snapshot = _legacy_finding_snapshot(row)
                if not snapshot:
                    continue
                raw_seen_runs = row.get("seen_runs")
                try:
                    seen_runs = json.loads(str(raw_seen_runs or "[]"))
                except (TypeError, json.JSONDecodeError):
                    seen_runs = []
                if not isinstance(seen_runs, list):
                    seen_runs = []
                for fallback in (row.get("engagement"), row.get("last_seen_run")):
                    if isinstance(fallback, str) and fallback.strip():
                        seen_runs.append(fallback)
                tenant_id = str(row.get("tenant_id") or "default")
                dedup_key = str(snapshot["dedup_key"])
                snapshot_json = _stable_json_bytes(snapshot).decode("utf-8")
                identity = _snapshot_identity(snapshot)
                for raw_run_id in dict.fromkeys(seen_runs):
                    run_id = str(raw_run_id or "").strip()
                    if not run_id:
                        continue
                    finding_id = str(snapshot.get("id") or "legacy-finding")
                    existing_membership = conn.exec_driver_sql(
                        "SELECT finding_id, snapshot_json, snapshot_identity "
                        "FROM finding_run_membership WHERE tenant_id=? "
                        "AND run_id=? AND dedup_key=?",
                        (tenant_id, run_id, dedup_key),
                    ).fetchone()
                    if existing_membership is not None:
                        if (
                            str(existing_membership[0]) != finding_id
                            or str(existing_membership[1]) != snapshot_json
                            or str(existing_membership[2]) != identity
                        ):
                            raise DatabaseInitializationError(
                                "conflicting legacy finding run membership"
                            )
                        continue
                    conn.exec_driver_sql(
                        "INSERT INTO finding_run_membership ("
                        "tenant_id, run_id, finding_id, dedup_key, snapshot_json, "
                        "snapshot_identity, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            tenant_id,
                            run_id,
                            finding_id,
                            dedup_key,
                            snapshot_json,
                            identity,
                            datetime.now(timezone.utc),
                        ),
                    )
            conn.exec_driver_sql(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (membership_migration, datetime.now(timezone.utc)),
            )
        for table in (
            "authorization_decisions",
            "authorization_consumptions",
            "authorization_execution_claims",
            "outbound_decisions",
            "route_health_evidence",
            "route_health_invalidations",
            "run_collection_truth",
            "finding_run_membership",
            "finding_delta_reports",
        ):
            conn.exec_driver_sql(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_update "
                f"BEFORE UPDATE ON {table} BEGIN "
                "SELECT RAISE(ABORT, 'security records are append-only'); END"
            )
            conn.exec_driver_sql(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_delete "
                f"BEFORE DELETE ON {table} BEGIN "
                "SELECT RAISE(ABORT, 'security records are append-only'); END"
            )
        legacy_truth_archive = conn.exec_driver_sql(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='run_collection_truth_legacy_v1'"
        ).fetchone()
        if legacy_truth_archive is not None:
            for operation in ("UPDATE", "DELETE"):
                suffix = operation.lower()
                conn.exec_driver_sql(
                    f"CREATE TRIGGER IF NOT EXISTS "
                    f"run_collection_truth_legacy_v1_no_{suffix} "
                    f"BEFORE {operation} ON run_collection_truth_legacy_v1 BEGIN "
                    "SELECT RAISE(ABORT, 'security records are append-only'); END"
                )
        conn.exec_driver_sql(
            "CREATE TRIGGER IF NOT EXISTS finding_run_membership_finalized_guard "
            "BEFORE INSERT ON finding_run_membership WHEN EXISTS ("
            "SELECT 1 FROM run_collection_truth t "
            "WHERE t.tenant_id=NEW.tenant_id AND t.run_id=NEW.run_id"
            ") BEGIN "
            "SELECT RAISE(ABORT, 'run membership is finalized'); END"
        )
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_tenant_dedup "
            "ON findings(tenant_id, dedup_key) "
            "WHERE dedup_key IS NOT NULL AND dedup_key<>''"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_finding_membership_tenant_run "
            "ON finding_run_membership(tenant_id, run_id, sequence)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_run_truth_series_latest "
            "ON run_collection_truth(tenant_id, framework, scope_binding, "
            "target_binding, run_sequence DESC)"
        )
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_run_truth_series_successor "
            "ON run_collection_truth(tenant_id, framework, scope_binding, "
            "target_binding, predecessor_run_id) "
            "WHERE predecessor_run_id<>''"
        )
        # Route-health observations are append-only, but a fresh process must
        # not silently establish a new baseline for an existing approved
        # route/action.  SQLite evaluates these guards inside the INSERT, so
        # concurrent workers cannot both accept conflicting egress identities.
        conn.exec_driver_sql(
            "CREATE TRIGGER IF NOT EXISTS route_health_configuration_guard "
            "BEFORE INSERT ON route_health_evidence "
            "WHEN EXISTS ("
            "SELECT 1 FROM route_health_evidence "
            "WHERE route_id=NEW.route_id "
            "AND tenant_id=NEW.tenant_id "
            "AND engagement_id=NEW.engagement_id "
            "AND action_id=NEW.action_id "
            "AND configuration_digest<>NEW.configuration_digest"
            ") BEGIN "
            "SELECT RAISE(ABORT, 'route_health_configuration_changed'); END"
        )
        conn.exec_driver_sql(
            "CREATE TRIGGER IF NOT EXISTS route_health_identity_guard "
            "BEFORE INSERT ON route_health_evidence "
            "WHEN EXISTS ("
            "SELECT 1 FROM route_health_evidence "
            "WHERE route_id=NEW.route_id "
            "AND tenant_id=NEW.tenant_id "
            "AND engagement_id=NEW.engagement_id "
            "AND action_id=NEW.action_id "
            "AND configuration_digest=NEW.configuration_digest "
            "AND (observed_egress<>NEW.observed_egress "
            "OR route_identity<>NEW.route_identity)"
            ") BEGIN "
            "SELECT RAISE(ABORT, 'route_health_identity_changed'); END"
        )
        # A consumed parent may issue each exact child action only once.  The
        # partial index leaves denial records append-only while making concurrent
        # duplicate child issuance fail closed at the database boundary.
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "uq_authorization_allowed_child "
            "ON authorization_decisions(parent_decision_id, action_kind, IFNULL(module_id, '')) "
            "WHERE parent_decision_id IS NOT NULL AND decision_outcome='allow'"
        )
        # A signed operator confirmation is one approval event, not a minting
        # oracle.  Prevent the same confirmation from creating multiple root
        # allow envelopes, including concurrent issuance attempts.
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "uq_authorization_confirmation_claim "
            "ON authorization_decisions(tenant_id, confirmation_digest) "
            "WHERE confirmation_digest IS NOT NULL "
            "AND confirmation_digest<>'' "
            "AND parent_decision_id IS NULL "
            "AND decision_outcome='allow'"
        )


_SCAN_JOB_JSON_FIELDS: dict[str, Any] = {
    "frameworks": [],
    "modules": [],
    "logs": {},
}

_SCAN_JOB_UPDATE_FIELDS = {
    "status",
    "target",
    "frameworks",
    "modules",
    "pid",
    "return_code",
    "results_dir",
    "logs",
    "error",
    "created_at",
    "updated_at",
    "started_at",
    "completed_at",
}


def _scan_job_json(value: Any, default: Any) -> str:
    """Serialize scan job structured fields to JSON text."""
    return json.dumps(redact_value(default if value is None else value))


def _scan_job_value(
    job_dict: dict[str, Any],
    existing: ScanJobModel | None,
    key: str,
    default: Any = None,
) -> Any:
    if key in job_dict:
        return job_dict[key]
    if existing is not None:
        value = getattr(existing, key)
        if value is not None:
            return value
    return default


def _scan_job_json_value(
    job_dict: dict[str, Any],
    existing: ScanJobModel | None,
    key: str,
    default: Any,
) -> str:
    if key in job_dict:
        return _scan_job_json(job_dict[key], default)
    if existing is not None:
        value = getattr(existing, key)
        if value is not None:
            return value
    return json.dumps(default)


def _has_valid_scan_job_authorization(
    session: Session,
    *,
    job_id: str,
    tenant_id: str,
    decision_id: Any,
    action_id: Any,
) -> bool:
    """Verify a job's allow linkage against immutable authorization records."""
    if not isinstance(decision_id, str) or not isinstance(action_id, str):
        return False
    if not decision_id or not action_id:
        return False
    decision = (
        session.query(AuthorizationDecisionModel)
        .filter_by(
            decision_id=decision_id,
            decision_outcome="allow",
            job_id=str(job_id),
            tenant_id=str(tenant_id),
            action_id=action_id,
        )
        .one_or_none()
    )
    if decision is None:
        return False
    consumption = (
        session.query(AuthorizationConsumptionModel)
        .filter_by(
            decision_id=decision_id,
            tenant_id=str(tenant_id),
            job_id=str(job_id),
            action_id=action_id,
            envelope_digest=decision.binding_digest,
        )
        .one_or_none()
    )
    if consumption is not None:
        return True
    # A derived engine/module permit is intentionally linked to the job before
    # its child execution boundary consumes it.  Its parent must already have
    # the exact one-time consumption that authorized the derivation; this keeps
    # the linkage server-verifiable without marking the child consumed early.
    if decision.parent_decision_id:
        parent = (
            session.query(AuthorizationDecisionModel)
            .filter_by(
                decision_id=decision.parent_decision_id,
                tenant_id=str(tenant_id),
                job_id=str(job_id),
                decision_outcome="allow",
            )
            .one_or_none()
        )
        if parent is None:
            return False
        parent_consumption = (
            session.query(AuthorizationConsumptionModel)
            .filter_by(
                decision_id=parent.decision_id,
                tenant_id=str(tenant_id),
                job_id=str(job_id),
                action_id=parent.action_id,
                envelope_digest=parent.binding_digest,
            )
            .one_or_none()
        )
        return parent_consumption is not None
    return False


def _canonical_context_marker(value: Any) -> Any:
    """Validate an explicit Task 101 context marker for legacy writers.

    The legacy ORM writers remain available for Gate 0 compatibility, but a
    caller that opts into canonical persistence must provide the full trusted
    context.  This helper is lazy-imported to keep ``common.db`` independent
    from the contract module at import time.
    """
    if value is None:
        return None
    from common.canonical import CanonicalContext, MissingCanonicalContextError

    if isinstance(value, CanonicalContext):
        context = value
    elif isinstance(value, dict):
        try:
            context = CanonicalContext(
                tenant_id=value.get("tenant_id"),
                engagement_id=value.get("engagement_id"),
                job_id=value.get("job_id"),
                module_version_id=value.get("module_version_id"),
                asset_id=value.get("asset_id"),
                action_id=value.get("action_id"),
            )
        except TypeError as exc:
            raise MissingCanonicalContextError("canonical context must be an object") from exc
    else:
        raise MissingCanonicalContextError("canonical context must be a Task 101 context")
    context.validate()
    return context


def _assert_canonical_payload_context(
    payload: dict[str, Any],
    context: Any,
    *,
    include_job_id: bool,
) -> None:
    """Require the persisted payload to carry the same trusted context."""
    from common.canonical import MissingCanonicalContextError

    names = ("tenant_id", "engagement_id", "job_id", "module_version_id", "asset_id")
    for name in names:
        if not payload.get(name) or payload.get(name) != getattr(context, name):
            raise MissingCanonicalContextError(
                f"canonical payload {name} does not match trusted context"
            )
    if include_job_id and str(payload.get("id")) != str(context.job_id):
        raise MissingCanonicalContextError("scan job ID does not match canonical context")


def save_scan_job(
    session: Session,
    job_dict: dict[str, Any],
    *,
    commit: bool = True,
    allow_legacy_compat: bool = False,
) -> None:
    """Persist or replace a dashboard scan job record.

    ``save_scan_job`` is the pre-Task-101 Gate-0 ORM compatibility writer.
    New adapters must provide a full ``canonical_context`` marker; otherwise
    the default strict boundary fails before any row is written.  A migration
    or inert Gate-0 fixture may opt into the legacy path explicitly with
    ``allow_legacy_compat=True`` while it is migrated to
    :class:`common.canonical.CanonicalAdapter`.
    """
    if "id" not in job_dict:
        raise ValueError("scan job id is required")
    # Legacy dashboard jobs do not carry the complete canonical graph.  Do
    # not let a strict adapter manufacture a tenant-only orphan; canonical
    # adapters must be used whenever the Task 101 context is available.
    canonical_context = _canonical_context_marker(job_dict.get("canonical_context"))
    if not allow_legacy_compat and canonical_context is None:
        from common.canonical import MissingCanonicalContextError

        raise MissingCanonicalContextError(
            "canonical scan-job adapters require tenant, engagement, job, module version, and asset context"
        )
    if canonical_context is not None:
        _assert_canonical_payload_context(job_dict, canonical_context, include_job_id=True)
        from common.canonical import MissingCanonicalContextError

        raise MissingCanonicalContextError(
            "legacy scan-job writer cannot persist canonical context; use CanonicalAdapter"
        )

    existing = session.get(ScanJobModel, job_dict["id"])
    if existing is not None:
        requested_tenant = job_dict.get("tenant_id", existing.tenant_id or "default")
        if requested_tenant != (existing.tenant_id or "default"):
            raise ValueError("scan job tenant linkage is immutable")
        for field in (
            "authorization_state",
            "authorization_decision_id",
            "authorization_action_id",
        ):
            if field in job_dict and job_dict[field] != getattr(existing, field):
                raise ValueError("scan job authorization linkage is immutable")
    target = redact_text(str(_scan_job_value(job_dict, existing, "target") or ""))
    if not target:
        raise ValueError("scan job target is required")

    authorization_state = str(
        _scan_job_value(
            job_dict,
            existing,
            "authorization_state",
            "unknown_not_authorized",
        )
        or "unknown_not_authorized"
    )
    authorization_decision_id = _scan_job_value(
        job_dict,
        existing,
        "authorization_decision_id",
    )
    authorization_action_id = _scan_job_value(
        job_dict,
        existing,
        "authorization_action_id",
    )
    tenant_id = str(_scan_job_value(job_dict, existing, "tenant_id", "default") or "default")
    if authorization_state == "allow":
        if not _has_valid_scan_job_authorization(
            session,
            job_id=str(job_dict["id"]),
            tenant_id=tenant_id,
            decision_id=authorization_decision_id,
            action_id=authorization_action_id,
        ):
            raise ValueError("scan job authorization linkage is not valid")
    elif authorization_decision_id or authorization_action_id:
        raise ValueError("non-authorized scan jobs cannot carry authorization linkage")

    now = datetime.now(timezone.utc)
    results_dir = _scan_job_value(job_dict, existing, "results_dir")
    model = ScanJobModel(
        id          = job_dict["id"],
        tenant_id   = _scan_job_value(job_dict, existing, "tenant_id", "default"),
        status      = _scan_job_value(job_dict, existing, "status", "pending"),
        target      = target,
        frameworks  = _scan_job_json_value(job_dict, existing, "frameworks", []),
        modules     = _scan_job_json_value(job_dict, existing, "modules", []),
        pid         = _scan_job_value(job_dict, existing, "pid"),
        return_code = _scan_job_value(job_dict, existing, "return_code"),
        results_dir = str(results_dir) if results_dir is not None else None,
        logs        = _scan_job_json_value(job_dict, existing, "logs", {}),
        error       = redact_text(str(_scan_job_value(job_dict, existing, "error") or "")) or None,
        created_at  = _scan_job_value(job_dict, existing, "created_at", now),
        updated_at  = job_dict.get("updated_at", now),
        started_at  = _scan_job_value(job_dict, existing, "started_at"),
        completed_at = _scan_job_value(job_dict, existing, "completed_at"),
        authorization_state = authorization_state,
        authorization_decision_id = authorization_decision_id,
        authorization_action_id = authorization_action_id,
    )
    session.merge(model)
    if commit:
        session.commit()


def get_scan_job(
    session: Session,
    job_id: str,
    *,
    tenant_id: str = "default",
) -> ScanJobModel | None:
    """Load one scan job only within its trusted tenant boundary."""
    return (
        session.query(ScanJobModel)
        .filter(
            ScanJobModel.id == job_id,
            ScanJobModel.tenant_id == tenant_id,
        )
        .one_or_none()
    )


def update_scan_job(
    session: Session,
    job_id: str,
    *,
    tenant_id: str = "default",
    **updates: Any,
) -> ScanJobModel | None:
    """Apply a partial update to a persisted scan job."""
    model = get_scan_job(session, job_id, tenant_id=tenant_id)
    if model is None:
        return None

    unknown = set(updates) - _SCAN_JOB_UPDATE_FIELDS
    if unknown:
        raise ValueError(f"unknown scan job fields: {', '.join(sorted(unknown))}")

    for key, value in updates.items():
        if key in _SCAN_JOB_JSON_FIELDS:
            setattr(model, key, _scan_job_json(value, _SCAN_JOB_JSON_FIELDS[key]))
        elif key == "results_dir" and value is not None:
            setattr(model, key, str(value))
        elif key in {"target", "error"} and value is not None:
            setattr(model, key, redact_text(str(value)))
        else:
            setattr(model, key, value)

    if "updated_at" not in updates:
        setattr(model, "updated_at", datetime.now(timezone.utc))
    session.commit()
    return model


_RETEST_JSON_FIELDS: dict[str, Any] = {
    "evidence": {},
    "metadata_json": {},
}

_RETEST_UPDATE_FIELDS = {
    "status",
    "module",
    "target",
    "url",
    "param",
    "payload_class",
    "session_ref",
    "job_id",
    "still_vulnerable",
    "confidence",
    "evidence",
    "metadata_json",
    "error",
    "created_at",
    "retested_at",
}

_RETEST_TEXT_FIELDS = frozenset(
    {
        "status",
        "module",
        "target",
        "url",
        "param",
        "payload_class",
        "session_ref",
        "job_id",
        "confidence",
        "error",
    }
)


def _retest_text(value: Any) -> str | None:
    """Return one detached, redacted retest string for ordinary persistence."""
    if value is None:
        return None
    return redact_text(str(value))


def _json_text(value: Any, default: Any) -> str:
    """Serialize structured DB fields to JSON text."""
    if isinstance(value, str):
        return redact_text(value)
    return json.dumps(redact_value(default if value is None else value))


def _parse_datetime(value: Any) -> datetime | None:
    """Best-effort conversion of stored/report timestamps to aware UTC datetimes."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            normalized = value.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _normalize_token(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _canonical_target(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/")[0]
    return host.rstrip(".")


def _canonical_port(finding_dict: dict[str, Any]) -> str:
    port = finding_dict.get("port")
    if port not in (None, ""):
        return str(port)
    for field in ("url", "target"):
        raw = finding_dict.get(field)
        if not raw:
            continue
        parsed = urlparse(str(raw) if "://" in str(raw) else f"//{raw}")
        if parsed.port:
            return str(parsed.port)
        if parsed.scheme == "https":
            return "443"
        if parsed.scheme == "http":
            return "80"
    return ""


_DIMENSION_METADATA_KEYS = (
    "observation",
    "canonical_observation",
    "observations",
    "metadata",
    "dimensions",
    "context",
)


def _dimension_value(
    finding_dict: dict[str, Any],
    *names: str,
    nested_names: tuple[str, ...] = (),
) -> str:
    """Return one canonical observation dimension from legacy payload shapes.

    The Gate-0 ``Finding`` object predates the canonical observation contract,
    so callers have historically placed route/check identity in a mixture of
    top-level fields, ``metadata``/``observation`` mappings, and evidence
    extras.  Resolve those aliases here without treating arbitrary evidence
    text as identity.  Identity values are deliberately normalized but are not
    redacted into the literal ``<redacted>`` marker (which would collapse
    otherwise unrelated observations).
    """
    containers: list[Any] = [finding_dict]
    for container_name in nested_names:
        value = finding_dict.get(container_name)
        if isinstance(value, Mapping):
            containers.append(value)
    metadata = finding_dict.get("metadata")
    if isinstance(metadata, Mapping):
        containers.append(metadata)
    verification = finding_dict.get("verification")
    if isinstance(verification, Mapping):
        containers.append(verification)
    evidence = finding_dict.get("evidence")
    if isinstance(evidence, Mapping):
        extra = evidence.get("extra")
        if isinstance(extra, Mapping):
            containers.append(extra)

    # Observation dimensions may be nested under evidence/verification by
    # adapters that predate the canonical fields.  Walk only named metadata
    # containers; arbitrary evidence payloads must not become identity fields.
    pending = list(containers)
    seen: set[int] = set()
    containers = []
    nested_aliases = tuple(dict.fromkeys((*nested_names, *_DIMENSION_METADATA_KEYS)))
    while pending:
        container = pending.pop(0)
        if not isinstance(container, Mapping) or id(container) in seen:
            continue
        seen.add(id(container))
        containers.append(container)
        for nested_name in nested_aliases:
            child = container.get(nested_name)
            if isinstance(child, Mapping):
                pending.append(child)

    for container in containers:
        for name in names:
            if isinstance(container, Mapping):
                value = container.get(name)
            else:
                value = getattr(container, name, None)
            if value is None:
                continue
            rendered = _normalize_token(value)
            if rendered:
                return rendered
    return ""


def _canonical_route_path(finding_dict: dict[str, Any]) -> str:
    """Resolve the route/path identity without conflating distinct checks.

    Explicit canonical observation fields win.  A specific ``url`` is a safe
    legacy fallback because it is the only pre-contract field intended to
    identify a route; the broad ``target`` remains host-scoped for compatibility
    with older Gate-0 findings that used a target such as ``host/path`` merely
    as a display label.
    """
    explicit = _dimension_value(
        finding_dict,
        "route",
        "path",
        "endpoint",
        "uri",
        nested_names=("observation", "canonical_observation"),
    )
    if explicit:
        return explicit
    raw_url = finding_dict.get("url") or finding_dict.get("target")
    if not raw_url:
        return ""
    parsed = urlparse(str(raw_url) if "://" in str(raw_url) else f"//{raw_url}")
    # A pre-contract caller often placed ``host/path`` in ``target``.  Keep
    # the host in the target dimension but retain a non-root path here so
    # distinct route observations cannot overwrite one another.
    path = parsed.path or ""
    if not path or path == "/":
        path = ""
    # Query names and values are part of the legacy adapter's only available
    # observation identity when no explicit canonical parameter is supplied.
    # Preserve them so ``/item?id=1`` and ``/item?name=x`` cannot overwrite
    # one another before Task 102 custody sees the records.
    query = parsed.query
    if query:
        path = f"{path}?{query}"
    return _normalize_token(path)


def finding_dedup_key(finding_dict: dict[str, Any]) -> str:
    """Return a stable key for one canonical finding identity.

    Legacy rows are mutable workflow summaries, so their identity must carry
    the same dimensions as the canonical observation contract.  In particular,
    title/host/port alone are insufficient: two routes, parameters, identities,
    checks, modules, or tenants must never overwrite one another.  The version
    marker is included in the material while the public key remains a 64-byte
    digest for the existing SQLite schema and run-membership contract.
    """
    check_identity = _dimension_value(
        finding_dict,
        "check_id",
        "check",
        "check_name",
        "finding_key",
        "vulnerability_id",
        "rule_id",
        nested_names=("observation", "canonical_observation"),
    ) or _normalize_token(finding_dict.get("title"))
    route_path = _canonical_route_path(finding_dict)
    parameter = _dimension_value(
        finding_dict,
        "parameter",
        "param",
        "field",
        nested_names=("observation", "canonical_observation"),
    )
    location = _dimension_value(
        finding_dict,
        "location",
        "in_location",
        "source_location",
        nested_names=("observation", "canonical_observation"),
    )
    identity = _dimension_value(
        finding_dict,
        "identity_ref",
        "identity",
        "principal",
        "account",
        "user",
        nested_names=("observation", "canonical_observation"),
    )
    asset_identity = _dimension_value(
        finding_dict,
        "asset_id",
        "asset",
        "asset_key",
        "source_asset_id",
        nested_names=("observation", "canonical_observation"),
    )
    module_version_identity = _dimension_value(
        finding_dict,
        "module_version_id",
        "module_version",
        "module_id",
        "check_pack_snapshot_id",
        nested_names=("observation", "canonical_observation"),
    ) or _dimension_value(
        finding_dict,
        "module",
        nested_names=("observation", "canonical_observation"),
    )
    material = "\x1f".join(
        [
            "finding-v2",
            _normalize_token(finding_dict.get("tenant_id") or "default"),
            module_version_identity,
            check_identity,
            asset_identity,
            _canonical_target(finding_dict.get("target") or finding_dict.get("url")),
            _canonical_port(finding_dict),
            route_path,
            parameter,
            location,
            identity,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _age_days(first_seen_at: datetime | None, now: datetime) -> int:
    if first_seen_at is None:
        return 0
    first = first_seen_at if first_seen_at.tzinfo else first_seen_at.replace(tzinfo=timezone.utc)
    current = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return max((current - first).days, 0)


def _priority_for(finding_dict: dict[str, Any], days_open: int) -> str:
    """Escalate stale open vulnerabilities without changing severity semantics."""
    severity = str(finding_dict.get("severity") or "Informational")
    base_rank = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Informational": 0,
    }.get(severity, 0)
    if days_open >= 30 and base_rank < 4:
        base_rank += 1
    if days_open >= 90 and base_rank < 4:
        base_rank += 1
    return {
        4: "CRITICAL",
        3: "HIGH",
        2: "MEDIUM",
        1: "LOW",
        0: "INFO",
    }[base_rank]


def _json_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


_LEGACY_RAW_EVIDENCE_FIELDS = frozenset(
    {
        "request_raw",
        "response_raw",
        "screenshot_path",
        "console_capture_path",
        "pcap_path",
        "console_capture",
        "pcap",
    }
)


def _strip_legacy_raw_evidence(value: Any) -> Any:
    """Remove raw/path evidence keys from mutable compatibility JSON."""
    if isinstance(value, dict):
        return {
            str(key): _strip_legacy_raw_evidence(item)
            for key, item in value.items()
            if str(key).strip().lower() not in _LEGACY_RAW_EVIDENCE_FIELDS
        }
    if isinstance(value, list):
        return [_strip_legacy_raw_evidence(item) for item in value]
    if isinstance(value, tuple):
        return [_strip_legacy_raw_evidence(item) for item in value]
    return value


def _legacy_custody_root(
    finding_dict: dict[str, Any],
    evidence: dict[str, Any],
    explicit_root: str | os.PathLike[str] | None,
) -> Path | None:
    """Resolve an explicit filesystem custody root for legacy evidence.

    A legacy writer has no trusted canonical context from which to infer a
    store location.  Production adapters therefore pass the root explicitly;
    silently defaulting to the process working directory would make artifact
    ownership and cleanup ambiguous.  The evidence ``extra`` aliases remain
    for old integrations but are never persisted themselves.
    """
    candidate: Any = explicit_root
    if candidate is None:
        for key in ("custody_root", "evidence_store", "evidence_root"):
            if evidence.get(key) is not None:
                candidate = evidence.get(key)
                break
    extra = evidence.get("extra")
    if candidate is None and isinstance(extra, dict):
        for key in ("custody_root", "evidence_store", "evidence_root"):
            if extra.get(key) is not None:
                candidate = extra.get(key)
                break
    if candidate is None:
        return None
    try:
        rendered = Path(os.fspath(candidate))
    except (TypeError, ValueError, OSError):
        return None
    # A relative root is intentionally rejected.  Custody paths must be
    # anchored to a server-owned result namespace and may not follow the
    # caller's changing working directory.
    if not rendered.is_absolute():
        return None
    return rendered


def _legacy_custody_identifier(seed: str, prefix: str) -> str:
    """Derive a bounded, opaque custody identifier from legacy values."""
    return f"{prefix}-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:48]}"


def _legacy_evidence_payloads(evidence: dict[str, Any]) -> list[tuple[str, bytes, str]]:
    """Extract legacy evidence bytes without retaining caller-controlled paths."""
    payloads: list[tuple[str, bytes, str]] = []
    for field, media_type in (
        ("request_raw", "text/plain"),
        ("response_raw", "text/plain"),
    ):
        value = evidence.get(field)
        if isinstance(value, str) and value:
            payloads.append((field, value.encode("utf-8"), media_type))
    path_fields = (
        ("screenshot_path", "image/png"),
        ("console_capture_path", "text/html"),
        ("pcap_path", "application/vnd.tcpdump.pcap"),
    )
    try:
        from common.artifact_io import ArtifactBoundaryError, read_verified_regular_file
    except Exception:  # pragma: no cover - import failure is fail-closed below
        return payloads
    for field, media_type in path_fields:
        value = evidence.get(field)
        if not isinstance(value, (str, os.PathLike)) or not os.fspath(value):
            continue
        try:
            payload = read_verified_regular_file(
                value,
                require_owner_only_mode=True,
            )
        except (ArtifactBoundaryError, OSError, ValueError):
            # A missing, symlinked, or caller-owned path is not evidence.  Do
            # not copy the path into a mutable row or fail the finding write.
            continue
        payloads.append((field, payload, media_type))
    return payloads


def _persist_legacy_custody(
    finding_dict: dict[str, Any],
    evidence: dict[str, Any],
    *,
    custody_root: Any,
    tenant_id: str,
    run_id: str | None,
) -> tuple[Any, list[dict[str, str]]]:
    """Stage available legacy evidence in the immutable custody store.

    The returned manifests are references only; no bytes or source paths are
    returned to the caller.  Originals are deliberately not retained because
    this compatibility path cannot prove a protected-original authorization.
    Callers must roll back the returned artifacts if their database transaction
    fails.
    """
    store = (
        custody_root
        if custody_root is not None
        and callable(getattr(custody_root, "store_artifact", None))
        else None
    )
    root = None if store is not None else _legacy_custody_root(
        finding_dict,
        evidence,
        custody_root,
    )
    payloads = _legacy_evidence_payloads(evidence)
    if (root is None and store is None) or not payloads:
        return None, []
    if store is None:
        try:
            from common.evidence_custody import EvidenceCustodyStore
        except Exception as exc:  # pragma: no cover - package is required in production
            raise ValueError("immutable evidence custody is unavailable") from exc
        store = EvidenceCustodyStore(cast(Path, root), tenant_id)
    elif str(getattr(store, "tenant_id", tenant_id)) != tenant_id:
        raise ValueError("immutable evidence custody tenant does not match finding")
    finding_id = str(finding_dict.get("id") or "legacy-finding")
    source_seed = "\x1f".join((tenant_id, str(run_id or "legacy"), finding_id))
    observation_id = _legacy_custody_identifier(source_seed, "legacy-observation")
    collector = _normalize_token(finding_dict.get("module")) or "legacy-db"
    collector = _legacy_custody_identifier(collector, "collector")
    source_target = str(finding_dict.get("target") or finding_dict.get("url") or "")[:2000] or None
    staged: list[dict[str, str]] = []
    try:
        for field, payload, media_type in payloads:
            manifest = store.store_artifact(
                payload,
                source_observation_id=observation_id,
                collector_id=collector,
                media_type=media_type,
                source_target=source_target,
                redaction_required=True,
                retain_original=False,
                metadata={
                    "legacy": True,
                    "field": field,
                    "module": _normalize_token(finding_dict.get("module")),
                    "run_id": str(run_id or "legacy"),
                },
            )
            staged.append(
                {
                    "artifact_id": manifest.artifact_id,
                    "manifest_digest": manifest.manifest_digest,
                    "field": field,
                }
            )
    except Exception:
        # Compensate any earlier artifacts created by this call.  The custody
        # store verifies each manifest before removing it and refuses broad
        # deletion, so failed writes cannot leave an orphan namespace behind.
        for item in reversed(staged):
            try:
                store.rollback_artifact(
                    item["artifact_id"],
                    expected_manifest_digest=item["manifest_digest"],
                )
            except Exception:
                pass
        raise
    return store, staged


def save_finding_retest(
    session: Session,
    retest_dict: dict[str, Any],
    *,
    allow_legacy_compat: bool = False,
) -> None:
    """Persist one legacy finding-retest row only for an explicit fixture.

    Task 101 canonical retests require tenant, finding, and source-observation
    lineage through ``CanonicalAdapter``.  This pre-Gate-1 table cannot express
    that graph, so production callers fail before a row is written.
    """
    if not allow_legacy_compat:
        from common.canonical import MissingCanonicalContextError

        raise MissingCanonicalContextError(
            "canonical retest adapters require tenant, finding, and source-observation context"
        )
    if "canonical_context" in retest_dict:
        from common.canonical import MissingCanonicalContextError

        raise MissingCanonicalContextError(
            "legacy retest writer cannot persist canonical context; use CanonicalAdapter"
        )
    if "id" not in retest_dict:
        raise ValueError("retest id is required")
    if "finding_id" not in retest_dict:
        raise ValueError("finding_id is required")
    if not retest_dict.get("module"):
        raise ValueError("retest module is required")
    if not retest_dict.get("target"):
        raise ValueError("retest target is required")

    existing = session.get(FindingRetestModel, retest_dict["id"])
    existing_value = (lambda key, default=None: getattr(existing, key, default) if existing else default)
    now = datetime.now(timezone.utc)
    model = FindingRetestModel(
        id               = retest_dict["id"],
        finding_id       = retest_dict["finding_id"],
        status           = _retest_text(retest_dict.get("status", existing_value("status", "pending"))),
        module           = _retest_text(retest_dict.get("module", existing_value("module", ""))),
        target           = _retest_text(retest_dict.get("target", existing_value("target", ""))),
        url              = _retest_text(retest_dict.get("url", existing_value("url"))),
        param            = _retest_text(retest_dict.get("param", existing_value("param"))),
        payload_class    = _retest_text(retest_dict.get("payload_class", existing_value("payload_class"))),
        session_ref      = _retest_text(retest_dict.get("session_ref", existing_value("session_ref"))),
        job_id           = _retest_text(retest_dict.get("job_id", existing_value("job_id"))),
        still_vulnerable = retest_dict.get("still_vulnerable", existing_value("still_vulnerable")),
        confidence       = _retest_text(retest_dict.get("confidence", existing_value("confidence"))),
        evidence         = _json_text(
            retest_dict.get("evidence", existing_value("evidence")),
            {},
        ),
        metadata_json    = _json_text(
            retest_dict.get("metadata_json", existing_value("metadata_json")),
            {},
        ),
        error            = _retest_text(retest_dict.get("error", existing_value("error"))),
        created_at       = retest_dict.get("created_at", existing_value("created_at", now)),
        retested_at      = retest_dict.get("retested_at", existing_value("retested_at")),
    )
    session.merge(model)
    session.commit()


def update_finding_retest(
    session: Session,
    retest_id: str,
    *,
    allow_legacy_compat: bool = False,
    **updates: Any,
) -> FindingRetestModel | None:
    """Update one explicitly opted-in legacy finding-retest fixture."""
    if not allow_legacy_compat:
        from common.canonical import MissingCanonicalContextError

        raise MissingCanonicalContextError(
            "canonical retest adapters require tenant, finding, and source-observation context"
        )
    model = session.get(FindingRetestModel, retest_id)
    if model is None:
        return None

    unknown = set(updates) - _RETEST_UPDATE_FIELDS
    if unknown:
        raise ValueError(f"unknown retest fields: {', '.join(sorted(unknown))}")

    for key, value in updates.items():
        if key in _RETEST_JSON_FIELDS:
            setattr(model, key, _json_text(value, _RETEST_JSON_FIELDS[key]))
        elif key in _RETEST_TEXT_FIELDS:
            setattr(model, key, _retest_text(value))
        else:
            setattr(model, key, value)
    # Clean any legacy ordinary text retained on rows updated through a
    # non-text field, rather than carrying a prior plaintext value forward.
    for key in _RETEST_TEXT_FIELDS:
        setattr(model, key, _retest_text(getattr(model, key, None)))
    session.commit()
    return model


def save_finding(
    session: Session,
    finding_dict: dict[str, Any],
    run_id: str | None = None,
    *,
    allow_legacy_compat: bool = False,
    evidence_store: str | os.PathLike[str] | None = None,
) -> None:
    """Persist a Finding.to_dict() result to the database.

    The strict adapter path fails closed before touching the legacy findings
    table when the complete Task 101 context marker is absent.  Strict mode is
    the default; an inert migration or Gate-0 fixture must opt into the named
    compatibility path with ``allow_legacy_compat=True`` until it emits a
    :class:`common.canonical.CanonicalAdapter` graph.  When a compatibility
    caller supplies ``evidence_store`` (or an ``EvidenceCustodyStore``), raw
    legacy evidence is staged as redacted derivative artifacts and only their
    immutable manifest references are retained in ``verification``; the
    historical findings evidence columns are always written as ``NULL``.
    """
    safe_finding = normalise_finding(dict(finding_dict))
    canonical_context = _canonical_context_marker(finding_dict.get("canonical_context"))
    if not allow_legacy_compat and canonical_context is None:
        from common.canonical import MissingCanonicalContextError

        raise MissingCanonicalContextError(
            "canonical finding adapters require tenant, engagement, job, module version, and asset context"
        )
    if canonical_context is not None:
        _assert_canonical_payload_context(finding_dict, canonical_context, include_job_id=False)
        from common.canonical import MissingCanonicalContextError

        raise MissingCanonicalContextError(
            "legacy finding writer cannot persist canonical context; use CanonicalAdapter"
        )
    for field in ("title", "target", "url", "description", "remediation"):
        if safe_finding.get(field) is not None:
            safe_finding[field] = redact_text(str(safe_finding[field]))
    for field in ("reproduction_steps", "references", "mitre_attack", "tags"):
        safe_finding[field] = redact_value(safe_finding.get(field, []))
    safe_finding["verification"] = _strip_legacy_raw_evidence(
        redact_value(safe_finding.get("verification") or {})
    )
    safe_finding["evidence"] = redact_value(safe_finding.get("evidence") or {})
    finding_dict = safe_finding
    ev = finding_dict.get("evidence", {})
    now = datetime.now(timezone.utc)
    seen_at = _parse_datetime(finding_dict.get("discovered_at")) or now
    # Caller-supplied legacy keys were generated from title/host/port and can
    # therefore merge unrelated canonical observations.  Always derive the
    # key from the complete tenant/check/route/parameter/location/identity
    # dimensions above; an incoming key is retained only by immutable legacy
    # migration paths, never by this writer.
    dedup_key = finding_dedup_key(finding_dict)
    tenant_id = str(finding_dict.get("tenant_id") or "default").strip() or "default"
    # This API has always been a committing persistence boundary.  End any
    # caller-side deferred read transaction before taking SQLite's write lock;
    # otherwise concurrent sessions can all observe a missing dedup row and
    # race duplicate inserts.  The unique tenant/key index remains the final
    # cross-process invariant for writers that bypass this helper.
    if session.in_transaction():
        session.commit()
    session.execute(text("BEGIN IMMEDIATE"))
    started_immediate = True
    existing = (
        session.query(FindingModel)
        .filter(
            FindingModel.tenant_id == tenant_id,
            FindingModel.dedup_key == dedup_key,
        )
        .order_by(FindingModel.first_seen_at.asc().nullslast(), FindingModel.discovered_at.asc())
        .first()
    )
    current_run = run_id or finding_dict.get("engagement") or (
        existing.last_seen_run if existing else None
    )
    if current_run:
        prior_membership = (
            session.query(FindingRunMembershipModel)
            .filter_by(
                tenant_id=tenant_id,
                run_id=str(current_run),
                dedup_key=str(dedup_key),
            )
            .one_or_none()
        )
        if prior_membership is not None:
            if existing is not None:
                # A retry may encounter a row written by an older adapter
                # before the custody boundary was enforced.  Clean the
                # nullable compatibility columns even when this run is already
                # represented; never preserve stale raw/path material merely
                # because dedup made the operation idempotent.
                for field_name in (
                    "request_raw",
                    "response_raw",
                    "screenshot_path",
                    "console_capture_path",
                    "pcap_path",
                ):
                    setattr(existing, field_name, None)
                try:
                    prior = json.loads(str(existing.verification or "{}"))
                except (TypeError, json.JSONDecodeError):
                    prior = {}
                setattr(existing, "verification", json.dumps(
                    _strip_legacy_raw_evidence(prior)
                    if isinstance(prior, dict)
                    else {},
                ))
                session.flush()
            if started_immediate:
                session.commit()
            return
    incoming_id = str(finding_dict.get("id") or "")
    identity_owner = session.get(FindingModel, incoming_id) if incoming_id else None
    if (
        identity_owner is not None
        and str(identity_owner.tenant_id or "default") != tenant_id
        and (existing is None or existing.id != identity_owner.id)
    ):
        if started_immediate:
            session.rollback()
        raise ValueError("finding identity belongs to another tenant")
    first_seen = (
        cast(datetime | None, existing.first_seen_at or existing.discovered_at)
        if existing
        else seen_at
    )
    days_open = _age_days(first_seen, now)
    priority = finding_dict.get("priority") or finding_dict.get("vpr_priority") or finding_dict.get("vpr")
    if not priority:
        priority = _priority_for(finding_dict, days_open)
    seen_runs = _json_list(existing.seen_runs if existing else None)
    if current_run and current_run not in seen_runs:
        seen_runs.append(current_run)
    staged_custody_store: Any = None
    staged_custody_artifacts: list[dict[str, str]] = []
    try:
        staged_custody_store, staged_custody_artifacts = _persist_legacy_custody(
            finding_dict,
            ev,
            custody_root=evidence_store,
            tenant_id=tenant_id,
            run_id=str(current_run) if current_run else None,
        )
    except Exception:
        if started_immediate:
            session.rollback()
        raise
    prior_verification: dict[str, Any] = {}
    if existing is not None:
        try:
            decoded_verification = json.loads(str(existing.verification or "{}"))
        except (TypeError, json.JSONDecodeError):
            decoded_verification = {}
        if isinstance(decoded_verification, dict):
            prior_verification = decoded_verification
    verification_value = finding_dict.get("verification") or {}
    verification = dict(verification_value) if isinstance(verification_value, dict) else {}
    prior_artifacts = prior_verification.get("custody_artifacts")
    if isinstance(prior_artifacts, list):
        verification["custody_artifacts"] = list(prior_artifacts)
    if staged_custody_artifacts:
        current_artifacts = verification.get("custody_artifacts")
        if not isinstance(current_artifacts, list):
            current_artifacts = []
        # Manifest identities are immutable.  De-duplicate only an exact
        # artifact reference; different runs and fields remain separate.
        known = {
            str(item.get("artifact_id"))
            for item in current_artifacts
            if isinstance(item, dict) and item.get("artifact_id")
        }
        for item in staged_custody_artifacts:
            if item["artifact_id"] not in known:
                current_artifacts.append(item)
                known.add(item["artifact_id"])
        verification["custody_artifacts"] = current_artifacts
    finding_dict["verification"] = (
        _strip_legacy_raw_evidence(redact_value(verification))
        if verification
        else {}
    )
    model = FindingModel(
        id                   = existing.id if existing else finding_dict["id"],
        tenant_id            = tenant_id,
        title                = finding_dict["title"],
        severity             = finding_dict["severity"],
        target               = finding_dict["target"],
        url                  = finding_dict.get("url"),
        port                 = finding_dict.get("port"),
        service              = finding_dict.get("service"),
        module               = finding_dict["module"],
        description          = finding_dict["description"],
        reproduction_steps   = json.dumps(finding_dict.get("reproduction_steps", [])),
        remediation          = finding_dict.get("remediation", ""),
        references           = json.dumps(finding_dict.get("references", [])),
        cvss_v31_vector      = finding_dict.get("cvss_v31_vector"),
        cvss_v31_score       = finding_dict.get("cvss_v31_score"),
        cvss_v40_vector      = finding_dict.get("cvss_v40_vector"),
        cvss_v40_score       = finding_dict.get("cvss_v40_score"),
        mitre_attack         = json.dumps(finding_dict.get("mitre_attack", [])),
        # These columns remain nullable for schema compatibility with old
        # databases, but the legacy writer intentionally leaves them empty.
        # Evidence bytes/paths belong in the immutable custody boundary, not
        # in a mutable finding summary row.
        screenshot_path      = None,
        request_raw          = None,
        response_raw         = None,
        console_capture_path = None,
        pcap_path            = None,
        operator_confirmed   = finding_dict.get("operator_confirmed", False),
        tags                 = json.dumps(finding_dict.get("tags", [])),
        confidence           = finding_dict.get("confidence", "UNVERIFIED"),
        status               = finding_dict.get("status", "open"),
        vpr_score            = finding_dict.get("vpr_score"),
        vpr_priority         = finding_dict.get("vpr_priority") or finding_dict.get("vpr"),
        verification         = json.dumps(finding_dict.get("verification") or {}),
        verification_state   = finding_dict.get("verification_state", "unknown"),
        proof_type           = finding_dict.get("proof_type", "unknown"),
        maturity             = finding_dict.get("maturity", "experimental"),
        dedup_key            = dedup_key,
        first_seen_at        = first_seen,
        last_seen_at         = seen_at,
        last_seen_run        = current_run,
        seen_runs            = json.dumps(seen_runs),
        times_seen           = (existing.times_seen or 1) + 1 if existing else 1,
        days_open            = days_open,
        priority             = priority,
        discovered_at        = existing.discovered_at if existing else seen_at,
        engagement           = run_id or finding_dict.get("engagement") or (existing.engagement if existing else None),
        tester               = finding_dict.get("tester") or (existing.tester if existing else None),
    )
    try:
        stored = session.merge(model)
        session.flush()
        if current_run:
            append_finding_run_snapshot(
                session,
                tenant_id=tenant_id,
                run_id=str(current_run),
                snapshot=finding_to_dict(stored),
                commit=False,
            )
        session.commit()
    except Exception:
        session.rollback()
        if staged_custody_store is not None:
            for item in reversed(staged_custody_artifacts):
                try:
                    staged_custody_store.rollback_artifact(
                        item["artifact_id"],
                        expected_manifest_digest=item["manifest_digest"],
                    )
                except Exception:
                    pass
        raise


def finding_to_dict(model: FindingModel) -> dict[str, Any]:
    """Convert a persisted finding row back to the canonical report dictionary."""
    row = {
        "id": model.id,
        "tenant_id": model.tenant_id or "default",
        "title": model.title,
        "severity": model.severity,
        "target": model.target,
        "url": model.url,
        "port": model.port,
        "service": model.service,
        "module": model.module,
        "description": model.description,
        "reproduction_steps": json.loads(
            cast(str | None, model.reproduction_steps) or "[]"
        ),
        "remediation": model.remediation,
        "references": json.loads(cast(str | None, model.references) or "[]"),
        "cvss_v31_vector": model.cvss_v31_vector,
        "cvss_v31_score": model.cvss_v31_score,
        "cvss_v40_vector": model.cvss_v40_vector,
        "cvss_v40_score": model.cvss_v40_score,
        "mitre_attack": json.loads(cast(str | None, model.mitre_attack) or "[]"),
        "discovered_at": model.discovered_at.isoformat() if model.discovered_at else None,
        "operator_confirmed": model.operator_confirmed,
        "tags": json.loads(cast(str | None, model.tags) or "[]"),
        "confidence": model.confidence or "UNVERIFIED",
        "status": model.status or "open",
        "vpr_score": model.vpr_score,
        "vpr_priority": model.vpr_priority,
        "verification": _strip_legacy_raw_evidence(
            json.loads(cast(str | None, model.verification) or "{}")
        ),
        "verification_state": model.verification_state or "unknown",
        "proof_type": model.proof_type or "unknown",
        "maturity": model.maturity or "experimental",
        "dedup_key": model.dedup_key,
        "first_seen_at": model.first_seen_at.isoformat() if model.first_seen_at else None,
        "last_seen_at": model.last_seen_at.isoformat() if model.last_seen_at else None,
        "last_seen_run": model.last_seen_run,
        "seen_runs": json.loads(cast(str | None, model.seen_runs) or "[]"),
        "times_seen": model.times_seen or 1,
        "days_open": model.days_open or 0,
        "priority": model.priority,
        "evidence": {
            # The old ORM columns are intentionally not read back.  They are
            # retained only as nullable migration shims; ordinary consumers
            # must resolve redacted derivatives through canonical custody.
            "request_raw": None,
            "response_raw": None,
            "screenshot_path": None,
            "console_capture_path": None,
            "pcap_path": None,
        },
    }
    safe = redact_value(normalise_finding(row))
    if not isinstance(safe, dict):
        return {}
    # Structural identities are required by tenant/run snapshot and delta
    # consumers.  They are opaque product identifiers, not credential keys.
    safe["id"] = model.id
    safe["tenant_id"] = model.tenant_id or "default"
    safe["dedup_key"] = model.dedup_key
    return safe


def save_audit_log(session: Session, event_dict: dict[str, Any]) -> AuditLogModel:
    """Persist one operator audit event and return the ORM row."""
    safe_event = redact_value(event_dict)
    model = AuditLogModel(
        timestamp=_parse_datetime(event_dict.get("timestamp")) or datetime.now(timezone.utc),
        tenant_id=str(safe_event.get("tenant_id") or "default"),
        operator=str(safe_event.get("operator") or "")[:200] or None,
        role=str(safe_event.get("role") or "")[:50] or None,
        ip=str(safe_event.get("ip") or "")[:100] or None,
        action=str(safe_event.get("action") or "")[:200],
        object_id=str(safe_event.get("object_id") or "")[:500] or None,
        status=str(safe_event.get("status") or "")[:50] or None,
        detail=_json_text(safe_event.get("detail") or {}, {}),
    )
    if not model.action:
        raise ValueError("audit action is required")
    session.add(model)
    session.commit()
    session.refresh(model)
    return model


def audit_log_to_dict(model: AuditLogModel) -> dict[str, Any]:
    """Convert an audit row to a JSON-friendly dictionary."""
    try:
        detail = json.loads(str(model.detail or "{}"))
    except json.JSONDecodeError:
        detail = {}
    return redact_value({
        "id": model.id,
        "timestamp": model.timestamp.isoformat() if model.timestamp else None,
        "tenant_id": model.tenant_id or "default",
        "operator": model.operator,
        "role": model.role,
        "ip": model.ip,
        "action": model.action,
        "object_id": model.object_id,
        "status": model.status,
        "detail": detail,
    })


def append_authorization_decision(
    session: Session,
    record: dict[str, Any],
    *,
    commit: bool = True,
) -> AuthorizationDecisionModel:
    """Append one immutable authorization decision.

    This intentionally has no update or delete companion. SQLite triggers also
    reject direct mutation so ordinary ORM access cannot rewrite the audit.
    """
    required = {
        "decision_id",
        "schema_version",
        "tenant_id",
        "engagement_id",
        "run_id",
        "job_id",
        "action_id",
        "operator_id",
        "operator_role",
        "action_kind",
        "engine",
        "requested_target",
        "resolved_target",
        "scope_snapshot",
        "scope_policy_version",
        "scope_decision",
        "scope_reason_code",
        "decision_outcome",
        "reason_code",
        "issued_at",
        "expires_at",
        "binding_digest",
        "envelope_json",
    }
    missing = sorted(required - set(record))
    if missing:
        raise ValueError(f"authorization record missing fields: {', '.join(missing)}")

    model = AuthorizationDecisionModel(
        decision_id=str(record["decision_id"]),
        schema_version=str(record["schema_version"]),
        parent_decision_id=str(record.get("parent_decision_id") or "") or None,
        tenant_id=str(record["tenant_id"]),
        engagement_id=str(record["engagement_id"]),
        run_id=str(record["run_id"]),
        job_id=str(record["job_id"]),
        action_id=str(record["action_id"]),
        operator_id=str(record["operator_id"]),
        operator_role=str(record["operator_role"]),
        action_kind=str(record["action_kind"]),
        engine=str(record["engine"]),
        module_id=str(record.get("module_id") or "") or None,
        requested_target=str(record["requested_target"]),
        resolved_target=str(record["resolved_target"]),
        scope_snapshot=str(record["scope_snapshot"]),
        scope_policy_version=str(record["scope_policy_version"]),
        scope_decision=str(record["scope_decision"]),
        scope_reason_code=str(record["scope_reason_code"]),
        decision_outcome=str(record["decision_outcome"]),
        reason_code=str(record["reason_code"]),
        issued_at=_parse_datetime(record["issued_at"]),
        expires_at=_parse_datetime(record["expires_at"]),
        binding_digest=str(record["binding_digest"]),
        confirmation_digest=str(record.get("confirmation_digest") or "") or None,
        envelope_json=str(record["envelope_json"]),
        detail=_json_text(record.get("detail") or {}, {}),
        recorded_at=_parse_datetime(record.get("recorded_at"))
        or datetime.now(timezone.utc),
    )
    if model.issued_at is None or model.expires_at is None:
        raise ValueError("authorization timestamps are required")
    session.add(model)
    session.flush()
    if commit:
        session.commit()
        session.refresh(model)
    return model


def authorization_decision_to_dict(model: AuthorizationDecisionModel) -> dict[str, Any]:
    """Return a detached, JSON-friendly decision record."""
    try:
        detail = json.loads(str(model.detail or "{}"))
    except json.JSONDecodeError:
        detail = {}
    return {
        "sequence": model.sequence,
        "decision_id": model.decision_id,
        "schema_version": model.schema_version,
        "parent_decision_id": model.parent_decision_id or "",
        "tenant_id": model.tenant_id,
        "engagement_id": model.engagement_id,
        "run_id": model.run_id,
        "job_id": model.job_id,
        "action_id": model.action_id,
        "operator_id": model.operator_id,
        "operator_role": model.operator_role,
        "action_kind": model.action_kind,
        "engine": model.engine,
        "module_id": model.module_id or "",
        "requested_target": model.requested_target,
        "resolved_target": model.resolved_target,
        "scope_snapshot": model.scope_snapshot,
        "scope_policy_version": model.scope_policy_version,
        "scope_decision": model.scope_decision,
        "scope_reason_code": model.scope_reason_code,
        "decision_outcome": model.decision_outcome,
        "reason_code": model.reason_code,
        "issued_at": model.issued_at.isoformat() if model.issued_at else None,
        "expires_at": model.expires_at.isoformat() if model.expires_at else None,
        "binding_digest": model.binding_digest,
        "confirmation_digest": model.confirmation_digest or "",
        "detail": detail,
        "recorded_at": model.recorded_at.isoformat() if model.recorded_at else None,
    }


def list_authorization_decisions(session: Session) -> list[dict[str, Any]]:
    """List immutable decisions in stable append order."""
    rows = (
        session.query(AuthorizationDecisionModel)
        .order_by(AuthorizationDecisionModel.sequence.asc())
        .all()
    )
    return [authorization_decision_to_dict(row) for row in rows]


def get_authorization_decision(
    session: Session,
    decision_id: str,
) -> AuthorizationDecisionModel | None:
    """Load one immutable decision by its server-generated id."""
    return (
        session.query(AuthorizationDecisionModel)
        .filter_by(decision_id=decision_id)
        .one_or_none()
    )


def get_authorization_child_decision(
    session: Session,
    parent_decision_id: str,
    action_kind: str,
    module_id: str = "",
) -> AuthorizationDecisionModel | None:
    """Return an already-issued allowed child in a parent authorization lineage."""
    return (
        session.query(AuthorizationDecisionModel)
        .filter_by(
            parent_decision_id=parent_decision_id,
            action_kind=action_kind,
            module_id=module_id or None,
            decision_outcome="allow",
        )
        .one_or_none()
    )


def append_authorization_consumption(
    session: Session,
    record: dict[str, Any],
    *,
    commit: bool = True,
) -> AuthorizationConsumptionModel:
    """Append the unique single-use consumption for an allow decision."""
    model = AuthorizationConsumptionModel(
        consumption_id=str(record["consumption_id"]),
        decision_id=str(record["decision_id"]),
        tenant_id=str(record["tenant_id"]),
        job_id=str(record["job_id"]),
        action_id=str(record["action_id"]),
        boundary=str(record["boundary"]),
        result_id=str(record["result_id"]),
        envelope_digest=str(record["envelope_digest"]),
        consumed_at=_parse_datetime(record["consumed_at"]),
    )
    if model.consumed_at is None:
        raise ValueError("authorization consumption timestamp is required")
    session.add(model)
    session.flush()
    if commit:
        session.commit()
        session.refresh(model)
    return model


def get_authorization_consumption(
    session: Session,
    decision_id: str,
) -> AuthorizationConsumptionModel | None:
    """Load the immutable consumption for a decision, if it was used."""
    return (
        session.query(AuthorizationConsumptionModel)
        .filter_by(decision_id=decision_id)
        .one_or_none()
    )


def append_authorization_execution_claim(
    session: Session,
    record: dict[str, Any],
    *,
    commit: bool = True,
) -> AuthorizationExecutionClaimModel:
    """Atomically append the sole execution claim for one consumed decision."""
    model = AuthorizationExecutionClaimModel(
        claim_id=str(record["claim_id"]),
        decision_id=str(record["decision_id"]),
        tenant_id=str(record["tenant_id"]),
        job_id=str(record["job_id"]),
        action_id=str(record["action_id"]),
        boundary=str(record["boundary"]),
        envelope_digest=str(record["envelope_digest"]),
        claimed_at=_parse_datetime(record["claimed_at"]),
    )
    if model.claimed_at is None:
        raise ValueError("authorization execution claim timestamp is required")
    session.add(model)
    session.flush()
    if commit:
        session.commit()
        session.refresh(model)
    return model


def get_authorization_execution_claim(
    session: Session,
    decision_id: str,
) -> AuthorizationExecutionClaimModel | None:
    """Load the immutable execution claim for a consumed decision, if present."""
    return (
        session.query(AuthorizationExecutionClaimModel)
        .filter_by(decision_id=decision_id)
        .one_or_none()
    )


def append_outbound_decision(
    session: Session,
    record: dict[str, Any],
    *,
    commit: bool = True,
) -> OutboundDecisionModel:
    """Append one immutable outbound policy decision."""
    required = {
        "decision_id",
        "schema_version",
        "authorization_decision_id",
        "action_id",
        "tenant_id",
        "engagement_id",
        "run_id",
        "job_id",
        "engine",
        "action_kind",
        "stage",
        "destination_ref",
        "outcome",
        "reason_code",
        "tls_mode",
        "binding_digest",
    }
    missing = sorted(required - set(record))
    if missing:
        raise ValueError(f"outbound decision missing fields: {', '.join(missing)}")
    model = OutboundDecisionModel(
        decision_id=str(record["decision_id"]),
        schema_version=str(record["schema_version"]),
        authorization_decision_id=str(record["authorization_decision_id"]),
        action_id=str(record["action_id"]),
        tenant_id=str(record["tenant_id"]),
        engagement_id=str(record["engagement_id"]),
        run_id=str(record["run_id"]),
        job_id=str(record["job_id"]),
        engine=str(record["engine"]),
        module_id=str(record.get("module_id") or "") or None,
        action_kind=str(record["action_kind"]),
        stage=str(record["stage"]),
        destination_ref=str(record["destination_ref"]),
        scheme=str(record.get("scheme") or "") or None,
        host=str(record.get("host") or "") or None,
        port=int(record["port"]) if record.get("port") is not None else None,
        resolved_addresses=_json_text(record.get("resolved_addresses") or [], []),
        outcome=str(record["outcome"]),
        reason_code=str(record["reason_code"]),
        route_id=str(record.get("route_id") or "") or None,
        route_configuration_digest=(
            str(record.get("route_configuration_digest") or "") or None
        ),
        tls_mode=str(record["tls_mode"]),
        binding_digest=str(record["binding_digest"]),
        detail=_json_text(record.get("detail") or {}, {}),
        recorded_at=_parse_datetime(record.get("recorded_at"))
        or datetime.now(timezone.utc),
    )
    session.add(model)
    session.flush()
    if commit:
        session.commit()
        session.refresh(model)
    return model


def outbound_decision_to_dict(model: OutboundDecisionModel) -> dict[str, Any]:
    """Return a detached, JSON-safe outbound decision."""
    return {
        "sequence": model.sequence,
        "decision_id": model.decision_id,
        "schema_version": model.schema_version,
        "authorization_decision_id": model.authorization_decision_id,
        "action_id": model.action_id,
        "tenant_id": model.tenant_id,
        "engagement_id": model.engagement_id,
        "run_id": model.run_id,
        "job_id": model.job_id,
        "engine": model.engine,
        "module_id": model.module_id or "",
        "action_kind": model.action_kind,
        "stage": model.stage,
        "destination_ref": model.destination_ref,
        "scheme": model.scheme or "",
        "host": model.host or "",
        "port": model.port,
        "resolved_addresses": _json_list(model.resolved_addresses),
        "outcome": model.outcome,
        "reason_code": model.reason_code,
        "route_id": model.route_id or "",
        "route_configuration_digest": model.route_configuration_digest or "",
        "tls_mode": model.tls_mode,
        "binding_digest": model.binding_digest,
        "detail": _json_value_dict(model.detail),
        "recorded_at": model.recorded_at.isoformat() if model.recorded_at else None,
    }


def get_outbound_decision(
    session: Session,
    decision_id: str,
) -> OutboundDecisionModel | None:
    """Load one immutable outbound decision by its stable identifier."""
    return (
        session.query(OutboundDecisionModel)
        .filter_by(decision_id=str(decision_id))
        .one_or_none()
    )


def _json_value_dict(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value or "{}"))
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def list_outbound_decisions(session: Session) -> list[dict[str, Any]]:
    rows = (
        session.query(OutboundDecisionModel)
        .order_by(OutboundDecisionModel.sequence.asc())
        .all()
    )
    return [outbound_decision_to_dict(row) for row in rows]


def append_route_health_evidence(
    session: Session,
    record: dict[str, Any],
    *,
    commit: bool = True,
) -> RouteHealthEvidenceModel:
    """Append one immutable approved-route health observation."""
    required = {
        "evidence_id",
        "schema_version",
        "route_id",
        "tenant_id",
        "engagement_id",
        "action_id",
        "configuration_digest",
        "runtime_id",
        "dns_mode",
        "verification_endpoint_ref",
        "observed_egress",
        "route_identity",
        "verified_at",
        "expires_at",
        "binding_digest",
    }
    missing = sorted(required - set(record))
    if missing:
        raise ValueError(f"route health evidence missing fields: {', '.join(missing)}")
    model = RouteHealthEvidenceModel(
        evidence_id=str(record["evidence_id"]),
        schema_version=str(record["schema_version"]),
        route_id=str(record["route_id"]),
        tenant_id=str(record["tenant_id"]),
        engagement_id=str(record["engagement_id"]),
        action_id=str(record["action_id"]),
        configuration_digest=str(record["configuration_digest"]),
        runtime_id=str(record["runtime_id"]),
        dns_mode=str(record["dns_mode"]),
        verification_endpoint_ref=str(record["verification_endpoint_ref"]),
        observed_egress=str(record["observed_egress"]),
        route_identity=str(record["route_identity"]),
        verified_at=_parse_datetime(record["verified_at"]),
        expires_at=_parse_datetime(record["expires_at"]),
        binding_digest=str(record["binding_digest"]),
        detail=_json_text(record.get("detail") or {}, {}),
        recorded_at=_parse_datetime(record.get("recorded_at"))
        or datetime.now(timezone.utc),
    )
    if model.verified_at is None or model.expires_at is None:
        raise ValueError("route health timestamps are required")
    session.add(model)
    try:
        session.flush()
        if commit:
            session.commit()
            session.refresh(model)
    except IntegrityError as exc:
        session.rollback()
        detail = str(getattr(exc, "orig", exc))
        if "route_health_configuration_changed" in detail:
            raise RouteHealthConfigurationChangedError(
                "approved route configuration changed"
            ) from exc
        if "route_health_identity_changed" in detail:
            raise RouteHealthIdentityChangedError(
                "approved route identity changed"
            ) from exc
        raise
    return model


def route_health_evidence_to_dict(model: RouteHealthEvidenceModel) -> dict[str, Any]:
    return {
        "sequence": model.sequence,
        "evidence_id": model.evidence_id,
        "schema_version": model.schema_version,
        "route_id": model.route_id,
        "tenant_id": model.tenant_id,
        "engagement_id": model.engagement_id,
        "action_id": model.action_id,
        "configuration_digest": model.configuration_digest,
        "runtime_id": model.runtime_id,
        "dns_mode": model.dns_mode,
        "verification_endpoint_ref": model.verification_endpoint_ref,
        "observed_egress": model.observed_egress,
        "route_identity": model.route_identity,
        "verified_at": model.verified_at.isoformat() if model.verified_at else None,
        "expires_at": model.expires_at.isoformat() if model.expires_at else None,
        "binding_digest": model.binding_digest,
        "detail": _json_value_dict(model.detail),
        "recorded_at": model.recorded_at.isoformat() if model.recorded_at else None,
    }


def list_route_health_evidence(session: Session) -> list[dict[str, Any]]:
    rows = (
        session.query(RouteHealthEvidenceModel)
        .order_by(RouteHealthEvidenceModel.sequence.asc())
        .all()
    )
    return [route_health_evidence_to_dict(row) for row in rows]


def append_route_health_invalidation(
    session: Session,
    record: dict[str, Any],
) -> RouteHealthInvalidationModel | None:
    """Atomically invalidate every health observation through the latest generation."""
    required = {
        "invalidation_id",
        "schema_version",
        "route_id",
        "tenant_id",
        "engagement_id",
        "action_id",
        "runtime_id",
        "reason_code",
        "recorded_at",
    }
    missing = sorted(required - set(record))
    if missing:
        raise ValueError(
            f"route health invalidation missing fields: {', '.join(missing)}"
        )
    session.execute(text("BEGIN IMMEDIATE"))
    latest = (
        session.query(RouteHealthEvidenceModel)
        .filter_by(
            route_id=str(record["route_id"]),
            tenant_id=str(record["tenant_id"]),
            engagement_id=str(record["engagement_id"]),
            action_id=str(record["action_id"]),
        )
        .order_by(RouteHealthEvidenceModel.sequence.desc())
        .first()
    )
    if latest is None:
        session.rollback()
        return None
    values = {
        "invalidation_id": str(record["invalidation_id"]),
        "schema_version": str(record["schema_version"]),
        "route_id": latest.route_id,
        "tenant_id": latest.tenant_id,
        "engagement_id": latest.engagement_id,
        "action_id": latest.action_id,
        "configuration_digest": latest.configuration_digest,
        "health_sequence": int(latest.sequence),
        "runtime_id": str(record["runtime_id"]),
        "reason_code": str(record["reason_code"]),
        "recorded_at": str(record["recorded_at"]),
    }
    binding_material = json.dumps(
        values,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8", "replace")
    model = RouteHealthInvalidationModel(
        **{
            **values,
            "binding_digest": (
                "sha256:" + hashlib.sha256(binding_material).hexdigest()
            ),
            "recorded_at": _parse_datetime(record["recorded_at"])
            or datetime.now(timezone.utc),
        }
    )
    session.add(model)
    session.flush()
    session.commit()
    session.refresh(model)
    return model


def route_health_store_is_current(
    session: Session,
    record: dict[str, Any],
) -> bool:
    """Return whether protected state still recognizes this healthy identity."""
    latest = (
        session.query(RouteHealthEvidenceModel)
        .filter_by(
            route_id=str(record["route_id"]),
            tenant_id=str(record["tenant_id"]),
            engagement_id=str(record["engagement_id"]),
            action_id=str(record["action_id"]),
            configuration_digest=str(record["configuration_digest"]),
        )
        .order_by(RouteHealthEvidenceModel.sequence.desc())
        .first()
    )
    if latest is None:
        return False
    if (
        latest.observed_egress != str(record["observed_egress"])
        or latest.route_identity != str(record["route_identity"])
    ):
        return False
    invalidation = (
        session.query(RouteHealthInvalidationModel)
        .filter_by(
            route_id=latest.route_id,
            tenant_id=latest.tenant_id,
            engagement_id=latest.engagement_id,
            action_id=latest.action_id,
            configuration_digest=latest.configuration_digest,
        )
        .order_by(
            RouteHealthInvalidationModel.health_sequence.desc(),
            RouteHealthInvalidationModel.sequence.desc(),
        )
        .first()
    )
    return invalidation is None or int(latest.sequence) > int(
        invalidation.health_sequence
    )


def list_route_health_invalidations(session: Session) -> list[dict[str, Any]]:
    rows = (
        session.query(RouteHealthInvalidationModel)
        .order_by(RouteHealthInvalidationModel.sequence.asc())
        .all()
    )
    return [
        {
            "sequence": row.sequence,
            "invalidation_id": row.invalidation_id,
            "schema_version": row.schema_version,
            "route_id": row.route_id,
            "tenant_id": row.tenant_id,
            "engagement_id": row.engagement_id,
            "action_id": row.action_id,
            "configuration_digest": row.configuration_digest,
            "health_sequence": row.health_sequence,
            "runtime_id": row.runtime_id,
            "reason_code": row.reason_code,
            "binding_digest": row.binding_digest,
            "recorded_at": row.recorded_at.isoformat() if row.recorded_at else None,
        }
        for row in rows
    ]


def append_finding_run_snapshot(
    session: Session,
    *,
    tenant_id: str,
    run_id: str,
    snapshot: dict[str, Any],
    commit: bool = True,
) -> FindingRunMembershipModel:
    """Append one immutable tenant/run membership; exact repeats are idempotent."""
    tenant = str(tenant_id or "").strip()
    run = str(run_id or "").strip()
    if not tenant or not run or not isinstance(snapshot, dict):
        raise ValueError("finding run snapshot identity is required")
    # ``redact_value`` deliberately treats key-like field names as sensitive.
    # A finding's ``dedup_key`` is instead a non-secret content identity that is
    # part of the immutable membership primary key, so capture and validate the
    # trusted structural fields before redacting free-form finding content and
    # restore them afterwards.  Redacting the digest to ``<redacted>`` would
    # collapse every finding in a run onto one membership row.
    snapshot_tenant = str(snapshot.get("tenant_id") or tenant).strip()
    dedup_key = str(snapshot.get("dedup_key") or finding_dedup_key(snapshot)).strip()
    finding_id = str(snapshot.get("id") or "").strip()
    if snapshot_tenant != tenant:
        raise ValueError("finding run snapshot tenant mismatch")
    if (
        not finding_id
        or len(finding_id) > 160
        or len(dedup_key) != 64
        or any(character not in "0123456789abcdef" for character in dedup_key.lower())
    ):
        raise ValueError("finding run snapshot finding identity is required")
    dedup_key = dedup_key.lower()
    safe = redact_value(dict(snapshot))
    if not isinstance(safe, dict):
        raise ValueError("finding run snapshot is invalid")
    safe["tenant_id"] = tenant
    safe["id"] = finding_id
    safe["dedup_key"] = dedup_key
    payload = _stable_json_bytes(safe).decode("utf-8")
    identity = _snapshot_identity(safe)
    started_immediate = not session.in_transaction()
    if started_immediate:
        session.execute(text("BEGIN IMMEDIATE"))
    savepoint: Any | None = None
    existing = (
        session.query(FindingRunMembershipModel)
        .filter_by(tenant_id=tenant, run_id=run, dedup_key=dedup_key)
        .one_or_none()
    )
    if existing is not None:
        if (
            existing.finding_id != finding_id
            or existing.snapshot_json != payload
            or existing.snapshot_identity != identity
        ):
            if started_immediate:
                session.rollback()
            raise ValueError("conflicting finding run snapshot")
        if commit:
            session.commit()
        return existing
    model = FindingRunMembershipModel(
        tenant_id=tenant,
        run_id=run,
        finding_id=finding_id,
        dedup_key=dedup_key,
        snapshot_json=payload,
        snapshot_identity=identity,
        recorded_at=datetime.now(timezone.utc),
    )
    if not started_immediate:
        savepoint = session.begin_nested()
    session.add(model)
    try:
        session.flush()
        if savepoint is not None:
            savepoint.commit()
            savepoint = None
        if commit:
            session.commit()
            session.refresh(model)
    except IntegrityError as exc:
        if savepoint is not None:
            savepoint.rollback()
            savepoint = None
        elif started_immediate:
            session.rollback()
        detail = str(getattr(exc, "orig", exc))
        if "run membership is finalized" in detail:
            raise ValueError("run membership is finalized") from exc
        concurrent = (
            session.query(FindingRunMembershipModel)
            .filter_by(tenant_id=tenant, run_id=run, dedup_key=dedup_key)
            .one_or_none()
        )
        if (
            concurrent is None
            or concurrent.finding_id != finding_id
            or concurrent.snapshot_json != payload
            or concurrent.snapshot_identity != identity
        ):
            raise ValueError("conflicting finding run snapshot") from exc
        if commit:
            session.commit()
        return concurrent
    except Exception:
        if savepoint is not None:
            savepoint.rollback()
        if started_immediate:
            session.rollback()
        raise
    return model


def list_findings_for_run(
    session: Session,
    run_id: str,
    *,
    tenant_id: str,
) -> list[dict[str, Any]]:
    """Load a validated immutable finding snapshot within one tenant boundary."""
    tenant = str(tenant_id or "").strip()
    run = str(run_id or "").strip()
    if not tenant or not run:
        raise PersistedRunTruthValidationError("run_identity_missing")
    rows = (
        session.query(FindingRunMembershipModel)
        .filter_by(tenant_id=tenant, run_id=run)
        .order_by(FindingRunMembershipModel.dedup_key.asc())
        .all()
    )
    findings: list[dict[str, Any]] = []
    for row in rows:
        try:
            snapshot = json.loads(str(row.snapshot_json))
        except (TypeError, json.JSONDecodeError):
            raise PersistedRunTruthValidationError("finding_snapshot_invalid") from None
        if (
            not isinstance(snapshot, dict)
            or str(snapshot.get("tenant_id") or "") != tenant
            or str(snapshot.get("dedup_key") or "") != row.dedup_key
            or _snapshot_identity(snapshot) != row.snapshot_identity
        ):
            raise PersistedRunTruthValidationError("finding_snapshot_invalid")
        findings.append(snapshot)
    return findings


def finding_set_identity(session: Session, *, tenant_id: str, run_id: str) -> str:
    """Hash the complete ordered immutable membership for one tenant/run."""
    findings = list_findings_for_run(session, run_id, tenant_id=tenant_id)
    members = [
        {
            "dedup_key": str(item.get("dedup_key") or ""),
            "snapshot_identity": _snapshot_identity(item),
        }
        for item in findings
    ]
    material = {
        "schema": "forge-finding-run-set-v1",
        "tenant_id": tenant_id,
        "run_id": run_id,
        "members": members,
    }
    return "sha256:" + hashlib.sha256(_stable_json_bytes(material)).hexdigest()


_RUN_TRUTH_SELECT = (
    "SELECT run_id, authorization_run_id, job_id, tenant_id, framework, "
    "scope_binding, target_binding, collection_status, coverage_complete, "
    "coverage_identity, finding_set_identity, predecessor_run_id, run_sequence, "
    "completed_at, authorization_decision_id, authorization_binding, authority_id, "
    "policy_id, policy_version, issuer_id, attestation, recorded_at "
    "FROM run_collection_truth "
)


def _run_collection_truth_from_persisted_row(
    row: Any,
    *,
    policy: RunTruthPolicy,
) -> RunCollectionTruth:
    """Decode one raw SQLite row without truth-inflating type coercion."""
    required_text = (
        "run_id",
        "authorization_run_id",
        "job_id",
        "tenant_id",
        "framework",
        "scope_binding",
        "target_binding",
        "collection_status",
        "coverage_identity",
        "finding_set_identity",
        "predecessor_run_id",
        "completed_at",
        "authorization_decision_id",
        "authorization_binding",
        "authority_id",
        "policy_id",
        "policy_version",
        "issuer_id",
        "attestation",
    )
    if not all(isinstance(row[field], str) for field in required_text):
        raise PersistedRunTruthValidationError("run_record_invalid")
    raw_complete = row["coverage_complete"]
    raw_sequence = row["run_sequence"]
    if type(raw_complete) is not int or raw_complete not in (0, 1):
        raise PersistedRunTruthValidationError("run_coverage_complete_invalid")
    if type(raw_sequence) is not int or raw_sequence < 1:
        raise PersistedRunTruthValidationError("run_sequence_invalid")
    if _parse_datetime(row["recorded_at"]) is None:
        raise PersistedRunTruthValidationError("run_recorded_at_invalid")
    try:
        collection_status = RunCollectionStatus(row["collection_status"])
    except ValueError:
        raise PersistedRunTruthValidationError(
            "run_collection_status_invalid"
        ) from None
    record = RunCollectionTruth(
        run_id=row["run_id"],
        authorization_run_id=row["authorization_run_id"],
        job_id=row["job_id"],
        tenant_id=row["tenant_id"],
        framework=row["framework"],
        scope_binding=row["scope_binding"],
        target_binding=row["target_binding"],
        collection_status=collection_status,
        coverage_complete=bool(raw_complete),
        coverage_identity=row["coverage_identity"],
        finding_set_identity=row["finding_set_identity"],
        predecessor_run_id=row["predecessor_run_id"],
        run_sequence=raw_sequence,
        completed_at=row["completed_at"],
        authorization_decision_id=row["authorization_decision_id"],
        authorization_binding=row["authorization_binding"],
        authority_id=row["authority_id"],
        policy_id=row["policy_id"],
        policy_version=row["policy_version"],
        issuer_id=row["issuer_id"],
        attestation=row["attestation"],
    )
    valid, reason = validate_run_collection_truth(record, policy=policy)
    if not valid:
        raise PersistedRunTruthValidationError(reason)
    return record


def load_run_collection_truth(
    session: Session,
    run_id: str,
    *,
    tenant_id: str,
    policy: RunTruthPolicy | None = None,
    verify_finding_set: bool = True,
) -> RunCollectionTruth | None:
    """Load signed run truth only through its explicit tenant and trust root."""
    run = str(run_id or "").strip()
    tenant = str(tenant_id or "").strip()
    if not run or not tenant:
        raise PersistedRunTruthValidationError("run_identity_missing")
    configured_policy = policy or run_truth_module.RUN_TRUTH_POLICY
    row = session.execute(
        text(_RUN_TRUTH_SELECT + "WHERE run_id=:run_id AND tenant_id=:tenant_id"),
        {"run_id": run, "tenant_id": tenant},
    ).mappings().one_or_none()
    if row is None:
        return None
    record = _run_collection_truth_from_persisted_row(
        row,
        policy=configured_policy,
    )
    if verify_finding_set and finding_set_identity(
        session,
        tenant_id=tenant,
        run_id=run,
    ) != record.finding_set_identity:
        raise PersistedRunTruthValidationError("finding_set_identity_mismatch")
    return record


def latest_run_collection_truth(
    session: Session,
    *,
    tenant_id: str,
    framework: str,
    scope_binding: str,
    target_binding: str,
    policy: RunTruthPolicy | None = None,
) -> RunCollectionTruth | None:
    """Load the latest validated finalization in one signed run series."""
    configured_policy = policy or run_truth_module.RUN_TRUTH_POLICY
    row = session.execute(
        text(
            _RUN_TRUTH_SELECT
            + "WHERE tenant_id=:tenant_id AND framework=:framework "
            "AND scope_binding=:scope_binding AND target_binding=:target_binding "
            "ORDER BY run_sequence DESC LIMIT 1"
        ),
        {
            "tenant_id": tenant_id,
            "framework": framework,
            "scope_binding": scope_binding,
            "target_binding": target_binding,
        },
    ).mappings().one_or_none()
    if row is None:
        return None
    record = _run_collection_truth_from_persisted_row(
        row,
        policy=configured_policy,
    )
    if finding_set_identity(
        session,
        tenant_id=record.tenant_id,
        run_id=record.run_id,
    ) != record.finding_set_identity:
        raise PersistedRunTruthValidationError("finding_set_identity_mismatch")
    return record


def append_run_collection_truth(
    session: Session,
    record: RunCollectionTruth,
    *,
    policy: RunTruthPolicy | None = None,
    commit: bool = True,
) -> RunCollectionTruthModel:
    """Atomically finalize one signed run after freezing its exact membership."""
    configured_policy = policy or run_truth_module.RUN_TRUTH_POLICY
    valid, reason = validate_run_collection_truth(record, policy=configured_policy)
    if not valid:
        raise ValueError(f"run collection truth rejected: {reason}")
    started_immediate = not session.in_transaction()
    if started_immediate:
        session.execute(text("BEGIN IMMEDIATE"))
    savepoint: Any | None = None
    try:
        existing_record = load_run_collection_truth(
            session,
            record.run_id,
            tenant_id=record.tenant_id,
            policy=configured_policy,
        )
        if existing_record is not None:
            if existing_record != record:
                raise ValueError("conflicting persisted run truth")
            model = (
                session.query(RunCollectionTruthModel)
                .filter_by(tenant_id=record.tenant_id, run_id=record.run_id)
                .one()
            )
            if commit:
                session.commit()
            return model
        actual_finding_set = finding_set_identity(
            session,
            tenant_id=record.tenant_id,
            run_id=record.run_id,
        )
        if actual_finding_set != record.finding_set_identity:
            raise ValueError("run finding set identity mismatch")
        predecessor = latest_run_collection_truth(
            session,
            tenant_id=record.tenant_id,
            framework=record.framework,
            scope_binding=record.scope_binding,
            target_binding=record.target_binding,
            policy=configured_policy,
        )
        predecessor_mismatch = False
        if predecessor is None:
            if record.run_sequence != 1 or record.predecessor_run_id:
                predecessor_mismatch = True
        elif (
            record.predecessor_run_id != predecessor.run_id
            or record.run_sequence != predecessor.run_sequence + 1
        ):
            predecessor_mismatch = True
        if predecessor_mismatch:
            # Another writer may have committed this exact tenant/run between
            # our initial identity lookup and series lookup.  Converge only on
            # byte-equivalent signed truth; a different successor or payload
            # remains a hard chain conflict.
            concurrent_record = load_run_collection_truth(
                session,
                record.run_id,
                tenant_id=record.tenant_id,
                policy=configured_policy,
            )
            if concurrent_record == record:
                model = (
                    session.query(RunCollectionTruthModel)
                    .filter_by(
                        tenant_id=record.tenant_id,
                        run_id=record.run_id,
                    )
                    .one()
                )
                if commit:
                    session.commit()
                return model
            raise ValueError("run predecessor chain mismatch")
        model = RunCollectionTruthModel(
            run_id=record.run_id,
            authorization_run_id=record.authorization_run_id,
            job_id=record.job_id,
            tenant_id=record.tenant_id,
            framework=record.framework,
            scope_binding=record.scope_binding,
            target_binding=record.target_binding,
            collection_status=record.collection_status.value,
            coverage_complete=record.coverage_complete,
            coverage_identity=record.coverage_identity,
            finding_set_identity=record.finding_set_identity,
            predecessor_run_id=record.predecessor_run_id,
            run_sequence=record.run_sequence,
            completed_at=record.completed_at,
            authorization_decision_id=record.authorization_decision_id,
            authorization_binding=record.authorization_binding,
            authority_id=record.authority_id,
            policy_id=record.policy_id,
            policy_version=record.policy_version,
            issuer_id=record.issuer_id,
            attestation=record.attestation,
            recorded_at=datetime.now(timezone.utc),
        )
        # A caller-owned transaction may contain other durable work.  Isolate
        # the unique insert so an exact concurrent winner can be recognized
        # without rolling back that caller's entire unit of work.
        if not started_immediate:
            savepoint = session.begin_nested()
        session.add(model)
        session.flush()
        if savepoint is not None:
            savepoint.commit()
            savepoint = None
        if commit:
            session.commit()
            session.refresh(model)
        return model
    except IntegrityError as exc:
        if savepoint is not None:
            savepoint.rollback()
            savepoint = None
        elif started_immediate:
            session.rollback()
        concurrent_record = load_run_collection_truth(
            session,
            record.run_id,
            tenant_id=record.tenant_id,
            policy=configured_policy,
        )
        if concurrent_record != record:
            raise ValueError("conflicting persisted run truth") from exc
        model = (
            session.query(RunCollectionTruthModel)
            .filter_by(tenant_id=record.tenant_id, run_id=record.run_id)
            .one()
        )
        if commit:
            session.commit()
        return model
    except Exception:
        if savepoint is not None:
            savepoint.rollback()
        if started_immediate:
            session.rollback()
        raise


def append_persisted_finding_delta(
    session: Session,
    *,
    tenant_id: str,
    report: dict[str, Any],
    authorization_decision_id: str,
    authorization_binding: str,
    policy: RunTruthPolicy | None = None,
    commit: bool = True,
) -> PersistedFindingDeltaModel:
    """Persist only the canonical delta derived from signed immutable run state."""
    tenant = str(tenant_id or "").strip()
    previous_run = str(report.get("previous_run") or "").strip()
    current_run = str(report.get("current_run") or "").strip()
    if not tenant or not current_run:
        raise ValueError("persisted delta identity is required")
    truth = load_run_collection_truth(
        session,
        current_run,
        tenant_id=tenant,
        policy=policy,
    )
    if truth is None:
        raise ValueError("persisted delta current run truth is missing")
    if (
        truth.authorization_decision_id != authorization_decision_id
        or truth.authorization_binding != authorization_binding
        or truth.predecessor_run_id != previous_run
    ):
        raise ValueError("persisted delta authorization binding mismatch")
    # The caller is a renderer, not a delta authority.  Recompute the exact
    # comparison from signed truth plus immutable memberships so a stale or
    # compromised first writer cannot serialize invented new/fixed outcomes.
    from common.reporting.delta_report import build_persisted_finding_delta

    canonical_report = build_persisted_finding_delta(
        session,
        truth.predecessor_run_id,
        truth.run_id,
        tenant_id=tenant,
        policy=policy,
    ).to_dict()
    safe_report = redact_value(dict(report))
    if not isinstance(safe_report, dict):
        raise ValueError("persisted delta report is invalid")
    if _stable_json_bytes(safe_report) != _stable_json_bytes(canonical_report):
        raise ValueError("persisted delta report does not match signed run truth")
    payload = _stable_json_bytes(safe_report).decode("utf-8")
    identity = "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
    existing = (
        session.query(PersistedFindingDeltaModel)
        .filter_by(tenant_id=tenant, current_run_id=current_run)
        .one_or_none()
    )
    if existing is not None:
        if (
            existing.previous_run_id != previous_run
            or existing.authorization_decision_id != authorization_decision_id
            or existing.authorization_binding != authorization_binding
            or existing.report_json != payload
            or existing.report_identity != identity
        ):
            raise ValueError("conflicting persisted finding delta")
        return existing
    model = PersistedFindingDeltaModel(
        tenant_id=tenant,
        previous_run_id=previous_run,
        current_run_id=current_run,
        authorization_decision_id=authorization_decision_id,
        authorization_binding=authorization_binding,
        report_json=payload,
        report_identity=identity,
        recorded_at=datetime.now(timezone.utc),
    )
    session.add(model)
    session.flush()
    if commit:
        session.commit()
        session.refresh(model)
    return model


def load_persisted_finding_delta(
    session: Session,
    *,
    tenant_id: str,
    current_run_id: str,
    policy: RunTruthPolicy | None = None,
) -> dict[str, Any] | None:
    row = (
        session.query(PersistedFindingDeltaModel)
        .filter_by(tenant_id=tenant_id, current_run_id=current_run_id)
        .one_or_none()
    )
    if row is None:
        return None
    identity = "sha256:" + hashlib.sha256(
        str(row.report_json).encode("utf-8")
    ).hexdigest()
    if identity != row.report_identity:
        raise PersistedRunTruthValidationError("persisted_delta_identity_mismatch")
    try:
        value = json.loads(str(row.report_json))
    except (TypeError, json.JSONDecodeError):
        raise PersistedRunTruthValidationError("persisted_delta_invalid") from None
    if not isinstance(value, dict):
        raise PersistedRunTruthValidationError("persisted_delta_invalid")
    truth = load_run_collection_truth(
        session,
        current_run_id,
        tenant_id=tenant_id,
        policy=policy,
    )
    if truth is None:
        raise PersistedRunTruthValidationError("persisted_delta_run_truth_missing")
    if (
        row.previous_run_id != truth.predecessor_run_id
        or row.authorization_decision_id != truth.authorization_decision_id
        or row.authorization_binding != truth.authorization_binding
    ):
        raise PersistedRunTruthValidationError(
            "persisted_delta_authorization_binding_mismatch"
        )
    from common.reporting.delta_report import build_persisted_finding_delta

    canonical = build_persisted_finding_delta(
        session,
        truth.predecessor_run_id,
        truth.run_id,
        tenant_id=tenant_id,
        policy=policy,
    ).to_dict()
    if _stable_json_bytes(value) != _stable_json_bytes(canonical):
        raise PersistedRunTruthValidationError("persisted_delta_truth_mismatch")
    return value


class TestDb:
    """Unit tests for db module."""

    def test_create_db(self, tmp_path: Path) -> None:
        session = create_db(tmp_path / "test.db")
        assert session is not None
        session.close()

    def test_save_and_retrieve_finding(self, tmp_path: Path) -> None:
        from common.finding import Finding, Severity
        session = create_db(tmp_path / "test2.db")
        f = Finding(
            title="Test SQL Injection",
            severity=Severity.HIGH,
            target="https://example.com",
            module="sqli_scanner",
            description="SQLi found",
            reproduction_steps=["Visit URL", "Inject payload"],
            remediation="Use parameterized queries",
            references=["CWE-89"],
        )
        # This embedded Gate-0 regression fixture has no canonical tenant /
        # engagement / module-version / asset graph.  Opt into the explicit
        # compatibility writer so the strict production default remains
        # fail-closed.
        save_finding(session, f.to_dict(), allow_legacy_compat=True)
        result = session.query(FindingModel).filter_by(id=f.id).first()
        assert result is not None
        assert result.title == "Test SQL Injection"
        session.close()
