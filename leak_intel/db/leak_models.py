"""Leak Intel DB — SQLite models for leak findings, credentials, and tested status.

Uses SQLAlchemy ORM consistent with the project's common/db.py patterns.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, Boolean, create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, Session

from common import db as database_boundary
from common.redaction import REDACTED, redact_secret_fragments, redact_value


class LeakDatabaseInitializationError(RuntimeError):
    """Fixed public failure for Leak Intel schema initialization."""


class _LeakDatabaseArtifactError(ValueError):
    """Fixed public failure for an unsafe Leak Intel database artifact."""


class LeakBase(DeclarativeBase):
    """Declarative base for leak intel ORM models."""


class LeakFinding(LeakBase):
    """A single leak finding from OSINT scanners."""
    __tablename__ = "leak_findings"

    id            = Column(String(36), primary_key=True)
    scanner       = Column(String(100), nullable=False)     # github_scanner, pastebin_scanner, etc.
    source_url    = Column(String(1000), nullable=True)     # Where the leak was found
    secret_type   = Column(String(100), nullable=True)      # aws_key, private_key, jwt, etc.
    severity      = Column(String(20), nullable=False)      # Critical/High/Medium/Low/Info
    title         = Column(String(500), nullable=False)
    description   = Column(Text, nullable=True)
    target_domain = Column(String(200), nullable=True)
    raw_match     = Column(Text, nullable=True)             # Redacted secret value
    file_path     = Column(String(500), nullable=True)      # File where the secret was found
    repo_name     = Column(String(200), nullable=True)
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_validated  = Column(Boolean, default=False)           # Has it been tested?
    is_valid      = Column(Boolean, nullable=True)           # Is the credential valid?
    tags          = Column(Text, nullable=True)              # JSON list


class LeakCredential(LeakBase):
    """A credential extracted from a leak finding."""
    __tablename__ = "leak_credentials"

    id            = Column(String(36), primary_key=True)
    finding_id    = Column(String(36), nullable=False)       # FK to leak_findings
    cred_type     = Column(String(50), nullable=False)       # password, api_key, aws_key, jwt
    username      = Column(String(200), nullable=True)
    # Store redacted values only — never store raw secrets
    redacted_value = Column(String(200), nullable=True)
    service       = Column(String(100), nullable=True)       # Service this cred belongs to
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    tested_at     = Column(DateTime, nullable=True)
    test_result   = Column(String(50), nullable=True)        # valid, invalid, error, untested
    test_service  = Column(String(100), nullable=True)       # Which service was it tested against


class AuditLog(LeakBase):
    """Audit log for credential testing attempts."""
    __tablename__ = "leak_audit_log"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    timestamp     = Column(Float, nullable=False, default=time.time)
    action        = Column(String(100), nullable=False)      # test_credential, validate_key, etc.
    service       = Column(String(100), nullable=False)      # azure_ad, aws_sts, jira, etc.
    username      = Column(String(200), nullable=True)
    cred_type     = Column(String(50), nullable=True)
    success       = Column(Boolean, nullable=True)
    detail        = Column(Text, nullable=True)
    source        = Column(String(500), nullable=True)       # Where the cred was found


def create_leak_db(db_path: Path) -> Session:
    """Create the leak intel database and return a session.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        SQLAlchemy Session.
    """
    db_path = database_boundary._absolute_artifact_path(Path(db_path))
    engine: Any | None = None
    try:
        engine = create_engine(
            URL.create("sqlite+pysqlite", database=os.fspath(db_path)),
            creator=lambda: database_boundary._connect_sqlite_file(db_path),
            echo=False,
        )
        with database_boundary._db_schema_lock(db_path):
            LeakBase.metadata.create_all(engine)
        _secure_sqlite_paths(db_path)
        session = database_boundary._engine_bound_session(
            engine,
            autocommit=False,
            autoflush=True,
        )
        session.info["leak_db_path"] = db_path
        return session
    except _LeakDatabaseArtifactError:
        if engine is not None:
            database_boundary._safe_dispose_engine(engine)
        raise
    except database_boundary._DatabaseArtifactError:
        if engine is not None:
            database_boundary._safe_dispose_engine(engine)
        raise _LeakDatabaseArtifactError(
            "leak database artifact is unavailable or unsafe"
        ) from None
    except Exception:
        if engine is not None:
            database_boundary._safe_dispose_engine(engine)
        raise LeakDatabaseInitializationError(
            "leak database initialization failed"
        ) from None


def _secure_sqlite_paths(db_path: Path) -> None:
    """Apply owner-only permissions to a database and any SQLite sidecars."""
    db_path = database_boundary._absolute_artifact_path(Path(db_path))
    descriptor = -1
    try:
        descriptor = database_boundary._open_owner_only_regular_file(
            db_path,
            create=False,
        )
        database_boundary._safe_close_descriptor(descriptor)
        descriptor = -1
        database_boundary._secure_existing_sqlite_sidecars(db_path)
    except Exception:
        raise _LeakDatabaseArtifactError(
            "leak database artifact is unavailable or unsafe"
        ) from None
    finally:
        database_boundary._safe_close_descriptor(descriptor)


def _session_db_path(session: Session) -> Path | None:
    value = session.info.get("leak_db_path")
    if isinstance(value, Path):
        return value
    try:
        bind = session.get_bind()
        url = getattr(bind, "url", None)
        database = getattr(url, "database", None)
    except Exception:
        return None
    return Path(database) if database else None


def _secure_session(session: Session) -> None:
    path = _session_db_path(session)
    if path is not None:
        _secure_sqlite_paths(path)


def _safe_text(value: Any) -> str | None:
    if value is None:
        return None
    return str(redact_value(value))


def _sensitive_literals(value: Any, *, key: str = "") -> set[str]:
    """Collect exact values supplied through semantically sensitive fields."""
    markers = (
        "secret", "password", "token", "credential", "match", "detail",
        "raw", "private_key", "access_key", "redacted_value",
    )
    found: set[str] = set()
    if isinstance(value, dict):
        for child_key, child in value.items():
            found.update(_sensitive_literals(child, key=str(child_key)))
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            found.update(_sensitive_literals(child, key=key))
    elif isinstance(value, str) and value and any(
        marker in key.lower() for marker in markers
    ):
        found.add(value)
    return found


def _replace_literals(value: Any, literals: set[str]) -> Any:
    if isinstance(value, str):
        return redact_secret_fragments(value, literals)
    if isinstance(value, dict):
        return {
            _replace_literals(key, literals): _replace_literals(child, literals)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_replace_literals(child, literals) for child in value]
    return value


def _safe_payload(value: dict[str, Any]) -> dict[str, Any]:
    safe = redact_value(dict(value))
    if not isinstance(safe, dict):
        return {}
    replaced = _replace_literals(safe, _sensitive_literals(value))
    return replaced if isinstance(replaced, dict) else {}


def _safe_unstructured_text(value: Any) -> str | None:
    """Conservatively suppress a free-form persistence field."""
    if value is None or value == "":
        return None
    safe = str(redact_value(value))
    return safe if safe != str(value) else REDACTED


def _safe_secret_preview(value: Any) -> str | None:
    """Never persist a purported secret preview supplied by a caller."""
    if value is None or value == "":
        return None
    return REDACTED


def save_leak_finding(session: Session, finding_data: dict[str, Any]) -> None:
    """Save a leak finding to the database.

    Args:
        session:      Active SQLAlchemy session.
        finding_data: Dict with finding fields.
    """
    import uuid
    safe = _safe_payload(finding_data)
    finding = LeakFinding(
        id=str(safe.get("id", str(uuid.uuid4()))),
        scanner=str(safe.get("scanner", "")),
        source_url=_safe_text(safe.get("source_url")),
        secret_type=_safe_text(safe.get("secret_type")),
        severity=str(safe.get("severity", "Medium")),
        title=str(safe.get("title", "")),
        description=_safe_unstructured_text(safe.get("description")),
        target_domain=_safe_text(safe.get("target_domain")),
        raw_match=_safe_secret_preview(safe.get("raw_match")),
        file_path=_safe_text(safe.get("file_path")),
        repo_name=_safe_text(safe.get("repo_name")),
        is_validated=bool(safe.get("is_validated", False)),
        is_valid=safe.get("is_valid"),
        tags=json.dumps(_replace_literals(safe.get("tags", []), _sensitive_literals(finding_data))),
    )
    _secure_session(session)
    session.merge(finding)
    session.commit()
    _secure_session(session)


def save_credential(session: Session, cred_data: dict[str, Any]) -> None:
    """Save a credential to the database."""
    import uuid
    safe = _safe_payload(cred_data)
    cred = LeakCredential(
        id=str(safe.get("id", str(uuid.uuid4()))),
        finding_id=str(safe.get("finding_id", "")),
        cred_type=str(safe.get("cred_type", "password")),
        username=_safe_text(safe.get("username")),
        redacted_value=_safe_secret_preview(safe.get("redacted_value")),
        service=_safe_text(safe.get("service")),
        test_result=_safe_text(safe.get("test_result", "untested")),
    )
    _secure_session(session)
    session.merge(cred)
    session.commit()
    _secure_session(session)


def log_audit(session: Session, entry: dict[str, Any]) -> None:
    """Log a credential test attempt."""
    safe = _safe_payload(entry)
    log_entry = AuditLog(
        timestamp=safe.get("timestamp", time.time()),
        action=str(safe.get("action", "test_credential")),
        service=str(safe.get("service", "")),
        username=_safe_text(safe.get("username")),
        cred_type=_safe_text(safe.get("cred_type")),
        success=safe.get("success"),
        detail=_safe_unstructured_text(safe.get("detail")),
        source=_safe_unstructured_text(safe.get("source")),
    )
    _secure_session(session)
    session.add(log_entry)
    session.commit()
    _secure_session(session)


class TestLeakModels:
    """Unit tests for leak DB models."""

    def test_create_db(self, tmp_path: Path) -> None:
        session = create_leak_db(tmp_path / "test_leak.db")
        assert session is not None
        session.close()

    def test_save_finding(self, tmp_path: Path) -> None:
        session = create_leak_db(tmp_path / "test_leak.db")
        save_leak_finding(session, {
            "scanner": "github_scanner",
            "title": "Test leak",
            "severity": "High",
            "secret_type": "api_key",
        })
        results = session.query(LeakFinding).all()
        assert len(results) == 1
        assert results[0].scanner == "github_scanner"
        session.close()

    def test_save_credential(self, tmp_path: Path) -> None:
        session = create_leak_db(tmp_path / "test_leak.db")
        save_credential(session, {
            "finding_id": "test-finding-id",
            "cred_type": "password",
            "username": "admin",
            "redacted_value": "adm***rd",
        })
        results = session.query(LeakCredential).all()
        assert len(results) == 1
        session.close()

    def test_audit_log(self, tmp_path: Path) -> None:
        session = create_leak_db(tmp_path / "test_leak.db")
        log_audit(session, {
            "action": "test_credential",
            "service": "azure_ad",
            "username": "test@example.com",
            "success": False,
        })
        results = session.query(AuditLog).all()
        assert len(results) == 1
        assert results[0].service == "azure_ad"
        session.close()
