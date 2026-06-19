"""SQLAlchemy 2.0 ORM base models for forge-suite findings storage."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer, String, Text, create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class FindingModel(Base):
    """ORM model for a security finding."""
    __tablename__ = "findings"

    id               = Column(String(36), primary_key=True)
    title            = Column(String(500), nullable=False)
    severity         = Column(String(20),  nullable=False)
    target           = Column(String(500), nullable=False)
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
    discovered_at    = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
    engagement       = Column(String(200), nullable=True)
    tester           = Column(String(200), nullable=True)


class ScanRunModel(Base):
    """ORM model for a scan run / engagement metadata."""
    __tablename__ = "scan_runs"

    id         = Column(String(36), primary_key=True)
    framework  = Column(String(20),  nullable=False)  # webforge/netforge/adforge
    target     = Column(String(500), nullable=False)
    mode       = Column(String(50),  nullable=True)
    engagement = Column(String(200), nullable=True)
    tester     = Column(String(200), nullable=True)
    started_at = Column(DateTime,    default=lambda: datetime.now(timezone.utc))
    ended_at   = Column(DateTime,    nullable=True)
    phase      = Column(Integer,     default=0)       # last completed phase index
    status     = Column(String(20),  default="running")  # running/completed/interrupted


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


class DashboardStateModel(Base):
    """Persisted dashboard state for crash recovery / session attach."""
    __tablename__ = "dashboard_state"

    id         = Column(String(36), primary_key=True)
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


def create_db(db_path: Path) -> Session:
    """Create SQLite database, all tables, and return a session.

    Args:
        db_path: Path to the .db file. Created if not exists.

    Returns:
        SQLAlchemy Session bound to the database.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        echo=False,
    )

    # Enable WAL mode for better concurrent access
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):  # type: ignore
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return SessionLocal()


def save_finding(session: Session, finding_dict: dict[str, Any], run_id: str | None = None) -> None:
    """Persist a Finding.to_dict() result to the database."""
    ev = finding_dict.get("evidence", {})
    model = FindingModel(
        id                   = finding_dict["id"],
        title                = finding_dict["title"],
        severity             = finding_dict["severity"],
        target               = finding_dict["target"],
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
        screenshot_path      = ev.get("screenshot_path"),
        request_raw          = ev.get("request_raw"),
        response_raw         = ev.get("response_raw"),
        console_capture_path = ev.get("console_capture_path"),
        pcap_path            = ev.get("pcap_path"),
        operator_confirmed   = finding_dict.get("operator_confirmed", False),
        tags                 = json.dumps(finding_dict.get("tags", [])),
    )
    session.merge(model)
    session.commit()


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
        save_finding(session, f.to_dict())
        result = session.query(FindingModel).filter_by(id=f.id).first()
        assert result is not None
        assert result.title == "Test SQL Injection"
        session.close()
