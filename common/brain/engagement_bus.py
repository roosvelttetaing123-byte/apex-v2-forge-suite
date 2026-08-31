"""EngagementBus — Cross-framework finding exchange and chain orchestration.

Singleton engagement bus that connects all 4 frameworks (NetForge, WebForge,
ADForge, AIForge) through a shared SQLite-backed finding store. Any framework
can publish findings, any can subscribe, and the bus handles:

    - publish(framework, finding)    → store + notify all subscribers
    - subscribe(callback)            → register for cross-framework findings
    - get_all_findings()             → all findings across all frameworks
    - get_credentials()              → all credentials across all frameworks
    - get_intel()                    → full EngagementIntelligence for the planner
    - Cross-framework chain triggers → SQLi→cred spray, SSRF→internal scan, etc.
    - Brain integration              → auto-analyze each published finding
    - Planner compatibility          → inert until canonical plan/node custody
    - EventBus integration           → emit FINDING_NEW, BRAIN_VERDICT, CHAIN_ACTION

Graceful degradation: works without brain (no analysis), without event bus
(no dashboard push). The finding store always works.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine

from common.confidence_policy import normalise_finding
from common.brain.truth_boundary import project_model_input
from common.credential_boundary import CredentialReference
from common.evidence import ordinary_finding_projection
from common.redaction import (
    is_sensitive_identifier,
    redact_text,
    redact_value,
    redacted_json_dumps,
)

log = logging.getLogger("forge.brain.engagement_bus")


# ══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════

class FindingSource(str, Enum):
    """Framework source for a finding."""
    NETFORGE = "netforge"
    WEBFORGE = "webforge"
    ADFORGE  = "adforge"
    AIFORGE  = "aiforge"
    C2       = "forge_c2"
    MANUAL   = "manual"


class ChainType(str, Enum):
    """Cross-framework attack chain types."""
    SQLI_TO_CRED_SPRAY           = "sqli_to_cred_spray"
    XSS_TO_SESSION_HIJACK        = "xss_to_session_hijack"
    SMB_SIGNING_TO_RELAY         = "smb_signing_to_relay"
    HOST_COMPROMISE_TO_C2        = "host_compromise_to_c2"
    DOMAIN_CREDS_TO_LATERAL      = "domain_creds_to_lateral"
    SSRF_TO_INTERNAL_RECON       = "ssrf_to_internal_recon"
    UPLOAD_TO_WEBSHELL           = "upload_to_webshell"
    ADCS_ESC_TO_DOMAIN_ADMIN     = "adcs_esc_to_domain_admin"
    ZEROLOGON_TO_DOMAIN_COMPROMISE = "zerologon_to_domain_compromise"


@dataclass
class ChainAction:
    """A cross-framework chain action triggered by a finding."""
    chain_type:       ChainType
    source_finding:   str           # finding ID that triggered this
    source_framework: str
    target_framework: str
    target_module:    str
    target:           str           # target URL/IP for the action
    rationale:        str
    auto_execute:     bool = False
    triggered_at:     str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class EngagementIntelligence:
    """Full engagement intelligence struct for the planner.

    Aggregates all findings, credentials, shells, and metadata
    across all frameworks into a single intelligence package.
    """
    findings:       list[dict[str, Any]] = field(default_factory=list)
    credentials:    list[dict[str, Any]] = field(default_factory=list)
    shells:         list[dict[str, Any]] = field(default_factory=list)
    persistence:    list[dict[str, Any]] = field(default_factory=list)
    lateral_moves:  list[dict[str, Any]] = field(default_factory=list)
    collection:     list[dict[str, Any]] = field(default_factory=list)
    chain_actions:  list[dict[str, Any]] = field(default_factory=list)
    frameworks_active: list[str]         = field(default_factory=list)
    total_findings:    int = 0
    severity_counts:   dict[str, int]    = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for brain/planner consumption."""
        return asdict(self)


# ══════════════════════════════════════════════════════════════════════
# SUBSCRIBER TYPES
# ══════════════════════════════════════════════════════════════════════

# Sync subscriber: called with (framework: str, finding: dict)
FindingSubscriber = Callable[[str, dict[str, Any]], None]
# Async subscriber: called with (framework: str, finding: dict)
AsyncFindingSubscriber = Callable[[str, dict[str, Any]], Coroutine[Any, Any, None]]
# The sink owns canonical advisory persistence and its validation boundary.
# EngagementBus only supplies a bounded, tenant-scoped record; it never creates
# jobs or interprets advisory data as execution authority.
CanonicalAdvisorySink = Callable[[Mapping[str, Any]], Any]


# ══════════════════════════════════════════════════════════════════════
# SQLITE FINDING STORE
# ══════════════════════════════════════════════════════════════════════

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    engagement_id TEXT NOT NULL DEFAULT 'default-engagement',
    framework   TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'Informational',
    target      TEXT NOT NULL DEFAULT '',
    module      TEXT NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    confidence  TEXT DEFAULT 'MEDIUM',
    data_json   TEXT DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    brain_verdict   TEXT DEFAULT '',
    brain_confidence TEXT DEFAULT '',
    brain_reasoning  TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS credentials (
    id          TEXT PRIMARY KEY,
    framework   TEXT NOT NULL,
    host        TEXT DEFAULT '',
    service     TEXT DEFAULT '',
    username    TEXT DEFAULT '',
    password    TEXT DEFAULT '',
    hash_value  TEXT DEFAULT '',
    hash_type   TEXT DEFAULT '',
    domain      TEXT DEFAULT '',
    source      TEXT DEFAULT '',
    data_json   TEXT DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chain_actions (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    engagement_id   TEXT NOT NULL DEFAULT 'default-engagement',
    chain_type      TEXT NOT NULL,
    source_finding  TEXT NOT NULL,
    source_framework TEXT NOT NULL,
    target_framework TEXT NOT NULL,
    target_module    TEXT NOT NULL,
    target          TEXT DEFAULT '',
    rationale       TEXT DEFAULT '',
    auto_execute    INTEGER DEFAULT 0,
    executed        INTEGER DEFAULT 0,
    triggered_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_framework ON findings(framework);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_credentials_framework ON credentials(framework);
CREATE INDEX IF NOT EXISTS idx_chain_source ON chain_actions(source_finding);

CREATE TABLE IF NOT EXISTS credential_refs (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    engagement_id        TEXT NOT NULL,
    framework            TEXT NOT NULL,
    credential_reference TEXT,
    credential_state     TEXT NOT NULL CHECK(
        credential_state IN ('protected_reference','purged_legacy')
    ),
    migrated_at          TEXT NOT NULL,
    migration_reason     TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    UNIQUE(tenant_id, engagement_id, id)
);

CREATE INDEX IF NOT EXISTS idx_credential_refs_scope
ON credential_refs(tenant_id, engagement_id, created_at);

CREATE TABLE IF NOT EXISTS engagement_migration_journal (
    version      TEXT PRIMARY KEY,
    state        TEXT NOT NULL CHECK(state IN ('applying','applied','failed')),
    started_at   TEXT NOT NULL,
    completed_at TEXT,
    detail       TEXT NOT NULL
);
"""

_CREDENTIAL_MIGRATION_VERSION = "forgebrain-credential-boundary-v1"


def _scope_id(value: str, field_name: str) -> str:
    rendered = str(value or "").strip()
    if not rendered or len(rendered) > 200 or any(c.isspace() for c in rendered):
        raise ValueError(f"invalid {field_name}")
    return rendered


class _FindingStore:
    """SQLite-backed finding store for the engagement bus.

    Thread-safe via a dedicated connection per instance with WAL mode.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        *,
        tenant_id: str = "default",
        engagement_id: str = "default-engagement",
    ) -> None:
        self._db_path = db_path
        self._tenant_id = _scope_id(tenant_id, "tenant_id")
        self._engagement_id = _scope_id(engagement_id, "engagement_id")
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database and schema."""
        if self._db_path != ":memory:":
            artifact = Path(os.path.abspath(self._db_path))
            if (
                artifact.parent.resolve() != artifact.parent
                or artifact.is_symlink()
                or (artifact.exists() and not artifact.is_file())
            ):
                raise ValueError("EngagementBus database path is unsafe")
            self._db_path = os.fspath(artifact)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._migrate_legacy_credentials()
        if self._db_path != ":memory:":
            for artifact in (
                Path(self._db_path),
                Path(self._db_path + "-wal"),
                Path(self._db_path + "-shm"),
            ):
                if artifact.exists():
                    artifact.chmod(0o600)
        log.debug("EngagementBus SQLite store initialized: %s", self._db_path)

    def _ensure_scope_columns(self) -> bool:
        legacy_scope_added = False
        for table in ("findings", "chain_actions"):
            columns = {
                str(row[1])
                for row in self._connection.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }
            if "tenant_id" not in columns:
                legacy_scope_added = True
                self._connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'"
                )
            if "engagement_id" not in columns:
                legacy_scope_added = True
                self._connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN engagement_id TEXT NOT NULL DEFAULT 'default-engagement'"
                )
        return legacy_scope_added

    @staticmethod
    def _protected_reference(value: Any) -> str:
        rendered = str(value or "").strip()
        if is_sensitive_identifier(rendered):
            return ""
        try:
            reference = CredentialReference.parse(rendered)
        except ValueError:
            return ""
        return reference.value

    def _migrate_legacy_credentials(self) -> None:
        """Purge legacy secret columns into safe reference/purge markers.

        The journal's applying marker is committed first.  A process stop in
        the migration transaction leaves the old rows intact and the next
        initialization replays the same idempotent transformation.
        """

        prior_journal = self._connection.execute(
            "SELECT state FROM engagement_migration_journal WHERE version=?",
            (_CREDENTIAL_MIGRATION_VERSION,),
        ).fetchone()
        legacy_scope_added = self._ensure_scope_columns()
        quarantine_legacy_scope = (
            legacy_scope_added
            or prior_journal is None
            or str(prior_journal[0]) != "applied"
        )
        stamp = datetime.now(timezone.utc).isoformat()
        self._connection.execute(
            """
            INSERT INTO engagement_migration_journal(
                version,state,started_at,completed_at,detail
            ) VALUES(?, 'applying', ?, NULL, ?)
            ON CONFLICT(version) DO UPDATE SET
                state=CASE
                    WHEN engagement_migration_journal.state='applied' THEN 'applied'
                    ELSE 'applying'
                END,
                started_at=CASE
                    WHEN engagement_migration_journal.state='applied'
                    THEN engagement_migration_journal.started_at ELSE excluded.started_at END,
                detail=excluded.detail
            """,
            (
                _CREDENTIAL_MIGRATION_VERSION,
                stamp,
                json.dumps({"secret_restore": False}, sort_keys=True),
            ),
        )
        self._connection.commit()
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            if quarantine_legacy_scope:
                self._connection.execute(
                    "UPDATE findings SET tenant_id='legacy-unattributed', engagement_id='legacy-unattributed'"
                )
                self._connection.execute(
                    "UPDATE chain_actions SET tenant_id='legacy-unattributed', engagement_id='legacy-unattributed'"
                )
            rows = self._connection.execute(
                "SELECT id,framework,data_json,created_at FROM credentials"
            ).fetchall()
            for row in rows:
                reference = ""
                try:
                    extra = json.loads(str(row[2] or "{}"))
                except (TypeError, json.JSONDecodeError):
                    extra = {}
                if isinstance(extra, dict):
                    reference = self._protected_reference(
                        extra.get("credential_reference")
                    )
                state = "protected_reference" if reference else "purged_legacy"
                reason = (
                    "validated protected reference retained"
                    if reference
                    else (
                        "legacy plaintext purged without secret-derived fingerprint "
                        "or tenant attribution"
                    )
                )
                self._connection.execute(
                    """
                    INSERT OR IGNORE INTO credential_refs(
                        id,tenant_id,engagement_id,framework,
                        credential_reference,credential_state,migrated_at,
                        migration_reason,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        str(row[0]),
                        "legacy-unattributed",
                        "legacy-unattributed",
                        str(row[1]),
                        reference or None,
                        state,
                        stamp,
                        reason,
                        str(row[3] or stamp),
                    ),
                )
                marker = self._connection.execute(
                    """
                    SELECT tenant_id,engagement_id,framework,
                           credential_reference,credential_state
                    FROM credential_refs WHERE id=?
                    """,
                    (str(row[0]),),
                ).fetchone()
                expected_marker = (
                    "legacy-unattributed",
                    "legacy-unattributed",
                    str(row[1]),
                    reference or None,
                    state,
                )
                if marker is None or tuple(marker) != expected_marker:
                    raise RuntimeError("legacy credential marker conflict")
            self._connection.execute(
                """
                UPDATE credentials
                SET host='',service='',username='',password='',hash_value='',
                    hash_type='',domain='',source='',data_json='{}'
                """
            )
            self._connection.execute(
                "UPDATE chain_actions SET auto_execute=0,executed=0"
            )
            self._connection.execute(
                """
                UPDATE engagement_migration_journal
                SET state='applied',completed_at=?,detail=? WHERE version=?
                """,
                (
                    stamp,
                    json.dumps(
                        {"rows": len(rows), "secret_restore": False},
                        sort_keys=True,
                    ),
                    _CREDENTIAL_MIGRATION_VERSION,
                ),
            )
            self._connection.execute("COMMIT")
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        # Remove the ordinary SQLite remnants that a file/WAL backup could
        # otherwise retain after an UPDATE.  Tests use only synthetic rows.
        if self._db_path != ":memory:":
            self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._connection.execute("VACUUM")
            self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    @property
    def _connection(self) -> sqlite3.Connection:
        """Return the open database connection or fail clearly after close."""
        if self._conn is None:
            raise RuntimeError("EngagementBus finding store is closed")
        return self._conn

    def store_finding(self, framework: str, finding: dict[str, Any]) -> str:
        """Store a finding and return its ID."""
        finding_id, _created = self.store_finding_once(framework, finding)
        return finding_id

    def store_finding_once(
        self, framework: str, finding: dict[str, Any]
    ) -> tuple[str, bool]:
        """Store one scoped identity and report whether it was newly created."""
        candidate_id = str(finding.get("id") or "").strip()
        finding_id = (
            candidate_id
            if candidate_id
            and len(candidate_id) <= 200
            and not any(char.isspace() for char in candidate_id)
            and not is_sensitive_identifier(candidate_id)
            else str(uuid.uuid4())
        )
        data = {k: v for k, v in finding.items()
                if k not in ("id", "framework", "title", "severity", "target",
                             "module", "description", "remediation", "confidence")}

        safe_data = redacted_json_dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        safe_title = redact_text(str(finding.get("title", "")))[:1000]
        safe_severity = str(finding.get("severity", "Informational"))[:100]
        safe_target = redact_text(str(finding.get("target", "")))[:2000]
        safe_module = str(finding.get("module", ""))[:200]
        safe_description = redact_text(str(finding.get("description", "")))[:8000]
        safe_remediation = redact_text(str(finding.get("remediation", "")))[:8000]
        safe_confidence = str(finding.get("confidence", "MEDIUM"))[:100]
        with self._lock:
            existing = self._connection.execute(
                """
                SELECT tenant_id,engagement_id,framework,title,severity,target,
                       module,description,remediation,confidence,data_json
                FROM findings WHERE id=?
                """,
                (finding_id,),
            ).fetchone()
            expected = (
                self._tenant_id,
                self._engagement_id,
                framework,
                safe_title,
                safe_severity,
                safe_target,
                safe_module,
                safe_description,
                safe_remediation,
                safe_confidence,
                safe_data,
            )
            if existing is not None and tuple(existing) != expected:
                raise ValueError("finding idempotency conflict")
            self._connection.execute(
                """INSERT INTO findings
                   (id, tenant_id, engagement_id, framework, title, severity, target, module,
                    description, remediation, confidence, data_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                     framework=excluded.framework,title=excluded.title,
                     severity=excluded.severity,target=excluded.target,
                     module=excluded.module,description=excluded.description,
                     remediation=excluded.remediation,confidence=excluded.confidence,
                     data_json=excluded.data_json""",
                (
                    finding_id,
                    self._tenant_id,
                    self._engagement_id,
                    framework,
                    safe_title,
                    safe_severity,
                    safe_target,
                    safe_module,
                    safe_description,
                    safe_remediation,
                    safe_confidence,
                    safe_data,
                ),
            )
            self._connection.commit()
        return finding_id, existing is None

    def update_brain_verdict(
        self, finding_id: str, verdict: str, confidence: str, reasoning: str
    ) -> None:
        """Update brain analysis results for a finding."""
        with self._lock:
            self._connection.execute(
                """UPDATE findings SET brain_verdict=?, brain_confidence=?,
                   brain_reasoning=? WHERE id=? AND tenant_id=? AND engagement_id=?""",
                (
                    str(verdict)[:100],
                    str(confidence)[:100],
                    redact_text(str(reasoning))[:4000],
                    finding_id,
                    self._tenant_id,
                    self._engagement_id,
                ),
            )
            self._connection.commit()

    def store_credential(self, framework: str, cred: dict[str, Any]) -> str:
        """Store only an opaque reference or an explicit purge marker."""
        cred_id = str(uuid.uuid4())
        reference = self._protected_reference(cred.get("credential_reference"))
        state = "protected_reference" if reference else "purged_legacy"
        reason = (
            "validated protected reference retained"
            if reference
            else "raw credential rejected and purged at EngagementBus boundary"
        )
        stamp = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._connection.execute(
                """INSERT INTO credential_refs(
                   id,tenant_id,engagement_id,framework,credential_reference,
                   credential_state,migrated_at,migration_reason,created_at
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    cred_id,
                    self._tenant_id,
                    self._engagement_id,
                    framework,
                    reference or None,
                    state,
                    stamp,
                    reason,
                    stamp,
                ),
            )
            self._connection.commit()
        return cred_id

    def store_chain_action(self, action: ChainAction) -> tuple[str, bool]:
        """Store an advisory chain suggestion without execution authority."""
        identity = {
            "tenant_id": self._tenant_id,
            "engagement_id": self._engagement_id,
            "chain_type": action.chain_type.value,
            "source_finding": action.source_finding,
            "source_framework": action.source_framework,
            "target_framework": action.target_framework,
            "target_module": action.target_module,
            "target": redact_text(str(action.target))[:2000],
        }
        action_id = "chain-action-" + hashlib.sha256(
            json.dumps(
                identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest()[:32]
        with self._lock:
            existing = self._connection.execute(
                """
                SELECT tenant_id,engagement_id,chain_type,source_finding,
                       source_framework,target_framework,target_module,target
                FROM chain_actions WHERE id=?
                """,
                (action_id,),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != tuple(identity.values()):
                    raise ValueError("chain advisory identity conflict")
                return action_id, False
            self._connection.execute(
                """INSERT INTO chain_actions
                   (id, tenant_id, engagement_id, chain_type, source_finding, source_framework,
                    target_framework, target_module, target, rationale,
                    auto_execute, triggered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    action_id,
                    self._tenant_id,
                    self._engagement_id,
                    action.chain_type.value,
                    action.source_finding,
                    action.source_framework,
                    action.target_framework,
                    action.target_module,
                    redact_text(str(action.target))[:2000],
                    redact_text(str(action.rationale))[:4000],
                    0,
                    action.triggered_at,
                ),
            )
            self._connection.commit()
        return action_id, True

    def get_all_findings(self) -> list[dict[str, Any]]:
        """Get all findings across all frameworks."""
        with self._lock:
            cursor = self._connection.execute(
                "SELECT * FROM findings WHERE tenant_id=? AND engagement_id=? ORDER BY created_at DESC",
                (self._tenant_id, self._engagement_id),
            )
            cols = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
        return [self._row_to_dict(cols, row) for row in rows]

    def get_findings_by_framework(self, framework: str) -> list[dict[str, Any]]:
        """Get findings for a specific framework."""
        with self._lock:
            cursor = self._connection.execute(
                "SELECT * FROM findings WHERE tenant_id=? AND engagement_id=? AND framework=? ORDER BY created_at DESC",
                (self._tenant_id, self._engagement_id, framework),
            )
            cols = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
        return [self._row_to_dict(cols, row) for row in rows]

    def get_all_credentials(self) -> list[dict[str, Any]]:
        """Get all credentials across all frameworks."""
        with self._lock:
            cursor = self._connection.execute(
                """SELECT id,tenant_id,engagement_id,framework,
                          credential_reference,credential_state,migrated_at,
                          migration_reason,created_at
                   FROM credential_refs
                   WHERE tenant_id=? AND engagement_id=?
                   ORDER BY created_at DESC""",
                (self._tenant_id, self._engagement_id),
            )
            cols = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
        return [self._row_to_dict(cols, row) for row in rows]

    def get_chain_actions(self, executed: bool | None = None) -> list[dict[str, Any]]:
        """Get chain actions, optionally filtered by execution status."""
        with self._lock:
            if executed is None:
                cursor = self._connection.execute(
                    "SELECT * FROM chain_actions WHERE tenant_id=? AND engagement_id=? ORDER BY triggered_at DESC",
                    (self._tenant_id, self._engagement_id),
                )
            else:
                cursor = self._connection.execute(
                    "SELECT * FROM chain_actions WHERE tenant_id=? AND engagement_id=? AND executed=? ORDER BY triggered_at DESC",
                    (self._tenant_id, self._engagement_id, 1 if executed else 0),
                )
            cols = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
        return [self._row_to_dict(cols, row) for row in rows]

    def count_findings(self) -> int:
        """Return total finding count."""
        with self._lock:
            cursor = self._connection.execute(
                "SELECT COUNT(*) FROM findings WHERE tenant_id=? AND engagement_id=?",
                (self._tenant_id, self._engagement_id),
            )
            return cursor.fetchone()[0]

    def severity_counts(self) -> dict[str, int]:
        """Return findings grouped by severity."""
        with self._lock:
            cursor = self._connection.execute(
                "SELECT severity, COUNT(*) FROM findings WHERE tenant_id=? AND engagement_id=? GROUP BY severity",
                (self._tenant_id, self._engagement_id),
            )
            return dict(cursor.fetchall())

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def safe_backup(self, destination: str | Path) -> Path:
        """Create an owner-private backup after replaying the purge boundary."""

        target = Path(os.path.abspath(os.fspath(destination)))
        if (
            target.parent.resolve() != target.parent
            or target.is_symlink()
            or (target.exists() and not target.is_file())
        ):
            raise ValueError("legacy backup destination is unsafe")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._lock:
            self._migrate_legacy_credentials()
            backup = sqlite3.connect(target)
            try:
                self._connection.backup(backup)
            finally:
                backup.close()
        target.chmod(0o600)
        return target

    @staticmethod
    def _row_to_dict(cols: list[str], row: tuple) -> dict[str, Any]:
        """Convert a sqlite row to dict, unpacking data_json."""
        d = dict(zip(cols, row))
        if "data_json" in d:
            try:
                extra = redact_value(json.loads(d.pop("data_json")))
                if isinstance(extra, dict):
                    for key, value in extra.items():
                        if key not in d:
                            d[key] = value
            except (json.JSONDecodeError, TypeError):
                d.pop("data_json", None)
        return d


# ══════════════════════════════════════════════════════════════════════
# CHAIN DETECTION RULES
# ══════════════════════════════════════════════════════════════════════

def _detect_chains(framework: str, finding: dict[str, Any]) -> list[ChainAction]:
    """Detect cross-framework chain opportunities from a new finding.

    Returns a list of ChainActions that should be triggered.
    """
    chains: list[ChainAction] = []
    title = (finding.get("title") or "").lower()
    finding_id = finding.get("id", "unknown")
    target = finding.get("target", "")

    # ── WebForge SQLi → NetForge credential reuse (SMB/SSH/RDP) ──────
    if framework in ("webforge",) and ("sqli" in title or "sql injection" in title):
        chains.append(ChainAction(
            chain_type=ChainType.SQLI_TO_CRED_SPRAY,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="netforge",
            target_module="credential_spray",
            target=target,
            rationale=(
                "SQLi credential extract → credential reuse across SMB/SSH/RDP. "
                "Extract DB creds via SQLi, then spray across network services."
            ),
        ))

    # ── WebForge XSS → session cookie hijack → account takeover ──────
    if framework in ("webforge",) and "xss" in title:
        chains.append(ChainAction(
            chain_type=ChainType.XSS_TO_SESSION_HIJACK,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="webforge",
            target_module="session_hijack",
            target=target,
            rationale=(
                "XSS → steal session cookies → account takeover → priv esc. "
                "Inject XSS payload that exfiltrates session tokens."
            ),
        ))

    # ── NetForge SMB signing disabled/not enforced → ADForge NTLM relay ─
    if framework in ("netforge",) and (
        "smb signing" in title or "smb relay" in title
    ) and any(kw in title for kw in (
        "disabled", "not enforced", "not required", "not configured", "missing"
    )):
        chains.append(ChainAction(
            chain_type=ChainType.SMB_SIGNING_TO_RELAY,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="adforge",
            target_module="ntlm_relay",
            target=target,
            rationale=(
                "SMB signing disabled → NTLM relay to capture domain credentials. "
                "Relay NTLM authentication to achieve domain user access."
            ),
        ))

    # ── NetForge host compromise → Forge C2 beacon deploy ────────────
    if framework in ("netforge", "webforge") and any(
        kw in title for kw in ("shell", "rce", "remote code execution", "command injection")
    ):
        chains.append(ChainAction(
            chain_type=ChainType.HOST_COMPROMISE_TO_C2,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="forge_c2",
            target_module="beacon_deploy",
            target=target,
            rationale=(
                "Host compromised → deploy C2 beacon for persistent access. "
                "Use RCE to stage and execute beacon implant."
            ),
        ))

    # ── ADForge domain creds → NetForge lateral movement ─────────────
    if framework in ("adforge",) and any(
        kw in title for kw in ("credential", "password", "ntlm", "kerberoast",
                               "as-rep", "dcsync", "golden ticket")
    ):
        chains.append(ChainAction(
            chain_type=ChainType.DOMAIN_CREDS_TO_LATERAL,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="netforge",
            target_module="lateral_smb",
            target=target,
            rationale=(
                "Domain credentials obtained → lateral movement via SMB/WMI/WinRM. "
                "Use captured domain creds to pivot across the network."
            ),
        ))

    # ── WebForge SSRF → NetForge internal network recon ──────────────
    if framework in ("webforge",) and "ssrf" in title:
        chains.append(ChainAction(
            chain_type=ChainType.SSRF_TO_INTERNAL_RECON,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="netforge",
            target_module="port_scanner",
            target=target,
            rationale=(
                "SSRF confirmed → pivot to scan internal network via SSRF. "
                "Use SSRF as proxy to discover internal services."
            ),
            auto_execute=True,  # Recon is safe
        ))

    # ── WebForge file upload → web shell → C2 beacon ─────────────────
    if framework in ("webforge",) and ("file upload" in title or "upload bypass" in title):
        chains.append(ChainAction(
            chain_type=ChainType.UPLOAD_TO_WEBSHELL,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="webforge",
            target_module="webshell_deploy",
            target=target,
            rationale=(
                "File upload vuln → deploy web shell → C2 beacon. "
                "Upload PHP/ASPX web shell for persistent RCE."
            ),
        ))

    # ── ADForge ADCS ESC → certificate forgery → domain admin ────────
    if framework in ("adforge",) and any(
        kw in title
        for kw in ("esc1", "esc2", "esc3", "esc4", "esc6", "esc7", "esc8",
                   "esc9", "esc10", "esc11", "esc13", "esc14",
                   "adcs", "certificate template", "certifried")
    ):
        chains.append(ChainAction(
            chain_type=ChainType.ADCS_ESC_TO_DOMAIN_ADMIN,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="adforge",
            target_module="dcsync",
            target=target,
            rationale=(
                "ADCS misconfiguration → forge certificate as domain admin → DCSync. "
                "Request certificate with SAN for domain admin, authenticate, then dump credentials."
            ),
        ))

    # ── Zerologon → instant domain compromise ────────────────────────
    if framework in ("adforge", "netforge") and "zerologon" in title:
        chains.append(ChainAction(
            chain_type=ChainType.ZEROLOGON_TO_DOMAIN_COMPROMISE,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="adforge",
            target_module="dcsync",
            target=target,
            rationale=(
                "Zerologon (CVE-2020-1472) detected → reset DC machine account password → "
                "DCSync all domain hashes. Instant full domain compromise."
            ),
        ))

    return chains


# ══════════════════════════════════════════════════════════════════════
# ENGAGEMENT BUS (SINGLETON)
# ══════════════════════════════════════════════════════════════════════

class EngagementBus:
    """Cross-framework finding exchange and chain orchestration.

    Singleton pattern: use EngagementBus.get_instance() to get the
    shared instance across all frameworks.

    Usage::

        bus = EngagementBus.get_instance()

        # Publish a finding from webforge
        await bus.publish("webforge", finding_dict)

        # Subscribe to all findings from any framework
        bus.subscribe(my_callback)

        # Get intel package for the planner
        intel = bus.get_intel()

        # Get all credentials found so far
        creds = bus.get_credentials()
    """

    _instance: EngagementBus | None = None
    _instance_lock = threading.Lock()

    def __init__(
        self,
        db_path: str | None = None,
        tenant_id: str = "default",
        engagement_id: str = "default-engagement",
        run_id: str = "",
        brain: Any | None = None,
        planner: Any | None = None,
        event_bus: Any | None = None,
        canonical_advisory_sink: CanonicalAdvisorySink | None = None,
        plan_trigger_threshold: int = 5,
    ) -> None:
        """Initialize the engagement bus.

        Args:
            db_path:    Explicit legacy compatibility database path. Without
                        one, the advisory bus is memory-only and cannot leave
                        an ordinary side database in the working directory.
            run_id:     Exact canonical run binding required for dashboard
                        event projection. Events are suppressed when absent.
            brain:      ForgeBrain instance for auto-analysis.
            planner:    Legacy AttackPlanner compatibility instance; it is not
                        invoked by finding input or the inert auto-plan hook.
            event_bus:  Dashboard EventBus for real-time push.
            canonical_advisory_sink: Callable receiving one canonical advisory
                                    record.  A chain is projected to the
                                    legacy store/event only after this sink
                                    explicitly accepts it and returns a
                                    canonical advisory/node object or mapping
                                    with a safe non-empty ``id``.
            plan_trigger_threshold: Retained advisory-notification threshold;
                                    it never invokes the planner.
        """
        self._db_path: str = db_path or os.environ.get(
            "FORGE_ENGAGEMENT_DB", ""
        ) or ":memory:"
        self._tenant_id = _scope_id(tenant_id, "tenant_id")
        self._engagement_id = _scope_id(engagement_id, "engagement_id")
        requested_run = str(
            run_id or getattr(event_bus, "run_id", "") or ""
        ).strip()
        self._run_id = (
            _scope_id(requested_run, "run_id") if requested_run else ""
        )
        if brain is not None and (
            str(getattr(brain, "_tenant_id", self._tenant_id)) != self._tenant_id
            or str(getattr(brain, "_engagement_id", self._engagement_id))
            != self._engagement_id
        ):
            raise ValueError("ForgeBrain scope does not match EngagementBus")
        planner_brain = getattr(planner, "brain", None)
        if planner_brain is not None and (
            str(getattr(planner_brain, "_tenant_id", "")) != self._tenant_id
            or str(getattr(planner_brain, "_engagement_id", ""))
            != self._engagement_id
        ):
            raise ValueError("planner scope does not match EngagementBus")
        self._store = _FindingStore(
            self._db_path,
            tenant_id=self._tenant_id,
            engagement_id=self._engagement_id,
        )
        self._brain = brain
        self._planner = planner
        self._event_bus = event_bus
        self._canonical_advisory_sink = canonical_advisory_sink
        self._plan_threshold = plan_trigger_threshold

        # Subscriber lists
        self._sync_subscribers: list[FindingSubscriber] = []
        self._async_subscribers: list[AsyncFindingSubscriber] = []
        self._lock = threading.Lock()

        # Counters
        self._findings_since_plan = 0
        self._total_published = 0
        self._total_chains_triggered = 0

        log.info(
            "EngagementBus initialized (db=%s, brain=%s, planner=%s, event_bus=%s)",
            self._db_path,
            "available" if brain and getattr(brain, "available", False) else "none",
            "yes" if planner else "none",
            "yes" if event_bus else "none",
        )

    @classmethod
    def get_instance(cls, **kwargs: Any) -> EngagementBus:
        """Get or create the singleton instance.

        Args:
            **kwargs: Passed to __init__ only on first creation.

        Returns:
            The shared EngagementBus instance.
        """
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(**kwargs)
            else:
                requested_tenant = str(
                    kwargs.get("tenant_id", cls._instance._tenant_id)
                )
                requested_engagement = str(
                    kwargs.get("engagement_id", cls._instance._engagement_id)
                )
                requested_run = str(
                    kwargs.get("run_id")
                    or getattr(kwargs.get("event_bus"), "run_id", "")
                    or cls._instance._run_id
                )
                if (
                    requested_tenant != cls._instance._tenant_id
                    or requested_engagement != cls._instance._engagement_id
                    or requested_run != cls._instance._run_id
                ):
                    raise ValueError("EngagementBus singleton scope mismatch")
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (for testing)."""
        with cls._instance_lock:
            if cls._instance is not None:
                cls._instance._store.close()
                cls._instance = None

    # ── Configuration ─────────────────────────────────────────────────

    def set_brain(self, brain: Any) -> None:
        """Set or replace the ForgeBrain instance."""
        if (
            str(getattr(brain, "_tenant_id", "")) != self._tenant_id
            or str(getattr(brain, "_engagement_id", "")) != self._engagement_id
        ):
            raise ValueError("ForgeBrain scope does not match EngagementBus")
        self._brain = brain

    def set_planner(self, planner: Any) -> None:
        """Set or replace the AttackPlanner instance."""
        planner_brain = getattr(planner, "brain", None)
        if planner_brain is None or (
            str(getattr(planner_brain, "_tenant_id", "")) != self._tenant_id
            or str(getattr(planner_brain, "_engagement_id", ""))
            != self._engagement_id
        ):
            raise ValueError("planner scope does not match EngagementBus")
        self._planner = planner

    @property
    def planner(self) -> Any | None:
        """Return the attached planner for read-only integration consumers."""
        return self._planner

    def set_event_bus(self, event_bus: Any, *, run_id: str = "") -> None:
        """Set the dashboard EventBus only with an exact stable run binding."""
        requested_run = str(run_id or getattr(event_bus, "run_id", "") or "").strip()
        if not requested_run:
            raise ValueError("EngagementBus event run binding is required")
        requested_run = _scope_id(requested_run, "run_id")
        if self._run_id and requested_run != self._run_id:
            raise ValueError("EngagementBus event run binding mismatch")
        self._run_id = requested_run
        self._event_bus = event_bus

    # ── Publishing ────────────────────────────────────────────────────

    async def publish(self, framework: str, finding: dict[str, Any]) -> str:
        """Publish a finding from any framework.

        Projects to the ordinary persisted-evidence boundary, stores in SQLite,
        notifies subscribers, and detects canonically persisted chain advice.
        Finding input never invokes brain analysis or planning.

        Args:
            framework: Source framework (netforge/webforge/adforge/aiforge).
            finding:   Finding dict from a canonical or compatibility producer.

        Returns:
            The finding ID.
        """
        # Keep the producer's canonical lineage fields beside the ordinary
        # projection.  ordinary_finding_projection intentionally strips
        # adapter-only fields, while the chain sink requires a canonical
        # finding or observation identity.
        source_payload = dict(finding)
        normalized = normalise_finding(source_payload)
        projected = ordinary_finding_projection(normalized)
        verification = normalized.get("verification")
        if isinstance(verification, dict):
            # Verification remains workflow metadata, but caller-controlled
            # probe/evidence structures do not cross this ordinary boundary.
            projected["verification"] = {
                "confidence": normalized["confidence"],
            }
        finding = normalise_finding(projected)

        # Store
        finding_id, finding_created = self._store.store_finding_once(
            framework, finding
        )
        finding["id"] = finding_id

        if not finding_created:
            return finding_id

        with self._lock:
            self._total_published += 1
            self._findings_since_plan += 1
            sync_subs = list(self._sync_subscribers)
            async_subs = list(self._async_subscribers)

        log.debug(
            "Finding published: %s [%s] %s (%s)",
            finding_id, framework,
            finding.get("title", "?"), finding.get("severity", "?"),
        )

        # Emit to dashboard EventBus
        self._emit_event("finding_new", {
            "id": finding_id,
            "framework": framework,
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "target": finding.get("target", ""),
            "tenant_id": self._tenant_id,
            "engagement_id": self._engagement_id,
        })

        # Notify sync subscribers (lists already captured under lock above)

        for sync_cb in sync_subs:
            try:
                sync_cb(framework, finding)
            except Exception as exc:
                log.error("Sync subscriber error: %s", redact_text(str(exc)))

        for async_cb in async_subs:
            try:
                await async_cb(framework, finding)
            except Exception as exc:
                log.error("Async subscriber error: %s", redact_text(str(exc)))

        # Detect and trigger chains
        chains = _detect_chains(framework, finding)
        for chain in chains:
            canonical_result = await self._persist_canonical_chain_advisory(
                chain,
                source_payload,
            )
            if canonical_result is None:
                # Missing/rejected canonical persistence is a hard stop for
                # this chain.  No compatibility row or chain event may imply
                # that an advisory was accepted.
                continue
            _chain_id, created = self._store.store_chain_action(chain)
            if not created:
                continue
            self._total_chains_triggered += 1
            log.info(
                "Chain triggered: %s → %s/%s (from %s)",
                chain.chain_type.value,
                chain.target_framework, chain.target_module,
                finding_id,
            )
            self._emit_event("chain_action_new", {
                "chain_type": chain.chain_type.value,
                "source_finding": finding_id,
                "source_framework": framework,
                "target_framework": chain.target_framework,
                "target_module": chain.target_module,
                "rationale": chain.rationale,
                "auto_execute": False,
                "execution_state": "advisory",
                "canonical_advisory_id": canonical_result,
                "tenant_id": self._tenant_id,
                "engagement_id": self._engagement_id,
            })

        # Finding/event input cannot schedule a model request or planner.  An
        # operator may explicitly request advisory analysis through a caller
        # that applies the model projection and canonical tenant context.
        if (
            self._planner
            and self._findings_since_plan >= self._plan_threshold
        ):
            log.info(
                "Planner advisory threshold reached; explicit analysis required"
            )

        return finding_id

    @staticmethod
    def _canonical_source_ids(
        finding: dict[str, Any],
    ) -> tuple[str, str, str]:
        """Extract one source identity for canonical sink validation.

        Compatibility findings commonly use ``id`` for a local/legacy row.
        Explicit canonical lineage fields (or persisted canonical evidence)
        take precedence; a safe producer id is passed to the injected
        canonical sink for authoritative existence/tenant validation.  The
        returned source kind is ``finding`` or ``observation`` and is empty
        when no safe identity is available.
        """

        def safe(value: Any) -> str:
            rendered = str(value or "").strip()
            if (
                not rendered
                or len(rendered) > 200
                or any(character.isspace() for character in rendered)
                or is_sensitive_identifier(rendered)
            ):
                return ""
            return rendered

        def first(mapping: Any, names: tuple[str, ...]) -> str:
            if not isinstance(mapping, Mapping):
                return ""
            for name in names:
                value = safe(mapping.get(name))
                if value:
                    return value
            return ""

        canonical_lineage = finding.get("canonical_lineage")
        canonical_finding = first(
            finding,
            ("canonical_finding_id", "source_finding_id", "finding_id"),
        ) or first(
            canonical_lineage,
            ("finding_id", "canonical_finding_id", "source_finding_id"),
        )
        canonical_finding = canonical_finding or safe(finding.get("id"))
        canonical_observation = first(
            finding,
            (
                "canonical_observation_id",
                "source_observation_id",
                "observation_id",
            ),
        ) or first(
            canonical_lineage,
            (
                "observation_id",
                "canonical_observation_id",
                "source_observation_id",
            ),
        )

        evidence = finding.get("evidence")
        if isinstance(evidence, Mapping) and evidence.get("state") == "persisted":
            canonical_finding = canonical_finding or safe(evidence.get("finding_id"))
            observations = evidence.get("observations")
            if isinstance(observations, list) and observations:
                first_observation = observations[0]
                canonical_observation = canonical_observation or first(
                    first_observation,
                    ("observation_id", "canonical_observation_id"),
                )

        # Canonical advisory plans accept exactly one source kind.  Prefer the
        # finding identity when both are present and retain the observation as
        # descriptive metadata below.
        if canonical_finding:
            return canonical_finding, canonical_observation, "finding"
        if canonical_observation:
            return "", canonical_observation, "observation"
        return "", "", ""

    def _canonical_chain_record(
        self,
        chain: ChainAction,
        source_payload: dict[str, Any],
    ) -> dict[str, Any] | None:
        source_finding, source_observation, source_kind = self._canonical_source_ids(
            source_payload
        )
        if not source_kind:
            return None
        target = redact_text(str(chain.target or ""))[:2_000]
        # The canonical advisory service accepts exactly one source lineage
        # kind.  Keep the non-selected identity only in descriptive metadata.
        selected_finding = source_finding if source_kind == "finding" else ""
        selected_observation = (
            source_observation if source_kind == "observation" else ""
        )
        identity = {
            "tenant_id": self._tenant_id,
            "engagement_id": self._engagement_id,
            "source_finding_id": selected_finding,
            "source_observation_id": selected_observation,
            "chain_type": chain.chain_type.value,
            "source_framework": chain.source_framework,
            "target_framework": chain.target_framework,
            "target_module": chain.target_module,
            "target": target,
        }
        idempotency_key = "chain-advisory-" + hashlib.sha256(
            json.dumps(
                identity,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()[:32]
        # Keep both the canonical-service fields and an explicit metadata
        # envelope so downstream adapters cannot confuse source and target
        # framework/module values.
        return {
            **identity,
            "source_kind": source_kind,
            "framework": chain.target_framework,
            "module": chain.target_module,
            "capability_id": f"{chain.target_framework}:{chain.target_module}",
            "capability_version": str(
                source_payload.get("capability_version") or ""
            )[:100],
            "next_module": chain.target_module,
            "description": redact_text(str(chain.rationale or ""))[:4_000],
            "idempotency_key": idempotency_key,
            "metadata": {
                "tenant_id": self._tenant_id,
                "engagement_id": self._engagement_id,
                "source_finding_id": source_finding,
                "source_observation_id": source_observation,
                "source_framework": chain.source_framework,
                "target_framework": chain.target_framework,
                "target_module": chain.target_module,
                "target": target,
                "idempotency_key": idempotency_key,
                "advisory": True,
            },
        }

    @staticmethod
    def _sink_result_id(result: Any) -> str:
        if isinstance(result, Mapping):
            value = result.get("id") or result.get("advisory_id")
        else:
            value = getattr(result, "id", "")
        rendered = str(value or "").strip()
        return (
            rendered[:200]
            if rendered
            and len(rendered) <= 200
            and not any(c.isspace() for c in rendered)
            and not is_sensitive_identifier(rendered)
            else ""
        )

    @classmethod
    def _sink_accepted(cls, result: Any) -> bool:
        """Require explicit success and reject negative status projections."""
        if result is None:
            return False
        if isinstance(result, bool):
            return result
        if isinstance(result, Mapping):
            if "accepted" in result:
                return result["accepted"] is True
            status = str(result.get("state") or result.get("status") or "").lower()
            return status not in {"rejected", "denied", "failed"}
        status = str(
            getattr(result, "state", "") or getattr(result, "status", "")
        ).lower()
        return status not in {"rejected", "denied", "failed"}

    async def _persist_canonical_chain_advisory(
        self,
        chain: ChainAction,
        source_payload: dict[str, Any],
    ) -> str | None:
        """Persist canonical advisory state before legacy chain projection/event."""
        sink = self._canonical_advisory_sink
        if sink is None:
            log.warning(
                "Canonical advisory sink unavailable; suppressing chain %s",
                chain.chain_type.value,
            )
            return None
        record = self._canonical_chain_record(chain, source_payload)
        if record is None:
            log.warning(
                "Canonical source lineage unavailable; suppressing chain %s",
                chain.chain_type.value,
            )
            return None
        try:
            result = sink(record)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            log.warning(
                "Canonical advisory sink rejected chain %s: %s",
                chain.chain_type.value,
                redact_text(str(exc)),
            )
            return None
        if not self._sink_accepted(result):
            log.warning(
                "Canonical advisory sink rejected chain %s",
                chain.chain_type.value,
            )
            return None
        result_id = self._sink_result_id(result)
        if not result_id:
            log.warning(
                "Canonical advisory sink returned no advisory identity for %s",
                chain.chain_type.value,
            )
            return None
        return result_id

    async def publish_credential(
        self, framework: str, cred: dict[str, Any]
    ) -> str:
        """Publish only a protected reference or a non-secret purge marker.

        Args:
            framework: Source framework.
            cred:      Mapping containing an opaque ``credential_reference``.
                       Raw secret fields are discarded and never persisted.

        Returns:
            The credential ID.
        """
        cred_id = self._store.store_credential(framework, cred)
        stored = next(
            (item for item in self._store.get_all_credentials() if item["id"] == cred_id),
            {"credential_state": "purged_legacy", "credential_reference": None},
        )
        log.debug("Credential boundary record published: %s [%s]", cred_id, framework)

        self._emit_event("credential_found", {
            "id": cred_id,
            "framework": framework,
            "credential_reference": stored.get("credential_reference"),
            "credential_state": stored.get("credential_state"),
            "tenant_id": self._tenant_id,
            "engagement_id": self._engagement_id,
        })

        return cred_id

    # ── Session Import ────────────────────────────────────────────────

    async def load_engagement_session(
        self,
        session: Path | dict[str, Any],
        *,
        engagement_name: str = "",
    ) -> dict[str, Any]:
        """Load a completed engagement session JSON into the forge brain.

        Accepts the nbc.json / edc.json export format. Publishes all
        findings and credentials via the normal pipeline (chain detection,
        brain analysis, event bus). Also seeds ForgeBrain.memory with
        lessons_learned, false_negatives, evasion techniques, payloads,
        error signatures, and attack chain summaries so future AI calls
        have full engagement context.

        Args:
            session:         Path to session JSON file, or a pre-loaded dict.
            engagement_name: Override for the target label (used if
                             export_metadata.target_summary is absent).

        Returns:
            Summary dict with keys: target, findings_loaded,
            credentials_loaded, brain_events_seeded.
        """
        if isinstance(session, Path):
            import json as _json
            data: dict[str, Any] = _json.loads(session.read_text())
        else:
            data = session

        meta = data.get("export_metadata", {})
        target_summary = redact_text(
            str(meta.get("target_summary", "") or engagement_name or "imported session")
        )[:2000]

        findings_loaded = 0
        credentials_loaded = 0
        brain_events = 0

        # 1. Publish all findings through the normal pipeline
        for finding in data.get("findings", []):
            framework = finding.get("framework", "manual")
            await self.publish(framework, dict(finding))
            findings_loaded += 1

        # 2. Publish credentials (if any)
        for cred in data.get("credentials", []):
            framework = cred.get("framework", "manual")
            await self.publish_credential(framework, dict(cred))
            credentials_loaded += 1

        # 3. Seed only the allowlisted, tenant-scoped model projection.  Raw
        # payload/evasion/error/session structures never enter memory.
        if self._brain and hasattr(self._brain, "memory"):
            mem = self._brain.memory

            if data.get("target_context"):
                mem.add(
                    "target_context",
                    "import",
                    project_model_input(
                        {"target": target_summary, "event_type": "target_context"},
                        tenant_id=self._tenant_id,
                        engagement_id=self._engagement_id,
                    ),
                )
                brain_events += 1

            for lesson in data.get("lessons_learned", []):
                mem.add(
                    "lesson",
                    "import",
                    project_model_input(
                        {
                            "event_type": "lesson",
                            "title": lesson.get("title") or lesson.get("name") or "imported lesson",
                            "description": lesson.get("description") or lesson.get("lesson") or "",
                        },
                        tenant_id=self._tenant_id,
                        engagement_id=self._engagement_id,
                    ),
                )
                brain_events += 1

            for fn in data.get("false_negatives_detected", []):
                mem.add(
                    "fn_hint",
                    "import",
                    project_model_input(
                        {
                            "event_type": "fn_hint",
                            "title": fn.get("title") or fn.get("likely_vuln") or "false-negative hint",
                            "reason_code": fn.get("reason_code") or "imported_hint",
                        },
                        tenant_id=self._tenant_id,
                        engagement_id=self._engagement_id,
                    ),
                )
                brain_events += 1

            for ac in data.get("attack_chains", []):
                mem.add(
                    "attack_chain",
                    "import",
                    project_model_input(
                        {
                            "event_type": "attack_chain",
                            "title": ac.get("chain_type") or "advisory chain",
                            "rationale": ac.get("rationale") or "",
                            "status": "advisory",
                        },
                        tenant_id=self._tenant_id,
                        engagement_id=self._engagement_id,
                    ),
                )
                brain_events += 1

        log.info(
            "Session loaded: %d findings, %d credentials, %d brain events (target=%s)",
            findings_loaded, credentials_loaded, brain_events, target_summary,
        )

        return {
            "target": target_summary,
            "findings_loaded": findings_loaded,
            "credentials_loaded": credentials_loaded,
            "brain_events_seeded": brain_events,
        }

    # ── Subscribing ───────────────────────────────────────────────────

    def subscribe(self, callback: FindingSubscriber) -> None:
        """Register a sync subscriber for all findings.

        Args:
            callback: Function(framework: str, finding: dict) called
                      on each new published finding.
        """
        with self._lock:
            self._sync_subscribers.append(callback)

    def async_subscribe(self, callback: AsyncFindingSubscriber) -> None:
        """Register an async subscriber for all findings.

        Args:
            callback: Async function(framework: str, finding: dict).
        """
        with self._lock:
            self._async_subscribers.append(callback)

    def unsubscribe(self, callback: FindingSubscriber) -> None:
        """Remove a sync subscriber."""
        with self._lock:
            if callback in self._sync_subscribers:
                self._sync_subscribers.remove(callback)

    def async_unsubscribe(self, callback: AsyncFindingSubscriber) -> None:
        """Remove an async subscriber."""
        with self._lock:
            if callback in self._async_subscribers:
                self._async_subscribers.remove(callback)

    # ── Querying ──────────────────────────────────────────────────────

    def get_all_findings(self) -> list[dict[str, Any]]:
        """Get all findings across all frameworks.

        Returns:
            List of finding dicts, newest first.
        """
        return self._store.get_all_findings()

    def get_findings_by_framework(self, framework: str) -> list[dict[str, Any]]:
        """Get findings for a specific framework."""
        return self._store.get_findings_by_framework(framework)

    def get_credentials(self) -> list[dict[str, Any]]:
        """Get all credentials found across all frameworks.

        Returns:
            List of credential dicts, newest first.
        """
        return self._store.get_all_credentials()

    def get_chain_actions(self, executed: bool | None = None) -> list[dict[str, Any]]:
        """Get cross-framework chain actions.

        Args:
            executed: Filter by execution status. None = all.
        """
        return self._store.get_chain_actions(executed)

    def get_intel(self) -> EngagementIntelligence:
        """Get full engagement intelligence for the planner.

        Aggregates all findings, credentials, and chain actions into
        a single EngagementIntelligence struct.

        Returns:
            EngagementIntelligence with all cross-framework data.
        """
        findings = self._store.get_all_findings()
        creds = self._store.get_all_credentials()
        chains = self._store.get_chain_actions()

        # Classify findings by type
        shells = [
            f for f in findings
            if any(kw in (f.get("title") or "").lower()
                   for kw in ("shell", "rce", "command execution"))
        ]
        persistence = [
            f for f in findings
            if any(kw in (f.get("title") or "").lower()
                   for kw in ("persistence", "backdoor", "cron", "scheduled task"))
        ]
        lateral = [
            f for f in findings
            if any(kw in (f.get("title") or "").lower()
                   for kw in ("lateral", "pivot", "pass-the-hash", "relay"))
        ]

        frameworks = list(set(f.get("framework", "") for f in findings) - {""})

        return EngagementIntelligence(
            findings=findings,
            credentials=creds,
            shells=shells,
            persistence=persistence,
            lateral_moves=lateral,
            chain_actions=chains,
            frameworks_active=sorted(frameworks),
            total_findings=len(findings),
            severity_counts=self._store.severity_counts(),
        )

    # ── Stats ─────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict[str, Any]:
        """Runtime stats for the engagement bus."""
        return {
            "total_published": self._total_published,
            "total_chains_triggered": self._total_chains_triggered,
            "findings_in_store": self._store.count_findings(),
            "severity_counts": self._store.severity_counts(),
            "findings_since_plan": self._findings_since_plan,
            "sync_subscribers": len(self._sync_subscribers),
            "async_subscribers": len(self._async_subscribers),
            "brain_available": bool(
                self._brain and getattr(self._brain, "available", False)
            ),
            "planner_attached": self._planner is not None,
            "event_bus_attached": self._event_bus is not None,
        }

    # ── Internal Helpers ──────────────────────────────────────────────

    def _emit_event(self, event_type_str: str, data: dict[str, Any]) -> None:
        """Emit an event to the dashboard EventBus if attached."""
        if not self._event_bus:
            return
        if not self._run_id:
            log.warning(
                "EngagementBus event suppressed: canonical run binding unavailable"
            )
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            projected = redact_value(dict(data))
            if not isinstance(projected, dict):
                projected = {}
            projected["tenant_id"] = self._tenant_id
            projected["engagement_id"] = self._engagement_id
            projected["run_id"] = self._run_id
            # Map string to EventType enum
            type_map = {
                "finding_new": EventType.FINDING_NEW,
                "credential_found": EventType.CREDENTIAL_FOUND,
                "brain_verdict": EventType.BRAIN_VERDICT,
                "chain_action_new": EventType.CHAIN_ACTION_NEW,
            }
            etype = type_map.get(event_type_str)
            if etype:
                self._event_bus.emit(Event(
                    event_type=etype,
                    data=projected,
                    source="engagement_bus",
                    run_id=self._run_id,
                ))
            else:
                self._event_bus.emit(Event(
                    event_type=EventType.STATE_SNAPSHOT,
                    data={"sub_type": event_type_str, **projected},
                    source="engagement_bus",
                    run_id=self._run_id,
                ))
        except Exception as exc:
            log.debug("EventBus emit failed (non-critical): %s", exc)

    async def _analyze_with_brain(
        self, finding_id: str, finding: dict[str, Any]
    ) -> None:
        """Analyze a finding with ForgeBrain and store the verdict."""
        try:
            brain = self._brain
            if brain is None:
                return
            del finding
            projected_verdict = "NEEDS_VERIFICATION"
            projected_confidence = "LOW"
            safe_reasoning = (
                "Advisory analysis only; canonical observation, finding, proof, "
                "and evidence lineage are required."
            )
            self._store.update_brain_verdict(
                finding_id,
                projected_verdict,
                projected_confidence,
                safe_reasoning,
            )
            log.debug(
                "Brain verdict for %s: %s (%s)",
                finding_id, projected_verdict, projected_confidence,
            )
            self._emit_event("brain_verdict", {
                "finding_id": finding_id,
                "verdict": projected_verdict,
                "confidence": projected_confidence,
                "reasoning": safe_reasoning[:200],
                "tenant_id": self._tenant_id,
                "engagement_id": self._engagement_id,
            })
        except Exception as exc:
            log.warning(
                "Brain analysis failed for %s: %s",
                finding_id,
                redact_text(str(exc)),
            )

    async def _auto_plan(self) -> None:
        """Remain inert until planner output has canonical plan/node custody."""
        return

    def close(self) -> None:
        """Close the engagement bus and its store."""
        self._store.close()


# ══════════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════════

class TestEngagementBus:
    """Unit tests for EngagementBus."""

    @staticmethod
    def _make_bus(tmp_path: str = ":memory:") -> EngagementBus:
        """Create a test bus with in-memory DB."""
        EngagementBus.reset_instance()
        return EngagementBus(db_path=tmp_path)

    def test_store_and_retrieve_finding(self) -> None:
        """Store findings while the legacy auto-plan hook remains inert."""
        calls = 0

        class RecordingPlanner:
            async def plan_next(self, *_args: Any, **_kwargs: Any) -> Any:
                nonlocal calls
                calls += 1
                return type("EmptyPlan", (), {"actions": []})()

        bus = self._make_bus()
        bus._planner = RecordingPlanner()
        try:
            asyncio.run(bus._auto_plan())
            assert calls == 0
            store = bus._store
            fid = store.store_finding("webforge", {
                "id": "test-1",
                "title": "SQLi in login",
                "severity": "Critical",
                "target": "https://example.com",
                "module": "sqli_scanner",
            })
            assert fid == "test-1"
            findings = store.get_all_findings()
            assert len(findings) >= 1
            assert findings[0]["title"] == "SQLi in login"
        finally:
            bus.close()

    def test_store_and_retrieve_credential(self) -> None:
        bus = self._make_bus()
        store = bus._store
        cid = store.store_credential("netforge", {
            "credential_reference": "cred:fixture:opaque-reference",
        })
        creds = store.get_all_credentials()
        assert len(creds) >= 1
        assert creds[0]["credential_state"] == "protected_reference"
        assert creds[0]["credential_reference"] == "cred:fixture:opaque-reference"
        bus.close()

    def test_severity_counts(self) -> None:
        bus = self._make_bus()
        store = bus._store
        store.store_finding("webforge", {"title": "SQLi", "severity": "Critical"})
        store.store_finding("webforge", {"title": "XSS", "severity": "High"})
        store.store_finding("netforge", {"title": "Info", "severity": "Critical"})
        counts = store.severity_counts()
        assert counts.get("Critical", 0) == 2
        assert counts.get("High", 0) == 1
        bus.close()

    def test_chain_detection_sqli(self) -> None:
        finding = {"id": "f1", "title": "SQL Injection in login", "target": "https://app.com"}
        chains = _detect_chains("webforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.SQLI_TO_CRED_SPRAY in types

    def test_chain_detection_xss(self) -> None:
        finding = {"id": "f2", "title": "Stored XSS in comments", "target": "https://app.com"}
        chains = _detect_chains("webforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.XSS_TO_SESSION_HIJACK in types

    def test_chain_detection_smb(self) -> None:
        finding = {"id": "f3", "title": "SMB Signing Disabled on DC", "target": "10.0.0.1"}
        chains = _detect_chains("netforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.SMB_SIGNING_TO_RELAY in types

    def test_chain_detection_rce(self) -> None:
        finding = {"id": "f4", "title": "Remote Code Execution via deserialization", "target": "10.0.0.5"}
        chains = _detect_chains("netforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.HOST_COMPROMISE_TO_C2 in types

    def test_chain_detection_ssrf(self) -> None:
        finding = {"id": "f5", "title": "SSRF via image proxy", "target": "https://app.com/proxy"}
        chains = _detect_chains("webforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.SSRF_TO_INTERNAL_RECON in types

    def test_chain_detection_upload(self) -> None:
        finding = {"id": "f6", "title": "Unrestricted file upload", "target": "https://app.com"}
        chains = _detect_chains("webforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.UPLOAD_TO_WEBSHELL in types

    def test_chain_detection_ad_creds(self) -> None:
        finding = {"id": "f7", "title": "Kerberoastable service account", "target": "dc.corp.local"}
        chains = _detect_chains("adforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.DOMAIN_CREDS_TO_LATERAL in types

    def test_chain_detection_smb_not_enforced(self) -> None:
        finding = {"id": "f3b", "title": "SMB Signing Not Enforced on 10.0.0.5", "target": "10.0.0.5"}
        chains = _detect_chains("netforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.SMB_SIGNING_TO_RELAY in types

    def test_chain_detection_smb_not_required(self) -> None:
        finding = {"id": "f3c", "title": "SMB Signing Not Required — 10.0.0.10", "target": "10.0.0.10"}
        chains = _detect_chains("netforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.SMB_SIGNING_TO_RELAY in types

    def test_chain_detection_adcs_esc(self) -> None:
        finding = {"id": "f8", "title": "ADCS ESC1 — Vulnerable Certificate Template", "target": "dc.corp.local"}
        chains = _detect_chains("adforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.ADCS_ESC_TO_DOMAIN_ADMIN in types

    def test_chain_detection_zerologon(self) -> None:
        finding = {"id": "f9", "title": "Zerologon (CVE-2020-1472) — DC Vulnerable", "target": "10.0.0.5"}
        chains = _detect_chains("adforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.ZEROLOGON_TO_DOMAIN_COMPROMISE in types

    def test_publish_raw_domain_credential_is_purged_and_does_not_chain(self) -> None:
        import asyncio
        bus = self._make_bus()
        cred = {
            "host": "dc.corp.local",
            "domain": "corp.local",
            "username": "svc_account",
            "password": "Password1!",
        }
        asyncio.run(bus.publish_credential("adforge", cred))
        chains = bus.get_chain_actions()
        assert chains == []
        assert bus.get_credentials()[0]["credential_state"] == "purged_legacy"
        bus.close()

    def test_publish_credential_no_domain_no_chain(self) -> None:
        import asyncio
        bus = self._make_bus()
        cred = {"host": "10.0.0.1", "username": "admin", "password": "pass123"}
        asyncio.run(bus.publish_credential("netforge", cred))
        chains = bus.get_chain_actions()
        assert len(chains) == 0
        bus.close()

    def test_async_unsubscribe(self) -> None:
        bus = self._make_bus()
        received: list = []

        async def cb(fw: str, f: dict) -> None:
            received.append(fw)

        bus.async_subscribe(cb)
        assert len(bus._async_subscribers) == 1
        bus.async_unsubscribe(cb)
        assert len(bus._async_subscribers) == 0
        bus.close()

    def test_no_chain_for_unrelated_finding(self) -> None:
        finding = {"id": "f99", "title": "Missing X-Frame-Options header", "target": "https://app.com"}
        chains = _detect_chains("webforge", finding)
        assert len(chains) == 0

    def test_publish_async(self) -> None:
        """Test that publish() works end-to-end."""
        import asyncio
        bus = self._make_bus()
        received: list[tuple[str, dict]] = []
        bus.subscribe(lambda fw, f: received.append((fw, f)))

        finding = {
            "title": "SQL Injection",
            "severity": "Critical",
            "target": "https://example.com",
        }
        fid = asyncio.run(bus.publish("webforge", finding))
        assert fid  # got an ID back
        assert len(received) == 1
        assert received[0][0] == "webforge"
        bus.close()

    def test_get_intel(self) -> None:
        bus = self._make_bus()
        store = bus._store
        store.store_finding("webforge", {
            "title": "SQL Injection", "severity": "Critical", "target": "https://app.com"
        })
        store.store_finding("netforge", {
            "title": "Shell access via RCE", "severity": "Critical", "target": "10.0.0.1"
        })
        store.store_credential("webforge", {
            "host": "db.local", "username": "admin", "password": "pass123"
        })

        intel = bus.get_intel()
        assert intel.total_findings == 2
        assert len(intel.credentials) == 1
        assert intel.credentials[0]["credential_state"] == "purged_legacy"
        assert len(intel.shells) >= 1  # RCE finding classified as shell
        assert "webforge" in intel.frameworks_active
        bus.close()

    def test_stats(self) -> None:
        bus = self._make_bus()
        stats = bus.stats
        assert stats["total_published"] == 0
        assert stats["brain_available"] is False
        bus.close()

    def test_brain_verdict_storage(self) -> None:
        bus = self._make_bus()
        store = bus._store
        store.store_finding("webforge", {
            "id": "bv-1", "title": "XSS", "severity": "High"
        })
        store.update_brain_verdict("bv-1", "TRUE_POSITIVE", "HIGH", "Strong evidence")
        findings = store.get_all_findings()
        f = next(f for f in findings if f["id"] == "bv-1")
        assert f["brain_verdict"] == "TRUE_POSITIVE"
        assert f["brain_confidence"] == "HIGH"
        bus.close()

    def test_singleton_pattern(self) -> None:
        EngagementBus.reset_instance()
        b1 = EngagementBus.get_instance(db_path=":memory:")
        b2 = EngagementBus.get_instance()
        assert b1 is b2
        EngagementBus.reset_instance()

    def test_engagement_intelligence_to_dict(self) -> None:
        intel = EngagementIntelligence(
            findings=[{"title": "test"}],
            total_findings=1,
            severity_counts={"Critical": 1},
        )
        d = intel.to_dict()
        assert d["total_findings"] == 1
        assert d["severity_counts"]["Critical"] == 1
