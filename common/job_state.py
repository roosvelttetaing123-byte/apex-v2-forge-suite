"""Transactional single-node job, attempt, lease, and event authority.

This module owns control-plane state only.  Observation/evidence bytes remain
owned by the canonical Task 101/102 stores; result submissions contain opaque
references and identities, never a second result store.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Protocol


TRANSITION_TABLE_VERSION = "forge-job-state-v1"


class JobState(str, Enum):
    PLANNED = "planned"
    PENDING_APPROVAL = "pending_approval"
    QUEUED = "queued"
    LEASED = "leased"
    RUNNING = "running"
    PAUSED = "paused"
    CANCELING = "canceling"
    CANCELED = "canceled"
    PARTIAL = "partial"
    FAILED = "failed"
    COMPLETED = "completed"
    EXPIRED = "expired"
    ORPHANED = "orphaned"

    # Compatibility aliases used by early Gate 0 callers.  They are aliases,
    # not additional persisted states.
    CREATED = PLANNED
    PENDING = PLANNED
    CANCEL_REQUESTED = CANCELING
    SUCCEEDED = COMPLETED


class AttemptState(str, Enum):
    LEASED = "leased"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    COMPLETED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELED = "canceled"
    ORPHANED = "orphaned"


class WorkState(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    TRUNCATED = "truncated"
    UNCOLLECTED = "uncollected"


TERMINAL_STATES = frozenset(
    {
        JobState.COMPLETED.value,
        JobState.PARTIAL.value,
        JobState.FAILED.value,
        JobState.CANCELED.value,
    }
)
ACTIVE_ATTEMPT_STATES = frozenset(
    {AttemptState.LEASED.value, AttemptState.RUNNING.value}
)


class JobStateError(RuntimeError):
    """Base class for durable state errors."""


class InvalidTransition(JobStateError, ValueError):
    """A caller attempted an illegal or stale transition."""


class LeaseError(JobStateError):
    """A lease is missing, expired, revoked, or owned by another worker."""


class LeaseUnavailable(LeaseError):
    """Another active attempt already owns a job."""


class IdempotencyConflict(JobStateError, ValueError):
    """An idempotency key was reused with different material parameters."""


class ProcessIdentityError(JobStateError, ValueError):
    """A PID-only or otherwise unsafe process identity was supplied."""


class TerminalStateError(InvalidTransition):
    """A terminal-state invariant prevents a requested transition."""


class ProcessSupervisor(Protocol):
    """Fakeable child-process boundary used by cancellation/reconciliation."""

    def is_alive(self, identity: "ProcessIdentity") -> bool: ...

    def terminate(self, identity: "ProcessIdentity") -> None: ...

    def kill(self, identity: "ProcessIdentity") -> None: ...


@dataclass(frozen=True)
class ProcessIdentity:
    """PID plus start/command identity; a PID alone is never sufficient."""

    pid: int
    start_token: str
    command_digest: str
    boot_id: str = ""

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid <= 0:
            raise ProcessIdentityError("a positive pid is required")
        if not self.start_token or "\x00" in self.start_token:
            raise ProcessIdentityError("a process start token is required")
        if len(self.command_digest) < 16:
            raise ProcessIdentityError("a command identity digest is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "start_token": self.start_token,
            "command_digest": self.command_digest,
            "boot_id": self.boot_id,
        }

    @classmethod
    def from_value(cls, value: "ProcessIdentity | Mapping[str, Any]") -> "ProcessIdentity":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise ProcessIdentityError("complete process identity is required")
        return cls(
            pid=value.get("pid"),  # type: ignore[arg-type]
            start_token=str(value.get("start_token") or ""),
            command_digest=str(value.get("command_digest") or ""),
            boot_id=str(value.get("boot_id") or ""),
        )


def process_identity(
    pid: int,
    *,
    start_token: str,
    command: str,
    boot_id: str = "",
) -> ProcessIdentity:
    """Construct an identity while retaining only a command digest."""

    return ProcessIdentity(
        pid=pid,
        start_token=start_token,
        boot_id=boot_id,
        command_digest=hashlib.sha256(command.encode("utf-8")).hexdigest(),
    )


_STATE_ALIASES = {
    "created": JobState.PLANNED.value,
    "pending": JobState.PLANNED.value,
    "cancel_requested": JobState.CANCELING.value,
    "succeeded": JobState.COMPLETED.value,
}

_TRANSITIONS: dict[str, frozenset[str]] = {
    JobState.PLANNED.value: frozenset(
        {
            JobState.PENDING_APPROVAL.value,
            JobState.QUEUED.value,
            JobState.PAUSED.value,
            JobState.CANCELING.value,
            JobState.CANCELED.value,
        }
    ),
    JobState.PENDING_APPROVAL.value: frozenset(
        {
            JobState.QUEUED.value,
            JobState.PAUSED.value,
            JobState.CANCELING.value,
            JobState.CANCELED.value,
        }
    ),
    JobState.QUEUED.value: frozenset(
        {
            JobState.LEASED.value,
            JobState.PAUSED.value,
            JobState.CANCELING.value,
            JobState.CANCELED.value,
        }
    ),
    JobState.LEASED.value: frozenset(
        {
            JobState.RUNNING.value,
            JobState.QUEUED.value,
            JobState.PAUSED.value,
            JobState.CANCELING.value,
            JobState.EXPIRED.value,
            JobState.ORPHANED.value,
            JobState.COMPLETED.value,
            JobState.PARTIAL.value,
            JobState.FAILED.value,
            JobState.QUEUED.value,
        }
    ),
    JobState.RUNNING.value: frozenset(
        {
            JobState.QUEUED.value,
            JobState.PAUSED.value,
            JobState.CANCELING.value,
            JobState.COMPLETED.value,
            JobState.PARTIAL.value,
            JobState.FAILED.value,
            JobState.EXPIRED.value,
            JobState.ORPHANED.value,
        }
    ),
    JobState.PAUSED.value: frozenset(
        {
            JobState.QUEUED.value,
            JobState.LEASED.value,
            JobState.RUNNING.value,
            JobState.CANCELING.value,
            JobState.CANCELED.value,
            JobState.COMPLETED.value,
            JobState.PARTIAL.value,
            JobState.FAILED.value,
            JobState.ORPHANED.value,
        }
    ),
    JobState.CANCELING.value: frozenset(
        {
            JobState.CANCELED.value,
            JobState.PARTIAL.value,
            JobState.FAILED.value,
            JobState.ORPHANED.value,
        }
    ),
    JobState.EXPIRED.value: frozenset(
        {
            JobState.QUEUED.value,
            JobState.CANCELING.value,
            JobState.CANCELED.value,
            JobState.FAILED.value,
        }
    ),
    JobState.ORPHANED.value: frozenset(
        {
            JobState.QUEUED.value,
            JobState.CANCELING.value,
            JobState.CANCELED.value,
            JobState.FAILED.value,
        }
    ),
    JobState.PARTIAL.value: frozenset({JobState.QUEUED.value}),
    JobState.FAILED.value: frozenset({JobState.QUEUED.value}),
    JobState.COMPLETED.value: frozenset(),
    JobState.CANCELED.value: frozenset(),
}


def _state(value: str | JobState) -> str:
    raw = value.value if isinstance(value, JobState) else str(value).strip().lower()
    return _STATE_ALIASES.get(raw, raw)


def transition_table() -> dict[str, Any]:
    """Return the versioned transition table and terminal invariants."""

    return {
        "version": TRANSITION_TABLE_VERSION,
        "states": [item.value for item in JobState],
        "terminal_states": sorted(TERMINAL_STATES),
        "transitions": {
            source: sorted(targets) for source, targets in _TRANSITIONS.items()
        },
        "rules": {
            "actor_required": True,
            "reason_required_for_terminal": True,
            "compare_and_swap": True,
            "completed_requires_complete_coverage": True,
            "completed_rejects_uncertain_work": True,
        },
    }


def allowed_transitions() -> dict[str, frozenset[str]]:
    return {source: frozenset(targets) for source, targets in _TRANSITIONS.items()}


def _now() -> float:
    return time.time()


def _tenant(value: Any) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 100 or "\x00" in result:
        raise ValueError("valid tenant_id is required")
    return result


def _identifier(value: Any, name: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 256 or "\x00" in result:
        raise ValueError(f"valid {name} is required")
    return result


def _json(value: Any, *, limit: int = 1_000_000) -> str:
    result = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if len(result.encode("utf-8")) > limit:
        raise ValueError("durable metadata exceeds size limit")
    return result


def _decode(value: Any, default: Any = None) -> Any:
    if value is None:
        return default
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def _identity(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _canonical_work_items(items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Normalize work material before hashing or applying it.

    Delivery identity must not depend on transport ordering.  Work keys are
    also canonicalized to strings here so a replay using an equivalent typed
    key cannot create a second logical work item.
    """

    normalized: list[dict[str, Any]] = []
    for raw in items:
        if not isinstance(raw, Mapping):
            raise ValueError("each work item must be an object")
        item = dict(raw)
        if not str(item.get("work_key") or "").strip():
            raise ValueError("each work item needs a work_key")
        item["work_key"] = str(item["work_key"]).strip()
        normalized.append(item)
    return sorted(
        normalized,
        key=lambda item: (str(item["work_key"]), _json(item)),
    )


def _token_digest(token: str) -> str:
    if not isinstance(token, str) or not token:
        raise LeaseError("lease token is required")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class JobStateService:
    """One transactional, tenant-qualified job state authority."""

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        *,
        clock: Callable[[], float] | None = None,
        process_supervisor: ProcessSupervisor | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.clock = clock or _now
        self.process_supervisor = process_supervisor
        self._lock = threading.RLock()
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            isolation_level=None,
            timeout=10,
        )
        self._closed = False
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=10000")
        if self.db_path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()
        self._lease_secret = self._load_lease_secret()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self.conn.close()
            self._closed = True

    def __del__(self) -> None:
        """Best-effort cleanup for short-lived service instances in workers/tests."""

        try:
            self.close()
        except Exception:
            # Interpreter teardown and partially constructed instances cannot
            # safely surface a cleanup exception.
            pass

    def __enter__(self) -> "JobStateService":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[None]:
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS job_state_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS durable_job_state_jobs (
                tenant_id TEXT NOT NULL DEFAULT 'default',
                id TEXT NOT NULL,
                idempotency_key TEXT,
                parent_id TEXT,
                state TEXT NOT NULL CHECK(state IN (
                    'planned','pending_approval','queued','leased','running',
                    'paused','canceling','canceled','partial','failed',
                    'completed','expired','orphaned'
                )),
                payload_json TEXT NOT NULL DEFAULT '{}',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                max_attempts INTEGER NOT NULL DEFAULT 1 CHECK(max_attempts > 0),
                required_work INTEGER NOT NULL DEFAULT 0 CHECK(required_work >= 0),
                completed_work INTEGER NOT NULL DEFAULT 0 CHECK(completed_work >= 0),
                skipped_work INTEGER NOT NULL DEFAULT 0 CHECK(skipped_work >= 0),
                failed_work INTEGER NOT NULL DEFAULT 0 CHECK(failed_work >= 0),
                truncated_work INTEGER NOT NULL DEFAULT 0 CHECK(truncated_work >= 0),
                uncollected_work INTEGER NOT NULL DEFAULT 0 CHECK(uncollected_work >= 0),
                version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                started_at REAL,
                terminal_at REAL,
                terminal_reason TEXT,
                terminal_actor TEXT,
                error_reason TEXT,
                result_ref TEXT,
                process_identity_json TEXT,
                PRIMARY KEY(tenant_id,id),
                FOREIGN KEY(tenant_id,parent_id) REFERENCES durable_job_state_jobs(tenant_id,id)
                    ON DELETE CASCADE
            );
            CREATE UNIQUE INDEX IF NOT EXISTS durable_job_state_uq_job_idempotency
                ON durable_job_state_jobs(tenant_id,idempotency_key)
                WHERE idempotency_key IS NOT NULL;
            CREATE INDEX IF NOT EXISTS durable_job_state_ix_job_state
                ON durable_job_state_jobs(tenant_id,state,updated_at);
            CREATE TABLE IF NOT EXISTS durable_job_state_attempts (
                tenant_id TEXT NOT NULL,
                id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                number INTEGER NOT NULL CHECK(number > 0),
                idempotency_key TEXT,
                state TEXT NOT NULL CHECK(state IN (
                    'leased','running','succeeded','failed','canceled',
                    'expired','orphaned'
                )),
                worker_id TEXT,
                lease_token_digest TEXT,
                lease_generation INTEGER NOT NULL DEFAULT 1,
                lease_expires_at REAL,
                started_at REAL,
                finished_at REAL,
                result_ref TEXT,
                result_identity TEXT,
                error_reason TEXT,
                version INTEGER NOT NULL DEFAULT 0,
                process_identity_json TEXT,
                PRIMARY KEY(tenant_id,id),
                UNIQUE(tenant_id,job_id,number),
                FOREIGN KEY(tenant_id,job_id) REFERENCES durable_job_state_jobs(tenant_id,id)
                    ON DELETE CASCADE
            );
            CREATE UNIQUE INDEX IF NOT EXISTS durable_job_state_uq_attempt_idempotency
                ON durable_job_state_attempts(tenant_id,job_id,idempotency_key)
                WHERE idempotency_key IS NOT NULL;
            CREATE INDEX IF NOT EXISTS durable_job_state_ix_attempt_active
                ON durable_job_state_attempts(tenant_id,job_id,state);
            CREATE TABLE IF NOT EXISTS durable_job_state_leases (
                tenant_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                token_digest TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 1,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                revoked_at REAL,
                revoke_reason TEXT,
                PRIMARY KEY(tenant_id,attempt_id),
                FOREIGN KEY(tenant_id,attempt_id) REFERENCES durable_job_state_attempts(tenant_id,id)
                    ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS durable_job_state_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                attempt_id TEXT,
                event_type TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                idempotency_key TEXT,
                data_json TEXT NOT NULL DEFAULT '{}',
                occurred_at REAL NOT NULL,
                FOREIGN KEY(tenant_id,job_id) REFERENCES durable_job_state_jobs(tenant_id,id)
                    ON DELETE CASCADE,
                FOREIGN KEY(tenant_id,attempt_id) REFERENCES durable_job_state_attempts(tenant_id,id)
                    ON DELETE CASCADE
            );
            CREATE UNIQUE INDEX IF NOT EXISTS durable_job_state_uq_event_idempotency
                ON durable_job_state_events(tenant_id,job_id,idempotency_key)
                WHERE idempotency_key IS NOT NULL;
            CREATE TABLE IF NOT EXISTS durable_job_state_logs (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                attempt_id TEXT,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                data_json TEXT NOT NULL DEFAULT '{}',
                occurred_at REAL NOT NULL,
                FOREIGN KEY(tenant_id,job_id) REFERENCES durable_job_state_jobs(tenant_id,id)
                    ON DELETE CASCADE,
                FOREIGN KEY(tenant_id,attempt_id) REFERENCES durable_job_state_attempts(tenant_id,id)
                    ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS durable_job_state_work_items (
                tenant_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                work_key TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'pending','completed','skipped','failed','truncated','uncollected'
                )),
                required INTEGER NOT NULL DEFAULT 1 CHECK(required IN (0,1)),
                reason TEXT,
                attempt_id TEXT,
                observation_id TEXT,
                result_ref TEXT,
                updated_at REAL NOT NULL,
                PRIMARY KEY(tenant_id,job_id,work_key),
                FOREIGN KEY(tenant_id,job_id) REFERENCES durable_job_state_jobs(tenant_id,id)
                    ON DELETE CASCADE,
                FOREIGN KEY(tenant_id,attempt_id) REFERENCES durable_job_state_attempts(tenant_id,id)
                    ON DELETE SET NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS durable_job_state_uq_work_observation
                ON durable_job_state_work_items(tenant_id,observation_id)
                WHERE observation_id IS NOT NULL;
            CREATE TABLE IF NOT EXISTS durable_job_state_deliveries (
                tenant_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                observation_id TEXT,
                result_ref TEXT,
                result_identity TEXT NOT NULL,
                accepted_at REAL NOT NULL,
                PRIMARY KEY(tenant_id,attempt_id,idempotency_key),
                UNIQUE(tenant_id,observation_id),
                FOREIGN KEY(tenant_id,attempt_id) REFERENCES durable_job_state_attempts(tenant_id,id)
                    ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS durable_job_state_children (
                tenant_id TEXT NOT NULL,
                parent_id TEXT NOT NULL,
                child_id TEXT NOT NULL,
                identity_key TEXT NOT NULL,
                required INTEGER NOT NULL DEFAULT 1 CHECK(required IN (0,1)),
                created_at REAL NOT NULL,
                PRIMARY KEY(tenant_id,parent_id,identity_key),
                UNIQUE(tenant_id,parent_id,child_id),
                FOREIGN KEY(tenant_id,parent_id) REFERENCES durable_job_state_jobs(tenant_id,id)
                    ON DELETE CASCADE,
                FOREIGN KEY(tenant_id,child_id) REFERENCES durable_job_state_jobs(tenant_id,id)
                    ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS durable_job_state_child_processes (
                tenant_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                identity_key TEXT NOT NULL,
                pid INTEGER NOT NULL,
                start_token TEXT NOT NULL,
                boot_id TEXT NOT NULL DEFAULT '',
                command_digest TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'running',
                cancel_requested_at REAL,
                stopped_at REAL,
                escalation_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(tenant_id,attempt_id,identity_key),
                FOREIGN KEY(tenant_id,job_id) REFERENCES durable_job_state_jobs(tenant_id,id)
                    ON DELETE CASCADE,
                FOREIGN KEY(tenant_id,attempt_id) REFERENCES durable_job_state_attempts(tenant_id,id)
                    ON DELETE CASCADE
            );
            """
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO job_state_meta(key,value) VALUES('schema_version',?)",
            (TRANSITION_TABLE_VERSION,),
        )

    def _load_lease_secret(self) -> bytes:
        """Load the per-store signing secret used to replay active leases.

        Lease tokens are deterministic HMAC capabilities rather than stored
        plaintext.  That lets a worker safely recover an acquire/renew
        response after a crash while the durable attempt record continues to
        contain only a token digest.
        """

        row = self.conn.execute(
            "SELECT value FROM job_state_meta WHERE key='lease_token_secret'"
        ).fetchone()
        if row is None:
            value = secrets.token_hex(32)
            self.conn.execute(
                "INSERT INTO job_state_meta(key,value) VALUES('lease_token_secret',?)",
                (value,),
            )
        else:
            value = str(row["value"])
        try:
            secret = bytes.fromhex(value)
        except ValueError as exc:
            raise JobStateError("durable lease signing secret is invalid") from exc
        if len(secret) < 32:
            raise JobStateError("durable lease signing secret is too short")
        return secret

    def _lease_token(self, tenant: str, attempt_id: str, generation: int) -> str:
        material = f"{tenant}\x00{attempt_id}\x00{int(generation)}".encode("utf-8")
        signature = hmac.new(self._lease_secret, material, hashlib.sha256).hexdigest()
        return f"forge-lease-v1.{signature}"

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        for key in ("payload_json", "metadata_json", "data_json", "process_identity_json"):
            if key in result:
                result[key.removesuffix("_json")] = _decode(result.pop(key), {})
        if "state" in result:
            result["status"] = result["state"]
        result.pop("lease_token_digest", None)
        return result

    def _job(self, tenant: str, job_id: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM durable_job_state_jobs WHERE tenant_id=? AND id=?", (tenant, job_id)
        ).fetchone()
        if row is None:
            raise KeyError(job_id)
        return row

    def _attempt(self, tenant: str, attempt_id: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM durable_job_state_attempts WHERE tenant_id=? AND id=?", (tenant, attempt_id)
        ).fetchone()
        if row is None:
            raise KeyError(attempt_id)
        return row

    def _event(
        self,
        tenant: str,
        job_id: str,
        event_type: str,
        *,
        attempt_id: str | None = None,
        from_state: str | None = None,
        to_state: str | None = None,
        actor: str = "system",
        reason: str = "unspecified",
        idempotency_key: str | None = None,
        data: Mapping[str, Any] | None = None,
    ) -> int:
        cursor = self.conn.execute(
            """
            INSERT INTO durable_job_state_events(
                tenant_id,job_id,attempt_id,event_type,from_state,to_state,
                actor,reason,idempotency_key,data_json,occurred_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                tenant,
                job_id,
                attempt_id,
                _identifier(event_type, "event_type"),
                from_state,
                to_state,
                _identifier(actor, "actor"),
                str(reason or "unspecified")[:2000],
                idempotency_key,
                _json(dict(data or {})),
                self.clock(),
            ),
        )
        if cursor.lastrowid is None:
            raise JobStateError("durable event was not assigned a sequence")
        return int(cursor.lastrowid)

    def _create_job_tx(
        self,
        *,
        tenant: str,
        job_id: str,
        payload: Mapping[str, Any],
        idempotency_key: str | None,
        parent_id: str | None,
        max_attempts: int,
        required_work: int,
        state: str,
        metadata: Mapping[str, Any],
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        now = self.clock()
        self.conn.execute(
            """
            INSERT INTO durable_job_state_jobs(
                tenant_id,id,idempotency_key,parent_id,state,payload_json,metadata_json,
                max_attempts,required_work,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                tenant,
                job_id,
                idempotency_key,
                parent_id,
                state,
                _json(dict(payload)),
                _json(dict(metadata)),
                max(1, int(max_attempts)),
                max(0, int(required_work)),
                now,
                now,
            ),
        )
        self._event(
            tenant,
            job_id,
            "job_created",
            to_state=state,
            actor=actor,
            reason=reason,
            data={"parent_id": parent_id},
        )
        return self._row(self._job(tenant, job_id)) or {}

    def _link_child_tx(
        self,
        tenant: str,
        parent_id: str,
        child_id: str,
        *,
        identity_key: str,
        required: bool,
        actor: str,
    ) -> None:
        """Register parent ownership in the same transaction as child creation."""

        existing = self.conn.execute(
            """
            SELECT identity_key FROM durable_job_state_children
            WHERE tenant_id=? AND parent_id=? AND child_id=?
            """,
            (tenant, parent_id, child_id),
        ).fetchone()
        if existing is not None:
            return
        parent = self._job(tenant, parent_id)
        if str(parent["state"]) in TERMINAL_STATES:
            raise TerminalStateError(
                f"cannot add a child to terminal job state {parent['state']}"
            )
        self.conn.execute(
            """
            INSERT INTO durable_job_state_children(
                tenant_id,parent_id,child_id,identity_key,required,created_at
            ) VALUES(?,?,?,?,?,?)
            """,
            (
                tenant,
                parent_id,
                child_id,
                _identifier(identity_key, "identity_key"),
                int(required),
                self.clock(),
            ),
        )
        self._event(
            tenant,
            parent_id,
            "child_created",
            actor=actor,
            reason="child identity registered",
            data={"child_id": child_id, "identity_key": identity_key},
        )

    def create_job(
        self,
        payload: Mapping[str, Any] | None = None,
        *,
        tenant_id: str = "default",
        job_id: str | None = None,
        idempotency_key: str | None = None,
        parent_id: str | None = None,
        max_attempts: int = 1,
        required_work: int | None = None,
        coverage_required: int | None = None,
        state: str | JobState = JobState.PLANNED,
        metadata: Mapping[str, Any] | None = None,
        actor: str = "system",
        reason: str = "job planned",
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        requested = _state(state)
        if requested not in {
            JobState.PLANNED.value,
            JobState.PENDING_APPROVAL.value,
            JobState.QUEUED.value,
        }:
            raise InvalidTransition("new durable_job_state_jobs must start planned, pending_approval, or queued")
        if required_work is None:
            required_work = coverage_required if coverage_required is not None else 0
        if int(required_work) < 0 or int(max_attempts) < 1:
            raise ValueError("invalid required_work or max_attempts")
        supplied_job_id = job_id
        job_id = _identifier(job_id or str(uuid.uuid4()), "job_id")
        parent_id = _identifier(parent_id, "parent_id") if parent_id else None
        if parent_id == job_id:
            raise ValueError("a job cannot be its own parent")
        payload_dict = dict(payload or {})
        metadata_dict = dict(metadata or {})
        with self._tx():
            if idempotency_key is not None:
                idempotency_key = _identifier(idempotency_key, "idempotency_key")
                old = self.conn.execute(
                    "SELECT * FROM durable_job_state_jobs WHERE tenant_id=? AND idempotency_key=?",
                    (tenant, idempotency_key),
                ).fetchone()
                if old is not None:
                    created = self.conn.execute(
                        """
                        SELECT to_state FROM durable_job_state_events
                        WHERE tenant_id=? AND job_id=? AND event_type='job_created'
                        ORDER BY sequence LIMIT 1
                        """,
                        (tenant, old["id"]),
                    ).fetchone()
                    same_request = (
                        _decode(old["payload_json"], {}) == payload_dict
                        and _decode(old["metadata_json"], {}) == metadata_dict
                        and str(old["parent_id"] or "") == str(parent_id or "")
                        and int(old["max_attempts"]) == int(max_attempts)
                        and int(old["required_work"]) == int(required_work)
                        and (
                            created is None
                            or str(created["to_state"] or "") == requested
                        )
                        and (
                            supplied_job_id is None
                            or str(old["id"]) == str(supplied_job_id)
                        )
                    )
                    if not same_request:
                        raise IdempotencyConflict("job idempotency parameters differ")
                    if parent_id is not None:
                        self._link_child_tx(
                            tenant,
                            parent_id,
                            str(old["id"]),
                            identity_key=f"job:{old['id']}",
                            required=True,
                            actor=actor,
                        )
                    return self._row(old) or {}
            existing = self.conn.execute(
                "SELECT * FROM durable_job_state_jobs WHERE tenant_id=? AND id=?", (tenant, job_id)
            ).fetchone()
            if existing is not None:
                raise IdempotencyConflict("job id already exists")
            created = self._create_job_tx(
                tenant=tenant,
                job_id=job_id,
                payload=payload_dict,
                idempotency_key=idempotency_key,
                parent_id=parent_id,
                max_attempts=int(max_attempts),
                required_work=int(required_work),
                state=requested,
                metadata=metadata_dict,
                actor=actor,
                reason=reason,
            )
            if parent_id is not None:
                self._link_child_tx(
                    tenant,
                    parent_id,
                    job_id,
                    identity_key=f"job:{job_id}",
                    required=True,
                    actor=actor,
                )
            return created

    enqueue = create_job

    def get_job(
        self, job_id: str, *, tenant_id: str = "default"
    ) -> dict[str, Any] | None:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._lock:
            return self._row(
                self.conn.execute(
                    "SELECT * FROM durable_job_state_jobs WHERE tenant_id=? AND id=?", (tenant, job_id)
                ).fetchone()
            )

    def list_jobs(
        self,
        *,
        tenant_id: str = "default",
        states: Iterable[str | JobState] | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        tenant = _tenant(tenant_id)
        selected = [_state(value) for value in states or ()]
        query = "SELECT * FROM durable_job_state_jobs WHERE tenant_id=?"
        params: list[Any] = [tenant]
        if selected:
            query += " AND state IN (" + ",".join("?" for _ in selected) + ")"
            params.extend(selected)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(10_000, int(limit))))
        with self._lock:
            return [
                self._row(row) or {}
                for row in self.conn.execute(query, params).fetchall()
            ]

    def _completion_blockers(self, tenant: str, job_id: str) -> list[str]:
        job = self._job(tenant, job_id)
        blockers: list[str] = []
        if int(job["completed_work"]) < int(job["required_work"]):
            blockers.append("required_work_incomplete")
        if self.conn.execute(
            """
            SELECT 1 FROM durable_job_state_work_items
            WHERE tenant_id=? AND job_id=? AND required=1 AND state='pending'
            LIMIT 1
            """,
            (tenant, job_id),
        ).fetchone():
            blockers.append("required_work_pending")
        for column, code in (
            ("skipped_work", "required_work_skipped"),
            ("failed_work", "required_work_failed"),
            ("truncated_work", "required_work_truncated"),
            ("uncollected_work", "required_work_uncollected"),
        ):
            if int(job[column]) > 0:
                blockers.append(code)
        if self.conn.execute(
            """
            SELECT 1 FROM durable_job_state_attempts
            WHERE tenant_id=? AND job_id=? AND state IN ('leased','running')
            LIMIT 1
            """,
            (tenant, job_id),
        ).fetchone():
            blockers.append("active_attempt")
        if self.conn.execute(
            """
            SELECT 1 FROM durable_job_state_child_processes
            WHERE tenant_id=? AND job_id=? AND state IN ('running','orphaned')
            LIMIT 1
            """,
            (tenant, job_id),
        ).fetchone():
            blockers.append("active_child_process")
        children = self.conn.execute(
            """
            SELECT c.identity_key,j.state
            FROM durable_job_state_children c JOIN durable_job_state_jobs j
              ON j.tenant_id=c.tenant_id AND j.id=c.child_id
            WHERE c.tenant_id=? AND c.parent_id=? AND c.required=1
            """,
            (tenant, job_id),
        ).fetchall()
        blockers.extend(
            f"unresolved_child:{row['identity_key']}"
            for row in children
            if row["state"] != JobState.COMPLETED.value
        )
        return blockers

    def completion_blockers(
        self, job_id: str, *, tenant_id: str = "default"
    ) -> list[str]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._lock:
            return self._completion_blockers(tenant, job_id)

    def _transition_tx(
        self,
        tenant: str,
        job_id: str,
        target: str,
        *,
        expected_version: int | None,
        actor: str,
        reason: str,
        idempotency_key: str | None,
        data: Mapping[str, Any] | None,
        allow_completion: bool = False,
    ) -> dict[str, Any]:
        row = self._job(tenant, job_id)
        if idempotency_key is not None:
            prior = self.conn.execute(
                """
                SELECT from_state,to_state,actor,reason,data_json
                FROM durable_job_state_events
                WHERE tenant_id=? AND job_id=? AND idempotency_key=?
                """,
                (tenant, job_id, idempotency_key),
            ).fetchone()
            if prior is not None:
                prior_data = _decode(prior["data_json"], {})
                if (
                    str(prior["to_state"] or "") != target
                    or (data is not None and prior_data != dict(data))
                ):
                    raise IdempotencyConflict(
                        "transition idempotency key was reused with different parameters"
                    )
                return self._row(row) or {}
        current = str(row["state"])
        if expected_version is not None and int(row["version"]) != int(expected_version):
            raise InvalidTransition("version conflict")
        if target == current:
            return self._row(row) or {}
        if target not in _TRANSITIONS.get(current, frozenset()):
            raise InvalidTransition(f"{current} -> {target}")
        if target == JobState.COMPLETED.value:
            if not allow_completion:
                raise TerminalStateError("completion requires terminal invariant validation")
            blockers = self._completion_blockers(tenant, job_id)
            if blockers:
                raise TerminalStateError("job cannot complete: " + ",".join(blockers))
        now = self.clock()
        changed = self.conn.execute(
            """
            UPDATE durable_job_state_jobs SET state=?,version=version+1,updated_at=?,
                terminal_at=?,terminal_reason=?,terminal_actor=?
            WHERE tenant_id=? AND id=? AND version=?
            """,
            (
                target,
                now,
                now if target in TERMINAL_STATES else None,
                str(reason or "unspecified")[:2000]
                if target in TERMINAL_STATES
                else None,
                str(actor or "system") if target in TERMINAL_STATES else None,
                tenant,
                job_id,
                int(row["version"]),
            ),
        )
        if changed.rowcount != 1:
            raise InvalidTransition("stale job version")
        self._event(
            tenant,
            job_id,
            "state_changed",
            from_state=current,
            to_state=target,
            actor=actor,
            reason=reason,
            idempotency_key=idempotency_key,
            data=data,
        )
        return self._row(self._job(tenant, job_id)) or {}

    def transition(
        self,
        job_id: str,
        to_state: str | JobState,
        *,
        tenant_id: str = "default",
        idempotency_key: str | None = None,
        data: Mapping[str, Any] | None = None,
        actor: str = "system",
        reason: str = "state transition",
        expected_version: int | None = None,
        version: int | None = None,
    ) -> dict[str, Any]:
        """Apply a dispatch/approval transition, never manufacture execution.

        Leasing, starting, terminal result acceptance, retry, cancellation,
        and restart recovery each have an operation with the preconditions
        needed to preserve attempt and lease authority.  Keeping this generic
        compatibility entry point limited to initial dispatch means a caller
        cannot turn a queued job into running work (or a completed result)
        merely by choosing a status string.
        """
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        target = _state(to_state)
        if target not in {item.value for item in JobState}:
            raise InvalidTransition(f"unknown state: {target}")
        expected = expected_version if expected_version is not None else version
        with self._tx():
            row = self._job(tenant, job_id)
            current = str(row["state"])
            # Preserve safe idempotent enqueue responses, including one whose
            # request is redelivered after a worker has already leased it.
            if target != current:
                dispatch_edges = {
                    JobState.PLANNED.value: {
                        JobState.PENDING_APPROVAL.value,
                        JobState.QUEUED.value,
                    },
                    JobState.PENDING_APPROVAL.value: {JobState.QUEUED.value},
                }
                if target not in dispatch_edges.get(current, set()):
                    raise InvalidTransition(
                        "use the lifecycle operation for "
                        f"{current} -> {target}"
                    )
            return self._transition_tx(
                tenant,
                job_id,
                target,
                expected_version=expected,
                actor=actor,
                reason=reason,
                idempotency_key=idempotency_key,
                data=data,
            )

    def complete_job(
        self,
        job_id: str,
        *,
        tenant_id: str = "default",
        actor: str = "system",
        reason: str = "required work completed",
        expected_version: int | None = None,
        result_ref: str | None = None,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._tx():
            row = self._job(tenant, job_id)
            self._transition_tx(
                tenant,
                job_id,
                JobState.COMPLETED.value,
                expected_version=expected_version if expected_version is not None else int(row["version"]),
                actor=actor,
                reason=reason,
                idempotency_key=None,
                data={"result_ref": result_ref},
                allow_completion=True,
            )
            if result_ref is not None:
                self.conn.execute(
                    "UPDATE durable_job_state_jobs SET result_ref=? WHERE tenant_id=? AND id=?",
                    (result_ref, tenant, job_id),
                )
            return self._row(self._job(tenant, job_id)) or {}

    def pause_job(
        self,
        job_id: str,
        *,
        tenant_id: str = "default",
        actor: str = "operator",
        reason: str = "operator pause",
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._tx():
            row = self._job(tenant, job_id)
            current = str(row["state"])
            if current == JobState.PAUSED.value:
                return self._row(row) or {}
            if current not in {
                JobState.PLANNED.value,
                JobState.PENDING_APPROVAL.value,
                JobState.QUEUED.value,
                JobState.LEASED.value,
                JobState.RUNNING.value,
            }:
                raise InvalidTransition(f"cannot pause from {current}")
            return self._transition_tx(
                tenant,
                job_id,
                JobState.PAUSED.value,
                expected_version=(
                    expected_version
                    if expected_version is not None
                    else int(row["version"])
                ),
                actor=actor,
                reason=reason,
                idempotency_key=None,
                data=None,
            )

    pause = pause_job

    def resume_job(
        self,
        job_id: str,
        *,
        tenant_id: str = "default",
        actor: str = "operator",
        reason: str = "operator resume",
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._tx():
            row = self._job(tenant, job_id)
            if str(row["state"]) != JobState.PAUSED.value:
                if str(row["state"]) == JobState.QUEUED.value:
                    return self._row(row) or {}
                raise InvalidTransition(f"cannot resume from {row['state']}")
            active = self._active_attempt(tenant, job_id)
            if active is None:
                target = JobState.QUEUED.value
            elif str(active["state"]) == AttemptState.RUNNING.value:
                target = JobState.RUNNING.value
            else:
                target = JobState.LEASED.value
            return self._transition_tx(
                tenant,
                job_id,
                target,
                expected_version=int(row["version"]),
                actor=actor,
                reason=reason,
                idempotency_key=None,
                data={"attempt_id": active["id"] if active is not None else None},
            )

    def cancel_job(
        self,
        job_id: str,
        *,
        tenant_id: str = "default",
        actor: str = "operator",
        reason: str = "operator cancellation",
        supervisor: ProcessSupervisor | None = None,
        sla_seconds: float = 5.0,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        supervisor = supervisor or self.process_supervisor
        with self._tx():
            row = self._job(tenant, job_id)
            current = str(row["state"])
            active_before_cancel = self._active_attempt(tenant, job_id)
            unresolved_before_cancel = self.conn.execute(
                """
                SELECT 1 FROM durable_job_state_child_processes
                WHERE tenant_id=? AND job_id=? AND state IN ('running','orphaned')
                LIMIT 1
                """,
                (tenant, job_id),
            ).fetchone()
            if current in {JobState.CANCELED.value, JobState.PARTIAL.value}:
                return self._row(row) or {}
            if current in {JobState.FAILED.value, JobState.COMPLETED.value}:
                return self._row(row) or {}
            if (
                current in {JobState.EXPIRED.value, JobState.ORPHANED.value}
                and unresolved_before_cancel is None
            ):
                self._record_missing_required_work_tx(
                    tenant,
                    job_id,
                    reason=reason,
                    actor=actor,
                )
                return self._transition_tx(
                    tenant,
                    job_id,
                    JobState.CANCELED.value,
                    expected_version=int(row["version"]),
                    actor=actor,
                    reason=reason,
                    idempotency_key=None,
                    data={"reconciled_state": current},
                )
            if (
                (
                    current
                    in {
                        JobState.PLANNED.value,
                        JobState.PENDING_APPROVAL.value,
                        JobState.QUEUED.value,
                    }
                    and unresolved_before_cancel is None
                )
                or (
                    current == JobState.PAUSED.value
                    and active_before_cancel is None
                    and unresolved_before_cancel is None
                )
            ):
                self._record_missing_required_work_tx(
                    tenant,
                    job_id,
                    reason=reason,
                    actor=actor,
                )
                result = self._transition_tx(
                    tenant,
                    job_id,
                    JobState.CANCELED.value,
                    expected_version=int(row["version"]),
                    actor=actor,
                    reason=reason,
                    idempotency_key=None,
                    data={"queued_work_prevented": True},
                )
                self._event(
                    tenant,
                    job_id,
                    "cancel_requested",
                    actor=actor,
                    reason=reason,
                    data={"immediate": True},
                )
                return result
            if current not in {
                JobState.PLANNED.value,
                JobState.PENDING_APPROVAL.value,
                JobState.QUEUED.value,
                JobState.LEASED.value,
                JobState.RUNNING.value,
                JobState.PAUSED.value,
                JobState.CANCELING.value,
                JobState.EXPIRED.value,
                JobState.ORPHANED.value,
            }:
                raise InvalidTransition(f"cannot cancel from {current}")
            if current != JobState.CANCELING.value:
                self._transition_tx(
                    tenant,
                    job_id,
                    JobState.CANCELING.value,
                    expected_version=int(row["version"]),
                    actor=actor,
                    reason=reason,
                    idempotency_key=None,
                    data={"sla_seconds": float(max(0, sla_seconds))},
                )
            processes = self.conn.execute(
                """
                SELECT * FROM durable_job_state_child_processes
                WHERE tenant_id=? AND job_id=? AND state='running'
                """,
                (tenant, job_id),
            ).fetchall()
            for process in processes:
                process_identity: ProcessIdentity | None = None
                try:
                    process_identity = ProcessIdentity(
                        pid=int(process["pid"]),
                        start_token=str(process["start_token"]),
                        boot_id=str(process["boot_id"]),
                        command_digest=str(process["command_digest"]),
                    )
                except Exception:
                    # The rejection is recorded below and the child remains
                    # explicitly uncertain rather than risking a PID-only
                    # signal to an unrelated process.
                    process_identity = None
                self._event(
                    tenant,
                    job_id,
                    "child_cancel_requested",
                    attempt_id=process["attempt_id"],
                    actor=actor,
                    reason=reason,
                    data={
                        "identity_key": process["identity_key"],
                        "pid": int(process["pid"]),
                    },
                )
                process_state = "orphaned"
                escalation_count = 0
                try:
                    if process_identity is None:
                        raise ProcessIdentityError("child process identity is invalid")
                    if supervisor is None:
                        raise ProcessIdentityError("no process supervisor is available")
                    alive = supervisor.is_alive(process_identity)
                    if alive:
                        self._event(
                            tenant,
                            job_id,
                            "child_terminate_requested",
                            attempt_id=process["attempt_id"],
                            actor=actor,
                            reason=reason,
                            data={"identity_key": process["identity_key"]},
                        )
                        supervisor.terminate(process_identity)
                        deadline = time.monotonic() + max(0.0, float(sla_seconds))
                        while (
                            time.monotonic() < deadline
                            and supervisor.is_alive(process_identity)
                        ):
                            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
                        if supervisor.is_alive(process_identity):
                            escalation_count = 1
                            self._event(
                                tenant,
                                job_id,
                                "child_kill_requested",
                                attempt_id=process["attempt_id"],
                                actor=actor,
                                reason="cancellation SLA elapsed",
                                data={"identity_key": process["identity_key"]},
                            )
                            supervisor.kill(process_identity)
                        process_state = (
                            "stopped"
                            if not supervisor.is_alive(process_identity)
                            else "orphaned"
                        )
                    else:
                        process_state = "stopped"
                except Exception as exc:
                    self._event(
                        tenant,
                        job_id,
                        "child_identity_rejected",
                        attempt_id=process["attempt_id"],
                        actor=actor,
                        reason="child identity could not be validated",
                        data={"identity_key": process["identity_key"], "error": type(exc).__name__},
                    )
                self.conn.execute(
                    """
                    UPDATE durable_job_state_child_processes SET state=?,stopped_at=?,
                        cancel_requested_at=COALESCE(cancel_requested_at,?),
                        escalation_count=escalation_count+?
                    WHERE tenant_id=? AND job_id=? AND attempt_id=? AND identity_key=?
                    """,
                    (
                        process_state,
                        self.clock() if process_state == "stopped" else None,
                        self.clock(),
                        escalation_count,
                        tenant,
                        job_id,
                        process["attempt_id"],
                        process["identity_key"],
                    ),
                )
            self._record_missing_required_work_tx(
                tenant,
                job_id,
                reason=reason,
                attempt_id=(
                    str(active_before_cancel["id"])
                    if active_before_cancel is not None
                    else None
                ),
                actor=actor,
            )
            # Cancellation revokes every active attempt atomically.  A late
            # worker result therefore cannot resurrect a canceled job.
            now = self.clock()
            active_attempts = self.conn.execute(
                """
                SELECT id FROM durable_job_state_attempts
                WHERE tenant_id=? AND job_id=? AND state IN ('leased','running')
                """,
                (tenant, job_id),
            ).fetchall()
            for active_attempt in active_attempts:
                self.conn.execute(
                    """
                    UPDATE durable_job_state_attempts SET state='canceled',finished_at=?,
                        lease_token_digest=NULL,lease_expires_at=NULL,version=version+1
                    WHERE tenant_id=? AND id=? AND state IN ('leased','running')
                    """,
                    (now, tenant, active_attempt["id"]),
                )
                self.conn.execute(
                    """
                    UPDATE durable_job_state_leases SET revoked_at=COALESCE(revoked_at,?),
                        revoke_reason=COALESCE(revoke_reason,?),expires_at=?
                    WHERE tenant_id=? AND attempt_id=?
                    """,
                    (now, reason, now, tenant, active_attempt["id"]),
                )
                self._event(
                    tenant,
                    job_id,
                    "attempt_canceled",
                    attempt_id=active_attempt["id"],
                    actor=actor,
                    reason=reason,
                )
            active = self.conn.execute(
                """
                SELECT 1 FROM durable_job_state_attempts
                WHERE tenant_id=? AND job_id=? AND state IN ('leased','running')
                LIMIT 1
                """,
                (tenant, job_id),
            ).fetchone()
            unresolved_process = self.conn.execute(
                """
                SELECT 1 FROM durable_job_state_child_processes
                WHERE tenant_id=? AND job_id=? AND state IN ('running','orphaned')
                LIMIT 1
                """,
                (tenant, job_id),
            ).fetchone()
            if active is None and unresolved_process is None:
                current_row = self._job(tenant, job_id)
                has_accepted_coverage = any(
                    int(current_row[column]) > 0
                    for column in (
                        "completed_work",
                        "skipped_work",
                        "failed_work",
                        "truncated_work",
                    )
                )
                self._transition_tx(
                    tenant,
                    job_id,
                    (
                        JobState.PARTIAL.value
                        if has_accepted_coverage
                        else JobState.CANCELED.value
                    ),
                    expected_version=int(current_row["version"]),
                    actor=actor,
                    reason=reason,
                    idempotency_key=None,
                    data={
                        "bounded_child_stop": True,
                        "accepted_partial_coverage": has_accepted_coverage,
                    },
                )
            elif unresolved_process is not None:
                current_row = self._job(tenant, job_id)
                if str(current_row["state"]) == JobState.CANCELING.value:
                    self._transition_tx(
                        tenant,
                        job_id,
                        JobState.ORPHANED.value,
                        expected_version=int(current_row["version"]),
                        actor=actor,
                        reason="cancellation could not validate child identity",
                        idempotency_key=None,
                        data={"bounded_child_stop": False},
                    )
            self._event(
                tenant,
                job_id,
                "cancel_reconciled",
                actor=actor,
                reason=reason,
                data={"sla_seconds": sla_seconds},
            )
            return self._row(self._job(tenant, job_id)) or {}

    cancel = cancel_job
    request_cancel = cancel_job

    def _active_attempt(self, tenant: str, job_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            """
            SELECT * FROM durable_job_state_attempts
            WHERE tenant_id=? AND job_id=? AND state IN ('leased','running')
            ORDER BY number DESC LIMIT 1
            """,
            (tenant, job_id),
        ).fetchone()

    def acquire_lease(
        self,
        job_id: str,
        worker_id: str,
        *,
        tenant_id: str = "default",
        lease_seconds: float = 60.0,
        idempotency_key: str | None = None,
        attempt_id: str | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        worker_id = _identifier(worker_id, "worker_id")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        with self._tx():
            job = self._job(tenant, job_id)
            if idempotency_key is not None:
                idempotency_key = _identifier(idempotency_key, "idempotency_key")
                old = self.conn.execute(
                    """
                    SELECT * FROM durable_job_state_attempts
                    WHERE tenant_id=? AND job_id=? AND idempotency_key=?
                    """,
                    (tenant, job_id, idempotency_key),
                ).fetchone()
                if old is not None:
                    if str(old["worker_id"]) != worker_id:
                        raise IdempotencyConflict(
                            "lease idempotency key was reused by another worker"
                        )
                    result = self._row(old) or {}
                    lease = self.conn.execute(
                        """
                        SELECT * FROM durable_job_state_leases
                        WHERE tenant_id=? AND attempt_id=?
                        """,
                        (tenant, old["id"]),
                    ).fetchone()
                    if (
                        lease is not None
                        and lease["revoked_at"] is None
                        and float(lease["expires_at"]) > float(self.clock())
                        and str(old["state"]) in ACTIVE_ATTEMPT_STATES
                    ):
                        token = self._lease_token(
                            tenant,
                            str(old["id"]),
                            int(lease["generation"]),
                        )
                        result["lease_token"] = token
                        result["token"] = token
                        result["generation"] = int(lease["generation"])
                    else:
                        result["lease_token"] = None
                    return result
            if self._active_attempt(tenant, job_id) is not None:
                raise LeaseUnavailable("job already has an active attempt")
            if self.conn.execute(
                """
                SELECT 1 FROM durable_job_state_child_processes
                WHERE tenant_id=? AND job_id=? AND state IN ('running','orphaned')
                LIMIT 1
                """,
                (tenant, job_id),
            ).fetchone():
                raise LeaseUnavailable("job has an unresolved child process")
            if str(job["state"]) != JobState.QUEUED.value:
                raise InvalidTransition(f"cannot lease from {job['state']}")
            count = int(
                self.conn.execute(
                    "SELECT COUNT(*) FROM durable_job_state_attempts WHERE tenant_id=? AND job_id=?",
                    (tenant, job_id),
                ).fetchone()[0]
            )
            if count >= int(job["max_attempts"]):
                raise InvalidTransition("attempt limit exhausted")
            now = self.clock()
            attempt_id = _identifier(attempt_id or str(uuid.uuid4()), "attempt_id")
            idempotency_key = idempotency_key or _identifier(
                f"lease:{attempt_id}", "idempotency_key"
            )
            token = self._lease_token(tenant, attempt_id, 1)
            digest = _token_digest(token)
            expires = now + float(lease_seconds)
            self.conn.execute(
                """
                INSERT INTO durable_job_state_attempts(
                    tenant_id,id,job_id,number,idempotency_key,state,worker_id,
                    lease_token_digest,lease_generation,lease_expires_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    tenant,
                    attempt_id,
                    job_id,
                    count + 1,
                    idempotency_key,
                    AttemptState.LEASED.value,
                    worker_id,
                    digest,
                    1,
                    expires,
                ),
            )
            self.conn.execute(
                """
                INSERT INTO durable_job_state_leases(
                    tenant_id,attempt_id,token_digest,owner_id,generation,
                    issued_at,expires_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (tenant, attempt_id, digest, worker_id, 1, now, expires),
            )
            self._transition_tx(
                tenant,
                job_id,
                JobState.LEASED.value,
                expected_version=int(job["version"]),
                actor=actor or worker_id,
                reason="lease acquired",
                idempotency_key=None,
                data={"attempt_id": attempt_id, "worker_id": worker_id},
            )
            self._event(
                tenant,
                job_id,
                "lease_acquired",
                attempt_id=attempt_id,
                actor=actor or worker_id,
                reason="lease acquired",
                data={"worker_id": worker_id, "expires_at": expires, "generation": 1},
            )
            result = self._row(self._attempt(tenant, attempt_id)) or {}
            result["lease_token"] = token
            result["token"] = token
            result["generation"] = 1
            return result

    lease_job = acquire_lease
    lease_attempt = acquire_lease

    def create_attempt(
        self,
        job_id: str,
        *,
        tenant_id: str = "default",
        worker_id: str | None = None,
        lease_seconds: float = 60.0,
        attempt_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Compatibility helper that queues a planned job before leasing."""

        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._tx():
            job = self._job(tenant, job_id)
            if str(job["state"]) == JobState.PLANNED.value:
                self._transition_tx(
                    tenant,
                    job_id,
                    JobState.QUEUED.value,
                    expected_version=int(job["version"]),
                    actor=worker_id or "system",
                    reason="job queued for attempt",
                    idempotency_key=None,
                    data={"compatibility": True},
                )
        return self.acquire_lease(
            job_id,
            worker_id or "worker",
            tenant_id=tenant,
            lease_seconds=lease_seconds,
            idempotency_key=idempotency_key,
            attempt_id=attempt_id,
        )

    def _refresh_counters(self, tenant: str, job_id: str) -> None:
        values = {}
        for state in (
            WorkState.COMPLETED.value,
            WorkState.SKIPPED.value,
            WorkState.FAILED.value,
            WorkState.TRUNCATED.value,
            WorkState.UNCOLLECTED.value,
        ):
            values[state] = int(
                self.conn.execute(
                    """
                    SELECT COUNT(*) FROM durable_job_state_work_items
                    WHERE tenant_id=? AND job_id=? AND required=1 AND state=?
                    """,
                    (tenant, job_id, state),
                ).fetchone()[0]
            )
        self.conn.execute(
            """
            UPDATE durable_job_state_jobs SET completed_work=?,skipped_work=?,failed_work=?,
                truncated_work=?,uncollected_work=?,updated_at=?
            WHERE tenant_id=? AND id=?
            """,
            (
                values[WorkState.COMPLETED.value],
                values[WorkState.SKIPPED.value],
                values[WorkState.FAILED.value],
                values[WorkState.TRUNCATED.value],
                values[WorkState.UNCOLLECTED.value],
                self.clock(),
                tenant,
                job_id,
            ),
        )

    def _record_missing_required_work_tx(
        self,
        tenant: str,
        job_id: str,
        *,
        reason: str,
        attempt_id: str | None = None,
        actor: str = "system",
    ) -> int:
        """Make cancellation/recovery gaps explicit before terminalization.

        A job may declare a required-work count before concrete keys are known.
        On a terminal interruption, pending known keys become uncollected and
        any remaining declared slots receive deterministic synthetic keys.
        This keeps coverage measured and auditable instead of silently treating
        an interrupted job as complete or fully described.
        """

        job = self._job(tenant, job_id)
        required_total = int(job["required_work"])
        if required_total <= 0:
            return 0
        safe_reason = str(reason or "work was not collected")[:2000]
        now = self.clock()
        self.conn.execute(
            """
            UPDATE durable_job_state_work_items
            SET state=?,reason=?,attempt_id=COALESCE(attempt_id,?),updated_at=?
            WHERE tenant_id=? AND job_id=? AND required=1 AND state='pending'
            """,
            (
                WorkState.UNCOLLECTED.value,
                safe_reason,
                attempt_id,
                now,
                tenant,
                job_id,
            ),
        )
        tracked = int(
            self.conn.execute(
                """
                SELECT COUNT(*) FROM durable_job_state_work_items
                WHERE tenant_id=? AND job_id=? AND required=1
                """,
                (tenant, job_id),
            ).fetchone()[0]
        )
        missing = max(0, required_total - tracked)
        for index in range(missing):
            # ``tracked`` makes the key collision-free even when cancellation
            # is retried after a crash between individual inserts.
            work_key = f"__uncollected_required__:{tracked + index + 1}"
            self.conn.execute(
                """
                INSERT INTO durable_job_state_work_items(
                    tenant_id,job_id,work_key,state,required,reason,attempt_id,
                    updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    tenant,
                    job_id,
                    work_key,
                    WorkState.UNCOLLECTED.value,
                    1,
                    safe_reason,
                    attempt_id,
                    now,
                ),
            )
        self._refresh_counters(tenant, job_id)
        if missing or tracked:
            self._event(
                tenant,
                job_id,
                "required_work_uncollected",
                attempt_id=attempt_id,
                actor=actor,
                reason=safe_reason,
                data={"declared_required": required_total, "missing_slots": missing},
            )
        return missing

    def _mark_work_tx(
        self,
        tenant: str,
        job_id: str,
        work_key: str,
        *,
        state: str | WorkState = WorkState.COMPLETED,
        required: bool = True,
        reason: str | None = None,
        attempt_id: str | None = None,
        observation_id: str | None = None,
        result_ref: str | None = None,
        actor: str = "worker",
        accepted_delivery: bool = False,
    ) -> bool:
        """Record one work item while the caller owns the active transaction.

        Composite operations such as result acceptance and attempt completion
        already run inside ``_tx``.  Keeping the write logic here prevents
        those operations from attempting a nested ``BEGIN IMMEDIATE`` while
        retaining ``mark_work`` as the public, standalone transactional API.
        """

        job_id = _identifier(job_id, "job_id")
        work_key = _identifier(work_key, "work_key")
        normalized_state = (
            state.value if isinstance(state, WorkState) else str(state).strip().lower()
        )
        if normalized_state not in {item.value for item in WorkState}:
            raise ValueError(f"unknown work state: {normalized_state}")
        job = self._job(tenant, job_id)
        old = self.conn.execute(
            """
            SELECT * FROM durable_job_state_work_items
            WHERE tenant_id=? AND job_id=? AND work_key=?
            """,
            (tenant, job_id, work_key),
        ).fetchone()
        if str(job["state"]) in TERMINAL_STATES:
            # Terminal coverage is immutable.  An exact replay is harmless,
            # but no later client input may turn a completed job into a
            # contradictory coverage record.
            if old is not None and str(old["state"]) == normalized_state:
                same_material = (
                    int(old["required"]) == int(required)
                    and str(old["reason"] or "") == str(reason or "")
                    and str(old["attempt_id"] or "") == str(attempt_id or "")
                    and str(old["observation_id"] or "")
                    == str(observation_id or "")
                    and str(old["result_ref"] or "") == str(result_ref or "")
                )
                if same_material:
                    return False
                raise IdempotencyConflict(
                    "work item was delivered with different result material"
                )
            raise TerminalStateError(
                f"cannot record work for terminal job state {job['state']}"
            )
        if normalized_state == WorkState.COMPLETED.value and required:
            if not accepted_delivery:
                raise InvalidTransition(
                    "completed required work must be accepted through a result delivery"
                )
            if attempt_id is None:
                raise InvalidTransition("completed required work needs an attempt")
            if not observation_id and not result_ref:
                raise ValueError(
                    "completed required work needs a canonical observation or result reference"
                )
        if (
            required
            and normalized_state
            in {
                WorkState.SKIPPED.value,
                WorkState.FAILED.value,
                WorkState.TRUNCATED.value,
                WorkState.UNCOLLECTED.value,
            }
            and not str(reason or "").strip()
        ):
            raise ValueError(f"{normalized_state} required work needs an explicit reason")
        if attempt_id is not None:
            attempt_id = _identifier(attempt_id, "attempt_id")
            linked_attempt = self._attempt(tenant, attempt_id)
            if str(linked_attempt["job_id"]) != job_id:
                raise InvalidTransition("attempt does not belong to the job")
        if old is not None:
            same_material = (
                str(old["state"]) == normalized_state
                and int(old["required"]) == int(required)
                and str(old["reason"] or "") == str(reason or "")
                and str(old["attempt_id"] or "") == str(attempt_id or "")
                and str(old["observation_id"] or "")
                == str(observation_id or "")
                and str(old["result_ref"] or "") == str(result_ref or "")
            )
            if str(old["state"]) == normalized_state and same_material:
                return False
            if str(old["state"]) != WorkState.PENDING.value:
                # A later attempt may resolve a previously failed/skipped
                # work key.  The current row is the latest truth; the prior
                # outcome remains in the ordered event stream.
                retry_row = None
                if attempt_id is not None and old["attempt_id"] is not None:
                    retry_row = self.conn.execute(
                        """
                        SELECT a_new.number > a_old.number AS is_newer
                        FROM durable_job_state_attempts a_new JOIN durable_job_state_attempts a_old
                          ON a_old.tenant_id=a_new.tenant_id
                         AND a_old.id=?
                        WHERE a_new.tenant_id=? AND a_new.id=?
                        """,
                        (old["attempt_id"], tenant, attempt_id),
                    ).fetchone()
                can_retry = (
                    normalized_state == WorkState.COMPLETED.value
                    and retry_row is not None
                    and bool(retry_row["is_newer"])
                )
                if not can_retry:
                    if str(old["state"]) == normalized_state:
                        raise IdempotencyConflict(
                            "work item was delivered with different result material"
                        )
                    raise IdempotencyConflict("work item already has a terminal state")
            self.conn.execute(
                """
                UPDATE durable_job_state_work_items SET state=?,required=?,reason=?,attempt_id=?,
                    observation_id=?,result_ref=?,updated_at=?
                WHERE tenant_id=? AND job_id=? AND work_key=?
                """,
                (
                    normalized_state,
                    int(required),
                    reason,
                    attempt_id,
                    observation_id,
                    result_ref,
                    self.clock(),
                    tenant,
                    job_id,
                    work_key,
                ),
            )
        else:
            self.conn.execute(
                """
                INSERT INTO durable_job_state_work_items(
                    tenant_id,job_id,work_key,state,required,reason,attempt_id,
                    observation_id,result_ref,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    tenant,
                    job_id,
                    work_key,
                    normalized_state,
                    int(required),
                    reason,
                    attempt_id,
                    observation_id,
                    result_ref,
                    self.clock(),
                ),
            )
        self._refresh_counters(tenant, job_id)
        self._event(
            tenant,
            job_id,
            "work_recorded",
            attempt_id=attempt_id,
            actor=actor,
            reason=reason or normalized_state,
            data={
                "work_key": work_key,
                "state": normalized_state,
                "required": bool(required),
                "observation_id": observation_id,
            },
        )
        return True

    def mark_work(
        self,
        job_id: str,
        work_key: str,
        *,
        state: str | WorkState = WorkState.COMPLETED,
        tenant_id: str = "default",
        required: bool = True,
        reason: str | None = None,
        attempt_id: str | None = None,
        observation_id: str | None = None,
        result_ref: str | None = None,
        actor: str = "worker",
    ) -> bool:
        """Record one work item in its own transaction."""

        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        work_key = _identifier(work_key, "work_key")
        with self._tx():
            return self._mark_work_tx(
                tenant,
                job_id,
                work_key,
                state=state,
                required=required,
                reason=reason,
                attempt_id=attempt_id,
                observation_id=observation_id,
                result_ref=result_ref,
                actor=actor,
            )

    def mark_coverage(
        self,
        job_id: str,
        key: str,
        *,
        tenant_id: str = "default",
        attempt_id: str | None = None,
        observation_id: str | None = None,
    ) -> bool:
        return self.mark_work(
            job_id,
            key,
            tenant_id=tenant_id,
            attempt_id=attempt_id,
            observation_id=observation_id,
        )

    def record_skipped(
        self,
        job_id: str,
        key: str,
        reason: str,
        *,
        tenant_id: str = "default",
        required: bool = True,
        attempt_id: str | None = None,
    ) -> bool:
        return self.mark_work(
            job_id,
            key,
            tenant_id=tenant_id,
            required=required,
            reason=reason,
            attempt_id=attempt_id,
            state=WorkState.SKIPPED,
        )

    def coverage_snapshot(
        self, job_id: str, *, tenant_id: str = "default"
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._lock:
            job = self._job(tenant, job_id)
            rows = self.conn.execute(
                """
                SELECT * FROM durable_job_state_work_items
                WHERE tenant_id=? AND job_id=? ORDER BY work_key
                """,
                (tenant, job_id),
            ).fetchall()
            return {
                "required": int(job["required_work"]),
                "completed": int(job["completed_work"]),
                "skipped": int(job["skipped_work"]),
                "failed": int(job["failed_work"]),
                "truncated": int(job["truncated_work"]),
                "uncollected": int(job["uncollected_work"]),
                "items": [self._row(row) or {} for row in rows],
                "complete": not self._completion_blockers(tenant, job_id),
            }

    def coverage_complete(
        self, job_id: str, *, tenant_id: str = "default"
    ) -> bool:
        return not self.completion_blockers(job_id, tenant_id=tenant_id)

    def _check_lease(
        self,
        tenant: str,
        attempt_id: str,
        token: str,
        *,
        worker_id: str | None = None,
    ) -> tuple[sqlite3.Row, sqlite3.Row]:
        attempt = self._attempt(tenant, attempt_id)
        lease = self.conn.execute(
            "SELECT * FROM durable_job_state_leases WHERE tenant_id=? AND attempt_id=?",
            (tenant, attempt_id),
        ).fetchone()
        if lease is None or lease["revoked_at"] is not None:
            raise LeaseError("lease is revoked or missing")
        if worker_id is not None and str(lease["owner_id"]) != str(worker_id):
            raise LeaseError("lease owner mismatch")
        supplied = _token_digest(token)
        if not hmac.compare_digest(str(lease["token_digest"]), supplied):
            raise LeaseError("lease token mismatch")
        if float(lease["expires_at"]) <= float(self.clock()):
            raise LeaseError("lease expired")
        if str(attempt["lease_token_digest"]) != supplied:
            raise LeaseError("stale lease generation")
        if str(attempt["state"]) not in ACTIVE_ATTEMPT_STATES:
            raise LeaseError("attempt is no longer active")
        return attempt, lease

    def _check_delivery_token(
        self,
        tenant: str,
        attempt_id: str,
        token: str,
    ) -> sqlite3.Row:
        """Authenticate an idempotent replay without reactivating a lease.

        Result delivery may be redelivered after the original attempt has
        atomically reached a terminal state.  The persisted token digest is
        sufficient to authenticate that exact replay, but it never authorizes
        a new result or any further state transition after revocation/expiry.
        """

        attempt = self._attempt(tenant, attempt_id)
        lease = self.conn.execute(
            "SELECT token_digest FROM durable_job_state_leases WHERE tenant_id=? AND attempt_id=?",
            (tenant, attempt_id),
        ).fetchone()
        if lease is None:
            raise LeaseError("lease is missing")
        if not hmac.compare_digest(str(lease["token_digest"]), _token_digest(token)):
            raise LeaseError("lease token mismatch")
        return attempt

    def start_attempt(
        self,
        attempt_id: str,
        lease_token: str,
        *,
        tenant_id: str = "default",
        actor: str = "worker",
        worker_id: str | None = None,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        with self._tx():
            attempt, _lease = self._check_lease(
                tenant, attempt_id, lease_token, worker_id=worker_id
            )
            if str(attempt["state"]) == AttemptState.RUNNING.value:
                result = self._row(attempt) or {}
                result["lease_token"] = lease_token
                return result
            job = self._job(tenant, str(attempt["job_id"]))
            if str(job["state"]) == JobState.PAUSED.value:
                raise InvalidTransition("cannot start an attempt while its job is paused")
            if str(job["state"]) != JobState.LEASED.value:
                raise InvalidTransition(
                    f"cannot start an attempt while job is {job['state']}"
                )
            self.conn.execute(
                """
                UPDATE durable_job_state_attempts SET state='running',started_at=?,version=version+1
                WHERE tenant_id=? AND id=?
                """,
                (self.clock(), tenant, attempt_id),
            )
            self._transition_tx(
                tenant,
                str(attempt["job_id"]),
                JobState.RUNNING.value,
                expected_version=int(job["version"]),
                actor=actor,
                reason="attempt started",
                idempotency_key=None,
                data={"attempt_id": attempt_id},
            )
            self._event(
                tenant,
                attempt["job_id"],
                "attempt_started",
                attempt_id=attempt_id,
                actor=actor,
                reason="attempt started",
            )
            result = self._row(self._attempt(tenant, attempt_id)) or {}
            result["lease_token"] = lease_token
            return result

    run_attempt = start_attempt

    def validate_lease(
        self,
        attempt_id: str,
        lease_token: str,
        *,
        tenant_id: str = "default",
        worker_id: str | None = None,
    ) -> bool:
        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        with self._lock:
            try:
                self._check_lease(tenant, attempt_id, lease_token, worker_id=worker_id)
            except (KeyError, LeaseError):
                return False
            return True

    def renew_lease(
        self,
        attempt_id: str,
        lease_token: str,
        lease_seconds: float = 60.0,
        *,
        tenant_id: str = "default",
        worker_id: str | None = None,
        actor: str = "worker",
    ) -> dict[str, Any]:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        with self._tx():
            attempt, lease = self._check_lease(
                tenant, attempt_id, lease_token, worker_id=worker_id
            )
            generation = int(lease["generation"]) + 1
            token = self._lease_token(tenant, attempt_id, generation)
            digest = _token_digest(token)
            expires = self.clock() + float(lease_seconds)
            self.conn.execute(
                """
                UPDATE durable_job_state_attempts SET lease_token_digest=?,lease_generation=?,
                    lease_expires_at=?,version=version+1
                WHERE tenant_id=? AND id=?
                """,
                (digest, generation, expires, tenant, attempt_id),
            )
            self.conn.execute(
                """
                UPDATE durable_job_state_leases SET token_digest=?,generation=?,expires_at=?
                WHERE tenant_id=? AND attempt_id=?
                """,
                (digest, generation, expires, tenant, attempt_id),
            )
            self._event(
                tenant,
                attempt["job_id"],
                "lease_renewed",
                attempt_id=attempt_id,
                actor=actor,
                reason="lease renewed",
                data={"generation": generation, "expires_at": expires},
            )
            result = self._row(self._attempt(tenant, attempt_id)) or {}
            result["lease_token"] = token
            result["token"] = token
            result["generation"] = generation
            return result

    renew = renew_lease

    def revoke_lease(
        self,
        attempt_id: str,
        *,
        tenant_id: str = "default",
        actor: str = "system",
        reason: str = "lease revoked",
    ) -> bool:
        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        with self._tx():
            attempt = self._attempt(tenant, attempt_id)
            lease = self.conn.execute(
                "SELECT * FROM durable_job_state_leases WHERE tenant_id=? AND attempt_id=?",
                (tenant, attempt_id),
            ).fetchone()
            if lease is None or lease["revoked_at"] is not None:
                return False
            now = self.clock()
            self.conn.execute(
                """
                UPDATE durable_job_state_leases SET revoked_at=?,revoke_reason=?,expires_at=?
                WHERE tenant_id=? AND attempt_id=?
                """,
                (now, reason, now, tenant, attempt_id),
            )
            self.conn.execute(
                """
                UPDATE durable_job_state_attempts SET state='orphaned',finished_at=?,
                    lease_token_digest=NULL,lease_expires_at=NULL,version=version+1
                WHERE tenant_id=? AND id=? AND state IN ('leased','running')
                """,
                (now, tenant, attempt_id),
            )
            job = self._job(tenant, attempt["job_id"])
            if str(job["state"]) in {JobState.LEASED.value, JobState.RUNNING.value}:
                self._transition_tx(
                    tenant,
                    attempt["job_id"],
                    JobState.ORPHANED.value,
                    expected_version=int(job["version"]),
                    actor=actor,
                    reason=reason,
                    idempotency_key=None,
                    data={"attempt_id": attempt_id},
                )
            self._event(
                tenant,
                attempt["job_id"],
                "lease_revoked",
                attempt_id=attempt_id,
                actor=actor,
                reason=reason,
            )
            return True

    def record_result(
        self,
        attempt_id: str,
        lease_token: str,
        *,
        delivery_key: str,
        tenant_id: str = "default",
        observation_id: str | None = None,
        result_ref: str | None = None,
        result_identity: str | None = None,
        work: Iterable[Mapping[str, Any]] = (),
        actor: str = "worker",
    ) -> dict[str, Any]:
        """Accept one attempt-scoped result exactly once."""

        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        delivery_key = _identifier(delivery_key, "delivery_key")
        materialized = _canonical_work_items(work)
        identity = result_identity or _identity(
            {
                "observation_id": observation_id,
                "result_ref": result_ref,
                "work": materialized,
            }
        )
        with self._tx():
            old = self.conn.execute(
                """
                SELECT * FROM durable_job_state_deliveries
                WHERE tenant_id=? AND attempt_id=? AND idempotency_key=?
                """,
                (tenant, attempt_id, delivery_key),
            ).fetchone()
            if old is not None:
                self._check_delivery_token(tenant, attempt_id, lease_token)
                if str(old["result_identity"]) != identity:
                    raise IdempotencyConflict(
                        "result delivery key was reused with different result material"
                    )
                return {
                    "accepted": True,
                    "duplicate": True,
                    "delivery_key": delivery_key,
                    "observation_id": old["observation_id"],
                    "result_identity": old["result_identity"],
                }
            attempt, _lease = self._check_lease(tenant, attempt_id, lease_token)
            if observation_id is not None and self.conn.execute(
                "SELECT 1 FROM durable_job_state_deliveries WHERE tenant_id=? AND observation_id=?",
                (tenant, observation_id),
            ).fetchone():
                prior_observation = self.conn.execute(
                    """
                    SELECT result_identity FROM durable_job_state_deliveries
                    WHERE tenant_id=? AND observation_id=?
                    """,
                    (tenant, observation_id),
                ).fetchone()
                if prior_observation is not None and str(
                    prior_observation["result_identity"]
                ) != identity:
                    raise IdempotencyConflict(
                        "observation was delivered with different result material"
                    )
                return {
                    "accepted": True,
                    "duplicate": True,
                    "delivery_key": delivery_key,
                    "observation_id": observation_id,
                    "result_identity": identity,
                }
            self.conn.execute(
                """
                INSERT INTO durable_job_state_deliveries(
                    tenant_id,attempt_id,idempotency_key,observation_id,result_ref,
                    result_identity,accepted_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    tenant,
                    attempt_id,
                    delivery_key,
                    observation_id,
                    result_ref,
                    identity,
                    self.clock(),
                ),
            )
            for item in materialized:
                self._mark_work_tx(
                    tenant,
                    attempt["job_id"],
                    str(item["work_key"]),
                    state=item.get("state", WorkState.COMPLETED.value),
                    required=bool(item.get("required", True)),
                    reason=item.get("reason"),
                    attempt_id=attempt_id,
                    observation_id=item.get("observation_id"),
                    result_ref=item.get("result_ref") or result_ref,
                    actor=actor,
                    accepted_delivery=True,
                )
            self._event(
                tenant,
                attempt["job_id"],
                "result_accepted",
                attempt_id=attempt_id,
                actor=actor,
                reason="idempotent result delivery accepted",
                data={
                    "delivery_key": delivery_key,
                    "observation_id": observation_id,
                    "result_identity": identity,
                },
            )
            return {
                "accepted": True,
                "duplicate": False,
                "delivery_key": delivery_key,
                "observation_id": observation_id,
                "result_identity": identity,
            }

    accept_result = record_result

    def has_accepted_result(
        self,
        attempt_id: str,
        *,
        tenant_id: str = "default",
    ) -> bool:
        """Return whether an attempt has a persisted result delivery.

        Process monitors use this read-only predicate to distinguish a worker
        result from a mere child-process exit.  It intentionally exposes no
        result bytes or lease capability.
        """

        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        with self._lock:
            self._attempt(tenant, attempt_id)
            return (
                self.conn.execute(
                    "SELECT 1 FROM durable_job_state_deliveries "
                    "WHERE tenant_id=? AND attempt_id=? LIMIT 1",
                    (tenant, attempt_id),
                ).fetchone()
                is not None
            )

    def latest_delivery(
        self,
        attempt_id: str,
        *,
        tenant_id: str = "default",
    ) -> dict[str, Any] | None:
        """Return the newest accepted delivery metadata for an attempt.

        Result bytes are intentionally not stored here.  The adapter uses the
        opaque reference/identity to recognize an exact redelivery after its
        compatibility projection has been rebuilt.
        """

        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        with self._lock:
            self._attempt(tenant, attempt_id)
            row = self.conn.execute(
                """
                SELECT idempotency_key,observation_id,result_ref,result_identity,accepted_at
                FROM durable_job_state_deliveries
                WHERE tenant_id=? AND attempt_id=?
                ORDER BY accepted_at DESC, idempotency_key DESC
                LIMIT 1
                """,
                (tenant, attempt_id),
            ).fetchone()
            return dict(row) if row is not None else None

    def finish_attempt(
        self,
        attempt_id: str,
        *,
        tenant_id: str = "default",
        success: bool = True,
        result: Any = None,
        result_ref: str | None = None,
        result_identity: str | None = None,
        error: str | None = None,
        error_reason: str | None = None,
        lease_token: str | None = None,
        coverage: int = 0,
        coverage_keys: Iterable[str] = (),
        skipped: Iterable[Mapping[str, Any]] = (),
        failed: Iterable[Mapping[str, Any]] = (),
        truncated: Iterable[Mapping[str, Any]] = (),
        uncollected: Iterable[Mapping[str, Any]] = (),
        delivery_key: str | None = None,
        terminal_reason: str | None = None,
        actor: str = "worker",
    ) -> dict[str, Any]:
        """Finish an attempt using accepted coverage, never process exit."""

        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        if lease_token is None:
            raise LeaseError("lease token is required")
        keys = [str(key).strip() for key in coverage_keys if str(key).strip()]
        if coverage and not keys:
            keys = [f"coverage:{index}" for index in range(int(coverage))]
        work: list[dict[str, Any]] = [
            {"work_key": key, "state": WorkState.COMPLETED.value} for key in keys
        ]
        work.extend({**dict(item), "state": WorkState.SKIPPED.value} for item in skipped)
        work.extend({**dict(item), "state": WorkState.FAILED.value} for item in failed)
        work.extend({**dict(item), "state": WorkState.TRUNCATED.value} for item in truncated)
        work.extend({**dict(item), "state": WorkState.UNCOLLECTED.value} for item in uncollected)
        work = _canonical_work_items(work)
        if result is not None and result_ref is None:
            raise ValueError(
                "result_ref must point to canonical observations or evidence"
            )
        identity = result_identity or (_identity(result) if result is not None else None)
        key = delivery_key or f"finish:{attempt_id}"
        delivery_identity = _identity(
            {
                "success": bool(success),
                "result_identity": identity,
                "result_ref": result_ref,
                "error_reason": error_reason or error,
                "terminal_reason": terminal_reason,
                "work": work,
            }
        )
        with self._tx():
            old = self.conn.execute(
                """
                SELECT * FROM durable_job_state_deliveries
                WHERE tenant_id=? AND attempt_id=? AND idempotency_key=?
                """,
                (tenant, attempt_id, key),
            ).fetchone()
            if old is not None:
                replay_attempt = self._check_delivery_token(
                    tenant, attempt_id, lease_token
                )
                if str(old["result_identity"]) != delivery_identity:
                    raise IdempotencyConflict(
                        "finish delivery key was reused with different result material"
                    )
                if str(replay_attempt["state"]) not in ACTIVE_ATTEMPT_STATES:
                    return self._row(replay_attempt) or {}
            attempt, _lease = self._check_lease(tenant, attempt_id, lease_token)
            if str(attempt["state"]) != AttemptState.RUNNING.value:
                raise InvalidTransition("an attempt must be started before it can finish")
            job_before = self._job(tenant, attempt["job_id"])
            if str(job_before["state"]) not in {
                JobState.RUNNING.value,
                JobState.PAUSED.value,
                JobState.CANCELING.value,
            }:
                raise InvalidTransition(
                    f"cannot finish an attempt while job is {job_before['state']}"
                )
            self.conn.execute(
                """
                INSERT INTO durable_job_state_deliveries(
                    tenant_id,attempt_id,idempotency_key,result_ref,
                    result_identity,accepted_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    tenant,
                    attempt_id,
                    key,
                    result_ref,
                    delivery_identity,
                    self.clock(),
                ),
            )
            for item in work:
                self._mark_work_tx(
                    tenant,
                    attempt["job_id"],
                    str(item["work_key"]),
                    state=item["state"],
                    required=bool(item.get("required", True)),
                    reason=item.get("reason"),
                    attempt_id=attempt_id,
                    observation_id=item.get("observation_id"),
                    result_ref=item.get("result_ref") or result_ref,
                    actor=actor,
                    accepted_delivery=True,
                )
            canceled = str(job_before["state"]) == JobState.CANCELING.value
            attempt_state = (
                AttemptState.CANCELED.value
                if canceled
                else (AttemptState.SUCCEEDED.value if success else AttemptState.FAILED.value)
            )
            now = self.clock()
            self.conn.execute(
                """
                UPDATE durable_job_state_attempts SET state=?,finished_at=?,result_ref=?,result_identity=?,
                    error_reason=?,lease_token_digest=NULL,lease_expires_at=NULL,
                    version=version+1
                WHERE tenant_id=? AND id=?
                """,
                (
                    attempt_state,
                    now,
                    result_ref,
                    identity,
                    error_reason or error,
                    tenant,
                    attempt_id,
                ),
            )
            self.conn.execute(
                """
                UPDATE durable_job_state_leases SET revoked_at=?,revoke_reason=?,expires_at=?
                WHERE tenant_id=? AND attempt_id=? AND revoked_at IS NULL
                """,
                (now, "attempt finished", now, tenant, attempt_id),
            )
            self._refresh_counters(tenant, attempt["job_id"])
            job = self._job(tenant, attempt["job_id"])
            unresolved_child = self.conn.execute(
                """
                SELECT 1 FROM durable_job_state_child_processes
                WHERE tenant_id=? AND job_id=? AND state IN ('running','orphaned')
                LIMIT 1
                """,
                (tenant, attempt["job_id"]),
            ).fetchone()
            if unresolved_child is not None:
                target = JobState.ORPHANED.value
                why = "attempt finished with an unresolved child process"
            elif str(job["state"]) == JobState.CANCELING.value:
                self._record_missing_required_work_tx(
                    tenant,
                    str(attempt["job_id"]),
                    reason=terminal_reason or "operator cancellation",
                    attempt_id=attempt_id,
                    actor=actor,
                )
                job = self._job(tenant, attempt["job_id"])
                target = (
                    JobState.PARTIAL.value
                    if any(
                        int(job[column]) > 0
                        for column in (
                            "completed_work",
                            "skipped_work",
                            "failed_work",
                            "truncated_work",
                        )
                    )
                    else JobState.CANCELED.value
                )
                why = terminal_reason or "operator cancellation"
            elif not success:
                target = (
                    JobState.QUEUED.value
                    if int(job["max_attempts"]) > int(attempt["number"])
                    else JobState.FAILED.value
                )
                why = terminal_reason or error_reason or error or "attempt failed"
                if target == JobState.FAILED.value:
                    self._record_missing_required_work_tx(
                        tenant,
                        str(attempt["job_id"]),
                        reason=why,
                        attempt_id=attempt_id,
                        actor=actor,
                    )
                    job = self._job(tenant, attempt["job_id"])
            else:
                blockers = self._completion_blockers(tenant, attempt["job_id"])
                target = JobState.COMPLETED.value if not blockers else JobState.PARTIAL.value
                why = terminal_reason or (
                    "completed" if target == JobState.COMPLETED.value else "partial coverage"
                )
                if target == JobState.PARTIAL.value:
                    self._record_missing_required_work_tx(
                        tenant,
                        str(attempt["job_id"]),
                        reason=why,
                        attempt_id=attempt_id,
                        actor=actor,
                    )
                    job = self._job(tenant, attempt["job_id"])
            if target != str(job["state"]):
                self._transition_tx(
                    tenant,
                    attempt["job_id"],
                    target,
                    expected_version=int(job["version"]),
                    actor=actor,
                    reason=why,
                    idempotency_key=None,
                    data={
                        "attempt_id": attempt_id,
                        "unresolved_child": unresolved_child is not None,
                    },
                    allow_completion=target == JobState.COMPLETED.value,
                )
            self._event(
                tenant,
                attempt["job_id"],
                "attempt_finished",
                attempt_id=attempt_id,
                actor=actor,
                reason=why,
                data={"success": bool(success), "state": attempt_state},
            )
            return self._row(self._attempt(tenant, attempt_id)) or {}

    complete_attempt = finish_attempt

    def retry_job(
        self,
        job_id: str,
        *,
        tenant_id: str = "default",
        actor: str = "system",
        reason: str = "retry requested",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._tx():
            row = self._job(tenant, job_id)
            if str(row["state"]) in {JobState.COMPLETED.value, JobState.CANCELED.value}:
                raise InvalidTransition("terminal job cannot be retried")
            if self._active_attempt(tenant, job_id) is not None:
                raise InvalidTransition("active attempt must finish before retry")
            if self.conn.execute(
                """
                SELECT 1 FROM durable_job_state_child_processes
                WHERE tenant_id=? AND job_id=? AND state IN ('running','orphaned')
                LIMIT 1
                """,
                (tenant, job_id),
            ).fetchone():
                raise InvalidTransition("unresolved child process must be recovered before retry")
            count = int(
                self.conn.execute(
                    "SELECT COUNT(*) FROM durable_job_state_attempts WHERE tenant_id=? AND job_id=?",
                    (tenant, job_id),
                ).fetchone()[0]
            )
            if count >= int(row["max_attempts"]):
                raise InvalidTransition("attempt limit exhausted")
            retry_key = _identifier(
                idempotency_key
                or f"retry:{job_id}:{count + 1}:{uuid.uuid4()}",
                "idempotency_key",
            )
            return self._transition_tx(
                tenant,
                job_id,
                JobState.QUEUED.value,
                expected_version=int(row["version"]),
                actor=actor,
                reason=reason,
                idempotency_key=retry_key,
                data={"attempt_number": count + 1},
            )

    def list_attempts(
        self, job_id: str, *, tenant_id: str = "default"
    ) -> list[dict[str, Any]]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._lock:
            return [
                self._row(row) or {}
                for row in self.conn.execute(
                    "SELECT * FROM durable_job_state_attempts WHERE tenant_id=? AND job_id=? ORDER BY number",
                    (tenant, job_id),
                ).fetchall()
            ]

    def append_log(
        self,
        job_id: str,
        message: str,
        *,
        tenant_id: str = "default",
        level: str = "info",
        attempt_id: str | None = None,
        data: Mapping[str, Any] | None = None,
        actor: str = "system",
    ) -> int:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._tx():
            self._job(tenant, job_id)
            if attempt_id is not None:
                attempt_id = _identifier(attempt_id, "attempt_id")
                attempt = self._attempt(tenant, attempt_id)
                if str(attempt["job_id"]) != job_id:
                    raise InvalidTransition("attempt does not belong to the job")
            cursor = self.conn.execute(
                """
                INSERT INTO durable_job_state_logs(
                    tenant_id,job_id,attempt_id,level,message,data_json,occurred_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    tenant,
                    job_id,
                    attempt_id,
                    str(level).lower(),
                    str(message)[:8000],
                    _json(dict(data or {})),
                    self.clock(),
                ),
            )
            self._event(
                tenant,
                job_id,
                "log_appended",
                attempt_id=attempt_id,
                actor=actor,
                reason="durable log",
            )
            if cursor.lastrowid is None:
                raise JobStateError("durable log was not assigned a sequence")
            return int(cursor.lastrowid)

    log = append_log

    def list_events(
        self, job_id: str, *, tenant_id: str = "default"
    ) -> list[dict[str, Any]]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._lock:
            result = []
            for row in self.conn.execute(
                "SELECT * FROM durable_job_state_events WHERE tenant_id=? AND job_id=? ORDER BY sequence",
                (tenant, job_id),
            ).fetchall():
                item = dict(row)
                item["data"] = _decode(item.pop("data_json"), {})
                result.append(item)
            return result

    events = list_events

    def list_logs(
        self, job_id: str, *, tenant_id: str = "default"
    ) -> list[dict[str, Any]]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._lock:
            result = []
            for row in self.conn.execute(
                "SELECT * FROM durable_job_state_logs WHERE tenant_id=? AND job_id=? ORDER BY sequence",
                (tenant, job_id),
            ).fetchall():
                item = dict(row)
                item["data"] = _decode(item.pop("data_json"), {})
                result.append(item)
            return result

    def create_child(
        self,
        parent_id: str,
        identity_key: str,
        payload: Mapping[str, Any] | None = None,
        *,
        tenant_id: str = "default",
        required: bool = True,
        **kwargs: Any,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        parent_id = _identifier(parent_id, "parent_id")
        identity_key = _identifier(identity_key, "identity_key")
        with self._tx():
            parent = self._job(tenant, parent_id)
            if str(parent["state"]) in TERMINAL_STATES:
                raise TerminalStateError(
                    f"cannot add a child to terminal job state {parent['state']}"
                )
            old = self.conn.execute(
                """
                SELECT j.* FROM durable_job_state_children c JOIN durable_job_state_jobs j
                  ON j.tenant_id=c.tenant_id AND j.id=c.child_id
                WHERE c.tenant_id=? AND c.parent_id=? AND c.identity_key=?
                """,
                (tenant, parent_id, identity_key),
            ).fetchone()
            if old is not None:
                return self._row(old) or {}
            child_id = _identifier(kwargs.pop("job_id", None) or str(uuid.uuid4()), "job_id")
            child_state = _state(kwargs.pop("state", JobState.PLANNED.value))
            if child_state not in {
                JobState.PLANNED.value,
                JobState.PENDING_APPROVAL.value,
                JobState.QUEUED.value,
            }:
                raise InvalidTransition(
                    "new child jobs must start planned, pending_approval, or queued"
                )
            child_idempotency_key = kwargs.pop("idempotency_key", None)
            if child_idempotency_key is not None:
                child_idempotency_key = _identifier(
                    child_idempotency_key, "idempotency_key"
                )
            child_max_attempts = int(kwargs.pop("max_attempts", 1))
            child_required_work = int(
                kwargs.pop("coverage_required", kwargs.pop("required_work", 0))
            )
            if child_max_attempts < 1 or child_required_work < 0:
                raise ValueError("invalid required_work or max_attempts")
            child = self._create_job_tx(
                tenant=tenant,
                job_id=child_id,
                payload=dict(payload or {}),
                idempotency_key=child_idempotency_key,
                parent_id=parent_id,
                max_attempts=child_max_attempts,
                required_work=child_required_work,
                state=child_state,
                metadata=dict(kwargs.pop("metadata", {})),
                actor=str(kwargs.pop("actor", "system")),
                reason=str(kwargs.pop("reason", "child planned")),
            )
            if kwargs:
                raise TypeError(f"unknown child options: {', '.join(sorted(kwargs))}")
            self._link_child_tx(
                tenant,
                parent_id,
                child_id,
                identity_key=identity_key,
                required=required,
                actor="system",
            )
            return child

    def children(
        self, parent_id: str, *, tenant_id: str = "default"
    ) -> list[dict[str, Any]]:
        tenant = _tenant(tenant_id)
        parent_id = _identifier(parent_id, "parent_id")
        with self._lock:
            return [
                self._row(row) or {}
                for row in self.conn.execute(
                    """
                    SELECT j.*,c.identity_key,c.required AS child_required
                    FROM durable_job_state_children c JOIN durable_job_state_jobs j
                      ON j.tenant_id=c.tenant_id AND j.id=c.child_id
                    WHERE c.tenant_id=? AND c.parent_id=? ORDER BY c.created_at
                    """,
                    (tenant, parent_id),
                ).fetchall()
            ]

    def register_process(
        self,
        job_id: str,
        attempt_id: str,
        identity: ProcessIdentity | Mapping[str, Any],
        *,
        tenant_id: str = "default",
        identity_key: str = "main",
        actor: str = "worker",
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        attempt_id = _identifier(attempt_id, "attempt_id")
        process = ProcessIdentity.from_value(identity)
        with self._tx():
            attempt = self._attempt(tenant, attempt_id)
            if str(attempt["job_id"]) != job_id:
                raise ProcessIdentityError("attempt does not belong to job")
            if str(attempt["state"]) not in ACTIVE_ATTEMPT_STATES:
                raise ProcessIdentityError("process must belong to an active attempt")
            identity_key = _identifier(identity_key, "identity_key")
            old = self.conn.execute(
                """
                SELECT * FROM durable_job_state_child_processes
                WHERE tenant_id=? AND attempt_id=? AND identity_key=?
                """,
                (tenant, attempt_id, identity_key),
            ).fetchone()
            if old is not None:
                same = (
                    int(old["pid"]) == process.pid
                    and str(old["start_token"]) == process.start_token
                    and str(old["boot_id"]) == process.boot_id
                    and str(old["command_digest"]) == process.command_digest
                )
                if not same:
                    raise ProcessIdentityError(
                        "process identity key is already bound to another process"
                    )
                return process.to_dict()
            self.conn.execute(
                """
                INSERT INTO durable_job_state_child_processes(
                    tenant_id,job_id,attempt_id,identity_key,pid,start_token,
                    boot_id,command_digest,state
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    tenant,
                    job_id,
                    attempt_id,
                    identity_key,
                    process.pid,
                    process.start_token,
                    process.boot_id,
                    process.command_digest,
                    "running",
                ),
            )
            self.conn.execute(
                "UPDATE durable_job_state_attempts SET process_identity_json=? WHERE tenant_id=? AND id=?",
                (_json(process.to_dict()), tenant, attempt_id),
            )
            self._event(
                tenant,
                job_id,
                "child_registered",
                attempt_id=attempt_id,
                actor=actor,
                reason="child process identity persisted",
                data={"pid": process.pid, "identity_key": identity_key},
            )
            return process.to_dict()

    def record_process_exit(
        self,
        job_id: str,
        attempt_id: str,
        identity: ProcessIdentity | Mapping[str, Any],
        *,
        tenant_id: str = "default",
        identity_key: str = "main",
        reason: str = "child process exited",
        actor: str = "worker",
    ) -> dict[str, Any]:
        """Persist a verified child exit without trusting a PID by itself."""

        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        attempt_id = _identifier(attempt_id, "attempt_id")
        identity_key = _identifier(identity_key, "identity_key")
        process = ProcessIdentity.from_value(identity)
        with self._tx():
            attempt = self._attempt(tenant, attempt_id)
            if str(attempt["job_id"]) != job_id:
                raise ProcessIdentityError("attempt does not belong to job")
            stored = self.conn.execute(
                """
                SELECT * FROM durable_job_state_child_processes
                WHERE tenant_id=? AND attempt_id=? AND identity_key=?
                """,
                (tenant, attempt_id, identity_key),
            ).fetchone()
            if stored is None:
                raise ProcessIdentityError("child process identity is not registered")
            same = (
                int(stored["pid"]) == process.pid
                and str(stored["start_token"]) == process.start_token
                and str(stored["boot_id"]) == process.boot_id
                and str(stored["command_digest"]) == process.command_digest
            )
            if not same:
                raise ProcessIdentityError("child process identity mismatch")
            if str(stored["state"]) == "stopped":
                return process.to_dict()
            self.conn.execute(
                """
                UPDATE durable_job_state_child_processes SET state='stopped',stopped_at=?
                WHERE tenant_id=? AND attempt_id=? AND identity_key=?
                """,
                (self.clock(), tenant, attempt_id, identity_key),
            )
            self._event(
                tenant,
                job_id,
                "child_exited",
                attempt_id=attempt_id,
                actor=actor,
                reason=reason,
                data={"identity_key": identity_key, "pid": process.pid},
            )
            return process.to_dict()

    mark_process_stopped = record_process_exit
    complete_process = record_process_exit

    def reconcile(
        self,
        *,
        tenant_id: str | None = None,
        requeue_expired: bool = True,
        actor: str = "reconciler",
    ) -> list[str]:
        """Reconcile expired durable_job_state_leases and uncertain workers after restart."""

        tenant_filter = _tenant(tenant_id) if tenant_id is not None else None
        changed: list[str] = []
        with self._tx():
            # Child ownership is durable, but a PID is not an identity.  On
            # restart validate the complete identity through the injected
            # supervisor; without one, preserve uncertainty as orphaned work.
            process_query = """
                SELECT * FROM durable_job_state_child_processes
                WHERE state='running'
            """
            process_params: list[Any] = []
            if tenant_filter is not None:
                process_query += " AND tenant_id=?"
                process_params.append(tenant_filter)
            for process in self.conn.execute(process_query, process_params).fetchall():
                process_identity = ProcessIdentity(
                    pid=int(process["pid"]),
                    start_token=str(process["start_token"]),
                    boot_id=str(process["boot_id"]),
                    command_digest=str(process["command_digest"]),
                )
                alive = False
                identity_error: str | None = None
                if self.process_supervisor is not None:
                    try:
                        alive = bool(self.process_supervisor.is_alive(process_identity))
                    except Exception as exc:
                        identity_error = type(exc).__name__
                else:
                    identity_error = "no_process_supervisor"
                if alive:
                    continue
                next_process_state = "stopped" if identity_error is None else "orphaned"
                tenant = str(process["tenant_id"])
                now = self.clock()
                self.conn.execute(
                    """
                    UPDATE durable_job_state_child_processes SET state=?,stopped_at=?
                    WHERE tenant_id=? AND attempt_id=? AND identity_key=? AND state='running'
                    """,
                    (
                        next_process_state,
                        now if next_process_state == "stopped" else None,
                        tenant,
                        process["attempt_id"],
                        process["identity_key"],
                    ),
                )
                attempt = self._attempt(tenant, str(process["attempt_id"]))
                if str(attempt["state"]) in ACTIVE_ATTEMPT_STATES:
                    self.conn.execute(
                        """
                        UPDATE durable_job_state_attempts SET state='orphaned',finished_at=?,
                            lease_token_digest=NULL,lease_expires_at=NULL,version=version+1
                        WHERE tenant_id=? AND id=? AND state IN ('leased','running')
                        """,
                        (now, tenant, process["attempt_id"]),
                    )
                    self.conn.execute(
                        """
                        UPDATE durable_job_state_leases SET revoked_at=COALESCE(revoked_at,?),
                            revoke_reason=COALESCE(revoke_reason,?),expires_at=?
                        WHERE tenant_id=? AND attempt_id=?
                        """,
                        (
                            now,
                            "child process unavailable after restart",
                            now,
                            tenant,
                            process["attempt_id"],
                        ),
                    )
                    job = self._job(tenant, str(process["job_id"]))
                    if str(job["state"]) in {
                        JobState.LEASED.value,
                        JobState.RUNNING.value,
                        JobState.PAUSED.value,
                        JobState.CANCELING.value,
                    }:
                        self._transition_tx(
                            tenant,
                            str(process["job_id"]),
                            JobState.ORPHANED.value,
                            expected_version=int(job["version"]),
                            actor=actor,
                            reason="child process unavailable after restart",
                            idempotency_key=None,
                            data={
                                "identity_key": process["identity_key"],
                                "state": next_process_state,
                                "error": identity_error,
                            },
                        )
                    self._event(
                        tenant,
                        str(process["job_id"]),
                        "child_reconciled",
                        attempt_id=str(process["attempt_id"]),
                        actor=actor,
                        reason="child process unavailable after restart",
                        data={
                            "identity_key": process["identity_key"],
                            "state": next_process_state,
                            "error": identity_error,
                        },
                    )
                    changed.append(str(process["attempt_id"]))

            # Do not requeue a job while the supervisor confirms that an old
            # child is still alive.  Its lease is no longer valid, so the
            # safest truthful state is orphaned work that needs recovery or
            # an explicit cancellation, never a second active attempt.
            live_process_attempts: set[tuple[str, str]] = set()
            if self.process_supervisor is not None:
                for process in self.conn.execute(process_query, process_params).fetchall():
                    try:
                        identity = ProcessIdentity(
                            pid=int(process["pid"]),
                            start_token=str(process["start_token"]),
                            boot_id=str(process["boot_id"]),
                            command_digest=str(process["command_digest"]),
                        )
                        if self.process_supervisor.is_alive(identity):
                            live_process_attempts.add(
                                (str(process["tenant_id"]), str(process["attempt_id"]))
                            )
                    except Exception:
                        # The first reconciliation pass above turns an
                        # unverifiable process into explicit orphaned work.
                        continue

            query = """
                SELECT a.*,l.expires_at
                FROM durable_job_state_attempts a JOIN durable_job_state_leases l
                  ON l.tenant_id=a.tenant_id AND l.attempt_id=a.id
                WHERE a.state IN ('leased','running') AND l.expires_at<=?
            """
            params: list[Any] = [self.clock()]
            if tenant_filter is not None:
                query += " AND a.tenant_id=?"
                params.append(tenant_filter)
            for attempt in self.conn.execute(query, params).fetchall():
                tenant = str(attempt["tenant_id"])
                attempt_id = str(attempt["id"])
                job_id = str(attempt["job_id"])
                now = self.clock()
                job = self._job(tenant, job_id)
                live_child = (tenant, attempt_id) in live_process_attempts
                next_attempt_state = (
                    AttemptState.ORPHANED.value if live_child else AttemptState.EXPIRED.value
                )
                revoke_reason = (
                    "lease expired while child process was still alive"
                    if live_child
                    else "lease expired"
                )
                self.conn.execute(
                    """
                    UPDATE durable_job_state_attempts SET state=?,finished_at=?,lease_token_digest=NULL,
                        lease_expires_at=NULL,version=version+1
                    WHERE tenant_id=? AND id=? AND state IN ('leased','running')
                    """,
                    (next_attempt_state, now, tenant, attempt_id),
                )
                self.conn.execute(
                    """
                    UPDATE durable_job_state_leases SET revoked_at=COALESCE(revoked_at,?),
                        revoke_reason=COALESCE(revoke_reason,?),expires_at=?
                    WHERE tenant_id=? AND attempt_id=?
                    """,
                    (now, revoke_reason, now, tenant, attempt_id),
                )
                current = str(job["state"])
                target: str | None = None
                if live_child:
                    if current in {
                        JobState.LEASED.value,
                        JobState.RUNNING.value,
                        JobState.PAUSED.value,
                        JobState.CANCELING.value,
                    }:
                        target = JobState.ORPHANED.value
                elif current in {JobState.LEASED.value, JobState.RUNNING.value}:
                    target = (
                        JobState.QUEUED.value
                        if requeue_expired and int(job["max_attempts"]) > int(attempt["number"])
                        else JobState.EXPIRED.value
                    )
                elif current == JobState.CANCELING.value:
                    target = JobState.CANCELED.value
                # A paused job remains paused after an idle lease expires.
                # Resume will return it to queued without silently starting
                # new work.
                if target is not None:
                    self._transition_tx(
                        tenant,
                        job_id,
                        target,
                        expected_version=int(job["version"]),
                        actor=actor,
                        reason=revoke_reason,
                        idempotency_key=None,
                        data={"attempt_id": attempt_id, "live_child": live_child},
                    )
                self._event(
                    tenant,
                    job_id,
                    "lease_expired",
                    attempt_id=attempt_id,
                    actor=actor,
                    reason=revoke_reason,
                    data={"live_child": live_child},
                )
                changed.append(attempt_id)

            query = """
                SELECT j.* FROM durable_job_state_jobs j
                WHERE j.state IN ('leased','running')
                  AND NOT EXISTS (
                    SELECT 1 FROM durable_job_state_attempts a
                    WHERE a.tenant_id=j.tenant_id AND a.job_id=j.id
                      AND a.state IN ('leased','running')
                  )
            """
            params = []
            if tenant_filter is not None:
                query += " AND j.tenant_id=?"
                params.append(tenant_filter)
            for job in self.conn.execute(query, params).fetchall():
                self._transition_tx(
                    str(job["tenant_id"]),
                    str(job["id"]),
                    JobState.ORPHANED.value,
                    expected_version=int(job["version"]),
                    actor=actor,
                    reason="running job has no active attempt after restart",
                    idempotency_key=None,
                    data={},
                )
                changed.append(str(job["id"]))

            # A restart can occur after the cancel request is durable but
            # before the worker has acknowledged it.  Once no active attempt
            # remains, resolve it deterministically rather than leaving an
            # unbounded canceling state forever.
            query = """
                SELECT j.* FROM durable_job_state_jobs j
                WHERE j.state='canceling'
                  AND NOT EXISTS (
                    SELECT 1 FROM durable_job_state_attempts a
                    WHERE a.tenant_id=j.tenant_id AND a.job_id=j.id
                      AND a.state IN ('leased','running')
                  )
            """
            params = []
            if tenant_filter is not None:
                query += " AND j.tenant_id=?"
                params.append(tenant_filter)
            for job in self.conn.execute(query, params).fetchall():
                unresolved = self.conn.execute(
                    """
                    SELECT 1 FROM durable_job_state_child_processes
                    WHERE tenant_id=? AND job_id=? AND state IN ('running','orphaned')
                    LIMIT 1
                    """,
                    (job["tenant_id"], job["id"]),
                ).fetchone()
                target = (
                    JobState.ORPHANED.value if unresolved is not None else JobState.CANCELED.value
                )
                self._transition_tx(
                    str(job["tenant_id"]),
                    str(job["id"]),
                    target,
                    expected_version=int(job["version"]),
                    actor=actor,
                    reason=(
                        "cancellation left an unresolved child after restart"
                        if unresolved is not None
                        else "cancellation reconciled after restart"
                    ),
                    idempotency_key=None,
                    data={"restart_reconciliation": True},
                )
                changed.append(str(job["id"]))
        return changed

    recover = reconcile
    reconcile_restart = reconcile


DurableJobStore = JobStateService
JobStore = JobStateService
JobStateMachine = JobStateService
TransitionService = JobStateService


__all__ = [
    "ACTIVE_ATTEMPT_STATES",
    "AttemptState",
    "DurableJobStore",
    "IdempotencyConflict",
    "InvalidTransition",
    "JobState",
    "JobStateError",
    "JobStateMachine",
    "JobStateService",
    "JobStore",
    "LeaseError",
    "LeaseUnavailable",
    "ProcessIdentity",
    "ProcessIdentityError",
    "ProcessSupervisor",
    "TERMINAL_STATES",
    "TerminalStateError",
    "TRANSITION_TABLE_VERSION",
    "TransitionService",
    "WorkState",
    "allowed_transitions",
    "process_identity",
    "transition_table",
]
