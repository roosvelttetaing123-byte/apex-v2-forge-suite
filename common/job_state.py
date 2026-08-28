"""Transactional single-node job, attempt, lease, and event authority.

This module owns control-plane state only.  Observation/evidence bytes remain
owned by the canonical Task 101/102 stores; result submissions contain opaque
references and identities, never a second result store.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Protocol, cast

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from common.db import (
    PersistedRunTruthValidationError,
    create_db,
    load_run_collection_truth,
)
from common.redaction import redact_value
from common.schema_migrations import (
    CANONICAL_SCHEMA_VERSION,
    JOB_STATE_SCHEMA_VERSION,
)
from common.run_truth import (
    RunCollectionStatus,
    RunCollectionTruth,
    run_collection_truth_attestation_payload,
)


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
    PAUSED = "paused"
    CANCELING = "canceling"
    COMPLETED = "completed"
    SUCCEEDED = COMPLETED
    PARTIAL = "partial"
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
    {
        AttemptState.LEASED.value,
        AttemptState.RUNNING.value,
        AttemptState.PAUSED.value,
        AttemptState.CANCELING.value,
    }
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

    def pause(self, identity: "ProcessIdentity") -> None: ...

    def resume(self, identity: "ProcessIdentity") -> None: ...

    def discover(self, launch_nonce: str) -> "ProcessIdentity | None": ...


@dataclass(frozen=True)
class TransitionActor:
    """Authenticated actor bound to one tenant and optional authorization."""

    tenant_id: str
    actor_id: str
    role: str
    authorization_decision_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _tenant(self.tenant_id))
        object.__setattr__(self, "actor_id", _identifier(self.actor_id, "actor_id"))
        object.__setattr__(self, "role", _identifier(self.role, "actor_role"))
        if self.authorization_decision_id is not None:
            object.__setattr__(
                self,
                "authorization_decision_id",
                _identifier(
                    self.authorization_decision_id,
                    "authorization_decision_id",
                ),
            )


@dataclass(frozen=True)
class ObservationReceipt:
    """Verified Task 102 observation/artifact receipt for one attempt."""

    tenant_id: str
    job_id: str
    attempt_id: str
    observation_id: str
    artifact_id: str
    result_ref: str
    manifest_digest: str

    def __post_init__(self) -> None:
        for field_name in (
            "tenant_id",
            "job_id",
            "attempt_id",
            "observation_id",
            "artifact_id",
            "result_ref",
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), field_name),
            )
        if not (
            isinstance(self.manifest_digest, str)
            and self.manifest_digest.startswith("sha256:")
            and len(self.manifest_digest) == 71
        ):
            raise ValueError("manifest_digest must be a SHA-256 reference")


@dataclass(frozen=True)
class RunTruthReceipt:
    """Verified immutable run-truth material bound to one attempt result."""

    tenant_id: str
    job_id: str
    attempt_id: str
    run_id: str
    authorization_run_id: str
    framework: str
    authorization_decision_id: str
    proof_identity: str
    coverage_identity: str
    result_ref: str
    outcome: str
    collection_status: str
    coverage_complete: bool

    def __post_init__(self) -> None:
        for field_name in (
            "tenant_id",
            "job_id",
            "attempt_id",
            "run_id",
            "authorization_run_id",
            "framework",
            "authorization_decision_id",
            "result_ref",
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), field_name),
            )
        for field_name in ("proof_identity", "coverage_identity"):
            value = getattr(self, field_name)
            if not (
                isinstance(value, str)
                and value.startswith("sha256:")
                and len(value) == 71
            ):
                raise ValueError(f"{field_name} must be a SHA-256 reference")
        if self.outcome not in {"success", "failure", "canceled", "partial"}:
            raise ValueError("run-truth outcome is invalid")
        try:
            RunCollectionStatus(self.collection_status)
        except ValueError:
            raise ValueError("run-truth collection status is invalid") from None
        if type(self.coverage_complete) is not bool:
            raise ValueError("run-truth coverage_complete must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "job_id": self.job_id,
            "attempt_id": self.attempt_id,
            "run_id": self.run_id,
            "authorization_run_id": self.authorization_run_id,
            "framework": self.framework,
            "authorization_decision_id": self.authorization_decision_id,
            "proof_identity": self.proof_identity,
            "coverage_identity": self.coverage_identity,
            "result_ref": self.result_ref,
            "outcome": self.outcome,
            "collection_status": self.collection_status,
            "coverage_complete": self.coverage_complete,
        }


@dataclass(frozen=True)
class ProcessIdentity:
    """PID plus start/command identity; a PID alone is never sufficient."""

    pid: int
    start_token: str
    command_digest: str
    boot_id: str = ""
    launch_nonce: str = ""

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid <= 0:
            raise ProcessIdentityError("a positive pid is required")
        if not self.start_token or "\x00" in self.start_token:
            raise ProcessIdentityError("a process start token is required")
        if len(self.command_digest) < 16:
            raise ProcessIdentityError("a command identity digest is required")
        if self.launch_nonce and "\x00" in self.launch_nonce:
            raise ProcessIdentityError("process launch nonce is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "start_token": self.start_token,
            "command_digest": self.command_digest,
            "boot_id": self.boot_id,
            "launch_nonce": self.launch_nonce,
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
            launch_nonce=str(value.get("launch_nonce") or ""),
        )


def process_identity(
    pid: int,
    *,
    start_token: str,
    command: str,
    boot_id: str = "",
    launch_nonce: str = "",
) -> ProcessIdentity:
    """Construct an identity while retaining only a command digest."""

    return ProcessIdentity(
        pid=pid,
        start_token=start_token,
        boot_id=boot_id,
        command_digest=hashlib.sha256(command.encode("utf-8")).hexdigest(),
        launch_nonce=launch_nonce,
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
            JobState.PENDING_APPROVAL.value,
            JobState.LEASED.value,
            JobState.PAUSED.value,
            JobState.CANCELING.value,
            JobState.CANCELED.value,
        }
    ),
    JobState.LEASED.value: frozenset(
        {
            JobState.PENDING_APPROVAL.value,
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
            JobState.PENDING_APPROVAL.value,
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
            JobState.PLANNED.value,
            JobState.PENDING_APPROVAL.value,
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
    JobState.PARTIAL.value: frozenset(),
    JobState.FAILED.value: frozenset(),
    JobState.COMPLETED.value: frozenset(),
    JobState.CANCELED.value: frozenset(),
}


def _state(value: str | JobState) -> str:
    raw = value.value if isinstance(value, JobState) else str(value).strip().lower()
    return _STATE_ALIASES.get(raw, raw)


def _canonical_job_status(target: str, previous: str) -> str:
    """Map the richer Task 103 state onto the Task 101 compatibility field."""

    if target in {
        JobState.PLANNED.value,
        JobState.PENDING_APPROVAL.value,
        JobState.QUEUED.value,
        JobState.RUNNING.value,
        JobState.FAILED.value,
        JobState.PARTIAL.value,
        JobState.COMPLETED.value,
    }:
        return target
    if target == JobState.PAUSED.value and previous in {
        JobState.PLANNED.value,
        JobState.PENDING_APPROVAL.value,
        JobState.QUEUED.value,
    }:
        return previous
    if target in {
        JobState.LEASED.value,
        JobState.PAUSED.value,
        JobState.CANCELING.value,
    }:
        return JobState.RUNNING.value
    return JobState.FAILED.value


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


def _reason_code(value: Any) -> str:
    """Return a stable, bounded machine-readable reason code."""

    rendered = re.sub(
        r"[^a-z0-9]+",
        "_",
        str(value or "unspecified").strip().lower(),
    ).strip("_")
    return (rendered or "unspecified")[:100]


def _json(value: Any, *, limit: int = 1_000_000) -> str:
    result = json.dumps(
        redact_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=str,
    )
    if len(result.encode("utf-8")) > limit:
        raise ValueError("durable metadata exceeds size limit")
    return result


def _authority_json(value: Any, *, limit: int = 1_000_000) -> str:
    """Serialize owner-private control material without corrupting signatures."""

    result = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    if len(result.encode("utf-8")) > limit:
        raise ValueError("authority JSON value exceeds the durable store limit")
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


def _iso_timestamp(value: float) -> str:
    return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()


def _actor(
    value: str | TransitionActor,
    *,
    tenant_id: str,
    default_role: str,
) -> TransitionActor:
    if isinstance(value, TransitionActor):
        if value.tenant_id != tenant_id:
            raise InvalidTransition("actor tenant does not match job tenant")
        return value
    actor_id = _identifier(value, "actor")
    role = default_role
    if actor_id in {"operator", "admin", "worker", "agent", "system"}:
        role = actor_id
    return TransitionActor(
        tenant_id=tenant_id,
        actor_id=actor_id,
        role=role,
    )


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


def _result_delivery_identity(
    receipt: ObservationReceipt,
    *,
    work: Iterable[Mapping[str, Any]],
    outcome: str,
    run_truths: Iterable[RunTruthReceipt] = (),
) -> tuple[str, list[dict[str, Any]]]:
    """Return one canonical identity for custody reservation and acceptance."""

    materialized = _canonical_work_items(work)
    truth_receipts = _canonical_run_truth_receipts(run_truths)
    identity = _identity(
        {
            "receipt": {
                "tenant_id": receipt.tenant_id,
                "job_id": receipt.job_id,
                "attempt_id": receipt.attempt_id,
                "observation_id": receipt.observation_id,
                "artifact_id": receipt.artifact_id,
                "result_ref": receipt.result_ref,
                "manifest_digest": receipt.manifest_digest,
            },
            "work": materialized,
            "outcome": outcome,
            "run_truths": [item.to_dict() for item in truth_receipts],
        }
    )
    return identity, materialized


def _run_truth_outcome(truth: RunCollectionTruth) -> str:
    if (
        truth.collection_status is RunCollectionStatus.SUCCESS
        and truth.coverage_complete
    ):
        return "success"
    if truth.collection_status is RunCollectionStatus.CANCELED:
        return "canceled"
    if truth.collection_status in {
        RunCollectionStatus.FAILED,
        RunCollectionStatus.COLLECTION_ERROR,
        RunCollectionStatus.UNAUTHORIZED,
    }:
        return "failure"
    return "partial"


def _run_truth_receipt(
    truth: RunCollectionTruth,
    *,
    tenant_id: str,
    job_id: str,
    attempt_id: str,
) -> RunTruthReceipt:
    proof_identity = "sha256:" + hashlib.sha256(
        run_collection_truth_attestation_payload(truth)
        + truth.attestation.encode("ascii")
    ).hexdigest()
    return RunTruthReceipt(
        tenant_id=tenant_id,
        job_id=job_id,
        attempt_id=attempt_id,
        run_id=truth.run_id,
        authorization_run_id=truth.authorization_run_id,
        framework=truth.framework,
        authorization_decision_id=truth.authorization_decision_id,
        proof_identity=proof_identity,
        coverage_identity=truth.coverage_identity,
        result_ref=f"run-truth:{truth.run_id}",
        outcome=_run_truth_outcome(truth),
        collection_status=truth.collection_status.value,
        coverage_complete=truth.coverage_complete,
    )


def _canonical_run_truth_receipts(
    values: Iterable[RunTruthReceipt],
) -> list[RunTruthReceipt]:
    receipts = list(values)
    if any(not isinstance(item, RunTruthReceipt) for item in receipts):
        raise ValueError("run truth must use typed receipts")
    identities = {(item.framework, item.run_id) for item in receipts}
    if len(identities) != len(receipts):
        raise IdempotencyConflict("run-truth receipt identity is duplicated")
    frameworks = {item.framework for item in receipts}
    if len(frameworks) != len(receipts):
        raise IdempotencyConflict("multiple run truths claim one framework")
    return sorted(receipts, key=lambda item: (item.framework, item.run_id))


def _aggregate_run_truth_outcome(values: Iterable[RunTruthReceipt]) -> str:
    receipts = _canonical_run_truth_receipts(values)
    if not receipts:
        raise ValueError("at least one run-truth receipt is required")
    outcomes = {item.outcome for item in receipts}
    if outcomes == {"success"}:
        return "success"
    if "failure" in outcomes:
        return "failure"
    if outcomes == {"canceled"}:
        return "canceled"
    return "partial"


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
        authorization_checker: (
            Callable[[str, str, str, str], bool] | None
        ) = None,
        observation_checker: Callable[[ObservationReceipt], bool] | None = None,
    ) -> None:
        self.db_path = str(db_path)
        if self.db_path == ":memory:":
            raise ValueError(
                "Task 103 requires a file-backed temporary database; use an isolated path"
            )
        self.clock = clock or _now
        self.process_supervisor = process_supervisor
        self.authorization_checker = authorization_checker
        self.observation_checker = observation_checker
        self._lock = threading.RLock()
        # ``create_db`` owns descriptor-safe SQLite creation and applies the
        # ordered Task 101/102/103 migration chain.  The retained bootstrap
        # session owns the private engine lifetime; operations use a pooled
        # DB-API connection from that exact verified engine.
        self._bootstrap_session = create_db(Path(self.db_path))
        bind = self._bootstrap_session.get_bind()
        if bind is None:
            self._bootstrap_session.close()
            raise JobStateError("durable job database engine is unavailable")
        engine = bind.engine if isinstance(bind, Connection) else bind
        self._pooled_connection = engine.raw_connection()
        driver_connection = self._pooled_connection.driver_connection
        if not isinstance(driver_connection, sqlite3.Connection):
            self._pooled_connection.close()
            self._bootstrap_session.close()
            raise JobStateError("durable SQLite connection is unavailable")
        self.conn: sqlite3.Connection = driver_connection
        self._closed = False
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=10000")
        self._verify_schema()
        self._lease_secret = self._load_lease_secret()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._pooled_connection.close()
            self._bootstrap_session.close()
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

    def _verify_schema(self) -> None:
        """Require the canonical migration layer's exact Task 103 schema."""

        row = self.conn.execute(
            "SELECT state FROM canonical_migration_journal WHERE version=?",
            (JOB_STATE_SCHEMA_VERSION,),
        ).fetchone()
        if row is None or str(row["state"]) != "applied":
            raise JobStateError("Task 103 job-state migration is not applied")
        required = {
            "durable_job_state_agents",
            "durable_job_state_jobs",
            "durable_job_state_job_authorizations",
            "durable_job_state_attempts",
            "durable_job_state_leases",
            "durable_job_state_events",
            "durable_job_state_logs",
            "durable_job_state_work_plan",
            "durable_job_state_work_items",
            "durable_job_state_deliveries",
            "durable_job_state_terminal_proofs",
            "durable_job_state_child_processes",
            "durable_job_state_launch_intents",
        }
        actual = {
            str(item[0])
            for item in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if not required <= actual:
            raise JobStateError("Task 103 job-state schema is incomplete")
        required_columns = {
            "durable_job_state_jobs": {
                "tenant_id",
                "id",
                "state",
                "version",
                "control_version",
                "terminal_reason_code",
            },
            "durable_job_state_attempts": {
                "tenant_id",
                "id",
                "job_id",
                "delivery_idempotency_key",
                "launch_nonce",
                "control_boot_id",
                "lease_max_expires_at",
                "error_reason_code",
            },
            "durable_job_state_job_authorizations": {
                "tenant_id",
                "job_id",
                "authorization_decision_id",
                "framework",
                "generation",
                "active",
            },
            "durable_job_state_events": {
                "sequence",
                "tenant_id",
                "job_id",
                "actor_role",
                "reason_code",
                "job_version",
            },
            "durable_job_state_deliveries": {
                "tenant_id",
                "attempt_id",
                "job_id",
                "state",
                "manifest_digest",
                "outcome",
                "work_json",
                "run_truth_json",
            },
            "durable_job_state_child_processes": {
                "tenant_id",
                "attempt_id",
                "launch_nonce",
                "pid",
                "start_token",
                "boot_id",
                "command_digest",
            },
        }
        for table, columns in required_columns.items():
            actual_columns = {
                str(item[1])
                for item in self.conn.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }
            if not columns <= actual_columns:
                raise JobStateError(
                    f"Task 103 table {table} is missing required columns"
                )
        required_triggers = {
            "durable_job_state_terminal_immutable",
            "durable_job_state_job_identity_immutable",
            "durable_job_state_attempt_identity_immutable",
            "durable_job_state_lease_identity_immutable",
            "durable_job_state_authorization_identity_immutable",
            "durable_job_state_authorization_no_reactivation",
            "durable_job_state_authorization_no_delete",
            "durable_job_state_events_no_update",
            "durable_job_state_events_no_delete",
            "durable_job_state_work_no_update",
            "durable_job_state_work_no_delete",
            "durable_job_state_work_plan_no_update",
            "durable_job_state_work_plan_no_delete",
            "durable_job_state_proofs_no_update",
            "durable_job_state_proofs_no_delete",
            "durable_job_state_process_identity_immutable",
            "durable_job_state_launch_identity_immutable",
            "durable_job_state_launch_no_delete",
            "canonical_observation_attempt_guard_insert",
            "canonical_observation_attempt_guard_update",
        }
        actual_triggers = {
            str(item[0])
            for item in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }
        if not required_triggers <= actual_triggers:
            raise JobStateError("Task 103 job-state guards are incomplete")
        observation_columns = {
            str(item[1])
            for item in self.conn.execute(
                "PRAGMA table_info(canonical_observations)"
            ).fetchall()
        }
        if "attempt_id" not in observation_columns:
            raise JobStateError("canonical observations lack Task 103 attempt lineage")

    def _load_lease_secret(self) -> bytes:
        """Load the per-store signing secret used to replay active leases.

        Lease tokens are deterministic HMAC capabilities rather than stored
        plaintext.  That lets a worker safely recover an acquire/renew
        response after a crash while the durable attempt record continues to
        contain only a token digest.
        """

        candidate = secrets.token_hex(32)
        with self._tx():
            self.conn.execute(
                "INSERT OR IGNORE INTO durable_job_state_meta(key,value) "
                "VALUES('lease_token_secret',?)",
                (candidate,),
            )
            row = self.conn.execute(
                "SELECT value FROM durable_job_state_meta "
                "WHERE key='lease_token_secret'"
            ).fetchone()
            if row is None:
                raise JobStateError("durable lease signing secret is unavailable")
            value = str(row["value"])
        try:
            secret = bytes.fromhex(value)
        except ValueError as exc:
            raise JobStateError("durable lease signing secret is invalid") from exc
        if len(secret) < 32:
            raise JobStateError("durable lease signing secret is too short")
        return secret

    def _lease_token(
        self,
        tenant: str,
        attempt_id: str,
        owner_id: str,
        generation: int,
    ) -> str:
        material = (
            f"{tenant}\x00{attempt_id}\x00{owner_id}\x00{int(generation)}"
        ).encode("utf-8")
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

    def _authorization_allowed(
        self,
        tenant: str,
        job_id: str,
        decision_id: str | None,
        action_id: str | None,
        *,
        require_consumed: bool = False,
    ) -> bool:
        """Verify the exact immutable Gate 0 authorization linkage."""

        if not decision_id or not action_id:
            return False
        if self.authorization_checker is not None:
            return bool(
                self.authorization_checker(
                    tenant,
                    job_id,
                    decision_id,
                    action_id,
                )
            )
        decision = self.conn.execute(
            """
            SELECT decision_id,parent_decision_id,binding_digest,expires_at
            FROM authorization_decisions
            WHERE tenant_id=? AND job_id=? AND decision_id=? AND action_id=?
              AND decision_outcome='allow'
            """,
            (tenant, job_id, decision_id, action_id),
        ).fetchone()
        if decision is None:
            return False
        try:
            expires = datetime.fromisoformat(str(decision["expires_at"]))
            if expires.tzinfo is None or expires.utcoffset() is None:
                # SQLAlchemy's SQLite DateTime adapter strips the offset from
                # values that were validated as UTC before persistence.
                expires = expires.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= expires.astimezone(timezone.utc):
                return False
        except (TypeError, ValueError):
            return False
        if not require_consumed:
            return True
        consumption = self.conn.execute(
            """
            SELECT 1 FROM authorization_consumptions
            WHERE tenant_id=? AND job_id=? AND decision_id=? AND action_id=?
              AND envelope_digest=?
            LIMIT 1
            """,
            (
                tenant,
                job_id,
                decision_id,
                action_id,
                decision["binding_digest"],
            ),
        ).fetchone()
        if consumption is not None:
            return True
        parent_id = str(decision["parent_decision_id"] or "")
        if not parent_id:
            return False
        parent = self.conn.execute(
            """
            SELECT decision_id,action_id,binding_digest
            FROM authorization_decisions
            WHERE tenant_id=? AND job_id=? AND decision_id=?
              AND decision_outcome='allow'
            """,
            (tenant, job_id, parent_id),
        ).fetchone()
        if parent is None:
            return False
        return self.conn.execute(
            """
            SELECT 1 FROM authorization_consumptions
            WHERE tenant_id=? AND job_id=? AND decision_id=? AND action_id=?
              AND envelope_digest=?
            LIMIT 1
            """,
            (
                tenant,
                job_id,
                parent["decision_id"],
                parent["action_id"],
                parent["binding_digest"],
            ),
        ).fetchone() is not None

    def _ensure_canonical_job_tx(
        self,
        *,
        tenant: str,
        engagement_id: str,
        job_id: str,
        job_kind: str,
        initial_status: str,
        now: float,
    ) -> None:
        """Create or validate the accepted Task 101 job identity."""

        stamp = _iso_timestamp(now)
        self.conn.execute(
            """
            INSERT OR IGNORE INTO canonical_tenants(
                id,schema_version,name,created_at,metadata_json
            ) VALUES(?,?,?,?,?)
            """,
            (tenant, CANONICAL_SCHEMA_VERSION, tenant, stamp, "{}"),
        )
        self.conn.execute(
            """
            INSERT OR IGNORE INTO canonical_engagements(
                id,tenant_id,project_id,schema_version,name,status,
                created_at,metadata_json
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                engagement_id,
                tenant,
                None,
                CANONICAL_SCHEMA_VERSION,
                str(redact_value(engagement_id))[:300],
                "active",
                stamp,
                "{}",
            ),
        )
        engagement = self.conn.execute(
            "SELECT tenant_id FROM canonical_engagements WHERE id=?",
            (engagement_id,),
        ).fetchone()
        if engagement is None or str(engagement["tenant_id"]) != tenant:
            raise InvalidTransition("canonical engagement identity conflicts")
        canonical_status = (
            initial_status
            if initial_status
            in {
                JobState.PLANNED.value,
                JobState.PENDING_APPROVAL.value,
                JobState.QUEUED.value,
            }
            else JobState.PLANNED.value
        )
        self.conn.execute(
            """
            INSERT OR IGNORE INTO canonical_jobs(
                id,tenant_id,engagement_id,schema_version,job_kind,status,
                created_at,metadata_json
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                job_id,
                tenant,
                engagement_id,
                CANONICAL_SCHEMA_VERSION,
                job_kind,
                canonical_status,
                stamp,
                "{}",
            ),
        )
        canonical = self.conn.execute(
            """
            SELECT tenant_id,engagement_id,job_kind FROM canonical_jobs WHERE id=?
            """,
            (job_id,),
        ).fetchone()
        if canonical is None or (
            str(canonical["tenant_id"]),
            str(canonical["engagement_id"]),
            str(canonical["job_kind"]),
        ) != (tenant, engagement_id, job_kind):
            raise InvalidTransition("canonical job identity conflicts")

    def _observation_receipt_valid(self, receipt: ObservationReceipt) -> bool:
        """Verify a Task 102 receipt without trusting caller-selected IDs."""

        if self.observation_checker is not None:
            return bool(self.observation_checker(receipt))
        row = self.conn.execute(
            """
            SELECT o.id,a.id,m.manifest_digest
            FROM canonical_observations o
            JOIN canonical_artifact_refs a
              ON a.tenant_id=o.tenant_id AND a.observation_id=o.id
            JOIN canonical_artifact_manifests m
              ON m.tenant_id=a.tenant_id AND m.artifact_id=a.id
             AND m.observation_id=o.id
            WHERE o.tenant_id=? AND o.job_id=? AND o.attempt_id=?
              AND o.id=? AND a.id=? AND m.manifest_digest=?
            LIMIT 1
            """,
            (
                receipt.tenant_id,
                receipt.job_id,
                receipt.attempt_id,
                receipt.observation_id,
                receipt.artifact_id,
                receipt.manifest_digest,
            ),
        ).fetchone()
        return row is not None

    def register_agent(
        self,
        agent_id: str,
        *,
        tenant_id: str,
        key_id: str,
        credential_digest: str,
        engines: Iterable[str],
        capabilities: Iterable[str],
        scope: Iterable[str],
        excluded_scope: Iterable[str] = (),
        enrollment_hint_digest: str | None = None,
        mtls_subject_digest: str | None = None,
        display_name: str = "",
        host_label: str = "",
        platform_label: str = "",
        version_label: str = "",
        active_scan_enabled: bool = False,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        """Persist one credential-bound agent and normalized capabilities."""

        tenant = _tenant(tenant_id)
        agent_id = _identifier(agent_id, "agent_id")
        key_id = _identifier(key_id, "key_id")
        credential_digest = _identifier(
            credential_digest,
            "credential_digest",
        )
        normalized_engines = sorted(
            {_identifier(value, "engine") for value in engines}
        )
        normalized_capabilities = sorted(
            {_identifier(value, "capability") for value in capabilities}
        )
        normalized_scope = [str(value).strip() for value in scope]
        normalized_excluded = [str(value).strip() for value in excluded_scope]
        if not normalized_engines or not normalized_capabilities or not normalized_scope:
            raise ValueError("agent engines, capabilities, and scope are required")
        now = self.clock()
        with self._tx():
            self.conn.execute(
                """
                INSERT OR IGNORE INTO canonical_tenants(
                    id,schema_version,name,created_at,metadata_json
                ) VALUES(?,?,?,?,?)
                """,
                (
                    tenant,
                    CANONICAL_SCHEMA_VERSION,
                    tenant,
                    _iso_timestamp(now),
                    "{}",
                ),
            )
            existing = self.conn.execute(
                "SELECT * FROM durable_job_state_agents "
                "WHERE tenant_id=? AND id=?",
                (tenant, agent_id),
            ).fetchone()
            if existing is not None and existing["revoked_at"] is not None:
                raise InvalidTransition("revoked agent cannot be re-registered")
            if existing is not None and expected_version is not None and int(
                existing["version"]
            ) != int(expected_version):
                raise InvalidTransition("agent version conflict")
            safe_name = str(redact_value(display_name))[:120]
            safe_host = str(redact_value(host_label))[:200]
            safe_platform = str(redact_value(platform_label))[:80]
            safe_version = str(redact_value(version_label))[:40]
            if existing is None:
                self.conn.execute(
                    """
                    INSERT INTO durable_job_state_agents(
                        tenant_id,id,key_id,credential_digest,
                        enrollment_hint_digest,mtls_subject_digest,display_name,
                        host_label,platform_label,version_label,
                        active_scan_enabled,state,version,issued_at,last_seen_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        tenant,
                        agent_id,
                        key_id,
                        credential_digest,
                        enrollment_hint_digest,
                        mtls_subject_digest,
                        safe_name,
                        safe_host,
                        safe_platform,
                        safe_version,
                        int(active_scan_enabled),
                        "idle",
                        0,
                        now,
                        now,
                    ),
                )
            else:
                changed = self.conn.execute(
                    """
                    UPDATE durable_job_state_agents
                    SET key_id=?,credential_digest=?,
                        enrollment_hint_digest=COALESCE(enrollment_hint_digest,?),
                        mtls_subject_digest=COALESCE(mtls_subject_digest,?),
                        display_name=?,host_label=?,platform_label=?,version_label=?,
                        active_scan_enabled=?,state='idle',last_seen_at=?,
                        version=version+1
                    WHERE tenant_id=? AND id=? AND version=?
                    """,
                    (
                        key_id,
                        credential_digest,
                        enrollment_hint_digest,
                        mtls_subject_digest,
                        safe_name,
                        safe_host,
                        safe_platform,
                        safe_version,
                        int(active_scan_enabled),
                        now,
                        tenant,
                        agent_id,
                        int(existing["version"]),
                    ),
                )
                if changed.rowcount != 1:
                    raise InvalidTransition("stale agent registration")
            for statement in (
                "DELETE FROM durable_job_state_agent_engines "
                "WHERE tenant_id=? AND agent_id=?",
                "DELETE FROM durable_job_state_agent_capabilities "
                "WHERE tenant_id=? AND agent_id=?",
                "DELETE FROM durable_job_state_agent_scope "
                "WHERE tenant_id=? AND agent_id=?",
            ):
                self.conn.execute(statement, (tenant, agent_id))
            for engine in normalized_engines:
                self.conn.execute(
                    "INSERT INTO durable_job_state_agent_engines "
                    "(tenant_id,agent_id,engine) VALUES(?,?,?)",
                    (tenant, agent_id, engine),
                )
            for capability in normalized_capabilities:
                self.conn.execute(
                    "INSERT INTO durable_job_state_agent_capabilities "
                    "(tenant_id,agent_id,capability) VALUES(?,?,?)",
                    (tenant, agent_id, capability),
                )
            for kind, entries in (
                ("allow", normalized_scope),
                ("exclude", normalized_excluded),
            ):
                for sequence, entry in enumerate(entries):
                    self.conn.execute(
                        "INSERT INTO durable_job_state_agent_scope "
                        "(tenant_id,agent_id,sequence,scope_kind,scope_entry) "
                        "VALUES(?,?,?,?,?)",
                        (tenant, agent_id, sequence, kind, entry),
                    )
            return self.get_agent(agent_id, tenant_id=tenant, _locked=True) or {}

    def get_agent(
        self,
        agent_id: str,
        *,
        tenant_id: str,
        _locked: bool = False,
    ) -> dict[str, Any] | None:
        tenant = _tenant(tenant_id)
        agent_id = _identifier(agent_id, "agent_id")

        def _load() -> dict[str, Any] | None:
            row = self.conn.execute(
                "SELECT * FROM durable_job_state_agents "
                "WHERE tenant_id=? AND id=?",
                (tenant, agent_id),
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["engines"] = [
                str(item[0])
                for item in self.conn.execute(
                    "SELECT engine FROM durable_job_state_agent_engines "
                    "WHERE tenant_id=? AND agent_id=? ORDER BY engine",
                    (tenant, agent_id),
                ).fetchall()
            ]
            result["capabilities"] = [
                str(item[0])
                for item in self.conn.execute(
                    "SELECT capability FROM durable_job_state_agent_capabilities "
                    "WHERE tenant_id=? AND agent_id=? ORDER BY capability",
                    (tenant, agent_id),
                ).fetchall()
            ]
            scope_rows = self.conn.execute(
                "SELECT scope_kind,scope_entry FROM durable_job_state_agent_scope "
                "WHERE tenant_id=? AND agent_id=? ORDER BY scope_kind,sequence",
                (tenant, agent_id),
            ).fetchall()
            result["scope"] = [
                str(item["scope_entry"])
                for item in scope_rows
                if str(item["scope_kind"]) == "allow"
            ]
            result["excluded_scope"] = [
                str(item["scope_entry"])
                for item in scope_rows
                if str(item["scope_kind"]) == "exclude"
            ]
            result["active_scan_enabled"] = bool(
                result.get("active_scan_enabled")
            )
            result["revoked"] = result.pop("revoked_at") is not None
            return result

        if _locked:
            return _load()
        with self._lock:
            return _load()

    def list_agents(self, *, tenant_id: str) -> list[dict[str, Any]]:
        tenant = _tenant(tenant_id)
        with self._lock:
            ids = [
                str(row[0])
                for row in self.conn.execute(
                    "SELECT id FROM durable_job_state_agents "
                    "WHERE tenant_id=? ORDER BY id",
                    (tenant,),
                ).fetchall()
            ]
            return [
                agent
                for agent_id in ids
                if (agent := self.get_agent(
                    agent_id,
                    tenant_id=tenant,
                    _locked=True,
                ))
                is not None
            ]

    def authenticate_agent(
        self,
        credential_digest: str,
        *,
        tenant_id: str,
        mtls_subject_digest: str | None = None,
    ) -> dict[str, Any] | None:
        tenant = _tenant(tenant_id)
        credential_digest = _identifier(
            credential_digest,
            "credential_digest",
        )
        with self._lock:
            rows = self.conn.execute(
                "SELECT id,credential_digest,mtls_subject_digest "
                "FROM durable_job_state_agents "
                "WHERE tenant_id=? AND revoked_at IS NULL",
                (tenant,),
            ).fetchall()
            for row in rows:
                if not hmac.compare_digest(
                    str(row["credential_digest"]),
                    credential_digest,
                ):
                    continue
                expected_subject = str(row["mtls_subject_digest"] or "")
                if expected_subject and not hmac.compare_digest(
                    expected_subject,
                    str(mtls_subject_digest or ""),
                ):
                    return None
                return self.get_agent(
                    str(row["id"]),
                    tenant_id=tenant,
                    _locked=True,
                )
            return None

    def revoke_agent(
        self,
        agent_id: str,
        *,
        tenant_id: str,
        expected_version: int | None = None,
    ) -> tuple[dict[str, Any], list[str]]:
        tenant = _tenant(tenant_id)
        agent_id = _identifier(agent_id, "agent_id")
        with self._tx():
            row = self.conn.execute(
                "SELECT * FROM durable_job_state_agents "
                "WHERE tenant_id=? AND id=?",
                (tenant, agent_id),
            ).fetchone()
            if row is None:
                raise KeyError(agent_id)
            if expected_version is not None and int(row["version"]) != int(
                expected_version
            ):
                raise InvalidTransition("agent version conflict")
            now = self.clock()
            self.conn.execute(
                "UPDATE durable_job_state_agents "
                "SET state='revoked',revoked_at=COALESCE(revoked_at,?),"
                "version=version+1 WHERE tenant_id=? AND id=?",
                (now, tenant, agent_id),
            )
            jobs = [
                str(item[0])
                for item in self.conn.execute(
                    "SELECT id FROM durable_job_state_jobs "
                    "WHERE tenant_id=? AND assigned_agent_id=? "
                    "AND state NOT IN ('canceled','partial','failed','completed')",
                    (tenant, agent_id),
                ).fetchall()
            ]
            return (
                self.get_agent(agent_id, tenant_id=tenant, _locked=True) or {},
                jobs,
            )

    def set_agent_state(
        self,
        agent_id: str,
        state: str,
        *,
        tenant_id: str,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        agent_id = _identifier(agent_id, "agent_id")
        normalized = str(state).strip().lower()
        if normalized not in {"idle", "online", "running", "paused", "offline"}:
            raise ValueError("unsupported agent state")
        with self._tx():
            changed = self.conn.execute(
                """
                UPDATE durable_job_state_agents
                SET state=?,last_seen_at=?,version=version+1
                WHERE tenant_id=? AND id=? AND revoked_at IS NULL
                """,
                (normalized, self.clock(), tenant, agent_id),
            )
            if changed.rowcount != 1:
                raise KeyError(agent_id)
            return self.get_agent(agent_id, tenant_id=tenant, _locked=True) or {}

    def cache_imported(
        self,
        cache_kind: str,
        source_identity: str,
        *,
        tenant_id: str,
    ) -> bool:
        tenant = _tenant(tenant_id)
        cache_kind = _identifier(cache_kind, "cache_kind")
        source_identity = _identifier(source_identity, "source_identity")
        with self._lock:
            return self.conn.execute(
                "SELECT 1 FROM durable_job_state_cache_imports "
                "WHERE tenant_id=? AND cache_kind=? AND source_identity=?",
                (tenant, cache_kind, source_identity),
            ).fetchone() is not None

    def record_cache_import(
        self,
        cache_kind: str,
        source_identity: str,
        *,
        tenant_id: str,
        result: str,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        tenant = _tenant(tenant_id)
        cache_kind = _identifier(cache_kind, "cache_kind")
        source_identity = _identifier(source_identity, "source_identity")
        with self._tx():
            self.conn.execute(
                """
                INSERT OR IGNORE INTO durable_job_state_cache_imports(
                    tenant_id,cache_kind,source_identity,imported_at,result,
                    detail_json
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    tenant,
                    cache_kind,
                    source_identity,
                    self.clock(),
                    str(result)[:100],
                    _json(dict(detail or {}), limit=16_384),
                ),
            )

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
        actor: str | TransitionActor = "system",
        reason: str = "unspecified",
        idempotency_key: str | None = None,
        data: Mapping[str, Any] | None = None,
    ) -> int:
        actor_record = _actor(actor, tenant_id=tenant, default_role="system")
        job_version = int(self._job(tenant, job_id)["version"])
        cursor = self.conn.execute(
            """
            INSERT INTO durable_job_state_events(
                tenant_id,job_id,attempt_id,event_type,from_state,to_state,
                actor,actor_role,authorization_decision_id,reason,reason_code,
                idempotency_key,job_version,data_json,occurred_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                tenant,
                job_id,
                attempt_id,
                _identifier(event_type, "event_type"),
                from_state,
                to_state,
                actor_record.actor_id,
                actor_record.role,
                actor_record.authorization_decision_id,
                str(reason or "unspecified")[:2000],
                _reason_code(reason),
                idempotency_key,
                job_version,
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
        engagement_id: str,
        run_id: str,
        job_kind: str,
        target: str,
        authorization_decision_id: str | None,
        authorization_action_id: str | None,
        assigned_agent_id: str | None,
        request_identity: str,
        authorization_bindings: Iterable[Mapping[str, str]],
        planned_work: Iterable[str],
        payload: Mapping[str, Any],
        idempotency_key: str | None,
        parent_id: str | None,
        max_attempts: int,
        required_work: int,
        state: str,
        metadata: Mapping[str, Any],
        actor: str | TransitionActor,
        reason: str,
    ) -> dict[str, Any]:
        now = self.clock()
        self._ensure_canonical_job_tx(
            tenant=tenant,
            engagement_id=engagement_id,
            job_id=job_id,
            job_kind=job_kind,
            initial_status=state,
            now=now,
        )
        self.conn.execute(
            """
            INSERT INTO durable_job_state_jobs(
                tenant_id,id,engagement_id,run_id,job_kind,target,
                authorization_decision_id,authorization_action_id,
                assigned_agent_id,idempotency_key,request_identity,parent_id,state,
                payload_json,metadata_json,max_attempts,required_work,
                created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                tenant,
                job_id,
                engagement_id,
                run_id,
                job_kind,
                target,
                authorization_decision_id,
                authorization_action_id,
                assigned_agent_id,
                idempotency_key,
                request_identity,
                parent_id,
                state,
                _authority_json(dict(payload)),
                _json(dict(metadata)),
                max(1, int(max_attempts)),
                max(0, int(required_work)),
                now,
                now,
            ),
        )
        for index, binding in enumerate(authorization_bindings):
            self.conn.execute(
                """
                INSERT INTO durable_job_state_job_authorizations(
                    tenant_id,job_id,authorization_decision_id,
                    authorization_action_id,framework,generation,active,
                    is_primary
                ) VALUES(?,?,?,?,?,1,1,?)
                """,
                (
                    tenant,
                    job_id,
                    binding["authorization_decision_id"],
                    binding["authorization_action_id"],
                    binding["framework"],
                    int(index == 0),
                ),
            )
        for work_key in planned_work:
            self.conn.execute(
                """
                INSERT INTO durable_job_state_work_plan(
                    tenant_id,job_id,work_key,required,created_at
                ) VALUES(?,?,?,?,?)
                """,
                (tenant, job_id, _identifier(work_key, "work_key"), 1, now),
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
        actor: str | TransitionActor,
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
        engagement_id: str | None = None,
        run_id: str | None = None,
        job_kind: str | None = None,
        target: str | None = None,
        authorization_decision_id: str | None = None,
        authorization_action_id: str | None = None,
        authorization_bindings: Iterable[Mapping[str, str]] = (),
        assigned_agent_id: str | None = None,
        idempotency_key: str | None = None,
        parent_id: str | None = None,
        max_attempts: int = 1,
        required_work: int | None = None,
        coverage_required: int | None = None,
        work_items: Iterable[str] = (),
        state: str | JobState = JobState.PLANNED,
        metadata: Mapping[str, Any] | None = None,
        actor: str | TransitionActor = "system",
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
        normalized_idempotency_key = (
            _identifier(idempotency_key, "idempotency_key")
            if idempotency_key is not None
            else None
        )
        supplied_job_id = job_id
        if job_id is None and normalized_idempotency_key is not None:
            job_id = "job-" + hashlib.sha256(
                (
                    tenant
                    + "\x00create-job\x00"
                    + normalized_idempotency_key
                ).encode("utf-8")
            ).hexdigest()[:32]
        job_id = _identifier(job_id or str(uuid.uuid4()), "job_id")
        parent_id = _identifier(parent_id, "parent_id") if parent_id else None
        if parent_id == job_id:
            raise ValueError("a job cannot be its own parent")
        payload_dict = dict(payload or {})
        metadata_dict = dict(metadata or {})
        planned_work = sorted(
            {
                _identifier(item, "work_key")
                for item in work_items
                if str(item).strip()
            }
        )
        if not planned_work:
            raw_declared = payload_dict.get("modules") or payload_dict.get("frameworks")
            if isinstance(raw_declared, (list, tuple)):
                planned_work = sorted(
                    {
                        _identifier(str(item), "work_key")
                        for item in raw_declared
                        if str(item).strip()
                    }
                )
        if not planned_work and int(required_work) > 0:
            planned_work = [
                f"required:{index + 1}" for index in range(int(required_work))
            ]
        if planned_work and int(required_work) not in {0, len(planned_work)}:
            raise ValueError("required_work must equal the exact work plan")
        required_work = len(planned_work)
        engagement_id = _identifier(
            engagement_id
            or payload_dict.pop("engagement_id", None)
            or f"engagement-{hashlib.sha256((tenant + chr(0) + job_id).encode()).hexdigest()[:32]}",
            "engagement_id",
        )
        run_id = _identifier(
            run_id
            or payload_dict.pop("run_id", None)
            or (
                "run-"
                + hashlib.sha256(
                    (
                        tenant
                        + "\x00"
                        + job_id
                        + "\x00"
                        + normalized_idempotency_key
                    ).encode("utf-8")
                ).hexdigest()[:32]
                if normalized_idempotency_key is not None
                else f"run-{uuid.uuid4().hex}"
            ),
            "run_id",
        )
        job_kind = _identifier(
            job_kind
            or payload_dict.pop("job_kind", None)
            or payload_dict.get("engine")
            or "job",
            "job_kind",
        )
        target = str(
            target
            if target is not None
            else payload_dict.get("target") or ""
        ).strip()[:2000]
        authorization_decision_id = (
            _identifier(
                authorization_decision_id,
                "authorization_decision_id",
            )
            if authorization_decision_id
            else None
        )
        authorization_action_id = (
            _identifier(authorization_action_id, "authorization_action_id")
            if authorization_action_id
            else None
        )
        normalized_authorizations: list[dict[str, str]] = []
        for raw_binding in authorization_bindings:
            decision = _identifier(
                raw_binding.get("authorization_decision_id"),
                "authorization_decision_id",
            )
            action = _identifier(
                raw_binding.get("authorization_action_id"),
                "authorization_action_id",
            )
            framework = _identifier(
                raw_binding.get("framework"),
                "authorization_framework",
            )
            if not self._authorization_allowed(
                tenant, job_id, decision, action
            ):
                raise InvalidTransition(
                    "job authorization binding is absent or stale"
                )
            normalized_authorizations.append(
                {
                    "authorization_decision_id": decision,
                    "authorization_action_id": action,
                    "framework": framework,
                }
            )
        if (
            not normalized_authorizations
            and authorization_decision_id
            and authorization_action_id
        ):
            normalized_authorizations.append(
                {
                    "authorization_decision_id": authorization_decision_id,
                    "authorization_action_id": authorization_action_id,
                    "framework": job_kind,
                }
            )
        assigned_agent_id = (
            _identifier(assigned_agent_id, "assigned_agent_id")
            if assigned_agent_id
            else None
        )
        if requested == JobState.QUEUED.value and not self._authorization_allowed(
            tenant,
            job_id,
            authorization_decision_id,
            authorization_action_id,
        ):
            raise InvalidTransition("queued job requires an exact allowed authorization")
        request_identity = _identity(
            {
                "tenant_id": tenant,
                "job_id": job_id,
                "engagement_id": engagement_id,
                "run_id": run_id,
                "job_kind": job_kind,
                "target": target,
                "authorization_decision_id": authorization_decision_id,
                "authorization_action_id": authorization_action_id,
                "authorization_bindings": normalized_authorizations,
                "assigned_agent_id": assigned_agent_id,
                "parent_id": parent_id,
                "state": requested,
                "payload": payload_dict,
                "metadata": metadata_dict,
                "max_attempts": int(max_attempts),
                "required_work": int(required_work),
                "work_items": planned_work,
            }
        )
        with self._tx():
            if assigned_agent_id is not None:
                assigned = self.conn.execute(
                    "SELECT 1 FROM durable_job_state_agents "
                    "WHERE tenant_id=? AND id=? AND revoked_at IS NULL",
                    (tenant, assigned_agent_id),
                ).fetchone()
                if assigned is None:
                    raise InvalidTransition("assigned agent is unavailable")
            if idempotency_key is not None:
                idempotency_key = normalized_idempotency_key
                old = self.conn.execute(
                    "SELECT * FROM durable_job_state_jobs WHERE tenant_id=? AND idempotency_key=?",
                    (tenant, idempotency_key),
                ).fetchone()
                if old is not None:
                    same_request = (
                        hmac.compare_digest(
                            str(old["request_identity"] or ""),
                            request_identity,
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
                engagement_id=engagement_id,
                run_id=run_id,
                job_kind=job_kind,
                target=target,
                authorization_decision_id=authorization_decision_id,
                authorization_action_id=authorization_action_id,
                assigned_agent_id=assigned_agent_id,
                request_identity=request_identity,
                authorization_bindings=normalized_authorizations,
                planned_work=planned_work,
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
        required_keys = {
            str(row["work_key"])
            for row in self.conn.execute(
                "SELECT work_key FROM durable_job_state_work_plan "
                "WHERE tenant_id=? AND job_id=? AND required=1",
                (tenant, job_id),
            ).fetchall()
        }
        latest = {
            str(row["work_key"]): row
            for row in self._latest_work_rows(tenant, job_id)
        }
        if int(job["completed_work"]) < int(job["required_work"]):
            blockers.append("required_work_incomplete")
        if any(
            key not in latest or str(latest[key]["state"]) == WorkState.PENDING.value
            for key in required_keys
        ):
            blockers.append("required_work_pending")
        for state, code in (
            (WorkState.SKIPPED.value, "required_work_skipped"),
            (WorkState.FAILED.value, "required_work_failed"),
            (WorkState.TRUNCATED.value, "required_work_truncated"),
            (WorkState.UNCOLLECTED.value, "required_work_uncollected"),
        ):
            if any(
                key in latest and str(latest[key]["state"]) == state
                for key in required_keys
            ):
                blockers.append(code)
        latest_attempt = self.conn.execute(
            "SELECT id FROM durable_job_state_attempts "
            "WHERE tenant_id=? AND job_id=? ORDER BY number DESC LIMIT 1",
            (tenant, job_id),
        ).fetchone()
        delivery = None
        if latest_attempt is not None:
            delivery = self.conn.execute(
                "SELECT * FROM durable_job_state_deliveries "
                "WHERE tenant_id=? AND job_id=? AND attempt_id=? "
                "AND state='accepted' ORDER BY accepted_at DESC LIMIT 1",
                (tenant, job_id, latest_attempt["id"]),
            ).fetchone()
        if latest_attempt is None:
            blockers.append("terminal_proof_missing")
        elif delivery is None:
            blockers.append("accepted_delivery_missing")
        elif self.conn.execute(
            "SELECT 1 FROM durable_job_state_terminal_proofs "
            "WHERE tenant_id=? AND job_id=? AND attempt_id=? "
            "AND proof_type='observation_receipt' "
            "AND coverage_identity=? AND result_ref=? LIMIT 1",
            (
                tenant,
                job_id,
                latest_attempt["id"],
                delivery["result_identity"],
                delivery["result_ref"],
            ),
        ).fetchone() is None:
            blockers.append("observation_receipt_missing")
        payload = _decode(job["payload_json"], {})
        requires_run_truth = bool(
            isinstance(payload, Mapping)
            and (
                payload.get("source") == "dashboard"
                or payload.get("dry_run") is False
            )
        )
        if requires_run_truth and latest_attempt is not None:
            proven_frameworks = {
                str(row[0])
                for row in self.conn.execute(
                    "SELECT DISTINCT r.framework "
                    "FROM durable_job_state_terminal_proofs p "
                    "JOIN run_collection_truth r "
                    "ON r.tenant_id=p.tenant_id "
                    "AND p.result_ref='run-truth:' || r.run_id "
                    "WHERE p.tenant_id=? AND p.job_id=? AND p.attempt_id=? "
                    "AND p.proof_type='run_truth'",
                    (tenant, job_id, latest_attempt["id"]),
                ).fetchall()
            }
            required_truth_frameworks = (
                {str(job["job_kind"])}
                if job["assigned_agent_id"] is not None
                else required_keys
            )
            blockers.extend(
                f"run_truth_missing:{key}"
                for key in sorted(required_truth_frameworks - proven_frameworks)
            )
        if self.conn.execute(
            """
            SELECT 1 FROM durable_job_state_attempts
            WHERE tenant_id=? AND job_id=?
              AND state IN ('leased','running','paused','canceling')
            LIMIT 1
            """,
            (tenant, job_id),
        ).fetchone():
            blockers.append("active_attempt")
        if self.conn.execute(
            """
            SELECT 1 FROM durable_job_state_child_processes
            WHERE tenant_id=? AND job_id=?
              AND state IN ('running','paused','canceling','orphaned')
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
        actor: str | TransitionActor,
        reason: str,
        idempotency_key: str | None,
        data: Mapping[str, Any] | None,
        allow_completion: bool = False,
    ) -> dict[str, Any]:
        row = self._job(tenant, job_id)
        actor_record = _actor(actor, tenant_id=tenant, default_role="system")
        if idempotency_key is not None:
            prior = self.conn.execute(
                """
                SELECT from_state,to_state,actor,actor_role,reason,data_json
                FROM durable_job_state_events
                WHERE tenant_id=? AND job_id=? AND idempotency_key=?
                """,
                (tenant, job_id, idempotency_key),
            ).fetchone()
            if prior is not None:
                prior_data = _decode(prior["data_json"], {})
                if (
                    str(prior["to_state"] or "") != target
                    or str(prior["actor"]) != actor_record.actor_id
                    or str(prior["actor_role"]) != actor_record.role
                    or str(prior["reason"]) != str(reason or "unspecified")[:2000]
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
        if current in TERMINAL_STATES:
            raise TerminalStateError(f"terminal job state {current} is immutable")
        if target not in _TRANSITIONS.get(current, frozenset()):
            raise InvalidTransition(f"{current} -> {target}")
        if target == JobState.QUEUED.value and not self._authorization_allowed(
            tenant,
            job_id,
            (
                str(row["authorization_decision_id"])
                if row["authorization_decision_id"] is not None
                else None
            ),
            (
                str(row["authorization_action_id"])
                if row["authorization_action_id"] is not None
                else None
            ),
        ):
            raise InvalidTransition("queued job authorization is absent or stale")
        if target == JobState.COMPLETED.value:
            if not allow_completion:
                raise TerminalStateError("completion requires terminal invariant validation")
            blockers = self._completion_blockers(tenant, job_id)
            if blockers:
                raise TerminalStateError("job cannot complete: " + ",".join(blockers))
        now = self.clock()
        entering_control_state = target in {
            JobState.PAUSED.value,
            JobState.CANCELING.value,
        }
        leaving_control_state = current == JobState.PAUSED.value
        changed = self.conn.execute(
            """
            UPDATE durable_job_state_jobs SET state=?,version=version+1,updated_at=?,
                terminal_at=?,terminal_reason=?,terminal_reason_code=?,terminal_actor=?,
                control_version=control_version+?,
                paused_from_state=?
            WHERE tenant_id=? AND id=? AND version=?
            """,
            (
                target,
                now,
                now if target in TERMINAL_STATES else None,
                str(reason or "unspecified")[:2000]
                if target in TERMINAL_STATES
                else None,
                _reason_code(reason) if target in TERMINAL_STATES else None,
                actor_record.actor_id if target in TERMINAL_STATES else None,
                int(entering_control_state or leaving_control_state),
                current if target == JobState.PAUSED.value else None,
                tenant,
                job_id,
                int(row["version"]),
            ),
        )
        if changed.rowcount != 1:
            raise InvalidTransition("stale job version")
        projected = self.conn.execute(
            "UPDATE canonical_jobs SET status=? WHERE tenant_id=? AND id=?",
            (_canonical_job_status(target, current), tenant, job_id),
        )
        if projected.rowcount != 1:
            raise InvalidTransition("canonical job projection is unavailable")
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

    def require_approval(
        self,
        job_id: str,
        *,
        tenant_id: str = "default",
        actor: str | TransitionActor = "system",
        reason: str = "fresh authorization required",
    ) -> dict[str, Any]:
        """Fence queued retry work until an adapter binds new authorization."""

        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._tx():
            row = self._job(tenant, job_id)
            if str(row["state"]) == JobState.PENDING_APPROVAL.value:
                return self._row(row) or {}
            if str(row["state"]) != JobState.QUEUED.value:
                raise InvalidTransition(
                    f"cannot require approval from {row['state']}"
                )
            return self._transition_tx(
                tenant,
                job_id,
                JobState.PENDING_APPROVAL.value,
                expected_version=int(row["version"]),
                actor=actor,
                reason=reason,
                idempotency_key=None,
                data={"retry_fenced": True},
            )

    def bind_retry_authorization(
        self,
        job_id: str,
        *,
        authorization_decision_id: str,
        authorization_action_id: str,
        run_id: str,
        authorization_bindings: Iterable[Mapping[str, str]] = (),
        payload_updates: Mapping[str, Any] | None = None,
        tenant_id: str = "default",
        actor: str | TransitionActor = "operator",
        reason: str = "retry authorization bound",
    ) -> dict[str, Any]:
        """Append a fresh authorization generation and release one retry."""

        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        decision_id = _identifier(
            authorization_decision_id,
            "authorization_decision_id",
        )
        action_id = _identifier(
            authorization_action_id,
            "authorization_action_id",
        )
        run_id = _identifier(run_id, "run_id")
        updates = dict(payload_updates or {})
        allowed_update_keys = {
            "authorization_envelope",
            "authorization_envelopes",
            "authorization_public",
            "runtime_context",
            "scope_decision",
            "authorization_id",
            "retry_generation",
            "authorized",
        }
        if set(updates) - allowed_update_keys:
            raise InvalidTransition(
                "retry authorization payload updates exceed the auth boundary"
            )
        normalized: list[dict[str, str]] = []
        for raw in authorization_bindings:
            normalized.append(
                {
                    "authorization_decision_id": _identifier(
                        raw.get("authorization_decision_id"),
                        "authorization_decision_id",
                    ),
                    "authorization_action_id": _identifier(
                        raw.get("authorization_action_id"),
                        "authorization_action_id",
                    ),
                    "framework": _identifier(
                        raw.get("framework"),
                        "authorization_framework",
                    ),
                }
            )
        with self._tx():
            row = self._job(tenant, job_id)
            if str(row["state"]) != JobState.PENDING_APPROVAL.value:
                raise InvalidTransition(
                    "retry authorization requires pending_approval"
                )
            if self._active_attempt(tenant, job_id) is not None:
                raise InvalidTransition(
                    "retry authorization cannot replace an active attempt"
                )
            if hmac.compare_digest(str(row["run_id"]), run_id):
                raise InvalidTransition(
                    "retry authorization requires a new run identity"
                )
            if not normalized:
                normalized = [
                    {
                        "authorization_decision_id": decision_id,
                        "authorization_action_id": action_id,
                        "framework": str(row["job_kind"]),
                    }
                ]
            if not any(
                item["authorization_decision_id"] == decision_id
                and item["authorization_action_id"] == action_id
                for item in normalized
            ):
                raise InvalidTransition(
                    "primary retry authorization is not in its bindings"
                )
            normalized.sort(
                key=lambda item: int(
                    not (
                        item["authorization_decision_id"] == decision_id
                        and item["authorization_action_id"] == action_id
                    )
                )
            )
            if len({item["framework"] for item in normalized}) != len(normalized):
                raise InvalidTransition(
                    "retry authorization frameworks are duplicated"
                )
            for item in normalized:
                if not self._authorization_allowed(
                    tenant,
                    job_id,
                    item["authorization_decision_id"],
                    item["authorization_action_id"],
                ):
                    raise InvalidTransition(
                        "retry authorization is absent or stale"
                    )
            generation = int(
                self.conn.execute(
                    "SELECT COALESCE(MAX(generation),0)+1 "
                    "FROM durable_job_state_job_authorizations "
                    "WHERE tenant_id=? AND job_id=?",
                    (tenant, job_id),
                ).fetchone()[0]
            )
            self.conn.execute(
                "UPDATE durable_job_state_job_authorizations SET active=0 "
                "WHERE tenant_id=? AND job_id=? AND active=1",
                (tenant, job_id),
            )
            for index, item in enumerate(normalized):
                self.conn.execute(
                    """
                    INSERT INTO durable_job_state_job_authorizations(
                        tenant_id,job_id,authorization_decision_id,
                        authorization_action_id,framework,generation,active,
                        is_primary
                    ) VALUES(?,?,?,?,?,?,1,?)
                    """,
                    (
                        tenant,
                        job_id,
                        item["authorization_decision_id"],
                        item["authorization_action_id"],
                        item["framework"],
                        generation,
                        int(index == 0),
                    ),
                )
            payload = _decode(row["payload_json"], {})
            if not isinstance(payload, dict):
                raise InvalidTransition("durable job payload is invalid")
            payload.update(updates)
            self.conn.execute(
                """
                UPDATE durable_job_state_jobs
                SET authorization_decision_id=?,authorization_action_id=?,
                    run_id=?,payload_json=?,updated_at=?
                WHERE tenant_id=? AND id=? AND version=?
                """,
                (
                    decision_id,
                    action_id,
                    run_id,
                    _authority_json(payload),
                    self.clock(),
                    tenant,
                    job_id,
                    int(row["version"]),
                ),
            )
            result = self._transition_tx(
                tenant,
                job_id,
                JobState.QUEUED.value,
                expected_version=int(row["version"]),
                actor=actor,
                reason=reason,
                idempotency_key=None,
                data={"authorization_generation": generation},
            )
            result["authorization_generation"] = generation
            return result

    def pause_job(
        self,
        job_id: str,
        *,
        tenant_id: str = "default",
        actor: str | TransitionActor = "operator",
        reason: str = "operator pause",
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        actor_record = _actor(actor, tenant_id=tenant, default_role="operator")
        if actor_record.role not in {"operator", "admin", "system"}:
            raise InvalidTransition("actor is not authorized to pause jobs")
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
            result = self._transition_tx(
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
            active = self._active_attempt(tenant, job_id)
            if active is not None:
                self.conn.execute(
                    """
                    UPDATE durable_job_state_attempts
                    SET state='paused',control_version=?,version=version+1
                    WHERE tenant_id=? AND id=?
                      AND state IN ('leased','running')
                    """,
                    (
                        int(result["control_version"]),
                        tenant,
                        active["id"],
                    ),
                )
                self.conn.execute(
                    """
                    UPDATE durable_job_state_child_processes SET state='paused'
                    WHERE tenant_id=? AND attempt_id=? AND state='running'
                    """,
                    (tenant, active["id"]),
                )
                self._event(
                    tenant,
                    job_id,
                    "attempt_paused",
                    attempt_id=str(active["id"]),
                    actor=actor_record,
                    reason=reason,
                    data={"control_version": int(result["control_version"])},
                )
            return self._row(self._job(tenant, job_id)) or {}

    pause = pause_job

    def resume_job(
        self,
        job_id: str,
        *,
        tenant_id: str = "default",
        actor: str | TransitionActor = "operator",
        reason: str = "operator resume",
        lease_seconds: float = 60.0,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        actor_record = _actor(actor, tenant_id=tenant, default_role="operator")
        if actor_record.role not in {"operator", "admin", "system"}:
            raise InvalidTransition("actor is not authorized to resume jobs")
        with self._tx():
            row = self._job(tenant, job_id)
            if str(row["state"]) != JobState.PAUSED.value:
                if str(row["state"]) == JobState.QUEUED.value:
                    return self._row(row) or {}
                raise InvalidTransition(f"cannot resume from {row['state']}")
            active = self._active_attempt(tenant, job_id)
            if active is None:
                target = str(row["paused_from_state"] or JobState.QUEUED.value)
                if target not in {
                    JobState.PLANNED.value,
                    JobState.PENDING_APPROVAL.value,
                    JobState.QUEUED.value,
                }:
                    target = JobState.QUEUED.value
            else:
                if str(active["state"]) != AttemptState.PAUSED.value:
                    raise InvalidTransition("paused job has a non-paused attempt")
                target = (
                    JobState.RUNNING.value
                    if str(row["paused_from_state"]) == JobState.RUNNING.value
                    else JobState.LEASED.value
                )
            if target in {JobState.LEASED.value, JobState.RUNNING.value} and not self._authorization_allowed(
                tenant,
                job_id,
                (
                    str(row["authorization_decision_id"])
                    if row["authorization_decision_id"] is not None
                    else None
                ),
                (
                    str(row["authorization_action_id"])
                    if row["authorization_action_id"] is not None
                    else None
                ),
                require_consumed=target == JobState.RUNNING.value,
            ):
                raise InvalidTransition("resume authorization is absent or stale")
            result = self._transition_tx(
                tenant,
                job_id,
                target,
                expected_version=int(row["version"]),
                actor=actor_record,
                reason=reason,
                idempotency_key=None,
                data={"attempt_id": active["id"] if active is not None else None},
            )
            if active is None:
                return result
            lease = self.conn.execute(
                "SELECT * FROM durable_job_state_leases "
                "WHERE tenant_id=? AND attempt_id=?",
                (tenant, active["id"]),
            ).fetchone()
            if lease is None:
                raise LeaseError("paused attempt lease is unavailable")
            generation = int(lease["generation"]) + 1
            owner_id = str(lease["owner_id"])
            token = self._lease_token(
                tenant,
                str(active["id"]),
                owner_id,
                generation,
            )
            digest = _token_digest(token)
            now = self.clock()
            max_expires = float(
                active["lease_max_expires_at"]
                if active["lease_max_expires_at"] is not None
                else lease["expires_at"]
            )
            if max_expires <= now:
                raise LeaseError("maximum lease lifetime expired")
            expires = min(now + float(lease_seconds), max_expires)
            attempt_state = (
                AttemptState.RUNNING.value
                if target == JobState.RUNNING.value
                else AttemptState.LEASED.value
            )
            self.conn.execute(
                """
                UPDATE durable_job_state_attempts
                SET state=?,lease_token_digest=?,lease_generation=?,
                    lease_expires_at=?,control_version=?,version=version+1
                WHERE tenant_id=? AND id=? AND state='paused'
                """,
                (
                    attempt_state,
                    digest,
                    generation,
                    expires,
                    int(result["control_version"]),
                    tenant,
                    active["id"],
                ),
            )
            self.conn.execute(
                """
                UPDATE durable_job_state_leases
                SET token_digest=?,generation=?,issued_at=?,expires_at=?,
                    revoked_at=NULL,revoke_reason=NULL
                WHERE tenant_id=? AND attempt_id=?
                """,
                (
                    digest,
                    generation,
                    now,
                    expires,
                    tenant,
                    active["id"],
                ),
            )
            self.conn.execute(
                """
                UPDATE durable_job_state_child_processes SET state='running'
                WHERE tenant_id=? AND attempt_id=? AND state='paused'
                """,
                (tenant, active["id"]),
            )
            resumed = self._row(self._job(tenant, job_id)) or {}
            resumed["attempt_id"] = str(active["id"])
            resumed["lease_token"] = token
            resumed["lease_generation"] = generation
            return resumed

    def cancel_job(
        self,
        job_id: str,
        *,
        tenant_id: str = "default",
        actor: str | TransitionActor = "operator",
        reason: str = "operator cancellation",
        supervisor: ProcessSupervisor | None = None,
        sla_seconds: float = 5.0,
    ) -> dict[str, Any]:
        """Fence, stop, and reconcile one job without holding a DB lock."""

        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        actor_record = _actor(actor, tenant_id=tenant, default_role="operator")
        if actor_record.role not in {"operator", "admin", "system"}:
            raise InvalidTransition("actor is not authorized to cancel jobs")
        supervisor = supervisor or self.process_supervisor
        total_sla = max(0.0, min(float(sla_seconds), 60.0))
        started_monotonic = time.monotonic()

        process_rows: list[dict[str, Any]] = []
        with self._tx():
            row = self._job(tenant, job_id)
            current = str(row["state"])
            if current in TERMINAL_STATES:
                return self._row(row) or {}
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
            active = self._active_attempt(tenant, job_id)
            children = self.conn.execute(
                """
                SELECT * FROM durable_job_state_child_processes
                WHERE tenant_id=? AND job_id=?
                  AND state IN ('running','paused','canceling','orphaned')
                ORDER BY attempt_id,identity_key
                """,
                (tenant, job_id),
            ).fetchall()
            if active is None and not children:
                self._record_missing_required_work_tx(
                    tenant,
                    job_id,
                    reason=reason,
                    actor=actor_record,
                )
                target = (
                    JobState.PARTIAL.value
                    if int(self._job(tenant, job_id)["completed_work"]) > 0
                    else JobState.CANCELED.value
                )
                result = self._transition_tx(
                    tenant,
                    job_id,
                    target,
                    expected_version=int(row["version"]),
                    actor=actor_record,
                    reason=reason,
                    idempotency_key=None,
                    data={"queued_work_prevented": True},
                )
                elapsed = max(
                    0.0,
                    time.monotonic() - started_monotonic,
                )
                self._event(
                    tenant,
                    job_id,
                    "cancel_reconciled",
                    actor=actor_record,
                    reason=reason,
                    data={
                        "sla_seconds": total_sla,
                        "elapsed_seconds": elapsed,
                        "within_sla": elapsed <= total_sla,
                        "immediate": True,
                    },
                )
                return result
            if current != JobState.CANCELING.value:
                row_dict = self._transition_tx(
                    tenant,
                    job_id,
                    JobState.CANCELING.value,
                    expected_version=int(row["version"]),
                    actor=actor_record,
                    reason=reason,
                    idempotency_key=None,
                    data={"sla_seconds": total_sla},
                )
            else:
                row_dict = self._row(row) or {}
            now = self.clock()
            if active is not None:
                self.conn.execute(
                    """
                    UPDATE durable_job_state_attempts
                    SET state='canceling',lease_token_digest=NULL,
                        lease_expires_at=NULL,control_version=?,version=version+1
                    WHERE tenant_id=? AND id=?
                      AND state IN ('leased','running','paused','canceling')
                    """,
                    (
                        int(row_dict["control_version"]),
                        tenant,
                        active["id"],
                    ),
                )
                self.conn.execute(
                    """
                    UPDATE durable_job_state_leases
                    SET revoked_at=COALESCE(revoked_at,?),
                        revoke_reason=COALESCE(revoke_reason,?),
                        expires_at=?
                    WHERE tenant_id=? AND attempt_id=?
                    """,
                    (now, reason, now, tenant, active["id"]),
                )
            self.conn.execute(
                """
                UPDATE durable_job_state_child_processes
                SET state='canceling',
                    cancel_requested_at=COALESCE(cancel_requested_at,?)
                WHERE tenant_id=? AND job_id=?
                  AND state IN ('running','paused','canceling','orphaned')
                """,
                (now, tenant, job_id),
            )
            process_rows = [dict(item) for item in children]
            self._event(
                tenant,
                job_id,
                "cancel_requested",
                attempt_id=str(active["id"]) if active is not None else None,
                actor=actor_record,
                reason=reason,
                data={
                    "child_count": len(process_rows),
                    "control_version": int(row_dict["control_version"]),
                    "sla_seconds": total_sla,
                },
            )

        deadline = started_monotonic + total_sla
        outcomes: list[tuple[dict[str, Any], str, int]] = []
        for process in process_rows:
            identity: ProcessIdentity | None
            try:
                identity = ProcessIdentity(
                    pid=int(process["pid"]),
                    start_token=str(process["start_token"]),
                    boot_id=str(process["boot_id"]),
                    command_digest=str(process["command_digest"]),
                    launch_nonce=str(process["launch_nonce"]),
                )
            except Exception:
                identity = None
            state = "orphaned"
            escalations = 0
            if identity is not None and supervisor is not None:
                try:
                    if not supervisor.is_alive(identity):
                        state = "stopped"
                    else:
                        supervisor.terminate(identity)
                        while (
                            time.monotonic() < deadline
                            and supervisor.is_alive(identity)
                        ):
                            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
                        if supervisor.is_alive(identity):
                            escalations = 1
                            supervisor.kill(identity)
                        state = (
                            "stopped"
                            if not supervisor.is_alive(identity)
                            else "orphaned"
                        )
                except Exception:
                    state = "orphaned"
            outcomes.append((process, state, escalations))

        with self._tx():
            row = self._job(tenant, job_id)
            if str(row["state"]) in TERMINAL_STATES:
                return self._row(row) or {}
            if str(row["state"]) != JobState.CANCELING.value:
                raise InvalidTransition(
                    "job changed while cancellation was being reconciled"
                )
            unresolved = False
            now = self.clock()
            for process, state, escalations in outcomes:
                changed = self.conn.execute(
                    """
                    UPDATE durable_job_state_child_processes
                    SET state=?,stopped_at=?,escalation_count=escalation_count+?
                    WHERE tenant_id=? AND attempt_id=? AND identity_key=?
                      AND state='canceling'
                    """,
                    (
                        state,
                        now if state == "stopped" else None,
                        escalations,
                        tenant,
                        process["attempt_id"],
                        process["identity_key"],
                    ),
                )
                if changed.rowcount != 1 and state != "stopped":
                    unresolved = True
                unresolved = unresolved or state != "stopped"
                self._event(
                    tenant,
                    job_id,
                    (
                        "child_cancel_stopped"
                        if state == "stopped"
                        else "child_cancel_orphaned"
                    ),
                    attempt_id=str(process["attempt_id"]),
                    actor=actor_record,
                    reason=reason,
                    data={
                        "identity_key": process["identity_key"],
                        "escalation_count": escalations,
                    },
                )
            active_rows = self.conn.execute(
                """
                SELECT id FROM durable_job_state_attempts
                WHERE tenant_id=? AND job_id=? AND state='canceling'
                """,
                (tenant, job_id),
            ).fetchall()
            for active in active_rows:
                self.conn.execute(
                    """
                    UPDATE durable_job_state_attempts
                    SET state=?,finished_at=?,version=version+1
                    WHERE tenant_id=? AND id=? AND state='canceling'
                    """,
                    (
                        AttemptState.ORPHANED.value
                        if unresolved
                        else AttemptState.CANCELED.value,
                        now,
                        tenant,
                        active["id"],
                    ),
                )
            attempt_for_gaps = (
                str(active_rows[0]["id"]) if active_rows else None
            )
            self._record_missing_required_work_tx(
                tenant,
                job_id,
                reason=reason,
                attempt_id=attempt_for_gaps,
                actor=actor_record,
            )
            row = self._job(tenant, job_id)
            target = (
                JobState.ORPHANED.value
                if unresolved
                else (
                    JobState.PARTIAL.value
                    if int(row["completed_work"]) > 0
                    else JobState.CANCELED.value
                )
            )
            result = self._transition_tx(
                tenant,
                job_id,
                target,
                expected_version=int(row["version"]),
                actor=actor_record,
                reason=(
                    "cancellation left an unverifiable child"
                    if unresolved
                    else reason
                ),
                idempotency_key=None,
                data={
                    "bounded_child_stop": not unresolved,
                    "child_count": len(outcomes),
                    "escalations": sum(item[2] for item in outcomes),
                },
            )
            elapsed = max(0.0, time.monotonic() - started_monotonic)
            self._event(
                tenant,
                job_id,
                "cancel_reconciled",
                actor=actor_record,
                reason=reason,
                data={
                    "sla_seconds": total_sla,
                    "elapsed_seconds": elapsed,
                    "within_sla": elapsed <= total_sla,
                },
            )
            return result

    cancel = cancel_job
    request_cancel = cancel_job

    def _active_attempt(self, tenant: str, job_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            """
            SELECT * FROM durable_job_state_attempts
            WHERE tenant_id=? AND job_id=?
              AND state IN ('leased','running','paused','canceling')
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
        max_lease_seconds: float | None = None,
        idempotency_key: str | None = None,
        attempt_id: str | None = None,
        actor: str | TransitionActor | None = None,
        attempt_authorization_decision_id: str | None = None,
        control_boot_id: str | None = None,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        worker_id = _identifier(worker_id, "worker_id")
        if control_boot_id is not None:
            control_boot_id = _identifier(
                control_boot_id,
                "control_boot_id",
            )
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        max_lease_seconds = (
            float(lease_seconds)
            if max_lease_seconds is None
            else float(max_lease_seconds)
        )
        if max_lease_seconds < float(lease_seconds):
            raise ValueError(
                "max_lease_seconds must be at least lease_seconds"
            )
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
                    if control_boot_id is not None and not hmac.compare_digest(
                        str(old["control_boot_id"] or ""),
                        control_boot_id,
                    ):
                        raise IdempotencyConflict(
                            "lease idempotency key was reused on another control boot"
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
                            str(lease["owner_id"]),
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
            decision_id = (
                str(job["authorization_decision_id"])
                if job["authorization_decision_id"] is not None
                else None
            )
            action_id = (
                str(job["authorization_action_id"])
                if job["authorization_action_id"] is not None
                else None
            )
            if not self._authorization_allowed(
                tenant,
                job_id,
                decision_id,
                action_id,
            ):
                raise InvalidTransition("lease requires an exact allowed authorization")
            if attempt_authorization_decision_id is not None:
                attempt_authorization_decision_id = _identifier(
                    attempt_authorization_decision_id,
                    "attempt_authorization_decision_id",
                )
                attempt_authorization = self.conn.execute(
                    "SELECT 1 FROM authorization_decisions "
                    "WHERE tenant_id=? AND job_id=? AND decision_id=? "
                    "AND decision_outcome='allow'",
                    (tenant, job_id, attempt_authorization_decision_id),
                ).fetchone()
                if (
                    attempt_authorization is None
                    and self.authorization_checker is None
                ):
                    raise InvalidTransition(
                        "attempt authorization is unavailable"
                    )
            assigned_agent = str(job["assigned_agent_id"] or "")
            if assigned_agent and not hmac.compare_digest(
                assigned_agent,
                worker_id,
            ):
                raise LeaseUnavailable("job is assigned to another worker")
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
            delivery_idempotency_key = _identifier(
                f"delivery:{uuid.uuid4().hex}",
                "delivery_idempotency_key",
            )
            launch_nonce = _identifier(
                f"launch-{uuid.uuid4().hex}",
                "launch_nonce",
            )
            attempt_run_id = _identifier(
                f"{job['run_id']}:attempt:{count + 1}",
                "attempt_run_id",
            )
            token = self._lease_token(tenant, attempt_id, worker_id, 1)
            digest = _token_digest(token)
            expires = now + float(lease_seconds)
            max_expires = now + max_lease_seconds
            self.conn.execute(
                """
                INSERT INTO durable_job_state_attempts(
                    tenant_id,id,job_id,number,idempotency_key,state,worker_id,
                    control_boot_id,lease_token_digest,lease_generation,lease_expires_at,
                    lease_max_expires_at,delivery_idempotency_key,run_id,
                    authorization_decision_id,
                    launch_nonce,control_version
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    tenant,
                    attempt_id,
                    job_id,
                    count + 1,
                    idempotency_key,
                    AttemptState.LEASED.value,
                    worker_id,
                    control_boot_id,
                    digest,
                    1,
                    expires,
                    max_expires,
                    delivery_idempotency_key,
                    attempt_run_id,
                    attempt_authorization_decision_id or decision_id,
                    launch_nonce,
                    int(job["control_version"]),
                ),
            )
            self.conn.execute(
                """
                INSERT INTO durable_job_state_leases(
                    tenant_id,attempt_id,job_id,token_digest,owner_id,generation,
                    issued_at,expires_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    tenant,
                    attempt_id,
                    job_id,
                    digest,
                    worker_id,
                    1,
                    now,
                    expires,
                ),
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

    def _latest_work_rows(
        self,
        tenant: str,
        job_id: str,
    ) -> list[sqlite3.Row]:
        """Return the latest immutable outcome for each planned work key."""

        return self.conn.execute(
            """
            SELECT wi.*
            FROM durable_job_state_work_items wi
            LEFT JOIN durable_job_state_attempts a
              ON a.tenant_id=wi.tenant_id AND a.id=wi.attempt_id
            WHERE wi.tenant_id=? AND wi.job_id=?
              AND NOT EXISTS (
                SELECT 1
                FROM durable_job_state_work_items newer
                LEFT JOIN durable_job_state_attempts newer_attempt
                  ON newer_attempt.tenant_id=newer.tenant_id
                 AND newer_attempt.id=newer.attempt_id
                WHERE newer.tenant_id=wi.tenant_id
                  AND newer.job_id=wi.job_id
                  AND newer.work_key=wi.work_key
                  AND (
                    COALESCE(newer_attempt.number, 2147483647)
                      > COALESCE(a.number, 2147483647)
                    OR (
                      COALESCE(newer_attempt.number, 2147483647)
                        = COALESCE(a.number, 2147483647)
                      AND newer.updated_at > wi.updated_at
                    )
                  )
              )
            ORDER BY wi.work_key
            """,
            (tenant, job_id),
        ).fetchall()

    def _refresh_counters(self, tenant: str, job_id: str) -> None:
        values = {
            state: 0
            for state in (
                WorkState.COMPLETED.value,
                WorkState.SKIPPED.value,
                WorkState.FAILED.value,
                WorkState.TRUNCATED.value,
                WorkState.UNCOLLECTED.value,
            )
        }
        required_keys = {
            str(row["work_key"])
            for row in self.conn.execute(
                "SELECT work_key FROM durable_job_state_work_plan "
                "WHERE tenant_id=? AND job_id=? AND required=1",
                (tenant, job_id),
            ).fetchall()
        }
        for row in self._latest_work_rows(tenant, job_id):
            if str(row["work_key"]) in required_keys and str(row["state"]) in values:
                values[str(row["state"])] += 1
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
        actor: str | TransitionActor = "system",
    ) -> int:
        """Make cancellation/recovery gaps explicit before terminalization.

        A job may declare a required-work count before concrete keys are known.
        On a terminal interruption, pending known keys become uncollected and
        any remaining declared slots receive deterministic synthetic keys.
        This keeps coverage measured and auditable instead of silently treating
        an interrupted job as complete or fully described.
        """

        job = self._job(tenant, job_id)
        planned = [
            str(row["work_key"])
            for row in self.conn.execute(
                "SELECT work_key FROM durable_job_state_work_plan "
                "WHERE tenant_id=? AND job_id=? AND required=1 "
                "ORDER BY work_key",
                (tenant, job_id),
            ).fetchall()
        ]
        if not planned:
            return 0
        safe_reason = str(reason or "work was not collected")[:2000]
        now = self.clock()
        latest = {
            str(row["work_key"]): row
            for row in self._latest_work_rows(tenant, job_id)
        }
        scope = attempt_id or "job-terminal"
        missing_keys = [key for key in planned if key not in latest]
        for work_key in missing_keys:
            self.conn.execute(
                """
                INSERT INTO durable_job_state_work_items(
                    tenant_id,job_id,attempt_id,attempt_scope,work_key,state,
                    required,reason,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(tenant_id,job_id,attempt_scope,work_key) DO NOTHING
                """,
                (
                    tenant,
                    job_id,
                    attempt_id,
                    scope,
                    work_key,
                    WorkState.UNCOLLECTED.value,
                    1,
                    safe_reason,
                    now,
                ),
            )
        self._refresh_counters(tenant, job_id)
        if missing_keys:
            self._event(
                tenant,
                job_id,
                "required_work_uncollected",
                attempt_id=attempt_id,
                actor=actor,
                reason=safe_reason,
                data={
                    "declared_required": int(job["required_work"]),
                    "missing_slots": len(missing_keys),
                    "work_keys": missing_keys,
                },
            )
        return len(missing_keys)

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
        actor: str | TransitionActor = "worker",
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
        plan = self.conn.execute(
            """
            SELECT required FROM durable_job_state_work_plan
            WHERE tenant_id=? AND job_id=? AND work_key=?
            """,
            (tenant, job_id, work_key),
        ).fetchone()
        if plan is None:
            raise InvalidTransition("work item is not in the immutable job plan")
        if bool(plan["required"]) != bool(required):
            raise InvalidTransition("work required flag differs from the job plan")
        if attempt_id is None:
            if normalized_state == WorkState.PENDING.value:
                return False
            raise InvalidTransition("work outcome requires an attempt")
        attempt_id = _identifier(attempt_id, "attempt_id")
        linked_attempt = self._attempt(tenant, attempt_id)
        if str(linked_attempt["job_id"]) != job_id:
            raise InvalidTransition("attempt does not belong to the job")
        attempt_scope = attempt_id
        old = self.conn.execute(
            """
            SELECT * FROM durable_job_state_work_items
            WHERE tenant_id=? AND job_id=? AND attempt_scope=? AND work_key=?
            """,
            (tenant, job_id, attempt_scope, work_key),
        ).fetchone()
        same_material = old is not None and (
            str(old["state"]) == normalized_state
            and int(old["required"]) == int(required)
            and str(old["reason"] or "") == str(reason or "")
            and str(old["observation_id"] or "") == str(observation_id or "")
            and str(old["result_ref"] or "") == str(result_ref or "")
        )
        if old is not None:
            if same_material:
                return False
            raise IdempotencyConflict(
                "attempt work item was delivered with different result material"
            )
        if str(job["state"]) in TERMINAL_STATES:
            raise TerminalStateError(
                f"cannot record work for terminal job state {job['state']}"
            )
        self.conn.execute(
            """
            INSERT INTO durable_job_state_work_items(
                tenant_id,job_id,attempt_id,attempt_scope,work_key,state,
                required,reason,observation_id,result_ref,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                tenant,
                job_id,
                attempt_id,
                attempt_scope,
                work_key,
                normalized_state,
                int(required),
                reason,
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
        actor: str | TransitionActor = "worker",
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
            history = self.conn.execute(
                """
                SELECT * FROM durable_job_state_work_items
                WHERE tenant_id=? AND job_id=?
                ORDER BY work_key,updated_at,attempt_scope
                """,
                (tenant, job_id),
            ).fetchall()
            latest = {
                str(row["work_key"]): self._row(row) or {}
                for row in self._latest_work_rows(tenant, job_id)
            }
            planned = [
                str(row["work_key"])
                for row in self.conn.execute(
                    "SELECT work_key FROM durable_job_state_work_plan "
                    "WHERE tenant_id=? AND job_id=? AND required=1 "
                    "ORDER BY work_key",
                    (tenant, job_id),
                ).fetchall()
            ]
            items = []
            for key in planned:
                if key in latest:
                    items.append(latest[key])
                else:
                    items.append(
                        {
                            "tenant_id": tenant,
                            "job_id": job_id,
                            "work_key": key,
                            "state": WorkState.PENDING.value,
                            "status": WorkState.PENDING.value,
                            "required": 1,
                            "reason": None,
                            "attempt_id": None,
                            "observation_id": None,
                            "result_ref": None,
                        }
                    )
            return {
                "required": int(job["required_work"]),
                "completed": int(job["completed_work"]),
                "skipped": int(job["skipped_work"]),
                "failed": int(job["failed_work"]),
                "truncated": int(job["truncated_work"]),
                "uncollected": int(job["uncollected_work"]),
                "items": items,
                "history": [self._row(row) or {} for row in history],
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
        if str(attempt["state"]) not in {
            AttemptState.LEASED.value,
            AttemptState.RUNNING.value,
        }:
            raise LeaseError("attempt is paused or canceling")
        job = self._job(tenant, str(attempt["job_id"]))
        if str(job["state"]) not in {
            JobState.LEASED.value,
            JobState.RUNNING.value,
        }:
            raise LeaseError("job state fences the lease")
        if int(attempt["control_version"]) != int(job["control_version"]):
            raise LeaseError("lease control version is stale")
        return attempt, lease

    def _check_delivery_token(
        self,
        tenant: str,
        attempt_id: str,
        token: str,
        *,
        worker_id: str | None = None,
        server_recovery: bool = False,
    ) -> sqlite3.Row:
        """Authenticate an idempotent replay without reactivating a lease.

        Result delivery may be redelivered after the original attempt has
        atomically reached a terminal state.  The persisted token digest is
        sufficient to authenticate that exact replay, but it never authorizes
        a new result or any further state transition after revocation/expiry.
        """

        attempt = self._attempt(tenant, attempt_id)
        lease = self.conn.execute(
            "SELECT token_digest,owner_id,expires_at,revoked_at,revoke_reason "
            "FROM durable_job_state_leases "
            "WHERE tenant_id=? AND attempt_id=?",
            (tenant, attempt_id),
        ).fetchone()
        if lease is None:
            raise LeaseError("lease is missing")
        if worker_id is not None and not hmac.compare_digest(
            str(lease["owner_id"]),
            _identifier(worker_id, "worker_id"),
        ):
            raise LeaseError("lease owner mismatch")
        if not hmac.compare_digest(str(lease["token_digest"]), _token_digest(token)):
            raise LeaseError("lease token mismatch")
        if not server_recovery:
            finished_replay = bool(
                lease["revoked_at"] is not None
                and str(lease["revoke_reason"] or "") == "attempt finished"
                and str(attempt["state"]) not in ACTIVE_ATTEMPT_STATES
            )
            if lease["revoked_at"] is not None and not finished_replay:
                raise LeaseError("lease is revoked")
            if (
                lease["revoked_at"] is None
                and float(lease["expires_at"]) <= float(self.clock())
            ):
                raise LeaseError("lease expired")
        return attempt

    def start_attempt(
        self,
        attempt_id: str,
        lease_token: str,
        *,
        tenant_id: str = "default",
        actor: str | TransitionActor = "worker",
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
            if not self._authorization_allowed(
                tenant,
                str(attempt["job_id"]),
                (
                    str(job["authorization_decision_id"])
                    if job["authorization_decision_id"] is not None
                    else None
                ),
                (
                    str(job["authorization_action_id"])
                    if job["authorization_action_id"] is not None
                    else None
                ),
                require_consumed=True,
            ):
                raise InvalidTransition(
                    "attempt start requires a consumed authorization"
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
        actor: str | TransitionActor = "worker",
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
            token = self._lease_token(
                tenant,
                attempt_id,
                str(lease["owner_id"]),
                generation,
            )
            digest = _token_digest(token)
            now = self.clock()
            max_expires = float(
                attempt["lease_max_expires_at"]
                if attempt["lease_max_expires_at"] is not None
                else lease["expires_at"]
            )
            if max_expires <= now:
                raise LeaseError("maximum lease lifetime expired")
            expires = min(now + float(lease_seconds), max_expires)
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
        actor: str | TransitionActor = "system",
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
                WHERE tenant_id=? AND id=?
                  AND state IN ('leased','running','paused','canceling')
                """,
                (now, tenant, attempt_id),
            )
            job = self._job(tenant, attempt["job_id"])
            if str(job["state"]) in {
                JobState.LEASED.value,
                JobState.RUNNING.value,
                JobState.PAUSED.value,
                JobState.CANCELING.value,
            }:
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

    def _bind_run_truth_receipts_session(
        self,
        session: Session,
        attempt_row: Mapping[str, Any],
        receipts: Iterable[RunTruthReceipt],
        *,
        actor: str | TransitionActor,
    ) -> None:
        """Bind validated proof rows inside the canonical custody transaction."""

        truth_receipts = _canonical_run_truth_receipts(receipts)
        if not truth_receipts:
            return
        tenant = str(attempt_row["tenant_id"])
        attempt_id = str(attempt_row["id"])
        job_id = str(attempt_row["job_id"])
        actor_record = _actor(actor, tenant_id=tenant, default_role="worker")
        for receipt in truth_receipts:
            try:
                truth = load_run_collection_truth(
                    session,
                    receipt.run_id,
                    tenant_id=tenant,
                )
            except PersistedRunTruthValidationError as exc:
                raise InvalidTransition("signed run truth is invalid") from exc
            if truth is None:
                raise InvalidTransition("signed run truth is unavailable")
            expected = _run_truth_receipt(
                truth,
                tenant_id=tenant,
                job_id=job_id,
                attempt_id=attempt_id,
            )
            if expected != receipt:
                raise InvalidTransition("signed run truth receipt changed")
            authorization_binding = session.execute(
                text(
                    "SELECT 1 FROM durable_job_state_job_authorizations "
                    "WHERE tenant_id=:tenant_id AND job_id=:job_id "
                    "AND authorization_decision_id=:decision_id "
                    "AND framework=:framework AND active=1"
                ),
                {
                    "tenant_id": tenant,
                    "job_id": job_id,
                    "decision_id": truth.authorization_decision_id,
                    "framework": truth.framework,
                },
            ).first()
            if (
                authorization_binding is None
                and attempt_row["assigned_agent_id"] is not None
            ):
                authorization_binding = session.execute(
                    text(
                        "SELECT 1 FROM authorization_decisions d "
                        "JOIN authorization_consumptions c "
                        "ON c.decision_id=d.decision_id "
                        "AND c.tenant_id=d.tenant_id "
                        "AND c.job_id=d.job_id "
                        "AND c.action_id=d.action_id "
                        "AND c.envelope_digest=d.binding_digest "
                        "WHERE d.tenant_id=:tenant_id AND d.job_id=:job_id "
                        "AND d.decision_id=:decision_id "
                        "AND d.parent_decision_id=:parent_decision_id "
                        "AND d.engine=:framework AND d.run_id=:run_id "
                        "AND d.decision_outcome='allow' "
                        "AND c.boundary=:boundary LIMIT 1"
                    ),
                    {
                        "tenant_id": tenant,
                        "job_id": job_id,
                        "decision_id": truth.authorization_decision_id,
                        "parent_decision_id": attempt_row[
                            "attempt_authorization_decision_id"
                        ],
                        "framework": truth.framework,
                        "run_id": truth.authorization_run_id,
                        "boundary": f"{truth.framework}.engine",
                    },
                ).first()
            if attempt_row["assigned_agent_id"] is not None:
                planned = (
                    truth.framework == str(attempt_row["job_kind"])
                    and session.execute(
                        text(
                            "SELECT 1 FROM durable_job_state_work_plan "
                            "WHERE tenant_id=:tenant_id AND job_id=:job_id "
                            "AND required=1 LIMIT 1"
                        ),
                        {"tenant_id": tenant, "job_id": job_id},
                    ).first()
                    is not None
                )
            else:
                planned = (
                    session.execute(
                        text(
                            "SELECT 1 FROM durable_job_state_work_plan "
                            "WHERE tenant_id=:tenant_id AND job_id=:job_id "
                            "AND work_key=:framework AND required=1"
                        ),
                        {
                            "tenant_id": tenant,
                            "job_id": job_id,
                            "framework": truth.framework,
                        },
                    ).first()
                    is not None
                )
            if (
                truth.tenant_id != tenant
                or truth.job_id != job_id
                or truth.authorization_run_id != str(attempt_row["job_run_id"])
                or authorization_binding is None
                or not planned
            ):
                raise InvalidTransition("signed run truth assignment mismatch")
            old = session.execute(
                text(
                    "SELECT outcome,coverage_identity,result_ref "
                    "FROM durable_job_state_terminal_proofs "
                    "WHERE tenant_id=:tenant_id AND attempt_id=:attempt_id "
                    "AND proof_type='run_truth' "
                    "AND proof_identity=:proof_identity"
                ),
                {
                    "tenant_id": tenant,
                    "attempt_id": attempt_id,
                    "proof_identity": receipt.proof_identity,
                },
            ).mappings().first()
            if old is not None:
                if (
                    str(old["outcome"]) != receipt.outcome
                    or str(old["coverage_identity"]) != receipt.coverage_identity
                    or str(old["result_ref"]) != receipt.result_ref
                ):
                    raise IdempotencyConflict("signed run-truth proof conflicts")
                continue
            now = self.clock()
            session.execute(
                text(
                    "INSERT INTO durable_job_state_terminal_proofs("
                    "tenant_id,job_id,attempt_id,proof_type,outcome,"
                    "proof_identity,coverage_identity,result_ref,recorded_at"
                    ") VALUES(:tenant_id,:job_id,:attempt_id,'run_truth',"
                    ":outcome,:proof_identity,:coverage_identity,:result_ref,"
                    ":recorded_at)"
                ),
                {
                    "tenant_id": tenant,
                    "job_id": job_id,
                    "attempt_id": attempt_id,
                    "outcome": receipt.outcome,
                    "proof_identity": receipt.proof_identity,
                    "coverage_identity": receipt.coverage_identity,
                    "result_ref": receipt.result_ref,
                    "recorded_at": now,
                },
            )
            session.execute(
                text(
                    "INSERT INTO durable_job_state_events("
                    "tenant_id,job_id,attempt_id,event_type,from_state,to_state,"
                    "actor,actor_role,authorization_decision_id,reason,"
                    "reason_code,idempotency_key,job_version,data_json,occurred_at"
                    ") VALUES(:tenant_id,:job_id,:attempt_id,'run_truth_accepted',"
                    "NULL,NULL,:actor,:actor_role,:authorization_decision_id,"
                    ":reason,:reason_code,NULL,:job_version,:data_json,:occurred_at)"
                ),
                {
                    "tenant_id": tenant,
                    "job_id": job_id,
                    "attempt_id": attempt_id,
                    "actor": actor_record.actor_id,
                    "actor_role": actor_record.role,
                    "authorization_decision_id": (
                        actor_record.authorization_decision_id
                    ),
                    "reason": receipt.collection_status,
                    "reason_code": _reason_code(receipt.collection_status),
                    "job_version": int(attempt_row["job_version"]),
                    "data_json": _json(
                        {
                            "run_truth_id": receipt.run_id,
                            "coverage_identity": receipt.coverage_identity,
                            "coverage_complete": receipt.coverage_complete,
                        }
                    ),
                    "occurred_at": now,
                },
            )

    def reserve_custodied_result(
        self,
        session: Session,
        attempt_id: str,
        lease_token: str,
        *,
        delivery_key: str,
        tenant_id: str,
        receipt: ObservationReceipt,
        outcome: str,
        work: Iterable[Mapping[str, Any]] = (),
        run_truths: Iterable[RunTruthReceipt] = (),
        worker_id: str | None = None,
        actor: str | TransitionActor = "worker",
    ) -> dict[str, Any]:
        """Atomically authorize custody inside its canonical SQLite transaction.

        ``CanonicalStore`` already holds ``BEGIN IMMEDIATE`` on the shared
        database when this method is called.  Validating the current lease and
        inserting the ``custodied`` delivery on that same connection makes the
        canonical observation and its durable acceptance reservation one
        commit.  A callback failure rolls back the database rows and the
        canonical evidence adapter rolls back newly staged custody bytes.
        """

        connection = session.connection()
        database = getattr(connection.engine.url, "database", None)
        if not database or Path(str(database)).resolve() != Path(self.db_path).resolve():
            raise InvalidTransition("custody transaction is outside the durable store")
        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        delivery_key = _identifier(delivery_key, "delivery_key")
        if not isinstance(receipt, ObservationReceipt):
            raise ValueError("custody reservation requires a typed observation receipt")
        if receipt.tenant_id != tenant or receipt.attempt_id != attempt_id:
            raise InvalidTransition("custody receipt assignment mismatch")
        normalized_outcome = str(outcome).strip().lower()
        if normalized_outcome not in {"success", "failure", "canceled", "partial"}:
            raise ValueError("unsupported result outcome")
        truth_receipts = _canonical_run_truth_receipts(run_truths)
        identity, materialized = _result_delivery_identity(
            receipt,
            work=work,
            outcome=normalized_outcome,
            run_truths=truth_receipts,
        )
        work_json = _json(materialized)
        run_truth_json = _json([item.to_dict() for item in truth_receipts])
        row = connection.exec_driver_sql(
            """
            SELECT a.tenant_id,a.id,a.job_id,a.state AS attempt_state,a.worker_id,
                   a.authorization_decision_id AS attempt_authorization_decision_id,
                   a.delivery_idempotency_key,a.lease_token_digest,
                   a.control_version AS attempt_control_version,
                   l.owner_id,l.token_digest,l.expires_at,l.revoked_at,
                   j.state AS job_state,j.control_version AS job_control_version,
                   j.version AS job_version,j.run_id AS job_run_id,
                   j.assigned_agent_id,j.job_kind
            FROM durable_job_state_attempts a
            JOIN durable_job_state_leases l
              ON l.tenant_id=a.tenant_id AND l.attempt_id=a.id
            JOIN durable_job_state_jobs j
              ON j.tenant_id=a.tenant_id AND j.id=a.job_id
            WHERE a.tenant_id=? AND a.id=?
            """,
            (tenant, attempt_id),
        ).mappings().first()
        if row is None or row["revoked_at"] is not None:
            raise LeaseError("lease is revoked or missing")
        owner = _identifier(worker_id, "worker_id") if worker_id is not None else None
        if owner is not None and not hmac.compare_digest(str(row["owner_id"]), owner):
            raise LeaseError("lease owner mismatch")
        supplied = _token_digest(lease_token)
        if not hmac.compare_digest(str(row["token_digest"]), supplied):
            raise LeaseError("lease token mismatch")
        if float(row["expires_at"]) <= float(self.clock()):
            raise LeaseError("lease expired")
        if not hmac.compare_digest(str(row["lease_token_digest"]), supplied):
            raise LeaseError("stale lease generation")
        if str(row["attempt_state"]) not in {
            AttemptState.LEASED.value,
            AttemptState.RUNNING.value,
        }:
            raise LeaseError("attempt is no longer deliverable")
        if str(row["job_state"]) not in {
            JobState.LEASED.value,
            JobState.RUNNING.value,
        }:
            raise LeaseError("job state fences the lease")
        if int(row["attempt_control_version"]) != int(row["job_control_version"]):
            raise LeaseError("lease control version is stale")
        if str(row["job_id"]) != receipt.job_id:
            raise InvalidTransition("custody receipt job mismatch")
        if not hmac.compare_digest(str(row["delivery_idempotency_key"]), delivery_key):
            raise IdempotencyConflict("delivery identity is not server-issued")
        if truth_receipts:
            if _aggregate_run_truth_outcome(truth_receipts) != normalized_outcome:
                raise IdempotencyConflict(
                    "result outcome conflicts with signed run truth"
                )
            work_by_key = {str(item["work_key"]): item for item in materialized}
            if row["assigned_agent_id"] is not None:
                planned_keys = {
                    str(item[0])
                    for item in connection.exec_driver_sql(
                        "SELECT work_key FROM durable_job_state_work_plan "
                        "WHERE tenant_id=? AND job_id=? AND required=1",
                        (tenant, receipt.job_id),
                    ).fetchall()
                }
                if (
                    len(truth_receipts) != 1
                    or truth_receipts[0].framework != str(row["job_kind"])
                    or set(work_by_key) != planned_keys
                ):
                    raise IdempotencyConflict(
                        "assigned result work does not match signed run truth"
                    )
                truth_for_work = {
                    work_key: truth_receipts[0] for work_key in planned_keys
                }
            else:
                truth_for_work = {
                    item.framework: item for item in truth_receipts
                }
            if set(work_by_key) != set(truth_for_work):
                raise IdempotencyConflict(
                    "result work does not match signed run-truth frameworks"
                )
            for work_key, truth_receipt in truth_for_work.items():
                expected_state = (
                    WorkState.COMPLETED.value
                    if truth_receipt.outcome == "success"
                    else WorkState.FAILED.value
                    if truth_receipt.outcome == "failure"
                    else WorkState.UNCOLLECTED.value
                )
                work_item = work_by_key[work_key]
                if (
                    not bool(work_item.get("required", True))
                    or str(work_item.get("state") or WorkState.COMPLETED.value)
                    != expected_state
                ):
                    raise IdempotencyConflict(
                        "result work conflicts with signed run truth"
                    )
            self._bind_run_truth_receipts_session(
                session,
                cast(Mapping[str, Any], row),
                truth_receipts,
                actor=actor,
            )
        old = connection.exec_driver_sql(
            "SELECT * FROM durable_job_state_deliveries "
            "WHERE tenant_id=? AND attempt_id=? AND idempotency_key=?",
            (tenant, attempt_id, delivery_key),
        ).mappings().first()
        if old is not None:
            exact = (
                hmac.compare_digest(str(old["payload_identity"]), identity)
                and hmac.compare_digest(str(old["observation_id"]), receipt.observation_id)
                and hmac.compare_digest(str(old["artifact_id"]), receipt.artifact_id)
                and hmac.compare_digest(str(old["result_ref"] or ""), receipt.result_ref)
                and hmac.compare_digest(
                    str(old["manifest_digest"]), receipt.manifest_digest
                )
                and str(old["outcome"]) == normalized_outcome
                and str(old["work_json"]) == work_json
                and str(old["run_truth_json"]) == run_truth_json
            )
            if not exact or str(old["state"]) not in {"custodied", "accepted"}:
                raise IdempotencyConflict("custody reservation identity conflicts")
            return {
                "state": str(old["state"]),
                "result_identity": identity,
                "duplicate": True,
                "work": materialized,
            }
        now = self.clock()
        connection.exec_driver_sql(
            """
            INSERT INTO durable_job_state_deliveries(
                tenant_id,attempt_id,job_id,idempotency_key,state,
                payload_identity,observation_id,artifact_id,result_ref,
                result_identity,manifest_digest,outcome,work_json,run_truth_json,
                reserved_at,accepted_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)
            """,
            (
                tenant,
                attempt_id,
                receipt.job_id,
                delivery_key,
                "custodied",
                identity,
                receipt.observation_id,
                receipt.artifact_id,
                receipt.result_ref,
                identity,
                receipt.manifest_digest,
                normalized_outcome,
                work_json,
                run_truth_json,
                now,
            ),
        )
        return {
            "state": "custodied",
            "result_identity": identity,
            "duplicate": False,
            "work": materialized,
        }

    def record_result(
        self,
        attempt_id: str,
        lease_token: str,
        *,
        delivery_key: str,
        tenant_id: str = "default",
        receipt: ObservationReceipt | None = None,
        outcome: str = "success",
        work: Iterable[Mapping[str, Any]] = (),
        run_truths: Iterable[RunTruthReceipt] = (),
        worker_id: str | None = None,
        actor: str | TransitionActor = "worker",
    ) -> dict[str, Any]:
        """Accept one currently leased, verified Task 102 receipt exactly once."""

        return self._record_result(
            attempt_id,
            lease_token,
            delivery_key=delivery_key,
            tenant_id=tenant_id,
            receipt=receipt,
            outcome=outcome,
            work=work,
            run_truths=run_truths,
            worker_id=worker_id,
            actor=actor,
            _recovery=False,
        )

    def _record_result(
        self,
        attempt_id: str,
        lease_token: str,
        *,
        delivery_key: str,
        tenant_id: str = "default",
        receipt: ObservationReceipt | None = None,
        outcome: str = "success",
        work: Iterable[Mapping[str, Any]] = (),
        run_truths: Iterable[RunTruthReceipt] = (),
        worker_id: str | None = None,
        actor: str | TransitionActor = "worker",
        _recovery: bool = False,
    ) -> dict[str, Any]:
        """Internal acceptance core with an explicit server-recovery mode."""

        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        delivery_key = _identifier(delivery_key, "delivery_key")
        if not isinstance(receipt, ObservationReceipt):
            raise ValueError("result delivery requires a typed observation receipt")
        if receipt.tenant_id != tenant or receipt.attempt_id != attempt_id:
            raise InvalidTransition("observation receipt assignment mismatch")
        outcome = str(outcome).strip().lower()
        if outcome not in {"success", "failure", "canceled", "partial"}:
            raise ValueError("unsupported result outcome")
        truth_receipts = _canonical_run_truth_receipts(run_truths)
        identity, materialized = _result_delivery_identity(
            receipt,
            work=work,
            outcome=outcome,
            run_truths=truth_receipts,
        )
        work_json = _json(materialized)
        run_truth_json = _json([item.to_dict() for item in truth_receipts])
        with self._tx():
            attempt = self._attempt(tenant, attempt_id)
            if str(attempt["job_id"]) != receipt.job_id:
                raise InvalidTransition("observation receipt job mismatch")
            if not hmac.compare_digest(
                str(attempt["delivery_idempotency_key"]),
                delivery_key,
            ):
                raise IdempotencyConflict("delivery identity is not server-issued")
            old = self.conn.execute(
                """
                SELECT * FROM durable_job_state_deliveries
                WHERE tenant_id=? AND attempt_id=? AND idempotency_key=?
                """,
                (tenant, attempt_id, delivery_key),
            ).fetchone()
            if old is not None and str(old["state"]) == "accepted":
                self._check_delivery_token(
                    tenant,
                    attempt_id,
                    lease_token,
                    worker_id=worker_id,
                )
                if str(old["payload_identity"]) != identity:
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
            custodied = old is not None and str(old["state"]) == "custodied"
            if custodied:
                if (
                    str(old["payload_identity"]) != identity
                    or str(old["observation_id"]) != receipt.observation_id
                    or str(old["artifact_id"]) != receipt.artifact_id
                    or str(old["result_ref"] or "") != receipt.result_ref
                    or str(old["manifest_digest"]) != receipt.manifest_digest
                    or str(old["outcome"]) != outcome
                    or str(old["work_json"]) != work_json
                    or str(old["run_truth_json"]) != run_truth_json
                ):
                    raise IdempotencyConflict(
                        "custodied result delivery material differs"
                    )
                if _recovery:
                    # Only server-owned reconciliation reconstructs the exact
                    # persisted owner/generation token. It may recover after
                    # expiry/revocation but cannot introduce different result
                    # material or reactivate the lease.
                    attempt = self._check_delivery_token(
                        tenant,
                        attempt_id,
                        lease_token,
                        worker_id=worker_id,
                        server_recovery=True,
                    )
                else:
                    attempt, _lease = self._check_lease(
                        tenant,
                        attempt_id,
                        lease_token,
                        worker_id=worker_id,
                    )
            else:
                attempt, _lease = self._check_lease(
                    tenant,
                    attempt_id,
                    lease_token,
                    worker_id=worker_id,
                )
            if not self._observation_receipt_valid(receipt):
                raise InvalidTransition("Task 102 observation receipt is not verified")
            now = self.clock()
            if old is None:
                self.conn.execute(
                    """
                    INSERT INTO durable_job_state_deliveries(
                        tenant_id,attempt_id,job_id,idempotency_key,state,
                        payload_identity,observation_id,artifact_id,result_ref,
                        result_identity,manifest_digest,outcome,work_json,
                        run_truth_json,reserved_at,accepted_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        tenant,
                        attempt_id,
                        receipt.job_id,
                        delivery_key,
                        "accepted",
                        identity,
                        receipt.observation_id,
                        receipt.artifact_id,
                        receipt.result_ref,
                        identity,
                        receipt.manifest_digest,
                        outcome,
                        work_json,
                        run_truth_json,
                        now,
                        now,
                    ),
                )
            else:
                if str(old["payload_identity"]) != identity:
                    raise IdempotencyConflict(
                        "reserved result delivery material differs"
                    )
                self.conn.execute(
                    """
                    UPDATE durable_job_state_deliveries
                    SET state='accepted',result_ref=?,result_identity=?,
                        manifest_digest=?,outcome=?,work_json=?,run_truth_json=?,
                        accepted_at=?
                    WHERE tenant_id=? AND attempt_id=? AND idempotency_key=?
                      AND state IN ('reserved','custodied')
                    """,
                    (
                        receipt.result_ref,
                        identity,
                        receipt.manifest_digest,
                        outcome,
                        work_json,
                        run_truth_json,
                        now,
                        tenant,
                        attempt_id,
                        delivery_key,
                    ),
                )
            self.conn.execute(
                """
                INSERT OR IGNORE INTO durable_job_state_terminal_proofs(
                    tenant_id,job_id,attempt_id,proof_type,outcome,proof_identity,
                    coverage_identity,result_ref,recorded_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    tenant,
                    receipt.job_id,
                    attempt_id,
                    "observation_receipt",
                    outcome,
                    receipt.manifest_digest,
                    identity,
                    receipt.result_ref,
                    now,
                ),
            )
            job = self._job(tenant, str(attempt["job_id"]))
            terminal_job = str(job["state"]) in TERMINAL_STATES
            if not terminal_job:
                for item in materialized:
                    self._mark_work_tx(
                        tenant,
                        attempt["job_id"],
                        str(item["work_key"]),
                        state=item.get("state", WorkState.COMPLETED.value),
                        required=bool(item.get("required", True)),
                        reason=item.get("reason"),
                        attempt_id=attempt_id,
                        observation_id=receipt.observation_id,
                        result_ref=receipt.result_ref,
                        actor=actor,
                        accepted_delivery=True,
                    )
            self._event(
                tenant,
                attempt["job_id"],
                (
                    "result_accepted_after_terminal"
                    if terminal_job
                    else "result_accepted"
                ),
                attempt_id=attempt_id,
                actor=actor,
                reason="idempotent result delivery accepted",
                data={
                    "delivery_key": delivery_key,
                    "observation_id": receipt.observation_id,
                    "artifact_id": receipt.artifact_id,
                    "result_identity": identity,
                },
            )
            return {
                "accepted": True,
                "duplicate": False,
                "delivery_key": delivery_key,
                "observation_id": receipt.observation_id,
                "artifact_id": receipt.artifact_id,
                "result_identity": identity,
                "terminal_job_unchanged": terminal_job,
            }

    def _load_validated_run_truth(
        self,
        tenant: str,
        run_truth_id: str,
    ) -> RunCollectionTruth:
        """Load one immutable signed truth through the Task 006 trust root."""

        session = create_db(Path(self.db_path))
        try:
            try:
                truth = load_run_collection_truth(
                    session,
                    run_truth_id,
                    tenant_id=tenant,
                )
            except PersistedRunTruthValidationError as exc:
                raise InvalidTransition("signed run truth is invalid") from exc
        finally:
            session.close()
        if truth is None:
            raise InvalidTransition("signed run truth is unavailable")
        return truth

    def _run_truth_assignment_valid_sqlite(
        self,
        tenant: str,
        attempt: sqlite3.Row,
        job: sqlite3.Row,
        truth: RunCollectionTruth,
    ) -> bool:
        authorization_binding = self.conn.execute(
            """
            SELECT 1 FROM durable_job_state_job_authorizations
            WHERE tenant_id=? AND job_id=?
              AND authorization_decision_id=? AND framework=?
              AND active=1
            """,
            (
                tenant,
                attempt["job_id"],
                truth.authorization_decision_id,
                truth.framework,
            ),
        ).fetchone()
        if authorization_binding is None and job["assigned_agent_id"] is not None:
            authorization_binding = self.conn.execute(
                """
                SELECT 1
                FROM authorization_decisions d
                JOIN authorization_consumptions c
                  ON c.decision_id=d.decision_id
                 AND c.tenant_id=d.tenant_id
                 AND c.job_id=d.job_id
                 AND c.action_id=d.action_id
                 AND c.envelope_digest=d.binding_digest
                WHERE d.tenant_id=? AND d.job_id=?
                  AND d.decision_id=? AND d.parent_decision_id=?
                  AND d.engine=? AND d.run_id=?
                  AND d.decision_outcome='allow'
                  AND c.boundary=?
                LIMIT 1
                """,
                (
                    tenant,
                    attempt["job_id"],
                    truth.authorization_decision_id,
                    attempt["authorization_decision_id"],
                    truth.framework,
                    truth.authorization_run_id,
                    f"{truth.framework}.engine",
                ),
            ).fetchone()
        return bool(
            truth.tenant_id == tenant
            and truth.job_id == str(attempt["job_id"])
            and truth.authorization_run_id == str(job["run_id"])
            and authorization_binding is not None
        )

    def _inspect_run_truth_sqlite(
        self,
        tenant: str,
        attempt: sqlite3.Row,
        job: sqlite3.Row,
        truth: RunCollectionTruth,
    ) -> dict[str, Any]:
        if not self._run_truth_assignment_valid_sqlite(tenant, attempt, job, truth):
            raise InvalidTransition("signed run truth assignment mismatch")
        planned = {
            str(row[0])
            for row in self.conn.execute(
                "SELECT work_key FROM durable_job_state_work_plan "
                "WHERE tenant_id=? AND job_id=? AND required=1",
                (tenant, attempt["job_id"]),
            ).fetchall()
        }
        if job["assigned_agent_id"] is not None:
            if truth.framework != str(job["job_kind"]):
                raise InvalidTransition(
                    "signed run truth framework does not match the assigned engine"
                )
            selected_work = sorted(planned)
        else:
            if planned and truth.framework not in planned:
                raise InvalidTransition(
                    "signed run truth framework is not in the job plan"
                )
            selected_work = [truth.framework]
        receipt = _run_truth_receipt(
            truth,
            tenant_id=tenant,
            job_id=str(attempt["job_id"]),
            attempt_id=str(attempt["id"]),
        )
        state = (
            WorkState.COMPLETED.value
            if receipt.outcome == "success"
            else WorkState.FAILED.value
            if receipt.outcome == "failure"
            else WorkState.UNCOLLECTED.value
        )
        reason = None
        if state != WorkState.COMPLETED.value:
            reason = (
                "signed run truth reports incomplete collection: "
                f"{receipt.collection_status}"
            )
        return {
            "receipt": receipt,
            "outcome": receipt.outcome,
            "work": [
                {
                    "work_key": work_key,
                    "required": True,
                    "state": state,
                    **({"reason": reason} if reason is not None else {}),
                }
                for work_key in selected_work
            ],
        }

    def inspect_run_truth(
        self,
        attempt_id: str,
        lease_token: str,
        run_truth_id: str,
        *,
        tenant_id: str = "default",
        worker_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate signed truth and return proof/work material without mutation."""

        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        run_truth_id = _identifier(run_truth_id, "run_truth_id")
        truth = self._load_validated_run_truth(tenant, run_truth_id)
        with self._lock:
            attempt, _lease = self._check_lease(
                tenant,
                attempt_id,
                lease_token,
                worker_id=worker_id,
            )
            job = self._job(tenant, str(attempt["job_id"]))
            return self._inspect_run_truth_sqlite(tenant, attempt, job, truth)

    def record_run_truth(
        self,
        attempt_id: str,
        lease_token: str,
        run_truth_id: str,
        *,
        tenant_id: str = "default",
        worker_id: str | None = None,
        actor: str | TransitionActor = "worker",
    ) -> dict[str, Any]:
        """Persist proof-only signed truth; it cannot update work or finish."""

        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        run_truth_id = _identifier(run_truth_id, "run_truth_id")
        truth = self._load_validated_run_truth(tenant, run_truth_id)
        with self._tx():
            attempt, _lease = self._check_lease(
                tenant,
                attempt_id,
                lease_token,
                worker_id=worker_id,
            )
            job = self._job(tenant, str(attempt["job_id"]))
            inspected = self._inspect_run_truth_sqlite(tenant, attempt, job, truth)
            receipt = cast(RunTruthReceipt, inspected["receipt"])
            old = self.conn.execute(
                """
                SELECT * FROM durable_job_state_terminal_proofs
                WHERE tenant_id=? AND attempt_id=? AND proof_type='run_truth'
                  AND proof_identity=?
                """,
                (tenant, attempt_id, receipt.proof_identity),
            ).fetchone()
            if old is not None:
                return {
                    "tenant_id": str(old["tenant_id"]),
                    "job_id": str(old["job_id"]),
                    "attempt_id": str(old["attempt_id"]),
                    "proof_type": str(old["proof_type"]),
                    "proof_identity": str(old["proof_identity"]),
                    "coverage_identity": str(old["coverage_identity"]),
                    "result_ref": str(old["result_ref"]),
                    "collection_status": receipt.collection_status,
                    "coverage_complete": receipt.coverage_complete,
                    "outcome": receipt.outcome,
                }
            self.conn.execute(
                """
                INSERT INTO durable_job_state_terminal_proofs(
                    tenant_id,job_id,attempt_id,proof_type,outcome,proof_identity,
                    coverage_identity,result_ref,recorded_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    tenant,
                    attempt["job_id"],
                    attempt_id,
                    "run_truth",
                    receipt.outcome,
                    receipt.proof_identity,
                    receipt.coverage_identity,
                    receipt.result_ref,
                    self.clock(),
                ),
            )
            self._event(
                tenant,
                str(attempt["job_id"]),
                "run_truth_accepted",
                attempt_id=attempt_id,
                actor=actor,
                reason=receipt.collection_status,
                data={
                    "run_truth_id": receipt.run_id,
                    "coverage_identity": receipt.coverage_identity,
                    "coverage_complete": receipt.coverage_complete,
                },
            )
            return {
                "tenant_id": tenant,
                "job_id": str(attempt["job_id"]),
                "attempt_id": attempt_id,
                "proof_type": "run_truth",
                "proof_identity": receipt.proof_identity,
                "coverage_identity": receipt.coverage_identity,
                "result_ref": receipt.result_ref,
                "collection_status": receipt.collection_status,
                "coverage_complete": receipt.coverage_complete,
                "outcome": receipt.outcome,
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
                    "WHERE tenant_id=? AND attempt_id=? AND state='accepted' LIMIT 1",
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
                SELECT idempotency_key,observation_id,artifact_id,result_ref,
                       result_identity,accepted_at
                FROM durable_job_state_deliveries
                WHERE tenant_id=? AND attempt_id=? AND state='accepted'
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
        success: bool | None = None,
        error: str | None = None,
        error_reason: str | None = None,
        lease_token: str | None = None,
        skipped: Iterable[Mapping[str, Any]] = (),
        failed: Iterable[Mapping[str, Any]] = (),
        truncated: Iterable[Mapping[str, Any]] = (),
        uncollected: Iterable[Mapping[str, Any]] = (),
        terminal_reason: str | None = None,
        worker_id: str | None = None,
        actor: str | TransitionActor = "worker",
        _recovery: bool = False,
    ) -> dict[str, Any]:
        """Finalize from accepted custody/coverage, never from process exit."""

        tenant = _tenant(tenant_id)
        attempt_id = _identifier(attempt_id, "attempt_id")
        if lease_token is None:
            raise LeaseError("lease token is required")
        work: list[dict[str, Any]] = []
        work.extend({**dict(item), "state": WorkState.SKIPPED.value} for item in skipped)
        work.extend({**dict(item), "state": WorkState.FAILED.value} for item in failed)
        work.extend({**dict(item), "state": WorkState.TRUNCATED.value} for item in truncated)
        work.extend({**dict(item), "state": WorkState.UNCOLLECTED.value} for item in uncollected)
        work = _canonical_work_items(work)
        finish_identity = _identity(
            {
                "error_reason": error_reason or error,
                "terminal_reason": terminal_reason,
                "work": work,
            }
        )
        with self._tx():
            replay_attempt = self._attempt(tenant, attempt_id)
            if str(replay_attempt["state"]) not in ACTIVE_ATTEMPT_STATES:
                self._check_delivery_token(
                    tenant,
                    attempt_id,
                    lease_token,
                    worker_id=worker_id,
                )
                if not hmac.compare_digest(
                    str(replay_attempt["result_identity"] or ""),
                    finish_identity,
                ):
                    raise IdempotencyConflict(
                        "attempt finish replay contains different material"
                    )
                return self._row(replay_attempt) or {}

            if _recovery:
                attempt = self._check_delivery_token(
                    tenant,
                    attempt_id,
                    lease_token,
                    worker_id=worker_id,
                )
            else:
                attempt, _lease = self._check_lease(
                    tenant,
                    attempt_id,
                    lease_token,
                    worker_id=worker_id,
                )
            if str(attempt["state"]) != AttemptState.RUNNING.value:
                raise InvalidTransition(
                    "an attempt must be running before it can finish"
                )
            job = self._job(tenant, str(attempt["job_id"]))
            if str(job["state"]) not in {
                JobState.RUNNING.value,
                JobState.CANCELING.value,
                *(
                    {JobState.LEASED.value}
                    if _recovery
                    else set()
                ),
            }:
                raise InvalidTransition(
                    f"cannot finish an attempt while job is {job['state']}"
                )
            delivery = self.conn.execute(
                """
                SELECT * FROM durable_job_state_deliveries
                WHERE tenant_id=? AND attempt_id=? AND state='accepted'
                ORDER BY accepted_at DESC,idempotency_key DESC LIMIT 1
                """,
                (tenant, attempt_id),
            ).fetchone()
            if delivery is None:
                raise TerminalStateError(
                    "attempt finish requires an accepted Task 102 delivery"
                )
            proof = self.conn.execute(
                """
                SELECT * FROM durable_job_state_terminal_proofs
                WHERE tenant_id=? AND attempt_id=?
                  AND proof_type='observation_receipt'
                  AND coverage_identity=? AND result_ref=?
                ORDER BY recorded_at DESC,proof_identity LIMIT 1
                """,
                (
                    tenant,
                    attempt_id,
                    delivery["result_identity"],
                    delivery["result_ref"],
                ),
            ).fetchone()
            if proof is None:
                raise TerminalStateError(
                    "attempt finish requires the accepted observation receipt"
                )
            proof_outcome = str(proof["outcome"])
            proof_success = proof_outcome == "success"
            if success is not None and bool(success) != proof_success:
                raise IdempotencyConflict(
                    "caller outcome conflicts with accepted terminal proof"
                )
            success = proof_success
            for item in work:
                self._mark_work_tx(
                    tenant,
                    str(attempt["job_id"]),
                    str(item["work_key"]),
                    state=item["state"],
                    required=bool(item.get("required", True)),
                    reason=item.get("reason"),
                    attempt_id=attempt_id,
                    observation_id=None,
                    result_ref=None,
                    actor=actor,
                    accepted_delivery=True,
                )

            now = self.clock()
            self.conn.execute(
                """
                UPDATE durable_job_state_leases
                SET revoked_at=COALESCE(revoked_at,?),
                    revoke_reason=COALESCE(revoke_reason,'attempt finished'),
                    expires_at=?
                WHERE tenant_id=? AND attempt_id=?
                """,
                (now, now, tenant, attempt_id),
            )
            self.conn.execute(
                """
                UPDATE durable_job_state_attempts
                SET state=?,finished_at=?,result_ref=?,result_identity=?,
                    error_reason=?,error_reason_code=?,lease_token_digest=NULL,
                    lease_expires_at=NULL,
                    version=version+1
                WHERE tenant_id=? AND id=? AND state='running'
                """,
                (
                    AttemptState.COMPLETED.value if success else AttemptState.FAILED.value,
                    now,
                    str(proof["result_ref"]),
                    finish_identity,
                    error_reason or error,
                    (
                        _reason_code(error_reason or error)
                        if error_reason or error
                        else None
                    ),
                    tenant,
                    attempt_id,
                ),
            )
            self._refresh_counters(tenant, str(attempt["job_id"]))
            job = self._job(tenant, str(attempt["job_id"]))
            unresolved_child = self.conn.execute(
                """
                SELECT 1 FROM durable_job_state_child_processes
                WHERE tenant_id=? AND job_id=?
                  AND state IN ('running','paused','canceling','orphaned')
                LIMIT 1
                """,
                (tenant, attempt["job_id"]),
            ).fetchone()

            why = terminal_reason or error_reason or error or (
                "accepted result completed" if success else "attempt failed"
            )
            if unresolved_child is not None:
                target = JobState.ORPHANED.value
                attempt_state = AttemptState.ORPHANED.value
                why = "attempt finished with an unresolved child process"
            elif str(job["state"]) == JobState.CANCELING.value:
                self._record_missing_required_work_tx(
                    tenant,
                    str(attempt["job_id"]),
                    reason=terminal_reason or "operator cancellation",
                    attempt_id=attempt_id,
                    actor=actor,
                )
                job = self._job(tenant, str(attempt["job_id"]))
                target = (
                    JobState.PARTIAL.value
                    if int(job["completed_work"]) > 0
                    else JobState.CANCELED.value
                )
                attempt_state = AttemptState.CANCELED.value
                why = terminal_reason or "operator cancellation"
            elif proof_outcome == "canceled":
                self._record_missing_required_work_tx(
                    tenant,
                    str(attempt["job_id"]),
                    reason=terminal_reason or "worker reported cancellation",
                    attempt_id=attempt_id,
                    actor=actor,
                )
                job = self._job(tenant, str(attempt["job_id"]))
                target = (
                    JobState.PARTIAL.value
                    if int(job["completed_work"]) > 0
                    else JobState.CANCELED.value
                )
                attempt_state = AttemptState.CANCELED.value
                why = terminal_reason or "worker reported cancellation"
            elif proof_outcome == "partial":
                if int(job["max_attempts"]) > int(attempt["number"]):
                    target = JobState.QUEUED.value
                else:
                    self._record_missing_required_work_tx(
                        tenant,
                        str(attempt["job_id"]),
                        reason=terminal_reason or "worker reported partial coverage",
                        attempt_id=attempt_id,
                        actor=actor,
                    )
                    job = self._job(tenant, str(attempt["job_id"]))
                    target = JobState.PARTIAL.value
                attempt_state = AttemptState.PARTIAL.value
                why = terminal_reason or "worker reported partial coverage"
            elif not success:
                if int(job["max_attempts"]) > int(attempt["number"]):
                    target = JobState.QUEUED.value
                else:
                    self._record_missing_required_work_tx(
                        tenant,
                        str(attempt["job_id"]),
                        reason=why,
                        attempt_id=attempt_id,
                        actor=actor,
                    )
                    job = self._job(tenant, str(attempt["job_id"]))
                    target = JobState.FAILED.value
                attempt_state = AttemptState.FAILED.value
            else:
                blockers = self._completion_blockers(
                    tenant,
                    str(attempt["job_id"]),
                )
                if not blockers:
                    target = JobState.COMPLETED.value
                    attempt_state = AttemptState.COMPLETED.value
                elif int(job["max_attempts"]) > int(attempt["number"]):
                    target = JobState.QUEUED.value
                    attempt_state = AttemptState.PARTIAL.value
                    why = terminal_reason or "retry required for incomplete coverage"
                else:
                    self._record_missing_required_work_tx(
                        tenant,
                        str(attempt["job_id"]),
                        reason=terminal_reason or "partial coverage",
                        attempt_id=attempt_id,
                        actor=actor,
                    )
                    job = self._job(tenant, str(attempt["job_id"]))
                    target = JobState.PARTIAL.value
                    attempt_state = AttemptState.PARTIAL.value
                    why = terminal_reason or "partial coverage"

            self.conn.execute(
                """
                UPDATE durable_job_state_attempts
                SET state=? WHERE tenant_id=? AND id=?
                """,
                (attempt_state, tenant, attempt_id),
            )
            if target != str(job["state"]):
                self._transition_tx(
                    tenant,
                    str(attempt["job_id"]),
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
                str(attempt["job_id"]),
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
        actor: str | TransitionActor = "system",
        reason: str = "retry requested",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._tx():
            row = self._job(tenant, job_id)
            if str(row["state"]) in TERMINAL_STATES:
                raise InvalidTransition("terminal job cannot be retried")
            if str(row["state"]) == JobState.PENDING_APPROVAL.value:
                raise InvalidTransition(
                    "retry requires a newly bound authorization"
                )
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
                engagement_id=str(parent["engagement_id"]),
                run_id=f"{parent['run_id']}:child:{child_id}",
                job_kind=str(parent["job_kind"]),
                target=str(parent["target"]),
                authorization_decision_id=(
                    str(parent["authorization_decision_id"])
                    if parent["authorization_decision_id"] is not None
                    else None
                ),
                authorization_action_id=(
                    str(parent["authorization_action_id"])
                    if parent["authorization_action_id"] is not None
                    else None
                ),
                assigned_agent_id=(
                    str(parent["assigned_agent_id"])
                    if parent["assigned_agent_id"] is not None
                    else None
                ),
                request_identity=_identity(
                    {
                        "parent_id": parent_id,
                        "child_id": child_id,
                        "identity_key": identity_key,
                        "payload": dict(payload or {}),
                        "state": child_state,
                    }
                ),
                authorization_bindings=(
                    {
                        "authorization_decision_id": str(
                            parent["authorization_decision_id"]
                        ),
                        "authorization_action_id": str(
                            parent["authorization_action_id"]
                        ),
                        "framework": str(parent["job_kind"]),
                    },
                )
                if parent["authorization_decision_id"] is not None
                and parent["authorization_action_id"] is not None
                else (),
                planned_work=(
                    f"required:{index + 1}"
                    for index in range(child_required_work)
                ),
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

    def reserve_process(
        self,
        job_id: str,
        attempt_id: str,
        identity_key: str,
        *,
        lease_token: str,
        worker_id: str,
        control_boot_id: str,
        expected_launch_nonce: str | None = None,
        tenant_id: str = "default",
        actor: str | TransitionActor = "worker",
    ) -> dict[str, Any]:
        """Atomically fence a child launch to one live lease and control boot."""

        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        attempt_id = _identifier(attempt_id, "attempt_id")
        identity_key = _identifier(identity_key, "identity_key")
        worker_id = _identifier(worker_id, "worker_id")
        control_boot_id = _identifier(control_boot_id, "control_boot_id")
        if expected_launch_nonce is not None:
            expected_launch_nonce = _identifier(
                expected_launch_nonce,
                "expected_launch_nonce",
            )
        with self._tx():
            attempt, _lease = self._check_lease(
                tenant,
                attempt_id,
                lease_token,
                worker_id=worker_id,
            )
            if str(attempt["job_id"]) != job_id:
                raise ProcessIdentityError("attempt does not belong to job")
            if str(attempt["state"]) not in ACTIVE_ATTEMPT_STATES:
                raise ProcessIdentityError("launch intent requires an active attempt")
            if not hmac.compare_digest(
                str(attempt["control_boot_id"] or ""),
                control_boot_id,
            ):
                raise ProcessIdentityError(
                    "process control boot does not match the leased attempt"
                )
            old = self.conn.execute(
                """
                SELECT * FROM durable_job_state_launch_intents
                WHERE tenant_id=? AND attempt_id=? AND identity_key=?
                """,
                (tenant, attempt_id, identity_key),
            ).fetchone()
            if old is not None:
                if expected_launch_nonce is not None and not hmac.compare_digest(
                    str(old["launch_nonce"]),
                    expected_launch_nonce,
                ):
                    raise ProcessIdentityError(
                        "reserved process launch nonce does not match delivery"
                    )
                return {
                    "tenant_id": str(old["tenant_id"]),
                    "job_id": str(old["job_id"]),
                    "attempt_id": str(old["attempt_id"]),
                    "identity_key": str(old["identity_key"]),
                    "launch_nonce": str(old["launch_nonce"]),
                    "control_boot_id": control_boot_id,
                    "state": str(old["state"]),
                }
            if expected_launch_nonce is not None:
                raise ProcessIdentityError(
                    "delivered process launch intent is not reserved"
                )
            launch_nonce = _identifier(
                f"launch-{uuid.uuid4().hex}",
                "launch_nonce",
            )
            self.conn.execute(
                """
                INSERT INTO durable_job_state_launch_intents(
                    tenant_id,job_id,attempt_id,identity_key,launch_nonce,
                    state,created_at
                ) VALUES(?,?,?,?,?,'reserved',?)
                """,
                (
                    tenant,
                    job_id,
                    attempt_id,
                    identity_key,
                    launch_nonce,
                    self.clock(),
                ),
            )
            self._event(
                tenant,
                job_id,
                "child_launch_reserved",
                attempt_id=attempt_id,
                actor=actor,
                reason="child launch intent persisted",
                data={"identity_key": identity_key},
            )
            return {
                "tenant_id": tenant,
                "job_id": job_id,
                "attempt_id": attempt_id,
                "identity_key": identity_key,
                "launch_nonce": launch_nonce,
                "control_boot_id": control_boot_id,
                "state": "reserved",
            }

    def register_process(
        self,
        job_id: str,
        attempt_id: str,
        identity: ProcessIdentity | Mapping[str, Any],
        *,
        lease_token: str,
        worker_id: str,
        control_boot_id: str,
        tenant_id: str = "default",
        identity_key: str = "main",
        actor: str | TransitionActor = "worker",
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        attempt_id = _identifier(attempt_id, "attempt_id")
        worker_id = _identifier(worker_id, "worker_id")
        control_boot_id = _identifier(control_boot_id, "control_boot_id")
        process = ProcessIdentity.from_value(identity)
        with self._tx():
            attempt, _lease = self._check_lease(
                tenant,
                attempt_id,
                lease_token,
                worker_id=worker_id,
            )
            if str(attempt["job_id"]) != job_id:
                raise ProcessIdentityError("attempt does not belong to job")
            if str(attempt["state"]) not in ACTIVE_ATTEMPT_STATES:
                raise ProcessIdentityError("process must belong to an active attempt")
            if not hmac.compare_digest(
                str(attempt["control_boot_id"] or ""),
                control_boot_id,
            ) or not hmac.compare_digest(process.boot_id, control_boot_id):
                raise ProcessIdentityError(
                    "process identity is outside the leased control boot"
                )
            identity_key = _identifier(identity_key, "identity_key")
            intent = self.conn.execute(
                """
                SELECT * FROM durable_job_state_launch_intents
                WHERE tenant_id=? AND attempt_id=? AND identity_key=?
                """,
                (tenant, attempt_id, identity_key),
            ).fetchone()
            if intent is None or not process.launch_nonce or not hmac.compare_digest(
                process.launch_nonce,
                str(intent["launch_nonce"]),
            ):
                raise ProcessIdentityError("process launch nonce does not match attempt")
            if str(intent["state"]) == "abandoned":
                raise ProcessIdentityError("process launch intent was abandoned")
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
                    and str(old["launch_nonce"]) == process.launch_nonce
                )
                if not same:
                    raise ProcessIdentityError(
                        "process identity key is already bound to another process"
                    )
                return process.to_dict()
            if str(intent["state"]) != "reserved":
                raise ProcessIdentityError(
                    "registered launch intent is missing its child identity"
                )
            self.conn.execute(
                """
                INSERT INTO durable_job_state_child_processes(
                    tenant_id,job_id,attempt_id,identity_key,pid,start_token,
                    boot_id,command_digest,launch_nonce,state
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
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
                    process.launch_nonce,
                    "running",
                ),
            )
            self.conn.execute(
                """
                UPDATE durable_job_state_launch_intents
                SET state='registered',registered_at=?
                WHERE tenant_id=? AND attempt_id=? AND identity_key=?
                  AND state='reserved'
                """,
                (
                    self.clock(),
                    tenant,
                    attempt_id,
                    identity_key,
                ),
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

    def abandon_process_launch(
        self,
        job_id: str,
        attempt_id: str,
        identity_key: str,
        *,
        worker_id: str,
        control_boot_id: str,
        tenant_id: str = "default",
        actor: str | TransitionActor = "worker",
        reason: str = "child process launch abandoned",
    ) -> dict[str, Any]:
        """Close a pre-launch or pre-registration intent without deleting history."""

        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        attempt_id = _identifier(attempt_id, "attempt_id")
        identity_key = _identifier(identity_key, "identity_key")
        worker_id = _identifier(worker_id, "worker_id")
        control_boot_id = _identifier(control_boot_id, "control_boot_id")
        with self._tx():
            attempt = self._attempt(tenant, attempt_id)
            if str(attempt["job_id"]) != job_id:
                raise ProcessIdentityError("attempt does not belong to job")
            if not hmac.compare_digest(str(attempt["worker_id"]), worker_id):
                raise ProcessIdentityError("process worker does not own the attempt")
            if not hmac.compare_digest(
                str(attempt["control_boot_id"] or ""),
                control_boot_id,
            ):
                raise ProcessIdentityError("process control boot does not own the attempt")
            intent = self.conn.execute(
                "SELECT * FROM durable_job_state_launch_intents "
                "WHERE tenant_id=? AND attempt_id=? AND identity_key=?",
                (tenant, attempt_id, identity_key),
            ).fetchone()
            if intent is None:
                raise ProcessIdentityError("process launch intent is missing")
            if str(intent["state"]) == "registered":
                raise ProcessIdentityError("registered process launch cannot be abandoned")
            if str(intent["state"]) == "abandoned":
                return {
                    "tenant_id": tenant,
                    "job_id": job_id,
                    "attempt_id": attempt_id,
                    "identity_key": identity_key,
                    "launch_nonce": str(intent["launch_nonce"]),
                    "control_boot_id": control_boot_id,
                    "state": "abandoned",
                }
            self.conn.execute(
                "UPDATE durable_job_state_launch_intents SET state='abandoned' "
                "WHERE tenant_id=? AND attempt_id=? AND identity_key=? "
                "AND state='reserved'",
                (tenant, attempt_id, identity_key),
            )
            self._event(
                tenant,
                job_id,
                "child_launch_abandoned",
                attempt_id=attempt_id,
                actor=actor,
                reason=reason,
                data={"identity_key": identity_key},
            )
            return {
                "tenant_id": tenant,
                "job_id": job_id,
                "attempt_id": attempt_id,
                "identity_key": identity_key,
                "launch_nonce": str(intent["launch_nonce"]),
                "control_boot_id": control_boot_id,
                "state": "abandoned",
            }

    def list_processes(
        self,
        job_id: str,
        *,
        tenant_id: str = "default",
    ) -> list[dict[str, Any]]:
        """Return persisted child identities without exposing a signal handle."""

        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        with self._lock:
            self._job(tenant, job_id)
            return [
                dict(row)
                for row in self.conn.execute(
                    "SELECT * FROM durable_job_state_child_processes "
                    "WHERE tenant_id=? AND job_id=? "
                    "ORDER BY attempt_id,identity_key",
                    (tenant, job_id),
                ).fetchall()
            ]

    def record_process_exit(
        self,
        job_id: str,
        attempt_id: str,
        identity: ProcessIdentity | Mapping[str, Any],
        *,
        worker_id: str,
        control_boot_id: str,
        tenant_id: str = "default",
        identity_key: str = "main",
        reason: str = "child process exited",
        actor: str = "worker",
        return_code: int | None = None,
    ) -> dict[str, Any]:
        """Persist a verified child exit without trusting a PID by itself."""

        tenant = _tenant(tenant_id)
        job_id = _identifier(job_id, "job_id")
        attempt_id = _identifier(attempt_id, "attempt_id")
        identity_key = _identifier(identity_key, "identity_key")
        worker_id = _identifier(worker_id, "worker_id")
        control_boot_id = _identifier(control_boot_id, "control_boot_id")
        process = ProcessIdentity.from_value(identity)
        with self._tx():
            attempt = self._attempt(tenant, attempt_id)
            if str(attempt["job_id"]) != job_id:
                raise ProcessIdentityError("attempt does not belong to job")
            if not hmac.compare_digest(str(attempt["worker_id"]), worker_id):
                raise ProcessIdentityError("process worker does not own the attempt")
            if not hmac.compare_digest(
                str(attempt["control_boot_id"] or ""),
                control_boot_id,
            ) or not hmac.compare_digest(process.boot_id, control_boot_id):
                raise ProcessIdentityError(
                    "process exit is outside the leased control boot"
                )
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
                and str(stored["launch_nonce"]) == process.launch_nonce
            )
            if not same:
                raise ProcessIdentityError("child process identity mismatch")
            if str(stored["state"]) == "stopped":
                return process.to_dict()
            self.conn.execute(
                """
                UPDATE durable_job_state_child_processes
                SET state='stopped',stopped_at=?,return_code=?
                WHERE tenant_id=? AND attempt_id=? AND identity_key=?
                """,
                (self.clock(), return_code, tenant, attempt_id, identity_key),
            )
            self._event(
                tenant,
                job_id,
                "child_exited",
                attempt_id=attempt_id,
                actor=actor,
                reason=reason,
                data={
                    "identity_key": identity_key,
                    "pid": process.pid,
                    "return_code": return_code,
                },
            )
            return process.to_dict()

    mark_process_stopped = record_process_exit
    complete_process = record_process_exit

    def reconcile(
        self,
        *,
        tenant_id: str | None = None,
        requeue_expired: bool = True,
        actor: str | TransitionActor = "reconciler",
    ) -> list[str]:
        """Converge every lifecycle state without treating uncertainty as success."""

        tenant_filter = _tenant(tenant_id) if tenant_id is not None else None
        changed: list[str] = []
        actor_by_tenant: dict[str, TransitionActor] = {}

        def actor_for(tenant: str) -> TransitionActor:
            if tenant not in actor_by_tenant:
                actor_by_tenant[tenant] = _actor(
                    actor,
                    tenant_id=tenant,
                    default_role="system",
                )
            return actor_by_tenant[tenant]

        query = (
            "SELECT d.*,l.owner_id,l.generation "
            "FROM durable_job_state_deliveries d "
            "JOIN durable_job_state_leases l "
            "ON l.tenant_id=d.tenant_id AND l.attempt_id=d.attempt_id "
            "WHERE d.state='custodied'"
        )
        parameters: list[Any] = []
        if tenant_filter is not None:
            query += " AND d.tenant_id=?"
            parameters.append(tenant_filter)
        query += " ORDER BY d.tenant_id,d.attempt_id,d.idempotency_key"
        with self._lock:
            custody_recoveries = [
                dict(row) for row in self.conn.execute(query, parameters).fetchall()
            ]
        for recovery in custody_recoveries:
            tenant = str(recovery["tenant_id"])
            attempt_id_value = str(recovery["attempt_id"])
            try:
                decoded_work = _decode(recovery["work_json"], [])
                decoded_truths = _decode(recovery["run_truth_json"], [])
                if not isinstance(decoded_work, list) or not isinstance(
                    decoded_truths, list
                ):
                    raise InvalidTransition(
                        "custodied recovery material is invalid"
                    )
                work = [
                    dict(item) for item in decoded_work if isinstance(item, Mapping)
                ]
                if len(work) != len(decoded_work):
                    raise InvalidTransition(
                        "custodied work recovery material is invalid"
                    )
                run_truths = [
                    RunTruthReceipt(**dict(item))
                    for item in decoded_truths
                    if isinstance(item, Mapping)
                ]
                if len(run_truths) != len(decoded_truths):
                    raise InvalidTransition(
                        "custodied run-truth recovery material is invalid"
                    )
                token = self._lease_token(
                    tenant,
                    attempt_id_value,
                    str(recovery["owner_id"]),
                    int(recovery["generation"]),
                )
                self._record_result(
                    attempt_id_value,
                    token,
                    delivery_key=str(recovery["idempotency_key"]),
                    tenant_id=tenant,
                    receipt=ObservationReceipt(
                        tenant_id=tenant,
                        job_id=str(recovery["job_id"]),
                        attempt_id=attempt_id_value,
                        observation_id=str(recovery["observation_id"]),
                        artifact_id=str(recovery["artifact_id"]),
                        result_ref=str(recovery["result_ref"]),
                        manifest_digest=str(recovery["manifest_digest"]),
                    ),
                    outcome=str(recovery["outcome"]),
                    work=work,
                    run_truths=run_truths,
                    worker_id=str(recovery["owner_id"]),
                    actor=actor_for(tenant),
                    _recovery=True,
                )
                changed.append(attempt_id_value)
            except (
                IdempotencyConflict,
                InvalidTransition,
                LeaseError,
                KeyError,
                TypeError,
                ValueError,
            ):
                # Leave the authenticated custody reservation and canonical
                # evidence intact. Later reconciliation must preserve
                # uncertainty rather than fabricate terminal truth.
                continue

        def active_process_rows() -> list[dict[str, Any]]:
            if tenant_filter is None:
                rows = self.conn.execute(
                    "SELECT * FROM durable_job_state_child_processes "
                    "WHERE state IN "
                    "('running','paused','canceling','orphaned')"
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM durable_job_state_child_processes "
                    "WHERE state IN "
                    "('running','paused','canceling','orphaned') "
                    "AND tenant_id=?",
                    (tenant_filter,),
                ).fetchall()
            return [dict(row) for row in rows]

        def reserved_launch_rows() -> list[dict[str, Any]]:
            if tenant_filter is None:
                rows = self.conn.execute(
                    "SELECT * FROM durable_job_state_launch_intents "
                    "WHERE state='reserved'"
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM durable_job_state_launch_intents "
                    "WHERE state='reserved' AND tenant_id=?",
                    (tenant_filter,),
                ).fetchall()
            return [dict(row) for row in rows]

        with self._lock:
            child_rows = active_process_rows()
            launch_intents = reserved_launch_rows()

        known_intents = {
            (
                str(row["tenant_id"]),
                str(row["attempt_id"]),
                str(row["identity_key"]),
            )
            for row in child_rows
        }
        discover = (
            getattr(self.process_supervisor, "discover", None)
            if self.process_supervisor is not None
            else None
        )
        if callable(discover):
            for intent in launch_intents:
                key = (
                    str(intent["tenant_id"]),
                    str(intent["attempt_id"]),
                    str(intent["identity_key"]),
                )
                if key in known_intents:
                    continue
                try:
                    discovered = discover(str(intent["launch_nonce"]))
                except Exception:
                    discovered = None
                if discovered is None:
                    continue
                if not isinstance(discovered, ProcessIdentity):
                    try:
                        discovered = ProcessIdentity.from_value(discovered)
                    except ProcessIdentityError:
                        continue
                if not hmac.compare_digest(
                    discovered.launch_nonce,
                    str(intent["launch_nonce"]),
                ):
                    continue
                with self._lock:
                    try:
                        intent_attempt = self._attempt(
                            str(intent["tenant_id"]),
                            str(intent["attempt_id"]),
                        )
                    except KeyError:
                        continue
                    intent_lease = self.conn.execute(
                        "SELECT * FROM durable_job_state_leases "
                        "WHERE tenant_id=? AND attempt_id=?",
                        (intent["tenant_id"], intent["attempt_id"]),
                    ).fetchone()
                if intent_lease is None:
                    continue
                worker_id = str(intent_attempt["worker_id"])
                control_boot_id = str(
                    intent_attempt["control_boot_id"] or ""
                )
                if not control_boot_id:
                    continue
                token = self._lease_token(
                    str(intent["tenant_id"]),
                    str(intent["attempt_id"]),
                    worker_id,
                    int(intent_lease["generation"]),
                )
                try:
                    self.register_process(
                        str(intent["job_id"]),
                        str(intent["attempt_id"]),
                        discovered,
                        lease_token=token,
                        worker_id=worker_id,
                        control_boot_id=control_boot_id,
                        tenant_id=str(intent["tenant_id"]),
                        identity_key=str(intent["identity_key"]),
                        actor=actor_for(str(intent["tenant_id"])),
                    )
                    changed.append(str(intent["attempt_id"]))
                except (InvalidTransition, LeaseError, ProcessIdentityError, KeyError):
                    continue

        with self._lock:
            child_rows = active_process_rows()

        liveness: dict[tuple[str, str, str], bool | None] = {}
        for process in child_rows:
            key = (
                str(process["tenant_id"]),
                str(process["attempt_id"]),
                str(process["identity_key"]),
            )
            try:
                identity = ProcessIdentity(
                    pid=int(process["pid"]),
                    start_token=str(process["start_token"]),
                    boot_id=str(process["boot_id"]),
                    command_digest=str(process["command_digest"]),
                    launch_nonce=str(process["launch_nonce"]),
                )
            except Exception:
                liveness[key] = None
                continue
            if self.process_supervisor is None:
                liveness[key] = None
                continue
            try:
                liveness[key] = bool(
                    self.process_supervisor.is_alive(identity)
                )
            except Exception:
                liveness[key] = None

        finalize: list[tuple[str, str, str]] = []
        canceling_jobs: set[tuple[str, str]] = set()
        revoked_agent_jobs: set[tuple[str, str]] = set()
        with self._tx():
            for process in child_rows:
                tenant = str(process["tenant_id"])
                key = (
                    tenant,
                    str(process["attempt_id"]),
                    str(process["identity_key"]),
                )
                alive = liveness.get(key)
                if alive is False:
                    self.conn.execute(
                        """
                        UPDATE durable_job_state_child_processes
                        SET state='stopped',stopped_at=COALESCE(stopped_at,?)
                        WHERE tenant_id=? AND attempt_id=? AND identity_key=?
                          AND state IN ('running','paused','canceling','orphaned')
                        """,
                        (
                            self.clock(),
                            tenant,
                            process["attempt_id"],
                            process["identity_key"],
                        ),
                    )
                    self._event(
                        tenant,
                        str(process["job_id"]),
                        "child_reconciled_stopped",
                        attempt_id=str(process["attempt_id"]),
                        actor=actor_for(tenant),
                        reason="child identity is no longer alive after restart",
                        data={"identity_key": process["identity_key"]},
                    )
                    changed.append(str(process["attempt_id"]))
                elif alive is None:
                    self.conn.execute(
                        """
                        UPDATE durable_job_state_child_processes
                        SET state='orphaned'
                        WHERE tenant_id=? AND attempt_id=? AND identity_key=?
                          AND state IN ('running','paused','canceling')
                        """,
                        (
                            tenant,
                            process["attempt_id"],
                            process["identity_key"],
                        ),
                    )

            query = (
                "SELECT * FROM durable_job_state_attempts "
                "WHERE state IN ('leased','running','paused','canceling')"
            )
            params = []
            if tenant_filter is not None:
                query += " AND tenant_id=?"
                params.append(tenant_filter)
            active_attempts = self.conn.execute(query, params).fetchall()
            for attempt in active_attempts:
                tenant = str(attempt["tenant_id"])
                attempt_id_value = str(attempt["id"])
                job_id_value = str(attempt["job_id"])
                job = self._job(tenant, job_id_value)
                job_state = str(job["state"])
                if job_state in TERMINAL_STATES:
                    continue
                child_states = [
                    str(row[0])
                    for row in self.conn.execute(
                        "SELECT state FROM durable_job_state_child_processes "
                        "WHERE tenant_id=? AND attempt_id=?",
                        (tenant, attempt_id_value),
                    ).fetchall()
                ]
                unresolved_child = any(
                    state in {"running", "paused", "canceling", "orphaned"}
                    for state in child_states
                )
                proof = self.conn.execute(
                    "SELECT p.outcome FROM durable_job_state_deliveries d "
                    "JOIN durable_job_state_terminal_proofs p "
                    "ON p.tenant_id=d.tenant_id "
                    "AND p.attempt_id=d.attempt_id "
                    "AND p.proof_type='observation_receipt' "
                    "AND p.coverage_identity=d.result_identity "
                    "AND p.result_ref=d.result_ref "
                    "WHERE d.tenant_id=? AND d.attempt_id=? "
                    "AND d.state='accepted' "
                    "ORDER BY p.recorded_at DESC LIMIT 1",
                    (tenant, attempt_id_value),
                ).fetchone()
                lease = self.conn.execute(
                    "SELECT * FROM durable_job_state_leases "
                    "WHERE tenant_id=? AND attempt_id=?",
                    (tenant, attempt_id_value),
                ).fetchone()
                if job_state == JobState.CANCELING.value:
                    canceling_jobs.add((tenant, job_id_value))
                    continue
                if job_state == JobState.PAUSED.value:
                    if str(attempt["state"]) != AttemptState.PAUSED.value:
                        self.conn.execute(
                            "UPDATE durable_job_state_attempts "
                            "SET state='paused',version=version+1 "
                            "WHERE tenant_id=? AND id=?",
                            (tenant, attempt_id_value),
                        )
                    if lease is not None and float(lease["expires_at"]) <= float(
                        self.clock()
                    ):
                        self.conn.execute(
                            "UPDATE durable_job_state_leases "
                            "SET revoked_at=COALESCE(revoked_at,?),"
                            "revoke_reason=COALESCE(revoke_reason,'paused lease expired'),"
                            "expires_at=? WHERE tenant_id=? AND attempt_id=?",
                            (
                                self.clock(),
                                self.clock(),
                                tenant,
                                attempt_id_value,
                            ),
                        )
                        self.conn.execute(
                            "UPDATE durable_job_state_attempts "
                            "SET lease_token_digest=NULL,lease_expires_at=NULL,"
                            "version=version+1 WHERE tenant_id=? AND id=?",
                            (tenant, attempt_id_value),
                        )
                        self._event(
                            tenant,
                            job_id_value,
                            "paused_lease_expired",
                            attempt_id=attempt_id_value,
                            actor=actor_for(tenant),
                            reason="paused lease expired during reconciliation",
                        )
                        changed.append(attempt_id_value)
                    continue
                if proof is not None and not unresolved_child and lease is not None:
                    token = self._lease_token(
                        tenant,
                        attempt_id_value,
                        str(lease["owner_id"]),
                        int(lease["generation"]),
                    )
                    finalize.append((tenant, attempt_id_value, token))
                    continue
                live_child = any(
                    liveness.get(
                        (
                            tenant,
                            attempt_id_value,
                            str(row["identity_key"]),
                        )
                    )
                    is True
                    for row in child_rows
                    if str(row["tenant_id"]) == tenant
                    and str(row["attempt_id"]) == attempt_id_value
                )
                unknown_child = any(
                    state == "orphaned" for state in child_states
                )
                if live_child or unknown_child:
                    now = self.clock()
                    self.conn.execute(
                        """
                        UPDATE durable_job_state_attempts
                        SET state='orphaned',finished_at=?,lease_token_digest=NULL,
                            lease_expires_at=NULL,version=version+1
                        WHERE tenant_id=? AND id=?
                          AND state IN ('leased','running','paused','canceling')
                        """,
                        (now, tenant, attempt_id_value),
                    )
                    if lease is not None:
                        self.conn.execute(
                            "UPDATE durable_job_state_leases "
                            "SET revoked_at=COALESCE(revoked_at,?),"
                            "revoke_reason=COALESCE(revoke_reason,"
                            "'worker ownership uncertain after restart'),"
                            "expires_at=? WHERE tenant_id=? AND attempt_id=?",
                            (now, now, tenant, attempt_id_value),
                        )
                    if job_state in {
                        JobState.LEASED.value,
                        JobState.RUNNING.value,
                    }:
                        self._transition_tx(
                            tenant,
                            job_id_value,
                            JobState.ORPHANED.value,
                            expected_version=int(job["version"]),
                            actor=actor_for(tenant),
                            reason="worker ownership uncertain after restart",
                            idempotency_key=None,
                            data={"attempt_id": attempt_id_value},
                        )
                    changed.append(attempt_id_value)
                    continue
                expired = (
                    lease is None
                    or lease["revoked_at"] is not None
                    or float(lease["expires_at"]) <= float(self.clock())
                )
                if expired:
                    now = self.clock()
                    self.conn.execute(
                        """
                        UPDATE durable_job_state_attempts
                        SET state='expired',finished_at=?,lease_token_digest=NULL,
                            lease_expires_at=NULL,version=version+1
                        WHERE tenant_id=? AND id=?
                          AND state IN ('leased','running')
                        """,
                        (now, tenant, attempt_id_value),
                    )
                    if lease is not None:
                        self.conn.execute(
                            "UPDATE durable_job_state_leases "
                            "SET revoked_at=COALESCE(revoked_at,?),"
                            "revoke_reason=COALESCE(revoke_reason,'lease expired'),"
                            "expires_at=? WHERE tenant_id=? AND attempt_id=?",
                            (now, now, tenant, attempt_id_value),
                        )
                    target = (
                        (
                            JobState.PENDING_APPROVAL.value
                            if job["assigned_agent_id"] is not None
                            else JobState.QUEUED.value
                        )
                        if requeue_expired
                        and int(job["max_attempts"]) > int(attempt["number"])
                        else JobState.EXPIRED.value
                    )
                    if job_state in {
                        JobState.LEASED.value,
                        JobState.RUNNING.value,
                    }:
                        self._transition_tx(
                            tenant,
                            job_id_value,
                            target,
                            expected_version=int(job["version"]),
                            actor=actor_for(tenant),
                            reason="lease expired during restart reconciliation",
                            idempotency_key=None,
                            data={"attempt_id": attempt_id_value},
                        )
                    changed.append(attempt_id_value)
                    continue
                if (
                    str(attempt["state"]) == AttemptState.RUNNING.value
                    and str(job["assigned_agent_id"] or "") == ""
                    and not unresolved_child
                ):
                    now = self.clock()
                    self.conn.execute(
                        "UPDATE durable_job_state_attempts "
                        "SET state='orphaned',finished_at=?,lease_token_digest=NULL,"
                        "lease_expires_at=NULL,version=version+1 "
                        "WHERE tenant_id=? AND id=? AND state='running'",
                        (now, tenant, attempt_id_value),
                    )
                    if lease is not None:
                        self.conn.execute(
                            "UPDATE durable_job_state_leases "
                            "SET revoked_at=COALESCE(revoked_at,?),"
                            "revoke_reason=COALESCE(revoke_reason,"
                            "'local worker disappeared after restart'),"
                            "expires_at=? WHERE tenant_id=? AND attempt_id=?",
                            (now, now, tenant, attempt_id_value),
                        )
                    if job_state == JobState.RUNNING.value:
                        self._transition_tx(
                            tenant,
                            job_id_value,
                            JobState.ORPHANED.value,
                            expected_version=int(job["version"]),
                            actor=actor_for(tenant),
                            reason="local worker disappeared after restart",
                            idempotency_key=None,
                            data={"attempt_id": attempt_id_value},
                        )
                    changed.append(attempt_id_value)

            query = (
                "SELECT * FROM durable_job_state_jobs "
                "WHERE state IN ('leased','running') AND NOT EXISTS ("
                "SELECT 1 FROM durable_job_state_attempts a "
                "WHERE a.tenant_id=durable_job_state_jobs.tenant_id "
                "AND a.job_id=durable_job_state_jobs.id "
                "AND a.state IN ('leased','running','paused','canceling'))"
            )
            params = []
            if tenant_filter is not None:
                query += " AND tenant_id=?"
                params.append(tenant_filter)
            for job in self.conn.execute(query, params).fetchall():
                self._transition_tx(
                    str(job["tenant_id"]),
                    str(job["id"]),
                    JobState.ORPHANED.value,
                    expected_version=int(job["version"]),
                    actor=actor_for(str(job["tenant_id"])),
                    reason="active job has no active attempt after restart",
                    idempotency_key=None,
                    data={},
                )
                changed.append(str(job["id"]))

            query = "SELECT tenant_id,id FROM durable_job_state_jobs WHERE state='canceling'"
            params = []
            if tenant_filter is not None:
                query += " AND tenant_id=?"
                params.append(tenant_filter)
            canceling_jobs.update(
                (str(row["tenant_id"]), str(row["id"]))
                for row in self.conn.execute(query, params).fetchall()
            )
            query = (
                "SELECT j.tenant_id,j.id FROM durable_job_state_jobs j "
                "JOIN durable_job_state_agents a "
                "ON a.tenant_id=j.tenant_id AND a.id=j.assigned_agent_id "
                "WHERE a.revoked_at IS NOT NULL "
                "AND j.state NOT IN ('canceled','partial','failed','completed')"
            )
            params = []
            if tenant_filter is not None:
                query += " AND j.tenant_id=?"
                params.append(tenant_filter)
            revoked_agent_jobs.update(
                (str(row["tenant_id"]), str(row["id"]))
                for row in self.conn.execute(query, params).fetchall()
            )

        for tenant, attempt_id_value, token in finalize:
            try:
                result = self.finish_attempt(
                    attempt_id_value,
                    tenant_id=tenant,
                    lease_token=token,
                    terminal_reason="accepted result reconciled after restart",
                    actor=actor_for(tenant),
                    _recovery=True,
                )
                changed.append(str(result["id"]))
            except (IdempotencyConflict, InvalidTransition, LeaseError, KeyError):
                # Accepted proof remains durable.  Preserve uncertainty rather
                # than hiding a failed reconciliation behind completion.
                with self._tx():
                    attempt = self._attempt(tenant, attempt_id_value)
                    job = self._job(tenant, str(attempt["job_id"]))
                    if str(job["state"]) in {
                        JobState.LEASED.value,
                        JobState.RUNNING.value,
                    }:
                        self._transition_tx(
                            tenant,
                            str(attempt["job_id"]),
                            JobState.ORPHANED.value,
                            expected_version=int(job["version"]),
                            actor=actor_for(tenant),
                            reason="accepted result could not be reconciled",
                            idempotency_key=None,
                            data={"attempt_id": attempt_id_value},
                        )
                        changed.append(attempt_id_value)

        for tenant, job_id_value in sorted(canceling_jobs):
            try:
                self.cancel_job(
                    job_id_value,
                    tenant_id=tenant,
                    actor=actor_for(tenant),
                    reason="cancellation reconciled after restart",
                    supervisor=self.process_supervisor,
                    sla_seconds=5.0,
                )
                changed.append(job_id_value)
            except (InvalidTransition, LeaseError, KeyError) as exc:
                with self._tx():
                    self._event(
                        tenant,
                        job_id_value,
                        "reconciliation_failed",
                        actor=actor_for(tenant),
                        reason="cancellation reconciliation failed",
                        data={"error_type": type(exc).__name__},
                    )
                changed.append(job_id_value)
        for tenant, job_id_value in sorted(revoked_agent_jobs):
            try:
                self.cancel_job(
                    job_id_value,
                    tenant_id=tenant,
                    actor=actor_for(tenant),
                    reason="revoked agent assignment fenced after restart",
                    supervisor=self.process_supervisor,
                    sla_seconds=0.0,
                )
                changed.append(job_id_value)
            except (InvalidTransition, LeaseError, KeyError) as exc:
                with self._tx():
                    self._event(
                        tenant,
                        job_id_value,
                        "reconciliation_failed",
                        actor=actor_for(tenant),
                        reason="revoked-agent reconciliation failed",
                        data={"error_type": type(exc).__name__},
                    )
                changed.append(job_id_value)
        return list(dict.fromkeys(changed))

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
    "ObservationReceipt",
    "ProcessIdentity",
    "ProcessIdentityError",
    "ProcessSupervisor",
    "RunTruthReceipt",
    "TERMINAL_STATES",
    "TerminalStateError",
    "TRANSITION_TABLE_VERSION",
    "TransitionService",
    "WorkState",
    "allowed_transitions",
    "process_identity",
    "transition_table",
]
