"""Thread-safe event bus for real-time dashboard communication.

The EventBus sits between module execution and dashboard rendering.
Modules publish events (findings, status changes, metrics) and
dashboard components subscribe to event types they care about.

Supports both sync (threading) and async (asyncio) consumers.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import math
import queue
import re
import secrets
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Mapping

from common.action_authorization import ActionAuthorizationEnvelope
from common.redaction import redact_text, redact_value
from common.scope import canonical_target

log = logging.getLogger("forge.dashboard.events")

class EventType(str, Enum):
    """All event types the dashboard can consume."""

    # ── Scan lifecycle ────────────────────────────────────────────────
    SCAN_START          = "scan_start"
    SCAN_COMPLETE       = "scan_complete"
    SCAN_INTERRUPTED    = "scan_interrupted"
    SCAN_PAUSED         = "scan_paused"
    SCAN_RESUMED        = "scan_resumed"
    SCAN_ABORTED        = "scan_aborted"

    # ── Phase lifecycle ───────────────────────────────────────────────
    PHASE_START         = "phase_start"
    PHASE_COMPLETE      = "phase_complete"

    # ── Module lifecycle ──────────────────────────────────────────────
    MODULE_START        = "module_start"
    MODULE_PROGRESS     = "module_progress"
    MODULE_COMPLETE     = "module_complete"
    MODULE_FAIL         = "module_fail"
    MODULE_SKIP         = "module_skip"

    # ── Findings ──────────────────────────────────────────────────────
    FINDING_NEW         = "finding_new"
    FINDING_UPDATED     = "finding_updated"

    # ── Network / HTTP metrics ────────────────────────────────────────
    REQUEST_SENT        = "request_sent"
    REQUEST_ERROR       = "request_error"
    WAF_BLOCK           = "waf_block"
    RATE_LIMIT_HIT      = "rate_limit_hit"

    # ── Credentials ───────────────────────────────────────────────────
    CREDENTIAL_FOUND    = "credential_found"

    # ── Target status ─────────────────────────────────────────────────
    TARGET_DISCOVERED   = "target_discovered"
    TARGET_PWNED        = "target_pwned"
    TARGET_QUEUED       = "target_queued"
    TARGET_SCANNING     = "target_scanning"
    TARGET_PAUSED       = "target_paused"
    TARGET_COMPLETED    = "target_completed"
    TARGET_FAILED       = "target_failed"
    SHELL_SESSION       = "shell_session"

    # ── Operator actions ──────────────────────────────────────────────
    CONFIRM_PROMPTED    = "confirm_prompted"
    CONFIRM_ACCEPTED    = "confirm_accepted"
    CONFIRM_DECLINED    = "confirm_declined"

    # ── C2 Framework ─────────────────────────────────────────────────
    BEACON_CHECKIN      = "beacon_checkin"
    BEACON_NEW          = "beacon_new"
    BEACON_DEAD         = "beacon_dead"
    BEACON_TASK_SENT    = "beacon_task_sent"
    BEACON_TASK_RESULT  = "beacon_task_result"
    LISTENER_START      = "listener_start"
    LISTENER_STOP       = "listener_stop"
    C2_OPERATOR_JOIN    = "c2_operator_join"
    C2_OPERATOR_LEAVE   = "c2_operator_leave"

    # ── Post-Exploitation ─────────────────────────────────────────────
    LATERAL_MOVE        = "lateral_move"
    PERSISTENCE_SET     = "persistence_set"
    ROOTKIT_DEPLOYED    = "rootkit_deployed"
    DATA_STAGED         = "data_staged"
    DATA_EXFILTRATED    = "data_exfiltrated"

    # ── Intel Pipeline ────────────────────────────────────────────────
    INTEL_SYNC_START    = "intel_sync_start"
    INTEL_SYNC_COMPLETE = "intel_sync_complete"
    INTEL_CVE_NEW       = "intel_cve_new"

    # ── Payload Generation ────────────────────────────────────────────
    PAYLOAD_GENERATED   = "payload_generated"

    # ── Brain / AI ────────────────────────────────────────────────────
    BRAIN_VERDICT       = "brain_verdict"
    CHAIN_ACTION_NEW    = "chain_action_new"

    # ── Dashboard internal ────────────────────────────────────────────
    STATE_SNAPSHOT      = "state_snapshot"
    HEARTBEAT           = "heartbeat"
    CONTROL_COMMAND     = "control_command"



REMOTE_EVENT_SCHEMA_VERSION = "forge-dashboard-event-v1"
REMOTE_EVENT_CREDENTIAL_TTL_SECONDS = 300
REMOTE_EVENT_MAX_EVENTS = 10_000
REMOTE_EVENT_CREDENTIAL_HEADER = "X-Forge-Event-Credential"
_EVENT_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_EVENT_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_EVENT_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_EVENT_TOKEN_ID_RE = re.compile(r"^event-cred-[a-f0-9]{32}$")
_EVENT_SUBMISSION_FIELDS = frozenset(
    {
        "schema_version",
        "tenant_id",
        "engagement_id",
        "run_id",
        "job_id",
        "engine",
        "module_id",
        "target",
        "event_type",
        "sequence",
        "nonce",
        "sender_id",
        "data",
    }
)


class EventAdmissionReason(str, Enum):
    """Stable, non-secret reasons returned by the remote-event boundary."""

    ALLOWED = "allowed"
    MISSING_CREDENTIAL = "missing_event_credential"
    MALFORMED_CREDENTIAL = "malformed_event_credential"
    FORGED_CREDENTIAL = "forged_event_credential"
    EXPIRED_CREDENTIAL = "expired_event_credential"
    MALFORMED_EVENT = "malformed_event"
    UNSUPPORTED_SCHEMA = "unsupported_event_schema"
    TENANT_MISMATCH = "event_tenant_mismatch"
    ENGAGEMENT_MISMATCH = "event_engagement_mismatch"
    RUN_MISMATCH = "event_run_mismatch"
    JOB_MISMATCH = "event_job_mismatch"
    ENGINE_MISMATCH = "event_engine_mismatch"
    MODULE_MISMATCH = "event_module_mismatch"
    TARGET_MISMATCH = "event_target_mismatch"
    SENDER_MISMATCH = "event_sender_mismatch"
    EVENT_TYPE_DENIED = "event_type_not_authorized"
    REPLAYED = "event_replayed"
    OUT_OF_ORDER = "event_out_of_order"
    PAYLOAD_FORBIDDEN = "event_payload_forbidden"
    EVENT_LIMIT = "event_credential_limit_reached"
    UNRECORDED_AUTHORIZATION = "unrecorded_event_authorization"
    JOB_NOT_ACTIVE = "event_job_not_active"


class EventAdmissionError(ValueError):
    """Fail-closed event admission error that never embeds submitted values."""

    def __init__(
        self,
        reason: EventAdmissionReason,
        *,
        credential_id: str = "",
    ) -> None:
        self.reason_code = reason.value
        self.credential_id = credential_id if _EVENT_TOKEN_ID_RE.fullmatch(credential_id) else ""
        super().__init__(reason.value)


def event_target_binding(target: str) -> str:
    """Return the Task-002-compatible opaque binding for an exact target."""
    if not isinstance(target, str) or not target.strip():
        raise EventAdmissionError(EventAdmissionReason.MALFORMED_EVENT)
    try:
        return canonical_target(target.strip())
    except (TypeError, ValueError) as exc:
        raise EventAdmissionError(EventAdmissionReason.MALFORMED_EVENT) from exc


def _event_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("event clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_event_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("event timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _event_identifier(value: Any) -> str:
    if not isinstance(value, str):
        raise EventAdmissionError(EventAdmissionReason.MALFORMED_EVENT)
    normalized = value.strip()
    if not _EVENT_IDENTIFIER_RE.fullmatch(normalized):
        raise EventAdmissionError(EventAdmissionReason.MALFORMED_EVENT)
    return normalized


REMOTE_EVENT_TYPES = frozenset(
    {
        EventType.MODULE_START,
        EventType.MODULE_PROGRESS,
        EventType.MODULE_FAIL,
        EventType.MODULE_SKIP,
    }
)


@dataclass(frozen=True)
class EventCredentialBinding:
    """Server-owned identity and authorization facts for one event stream."""

    credential_id: str
    authorization_decision_id: str
    tenant_id: str
    engagement_id: str
    run_id: str
    job_id: str
    engine: str
    module_id: str
    target_binding: str
    sender_id: str
    allowed_event_types: tuple[EventType, ...]
    issued_at: str
    expires_at: str
    max_events: int = REMOTE_EVENT_MAX_EVENTS


@dataclass(frozen=True)
class IssuedEventCredential:
    """One opaque credential plus its non-secret, immutable stream binding."""

    token: str = field(repr=False)
    binding: EventCredentialBinding


@dataclass(frozen=True)
class AdmittedEvent:
    """Canonical event produced only after the exact credential is consumed."""

    event: "Event"
    binding: EventCredentialBinding
    sequence: int


@dataclass
class _EventCredentialState:
    binding: EventCredentialBinding
    token_digest: str
    stream_key: tuple[str, ...]
    events_admitted: int = 0


@dataclass
class _EventStreamLedger:
    """Replay state shared by every credential rotation for one exact stream."""

    next_sequence: int = 1
    consumed_nonces: set[str] = field(default_factory=set)
    active_credential_id: str = ""


class EventCredentialRegistry:
    """Short-lived, in-memory event authority and replay ledger.

    Task 004 deliberately keeps this single-node and process-local. Gate 1 owns
    durable job/event state, while Task 005 owns distributed-agent leases.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        authorization_resolver: (
            Callable[[str], ActionAuthorizationEnvelope | Mapping[str, Any] | None]
            | None
        ) = None,
        job_state_resolver: Callable[[EventCredentialBinding], str | None] | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._authorization_resolver = authorization_resolver
        self._job_state_resolver = job_state_resolver
        self._records: dict[str, _EventCredentialState] = {}
        # A stream ledger deliberately outlives individual short-lived tokens.
        # Otherwise credential rotation could reset sequence/nonce admission and
        # accept the same logical delivery more than once while a job is active.
        self._stream_ledgers: dict[tuple[str, ...], _EventStreamLedger] = {}
        self._lock = threading.RLock()
        self._dummy_digest = hashlib.sha256(b"forge-invalid-event-token").hexdigest()

    def issue(
        self,
        *,
        authorization: ActionAuthorizationEnvelope | Mapping[str, Any],
        module_id: str,
        target: str,
        sender_id: str,
        allowed_event_types: tuple[EventType, ...] | list[EventType],
        ttl_seconds: int = 120,
        max_events: int = REMOTE_EVENT_MAX_EVENTS,
    ) -> IssuedEventCredential:
        """Derive a narrower event capability from one allowed action envelope."""
        envelope = ActionAuthorizationEnvelope.from_value(authorization)
        if self._authorization_resolver is None:
            raise EventAdmissionError(EventAdmissionReason.UNRECORDED_AUTHORIZATION)
        try:
            resolved = self._authorization_resolver(envelope.decision_id)
            persisted = ActionAuthorizationEnvelope.from_value(resolved) if resolved is not None else None
        except Exception as exc:
            raise EventAdmissionError(EventAdmissionReason.UNRECORDED_AUTHORIZATION) from exc
        if persisted is None or not hmac.compare_digest(persisted.to_json(), envelope.to_json()):
            raise EventAdmissionError(EventAdmissionReason.UNRECORDED_AUTHORIZATION)
        now = self._clock().astimezone(timezone.utc)
        try:
            envelope_expiry = _parse_event_timestamp(envelope.expires_at)
        except (TypeError, ValueError) as exc:
            raise EventAdmissionError(EventAdmissionReason.MALFORMED_EVENT) from exc
        if (
            envelope.decision_outcome != "allow"
            or envelope.scope_decision != "allowed"
            or now >= envelope_expiry
        ):
            raise EventAdmissionError(EventAdmissionReason.EXPIRED_CREDENTIAL)
        if type(ttl_seconds) is not int or not (1 <= ttl_seconds <= REMOTE_EVENT_CREDENTIAL_TTL_SECONDS):
            raise ValueError("event credential ttl is invalid")
        if type(max_events) is not int or not (1 <= max_events <= REMOTE_EVENT_MAX_EVENTS):
            raise ValueError("event credential event limit is invalid")
        module = _event_identifier(module_id).lower()
        if not envelope.module_id or not hmac.compare_digest(module, envelope.module_id.lower()):
            raise EventAdmissionError(EventAdmissionReason.MODULE_MISMATCH)
        sender = _event_identifier(sender_id)
        target_digest = event_target_binding(target)
        if not (
            hmac.compare_digest(target_digest, envelope.requested_target)
            or hmac.compare_digest(target_digest, envelope.resolved_target)
        ):
            raise EventAdmissionError(EventAdmissionReason.TARGET_MISMATCH)
        requested_types = tuple(dict.fromkeys(EventType(item) for item in allowed_event_types))
        if not requested_types or any(item not in REMOTE_EVENT_TYPES for item in requested_types):
            raise EventAdmissionError(EventAdmissionReason.EVENT_TYPE_DENIED)
        expires_at = min(now + timedelta(seconds=ttl_seconds), envelope_expiry)
        credential_id = f"event-cred-{secrets.token_hex(16)}"
        secret = secrets.token_urlsafe(32)
        token = f"{credential_id}.{secret}"
        binding = EventCredentialBinding(
            credential_id=credential_id,
            authorization_decision_id=envelope.decision_id,
            tenant_id=envelope.tenant_id,
            engagement_id=envelope.engagement_id,
            run_id=envelope.run_id,
            job_id=envelope.job_id,
            engine=envelope.engine,
            module_id=module,
            target_binding=target_digest,
            sender_id=sender,
            allowed_event_types=requested_types,
            issued_at=_event_timestamp(now),
            expires_at=_event_timestamp(expires_at),
            max_events=max_events,
        )
        if self._resolve_job_state(binding) not in {"pending", "running"}:
            raise EventAdmissionError(EventAdmissionReason.JOB_NOT_ACTIVE)
        state = _EventCredentialState(
            binding=binding,
            token_digest=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            stream_key=self._stream_key(binding),
        )
        with self._lock:
            self._purge_expired_locked(now)
            ledger = self._stream_ledgers.setdefault(
                state.stream_key,
                _EventStreamLedger(),
            )
            if ledger.active_credential_id:
                self._records.pop(ledger.active_credential_id, None)
            ledger.active_credential_id = credential_id
            self._records[credential_id] = state
        return IssuedEventCredential(token=token, binding=binding)

    def admit(self, token: str | None, submission: Mapping[str, Any]) -> AdmittedEvent:
        """Authenticate, bind, sequence, and consume one untrusted submission."""
        credential_id = self._credential_id(token)
        supplied_digest = hashlib.sha256((token or "").encode("utf-8")).hexdigest()
        with self._lock:
            state = self._records.get(credential_id)
            expected_digest = state.token_digest if state else self._dummy_digest
            valid = hmac.compare_digest(supplied_digest, expected_digest)
            if not valid or state is None:
                raise EventAdmissionError(
                    EventAdmissionReason.FORGED_CREDENTIAL,
                    credential_id=credential_id,
                )
            ledger = self._stream_ledgers.get(state.stream_key)
            if ledger is None or ledger.active_credential_id != credential_id:
                self._records.pop(credential_id, None)
                raise EventAdmissionError(
                    EventAdmissionReason.FORGED_CREDENTIAL,
                    credential_id=credential_id,
                )
            now = self._clock().astimezone(timezone.utc)
            if now >= _parse_event_timestamp(state.binding.expires_at):
                raise EventAdmissionError(
                    EventAdmissionReason.EXPIRED_CREDENTIAL,
                    credential_id=credential_id,
                )
            if self._resolve_job_state(state.binding) not in {"pending", "running"}:
                self._retire_credential_locked(credential_id)
                raise EventAdmissionError(
                    EventAdmissionReason.JOB_NOT_ACTIVE,
                    credential_id=credential_id,
                )
            validated = self._validate_submission(state, submission)
            sequence, nonce, event_type, event_data = validated
            if sequence < ledger.next_sequence or nonce in ledger.consumed_nonces:
                raise EventAdmissionError(
                    EventAdmissionReason.REPLAYED,
                    credential_id=credential_id,
                )
            if sequence > ledger.next_sequence:
                raise EventAdmissionError(
                    EventAdmissionReason.OUT_OF_ORDER,
                    credential_id=credential_id,
                )
            if state.events_admitted >= state.binding.max_events:
                raise EventAdmissionError(
                    EventAdmissionReason.EVENT_LIMIT,
                    credential_id=credential_id,
                )
            ledger.consumed_nonces.add(nonce)
            ledger.next_sequence += 1
            state.events_admitted += 1
            public_event_id = uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{credential_id}:{sequence}",
            ).hex[:16]
            canonical_data = {
                **event_data,
                "tenant_id": state.binding.tenant_id,
                "engagement_id": state.binding.engagement_id,
                "job_id": state.binding.job_id,
                "engine": state.binding.engine,
                "module_id": state.binding.module_id,
                "target_binding": state.binding.target_binding,
                "sender_id": state.binding.sender_id,
                "authorization_decision_id": state.binding.authorization_decision_id,
                "sequence": sequence,
            }
            event = Event(
                event_type=event_type,
                data=canonical_data,
                source=state.binding.module_id,
                timestamp=_event_timestamp(now),
                event_id=public_event_id,
                run_id=state.binding.run_id,
            )
            return AdmittedEvent(event=event, binding=state.binding, sequence=sequence)

    def revoke(self, credential_id: str) -> None:
        """Revoke one active credential while retaining its stream replay ledger."""
        with self._lock:
            self._retire_credential_locked(credential_id)

    @staticmethod
    def _stream_key(binding: EventCredentialBinding) -> tuple[str, ...]:
        """Return the exact server-owned identity of one ordered event stream."""
        return (
            binding.tenant_id,
            binding.engagement_id,
            binding.run_id,
            binding.job_id,
            binding.engine,
            binding.module_id,
            binding.target_binding,
            binding.sender_id,
        )

    def _retire_credential_locked(self, credential_id: str) -> None:
        state = self._records.pop(credential_id, None)
        if state is None:
            return
        ledger = self._stream_ledgers.get(state.stream_key)
        if ledger is not None and ledger.active_credential_id == credential_id:
            ledger.active_credential_id = ""

    def _credential_id(self, token: str | None) -> str:
        if not token:
            raise EventAdmissionError(EventAdmissionReason.MISSING_CREDENTIAL)
        if not isinstance(token, str) or token.count(".") != 1:
            raise EventAdmissionError(EventAdmissionReason.MALFORMED_CREDENTIAL)
        credential_id, secret = token.split(".", 1)
        if not _EVENT_TOKEN_ID_RE.fullmatch(credential_id) or not (32 <= len(secret) <= 128):
            raise EventAdmissionError(EventAdmissionReason.MALFORMED_CREDENTIAL)
        return credential_id

    def _validate_submission(
        self,
        state: _EventCredentialState,
        submission: Mapping[str, Any],
    ) -> tuple[int, str, EventType, dict[str, Any]]:
        if not isinstance(submission, Mapping) or set(submission) != _EVENT_SUBMISSION_FIELDS:
            raise EventAdmissionError(
                EventAdmissionReason.MALFORMED_EVENT,
                credential_id=state.binding.credential_id,
            )
        if submission.get("schema_version") != REMOTE_EVENT_SCHEMA_VERSION:
            raise EventAdmissionError(
                EventAdmissionReason.UNSUPPORTED_SCHEMA,
                credential_id=state.binding.credential_id,
            )
        comparisons = (
            ("tenant_id", state.binding.tenant_id, EventAdmissionReason.TENANT_MISMATCH),
            ("engagement_id", state.binding.engagement_id, EventAdmissionReason.ENGAGEMENT_MISMATCH),
            ("run_id", state.binding.run_id, EventAdmissionReason.RUN_MISMATCH),
            ("job_id", state.binding.job_id, EventAdmissionReason.JOB_MISMATCH),
            ("engine", state.binding.engine, EventAdmissionReason.ENGINE_MISMATCH),
            ("module_id", state.binding.module_id, EventAdmissionReason.MODULE_MISMATCH),
            ("sender_id", state.binding.sender_id, EventAdmissionReason.SENDER_MISMATCH),
        )
        for field_name, expected, reason in comparisons:
            raw = submission.get(field_name)
            if not isinstance(raw, str) or not hmac.compare_digest(raw, expected):
                raise EventAdmissionError(reason, credential_id=state.binding.credential_id)
        try:
            submitted_target = event_target_binding(str(submission.get("target", "")))
        except EventAdmissionError as exc:
            raise EventAdmissionError(
                EventAdmissionReason.TARGET_MISMATCH,
                credential_id=state.binding.credential_id,
            ) from exc
        if not hmac.compare_digest(submitted_target, state.binding.target_binding):
            raise EventAdmissionError(
                EventAdmissionReason.TARGET_MISMATCH,
                credential_id=state.binding.credential_id,
            )
        try:
            event_type = EventType(submission.get("event_type"))
        except (TypeError, ValueError) as exc:
            raise EventAdmissionError(
                EventAdmissionReason.EVENT_TYPE_DENIED,
                credential_id=state.binding.credential_id,
            ) from exc
        if event_type not in state.binding.allowed_event_types or event_type not in REMOTE_EVENT_TYPES:
            raise EventAdmissionError(
                EventAdmissionReason.EVENT_TYPE_DENIED,
                credential_id=state.binding.credential_id,
            )
        sequence = submission.get("sequence")
        nonce = submission.get("nonce")
        if type(sequence) is not int or sequence <= 0 or not isinstance(nonce, str) or not _EVENT_NONCE_RE.fullmatch(nonce):
            raise EventAdmissionError(
                EventAdmissionReason.MALFORMED_EVENT,
                credential_id=state.binding.credential_id,
            )
        data = self._validated_event_data(event_type, submission.get("data"), state.binding)
        return sequence, nonce, event_type, data

    def _validated_event_data(
        self,
        event_type: EventType,
        raw_data: Any,
        binding: EventCredentialBinding,
    ) -> dict[str, Any]:
        if not isinstance(raw_data, Mapping):
            raise EventAdmissionError(EventAdmissionReason.PAYLOAD_FORBIDDEN, credential_id=binding.credential_id)
        data = dict(raw_data)
        if event_type is EventType.MODULE_START:
            if set(data) != {"name", "phase"}:
                raise EventAdmissionError(EventAdmissionReason.PAYLOAD_FORBIDDEN, credential_id=binding.credential_id)
            phase = data.get("phase")
            if type(phase) is not int or not (0 <= phase <= 100):
                raise EventAdmissionError(EventAdmissionReason.PAYLOAD_FORBIDDEN, credential_id=binding.credential_id)
            result: dict[str, Any] = {"name": binding.module_id, "phase": phase}
        elif event_type is EventType.MODULE_PROGRESS:
            if set(data) != {"name", "progress"}:
                raise EventAdmissionError(EventAdmissionReason.PAYLOAD_FORBIDDEN, credential_id=binding.credential_id)
            progress = data.get("progress")
            if isinstance(progress, bool) or not isinstance(progress, (int, float)) or not math.isfinite(float(progress)) or not (0 <= float(progress) <= 100):
                raise EventAdmissionError(EventAdmissionReason.PAYLOAD_FORBIDDEN, credential_id=binding.credential_id)
            result = {"name": binding.module_id, "progress": float(progress)}
        elif event_type in {EventType.MODULE_FAIL, EventType.MODULE_SKIP}:
            if set(data) != {"name", "reason_code"}:
                raise EventAdmissionError(EventAdmissionReason.PAYLOAD_FORBIDDEN, credential_id=binding.credential_id)
            reason_code = data.get("reason_code")
            if not isinstance(reason_code, str) or not _EVENT_REASON_RE.fullmatch(reason_code):
                raise EventAdmissionError(EventAdmissionReason.PAYLOAD_FORBIDDEN, credential_id=binding.credential_id)
            key = "error" if event_type is EventType.MODULE_FAIL else "reason"
            result = {"name": binding.module_id, key: reason_code}
        else:
            raise EventAdmissionError(EventAdmissionReason.EVENT_TYPE_DENIED, credential_id=binding.credential_id)
        supplied_name = data.get("name")
        if not isinstance(supplied_name, str) or not hmac.compare_digest(supplied_name, binding.module_id):
            raise EventAdmissionError(EventAdmissionReason.MODULE_MISMATCH, credential_id=binding.credential_id)
        return result

    def _purge_expired_locked(self, now: datetime) -> None:
        expired = [
            credential_id
            for credential_id, state in self._records.items()
            if now >= _parse_event_timestamp(state.binding.expires_at)
        ]
        for credential_id in expired:
            self._retire_credential_locked(credential_id)

    def _resolve_job_state(self, binding: EventCredentialBinding) -> str | None:
        if self._job_state_resolver is None:
            return None
        try:
            value = self._job_state_resolver(binding)
        except Exception:
            return None
        return str(value).strip().lower() if value is not None else None


@dataclass
class Event:
    """A single event emitted by a module or the scan orchestrator.

    Attributes:
        event_type: Category of event (from EventType enum).
        data:       Payload dict — contents vary by event type.
        source:     Module or component that emitted the event.
        timestamp:  UTC ISO-8601 timestamp.
        event_id:   Unique identifier for dedup/replay.
        run_id:     Scan run UUID for correlation.
    """

    event_type: EventType
    data:       dict[str, Any] = field(default_factory=dict)
    source:     str            = ""
    timestamp:  str            = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_id:   str            = field(default_factory=lambda: str(uuid.uuid4())[:8])
    run_id:     str            = ""

    def __post_init__(self) -> None:
        self.data = redact_value(self.data)
        self.source = redact_text(self.source)

    def to_json(self) -> str:
        """Serialize for WebSocket transmission."""
        d = redact_value(asdict(self))
        d["event_type"] = self.event_type.value
        return json.dumps(d, default=str)

    @classmethod
    def from_json(cls, raw: str) -> "Event":
        """Deserialize from WebSocket message."""
        d = json.loads(raw)
        d["event_type"] = EventType(d["event_type"])
        return cls(**d)


# Subscriber callback signature: receives the Event object
Subscriber = Callable[[Event], None]
AsyncSubscriber = Callable[[Event], Any]  # coroutine


class EventBus:
    """Thread-safe publish/subscribe event bus.

    Publishers call emit() from any thread (module execution threads).
    Subscribers register via subscribe() and get called on the bus's
    dispatch thread, or via async_subscribe() for asyncio consumers.

    Usage::

        bus = EventBus()
        bus.start()

        # Subscribe (sync)
        bus.subscribe(EventType.FINDING_NEW, my_callback)

        # Subscribe (async — for web dashboard WebSocket push)
        bus.async_subscribe(EventType.FINDING_NEW, my_async_callback)

        # Publish from a module
        bus.emit(Event(EventType.FINDING_NEW, data={...}, source="sqli_scanner"))

        # Shutdown
        bus.stop()
    """

    def __init__(self, run_id: str = "", history_size: int = 10_000) -> None:
        """Initialize the event bus.

        Args:
            run_id:       Scan run UUID stamped on all events.
            history_size: Max events kept in replay buffer.
        """
        self.run_id = run_id
        self._queue: queue.Queue[Event | None] = queue.Queue(maxsize=50_000)
        self._subscribers: dict[EventType, list[Subscriber]] = {}
        self._async_subscribers: dict[EventType, list[AsyncSubscriber]] = {}
        self._wildcard_subscribers: list[Subscriber] = []
        self._async_wildcard_subscribers: list[AsyncSubscriber] = []
        self._history: list[Event] = []
        self._history_size = history_size
        self._lock = threading.Lock()
        self._dispatch_thread: threading.Thread | None = None
        self._running = False
        self._event_count = 0
        self._loop: asyncio.AbstractEventLoop | None = None

    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Start the dispatch thread.

        Args:
            loop: asyncio event loop for scheduling async subscribers.
                  If None, async subscribers won't fire.
        """
        if self._running:
            return
        self._running = True
        self._loop = loop
        self._dispatch_thread = threading.Thread(
            target=self._dispatch_loop,
            name="EventBus-Dispatch",
            daemon=True,
        )
        self._dispatch_thread.start()
        log.debug("EventBus started (run_id=%s)", self.run_id)

    def stop(self) -> None:
        """Stop the dispatch thread gracefully."""
        if not self._running:
            return
        self._running = False
        self._queue.put(None)  # sentinel to unblock
        if self._dispatch_thread:
            self._dispatch_thread.join(timeout=5.0)
        log.debug("EventBus stopped (%d events processed)", self._event_count)

    def emit(self, event: Event) -> None:
        """Publish an event to the bus (thread-safe, non-blocking).

        Args:
            event: The Event to publish.
        """
        if not event.run_id:
            event.run_id = self.run_id
        event.data = redact_value(event.data)
        event.source = redact_text(event.source)
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            log.warning("EventBus queue full — dropping event: %s", event.event_type.value)

    def emit_simple(
        self,
        event_type: EventType,
        source: str = "",
        **data: Any,
    ) -> None:
        """Convenience method: emit an event with keyword data.

        Args:
            event_type: Type of event to emit.
            source:     Emitting module name.
            **data:     Keyword arguments become the event data dict.
        """
        self.emit(Event(
            event_type=event_type,
            data=data,
            source=source,
            run_id=self.run_id,
        ))

    def subscribe(self, event_type: EventType | None, callback: Subscriber) -> None:
        """Register a sync subscriber for a specific event type.

        Args:
            event_type: Type to subscribe to, or None for wildcard (all events).
            callback:   Function called with each matching Event.
        """
        with self._lock:
            if event_type is None:
                self._wildcard_subscribers.append(callback)
            else:
                self._subscribers.setdefault(event_type, []).append(callback)

    def async_subscribe(self, event_type: EventType | None, callback: AsyncSubscriber) -> None:
        """Register an async subscriber for a specific event type.

        Args:
            event_type: Type to subscribe to, or None for wildcard.
            callback:   Async function called with each matching Event.
        """
        with self._lock:
            if event_type is None:
                self._async_wildcard_subscribers.append(callback)
            else:
                self._async_subscribers.setdefault(event_type, []).append(callback)

    def unsubscribe(self, event_type: EventType | None, callback: Subscriber) -> None:
        """Remove a sync subscriber."""
        with self._lock:
            if event_type is None:
                if callback in self._wildcard_subscribers:
                    self._wildcard_subscribers.remove(callback)
            else:
                subs = self._subscribers.get(event_type, [])
                if callback in subs:
                    subs.remove(callback)

    def get_history(
        self,
        event_type: EventType | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Return recent events from the replay buffer.

        Args:
            event_type: Filter by type, or None for all.
            limit:      Max events to return.

        Returns:
            List of Events, newest first.
        """
        with self._lock:
            if event_type:
                filtered = [e for e in self._history if e.event_type == event_type]
            else:
                filtered = list(self._history)
            return filtered[-limit:]

    @property
    def event_count(self) -> int:
        """Total number of events processed since start."""
        return self._event_count

    @property
    def queue_size(self) -> int:
        """Current number of events waiting in the dispatch queue."""
        return self._queue.qsize()

    @staticmethod
    def _observe_async_subscriber(
        task: asyncio.Future[Any],
        event_type: EventType,
    ) -> None:
        """Retrieve one task failure without exposing subscriber exception text."""
        try:
            failure = task.exception()
        except asyncio.CancelledError:
            return
        except BaseException:
            log.error(
                "Async subscriber callback failed on %s",
                event_type.value,
            )
            return
        if failure is not None:
            log.error(
                "Async subscriber callback failed on %s",
                event_type.value,
            )

    def _schedule_async_subscriber(
        self,
        callback: AsyncSubscriber,
        event: Event,
    ) -> None:
        """Create and observe an async subscriber task on the event-loop thread."""
        awaitable: Any = None
        try:
            awaitable = callback(event)
            task = asyncio.ensure_future(awaitable)
            task.add_done_callback(
                lambda completed, kind=event.event_type: self._observe_async_subscriber(
                    completed,
                    kind,
                )
            )
        except BaseException:
            close = getattr(awaitable, "close", None)
            if callable(close):
                try:
                    close()
                except BaseException:
                    pass
            log.error(
                "Async subscriber callback failed on %s",
                event.event_type.value,
            )

    def _dispatch_loop(self) -> None:
        """Internal dispatch thread — routes events to subscribers."""
        while self._running:
            try:
                event = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if event is None:  # sentinel
                break

            self._event_count += 1

            # Store in history
            with self._lock:
                self._history.append(event)
                if len(self._history) > self._history_size:
                    self._history = self._history[-self._history_size:]

            # Dispatch to sync subscribers
            with self._lock:
                type_subs = list(self._subscribers.get(event.event_type, []))
                wildcard_subs = list(self._wildcard_subscribers)

            for cb in type_subs + wildcard_subs:
                try:
                    cb(event)
                except Exception:
                    log.error(
                        "Subscriber callback failed on %s",
                        event.event_type.value,
                    )

            # Dispatch to async subscribers
            loop = self._loop
            if loop and not loop.is_closed():
                with self._lock:
                    async_type_subs = list(self._async_subscribers.get(event.event_type, []))
                    async_wildcard_subs = list(self._async_wildcard_subscribers)

                for cb in async_type_subs + async_wildcard_subs:
                    try:
                        loop.call_soon_threadsafe(
                            self._schedule_async_subscriber,
                            cb,
                            event,
                        )
                    except RuntimeError:
                        # The loop may close between the check and scheduling.
                        # Keep this failure observable without rendering the
                        # callback, event payload, or exception text.
                        log.error(
                            "Async subscriber callback failed on %s",
                            event.event_type.value,
                        )
                    except Exception:
                        log.error(
                            "Async subscriber callback failed on %s",
                            event.event_type.value,
                        )


class RemoteEventBus:
    """Inert compatibility adapter for the disabled remote-event surface.

    A future implementation must supply a distinct Task-003-authorized
    dashboard-origin transport plus the scoped credential contract above.
    This adapter performs no resolver, socket, TLS, thread, or HTTP work.
    """

    def __init__(self, url: str, run_id: str = "") -> None:
        self.url = url.rstrip("/")
        self.run_id = run_id
        self._queue: queue.Queue[Event | None] = queue.Queue(maxsize=10_000)
        self._thread: threading.Thread | None = None
        self._running = False
        self.disabled_reason = "remote_event_destination_not_authorized"

    def start(self, loop: Any = None) -> bool:
        del loop
        if self._running:
            return True
        # A scan/module envelope authorizes the inspected target, not a
        # dashboard origin.  Until a distinct control-plane egress envelope is
        # supplied, remote forwarding remains visibly disabled and creates no
        # thread, resolver call, TLS context, or HTTP request.
        log.warning(
            "RemoteEventBus disabled: dashboard destination lacks exact outbound authorization"
        )
        return False

    def stop(self) -> None:
        self._running = False
        self._queue.put(None)
        if self._thread:
            self._thread.join(timeout=5.0)

    def emit(self, event: Event) -> None:
        if not self._running:
            return
        if not event.run_id:
            event.run_id = self.run_id
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            log.warning("RemoteEventBus queue full — dropping %s", event.event_type.value)

    def emit_simple(
        self,
        event_type: EventType,
        source: str = "",
        **data: Any,
    ) -> None:
        self.emit(Event(
            event_type=event_type,
            data=data,
            source=source,
            run_id=self.run_id,
        ))

    # No-op stubs so code that calls subscribe/async_subscribe doesn't crash
    def subscribe(self, *_: Any, **__: Any) -> None:
        pass

    def async_subscribe(self, *_: Any, **__: Any) -> None:
        pass

    def _send_loop(self) -> None:
        return


class TestEventBus:
    """Unit tests for event_bus module."""

    def test_emit_and_subscribe(self) -> None:
        bus = EventBus(run_id="test-run")
        bus.start()
        received: list[Event] = []
        bus.subscribe(EventType.FINDING_NEW, lambda e: received.append(e))

        bus.emit(Event(
            event_type=EventType.FINDING_NEW,
            data={"title": "SQLi", "severity": "High"},
            source="sqli_scanner",
        ))

        time.sleep(0.2)
        bus.stop()
        assert len(received) == 1
        assert received[0].data["title"] == "SQLi"
        assert received[0].run_id == "test-run"

    def test_wildcard_subscriber(self) -> None:
        bus = EventBus()
        bus.start()
        received: list[Event] = []
        bus.subscribe(None, lambda e: received.append(e))

        bus.emit_simple(EventType.MODULE_START, source="test_mod", name="test")
        bus.emit_simple(EventType.FINDING_NEW, source="test_mod", title="XSS")

        time.sleep(0.2)
        bus.stop()
        assert len(received) == 2

    def test_history(self) -> None:
        bus = EventBus()
        bus.start()
        for i in range(5):
            bus.emit_simple(EventType.HEARTBEAT, source="test", count=i)
        time.sleep(0.3)
        bus.stop()
        history = bus.get_history(EventType.HEARTBEAT, limit=3)
        assert len(history) == 3

    def test_event_serialization(self) -> None:
        event = Event(
            event_type=EventType.FINDING_NEW,
            data={"title": "Test", "severity": "High"},
            source="test_module",
            run_id="run-123",
        )
        json_str = event.to_json()
        restored = Event.from_json(json_str)
        assert restored.event_type == EventType.FINDING_NEW
        assert restored.data["title"] == "Test"
        assert restored.run_id == "run-123"

    def test_queue_overflow_doesnt_crash(self) -> None:
        bus = EventBus()
        # Don't start — queue will fill up
        for _ in range(60_000):
            bus.emit_simple(EventType.HEARTBEAT, source="test")
        # Should not raise, just log warnings
        assert bus.queue_size <= 50_000
