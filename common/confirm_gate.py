"""Operator confirmation gate — required before any active exploitation action."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping
from typing import Callable

from rich.console import Console
from rich.panel import Panel

from common.scope import (
    ScopeDecision,
    ScopeReason,
    canonical_target,
    decide_scope,
    decision_for_reason,
    safe_target_display,
)

console = Console()
log = logging.getLogger(__name__)

CONFIRMATION_SCHEMA_VERSION = "forge-action-confirmation-v1"
LAUNCH_CONTEXT_SCHEMA_VERSION = "forge-launch-context-v1"
LAUNCH_CONFIRMATIONS_ENV = "FORGE_LAUNCH_CONFIRMATIONS"
LAUNCH_JOB_ID_ENV = "FORGE_LAUNCH_JOB_ID"
LAUNCH_ACTION_ENV = "FORGE_LAUNCH_ACTION"
DEFAULT_CONFIRMATION_MAX_AGE_SECONDS = 300
_MAX_FUTURE_SKEW_SECONDS = 30
_CONFIRMATION_KEYS = {
    "schema_version",
    "confirmed",
    "job_id",
    "target",
    "engine",
    "action",
    "issued_at",
    "binding_digest",
}
_SHA256_BINDING = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _utc_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime):
        raise ValueError("confirmation timestamps must be datetimes")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("confirmation timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("confirmation timestamps must be strings")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("confirmation timestamps must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _binding_digest(
    *,
    confirmed: bool,
    job_id: str,
    target: str,
    engine: str,
    action: str,
    issued_at: str,
) -> str:
    payload = {
        "schema_version": CONFIRMATION_SCHEMA_VERSION,
        "confirmed": confirmed,
        "job_id": job_id,
        "target": target,
        "engine": engine,
        "action": action,
        "issued_at": issued_at,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ActionConfirmation:
    """Short-lived exact-action acknowledgement, not an authentication envelope.

    The binding digest is a mutation checksum. Caller authentication, issuance,
    replay prevention, persistence, and audit remain authorization-envelope work.
    """

    schema_version: str
    confirmed: bool
    job_id: str
    target: str
    engine: str
    action: str
    issued_at: str
    binding_digest: str

    @classmethod
    def create(
        cls,
        *,
        job_id: str,
        target: str,
        engine: str,
        action: str,
        issued_at: datetime | None = None,
        confirmed: bool = True,
    ) -> "ActionConfirmation":
        if not isinstance(job_id, str) or not isinstance(engine, str) or not isinstance(action, str):
            raise ValueError("confirmation identifiers must be strings")
        if type(confirmed) is not bool:
            raise ValueError("confirmation flag must be boolean")
        canonical_job = job_id.strip()
        canonical_engine = engine.strip().lower()
        canonical_action = action.strip().lower()
        if not canonical_job or len(canonical_job) > 160:
            raise ValueError("confirmation requires a bounded job id")
        if not canonical_engine or not canonical_action:
            raise ValueError("confirmation requires an engine and action")
        canonical_target_value = canonical_target(target)
        timestamp = _utc_timestamp(
            datetime.now(timezone.utc) if issued_at is None else issued_at
        )
        digest = _binding_digest(
            confirmed=confirmed,
            job_id=canonical_job,
            target=canonical_target_value,
            engine=canonical_engine,
            action=canonical_action,
            issued_at=timestamp,
        )
        return cls(
            schema_version=CONFIRMATION_SCHEMA_VERSION,
            confirmed=confirmed,
            job_id=canonical_job,
            target=canonical_target_value,
            engine=canonical_engine,
            action=canonical_action,
            issued_at=timestamp,
            binding_digest=digest,
        )

    @classmethod
    def from_value(
        cls,
        value: "ActionConfirmation | Mapping[str, object]",
    ) -> "ActionConfirmation":
        if isinstance(value, cls):
            value = value.to_dict()
        if not isinstance(value, Mapping) or set(value) != _CONFIRMATION_KEYS:
            raise ValueError("confirmation has an invalid shape")
        if value.get("schema_version") != CONFIRMATION_SCHEMA_VERSION:
            raise ValueError("confirmation schema is unsupported")
        if not isinstance(value.get("confirmed"), bool):
            raise ValueError("confirmation flag must be boolean")
        fields = {
            key: value.get(key)
            for key in ("job_id", "target", "engine", "action", "issued_at", "binding_digest")
        }
        if not all(isinstance(item, str) for item in fields.values()):
            raise ValueError("confirmation fields must be strings")
        record = cls(
            schema_version=CONFIRMATION_SCHEMA_VERSION,
            confirmed=bool(value["confirmed"]),
            job_id=str(value["job_id"]),
            target=str(value["target"]),
            engine=str(value["engine"]),
            action=str(value["action"]),
            issued_at=str(value["issued_at"]),
            binding_digest=str(value["binding_digest"]),
        )
        if (
            not record.job_id.strip()
            or len(record.job_id) > 160
            or record.engine != record.engine.strip().lower()
            or record.action != record.action.strip().lower()
            or not record.engine
            or not record.action
            or not _SHA256_BINDING.fullmatch(record.target)
            or not _SHA256_HEX.fullmatch(record.binding_digest)
        ):
            raise ValueError("confirmation fields are not canonical")
        _parse_timestamp(record.issued_at)
        return record

    def has_valid_binding(self) -> bool:
        expected = _binding_digest(
            confirmed=self.confirmed,
            job_id=self.job_id,
            target=self.target,
            engine=self.engine,
            action=self.action,
            issued_at=self.issued_at,
        )
        return hmac.compare_digest(self.binding_digest, expected)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "confirmed": self.confirmed,
            "job_id": self.job_id,
            "target": self.target,
            "engine": self.engine,
            "action": self.action,
            "issued_at": self.issued_at,
            "binding_digest": self.binding_digest,
        }


def decide_action(
    *,
    target: str,
    allowed_scope: Iterable[str] | str | None,
    excluded_scope: Iterable[str] | str | None,
    confirmation: ActionConfirmation | Mapping[str, object] | None,
    job_id: str,
    engine: str,
    action: str,
    now: datetime | None = None,
    require_confirmation: bool = True,
    max_age_seconds: int = DEFAULT_CONFIRMATION_MAX_AGE_SECONDS,
) -> ScopeDecision:
    """Decide scope and exact confirmation without performing side effects."""
    scope_decision = decide_scope(target, allowed_scope, excluded_scope)
    if not scope_decision.allowed:
        return scope_decision
    if type(require_confirmation) is not bool:
        return decision_for_reason(
            ScopeReason.INVALID_CONFIRMATION,
            normalized_target=scope_decision.normalized_target,
            matched_scope=scope_decision.matched_scope,
        )
    if not require_confirmation:
        return decision_for_reason(
            ScopeReason.SCOPE_MATCHED,
            normalized_target=scope_decision.normalized_target,
            matched_scope=scope_decision.matched_scope,
        )
    if confirmation is None:
        return decision_for_reason(
            ScopeReason.MISSING_CONFIRMATION,
            normalized_target=scope_decision.normalized_target,
            matched_scope=scope_decision.matched_scope,
        )
    if (
        type(max_age_seconds) is not int
        or max_age_seconds <= 0
        or max_age_seconds > DEFAULT_CONFIRMATION_MAX_AGE_SECONDS
    ):
        return decision_for_reason(
            ScopeReason.INVALID_CONFIRMATION,
            normalized_target=scope_decision.normalized_target,
            matched_scope=scope_decision.matched_scope,
        )
    try:
        record = ActionConfirmation.from_value(confirmation)
        expected_target = canonical_target(target)
    except (TypeError, ValueError, OverflowError):
        return decision_for_reason(
            ScopeReason.INVALID_CONFIRMATION,
            normalized_target=scope_decision.normalized_target,
            matched_scope=scope_decision.matched_scope,
        )
    if not record.confirmed or not record.has_valid_binding():
        return decision_for_reason(
            ScopeReason.INVALID_CONFIRMATION,
            normalized_target=scope_decision.normalized_target,
            matched_scope=scope_decision.matched_scope,
        )
    if not isinstance(job_id, str) or not isinstance(engine, str) or not isinstance(action, str):
        return decision_for_reason(
            ScopeReason.INVALID_CONFIRMATION,
            normalized_target=scope_decision.normalized_target,
            matched_scope=scope_decision.matched_scope,
        )
    if record.job_id != job_id.strip():
        reason = ScopeReason.JOB_MISMATCH
    elif record.engine != engine.strip().lower():
        reason = ScopeReason.ENGINE_MISMATCH
    elif record.action != action.strip().lower():
        reason = ScopeReason.ACTION_MISMATCH
    elif record.target != expected_target:
        reason = ScopeReason.TARGET_MISMATCH
    else:
        reason = ScopeReason.ALLOWED
    if reason is not ScopeReason.ALLOWED:
        return decision_for_reason(
            reason,
            normalized_target=scope_decision.normalized_target,
            matched_scope=scope_decision.matched_scope,
        )

    try:
        issued_at = _parse_timestamp(record.issued_at)
        current = datetime.now(timezone.utc) if now is None else now
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("current time must be timezone-aware")
        age = (current.astimezone(timezone.utc) - issued_at).total_seconds()
    except (AttributeError, TypeError, ValueError, OverflowError):
        age = float("inf")
    if age > max_age_seconds or age < -_MAX_FUTURE_SKEW_SECONDS:
        return decision_for_reason(
            ScopeReason.STALE_CONFIRMATION,
            normalized_target=scope_decision.normalized_target,
            matched_scope=scope_decision.matched_scope,
        )
    return decision_for_reason(
        ScopeReason.ALLOWED,
        normalized_target=scope_decision.normalized_target,
        matched_scope=scope_decision.matched_scope,
    )


def encode_launch_confirmations(confirmations: Iterable[ActionConfirmation]) -> str:
    """Serialize bounded confirmations for a trusted parent-to-child launch."""
    return json.dumps(
        {
            "schema_version": LAUNCH_CONTEXT_SCHEMA_VERSION,
            "confirmations": [confirmation.to_dict() for confirmation in confirmations],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def load_launch_confirmations(
    environ: Mapping[str, str] | None = None,
) -> list[ActionConfirmation]:
    """Load confirmations supplied by a trusted local launcher environment."""
    source = environ if environ is not None else os.environ
    raw = source.get(LAUNCH_CONFIRMATIONS_ENV, "")
    if not raw:
        return []
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("launch context must be an object")
        if payload.get("schema_version") != LAUNCH_CONTEXT_SCHEMA_VERSION:
            raise ValueError("launch context schema is unsupported")
        values = payload.get("confirmations")
        if not isinstance(values, list) or len(values) > 1000:
            raise ValueError("launch confirmations must be a bounded list")
        return [ActionConfirmation.from_value(value) for value in values]
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        log.warning("Invalid launch confirmation context: %s", type(exc).__name__)
        return []


def load_launch_expectation(
    environ: Mapping[str, str] | None = None,
) -> tuple[str, str] | None:
    """Load the independent expected job/action for a child launch."""
    source = environ if environ is not None else os.environ
    job_id = source.get(LAUNCH_JOB_ID_ENV, "")
    action = source.get(LAUNCH_ACTION_ENV, "")
    if not isinstance(job_id, str) or not isinstance(action, str):
        return None
    if (
        job_id != job_id.strip()
        or not job_id
        or len(job_id) > 160
        or action != action.strip().lower()
        or not action
        or len(action) > 80
    ):
        return None
    return job_id, action


def select_launch_confirmation(
    confirmations: Iterable[ActionConfirmation],
    *,
    target: str,
    engine: str,
    action: str,
    job_id: str | None = None,
) -> ActionConfirmation | None:
    """Select one parent-provided confirmation for an engine action."""
    records = list(confirmations)
    engine_value = str(engine).strip().lower()
    action_value = str(action).strip().lower()
    candidates = [
        record
        for record in records
        if record.engine == engine_value and record.action == action_value
    ]
    try:
        expected_target = canonical_target(target)
    except ValueError:
        return None
    exact = [
        record
        for record in candidates
        if record.target == expected_target
        and (job_id is None or record.job_id == str(job_id).strip())
    ]
    return exact[0] if len(exact) == 1 else None

# Global flag — set via --auto-confirm CLI flag (dangerous, documented)
_AUTO_CONFIRM: bool = False


def set_auto_confirm(enabled: bool) -> None:
    """Enable or disable auto-confirm mode. Only set from CLI --auto-confirm flag."""
    if type(enabled) is not bool:
        raise ValueError("auto-confirm flag must be boolean")
    global _AUTO_CONFIRM
    _AUTO_CONFIRM = enabled
    if enabled:
        log.warning(
            "AUTO-CONFIRM MODE ENABLED — all confirmation gates will be bypassed automatically",
            extra={"detail": {"auto_confirm": True}},
        )


def confirm(
    module: str,
    action: str,
    target: str,
    risk: str,
    on_confirm: Callable[[], None] | None = None,
    on_skip: Callable[[], None] | None = None,
) -> bool:
    """Display an operator confirmation prompt before executing a sensitive action.

    Args:
        module:     Module name requesting confirmation (e.g. 'kerberoast').
        action:     Human-readable description of what will happen.
        target:     The affected target (IP, hostname, object).
        risk:       Description of the risk/impact.
        on_confirm: Optional callback to run if operator confirms.
        on_skip:    Optional callback to run if operator skips.

    Returns:
        True if operator confirmed execution, False if skipped.
    """
    safe_target = safe_target_display(target)
    action_ref = hashlib.sha256(str(action).encode("utf-8", "replace")).hexdigest()[:12]
    if _AUTO_CONFIRM:
        log.info(
            "AUTO-CONFIRM: module=%s action_ref=%s target=%s",
            module,
            action_ref,
            safe_target,
            extra={
                "forge_module": module,
                "target": safe_target,
                "operator_confirmed": True,
                "detail": {"action_ref": action_ref, "auto": True},
            },
        )
        if on_confirm:
            on_confirm()
        return True

    console.print(Panel(
        f"  [bold yellow]Module  :[/bold yellow] {module}\n"
        f"  [bold yellow]Action  :[/bold yellow] {action}\n"
        f"  [bold yellow]Target  :[/bold yellow] {safe_target}\n"
        f"  [bold red]Risk    :[/bold red] {risk}\n\n"
        f"  Execute this action? ([green]yes[/green]/[red]no[/red]):",
        title="[bold cyan]ACTION REQUIRES OPERATOR CONFIRMATION[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))

    try:
        answer = input("  Confirm (yes/no): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "no"

    confirmed = answer == "yes"

    log.info(
        "%s action_ref=%s target=%s: %s",
        module,
        action_ref,
        safe_target,
        "CONFIRMED" if confirmed else "SKIPPED",
        extra={
            "forge_module": module,
            "target": safe_target,
            "operator_confirmed": confirmed,
            "detail": {"action_ref": action_ref},
        },
    )

    if confirmed:
        console.print(f"[green]  [+] Executing: {action}[/green]")
        if on_confirm:
            on_confirm()
    else:
        console.print(f"[yellow]  [-] Skipped: {action} (logged as finding)[/yellow]")
        if on_skip:
            on_skip()

    return confirmed


class TestConfirmGate:
    """Unit tests for confirm_gate module."""

    def test_auto_confirm_mode(self) -> None:
        set_auto_confirm(True)
        result = confirm(
            module="test", action="test action", target="127.0.0.1",
            risk="low", on_confirm=None, on_skip=None,
        )
        assert result is True
        set_auto_confirm(False)

    def test_set_auto_confirm(self) -> None:
        set_auto_confirm(True)
        assert _AUTO_CONFIRM is True
        set_auto_confirm(False)
        assert _AUTO_CONFIRM is False

    def test_callbacks_called(self) -> None:
        called = []
        set_auto_confirm(True)
        confirm(
            module="test", action="act", target="t", risk="r",
            on_confirm=lambda: called.append("confirmed"),
        )
        assert "confirmed" in called
        set_auto_confirm(False)
