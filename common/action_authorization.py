"""Versioned, single-use action authorization and immutable audit support.

The Work Package 001 scope decision remains the source of scope truth.  This
module binds that decision and an exact operator confirmation to one action,
persists the decision before execution, and atomically consumes it once.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, TypeVar, cast
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from common.confirm_gate import (
    DEFAULT_CONFIRMATION_MAX_AGE_SECONDS,
    ActionConfirmation,
    decide_action,
)
from common.redaction import redact_value
from common.db import (
    append_authorization_execution_claim,
    append_authorization_consumption,
    append_authorization_decision,
    create_db,
    get_authorization_execution_claim,
    get_authorization_consumption,
    get_authorization_child_decision,
    get_authorization_decision,
    open_existing_db,
    save_scan_job,
)
from common.scope import canonical_target, decide_scope


log = logging.getLogger(__name__)

AUTHORIZATION_SCHEMA_VERSION = "forge-action-authorization-v1"
AUTHORIZATION_CONTEXT_SCHEMA_VERSION = "forge-action-authorizations-v1"
AUTHORIZATION_ENVELOPES_ENV = "FORGE_ACTION_AUTHORIZATIONS"
AUTHORIZATION_DB_ENV = "FORGE_AUTHORIZATION_DB"
AUTHORIZATION_DB_PREINITIALIZED_ENV = (
    "FORGE_AUTHORIZATION_DB_PREINITIALIZED"
)
AUTHORIZATION_TENANT_ENV = "FORGE_AUTHORIZATION_TENANT_ID"
AUTHORIZATION_ENGAGEMENT_ENV = "FORGE_AUTHORIZATION_ENGAGEMENT_ID"
AUTHORIZATION_RUN_ENV = "FORGE_AUTHORIZATION_RUN_ID"
AUTHORIZATION_OPERATOR_ENV = "FORGE_AUTHORIZATION_OPERATOR_ID"
AUTHORIZATION_ROLE_ENV = "FORGE_AUTHORIZATION_OPERATOR_ROLE"
AUTHORIZATION_SCOPE_POLICY_ENV = "FORGE_AUTHORIZATION_SCOPE_POLICY"
AUTHORIZATION_SAFETY_MODE_ENV = "FORGE_AUTHORIZATION_SAFETY_MODE"
DEFAULT_AUTHORIZATION_TTL_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 30

_SHA256_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,199}$")
# Keep credential bindings reproducible within one running authorization
# service while making a database-only offline dictionary attack useless.
# A restart intentionally invalidates in-memory secret-derived bindings.
_CREDENTIAL_REFERENCE_KEY = secrets.token_bytes(32)


class AuthorizationOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN_NOT_AUTHORIZED = "unknown_not_authorized"


class SafetyMode(str, Enum):
    PASSIVE = "passive"
    STANDARD = "standard"
    ACTIVE = "active"
    CREDENTIAL = "credential"
    HIGH_RISK = "high_risk"
    LOCAL_LAB = "local_lab"


class ConfirmationMethod(str, Enum):
    NONE = "none"
    CLI_PROMPT = "cli_prompt"
    CLI_FLAG = "cli_flag"
    DASHBOARD = "dashboard"
    AGENT_JOB = "agent_job"
    INHERITED = "inherited"


class OperatorRole(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"
    AGENT = "agent"
    SYSTEM = "system"


class AuthorizationReason(str, Enum):
    ALLOWED = "allowed"
    MISSING_REQUIRED_FIELD = "missing_required_field"
    MALFORMED_FIELD = "malformed_field"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    INTEGRITY_MISMATCH = "integrity_mismatch"
    UNRECORDED_DECISION = "unrecorded_decision"
    TENANT_MISMATCH = "tenant_mismatch"
    ENGAGEMENT_MISMATCH = "engagement_mismatch"
    RUN_MISMATCH = "run_mismatch"
    JOB_MISMATCH = "job_mismatch"
    OPERATOR_MISMATCH = "operator_mismatch"
    ROLE_MISMATCH = "role_mismatch"
    ENGINE_MISMATCH = "engine_mismatch"
    MODULE_MISMATCH = "module_mismatch"
    ACTION_MISMATCH = "action_mismatch"
    REQUESTED_TARGET_MISMATCH = "requested_target_mismatch"
    RESOLVED_TARGET_MISMATCH = "resolved_target_mismatch"
    SCOPE_POLICY_MISMATCH = "scope_policy_mismatch"
    SAFETY_MODE_MISMATCH = "safety_mode_mismatch"
    APPROVAL_MISMATCH = "approval_mismatch"
    EXPIRED = "expired"
    FUTURE_ISSUED = "future_issued"
    REPLAYED = "replayed"
    ALREADY_CONSUMED = "already_consumed"
    ALREADY_DERIVED = "already_derived"
    NOT_CONSUMED = "not_consumed"
    LEGACY_NOT_AUTHORIZED = "legacy_not_authorized"
    PARENT_NOT_AUTHORIZED = "parent_not_authorized"
    AUDIT_PERSISTENCE_FAILED = "audit_persistence_failed"
    HANDOFF_PERSISTENCE_FAILED = "handoff_persistence_failed"


_REASON_MESSAGES: dict[str, str] = {
    AuthorizationReason.ALLOWED.value: "The exact action authorization is valid and single-use.",
    AuthorizationReason.MISSING_REQUIRED_FIELD.value: "The authorization envelope is missing a required field.",
    AuthorizationReason.MALFORMED_FIELD.value: "The authorization envelope contains malformed or ambiguous data.",
    AuthorizationReason.UNSUPPORTED_SCHEMA.value: "The authorization envelope schema is unsupported.",
    AuthorizationReason.INTEGRITY_MISMATCH.value: "The authorization envelope was modified after its decision.",
    AuthorizationReason.UNRECORDED_DECISION.value: "The authorization decision is not present in the immutable audit store.",
    AuthorizationReason.TENANT_MISMATCH.value: "The authorization is bound to a different tenant.",
    AuthorizationReason.ENGAGEMENT_MISMATCH.value: "The authorization is bound to a different engagement.",
    AuthorizationReason.RUN_MISMATCH.value: "The authorization is bound to a different run.",
    AuthorizationReason.JOB_MISMATCH.value: "The authorization is bound to a different job.",
    AuthorizationReason.OPERATOR_MISMATCH.value: "The authorization is bound to a different operator.",
    AuthorizationReason.ROLE_MISMATCH.value: "The authorization is bound to a different operator role.",
    AuthorizationReason.ENGINE_MISMATCH.value: "The authorization is bound to a different engine.",
    AuthorizationReason.MODULE_MISMATCH.value: "The authorization is bound to a different module or check.",
    AuthorizationReason.ACTION_MISMATCH.value: "The authorization is bound to a different action.",
    AuthorizationReason.REQUESTED_TARGET_MISMATCH.value: "The requested target does not match the authorized action.",
    AuthorizationReason.RESOLVED_TARGET_MISMATCH.value: "The resolved target does not match the authorized action.",
    AuthorizationReason.SCOPE_POLICY_MISMATCH.value: "The effective scope snapshot or policy changed.",
    AuthorizationReason.SAFETY_MODE_MISMATCH.value: "The safety mode does not match the authorized action.",
    AuthorizationReason.APPROVAL_MISMATCH.value: "The required separate approvals do not match the authorized action.",
    AuthorizationReason.EXPIRED.value: "The authorization envelope expired before execution.",
    AuthorizationReason.FUTURE_ISSUED.value: "The authorization envelope was issued too far in the future.",
    AuthorizationReason.REPLAYED.value: "The authorization envelope was replayed at another boundary.",
    AuthorizationReason.ALREADY_CONSUMED.value: "The single-use authorization was already consumed.",
    AuthorizationReason.ALREADY_DERIVED.value: "This parent authorization already issued the exact child action.",
    AuthorizationReason.NOT_CONSUMED.value: "The authorization was not consumed at the required execution boundary.",
    AuthorizationReason.LEGACY_NOT_AUTHORIZED.value: "The legacy record has no active authorization envelope.",
    AuthorizationReason.PARENT_NOT_AUTHORIZED.value: "The parent action was not validly authorized and consumed.",
    AuthorizationReason.AUDIT_PERSISTENCE_FAILED.value: "The authorization audit could not be persisted; execution was denied.",
    AuthorizationReason.HANDOFF_PERSISTENCE_FAILED.value: "The authorized action handoff could not be persisted; execution was denied.",
}


def _reason_message(reason_code: str) -> str:
    return _REASON_MESSAGES.get(reason_code, "The action was not authorized.")


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("authorization timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("authorization timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return _utc(parsed)


def _enum_value(value: Enum | str) -> str:
    return value.value if isinstance(value, Enum) else str(value)


def _safe_identifier(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized and allow_empty:
        return ""
    if not normalized or not _SAFE_IDENTIFIER.fullmatch(normalized):
        raise ValueError(f"{field} is malformed")
    return normalized


def _safe_target_for_binding(target: str) -> str:
    """Return an opaque digest of the exact target without persisting its value."""
    if not isinstance(target, str):
        raise ValueError("target must be a string")
    raw = target.strip()
    try:
        return canonical_target(raw)
    except (TypeError, ValueError):
        # Scope validation will still deny malformed targets.  Hashing the exact
        # submitted bytes here avoids collapsing two secret-bearing URLs into the
        # same authorization binding while keeping those bytes out of persistence.
        return f"sha256:{hashlib.sha256(raw.encode('utf-8', 'replace')).hexdigest()}"


def _scope_snapshot(allowed: Iterable[str], excluded: Iterable[str]) -> str:
    material = {
        "allowed": sorted(str(value).strip() for value in allowed),
        "excluded": sorted(str(value).strip() for value in excluded),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def module_set_binding(modules: Iterable[str] | None) -> str:
    """Return the stable envelope binding for one explicit module selection.

    An empty selection means the engine's normal/default module plan and keeps
    the historical empty ``module_id``.  Explicit selections are normalized so
    dashboard, agent, unified CLI, and engine adapters derive the same binding.
    """
    normalized: set[str] = set()
    for item in modules or ():
        if not isinstance(item, str):
            raise ValueError("module selection entries must be strings")
        value = item.strip().lower()
        if value:
            normalized.add(value)
    if not normalized:
        return ""
    material = "|".join(sorted(normalized))
    return f"module-set-{uuid.uuid5(uuid.NAMESPACE_URL, material).hex}"


def module_binding_allows(
    binding: str,
    modules: Iterable[str] | None,
    module_id: str,
) -> bool:
    """Verify that an exact module is contained in its bound selection."""
    requested = {
        item.strip().lower()
        for item in modules or ()
        if isinstance(item, str) and item.strip()
    }
    candidate = str(module_id).strip().lower()
    if not binding:
        return True
    if binding.startswith("module-set-"):
        return (
            bool(candidate)
            and candidate in requested
            and hmac.compare_digest(binding, module_set_binding(requested))
        )
    return hmac.compare_digest(binding, candidate)


def protected_credential_reference(values: Mapping[str, Any]) -> str:
    """Bind credential-bearing runtime inputs without serializing their values.

    The process-local keyed digest is an equality binding, not a credential
    verifier.  Persisted authorization records therefore cannot be used to
    test password guesses without the live authorization process key.
    """
    material = {
        str(key): str(value)
        for key, value in values.items()
        if value is not None and str(value) != ""
    }
    if not material:
        return ""
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hmac.new(
        _CREDENTIAL_REFERENCE_KEY,
        ("forge-credential-reference-v2\0" + canonical).encode(
            "utf-8", "replace"
        ),
        hashlib.sha256,
    ).hexdigest()
    return f"cred:sha256:{digest}"


def authorization_runtime_environment(
    envelope: "ActionAuthorizationEnvelope",
) -> dict[str, str]:
    """Return trusted, non-secret process-handoff facts for engine validation."""
    record = ActionAuthorizationEnvelope.from_value(envelope)
    return {
        AUTHORIZATION_TENANT_ENV: record.tenant_id,
        AUTHORIZATION_ENGAGEMENT_ENV: record.engagement_id,
        AUTHORIZATION_RUN_ENV: record.run_id,
        AUTHORIZATION_OPERATOR_ENV: record.operator_id,
        AUTHORIZATION_ROLE_ENV: record.operator_role,
        AUTHORIZATION_SCOPE_POLICY_ENV: record.scope_policy_version,
        AUTHORIZATION_SAFETY_MODE_ENV: record.safety_mode,
    }


def load_authorization_runtime_facts(
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Load the independent, non-secret execution facts supplied by a launcher.

    The envelope is deliberately not an input.  A missing or partial handoff
    therefore cannot be filled from the capability it is intended to verify.
    """
    values = os.environ if source is None else source
    mapping = {
        "tenant_id": AUTHORIZATION_TENANT_ENV,
        "engagement_id": AUTHORIZATION_ENGAGEMENT_ENV,
        "run_id": AUTHORIZATION_RUN_ENV,
        "operator_id": AUTHORIZATION_OPERATOR_ENV,
        "operator_role": AUTHORIZATION_ROLE_ENV,
        "scope_policy_version": AUTHORIZATION_SCOPE_POLICY_ENV,
        "safety_mode": AUTHORIZATION_SAFETY_MODE_ENV,
    }
    loaded: dict[str, str] = {}
    for field, env_key in mapping.items():
        raw = values.get(env_key)
        if not isinstance(raw, str) or not raw.strip():
            return {}
        loaded[field] = raw.strip()
    try:
        _safe_identifier(loaded["tenant_id"], "tenant_id")
        _safe_identifier(loaded["engagement_id"], "engagement_id")
        _safe_identifier(loaded["run_id"], "run_id")
        _safe_identifier(loaded["operator_id"], "operator_id")
        _safe_identifier(loaded["scope_policy_version"], "scope_policy_version")
        OperatorRole(loaded["operator_role"])
        SafetyMode(loaded["safety_mode"])
    except (TypeError, ValueError):
        return {}
    return loaded


def authorization_runtime_environment_from_facts(
    facts: Mapping[str, Any],
) -> dict[str, str]:
    """Encode already trusted runtime facts for a subprocess handoff."""
    def _text(field: str) -> str:
        raw = facts.get(field)
        return "" if raw is None else str(raw)

    source = {
        AUTHORIZATION_TENANT_ENV: _text("tenant_id"),
        AUTHORIZATION_ENGAGEMENT_ENV: _text("engagement_id"),
        AUTHORIZATION_RUN_ENV: _text("run_id"),
        AUTHORIZATION_OPERATOR_ENV: _text("operator_id"),
        AUTHORIZATION_ROLE_ENV: _text("operator_role"),
        AUTHORIZATION_SCOPE_POLICY_ENV: _text("scope_policy_version"),
        AUTHORIZATION_SAFETY_MODE_ENV: _text("safety_mode"),
    }
    if not load_authorization_runtime_facts(source):
        raise ValueError("authorization runtime facts are incomplete or malformed")
    return source


def redact_authorization_value(value: Any, _seen: set[int] | None = None) -> Any:
    """Compatibility alias for the canonical WP-007 redaction policy."""
    return redact_value(value, _seen)


@dataclass(frozen=True)
class AuthorizationContext:
    """Trusted action facts used by every CLI, dashboard, agent, and module adapter."""

    tenant_id: str
    engagement_id: str
    run_id: str
    job_id: str
    operator_id: str
    operator_role: OperatorRole | str
    action_kind: str
    engine: str
    module_id: str
    requested_target: str
    resolved_target: str
    allowed_scope: Iterable[str]
    excluded_scope: Iterable[str]
    scope_policy_version: str = "scope-policy-v1"
    safety_mode: SafetyMode | str = SafetyMode.ACTIVE
    credential_approval_required: bool = False
    network_escalation_approval_required: bool = False
    high_risk_approval_required: bool = False
    confirmation_method: ConfirmationMethod | str = ConfirmationMethod.INHERITED
    confirmed_by: str = ""
    credential_reference: str = ""
    parent_decision_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_scope", tuple(self.allowed_scope))
        object.__setattr__(self, "excluded_scope", tuple(self.excluded_scope))
        object.__setattr__(self, "operator_role", OperatorRole(_enum_value(self.operator_role)))
        object.__setattr__(self, "safety_mode", SafetyMode(_enum_value(self.safety_mode)))
        object.__setattr__(
            self,
            "confirmation_method",
            ConfirmationMethod(_enum_value(self.confirmation_method)),
        )
        for field in (
            "credential_approval_required",
            "network_escalation_approval_required",
            "high_risk_approval_required",
        ):
            if type(getattr(self, field)) is not bool:
                raise ValueError(f"{field} must be boolean")


def _normalize_adapter(
    _untrusted: Mapping[str, Any] | None = None,
    **trusted: Any,
) -> AuthorizationContext:
    """Build context exclusively from trusted adapter arguments."""
    return AuthorizationContext(**trusted)


def normalize_cli_authorization(
    untrusted: Mapping[str, Any] | None = None,
    **trusted: Any,
) -> AuthorizationContext:
    return _normalize_adapter(untrusted, **trusted)


def normalize_dashboard_authorization(
    untrusted: Mapping[str, Any] | None = None,
    **trusted: Any,
) -> AuthorizationContext:
    return _normalize_adapter(untrusted, **trusted)


def normalize_agent_authorization(
    untrusted: Mapping[str, Any] | None = None,
    **trusted: Any,
) -> AuthorizationContext:
    return _normalize_adapter(untrusted, **trusted)


_ENVELOPE_FIELDS = (
    "schema_version",
    "decision_id",
    "parent_decision_id",
    "tenant_id",
    "engagement_id",
    "run_id",
    "job_id",
    "action_id",
    "operator_id",
    "operator_role",
    "action_kind",
    "engine",
    "module_id",
    "requested_target",
    "resolved_target",
    "scope_snapshot",
    "scope_policy_version",
    "scope_decision",
    "scope_reason_code",
    "scope_reason",
    "safety_mode",
    "credential_approval_required",
    "network_escalation_approval_required",
    "high_risk_approval_required",
    "credential_reference",
    "confirmation_method",
    "confirmed_by",
    "confirmed_at",
    "issued_at",
    "expires_at",
    "decision_outcome",
    "reason_code",
    "decision_reason",
    "single_use",
    "binding_digest",
)


class AuthorizationEnvelopeError(ValueError):
    """Safe envelope parsing error that never includes submitted values."""

    def __init__(self, reason_code: AuthorizationReason, field: str = "") -> None:
        self.reason_code = reason_code
        self.field = field
        super().__init__(f"{reason_code.value}: {field or 'authorization envelope'}")


def compute_envelope_digest(value: Mapping[str, Any]) -> str:
    """Compute the canonical checksum used with the immutable stored record."""
    payload = {key: item for key, item in value.items() if key != "binding_digest"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


@dataclass(frozen=True)
class ActionAuthorizationEnvelope:
    schema_version: str
    decision_id: str
    parent_decision_id: str
    tenant_id: str
    engagement_id: str
    run_id: str
    job_id: str
    action_id: str
    operator_id: str
    operator_role: str
    action_kind: str
    engine: str
    module_id: str
    requested_target: str
    resolved_target: str
    scope_snapshot: str
    scope_policy_version: str
    scope_decision: str
    scope_reason_code: str
    scope_reason: str
    safety_mode: str
    credential_approval_required: bool
    network_escalation_approval_required: bool
    high_risk_approval_required: bool
    credential_reference: str
    confirmation_method: str
    confirmed_by: str
    confirmed_at: str
    issued_at: str
    expires_at: str
    decision_outcome: str
    reason_code: str
    decision_reason: str
    single_use: bool
    binding_digest: str

    @classmethod
    def required_fields(cls) -> tuple[str, ...]:
        return _ENVELOPE_FIELDS

    @classmethod
    def from_value(
        cls,
        value: "ActionAuthorizationEnvelope | Mapping[str, Any]",
    ) -> "ActionAuthorizationEnvelope":
        if isinstance(value, cls):
            value = value.to_dict()
        if not isinstance(value, Mapping):
            raise AuthorizationEnvelopeError(AuthorizationReason.MALFORMED_FIELD)
        missing = [field for field in _ENVELOPE_FIELDS if field not in value]
        if missing:
            raise AuthorizationEnvelopeError(
                AuthorizationReason.MISSING_REQUIRED_FIELD,
                missing[0],
            )
        if set(value) != set(_ENVELOPE_FIELDS):
            raise AuthorizationEnvelopeError(AuthorizationReason.MALFORMED_FIELD)
        if value.get("schema_version") != AUTHORIZATION_SCHEMA_VERSION:
            raise AuthorizationEnvelopeError(AuthorizationReason.UNSUPPORTED_SCHEMA, "schema_version")
        for field in _ENVELOPE_FIELDS:
            if field in {
                "credential_approval_required",
                "network_escalation_approval_required",
                "high_risk_approval_required",
                "single_use",
            }:
                if type(value[field]) is not bool:
                    raise AuthorizationEnvelopeError(AuthorizationReason.MALFORMED_FIELD, field)
            elif not isinstance(value[field], str):
                raise AuthorizationEnvelopeError(AuthorizationReason.MALFORMED_FIELD, field)
        if value["single_use"] is not True:
            raise AuthorizationEnvelopeError(AuthorizationReason.MALFORMED_FIELD, "single_use")
        try:
            for field in (
                "decision_id",
                "tenant_id",
                "engagement_id",
                "run_id",
                "job_id",
                "action_id",
                "operator_id",
                "action_kind",
                "engine",
                "scope_policy_version",
                "reason_code",
            ):
                _safe_identifier(value[field], field)
            for field in ("parent_decision_id", "module_id", "confirmed_by"):
                _safe_identifier(value[field], field, allow_empty=True)
        except ValueError as exc:
            raise AuthorizationEnvelopeError(AuthorizationReason.MALFORMED_FIELD) from exc
        if value["scope_decision"] not in {"allowed", "denied"}:
            raise AuthorizationEnvelopeError(
                AuthorizationReason.MALFORMED_FIELD,
                "scope_decision",
            )
        if not value["scope_reason_code"] or not value["scope_reason"]:
            raise AuthorizationEnvelopeError(AuthorizationReason.MALFORMED_FIELD)
        if not value["decision_reason"] or len(value["decision_reason"]) > 1000:
            raise AuthorizationEnvelopeError(
                AuthorizationReason.MALFORMED_FIELD,
                "decision_reason",
            )
        for field in ("requested_target", "resolved_target", "scope_snapshot", "binding_digest"):
            if not _SHA256_REF.fullmatch(str(value[field])):
                raise AuthorizationEnvelopeError(AuthorizationReason.MALFORMED_FIELD, field)
        try:
            OperatorRole(str(value["operator_role"]))
            SafetyMode(str(value["safety_mode"]))
            ConfirmationMethod(str(value["confirmation_method"]))
            AuthorizationOutcome(str(value["decision_outcome"]))
            issued_at = _parse_timestamp(str(value["issued_at"]))
            expires_at = _parse_timestamp(str(value["expires_at"]))
            if value["confirmed_at"]:
                confirmed_at = _parse_timestamp(str(value["confirmed_at"]))
            else:
                confirmed_at = None
        except (TypeError, ValueError) as exc:
            raise AuthorizationEnvelopeError(AuthorizationReason.MALFORMED_FIELD) from exc
        if expires_at <= issued_at or (
            expires_at - issued_at
        ).total_seconds() > DEFAULT_AUTHORIZATION_TTL_SECONDS:
            raise AuthorizationEnvelopeError(AuthorizationReason.MALFORMED_FIELD, "expires_at")
        if value["decision_outcome"] == AuthorizationOutcome.ALLOW.value:
            if (
                value["scope_decision"] != "allowed"
                or not value["confirmed_by"]
                or confirmed_at is None
                or value["confirmation_method"] == ConfirmationMethod.NONE.value
            ):
                raise AuthorizationEnvelopeError(AuthorizationReason.MALFORMED_FIELD)
        expected_digest = compute_envelope_digest(value)
        if not hmac.compare_digest(str(value["binding_digest"]), expected_digest):
            raise AuthorizationEnvelopeError(AuthorizationReason.INTEGRITY_MISMATCH, "binding_digest")
        if value["credential_reference"] and not str(value["credential_reference"]).startswith("cred:"):
            raise AuthorizationEnvelopeError(
                AuthorizationReason.MALFORMED_FIELD,
                "credential_reference",
            )
        return cls(**{field: value[field] for field in _ENVELOPE_FIELDS})

    def to_dict(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in _ENVELOPE_FIELDS}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def to_event_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "decision_id": self.decision_id,
            "action_id": self.action_id,
            "job_id": self.job_id,
            "tenant_id": self.tenant_id,
            "engine": self.engine,
            "module_id": self.module_id,
            "requested_target": self.requested_target,
            "resolved_target": self.resolved_target,
            "decision_outcome": self.decision_outcome,
            "reason_code": self.reason_code,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason_code: str
    reason: str
    envelope: ActionAuthorizationEnvelope
    audit_decision_id: str

    def __str__(self) -> str:
        return (
            f"AuthorizationDecision(allowed={self.allowed}, "
            f"reason_code={self.reason_code}, decision_id={self.audit_decision_id})"
        )


class AuthorizationPersistenceError(RuntimeError):
    """Raised when the immutable audit cannot be persisted before execution."""

    def __init__(self) -> None:
        super().__init__(_reason_message(AuthorizationReason.AUDIT_PERSISTENCE_FAILED.value))


def _validated_context(context: AuthorizationContext) -> AuthorizationContext:
    values = {
        "tenant_id": _safe_identifier(context.tenant_id, "tenant_id"),
        "engagement_id": _safe_identifier(context.engagement_id, "engagement_id"),
        "run_id": _safe_identifier(context.run_id, "run_id"),
        "job_id": _safe_identifier(context.job_id, "job_id"),
        "operator_id": _safe_identifier(context.operator_id, "operator_id"),
        "action_kind": _safe_identifier(context.action_kind, "action_kind").lower(),
        "engine": _safe_identifier(context.engine, "engine").lower(),
        "module_id": _safe_identifier(context.module_id, "module_id", allow_empty=True).lower(),
        "scope_policy_version": _safe_identifier(
            context.scope_policy_version,
            "scope_policy_version",
        ),
        "confirmed_by": _safe_identifier(
            context.confirmed_by,
            "confirmed_by",
            allow_empty=True,
        ),
        "parent_decision_id": _safe_identifier(
            context.parent_decision_id,
            "parent_decision_id",
            allow_empty=True,
        ),
    }
    credential_reference = context.credential_reference.strip()
    if credential_reference and (
        not credential_reference.startswith("cred:")
        or len(credential_reference) > 300
        or any(char.isspace() for char in credential_reference)
    ):
        raise ValueError("credential_reference must be an opaque protected reference")
    return replace(
        context,
        credential_reference=credential_reference,
        **cast(Any, values),
    )


def _build_envelope(
    context: AuthorizationContext,
    *,
    scope_allowed: bool,
    scope_reason_code: str,
    scope_reason: str,
    outcome: AuthorizationOutcome,
    reason_code: str,
    reason: str,
    now: datetime,
    ttl_seconds: int,
    confirmed_at: str,
    decision_id: str | None = None,
    action_id: str | None = None,
) -> ActionAuthorizationEnvelope:
    context = _validated_context(context)
    issued_at = _utc(now)
    if type(ttl_seconds) is not int or ttl_seconds <= 0 or ttl_seconds > DEFAULT_AUTHORIZATION_TTL_SECONDS:
        raise ValueError("authorization ttl is invalid")
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    if outcome is AuthorizationOutcome.ALLOW:
        # The envelope must never outlive the operator acknowledgement that
        # authorized it.  Otherwise issuing near the end of the confirmation
        # window silently resets that window for another full envelope TTL.
        confirmation_expires_at = _parse_timestamp(confirmed_at) + timedelta(
            seconds=DEFAULT_CONFIRMATION_MAX_AGE_SECONDS
        )
        expires_at = min(expires_at, confirmation_expires_at)
    values: dict[str, Any] = {
        "schema_version": AUTHORIZATION_SCHEMA_VERSION,
        "decision_id": decision_id or f"authz-{uuid.uuid4().hex}",
        "parent_decision_id": context.parent_decision_id,
        "tenant_id": context.tenant_id,
        "engagement_id": context.engagement_id,
        "run_id": context.run_id,
        "job_id": context.job_id,
        "action_id": action_id or f"action-{uuid.uuid4().hex}",
        "operator_id": context.operator_id,
        "operator_role": _enum_value(context.operator_role),
        "action_kind": context.action_kind,
        "engine": context.engine,
        "module_id": context.module_id,
        "requested_target": _safe_target_for_binding(context.requested_target),
        "resolved_target": _safe_target_for_binding(context.resolved_target),
        "scope_snapshot": _scope_snapshot(context.allowed_scope, context.excluded_scope),
        "scope_policy_version": context.scope_policy_version,
        "scope_decision": "allowed" if scope_allowed else "denied",
        "scope_reason_code": scope_reason_code,
        "scope_reason": scope_reason,
        "safety_mode": _enum_value(context.safety_mode),
        "credential_approval_required": context.credential_approval_required,
        "network_escalation_approval_required": context.network_escalation_approval_required,
        "high_risk_approval_required": context.high_risk_approval_required,
        "credential_reference": context.credential_reference,
        "confirmation_method": _enum_value(context.confirmation_method),
        "confirmed_by": context.confirmed_by if outcome is AuthorizationOutcome.ALLOW else "",
        "confirmed_at": confirmed_at if outcome is AuthorizationOutcome.ALLOW else "",
        "issued_at": _timestamp(issued_at),
        "expires_at": _timestamp(expires_at),
        "decision_outcome": outcome.value,
        "reason_code": reason_code,
        "decision_reason": reason,
        "single_use": True,
    }
    values["binding_digest"] = compute_envelope_digest(values)
    return ActionAuthorizationEnvelope.from_value(values)


def _decision_record(
    envelope: ActionAuthorizationEnvelope,
    detail: Mapping[str, Any] | None,
    now: datetime,
    *,
    confirmation_digest: str = "",
) -> dict[str, Any]:
    return {
        **envelope.to_dict(),
        "confirmation_digest": confirmation_digest,
        "envelope_json": envelope.to_json(),
        "detail": redact_authorization_value(dict(detail or {})),
        "recorded_at": _timestamp(now),
    }


def _append_decision(
    session: Session,
    envelope: ActionAuthorizationEnvelope,
    *,
    detail: Mapping[str, Any] | None,
    now: datetime,
    commit: bool = True,
    confirmation_digest: str = "",
) -> None:
    try:
        append_authorization_decision(
            session,
            _decision_record(
                envelope,
                detail,
                now,
                confirmation_digest=confirmation_digest,
            ),
            commit=commit,
        )
    except Exception as exc:
        session.rollback()
        log.error(
            "Authorization audit persistence failed reason=%s",
            type(exc).__name__,
        )
        raise AuthorizationPersistenceError() from exc


def issue_authorization(
    *,
    session: Session,
    context: AuthorizationContext,
    confirmation: ActionConfirmation | Mapping[str, Any] | None,
    now: datetime | None = None,
    ttl_seconds: int = DEFAULT_AUTHORIZATION_TTL_SECONDS,
    detail: Mapping[str, Any] | None = None,
    commit: bool = True,
) -> AuthorizationDecision:
    """Evaluate WP001 scope/confirmation and persist one immutable decision."""
    current = datetime.now(timezone.utc) if now is None else _utc(now)
    context = _validated_context(context)
    scope_decision = decide_action(
        target=context.resolved_target,
        allowed_scope=context.allowed_scope,
        excluded_scope=context.excluded_scope,
        confirmation=confirmation,
        job_id=context.job_id,
        engine=context.engine,
        action=context.action_kind,
        now=current,
        require_confirmation=True,
    )
    allowed = bool(scope_decision.allowed)
    outcome = AuthorizationOutcome.ALLOW if allowed else AuthorizationOutcome.DENY
    confirmed_at = ""
    confirmation_digest = ""
    if allowed:
        confirmation_record = ActionConfirmation.from_value(confirmation)  # type: ignore[arg-type]
        confirmed_at = confirmation_record.issued_at
        confirmation_digest = confirmation_record.binding_digest
    reason_code = AuthorizationReason.ALLOWED.value if allowed else scope_decision.reason_code
    reason = _reason_message(reason_code) if allowed else scope_decision.reason
    envelope = _build_envelope(
        context,
        scope_allowed=scope_decision.allowed,
        scope_reason_code=scope_decision.reason_code,
        scope_reason=scope_decision.reason,
        outcome=outcome,
        reason_code=reason_code,
        reason=reason,
        now=current,
        ttl_seconds=ttl_seconds,
        confirmed_at=confirmed_at,
    )
    try:
        _append_decision(
            session,
            envelope,
            detail=detail,
            now=current,
            commit=commit,
            confirmation_digest=confirmation_digest,
        )
    except AuthorizationPersistenceError as exc:
        if confirmation_digest and isinstance(exc.__cause__, IntegrityError):
            return _record_denial(
                session,
                context,
                AuthorizationReason.REPLAYED,
                now=current,
                commit=commit,
            )
        raise
    return AuthorizationDecision(
        allowed=allowed,
        reason_code=reason_code,
        reason=reason,
        envelope=envelope,
        audit_decision_id=envelope.decision_id,
    )


def _record_denial(
    session: Session,
    context: AuthorizationContext,
    reason_code: AuthorizationReason | str,
    *,
    now: datetime,
    field: str = "",
    outcome: AuthorizationOutcome = AuthorizationOutcome.DENY,
    parent_decision_id: str = "",
    commit: bool = True,
) -> AuthorizationDecision:
    code = _enum_value(reason_code)
    context = replace(context, parent_decision_id=parent_decision_id or context.parent_decision_id)
    scope = decide_scope(context.resolved_target, context.allowed_scope, context.excluded_scope)
    envelope = _build_envelope(
        context,
        scope_allowed=scope.allowed,
        scope_reason_code=scope.reason_code,
        scope_reason=scope.reason,
        outcome=outcome,
        reason_code=code,
        reason=_reason_message(code),
        now=now,
        ttl_seconds=DEFAULT_AUTHORIZATION_TTL_SECONDS,
        confirmed_at="",
    )
    detail = {"field": field} if field else {}
    _append_decision(session, envelope, detail=detail, now=now, commit=commit)
    return AuthorizationDecision(
        allowed=False,
        reason_code=code,
        reason=_reason_message(code),
        envelope=envelope,
        audit_decision_id=envelope.decision_id,
    )


def record_authorization_denial(
    *,
    session: Session,
    context: AuthorizationContext,
    reason_code: AuthorizationReason | str,
    now: datetime | None = None,
    field: str = "",
    outcome: AuthorizationOutcome = AuthorizationOutcome.DENY,
    parent_decision_id: str = "",
) -> AuthorizationDecision:
    """Persist a safe denial generated by a trusted boundary capability check."""
    current = datetime.now(timezone.utc) if now is None else _utc(now)
    return _record_denial(
        session,
        context,
        reason_code,
        now=current,
        field=field,
        outcome=outcome,
        parent_decision_id=parent_decision_id,
    )


def _audit_safe_identifier(value: Any, prefix: str) -> str:
    raw = value.strip() if isinstance(value, str) else ""
    if raw:
        try:
            return _safe_identifier(raw, prefix)
        except ValueError:
            pass
    digest = hashlib.sha256(
        str(value).encode("utf-8", "replace")
    ).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _audit_scope_values(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        items = list(value)[:1000]
        if not all(isinstance(item, str) for item in items):
            return ("*",)
        return tuple(items)
    return ()


def record_boundary_denial(
    *,
    session: Session,
    reason_code: AuthorizationReason | str,
    action_kind: Any,
    engine: Any,
    target: Any,
    allowed_scope: Any,
    excluded_scope: Any = (),
    tenant_id: Any = "default",
    engagement_id: Any = "preflight",
    run_id: Any = "preflight-run",
    job_id: Any = "preflight-job",
    operator_id: Any = "unknown-operator",
    operator_role: OperatorRole | str = OperatorRole.SYSTEM,
    module_id: Any = "",
    scope_policy_version: Any = "scope-policy-v1",
    safety_mode: SafetyMode | str = SafetyMode.ACTIVE,
    credential_reference: str = "",
    network_escalation_approval_required: bool = False,
    high_risk_approval_required: bool = False,
) -> AuthorizationDecision:
    """Persist an early denial even when submitted action fields are malformed.

    Raw malformed identifiers are replaced by stable opaque digests, and target
    values continue through the envelope's opaque target binding.  Callers must
    allow persistence failures to propagate so an audit outage stays fail-closed.
    """
    try:
        role = OperatorRole(_enum_value(operator_role))
    except ValueError:
        role = OperatorRole.SYSTEM
    try:
        mode = SafetyMode(_enum_value(safety_mode))
    except ValueError:
        mode = SafetyMode.ACTIVE
    target_value = target.strip() if isinstance(target, str) and target.strip() else "invalid-target"
    context = AuthorizationContext(
        tenant_id=_audit_safe_identifier(tenant_id, "tenant"),
        engagement_id=_audit_safe_identifier(engagement_id, "engagement"),
        run_id=_audit_safe_identifier(run_id, "run"),
        job_id=_audit_safe_identifier(job_id, "job"),
        operator_id=_audit_safe_identifier(operator_id, "operator"),
        operator_role=role,
        action_kind=_audit_safe_identifier(action_kind, "action"),
        engine=_audit_safe_identifier(engine, "engine"),
        module_id=(
            ""
            if module_id in (None, "")
            else _audit_safe_identifier(module_id, "module")
        ),
        requested_target=target_value,
        resolved_target=target_value,
        allowed_scope=_audit_scope_values(allowed_scope),
        excluded_scope=_audit_scope_values(excluded_scope),
        scope_policy_version=_audit_safe_identifier(
            scope_policy_version,
            "policy",
        ),
        safety_mode=mode,
        credential_approval_required=bool(credential_reference),
        network_escalation_approval_required=bool(
            network_escalation_approval_required
        ),
        high_risk_approval_required=bool(high_risk_approval_required),
        credential_reference=credential_reference,
        confirmation_method=ConfirmationMethod.NONE,
    )
    return record_authorization_denial(
        session=session,
        context=context,
        reason_code=reason_code,
    )


def _binding_mismatch(
    envelope: ActionAuthorizationEnvelope,
    expected: AuthorizationContext,
) -> AuthorizationReason | None:
    expected = _validated_context(expected)
    comparisons: tuple[tuple[bool, AuthorizationReason], ...] = (
        (envelope.tenant_id == expected.tenant_id, AuthorizationReason.TENANT_MISMATCH),
        (
            envelope.engagement_id == expected.engagement_id,
            AuthorizationReason.ENGAGEMENT_MISMATCH,
        ),
        (envelope.run_id == expected.run_id, AuthorizationReason.RUN_MISMATCH),
        (envelope.job_id == expected.job_id, AuthorizationReason.JOB_MISMATCH),
        (envelope.operator_id == expected.operator_id, AuthorizationReason.OPERATOR_MISMATCH),
        (envelope.operator_role == _enum_value(expected.operator_role), AuthorizationReason.ROLE_MISMATCH),
        (envelope.engine == expected.engine, AuthorizationReason.ENGINE_MISMATCH),
        (envelope.module_id == expected.module_id, AuthorizationReason.MODULE_MISMATCH),
        (envelope.action_kind == expected.action_kind, AuthorizationReason.ACTION_MISMATCH),
        (
            envelope.requested_target == _safe_target_for_binding(expected.requested_target),
            AuthorizationReason.REQUESTED_TARGET_MISMATCH,
        ),
        (
            envelope.resolved_target == _safe_target_for_binding(expected.resolved_target),
            AuthorizationReason.RESOLVED_TARGET_MISMATCH,
        ),
        (
            envelope.scope_snapshot
            == _scope_snapshot(expected.allowed_scope, expected.excluded_scope)
            and envelope.scope_policy_version == expected.scope_policy_version,
            AuthorizationReason.SCOPE_POLICY_MISMATCH,
        ),
        (envelope.safety_mode == _enum_value(expected.safety_mode), AuthorizationReason.SAFETY_MODE_MISMATCH),
        (
            envelope.credential_approval_required == expected.credential_approval_required
            and envelope.network_escalation_approval_required
            == expected.network_escalation_approval_required
            and envelope.high_risk_approval_required == expected.high_risk_approval_required
            and envelope.credential_reference == expected.credential_reference,
            AuthorizationReason.APPROVAL_MISMATCH,
        ),
        (
            envelope.confirmation_method
            == _enum_value(expected.confirmation_method)
            and envelope.confirmed_by == expected.confirmed_by,
            AuthorizationReason.APPROVAL_MISMATCH,
        ),
    )
    for matches, reason in comparisons:
        if not matches:
            return reason
    return None


def consume_authorization(
    *,
    session: Session,
    envelope: ActionAuthorizationEnvelope | Mapping[str, Any] | None,
    expected: AuthorizationContext,
    boundary: str,
    now: datetime | None = None,
    commit: bool = True,
) -> AuthorizationDecision:
    """Validate the stored envelope and atomically consume its one allowed use."""
    current = datetime.now(timezone.utc) if now is None else _utc(now)
    expected = _validated_context(expected)
    boundary_value = _safe_identifier(boundary, "boundary")
    if envelope is None:
        return _record_denial(
            session,
            expected,
            AuthorizationReason.LEGACY_NOT_AUTHORIZED,
            now=current,
            outcome=AuthorizationOutcome.UNKNOWN_NOT_AUTHORIZED,
            commit=commit,
        )
    try:
        record = ActionAuthorizationEnvelope.from_value(envelope)
    except AuthorizationEnvelopeError as exc:
        return _record_denial(
            session,
            expected,
            exc.reason_code,
            now=current,
            field=exc.field,
            commit=commit,
        )

    stored = get_authorization_decision(session, record.decision_id)
    if stored is None:
        return _record_denial(
            session,
            expected,
            AuthorizationReason.UNRECORDED_DECISION,
            now=current,
            parent_decision_id=record.decision_id,
            commit=commit,
        )
    if not hmac.compare_digest(str(stored.binding_digest), record.binding_digest):
        return _record_denial(
            session,
            expected,
            AuthorizationReason.INTEGRITY_MISMATCH,
            now=current,
            parent_decision_id=record.decision_id,
            commit=commit,
        )
    canonical_stored = str(stored.envelope_json)
    if not hmac.compare_digest(canonical_stored, record.to_json()):
        return _record_denial(
            session,
            expected,
            AuthorizationReason.INTEGRITY_MISMATCH,
            now=current,
            parent_decision_id=record.decision_id,
            commit=commit,
        )
    if record.decision_outcome != AuthorizationOutcome.ALLOW.value:
        return AuthorizationDecision(
            allowed=False,
            reason_code=record.reason_code,
            reason=record.decision_reason,
            envelope=record,
            audit_decision_id=record.decision_id,
        )

    mismatch = _binding_mismatch(record, expected)
    if mismatch is not None:
        return _record_denial(
            session,
            expected,
            mismatch,
            now=current,
            parent_decision_id=record.decision_id,
            commit=commit,
        )
    issued_at = _parse_timestamp(record.issued_at)
    expires_at = _parse_timestamp(record.expires_at)
    if current < issued_at - timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
        return _record_denial(
            session,
            expected,
            AuthorizationReason.FUTURE_ISSUED,
            now=current,
            parent_decision_id=record.decision_id,
            commit=commit,
        )
    if current > expires_at:
        return _record_denial(
            session,
            expected,
            AuthorizationReason.EXPIRED,
            now=current,
            parent_decision_id=record.decision_id,
            commit=commit,
        )

    existing = get_authorization_consumption(session, record.decision_id)
    if existing is not None:
        reason = (
            AuthorizationReason.ALREADY_CONSUMED
            if existing.boundary == boundary_value
            else AuthorizationReason.REPLAYED
        )
        return _record_denial(
            session,
            expected,
            reason,
            now=current,
            parent_decision_id=record.decision_id,
            commit=commit,
        )
    try:
        append_authorization_consumption(
            session,
            {
                "consumption_id": f"consume-{uuid.uuid4().hex}",
                "decision_id": record.decision_id,
                "tenant_id": record.tenant_id,
                "job_id": record.job_id,
                "action_id": record.action_id,
                "boundary": boundary_value,
                "result_id": record.action_id,
                "envelope_digest": record.binding_digest,
                "consumed_at": _timestamp(current),
            },
            commit=commit,
        )
    except IntegrityError:
        session.rollback()
        return _record_denial(
            session,
            expected,
            AuthorizationReason.REPLAYED,
            now=current,
            parent_decision_id=record.decision_id,
            commit=commit,
        )
    except Exception as exc:
        session.rollback()
        log.error("Authorization consumption persistence failed reason=%s", type(exc).__name__)
        raise AuthorizationPersistenceError() from exc
    return AuthorizationDecision(
        allowed=True,
        reason_code=AuthorizationReason.ALLOWED.value,
        reason=_reason_message(AuthorizationReason.ALLOWED.value),
        envelope=record,
        audit_decision_id=record.decision_id,
    )


def validate_consumed_authorization(
    *,
    session: Session,
    envelope: ActionAuthorizationEnvelope | Mapping[str, Any] | None,
    expected: AuthorizationContext,
    boundary: str,
    now: datetime | None = None,
) -> AuthorizationDecision:
    """Verify an exact, previously consumed capability without consuming it again.

    This is for an in-process handoff after a boundary has already atomically
    consumed the envelope (for example, WebForge preflight to its scan loop).
    It is deliberately distinct from replaying ``consume_authorization``.
    """
    current = datetime.now(timezone.utc) if now is None else _utc(now)
    expected = _validated_context(expected)
    boundary_value = _safe_identifier(boundary, "boundary")
    if envelope is None:
        return _record_denial(
            session,
            expected,
            AuthorizationReason.LEGACY_NOT_AUTHORIZED,
            now=current,
            outcome=AuthorizationOutcome.UNKNOWN_NOT_AUTHORIZED,
        )
    try:
        record = ActionAuthorizationEnvelope.from_value(envelope)
    except AuthorizationEnvelopeError as exc:
        return _record_denial(
            session,
            expected,
            exc.reason_code,
            now=current,
            field=exc.field,
        )

    stored = get_authorization_decision(session, record.decision_id)
    if stored is None:
        return _record_denial(
            session,
            expected,
            AuthorizationReason.UNRECORDED_DECISION,
            now=current,
            parent_decision_id=record.decision_id,
        )
    if (
        not hmac.compare_digest(str(stored.binding_digest), record.binding_digest)
        or not hmac.compare_digest(str(stored.envelope_json), record.to_json())
    ):
        return _record_denial(
            session,
            expected,
            AuthorizationReason.INTEGRITY_MISMATCH,
            now=current,
            parent_decision_id=record.decision_id,
        )
    if record.decision_outcome != AuthorizationOutcome.ALLOW.value:
        return AuthorizationDecision(
            allowed=False,
            reason_code=record.reason_code,
            reason=record.decision_reason,
            envelope=record,
            audit_decision_id=record.decision_id,
        )

    mismatch = _binding_mismatch(record, expected)
    if mismatch is not None:
        return _record_denial(
            session,
            expected,
            mismatch,
            now=current,
            parent_decision_id=record.decision_id,
        )
    issued_at = _parse_timestamp(record.issued_at)
    expires_at = _parse_timestamp(record.expires_at)
    if current < issued_at - timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
        return _record_denial(
            session,
            expected,
            AuthorizationReason.FUTURE_ISSUED,
            now=current,
            parent_decision_id=record.decision_id,
        )
    if current > expires_at:
        return _record_denial(
            session,
            expected,
            AuthorizationReason.EXPIRED,
            now=current,
            parent_decision_id=record.decision_id,
        )

    consumed = get_authorization_consumption(session, record.decision_id)
    if consumed is None:
        return _record_denial(
            session,
            expected,
            AuthorizationReason.NOT_CONSUMED,
            now=current,
            parent_decision_id=record.decision_id,
        )
    if (
        str(consumed.boundary) != boundary_value
        or str(consumed.tenant_id) != record.tenant_id
        or str(consumed.job_id) != record.job_id
        or str(consumed.action_id) != record.action_id
        or not hmac.compare_digest(
            str(consumed.envelope_digest),
            record.binding_digest,
        )
    ):
        return _record_denial(
            session,
            expected,
            AuthorizationReason.INTEGRITY_MISMATCH,
            now=current,
            parent_decision_id=record.decision_id,
        )
    return AuthorizationDecision(
        allowed=True,
        reason_code=AuthorizationReason.ALLOWED.value,
        reason=_reason_message(AuthorizationReason.ALLOWED.value),
        envelope=record,
        audit_decision_id=record.decision_id,
    )


def claim_consumed_authorization_execution(
    *,
    session: Session,
    envelope: ActionAuthorizationEnvelope | Mapping[str, Any] | None,
    expected: AuthorizationContext,
    boundary: str,
    now: datetime | None = None,
) -> AuthorizationDecision:
    """Atomically claim the sole execution permitted by a consumed action.

    Consumption authorizes the boundary handoff.  This separate append-only
    claim binds that handoff to one actual invocation, so reconstruction,
    duplicate delivery, concurrent calls, and process restart cannot execute
    the same decision/action again.
    """
    current = datetime.now(timezone.utc) if now is None else _utc(now)
    expected = _validated_context(expected)
    boundary_value = _safe_identifier(boundary, "boundary")
    verified = validate_consumed_authorization(
        session=session,
        envelope=envelope,
        expected=expected,
        boundary=boundary_value,
        now=current,
    )
    if not verified.allowed:
        return verified

    record = verified.envelope
    existing = get_authorization_execution_claim(session, record.decision_id)
    if existing is not None:
        exact_existing = (
            str(existing.tenant_id) == record.tenant_id
            and str(existing.job_id) == record.job_id
            and str(existing.action_id) == record.action_id
            and str(existing.boundary) == boundary_value
            and hmac.compare_digest(
                str(existing.envelope_digest),
                record.binding_digest,
            )
        )
        return _record_denial(
            session,
            expected,
            (
                AuthorizationReason.ALREADY_CONSUMED
                if exact_existing
                else AuthorizationReason.INTEGRITY_MISMATCH
            ),
            now=current,
            parent_decision_id=record.decision_id,
        )

    try:
        append_authorization_execution_claim(
            session,
            {
                "claim_id": f"execute-{uuid.uuid4().hex}",
                "decision_id": record.decision_id,
                "tenant_id": record.tenant_id,
                "job_id": record.job_id,
                "action_id": record.action_id,
                "boundary": boundary_value,
                "envelope_digest": record.binding_digest,
                "claimed_at": _timestamp(current),
            },
        )
    except IntegrityError:
        session.rollback()
        return _record_denial(
            session,
            expected,
            AuthorizationReason.REPLAYED,
            now=current,
            parent_decision_id=record.decision_id,
        )
    except Exception as exc:
        session.rollback()
        log.error(
            "Authorization execution claim persistence failed reason=%s",
            type(exc).__name__,
        )
        raise AuthorizationPersistenceError() from exc
    return verified


def derive_authorization(
    *,
    session: Session,
    parent_envelope: ActionAuthorizationEnvelope | Mapping[str, Any],
    context: AuthorizationContext,
    parent_boundary: str,
    now: datetime | None = None,
    ttl_seconds: int = DEFAULT_AUTHORIZATION_TTL_SECONDS,
    commit: bool = True,
) -> AuthorizationDecision:
    """Issue a child action only from an already consumed parent decision.

    ``parent_boundary`` names the exact trusted boundary that must have
    consumed the parent.  Merely finding any consumption record is not enough:
    accepting a parent consumed by another component would let that component
    mint capabilities outside its handoff path.

    ``commit=False`` lets a caller stage the child (including any denial
    record) inside a larger authorization transaction and decide atomically
    whether the whole batch is durable.
    """
    current = datetime.now(timezone.utc) if now is None else _utc(now)
    context = _validated_context(context)
    parent_boundary_value = _safe_identifier(parent_boundary, "parent_boundary")
    try:
        parent = ActionAuthorizationEnvelope.from_value(parent_envelope)
    except AuthorizationEnvelopeError:
        return _record_denial(
            session,
            context,
            AuthorizationReason.PARENT_NOT_AUTHORIZED,
            now=current,
            commit=commit,
        )
    stored = get_authorization_decision(session, parent.decision_id)
    consumed = get_authorization_consumption(session, parent.decision_id)
    if (
        stored is None
        or consumed is None
        or parent.decision_outcome != AuthorizationOutcome.ALLOW.value
        or not hmac.compare_digest(str(stored.binding_digest), parent.binding_digest)
        or not hmac.compare_digest(str(stored.envelope_json), parent.to_json())
        or not hmac.compare_digest(
            str(consumed.envelope_digest),
            parent.binding_digest,
        )
        or str(consumed.boundary) != parent_boundary_value
        or str(consumed.tenant_id) != parent.tenant_id
        or str(consumed.job_id) != parent.job_id
        or str(consumed.action_id) != parent.action_id
    ):
        return _record_denial(
            session,
            context,
            AuthorizationReason.PARENT_NOT_AUTHORIZED,
            now=current,
            parent_decision_id=parent.decision_id,
            commit=commit,
        )
    parent_issued_at = _parse_timestamp(parent.issued_at)
    parent_expires_at = _parse_timestamp(parent.expires_at)
    if current < parent_issued_at - timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
        return _record_denial(
            session,
            context,
            AuthorizationReason.FUTURE_ISSUED,
            now=current,
            parent_decision_id=parent.decision_id,
            commit=commit,
        )
    if current > parent_expires_at:
        return _record_denial(
            session,
            context,
            AuthorizationReason.EXPIRED,
            now=current,
            parent_decision_id=parent.decision_id,
            commit=commit,
        )

    allowed_transitions = {
        "scan": {"engine.execute", "agent.execute"},
        "retest": {"engine.execute"},
        "web_to_network": {"engine.execute"},
        "agent.execute": {"engine.execute"},
        "engine.execute": {"module.execute"},
        "module.execute": {"outbound.insecure_tls"},
    }
    if context.action_kind not in allowed_transitions.get(parent.action_kind, set()):
        return _record_denial(
            session,
            context,
            AuthorizationReason.PARENT_NOT_AUTHORIZED,
            now=current,
            parent_decision_id=parent.decision_id,
            commit=commit,
        )
    if context.action_kind == "module.execute" and not context.module_id:
        return _record_denial(
            session,
            context,
            AuthorizationReason.PARENT_NOT_AUTHORIZED,
            now=current,
            parent_decision_id=parent.decision_id,
            commit=commit,
        )
    if context.confirmed_by != parent.confirmed_by:
        return _record_denial(
            session,
            context,
            AuthorizationReason.PARENT_NOT_AUTHORIZED,
            now=current,
            parent_decision_id=parent.decision_id,
            commit=commit,
        )
    if (
        parent.action_kind != "engine.execute"
        and parent.module_id != context.module_id
    ):
        return _record_denial(
            session,
            context,
            AuthorizationReason.PARENT_NOT_AUTHORIZED,
            now=current,
            parent_decision_id=parent.decision_id,
            commit=commit,
        )
    # An exact module binding can be checked centrally.  Module-set bindings
    # carry a normalized set digest and are additionally checked by the
    # adapter's module plan validator; an empty/default binding remains a
    # deliberately conservative compatibility path until each engine exposes
    # its expanded default plan.
    if (
        context.action_kind == "module.execute"
        and parent.action_kind == "engine.execute"
        and parent.module_id
        and not parent.module_id.startswith("module-set-")
        and parent.module_id != context.module_id
    ):
        return _record_denial(
            session,
            context,
            AuthorizationReason.PARENT_NOT_AUTHORIZED,
            now=current,
            parent_decision_id=parent.decision_id,
            commit=commit,
        )

    for actual, expected_value in (
        (parent.tenant_id, context.tenant_id),
        (parent.engagement_id, context.engagement_id),
        (parent.run_id, context.run_id),
        (parent.job_id, context.job_id),
        (parent.operator_id, context.operator_id),
        (parent.operator_role, _enum_value(context.operator_role)),
        (parent.engine, context.engine),
        (parent.requested_target, _safe_target_for_binding(context.requested_target)),
        (parent.resolved_target, _safe_target_for_binding(context.resolved_target)),
        (
            parent.scope_snapshot,
            _scope_snapshot(context.allowed_scope, context.excluded_scope),
        ),
        (parent.scope_policy_version, context.scope_policy_version),
        (parent.safety_mode, _enum_value(context.safety_mode)),
        (
            parent.credential_approval_required,
            context.credential_approval_required,
        ),
        (
            parent.network_escalation_approval_required,
            context.network_escalation_approval_required,
        ),
        (parent.high_risk_approval_required, context.high_risk_approval_required),
        (parent.credential_reference, context.credential_reference),
    ):
        if actual != expected_value:
            return _record_denial(
                session,
                context,
                AuthorizationReason.PARENT_NOT_AUTHORIZED,
                now=current,
                parent_decision_id=parent.decision_id,
                commit=commit,
            )
    scope = decide_scope(context.resolved_target, context.allowed_scope, context.excluded_scope)
    if not scope.allowed:
        return _record_denial(
            session,
            context,
            scope.reason_code,
            now=current,
            parent_decision_id=parent.decision_id,
            commit=commit,
        )
    if get_authorization_child_decision(
        session,
        parent.decision_id,
        context.action_kind,
        context.module_id,
    ) is not None:
        return _record_denial(
            session,
            context,
            AuthorizationReason.ALREADY_DERIVED,
            now=current,
            parent_decision_id=parent.decision_id,
            commit=commit,
        )
    child_context = replace(
        context,
        parent_decision_id=parent.decision_id,
        confirmation_method=ConfirmationMethod.INHERITED,
        confirmed_by=parent.confirmed_by,
    )
    remaining_seconds = int((parent_expires_at - current).total_seconds())
    if remaining_seconds <= 0:
        return _record_denial(
            session,
            context,
            AuthorizationReason.EXPIRED,
            now=current,
            parent_decision_id=parent.decision_id,
            commit=commit,
        )
    child_ttl_seconds = min(ttl_seconds, remaining_seconds)
    envelope = _build_envelope(
        child_context,
        scope_allowed=True,
        scope_reason_code=scope.reason_code,
        scope_reason=scope.reason,
        outcome=AuthorizationOutcome.ALLOW,
        reason_code=AuthorizationReason.ALLOWED.value,
        reason=_reason_message(AuthorizationReason.ALLOWED.value),
        now=current,
        ttl_seconds=child_ttl_seconds,
        confirmed_at=parent.confirmed_at or parent.issued_at,
    )
    _append_decision(
        session,
        envelope,
        detail={"derived": True},
        now=current,
        commit=commit,
    )
    return AuthorizationDecision(
        allowed=True,
        reason_code=AuthorizationReason.ALLOWED.value,
        reason=_reason_message(AuthorizationReason.ALLOWED.value),
        envelope=envelope,
        audit_decision_id=envelope.decision_id,
    )


T = TypeVar("T")


def execute_authorized(
    *,
    session: Session,
    envelope: ActionAuthorizationEnvelope | Mapping[str, Any] | None,
    expected: AuthorizationContext,
    boundary: str,
    executor: Callable[[str], T],
    now: datetime | None = None,
) -> tuple[AuthorizationDecision, T | None]:
    """Consume authorization before invoking a synchronous execution boundary."""
    decision = consume_authorization(
        session=session,
        envelope=envelope,
        expected=expected,
        boundary=boundary,
        now=now,
    )
    if not decision.allowed:
        return decision, None
    return decision, executor(decision.envelope.action_id)


def authorize_and_link_scan_job(
    *,
    session: Session,
    context: AuthorizationContext,
    confirmation: ActionConfirmation | Mapping[str, Any] | None,
    boundary: str,
    job_record: Mapping[str, Any],
    now: datetime | None = None,
) -> AuthorizationDecision:
    """Atomically persist, consume, and link one authorization to a scan job."""
    current = datetime.now(timezone.utc) if now is None else _utc(now)
    try:
        issued = issue_authorization(
            session=session,
            context=context,
            confirmation=confirmation,
            now=current,
            commit=False,
        )
        if not issued.allowed:
            session.commit()
            return issued
        consumed = consume_authorization(
            session=session,
            envelope=issued.envelope,
            expected=context,
            boundary=boundary,
            now=current,
            commit=False,
        )
        if not consumed.allowed:
            session.commit()
            return consumed
        persisted_job = dict(job_record)
        persisted_job["id"] = context.job_id
        persisted_job["tenant_id"] = context.tenant_id
        persisted_job["authorization_state"] = AuthorizationOutcome.ALLOW.value
        persisted_job["authorization_decision_id"] = issued.envelope.decision_id
        persisted_job["authorization_action_id"] = issued.envelope.action_id
        # This pre-Task-101 handoff row is deliberately explicit legacy
        # compatibility.  Canonical job/finding adapters must provide the
        # complete tenant/engagement/module/asset context instead.
        save_scan_job(
            session,
            persisted_job,
            commit=False,
            # Authorization alone does not supply the canonical job/module /
            # asset lineage.  Refuse an orphan compatibility row until the
            # durable job adapter owns this handoff.
            allow_legacy_compat=False,
        )
        session.commit()
        return consumed
    except Exception:
        session.rollback()
        raise


def encode_authorization_envelopes(
    envelopes: Iterable[ActionAuthorizationEnvelope],
) -> str:
    values = [ActionAuthorizationEnvelope.from_value(value).to_dict() for value in envelopes]
    return json.dumps(
        {
            "schema_version": AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
            "authorizations": values,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def load_authorization_envelopes(
    environ: Mapping[str, str] | None = None,
) -> list[ActionAuthorizationEnvelope]:
    source = os.environ if environ is None else environ
    raw = source.get(AUTHORIZATION_ENVELOPES_ENV, "")
    if not raw:
        return []
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            return []
        if payload.get("schema_version") != AUTHORIZATION_CONTEXT_SCHEMA_VERSION:
            return []
        values = payload.get("authorizations")
        if not isinstance(values, list) or len(values) > 1000:
            return []
        return [ActionAuthorizationEnvelope.from_value(item) for item in values]
    except (AuthorizationEnvelopeError, TypeError, ValueError, json.JSONDecodeError):
        log.warning("Invalid action authorization launch context")
        return []


def select_authorization_envelope(
    envelopes: Iterable[ActionAuthorizationEnvelope],
    *,
    job_id: str,
    engine: str,
    action_kind: str,
    requested_target: str,
    resolved_target: str,
    module_id: str = "",
) -> ActionAuthorizationEnvelope | None:
    requested_ref = _safe_target_for_binding(requested_target)
    resolved_ref = _safe_target_for_binding(resolved_target)
    matches = [
        item
        for item in envelopes
        if item.job_id == job_id
        and item.engine == engine.strip().lower()
        and item.action_kind == action_kind.strip().lower()
        and item.module_id == module_id.strip().lower()
        and item.requested_target == requested_ref
        and item.resolved_target == resolved_ref
    ]
    return matches[0] if len(matches) == 1 else None


def default_authorization_db_path(
    environ: Mapping[str, str] | None = None,
) -> Path:
    source = os.environ if environ is None else environ
    configured = source.get(AUTHORIZATION_DB_ENV, "").strip()
    if configured:
        return Path(os.path.abspath(os.fspath(Path(configured).expanduser())))
    return Path.home() / ".local" / "state" / "forge-suite" / "authorization.db"


def open_authorization_session(path: Path | None = None) -> Session:
    configured_path = path or default_authorization_db_path()
    db_path = Path(
        os.path.abspath(os.fspath(Path(configured_path).expanduser()))
    )
    if os.environ.get(AUTHORIZATION_DB_PREINITIALIZED_ENV, "").strip() == "1":
        expected = default_authorization_db_path()
        if db_path != expected:
            raise ValueError(
                "preinitialized authorization database path mismatch"
            )
        return open_existing_db(db_path)
    return create_db(db_path)
