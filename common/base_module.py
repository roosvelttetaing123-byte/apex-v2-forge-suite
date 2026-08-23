"""Abstract BaseModule — all forge modules inherit from this."""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import math
import re
import time
import uuid
import weakref
from abc import ABC, ABCMeta, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import FunctionType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from common.dashboard.event_bus import EventBus

from common.config import BaseForgeConfig
from common.confirm_gate import confirm
from common.db import Session, save_finding
from common.evidence import Evidence
from common.finding import Finding, Severity, cvss31_score
from common.scope import Scope, ScopeViolation

from common.action_authorization import (
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    claim_consumed_authorization_execution,
    open_authorization_session,
    redact_authorization_value,
    validate_consumed_authorization,
)
from common.canonical import MissingCanonicalContextError
from common.outbound_policy import (
    ApprovedEgressRoute,
    AuthorizationDatabaseOutboundAuditSink,
    DeniedPolicyHttpClient,
    OutboundContext,
    OutboundPolicy,
    OutboundReason,
    OutboundDenied,
    PolicyHttpClient,
    _outbound_context_runtime_binding,
    _outbound_policy_runtime_binding,
    _normalized_proxy_origin,
    evaluate_module_outbound_support,
    module_requires_outbound_context,
    outbound_context_claim_is_valid,
)


@dataclass
class ModuleResult:
    """Container for all findings produced by a module run."""
    module_name: str
    findings:    list[Finding] = field(default_factory=list)
    errors:      list[str]     = field(default_factory=list)
    duration_s:  float         = 0.0
    skipped:     bool          = False
    skip_reason: str           = ""


def module_result_error_text(result: Any) -> str:
    """Return redacted terminal error text from a module result, fail closed."""
    raw_errors = getattr(result, "errors", []) if result is not None else []
    if not raw_errors:
        return ""
    if isinstance(raw_errors, (str, bytes)):
        items = [raw_errors]
    elif isinstance(raw_errors, (list, tuple, set)):
        items = list(raw_errors)
    else:
        return "malformed module result errors"
    safe_errors = [
        str(redact_authorization_value(str(item)))
        for item in items
        if str(item).strip()
    ]
    return "; ".join(safe_errors) or "module reported an unspecified error"


_MODULE_SHARED_OUTPUT_KEYS = frozenset(
    {
        "crawled_urls",
        "found_forms",
        "found_params",
        "js_api_endpoints",
        "hidden_form_fields",
        "js_files_analyzed",
    }
)


_BASE_MODULE_EXECUTION_AUTHORITIES: dict[int, tuple[Any, ...]] = {}
_BASE_MODULE_OUTBOUND_AUTHORITIES: dict[int, tuple[Any, ...]] = {}
_GUARDED_RUN_AUTHORITIES: dict[int, tuple[Any, ...]] = {}


# These aliases mirror the canonical observation contract and the legacy
# payloads emitted by adapters.  Keep the values in the adapter identity even
# though ``Finding`` predates first-class route/parameter fields.
_DEDUP_DIMENSION_ALIASES: dict[str, tuple[str, ...]] = {
    "route": ("route", "path", "endpoint", "uri"),
    "parameter": ("query", "parameter", "param", "field"),
    "location": ("location", "in_location", "source_location"),
    "identity": ("identity", "identity_ref", "principal", "account", "user"),
}
_DEDUP_NESTED_KEYS = (
    "observation",
    "canonical_observation",
    "observations",
    "metadata",
    "dimensions",
    "context",
)


def _dedup_identity_value(value: Any) -> str:
    """Render one identity value deterministically without exposing it.

    Observation dimensions are generally strings, but adapters occasionally
    provide structured query/identity metadata.  Canonical JSON keeps those
    shapes stable; the resulting material is hashed before it enters a key.
    """
    if value is None:
        return ""
    if isinstance(value, Mapping):
        normalized = {
            str(key): _dedup_identity_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
        return json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if isinstance(value, (list, tuple)):
        return json.dumps(
            [_dedup_identity_value(item) for item in value],
            ensure_ascii=True,
            separators=(",", ":"),
        )
    if isinstance(value, (set, frozenset)):
        return json.dumps(
            sorted(_dedup_identity_value(item) for item in value),
            ensure_ascii=True,
            separators=(",", ":"),
        )
    return " ".join(str(value).strip().split())


def _dedup_containers(finding: Finding) -> list[Any]:
    """Return finding metadata containers that may carry observation fields."""
    pending: list[Any] = [finding]
    evidence = getattr(finding, "evidence", None)
    verification = getattr(finding, "verification", None)
    if evidence is not None:
        pending.append(evidence)
        pending.append(getattr(evidence, "extra", None))
    if verification is not None:
        pending.append(verification)

    containers: list[Any] = []
    seen: set[int] = set()
    while pending:
        current = pending.pop(0)
        if current is None or id(current) in seen:
            continue
        if current is not finding and not isinstance(current, Mapping) and not any(
            hasattr(current, name)
            for name in _DEDUP_DIMENSION_ALIASES["route"]
            + _DEDUP_DIMENSION_ALIASES["parameter"]
            + _DEDUP_DIMENSION_ALIASES["location"]
            + _DEDUP_DIMENSION_ALIASES["identity"]
        ):
            continue
        seen.add(id(current))
        containers.append(current)
        for name in _DEDUP_NESTED_KEYS:
            if isinstance(current, Mapping):
                child = current.get(name)
            else:
                child = getattr(current, name, None)
            if child is not None:
                pending.append(child)
        if isinstance(current, Mapping):
            extra = current.get("extra")
            if extra is not None:
                pending.append(extra)
        else:
            extra = getattr(current, "extra", None)
            if extra is not None:
                pending.append(extra)
    return containers


def _dedup_dimension(finding: Finding, aliases: tuple[str, ...]) -> str:
    """Read the first non-empty dimension from all supported payload shapes."""
    for container in _dedup_containers(finding):
        for name in aliases:
            if isinstance(container, Mapping):
                value = container.get(name)
            else:
                value = getattr(container, name, None)
            rendered = _dedup_identity_value(value)
            if rendered:
                return rendered
    return ""


def _finding_observation_identity(finding: Finding) -> str:
    """Return a non-secret digest for every adapter-level observation dimension."""
    url = _dedup_identity_value(
        getattr(finding, "url", None) or getattr(finding, "target", None) or ""
    )
    material = (
        "finding-observation-v2",
        url,
        _dedup_dimension(finding, _DEDUP_DIMENSION_ALIASES["route"]),
        _dedup_dimension(finding, _DEDUP_DIMENSION_ALIASES["parameter"]),
        _dedup_dimension(finding, _DEDUP_DIMENSION_ALIASES["location"]),
        _dedup_dimension(finding, _DEDUP_DIMENSION_ALIASES["identity"]),
    )
    encoded = "\x1f".join(material).encode("utf-8", errors="replace")
    return hashlib.sha256(encoded).hexdigest()


def _dedup_log_target(value: Any) -> str:
    """Return a query-safe target label for duplicate warnings."""
    rendered = _dedup_identity_value(value)
    if "?" in rendered:
        return rendered.split("?", 1)[0] + "?<redacted>"
    return rendered


def merge_module_output_extra(
    shared: dict[str, Any],
    isolated: dict[str, Any],
) -> None:
    """Publish module-produced workflow state without leaking capabilities."""
    for key, value in isolated.items():
        name = str(key)
        if name not in _MODULE_SHARED_OUTPUT_KEYS:
            continue
        shared[name] = value


def _has_valid_module_authorization(
    instance: "BaseModule",
    *,
    engine: str,
    module_id: str,
) -> bool:
    """Validate the exact consumed Task 002 module-execution capability."""
    claim_session = None
    try:
        authority = _BASE_MODULE_EXECUTION_AUTHORITIES.get(id(instance))
        if authority is None or authority[0]() is not instance:
            return False
        trusted_envelope = authority[1]
        trusted_context = authority[2]
        trusted_boundary = authority[3]
        envelope = object.__getattribute__(instance, "authorization_envelope")
        context = object.__getattribute__(instance, "authorization_context")
        boundary = object.__getattribute__(instance, "authorization_boundary")
        config = object.__getattribute__(instance, "config")
        if not (
            type(envelope) is ActionAuthorizationEnvelope
            and envelope is trusted_envelope
            and type(context) is AuthorizationContext
            and context is trusted_context
            and boundary == trusted_boundary == f"{engine}.module"
            and object.__getattribute__(instance, "authorization_decision_id")
            == envelope.decision_id
            and envelope.engine == engine
            and envelope.module_id == module_id
            and envelope.run_id == object.__getattribute__(instance, "run_id")
            and context.engine == engine
            and context.module_id == module_id
            and context.run_id == envelope.run_id
            and context.action_kind == "module.execute"
            and context.requested_target == config.target
            and context.resolved_target == config.target
            and context.allowed_scope
            == tuple(config.extra.get("allowed_scope", []))
            and context.excluded_scope
            == tuple(config.extra.get("excluded_scope", []))
        ):
            return False
        claim_session = open_authorization_session()
        return validate_consumed_authorization(
            session=claim_session,
            envelope=envelope,
            expected=context,
            boundary=boundary,
        ).allowed
    except Exception:
        return False
    finally:
        if claim_session is not None:
            claim_session.close()


def _claim_module_execution(
    instance: "BaseModule",
    *,
    engine: str,
    module_id: str,
) -> bool:
    """Atomically claim this consumed action's one permitted invocation."""
    claim_session = None
    try:
        if not _has_valid_module_authorization(
            instance,
            engine=engine,
            module_id=module_id,
        ):
            return False
        authority = _BASE_MODULE_EXECUTION_AUTHORITIES.get(id(instance))
        if authority is None or authority[0]() is not instance:
            return False
        claim_session = open_authorization_session()
        return claim_consumed_authorization_execution(
            session=claim_session,
            envelope=authority[1],
            expected=authority[2],
            boundary=authority[3],
        ).allowed
    except Exception:
        return False
    finally:
        if claim_session is not None:
            claim_session.close()


def _has_valid_outbound_context(
    instance: "BaseModule",
    *,
    engine: str,
    module_id: str,
) -> bool:
    """Validate transport authority captured by the canonical Base initializer."""
    claim_session = None
    try:
        if not _has_valid_module_authorization(
            instance,
            engine=engine,
            module_id=module_id,
        ):
            return False
        authority = _BASE_MODULE_OUTBOUND_AUTHORITIES.get(id(instance))
        if authority is None or authority[0]() is not instance:
            return False
        trusted_policy = authority[1]()
        trusted_context = authority[2]()
        if trusted_policy is None or trusted_context is None:
            return False
        trusted_policy_binding = authority[3]
        trusted_context_binding = authority[4]
        trusted_rate = authority[5]
        policy = object.__getattribute__(instance, "outbound_policy")
        if (
            type(policy) is not OutboundPolicy
            or policy is not trusted_policy
            or policy
            is not object.__getattribute__(
                instance,
                "_authorized_outbound_policy",
            )
        ):
            return False
        context = policy.context
        if (
            type(context) is not OutboundContext
            or context is not trusted_context
            or context
            is not object.__getattribute__(
                instance,
                "_authorized_outbound_context",
            )
        ):
            return False
        if (
            _outbound_policy_runtime_binding(policy) != trusted_policy_binding
            or object.__getattribute__(
                instance,
                "_authorized_outbound_policy_binding",
            )
            != trusted_policy_binding
        ):
            return False
        if (
            _outbound_context_runtime_binding(context) != trusted_context_binding
            or object.__getattribute__(
                instance,
                "_authorized_outbound_context_binding",
            )
            != trusted_context_binding
        ):
            return False
        envelope = context.envelope
        boundary = f"{engine}.module"
        config = object.__getattribute__(instance, "config")
        configured_rate = config.rate.requests_per_second
        retained_envelope = object.__getattribute__(
            instance,
            "authorization_envelope",
        )
        retained_context = object.__getattribute__(
            instance,
            "authorization_context",
        )
        if not (
            type(retained_envelope) is ActionAuthorizationEnvelope
            and type(retained_context) is AuthorizationContext
            and retained_envelope == envelope
            and object.__getattribute__(
                instance,
                "authorization_decision_id",
            )
            == envelope.decision_id
            and object.__getattribute__(
                instance,
                "authorization_boundary",
            )
            == boundary
            and envelope.engine == engine
            and envelope.module_id == module_id
            and envelope.run_id == object.__getattribute__(instance, "run_id")
            and context.authorized_target == config.target
            and context.allowed_scope
            == tuple(config.extra.get("allowed_scope", []))
            and context.excluded_scope
            == tuple(config.extra.get("excluded_scope", []))
            and retained_context.engine == engine
            and retained_context.module_id == module_id
            and retained_context.run_id == envelope.run_id
            and retained_context.resolved_target == context.authorized_target
            and type(configured_rate) in {int, float}
            and math.isfinite(float(configured_rate))
            and float(configured_rate) == trusted_rate
            and object.__getattribute__(
                instance,
                "_authorized_rate_requests_per_second",
            )
            == trusted_rate
        ):
            return False
        claim_session = open_authorization_session()
        return outbound_context_claim_is_valid(
            session=claim_session,
            context=context,
            expected=retained_context,
            boundary=boundary,
        )
    except Exception:
        return False
    finally:
        if claim_session is not None:
            claim_session.close()


class _GuardedRunDescriptor:
    """Non-shadowable run boundary installed by the BaseModule metaclass."""

    _declared_identity_valid: bool
    _declared_module_path: str
    _declared_engine: str
    _declared_module_id: str
    _implementation_valid: bool

    __slots__ = (
        "_declared_identity_valid",
        "_declared_module_path",
        "_declared_engine",
        "_declared_module_id",
        "_implementation_valid",
        "__isabstractmethod__",
        "__weakref__",
    )

    def __init__(
        self,
        original_run: Any,
        declared_module_value: Any,
        declared_name_value: Any,
        *,
        implementation_valid: bool,
    ) -> None:
        declared_identity_valid = (
            type(declared_module_value) is str
            and type(declared_name_value) is str
        )
        declared_module_path = declared_module_value if declared_identity_valid else ""
        declared_engine = declared_module_path.partition(".")[0].strip().lower()
        declared_module_id = (
            declared_name_value.strip() if declared_identity_valid else ""
        )
        object.__setattr__(
            self,
            "_declared_identity_valid",
            declared_identity_valid,
        )
        object.__setattr__(self, "_declared_module_path", declared_module_path)
        object.__setattr__(self, "_declared_engine", declared_engine)
        object.__setattr__(self, "_declared_module_id", declared_module_id)
        object.__setattr__(self, "_implementation_valid", implementation_valid)
        object.__setattr__(
            self,
            "__isabstractmethod__",
            bool(getattr(original_run, "__isabstractmethod__", False)),
        )
        descriptor_id = id(self)

        def forget_descriptor(
            reference: weakref.ReferenceType[_GuardedRunDescriptor],
        ) -> None:
            current_authority = _GUARDED_RUN_AUTHORITIES.get(descriptor_id)
            if current_authority is not None and current_authority[0] is reference:
                _GUARDED_RUN_AUTHORITIES.pop(descriptor_id, None)

        _GUARDED_RUN_AUTHORITIES[descriptor_id] = (
            weakref.ref(self, forget_descriptor),
            original_run,
            declared_identity_valid,
            declared_module_path,
            declared_engine,
            declared_module_id,
            implementation_valid,
        )

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("module run boundary metadata is immutable")

    def __get__(self, instance: Any, _owner: Any = None) -> Any:
        if instance is None:
            return self

        async def bound_run(*args: Any, **kwargs: Any) -> ModuleResult:
            return await self(instance, *args, **kwargs)

        return bound_run

    def __set__(self, _instance: Any, _value: Any) -> None:
        raise AttributeError("module run boundary cannot be replaced")

    async def __call__(
        self,
        instance: "BaseModule",
        *args: Any,
        **run_kwargs: Any,
    ) -> ModuleResult:
        authority = _GUARDED_RUN_AUTHORITIES.get(id(self))
        if authority is None or authority[0]() is not self:
            return ModuleResult(
                module_name="",
                findings=[],
                errors=[OutboundReason.AUTHORIZATION_INVALID.value],
                duration_s=0.0,
                skipped=True,
                skip_reason=OutboundReason.AUTHORIZATION_INVALID.value,
            )
        original_run = authority[1]
        declared_identity_valid = authority[2]
        declared_module_path = authority[3]
        declared_engine = authority[4]
        declared_module_id = authority[5]
        implementation_valid = authority[6]
        if (
            self._declared_identity_valid != declared_identity_valid
            or self._declared_module_path != declared_module_path
            or self._declared_engine != declared_engine
            or self._declared_module_id != declared_module_id
            or self._implementation_valid is not implementation_valid
        ):
            implementation_valid = False
        runtime_class = type(instance)
        try:
            runtime_module_value = type.__getattribute__(
                runtime_class,
                "__module__",
            )
            runtime_name_value = type.__getattribute__(runtime_class, "NAME")
        except Exception:
            runtime_module_value = None
            runtime_name_value = None
        runtime_identity_valid = (
            type(runtime_module_value) is str
            and type(runtime_name_value) is str
        )
        runtime_module_path = runtime_module_value if runtime_identity_valid else ""
        runtime_engine = runtime_module_path.partition(".")[0].strip().lower()
        runtime_module_id = (
            runtime_name_value.strip() if runtime_identity_valid else ""
        )
        # Every concrete BaseModule is guarded by default.  Engine/module
        # registries decide support; no caller-selected module namespace is a
        # no-context exception.
        protected = True
        reason = ""
        if not implementation_valid:
            reason = OutboundReason.AUTHORIZATION_INVALID.value
        elif protected and (
            not declared_identity_valid
            or not runtime_identity_valid
            or not declared_engine
            or not declared_module_id
            or not runtime_engine
            or not runtime_module_id
            or runtime_module_path != declared_module_path
            or runtime_engine != declared_engine
            or runtime_module_id != declared_module_id
        ):
            reason = OutboundReason.AUTHORIZATION_INVALID.value
        elif protected:
            support = evaluate_module_outbound_support(
                engine=declared_engine,
                module_id=declared_module_id,
            )
            if not support.supported:
                reason = support.reason_code
            elif not _has_valid_module_authorization(
                instance,
                engine=declared_engine,
                module_id=declared_module_id,
            ):
                reason = OutboundReason.AUTHORIZATION_INVALID.value
            elif (
                module_requires_outbound_context(
                    engine=declared_engine,
                    module_id=declared_module_id,
                )
                and not _has_valid_outbound_context(
                    instance,
                    engine=declared_engine,
                    module_id=declared_module_id,
                )
            ):
                reason = OutboundReason.AUTHORIZATION_INVALID.value
            elif not _claim_module_execution(
                instance,
                engine=declared_engine,
                module_id=declared_module_id,
            ):
                reason = OutboundReason.AUTHORIZATION_INVALID.value
        if reason:
            object.__setattr__(instance, "_outbound_denied_reason", reason)
            return ModuleResult(
                module_name=declared_module_id or runtime_module_id,
                findings=[],
                errors=[reason],
                duration_s=0.0,
                skipped=True,
                skip_reason=reason,
            )
        return await original_run(instance, *args, **run_kwargs)


class _BaseModuleMeta(ABCMeta):
    """Install and preserve the non-shadowable module execution boundary."""

    def __new__(
        mcls,
        name: str,
        bases: tuple[type, ...],
        namespace: dict[str, Any],
        **kwargs: Any,
    ) -> "_BaseModuleMeta":
        class_namespace = dict(namespace)
        for forbidden_name in ("__getattribute__", "__getattr__"):
            if forbidden_name in class_namespace:
                raise TypeError(
                    f"BaseModule subclasses cannot override {forbidden_name}"
                )
        if "run" in class_namespace:
            original_run = class_namespace["run"]
            if isinstance(original_run, _GuardedRunDescriptor):
                source_authority = _GUARDED_RUN_AUTHORITIES.get(id(original_run))
                if (
                    source_authority is not None
                    and source_authority[0]() is original_run
                ):
                    original_run = source_authority[1]
                    implementation_valid = bool(source_authority[6])
                else:
                    implementation_valid = False
            else:
                implementation_valid = (
                    type(original_run) is FunctionType
                    and inspect.iscoroutinefunction(original_run)
                )
            declared_name_value = class_namespace.get("NAME")
            if declared_name_value is None:
                for base in bases:
                    try:
                        declared_name_value = type.__getattribute__(base, "NAME")
                    except Exception:
                        continue
                    break
            class_namespace["run"] = _GuardedRunDescriptor(
                original_run,
                class_namespace.get("__module__"),
                declared_name_value,
                implementation_valid=implementation_valid,
            )
        return super().__new__(mcls, name, bases, class_namespace, **kwargs)

    def __setattr__(cls, name: str, value: Any) -> None:
        if name in {"run", "__getattribute__", "__getattr__"}:
            raise AttributeError("module run boundary cannot be replaced")
        super().__setattr__(name, value)

    def __delattr__(cls, name: str) -> None:
        if name in {"run", "__getattribute__", "__getattr__"}:
            raise AttributeError("module run boundary cannot be removed")
        super().__delattr__(name)


class BaseModule(ABC, metaclass=_BaseModuleMeta):
    """Abstract base class for all forge modules.

    Every module must implement run() and provide NAME, DESCRIPTION, PHASE.
    Subclasses inherit scope checking, rate limiting, logging, finding
    persistence, screenshot capture, and operator confirmation gate.
    """

    NAME:        str = "base_module"
    DESCRIPTION: str = "Base module"
    PHASE:       int = 0
    TAGS:        list[str] = []

    # Shared rate-limit state per target — ensures the configured req/s limit
    # holds globally even when multiple modules run concurrently in a phase.
    _shared_rate_locks: dict[str, asyncio.Lock] = {}
    _shared_rate_last:  dict[str, float]        = {}

    def __init__(
        self,
        config: BaseForgeConfig,
        scope: Scope,
        db_session: Session,
        results_dir: Path,
        run_id: str | None = None,
        event_bus: "EventBus | None" = None,
    ) -> None:
        """Initialize module with shared resources.

        Args:
            config:      Framework configuration.
            scope:       Scope enforcer instance.
            db_session:  Active SQLAlchemy session.
            results_dir: Directory for evidence output.
            run_id:      Scan run UUID for correlation.
            event_bus:   Optional dashboard event bus for real-time UI.
        """
        _BASE_MODULE_EXECUTION_AUTHORITIES.pop(id(self), None)
        _BASE_MODULE_OUTBOUND_AUTHORITIES.pop(id(self), None)
        self.config      = config
        self.scope       = scope
        self.db          = db_session
        self.results_dir = results_dir
        self.run_id      = run_id or str(uuid.uuid4())
        self.findings:   list[Finding] = []
        self.log         = logging.getLogger(f"forge.{self.NAME}")
        self._evidence_dir = results_dir / "evidence"
        self._screenshot_dir = self._evidence_dir / "screenshots"
        self._event_bus: "EventBus | None" = event_bus
        self._request_count: int = 0
        self._authorized_rate_requests_per_second = float(
            config.rate.requests_per_second
        )
        if (
            not math.isfinite(self._authorized_rate_requests_per_second)
            or self._authorized_rate_requests_per_second <= 0
            or self._authorized_rate_requests_per_second > 1000
        ):
            raise ValueError("requests_per_second is outside the supported bound")
        self.authorization_decision_id = ""
        self.authorization_envelope: ActionAuthorizationEnvelope | None = None
        self.authorization_context: AuthorizationContext | None = None
        self.authorization_boundary = ""
        self.outbound_policy: OutboundPolicy | None = None
        self._authorized_outbound_policy: OutboundPolicy | None = None
        self._authorized_outbound_context: OutboundContext | None = None
        self._authorized_outbound_policy_binding: tuple[Any, ...] | None = None
        self._authorized_outbound_context_binding: tuple[Any, ...] | None = None
        self._outbound_denied_reason = ""
        # Deduplication guard — tracks module/title plus an opaque observation
        # identity already emitted.  This prevents per-origin / per-payload /
        # per-probe-variant inflation without dropping distinct route dimensions.
        # Initialize it before the local-only authorization path returns without
        # constructing any network transport context.
        self._seen_finding_keys: dict[str, int] = {}
        # A plain id/boolean in config is not an authorization capability.  The
        # engine adapter must provide the exact envelope and a persisted,
        # single-use consumption; verify both before exposing confirmation to a
        # sensitive module.
        authorized_envelopes = config.extra.get("authorized_module_envelopes", {})
        envelope_value = (
            authorized_envelopes.get(self.NAME)
            if isinstance(authorized_envelopes, dict)
            else None
        )
        if envelope_value is not None:
            try:
                envelope = ActionAuthorizationEnvelope.from_value(envelope_value)
                expected = AuthorizationContext(
                    tenant_id=envelope.tenant_id,
                    engagement_id=envelope.engagement_id,
                    run_id=self.run_id,
                    job_id=envelope.job_id,
                    operator_id=envelope.operator_id,
                    operator_role=envelope.operator_role,
                    action_kind="module.execute",
                    engine=envelope.engine,
                    module_id=self.NAME,
                    requested_target=config.target,
                    resolved_target=config.target,
                    allowed_scope=config.extra.get("allowed_scope", []),
                    excluded_scope=config.extra.get("excluded_scope", []),
                    scope_policy_version=envelope.scope_policy_version,
                    safety_mode=envelope.safety_mode,
                    credential_approval_required=envelope.credential_approval_required,
                    network_escalation_approval_required=(
                        envelope.network_escalation_approval_required
                    ),
                    high_risk_approval_required=envelope.high_risk_approval_required,
                    confirmation_method=envelope.confirmation_method,
                    confirmed_by=envelope.confirmed_by,
                    credential_reference=envelope.credential_reference,
                    parent_decision_id=envelope.parent_decision_id,
                )
                auth_session = open_authorization_session()
                try:
                    verified = validate_consumed_authorization(
                        session=auth_session,
                        envelope=envelope,
                        expected=expected,
                        boundary=f"{envelope.engine}.module",
                    )
                finally:
                    auth_session.close()
                if verified.allowed:
                    self.authorization_decision_id = envelope.decision_id
                    self.authorization_envelope = envelope
                    self.authorization_context = expected
                    self.authorization_boundary = f"{envelope.engine}.module"
                    instance_id = id(self)

                    def forget_instance(
                        reference: weakref.ReferenceType[BaseModule],
                    ) -> None:
                        for registry in (
                            _BASE_MODULE_EXECUTION_AUTHORITIES,
                            _BASE_MODULE_OUTBOUND_AUTHORITIES,
                        ):
                            current_authority = registry.get(instance_id)
                            if (
                                current_authority is not None
                                and current_authority[0] is reference
                            ):
                                registry.pop(instance_id, None)

                    instance_reference = weakref.ref(self, forget_instance)
                    _BASE_MODULE_EXECUTION_AUTHORITIES[instance_id] = (
                        instance_reference,
                        envelope,
                        expected,
                        self.authorization_boundary,
                    )
                    if not module_requires_outbound_context(
                        engine=envelope.engine,
                        module_id=self.NAME,
                    ):
                        return
                    route_value = config.extra.get("approved_egress_route")
                    route_values = config.extra.get("approved_egress_routes", {})
                    if isinstance(route_values, dict) and self.NAME in route_values:
                        route_value = route_values[self.NAME]
                    approved_route = (
                        ApprovedEgressRoute.from_value(route_value)
                        if route_value is not None
                        else None
                    )
                    configured_proxy = str(
                        getattr(config, "proxy", "")
                        or config.extra.get("proxy", "")
                        or ""
                    ).strip()
                    if configured_proxy and approved_route is None:
                        raise OutboundDenied(OutboundReason.ROUTE_REQUIRED)
                    if (
                        configured_proxy
                        and approved_route is not None
                        and _normalized_proxy_origin(configured_proxy)
                        != approved_route.proxy_url
                    ):
                        raise OutboundDenied(OutboundReason.ROUTE_BINDING_MISMATCH)
                    outbound_auth_session = open_authorization_session()
                    try:
                        outbound_context = OutboundContext.from_consumed_authorization(
                            session=outbound_auth_session,
                            envelope=envelope,
                            expected=expected,
                            boundary=f"{envelope.engine}.module",
                            authorized_target=config.target,
                            allowed_scope=tuple(config.extra.get("allowed_scope", [])),
                            excluded_scope=tuple(config.extra.get("excluded_scope", [])),
                            audit_sink=AuthorizationDatabaseOutboundAuditSink(),
                            route=approved_route,
                            max_redirects=int(config.extra.get("outbound_max_redirects", 5)),
                            max_retries=int(config.extra.get("outbound_max_retries", 2)),
                            timeout_seconds=float(config.extra.get("outbound_timeout_seconds", 30.0)),
                            max_response_bytes=int(
                                config.extra.get("outbound_max_response_bytes", 10 * 1024 * 1024)
                            ),
                            cancellation_check=(
                                config.extra.get("outbound_cancellation_check")
                                if callable(config.extra.get("outbound_cancellation_check"))
                                else None
                            ),
                            attempt_limiter=self.rate_limit,
                            # A mutable config flag is not the separately consumed,
                            # target-bound child authorization required to disable
                            # certificate verification.  Engine integration remains
                            # fail-closed until that child envelope is handed off.
                            lab_only_insecure_tls=False,
                            insecure_tls_target=str(
                                config.extra.get("insecure_tls_target", "") or ""
                            ),
                        )
                    finally:
                        outbound_auth_session.close()
                    # Route continuity is enforced atomically by the protected
                    # append-only route-health store.  Never let caller-owned
                    # config establish or replace that baseline.
                    self.outbound_policy = OutboundPolicy(outbound_context)
                    self._authorized_outbound_policy = self.outbound_policy
                    self._authorized_outbound_context = outbound_context
                    self._authorized_outbound_policy_binding = (
                        _outbound_policy_runtime_binding(self.outbound_policy)
                    )
                    self._authorized_outbound_context_binding = (
                        _outbound_context_runtime_binding(outbound_context)
                    )
                    # Engines pass each module an isolated config copy.  This is
                    # an in-process capability handoff for shared helpers, not a
                    # caller-controlled authorization flag.
                    self.config.extra["outbound_policy"] = self.outbound_policy
                    _BASE_MODULE_OUTBOUND_AUTHORITIES[instance_id] = (
                        instance_reference,
                        weakref.ref(self.outbound_policy),
                        weakref.ref(outbound_context),
                        self._authorized_outbound_policy_binding,
                        self._authorized_outbound_context_binding,
                        self._authorized_rate_requests_per_second,
                    )
            except Exception as exc:
                if isinstance(exc, OutboundDenied):
                    self._outbound_denied_reason = exc.reason_code
                self.log.warning(
                    "Sensitive module authorization unavailable; action denied (%s)",
                    type(exc).__name__,
                )
    # ── Cross-module global dedup ────────────────────────────────────────
    # Normalized keys shared across module instances, scoped by run_id.
    # Catches: CSP missing from header_audit AND csp_audit, clickjacking
    # from header_audit AND clickjacking module, version disclosure from
    # tech_detect AND header_audit, etc.
    _global_finding_keys: set[str] = set()

    @classmethod
    def reset_global_dedup(cls) -> None:
        """Reset global dedup between scan runs."""
        cls._global_finding_keys = set()

    @abstractmethod
    async def run(self) -> ModuleResult:
        """Execute the module. Must be implemented by every module.

        Returns:
            ModuleResult containing all findings and metadata.
        """

    @staticmethod
    def _normalize_for_global_dedup(title: str) -> str:
        """Normalize a finding title for cross-module dedup.

        Uses explicit keyword mapping to canonicalize overlapping findings.
        """
        t = title.lower().strip()

        # Explicit concept mapping — order matters, first match wins
        _CONCEPT_KEYWORDS = [
            ("content-security-policy", "csp-missing"),
            ("csp", "csp-missing"),
            ("x-frame-options", "clickjacking"),
            ("clickjacking", "clickjacking"),
            ("x-content-type-options", "xcto-missing"),
            ("strict-transport-security", "hsts-missing"),
            ("hsts", "hsts-missing"),
            ("referrer-policy", "referrer-policy-missing"),
            ("permissions-policy", "permissions-policy-missing"),
            ("cross-origin-opener", "coop-missing"),
            ("cross-origin-embedder", "coep-missing"),
            ("cross-origin-resource", "corp-missing"),
        ]

        for keyword, concept in _CONCEPT_KEYWORDS:
            if keyword in t:
                return concept

        # For info disclosure headers, extract the header name
        # "Information Disclosure — Response Header 'Server'" → "info:server"
        # "Version Disclosure in 'server' Header" → "info:server"
        import re
        m = re.search(r"['\"]([^'\"]+)['\"]", t)
        if m and ("disclosure" in t or "version" in t):
            return f"info:{m.group(1).lower()}"

        # Fallback: return the title as-is (no normalization)
        return t

    def check_scope(self, target: str) -> bool:
        """Validate target is in scope before any request.

        Returns:
            True if in scope. Logs and returns False if out of scope.
        """
        try:
            return self.scope.check(target)
        except ScopeViolation as exc:
            self.log.warning("Scope violation blocked: %s", exc)
            return False

    async def rate_limit(self, bytes_out: int = 0, bytes_in: int = 0) -> None:
        """Enforce rate limiting between requests, shared across concurrent modules.

        Uses a class-level lock per target so the configured req/s cap holds
        globally regardless of how many modules are running in parallel.
        """
        requests_per_second = self._authorized_rate_requests_per_second
        authority = _BASE_MODULE_OUTBOUND_AUTHORITIES.get(id(self))
        if authority is not None and authority[0]() is self:
            requests_per_second = float(authority[5])
        if (
            not math.isfinite(requests_per_second)
            or requests_per_second <= 0
            or requests_per_second > 1000
        ):
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        target = self.config.target
        if target not in BaseModule._shared_rate_locks:
            BaseModule._shared_rate_locks[target] = asyncio.Lock()
            BaseModule._shared_rate_last[target]  = 0.0
        min_interval = 1.0 / requests_per_second
        async with BaseModule._shared_rate_locks[target]:
            elapsed = time.monotonic() - BaseModule._shared_rate_last[target]
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            BaseModule._shared_rate_last[target] = time.monotonic()
        self._request_count += 1
        self._emit_event("request_sent", bytes_out=bytes_out, bytes_in=bytes_in)

    def add_finding(self, finding: Finding) -> None:
        """Record a finding, persist to DB, emit to dashboard, and log it.

        Duplicate suppression: if this module has already emitted a finding with
        the same title and observation identity, the second call is dropped and
        a warning is logged.  The identity includes route/query, parameter,
        location, and principal dimensions so per-payload / per-probe-variant
        inflation is suppressed without merging distinct observations.
        """
        _url = finding.url or finding.target or ""
        # Preserve all observation dimensions before canonical persistence.
        # The digest keeps query/identity values out of logs and opaque key
        # material while still making distinct routes, parameters, locations,
        # and principals independently observable.
        _dedup_identity = _finding_observation_identity(finding)
        _dedup_key = f"{self.NAME}\x00{finding.title}\x00{_dedup_identity}"
        if _dedup_key in self._seen_finding_keys:
            self._seen_finding_keys[_dedup_key] += 1
            self.log.warning(
                "[DEDUP] Suppressed duplicate finding (occurrence %d): '%s' at '%s'",
                self._seen_finding_keys[_dedup_key],
                finding.title,
                _dedup_log_target(_url),
            )
            return
        self._seen_finding_keys[_dedup_key] = 1

        # Cross-module dedup — normalize title to catch overlapping modules
        # e.g. "Security Header Missing: Content-Security-Policy" ≈ "Content-Security-Policy Header Missing"
        _norm_title = self._normalize_for_global_dedup(finding.title)
        _tenant_id = (
            self.authorization_envelope.tenant_id
            if self.authorization_envelope is not None
            else "default"
        )
        _global_key = (
            f"{_tenant_id}\x00{self.run_id}\x00{_norm_title}\x00{_dedup_identity}"
        )
        if _global_key in BaseModule._global_finding_keys:
            self.log.warning(
                "[GLOBAL-DEDUP] Suppressed cross-module duplicate: '%s' (module=%s)",
                finding.title, self.NAME,
            )
            return
        BaseModule._global_finding_keys.add(_global_key)
        self.findings.append(finding)
        # Task 101 adapters are strict by default: a module finding may not
        # silently fall back to the legacy ORM writer and create an orphan
        # record.  Gate-0 fixtures that genuinely need the compatibility
        # writer must opt in explicitly; a missing/falsey flag is never
        # treated as authorization to persist without canonical lineage.
        canonical_required = not (
            self.config.extra.get("allow_legacy_compat") is True
            and self.config.extra.get("canonical_context") is None
        )
        # A caller that supplies a context marker is always on the canonical
        # path.  The legacy writer cannot persist that graph, even when a
        # stale compatibility flag is present in a reused config object.
        if self.config.extra.get("canonical_context") is not None:
            canonical_required = True
        persisted = True
        try:
            save_finding(
                self.db,
                finding.to_dict(),
                run_id=self.run_id,
                allow_legacy_compat=not canonical_required,
                evidence_store=self.results_dir / "evidence-custody",
            )
        except MissingCanonicalContextError:
            if canonical_required:
                self.findings.pop()
                self._seen_finding_keys.pop(_dedup_key, None)
                BaseModule._global_finding_keys.discard(_global_key)
                raise
            # Explicit Gate-0 fixture compatibility: retain the finding in
            # memory for existing reporters, but do not emit a success event
            # or claim that a canonical row was persisted.
            persisted = False
            self.log.warning(
                "Finding retained in memory only; canonical context is unavailable"
            )
        except Exception as exc:
            self.log.error("Failed to save finding to DB: %s", exc)
        if not persisted:
            return
        self.log.info(
            "[FINDING] %s | %s | %s",
            finding.severity.value,
            finding.title,
            finding.target,
            extra={"forge_module": self.NAME, "target": finding.target},
        )
        # Emit to dashboard event bus
        self._emit_event(
            "finding_new",
            id=finding.id,
            title=finding.title,
            severity=finding.severity.value,
            module=self.NAME,
            target=finding.target,
            cvss_score=finding.cvss_v31_score,
            url=finding.url or "",
            port=finding.port,
            service=finding.service,
            description=finding.description,
            mitre_attack=finding.mitre_attack,
            confidence=finding.confidence,
            status=finding.status,
            vpr_score=finding.vpr_score,
            vpr_priority=finding.vpr_priority or finding.vpr,
            verification_state=finding.verification_state,
            proof_type=finding.proof_type,
            maturity=finding.maturity,
            verification=finding.verification or {},
            evidence=finding.evidence.to_dict(),
        )

        # External model analysis is an independent outbound action.  It stays
        # disabled until a provider-specific consumed envelope and canonical
        # policy client are injected; environment API keys are not authority.
        self.config.extra["brain_outbound_state"] = "outbound_policy_unsupported"

    async def _async_analyze_finding(self, finding: Finding) -> None:
        """External finding analysis is inert without its own outbound policy."""
        self.config.extra["brain_outbound_state"] = "outbound_policy_unsupported"
        return
        # Retained implementation below is unreachable until the provider
        # adapter is migrated to the canonical outbound boundary.
        try:
            from common.brain.analyst import FindingAnalyst
            analyst = FindingAnalyst()
            if not analyst.brain.available:
                return
            analysis = await analyst.analyze(finding)
            analyst.enrich_finding(finding, analysis)
            
            # Re-save enriched finding
            try:
                from common.db import save_finding
                save_finding(
                    self.db,
                    finding.to_dict(),
                    run_id=self.run_id,
                    allow_legacy_compat=False,
                    evidence_store=self.results_dir / "evidence-custody",
                )
            except Exception as exc:
                self.log.debug("Failed to update finding after analysis: %s", exc)

            # Emit verdict event
            self._emit_event(
                "brain_verdict",
                finding_id=finding.id,
                verdict=analysis.verdict.value,
                confidence=analysis.confidence.value,
                reasoning=analysis.reasoning,
                severity_adjustment=analysis.severity_adjustment,
            )
        except Exception as exc:
            self.log.debug("Finding auto-analysis failed: %s", exc)

    def new_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        reproduction_steps: list[str],
        remediation: str,
        references: list[str],
        evidence: Evidence | None = None,
        cvss_v31_vector: str | None = None,
        cvss_v40_vector: str | None = None,
        mitre_attack: list[str] | None = None,
        port: int | None = None,
        service: str | None = None,
        target: str | None = None,
        url: str | None = None,
        confidence: str | None = "UNVERIFIED",
        verification: "dict[str, Any] | None" = None,
        proof_type: str = "unknown",
        maturity: str = "experimental",
        operator_confirmed: bool = False,
        tags: list[str] | None = None,
    ) -> Finding:
        """Create a new finding, add it, and return it."""
        evidence = evidence or Evidence()
        if verification is None or (isinstance(verification, dict) and not verification):
            verification = self._verification_from_evidence(evidence)
        elif not isinstance(verification, dict):
            verification = {}
        confidence = self._normalise_confidence(
            confidence,
            verification=verification,
            evidence=evidence,
        )
        cvss_score = cvss31_score(cvss_v31_vector) if cvss_v31_vector else 0.0
        vpr_score, vpr_priority = self._calculate_vpr(cvss_score, title)
        if verification:
            verification.setdefault("confidence", confidence)
            verification.setdefault("proof_type", proof_type)
            verification.setdefault("maturity", maturity)

        f = Finding(
            title=title,
            severity=severity,
            target=target or self.config.target,
            module=self.NAME,
            description=description,
            reproduction_steps=reproduction_steps,
            remediation=remediation,
            references=references,
            evidence=evidence,
            cvss_v31_vector=cvss_v31_vector,
            cvss_v40_vector=cvss_v40_vector,
            mitre_attack=mitre_attack or [],
            port=port,
            service=service,
            operator_confirmed=operator_confirmed,
            tags=tags or [],
            url=url,
            confidence=confidence,
            status="open",
            vpr_score=vpr_score,
            vpr_priority=vpr_priority,
            vpr=vpr_priority,
            verification=verification or None,
            proof_type=proof_type,
            maturity=maturity,
        )
        self.add_finding(f)
        return f

    def auth_headers(
        self,
        headers: dict[str, str] | None = None,
        include_auth: bool = True,
    ) -> dict[str, str]:
        """Build HTTP headers with the scan's authenticated context applied."""
        merged: dict[str, str] = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
                "Gecko/20100101 Firefox/120.0"
            ),
            "Accept-Encoding": "gzip, deflate",
        }
        if include_auth:
            merged.update(self.config.extra.get("session_headers", {}) or {})
            token = self.config.extra.get("token") or self.config.extra.get("jwt_token")
            if token and "Authorization" not in merged:
                merged["Authorization"] = f"Bearer {token}"
            cookie_header = self.config.extra.get("cookie")
            if cookie_header and "Cookie" not in merged:
                merged["Cookie"] = self._clean_cookie_header(str(cookie_header))
        merged.update(headers or {})
        return merged

    def auth_cookies(self, cookies: dict[str, str] | None = None) -> dict[str, str]:
        """Return cookies captured from CLI, browser storage state, or SSO capture."""
        merged: dict[str, str] = {}
        merged.update(self.config.extra.get("session_cookies", {}) or {})

        cookie_header = (
            self.config.extra.get("cookie")
            or (self.config.extra.get("session_headers", {}) or {}).get("Cookie")
        )
        if cookie_header:
            merged.update(self._parse_cookie_header(str(cookie_header)))

        merged.update(cookies or {})
        return merged

    def http_session(
        self,
        timeout: float = 10.0,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        include_auth: bool = True,
        **kwargs: Any,
    ) -> Any:
        """Create a module-bound policy client; legacy direct sessions are denied."""
        if self.outbound_policy is None:
            return DeniedPolicyHttpClient(
                OutboundReason.AUTHORIZATION_INVALID,
                on_deny=lambda reason: setattr(self, "_outbound_denied_reason", reason),
            )
        if kwargs:
            raise ValueError("custom HTTP session options bypass the outbound policy")
        context = self.outbound_policy.context.with_timeout_seconds(
            min(float(timeout), self.outbound_policy.context.timeout_seconds),
        )
        policy = self.outbound_policy.fork(context)
        return PolicyHttpClient(
            policy,
            headers=self.auth_headers(headers, include_auth=include_auth),
            cookies=self.auth_cookies(cookies) if include_auth else (cookies or {}),
            cookie_provenance=(
                self.config.extra.get("session_cookie_provenance", {})
                if include_auth
                else {}
            ),
        )

    def _parse_cookie_header(self, value: str) -> dict[str, str]:
        """Parse a Cookie header into a dict without treating attributes as cookies."""
        cleaned = self._clean_cookie_header(value)
        parsed: dict[str, str] = {}
        for part in cleaned.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, cookie_value = part.split("=", 1)
            name = name.strip()
            if name.lower() in {"path", "domain", "expires", "max-age", "secure", "httponly", "samesite"}:
                continue
            parsed[name] = cookie_value.strip()
        return parsed

    def _clean_cookie_header(self, value: str) -> str:
        return re.sub(r"^cookie:\s*", "", value.strip(), flags=re.IGNORECASE)

    def _normalise_confidence(
        self,
        confidence: str | None,
        verification: dict[str, Any] | None = None,
        evidence: Evidence | None = None,
    ) -> str:
        """Return canonical finding confidence."""
        if confidence is None:
            return "UNVERIFIED"
        raw = confidence
        if raw == "UNVERIFIED" and isinstance(verification, dict):
            raw = str(verification.get("confidence") or raw)
        if raw == "UNVERIFIED" and evidence:
            raw = str(evidence.extra.get("fp_confidence") or raw)
        raw = raw.upper().replace(" ", "_")
        return raw if raw in {"HIGH", "MEDIUM", "LOW", "UNVERIFIED"} else "UNVERIFIED"

    def _verification_from_evidence(self, evidence: Evidence) -> dict[str, Any]:
        """Promote FPReducer evidence extras into the first-class verification field."""
        extra = evidence.extra or {}
        if not any(k in extra for k in ("fp_confidence", "fp_evidence", "fp_probe_count", "fp_probe_hits")):
            return {}
        return {
            "confidence": extra.get("fp_confidence", "UNVERIFIED"),
            "evidence": extra.get("fp_evidence", []),
            "probe_count": extra.get("fp_probe_count", 0),
            "probe_hits": extra.get("fp_probe_hits", 0),
        }

    def _is_waf_placeholder(
        self,
        body: str,
        status: int | None = None,
        headers: Any | None = None,
    ) -> bool:
        """Return True for generic WAF/firewall block pages, not app content."""
        haystack = body[:2000].lower()
        patterns = (
            "request rejected",
            "the requested url was rejected",
            "please consult with your administrator",
            "your support id is",
            "access denied",
            "blocked by",
            "web application firewall",
            "mod_security",
            "modsecurity",
            "forbidden by rule",
        )
        if any(p in haystack for p in patterns):
            return True
        header_text = " ".join(f"{k}: {v}" for k, v in dict(headers or {}).items()).lower()
        return status in {403, 406, 429} and any(
            p in header_text for p in ("waf", "firewall", "akamai", "cloudflare", "imperva", "f5")
        )

    async def _soft_404_fingerprints(self, target: str, probes: int = 2) -> set[str]:
        """Fingerprint unknown-path responses used by SPAs, CDNs, and firewalls."""
        _cache_key = f"_soft404_fp_cache\x00{target}"
        if _cache_key in self.config.extra:
            return set(self.config.extra[_cache_key] or [])

        fps: set[str] = set()
        try:
            async with self.http_session(timeout=5, include_auth=False) as session:
                for _ in range(max(1, probes)):
                    canary = f"{target}/_forge_missing_{uuid.uuid4().hex[:12]}"
                    async with session.get(
                        canary, allow_redirects=True,
                        timeout=5,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        if resp.status in {200, 401, 403, 404, 406, 429}:
                            fps.add(self._response_fingerprint(body, resp.status))
        except Exception:
            pass

        self.config.extra[_cache_key] = sorted(fps)
        return fps

    def _response_fingerprint(self, body: str, status: int | None = None) -> str:
        """Stable fingerprint with volatile support/request IDs stripped."""
        normalized = re.sub(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            "<uuid>",
            body[:4096],
            flags=re.IGNORECASE,
        )
        normalized = re.sub(r"\b[0-9a-f]{16,}\b", "<hex>", normalized, flags=re.IGNORECASE)
        normalized = re.sub(r"\b\d{6,}\b", "<num>", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        digest = hashlib.md5(normalized.encode(errors="ignore")).hexdigest()
        return f"{status or 0}:{digest}:{len(normalized)}"

    def _is_soft_404_body(self, body: str, status: int, fingerprints: set[str] | None) -> bool:
        """Return True when a response matches unknown-path baseline fingerprints."""
        if not fingerprints:
            return False
        return self._response_fingerprint(body, status) in fingerprints

    def _calculate_vpr(self, cvss_score: float, title: str) -> tuple[float | None, str | None]:
        """Calculate a lightweight VPR score when CVSS is available."""
        try:
            if cvss_score <= 0:
                return None, None
            from common.vpr import calculate_vpr
            score = calculate_vpr(cvss_score, vuln_type=self._infer_vuln_type(title))
            return round(score.vpr, 2), score.priority
        except Exception:
            if cvss_score >= 9.0:
                return cvss_score, "Critical"
            if cvss_score >= 7.0:
                return cvss_score, "High"
            if cvss_score >= 4.0:
                return cvss_score, "Medium"
            if cvss_score > 0:
                return cvss_score, "Low"
            return None, None

    def _infer_vuln_type(self, title: str) -> str:
        """Infer a VPR vuln type from the module name and title."""
        haystack = f"{self.NAME} {title}".lower()
        mappings = {
            "sqli": ("sqli", "sql injection"),
            "xss": ("xss", "cross-site scripting"),
            "ssti": ("ssti", "template injection"),
            "cmdi": ("cmdi", "command injection", "cmd injection"),
            "ssrf": ("ssrf",),
            "lfi": ("lfi", "local file inclusion"),
            "xxe": ("xxe",),
            "idor": ("idor",),
            "auth_bypass": ("auth bypass", "authentication bypass"),
            "rce": ("rce", "remote code execution"),
        }
        for vuln_type, needles in mappings.items():
            if any(needle in haystack for needle in needles):
                return vuln_type
        return ""

    def confirm_action(
        self,
        action: str,
        target: str,
        risk: str,
        on_confirm: Any = None,
        on_skip: Any = None,
        module: str | None = None,
    ) -> bool:
        """Collect human confirmation only after exact module authorization."""
        if not self.authorization_decision_id:
            self.log.warning(
                "Sensitive action denied: module authorization envelope is missing"
            )
            if on_skip:
                on_skip()
            return False
        return confirm(
            module=module or self.NAME,
            action=action,
            target=target,
            risk=risk,
            on_confirm=on_confirm,
            on_skip=on_skip,
        )

    def capture_screenshot(
        self,
        url: str,
        finding_id: str,
        highlight_js: str | None = None,
        cookies: list[dict] | None = None,
    ) -> str | None:
        """Capture a screenshot for POC evidence.

        Returns path to PNG, or None if screenshot unavailable.
        """
        try:
            from common.screenshot import capture
            return capture(
                url=url,
                output_dir=self._screenshot_dir,
                highlight_js=highlight_js,
                cookies=cookies,
                finding_id=finding_id,
            )
        except Exception as exc:
            self.log.debug("Screenshot unavailable: %s", exc)
            return None

    def _make_result(self, start_time: float, skipped: bool = False, skip_reason: str = "") -> ModuleResult:
        """Build a ModuleResult from accumulated findings."""
        policy_denial = (
            self.outbound_policy.last_denial_reason
            if self.outbound_policy is not None
            else ""
        )
        denial_reason = self._outbound_denied_reason or policy_denial
        if denial_reason and not skipped:
            skipped = True
            skip_reason = denial_reason
        duration = time.monotonic() - start_time
        if skipped:
            self._emit_event("module_skip", name=self.NAME, reason=skip_reason)
        else:
            self._emit_event(
                "module_complete", name=self.NAME,
                findings_count=len(self.findings), duration=duration,
            )
        return ModuleResult(
            module_name=self.NAME,
            findings=self.findings,
            errors=[denial_reason] if denial_reason else [],
            duration_s=duration,
            skipped=skipped,
            skip_reason=skip_reason,
        )

    def _emit_event(self, event_type_str: str, **data: Any) -> None:
        """Emit a dashboard event if event_bus is connected."""
        if not self._event_bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            et = EventType(event_type_str)
            self._event_bus.emit(Event(
                event_type=et, data=data, source=self.NAME, run_id=self.run_id,
            ))
        except (ValueError, ImportError) as exc:
            self.log.debug("Event emission skipped (%s): %s", event_type_str, exc)

    async def _spa_fingerprint(self, target: str) -> str | None:
        """Return MD5 fingerprint if the target uses SPA catch-all routing.

        GETs a random canary URL; if the server returns 200 (SPA rewrites
        all unknown paths to index.html), returns the body MD5 so callers
        can compare against it and skip findings that are just the SPA shell.
        Returns None if the server correctly 404s on unknown paths.

        Result is cached in config.extra so all modules in the same scan
        share it — only one HTTP probe is sent per target per scan run.
        """
        _cache_key = f"_spa_fp_cache\x00{target}"
        if _cache_key in self.config.extra:
            return self.config.extra[_cache_key]

        canary = f"{target}/_forge_probe_{uuid.uuid4().hex[:8]}"
        result: str | None = None
        try:
            async with self.http_session(timeout=5, include_auth=False) as session:
                async with session.get(
                    canary, allow_redirects=True,
                    timeout=5,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        result = hashlib.md5(body.encode()).hexdigest()
        except Exception:
            pass

        self.config.extra[_cache_key] = result  # cache even None to avoid re-probing
        return result

    def _is_spa_body(self, body: str, spa_fp: str | None) -> bool:
        """Return True when body matches the SPA catch-all fingerprint."""
        if spa_fp is None:
            return False
        return hashlib.md5(body.encode()).hexdigest() == spa_fp


class TestBaseModule:
    """Unit tests for base_module."""

    def test_module_requires_run(self) -> None:
        import inspect
        assert inspect.isabstract(BaseModule)

    def test_concrete_module(self, tmp_path: Path) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        class DummyModule(BaseModule):
            NAME = "dummy"
            DESCRIPTION = "Test module"
            PHASE = 1

            async def fixture_run(self) -> ModuleResult:
                start = time.monotonic()
                return self._make_result(start)

            async def run(self) -> ModuleResult:
                return await self.fixture_run()

        cfg = BaseForgeConfig(target="10.0.0.1")
        scope = Scope(["10.0.0.0/24"])
        session = create_db(tmp_path / "test.db")
        mod = DummyModule(cfg, scope, session, tmp_path)
        result = asyncio.run(mod.fixture_run())
        assert result.module_name == "dummy"
        assert result.findings == []
        session.close()
