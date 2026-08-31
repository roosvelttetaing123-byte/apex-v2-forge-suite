"""Canonical advisory boundary for ForgeBrain and attack-chain proposals.

This module deliberately owns no execution primitive.  It persists advisory
plans, resolves one exact accepted capability, evaluates deterministic policy,
consumes the existing action authorization, and asks Task 103 to create one
queued job without leasing or running it.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Protocol, Sequence

from sqlalchemy.orm import Session

from common.action_authorization import (
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    consume_authorization,
    validate_consumed_authorization,
)
from common.job_state import JobState, JobStateService
from common.credential_boundary import CredentialReference
from common.db import (
    PersistedRunTruthValidationError,
    get_authorization_consumption,
    list_findings_for_run,
    load_run_collection_truth,
    open_existing_db,
)
from common.redaction import is_sensitive_identifier, redact_text, redact_value
from common.evidence_custody import EvidenceCustodyStore
from common.retest import (
    HEADER_CSP_CHECK_ID,
    HEADER_CSP_PROOF_POLICY,
    HEADER_CSP_VERIFIER_VERSION,
)
from common.run_truth import run_collection_truth_attestation_payload
from common.schema_migrations import (
    BRAIN_TRUTH_SCHEMA_VERSION,
    CANONICAL_SCHEMA_VERSION,
)
from common.scope import canonical_target, decide_scope, safe_target_display
from common.verification_policy import registered_capability_entries
from common.version import VERSION


CAPABILITY_REGISTRY_VERSION = "forge-capability-registry-v1"
POLICY_ID = "forgebrain-action-policy"
POLICY_VERSION = "1.0.0"
ACTION_BOUNDARY = "forgebrain.action.create"
SUPPORTED_CAPABILITY_ID = "webforge:header_audit"
SUPPORTED_CAPABILITY_VERSION = HEADER_CSP_VERIFIER_VERSION
SUPPORTED_ENGINE = "webforge"
SUPPORTED_IMPLEMENTATION = "header_audit"
SUPPORTED_REFERENCE_SLICE = "header-audit-csp-v1"
SUPPORTED_SOURCE_DIGEST = (
    "sha256:5c2a0887403fbd0959ccd9e2a08cc9b5ac6d355305cb9511478f241509daad84"
)

MAX_PRECONDITIONS = 64
MAX_EVIDENCE_REFS = 64
MAX_PARAMETERS_BYTES = 16_384
MAX_RATIONALE_CHARS = 4_096
MAX_MODEL_PROJECTION_BYTES = 32_768
_SENSITIVE_INPUT_KEY = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|cookie|authorization|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|passphrase|credential|hash|session)"
)


class TruthBoundaryError(RuntimeError):
    """Base exception whose message contains only stable reason codes."""


class BoundaryDenied(TruthBoundaryError):
    pass


class BoundaryConflict(TruthBoundaryError):
    pass


class BoundaryPersistenceError(TruthBoundaryError):
    pass


class CapabilityReason(str, Enum):
    SUPPORTED = "supported"
    UNKNOWN = "unknown_capability"
    DISABLED = "disabled_capability"
    VERSION_MISSING = "version_missing"
    INCOMPATIBLE_VERSION = "incompatible_version"
    WRONG_ENGINE = "wrong_engine"
    WRONG_INPUT = "wrong_input_type"
    SOURCE_MISMATCH = "capability_source_mismatch"


class PolicyReason(str, Enum):
    ALLOWED = "allowed"
    CAPABILITY_REJECTED = "capability_rejected"
    OUT_OF_SCOPE = "out_of_scope"
    WRONG_SAFETY = "wrong_safety_mode"
    WRONG_INPUT = "wrong_input_contract"
    CREDENTIAL_FORBIDDEN = "credential_forbidden"
    EXTRA_MODULE = "extra_module_forbidden"
    MISSING_POLICY = "missing_policy"


class ExecutionOutcome(str, Enum):
    ADVISORY = "advisory"
    SIMULATION = "simulation"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELED = "canceled"
    TIMEOUT = "timeout"
    UNAUTHORIZED = "unauthorized"
    UNSUPPORTED = "unsupported"
    INCONCLUSIVE = "inconclusive"


def _now_iso(clock: Callable[[], float]) -> str:
    return datetime.fromtimestamp(clock(), timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _stable_id(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(material).hexdigest()[:32]}"


def _digest(value: Any) -> str:
    rendered = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return "sha256:" + hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _bounded_json(value: Any, *, maximum: int, field_name: str) -> str:
    rendered = json.dumps(
        redact_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    if len(rendered.encode("utf-8")) > maximum:
        raise BoundaryDenied(f"{field_name}_too_large")
    return rendered


def _safe_identifier(value: str, field_name: str) -> str:
    rendered = str(value or "").strip()
    if (
        not rendered
        or len(rendered) > 200
        or any(character.isspace() for character in rendered)
        or is_sensitive_identifier(rendered)
    ):
        raise BoundaryDenied(f"invalid_{field_name}")
    return rendered


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            bool(_SENSITIVE_INPUT_KEY.search(str(key)))
            or is_sensitive_identifier(str(key))
            or _contains_sensitive_key(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set)):
        return any(_contains_sensitive_key(item) for item in value)
    if isinstance(value, str):
        return is_sensitive_identifier(value) or redact_value(value) != value
    return False


def _opaque_evidence_ref(value: Any) -> str:
    rendered = str(value or "").strip()
    if (
        not rendered
        or len(rendered) > 500
        or is_sensitive_identifier(rendered)
        or not rendered.startswith(("artifact:", "sha256:"))
    ):
        return ""
    return rendered


@dataclass(frozen=True)
class CapabilityEntry:
    id: str
    version: str = ""
    engine: str = ""
    input_kind: str = ""
    safety: str = ""
    maturity: str = "experimental"
    implementation: str = ""
    reference_slice: str = ""
    source_digest: str = ""
    enabled: bool = True

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CapabilityEntry":
        capability_id = _safe_identifier(str(value.get("id", "")), "capability_id")
        engine = str(value.get("engine") or capability_id.split(":", 1)[0])
        source_digest = str(value.get("source_digest") or "")
        if source_digest and not re.fullmatch(r"sha256:[0-9a-f]{64}", source_digest):
            raise BoundaryDenied("invalid_capability_source_digest")
        return cls(
            id=capability_id,
            version=str(value.get("version") or ""),
            engine=_safe_identifier(engine, "engine"),
            input_kind=str(value.get("input_kind") or ""),
            safety=str(value.get("safety") or ""),
            maturity=str(value.get("maturity") or "experimental"),
            implementation=str(value.get("implementation") or ""),
            reference_slice=str(value.get("reference_slice") or ""),
            source_digest=source_digest,
            enabled=bool(value.get("enabled", True)),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CapabilitySnapshot:
    id: str
    registry_version: str
    registry_digest: str
    entries: tuple[CapabilityEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "registry_version": self.registry_version,
            "registry_digest": self.registry_digest,
            "entries": [entry.to_dict() for entry in self.entries],
        }


@dataclass(frozen=True)
class CapabilityResolution:
    supported: bool
    reason: str
    requested_id: str
    requested_version: str
    capability_id: str = ""
    capability_version: str = ""
    engine: str = ""
    input_kind: str = ""
    safety: str = ""
    maturity: str = ""
    registry_version: str = CAPABILITY_REGISTRY_VERSION
    registry_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CapabilityRegistry:
    """Exact deterministic view over the current classified inventory."""

    def __init__(self, entries: Iterable[CapabilityEntry]) -> None:
        indexed: dict[str, CapabilityEntry] = {}
        for entry in entries:
            if entry.id in indexed:
                raise BoundaryConflict("duplicate_capability_id")
            indexed[entry.id] = entry
        self._entries = indexed

    @classmethod
    def from_entries(cls, entries: Iterable[Mapping[str, Any]]) -> "CapabilityRegistry":
        return cls(CapabilityEntry.from_mapping(entry) for entry in entries)

    @classmethod
    def current(cls) -> "CapabilityRegistry":
        entries = {
            str(value["id"]): CapabilityEntry.from_mapping(value)
            for value in registered_capability_entries()
        }
        current = entries.get(SUPPORTED_CAPABILITY_ID)
        if current is None:
            raise BoundaryDenied(CapabilityReason.UNKNOWN.value)
        source = (
            Path(__file__).resolve().parents[2]
            / "webforge"
            / "modules"
            / "headers"
            / "header_audit.py"
        )
        actual_source_digest = (
            "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
            if source.is_file()
            else ""
        )
        # Task 104/105 supplies the exact verifier version and accepted source
        # digest.  Preserve the central maturity label; do not promote it.
        entries[SUPPORTED_CAPABILITY_ID] = CapabilityEntry(
            id=SUPPORTED_CAPABILITY_ID,
            version=SUPPORTED_CAPABILITY_VERSION,
            engine="webforge",
            input_kind="url",
            safety=SafetyMode.PASSIVE.value,
            maturity=current.maturity,
            implementation=SUPPORTED_IMPLEMENTATION,
            reference_slice=SUPPORTED_REFERENCE_SLICE,
            source_digest=actual_source_digest,
            enabled=current.maturity != "disabled",
        )
        return cls(entries.values())

    def snapshot(self) -> CapabilitySnapshot:
        entries = tuple(self._entries[key] for key in sorted(self._entries))
        payload = {
            "registry_version": CAPABILITY_REGISTRY_VERSION,
            "entries": [entry.to_dict() for entry in entries],
        }
        registry_digest = _digest(payload)
        return CapabilitySnapshot(
            id=_stable_id("cap-snapshot", CAPABILITY_REGISTRY_VERSION, registry_digest),
            registry_version=CAPABILITY_REGISTRY_VERSION,
            registry_digest=registry_digest,
            entries=entries,
        )

    def resolve(
        self,
        capability_id: str,
        capability_version: str,
        *,
        expected_engine: str | None = None,
        input_kind: str | None = None,
        source_digest: str | None = None,
    ) -> CapabilityResolution:
        requested_id = str(capability_id or "")
        requested_version = str(capability_version or "")
        snapshot = self.snapshot()
        entry = self._entries.get(requested_id)
        reason = CapabilityReason.SUPPORTED
        if entry is None:
            reason = CapabilityReason.UNKNOWN
        elif not entry.enabled or entry.maturity == "disabled":
            reason = CapabilityReason.DISABLED
        elif expected_engine is not None and entry.engine != expected_engine:
            reason = CapabilityReason.WRONG_ENGINE
        elif input_kind is not None and entry.input_kind != input_kind:
            reason = CapabilityReason.WRONG_INPUT
        elif not entry.version:
            reason = CapabilityReason.VERSION_MISSING
        elif not requested_version or requested_version != entry.version:
            reason = CapabilityReason.INCOMPATIBLE_VERSION
        elif source_digest is not None and not hmac.compare_digest(
            entry.source_digest, source_digest
        ):
            reason = CapabilityReason.SOURCE_MISMATCH
        supported = reason is CapabilityReason.SUPPORTED
        return CapabilityResolution(
            supported=supported,
            reason=reason.value,
            requested_id=requested_id,
            requested_version=requested_version,
            capability_id=entry.id if supported and entry is not None else "",
            capability_version=entry.version if supported and entry is not None else "",
            engine=entry.engine if entry is not None else "",
            input_kind=entry.input_kind if entry is not None else "",
            safety=entry.safety if entry is not None else "",
            maturity=entry.maturity if entry is not None else "",
            registry_digest=snapshot.registry_digest,
        )


@dataclass(frozen=True)
class AdvisoryPlan:
    tenant_id: str
    engagement_id: str
    source_id: str
    rationale: str
    target: str = ""
    source_kind: str = "finding"
    model_id: str = "forgebrain"
    model_version: str = "unversioned-advisory"
    planner_id: str = "attack-planner"
    planner_version: str = "1.0.0"
    state: str = ExecutionOutcome.ADVISORY.value
    revision: int = 1
    created_at: str = ""
    id: str = ""
    model_output: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.state not in {ExecutionOutcome.ADVISORY.value, ExecutionOutcome.SIMULATION.value}:
            raise BoundaryDenied("invalid_plan_state")
        if not self.id:
            object.__setattr__(
                self,
                "id",
                _stable_id(
                    "plan",
                    self.tenant_id,
                    self.engagement_id,
                    self.source_kind,
                    self.source_id,
                    self.revision,
                ),
            )
        object.__setattr__(self, "model_output", "")

    @property
    def advisory(self) -> bool:
        return True


@dataclass(frozen=True)
class AdvisoryPlanNode:
    plan_id: str
    capability_id: str
    capability_version: str
    target: str
    parameters: Mapping[str, Any]
    tenant_id: str = ""
    engagement_id: str = ""
    source_id: str = ""
    input_kind: str = "url"
    preconditions: tuple[str, ...] = ()
    rationale: str = ""
    state: str = ExecutionOutcome.ADVISORY.value
    resolution: CapabilityResolution | None = None
    idempotency_key: str = ""
    parameter_digest: str = ""
    request_digest: str = ""
    created_at: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        parameter_digest = self.parameter_digest or _digest(dict(self.parameters))
        object.__setattr__(self, "parameter_digest", parameter_digest)
        idempotency = self.idempotency_key or _stable_id(
            "plan-node-key", self.plan_id, self.capability_id, canonical_target(self.target), parameter_digest
        )
        object.__setattr__(self, "idempotency_key", idempotency)
        request_digest = self.request_digest or _digest(
            {
                "plan_id": self.plan_id,
                "capability_id": self.capability_id,
                "capability_version": self.capability_version,
                "target": canonical_target(self.target),
                "parameter_digest": parameter_digest,
                "input_kind": self.input_kind,
            }
        )
        object.__setattr__(self, "request_digest", request_digest)
        if not self.id:
            object.__setattr__(self, "id", _stable_id("plan-node", idempotency))

    @property
    def executable(self) -> bool:
        return False

    @property
    def authority_text(self) -> str:
        return "advisory only"


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    decision: str
    reason: str
    policy_id: str
    policy_version: str
    policy_digest: str
    tenant_id: str
    engagement_id: str
    node_id: str
    target_digest: str
    capability_id: str
    capability_version: str
    safety_mode: str
    parameter_digest: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ApprovalReference:
    id: str
    tenant_id: str
    engagement_id: str
    plan_id: str
    node_id: str
    action_id: str
    job_id: str
    operator_id: str
    operator_role: str
    target_digest: str
    capability_id: str
    capability_version: str
    safety_mode: str
    parameter_digest: str
    envelope_digest: str
    expires_at: str
    nonce: str
    idempotency_key: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CanonicalActionLink:
    tenant_id: str
    engagement_id: str
    plan_id: str
    node_id: str
    action_id: str
    job_id: str
    run_id: str
    attempt_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CanonicalActionRequest:
    tenant_id: str
    engagement_id: str
    plan_id: str
    node_id: str
    action_id: str
    job_id: str
    run_id: str
    capability_id: str
    capability_version: str
    target_digest: str
    target_display: str
    parameter_digest: str
    authorization_decision_id: str
    idempotency_key: str
    work_key: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OutcomeRecord:
    outcome: str
    tenant_id: str
    engagement_id: str
    node_id: str
    action_id: str = ""
    job_id: str = ""
    attempt_id: str = ""
    job_state: str = ""
    terminal_reason: str = ""
    signed_outcome_ref: str = ""
    evidence_refs: tuple[str, ...] = ()
    classification_source: str = "forgebrain-outcome-policy-v1"
    recorded_at: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        ExecutionOutcome(self.outcome)
        _safe_identifier(self.tenant_id, "tenant_id")
        _safe_identifier(self.engagement_id, "engagement_id")
        _safe_identifier(self.node_id, "node_id")
        if len(self.evidence_refs) > MAX_EVIDENCE_REFS:
            raise BoundaryDenied("too_many_evidence_refs")
        if any(not _opaque_evidence_ref(ref) for ref in self.evidence_refs):
            raise BoundaryDenied("invalid_evidence_reference")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NarrativeProjection:
    tenant_id: str
    engagement_id: str
    plan_id: str
    node_id: str
    capability_id: str
    capability_version: str
    target: str
    state: str
    outcome: str
    terminal_reason: str
    evidence_refs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CanonicalJobFactory(Protocol):
    def create_job(self, **kwargs: Any) -> Mapping[str, Any]: ...


class Task103InertJobFactory:
    """The sole production job adapter; it never leases or executes work."""

    def __init__(self, service: JobStateService) -> None:
        self.service = service

    def create_job(self, **kwargs: Any) -> Mapping[str, Any]:
        if kwargs.pop("inert", None) is not True:
            raise BoundaryDenied("inert_job_required")
        if kwargs.pop("acquire_lease", None) not in {False, None}:
            raise BoundaryDenied("lease_forbidden")
        return self.service.create_job(**kwargs)


def project_model_input(
    value: Mapping[str, Any], *, tenant_id: str, engagement_id: str
) -> dict[str, Any]:
    """Build one bounded allowlisted view for all external-model adapters."""

    allowed = {
        "finding_id", "observation_id", "title", "severity", "module",
        "framework", "target", "status", "confidence", "verification_state",
        "proof_type", "maturity", "description", "remediation", "capability_id",
        "capability_version", "rationale", "outcome", "reason_code", "event_type",
        "created_at", "credential_reference", "credential_type", "credential_count",
    }
    projected: dict[str, Any] = {
        "tenant_id": _safe_identifier(tenant_id, "tenant_id"),
        "engagement_id": _safe_identifier(engagement_id, "engagement_id"),
    }
    for key in sorted(allowed):
        if key not in value:
            continue
        item = value[key]
        if key == "credential_reference" and item:
            try:
                item = CredentialReference.parse(item).value
            except ValueError:
                continue
        if isinstance(item, (str, int, float, bool)) or item is None:
            rendered = redact_value(item)
            projected[key] = rendered[:4_096] if isinstance(rendered, str) else rendered
    # Preserve only evidence availability, never evidence bodies or
    # caller-controlled derivatives. This lets the model distinguish
    # unavailable evidence from canonical persisted evidence without exposing
    # requests, responses, artifact paths, or protected originals.
    evidence = value.get("evidence")
    if isinstance(evidence, Mapping):
        evidence_state = str(evidence.get("state") or "unavailable").strip().lower()
        if evidence_state not in {"persisted", "unavailable"}:
            evidence_state = "unavailable"
        observations = evidence.get("observations")
        observation_count = (
            min(len(observations), 10_000)
            if isinstance(observations, (list, tuple))
            else 0
        )
        projected["evidence"] = {
            "state": evidence_state,
            "observation_count": observation_count,
        }
    encoded = _bounded_json(
        projected, maximum=MAX_MODEL_PROJECTION_BYTES, field_name="model_projection"
    )
    return json.loads(encoded)


def advisory_narrative_projection(
    entries: Sequence[Mapping[str, Any]],
) -> str:
    """Render an inert narrative without publishing caller/model truth claims."""

    count = min(len(entries), 10_000)
    return (
        "# Attack Narrative\n\n"
        "**Advisory projection only.** This view does not assert that any "
        "network action, module execution, finding verification, evidence "
        "creation, or canonical completion occurred.\n\n"
        f"Recorded advisory entries: **{count}**.\n\n"
        "Observation detail withheld because caller-supplied result and "
        "verification labels are not canonical truth.\n\n"
        "Resolve exact action, job, attempt, signed outcome, observation, and "
        "artifact lineage from canonical Task 102/103 records before making "
        "an execution or evidence claim.\n"
    )


def advisory_report_projection(
    *, projection_kind: str, entry_count: int = 0
) -> str:
    """Render a bounded report notice without trusting generic caller records."""

    kind = _safe_identifier(projection_kind, "projection_kind").replace("_", " ")
    count = max(0, min(int(entry_count), 10_000))
    return (
        f"## {kind.title()}\n\n"
        "**Advisory projection only.** Generic caller or model records are not "
        "published as execution, finding verification, severity, evidence, or "
        "completion truth.\n\n"
        f"Submitted advisory records: **{count}**.\n\n"
        "Consult the canonical plan/action/job/attempt/outcome/observation/"
        "artifact projection for reportable facts.\n"
    )


def publishable_model_prose(model_output: str, *, projection_kind: str) -> str:
    """Apply a hard postcondition: raw model prose is never report authority."""

    del model_output
    return advisory_report_projection(
        projection_kind=projection_kind,
        entry_count=0,
    )


def model_cache_key(
    projection: Mapping[str, Any], *, provider: str, model: str, system_version: str
) -> str:
    return _digest(
        {
            "projection": dict(projection),
            "provider": str(provider),
            "model": str(model),
            "system_version": str(system_version),
        }
    )


def classify_terminal_outcome(
    job_state: str,
    *,
    signed_outcome: str = "",
    evidence_refs: Sequence[str] = (),
) -> tuple[ExecutionOutcome, str]:
    """Map persisted Task 103 truth without consulting narrative or events."""

    state = str(job_state or "").lower()
    if state == JobState.COMPLETED.value:
        if signed_outcome == "success" and tuple(evidence_refs):
            return ExecutionOutcome.SUCCESS, "signed_success_with_evidence"
        return (
            ExecutionOutcome.INCONCLUSIVE,
            "completed_without_signed_evidence_lineage",
        )
    if state == JobState.FAILED.value:
        return ExecutionOutcome.FAILED, "job_failed"
    if state == JobState.PARTIAL.value:
        return ExecutionOutcome.PARTIAL, "job_partial"
    if state == JobState.CANCELED.value:
        return ExecutionOutcome.CANCELED, "job_canceled"
    if state == JobState.EXPIRED.value:
        return ExecutionOutcome.TIMEOUT, "job_expired"
    if state == JobState.ORPHANED.value:
        return ExecutionOutcome.INCONCLUSIVE, "orphaned_unresolved"
    return ExecutionOutcome.INCONCLUSIVE, "job_not_terminal"


def validated_job_success(
    jobs: JobStateService,
    *,
    database_path: str | Path,
    tenant_id: str,
    job_id: str,
) -> Mapping[str, Any] | None:
    """Return signed/evidenced success or ``None`` from persisted authority."""

    job = jobs.get_job(job_id, tenant_id=tenant_id)
    if job is None or str(job.get("state") or "") != JobState.COMPLETED.value:
        return None
    attempts = jobs.list_attempts(job_id, tenant_id=tenant_id)
    if not attempts:
        return None
    attempt_id = str(attempts[-1].get("id") or "")
    proof = jobs.conn.execute(
        """
        SELECT outcome,result_ref,proof_identity
        FROM durable_job_state_terminal_proofs
        WHERE tenant_id=? AND job_id=? AND attempt_id=?
          AND proof_type='run_truth'
        ORDER BY recorded_at DESC LIMIT 1
        """,
        (tenant_id, job_id, attempt_id),
    ).fetchone()
    if proof is None:
        return None
    signed_ref = str(proof["result_ref"] or "")
    if str(proof["outcome"] or "") != "success" or not signed_ref.startswith(
        "run-truth:"
    ):
        return None
    session = open_existing_db(Path(database_path))
    try:
        truth = load_run_collection_truth(
            session,
            signed_ref.removeprefix("run-truth:"),
            tenant_id=tenant_id,
            verify_finding_set=True,
        )
        truth_finding_ids = {
            str(item.get("id") or "")
            for item in list_findings_for_run(
                session,
                signed_ref.removeprefix("run-truth:"),
                tenant_id=tenant_id,
            )
        }
    except PersistedRunTruthValidationError:
        return None
    finally:
        session.close()
    if truth is None:
        return None
    proof_identity = "sha256:" + hashlib.sha256(
        run_collection_truth_attestation_payload(truth)
        + truth.attestation.encode("ascii")
    ).hexdigest()
    if (
        truth.job_id != job_id
        or truth.authorization_run_id != str(job.get("run_id") or "")
        or not hmac.compare_digest(str(proof["proof_identity"]), proof_identity)
    ):
        return None
    payload = job.get("payload")
    payload_value = dict(payload) if isinstance(payload, Mapping) else {}
    plan_id = str(payload_value.get("plan_id") or "")
    node_id = str(payload_value.get("node_id") or "")
    action_id = str(job.get("authorization_action_id") or "")
    engagement_id = str(job.get("engagement_id") or "")
    run_id = str(job.get("run_id") or "")
    capability_id = str(payload_value.get("capability_id") or "")
    capability_version = str(payload_value.get("capability_version") or "")
    module_id = str(payload_value.get("module_id") or "")
    target_digest = str(payload_value.get("target_digest") or "")
    if (
        not plan_id
        or not node_id
        or not action_id
        or not engagement_id
        or not run_id
        or capability_id != SUPPORTED_CAPABILITY_ID
        or capability_version != SUPPORTED_CAPABILITY_VERSION
        or module_id != SUPPORTED_IMPLEMENTATION
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", target_digest)
        or truth.framework != SUPPORTED_ENGINE
        or truth.target_binding != target_digest
    ):
        return None
    node_row = jobs.conn.execute(
        """
        SELECT plan_id,action_id,job_id,requested_capability_id,
               requested_capability_version,target_digest,state
        FROM canonical_advisory_nodes
        WHERE tenant_id=? AND engagement_id=? AND id=?
        """,
        (tenant_id, engagement_id, node_id),
    ).fetchone()
    if (
        node_row is None
        or tuple(str(node_row[index] or "") for index in range(6))
        != (
            plan_id,
            action_id,
            job_id,
            capability_id,
            capability_version,
            target_digest,
        )
        or str(node_row["state"] or "") not in {"job_created", "terminal"}
    ):
        return None
    intent_row = jobs.conn.execute(
        """
        SELECT approval_decision_id,envelope_digest,boundary,status,
               action_id,job_id,run_id
        FROM canonical_advisory_action_intents
        WHERE tenant_id=? AND engagement_id=? AND node_id=?
        """,
        (tenant_id, engagement_id, node_id),
    ).fetchone()
    if (
        intent_row is None
        or str(intent_row["approval_decision_id"] or "")
        != str(job.get("authorization_decision_id") or "")
        or str(intent_row["approval_decision_id"] or "")
        != truth.authorization_decision_id
        or not hmac.compare_digest(
            str(intent_row["envelope_digest"] or ""),
            truth.authorization_binding,
        )
        or str(intent_row["boundary"] or "") != ACTION_BOUNDARY
        or str(intent_row["status"] or "") != "job_created"
        or str(intent_row["action_id"] or "") != action_id
        or str(intent_row["job_id"] or "") != job_id
        or str(intent_row["run_id"] or "") != run_id
        or str(job.get("authorization_action_id") or "") != action_id
    ):
        return None
    source_row = jobs.conn.execute(
        """
        SELECT mv.module_id,mv.version,mv.manifest_digest
        FROM canonical_advisory_nodes n
        JOIN canonical_module_versions mv
          ON mv.tenant_id=n.tenant_id AND mv.id=n.module_version_id
        WHERE n.tenant_id=? AND n.engagement_id=? AND n.id=?
        """,
        (tenant_id, engagement_id, node_id),
    ).fetchone()
    if source_row is None or tuple(str(item or "") for item in source_row) != (
        capability_id,
        capability_version,
        SUPPORTED_SOURCE_DIGEST,
    ):
        return None
    delivery_rows = jobs.conn.execute(
        """
            SELECT DISTINCT a.id AS artifact_id,a.reference,a.digest,
                   a.integrity_state,a.manifest_digest,
                   am.manifest_digest AS persisted_manifest_digest,
                   o.id AS observation_id,
                   o.status AS observation_status,o.action_id,
                   o.engagement_id,asset.identity_key AS asset_identity
            FROM durable_job_state_deliveries d
            JOIN canonical_observations o
              ON o.tenant_id=d.tenant_id
             AND o.id=d.observation_id
             AND o.job_id=d.job_id
             AND o.attempt_id=d.attempt_id
            JOIN canonical_artifact_refs a
              ON a.tenant_id=d.tenant_id
             AND a.id=d.artifact_id
             AND a.observation_id=d.observation_id
            JOIN canonical_artifact_manifests am
              ON am.tenant_id=a.tenant_id
             AND am.artifact_id=a.id
             AND am.observation_id=o.id
            JOIN canonical_assets asset
              ON asset.tenant_id=o.tenant_id
             AND asset.id=o.asset_id
            WHERE d.tenant_id=? AND d.job_id=? AND d.attempt_id=?
              AND d.state='accepted' AND d.outcome='success'
            ORDER BY o.id,asset.identity_key,a.reference
        """,
        (tenant_id, job_id, attempt_id),
    ).fetchall()
    if not delivery_rows:
        return None

    def target_matches(value: Any) -> bool:
        identity = str(value or "")
        if identity == target_digest:
            return True
        try:
            return hmac.compare_digest(canonical_target(identity), target_digest)
        except (TypeError, ValueError):
            return False

    custody_root = Path(database_path).parent / "evidence-custody"

    def custody_manifest_valid(row: Mapping[str, Any]) -> bool:
        artifact_id = str(row.get("artifact_id") or "")
        if not custody_root.is_dir() or artifact_id != str(row.get("reference") or ""):
            return False
        try:
            custody = EvidenceCustodyStore(
                custody_root,
                tenant_id,
                create=False,
            )
            manifest = custody.verify(artifact_id)
        except Exception:
            return False
        return (
            str(row.get("integrity_state") or "") == "sha256_verified"
            and str(row.get("manifest_digest") or "")
            == str(row.get("persisted_manifest_digest") or "")
            == manifest.manifest_digest
            and str(row.get("digest") or "") == manifest.sha256
        )

    def verified_finding_artifacts(
        finding_id: str, observation_id: str
    ) -> list[dict[str, str]] | None:
        if not custody_root.is_dir():
            return None
        rows = jobs.conn.execute(
            """
            SELECT oa.artifact_id,a.reference,a.digest,a.integrity_state,
                   a.manifest_digest,
                   am.manifest_digest AS persisted_manifest_digest,
                   am.metadata_json
            FROM canonical_finding_observations fo
            JOIN canonical_observation_artifacts oa
              ON oa.tenant_id=fo.tenant_id
             AND oa.observation_id=fo.observation_id
             AND oa.role<>'derivative'
            JOIN canonical_artifact_refs a
              ON a.tenant_id=oa.tenant_id AND a.id=oa.artifact_id
             AND a.observation_id=oa.observation_id
            JOIN canonical_artifact_manifests am
              ON am.tenant_id=a.tenant_id AND am.artifact_id=a.id
             AND am.observation_id=a.observation_id
            WHERE fo.tenant_id=? AND fo.finding_id=? AND fo.observation_id=?
            ORDER BY oa.sequence,oa.artifact_id
            """,
            (tenant_id, finding_id, observation_id),
        ).fetchall()
        if not rows:
            return None
        try:
            custody = EvidenceCustodyStore(
                custody_root,
                tenant_id,
                create=False,
            )
            artifacts: list[dict[str, str]] = []
            for row in rows:
                values = dict(row)
                if not custody_manifest_valid(values):
                    return None
                artifact_id = str(row["artifact_id"] or "")
                manifest = custody.verify(artifact_id)
                derivative = custody.read(artifact_id)[:16_384]
                metadata = json.loads(str(row["metadata_json"] or "{}"))
                if not isinstance(metadata, Mapping):
                    return None
                artifacts.append(
                    {
                        "artifact_id": artifact_id,
                        "capture_kind": str(metadata.get("capture_kind") or ""),
                        "derivative": redact_text(
                            derivative.decode("utf-8", errors="replace")
                        ),
                        "manifest_digest": manifest.manifest_digest,
                    }
                )
            return artifacts
        except Exception:
            return None

    lineage: list[dict[str, str]] = []
    evidence_refs: set[str] = set()
    for row in delivery_rows:
        reference = _opaque_evidence_ref(row["reference"])
        observation_id = str(row["observation_id"] or "")
        observation_status = str(row["observation_status"] or "")
        if (
            not reference
            or not observation_id
            or str(row["observation_status"] or "") != "observed"
            or not custody_manifest_valid(dict(row))
            or str(row["action_id"] or "") != action_id
            or str(row["engagement_id"] or "") != engagement_id
            or not target_matches(row["asset_identity"])
        ):
            return None
        evidence_refs.add(reference)
        lineage.append(
            {
                "plan_id": plan_id,
                "node_id": node_id,
                "action_id": action_id,
                "job_id": job_id,
                "attempt_id": attempt_id,
                "capability_id": capability_id,
                "capability_version": capability_version,
                "module_id": module_id,
                "target_digest": target_digest,
                "observation_id": observation_id,
                "observation_status": observation_status,
                "finding_id": "",
                "finding_status": "",
                "evidence_ref": reference,
            }
        )

    finding_rows = jobs.conn.execute(
        """
        SELECT DISTINCT a.reference,o.id AS observation_id,
               fo.finding_id,f.status AS finding_status,
               f.title AS finding_title,f.severity AS finding_severity,
               f.description AS finding_description,f.finding_key,f.created_at,
               o.status AS observation_status,o.action_id,o.engagement_id,
               o.check_id,o.proof_type,o.route,
               mv.version AS runtime_module_version,
               asset.identity_key AS asset_identity
        FROM canonical_observations o
        JOIN canonical_module_versions mv
          ON mv.tenant_id=o.tenant_id
         AND mv.id=o.module_version_id
        JOIN canonical_assets asset
          ON asset.tenant_id=o.tenant_id
         AND asset.id=o.asset_id
        JOIN canonical_finding_observations fo
          ON fo.tenant_id=o.tenant_id
         AND fo.observation_id=o.id
        JOIN canonical_findings f
          ON f.tenant_id=fo.tenant_id
         AND f.id=fo.finding_id
        JOIN canonical_artifact_refs a
          ON a.tenant_id=o.tenant_id
         AND a.observation_id=o.id
         AND a.id=COALESCE(fo.artifact_id,f.artifact_id)
        WHERE o.tenant_id=? AND o.job_id=? AND o.attempt_id=?
          AND mv.module_id=?
        ORDER BY o.id,fo.finding_id,a.reference
        """,
        (tenant_id, job_id, attempt_id, module_id),
    ).fetchall()
    delivery_observation_ids = {
        str(row["observation_id"] or "") for row in delivery_rows
    }
    if len(truth_finding_ids) > 1:
        return None
    matched_finding_ids: set[str] = set()
    for row in finding_rows:
        reference = _opaque_evidence_ref(row["reference"])
        observation_id = str(row["observation_id"] or "")
        finding_id = str(row["finding_id"] or "")
        finding_status = str(row["finding_status"] or "")
        runtime_version = str(row["runtime_module_version"] or "")
        if (
            not reference
            or not observation_id
            or not finding_id
            or observation_id in delivery_observation_ids
            or runtime_version != VERSION
            or str(row["observation_status"] or "") != "observed"
            or str(row["check_id"] or "") != HEADER_CSP_CHECK_ID
            or str(row["proof_type"] or "") != "passive"
            or str(row["finding_key"] or "") != HEADER_CSP_CHECK_ID
            or finding_status != "open"
            or not str(row["route"] or "").startswith("/")
            or str(row["action_id"] or "") != action_id
            or str(row["engagement_id"] or "") != engagement_id
            or not target_matches(row["asset_identity"])
        ):
            return None
        if finding_id not in truth_finding_ids:
            continue
        artifacts = verified_finding_artifacts(finding_id, observation_id)
        if artifacts is None:
            return None
        by_kind = {
            str(item.get("capture_kind") or ""): item
            for item in artifacts
            if isinstance(item, Mapping)
        }
        if len(by_kind) != len(artifacts) or not {
            "request", "response", "structured_proof"
        } <= set(by_kind):
            return None
        try:
            structured_proof = json.loads(
                str(by_kind["structured_proof"].get("derivative") or "")
            )
        except json.JSONDecodeError:
            return None
        if (
            not isinstance(structured_proof, Mapping)
            or structured_proof.get("check_id") != HEADER_CSP_CHECK_ID
            or structured_proof.get("proof_policy") != HEADER_CSP_PROOF_POLICY
            or structured_proof.get("proof_type") != "passive"
        ):
            return None
        artifact_ids = tuple(
            sorted(
                {
                    safe
                    for item in artifacts
                    if isinstance(item, Mapping)
                    and (safe := _opaque_evidence_ref(item.get("artifact_id")))
                }
            )
        )
        if len(artifact_ids) != len(artifacts):
            return None
        matched_finding_ids.add(finding_id)
        evidence_refs.update(artifact_ids)
        for artifact_reference in artifact_ids:
            lineage.append({
                "plan_id": plan_id,
                "node_id": node_id,
                "action_id": action_id,
                "job_id": job_id,
                "attempt_id": attempt_id,
                "capability_id": capability_id,
                "capability_version": capability_version,
                "module_id": module_id,
                "runtime_module_version": runtime_version,
                "check_id": HEADER_CSP_CHECK_ID,
                "proof_policy": str(structured_proof["proof_policy"]),
                "target_digest": target_digest,
                "observation_id": observation_id,
                "observation_status": str(row["observation_status"] or ""),
                "finding_id": finding_id,
                "finding_status": finding_status,
                "finding_title": str(row["finding_title"] or ""),
                "finding_severity": str(row["finding_severity"] or ""),
                "finding_description": str(row["finding_description"] or ""),
                "finding_created_at": str(row["created_at"] or ""),
                "verification_state": "candidate",
                "proof_type": "passive",
                "confidence": "UNVERIFIED",
                "maturity": "experimental",
                "evidence_ref": artifact_reference,
            })
    if matched_finding_ids != truth_finding_ids:
        return None
    if not evidence_refs or not lineage:
        return None
    return {
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "run_id": run_id,
        "canonical_plan_id": plan_id,
        "canonical_node_id": node_id,
        "canonical_action_id": action_id,
        "canonical_job_id": job_id,
        "canonical_attempt_id": attempt_id,
        "canonical_capability_id": capability_id,
        "canonical_capability_version": capability_version,
        "canonical_module_id": module_id,
        "canonical_runtime_module_version": VERSION,
        "canonical_target": target_digest,
        "canonical_target_display": str(job.get("target") or ""),
        "canonical_lineage": tuple(lineage),
        "canonical_outcome": "success",
        "signed_outcome_ref": signed_ref,
        "evidence_refs": tuple(sorted(evidence_refs)),
    }


class ForgeBrainTruthBoundary:
    """Persist and reconcile advisory plans against canonical Task 103 truth."""

    def __init__(
        self,
        *,
        database_path: str | Path,
        tenant_id: str,
        clock: Callable[[], float] | None = None,
        job_service: JobStateService | None = None,
        job_factory: CanonicalJobFactory | None = None,
        registry: CapabilityRegistry | None = None,
        failure_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.database_path = Path(database_path).resolve()
        self.tenant_id = _safe_identifier(tenant_id, "tenant_id")
        self.clock = clock or (lambda: datetime.now(timezone.utc).timestamp())
        self._owns_jobs = job_service is None
        self.jobs = job_service or JobStateService(self.database_path, clock=self.clock)
        self.conn: sqlite3.Connection = self.jobs.conn
        self.factory = job_factory or Task103InertJobFactory(self.jobs)
        self.registry = registry or CapabilityRegistry.current()
        self.failure_hook = failure_hook
        self._lock = threading.RLock()
        self._verify_schema()

    def close(self) -> None:
        if self._owns_jobs:
            self.jobs.close()

    def __enter__(self) -> "ForgeBrainTruthBoundary":
        return self

    def __exit__(self, *_args: Any) -> None:
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
        row = self.conn.execute(
            "SELECT state FROM canonical_migration_journal WHERE version=?",
            (BRAIN_TRUTH_SCHEMA_VERSION,),
        ).fetchone()
        if row is None or str(row[0]) != "applied":
            raise BoundaryPersistenceError("brain_truth_schema_missing")

    def _tenant(self, tenant_id: str | None) -> str:
        tenant = self.tenant_id if tenant_id is None else _safe_identifier(
            tenant_id, "tenant_id"
        )
        if tenant != self.tenant_id:
            raise BoundaryDenied("cross_tenant")
        return tenant

    def _failpoint(self, name: str) -> None:
        if self.failure_hook is not None:
            self.failure_hook(name)

    def _ensure_engagement(self, tenant: str, engagement_id: str) -> None:
        engagement = _safe_identifier(engagement_id, "engagement_id")
        stamp = _now_iso(self.clock)
        self.conn.execute(
            "INSERT OR IGNORE INTO canonical_tenants(id,schema_version,name,created_at,metadata_json) VALUES(?,?,?,?,?)",
            (tenant, CANONICAL_SCHEMA_VERSION, tenant, stamp, "{}"),
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO canonical_engagements(id,tenant_id,project_id,schema_version,name,status,created_at,metadata_json) VALUES(?,?,?,?,?,?,?,?)",
            (engagement, tenant, None, CANONICAL_SCHEMA_VERSION, engagement, "active", stamp, "{}"),
        )
        row = self.conn.execute(
            "SELECT tenant_id FROM canonical_engagements WHERE id=?", (engagement,)
        ).fetchone()
        if row is None or str(row[0]) != tenant:
            raise BoundaryConflict("engagement_identity_conflict")

    def _source(
        self,
        tenant: str,
        engagement_id: str,
        source_id: str,
        source_kind: str,
    ) -> tuple[str | None, str | None]:
        source = _safe_identifier(source_id, "source_id")
        if source_kind == "observation":
            row = self.conn.execute(
                "SELECT tenant_id,engagement_id FROM canonical_observations WHERE id=?",
                (source,),
            ).fetchone()
        elif source_kind == "finding":
            row = self.conn.execute(
                """
                SELECT f.tenant_id,o.engagement_id
                FROM canonical_findings f
                JOIN canonical_observations o
                  ON o.tenant_id=f.tenant_id AND o.id=f.observation_id
                WHERE f.id=?
                """,
                (source,),
            ).fetchone()
        else:
            raise BoundaryDenied("invalid_source_kind")
        if row is None:
            raise BoundaryDenied("source_not_found")
        if str(row[0]) != tenant:
            raise BoundaryDenied("cross_tenant_source")
        if str(row[1]) != engagement_id:
            raise BoundaryDenied("cross_engagement_source")
        return (source, None) if source_kind == "observation" else (None, source)

    def _persist_snapshot(self, tenant: str, snapshot: CapabilitySnapshot) -> str:
        snapshot_id = _stable_id(
            "cap-snapshot",
            tenant,
            snapshot.registry_version,
            snapshot.registry_digest,
        )
        entries_json = _bounded_json(
            [entry.to_dict() for entry in snapshot.entries],
            maximum=1_000_000,
            field_name="capability_snapshot",
        )
        self.conn.execute(
            """
            INSERT OR IGNORE INTO canonical_advisory_capability_snapshots(
                id,tenant_id,schema_version,registry_version,registry_digest,
                entries_json,created_at
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                snapshot_id,
                tenant,
                BRAIN_TRUTH_SCHEMA_VERSION,
                snapshot.registry_version,
                snapshot.registry_digest,
                entries_json,
                _now_iso(self.clock),
            ),
        )
        return snapshot_id

    def plan(
        self,
        *,
        source_id: str,
        capability_id: str,
        capability_version: str,
        target: str,
        parameters: Mapping[str, Any],
        engagement_id: str = "engagement-a",
        tenant_id: str | None = None,
        source_kind: str = "finding",
        rationale: str = "advisory proposal",
        model_id: str = "forgebrain",
        model_version: str = "unversioned-advisory",
        planner_id: str = "attack-planner",
        planner_version: str = "1.0.0",
        state: str = ExecutionOutcome.ADVISORY.value,
        revision: int = 1,
        supersedes_plan_id: str | None = None,
    ) -> AdvisoryPlan:
        tenant = self._tenant(tenant_id)
        engagement = _safe_identifier(engagement_id, "engagement_id")
        if not isinstance(parameters, Mapping) or _contains_sensitive_key(parameters):
            raise BoundaryDenied("secret_parameter_rejected")
        canonical_target(target)
        safe_rationale = redact_text(str(rationale))[:MAX_RATIONALE_CHARS]
        plan_id = _stable_id(
            "plan", tenant, engagement, source_kind, source_id, revision
        )
        stamp = _now_iso(self.clock)
        plan = AdvisoryPlan(
            id=plan_id,
            tenant_id=tenant,
            engagement_id=engagement,
            source_id=source_id,
            source_kind=source_kind,
            rationale=safe_rationale,
            target=target,
            model_id=_safe_identifier(model_id, "model_id"),
            model_version=_safe_identifier(model_version, "model_version"),
            planner_id=_safe_identifier(planner_id, "planner_id"),
            planner_version=_safe_identifier(planner_version, "planner_version"),
            state=state,
            revision=int(revision),
            created_at=stamp,
        )
        with self._tx():
            self._ensure_engagement(tenant, engagement)
            observation_id, finding_id = self._source(
                tenant, engagement, source_id, source_kind
            )
            existing = self.conn.execute(
                "SELECT * FROM canonical_advisory_plans WHERE tenant_id=? AND id=?",
                (tenant, plan.id),
            ).fetchone()
            identity = (
                engagement,
                observation_id,
                finding_id,
                canonical_target(target),
                int(revision),
            )
            if existing is not None:
                old = (
                    str(existing["engagement_id"]),
                    existing["source_observation_id"],
                    existing["source_finding_id"],
                    str(existing["target_digest"]),
                    int(existing["revision"]),
                )
                if old != identity:
                    raise BoundaryConflict("plan_identity_conflict")
                return plan
            if supersedes_plan_id:
                supersedes_plan_id = _safe_identifier(
                    supersedes_plan_id, "supersedes_plan_id"
                )
            self.conn.execute(
                """
                INSERT INTO canonical_advisory_plans(
                    id,tenant_id,engagement_id,schema_version,revision,
                    supersedes_plan_id,source_observation_id,source_finding_id,
                    target_digest,target_display,model_id,model_version,planner_id,
                    planner_version,state,created_at,revised_at,metadata_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    plan.id,
                    tenant,
                    engagement,
                    BRAIN_TRUTH_SCHEMA_VERSION,
                    int(revision),
                    supersedes_plan_id,
                    observation_id,
                    finding_id,
                    canonical_target(target),
                    safe_target_display(target),
                    plan.model_id,
                    plan.model_version,
                    plan.planner_id,
                    plan.planner_version,
                    state,
                    stamp,
                    stamp,
                    "{}",
                ),
            )
        # Capability fields are accepted only to make the next explicit node
        # construction deterministic; they are not plan authority.
        _safe_identifier(capability_id, "capability_id")
        if capability_version:
            _safe_identifier(capability_version, "capability_version")
        return plan

    def record_chain_advisory(
        self, record: Mapping[str, Any]
    ) -> AdvisoryPlanNode:
        """Persist an injected ChainEngine record as an untrusted advisory node."""

        tenant = self._tenant(str(record.get("tenant_id") or ""))
        engagement_id = _safe_identifier(
            str(record.get("engagement_id") or ""), "engagement_id"
        )
        source_finding = str(record.get("source_finding_id") or "")
        source_observation = str(record.get("source_observation_id") or "")
        if bool(source_finding) == bool(source_observation):
            raise BoundaryDenied("chain_source_lineage_required")
        source_id = source_finding or source_observation
        source_kind = "finding" if source_finding else "observation"
        requested_id = str(record.get("capability_id") or "")
        if not requested_id:
            requested_id = "legacy:" + _safe_identifier(
                str(record.get("next_module") or ""), "requested_module"
            )
        requested_version = str(record.get("capability_version") or "")
        target = str(record.get("target") or "")
        plan = self.plan(
            source_id=source_id,
            source_kind=source_kind,
            capability_id=requested_id,
            capability_version=requested_version,
            target=target,
            parameters={},
            engagement_id=engagement_id,
            rationale=str(record.get("description") or "chain advisory"),
            planner_id="chain-engine",
            planner_version="advisory-v1",
        )
        return self.node(
            plan,
            target=target,
            parameters={},
            capability_id=requested_id,
            capability_version=requested_version,
            input_kind="url" if target.startswith(("http://", "https://")) else "unknown",
            rationale=str(record.get("description") or "chain advisory"),
        )

    def node(
        self,
        plan: AdvisoryPlan,
        *,
        target: str,
        parameters: Mapping[str, Any],
        capability_id: str = SUPPORTED_CAPABILITY_ID,
        capability_version: str = SUPPORTED_CAPABILITY_VERSION,
        input_kind: str = "url",
        preconditions: Sequence[str] = (),
        rationale: str | None = None,
    ) -> AdvisoryPlanNode:
        tenant = self._tenant(plan.tenant_id)
        capability_id = _safe_identifier(capability_id, "capability_id")
        if capability_version:
            capability_version = _safe_identifier(
                capability_version, "capability_version"
            )
        if plan.engagement_id == "":
            raise BoundaryDenied("missing_engagement")
        if len(preconditions) > MAX_PRECONDITIONS:
            raise BoundaryDenied("too_many_preconditions")
        if not isinstance(parameters, Mapping) or _contains_sensitive_key(parameters):
            raise BoundaryDenied("secret_parameter_rejected")
        parameters_json = _bounded_json(
            dict(parameters), maximum=MAX_PARAMETERS_BYTES, field_name="parameters"
        )
        normalized_parameters = json.loads(parameters_json)
        resolution = self.registry.resolve(
            capability_id,
            capability_version,
            expected_engine="webforge",
            input_kind=input_kind,
            source_digest=SUPPORTED_SOURCE_DIGEST,
        )
        snapshot = self.registry.snapshot()
        safe_preconditions = tuple(redact_text(str(item))[:1_000] for item in preconditions)
        node = AdvisoryPlanNode(
            plan_id=plan.id,
            capability_id=capability_id,
            capability_version=capability_version,
            target=target,
            parameters=normalized_parameters,
            tenant_id=tenant,
            engagement_id=plan.engagement_id,
            source_id=plan.source_id,
            input_kind=input_kind,
            preconditions=safe_preconditions,
            rationale=redact_text(rationale or plan.rationale)[:MAX_RATIONALE_CHARS],
            state=(
                plan.state
                if resolution.supported
                else "rejected"
            ),
            resolution=resolution,
            created_at=_now_iso(self.clock),
        )
        with self._tx():
            snapshot_id = self._persist_snapshot(tenant, snapshot)
            existing = self.conn.execute(
                "SELECT request_digest FROM canonical_advisory_nodes WHERE tenant_id=? AND idempotency_key=?",
                (tenant, node.idempotency_key),
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(str(existing[0]), node.request_digest):
                    raise BoundaryConflict("node_idempotency_conflict")
                return node
            self.conn.execute(
                """
                INSERT INTO canonical_advisory_nodes(
                    id,tenant_id,engagement_id,plan_id,capability_snapshot_id,
                    schema_version,requested_capability_id,
                    requested_capability_version,resolved_capability_id,
                    resolved_capability_version,resolution_reason,target_digest,
                    target_display,input_kind,parameter_digest,parameters_json,
                    preconditions_json,rationale,state,policy_decision,
                    policy_reason,policy_id,policy_version,policy_digest,
                    approval_reference,scope_decision_id,action_id,job_id,
                    attempt_id,module_version_id,asset_id,
                    idempotency_key,request_digest,created_at,revised_at,metadata_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    node.id,
                    tenant,
                    plan.engagement_id,
                    plan.id,
                    snapshot_id,
                    BRAIN_TRUTH_SCHEMA_VERSION,
                    capability_id,
                    capability_version,
                    resolution.capability_id or None,
                    resolution.capability_version or None,
                    resolution.reason,
                    canonical_target(target),
                    safe_target_display(target),
                    input_kind,
                    node.parameter_digest,
                    parameters_json,
                    _bounded_json(
                        safe_preconditions,
                        maximum=64_000,
                        field_name="preconditions",
                    ),
                    node.rationale,
                    node.state,
                    "missing",
                    PolicyReason.MISSING_POLICY.value,
                    POLICY_ID,
                    POLICY_VERSION,
                    self.policy_digest,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    node.idempotency_key,
                    node.request_digest,
                    node.created_at,
                    node.created_at,
                    "{}",
                ),
            )
            if not resolution.supported:
                self._append_outcome_tx(
                    node,
                    ExecutionOutcome.UNSUPPORTED,
                    job_state="",
                    terminal_reason=resolution.reason,
                )
        return node

    @property
    def policy_digest(self) -> str:
        return _digest(
            {
                "policy_id": POLICY_ID,
                "policy_version": POLICY_VERSION,
                "capability": f"{SUPPORTED_CAPABILITY_ID}@{SUPPORTED_CAPABILITY_VERSION}",
                "safety": SafetyMode.PASSIVE.value,
                "parameters": {},
                "credentials": False,
                "extra_modules": False,
            }
        )

    def policy(
        self,
        node: AdvisoryPlanNode,
        *,
        allowed_scope: Iterable[str],
        excluded_scope: Iterable[str] = (),
        safety_mode: SafetyMode | str = SafetyMode.PASSIVE,
        credential_reference: str = "",
        modules: Sequence[str] = (SUPPORTED_IMPLEMENTATION,),
    ) -> PolicyDecision:
        tenant = self._tenant(node.tenant_id)
        resolution = node.resolution or self.registry.resolve(
            node.capability_id,
            node.capability_version,
            expected_engine="webforge",
            input_kind=node.input_kind,
            source_digest=SUPPORTED_SOURCE_DIGEST,
        )
        requested_safety = redact_text(
            str(getattr(safety_mode, "value", safety_mode))
        )[:100]
        try:
            normalized_safety = SafetyMode(requested_safety)
        except ValueError:
            normalized_safety = None
        reason = PolicyReason.ALLOWED
        if not resolution.supported:
            reason = PolicyReason.CAPABILITY_REJECTED
        elif node.state == ExecutionOutcome.SIMULATION.value:
            reason = PolicyReason.WRONG_INPUT
        elif normalized_safety is not SafetyMode.PASSIVE:
            reason = PolicyReason.WRONG_SAFETY
        elif credential_reference:
            reason = PolicyReason.CREDENTIAL_FORBIDDEN
        elif tuple(modules) != (SUPPORTED_IMPLEMENTATION,):
            reason = PolicyReason.EXTRA_MODULE
        elif dict(node.parameters):
            reason = PolicyReason.WRONG_INPUT
        elif not decide_scope(node.target, allowed_scope, excluded_scope).allowed:
            reason = PolicyReason.OUT_OF_SCOPE
        allowed = reason is PolicyReason.ALLOWED
        decision = PolicyDecision(
            allowed=allowed,
            decision="allow" if allowed else "deny",
            reason=reason.value,
            policy_id=POLICY_ID,
            policy_version=POLICY_VERSION,
            policy_digest=self.policy_digest,
            tenant_id=tenant,
            engagement_id=node.engagement_id,
            node_id=node.id,
            target_digest=canonical_target(node.target),
            capability_id=node.capability_id,
            capability_version=node.capability_version,
            safety_mode=requested_safety,
            parameter_digest=node.parameter_digest,
        )
        with self._tx():
            existing = self.conn.execute(
                "SELECT approval_reference,action_id,job_id FROM canonical_advisory_nodes WHERE tenant_id=? AND id=?",
                (tenant, node.id),
            ).fetchone()
            if existing is None:
                raise BoundaryPersistenceError("node_not_found")
            if any(existing):
                raise BoundaryConflict("approved_policy_is_immutable")
            cursor = self.conn.execute(
                """
                UPDATE canonical_advisory_nodes
                SET policy_decision=?,policy_reason=?,policy_id=?,policy_version=?,
                    policy_digest=?,state=?,revised_at=?
                WHERE tenant_id=? AND id=? AND request_digest=?
                """,
                (
                    decision.decision,
                    decision.reason,
                    decision.policy_id,
                    decision.policy_version,
                    decision.policy_digest,
                    "awaiting_approval" if allowed else "rejected",
                    _now_iso(self.clock),
                    tenant,
                    node.id,
                    node.request_digest,
                ),
            )
            if cursor.rowcount != 1:
                raise BoundaryPersistenceError("node_policy_update_failed")
            if not allowed:
                self._append_outcome_tx(
                    node,
                    (
                        ExecutionOutcome.UNSUPPORTED
                        if not resolution.supported
                        else ExecutionOutcome.UNAUTHORIZED
                    ),
                    job_state="",
                    terminal_reason=decision.reason,
                )
        return decision

    def action_context(
        self,
        node: AdvisoryPlanNode,
        decision: PolicyDecision,
        *,
        operator_id: str,
        operator_role: OperatorRole | str,
        allowed_scope: Iterable[str],
        excluded_scope: Iterable[str] = (),
        confirmed_by: str | None = None,
    ) -> AuthorizationContext:
        self._validated_policy(node, decision)
        operator = _safe_identifier(operator_id, "operator_id")
        job_id = _stable_id("job", node.tenant_id, node.id, node.idempotency_key)
        action_id = _stable_id("action", node.tenant_id, node.id, node.idempotency_key)
        run_id = _stable_id("run", node.tenant_id, node.id, node.idempotency_key)
        return AuthorizationContext(
            tenant_id=node.tenant_id,
            engagement_id=node.engagement_id,
            run_id=run_id,
            job_id=job_id,
            operator_id=operator,
            operator_role=operator_role,
            action_kind="forgebrain.reference_action",
            engine="webforge",
            module_id=SUPPORTED_IMPLEMENTATION,
            requested_target=node.target,
            resolved_target=node.target,
            allowed_scope=tuple(allowed_scope),
            excluded_scope=tuple(excluded_scope),
            scope_policy_version="forgebrain-scope-policy-v1",
            safety_mode=SafetyMode.PASSIVE,
            credential_approval_required=False,
            network_escalation_approval_required=False,
            high_risk_approval_required=False,
            confirmation_method=ConfirmationMethod.DASHBOARD,
            confirmed_by=confirmed_by or operator,
            credential_reference="",
        )

    def _validated_policy(
        self, node: AdvisoryPlanNode, decision: PolicyDecision
    ) -> sqlite3.Row:
        tenant = self._tenant(node.tenant_id)
        row = self.conn.execute(
            "SELECT * FROM canonical_advisory_nodes WHERE tenant_id=? AND id=?",
            (tenant, node.id),
        ).fetchone()
        current_resolution = self.registry.resolve(
            node.capability_id,
            node.capability_version,
            expected_engine="webforge",
            input_kind=node.input_kind,
            source_digest=SUPPORTED_SOURCE_DIGEST,
        )
        snapshot = (
            self.conn.execute(
                "SELECT registry_digest FROM canonical_advisory_capability_snapshots WHERE tenant_id=? AND id=?",
                (tenant, str(row["capability_snapshot_id"])),
            ).fetchone()
            if row is not None
            else None
        )
        exact = (
            row is not None
            and current_resolution.supported
            and snapshot is not None
            and hmac.compare_digest(
                str(snapshot[0]), current_resolution.registry_digest
            )
            and decision.allowed
            and decision.decision == "allow"
            and decision.reason == PolicyReason.ALLOWED.value
            and decision.tenant_id == tenant
            and decision.engagement_id == node.engagement_id
            and decision.node_id == node.id
            and decision.target_digest == canonical_target(node.target)
            and decision.capability_id == node.capability_id
            and decision.capability_version == node.capability_version
            and decision.safety_mode == SafetyMode.PASSIVE.value
            and decision.parameter_digest == node.parameter_digest
            and decision.policy_id == POLICY_ID
            and decision.policy_version == POLICY_VERSION
            and hmac.compare_digest(decision.policy_digest, self.policy_digest)
            and str(row["policy_decision"]) == "allow"
            and str(row["policy_reason"]) == PolicyReason.ALLOWED.value
            and hmac.compare_digest(str(row["policy_digest"]), self.policy_digest)
            and str(row["resolution_reason"]) == CapabilityReason.SUPPORTED.value
            and hmac.compare_digest(str(row["request_digest"]), node.request_digest)
        )
        if not exact:
            raise BoundaryDenied("policy_not_allowed")
        return row

    def bind_approval(
        self,
        node: AdvisoryPlanNode,
        decision: PolicyDecision,
        *,
        session: Session,
        envelope: ActionAuthorizationEnvelope | Mapping[str, Any],
        expected: AuthorizationContext,
        nonce: str,
        boundary: str = ACTION_BOUNDARY,
    ) -> ApprovalReference:
        tenant = self._tenant(node.tenant_id)
        if boundary != ACTION_BOUNDARY:
            raise BoundaryDenied("action_boundary_mismatch")
        self._validated_policy(node, decision)
        if expected.tenant_id != tenant or expected.engagement_id != node.engagement_id:
            raise BoundaryDenied("approval_context_mismatch")
        record = ActionAuthorizationEnvelope.from_value(envelope)
        if (
            record.tenant_id != tenant
            or record.engagement_id != node.engagement_id
            or record.job_id != expected.job_id
            or record.run_id != expected.run_id
            or record.operator_id != expected.operator_id
            or record.action_kind != expected.action_kind
            or record.engine != "webforge"
            or record.module_id != SUPPORTED_IMPLEMENTATION
            or record.safety_mode != SafetyMode.PASSIVE.value
            or not hmac.compare_digest(record.requested_target, canonical_target(node.target))
            or not hmac.compare_digest(record.resolved_target, canonical_target(node.target))
        ):
            raise BoundaryDenied("approval_binding_mismatch")
        if record.decision_outcome != "allow":
            with self._tx():
                self.conn.execute(
                    "UPDATE canonical_advisory_nodes SET state='rejected',revised_at=? WHERE tenant_id=? AND id=?",
                    (_now_iso(self.clock), tenant, node.id),
                )
                self._append_outcome_tx(
                    node,
                    ExecutionOutcome.UNAUTHORIZED,
                    job_state="",
                    terminal_reason=record.reason_code,
                )
            raise BoundaryDenied("authorization_denied")
        nonce_value = _safe_identifier(nonce, "approval_nonce")
        intent_id = _stable_id("action-intent", tenant, node.id, node.idempotency_key)
        stamp = _now_iso(self.clock)
        with self._tx():
            existing = self.conn.execute(
                "SELECT * FROM canonical_advisory_action_intents WHERE tenant_id=? AND node_id=?",
                (tenant, node.id),
            ).fetchone()
            exact = (
                existing is not None
                and hmac.compare_digest(str(existing["request_digest"]), node.request_digest)
                and hmac.compare_digest(str(existing["envelope_digest"]), record.binding_digest)
                and str(existing["action_id"]) == record.action_id
                and str(existing["job_id"]) == record.job_id
                and str(existing["run_id"]) == record.run_id
                and str(existing["approval_decision_id"]) == record.decision_id
                and str(existing["operator_id"]) == record.operator_id
                and str(existing["operator_role"]) == record.operator_role
                and hmac.compare_digest(
                    str(existing["parameter_digest"]), node.parameter_digest
                )
                and str(existing["boundary"]) == ACTION_BOUNDARY
                and str(existing["nonce"]) == nonce_value
                and str(existing["idempotency_key"]) == node.idempotency_key
                and str(existing["expires_at"]) == record.expires_at
            )
            if existing is not None and not exact:
                raise BoundaryConflict("approval_intent_conflict")
            if existing is None:
                self.conn.execute(
                    """
                    INSERT INTO canonical_advisory_action_intents(
                        id,tenant_id,engagement_id,node_id,schema_version,
                        action_id,job_id,run_id,approval_decision_id,operator_id,
                        operator_role,request_digest,
                        parameter_digest,envelope_digest,boundary,nonce,
                        idempotency_key,expires_at,status,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        intent_id,
                        tenant,
                        node.engagement_id,
                        node.id,
                        BRAIN_TRUTH_SCHEMA_VERSION,
                        record.action_id,
                        record.job_id,
                        expected.run_id,
                        record.decision_id,
                        record.operator_id,
                        record.operator_role,
                        node.request_digest,
                        node.parameter_digest,
                        record.binding_digest,
                        ACTION_BOUNDARY,
                        nonce_value,
                        node.idempotency_key,
                        record.expires_at,
                        "prepared",
                        stamp,
                        stamp,
                    ),
                )
        existing_status = self.conn.execute(
            "SELECT status FROM canonical_advisory_action_intents WHERE tenant_id=? AND node_id=?",
            (tenant, node.id),
        ).fetchone()
        if existing_status is None:
            raise BoundaryPersistenceError("approval_intent_missing")
        if str(existing_status[0]) == "rejected":
            raise BoundaryDenied("authorization_denied")
        self._failpoint("after_intent")
        if str(existing_status[0]) == "prepared":
            consumption = get_authorization_consumption(
                session, record.decision_id
            )
            if consumption is None:
                auth_decision = consume_authorization(
                    session=session,
                    envelope=record,
                    expected=expected,
                    boundary=ACTION_BOUNDARY,
                    now=datetime.fromtimestamp(self.clock(), timezone.utc),
                )
            else:
                auth_decision = validate_consumed_authorization(
                    session=session,
                    envelope=record,
                    expected=expected,
                    boundary=ACTION_BOUNDARY,
                    now=datetime.fromtimestamp(self.clock(), timezone.utc),
                )
        else:
            auth_decision = validate_consumed_authorization(
                session=session,
                envelope=record,
                expected=expected,
                boundary=ACTION_BOUNDARY,
                now=datetime.fromtimestamp(self.clock(), timezone.utc),
            )
        if not auth_decision.allowed:
            with self._tx():
                self.conn.execute(
                    "UPDATE canonical_advisory_action_intents SET status='rejected',updated_at=? WHERE tenant_id=? AND node_id=?",
                    (_now_iso(self.clock), tenant, node.id),
                )
                self.conn.execute(
                    "UPDATE canonical_advisory_nodes SET state='rejected',revised_at=? WHERE tenant_id=? AND id=?",
                    (_now_iso(self.clock), tenant, node.id),
                )
                self._append_outcome_tx(
                    node,
                    ExecutionOutcome.UNAUTHORIZED,
                    job_state="",
                    terminal_reason=auth_decision.reason_code,
                )
            raise BoundaryDenied("authorization_denied")
        self._failpoint("after_consume")
        with self._tx():
            self.conn.execute(
                "UPDATE canonical_advisory_action_intents SET status='consumed',updated_at=? WHERE tenant_id=? AND node_id=? AND status='prepared'",
                (_now_iso(self.clock), tenant, node.id),
            )
            self.conn.execute(
                "UPDATE canonical_advisory_nodes SET approval_reference=?,state='approved',revised_at=? WHERE tenant_id=? AND id=?",
                (record.decision_id, _now_iso(self.clock), tenant, node.id),
            )
        return ApprovalReference(
            id=record.decision_id,
            tenant_id=tenant,
            engagement_id=node.engagement_id,
            plan_id=node.plan_id,
            node_id=node.id,
            action_id=record.action_id,
            job_id=record.job_id,
            operator_id=record.operator_id,
            operator_role=record.operator_role,
            target_digest=canonical_target(node.target),
            capability_id=node.capability_id,
            capability_version=node.capability_version,
            safety_mode=record.safety_mode,
            parameter_digest=node.parameter_digest,
            envelope_digest=record.binding_digest,
            expires_at=record.expires_at,
            nonce=nonce_value,
            idempotency_key=node.idempotency_key,
        )

    def create_action(
        self,
        node: AdvisoryPlanNode,
        approval: ApprovalReference,
    ) -> CanonicalActionLink:
        tenant = self._tenant(node.tenant_id)
        if (
            approval.tenant_id != tenant
            or approval.engagement_id != node.engagement_id
            or approval.plan_id != node.plan_id
            or approval.node_id != node.id
            or approval.target_digest != canonical_target(node.target)
            or approval.capability_id != node.capability_id
            or approval.capability_version != node.capability_version
            or approval.parameter_digest != node.parameter_digest
            or approval.idempotency_key != node.idempotency_key
        ):
            raise BoundaryDenied("approval_reference_mismatch")
        stored_node = self.conn.execute(
            "SELECT * FROM canonical_advisory_nodes WHERE tenant_id=? AND id=?",
            (tenant, node.id),
        ).fetchone()
        if (
            stored_node is None
            or str(stored_node["resolution_reason"])
            != CapabilityReason.SUPPORTED.value
            or str(stored_node["policy_decision"]) != "allow"
            or not hmac.compare_digest(
                str(stored_node["policy_digest"]), self.policy_digest
            )
            or str(stored_node["approval_reference"] or "") != approval.id
            or str(stored_node["state"]) not in {"approved", "job_created"}
        ):
            raise BoundaryDenied("approved_node_state_missing")
        intent = self.conn.execute(
            "SELECT * FROM canonical_advisory_action_intents WHERE tenant_id=? AND node_id=?",
            (tenant, node.id),
        ).fetchone()
        if intent is None or not hmac.compare_digest(
            str(intent["envelope_digest"]), approval.envelope_digest
        ):
            raise BoundaryDenied("approval_intent_missing")
        if (
            str(intent["approval_decision_id"]) != approval.id
            or str(intent["action_id"]) != approval.action_id
            or str(intent["job_id"]) != approval.job_id
            or str(intent["operator_id"]) != approval.operator_id
            or str(intent["operator_role"]) != approval.operator_role
            or str(intent["expires_at"]) != approval.expires_at
            or str(intent["nonce"]) != approval.nonce
            or str(intent["idempotency_key"]) != approval.idempotency_key
            or str(intent["boundary"]) != ACTION_BOUNDARY
        ):
            raise BoundaryDenied("approval_reference_mismatch")
        if str(intent["status"]) not in {"consumed", "job_created"}:
            raise BoundaryDenied("approval_not_consumed")
        request = CanonicalActionRequest(
            tenant_id=tenant,
            engagement_id=node.engagement_id,
            plan_id=node.plan_id,
            node_id=node.id,
            action_id=approval.action_id,
            job_id=approval.job_id,
            run_id=str(intent["run_id"]),
            capability_id=node.capability_id,
            capability_version=node.capability_version,
            target_digest=canonical_target(node.target),
            target_display=safe_target_display(node.target),
            parameter_digest=node.parameter_digest,
            authorization_decision_id=approval.id,
            idempotency_key=f"forgebrain:{node.idempotency_key}",
            work_key=SUPPORTED_ENGINE,
        )
        expected_payload = {
            "reference_slice": SUPPORTED_REFERENCE_SLICE,
            "plan_id": request.plan_id,
            "node_id": request.node_id,
            "capability_id": request.capability_id,
            "capability_version": request.capability_version,
            "module_id": SUPPORTED_IMPLEMENTATION,
            "target_digest": request.target_digest,
            "parameter_digest": request.parameter_digest,
        }
        expected_metadata = {"inert_until_worker_authority": True}
        existing = self.jobs.get_job(approval.job_id, tenant_id=tenant)
        if existing is None:
            self.factory.create_job(
                payload=expected_payload,
                tenant_id=request.tenant_id,
                job_id=request.job_id,
                engagement_id=request.engagement_id,
                run_id=request.run_id,
                job_kind="forgebrain.reference_action",
                target=request.target_display,
                authorization_decision_id=request.authorization_decision_id,
                authorization_action_id=request.action_id,
                authorization_bindings=(
                    {
                        "authorization_decision_id": approval.id,
                        "authorization_action_id": approval.action_id,
                        "framework": SUPPORTED_ENGINE,
                    },
                ),
                idempotency_key=request.idempotency_key,
                max_attempts=1,
                work_items=(request.work_key,),
                state=JobState.QUEUED,
                metadata=expected_metadata,
                actor="operator",
                reason="exact ForgeBrain advisory action approved",
                inert=True,
                acquire_lease=False,
            )
            persisted = self.jobs.get_job(approval.job_id, tenant_id=tenant)
            if persisted is None:
                raise BoundaryPersistenceError(
                    "canonical_job_factory_did_not_persist"
                )
            existing = dict(persisted)
            self._failpoint("after_job_create")
        job_bindings = self.jobs.conn.execute(
            """
            SELECT authorization_decision_id,authorization_action_id,framework,
                   active
            FROM durable_job_state_job_authorizations
            WHERE tenant_id=? AND job_id=?
            ORDER BY authorization_decision_id,authorization_action_id,framework
            """,
            (tenant, request.job_id),
        ).fetchall()
        work_items = self.jobs.coverage_snapshot(
            request.job_id, tenant_id=tenant
        ).get("items") or ()
        existing_payload = existing.get("payload")
        existing_metadata = existing.get("metadata")
        exact_existing_job = (
            str(existing.get("id") or "") == request.job_id
            and str(existing.get("tenant_id") or "") == request.tenant_id
            and str(existing.get("engagement_id") or "") == request.engagement_id
            and str(existing.get("run_id") or "") == request.run_id
            and str(existing.get("job_kind") or "")
            == "forgebrain.reference_action"
            and str(existing.get("target") or "") == request.target_display
            and str(existing.get("authorization_decision_id") or "")
            == request.authorization_decision_id
            and str(existing.get("authorization_action_id") or "")
            == request.action_id
            and str(existing.get("idempotency_key") or "")
            == request.idempotency_key
            and int(existing.get("max_attempts") or 0) == 1
            and existing.get("assigned_agent_id") is None
            and isinstance(existing_payload, Mapping)
            and dict(existing_payload) == expected_payload
            and isinstance(existing_metadata, Mapping)
            and dict(existing_metadata) == expected_metadata
            and len(job_bindings) == 1
            and tuple(str(item) for item in job_bindings[0])
            == (approval.id, approval.action_id, SUPPORTED_ENGINE, "1")
            and isinstance(work_items, (list, tuple))
            and len(work_items) == 1
            and str(work_items[0].get("work_key") or "") == request.work_key
            and bool(work_items[0].get("required"))
        )
        if not exact_existing_job:
            raise BoundaryConflict("canonical_job_identity_conflict")
        with self._tx():
            scope_decision_id, module_version_id, asset_id = (
                self._ensure_canonical_action_context_tx(node, approval)
            )
            self.conn.execute(
                """
                INSERT OR IGNORE INTO canonical_actions(
                    id,tenant_id,engagement_id,job_id,schema_version,
                    action_kind,authorization_decision_id,created_at,metadata_json
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    approval.action_id,
                    tenant,
                    node.engagement_id,
                    approval.job_id,
                    CANONICAL_SCHEMA_VERSION,
                    "forgebrain.reference_action",
                    scope_decision_id,
                    _now_iso(self.clock),
                    "{}",
                ),
            )
            action = self.conn.execute(
                "SELECT tenant_id,engagement_id,job_id,action_kind FROM canonical_actions WHERE id=?",
                (approval.action_id,),
            ).fetchone()
            if action is None or tuple(str(item) for item in action) != (
                tenant,
                node.engagement_id,
                approval.job_id,
                "forgebrain.reference_action",
            ):
                raise BoundaryConflict("canonical_action_identity_conflict")
            self.conn.execute(
                "UPDATE canonical_advisory_action_intents SET status='job_created',updated_at=? WHERE tenant_id=? AND node_id=?",
                (_now_iso(self.clock), tenant, node.id),
            )
            self.conn.execute(
                """
                UPDATE canonical_advisory_nodes
                SET scope_decision_id=?,action_id=?,job_id=?,module_version_id=?,
                    asset_id=?,state='job_created',revised_at=?
                WHERE tenant_id=? AND id=? AND request_digest=?
                """,
                (
                    scope_decision_id,
                    approval.action_id,
                    approval.job_id,
                    module_version_id,
                    asset_id,
                    _now_iso(self.clock),
                    tenant,
                    node.id,
                    node.request_digest,
                ),
            )
        self._failpoint("after_link")
        return CanonicalActionLink(
            tenant_id=tenant,
            engagement_id=node.engagement_id,
            plan_id=node.plan_id,
            node_id=node.id,
            action_id=approval.action_id,
            job_id=approval.job_id,
            run_id=str(intent["run_id"]),
        )

    def _ensure_canonical_action_context_tx(
        self,
        node: AdvisoryPlanNode,
        approval: ApprovalReference,
    ) -> tuple[str, str, str]:
        """Create exact canonical operator/scope/module/asset identities."""

        tenant = node.tenant_id
        stamp = _now_iso(self.clock)
        operator_id = _stable_id(
            "operator", tenant, approval.operator_id
        )
        role_id = _stable_id("role", tenant, approval.operator_role)
        scope_decision_id = _stable_id(
            "scope-decision",
            tenant,
            node.id,
            self.policy_digest,
            approval.id,
        )
        module_version_id = _stable_id(
            "module-version",
            tenant,
            node.capability_id,
            node.capability_version,
            SUPPORTED_SOURCE_DIGEST,
        )
        asset_id = _stable_id(
            "asset", tenant, canonical_target(node.target)
        )
        self.conn.execute(
            """
            INSERT OR IGNORE INTO canonical_operators(
                id,tenant_id,schema_version,display_name,external_ref,
                created_at,metadata_json
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                operator_id,
                tenant,
                CANONICAL_SCHEMA_VERSION,
                redact_text(approval.operator_id)[:200],
                approval.operator_id,
                stamp,
                "{}",
            ),
        )
        self.conn.execute(
            """
            INSERT OR IGNORE INTO canonical_roles(
                id,tenant_id,schema_version,name,created_at,metadata_json
            ) VALUES(?,?,?,?,?,?)
            """,
            (
                role_id,
                tenant,
                CANONICAL_SCHEMA_VERSION,
                approval.operator_role,
                stamp,
                "{}",
            ),
        )
        self.conn.execute(
            """
            INSERT OR IGNORE INTO canonical_scope_decisions(
                id,tenant_id,engagement_id,operator_id,role_id,schema_version,
                outcome,policy_version,decision_reason,decided_at,created_at,
                metadata_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                scope_decision_id,
                tenant,
                node.engagement_id,
                operator_id,
                role_id,
                CANONICAL_SCHEMA_VERSION,
                "allow",
                POLICY_VERSION,
                "exact Task 106 capability and scope policy allowed",
                stamp,
                stamp,
                "{}",
            ),
        )
        self.conn.execute(
            """
            INSERT OR IGNORE INTO canonical_module_versions(
                id,tenant_id,schema_version,module_id,version,module_kind,
                manifest_digest,policy_version,intelligence_snapshot_id,
                check_pack_snapshot_id,provenance_id,created_at,metadata_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                module_version_id,
                tenant,
                CANONICAL_SCHEMA_VERSION,
                node.capability_id,
                node.capability_version,
                "passive",
                SUPPORTED_SOURCE_DIGEST,
                POLICY_VERSION,
                None,
                None,
                None,
                stamp,
                "{}",
            ),
        )
        self.conn.execute(
            """
            INSERT OR IGNORE INTO canonical_assets(
                id,tenant_id,schema_version,kind,identity_key,display_name,
                canonical_uri,created_at,metadata_json
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                asset_id,
                tenant,
                CANONICAL_SCHEMA_VERSION,
                "url",
                canonical_target(node.target),
                safe_target_display(node.target),
                None,
                stamp,
                "{}",
            ),
        )
        expected_rows = (
            (
                "canonical_scope_decisions",
                scope_decision_id,
                ("tenant_id", "engagement_id", "outcome"),
                (tenant, node.engagement_id, "allow"),
            ),
            (
                "canonical_module_versions",
                module_version_id,
                ("tenant_id", "module_id", "version", "manifest_digest"),
                (
                    tenant,
                    node.capability_id,
                    node.capability_version,
                    SUPPORTED_SOURCE_DIGEST,
                ),
            ),
            (
                "canonical_assets",
                asset_id,
                ("tenant_id", "kind", "identity_key"),
                (tenant, "url", canonical_target(node.target)),
            ),
        )
        for table, identifier, columns, expected in expected_rows:
            row = self.conn.execute(
                f"SELECT {','.join(columns)} FROM {table} WHERE id=?",
                (identifier,),
            ).fetchone()
            if row is None or tuple(str(item) for item in row) != expected:
                raise BoundaryConflict("canonical_action_context_conflict")
        return scope_decision_id, module_version_id, asset_id

    def _append_outcome_tx(
        self,
        node: AdvisoryPlanNode,
        outcome: ExecutionOutcome,
        *,
        job_state: str,
        terminal_reason: str,
        action_id: str = "",
        job_id: str = "",
        attempt_id: str = "",
        signed_outcome_ref: str = "",
        evidence_refs: Sequence[str] = (),
    ) -> OutcomeRecord:
        if len(evidence_refs) > MAX_EVIDENCE_REFS:
            raise BoundaryDenied("too_many_evidence_refs")
        refs = tuple(
            sorted(
                {
                    safe
                    for ref in evidence_refs
                    if (safe := _opaque_evidence_ref(ref))
                }
            )
        )
        stamp = _now_iso(self.clock)
        outcome_id = _stable_id(
            "advisory-outcome",
            node.tenant_id,
            node.id,
            outcome.value,
            job_state,
            attempt_id,
            signed_outcome_ref,
            _digest(refs),
        )
        record = OutcomeRecord(
            id=outcome_id,
            outcome=outcome.value,
            tenant_id=node.tenant_id,
            engagement_id=node.engagement_id,
            node_id=node.id,
            action_id=action_id,
            job_id=job_id,
            attempt_id=attempt_id,
            job_state=job_state,
            terminal_reason=redact_text(str(terminal_reason))[:1_000],
            signed_outcome_ref=signed_outcome_ref,
            evidence_refs=refs,
            recorded_at=stamp,
        )
        self.conn.execute(
            """
            INSERT OR IGNORE INTO canonical_advisory_outcomes(
                id,tenant_id,engagement_id,node_id,schema_version,action_id,
                job_id,attempt_id,outcome,job_state,terminal_reason,
                signed_outcome_ref,evidence_refs_json,classification_source,
                recorded_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                record.id,
                record.tenant_id,
                record.engagement_id,
                record.node_id,
                BRAIN_TRUTH_SCHEMA_VERSION,
                record.action_id or None,
                record.job_id or None,
                record.attempt_id or None,
                record.outcome,
                record.job_state,
                record.terminal_reason,
                record.signed_outcome_ref or None,
                _bounded_json(
                    record.evidence_refs,
                    maximum=64_000,
                    field_name="evidence_refs",
                ),
                record.classification_source,
                record.recorded_at,
            ),
        )
        return record

    def reconcile(self, node: AdvisoryPlanNode) -> OutcomeRecord:
        tenant = self._tenant(node.tenant_id)
        stored = self.conn.execute(
            "SELECT * FROM canonical_advisory_nodes WHERE tenant_id=? AND id=?",
            (tenant, node.id),
        ).fetchone()
        if stored is None:
            raise BoundaryDenied("node_not_found")
        job_id = str(stored["job_id"] or "")
        action_id = str(stored["action_id"] or "")
        if not job_id:
            if str(stored["resolution_reason"]) != CapabilityReason.SUPPORTED.value:
                outcome = ExecutionOutcome.UNSUPPORTED
                reason = str(stored["resolution_reason"])
            elif str(stored["policy_decision"]) == "deny":
                outcome = ExecutionOutcome.UNAUTHORIZED
                reason = str(stored["policy_reason"])
            elif str(stored["state"]) == "simulation":
                outcome = ExecutionOutcome.SIMULATION
                reason = "simulation_has_no_execution"
            elif str(stored["state"]) == "rejected" and stored["approval_reference"]:
                outcome = ExecutionOutcome.UNAUTHORIZED
                reason = "authorization_denied"
            else:
                outcome = ExecutionOutcome.ADVISORY
                reason = "advisory_has_no_execution"
            with self._tx():
                return self._append_outcome_tx(
                    node, outcome, job_state="", terminal_reason=reason
                )
        job = self.jobs.get_job(job_id, tenant_id=tenant)
        if job is None:
            raise BoundaryPersistenceError("canonical_job_missing")
        state = str(job.get("state") or "")
        attempts = self.jobs.list_attempts(job_id, tenant_id=tenant)
        attempt_id = str(attempts[-1].get("id") or "") if attempts else ""
        validated = validated_job_success(
            self.jobs,
            database_path=self.database_path,
            tenant_id=tenant,
            job_id=job_id,
        )
        if validated is not None:
            attempt_id = str(validated["canonical_attempt_id"])
            evidence_refs = tuple(validated["evidence_refs"])
            signed_ref = str(validated["signed_outcome_ref"])
            signed_outcome = "success"
        else:
            evidence_refs = ()
            signed_ref = ""
            signed_outcome = ""
        outcome, reason = classify_terminal_outcome(
            state,
            signed_outcome=signed_outcome,
            evidence_refs=evidence_refs,
        )
        persisted_reason = str(job.get("terminal_reason") or "")
        if persisted_reason and outcome in {
            ExecutionOutcome.FAILED,
            ExecutionOutcome.PARTIAL,
            ExecutionOutcome.CANCELED,
            ExecutionOutcome.TIMEOUT,
            ExecutionOutcome.INCONCLUSIVE,
        }:
            reason = persisted_reason
        with self._tx():
            record = self._append_outcome_tx(
                node,
                outcome,
                job_state=state,
                terminal_reason=reason,
                action_id=action_id,
                job_id=job_id,
                attempt_id=attempt_id,
                signed_outcome_ref=signed_ref,
                evidence_refs=evidence_refs,
            )
            if outcome in {
                ExecutionOutcome.SUCCESS,
                ExecutionOutcome.FAILED,
                ExecutionOutcome.PARTIAL,
                ExecutionOutcome.CANCELED,
                ExecutionOutcome.TIMEOUT,
                ExecutionOutcome.UNAUTHORIZED,
                ExecutionOutcome.UNSUPPORTED,
            }:
                self.conn.execute(
                    "UPDATE canonical_advisory_nodes SET state='terminal',attempt_id=?,revised_at=? WHERE tenant_id=? AND id=?",
                    (attempt_id or None, _now_iso(self.clock), tenant, node.id),
                )
        return record

    def narrative(self, node: AdvisoryPlanNode) -> NarrativeProjection:
        tenant = self._tenant(node.tenant_id)
        row = self.conn.execute(
            """
            SELECT n.plan_id,n.requested_capability_id,
                   n.requested_capability_version,n.target_display,n.state,
                   o.outcome,o.terminal_reason,o.evidence_refs_json
            FROM canonical_advisory_nodes n
            LEFT JOIN canonical_advisory_outcomes o
              ON o.tenant_id=n.tenant_id AND o.node_id=n.id
            WHERE n.tenant_id=? AND n.id=?
            ORDER BY o.recorded_at DESC LIMIT 1
            """,
            (tenant, node.id),
        ).fetchone()
        if row is None:
            raise BoundaryDenied("node_not_found")
        refs_raw = json.loads(str(row["evidence_refs_json"] or "[]"))
        refs = tuple(
            safe
            for ref in refs_raw[:MAX_EVIDENCE_REFS]
            if (safe := _opaque_evidence_ref(ref))
        )
        return NarrativeProjection(
            tenant_id=tenant,
            engagement_id=node.engagement_id,
            plan_id=str(row["plan_id"]),
            node_id=node.id,
            capability_id=str(row["requested_capability_id"]),
            capability_version=str(row["requested_capability_version"]),
            target=str(row["target_display"]),
            state=str(row["state"]),
            outcome=str(row["outcome"] or ExecutionOutcome.ADVISORY.value),
            terminal_reason=redact_text(str(row["terminal_reason"] or ""))[:1_000],
            evidence_refs=refs,
        )

    def migrate(self, version: str = BRAIN_TRUTH_SCHEMA_VERSION) -> str:
        if version != BRAIN_TRUTH_SCHEMA_VERSION:
            raise BoundaryDenied("unsupported_migration")
        self._verify_schema()
        return BRAIN_TRUTH_SCHEMA_VERSION


__all__ = [
    "ACTION_BOUNDARY",
    "AdvisoryPlan",
    "AdvisoryPlanNode",
    "ApprovalReference",
    "BRAIN_TRUTH_SCHEMA_VERSION",
    "BoundaryConflict",
    "BoundaryDenied",
    "BoundaryPersistenceError",
    "CapabilityEntry",
    "CapabilityReason",
    "CapabilityRegistry",
    "CapabilityResolution",
    "CapabilitySnapshot",
    "CanonicalActionLink",
    "CanonicalActionRequest",
    "ExecutionOutcome",
    "ForgeBrainTruthBoundary",
    "NarrativeProjection",
    "OutcomeRecord",
    "PolicyDecision",
    "Task103InertJobFactory",
    "TruthBoundaryError",
    "model_cache_key",
    "classify_terminal_outcome",
    "project_model_input",
    "advisory_narrative_projection",
    "advisory_report_projection",
    "publishable_model_prose",
    "validated_job_success",
]
