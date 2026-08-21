"""Central truth policy for finding proof, maturity, and verification promotion."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class ProofType(str, Enum):
    ACTIVE = "active"
    PASSIVE = "passive"
    VERSION_CORRELATION = "version_correlation"
    OOB = "OOB"
    STATIC = "static"
    CREDENTIALED_CONFIG = "credentialed_config"
    MANUAL = "manual"
    SIMULATION = "simulation"
    UNKNOWN = "unknown"


class CapabilityMaturity(str, Enum):
    VERIFIED = "verified"
    HEURISTIC = "heuristic"
    WRAPPER = "wrapper"
    SIMULATION = "simulation"
    EXPERIMENTAL = "experimental"
    DISABLED = "disabled"


class VerificationState(str, Enum):
    VERIFIED = "verified"
    CANDIDATE = "candidate"
    INFORMATIONAL = "informational"
    SIMULATION = "simulation"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VerificationDecision:
    state: VerificationState
    proof_type: ProofType
    maturity: CapabilityMaturity
    verified: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)
    policy_id: str = "forge-verification-policy"
    policy_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "verified": self.verified,
            "proof_type": self.proof_type.value,
            "maturity": self.maturity.value,
            "reasons": list(self.reasons),
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class ProofPolicy:
    """Reviewed proof contract bound to one known capability and exact version."""

    policy_id: str
    policy_version: str
    capability_id: str
    capability_version: str
    proof_type: ProofType
    required_observation_types: frozenset[str]
    issuer_id: str
    issuer_public_key: str
    subject_prefix: str = ""
    evidence_validator: Callable[[str], bool] | None = None
    evidence_resolver: Callable[[str], bool] | None = None


@dataclass(frozen=True)
class TrustedProofObservation:
    """One authority-recorded observation and its immutable evidence identity."""

    observation_type: str
    evidence_ref: str


@dataclass(frozen=True)
class TrustedProofRecord:
    """Canonical proof outcome returned by a trusted execution authority.

    Serialized finding fields are claimant-controlled.  They may carry only the
    opaque ``record_id`` used to request this record; none of the remaining
    fields are recovered from the finding being evaluated.
    """

    record_id: str
    subject_id: str
    proof_policy_id: str
    proof_policy_version: str
    capability_id: str
    capability_version: str
    capability_maturity: CapabilityMaturity
    proof_type: ProofType
    policy_satisfied: bool
    observations: tuple[TrustedProofObservation, ...]
    issuer_id: str = ""
    attestation: str = ""


@dataclass(frozen=True)
class VerificationAuthority:
    """Out-of-band resolver for canonical signed proof records."""

    record_resolver: Callable[[str], TrustedProofRecord | None]

    def resolve_record(self, record_id: str) -> TrustedProofRecord | None:
        try:
            record = self.record_resolver(record_id)
        except Exception:
            return None
        return record if isinstance(record, TrustedProofRecord) else None

_PROOF_CAPABILITY_ID = "forge:active-proof-review"
_PROOF_CAPABILITY_VERSION = "1.0"
_REVIEWED_CAPABILITY_REGISTRATIONS: dict[str, tuple[str, CapabilityMaturity]] = {
    _PROOF_CAPABILITY_ID: (
        _PROOF_CAPABILITY_VERSION,
        CapabilityMaturity.VERIFIED,
    ),
}
_FIXTURE_AUTHORITY_ID = "forge-fixture-authority-v1"
# Deterministic fixture-policy trust root. Its private key is intentionally
# absent from source. Production capabilities require their own reviewed,
# versioned issuer entry rather than inheriting this fixture identity.
_FIXTURE_AUTHORITY_PUBLIC_KEY = "AsUopgpGCuQULOSiOJpnqVXVVnfgEAoOeAL3Xj42als="
_PROOF_POLICIES: dict[tuple[str, str], ProofPolicy] = {
    ("forge-active-proof-v1", "1.0"): ProofPolicy(
        policy_id="forge-active-proof-v1",
        policy_version="1.0",
        capability_id=_PROOF_CAPABILITY_ID,
        capability_version=_PROOF_CAPABILITY_VERSION,
        proof_type=ProofType.ACTIVE,
        required_observation_types=frozenset({"request", "response", "semantic_match"}),
        issuer_id=_FIXTURE_AUTHORITY_ID,
        issuer_public_key=_FIXTURE_AUTHORITY_PUBLIC_KEY,
        subject_prefix="fixture:",
        evidence_validator=lambda ref: ref.startswith("sha256:") and len(ref) == 71,
    ),
}


_WEAK_SIGNAL_KEYS = frozenset(
    {
        "status_code",
        "http_status",
        "banner",
        "product",
        "service",
        "version",
        "cpe",
        "process_exit_code",
        "exit_code",
        "return_code",
        "log_message",
    }
)
_PROOF_METADATA_KEYS = frozenset(
    {
        "proof_policy_id",
        "proof_policy_version",
        "proof_record_id",
        "proof_satisfied",
        "capability_id",
        "capability_version",
        "independent_observations",
    }
)

# Persisted proof lineage is re-evaluated on every load.  It is intentionally
# separate from confidence and workflow status so a cached ``verified`` flag
# cannot survive without its registered policy and immutable evidence.
_PROOF_LINEAGE_KEYS = frozenset(
    {
        "proof_policy_id",
        "proof_policy_version",
        "proof_record_id",
        "capability_id",
        "capability_version",
        "independent_observations",
    }
)
_FORBIDDEN_SIMULATION_OUTCOMES = frozenset(
    {"success", "exploited", "still_vulnerable", "fixed", "verified"}
)


def validate_simulation_serialization(value: Mapping[str, Any]) -> dict[str, Any]:
    """Reject simulation records that claim executed or verified outcomes."""

    def walk(node: Any) -> None:
        if isinstance(node, Mapping):
            for key, item in node.items():
                lowered_key = str(key).strip().lower()
                if lowered_key in _FORBIDDEN_SIMULATION_OUTCOMES and item not in (
                    False,
                    None,
                    "",
                    0,
                ):
                    raise ValueError(
                        f"simulation cannot serialize outcome: {lowered_key}"
                    )
                if (
                    isinstance(item, str)
                    and item.strip().lower() in _FORBIDDEN_SIMULATION_OUTCOMES
                ):
                    raise ValueError(
                        f"simulation cannot serialize outcome: {item.strip().lower()}"
                    )
                walk(item)
        elif isinstance(node, (list, tuple, set)):
            for item in node:
                walk(item)

    walk(value)
    return dict(value)


def normalise_proof_type(value: Any) -> ProofType:
    if isinstance(value, ProofType):
        return value
    raw = str(value or "unknown").strip()
    aliases = {"oob": ProofType.OOB, "active-probe": ProofType.ACTIVE}
    if raw.lower() in aliases:
        return aliases[raw.lower()]
    for proof_type in ProofType:
        if raw == proof_type.value or raw.lower() == proof_type.value.lower():
            return proof_type
    return ProofType.UNKNOWN


def normalise_maturity(value: Any) -> CapabilityMaturity:
    if isinstance(value, CapabilityMaturity):
        return value
    raw = str(value or "experimental").strip().lower()
    try:
        return CapabilityMaturity(raw)
    except ValueError:
        return CapabilityMaturity.EXPERIMENTAL


def _signal_only_reasons(observations: Mapping[str, Any]) -> list[str]:
    keys = {
        str(key)
        for key, value in observations.items()
        if value not in (None, "", [], {}, ())
    }
    signal_keys = keys - _PROOF_METADATA_KEYS
    reasons: list[str] = []
    if signal_keys and signal_keys <= {"status_code", "http_status"}:
        reasons.append("status_code_only")
    if signal_keys and signal_keys <= {"banner", "product", "service"}:
        reasons.append("banner_or_product_only")
    if signal_keys and signal_keys <= {"version", "product", "service", "cpe"}:
        reasons.append("version_correlation_only")
    if signal_keys and signal_keys <= {
        "process_exit_code",
        "exit_code",
        "return_code",
        "log_message",
    }:
        reasons.append("process_exit_only")
    if signal_keys and signal_keys <= _WEAK_SIGNAL_KEYS and not reasons:
        reasons.append("weak_signals_only")
    return reasons


def _trusted_observation_bindings(
    value: tuple[TrustedProofObservation, ...],
) -> dict[str, str]:
    """Validate authority-recorded observations and distinct immutable refs."""
    bindings: dict[str, str] = {}
    used_refs: set[str] = set()
    for item in value:
        if not isinstance(item, TrustedProofObservation):
            return {}
        name = str(item.observation_type or "").strip()
        evidence_ref = str(item.evidence_ref or "").strip().lower()
        if (
            not name
            or not evidence_ref.startswith("sha256:")
            or len(evidence_ref) != 71
        ):
            return {}
        digest = evidence_ref.removeprefix("sha256:")
        if any(char not in "0123456789abcdef" for char in digest):
            return {}
        if name in bindings or evidence_ref in used_refs:
            return {}
        bindings[name] = evidence_ref
        used_refs.add(evidence_ref)
    return bindings


def _trusted_proof_attestation_payload(record: TrustedProofRecord) -> bytes:
    """Return the stable signed representation of one authority proof record."""
    payload = {
        "record_id": record.record_id,
        "subject_id": record.subject_id,
        "proof_policy_id": record.proof_policy_id,
        "proof_policy_version": record.proof_policy_version,
        "capability_id": record.capability_id,
        "capability_version": record.capability_version,
        "capability_maturity": record.capability_maturity.value,
        "proof_type": record.proof_type.value,
        "policy_satisfied": record.policy_satisfied,
        "observations": [
            {
                "type": observation.observation_type,
                "evidence_ref": observation.evidence_ref,
            }
            for observation in record.observations
        ],
        "issuer_id": record.issuer_id,
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _trusted_proof_attestation_valid(
    record: TrustedProofRecord,
    policy: ProofPolicy,
) -> bool:
    """Verify a proof record against the policy-pinned execution trust root."""
    if (
        record.issuer_id != policy.issuer_id
        or not record.attestation
        or (policy.subject_prefix and not record.subject_id.startswith(policy.subject_prefix))
    ):
        return False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(policy.issuer_public_key, validate=True)
        )
        signature = base64.b64decode(record.attestation, validate=True)
        public_key.verify(signature, _trusted_proof_attestation_payload(record))
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def _policy_evidence_exists(policy: ProofPolicy, evidence_ref: str) -> bool:
    """Resolve evidence only through the policy-owned canonical resolver."""
    if policy.evidence_resolver is None:
        return False
    try:
        return policy.evidence_resolver(evidence_ref) is True
    except Exception:
        return False


def _registered_capability_maturity(capability_id: str) -> CapabilityMaturity:
    """Resolve maturity from the ordinary reviewed inventory, never the finding."""
    if not capability_id:
        return CapabilityMaturity.EXPERIMENTAL
    try:
        return classify_current_capability_inventory().get(
            capability_id,
            CapabilityMaturity.EXPERIMENTAL,
        )
    except Exception:
        return CapabilityMaturity.EXPERIMENTAL


def _registered_capability_version(capability_id: str) -> str:
    registration = _REVIEWED_CAPABILITY_REGISTRATIONS.get(capability_id)
    return registration[0] if registration is not None else ""


def _trusted_proof_record(
    authority: VerificationAuthority | None,
    record_id: str,
    subject_id: str,
) -> tuple[TrustedProofRecord | None, str]:
    """Resolve one subject-bound record without accepting serialized authority."""
    if not record_id:
        return None, "trusted_proof_record_missing"
    if authority is None:
        return None, "verification_authority_unavailable"
    record = authority.resolve_record(record_id)
    if record is None:
        return None, "trusted_proof_record_missing"
    if record.record_id != record_id or not subject_id or record.subject_id != subject_id:
        return None, "trusted_proof_subject_mismatch"
    policy = _PROOF_POLICIES.get(
        (record.proof_policy_id, record.proof_policy_version)
    )
    if policy is None or not _trusted_proof_attestation_valid(record, policy):
        return None, "trusted_proof_attestation_invalid"
    return record, ""


def _serialise_lineage_value(value: Any) -> Any:
    """Return a JSON-safe copy of persisted proof-lineage metadata."""
    if isinstance(value, Mapping):
        return {
            str(key): _serialise_lineage_value(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_serialise_lineage_value(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _proof_observations(
    verification: Mapping[str, Any],
    extra: Mapping[str, Any],
) -> dict[str, Any]:
    """Recover proof inputs from current or legacy persisted finding shapes."""
    nested = verification.get("observations")
    if isinstance(nested, Mapping):
        return dict(nested)
    nested = extra.get("proof_observations")
    if isinstance(nested, Mapping):
        return dict(nested)
    # Some current rows store lineage keys at the verification top level.
    # Evaluation still validates the complete policy and evidence, so reading
    # this shape does not turn cached metadata into proof.
    return {
        key: verification[key]
        for key in _PROOF_LINEAGE_KEYS
        if key in verification
    }


def evaluate_verification(
    *,
    severity: Any,
    proof_type: ProofType | str | None,
    maturity: CapabilityMaturity | str | None,
    observations: Mapping[str, Any] | None = None,
    confidence: Any = "UNVERIFIED",
    subject_id: Any = "",
    authority: VerificationAuthority | None = None,
) -> VerificationDecision:
    """Apply the only supported finding-verification promotion policy.

    Confidence and severity influence triage, never proof. Critical/high findings
    require an explicit, versioned proof policy plus independently recorded
    observations. Simulation and version correlation are never verified here.
    """
    proof = normalise_proof_type(proof_type)
    observed = dict(observations or {})
    reasons = _signal_only_reasons(observed)
    record_id = str(observed.get("proof_record_id") or "").strip()
    canonical_subject_id = str(subject_id or "").strip()
    trusted_record, authority_reason = _trusted_proof_record(
        authority,
        record_id,
        canonical_subject_id,
    )
    declared_capability_id = str(observed.get("capability_id") or "").strip()
    resolved_capability_id = (
        str(trusted_record.capability_id or "").strip()
        if trusted_record is not None
        else declared_capability_id
    )
    # A signature proves what the issuer said; it does not let the issuer mint
    # product maturity. Maturity and version are resolved from the independently
    # reviewed central inventory on every evaluation.
    capability = _registered_capability_maturity(resolved_capability_id)

    if proof == ProofType.SIMULATION or capability == CapabilityMaturity.SIMULATION:
        return VerificationDecision(
            state=VerificationState.SIMULATION,
            proof_type=proof,
            maturity=capability,
            reasons=("simulation_cannot_verify",),
        )
    if capability == CapabilityMaturity.DISABLED:
        return VerificationDecision(
            state=VerificationState.UNKNOWN,
            proof_type=proof,
            maturity=capability,
            reasons=("capability_disabled",),
        )
    if proof == ProofType.UNKNOWN:
        return VerificationDecision(
            state=VerificationState.UNKNOWN,
            proof_type=proof,
            maturity=capability,
            reasons=("proof_lineage_missing",),
        )
    if proof == ProofType.VERSION_CORRELATION:
        return VerificationDecision(
            state=VerificationState.CANDIDATE,
            proof_type=proof,
            maturity=capability,
            reasons=("version_correlation_is_candidate",),
        )
    if reasons:
        return VerificationDecision(
            state=VerificationState.CANDIDATE,
            proof_type=proof,
            maturity=capability,
            reasons=tuple(reasons),
        )
    if capability != CapabilityMaturity.VERIFIED:
        return VerificationDecision(
            state=VerificationState.CANDIDATE,
            proof_type=proof,
            maturity=capability,
            reasons=("capability_not_verified",),
        )

    if trusted_record is None:
        return VerificationDecision(
            state=VerificationState.CANDIDATE,
            proof_type=proof,
            maturity=capability,
            reasons=(authority_reason,),
        )

    policy_id = str(trusted_record.proof_policy_id or "").strip()
    policy_version = str(trusted_record.proof_policy_version or "").strip()
    capability_id = str(trusted_record.capability_id or "").strip()
    capability_version = str(trusted_record.capability_version or "").strip()
    observation_bindings = _trusted_observation_bindings(trusted_record.observations)
    observation_types = set(observation_bindings)
    policy = _PROOF_POLICIES.get((policy_id, policy_version))
    proof_allowed = proof in {
        ProofType.ACTIVE,
        ProofType.OOB,
        ProofType.STATIC,
        ProofType.CREDENTIALED_CONFIG,
        ProofType.MANUAL,
    }
    if policy is None:
        return VerificationDecision(
            state=VerificationState.CANDIDATE,
            proof_type=proof,
            maturity=capability,
            reasons=("proof_policy_unregistered",),
        )
    if (
        policy.capability_id != capability_id
        or policy.capability_version != capability_version
        or _registered_capability_version(capability_id) != capability_version
        or policy.proof_type != proof
        or normalise_proof_type(trusted_record.proof_type) != proof
        or capability != CapabilityMaturity.VERIFIED
    ):
        return VerificationDecision(
            state=VerificationState.CANDIDATE,
            proof_type=proof,
            maturity=capability,
            reasons=("proof_policy_binding_mismatch",),
        )
    if (
        proof_allowed
        and trusted_record.policy_satisfied is True
        and observation_types == set(policy.required_observation_types)
        and all(
            _policy_evidence_exists(policy, ref)
            for ref in observation_bindings.values()
        )
        and policy.evidence_validator is not None
        and all(policy.evidence_validator(ref) for ref in observation_bindings.values())
    ):
        return VerificationDecision(
            state=VerificationState.VERIFIED,
            proof_type=proof,
            maturity=capability,
            verified=True,
            reasons=("documented_proof_policy_satisfied",),
            policy_id=policy_id,
            policy_version=policy_version,
        )

    return VerificationDecision(
        state=VerificationState.CANDIDATE,
        proof_type=proof,
        maturity=capability,
        reasons=("documented_proof_policy_not_satisfied",),
    )


def normalise_finding_truth(
    finding: Mapping[str, Any],
    *,
    authority: VerificationAuthority | None = None,
) -> dict[str, Any]:
    """Return truth fields for a finding without upgrading legacy claims."""
    verification_value = finding.get("verification")
    verification = dict(verification_value) if isinstance(verification_value, Mapping) else {}
    evidence_value = finding.get("evidence")
    evidence = dict(evidence_value) if isinstance(evidence_value, Mapping) else {}
    extra_value = evidence.get("extra")
    extra = dict(extra_value) if isinstance(extra_value, Mapping) else {}
    proof = normalise_proof_type(
        finding.get("proof_type") or verification.get("proof_type") or extra.get("proof_type")
    )
    maturity = normalise_maturity(
        finding.get("maturity") or verification.get("maturity") or extra.get("maturity")
    )
    observations = _proof_observations(verification, extra)
    decision = evaluate_verification(
        severity=finding.get("severity", "informational"),
        proof_type=proof,
        maturity=maturity,
        observations=observations,
        confidence=finding.get("confidence", "UNVERIFIED"),
        subject_id=finding.get("id", ""),
        authority=authority,
    )
    if decision.state == VerificationState.SIMULATION:
        validate_simulation_serialization(finding)
    raw_status = str(finding.get("status") or "open").strip().lower() or "open"
    requested_verified = (
        str(finding.get("verification_state") or "").lower() == "verified"
        or str(verification.get("state") or "").lower() == "verified"
        or raw_status == "verified"
        or verification.get("verified") is True
    )
    if requested_verified and not decision.verified:
        verification.setdefault("legacy_status", "verified")
    # Preserve the validated inputs with the decision.  A verified finding
    # must be re-evaluable after SQLite/API/report round trips; otherwise its
    # truth would depend on which renderer happened to load it first.
    for key in _PROOF_LINEAGE_KEYS:
        if key in observations:
            verification[key] = _serialise_lineage_value(observations[key])
    if observations:
        verification["observations"] = _serialise_lineage_value(observations)
    verification.update(decision.to_dict())
    workflow_status = "open" if raw_status == "verified" else raw_status
    return {
        "status": workflow_status,
        "verification_state": decision.state.value,
        "proof_type": decision.proof_type.value,
        "maturity": decision.maturity.value,
        "verification": verification,
    }


def classify_registered_capabilities(
    capability_ids: Iterable[str],
    overrides: Mapping[str, Any] | None = None,
) -> dict[str, CapabilityMaturity]:
    """Classify a complete registry, defaulting reviewed-but-unlabelled IDs closed."""
    override_values = dict(overrides or {})
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for value in capability_ids:
        capability_id = str(value or "").strip()
        if not capability_id:
            raise ValueError("capability id is required")
        if capability_id in seen:
            raise ValueError(f"duplicate capability id: {capability_id}")
        seen.add(capability_id)
        maturity = override_values.pop(capability_id, CapabilityMaturity.EXPERIMENTAL.value)
        entries.append({"id": capability_id, "maturity": str(maturity)})
    if override_values:
        unknown = ", ".join(sorted(override_values))
        raise ValueError(f"unknown capability id in classification overrides: {unknown}")
    return classify_capabilities(entries)


def classify_capabilities(entries: Iterable[Mapping[str, Any]]) -> dict[str, CapabilityMaturity]:
    """Validate a central capability inventory; duplicates and unknown labels fail."""
    classified: dict[str, CapabilityMaturity] = {}
    for entry in entries:
        capability_id = str(entry.get("id") or "").strip()
        if not capability_id:
            raise ValueError("capability id is required")
        if capability_id in classified:
            raise ValueError(f"duplicate capability id: {capability_id}")
        raw_maturity = str(entry.get("maturity") or "").strip().lower()
        try:
            maturity = CapabilityMaturity(raw_maturity)
        except ValueError as exc:
            raise ValueError(f"unknown maturity for capability {capability_id}: {raw_maturity}") from exc
        classified[capability_id] = maturity
    return classified


_WRAPPER_CAPABILITIES = frozenset(
    {
        "netforge:nmap_vulns",
        "netforge:nuclei_runner",
        "netforge:exploit_suggest",
        "netforge:hydra_wrap",
        "netforge:html_report",
        "netforge:pdf_report",
        "netforge:json_export",
        "netforge:csv_export",
        "netforge:network_diagram",
        "adforge:html_report",
        "adforge:pdf_report",
        "adforge:json_export",
        "adforge:csv_export",
        "adforge:bloodhound_export",
        "adforge:attack_path_svg",
        "aiforge:html_report",
        "aiforge:pdf_report",
    }
)


def registered_capability_entries(
    checks_dir: Path | None = None,
) -> list[dict[str, str]]:
    """Return the centrally classified current module/check inventory.

    Implementations are qualified by engine and enter as experimental unless
    this reviewed registry identifies them as wrappers or simulations.  Native
    check loading remains strict about duplicate IDs.
    """
    from adforge.adforge import MODULE_MAP as ADFORGE_MODULES
    from aiforge.aiforge import MODULE_MAP as AIFORGE_MODULES
    from netforge.data.check_schema import load_checks_from_directory
    from netforge.netforge import MODULE_MAP as NETFORGE_MODULES
    from webforge.webforge import MODULE_MAP as WEBFORGE_MODULES

    engine_maps = (
        ("webforge", WEBFORGE_MODULES),
        ("netforge", NETFORGE_MODULES),
        ("adforge", ADFORGE_MODULES),
        ("aiforge", AIFORGE_MODULES),
    )
    entries: list[dict[str, str]] = []
    for engine, module_map in engine_maps:
        for module_id in module_map:
            capability_id = f"{engine}:{module_id}"
            maturity = (
                CapabilityMaturity.WRAPPER
                if capability_id in _WRAPPER_CAPABILITIES
                else CapabilityMaturity.EXPERIMENTAL
            )
            entries.append({"id": capability_id, "maturity": maturity.value})

    native_dir = checks_dir or (
        Path(__file__).resolve().parents[1] / "netforge" / "data" / "checks"
    )
    for check in load_checks_from_directory(native_dir):
        entries.append(
            {
                "id": f"netforge.yaml:{check.id}",
                "maturity": normalise_maturity(check.maturity).value,
            }
        )

    entries.append(
        {
            "id": "forge_c2:emulation",
            "maturity": CapabilityMaturity.SIMULATION.value,
        }
    )
    for capability_id, (_, maturity) in sorted(
        _REVIEWED_CAPABILITY_REGISTRATIONS.items()
    ):
        entries.append({"id": capability_id, "maturity": maturity.value})
    return entries


def classify_current_capability_inventory(
    checks_dir: Path | None = None,
) -> dict[str, CapabilityMaturity]:
    """Validate and return every currently registered capability label."""
    return classify_capabilities(registered_capability_entries(checks_dir))
