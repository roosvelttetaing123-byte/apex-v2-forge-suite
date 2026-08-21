"""Signed collection and coverage truth for persisted scan-run comparison."""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


_SHA256_REFERENCE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CANONICAL_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,199}$")


class RunCollectionStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELED = "canceled"
    UNAUTHORIZED = "unauthorized"
    UNSUPPORTED = "unsupported"
    COLLECTION_ERROR = "collection_error"


@dataclass(frozen=True)
class RunTruthPolicy:
    policy_id: str
    policy_version: str
    issuer_id: str
    issuer_public_key: str


RUN_TRUTH_POLICY = RunTruthPolicy(
    policy_id="forge-run-coverage-v1",
    policy_version="1.0",
    issuer_id="forge-run-authority-v1",
    # The corresponding private key belongs to the execution control plane and
    # is intentionally absent from source, report workers, and persisted rows.
    issuer_public_key="AsUopgpGCuQULOSiOJpnqVXVVnfgEAoOeAL3Xj42als=",
)


@dataclass(frozen=True)
class RunCollectionTruth:
    """Authority-attested run outcome and exact coverage identity."""

    run_id: str
    authorization_run_id: str
    job_id: str
    tenant_id: str
    framework: str
    scope_binding: str
    target_binding: str
    collection_status: RunCollectionStatus
    coverage_complete: bool
    coverage_identity: str
    finding_set_identity: str
    predecessor_run_id: str
    run_sequence: int
    completed_at: str
    authorization_decision_id: str
    authorization_binding: str
    authority_id: str
    policy_id: str = RUN_TRUTH_POLICY.policy_id
    policy_version: str = RUN_TRUTH_POLICY.policy_version
    issuer_id: str = RUN_TRUTH_POLICY.issuer_id
    attestation: str = ""


def _sha256_ref(value: object) -> bool:
    # Signed series keys are persisted and queried byte-for-byte.  Accepting an
    # equivalent upper-case or whitespace-padded spelling lets one logical
    # series fork into multiple sequence-1 rows.  Require the canonical wire
    # representation rather than normalizing after signature verification.
    return isinstance(value, str) and _SHA256_REFERENCE.fullmatch(value) is not None


def _nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def _canonical_identifier(value: object, *, allow_empty: bool = False) -> bool:
    if not isinstance(value, str) or value != value.strip():
        return False
    if not value:
        return allow_empty
    return _CANONICAL_IDENTIFIER.fullmatch(value) is not None


def run_collection_truth_attestation_payload(record: RunCollectionTruth) -> bytes:
    """Return the stable signed representation of persisted run truth."""
    payload = {
        "run_id": record.run_id,
        "authorization_run_id": record.authorization_run_id,
        "job_id": record.job_id,
        "tenant_id": record.tenant_id,
        "framework": record.framework,
        "scope_binding": record.scope_binding,
        "target_binding": record.target_binding,
        "collection_status": record.collection_status.value,
        "coverage_complete": record.coverage_complete,
        "coverage_identity": record.coverage_identity,
        "finding_set_identity": record.finding_set_identity,
        "predecessor_run_id": record.predecessor_run_id,
        "run_sequence": record.run_sequence,
        "completed_at": record.completed_at,
        "authorization_decision_id": record.authorization_decision_id,
        "authorization_binding": record.authorization_binding,
        "authority_id": record.authority_id,
        "policy_id": record.policy_id,
        "policy_version": record.policy_version,
        "issuer_id": record.issuer_id,
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def validate_run_collection_truth(
    record: RunCollectionTruth,
    *,
    policy: RunTruthPolicy = RUN_TRUTH_POLICY,
) -> tuple[bool, str]:
    """Validate identity, bindings, state, and the policy-pinned attestation."""
    if not isinstance(record, RunCollectionTruth):
        return False, "run_record_invalid"
    if not isinstance(policy, RunTruthPolicy):
        return False, "run_policy_invalid"
    if not all(
        _canonical_identifier(value)
        for value in (
            record.run_id,
            record.authorization_run_id,
            record.job_id,
            record.tenant_id,
            record.framework,
            record.authorization_decision_id,
        )
    ):
        return False, "run_identity_missing"
    if (
        not _canonical_identifier(record.authority_id)
        or record.framework != record.framework.lower()
    ):
        return False, "run_authority_missing"
    if not isinstance(record.collection_status, RunCollectionStatus):
        return False, "run_collection_status_invalid"
    if type(record.coverage_complete) is not bool:
        return False, "run_coverage_complete_invalid"
    if type(record.run_sequence) is not int or record.run_sequence < 1:
        return False, "run_sequence_invalid"
    if record.predecessor_run_id:
        if (
            not _canonical_identifier(record.predecessor_run_id)
            or record.predecessor_run_id == record.run_id
            or record.run_sequence == 1
        ):
            return False, "run_predecessor_invalid"
    elif record.run_sequence != 1:
        return False, "run_predecessor_missing"
    try:
        completed_at = datetime.fromisoformat(
            record.completed_at.replace("Z", "+00:00")
        )
    except (AttributeError, TypeError, ValueError):
        return False, "run_completed_at_invalid"
    if completed_at.tzinfo is None or completed_at.utcoffset() is None:
        return False, "run_completed_at_invalid"
    if not all(
        _sha256_ref(value)
        for value in (
            record.scope_binding,
            record.target_binding,
            record.coverage_identity,
            record.finding_set_identity,
            record.authorization_binding,
        )
    ):
        return False, "run_binding_invalid"
    if (
        not all(
            _canonical_identifier(value)
            for value in (
                record.policy_id,
                record.policy_version,
                record.issuer_id,
                policy.policy_id,
                policy.policy_version,
                policy.issuer_id,
            )
        )
        or not _nonempty_text(policy.issuer_public_key)
        or record.policy_id != policy.policy_id
        or record.policy_version != policy.policy_version
        or record.issuer_id != policy.issuer_id
        or not _nonempty_text(record.attestation)
    ):
        return False, "run_attestation_binding_mismatch"
    try:
        public_key_bytes = base64.b64decode(
            policy.issuer_public_key,
            validate=True,
        )
        signature = base64.b64decode(record.attestation, validate=True)
        if len(public_key_bytes) != 32 or len(signature) != 64:
            return False, "run_attestation_invalid"
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, run_collection_truth_attestation_payload(record))
    except (AttributeError, InvalidSignature, TypeError, ValueError):
        return False, "run_attestation_invalid"
    return True, ""


def persisted_run_comparability(
    previous: RunCollectionTruth | None,
    current: RunCollectionTruth | None,
    *,
    policy: RunTruthPolicy = RUN_TRUTH_POLICY,
) -> tuple[bool, str]:
    """Require two signed, successful runs with exactly matching coverage."""
    if previous is None:
        return False, "previous_persisted_run_truth_missing"
    if current is None:
        return False, "current_persisted_run_truth_missing"
    previous_valid, previous_reason = validate_run_collection_truth(
        previous,
        policy=policy,
    )
    if not previous_valid:
        return False, f"previous_{previous_reason}"
    current_valid, current_reason = validate_run_collection_truth(
        current,
        policy=policy,
    )
    if not current_valid:
        return False, f"current_{current_reason}"
    if previous.run_id == current.run_id:
        return False, "distinct_runs_required"
    if previous.tenant_id != current.tenant_id:
        return False, "persisted_tenant_mismatch"
    if previous.framework != current.framework:
        return False, "persisted_framework_mismatch"
    if previous.scope_binding != current.scope_binding:
        return False, "persisted_scope_binding_mismatch"
    if previous.target_binding != current.target_binding:
        return False, "persisted_target_binding_mismatch"
    if current.run_sequence <= previous.run_sequence:
        return False, "signed_run_order_invalid"
    if current.run_sequence != previous.run_sequence + 1:
        return False, "signed_run_sequence_gap"
    if current.predecessor_run_id != previous.run_id:
        return False, "signed_predecessor_mismatch"
    if previous.collection_status != RunCollectionStatus.SUCCESS:
        return False, f"previous_collection_{previous.collection_status.value}"
    if current.collection_status != RunCollectionStatus.SUCCESS:
        return False, f"current_collection_{current.collection_status.value}"
    if not previous.coverage_complete or not current.coverage_complete:
        return False, "persisted_coverage_incomplete"
    if previous.coverage_identity != current.coverage_identity:
        return False, "persisted_coverage_identity_mismatch"
    return True, ""
