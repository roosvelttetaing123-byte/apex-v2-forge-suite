"""Finding confidence policy shared by reports and dashboard exports."""
from __future__ import annotations

from typing import Any

from common.verification_policy import normalise_finding_truth


CANONICAL_CONFIDENCE = {"HIGH", "MEDIUM", "LOW", "UNVERIFIED"}
SUPPRESSED_BY_DEFAULT = {"LOW", "UNVERIFIED"}


def normalise_confidence(value: Any, default: str = "UNVERIFIED") -> str:
    """Return a canonical confidence value without optimistic legacy defaults."""
    fallback = str(default or "UNVERIFIED").upper().replace(" ", "_")
    if fallback not in CANONICAL_CONFIDENCE:
        fallback = "UNVERIFIED"
    raw = str(value or fallback).upper().replace(" ", "_")
    return raw if raw in CANONICAL_CONFIDENCE else fallback


def infer_confidence(finding: dict[str, Any], default: str = "UNVERIFIED") -> str:
    """Infer confidence from first-class fields, verification, or evidence extras."""
    verification = finding.get("verification") or {}
    evidence = finding.get("evidence") or {}
    extra = evidence.get("extra") or {}
    return normalise_confidence(
        finding.get("confidence")
        or verification.get("confidence")
        or extra.get("fp_confidence"),
        default=default,
    )


def normalise_finding(finding: dict[str, Any], legacy_default: str = "UNVERIFIED") -> dict[str, Any]:
    """Return a copy with confidence, truth, and VPR fields populated safely."""
    row = dict(finding)
    confidence = infer_confidence(row, default=legacy_default)
    row["confidence"] = confidence

    cvss = row.get("cvss_v31_score") or row.get("cvss_score") or 0.0
    row.setdefault("vpr_score", cvss or 0.0)
    if not row.get("vpr_priority") and not row.get("vpr") and float(row.get("vpr_score") or 0.0) > 0:
        row["vpr_priority"] = _priority_from_score(float(row["vpr_score"]))
        row["vpr"] = row["vpr_priority"]

    verification = row.get("verification") or {}
    if not verification:
        evidence = row.get("evidence") or {}
        extra = evidence.get("extra") or {}
        if extra.get("fp_confidence") or extra.get("fp_evidence"):
            verification = {
                "confidence": confidence,
                "evidence": extra.get("fp_evidence", []),
                "probe_count": extra.get("fp_probe_count", 0),
                "probe_hits": extra.get("fp_probe_hits", 0),
            }
    row["verification"] = verification or None
    row.update(normalise_finding_truth(row))
    return row


def should_include_default(finding: dict[str, Any]) -> bool:
    """Return True when a finding should appear in the default report."""
    return infer_confidence(finding) not in SUPPRESSED_BY_DEFAULT


def _priority_from_score(score: float) -> str:
    if score >= 8.0:
        return "Critical"
    if score >= 5.0:
        return "High"
    if score >= 2.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"

