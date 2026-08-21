"""Finding confidence policy shared by reports and dashboard exports."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any


CANONICAL_CONFIDENCE = {"HIGH", "MEDIUM", "LOW", "UNVERIFIED"}
DEFAULT_CONFIDENCE = "UNVERIFIED"
SUPPRESSED_BY_DEFAULT = {"LOW", "UNVERIFIED"}


def normalise_confidence(value: Any, default: str = DEFAULT_CONFIDENCE) -> str:
    """Return a canonical confidence value, failing closed when it is absent.

    ``default`` remains in the signature for compatibility with older callers,
    but an absent, blank, or unknown value is never promoted.  Only an explicit
    canonical value can produce reportable confidence; everything else is
    ``UNVERIFIED``.
    """
    del default  # compatibility parameter; fail-closed behavior is mandatory
    candidate = getattr(value, "value", value)
    raw = str(candidate or "").strip().upper().replace(" ", "_")
    return raw if raw in CANONICAL_CONFIDENCE else DEFAULT_CONFIDENCE


def infer_confidence(
    finding: dict[str, Any], default: str = DEFAULT_CONFIDENCE,
) -> str:
    """Infer confidence from first-class fields, verification, or evidence extras."""
    if "confidence" in finding:
        return normalise_confidence(finding.get("confidence"), default=default)

    verification_value = finding.get("verification")
    if verification_value is not None and not isinstance(verification_value, Mapping):
        return DEFAULT_CONFIDENCE
    verification = verification_value if isinstance(verification_value, Mapping) else {}
    if "confidence" in verification:
        return normalise_confidence(verification.get("confidence"), default=default)

    evidence_value = finding.get("evidence")
    if evidence_value is not None and not isinstance(evidence_value, Mapping):
        return DEFAULT_CONFIDENCE
    evidence = evidence_value if isinstance(evidence_value, Mapping) else {}
    extra_value = evidence.get("extra")
    if extra_value is not None and not isinstance(extra_value, Mapping):
        return DEFAULT_CONFIDENCE
    extra = extra_value if isinstance(extra_value, Mapping) else {}
    if "fp_confidence" in extra:
        return normalise_confidence(extra.get("fp_confidence"), default=default)

    return DEFAULT_CONFIDENCE


def normalise_finding(
    finding: dict[str, Any], legacy_default: str = DEFAULT_CONFIDENCE,
) -> dict[str, Any]:
    """Return a copy with confidence/status/VPR fields consistently populated."""
    row = dict(finding)
    confidence = infer_confidence(row, default=legacy_default)
    row["confidence"] = confidence
    row.setdefault("status", "verified" if confidence in {"HIGH", "MEDIUM"} else "open")

    evidence_value = row.get("evidence")
    evidence = dict(evidence_value) if isinstance(evidence_value, Mapping) else {}
    extra_value = evidence.get("extra")
    extra = dict(extra_value) if isinstance(extra_value, Mapping) else {}
    if "extra" in evidence:
        evidence["extra"] = extra
    if "evidence" in row:
        row["evidence"] = evidence

    cvss = row.get("cvss_v31_score") or row.get("cvss_score") or 0.0
    row.setdefault("vpr_score", cvss or 0.0)
    if not row.get("vpr_priority") and not row.get("vpr"):
        row["vpr_priority"] = _priority_from_score(float(row.get("vpr_score") or 0.0))
        row["vpr"] = row["vpr_priority"]

    verification_value = row.get("verification")
    verification = dict(verification_value) if isinstance(verification_value, Mapping) else {}
    if verification:
        verification["confidence"] = (
            normalise_confidence(verification.get("confidence"))
            if "confidence" in verification
            else confidence
        )
    if not verification:
        if extra.get("fp_confidence") or extra.get("fp_evidence"):
            verification = {
                "confidence": confidence,
                "evidence": extra.get("fp_evidence", []),
                "probe_count": extra.get("fp_probe_count", 0),
                "probe_hits": extra.get("fp_probe_hits", 0),
            }
    row["verification"] = verification or None
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
