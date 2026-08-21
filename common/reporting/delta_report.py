"""Delta reporting helpers for persisted Forge findings."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from common.artifact_io import (
    ArtifactBoundaryError,
    atomic_write_bytes,
    ensure_private_directory,
)
from common.db import (
    PersistedRunTruthValidationError,
    finding_dedup_key,
    list_findings_for_run,
    load_run_collection_truth,
)
import common.run_truth as run_truth_module
from common.run_truth import RunTruthPolicy, persisted_run_comparability
from common.redaction import REDACTED, redact_value


_UNSTRUCTURED_FINDING_FIELDS = frozenset(
    {
        "description",
        "detail",
        "details",
        "evidence",
        "extra",
        "notes",
        "output",
        "raw",
        "raw_match",
        "remediation",
        "reproduction_steps",
        "request",
        "request_raw",
        "response",
        "response_raw",
        "stderr",
        "stdout",
        "verification",
    }
)


def _ensure_output_parent(parent: Path) -> None:
    """Validate/create a no-follow private parent directory chain."""
    try:
        ensure_private_directory(parent)
    except ArtifactBoundaryError as exc:
        if str(exc) == "artifact directory must be a real directory":
            raise ValueError("delta report parent must be a real directory") from None
        raise ValueError("delta report parent is unavailable") from None


def _safe_delta_finding(value: dict[str, Any]) -> dict[str, Any]:
    """Build a detached delta projection without free-form evidence text.

    Delta reports are ordinary comparison artifacts, not protected-original
    evidence.  Pattern redaction alone cannot recognize an unlabeled exact
    credential embedded in a description or provider detail, so free-form
    fields are represented by a marker while structured finding metadata
    remains available for comparison and triage.
    """
    safe = redact_value(dict(value))
    if not isinstance(safe, dict):
        return {}
    for key in _UNSTRUCTURED_FINDING_FIELDS:
        if key in safe and safe[key] not in (None, "", [], {}):
            safe[key] = REDACTED
    return safe


@dataclass(frozen=True)
class FindingDeltaReport:
    """Current-vs-previous finding comparison."""

    previous_run: str
    current_run: str
    generated_at: str
    new: list[dict[str, Any]]
    fixed: list[dict[str, Any]]
    remaining: list[dict[str, Any]]
    inconclusive: list[dict[str, Any]] = field(default_factory=list)
    comparison_state: str = "comparable"
    comparison_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        raw = {
            "previous_run": self.previous_run,
            "current_run": self.current_run,
            "generated_at": self.generated_at,
            "summary": {
                "new": len(self.new),
                "fixed": len(self.fixed),
                "remaining": len(self.remaining),
                "inconclusive": len(self.inconclusive),
            },
            "comparison_state": self.comparison_state,
            "comparison_reason": self.comparison_reason,
            "new": [_safe_delta_finding(item) for item in self.new],
            "fixed": [_safe_delta_finding(item) for item in self.fixed],
            "remaining": [_safe_delta_finding(item) for item in self.remaining],
            "inconclusive": [
                _safe_delta_finding(item) for item in self.inconclusive
            ],
        }
        # Return a detached, redacted serialization view.  Callers may retain
        # or mutate the returned lists; neither action can expose or alter the
        # report's in-memory source findings.
        safe = redact_value(raw)
        return safe if isinstance(safe, dict) else {}

    def write_json(self, path: str | Path) -> Path:
        out_path = Path(path)
        _ensure_output_parent(out_path.parent)
        payload = json.dumps(
            self.to_dict(), indent=2, default=str, ensure_ascii=True
        ).encode("utf-8")
        # Replace through a same-directory temporary inode so readers observe
        # either the old complete report or the new complete report, never a
        # partially serialized JSON document.  The temporary and final files
        # are owner-only regardless of the process umask.
        atomic_write_bytes(out_path, payload, mode=0o600)
        return out_path


def _dedup_map(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for finding in findings:
        persisted_key = finding.get("dedup_key")
        key = (
            str(persisted_key)
            if persisted_key and persisted_key != "<redacted>"
            else finding_dedup_key(finding)
        )
        row = dict(finding)
        row["dedup_key"] = key
        rows[key] = row
    return rows


def build_finding_delta(
    previous_findings: list[dict[str, Any]],
    current_findings: list[dict[str, Any]],
    *,
    previous_run: str = "",
    current_run: str = "",
    current_collection_status: str = "unknown",
    current_coverage_complete: bool = False,
    generated_at: str | None = None,
) -> FindingDeltaReport:
    """Compare two finding sets using deterministic finding fingerprints."""
    previous = _dedup_map(previous_findings)
    current = _dedup_map(current_findings)

    def ordered(keys: set[str], source: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            source[key]
            for key in sorted(
                keys,
                key=lambda item: (
                    source[item].get("severity", ""),
                    source[item].get("title", ""),
                    source[item].get("target", ""),
                    source[item].get("port") or 0,
                ),
            )
        ]

    previous_keys = set(previous)
    current_keys = set(current)
    missing = ordered(previous_keys - current_keys, previous)
    current_only = ordered(current_keys - previous_keys, current)
    comparable = current_collection_status == "success" and current_coverage_complete
    asymmetric = {
        **{str(item["dedup_key"]): item for item in missing},
        **{str(item["dedup_key"]): item for item in current_only},
    }
    return FindingDeltaReport(
        previous_run=previous_run,
        current_run=current_run,
        generated_at=generated_at or datetime.now(timezone.utc).isoformat(),
        new=current_only if comparable else [],
        fixed=missing if comparable else [],
        remaining=ordered(current_keys & previous_keys, current),
        inconclusive=(
            [] if comparable else ordered(set(asymmetric), asymmetric)
        ),
        comparison_state="comparable" if comparable else "inconclusive",
        comparison_reason=(
            "" if comparable
            else f"current_collection_{current_collection_status}_or_incomplete_coverage"
        ),
    )


def build_persisted_finding_delta(
    session: Session,
    previous_run: str,
    current_run: str,
    *,
    tenant_id: str,
    policy: RunTruthPolicy | None = None,
    current_collection_status: str | None = None,
    current_coverage_complete: bool | None = None,
) -> FindingDeltaReport:
    """Build a persisted delta from signed run truth, never caller assertions."""
    # Kept only for API compatibility with older call sites.  Comparability is
    # authority-attested persisted state; these caller values cannot affect it.
    del current_collection_status, current_coverage_complete

    comparison_reason = ""
    configured_policy = policy or run_truth_module.RUN_TRUTH_POLICY
    if previous_run:
        try:
            previous_truth = load_run_collection_truth(
                session,
                previous_run,
                tenant_id=tenant_id,
                policy=configured_policy,
            )
        except PersistedRunTruthValidationError as exc:
            previous_truth = None
            comparison_reason = f"previous_{exc.reason}"
    else:
        previous_truth = None
        comparison_reason = "previous_persisted_run_truth_missing"
    try:
        current_truth = load_run_collection_truth(
            session,
            current_run,
            tenant_id=tenant_id,
            policy=configured_policy,
        )
    except PersistedRunTruthValidationError as exc:
        current_truth = None
        if not comparison_reason:
            comparison_reason = f"current_{exc.reason}"

    if comparison_reason:
        comparable = False
    else:
        comparable, comparison_reason = persisted_run_comparability(
            previous_truth,
            current_truth,
            policy=configured_policy,
        )
    report = build_finding_delta(
        (
            list_findings_for_run(session, previous_run, tenant_id=tenant_id)
            if previous_run
            else []
        ),
        list_findings_for_run(session, current_run, tenant_id=tenant_id),
        previous_run=previous_run,
        current_run=current_run,
        current_collection_status="success" if comparable else "unknown",
        current_coverage_complete=comparable,
        generated_at=(current_truth.completed_at if current_truth is not None else None),
    )
    return replace(
        report,
        comparison_reason="" if comparable else comparison_reason,
    )
