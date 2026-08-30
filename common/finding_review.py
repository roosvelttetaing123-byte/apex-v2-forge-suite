"""Canonical optimistic reviewer workflow for persisted findings.

Task 105 keeps one mutable current projection and an append-only revision
history.  Authenticated server context supplies the actor and any claimed
owner; clients supply only an expected version and the requested field values.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from common.redaction import redact_text
from common.schema_migrations import REFERENCE_SLICE_SCHEMA_VERSION


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,199}$")


class FindingReviewError(RuntimeError):
    """A reviewer request failed closed."""

    reason_code = "finding_review_failed"


class FindingReviewNotFound(FindingReviewError):
    reason_code = "finding_not_found"


class FindingReviewConflict(FindingReviewError):
    reason_code = "finding_review_version_conflict"


class FindingReviewFixedProofRequired(FindingReviewConflict):
    reason_code = "finding_review_fixed_proof_required"


class FindingReviewForbidden(FindingReviewError):
    reason_code = "finding_review_forbidden"


class FindingReviewInvalid(FindingReviewError, ValueError):
    reason_code = "finding_review_invalid"


class ReviewStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class OwnershipAction(str, Enum):
    UNCHANGED = "unchanged"
    CLAIM = "claim"
    RELEASE = "release"


_STATUS_ALIASES = {
    "open": ReviewStatus.OPEN,
    "in progress": ReviewStatus.IN_PROGRESS,
    "in_progress": ReviewStatus.IN_PROGRESS,
    "fixed": ReviewStatus.REMEDIATED,
    "remediated": ReviewStatus.REMEDIATED,
    "accepted": ReviewStatus.ACCEPTED_RISK,
    "accepted_risk": ReviewStatus.ACCEPTED_RISK,
    "false positive": ReviewStatus.FALSE_POSITIVE,
    "false_positive": ReviewStatus.FALSE_POSITIVE,
}


def _identifier(value: str, field: str) -> str:
    normalized = str(value or "").strip()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise FindingReviewInvalid(f"{field} is invalid")
    return normalized


def _status(value: str | ReviewStatus) -> ReviewStatus:
    if isinstance(value, ReviewStatus):
        return value
    normalized = str(value or "").strip().lower()
    try:
        return _STATUS_ALIASES[normalized]
    except KeyError:
        raise FindingReviewInvalid("review status is invalid") from None


def _timestamp(clock: Any) -> str:
    value = clock()
    if not isinstance(value, datetime):
        raise FindingReviewInvalid("review clock is invalid")
    if value.tzinfo is None or value.utcoffset() is None:
        raise FindingReviewInvalid("review clock must be timezone aware")
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _revision_id(tenant_id: str, finding_id: str, version: int) -> str:
    material = f"{tenant_id}\x00{finding_id}\x00{version}".encode("utf-8")
    return "review-revision:" + hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class FindingReviewProjection:
    tenant_id: str
    finding_id: str
    version: int
    status: ReviewStatus
    owner_operator_id: str | None
    notes: str
    revision_id: str | None
    updated_by_operator_id: str | None
    updated_at: str | None
    duplicate: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "duplicate": self.duplicate,
            "finding_id": self.finding_id,
            "notes": self.notes,
            "owner_operator_id": self.owner_operator_id,
            "revision_id": self.revision_id,
            "schema_version": REFERENCE_SLICE_SCHEMA_VERSION,
            "status": self.status.value,
            "tenant_id": self.tenant_id,
            "updated_at": self.updated_at,
            "updated_by_operator_id": self.updated_by_operator_id,
            "version": self.version,
        }


class FindingReviewService:
    """CAS-backed current reviewer state with immutable revisions."""

    def __init__(self, session: Session, *, tenant_id: str, clock: Any = None):
        self.session = session
        self.tenant_id = _identifier(tenant_id, "tenant_id")
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _finding_status(self, finding_id: str) -> ReviewStatus:
        row = self.session.execute(
            text(
                "SELECT status FROM canonical_findings "
                "WHERE tenant_id=:tenant_id AND id=:finding_id"
            ),
            {"tenant_id": self.tenant_id, "finding_id": finding_id},
        ).first()
        if row is None:
            raise FindingReviewNotFound("finding is unavailable")
        try:
            return _status(str(row[0]))
        except FindingReviewInvalid:
            return ReviewStatus.OPEN

    def _current_row(self, finding_id: str) -> Any:
        return self.session.execute(
            text(
                "SELECT * FROM canonical_finding_review_current "
                "WHERE tenant_id=:tenant_id AND finding_id=:finding_id"
            ),
            {"tenant_id": self.tenant_id, "finding_id": finding_id},
        ).mappings().first()

    def _latest_retest_is_sufficient_fixed(self, finding_id: str) -> bool:
        """Require the latest Task 104 attempt to carry its exact fixed proof."""

        row = self.session.execute(
            text(
                "SELECT r.id AS retest_id,r.source_observation_id,"
                "r.verifier_id AS request_verifier_id,"
                "r.verifier_version AS request_verifier_version,"
                "r.proof_policy_version AS request_proof_policy_version,"
                "r.proof_expectation AS request_proof_expectation,"
                "ra.id AS attempt_id,ra.state AS attempt_state,ra.verdict,"
                "ra.proof_id AS attempt_proof_id,p.id AS proof_id,"
                "p.retest_id AS proof_retest_id,"
                "p.retest_attempt_id AS proof_attempt_id,"
                "p.original_observation_id,p.verifier_id AS proof_verifier_id,"
                "p.verifier_version AS proof_verifier_version,"
                "p.proof_policy_version AS proof_policy_version,"
                "p.proof_expectation AS proof_expectation,p.sufficient "
                "FROM canonical_retests r "
                "JOIN canonical_retest_attempts ra "
                "ON ra.tenant_id=r.tenant_id AND ra.retest_id=r.id "
                "LEFT JOIN canonical_retest_proofs p "
                "ON p.tenant_id=ra.tenant_id AND p.id=ra.proof_id "
                "WHERE r.tenant_id=:tenant_id AND r.finding_id=:finding_id "
                "ORDER BY COALESCE(ra.finished_at,ra.started_at,ra.created_at) "
                "DESC,ra.id DESC LIMIT 1"
            ),
            {"tenant_id": self.tenant_id, "finding_id": finding_id},
        ).mappings().first()
        if row is None:
            return False
        return bool(
            row["attempt_state"] == "terminal"
            and row["verdict"] == "fixed"
            and row["attempt_proof_id"] is not None
            and row["attempt_proof_id"] == row["proof_id"]
            and row["proof_retest_id"] == row["retest_id"]
            and row["proof_attempt_id"] == row["attempt_id"]
            and row["original_observation_id"] == row["source_observation_id"]
            and row["proof_verifier_id"] == row["request_verifier_id"]
            and row["proof_verifier_version"]
            == row["request_verifier_version"]
            and row["proof_policy_version"]
            == row["request_proof_policy_version"]
            and row["proof_expectation"] == row["request_proof_expectation"]
            and int(row["sufficient"] or 0) == 1
        )

    def _require_latest_fixed_proof(self, finding_id: str) -> None:
        if not self._latest_retest_is_sufficient_fixed(finding_id):
            raise FindingReviewFixedProofRequired(
                "remediated review status requires the latest sufficient "
                "Task 104 fixed proof"
            )

    @staticmethod
    def _duplicate_replay(
        current: Any,
        *,
        expected_version: int,
        actor: str,
        requested_status: ReviewStatus | None,
        safe_notes: str | None,
        ownership_action: OwnershipAction,
    ) -> bool:
        """Recognize one already-committed retry without hiding lost updates."""

        if (
            current is None
            or int(current["version"]) != expected_version + 1
            or str(current["updated_by_operator_id"]) != actor
        ):
            return False
        supplied_change = False
        if requested_status is not None:
            supplied_change = True
            if str(current["status"]) != requested_status.value:
                return False
        if safe_notes is not None:
            supplied_change = True
            if str(current["notes"]) != safe_notes:
                return False
        if ownership_action is OwnershipAction.CLAIM:
            supplied_change = True
            if current["owner_operator_id"] != actor:
                return False
        elif ownership_action is OwnershipAction.RELEASE:
            supplied_change = True
            if current["owner_operator_id"] is not None:
                return False
        return supplied_change

    @staticmethod
    def _is_review_unique_race(exc: IntegrityError) -> bool:
        message = str(getattr(exc, "orig", exc)).lower()
        return "unique constraint failed" in message and (
            "canonical_finding_review_revisions" in message
            or "canonical_finding_review_current" in message
        )

    @staticmethod
    def _is_database_busy(exc: OperationalError) -> bool:
        message = str(getattr(exc, "orig", exc)).lower()
        return "locked" in message or "database is busy" in message

    def get(self, finding_id: str) -> FindingReviewProjection:
        finding = _identifier(finding_id, "finding_id")
        try:
            status = self._finding_status(finding)
            row = self._current_row(finding)
            if row is None:
                projection = FindingReviewProjection(
                    tenant_id=self.tenant_id,
                    finding_id=finding,
                    version=0,
                    status=status,
                    owner_operator_id=None,
                    notes="",
                    revision_id=None,
                    updated_by_operator_id=None,
                    updated_at=None,
                )
            else:
                projection = self._projection(row)
            if projection.status is ReviewStatus.REMEDIATED:
                self._require_latest_fixed_proof(finding)
        finally:
            if self.session.in_transaction():
                self.session.rollback()
        return projection

    @staticmethod
    def _projection(row: Any, *, duplicate: bool = False) -> FindingReviewProjection:
        return FindingReviewProjection(
            tenant_id=str(row["tenant_id"]),
            finding_id=str(row["finding_id"]),
            version=int(row["version"]),
            status=ReviewStatus(str(row["status"])),
            owner_operator_id=(
                str(row["owner_operator_id"])
                if row["owner_operator_id"] is not None
                else None
            ),
            notes=str(row["notes"]),
            revision_id=str(row["revision_id"]),
            updated_by_operator_id=str(row["updated_by_operator_id"]),
            updated_at=str(row["updated_at"]),
            duplicate=duplicate,
        )

    def _ensure_operator(self, operator_id: str) -> None:
        self.session.execute(
            text(
                "INSERT OR IGNORE INTO canonical_operators "
                "(id,tenant_id,schema_version,display_name,external_ref,created_at,metadata_json) "
                "VALUES (:id,:tenant_id,'forge-canonical-v1',:display_name,NULL,:created_at,'{}')"
            ),
            {
                "id": operator_id,
                "tenant_id": self.tenant_id,
                "display_name": operator_id,
                "created_at": _timestamp(self.clock),
            },
        )
        tenant = self.session.execute(
            text("SELECT tenant_id FROM canonical_operators WHERE id=:id"),
            {"id": operator_id},
        ).scalar_one_or_none()
        if tenant != self.tenant_id:
            raise FindingReviewForbidden("operator belongs to another tenant")

    def update(
        self,
        finding_id: str,
        *,
        expected_version: int,
        actor_operator_id: str,
        actor_role: str,
        status: str | ReviewStatus | None = None,
        notes: str | None = None,
        ownership: str | OwnershipAction = OwnershipAction.UNCHANGED,
    ) -> FindingReviewProjection:
        finding = _identifier(finding_id, "finding_id")
        actor = _identifier(actor_operator_id, "actor_operator_id")
        role = str(actor_role or "").strip().lower()
        if role not in {"operator", "admin", "system"}:
            raise FindingReviewForbidden("reviewer role is not allowed")
        if isinstance(expected_version, bool) or not isinstance(
            expected_version, int
        ) or expected_version < 0:
            raise FindingReviewInvalid("expected_version is invalid")
        try:
            ownership_action = OwnershipAction(ownership)
        except ValueError:
            raise FindingReviewInvalid("ownership action is invalid") from None
        if notes is not None and not isinstance(notes, str):
            raise FindingReviewInvalid("review notes must be text")
        requested_status = _status(status) if status is not None else None
        safe_notes = None if notes is None else redact_text(notes)
        if safe_notes is not None and len(safe_notes) > 4000:
            raise FindingReviewInvalid("review notes exceed the limit")
        if self.session.in_transaction():
            raise FindingReviewInvalid("review update requires an idle session")

        try:
            with self.session.begin():
                finding_status = self._finding_status(finding)
                current = self._current_row(finding)
                current_version = (
                    int(current["version"]) if current is not None else 0
                )
                if current_version != expected_version:
                    if self._duplicate_replay(
                        current,
                        expected_version=expected_version,
                        actor=actor,
                        requested_status=requested_status,
                        safe_notes=safe_notes,
                        ownership_action=ownership_action,
                    ):
                        projection = self._projection(current, duplicate=True)
                        if projection.status is ReviewStatus.REMEDIATED:
                            self._require_latest_fixed_proof(finding)
                        return projection
                    raise FindingReviewConflict("review version is stale")
                self._ensure_operator(actor)
                current_status = (
                    ReviewStatus(str(current["status"]))
                    if current is not None
                    else finding_status
                )
                next_status = requested_status or current_status
                if next_status is ReviewStatus.REMEDIATED:
                    self._require_latest_fixed_proof(finding)
                current_owner = (
                    str(current["owner_operator_id"])
                    if current is not None
                    and current["owner_operator_id"] is not None
                    else None
                )
                if ownership_action is OwnershipAction.CLAIM:
                    if (
                        current_owner not in {None, actor}
                        and role != "admin"
                    ):
                        raise FindingReviewForbidden(
                            "only an administrator may replace another owner"
                        )
                    next_owner = actor
                elif ownership_action is OwnershipAction.RELEASE:
                    if current_owner not in {None, actor} and role != "admin":
                        raise FindingReviewForbidden(
                            "only the current owner or an administrator may "
                            "release ownership"
                        )
                    next_owner = None
                else:
                    next_owner = current_owner
                next_notes = (
                    safe_notes
                    if safe_notes is not None
                    else str(current["notes"] if current is not None else "")
                )
                if (
                    current is not None
                    and next_status.value == str(current["status"])
                    and next_owner == current_owner
                    and next_notes == str(current["notes"])
                ):
                    return self._projection(current, duplicate=True)

                next_version = current_version + 1
                revision_id = _revision_id(
                    self.tenant_id,
                    finding,
                    next_version,
                )
                created_at = _timestamp(self.clock)
                self.session.execute(
                    text(
                        "INSERT INTO canonical_finding_review_revisions "
                        "(id,tenant_id,finding_id,schema_version,version,status,"
                        "owner_operator_id,notes,actor_operator_id,actor_role,created_at) "
                        "VALUES (:id,:tenant_id,:finding_id,:schema_version,:version,:status,"
                        ":owner,:notes,:actor,:role,:created_at)"
                    ),
                    {
                        "id": revision_id,
                        "tenant_id": self.tenant_id,
                        "finding_id": finding,
                        "schema_version": REFERENCE_SLICE_SCHEMA_VERSION,
                        "version": next_version,
                        "status": next_status.value,
                        "owner": next_owner,
                        "notes": next_notes,
                        "actor": actor,
                        "role": role,
                        "created_at": created_at,
                    },
                )
                values = {
                    "tenant_id": self.tenant_id,
                    "finding_id": finding,
                    "revision_id": revision_id,
                    "schema_version": REFERENCE_SLICE_SCHEMA_VERSION,
                    "version": next_version,
                    "status": next_status.value,
                    "owner": next_owner,
                    "notes": next_notes,
                    "actor": actor,
                    "updated_at": created_at,
                    "expected_version": expected_version,
                }
                if current is None:
                    self.session.execute(
                        text(
                            "INSERT INTO canonical_finding_review_current "
                            "(tenant_id,finding_id,revision_id,schema_version,version,status,"
                            "owner_operator_id,notes,updated_by_operator_id,updated_at) "
                            "VALUES (:tenant_id,:finding_id,:revision_id,:schema_version,"
                            ":version,:status,:owner,:notes,:actor,:updated_at)"
                        ),
                        values,
                    )
                else:
                    result = self.session.execute(
                        text(
                            "UPDATE canonical_finding_review_current SET "
                            "revision_id=:revision_id,schema_version=:schema_version,"
                            "version=:version,status=:status,owner_operator_id=:owner,"
                            "notes=:notes,updated_by_operator_id=:actor,"
                            "updated_at=:updated_at "
                            "WHERE tenant_id=:tenant_id AND finding_id=:finding_id "
                            "AND version=:expected_version"
                        ),
                        values,
                    )
                    if getattr(result, "rowcount", 0) != 1:
                        raise FindingReviewConflict(
                            "review version changed concurrently"
                        )
                # Do not mirror reviewer status into canonical_findings.  A
                # repeat observation may refresh that deduplicated finding
                # summary; the versioned row above remains reviewer truth.
                row = self._current_row(finding)
                if row is None:
                    raise FindingReviewError(
                        "review projection was not persisted"
                    )
                projection = self._projection(row)
            return projection
        except IntegrityError as exc:
            if not self._is_review_unique_race(exc):
                raise
            self.session.rollback()
            try:
                current = self._current_row(finding)
                if self._duplicate_replay(
                    current,
                    expected_version=expected_version,
                    actor=actor,
                    requested_status=requested_status,
                    safe_notes=safe_notes,
                    ownership_action=ownership_action,
                ):
                    projection = self._projection(current, duplicate=True)
                    if projection.status is ReviewStatus.REMEDIATED:
                        self._require_latest_fixed_proof(finding)
                    return projection
            except OperationalError as race_exc:
                if not self._is_database_busy(race_exc):
                    raise
                raise FindingReviewConflict(
                    "review database was busy while resolving a uniqueness race"
                ) from None
            finally:
                if self.session.in_transaction():
                    self.session.rollback()
            raise FindingReviewConflict(
                "review version changed concurrently"
            ) from None
        except OperationalError as exc:
            if not self._is_database_busy(exc):
                raise
            self.session.rollback()
            raise FindingReviewConflict(
                "review database was busy during compare-and-swap"
            ) from None

    def revisions(self, finding_id: str) -> list[dict[str, Any]]:
        finding = _identifier(finding_id, "finding_id")
        self._finding_status(finding)
        rows = self.session.execute(
            text(
                "SELECT * FROM canonical_finding_review_revisions "
                "WHERE tenant_id=:tenant_id AND finding_id=:finding_id "
                "ORDER BY version"
            ),
            {"tenant_id": self.tenant_id, "finding_id": finding},
        ).mappings().all()
        if self.session.in_transaction():
            self.session.rollback()
        return [dict(row) for row in rows]


__all__ = [
    "FindingReviewConflict",
    "FindingReviewError",
    "FindingReviewFixedProofRequired",
    "FindingReviewForbidden",
    "FindingReviewInvalid",
    "FindingReviewNotFound",
    "FindingReviewProjection",
    "FindingReviewService",
    "OwnershipAction",
    "ReviewStatus",
]
