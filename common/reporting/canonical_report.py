"""Locked canonical HTML reports and audited exports.

The service freezes persisted Task 101-104 source identities, renders only
Task 102 redacted derivatives, stores the HTML through the same custody
boundary, and returns exports only after a current exact action authorization
has already been consumed by the caller.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from common.action_authorization import ActionAuthorizationEnvelope
from common.artifact_io import read_verified_regular_file
from common.canonical import (
    ArtifactIntegrityState,
    ArtifactReference,
    CanonicalStore,
    RedactionState,
    parse_utc,
)
from common.canonical_evidence import CanonicalEvidenceReader
from common.evidence_custody import (
    ArtifactManifest,
    ArtifactNotFound,
    EvidenceCustodyStore,
)
from common.reporting.report_engine import ReportConfig, ReportEngine
from common.schema_migrations import REFERENCE_SLICE_SCHEMA_VERSION
from common.version import VERSION


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,199}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class CanonicalReportError(RuntimeError):
    reason_code = "canonical_report_failed"


class CanonicalReportNotFound(CanonicalReportError):
    reason_code = "canonical_report_not_found"


class CanonicalReportSourceIncomplete(CanonicalReportError):
    reason_code = "canonical_report_source_incomplete"


class CanonicalReportConflict(CanonicalReportError):
    reason_code = "canonical_report_conflict"


class CanonicalReportAuthorizationError(CanonicalReportError):
    reason_code = "canonical_report_export_not_authorized"


def _identifier(value: str, field: str) -> str:
    normalized = str(value or "").strip()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise CanonicalReportError(f"{field} is invalid")
    return normalized


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes | str) -> str:
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _stable_id(prefix: str, *parts: object) -> str:
    return (
        f"{prefix}:"
        + hashlib.sha256("\x1f".join(str(part) for part in parts).encode("utf-8")).hexdigest()
    )


def report_export_binding(report_id: str, artifact_sha256: str) -> str:
    """Return the exact authorization resource binding for one report version."""

    report = _identifier(report_id, "report_id")
    if _DIGEST.fullmatch(str(artifact_sha256)) is None:
        raise CanonicalReportError("report artifact digest is invalid")
    material = _sha256(f"{report}\x00{artifact_sha256}")
    return "report-export-" + material.removeprefix("sha256:")


def _now(clock: Any) -> str:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CanonicalReportError("report clock must be timezone aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class LockedReport:
    tenant_id: str
    engagement_id: str
    report_id: str
    report_series_id: str
    version: int
    name: str
    source_digest: str
    artifact_id: str
    artifact_sha256: str
    artifact_size: int
    media_type: str
    redaction_state: str
    created_by_operator_id: str
    locked_at: str
    target: str
    source_count: int
    duplicate: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size": self.artifact_size,
            "created_by_operator_id": self.created_by_operator_id,
            "duplicate": self.duplicate,
            "engagement_id": self.engagement_id,
            "format": "html",
            "locked_at": self.locked_at,
            "media_type": self.media_type,
            "name": self.name,
            "redaction_state": self.redaction_state,
            "report_id": self.report_id,
            "report_series_id": self.report_series_id,
            "schema_version": REFERENCE_SLICE_SCHEMA_VERSION,
            "source_count": self.source_count,
            "source_digest": self.source_digest,
            "status": "locked",
            "target": self.target,
            "tenant_id": self.tenant_id,
            "version": self.version,
        }


@dataclass(frozen=True)
class ExportedReport:
    report: LockedReport
    export_id: str
    exported_at: str
    operator_id: str
    authorization_decision_id: str
    authorization_action_id: str
    audit_event_id: str
    content: bytes
    duplicate: bool = False

    def receipt(self) -> dict[str, Any]:
        return {
            "artifact_id": self.report.artifact_id,
            "artifact_sha256": self.report.artifact_sha256,
            "audit_event_id": self.audit_event_id,
            "authorization_action_id": self.authorization_action_id,
            "authorization_decision_id": self.authorization_decision_id,
            "duplicate": self.duplicate,
            "export_id": self.export_id,
            "exported_at": self.exported_at,
            "format": "html",
            "operator_id": self.operator_id,
            "outcome": "completed",
            "report_id": self.report.report_id,
            "report_version": self.report.version,
            "schema_version": REFERENCE_SLICE_SCHEMA_VERSION,
            "tenant_id": self.report.tenant_id,
        }


class CanonicalReportService:
    """Create immutable report versions and export their persisted bytes."""

    def __init__(
        self,
        session: Session,
        custody_root: str | Path,
        *,
        tenant_id: str,
        clock: Any = None,
    ) -> None:
        self.session = session
        self.custody_root = Path(custody_root)
        self.tenant_id = _identifier(tenant_id, "tenant_id")
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.custody = EvidenceCustodyStore(
            self.custody_root,
            self.tenant_id,
        )

    def _ensure_operator(self, operator_id: str, created_at: str) -> None:
        self.session.execute(
            text(
                "INSERT OR IGNORE INTO canonical_operators "
                "(id,tenant_id,schema_version,display_name,external_ref,created_at,metadata_json) "
                "VALUES (:id,:tenant_id,'forge-canonical-v1',:display,NULL,:created_at,'{}')"
            ),
            {
                "id": operator_id,
                "tenant_id": self.tenant_id,
                "display": operator_id,
                "created_at": created_at,
            },
        )
        tenant = self.session.execute(
            text("SELECT tenant_id FROM canonical_operators WHERE id=:id"),
            {"id": operator_id},
        ).scalar_one_or_none()
        if tenant != self.tenant_id:
            raise CanonicalReportAuthorizationError("operator belongs to another tenant")

    def _source_snapshot(self, finding_id: str) -> dict[str, Any]:
        finding = (
            self.session.execute(
                text(
                    "SELECT f.id,f.observation_id,f.artifact_id,f.title,f.status,"
                    "o.engagement_id,o.job_id,o.asset_id,a.canonical_uri,a.identity_key,"
                    "rc.revision_id,rc.version AS review_version,rc.status AS review_status,"
                    "rc.owner_operator_id,rc.notes,rc.updated_by_operator_id,rc.updated_at "
                    "FROM canonical_findings f "
                    "JOIN canonical_observations o "
                    "ON o.tenant_id=f.tenant_id AND o.id=f.observation_id "
                    "JOIN canonical_assets a "
                    "ON a.tenant_id=o.tenant_id AND a.id=o.asset_id "
                    "LEFT JOIN canonical_finding_review_current rc "
                    "ON rc.tenant_id=f.tenant_id AND rc.finding_id=f.id "
                    "WHERE f.tenant_id=:tenant_id AND f.id=:finding_id"
                ),
                {"tenant_id": self.tenant_id, "finding_id": finding_id},
            )
            .mappings()
            .first()
        )
        if finding is None:
            raise CanonicalReportNotFound("finding is unavailable")
        if finding["revision_id"] is None:
            raise CanonicalReportSourceIncomplete(
                "reviewer revision is required before report locking"
            )
        rows = (
            self.session.execute(
                text(
                    "SELECT fo.observation_id,oa.artifact_id,o.engagement_id,o.job_id,"
                    "o.asset_id,o.observed_at,o.proof_type,o.check_id,o.route,"
                    "ar.digest,ar.manifest_digest,am.derivative_sha256,am.derivative_size "
                    "FROM canonical_finding_observations fo "
                    "JOIN canonical_observations o "
                    "ON o.tenant_id=fo.tenant_id AND o.id=fo.observation_id "
                    "JOIN canonical_observation_artifacts oa "
                    "ON oa.tenant_id=o.tenant_id AND oa.observation_id=o.id "
                    "AND oa.role<>'derivative' "
                    "JOIN canonical_artifact_refs ar "
                    "ON ar.tenant_id=oa.tenant_id AND ar.id=oa.artifact_id "
                    "AND ar.observation_id=o.id "
                    "JOIN canonical_artifact_manifests am "
                    "ON am.tenant_id=ar.tenant_id AND am.artifact_id=ar.id "
                    "WHERE fo.tenant_id=:tenant_id AND fo.finding_id=:finding_id "
                    "ORDER BY o.observed_at,o.id,oa.sequence,oa.artifact_id"
                ),
                {"tenant_id": self.tenant_id, "finding_id": finding_id},
            )
            .mappings()
            .all()
        )
        if not rows:
            raise CanonicalReportSourceIncomplete(
                "finding has no verified canonical source artifacts"
            )
        sources = [
            {
                "artifact_id": str(row["artifact_id"]),
                "derivative_sha256": str(row["derivative_sha256"]),
                "derivative_size": int(row["derivative_size"]),
                "engagement_id": str(row["engagement_id"]),
                "job_id": str(row["job_id"]),
                "manifest_digest": str(row["manifest_digest"]),
                "observation_id": str(row["observation_id"]),
                "primary_sha256": str(row["digest"]),
                "retest_attempt_id": None,
                "retest_id": None,
                "retest_proof_id": None,
            }
            for row in rows
        ]
        retest = (
            self.session.execute(
                text(
                    "SELECT r.id AS retest_id,ra.id AS retest_attempt_id,"
                    "ra.state,ra.verdict,p.id AS retest_proof_id,p.sufficient,"
                    "p.observation_id,"
                    "p.artifact_id,o.engagement_id,o.job_id,ar.digest,"
                    "ar.manifest_digest,am.derivative_sha256,am.derivative_size "
                    "FROM canonical_retests r "
                    "JOIN canonical_retest_attempts ra "
                    "ON ra.tenant_id=r.tenant_id AND ra.retest_id=r.id "
                    "LEFT JOIN canonical_retest_proofs p "
                    "ON p.tenant_id=ra.tenant_id AND p.id=ra.proof_id "
                    "LEFT JOIN canonical_observations o "
                    "ON o.tenant_id=p.tenant_id AND o.id=p.observation_id "
                    "LEFT JOIN canonical_artifact_refs ar "
                    "ON ar.tenant_id=p.tenant_id AND ar.id=p.artifact_id "
                    "LEFT JOIN canonical_artifact_manifests am "
                    "ON am.tenant_id=ar.tenant_id AND am.artifact_id=ar.id "
                    "WHERE r.tenant_id=:tenant_id AND r.finding_id=:finding_id "
                    "ORDER BY COALESCE(ra.finished_at,ra.started_at,ra.created_at) DESC,"
                    "ra.id DESC LIMIT 1"
                ),
                {"tenant_id": self.tenant_id, "finding_id": finding_id},
            )
            .mappings()
            .first()
        )
        if (
            retest is None
            or retest["state"] != "terminal"
            or retest["verdict"] is None
            or retest["retest_proof_id"] is None
            or retest["observation_id"] is None
            or retest["artifact_id"] is None
            or retest["manifest_digest"] is None
        ):
            raise CanonicalReportSourceIncomplete(
                "terminal Task 104 proof is required before report locking"
            )
        if finding["review_status"] == "remediated" and not (
            retest["verdict"] == "fixed" and int(retest["sufficient"] or 0) == 1
        ):
            raise CanonicalReportSourceIncomplete(
                "remediated review status conflicts with latest Task 104 proof"
            )
        sources.append(
            {
                "artifact_id": str(retest["artifact_id"]),
                "derivative_sha256": str(retest["derivative_sha256"]),
                "derivative_size": int(retest["derivative_size"]),
                "engagement_id": str(retest["engagement_id"]),
                "job_id": str(retest["job_id"]),
                "manifest_digest": str(retest["manifest_digest"]),
                "observation_id": str(retest["observation_id"]),
                "primary_sha256": str(retest["digest"]),
                "retest_attempt_id": str(retest["retest_attempt_id"]),
                "retest_id": str(retest["retest_id"]),
                "retest_proof_id": str(retest["retest_proof_id"]),
            }
        )
        snapshot = {
            "finding": {
                "artifact_id": str(finding["artifact_id"]),
                "engagement_id": str(finding["engagement_id"]),
                "finding_id": str(finding["id"]),
                "job_id": str(finding["job_id"]),
                "observation_id": str(finding["observation_id"]),
                "status": str(finding["status"]),
                "target": str(finding["canonical_uri"] or finding["identity_key"]),
                "title": str(finding["title"]),
            },
            "review": {
                "notes": str(finding["notes"]),
                "owner_operator_id": (
                    str(finding["owner_operator_id"])
                    if finding["owner_operator_id"] is not None
                    else None
                ),
                "revision_id": str(finding["revision_id"]),
                "status": str(finding["review_status"]),
                "updated_at": str(finding["updated_at"]),
                "updated_by_operator_id": str(finding["updated_by_operator_id"]),
                "version": int(finding["review_version"]),
            },
            "sources": sources,
            # A finding series can span the original scan and later Task 104
            # retest engagements.  Freeze that multi-engagement scope
            # explicitly; the rendered artifact hash and export binding then
            # authorize this exact historical set rather than implying every
            # source belongs to the anchor engagement.
            "source_engagement_ids": sorted({str(item["engagement_id"]) for item in sources}),
        }
        snapshot["source_digest"] = _sha256(_canonical_json(snapshot))
        return snapshot

    def _locked_report_row(
        self,
        *,
        report_id: str | None = None,
        report_series_id: str | None = None,
        source_digest: str | None = None,
    ) -> Any:
        clauses = ["l.tenant_id=:tenant_id"]
        values: dict[str, Any] = {"tenant_id": self.tenant_id}
        if report_id is not None:
            clauses.append("l.report_id=:report_id")
            values["report_id"] = report_id
        if report_series_id is not None:
            clauses.append("l.report_series_id=:report_series_id")
            values["report_series_id"] = report_series_id
        if source_digest is not None:
            clauses.append("l.source_digest=:source_digest")
            values["source_digest"] = source_digest
        return (
            self.session.execute(
                text(
                    "SELECT l.*,r.name,r.version,a.canonical_uri,a.identity_key,"
                    "(SELECT COUNT(*) FROM canonical_report_sources rs "
                    "WHERE rs.tenant_id=l.tenant_id AND rs.report_id=l.report_id) "
                    "AS source_count "
                    "FROM canonical_report_locks l "
                    "JOIN canonical_reports r "
                    "ON r.tenant_id=l.tenant_id AND r.id=l.report_id "
                    "JOIN canonical_report_sources s "
                    "ON s.tenant_id=l.tenant_id AND s.report_id=l.report_id "
                    "AND s.ordinal=0 "
                    "JOIN canonical_observations o "
                    "ON o.tenant_id=s.tenant_id AND o.id=s.observation_id "
                    "JOIN canonical_assets a "
                    "ON a.tenant_id=o.tenant_id AND a.id=o.asset_id "
                    f"WHERE {' AND '.join(clauses)} "
                    "ORDER BY r.version DESC,l.locked_at DESC LIMIT 1"
                ),
                values,
            )
            .mappings()
            .first()
        )

    @staticmethod
    def _locked_projection(row: Any, *, duplicate: bool = False) -> LockedReport:
        return LockedReport(
            tenant_id=str(row["tenant_id"]),
            engagement_id=str(row["engagement_id"]),
            report_id=str(row["report_id"]),
            report_series_id=str(row["report_series_id"]),
            version=int(row["version"]),
            name=str(row["name"]),
            source_digest=str(row["source_digest"]),
            artifact_id=str(row["artifact_id"]),
            artifact_sha256=str(row["artifact_sha256"]),
            artifact_size=int(row["artifact_size"]),
            media_type=str(row["media_type"]),
            redaction_state=str(row["redaction_state"]),
            created_by_operator_id=str(row["created_by_operator_id"]),
            locked_at=str(row["locked_at"]),
            target=str(row["canonical_uri"] or row["identity_key"]),
            source_count=int(row["source_count"]),
            duplicate=duplicate,
        )

    def _verified_locked_projection(
        self,
        row: Any,
        *,
        duplicate: bool = False,
    ) -> LockedReport:
        """Return metadata only after the locked custody bytes verify."""

        manifest = self.custody.verify(str(row["artifact_id"]))
        if not all(
            (
                manifest.manifest_digest == str(row["artifact_manifest_digest"]),
                manifest.source_observation_id == str(row["artifact_observation_id"]),
                manifest.derivative_sha256 == str(row["artifact_sha256"]),
                manifest.derivative_size == int(row["artifact_size"]),
                manifest.media_type == str(row["media_type"]),
                manifest.redaction_state == str(row["redaction_state"]),
            )
        ):
            raise CanonicalReportError("locked report custody does not match its canonical lock")
        return self._locked_projection(row, duplicate=duplicate)

    def _validate_export_authorization(
        self,
        report: LockedReport,
        *,
        operator_id: str,
        authorization: ActionAuthorizationEnvelope,
    ) -> ActionAuthorizationEnvelope:
        """Revalidate one persisted, consumed, exact report action."""

        try:
            envelope = ActionAuthorizationEnvelope.from_value(authorization)
        except Exception:
            raise CanonicalReportAuthorizationError(
                "exact report export authorization is required"
            ) from None
        expected_binding = report_export_binding(
            report.report_id,
            report.artifact_sha256,
        )
        try:
            expires_at = datetime.fromisoformat(
                envelope.expires_at.replace("Z", "+00:00")
            ).astimezone(timezone.utc)
            now = self.clock()
            if not isinstance(now, datetime) or now.tzinfo is None:
                raise ValueError
            now = now.astimezone(timezone.utc)
        except (TypeError, ValueError):
            raise CanonicalReportAuthorizationError(
                "exact report export authorization is required"
            ) from None
        row = (
            self.session.execute(
                text(
                    "SELECT d.envelope_json,d.binding_digest,d.decision_outcome,"
                    "d.tenant_id,d.engagement_id,d.job_id,d.action_id,d.operator_id,"
                    "d.operator_role,d.action_kind,d.engine,d.module_id,"
                    "c.boundary,c.envelope_digest,c.tenant_id AS consumption_tenant,"
                    "c.job_id AS consumption_job,c.action_id AS consumption_action "
                    "FROM authorization_decisions d "
                    "JOIN authorization_consumptions c "
                    "ON c.decision_id=d.decision_id "
                    "WHERE d.decision_id=:decision_id LIMIT 1"
                ),
                {"decision_id": envelope.decision_id},
            )
            .mappings()
            .first()
        )
        if self.session.in_transaction():
            self.session.rollback()
        if row is None or not all(
            (
                envelope.decision_outcome == "allow",
                envelope.single_use is True,
                envelope.tenant_id == self.tenant_id,
                envelope.engagement_id == report.engagement_id,
                envelope.operator_id == operator_id,
                envelope.operator_role in {"operator", "admin"},
                envelope.action_kind == "report.export",
                envelope.engine == "forge",
                envelope.module_id == expected_binding,
                expires_at >= now,
                str(row["envelope_json"]) == envelope.to_json(),
                hmac.compare_digest(
                    str(row["binding_digest"]),
                    envelope.binding_digest,
                ),
                str(row["decision_outcome"]) == "allow",
                str(row["tenant_id"]) == self.tenant_id,
                str(row["engagement_id"]) == report.engagement_id,
                str(row["job_id"]) == envelope.job_id,
                str(row["action_id"]) == envelope.action_id,
                str(row["operator_id"]) == operator_id,
                str(row["operator_role"]) == envelope.operator_role,
                str(row["action_kind"]) == "report.export",
                str(row["engine"]) == "forge",
                str(row["module_id"]) == expected_binding,
                str(row["boundary"]) == "dashboard.report.export",
                hmac.compare_digest(
                    str(row["envelope_digest"]),
                    envelope.binding_digest,
                ),
                str(row["consumption_tenant"]) == self.tenant_id,
                str(row["consumption_job"]) == envelope.job_id,
                str(row["consumption_action"]) == envelope.action_id,
            )
        ):
            raise CanonicalReportAuthorizationError("exact report export authorization is required")
        return envelope

    async def create_html_report(
        self,
        finding_id: str,
        *,
        operator_id: str,
    ) -> LockedReport:
        finding = _identifier(finding_id, "finding_id")
        operator = _identifier(operator_id, "operator_id")
        if self.session.in_transaction():
            self.session.rollback()
        source = self._source_snapshot(finding)
        if self.session.in_transaction():
            self.session.rollback()
        projection = CanonicalEvidenceReader(
            self.session,
            self.custody_root,
            self.tenant_id,
            audit_actor_id=operator,
        ).get_finding_projection(finding)
        if projection is None:
            raise CanonicalReportNotFound("finding is unavailable")
        if self.session.in_transaction():
            self.session.rollback()
        report_series_id = _stable_id(
            "report-series",
            self.tenant_id,
            source["finding"]["engagement_id"],
            finding,
            "html",
        )
        existing = self._locked_report_row(
            report_series_id=report_series_id,
            source_digest=str(source["source_digest"]),
        )
        if self.session.in_transaction():
            self.session.rollback()
        if existing is not None:
            return self._verified_locked_projection(existing, duplicate=True)

        locked_at = _now(self.clock)
        staged_manifest: ArtifactManifest | None = None
        staged_created = False
        committed = False
        transaction_error: Exception | None = None
        report_id = ""
        try:
            try:
                with self.session.begin():
                    if self._source_snapshot(finding) != source:
                        raise CanonicalReportConflict(
                            "canonical report source changed before locking"
                        )
                    version = (
                        int(
                            self.session.execute(
                                text(
                                    "SELECT COALESCE(MAX(r.version),0) "
                                    "FROM canonical_reports r "
                                    "JOIN canonical_report_locks l "
                                    "ON l.tenant_id=r.tenant_id "
                                    "AND l.report_id=r.id "
                                    "WHERE l.tenant_id=:tenant_id "
                                    "AND l.report_series_id=:series_id"
                                ),
                                {
                                    "tenant_id": self.tenant_id,
                                    "series_id": report_series_id,
                                },
                            ).scalar_one()
                        )
                        + 1
                    )
                    report_id = _stable_id(
                        "report-version",
                        report_series_id,
                        version,
                        source["source_digest"],
                    )
                    artifact_id = _stable_id(
                        "artifact",
                        report_id,
                        source["source_digest"],
                    )
                    try:
                        staged_manifest = self.custody.verify(artifact_id)
                    except ArtifactNotFound:
                        pass
                    else:
                        recovered_locked_at = staged_manifest.metadata.get("locked_at")
                        if not isinstance(recovered_locked_at, str):
                            raise CanonicalReportConflict("orphan report artifact lacks lock time")
                        try:
                            parsed_locked_at = datetime.fromisoformat(
                                recovered_locked_at.replace("Z", "+00:00")
                            )
                        except ValueError:
                            raise CanonicalReportConflict(
                                "orphan report artifact lock time is invalid"
                            ) from None
                        if parsed_locked_at.tzinfo is None:
                            raise CanonicalReportConflict(
                                "orphan report artifact lock time is invalid"
                            )
                        locked_at = recovered_locked_at
                    self._ensure_operator(operator, locked_at)
                    self.session.execute(
                        text(
                            "INSERT INTO canonical_reports "
                            "(id,tenant_id,schema_version,name,version,status,"
                            "created_by,created_at,metadata_json) "
                            "VALUES (:id,:tenant_id,'forge-canonical-v1',"
                            "'Reference CSP Assessment',:version,'final',"
                            ":created_by,:created_at,'{}')"
                        ),
                        {
                            "id": report_id,
                            "tenant_id": self.tenant_id,
                            "version": version,
                            "created_by": operator,
                            "created_at": locked_at,
                        },
                    )
                    self.session.execute(
                        text(
                            "INSERT INTO canonical_report_memberships "
                            "(id,tenant_id,report_id,finding_id,observation_id,"
                            "schema_version,created_at,metadata_json) "
                            "VALUES (:id,:tenant_id,:report_id,:finding_id,"
                            ":observation_id,'forge-canonical-v1',:created_at,'{}')"
                        ),
                        {
                            "id": _stable_id("report-membership", report_id, finding),
                            "tenant_id": self.tenant_id,
                            "report_id": report_id,
                            "finding_id": finding,
                            "observation_id": source["finding"]["observation_id"],
                            "created_at": locked_at,
                        },
                    )
                    for ordinal, item in enumerate(source["sources"]):
                        self.session.execute(
                            text(
                                "INSERT INTO canonical_report_sources "
                                "(tenant_id,report_id,ordinal,schema_version,"
                                "engagement_id,finding_id,job_id,observation_id,"
                                "artifact_id,retest_id,retest_attempt_id,"
                                "retest_proof_id,review_revision_id,created_at) "
                                "VALUES (:tenant_id,:report_id,:ordinal,"
                                ":schema_version,:engagement_id,:finding_id,"
                                ":job_id,:observation_id,:artifact_id,:retest_id,"
                                ":retest_attempt_id,:retest_proof_id,"
                                ":review_revision_id,:created_at)"
                            ),
                            {
                                **item,
                                "tenant_id": self.tenant_id,
                                "report_id": report_id,
                                "ordinal": ordinal,
                                "schema_version": REFERENCE_SLICE_SCHEMA_VERSION,
                                "finding_id": finding,
                                "review_revision_id": source["review"]["revision_id"],
                                "created_at": locked_at,
                            },
                        )

                    with tempfile.TemporaryDirectory(
                        prefix=".report-render-",
                        dir=self.custody_root,
                    ) as temporary:
                        render_root = Path(temporary)
                        render_root.chmod(0o700)
                        config = ReportConfig(
                            engagement=str(source["finding"]["engagement_id"]),
                            target=str(source["finding"]["target"]),
                            tester=operator,
                            formats=["html"],
                            output_dir=str(render_root),
                            include_exec_summary=False,
                            include_compliance=False,
                            include_unverified=True,
                            methodology=[
                                "Existing header_audit Content-Security-Policy passive proof"
                            ],
                            scope=[str(source["finding"]["target"])],
                        )
                        engine = ReportEngine([projection], config)
                        engine.generated_at = locked_at
                        engine.findings[0]["canonical_lineage"] = {
                            "artifact_ids": [item["artifact_id"] for item in source["sources"]],
                            "engagement_ids": source["source_engagement_ids"],
                            "finding_id": finding,
                            "job_ids": sorted({item["job_id"] for item in source["sources"]}),
                            "observation_ids": [
                                item["observation_id"] for item in source["sources"]
                            ],
                            "report_id": report_id,
                            "report_version": version,
                            "retest_attempt_id": source["sources"][-1]["retest_attempt_id"],
                            "retest_id": source["sources"][-1]["retest_id"],
                            "review_revision_id": source["review"]["revision_id"],
                            "source_digest": source["source_digest"],
                        }
                        engine.findings[0]["review"] = dict(source["review"])
                        paths = await engine.generate()
                        html_path = paths.get("html")
                        if not html_path:
                            raise CanonicalReportError("HTML report rendering failed")
                        html_bytes = read_verified_regular_file(
                            Path(html_path),
                            require_owner_only_mode=True,
                        )

                    primary_source = source["sources"][0]
                    source_observation = (
                        self.session.execute(
                            text(
                                "SELECT asset_id FROM canonical_observations "
                                "WHERE tenant_id=:tenant_id AND id=:observation_id"
                            ),
                            {
                                "tenant_id": self.tenant_id,
                                "observation_id": primary_source["observation_id"],
                            },
                        )
                        .mappings()
                        .one()
                    )
                    if staged_manifest is None:
                        staged_manifest = self.custody.store_artifact(
                            html_bytes,
                            source_observation_id=primary_source["observation_id"],
                            collector_id="canonical-report-html",
                            media_type="text/html",
                            source_target=str(source["finding"]["target"]),
                            source_asset_id=str(source_observation["asset_id"]),
                            retain_original=False,
                            retention_class="standard",
                            metadata={
                                "capture_kind": "locked_report_html",
                                "locked_at": locked_at,
                            },
                            artifact_id=artifact_id,
                        )
                        staged_created = True
                    expected_html_digest = _sha256(html_bytes)
                    if not all(
                        (
                            staged_manifest.artifact_id == artifact_id,
                            staged_manifest.source_observation_id
                            == primary_source["observation_id"],
                            staged_manifest.collector_id == "canonical-report-html",
                            staged_manifest.media_type == "text/html",
                            staged_manifest.source_target == str(source["finding"]["target"]),
                            staged_manifest.source_asset_id == str(source_observation["asset_id"]),
                            staged_manifest.sha256 == expected_html_digest,
                            staged_manifest.derivative_sha256 == expected_html_digest,
                            staged_manifest.byte_size == len(html_bytes),
                            staged_manifest.derivative_size == len(html_bytes),
                            staged_manifest.metadata.get("capture_kind") == "locked_report_html",
                            staged_manifest.metadata.get("locked_at") == locked_at,
                        )
                    ):
                        raise CanonicalReportConflict(
                            "orphan report artifact conflicts with exact source lock"
                        )
                    artifact = ArtifactReference(
                        id=staged_manifest.artifact_id,
                        tenant_id=self.tenant_id,
                        observation_id=staged_manifest.source_observation_id,
                        reference=staged_manifest.artifact_id,
                        digest=staged_manifest.sha256,
                        media_type=staged_manifest.media_type,
                        size=staged_manifest.byte_size,
                        redaction_state=RedactionState(staged_manifest.redaction_state),
                        encryption_state=staged_manifest.encryption_state,
                        collected_at=parse_utc(staged_manifest.collected_at),
                        collector_id=staged_manifest.collector_id,
                        collector_version=VERSION,
                        source_target=staged_manifest.source_target or "unknown",
                        source_asset_id=staged_manifest.source_asset_id,
                        redaction_version=staged_manifest.redaction_version,
                        protection_state=staged_manifest.protection_state,
                        signer_state=staged_manifest.signer_state,
                        integrity_state=ArtifactIntegrityState.VERIFIED,
                        retention_class=staged_manifest.retention_class,
                        retention_expires_at=(
                            parse_utc(staged_manifest.retention_expires_at)
                            if staged_manifest.retention_expires_at
                            else None
                        ),
                        protected_original_authorization_ref=(
                            staged_manifest.protected_original_authorization_ref
                        ),
                        derivative_reference=(staged_manifest.derivative_artifact_id),
                        manifest_digest=staged_manifest.manifest_digest,
                        metadata={"capture_kind": "locked_report_html"},
                    )
                    canonical = CanonicalStore(self.session)
                    canonical.insert(artifact)
                    canonical.persist_artifact_manifest(
                        staged_manifest,
                        custody_store=self.custody,
                        artifact=artifact,
                        role="derivative",
                        sequence=0,
                    )
                    self.session.execute(
                        text(
                            "INSERT INTO canonical_report_locks "
                            "(tenant_id,report_id,schema_version,engagement_id,"
                            "report_series_id,source_digest,artifact_id,"
                            "artifact_observation_id,artifact_manifest_digest,"
                            "artifact_sha256,artifact_size,media_type,"
                            "redaction_state,created_by_operator_id,locked_at) "
                            "VALUES (:tenant_id,:report_id,:schema_version,"
                            ":engagement_id,:series_id,:source_digest,:artifact_id,"
                            ":observation_id,:manifest_digest,:artifact_sha256,"
                            ":artifact_size,'text/html',:redaction_state,"
                            ":created_by,:locked_at)"
                        ),
                        {
                            "tenant_id": self.tenant_id,
                            "report_id": report_id,
                            "schema_version": REFERENCE_SLICE_SCHEMA_VERSION,
                            "engagement_id": source["finding"]["engagement_id"],
                            "series_id": report_series_id,
                            "source_digest": source["source_digest"],
                            "artifact_id": staged_manifest.artifact_id,
                            "observation_id": staged_manifest.source_observation_id,
                            "manifest_digest": staged_manifest.manifest_digest,
                            "artifact_sha256": staged_manifest.derivative_sha256,
                            "artifact_size": staged_manifest.derivative_size,
                            "redaction_state": staged_manifest.redaction_state,
                            "created_by": operator,
                            "locked_at": locked_at,
                        },
                    )
                committed = True
            except (IntegrityError, OperationalError) as exc:
                transaction_error = exc
        finally:
            if staged_manifest is not None and staged_created and not committed:
                if self.session.in_transaction():
                    self.session.rollback()
                self.custody.rollback_artifact(
                    staged_manifest.artifact_id,
                    expected_manifest_digest=staged_manifest.manifest_digest,
                )
        if transaction_error is not None:
            if self.session.in_transaction():
                self.session.rollback()
            concurrent = self._locked_report_row(
                report_series_id=report_series_id,
                source_digest=str(source["source_digest"]),
            )
            if self.session.in_transaction():
                self.session.rollback()
            if concurrent is not None:
                return self._verified_locked_projection(
                    concurrent,
                    duplicate=True,
                )
            raise CanonicalReportConflict(
                "concurrent canonical report lock was not idempotent"
            ) from transaction_error
        row = self._locked_report_row(report_id=report_id)
        if self.session.in_transaction():
            self.session.rollback()
        if row is None:
            raise CanonicalReportError("locked report was not persisted")
        return self._verified_locked_projection(row)

    def get_report(self, report_id: str) -> LockedReport:
        report = _identifier(report_id, "report_id")
        row = self._locked_report_row(report_id=report)
        if self.session.in_transaction():
            self.session.rollback()
        if row is None:
            raise CanonicalReportNotFound("report is unavailable")
        return self._verified_locked_projection(row)

    def list_reports(self, *, limit: int = 50) -> list[LockedReport]:
        bounded = max(1, min(int(limit), 200))
        rows = (
            self.session.execute(
                text(
                    "SELECT l.*,r.name,r.version,a.canonical_uri,a.identity_key,"
                    "(SELECT COUNT(*) FROM canonical_report_sources rs "
                    "WHERE rs.tenant_id=l.tenant_id AND rs.report_id=l.report_id) "
                    "AS source_count "
                    "FROM canonical_report_locks l "
                    "JOIN canonical_reports r "
                    "ON r.tenant_id=l.tenant_id AND r.id=l.report_id "
                    "JOIN canonical_report_sources s "
                    "ON s.tenant_id=l.tenant_id AND s.report_id=l.report_id "
                    "AND s.ordinal=0 "
                    "JOIN canonical_observations o "
                    "ON o.tenant_id=s.tenant_id AND o.id=s.observation_id "
                    "JOIN canonical_assets a "
                    "ON a.tenant_id=o.tenant_id AND a.id=o.asset_id "
                    "WHERE l.tenant_id=:tenant_id "
                    "ORDER BY l.locked_at DESC,r.version DESC LIMIT :limit"
                ),
                {"tenant_id": self.tenant_id, "limit": bounded},
            )
            .mappings()
            .all()
        )
        if self.session.in_transaction():
            self.session.rollback()
        return [self._verified_locked_projection(row) for row in rows]

    def export_html(
        self,
        report_id: str,
        *,
        operator_id: str,
        authorization: ActionAuthorizationEnvelope,
        request_id: str,
    ) -> ExportedReport:
        report_name = _identifier(report_id, "report_id")
        row = self._locked_report_row(report_id=report_name)
        if self.session.in_transaction():
            self.session.rollback()
        if row is None:
            raise CanonicalReportNotFound("report is unavailable")
        # Authorization is checked against immutable lock metadata before any
        # custody read, so an unactioned caller cannot use integrity failures
        # as an artifact-existence oracle.
        report = self._locked_projection(row)
        operator = _identifier(operator_id, "operator_id")
        request = _identifier(request_id, "request_id")
        authorization = self._validate_export_authorization(
            report,
            operator_id=operator,
            authorization=authorization,
        )
        report = self._verified_locked_projection(row)
        existing = (
            self.session.execute(
                text(
                    "SELECT er.*,e.created_at FROM canonical_export_receipts er "
                    "JOIN canonical_exports e "
                    "ON e.tenant_id=er.tenant_id AND e.id=er.export_id "
                    "WHERE er.tenant_id=:tenant_id AND er.report_id=:report_id "
                    "AND er.operator_id=:operator_id AND er.request_id=:request_id"
                ),
                {
                    "tenant_id": self.tenant_id,
                    "report_id": report.report_id,
                    "operator_id": operator,
                    "request_id": request,
                },
            )
            .mappings()
            .first()
        )
        if self.session.in_transaction():
            self.session.rollback()
        content = self.custody.read(
            report.artifact_id,
            actor_id=operator,
        )
        if _sha256(content) != report.artifact_sha256 or len(content) != report.artifact_size:
            raise CanonicalReportError("locked report artifact failed verification")
        if existing is not None:
            if not all(
                (
                    str(existing["report_id"]) == report.report_id,
                    int(existing["report_version"]) == report.version,
                    str(existing["report_artifact_id"]) == report.artifact_id,
                    str(existing["report_sha256"]) == report.artifact_sha256,
                    str(existing["operator_id"]) == operator,
                    str(existing["authorization_decision_id"]) == authorization.decision_id,
                    str(existing["authorization_action_id"]) == authorization.action_id,
                )
            ):
                raise CanonicalReportConflict(
                    "export idempotency key conflicts with prior authorization"
                )
            return ExportedReport(
                report=report,
                export_id=str(existing["export_id"]),
                exported_at=str(existing["exported_at"]),
                operator_id=operator,
                authorization_decision_id=str(existing["authorization_decision_id"]),
                authorization_action_id=str(existing["authorization_action_id"]),
                audit_event_id=str(existing["audit_event_id"]),
                content=content,
                duplicate=True,
            )
        exported_at = _now(self.clock)
        export_id = _stable_id(
            "export",
            self.tenant_id,
            report.report_id,
            operator,
            request,
        )
        audit_event_id = _stable_id("event", export_id, "completed")
        try:
            with self.session.begin():
                self._ensure_operator(operator, exported_at)
                source = (
                    self.session.execute(
                        text(
                            "SELECT finding_id,observation_id,job_id "
                            "FROM canonical_report_sources "
                            "WHERE tenant_id=:tenant_id AND report_id=:report_id "
                            "ORDER BY ordinal LIMIT 1"
                        ),
                        {"tenant_id": self.tenant_id, "report_id": report.report_id},
                    )
                    .mappings()
                    .one()
                )
                self.session.execute(
                    text(
                        "INSERT INTO canonical_events "
                        "(id,tenant_id,job_id,actor_id,schema_version,event_type,level,"
                        "created_at,metadata_json) "
                        "VALUES (:id,:tenant_id,:job_id,:actor_id,'forge-canonical-v1',"
                        "'report.export.completed','info',:created_at,:metadata_json)"
                    ),
                    {
                        "id": audit_event_id,
                        "tenant_id": self.tenant_id,
                        "job_id": source["job_id"],
                        "actor_id": operator,
                        "created_at": exported_at,
                        "metadata_json": json.dumps(
                            {
                                "format": "html",
                                "outcome": "completed",
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    },
                )
                self.session.execute(
                    text(
                        "INSERT INTO canonical_exports "
                        "(id,tenant_id,finding_id,source_observation_id,report_id,"
                        "provenance_id,schema_version,format,status,created_at,metadata_json) "
                        "VALUES (:id,:tenant_id,:finding_id,:observation_id,:report_id,NULL,"
                        "'forge-canonical-v1','html','completed',:created_at,'{}')"
                    ),
                    {
                        "id": export_id,
                        "tenant_id": self.tenant_id,
                        "finding_id": source["finding_id"],
                        "observation_id": source["observation_id"],
                        "report_id": report.report_id,
                        "created_at": exported_at,
                    },
                )
                self.session.execute(
                    text(
                        "INSERT INTO canonical_export_receipts "
                        "(tenant_id,export_id,schema_version,engagement_id,report_id,"
                        "report_version,report_artifact_id,report_sha256,operator_id,"
                        "authorization_decision_id,authorization_action_id,request_id,"
                        "exported_at,format,outcome,audit_event_id) "
                        "VALUES (:tenant_id,:export_id,:schema_version,:engagement_id,"
                        ":report_id,:report_version,:artifact_id,:report_sha256,"
                        ":operator_id,:decision_id,:action_id,:request_id,:exported_at,"
                        "'html','completed',:audit_event_id)"
                    ),
                    {
                        "tenant_id": self.tenant_id,
                        "export_id": export_id,
                        "schema_version": REFERENCE_SLICE_SCHEMA_VERSION,
                        "engagement_id": report.engagement_id,
                        "report_id": report.report_id,
                        "report_version": report.version,
                        "artifact_id": report.artifact_id,
                        "report_sha256": report.artifact_sha256,
                        "operator_id": operator,
                        "decision_id": authorization.decision_id,
                        "action_id": authorization.action_id,
                        "request_id": request,
                        "exported_at": exported_at,
                        "audit_event_id": audit_event_id,
                    },
                )
        except (IntegrityError, OperationalError) as exc:
            if self.session.in_transaction():
                self.session.rollback()
            concurrent = (
                self.session.execute(
                    text(
                        "SELECT er.*,e.created_at FROM canonical_export_receipts er "
                        "JOIN canonical_exports e "
                        "ON e.tenant_id=er.tenant_id AND e.id=er.export_id "
                        "WHERE er.tenant_id=:tenant_id "
                        "AND er.report_id=:report_id "
                        "AND er.operator_id=:operator_id "
                        "AND er.request_id=:request_id"
                    ),
                    {
                        "tenant_id": self.tenant_id,
                        "report_id": report.report_id,
                        "operator_id": operator,
                        "request_id": request,
                    },
                )
                .mappings()
                .first()
            )
            if self.session.in_transaction():
                self.session.rollback()
            if concurrent is not None and all(
                (
                    int(concurrent["report_version"]) == report.version,
                    str(concurrent["report_artifact_id"]) == report.artifact_id,
                    str(concurrent["report_sha256"]) == report.artifact_sha256,
                    str(concurrent["authorization_decision_id"]) == authorization.decision_id,
                    str(concurrent["authorization_action_id"]) == authorization.action_id,
                )
            ):
                return ExportedReport(
                    report=report,
                    export_id=str(concurrent["export_id"]),
                    exported_at=str(concurrent["exported_at"]),
                    operator_id=operator,
                    authorization_decision_id=authorization.decision_id,
                    authorization_action_id=authorization.action_id,
                    audit_event_id=str(concurrent["audit_event_id"]),
                    content=content,
                    duplicate=True,
                )
            raise CanonicalReportConflict("concurrent canonical export was not idempotent") from exc
        return ExportedReport(
            report=report,
            export_id=export_id,
            exported_at=exported_at,
            operator_id=operator,
            authorization_decision_id=authorization.decision_id,
            authorization_action_id=authorization.action_id,
            audit_event_id=audit_event_id,
            content=content,
        )


__all__ = [
    "CanonicalReportAuthorizationError",
    "CanonicalReportConflict",
    "CanonicalReportError",
    "CanonicalReportNotFound",
    "CanonicalReportService",
    "CanonicalReportSourceIncomplete",
    "ExportedReport",
    "LockedReport",
    "report_export_binding",
]
