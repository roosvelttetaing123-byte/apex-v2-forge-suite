"""Application boundary for canonical finding and evidence persistence.

Task 102 requires one production path from a consumed action authorization to
immutable observations, custodied artifact manifests, mutable finding
summaries, and verified ordinary-consumer projections.  This module owns that
path; callers never assemble filesystem paths or inline raw evidence records.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from common.action_authorization import ActionAuthorizationEnvelope
from common.canonical import (
    Action,
    ArtifactReference,
    ArtifactIntegrityState,
    Asset,
    AssetKind,
    CanonicalContractError,
    CanonicalStore,
    CollectionStatus,
    Engagement,
    EngagementStatus,
    Finding as CanonicalFinding,
    FindingSeverity,
    FindingStatus,
    Job,
    JobStatus,
    ModuleExecution,
    ModuleExecutionStatus,
    ModuleVersion,
    Observation,
    ObservationStatus,
    Operator,
    RedactionState,
    Role,
    ScopeDecision,
    ScopeOutcome,
    Tenant,
    normalize_asset_identity,
    parse_utc,
    utc_now,
)
from common.evidence import CapturedEvidenceArtifact
from common.evidence_custody import (
    ArtifactAccessDenied,
    ArtifactManifest,
    ArtifactNotFound,
    ArtifactTransactionError,
    EvidenceCustodyStore,
    ProtectedOriginalAuthorization,
)
from common.finding import Finding
from common.redaction import redact_text, redact_value
from common.version import VERSION


_MAX_DERIVATIVE_PROJECTION_BYTES = 16_384
JOB_ATTEMPT_ID_ENV = "FORGE_JOB_ATTEMPT_ID"


class CanonicalEvidenceError(CanonicalContractError):
    """Canonical evidence integration failed closed."""


def _stable_id(prefix: str, *parts: str) -> str:
    material = "\x1f".join(str(part) for part in parts).encode(
        "utf-8", errors="strict"
    )
    return f"{prefix}:{hashlib.sha256(material).hexdigest()}"


def _safe_url_asset(value: str) -> tuple[AssetKind, str]:
    rendered = str(value or "").strip()
    parsed = urlsplit(rendered)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        # Query values can carry credentials or payload bytes.  Route and
        # parameter names remain first-class observation dimensions; the asset
        # identity deliberately excludes query values and fragments.
        rendered = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path or "/", "", "")
        )
        return normalize_asset_identity(AssetKind.URL, rendered)
    return normalize_asset_identity(AssetKind.HOST, rendered or "unknown")


def _dimension(extra: Mapping[str, Any], aliases: tuple[str, ...]) -> str | None:
    pending: list[Mapping[str, Any]] = [extra]
    seen: set[int] = set()
    while pending:
        current = pending.pop(0)
        if id(current) in seen:
            continue
        seen.add(id(current))
        for alias in aliases:
            value = current.get(alias)
            if value is None or value == "":
                continue
            if isinstance(value, Mapping):
                # A mapping commonly represents query/form parameters.  Its
                # values are protected evidence, not observation identity.
                names = sorted(
                    {
                        redact_text(str(key)).strip()
                        for key in value
                        if str(key).strip()
                    }
                )
                return ",".join(names) or None
            if isinstance(value, (list, tuple)):
                # Preserve scalar dimension names while refusing to flatten
                # nested payloads into ordinary canonical projections.
                items = [
                    redact_text(str(item)).strip()
                    for item in value
                    if item is not None
                    and not isinstance(item, (Mapping, list, tuple, set))
                    and str(item).strip()
                ]
                return ",".join(items) or None
            return redact_text(str(value))
        for key in (
            "observation",
            "canonical_observation",
            "dimensions",
            "context",
            "metadata",
        ):
            child = current.get(key)
            if isinstance(child, Mapping):
                pending.append(child)
    return None


@dataclass(frozen=True)
class CanonicalEvidenceContext:
    """Exact trusted execution context for one module evidence producer."""

    tenant_id: str
    engagement_id: str
    run_id: str
    job_id: str
    action_id: str
    decision_id: str
    operator_id: str
    operator_role: str
    engine: str
    module_id: str
    action_kind: str
    scope_policy_version: str
    scope_reason: str
    attempt_id: str | None = None
    decided_at: datetime = field(default_factory=utc_now)

    @property
    def original_authorization_ref(self) -> str:
        return f"authorization:{self.decision_id}"

    @classmethod
    def from_authorization(
        cls,
        envelope: ActionAuthorizationEnvelope,
        *,
        attempt_id: str | None = None,
    ) -> "CanonicalEvidenceContext":
        if not isinstance(envelope, ActionAuthorizationEnvelope):
            raise CanonicalEvidenceError(
                "canonical evidence requires a typed authorization envelope"
            )
        if envelope.decision_outcome != "allow" or envelope.scope_decision != "allowed":
            raise CanonicalEvidenceError(
                "canonical evidence requires an allowed scope decision"
            )
        return cls(
            tenant_id=envelope.tenant_id,
            engagement_id=envelope.engagement_id,
            run_id=envelope.run_id,
            job_id=envelope.job_id,
            action_id=envelope.action_id,
            decision_id=envelope.decision_id,
            operator_id=envelope.operator_id,
            operator_role=envelope.operator_role,
            engine=envelope.engine,
            module_id=envelope.module_id,
            action_kind=envelope.action_kind,
            scope_policy_version=envelope.scope_policy_version,
            scope_reason=envelope.scope_reason,
            attempt_id=attempt_id,
            decided_at=parse_utc(envelope.issued_at),
        )


class CanonicalEvidenceReader:
    """Tenant-scoped canonical reader for API, UI, report, and export paths."""

    def __init__(
        self,
        session: Session,
        custody_root: str | Path,
        tenant_id: str,
        *,
        audit_actor_id: str | None = None,
        expected_original_operator_id: str | None = None,
    ) -> None:
        self.session = session
        self.tenant_id = tenant_id
        self.audit_actor_id = audit_actor_id
        self.expected_original_operator_id = expected_original_operator_id
        self.store = CanonicalStore(session)
        self.custody = EvidenceCustodyStore(
            custody_root,
            tenant_id,
            audit_sink=self._audit_sink,
        )

    def _audit_sink(self, event: Mapping[str, Any]) -> None:
        event_name = str(event.get("event") or "")
        if event_name not in {
            "artifact.read.redacted",
            "artifact.read.original.denied",
            "artifact.read.original.authorized",
        }:
            return
        artifact_id = str(event.get("artifact_id") or "")
        observation_id = str(event.get("source_observation_id") or "")
        manifest = self.custody.get_manifest(artifact_id)
        protected = event_name.startswith("artifact.read.original")
        authorization_ref = (
            manifest.protected_original_authorization_ref if protected else None
        )
        actor = str(event.get("actor_id") or self.audit_actor_id or "")
        metadata = {
            "event": event_name,
            "outcome": event_name.rsplit(".", 1)[-1],
            "operator_digest": (
                "sha256:" + hashlib.sha256(actor.encode("utf-8")).hexdigest()
                if actor
                else "none"
            ),
        }
        # Audit on an independent database transaction. Reading a derivative
        # may happen inside a caller's consistent read snapshot; silently
        # rolling that transaction back would corrupt unrelated caller state.
        # A connection-bound Session cannot provide an independent durable
        # audit transaction, so fail closed instead of sharing its transaction.
        bind = self.session.get_bind()
        if not isinstance(bind, Engine):
            raise CanonicalEvidenceError(
                "evidence access audit requires an engine-bound session"
            )
        audit_session = Session(bind=bind, autoflush=False, expire_on_commit=False)
        try:
            CanonicalStore(audit_session).record_evidence_access(
                tenant_id=self.tenant_id,
                artifact_id=artifact_id,
                observation_id=observation_id,
                access_kind=(
                    "protected_original" if protected else "redacted_derivative"
                ),
                authorization_ref=authorization_ref,
                metadata=metadata,
            )
            audit_session.commit()
        finally:
            audit_session.close()

    def get_finding_projection(self, finding_id: str) -> dict[str, Any] | None:
        """Read one persisted finding with verified derivatives only."""
        rows = self.session.execute(
            text(
                "SELECT f.id AS finding_id,f.title,f.severity,f.description,f.status,"
                "f.finding_key,f.dedup_key,f.created_at AS finding_created_at,"
                "f.metadata_json AS finding_metadata,mv.module_id,asset.display_name AS target,"
                "asset.canonical_uri,fo.observation_id,o.engagement_id,o.job_id,"
                "o.module_execution_id,o.asset_id,o.observed_at,o.proof_type,"
                "o.collection_status,o.check_id,o.route,o.parameter,o.location,o.identity_ref,"
                "oa.artifact_id,oa.role,oa.sequence,a.reference,a.digest,a.media_type,a.size,"
                "a.redaction_state,a.protection_state,a.integrity_state,a.manifest_digest,am.derivative_sha256,"
                "am.derivative_size,am.metadata_json AS manifest_metadata "
                "FROM canonical_findings f "
                "JOIN canonical_finding_observations fo ON fo.tenant_id=f.tenant_id AND fo.finding_id=f.id "
                "JOIN canonical_observations o ON o.tenant_id=fo.tenant_id AND o.id=fo.observation_id "
                "JOIN canonical_module_versions mv ON mv.tenant_id=o.tenant_id AND mv.id=o.module_version_id "
                "JOIN canonical_assets asset ON asset.tenant_id=o.tenant_id AND asset.id=o.asset_id "
                "LEFT JOIN canonical_observation_artifacts oa ON oa.tenant_id=o.tenant_id AND oa.observation_id=o.id "
                "AND oa.role<>'derivative' "
                "LEFT JOIN canonical_artifact_refs a ON a.tenant_id=oa.tenant_id AND a.id=oa.artifact_id "
                "LEFT JOIN canonical_artifact_manifests am ON am.tenant_id=a.tenant_id AND am.artifact_id=a.id "
                "WHERE f.tenant_id=:tenant_id AND f.id=:finding_id "
                "ORDER BY o.observed_at,o.id,oa.sequence,oa.artifact_id"
            ),
            {"tenant_id": self.tenant_id, "finding_id": finding_id},
        ).mappings().all()
        if not rows:
            return None
        observations: dict[str, dict[str, Any]] = {}
        for row in rows:
            observation_id = str(row["observation_id"])
            observation = observations.setdefault(
                observation_id,
                {
                    "artifacts": [],
                    "asset_id": str(row["asset_id"]),
                    "check_id": row["check_id"],
                    "collection_status": row["collection_status"],
                    "engagement_id": str(row["engagement_id"]),
                    "identity_ref": row["identity_ref"],
                    "job_id": str(row["job_id"]),
                    "location": row["location"],
                    "module_execution_id": row["module_execution_id"],
                    "observation_id": observation_id,
                    "observed_at": row["observed_at"],
                    "parameter": row["parameter"],
                    "proof_type": row["proof_type"],
                    "route": row["route"],
                },
            )
            if row["artifact_id"] is None:
                continue
            artifact_id = str(row["artifact_id"])
            if (
                row["manifest_digest"] is None
                or row["derivative_sha256"] is None
                or row["derivative_size"] is None
            ):
                if (
                    row["digest"] is None
                    and row["integrity_state"] == "unknown"
                    and row["protection_state"] == "legacy_unknown"
                ):
                    continue
                raise CanonicalEvidenceError(
                    "persisted artifact is missing its custody manifest"
                )
            manifest = self.custody.get_manifest(artifact_id)
            if (
                manifest.manifest_digest != row["manifest_digest"]
                or manifest.derivative_sha256 != row["derivative_sha256"]
                or manifest.derivative_size != int(row["derivative_size"])
            ):
                raise CanonicalEvidenceError(
                    "persisted artifact manifest does not match custody"
                )
            derivative = self.custody.read(
                artifact_id,
                actor_id=self.audit_actor_id,
            )
            bounded = derivative[:_MAX_DERIVATIVE_PROJECTION_BYTES]
            derivative_text = redact_text(
                bounded.decode("utf-8", errors="replace")
            )
            if len(derivative) > len(bounded):
                derivative_text += "\n<truncated>"
            try:
                manifest_metadata = json.loads(str(row["manifest_metadata"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise CanonicalEvidenceError(
                    "persisted artifact metadata is malformed"
                ) from exc
            if not isinstance(manifest_metadata, dict):
                raise CanonicalEvidenceError(
                    "persisted artifact metadata is malformed"
                )
            observation["artifacts"].append(
                {
                    "artifact_id": artifact_id,
                    "capture_kind": manifest_metadata.get("capture_kind", "unknown"),
                    "derivative": derivative_text,
                    "derivative_sha256": row["derivative_sha256"],
                    "derivative_size": row["derivative_size"],
                    "integrity_state": row["integrity_state"],
                    "manifest_digest": row["manifest_digest"],
                    "media_type": row["media_type"],
                    "primary_sha256": row["digest"],
                    "primary_size": row["size"],
                    "redaction_state": row["redaction_state"],
                    "role": row["role"],
                    "sequence": row["sequence"],
                }
            )
        first = rows[0]
        try:
            finding_metadata = json.loads(str(first["finding_metadata"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise CanonicalEvidenceError(
                "persisted finding metadata is malformed"
            ) from exc
        if not isinstance(finding_metadata, dict):
            raise CanonicalEvidenceError("persisted finding metadata is malformed")
        persisted_observations = [
            observation
            for observation in observations.values()
            if observation["artifacts"]
        ]
        evidence = (
            {
                "finding_id": str(first["finding_id"]),
                "observations": persisted_observations,
                "state": "persisted",
            }
            if persisted_observations
            else {"observations": [], "state": "unavailable"}
        )
        projection = {
            "confidence": finding_metadata.get("confidence", "UNVERIFIED"),
            "cvss_score": finding_metadata.get("cvss_v31_score"),
            "cvss_v31_score": finding_metadata.get("cvss_v31_score"),
            "cvss_v31_vector": finding_metadata.get("cvss_v31_vector"),
            "cvss_v40_score": finding_metadata.get("cvss_v40_score"),
            "cvss_v40_vector": finding_metadata.get("cvss_v40_vector"),
            "dedup_key": first["dedup_key"],
            "description": redact_text(str(first["description"])),
            "evidence": evidence,
            "finding_key": first["finding_key"],
            "id": str(first["finding_id"]),
            "maturity": finding_metadata.get("maturity", "experimental"),
            "mitre": finding_metadata.get("mitre_attack", []),
            "mitre_attack": finding_metadata.get("mitre_attack", []),
            "module": redact_text(str(first["module_id"])),
            "port": finding_metadata.get("port"),
            "proof_type": finding_metadata.get(
                "proof_type", first["proof_type"]
            ),
            "remediation": finding_metadata.get("remediation", ""),
            "reproduction_steps": finding_metadata.get(
                "reproduction_steps", []
            ),
            "service": finding_metadata.get("service"),
            "severity": first["severity"],
            "status": first["status"],
            "target": redact_text(str(first["target"])),
            "timestamp": str(first["finding_created_at"]),
            "title": redact_text(str(first["title"])),
            "url": (
                redact_text(str(first["canonical_uri"]))
                if first["canonical_uri"] is not None
                else ""
            ),
            "verification_state": finding_metadata.get(
                "verification_state", "unknown"
            ),
            "vpr_priority": finding_metadata.get("vpr_priority"),
            "vpr_score": finding_metadata.get("vpr_score"),
        }
        retest = self.session.execute(
            text(
                "SELECT r.id AS retest_id,ra.id AS retest_attempt_id,"
                "ra.job_id,ra.durable_attempt_id,ra.state AS retest_state,"
                "ra.verdict AS retest_verdict,ra.reason_code,p.observation_id "
                "AS retest_observation_id,p.artifact_id AS retest_artifact_id,"
                "p.sufficient AS retest_proof_sufficient,p.proof_digest AS "
                "retest_proof_digest,pm.manifest_digest AS retest_manifest_digest,"
                "ro.asset_id AS retest_asset_id,ro.engagement_id AS "
                "retest_engagement_id,ro.check_id AS retest_check_id,"
                "ro.collection_status AS retest_collection_status,"
                "ro.identity_ref AS retest_identity_ref,ro.location AS retest_location,"
                "ro.module_execution_id AS retest_module_execution_id,"
                "ro.observed_at AS retest_observed_at,ro.parameter AS retest_parameter,"
                "ro.proof_type AS retest_proof_type,ro.route AS retest_route,"
                "pa.digest AS retest_primary_sha256,pa.media_type AS retest_media_type,"
                "pa.size AS retest_primary_size,pa.redaction_state AS "
                "retest_redaction_state,pa.integrity_state AS retest_integrity_state,"
                "pm.derivative_sha256 AS retest_derivative_sha256,"
                "pm.derivative_size AS retest_derivative_size,pm.metadata_json AS "
                "retest_manifest_metadata "
                "FROM canonical_retests r "
                "JOIN canonical_retest_attempts ra "
                "ON ra.tenant_id=r.tenant_id AND ra.retest_id=r.id "
                "LEFT JOIN canonical_retest_proofs p "
                "ON p.tenant_id=ra.tenant_id AND p.id=ra.proof_id "
                "LEFT JOIN canonical_artifact_manifests pm "
                "ON pm.tenant_id=p.tenant_id AND pm.artifact_id=p.artifact_id "
                "AND pm.observation_id=p.observation_id "
                "LEFT JOIN canonical_observations ro "
                "ON ro.tenant_id=p.tenant_id AND ro.id=p.observation_id "
                "LEFT JOIN canonical_artifact_refs pa "
                "ON pa.tenant_id=p.tenant_id AND pa.id=p.artifact_id "
                "AND pa.observation_id=p.observation_id "
                "WHERE r.tenant_id=:tenant_id AND r.finding_id=:finding_id "
                "ORDER BY COALESCE(ra.finished_at,ra.started_at,ra.created_at) "
                "DESC,ra.id DESC LIMIT 1"
            ),
            {"tenant_id": self.tenant_id, "finding_id": finding_id},
        ).mappings().first()
        if retest is None:
            projection.update(
                {
                    "retest_status": "not_retested",
                    "retest_state": "not_started",
                    "retest_verdict": None,
                }
            )
        else:
            verdict = (
                str(retest["retest_verdict"])
                if retest["retest_verdict"] is not None
                else None
            )
            if verdict is not None:
                if (
                    retest["retest_artifact_id"] is None
                    or retest["retest_observation_id"] is None
                    or retest["retest_proof_digest"] is None
                    or retest["retest_manifest_digest"] is None
                ):
                    raise CanonicalEvidenceError(
                        "terminal retest verdict is missing immutable proof"
                    )
                retest_manifest = self.custody.verify(
                    str(retest["retest_artifact_id"])
                )
                if (
                    retest_manifest.source_observation_id
                    != str(retest["retest_observation_id"])
                    or retest_manifest.manifest_digest
                    != str(retest["retest_manifest_digest"])
                    or retest_manifest.sha256
                    != str(retest["retest_proof_digest"])
                ):
                    raise CanonicalEvidenceError(
                        "terminal retest proof does not match custody"
                    )
                if verdict in {"fixed", "still_vulnerable"} and int(
                    retest["retest_proof_sufficient"] or 0
                ) != 1:
                    raise CanonicalEvidenceError(
                        "terminal retest proof is insufficient for its verdict"
                    )
                derivative = self.custody.read(
                    str(retest["retest_artifact_id"]),
                    actor_id=self.audit_actor_id,
                )
                try:
                    retest_manifest_metadata = json.loads(
                        str(retest["retest_manifest_metadata"])
                    )
                except (TypeError, json.JSONDecodeError) as exc:
                    raise CanonicalEvidenceError(
                        "terminal retest artifact metadata is malformed"
                    ) from exc
                if not isinstance(retest_manifest_metadata, dict):
                    raise CanonicalEvidenceError(
                        "terminal retest artifact metadata is malformed"
                    )
                retest_observations = evidence.get("observations")
                if not isinstance(retest_observations, list):
                    raise CanonicalEvidenceError(
                        "terminal retest evidence projection is malformed"
                    )
                retest_observations.append(
                    {
                        "artifacts": [
                            {
                                "artifact_id": str(retest["retest_artifact_id"]),
                                "capture_kind": retest_manifest_metadata.get(
                                    "capture_kind", "retest_proof"
                                ),
                                "derivative": redact_text(
                                    derivative.decode("utf-8", errors="replace")
                                ),
                                "derivative_sha256": retest[
                                    "retest_derivative_sha256"
                                ],
                                "derivative_size": retest["retest_derivative_size"],
                                "integrity_state": retest["retest_integrity_state"],
                                "manifest_digest": retest["retest_manifest_digest"],
                                "media_type": retest["retest_media_type"],
                                "primary_sha256": retest["retest_primary_sha256"],
                                "primary_size": retest["retest_primary_size"],
                                "redaction_state": retest["retest_redaction_state"],
                                "role": "retest_proof",
                                "sequence": 0,
                            }
                        ],
                        "asset_id": str(retest["retest_asset_id"]),
                        "check_id": retest["retest_check_id"],
                        "collection_status": retest["retest_collection_status"],
                        "engagement_id": str(retest["retest_engagement_id"]),
                        "identity_ref": retest["retest_identity_ref"],
                        "job_id": str(retest["job_id"]),
                        "location": retest["retest_location"],
                        "module_execution_id": retest[
                            "retest_module_execution_id"
                        ],
                        "observation_id": str(retest["retest_observation_id"]),
                        "observed_at": retest["retest_observed_at"],
                        "parameter": retest["retest_parameter"],
                        "proof_type": retest["retest_proof_type"],
                        "route": retest["retest_route"],
                    }
                )
            projection.update(
                {
                    "retest_id": str(retest["retest_id"]),
                    "retest_attempt_id": str(retest["retest_attempt_id"]),
                    "retest_job_id": str(retest["job_id"]),
                    "retest_durable_attempt_id": str(
                        retest["durable_attempt_id"]
                    ),
                    "retest_state": str(retest["retest_state"]),
                    "retest_verdict": verdict,
                    "retest_status": verdict or str(retest["retest_state"]),
                    "retest_reason_code": str(retest["reason_code"] or ""),
                    "retest_observation_id": (
                        str(retest["retest_observation_id"])
                        if retest["retest_observation_id"] is not None
                        else None
                    ),
                    "retest_artifact_id": (
                        str(retest["retest_artifact_id"])
                        if retest["retest_artifact_id"] is not None
                        else None
                    ),
                }
            )
        review_table = self.session.execute(
            text(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='canonical_finding_review_current'"
            )
        ).first()
        review = (
            self.session.execute(
                text(
                    "SELECT revision_id,version,status,owner_operator_id,notes,"
                    "updated_by_operator_id,updated_at "
                    "FROM canonical_finding_review_current "
                    "WHERE tenant_id=:tenant_id AND finding_id=:finding_id"
                ),
                {"tenant_id": self.tenant_id, "finding_id": finding_id},
            ).mappings().first()
            if review_table is not None
            else None
        )
        if review is None:
            projection.update(
                {
                    "review_notes": "",
                    "review_owner_operator_id": None,
                    "review_revision_id": None,
                    "review_status": projection["status"],
                    "review_updated_at": None,
                    "review_updated_by_operator_id": None,
                    "review_version": 0,
                }
            )
        else:
            projection.update(
                {
                    "review_notes": redact_text(str(review["notes"])),
                    "review_owner_operator_id": (
                        str(review["owner_operator_id"])
                        if review["owner_operator_id"] is not None
                        else None
                    ),
                    "review_revision_id": str(review["revision_id"]),
                    "review_status": str(review["status"]),
                    "review_updated_at": str(review["updated_at"]),
                    "review_updated_by_operator_id": str(
                        review["updated_by_operator_id"]
                    ),
                    "review_version": int(review["version"]),
                }
            )
        # Finding metadata is contract-bounded and redacted at persistence.
        # Apply the emergency redactor again to all presentation fields while
        # preserving custody IDs/digests already verified above.
        for key in tuple(projection):
            if key in {
                "dedup_key",
                "evidence",
                "finding_key",
                "id",
                "retest_artifact_id",
                "retest_attempt_id",
                "retest_durable_attempt_id",
                "retest_id",
                "retest_job_id",
                "retest_observation_id",
                "review_revision_id",
            }:
                continue
            projection[key] = redact_value(projection[key])
        return projection

    def list_finding_projections(self) -> list[dict[str, Any]]:
        ids = [
            str(row[0])
            for row in self.session.execute(
                text(
                    "SELECT id FROM canonical_findings WHERE tenant_id=:tenant_id "
                    "ORDER BY created_at,id"
                ),
                {"tenant_id": self.tenant_id},
            ).all()
        ]
        return [
            projection
            for finding_id in ids
            if (projection := self.get_finding_projection(finding_id)) is not None
        ]

    def export_finding(self, finding_id: str) -> bytes:
        """Return a deterministic backend export from persisted derivatives."""
        projection = self.get_finding_projection(finding_id)
        if projection is None:
            raise CanonicalEvidenceError("canonical finding is unavailable")
        return json.dumps(
            projection,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    def read_protected_original(
        self,
        artifact_id: str,
        authorization: ProtectedOriginalAuthorization,
    ) -> bytes:
        """Read an original only for an exact typed and audited authority."""
        if not isinstance(authorization, ProtectedOriginalAuthorization):
            raise ArtifactAccessDenied(
                "protected original requires typed authorization"
            )
        if (
            self.expected_original_operator_id is not None
            and authorization.operator_id != self.expected_original_operator_id
        ):
            manifest = self.custody.get_manifest(artifact_id)
            self._audit_sink(
                {
                    "event": "artifact.read.original.denied",
                    "tenant_id": self.tenant_id,
                    "artifact_id": artifact_id,
                    "source_observation_id": manifest.source_observation_id,
                    "actor_id": authorization.operator_id,
                }
            )
            raise ArtifactAccessDenied(
                "protected original operator does not match execution authority"
            )
        return self.custody.read(
            artifact_id,
            include_original=True,
            authorization=authorization,
            actor_id=authorization.operator_id,
        )

    def update_finding_status(self, finding_id: str, status: str) -> None:
        """Update only mutable workflow state within the exact tenant."""
        try:
            normalized = FindingStatus(str(status).lower())
        except ValueError as exc:
            raise CanonicalEvidenceError("unsupported finding status") from exc
        if self.session.in_transaction():
            raise CanonicalEvidenceError(
                "finding status update requires an idle database session"
            )
        with self.session.begin():
            result = self.session.execute(
                text(
                    "UPDATE canonical_findings SET status=:status "
                    "WHERE tenant_id=:tenant_id AND id=:finding_id"
                ),
                {
                    "status": normalized.value,
                    "tenant_id": self.tenant_id,
                    "finding_id": finding_id,
                },
            )
            if getattr(result, "rowcount", None) != 1:
                raise CanonicalEvidenceError("canonical finding is unavailable")


class CanonicalEvidenceService(CanonicalEvidenceReader):
    """Persist and read tenant-bound finding evidence through one boundary."""

    def __init__(
        self,
        session: Session,
        custody_root: str | Path,
        context: CanonicalEvidenceContext,
    ) -> None:
        if not isinstance(context, CanonicalEvidenceContext):
            raise CanonicalEvidenceError(
                "canonical evidence context must be typed and complete"
            )
        self.context = context
        super().__init__(
            session,
            custody_root,
            context.tenant_id,
            expected_original_operator_id=context.operator_id,
        )

    @classmethod
    def from_authorization(
        cls,
        session: Session,
        custody_root: str | Path,
        envelope: ActionAuthorizationEnvelope,
        *,
        attempt_id: str | None = None,
    ) -> "CanonicalEvidenceService":
        return cls(
            session,
            custody_root,
            CanonicalEvidenceContext.from_authorization(
                envelope,
                attempt_id=attempt_id,
            ),
        )

    def _records_for_finding(
        self,
        finding: Finding,
        *,
        observation: Observation,
        asset: Asset,
        primary_artifact: ArtifactReference,
    ) -> dict[str, Any]:
        context = self.context
        tenant = Tenant(id=context.tenant_id, name=context.tenant_id)
        engagement = Engagement(
            id=context.engagement_id,
            tenant_id=context.tenant_id,
            name=context.engagement_id,
            status=EngagementStatus.ACTIVE,
        )
        operator = Operator(
            id=context.operator_id,
            tenant_id=context.tenant_id,
            display_name="Authorized operator",
        )
        role = Role(
            id=_stable_id("role", context.tenant_id, context.operator_role),
            tenant_id=context.tenant_id,
            name=context.operator_role,
        )
        scope_decision = ScopeDecision(
            id=context.decision_id,
            tenant_id=context.tenant_id,
            engagement_id=context.engagement_id,
            operator_id=context.operator_id,
            role_id=role.id,
            outcome=ScopeOutcome.ALLOW,
            policy_version=context.scope_policy_version,
            decision_reason=context.scope_reason,
            decided_at=context.decided_at,
        )
        persisted_job = self.session.execute(
            text(
                "SELECT status,job_kind FROM canonical_jobs "
                "WHERE tenant_id=:tenant_id AND id=:job_id"
            ),
            {"tenant_id": context.tenant_id, "job_id": context.job_id},
        ).mappings().first()
        if self.session.in_transaction():
            self.session.rollback()
        job = Job(
            id=context.job_id,
            tenant_id=context.tenant_id,
            engagement_id=context.engagement_id,
            job_kind=(
                str(persisted_job["job_kind"])
                if persisted_job is not None
                else context.engine
            ),
            status=(
                JobStatus(str(persisted_job["status"]))
                if persisted_job is not None
                else JobStatus.RUNNING
            ),
        )
        action = Action(
            id=context.action_id,
            tenant_id=context.tenant_id,
            engagement_id=context.engagement_id,
            job_id=context.job_id,
            action_kind=context.action_kind,
            authorization_decision_id=context.decision_id,
        )
        module_version = ModuleVersion(
            id=observation.module_version_id,
            tenant_id=context.tenant_id,
            module_id=context.module_id,
            version=VERSION,
            module_kind="check",
        )
        module_execution = ModuleExecution(
            id=observation.module_execution_id or "",
            tenant_id=context.tenant_id,
            job_id=context.job_id,
            module_version_id=module_version.id,
            status=ModuleExecutionStatus.RUNNING,
        )
        severity = FindingSeverity(str(finding.severity.value).lower())
        try:
            status = FindingStatus(str(finding.status).lower())
        except ValueError:
            status = FindingStatus.UNKNOWN
        canonical_finding = CanonicalFinding(
            tenant_id=context.tenant_id,
            observation_id=observation.id,
            artifact_id=primary_artifact.id,
            title=finding.title,
            severity=severity,
            description=finding.description,
            status=status,
            finding_key=observation.check_id or context.module_id,
            metadata={
                "confidence": finding.confidence,
                "cvss_v31_score": finding.cvss_v31_score,
                "cvss_v31_vector": finding.cvss_v31_vector,
                "cvss_v40_score": finding.cvss_v40_score,
                "cvss_v40_vector": finding.cvss_v40_vector,
                "maturity": finding.maturity,
                "mitre_attack": list(finding.mitre_attack),
                "port": finding.port,
                "proof_type": finding.proof_type,
                "remediation": finding.remediation,
                "reproduction_steps": list(finding.reproduction_steps),
                "service": finding.service,
                "verification_state": finding.verification_state,
                "vpr_priority": finding.vpr_priority or finding.vpr,
                "vpr_score": finding.vpr_score,
            },
        )
        return {
            "tenant": tenant,
            "engagement": engagement,
            "operator": operator,
            "role": role,
            "scope_decision": scope_decision,
            "job": job,
            "action": action,
            "module_version": module_version,
            "module_execution": module_execution,
            "asset": asset,
            "observation": observation,
            "finding": canonical_finding,
        }

    def _rollback_staged(self, manifests: list[ArtifactManifest]) -> None:
        errors: list[Exception] = []
        for manifest in reversed(manifests):
            try:
                self.custody.rollback_artifact(
                    manifest.artifact_id,
                    expected_manifest_digest=manifest.manifest_digest,
                )
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise ArtifactTransactionError(
                "staged evidence rollback did not complete"
            ) from errors[0]

    def persist_job_observation(
        self,
        *,
        attempt_id: str,
        delivery_key: str,
        payload: Mapping[str, Any],
        source_target: str,
        outcome: str,
        module_id: str | None = None,
        module_version: str = VERSION,
        module_kind: str = "job_result",
        proof_type: str = "unknown",
        check_id: str = "job-result",
        route: str | None = None,
        parameter: str | None = None,
        location: str | None = None,
        identity_ref: str | None = None,
        capture_kind: str = "job_result",
        transaction_guard: (
            Callable[[Session, Mapping[str, Any]], None] | None
        ) = None,
    ) -> dict[str, Any]:
        """Persist one deterministic attempt result and return its receipt."""

        context = self.context
        if context.attempt_id is None or context.attempt_id != attempt_id:
            raise CanonicalEvidenceError(
                "job observation attempt does not match trusted context"
            )
        normalized_outcome = str(outcome).strip().lower()
        outcome_map = {
            "success": (
                ObservationStatus.OBSERVED,
                CollectionStatus.COLLECTED,
            ),
            "failure": (
                ObservationStatus.FAILED,
                CollectionStatus.FAILED,
            ),
            "canceled": (
                ObservationStatus.CANCELED,
                CollectionStatus.CANCELED,
            ),
            "partial": (
                ObservationStatus.PARTIAL,
                CollectionStatus.PARTIAL,
            ),
        }
        if normalized_outcome not in outcome_map:
            raise CanonicalEvidenceError("unsupported job observation outcome")
        try:
            canonical_payload = json.dumps(
                dict(payload),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise CanonicalEvidenceError("job observation payload is invalid") from exc
        if len(canonical_payload) > 1_048_576:
            raise CanonicalEvidenceError("job observation payload exceeds limit")

        observation_id = _stable_id(
            "observation",
            context.tenant_id,
            context.job_id,
            attempt_id,
            delivery_key,
        )
        artifact_id = _stable_id(
            "artifact",
            context.tenant_id,
            context.job_id,
            attempt_id,
            delivery_key,
        )
        existing = self.session.execute(
            text(
                "SELECT o.id AS observation_id,a.id AS artifact_id,"
                "m.manifest_digest,a.reference "
                "FROM canonical_observations o "
                "JOIN canonical_artifact_refs a "
                "ON a.tenant_id=o.tenant_id AND a.observation_id=o.id "
                "JOIN canonical_artifact_manifests m "
                "ON m.tenant_id=a.tenant_id AND m.artifact_id=a.id "
                "AND m.observation_id=o.id "
                "WHERE o.tenant_id=:tenant_id AND o.job_id=:job_id "
                "AND o.attempt_id=:attempt_id AND o.id=:observation_id "
                "AND a.id=:artifact_id LIMIT 1"
            ),
            {
                "tenant_id": context.tenant_id,
                "job_id": context.job_id,
                "attempt_id": attempt_id,
                "observation_id": observation_id,
                "artifact_id": artifact_id,
            },
        ).mappings().first()
        if existing is not None:
            manifest = self.custody.verify(artifact_id)
            expected_digest = "sha256:" + hashlib.sha256(canonical_payload).hexdigest()
            if (
                manifest.source_observation_id != observation_id
                or manifest.sha256 != expected_digest
                or str(existing["manifest_digest"]) != manifest.manifest_digest
            ):
                raise CanonicalEvidenceError(
                    "job observation replay conflicts with persisted custody"
                )
            if self.session.in_transaction():
                self.session.rollback()
            return {
                "tenant_id": context.tenant_id,
                "job_id": context.job_id,
                "attempt_id": attempt_id,
                "observation_id": observation_id,
                "artifact_id": artifact_id,
                "result_ref": str(existing["reference"]),
                "manifest_digest": manifest.manifest_digest,
                "duplicate": True,
            }
        if self.session.in_transaction():
            self.session.rollback()

        asset_kind, asset_identity = _safe_url_asset(source_target or "unknown")
        asset = Asset(
            id=_stable_id(
                "asset",
                context.tenant_id,
                asset_kind.value,
                asset_identity,
            ),
            tenant_id=context.tenant_id,
            kind=asset_kind,
            identity_key=asset_identity,
            display_name=asset_identity,
            canonical_uri=(
                asset_identity if asset_kind is AssetKind.URL else None
            ),
        )
        # An authorization may bind a whole module set using a UUID-shaped
        # control identifier. Canonical ``ModuleVersion.module_id`` is an
        # ordinary, redacted label, so represent this aggregate delivery with
        # a stable engine-level adapter identity. The exact module-set binding
        # remains protected by the linked authorization decision.
        canonical_module_id = module_id or f"{context.engine}-job-result"
        module_version_id = _stable_id(
            "module-version",
            context.tenant_id,
            canonical_module_id,
            module_version,
        )
        module_execution_id = _stable_id(
            "module-execution",
            context.tenant_id,
            context.job_id,
            attempt_id,
            delivery_key,
        )
        observation_status, collection_status = outcome_map[normalized_outcome]
        observation = Observation(
            id=observation_id,
            tenant_id=context.tenant_id,
            engagement_id=context.engagement_id,
            job_id=context.job_id,
            attempt_id=attempt_id,
            module_version_id=module_version_id,
            module_execution_id=module_execution_id,
            asset_id=asset.id,
            action_id=context.action_id,
            status=observation_status,
            proof_type=proof_type,
            collection_status=collection_status,
            check_id=check_id,
            route=route,
            parameter=parameter,
            location=location,
            identity_ref=identity_ref,
        )
        tenant = Tenant(id=context.tenant_id, name=context.tenant_id)
        engagement = Engagement(
            id=context.engagement_id,
            tenant_id=context.tenant_id,
            name=context.engagement_id,
            status=EngagementStatus.ACTIVE,
        )
        persisted_job = self.session.execute(
            text(
                "SELECT status,job_kind FROM canonical_jobs "
                "WHERE tenant_id=:tenant_id AND id=:job_id"
            ),
            {"tenant_id": context.tenant_id, "job_id": context.job_id},
        ).mappings().first()
        if self.session.in_transaction():
            self.session.rollback()
        job = Job(
            id=context.job_id,
            tenant_id=context.tenant_id,
            engagement_id=context.engagement_id,
            job_kind=(
                str(persisted_job["job_kind"])
                if persisted_job is not None
                else context.engine
            ),
            status=(
                JobStatus(str(persisted_job["status"]))
                if persisted_job is not None
                else JobStatus.RUNNING
            ),
        )
        operator = Operator(
            id=context.operator_id,
            tenant_id=context.tenant_id,
            display_name="Authorized operator",
        )
        role = Role(
            id=_stable_id("role", context.tenant_id, context.operator_role),
            tenant_id=context.tenant_id,
            name=context.operator_role,
        )
        scope_decision = ScopeDecision(
            id=context.decision_id,
            tenant_id=context.tenant_id,
            engagement_id=context.engagement_id,
            operator_id=context.operator_id,
            role_id=role.id,
            outcome=ScopeOutcome.ALLOW,
            policy_version=context.scope_policy_version,
            decision_reason=context.scope_reason,
            decided_at=context.decided_at,
        )
        action = Action(
            id=context.action_id,
            tenant_id=context.tenant_id,
            engagement_id=context.engagement_id,
            job_id=context.job_id,
            action_kind=context.action_kind,
            authorization_decision_id=context.decision_id,
        )
        module_version_record = ModuleVersion(
            id=module_version_id,
            tenant_id=context.tenant_id,
            module_id=canonical_module_id,
            version=module_version,
            module_kind=module_kind,
        )
        module_execution = ModuleExecution(
            id=module_execution_id,
            tenant_id=context.tenant_id,
            job_id=context.job_id,
            module_version_id=module_version_id,
            status=ModuleExecutionStatus.COMPLETED,
        )

        manifests: list[ArtifactManifest] = []
        created_artifact = False
        try:
            try:
                manifest = self.custody.get_manifest(artifact_id)
                self.custody.verify(artifact_id)
                expected_digest = (
                    "sha256:" + hashlib.sha256(canonical_payload).hexdigest()
                )
                if (
                    manifest.source_observation_id != observation_id
                    or manifest.sha256 != expected_digest
                ):
                    raise CanonicalEvidenceError(
                        "orphan custody artifact conflicts with job delivery"
                    )
            except ArtifactNotFound:
                manifest = self.custody.store_artifact(
                    canonical_payload,
                    source_observation_id=observation_id,
                    collector_id=(
                        "collector:"
                        + hashlib.sha256(module_execution_id.encode()).hexdigest()[:24]
                    ),
                    media_type="application/json",
                    source_target=source_target,
                    source_asset_id=asset.id,
                    retain_original=True,
                    protected_original_authorization_ref=(
                        context.original_authorization_ref
                    ),
                    retention_class="standard",
                    metadata={"capture_kind": capture_kind},
                    artifact_id=artifact_id,
                )
                created_artifact = True
            manifests.append(manifest)
            artifact = ArtifactReference(
                id=artifact_id,
                tenant_id=context.tenant_id,
                observation_id=observation_id,
                reference=artifact_id,
                digest=manifest.sha256,
                media_type=manifest.media_type,
                size=manifest.byte_size,
                redaction_state=RedactionState(manifest.redaction_state),
                encryption_state=manifest.encryption_state,
                collected_at=parse_utc(manifest.collected_at),
                collector_id=manifest.collector_id,
                collector_version=module_version_record.version,
                source_target=manifest.source_target or "unknown",
                source_asset_id=manifest.source_asset_id,
                redaction_version=manifest.redaction_version,
                protection_state=manifest.protection_state,
                signer_state=manifest.signer_state,
                integrity_state=ArtifactIntegrityState.VERIFIED,
                retention_class=manifest.retention_class,
                retention_expires_at=(
                    parse_utc(manifest.retention_expires_at)
                    if manifest.retention_expires_at is not None
                    else None
                ),
                protected_original_authorization_ref=(
                    manifest.protected_original_authorization_ref
                ),
                derivative_reference=manifest.derivative_artifact_id,
                manifest_digest=manifest.manifest_digest,
                metadata={"capture_kind": capture_kind},
            )
            receipt_data = {
                "tenant_id": context.tenant_id,
                "job_id": context.job_id,
                "attempt_id": attempt_id,
                "observation_id": observation_id,
                "artifact_id": artifact_id,
                "result_ref": artifact_id,
                "manifest_digest": manifest.manifest_digest,
                "duplicate": False,
            }
            self.store.persist_custodied_observation(
                custody_store=self.custody,
                manifests=manifests,
                tenant=tenant,
                engagement=engagement,
                operator=operator,
                role=role,
                scope_decision=scope_decision,
                job=job,
                action=action,
                module_version=module_version_record,
                module_execution=module_execution,
                asset=asset,
                observation=observation,
                primary_artifact=artifact,
                rollback_manifest_ids=(artifact_id,) if created_artifact else (),
                transaction_guard=(
                    (
                        lambda connection: transaction_guard(
                            connection,
                            receipt_data,
                        )
                    )
                    if transaction_guard is not None
                    else None
                ),
            )
        except Exception:
            raise
        return receipt_data

    def persist_finding(self, finding: Finding) -> dict[str, Any]:
        """Persist one new observation and bind its verified safe projection."""
        if self.session.in_transaction():
            raise CanonicalEvidenceError(
                "canonical evidence persistence requires an idle database session"
            )
        context = self.context
        extra = finding.evidence.extra
        target = finding.url or finding.target or "unknown"
        asset_kind, asset_identity = _safe_url_asset(target)
        asset = Asset(
            id=_stable_id(
                "asset", context.tenant_id, asset_kind.value, asset_identity
            ),
            tenant_id=context.tenant_id,
            kind=asset_kind,
            identity_key=asset_identity,
            display_name=asset_identity,
            canonical_uri=(asset_identity if asset_kind is AssetKind.URL else None),
        )
        module_version_id = _stable_id(
            "module-version", context.tenant_id, context.module_id, VERSION
        )
        module_execution_id = _stable_id(
            "module-execution",
            context.tenant_id,
            context.job_id,
            context.action_id,
            context.module_id,
            context.run_id,
        )
        parsed_target = urlsplit(target)
        route = _dimension(extra, ("route", "path", "endpoint", "uri"))
        if route is None and parsed_target.scheme and parsed_target.netloc:
            route = parsed_target.path or "/"
        parameter = _dimension(extra, ("parameter", "param", "field", "query"))
        if parameter is None and parsed_target.query:
            parameter = ",".join(
                sorted({name for name, _value in parse_qsl(parsed_target.query)})
            ) or None
        location = _dimension(extra, ("location", "in_location", "source_location"))
        if location is None and parameter is not None:
            location = "query"
        identity_ref = _dimension(
            extra, ("identity_ref", "identity", "principal", "account", "user")
        )
        check_id = _dimension(
            extra,
            ("check_id", "check", "check_name", "finding_key", "rule_id"),
        ) or context.module_id
        observation = Observation(
            tenant_id=context.tenant_id,
            engagement_id=context.engagement_id,
            job_id=context.job_id,
            module_version_id=module_version_id,
            module_execution_id=module_execution_id,
            asset_id=asset.id,
            action_id=context.action_id,
            attempt_id=context.attempt_id,
            proof_type=finding.proof_type or "unknown",
            collection_status=CollectionStatus.COLLECTED,
            check_id=check_id,
            route=route,
            parameter=parameter,
            location=location,
            identity_ref=identity_ref,
        )
        captures = list(finding.evidence.consume())
        if not captures:
            captures.append(
                CapturedEvidenceArtifact(
                    kind="finding_summary",
                    content=json.dumps(
                        {
                            "description": finding.description,
                            "severity": finding.severity.value,
                            "title": finding.title,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("utf-8"),
                    media_type="application/json",
                )
            )

        manifests: list[ArtifactManifest] = []
        collector_id = "collector:" + hashlib.sha256(
            module_execution_id.encode("utf-8")
        ).hexdigest()[:24]
        try:
            for capture in captures:
                protected = capture.kind != "finding_summary"
                manifests.append(
                    self.custody.store_artifact(
                        capture.content,
                        source_observation_id=observation.id,
                        collector_id=collector_id,
                        media_type=capture.media_type,
                        source_target=target,
                        source_asset_id=asset.id,
                        retain_original=protected,
                        protected_original_authorization_ref=(
                            context.original_authorization_ref if protected else None
                        ),
                        retention_class="standard",
                        metadata={"capture_kind": capture.kind},
                    )
                )
        except Exception:
            self._rollback_staged(manifests)
            raise

        handed_off = False
        try:
            artifacts = [
                ArtifactReference(
                    id=manifest.artifact_id,
                    tenant_id=context.tenant_id,
                    observation_id=observation.id,
                    reference=manifest.artifact_id,
                    digest=manifest.sha256,
                    media_type=manifest.media_type,
                    size=manifest.byte_size,
                    redaction_state=RedactionState(manifest.redaction_state),
                    encryption_state=manifest.encryption_state,
                    collected_at=parse_utc(manifest.collected_at),
                    metadata={
                        "capture_kind": str(manifest.metadata["capture_kind"])
                    },
                    collector_id=manifest.collector_id,
                    collector_version=VERSION,
                    source_target=manifest.source_target or "unknown",
                    source_asset_id=manifest.source_asset_id,
                    redaction_version=manifest.redaction_version,
                    protection_state=manifest.protection_state,
                    signer_state=manifest.signer_state,
                    integrity_state=ArtifactIntegrityState(
                        ArtifactIntegrityState.VERIFIED.value
                        if manifest.integrity_state == "verified"
                        else manifest.integrity_state
                    ),
                    retention_class=manifest.retention_class,
                    retention_expires_at=(
                        parse_utc(manifest.retention_expires_at)
                        if manifest.retention_expires_at is not None
                        else None
                    ),
                    protected_original_authorization_ref=(
                        manifest.protected_original_authorization_ref
                    ),
                    derivative_reference=manifest.derivative_artifact_id,
                )
                for manifest in manifests
            ]
            records = self._records_for_finding(
                finding,
                observation=observation,
                asset=asset,
                primary_artifact=artifacts[0],
            )
            # CanonicalStore owns compensation once it receives the manifests.
            handed_off = True
            result = self.store.persist_custodied_lineage(
                custody_store=self.custody,
                manifests=manifests,
                primary_artifact=artifacts[0],
                supporting_artifacts=artifacts[1:],
                **records,
            )
        except Exception:
            if not handed_off:
                self._rollback_staged(manifests)
            raise
        canonical_finding = result["finding"]
        if not isinstance(canonical_finding, CanonicalFinding):
            raise CanonicalEvidenceError("canonical finding persistence returned no summary")
        try:
            projection = self.get_finding_projection(canonical_finding.id)
        finally:
            # persist_finding entered with an idle session and owns the read
            # transaction opened solely to verify the just-committed graph.
            # Leave the caller idle without disturbing transactions created by
            # standalone CanonicalEvidenceReader consumers.
            if self.session.in_transaction():
                self.session.rollback()
        if projection is None:
            raise CanonicalEvidenceError("persisted canonical finding is unreadable")
        finding.id = canonical_finding.id
        finding.bind_canonical_evidence(projection["evidence"])
        return projection

__all__ = [
    "CanonicalEvidenceContext",
    "CanonicalEvidenceError",
    "CanonicalEvidenceReader",
    "CanonicalEvidenceService",
    "JOB_ATTEMPT_ID_ENV",
]
