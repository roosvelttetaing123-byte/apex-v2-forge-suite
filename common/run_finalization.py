"""Authorization-bound managed signing and persistence for completed scan runs."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from common.action_authorization import (
    ActionAuthorizationEnvelope,
    _safe_target_for_binding,
    default_authorization_db_path,
    module_set_binding,
    open_authorization_session,
)
from common.db import (
    ScanRunModel,
    append_finding_run_snapshot,
    append_persisted_finding_delta,
    append_run_collection_truth,
    finding_set_identity,
    get_authorization_consumption,
    get_authorization_decision,
    latest_run_collection_truth,
    list_findings_for_run,
    load_persisted_finding_delta,
    load_run_collection_truth,
)
from common.reporting.delta_report import build_persisted_finding_delta
from common.run_truth import (
    RunCollectionStatus,
    RunCollectionTruth,
    RunTruthPolicy,
    run_collection_truth_attestation_payload,
)


RUN_TRUTH_POLICY_ID_ENV = "FORGE_RUN_TRUTH_POLICY_ID"
RUN_TRUTH_POLICY_VERSION_ENV = "FORGE_RUN_TRUTH_POLICY_VERSION"
RUN_TRUTH_ISSUER_ID_ENV = "FORGE_RUN_TRUTH_ISSUER_ID"
RUN_TRUTH_PUBLIC_KEY_ENV = "FORGE_RUN_TRUTH_PUBLIC_KEY"
RUN_TRUTH_PRIVATE_KEY_FILE_ENV = "FORGE_RUN_TRUTH_PRIVATE_KEY_FILE"
RUN_TRUTH_AUTHORITY_ID_ENV = "FORGE_RUN_TRUTH_AUTHORITY_ID"


class RunFinalizationError(RuntimeError):
    """Stable reason-code failure at the run-finalization boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class ManagedRunTruthSigner:
    policy: RunTruthPolicy
    authority_id: str
    private_key: Ed25519PrivateKey

    def sign(self, record: RunCollectionTruth) -> RunCollectionTruth:
        if (
            record.policy_id != self.policy.policy_id
            or record.policy_version != self.policy.policy_version
            or record.issuer_id != self.policy.issuer_id
            or record.authority_id != self.authority_id
        ):
            raise RunFinalizationError("run_truth_signer_binding_mismatch")
        signature = self.private_key.sign(
            run_collection_truth_attestation_payload(record)
        )
        return replace(
            record,
            attestation=base64.b64encode(signature).decode("ascii"),
        )


@dataclass(frozen=True)
class RunCompletionManifest:
    planned_capabilities: tuple[str, ...]
    completed_capabilities: tuple[str, ...]
    status: str
    completed_at: datetime
    engine_version: str

    def __post_init__(self) -> None:
        planned = tuple(sorted({str(item).strip().lower() for item in self.planned_capabilities if str(item).strip()}))
        completed = tuple(sorted({str(item).strip().lower() for item in self.completed_capabilities if str(item).strip()}))
        if not planned or not set(completed).issubset(planned):
            raise RunFinalizationError("run_completion_coverage_invalid")
        if self.status.strip().lower() not in {
            "completed",
            "failed",
            "aborted",
            "canceled",
            "unauthorized",
        }:
            raise RunFinalizationError("run_completion_status_invalid")
        if (
            self.completed_at.tzinfo is None
            or self.completed_at.utcoffset() is None
            or not self.engine_version.strip()
        ):
            raise RunFinalizationError("run_completion_identity_invalid")
        object.__setattr__(self, "planned_capabilities", planned)
        object.__setattr__(self, "completed_capabilities", completed)
        object.__setattr__(self, "status", self.status.strip().lower())
        object.__setattr__(self, "engine_version", self.engine_version.strip())

    @property
    def coverage_complete(self) -> bool:
        return (
            self.status == "completed"
            and self.completed_capabilities == self.planned_capabilities
        )

    @property
    def collection_status(self) -> RunCollectionStatus:
        if self.status in {"aborted", "canceled"}:
            return RunCollectionStatus.CANCELED
        if self.status == "unauthorized":
            return RunCollectionStatus.UNAUTHORIZED
        if self.status == "failed":
            return (
                RunCollectionStatus.PARTIAL
                if self.completed_capabilities
                else RunCollectionStatus.FAILED
            )
        return (
            RunCollectionStatus.SUCCESS
            if self.coverage_complete
            else RunCollectionStatus.PARTIAL
        )

    def coverage_identity(self, framework: str) -> str:
        material = json.dumps(
            {
                "schema": "forge-run-coverage-plan-v1",
                "framework": framework,
                "engine_version": self.engine_version,
                "planned_capabilities": list(self.planned_capabilities),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class RunFinalizationResult:
    truth: RunCollectionTruth
    delta: dict[str, object]
    database_path: Path


def load_configured_run_truth_policy(
    environ: Mapping[str, str] | None = None,
) -> RunTruthPolicy:
    source = os.environ if environ is None else environ
    policy_id = source.get(RUN_TRUTH_POLICY_ID_ENV, "forge-run-coverage-v1").strip()
    policy_version = source.get(RUN_TRUTH_POLICY_VERSION_ENV, "1.0").strip()
    issuer_id = source.get(RUN_TRUTH_ISSUER_ID_ENV, "").strip()
    public_key = source.get(RUN_TRUTH_PUBLIC_KEY_ENV, "").strip()
    if not policy_id or not policy_version:
        raise RunFinalizationError("run_truth_policy_config_missing")
    if not issuer_id:
        raise RunFinalizationError("run_truth_issuer_config_missing")
    try:
        raw_public = base64.b64decode(public_key, validate=True)
    except (TypeError, ValueError):
        raise RunFinalizationError("run_truth_public_key_invalid") from None
    if len(raw_public) != 32:
        raise RunFinalizationError("run_truth_public_key_invalid")
    return RunTruthPolicy(
        policy_id=policy_id,
        policy_version=policy_version,
        issuer_id=issuer_id,
        issuer_public_key=public_key,
    )


def _read_private_key_file(path_value: str) -> bytes:
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        raise RunFinalizationError("run_truth_private_key_path_invalid")
    try:
        before = os.lstat(path)
    except OSError:
        raise RunFinalizationError("run_truth_private_key_unavailable") from None
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise RunFinalizationError("run_truth_private_key_permissions_invalid")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) & 0o077
            or after.st_size > 4096
        ):
            raise RunFinalizationError("run_truth_private_key_permissions_invalid")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).strip()
    except OSError:
        raise RunFinalizationError("run_truth_private_key_unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_managed_run_truth_signer(
    environ: Mapping[str, str] | None = None,
) -> ManagedRunTruthSigner:
    source = os.environ if environ is None else environ
    policy = load_configured_run_truth_policy(source)
    authority_id = source.get(RUN_TRUTH_AUTHORITY_ID_ENV, "").strip()
    private_key_path = source.get(RUN_TRUTH_PRIVATE_KEY_FILE_ENV, "").strip()
    if not authority_id:
        raise RunFinalizationError("run_truth_authority_config_missing")
    if not private_key_path:
        raise RunFinalizationError("run_truth_private_key_config_missing")
    encoded_private = _read_private_key_file(private_key_path)
    try:
        private_bytes = base64.b64decode(encoded_private, validate=True)
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    except (TypeError, ValueError):
        raise RunFinalizationError("run_truth_private_key_invalid") from None
    derived_public = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    if not hmac.compare_digest(derived_public, policy.issuer_public_key):
        raise RunFinalizationError("run_truth_signing_key_mismatch")
    return ManagedRunTruthSigner(
        policy=policy,
        authority_id=authority_id,
        private_key=private_key,
    )


def _validate_finalization_authorization(
    session: Session,
    authorization: ActionAuthorizationEnvelope,
    *,
    framework: str,
    target: str,
    planned_capabilities: tuple[str, ...],
) -> None:
    if authorization.decision_outcome != "allow":
        raise RunFinalizationError("run_finalization_not_authorized")
    if authorization.engine != framework:
        raise RunFinalizationError("run_finalization_engine_mismatch")
    target_binding = _safe_target_for_binding(target)
    if (
        authorization.requested_target != target_binding
        or authorization.resolved_target != target_binding
    ):
        raise RunFinalizationError("run_finalization_target_mismatch")
    if (
        authorization.module_id
        and authorization.module_id != module_set_binding(planned_capabilities)
    ):
        raise RunFinalizationError("run_finalization_coverage_mismatch")
    stored = get_authorization_decision(session, authorization.decision_id)
    consumed = get_authorization_consumption(session, authorization.decision_id)
    if (
        stored is None
        or consumed is None
        or str(stored.decision_outcome) != "allow"
        or str(stored.tenant_id) != authorization.tenant_id
        or str(stored.run_id) != authorization.run_id
        or str(stored.job_id) != authorization.job_id
        or str(stored.action_id) != authorization.action_id
        or not hmac.compare_digest(
            str(stored.binding_digest), authorization.binding_digest
        )
        or not hmac.compare_digest(
            str(stored.envelope_json), authorization.to_json()
        )
        or str(consumed.tenant_id) != authorization.tenant_id
        or str(consumed.job_id) != authorization.job_id
        or str(consumed.action_id) != authorization.action_id
        or str(consumed.boundary) != f"{framework}.engine"
        or not hmac.compare_digest(
            str(consumed.envelope_digest), authorization.binding_digest
        )
    ):
        raise RunFinalizationError("run_finalization_authorization_invalid")


def _validate_source_completion(
    session: Session,
    authorization: ActionAuthorizationEnvelope,
    *,
    framework: str,
    target: str,
    manifest: RunCompletionManifest,
) -> None:
    """Bind a signed completion to the engine's exact persisted run record."""
    source_run = session.get(ScanRunModel, authorization.run_id)
    if source_run is None:
        raise RunFinalizationError("run_completion_record_missing")
    raw_ended_at = source_run.ended_at
    if raw_ended_at is None:
        raise RunFinalizationError("run_completion_record_incomplete")
    ended_at = (
        raw_ended_at.replace(tzinfo=timezone.utc)
        if raw_ended_at.tzinfo is None
        else raw_ended_at.astimezone(timezone.utc)
    )
    if (
        str(source_run.tenant_id or "default") != authorization.tenant_id
        or str(source_run.framework or "").strip().lower() != framework
        or str(source_run.target or "") != target
        or str(source_run.status or "").strip().lower() != manifest.status
        or ended_at != manifest.completed_at.astimezone(timezone.utc)
    ):
        raise RunFinalizationError("run_completion_record_mismatch")


def finalize_authorized_run(
    source_session: Session,
    *,
    authorization: ActionAuthorizationEnvelope | Mapping[str, object],
    framework: str,
    target: str,
    manifest: RunCompletionManifest,
    central_db_path: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> RunFinalizationResult:
    """Finalize a real engine run into the shared authorization/truth store."""
    try:
        envelope = ActionAuthorizationEnvelope.from_value(authorization)
    except Exception:
        raise RunFinalizationError("run_finalization_authorization_invalid") from None
    engine = str(framework or "").strip().lower()
    if not engine:
        raise RunFinalizationError("run_finalization_engine_mismatch")
    signer = load_managed_run_truth_signer(environ)
    database_path = central_db_path or default_authorization_db_path(environ)
    central = open_authorization_session(database_path)
    central_engine = central.get_bind()
    truth_run_id = f"{envelope.run_id}:{engine}"
    if len(truth_run_id) > 160:
        central.close()
        if isinstance(central_engine, Engine):
            central_engine.dispose()
        raise RunFinalizationError("run_finalization_identity_invalid")
    try:
        _validate_finalization_authorization(
            central,
            envelope,
            framework=engine,
            target=target,
            planned_capabilities=manifest.planned_capabilities,
        )
        _validate_source_completion(
            source_session,
            envelope,
            framework=engine,
            target=target,
            manifest=manifest,
        )
        central.rollback()
        central.execute(text("BEGIN IMMEDIATE"))
        source_findings = list_findings_for_run(
            source_session,
            envelope.run_id,
            tenant_id=envelope.tenant_id,
        )
        for snapshot in source_findings:
            append_finding_run_snapshot(
                central,
                tenant_id=envelope.tenant_id,
                run_id=truth_run_id,
                snapshot=snapshot,
                commit=False,
            )
        central_findings = list_findings_for_run(
            central,
            truth_run_id,
            tenant_id=envelope.tenant_id,
        )
        if central_findings != source_findings:
            raise RunFinalizationError("run_finalization_replay_conflict")
        existing = load_run_collection_truth(
            central,
            truth_run_id,
            tenant_id=envelope.tenant_id,
            policy=signer.policy,
        )
        if existing is None:
            predecessor = latest_run_collection_truth(
                central,
                tenant_id=envelope.tenant_id,
                framework=engine,
                scope_binding=envelope.scope_snapshot,
                target_binding=envelope.resolved_target,
                policy=signer.policy,
            )
            unsigned = RunCollectionTruth(
                run_id=truth_run_id,
                authorization_run_id=envelope.run_id,
                job_id=envelope.job_id,
                tenant_id=envelope.tenant_id,
                framework=engine,
                scope_binding=envelope.scope_snapshot,
                target_binding=envelope.resolved_target,
                collection_status=manifest.collection_status,
                coverage_complete=manifest.coverage_complete,
                coverage_identity=manifest.coverage_identity(engine),
                finding_set_identity=finding_set_identity(
                    central,
                    tenant_id=envelope.tenant_id,
                    run_id=truth_run_id,
                ),
                predecessor_run_id=(predecessor.run_id if predecessor else ""),
                run_sequence=(predecessor.run_sequence + 1 if predecessor else 1),
                completed_at=manifest.completed_at.astimezone(timezone.utc).isoformat(),
                authorization_decision_id=envelope.decision_id,
                authorization_binding=envelope.binding_digest,
                authority_id=signer.authority_id,
                policy_id=signer.policy.policy_id,
                policy_version=signer.policy.policy_version,
                issuer_id=signer.policy.issuer_id,
            )
            existing = signer.sign(unsigned)
            append_run_collection_truth(
                central,
                existing,
                policy=signer.policy,
                commit=False,
            )
        elif (
            existing.authorization_run_id != envelope.run_id
            or existing.job_id != envelope.job_id
            or existing.authorization_decision_id != envelope.decision_id
            or existing.authorization_binding != envelope.binding_digest
            or existing.coverage_identity != manifest.coverage_identity(engine)
            or existing.collection_status != manifest.collection_status
            or existing.coverage_complete != manifest.coverage_complete
            or existing.completed_at
            != manifest.completed_at.astimezone(timezone.utc).isoformat()
        ):
            raise RunFinalizationError("run_finalization_replay_conflict")
        report = build_persisted_finding_delta(
            central,
            existing.predecessor_run_id,
            existing.run_id,
            tenant_id=envelope.tenant_id,
            policy=signer.policy,
        ).to_dict()
        append_persisted_finding_delta(
            central,
            tenant_id=envelope.tenant_id,
            report=report,
            authorization_decision_id=envelope.decision_id,
            authorization_binding=envelope.binding_digest,
            policy=signer.policy,
            commit=False,
        )
        central.commit()
        return RunFinalizationResult(
            truth=existing,
            delta=report,
            database_path=Path(database_path),
        )
    except RunFinalizationError:
        central.rollback()
        raise
    except Exception:
        central.rollback()
        raise RunFinalizationError("run_finalization_persistence_failed") from None
    finally:
        central.close()
        if isinstance(central_engine, Engine):
            central_engine.dispose()


def load_configured_persisted_delta(
    *,
    tenant_id: str,
    current_run_id: str,
    central_db_path: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, object] | None:
    """Production consumer that revalidates signed current truth after restart."""
    policy = load_configured_run_truth_policy(environ)
    database_path = central_db_path or default_authorization_db_path(environ)
    session = open_authorization_session(database_path)
    engine = session.get_bind()
    try:
        truth = load_run_collection_truth(
            session,
            current_run_id,
            tenant_id=tenant_id,
            policy=policy,
        )
        if truth is None:
            return None
        return load_persisted_finding_delta(
            session,
            tenant_id=tenant_id,
            current_run_id=current_run_id,
            policy=policy,
        )
    finally:
        session.close()
        if isinstance(engine, Engine):
            engine.dispose()
