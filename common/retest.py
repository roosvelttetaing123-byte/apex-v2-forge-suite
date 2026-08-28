"""Canonical evidence-backed retest service for Task 104.

Only the existing WebForge ``header_audit`` CSP condition is registered.  The
service derives every verifier input from persisted canonical lineage, executes
through Task 103, stores proof through Task 102, and treats unknown families as
unsupported without a connection or generic module rerun.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, ContextManager, Iterator, Mapping, Protocol, cast
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from common.action_authorization import (
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    OperatorRole,
    SafetyMode,
    module_set_binding,
    validate_consumed_authorization,
)
from common.canonical import (
    Action,
    CanonicalStore,
    Operator,
    RetestAttempt,
    RetestAttemptState,
    RetestProof,
    RetestRequest,
    RetestRequestState,
    RetestStatus,
    Role,
    ScopeDecision,
    ScopeOutcome,
    parse_utc,
    utc_now,
)
from common.canonical_evidence import (
    CanonicalEvidenceError,
    CanonicalEvidenceReader,
    CanonicalEvidenceService,
)
from common.credential_boundary import (
    CredentialReference,
    CredentialUseApproval,
)
from common.evidence_custody import CustodyError, EvidenceCustodyStore, make_original_authorization
from common.job_state import (
    JobState,
    JobStateService,
    ObservationReceipt,
    TransitionActor,
    WorkState,
)
from common.outbound_policy import (
    DatabaseOutboundAuditSink,
    OutboundContext,
    OutboundDenied,
    OutboundPolicy,
    _scope_snapshot,
)
from common.scope import canonical_target
from common.version import VERSION
from webforge.core.session import ForgeSession
from webforge.modules.headers.header_audit import REQUIRED_HEADERS


RETEST_CONTRACT_VERSION = "forge-real-retest-v1"
HEADER_CSP_VERIFIER_ID = "webforge.header_audit.csp"
HEADER_CSP_VERIFIER_VERSION = "1.0.0"
HEADER_CSP_PROOF_POLICY = "header-audit-csp-proof-v1"
HEADER_CSP_CHECK_ID = "Content-Security-Policy"
class RetestError(RuntimeError):
    """Base class for a safe retest failure."""


class RetestLineageError(RetestError):
    """The exact persisted original condition cannot be reconstructed."""


class RetestUnsupportedError(RetestError):
    """No exact registered verifier family applies to the original proof."""


class RetestAuthorizationError(RetestError):
    """Current scope/action/session authority is unavailable or mismatched."""


class RetestPersistenceError(RetestError):
    """Canonical retest state or proof could not be persisted safely."""


class RetestCanceled(RetestError):
    """Task 103 cancellation fenced the verifier before terminal proof."""


def _stable_id(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(material).hexdigest()}"


def _sha256(value: bytes | str) -> str:
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _exact_url(value: str, route: str) -> str:
    parsed = urlsplit(str(value).strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise RetestLineageError("original retest asset is not an HTTP URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RetestLineageError("original retest asset identity is ambiguous")
    if not route.startswith("/"):
        raise RetestLineageError("original retest route is not absolute")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, route, "", ""))


def _same_exact_url(left: str, right: str) -> bool:
    try:
        left_parts = urlsplit(left)
        right_parts = urlsplit(right)
        if any(
            (
                left_parts.username,
                left_parts.password,
                left_parts.fragment,
                right_parts.username,
                right_parts.password,
                right_parts.fragment,
            )
        ):
            return False
        return (
            left_parts.scheme.lower(),
            (left_parts.hostname or "").lower(),
            left_parts.port,
            left_parts.path or "/",
            left_parts.query,
        ) == (
            right_parts.scheme.lower(),
            (right_parts.hostname or "").lower(),
            right_parts.port,
            right_parts.path or "/",
            right_parts.query,
        )
    except ValueError:
        return False


def _csp_rule() -> Callable[[Any], Any]:
    for definition in REQUIRED_HEADERS:
        if definition.get("name") == HEADER_CSP_CHECK_ID:
            check = definition.get("check")
            if callable(check):
                return cast(Callable[[Any], Any], check)
    raise RetestError("header_audit CSP rule is unavailable")


def classify_csp(value: str | None) -> str:
    """Classify one CSP value through the existing ``header_audit`` rule."""

    if value is None:
        return "csp_missing"
    try:
        return "csp_strong" if bool(_csp_rule()(value)) else "csp_weak"
    except Exception:
        return "csp_weak"


@dataclass(frozen=True)
class VerifierRegistration:
    """Allowlisted source/version/proof policy for one exact verifier."""

    module_id: str
    check_ids: tuple[str, ...]
    source_versions: tuple[str, ...]
    verifier_id: str
    verifier_version: str
    proof_policy_version: str
    proof_expectations: tuple[str, ...]
    compatibility_migrations: Mapping[str, str] = field(default_factory=dict)
    allows_not_applicable: bool = False

    def __post_init__(self) -> None:
        values = (
            self.module_id,
            self.verifier_id,
            self.verifier_version,
            self.proof_policy_version,
            *self.check_ids,
            *self.source_versions,
            *self.proof_expectations,
        )
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValueError("retest verifier registration is incomplete")
        if (
            len(set(self.check_ids)) != len(self.check_ids)
            or len(set(self.source_versions)) != len(self.source_versions)
            or len(set(self.proof_expectations)) != len(self.proof_expectations)
        ):
            raise ValueError("retest verifier registration contains duplicates")
        if type(self.allows_not_applicable) is not bool:
            raise ValueError("allows_not_applicable must be boolean")
        migrations = dict(self.compatibility_migrations)
        if any(
            not isinstance(source, str)
            or not source
            or target != self.verifier_version
            for source, target in migrations.items()
        ):
            raise ValueError("retest verifier compatibility migration is invalid")
        object.__setattr__(
            self,
            "compatibility_migrations",
            MappingProxyType(migrations),
        )

    def supports(
        self,
        *,
        module_id: str,
        check_id: str,
        source_version: str,
        proof_expectation: str,
    ) -> bool:
        if (
            module_id != self.module_id
            or check_id not in self.check_ids
            or proof_expectation not in self.proof_expectations
        ):
            return False
        if source_version in self.source_versions:
            return True
        return self.compatibility_migrations.get(source_version) == self.verifier_version


class RetestVerifierRegistry:
    """Typed allowlist; absence is always unsupported."""

    def __init__(self, registrations: tuple[VerifierRegistration, ...]) -> None:
        by_module: dict[str, VerifierRegistration] = {}
        for registration in registrations:
            if registration.module_id in by_module:
                raise ValueError("duplicate retest verifier module registration")
            by_module[registration.module_id] = registration
        self._by_module = by_module

    def resolve(
        self,
        *,
        module_id: str,
        check_id: str,
        source_version: str,
        proof_expectation: str,
    ) -> VerifierRegistration | None:
        registration = self._by_module.get(module_id)
        if registration is None:
            return None
        if not registration.supports(
            module_id=module_id,
            check_id=check_id,
            source_version=source_version,
            proof_expectation=proof_expectation,
        ):
            return None
        return registration

    @property
    def supported_modules(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_module))


DEFAULT_RETEST_REGISTRY = RetestVerifierRegistry(
    (
        VerifierRegistration(
            module_id="header_audit",
            check_ids=("header_audit", HEADER_CSP_CHECK_ID),
            source_versions=(VERSION,),
            verifier_id=HEADER_CSP_VERIFIER_ID,
            verifier_version=HEADER_CSP_VERIFIER_VERSION,
            proof_policy_version=HEADER_CSP_PROOF_POLICY,
            proof_expectations=("csp_missing", "csp_weak"),
        ),
    )
)


@dataclass(frozen=True)
class HeaderResponse:
    status: int
    headers: Mapping[str, str]
    final_url: str
    evidence_complete: bool = True

    def __post_init__(self) -> None:
        if (
            isinstance(self.status, bool)
            or not isinstance(self.status, int)
            or not 100 <= self.status <= 599
        ):
            raise ValueError("header verifier response status is invalid")
        if not isinstance(self.headers, Mapping) or any(
            not isinstance(name, str) or not isinstance(value, str)
            for name, value in self.headers.items()
        ):
            raise ValueError("header verifier response headers are invalid")
        if not isinstance(self.final_url, str) or not self.final_url:
            raise ValueError("header verifier final URL is invalid")
        if type(self.evidence_complete) is not bool:
            raise ValueError("header verifier evidence state must be boolean")


@dataclass(frozen=True)
class VerifierInput:
    request: RetestRequest
    outbound_policy: Any
    session_headers: Mapping[str, str] = field(default_factory=dict)
    session_cookies: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class VerifierOutput:
    verdict: RetestStatus
    reason_code: str
    observed_condition: str
    response_status: int | None
    sufficient: bool
    header_value_digest: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "verdict", RetestStatus(self.verdict))
        if not self.reason_code or not self.observed_condition:
            raise ValueError("retest verifier output reason/condition is required")
        if type(self.sufficient) is not bool:
            raise ValueError("retest verifier output sufficiency must be boolean")
        if self.response_status is not None and (
            isinstance(self.response_status, bool)
            or not isinstance(self.response_status, int)
            or not 100 <= self.response_status <= 599
        ):
            raise ValueError("retest verifier response status is invalid")
        if self.header_value_digest is not None and (
            not self.header_value_digest.startswith("sha256:")
            or len(self.header_value_digest) != 71
        ):
            raise ValueError("retest verifier header digest is invalid")

    def proof_payload(self, request: RetestRequest) -> dict[str, Any]:
        return {
            "schema_version": RETEST_CONTRACT_VERSION,
            "retest_id": request.id,
            "verifier_id": request.verifier_id,
            "verifier_version": request.verifier_version,
            "proof_policy_version": request.proof_policy_version,
            "proof_expectation": request.proof_expectation,
            "observed_condition": self.observed_condition,
            "method": request.method,
            "route": request.route,
            "response_status": self.response_status,
            "sufficient": self.sufficient,
            "header_value_digest": self.header_value_digest,
            "verdict": self.verdict.value,
            "reason_code": self.reason_code,
        }


class HeaderFetcher(Protocol):
    async def __call__(
        self,
        target: str,
        outbound_policy: Any,
        headers: Mapping[str, str],
        cookies: Mapping[str, str],
    ) -> HeaderResponse: ...


class RetestVerifier(Protocol):
    async def verify(self, value: VerifierInput) -> VerifierOutput: ...


async def _governed_header_fetch(
    target: str,
    outbound_policy: OutboundPolicy,
    headers: Mapping[str, str],
    cookies: Mapping[str, str],
) -> HeaderResponse:
    """Fetch exactly one route through the existing governed session boundary."""

    async with ForgeSession(
        rate=10.0,
        timeout=10,
        headers=dict(headers),
        cookies=dict(cookies),
        outbound_policy=outbound_policy,
    ) as session:
        response = await session.get(
            target,
            allow_redirects=False,
            retries=1,
        )
        try:
            return HeaderResponse(
                status=int(response.status),
                headers=dict(response.headers),
                final_url=str(response.url),
                evidence_complete=True,
            )
        finally:
            response.release()


class HeaderAuditCspVerifier:
    """Proof-backed verifier for the existing header_audit CSP condition."""

    def __init__(self, fetcher: HeaderFetcher | None = None) -> None:
        self.fetcher = fetcher or _governed_header_fetch

    async def verify(self, value: VerifierInput) -> VerifierOutput:
        request = value.request
        try:
            response = await self.fetcher(
                request.target_url,
                value.outbound_policy,
                value.session_headers,
                value.session_cookies,
            )
        except asyncio.CancelledError:
            raise RetestCanceled("retest verifier was canceled") from None
        except RetestCanceled:
            raise
        except OutboundDenied as exc:
            if str(exc.reason_code).endswith("cancelled"):
                raise RetestCanceled("retest verifier was canceled") from None
            return VerifierOutput(
                verdict=RetestStatus.FAILED,
                reason_code=f"outbound_{exc.reason_code}",
                observed_condition="execution_failed",
                response_status=None,
                sufficient=False,
                header_value_digest=None,
            )
        except Exception:
            return VerifierOutput(
                verdict=RetestStatus.FAILED,
                reason_code="verifier_transport_failed",
                observed_condition="execution_failed",
                response_status=None,
                sufficient=False,
                header_value_digest=None,
            )

        if not response.evidence_complete or not _same_exact_url(
            response.final_url,
            request.target_url,
        ):
            return VerifierOutput(
                verdict=RetestStatus.INCONCLUSIVE,
                reason_code="response_evidence_incomplete",
                observed_condition="evidence_incomplete",
                response_status=response.status,
                sufficient=False,
                header_value_digest=None,
            )
        if response.status in {401, 403}:
            return VerifierOutput(
                verdict=RetestStatus.INCONCLUSIVE,
                reason_code="authenticated_session_lost",
                observed_condition="session_lost",
                response_status=response.status,
                sufficient=False,
                header_value_digest=None,
            )
        if not 200 <= response.status <= 299:
            return VerifierOutput(
                verdict=RetestStatus.INCONCLUSIVE,
                reason_code="http_error_without_proof",
                observed_condition="http_error",
                response_status=response.status,
                sufficient=False,
                header_value_digest=None,
            )
        headers = {str(name).lower(): str(item) for name, item in response.headers.items()}
        header = headers.get("content-security-policy")
        observed = classify_csp(header)
        header_digest = _sha256(header) if header is not None else None
        if observed == "csp_strong":
            return VerifierOutput(
                verdict=RetestStatus.FIXED,
                reason_code="original_csp_condition_corrected",
                observed_condition=observed,
                response_status=response.status,
                sufficient=True,
                header_value_digest=header_digest,
            )
        if observed == request.proof_expectation:
            return VerifierOutput(
                verdict=RetestStatus.STILL_VULNERABLE,
                reason_code="original_csp_condition_reproduced",
                observed_condition=observed,
                response_status=response.status,
                sufficient=True,
                header_value_digest=header_digest,
            )
        return VerifierOutput(
            verdict=RetestStatus.INCONCLUSIVE,
            reason_code="csp_condition_changed_without_correction",
            observed_condition=observed,
            response_status=response.status,
            sufficient=False,
            header_value_digest=header_digest,
        )


class SessionReferenceResolver(Protocol):
    def resolve(
        self,
        reference: CredentialReference | str,
        *,
        approval: CredentialUseApproval,
        target: str,
    ) -> ContextManager[Mapping[str, Any]]: ...


@dataclass(frozen=True)
class OriginalRetestLineage:
    tenant_id: str
    original_engagement_id: str
    finding_id: str
    source_observation_id: str
    source_artifact_id: str
    source_proof_artifact_id: str
    original_job_id: str
    original_attempt_id: str
    original_action_id: str
    original_authorization_decision_id: str
    original_module_version_id: str
    module_id: str
    module_version: str
    check_id: str
    asset_id: str
    target_url: str
    route: str
    method: str
    parameter: str | None
    location: str | None
    identity_ref: str | None
    proof_expectation: str
    evidence_baseline_digest: str
    session_reference: str | None
    session_policy_digest: str


@dataclass(frozen=True)
class RetestExecutionResult:
    state: str
    verdict: RetestStatus | None
    reason_code: str
    finding_id: str
    retest_id: str | None = None
    retest_attempt_id: str | None = None
    job_id: str | None = None
    durable_attempt_id: str | None = None
    observation_id: str | None = None
    artifact_id: str | None = None
    duplicate: bool = False

    def to_dict(self) -> dict[str, Any]:
        if self.artifact_id is not None:
            verdict_authority = "canonical_retest_proof"
        elif self.verdict is RetestStatus.NOT_AUTHORIZED:
            verdict_authority = "authorization_guard"
        elif self.verdict is RetestStatus.UNSUPPORTED:
            verdict_authority = "verifier_registry"
        elif self.verdict is RetestStatus.INCONCLUSIVE:
            verdict_authority = "canonical_lineage_guard"
        elif self.verdict is None:
            verdict_authority = "task103_job_state"
        else:
            verdict_authority = "canonical_retest_service"
        return {
            "schema_version": RETEST_CONTRACT_VERSION,
            "state": self.state,
            "retest_verdict": self.verdict.value if self.verdict else None,
            "reason_code": self.reason_code,
            "finding_id": self.finding_id,
            "retest_id": self.retest_id,
            "retest_attempt_id": self.retest_attempt_id,
            "job_id": self.job_id,
            "durable_attempt_id": self.durable_attempt_id,
            "observation_id": self.observation_id,
            "artifact_id": self.artifact_id,
            "duplicate": self.duplicate,
            "verdict_authority": verdict_authority,
        }


PolicyFactory = Callable[
    [ActionAuthorizationEnvelope, AuthorizationContext, str, tuple[str, ...], tuple[str, ...]],
    Any,
]


class RetestService:
    """Canonical request/attempt/verifier/proof integration coordinator."""

    def __init__(
        self,
        session: Session,
        custody_root: str | Path,
        job_state: JobStateService,
        *,
        authorization_session_factory: Callable[[], Session] | None = None,
        authorization_loader: Callable[[str], ActionAuthorizationEnvelope | None]
        | None = None,
        outbound_policy_factory: PolicyFactory | None = None,
        session_resolver: SessionReferenceResolver | None = None,
        registry: RetestVerifierRegistry = DEFAULT_RETEST_REGISTRY,
        header_verifier: RetestVerifier | None = None,
        clock: Callable[[], datetime] = utc_now,
        post_job_finish_hook: Callable[[], None] | None = None,
    ) -> None:
        self.session = session
        self.custody_root = Path(custody_root)
        self.job_state = job_state
        self.authorization_session_factory = authorization_session_factory
        self.authorization_loader = authorization_loader
        self.outbound_policy_factory = outbound_policy_factory
        self.session_resolver = session_resolver
        self.registry = registry
        self.header_verifier = header_verifier or HeaderAuditCspVerifier()
        self.clock = clock
        self.post_job_finish_hook = post_job_finish_hook

    def _load_authorization(self, decision_id: str) -> ActionAuthorizationEnvelope | None:
        if self.authorization_loader is not None:
            return self.authorization_loader(decision_id)
        if self.authorization_session_factory is None:
            return None
        from common.db import get_authorization_decision

        session = self.authorization_session_factory()
        try:
            record = get_authorization_decision(session, decision_id)
            if record is None:
                return None
            return ActionAuthorizationEnvelope.from_value(
                json.loads(str(record.envelope_json))
            )
        except Exception:
            return None
        finally:
            session.close()

    def _projection(self, finding_id: str, actor_id: str) -> dict[str, Any]:
        reader = CanonicalEvidenceReader(
            self.session,
            self.custody_root,
            audit_actor_id=actor_id,
            tenant_id=cast(str, self._finding_tenant(finding_id)),
        )
        projection = reader.get_finding_projection(finding_id)
        if projection is None:
            raise RetestLineageError("canonical finding is unavailable")
        return projection

    def _finding_tenant(self, finding_id: str) -> str:
        tenant = self.session.execute(
            text("SELECT tenant_id FROM canonical_findings WHERE id=:finding_id"),
            {"finding_id": finding_id},
        ).scalar_one_or_none()
        if self.session.in_transaction():
            self.session.rollback()
        if tenant is None:
            raise RetestLineageError("canonical finding is unavailable")
        return str(tenant)

    def _load_lineage(
        self,
        finding_id: str,
        *,
        tenant_id: str,
        actor_id: str,
    ) -> OriginalRetestLineage:
        row = self.session.execute(
            text(
                "SELECT f.id AS finding_id,f.observation_id,f.artifact_id,"
                "o.engagement_id,o.job_id,o.attempt_id,o.action_id,"
                "o.module_version_id,o.asset_id,o.check_id,o.route,o.parameter,"
                "o.location,o.identity_ref,mv.module_id,mv.version,"
                "asset.canonical_uri,asset.identity_key,"
                "action.authorization_decision_id "
                "FROM canonical_findings f "
                "JOIN canonical_observations o "
                "ON o.tenant_id=f.tenant_id AND o.id=f.observation_id "
                "JOIN canonical_module_versions mv "
                "ON mv.tenant_id=o.tenant_id AND mv.id=o.module_version_id "
                "JOIN canonical_assets asset "
                "ON asset.tenant_id=o.tenant_id AND asset.id=o.asset_id "
                "JOIN canonical_actions action "
                "ON action.tenant_id=o.tenant_id AND action.id=o.action_id "
                "JOIN canonical_finding_observations fo "
                "ON fo.tenant_id=f.tenant_id AND fo.finding_id=f.id "
                "AND fo.observation_id=o.id AND fo.artifact_id=f.artifact_id "
                "WHERE f.tenant_id=:tenant_id AND f.id=:finding_id"
            ),
            {"tenant_id": tenant_id, "finding_id": finding_id},
        ).mappings().first()
        if row is None:
            if self.session.in_transaction():
                self.session.rollback()
            raise RetestLineageError("canonical retest source lineage is incomplete")
        if not row["attempt_id"] or not row["action_id"]:
            if self.session.in_transaction():
                self.session.rollback()
            raise RetestLineageError("canonical retest source lacks Task 103 lineage")
        projection = self._projection(finding_id, actor_id)
        evidence = projection.get("evidence")
        observations = (
            evidence.get("observations", [])
            if isinstance(evidence, Mapping)
            else []
        )
        source_projection = next(
            (
                item
                for item in observations
                if isinstance(item, Mapping)
                and item.get("observation_id") == row["observation_id"]
            ),
            None,
        )
        if not isinstance(source_projection, Mapping):
            raise RetestLineageError("canonical retest source evidence is unavailable")
        request_evidence: list[tuple[str, str]] = []
        proof_evidence: list[tuple[str, str]] = []
        baseline: list[dict[str, str]] = []
        for artifact in source_projection.get("artifacts", []):
            if not isinstance(artifact, Mapping):
                continue
            artifact_id = str(artifact.get("artifact_id") or "")
            baseline.append(
                {
                    "artifact_id": artifact_id,
                    "manifest_digest": str(artifact.get("manifest_digest") or ""),
                    "primary_sha256": str(artifact.get("primary_sha256") or ""),
                }
            )
            derivative = str(artifact.get("derivative") or "")
            if (
                artifact_id == str(row["artifact_id"])
                and artifact.get("capture_kind") == "request"
                and derivative
            ):
                request_line = derivative.splitlines()[0].strip().split()
                if len(request_line) >= 2:
                    method = request_line[0].upper()
                    request_target = request_line[1]
                    request_route = (
                        urlsplit(request_target).path
                        if "://" in request_target
                        else request_target.split("?", 1)[0]
                    ) or "/"
                    request_evidence.append((method, request_route))
            if artifact.get("capture_kind") == "structured_proof" and derivative:
                try:
                    proof = json.loads(derivative)
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(proof, Mapping) or proof.get("header") != HEADER_CSP_CHECK_ID:
                    continue
                issue = str(proof.get("issue") or "")
                if issue == "Missing":
                    proof_evidence.append((artifact_id, "csp_missing"))
                elif issue.startswith("Weak value:"):
                    proof_evidence.append((artifact_id, "csp_weak"))
        if not proof_evidence:
            raise RetestUnsupportedError(
                "original finding has no registered CSP/header proof"
            )
        if len(request_evidence) != 1 or len(proof_evidence) != 1:
            raise RetestLineageError("original header proof evidence is ambiguous")
        method, request_route = request_evidence[0]
        source_proof_artifact_id, expectation = proof_evidence[0]
        if method != "GET" or expectation not in {"csp_missing", "csp_weak"}:
            raise RetestLineageError("original header proof expectation is incomplete")
        route = str(row["route"] or "").strip()
        check_id = str(row["check_id"] or "").strip()
        target_identity = str(row["canonical_uri"] or row["identity_key"] or "")
        if not route or not check_id:
            raise RetestLineageError(
                "original observation route/check identity is unavailable"
            )
        if request_route != route:
            raise RetestLineageError(
                "original request evidence does not match the canonical route"
            )
        target_url = _exact_url(target_identity, route)
        original_envelope = self._load_authorization(
            str(row["authorization_decision_id"])
        )
        if original_envelope is None or not all(
            (
                original_envelope.decision_outcome == "allow",
                original_envelope.tenant_id == tenant_id,
                original_envelope.engagement_id == str(row["engagement_id"]),
                original_envelope.job_id == str(row["job_id"]),
                original_envelope.action_id == str(row["action_id"]),
                original_envelope.decision_id
                == str(row["authorization_decision_id"]),
                original_envelope.module_id
                in {
                    str(row["module_id"]),
                    module_set_binding([str(row["module_id"])]),
                },
                original_envelope.resolved_target == canonical_target(target_url),
            )
        ):
            raise RetestLineageError(
                "original session/authorization policy is unavailable or mismatched"
            )
        session_reference = (
            original_envelope.credential_reference
            if original_envelope.credential_reference
            else None
        )
        session_policy_digest = _sha256(
            _canonical_json(
                {
                    "tenant_id": original_envelope.tenant_id,
                    "engagement_id": original_envelope.engagement_id,
                    "operator_id": original_envelope.operator_id,
                    "operator_role": original_envelope.operator_role,
                    "engine": original_envelope.engine,
                    "module_id": original_envelope.module_id,
                    "requested_target": original_envelope.requested_target,
                    "resolved_target": original_envelope.resolved_target,
                    "scope_snapshot": original_envelope.scope_snapshot,
                    "scope_policy_version": original_envelope.scope_policy_version,
                    "credential_reference": original_envelope.credential_reference,
                }
            )
        )
        baseline_digest = _sha256(
            json.dumps(
                sorted(baseline, key=lambda item: item["artifact_id"]),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
        )
        if self.session.in_transaction():
            self.session.rollback()
        return OriginalRetestLineage(
            tenant_id=tenant_id,
            original_engagement_id=str(row["engagement_id"]),
            finding_id=finding_id,
            source_observation_id=str(row["observation_id"]),
            source_artifact_id=str(row["artifact_id"]),
            source_proof_artifact_id=source_proof_artifact_id,
            original_job_id=str(row["job_id"]),
            original_attempt_id=str(row["attempt_id"]),
            original_action_id=str(row["action_id"]),
            original_authorization_decision_id=str(
                row["authorization_decision_id"]
            ),
            original_module_version_id=str(row["module_version_id"]),
            module_id=str(row["module_id"]),
            module_version=str(row["version"]),
            check_id=check_id,
            asset_id=str(row["asset_id"]),
            target_url=target_url,
            route=route,
            method=method,
            parameter=(str(row["parameter"]) if row["parameter"] else None),
            location=(str(row["location"]) if row["location"] else None),
            identity_ref=(str(row["identity_ref"]) if row["identity_ref"] else None),
            proof_expectation=expectation,
            evidence_baseline_digest=baseline_digest,
            session_reference=session_reference,
            session_policy_digest=session_policy_digest,
        )

    def _current_authorization_context(
        self,
        envelope: ActionAuthorizationEnvelope,
        lineage: OriginalRetestLineage,
        allowed_scope: tuple[str, ...],
        excluded_scope: tuple[str, ...],
    ) -> AuthorizationContext:
        return AuthorizationContext(
            tenant_id=envelope.tenant_id,
            engagement_id=envelope.engagement_id,
            run_id=envelope.run_id,
            job_id=envelope.job_id,
            operator_id=envelope.operator_id,
            operator_role=OperatorRole(envelope.operator_role),
            action_kind=envelope.action_kind,
            engine=envelope.engine,
            module_id=envelope.module_id,
            requested_target=lineage.target_url,
            resolved_target=lineage.target_url,
            allowed_scope=allowed_scope,
            excluded_scope=excluded_scope,
            scope_policy_version=envelope.scope_policy_version,
            safety_mode=SafetyMode(envelope.safety_mode),
            credential_approval_required=bool(lineage.session_reference),
            credential_reference=lineage.session_reference or "",
            confirmation_method=envelope.confirmation_method,
            confirmed_by=envelope.confirmed_by,
            parent_decision_id=envelope.parent_decision_id,
        )

    def _authorization_valid(
        self,
        envelope: ActionAuthorizationEnvelope,
        lineage: OriginalRetestLineage,
        allowed_scope: tuple[str, ...],
        excluded_scope: tuple[str, ...],
    ) -> bool:
        try:
            now = self.clock().astimezone(timezone.utc)
            expires = parse_utc(envelope.expires_at)
        except Exception:
            return False
        return all(
            (
                envelope.decision_outcome == "allow",
                envelope.scope_decision == "allowed",
                envelope.tenant_id == lineage.tenant_id,
                envelope.operator_role
                in {OperatorRole.OPERATOR.value, OperatorRole.ADMIN.value},
                envelope.engine in {"webforge", "netforge", "forge"},
                envelope.action_kind == "engine.execute",
                envelope.module_id == module_set_binding([lineage.module_id]),
                envelope.requested_target == canonical_target(lineage.target_url),
                envelope.resolved_target == canonical_target(lineage.target_url),
                envelope.scope_snapshot
                == _scope_snapshot(allowed_scope, excluded_scope),
                envelope.credential_approval_required
                is bool(lineage.session_reference),
                now < expires,
                (envelope.credential_reference or None)
                == lineage.session_reference,
            )
        )

    def _current_authorization_valid(
        self,
        envelope: ActionAuthorizationEnvelope,
        lineage: OriginalRetestLineage,
        allowed_scope: tuple[str, ...],
        excluded_scope: tuple[str, ...],
    ) -> bool:
        """Validate the complete persisted consumed authority before replay."""

        if not self._authorization_valid(
            envelope,
            lineage,
            allowed_scope,
            excluded_scope,
        ):
            return False
        expected = self._current_authorization_context(
            envelope,
            lineage,
            allowed_scope,
            excluded_scope,
        )
        if self.authorization_session_factory is not None:
            authorization_session = self.authorization_session_factory()
        else:
            bind = self.session.get_bind()
            if bind is None:
                return False
            authorization_session = Session(
                bind=bind,
                autoflush=False,
                expire_on_commit=False,
            )
        try:
            decision = validate_consumed_authorization(
                session=authorization_session,
                envelope=envelope,
                expected=expected,
                boundary="retest.verifier",
                now=self.clock(),
            )
            return bool(decision.allowed)
        except Exception:
            return False
        finally:
            authorization_session.close()

    def _build_policy(
        self,
        envelope: ActionAuthorizationEnvelope,
        expected: AuthorizationContext,
        target: str,
        allowed_scope: tuple[str, ...],
        excluded_scope: tuple[str, ...],
    ) -> Any:
        if self.outbound_policy_factory is not None:
            return self.outbound_policy_factory(
                envelope,
                expected,
                target,
                allowed_scope,
                excluded_scope,
            )
        if self.authorization_session_factory is None:
            raise RetestAuthorizationError(
                "retest outbound authorization database is unavailable"
            )
        session = self.authorization_session_factory()
        try:
            context = OutboundContext.from_consumed_authorization(
                session=session,
                envelope=envelope,
                expected=expected,
                boundary="retest.verifier",
                authorized_target=target,
                allowed_scope=allowed_scope,
                excluded_scope=excluded_scope,
                audit_sink=DatabaseOutboundAuditSink(session),
                max_redirects=0,
                max_retries=0,
                timeout_seconds=10.0,
                max_response_bytes=1024 * 1024,
                cancellation_check=lambda: (
                    (
                        current := self.job_state.get_job(
                            envelope.job_id,
                            tenant_id=envelope.tenant_id,
                        )
                    )
                    is not None
                    and str(current.get("state") or "")
                    in {
                        JobState.CANCELING.value,
                        JobState.CANCELED.value,
                    }
                ),
            )
            return OutboundPolicy(context)
        except Exception:
            raise RetestAuthorizationError(
                "retest outbound authorization is invalid"
            ) from None
        finally:
            session.close()

    def _ensure_current_context(
        self,
        envelope: ActionAuthorizationEnvelope,
    ) -> tuple[str, str]:
        role_id = _stable_id("role", envelope.tenant_id, envelope.operator_role)
        records = (
            Operator(
                id=envelope.operator_id,
                tenant_id=envelope.tenant_id,
                display_name="Authorized operator",
            ),
            Role(
                id=role_id,
                tenant_id=envelope.tenant_id,
                name=envelope.operator_role,
            ),
            ScopeDecision(
                id=envelope.decision_id,
                tenant_id=envelope.tenant_id,
                engagement_id=envelope.engagement_id,
                operator_id=envelope.operator_id,
                role_id=role_id,
                outcome=ScopeOutcome.ALLOW,
                policy_version=envelope.scope_policy_version,
                decision_reason=envelope.scope_reason,
                decided_at=parse_utc(envelope.issued_at),
            ),
            Action(
                id=envelope.action_id,
                tenant_id=envelope.tenant_id,
                engagement_id=envelope.engagement_id,
                job_id=envelope.job_id,
                action_kind=envelope.action_kind,
                authorization_decision_id=envelope.decision_id,
            ),
        )
        if self.session.in_transaction():
            self.session.rollback()
        store = CanonicalStore(self.session)
        with self.session.begin():
            for record in records:
                store._insert_or_validate_existing(record)
        return role_id, envelope.decision_id

    def _content_snapshot(self) -> str:
        return _sha256(
            Path(__file__).resolve().parents[1]
            .joinpath("webforge/modules/headers/header_audit.py")
            .read_bytes()
        )

    def _existing_result(
        self,
        *,
        tenant_id: str,
        request_id: str,
        finding_id: str,
        authorization: ActionAuthorizationEnvelope | None = None,
    ) -> RetestExecutionResult | None:
        row = self.session.execute(
            text(
                "SELECT r.finding_id,r.engagement_id,r.current_operator_id,"
                "r.authorization_decision_id,r.authorization_action_id,"
                "r.new_job_id,r.session_reference,"
                "ra.id AS attempt_id,ra.job_id,ra.durable_attempt_id,"
                "ra.state,ra.verdict,ra.reason_code,ra.proof_id,p.observation_id,"
                "p.artifact_id,p.sufficient,p.proof_digest,pm.manifest_digest "
                "FROM canonical_retests r "
                "JOIN canonical_retest_attempts ra "
                "ON ra.tenant_id=r.tenant_id AND ra.retest_id=r.id "
                "LEFT JOIN canonical_retest_proofs p "
                "ON p.tenant_id=ra.tenant_id AND p.id=ra.proof_id "
                "LEFT JOIN canonical_artifact_manifests pm "
                "ON pm.tenant_id=p.tenant_id AND pm.artifact_id=p.artifact_id "
                "AND pm.observation_id=p.observation_id "
                "WHERE r.tenant_id=:tenant_id AND r.id=:request_id "
                "ORDER BY ra.created_at DESC,ra.id DESC LIMIT 1"
            ),
            {"tenant_id": tenant_id, "request_id": request_id},
        ).mappings().first()
        if self.session.in_transaction():
            self.session.rollback()
        if row is None or str(row["state"]) not in {"terminal", "canceled"}:
            return None
        if str(row["finding_id"]) != finding_id:
            raise RetestPersistenceError(
                "terminal retest result conflicts with its finding"
            )
        if authorization is not None and not all(
            (
                str(row["engagement_id"]) == authorization.engagement_id,
                str(row["current_operator_id"]) == authorization.operator_id,
                str(row["authorization_decision_id"])
                == authorization.decision_id,
                str(row["authorization_action_id"])
                == authorization.action_id,
                str(row["new_job_id"]) == authorization.job_id,
                (
                    str(row["session_reference"])
                    if row["session_reference"] is not None
                    else None
                )
                == (authorization.credential_reference or None),
            )
        ):
            raise RetestAuthorizationError(
                "terminal retest replay authorization does not match"
            )
        verdict = RetestStatus(str(row["verdict"])) if row["verdict"] else None
        durable_job = self.job_state.get_job(
            str(row["job_id"]),
            tenant_id=tenant_id,
        )
        if durable_job is None or str(durable_job.get("state") or "") not in {
            JobState.COMPLETED.value,
            JobState.FAILED.value,
            JobState.PARTIAL.value,
            JobState.CANCELED.value,
        }:
            raise RetestPersistenceError(
                "terminal retest result conflicts with Task 103 truth"
            )
        if verdict is not None:
            if (
                row["artifact_id"] is None
                or row["observation_id"] is None
                or row["proof_digest"] is None
                or row["manifest_digest"] is None
            ):
                raise RetestPersistenceError(
                    "terminal retest result is missing immutable proof"
                )
            try:
                manifest = EvidenceCustodyStore(
                    self.custody_root,
                    tenant_id,
                ).verify(str(row["artifact_id"]))
            except Exception as exc:
                raise RetestPersistenceError(
                    "terminal retest result failed custody verification"
                ) from exc
            if (
                manifest.source_observation_id != str(row["observation_id"])
                or manifest.manifest_digest != str(row["manifest_digest"])
                or manifest.sha256 != str(row["proof_digest"])
            ):
                raise RetestPersistenceError(
                    "terminal retest result does not match custody"
                )
            if verdict in {
                RetestStatus.FIXED,
                RetestStatus.STILL_VULNERABLE,
            } and int(row["sufficient"] or 0) != 1:
                raise RetestPersistenceError(
                    "terminal retest result has insufficient proof"
                )
        return RetestExecutionResult(
            state=str(row["state"]),
            verdict=verdict,
            reason_code=str(row["reason_code"] or "retest_canceled"),
            finding_id=finding_id,
            retest_id=request_id,
            retest_attempt_id=str(row["attempt_id"]),
            job_id=str(row["job_id"]),
            durable_attempt_id=str(row["durable_attempt_id"]),
            observation_id=(str(row["observation_id"]) if row["observation_id"] else None),
            artifact_id=(str(row["artifact_id"]) if row["artifact_id"] else None),
            duplicate=True,
        )

    def _active_request_attempt(
        self,
        *,
        tenant_id: str,
        request_id: str,
    ) -> tuple[RetestRequest, RetestAttempt] | None:
        request_row = self.session.execute(
            text(
                "SELECT * FROM canonical_retests "
                "WHERE tenant_id=:tenant_id AND id=:request_id"
            ),
            {"tenant_id": tenant_id, "request_id": request_id},
        ).mappings().first()
        attempt_row = self.session.execute(
            text(
                "SELECT * FROM canonical_retest_attempts "
                "WHERE tenant_id=:tenant_id AND retest_id=:request_id "
                "ORDER BY created_at DESC,id DESC LIMIT 1"
            ),
            {"tenant_id": tenant_id, "request_id": request_id},
        ).mappings().first()
        if self.session.in_transaction():
            self.session.rollback()
        if request_row is None or attempt_row is None:
            return None
        if str(attempt_row["state"]) not in {"planned", "running"}:
            return None
        try:
            request = RetestRequest(
                id=str(request_row["id"]),
                tenant_id=str(request_row["tenant_id"]),
                engagement_id=str(request_row["engagement_id"]),
                original_engagement_id=str(
                    request_row["original_engagement_id"]
                ),
                finding_id=str(request_row["finding_id"]),
                source_observation_id=str(request_row["source_observation_id"]),
                source_artifact_id=str(request_row["source_artifact_id"]),
                source_proof_artifact_id=str(
                    request_row["source_proof_artifact_id"]
                ),
                source_snapshot_id=str(request_row["source_snapshot_id"]),
                original_job_id=str(request_row["original_job_id"]),
                original_attempt_id=str(request_row["original_attempt_id"]),
                original_action_id=str(request_row["original_action_id"]),
                original_authorization_decision_id=str(
                    request_row["original_authorization_decision_id"]
                ),
                original_module_version_id=str(
                    request_row["original_module_version_id"]
                ),
                asset_id=str(request_row["asset_id"]),
                current_operator_id=str(request_row["current_operator_id"]),
                current_role_id=str(request_row["current_role_id"]),
                current_scope_decision_id=str(
                    request_row["current_scope_decision_id"]
                ),
                authorization_decision_id=str(
                    request_row["authorization_decision_id"]
                ),
                authorization_action_id=str(
                    request_row["authorization_action_id"]
                ),
                new_job_id=str(request_row["new_job_id"]),
                module_id=str(request_row["module_id"]),
                check_id=str(request_row["check_id"]),
                module_version=str(request_row["module_version"]),
                content_snapshot_digest=str(
                    request_row["content_snapshot_digest"]
                ),
                policy_snapshot=str(request_row["policy_snapshot"]),
                target_url=str(request_row["target_url"]),
                route=str(request_row["route"]),
                method=str(request_row["method"]),
                parameter=(
                    str(request_row["parameter"])
                    if request_row["parameter"] is not None
                    else None
                ),
                location=(
                    str(request_row["location"])
                    if request_row["location"] is not None
                    else None
                ),
                identity_ref=(
                    str(request_row["identity_ref"])
                    if request_row["identity_ref"] is not None
                    else None
                ),
                session_reference=(
                    str(request_row["session_reference"])
                    if request_row["session_reference"] is not None
                    else None
                ),
                session_policy_digest=str(
                    request_row["session_policy_digest"]
                ),
                mutation_class=str(request_row["mutation_class"]),
                proof_expectation=str(request_row["proof_expectation"]),
                proof_policy_version=str(request_row["proof_policy_version"]),
                evidence_baseline_digest=str(
                    request_row["evidence_baseline_digest"]
                ),
                verifier_id=str(request_row["verifier_id"]),
                verifier_version=str(request_row["verifier_version"]),
                verifier_policy_id=str(request_row["verifier_policy_id"]),
                idempotency_key=str(request_row["idempotency_key"]),
                state=RetestRequestState(str(request_row["state"])),
                schema_version=str(request_row["schema_version"]),
                created_at=parse_utc(str(request_row["created_at"])),
                metadata=json.loads(str(request_row["metadata_json"])),
            )
            attempt = RetestAttempt(
                id=str(attempt_row["id"]),
                tenant_id=str(attempt_row["tenant_id"]),
                retest_id=str(attempt_row["retest_id"]),
                job_id=str(attempt_row["job_id"]),
                durable_attempt_id=str(attempt_row["durable_attempt_id"]),
                verifier_id=str(attempt_row["verifier_id"]),
                verifier_version=str(attempt_row["verifier_version"]),
                proof_policy_version=str(attempt_row["proof_policy_version"]),
                idempotency_key=str(attempt_row["idempotency_key"]),
                state=RetestAttemptState(str(attempt_row["state"])),
                reason_code=(
                    str(attempt_row["reason_code"])
                    if attempt_row["reason_code"] is not None
                    else None
                ),
                started_at=(
                    parse_utc(str(attempt_row["started_at"]))
                    if attempt_row["started_at"] is not None
                    else None
                ),
                created_at=parse_utc(str(attempt_row["created_at"])),
                metadata=json.loads(str(attempt_row["metadata_json"])),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RetestPersistenceError(
                "persisted retest request/attempt is invalid"
            ) from exc
        return request, attempt

    @staticmethod
    def _replay_identity_matches(
        request: RetestRequest,
        attempt: RetestAttempt,
        *,
        lineage: OriginalRetestLineage,
        envelope: ActionAuthorizationEnvelope,
        finding_id: str,
        idempotency_key: str,
        verifier_id: str,
        verifier_version: str,
        proof_policy: str,
    ) -> bool:
        """Bind a duplicate/restart to the exact immutable request identity."""

        return all(
            (
                request.tenant_id == lineage.tenant_id,
                request.engagement_id == envelope.engagement_id,
                request.original_engagement_id
                == lineage.original_engagement_id,
                request.finding_id == finding_id == lineage.finding_id,
                request.source_observation_id
                == lineage.source_observation_id,
                request.source_artifact_id == lineage.source_artifact_id,
                request.source_proof_artifact_id
                == lineage.source_proof_artifact_id,
                request.source_snapshot_id
                == _stable_id(
                    "retest-source-snapshot",
                    lineage.tenant_id,
                    lineage.finding_id,
                    lineage.source_observation_id,
                    lineage.source_artifact_id,
                    lineage.source_proof_artifact_id,
                    lineage.original_action_id,
                    lineage.original_authorization_decision_id,
                    lineage.method,
                    lineage.session_reference or "",
                    lineage.session_policy_digest,
                    lineage.proof_expectation,
                    lineage.evidence_baseline_digest,
                ),
                request.original_job_id == lineage.original_job_id,
                request.original_attempt_id == lineage.original_attempt_id,
                request.original_action_id == lineage.original_action_id,
                request.original_authorization_decision_id
                == lineage.original_authorization_decision_id,
                request.original_module_version_id
                == lineage.original_module_version_id,
                request.asset_id == lineage.asset_id,
                request.current_operator_id == envelope.operator_id,
                request.current_role_id
                == _stable_id(
                    "role", envelope.tenant_id, envelope.operator_role
                ),
                request.current_scope_decision_id == envelope.decision_id,
                request.authorization_decision_id == envelope.decision_id,
                request.authorization_action_id == envelope.action_id,
                request.new_job_id == envelope.job_id,
                request.module_id == lineage.module_id,
                request.check_id == lineage.check_id,
                request.module_version == lineage.module_version,
                request.target_url == lineage.target_url,
                request.route == lineage.route,
                request.method == lineage.method,
                request.parameter == lineage.parameter,
                request.location == lineage.location,
                request.identity_ref == lineage.identity_ref,
                request.session_reference == lineage.session_reference,
                request.session_policy_digest == lineage.session_policy_digest,
                request.proof_expectation == lineage.proof_expectation,
                request.evidence_baseline_digest
                == lineage.evidence_baseline_digest,
                request.idempotency_key == idempotency_key,
                request.verifier_id == verifier_id,
                request.verifier_version == verifier_version,
                request.proof_policy_version == proof_policy,
                request.verifier_policy_id
                == _stable_id(
                    "retest-verifier-policy",
                    request.tenant_id,
                    request.module_id,
                    request.check_id,
                    request.module_version,
                    request.content_snapshot_digest,
                    request.policy_snapshot,
                    request.mutation_class,
                    request.verifier_id,
                    request.verifier_version,
                    request.proof_policy_version,
                ),
                attempt.retest_id == request.id,
                attempt.job_id == envelope.job_id,
                attempt.verifier_id == verifier_id,
                attempt.verifier_version == verifier_version,
                attempt.proof_policy_version == proof_policy,
            )
        )

    @staticmethod
    def _output_from_proof_payload(
        request: RetestRequest,
        payload: Mapping[str, Any],
    ) -> VerifierOutput:
        expected_keys = {
            "schema_version",
            "retest_id",
            "verifier_id",
            "verifier_version",
            "proof_policy_version",
            "proof_expectation",
            "observed_condition",
            "method",
            "route",
            "response_status",
            "sufficient",
            "header_value_digest",
            "verdict",
            "reason_code",
        }
        if set(payload) != expected_keys or any(
            payload.get(key) != value
            for key, value in {
                "schema_version": RETEST_CONTRACT_VERSION,
                "retest_id": request.id,
                "verifier_id": request.verifier_id,
                "verifier_version": request.verifier_version,
                "proof_policy_version": request.proof_policy_version,
                "proof_expectation": request.proof_expectation,
                "method": request.method,
                "route": request.route,
            }.items()
        ):
            raise RetestPersistenceError(
                "persisted retest proof payload does not match its request"
            )
        try:
            verdict = RetestStatus(str(payload["verdict"]))
            sufficient = payload["sufficient"]
            if type(sufficient) is not bool:
                raise ValueError
            status = payload["response_status"]
            if status is not None and (
                isinstance(status, bool)
                or not isinstance(status, int)
                or not 100 <= status <= 599
            ):
                raise ValueError
            header_digest = payload["header_value_digest"]
            if header_digest is not None and (
                not isinstance(header_digest, str)
                or not header_digest.startswith("sha256:")
                or len(header_digest) != 71
            ):
                raise ValueError
            output = VerifierOutput(
                verdict=verdict,
                reason_code=str(payload["reason_code"]),
                observed_condition=str(payload["observed_condition"]),
                response_status=status,
                sufficient=sufficient,
                header_value_digest=header_digest,
            )
        except (TypeError, ValueError) as exc:
            raise RetestPersistenceError(
                "persisted retest proof payload is malformed"
            ) from exc
        if output.verdict is RetestStatus.FIXED and not (
            output.sufficient
            and output.observed_condition == "csp_strong"
            and output.response_status is not None
            and 200 <= output.response_status <= 299
        ):
            raise RetestPersistenceError("persisted fixed proof is insufficient")
        if output.verdict is RetestStatus.STILL_VULNERABLE and not (
            output.sufficient
            and output.observed_condition == request.proof_expectation
            and output.response_status is not None
            and 200 <= output.response_status <= 299
        ):
            raise RetestPersistenceError(
                "persisted still-vulnerable proof is insufficient"
            )
        if output.verdict not in {
            RetestStatus.FIXED,
            RetestStatus.STILL_VULNERABLE,
        } and output.sufficient:
            raise RetestPersistenceError(
                "non-proof retest verdict cannot claim sufficient evidence"
            )
        if (
            output.verdict is RetestStatus.NOT_APPLICABLE
            and request.verifier_id == HEADER_CSP_VERIFIER_ID
        ):
            raise RetestPersistenceError(
                "header CSP policy cannot emit not_applicable"
            )
        return output

    def _accepted_delivery_recovery(
        self,
        request: RetestRequest,
        attempt: RetestAttempt,
        *,
        lease_token: str,
    ) -> RetestExecutionResult | None:
        if attempt.durable_attempt_id is None:
            return None
        delivery_row = self.session.execute(
            text(
                "SELECT * FROM durable_job_state_deliveries "
                "WHERE tenant_id=:tenant_id AND attempt_id=:attempt_id "
                "AND state='accepted' ORDER BY accepted_at DESC,"
                "idempotency_key DESC LIMIT 1"
            ),
            {
                "tenant_id": request.tenant_id,
                "attempt_id": attempt.durable_attempt_id,
            },
        ).mappings().first()
        if self.session.in_transaction():
            self.session.rollback()
        if delivery_row is None:
            return None
        delivery = dict(delivery_row)
        artifact_id = str(delivery.get("artifact_id") or "")
        observation_id = str(delivery.get("observation_id") or "")
        manifest_digest = str(delivery.get("manifest_digest") or "")
        custody = EvidenceCustodyStore(self.custody_root, request.tenant_id)
        try:
            manifest = custody.verify(artifact_id)
            reader = CanonicalEvidenceReader(
                self.session,
                self.custody_root,
                request.tenant_id,
                audit_actor_id=request.current_operator_id,
                expected_original_operator_id=request.current_operator_id,
            )
            original = reader.read_protected_original(
                artifact_id,
                make_original_authorization(
                    tenant_id=request.tenant_id,
                    artifact_id=artifact_id,
                    authorization_ref=(
                        f"authorization:{request.authorization_decision_id}"
                    ),
                    operator_id=request.current_operator_id,
                    reason="recover exact Task 104 verifier proof",
                ),
            )
            payload = json.loads(original.decode("utf-8"))
        except Exception as exc:
            raise RetestPersistenceError(
                "accepted retest delivery failed custody verification"
            ) from exc
        if (
            not isinstance(payload, Mapping)
            or manifest.source_observation_id != observation_id
            or manifest.manifest_digest != manifest_digest
        ):
            raise RetestPersistenceError(
                "accepted retest delivery does not match custody"
            )
        output = self._output_from_proof_payload(request, payload)
        durable_job = self.job_state.get_job(
            attempt.job_id,
            tenant_id=request.tenant_id,
        )
        if durable_job is None:
            raise RetestPersistenceError("accepted retest job is unavailable")
        if str(durable_job["state"]) == JobState.CANCELED.value:
            return self._mark_canceled(
                request,
                attempt,
                reason_code="task103_job_canceled",
            )
        if str(durable_job["state"]) not in {
            JobState.COMPLETED.value,
            JobState.FAILED.value,
            JobState.PARTIAL.value,
        }:
            if not lease_token:
                raise RetestPersistenceError(
                    "accepted retest delivery lacks a recoverable lease"
                )
            self.job_state.finish_attempt(
                attempt.durable_attempt_id,
                tenant_id=request.tenant_id,
                lease_token=lease_token,
                worker_id="retest-verifier",
                error_reason=(
                    output.reason_code
                    if output.verdict
                    in {RetestStatus.FAILED, RetestStatus.NOT_AUTHORIZED}
                    else None
                ),
                terminal_reason=output.reason_code,
                actor=TransitionActor(
                    tenant_id=request.tenant_id,
                    actor_id="retest-recovery",
                    role="system",
                    authorization_decision_id=request.authorization_decision_id,
                ),
            )
        proof = self._record_terminal_proof(
            request,
            attempt,
            output,
            ObservationReceipt(
                tenant_id=request.tenant_id,
                job_id=attempt.job_id,
                attempt_id=attempt.durable_attempt_id,
                observation_id=observation_id,
                artifact_id=artifact_id,
                result_ref=str(delivery.get("result_ref") or artifact_id),
                manifest_digest=manifest_digest,
            ),
        )
        return RetestExecutionResult(
            state="terminal",
            verdict=output.verdict,
            reason_code=output.reason_code,
            finding_id=request.finding_id,
            retest_id=request.id,
            retest_attempt_id=attempt.id,
            job_id=attempt.job_id,
            durable_attempt_id=attempt.durable_attempt_id,
            observation_id=proof.observation_id,
            artifact_id=proof.artifact_id,
            duplicate=True,
        )

    @contextmanager
    def _resolved_session(
        self,
        request: RetestRequest,
        envelope: ActionAuthorizationEnvelope,
    ) -> Iterator[tuple[Mapping[str, str], Mapping[str, str]]]:
        if request.session_reference is None:
            yield {}, {}
            return
        if self.session_resolver is None:
            raise RetestAuthorizationError(
                "protected session reference cannot be resolved"
            )
        reference = CredentialReference.parse(request.session_reference)
        approval = CredentialUseApproval(
            approval_id=envelope.decision_id,
            provider=reference.provider,
            target=request.target_url,
            credential_reference=reference.value,
            max_uses=1,
        )
        stack = ExitStack()
        try:
            values = stack.enter_context(self.session_resolver.resolve(
                reference,
                approval=approval,
                target=request.target_url,
            ))
            headers_value = values.get("headers", values.get("session_headers", {}))
            cookies_value = values.get("cookies", values.get("session_cookies", {}))
            headers = (
                {str(key): str(item) for key, item in headers_value.items()}
                if isinstance(headers_value, Mapping)
                else {}
            )
            cookies = (
                {str(key): str(item) for key, item in cookies_value.items()}
                if isinstance(cookies_value, Mapping)
                else {}
            )
            if not headers and not cookies:
                raise RetestAuthorizationError(
                    "protected session resolved no governed HTTP material"
                )
        except RetestAuthorizationError:
            stack.close()
            raise
        except Exception:
            stack.close()
            raise RetestAuthorizationError(
                "protected session authority is unavailable or mismatched"
            ) from None
        try:
            yield headers, cookies
        finally:
            stack.close()

    def _persist_request_attempt(
        self,
        request: RetestRequest,
        attempt: RetestAttempt,
    ) -> bool:
        store = CanonicalStore(self.session)
        if self.session.in_transaction():
            self.session.rollback()
        try:
            with self.session.begin():
                self._insert_or_validate_request_authorities(request)
                store._insert(request)
                store._insert(attempt)
                self.session.execute(
                    text(
                        "INSERT INTO canonical_retest_attempt_events("
                        "tenant_id,retest_id,retest_attempt_id,from_state,to_state,"
                        "verdict,reason_code,occurred_at) "
                        "VALUES(:tenant_id,:retest_id,:attempt_id,NULL,'planned',"
                        "NULL,'verifier_planned',:occurred_at)"
                    ),
                    {
                        "tenant_id": request.tenant_id,
                        "retest_id": request.id,
                        "attempt_id": attempt.id,
                        "occurred_at": self.clock().isoformat(),
                    },
                )
            return True
        except IntegrityError:
            if self.session.in_transaction():
                self.session.rollback()
            return False
        except Exception as exc:
            raise RetestPersistenceError(
                "canonical retest request/attempt persistence failed"
            ) from exc

    def _insert_or_validate_request_authorities(
        self,
        request: RetestRequest,
    ) -> None:
        """Persist immutable source and verifier-policy rows before the request."""

        source_values: dict[str, Any] = {
            "id": request.source_snapshot_id,
            "tenant_id": request.tenant_id,
            "finding_id": request.finding_id,
            "source_observation_id": request.source_observation_id,
            "source_artifact_id": request.source_artifact_id,
            "source_proof_artifact_id": request.source_proof_artifact_id,
            "original_action_id": request.original_action_id,
            "original_authorization_decision_id": (
                request.original_authorization_decision_id
            ),
            "method": request.method,
            "session_reference": request.session_reference,
            "session_policy_digest": request.session_policy_digest,
            "proof_expectation": request.proof_expectation,
            "evidence_baseline_digest": request.evidence_baseline_digest,
            "schema_version": request.schema_version,
            "created_at": request.created_at.isoformat(),
            "metadata_json": "{}",
        }
        policy_values: dict[str, Any] = {
            "id": request.verifier_policy_id,
            "tenant_id": request.tenant_id,
            "module_id": request.module_id,
            "check_id": request.check_id,
            "source_version": request.module_version,
            "content_snapshot_digest": request.content_snapshot_digest,
            "policy_snapshot": request.policy_snapshot,
            "mutation_class": request.mutation_class,
            "verifier_id": request.verifier_id,
            "verifier_version": request.verifier_version,
            "proof_policy_version": request.proof_policy_version,
            "schema_version": request.schema_version,
            "created_at": request.created_at.isoformat(),
            "metadata_json": "{}",
        }
        self.session.execute(
            text(
                "INSERT OR IGNORE INTO canonical_retest_source_snapshots("
                + ",".join(source_values)
                + ") VALUES("
                + ",".join(f":{name}" for name in source_values)
                + ")"
            ),
            source_values,
        )
        self.session.execute(
            text(
                "INSERT OR IGNORE INTO canonical_retest_verifier_policies("
                + ",".join(policy_values)
                + ") VALUES("
                + ",".join(f":{name}" for name in policy_values)
                + ")"
            ),
            policy_values,
        )
        for table, values in (
            ("canonical_retest_source_snapshots", source_values),
            ("canonical_retest_verifier_policies", policy_values),
        ):
            row = self.session.execute(
                text(
                    f"SELECT * FROM {table} "
                    "WHERE tenant_id=:tenant_id AND id=:id"
                ),
                {"tenant_id": request.tenant_id, "id": values["id"]},
            ).mappings().first()
            compared = {key: value for key, value in values.items() if key != "created_at"}
            if row is None or any(row[key] != value for key, value in compared.items()):
                raise RetestPersistenceError(
                    "canonical retest source/policy identity conflicts"
                )

    def _claim_attempt(
        self,
        request: RetestRequest,
        attempt: RetestAttempt,
    ) -> bool:
        """Atomically claim the one canonical verifier execution."""

        if self.session.in_transaction():
            self.session.rollback()
        with self.session.begin():
            result = self.session.execute(
                text(
                    "UPDATE canonical_retest_attempts SET state='running',"
                    "started_at=:started_at WHERE tenant_id=:tenant_id "
                    "AND id=:attempt_id AND state='planned'"
                ),
                {
                    "started_at": self.clock().isoformat(),
                    "tenant_id": request.tenant_id,
                    "attempt_id": attempt.id,
                },
            )
            claimed = getattr(result, "rowcount", None) == 1
            if claimed:
                self.session.execute(
                    text(
                        "INSERT INTO canonical_retest_attempt_events("
                        "tenant_id,retest_id,retest_attempt_id,from_state,to_state,"
                        "verdict,reason_code,occurred_at) VALUES("
                        ":tenant_id,:retest_id,:attempt_id,'planned','running',"
                        "NULL,'verifier_started',:occurred_at)"
                    ),
                    {
                        "tenant_id": request.tenant_id,
                        "retest_id": request.id,
                        "attempt_id": attempt.id,
                        "occurred_at": self.clock().isoformat(),
                    },
                )
        return claimed

    async def _wait_for_duplicate_result(
        self,
        request: RetestRequest,
        attempt: RetestAttempt,
        *,
        authorization: ActionAuthorizationEnvelope,
        timeout_seconds: float = 15.0,
    ) -> RetestExecutionResult:
        """Wait for the claimed execution or return bounded durable lifecycle."""

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        while True:
            prior = self._existing_result(
                tenant_id=request.tenant_id,
                request_id=request.id,
                finding_id=request.finding_id,
                authorization=authorization,
            )
            if prior is not None:
                return prior
            active = self._active_request_attempt(
                tenant_id=request.tenant_id,
                request_id=request.id,
            )
            if active is None:
                raise RetestPersistenceError(
                    "duplicate retest lost its canonical attempt"
                )
            active_request, active_attempt = active
            durable_job = self.job_state.get_job(
                active_attempt.job_id,
                tenant_id=request.tenant_id,
            )
            if durable_job is not None and str(durable_job.get("state") or "") in {
                JobState.COMPLETED.value,
                JobState.FAILED.value,
                JobState.PARTIAL.value,
                JobState.CANCELED.value,
            }:
                recovered = self._accepted_delivery_recovery(
                    active_request,
                    active_attempt,
                    lease_token="",
                )
                if recovered is not None:
                    return recovered
            if loop.time() >= deadline:
                return RetestExecutionResult(
                    state=active_attempt.state.value,
                    verdict=None,
                    reason_code="duplicate_execution_in_progress",
                    finding_id=request.finding_id,
                    retest_id=request.id,
                    retest_attempt_id=active_attempt.id,
                    job_id=active_attempt.job_id,
                    durable_attempt_id=active_attempt.durable_attempt_id,
                    duplicate=True,
                )
            await asyncio.sleep(0.05)

    def _record_terminal_proof(
        self,
        request: RetestRequest,
        attempt: RetestAttempt,
        output: VerifierOutput,
        receipt: ObservationReceipt,
    ) -> RetestProof:
        payload = output.proof_payload(request)
        proof_digest = _sha256(_canonical_json(payload))
        proof = RetestProof(
            id=_stable_id("retest-proof", request.tenant_id, attempt.id),
            tenant_id=request.tenant_id,
            retest_id=request.id,
            retest_attempt_id=attempt.id,
            durable_job_id=request.new_job_id or attempt.job_id,
            durable_attempt_id=attempt.durable_attempt_id or "",
            original_observation_id=request.source_observation_id,
            observation_id=receipt.observation_id,
            artifact_id=receipt.artifact_id,
            verifier_id=request.verifier_id,
            verifier_version=request.verifier_version,
            proof_policy_version=request.proof_policy_version,
            proof_expectation=request.proof_expectation,
            observed_condition=output.observed_condition,
            route=request.route,
            method=request.method,
            response_status=output.response_status,
            sufficient=output.sufficient,
            header_value_digest=output.header_value_digest,
            proof_digest=proof_digest,
        )
        existing = self._load_exact_terminal_proof(
            proof,
            verdict=output.verdict,
            reason_code=output.reason_code,
        )
        if existing is not None:
            return existing
        store = CanonicalStore(self.session)
        if self.session.in_transaction():
            self.session.rollback()
        try:
            with self.session.begin():
                store._insert(proof)
                self.session.execute(
                    text(
                        "INSERT INTO canonical_retest_proof_artifacts("
                        "tenant_id,proof_id,observation_id,artifact_id,role,created_at) "
                        "VALUES(:tenant_id,:proof_id,:observation_id,:artifact_id,"
                        "'primary',:created_at)"
                    ),
                    {
                        "tenant_id": request.tenant_id,
                        "proof_id": proof.id,
                        "observation_id": receipt.observation_id,
                        "artifact_id": receipt.artifact_id,
                        "created_at": self.clock().isoformat(),
                    },
                )
                result = self.session.execute(
                    text(
                        "UPDATE canonical_retest_attempts SET state='terminal',"
                        "verdict=:verdict,reason_code=:reason_code,proof_id=:proof_id,"
                        "finished_at=:finished_at WHERE tenant_id=:tenant_id AND id=:id "
                        "AND state='running'"
                    ),
                    {
                        "verdict": output.verdict.value,
                        "reason_code": output.reason_code,
                        "proof_id": proof.id,
                        "finished_at": self.clock().isoformat(),
                        "tenant_id": request.tenant_id,
                        "id": attempt.id,
                    },
                )
                if getattr(result, "rowcount", None) != 1:
                    raise RetestPersistenceError(
                        "canonical retest attempt terminal transition failed"
                    )
                self.session.execute(
                    text(
                        "INSERT INTO canonical_retest_attempt_events("
                        "tenant_id,retest_id,retest_attempt_id,from_state,to_state,"
                        "verdict,reason_code,occurred_at) "
                        "VALUES(:tenant_id,:retest_id,:attempt_id,'running','terminal',"
                        ":verdict,:reason_code,:occurred_at)"
                    ),
                    {
                        "tenant_id": request.tenant_id,
                        "retest_id": request.id,
                        "attempt_id": attempt.id,
                        "verdict": output.verdict.value,
                        "reason_code": output.reason_code,
                        "occurred_at": self.clock().isoformat(),
                    },
                )
        except IntegrityError as exc:
            if self.session.in_transaction():
                self.session.rollback()
            existing = self._load_exact_terminal_proof(
                proof,
                verdict=output.verdict,
                reason_code=output.reason_code,
            )
            if existing is not None:
                return existing
            raise RetestPersistenceError(
                "conflicting concurrent retest proof"
            ) from exc
        return proof

    def _load_exact_terminal_proof(
        self,
        proof: RetestProof,
        *,
        verdict: RetestStatus,
        reason_code: str,
    ) -> RetestProof | None:
        row = self.session.execute(
            text(
                "SELECT p.*,ra.state AS attempt_state,ra.verdict,"
                "ra.reason_code,ra.proof_id AS attempt_proof_id,pa.role "
                "FROM canonical_retest_proofs p "
                "JOIN canonical_retest_attempts ra "
                "ON ra.tenant_id=p.tenant_id AND ra.id=p.retest_attempt_id "
                "JOIN canonical_retest_proof_artifacts pa "
                "ON pa.tenant_id=p.tenant_id AND pa.proof_id=p.id "
                "AND pa.observation_id=p.observation_id "
                "AND pa.artifact_id=p.artifact_id "
                "WHERE p.tenant_id=:tenant_id AND p.id=:proof_id"
            ),
            {"tenant_id": proof.tenant_id, "proof_id": proof.id},
        ).mappings().first()
        if self.session.in_transaction():
            self.session.rollback()
        if row is None:
            return None
        expected = {
            "retest_id": proof.retest_id,
            "retest_attempt_id": proof.retest_attempt_id,
            "durable_job_id": proof.durable_job_id,
            "durable_attempt_id": proof.durable_attempt_id,
            "original_observation_id": proof.original_observation_id,
            "observation_id": proof.observation_id,
            "artifact_id": proof.artifact_id,
            "verifier_id": proof.verifier_id,
            "verifier_version": proof.verifier_version,
            "proof_policy_version": proof.proof_policy_version,
            "proof_expectation": proof.proof_expectation,
            "observed_condition": proof.observed_condition,
            "route": proof.route,
            "method": proof.method,
            "response_status": proof.response_status,
            "sufficient": int(proof.sufficient),
            "header_value_digest": proof.header_value_digest,
            "proof_digest": proof.proof_digest,
        }
        if (
            any(row[key] != value for key, value in expected.items())
            or str(row["attempt_state"]) != "terminal"
            or str(row["verdict"]) != verdict.value
            or str(row["reason_code"]) != reason_code
            or str(row["attempt_proof_id"]) != proof.id
            or str(row["role"]) != "primary"
        ):
            raise RetestPersistenceError(
                "existing retest proof conflicts with terminal truth"
            )
        return RetestProof(
            **{
                **proof.to_dict(),
                "created_at": parse_utc(str(row["created_at"])),
                "metadata": json.loads(str(row["metadata_json"])),
            }
        )

    def _persist_evidence_and_finish(
        self,
        *,
        request: RetestRequest,
        attempt: RetestAttempt,
        envelope: ActionAuthorizationEnvelope,
        durable_attempt: Mapping[str, Any],
        lease_token: str,
        output: VerifierOutput,
    ) -> RetestExecutionResult:
        worker_id = "retest-verifier"
        actor = TransitionActor(
            tenant_id=request.tenant_id,
            actor_id=worker_id,
            role="verifier",
            authorization_decision_id=envelope.decision_id,
        )
        proof_payload = output.proof_payload(request)
        work_state = (
            WorkState.FAILED.value
            if output.verdict in {RetestStatus.FAILED, RetestStatus.NOT_AUTHORIZED}
            else WorkState.COMPLETED.value
        )
        work = (
            {
                "work_key": request.verifier_id,
                "state": work_state,
                "required": True,
                "reason": output.reason_code,
            },
        )
        outcome = (
            "failure"
            if output.verdict in {RetestStatus.FAILED, RetestStatus.NOT_AUTHORIZED}
            else "success"
        )

        def reserve(session: Session, receipt_data: Mapping[str, Any]) -> None:
            self.job_state.reserve_custodied_result(
                session,
                cast(str, durable_attempt["id"]),
                lease_token,
                delivery_key=cast(str, durable_attempt["delivery_idempotency_key"]),
                tenant_id=request.tenant_id,
                receipt=ObservationReceipt(
                    tenant_id=str(receipt_data["tenant_id"]),
                    job_id=str(receipt_data["job_id"]),
                    attempt_id=str(receipt_data["attempt_id"]),
                    observation_id=str(receipt_data["observation_id"]),
                    artifact_id=str(receipt_data["artifact_id"]),
                    result_ref=str(receipt_data["result_ref"]),
                    manifest_digest=str(receipt_data["manifest_digest"]),
                ),
                outcome=outcome,
                work=work,
                worker_id=worker_id,
                actor=actor,
            )

        evidence = CanonicalEvidenceService.from_authorization(
            self.session,
            self.custody_root,
            envelope,
            attempt_id=cast(str, durable_attempt["id"]),
        )
        receipt_data = evidence.persist_job_observation(
            attempt_id=cast(str, durable_attempt["id"]),
            delivery_key=cast(str, durable_attempt["delivery_idempotency_key"]),
            payload=proof_payload,
            source_target=request.target_url,
            outcome=outcome,
            module_id=request.verifier_id,
            module_version=request.verifier_version,
            module_kind="retest_verifier",
            proof_type="passive",
            check_id=HEADER_CSP_CHECK_ID,
            route=request.route,
            parameter=request.parameter,
            location=request.location,
            identity_ref=request.identity_ref,
            capture_kind="retest_proof",
            transaction_guard=reserve,
        )
        receipt = ObservationReceipt(
            tenant_id=str(receipt_data["tenant_id"]),
            job_id=str(receipt_data["job_id"]),
            attempt_id=str(receipt_data["attempt_id"]),
            observation_id=str(receipt_data["observation_id"]),
            artifact_id=str(receipt_data["artifact_id"]),
            result_ref=str(receipt_data["result_ref"]),
            manifest_digest=str(receipt_data["manifest_digest"]),
        )
        self.job_state.record_result(
            cast(str, durable_attempt["id"]),
            lease_token,
            delivery_key=cast(str, durable_attempt["delivery_idempotency_key"]),
            tenant_id=request.tenant_id,
            receipt=receipt,
            outcome=outcome,
            work=work,
            worker_id=worker_id,
            actor=actor,
        )
        self.job_state.finish_attempt(
            cast(str, durable_attempt["id"]),
            tenant_id=request.tenant_id,
            lease_token=lease_token,
            worker_id=worker_id,
            error_reason=(output.reason_code if outcome == "failure" else None),
            terminal_reason=output.reason_code,
            actor=actor,
        )
        if self.post_job_finish_hook is not None:
            self.post_job_finish_hook()
        proof = self._record_terminal_proof(request, attempt, output, receipt)
        return RetestExecutionResult(
            state="terminal",
            verdict=output.verdict,
            reason_code=output.reason_code,
            finding_id=request.finding_id,
            retest_id=request.id,
            retest_attempt_id=attempt.id,
            job_id=request.new_job_id,
            durable_attempt_id=attempt.durable_attempt_id,
            observation_id=proof.observation_id,
            artifact_id=proof.artifact_id,
            duplicate=bool(receipt_data.get("duplicate")),
        )

    def _mark_canceled(
        self,
        request: RetestRequest,
        attempt: RetestAttempt,
        *,
        reason_code: str,
    ) -> RetestExecutionResult:
        if self.session.in_transaction():
            self.session.rollback()
        updated = False
        with self.session.begin():
            result = self.session.execute(
                text(
                    "UPDATE canonical_retest_attempts SET state='canceled',"
                    "reason_code=:reason_code,finished_at=:finished_at "
                    "WHERE tenant_id=:tenant_id AND id=:id AND state='running'"
                ),
                {
                    "reason_code": reason_code,
                    "finished_at": self.clock().isoformat(),
                    "tenant_id": request.tenant_id,
                    "id": attempt.id,
                },
            )
            updated = getattr(result, "rowcount", None) == 1
            if updated:
                self.session.execute(
                    text(
                        "INSERT INTO canonical_retest_attempt_events("
                        "tenant_id,retest_id,retest_attempt_id,from_state,to_state,"
                        "verdict,reason_code,occurred_at) VALUES("
                        ":tenant_id,:retest_id,:attempt_id,'running','canceled',NULL,"
                        ":reason_code,:occurred_at)"
                    ),
                    {
                        "tenant_id": request.tenant_id,
                        "retest_id": request.id,
                        "attempt_id": attempt.id,
                        "reason_code": reason_code,
                        "occurred_at": self.clock().isoformat(),
                    },
                )
        if not updated:
            existing = self._existing_result(
                tenant_id=request.tenant_id,
                request_id=request.id,
                finding_id=request.finding_id,
            )
            if existing is not None:
                return existing
            raise RetestPersistenceError(
                "retest cancellation lost its terminalization race"
            )
        return RetestExecutionResult(
            state="canceled",
            verdict=None,
            reason_code=reason_code,
            finding_id=request.finding_id,
            retest_id=request.id,
            retest_attempt_id=attempt.id,
            job_id=request.new_job_id,
            durable_attempt_id=attempt.durable_attempt_id,
        )

    async def execute(
        self,
        *,
        finding_id: str,
        tenant_id: str,
        authorization: ActionAuthorizationEnvelope | Mapping[str, Any] | None,
        allowed_scope: tuple[str, ...],
        excluded_scope: tuple[str, ...] = (),
        idempotency_key: str,
    ) -> RetestExecutionResult:
        """Execute one exact retest or return a safe pre-connection verdict."""

        if authorization is None:
            return RetestExecutionResult(
                state="terminal",
                verdict=RetestStatus.NOT_AUTHORIZED,
                reason_code="authorization_missing",
                finding_id=finding_id,
            )
        try:
            envelope = ActionAuthorizationEnvelope.from_value(authorization)
        except Exception:
            return RetestExecutionResult(
                state="terminal",
                verdict=RetestStatus.NOT_AUTHORIZED,
                reason_code="authorization_malformed",
                finding_id=finding_id,
            )
        if envelope.tenant_id != tenant_id:
            return RetestExecutionResult(
                state="terminal",
                verdict=RetestStatus.NOT_AUTHORIZED,
                reason_code="tenant_authorization_mismatch",
                finding_id=finding_id,
            )
        try:
            lineage = self._load_lineage(
                finding_id,
                tenant_id=tenant_id,
                actor_id=envelope.operator_id,
            )
        except (CanonicalEvidenceError, CustodyError):
            return RetestExecutionResult(
                state="terminal",
                verdict=RetestStatus.INCONCLUSIVE,
                reason_code="original_evidence_integrity_failure",
                finding_id=finding_id,
            )
        except RetestUnsupportedError:
            return RetestExecutionResult(
                state="terminal",
                verdict=RetestStatus.UNSUPPORTED,
                reason_code="verifier_unregistered_for_original_proof",
                finding_id=finding_id,
            )
        except RetestLineageError:
            return RetestExecutionResult(
                state="terminal",
                verdict=RetestStatus.INCONCLUSIVE,
                reason_code="original_lineage_incomplete",
                finding_id=finding_id,
            )
        if not self._current_authorization_valid(
            envelope,
            lineage,
            allowed_scope,
            excluded_scope,
        ):
            return RetestExecutionResult(
                state="terminal",
                verdict=RetestStatus.NOT_AUTHORIZED,
                reason_code="authorization_mismatch_or_expired",
                finding_id=finding_id,
            )
        registration = self.registry.resolve(
            module_id=lineage.module_id,
            check_id=lineage.check_id,
            source_version=lineage.module_version,
            proof_expectation=lineage.proof_expectation,
        )
        verifier_id = (
            registration.verifier_id if registration is not None else "unsupported"
        )
        verifier_version = (
            registration.verifier_version if registration is not None else "0"
        )
        proof_policy = (
            registration.proof_policy_version
            if registration is not None
            else "unsupported"
        )
        request_id = _stable_id(
            "retest-request",
            tenant_id,
            finding_id,
            idempotency_key,
        )
        try:
            prior = self._existing_result(
                tenant_id=tenant_id,
                request_id=request_id,
                finding_id=finding_id,
                authorization=envelope,
            )
        except RetestAuthorizationError:
            return RetestExecutionResult(
                state="terminal",
                verdict=RetestStatus.NOT_AUTHORIZED,
                reason_code="replay_authorization_mismatch",
                finding_id=finding_id,
            )
        if prior is not None:
            return prior
        active = self._active_request_attempt(
            tenant_id=tenant_id,
            request_id=request_id,
        )
        if active is not None:
            active_request, active_attempt = active
            if not self._replay_identity_matches(
                active_request,
                active_attempt,
                lineage=lineage,
                envelope=envelope,
                finding_id=finding_id,
                idempotency_key=idempotency_key,
                verifier_id=verifier_id,
                verifier_version=verifier_version,
                proof_policy=proof_policy,
            ):
                return RetestExecutionResult(
                    state="terminal",
                    verdict=RetestStatus.NOT_AUTHORIZED,
                    reason_code="replay_authorization_mismatch",
                    finding_id=finding_id,
                )
            return await self._wait_for_duplicate_result(
                active_request,
                active_attempt,
                authorization=envelope,
            )

        outbound_policy: Any = None
        if registration is not None:
            expected = self._current_authorization_context(
                envelope,
                lineage,
                allowed_scope,
                excluded_scope,
            )
            try:
                outbound_policy = self._build_policy(
                    envelope,
                    expected,
                    lineage.target_url,
                    allowed_scope,
                    excluded_scope,
                )
            except RetestAuthorizationError:
                return RetestExecutionResult(
                    state="terminal",
                    verdict=RetestStatus.NOT_AUTHORIZED,
                    reason_code="outbound_authorization_invalid",
                    finding_id=finding_id,
                )

        actor = TransitionActor(
            tenant_id=tenant_id,
            actor_id=envelope.operator_id,
            role=envelope.operator_role,
            authorization_decision_id=envelope.decision_id,
        )
        job = self.job_state.create_job(
            {
                "source": "canonical_retest",
                "finding_id": finding_id,
                "retest_id": request_id,
                "verifier_id": verifier_id,
            },
            tenant_id=tenant_id,
            job_id=envelope.job_id,
            engagement_id=envelope.engagement_id,
            run_id=envelope.run_id,
            job_kind="canonical_retest",
            target=lineage.target_url,
            authorization_decision_id=envelope.decision_id,
            authorization_action_id=envelope.action_id,
            authorization_bindings=(
                {
                    "authorization_decision_id": envelope.decision_id,
                    "authorization_action_id": envelope.action_id,
                    "framework": envelope.engine,
                },
            ),
            idempotency_key=f"retest-job:{request_id}",
            max_attempts=1,
            state=JobState.QUEUED,
            work_items=(verifier_id,),
            actor=actor,
            reason="authorized canonical retest queued",
        )
        del job
        role_id, scope_decision_id = self._ensure_current_context(envelope)
        durable_attempt = self.job_state.acquire_lease(
            envelope.job_id,
            "retest-verifier",
            tenant_id=tenant_id,
            lease_seconds=60.0,
            max_lease_seconds=120.0,
            idempotency_key=f"retest-attempt:{request_id}:1",
            attempt_id=_stable_id("job-attempt", tenant_id, request_id, "1"),
            attempt_authorization_decision_id=envelope.decision_id,
            actor=actor,
        )
        lease_token = str(durable_attempt.get("lease_token") or "")
        if lease_token:
            self.job_state.start_attempt(
                str(durable_attempt["id"]),
                lease_token,
                tenant_id=tenant_id,
                actor=actor,
                worker_id="retest-verifier",
            )
        content_snapshot_digest = self._content_snapshot()
        source_snapshot_id = _stable_id(
            "retest-source-snapshot",
            lineage.tenant_id,
            lineage.finding_id,
            lineage.source_observation_id,
            lineage.source_artifact_id,
            lineage.source_proof_artifact_id,
            lineage.original_action_id,
            lineage.original_authorization_decision_id,
            lineage.method,
            lineage.session_reference or "",
            lineage.session_policy_digest,
            lineage.proof_expectation,
            lineage.evidence_baseline_digest,
        )
        verifier_policy_id = _stable_id(
            "retest-verifier-policy",
            tenant_id,
            lineage.module_id,
            lineage.check_id,
            lineage.module_version,
            content_snapshot_digest,
            proof_policy,
            "passive_header_get",
            verifier_id,
            verifier_version,
            proof_policy,
        )
        candidate_request = RetestRequest(
            id=request_id,
            tenant_id=tenant_id,
            engagement_id=envelope.engagement_id,
            original_engagement_id=lineage.original_engagement_id,
            finding_id=finding_id,
            source_observation_id=lineage.source_observation_id,
            source_artifact_id=lineage.source_artifact_id,
            source_proof_artifact_id=lineage.source_proof_artifact_id,
            source_snapshot_id=source_snapshot_id,
            original_job_id=lineage.original_job_id,
            original_attempt_id=lineage.original_attempt_id,
            original_action_id=lineage.original_action_id,
            original_authorization_decision_id=(
                lineage.original_authorization_decision_id
            ),
            original_module_version_id=lineage.original_module_version_id,
            asset_id=lineage.asset_id,
            current_operator_id=envelope.operator_id,
            current_role_id=role_id,
            current_scope_decision_id=scope_decision_id,
            authorization_decision_id=envelope.decision_id,
            authorization_action_id=envelope.action_id,
            new_job_id=envelope.job_id,
            module_id=lineage.module_id,
            check_id=lineage.check_id,
            module_version=lineage.module_version,
            content_snapshot_digest=content_snapshot_digest,
            policy_snapshot=proof_policy,
            target_url=lineage.target_url,
            route=lineage.route,
            method=lineage.method,
            parameter=lineage.parameter,
            location=lineage.location,
            identity_ref=lineage.identity_ref,
            session_reference=lineage.session_reference,
            session_policy_digest=lineage.session_policy_digest,
            mutation_class="passive_header_get",
            proof_expectation=lineage.proof_expectation,
            proof_policy_version=proof_policy,
            evidence_baseline_digest=lineage.evidence_baseline_digest,
            verifier_id=verifier_id,
            verifier_version=verifier_version,
            verifier_policy_id=verifier_policy_id,
            idempotency_key=idempotency_key,
            state=RetestRequestState.AUTHORIZED,
        )
        candidate_attempt = RetestAttempt(
            id=_stable_id(
                "retest-attempt", tenant_id, request_id, durable_attempt["id"]
            ),
            tenant_id=tenant_id,
            retest_id=request_id,
            job_id=envelope.job_id,
            durable_attempt_id=str(durable_attempt["id"]),
            verifier_id=verifier_id,
            verifier_version=verifier_version,
            proof_policy_version=proof_policy,
            idempotency_key=f"retest-attempt:{request_id}:1",
            state=RetestAttemptState.PLANNED,
        )
        if active is None:
            if not lease_token:
                raise RetestPersistenceError(
                    "new durable retest lease is unavailable"
                )
            request, attempt = candidate_request, candidate_attempt
            if not self._persist_request_attempt(request, attempt):
                concurrent = self._active_request_attempt(
                    tenant_id=tenant_id,
                    request_id=request_id,
                )
                if concurrent is None:
                    raise RetestPersistenceError(
                        "concurrent retest request could not be recovered"
                    )
                concurrent_request, concurrent_attempt = concurrent
                if not self._replay_identity_matches(
                    concurrent_request,
                    concurrent_attempt,
                    lineage=lineage,
                    envelope=envelope,
                    finding_id=finding_id,
                    idempotency_key=idempotency_key,
                    verifier_id=verifier_id,
                    verifier_version=verifier_version,
                    proof_policy=proof_policy,
                ):
                    raise RetestPersistenceError(
                        "concurrent retest request identity conflicts"
                    )
                return await self._wait_for_duplicate_result(
                    concurrent_request,
                    concurrent_attempt,
                    authorization=envelope,
                )
        else:
            request, attempt = active
            if (
                request.finding_id != finding_id
                or request.new_job_id != envelope.job_id
                or request.authorization_decision_id != envelope.decision_id
                or request.authorization_action_id != envelope.action_id
                or request.idempotency_key != idempotency_key
                or request.verifier_id != verifier_id
                or request.verifier_version != verifier_version
                or request.proof_policy_version != proof_policy
                or attempt.durable_attempt_id != str(durable_attempt["id"])
            ):
                raise RetestPersistenceError(
                    "persisted retest replay identity conflicts"
                )
            recovered = self._accepted_delivery_recovery(
                request,
                attempt,
                lease_token=lease_token,
            )
            if recovered is not None:
                return recovered
            if not lease_token:
                raise RetestPersistenceError(
                    "durable retest lease could not be recovered"
                )

        if not self._claim_attempt(request, attempt):
            return await self._wait_for_duplicate_result(
                request,
                attempt,
                authorization=envelope,
            )

        if registration is None:
            output = VerifierOutput(
                verdict=RetestStatus.UNSUPPORTED,
                reason_code="verifier_unregistered_or_version_incompatible",
                observed_condition="unsupported",
                response_status=None,
                sufficient=False,
                header_value_digest=None,
            )
        else:
            try:
                with self._resolved_session(request, envelope) as (headers, cookies):
                    output = await self.header_verifier.verify(
                        VerifierInput(
                            request=request,
                            outbound_policy=outbound_policy,
                            session_headers=headers,
                            session_cookies=cookies,
                        )
                    )
            except RetestAuthorizationError:
                output = VerifierOutput(
                    verdict=RetestStatus.NOT_AUTHORIZED,
                    reason_code="protected_session_authorization_invalid",
                    observed_condition="not_authorized",
                    response_status=None,
                    sufficient=False,
                    header_value_digest=None,
                )
            except RetestCanceled:
                self.job_state.cancel_job(
                    envelope.job_id,
                    tenant_id=tenant_id,
                    actor=actor,
                    reason="retest verifier canceled",
                    sla_seconds=0,
                )
                return self._mark_canceled(
                    request,
                    attempt,
                    reason_code="retest_canceled",
                )
            except Exception:
                output = VerifierOutput(
                    verdict=RetestStatus.FAILED,
                    reason_code="verifier_execution_failed",
                    observed_condition="execution_failed",
                    response_status=None,
                    sufficient=False,
                    header_value_digest=None,
                )
            if (
                output.verdict is RetestStatus.NOT_APPLICABLE
                and not registration.allows_not_applicable
            ):
                output = VerifierOutput(
                    verdict=RetestStatus.FAILED,
                    reason_code="not_applicable_policy_unauthorized",
                    observed_condition="verifier_policy_violation",
                    response_status=output.response_status,
                    sufficient=False,
                    header_value_digest=output.header_value_digest,
                )
        return self._persist_evidence_and_finish(
            request=request,
            attempt=attempt,
            envelope=envelope,
            durable_attempt=durable_attempt,
            lease_token=lease_token,
            output=output,
        )


__all__ = [
    "DEFAULT_RETEST_REGISTRY",
    "HEADER_CSP_CHECK_ID",
    "HEADER_CSP_PROOF_POLICY",
    "HEADER_CSP_VERIFIER_ID",
    "HEADER_CSP_VERIFIER_VERSION",
    "HeaderAuditCspVerifier",
    "HeaderResponse",
    "OriginalRetestLineage",
    "RETEST_CONTRACT_VERSION",
    "RetestAuthorizationError",
    "RetestCanceled",
    "RetestError",
    "RetestExecutionResult",
    "RetestLineageError",
    "RetestPersistenceError",
    "RetestService",
    "RetestUnsupportedError",
    "RetestVerifierRegistry",
    "RetestVerifier",
    "SessionReferenceResolver",
    "VerifierInput",
    "VerifierOutput",
    "VerifierRegistration",
    "classify_csp",
]
