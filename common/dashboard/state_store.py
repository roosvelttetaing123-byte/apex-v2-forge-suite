"""Rebuildable in-memory projection for the War Room dashboard.

Canonical jobs/findings/evidence remain the source of truth.
It subscribes to EventBus events, aggregates them into structured state,
and provides thread-safe snapshots for the TUI and web dashboard.

Persists snapshots to SQLite every 5 seconds for crash recovery,
and can restore state from DB when attaching to a running session.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from common.dashboard.event_bus import Event, EventBus, EventType
from common.dashboard.kill_chain import KillChainState
from common.dashboard.metrics import MetricsCollector, MetricsSnapshot
from common.brain.truth_boundary import canonical_target

log = logging.getLogger("forge.dashboard.state")

_STATE_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")


def _validated_state_tenant_id(value: str) -> str:
    """Return the canonical tenant used by persistent dashboard state."""
    if not isinstance(value, str):
        raise ValueError("invalid dashboard state tenant identifier")
    tenant_id = value.strip()
    if not _STATE_TENANT_ID_RE.fullmatch(tenant_id):
        raise ValueError("invalid dashboard state tenant identifier")
    return tenant_id


def _sqlite_state_record_id(tenant_id: str, run_id: str) -> str:
    """Bind the exact tenant/run tuple without delimiter ambiguity."""
    binding = json.dumps(
        [tenant_id, run_id],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"forge-dashboard-state:v2:{binding}",
        )
    )


class StateBackend:
    """Persistence adapter for dashboard snapshots."""

    name = "memory"

    def save(self, run_id: str, snapshot: dict[str, Any]) -> None:
        return None

    def load(self, run_id: str) -> dict[str, Any] | None:
        return None


class SQLiteStateBackend(StateBackend):
    """SQLite-backed StateStore persistence adapter."""

    name = "sqlite"

    def __init__(self, db_session: Any, tenant_id: str = "default") -> None:
        self.db_session = db_session
        self.tenant_id = tenant_id

    def save(self, run_id: str, snapshot: dict[str, Any]) -> None:
        from common.db import DashboardStateModel

        model = DashboardStateModel(
            id=_sqlite_state_record_id(self.tenant_id, run_id),
            tenant_id=self.tenant_id,
            run_id=run_id,
            state_json=json.dumps(snapshot, default=str),
            updated_at=datetime.now(timezone.utc),
        )
        self.db_session.merge(model)
        self.db_session.commit()

    def load(self, run_id: str) -> dict[str, Any] | None:
        from common.db import DashboardStateModel

        model = (
            self.db_session.query(DashboardStateModel)
            .filter_by(tenant_id=self.tenant_id, run_id=run_id)
            .order_by(DashboardStateModel.updated_at.desc())
            .first()
        )
        if not model:
            return None
        return json.loads(model.state_json)


class RedisStateBackend(StateBackend):
    """Redis-backed StateStore adapter used when redis-py is available."""

    name = "redis"

    def __init__(
        self,
        redis_url: str,
        key_prefix: str = "forge:dashboard:state",
        *,
        tenant_id: str = "default",
    ) -> None:
        self.tenant_id = _validated_state_tenant_id(tenant_id)
        self._tenant_digest = hashlib.sha256(self.tenant_id.encode("utf-8")).hexdigest()
        import redis

        self.client = redis.from_url(redis_url)
        self.key_prefix = key_prefix.rstrip(":")

    def _key(self, run_id: str) -> str:
        if not isinstance(run_id, str):
            raise ValueError("invalid dashboard state run identifier")
        run_digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
        return (
            f"{self.key_prefix}:tenant-sha256:{self._tenant_digest}"
            f":run-sha256:{run_digest}"
        )

    def save(self, run_id: str, snapshot: dict[str, Any]) -> None:
        self.client.set(self._key(run_id), json.dumps(snapshot, default=str))

    def load(self, run_id: str) -> dict[str, Any] | None:
        raw = self.client.get(self._key(run_id))
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return json.loads(raw)


def make_state_backend(
    kind: str = "memory",
    *,
    db_session: Any = None,
    redis_url: str = "",
    tenant_id: str = "default",
) -> StateBackend:
    """Create a dashboard state backend from configuration."""
    normalized = (kind or "memory").strip().lower()
    if normalized == "sqlite":
        if db_session is None:
            raise ValueError("SQLite state backend requires db_session")
        return SQLiteStateBackend(db_session, tenant_id=tenant_id)
    if normalized == "redis":
        if not redis_url:
            raise ValueError("Redis state backend requires redis_url")
        return RedisStateBackend(redis_url, tenant_id=tenant_id)
    return StateBackend()


@dataclass
class FindingEntry:
    """A finding as displayed in the dashboard feed."""
    id:          str
    title:       str
    severity:    str
    module:      str
    target:      str
    cvss_score:  float | None = None
    timestamp:   str = ""
    url:         str = ""
    port:        int | None = None
    service:     str = ""
    description: str = ""
    mitre:       list[str] = field(default_factory=list)
    evidence:    dict[str, Any] = field(default_factory=dict)
    confidence:  str = "UNVERIFIED"
    status:      str = "open"
    vpr_score:   float | None = None
    vpr_priority: str = ""
    verification: dict[str, Any] = field(default_factory=dict)
    verification_state: str = "unknown"
    proof_type: str = "unknown"
    maturity: str = "experimental"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "module": self.module, "target": self.target,
            "cvss_score": self.cvss_score, "timestamp": self.timestamp,
            "url": self.url, "port": self.port, "service": self.service,
            "description": self.description, "mitre": self.mitre,
            "evidence": self.evidence, "confidence": self.confidence,
            "status": self.status, "vpr_score": self.vpr_score,
            "vpr_priority": self.vpr_priority, "verification": self.verification,
            "verification_state": self.verification_state,
            "proof_type": self.proof_type, "maturity": self.maturity,
        }


@dataclass
class BrainVerdictEntry:
    """ForgeBrain analysis verdict for a finding."""
    finding_id: str
    finding: str = ""
    verdict: str = "LIKELY"
    confidence: str = "UNVERIFIED"
    reasoning: str = ""
    severity_adjustment: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding": self.finding,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "severity_adjustment": self.severity_adjustment,
            "timestamp": self.timestamp,
        }


@dataclass
class ChainActionEntry:
    """Cross-framework chain action emitted by EngagementBus or planner."""
    chain_type: str = ""
    source_finding: str = ""
    source_framework: str = ""
    target_framework: str = ""
    target_module: str = ""
    target: str = ""
    rationale: str = ""
    auto_execute: bool = False
    execution_state: str = "advisory"
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_type": self.chain_type,
            "source_finding": self.source_finding,
            "source_framework": self.source_framework,
            "target_framework": self.target_framework,
            "target_module": self.target_module,
            "target": self.target,
            "rationale": self.rationale,
            "auto_execute": self.auto_execute,
            "execution_state": self.execution_state,
            "timestamp": self.timestamp,
        }


@dataclass
class ModuleStatus:
    """Status of a single module in the assessment."""
    name:          str
    status:        str = "queued"      # queued, running, complete, failed, skipped
    progress_pct:  float = 0.0
    start_time:    float = 0.0
    end_time:      float = 0.0
    duration:      float = 0.0
    findings_count: int = 0
    error:         str = ""
    phase:         int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "status": self.status,
            "progress_pct": round(self.progress_pct, 1),
            "duration": round(self.duration, 1),
            "findings_count": self.findings_count, "error": self.error,
            "phase": self.phase,
        }


@dataclass
class PhaseStatus:
    """Status of an assessment phase."""
    number:   int
    name:     str
    status:   str = "queued"
    modules:  list[str] = field(default_factory=list)
    findings: int = 0
    duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "number": self.number, "name": self.name,
            "status": self.status, "modules": self.modules,
            "findings": self.findings, "duration": round(self.duration, 1),
        }


@dataclass
class TargetStatus:
    """Compromise status of a target."""
    target:       str
    pwned:        bool = False
    shell:        bool = False
    access_level: str = ""
    creds_count:  int = 0
    services:     list[str] = field(default_factory=list)
    findings:     int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target, "pwned": self.pwned,
            "shell": self.shell, "access_level": self.access_level,
            "creds_count": self.creds_count, "services": self.services,
            "findings": self.findings,
        }


@dataclass
class CredentialEntry:
    """A protected credential reference or explicit purge marker."""
    id:            str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    cred_type:     str = ""    # PLAINTEXT, NTLM_HASH, KERB_TICKET, API_KEY, SSH_KEY, JWT
    account:       str = ""
    credential_reference: str = ""
    credential_state: str = "purged_legacy"
    secret: str = field(default="", repr=False, compare=False)
    target:        str = ""
    discovered_by: str = ""
    timestamp:     str = ""

    def __post_init__(self) -> None:
        # Compatibility callers may still pass ``secret``; discard it before
        # the value can enter state, snapshots, UI, reports, or exports.
        self.secret = ""

    def to_dict(self, mask: bool = True) -> dict[str, Any]:
        del mask
        return {
            "id": self.id, "cred_type": self.cred_type,
            "account": self.account,
            "credential_reference": self.credential_reference,
            "credential_state": self.credential_state,
            "target": self.target, "discovered_by": self.discovered_by,
            "timestamp": self.timestamp,
        }


@dataclass
class ShellSession:
    """An active shell session."""
    session_id:   int = 0
    target:       str = ""
    shell_type:   str = ""   # CMD, BASH, PowerShell
    access_level: str = ""   # user, admin, SYSTEM, DA, root
    established:  str = ""
    module:       str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id, "target": self.target,
            "shell_type": self.shell_type, "access_level": self.access_level,
            "established": self.established, "module": self.module,
        }


class StateStore:
    """Thread-safe in-memory state store for dashboard rendering.

    Subscribes to EventBus events, maintains aggregated state,
    and provides snapshots for dashboard panels.

    Args:
        event_bus:     EventBus to subscribe to.
        framework:     Which framework is running (webforge/netforge/adforge/aiforge).
        run_id:        Scan run UUID.
        target:        Primary assessment target.
        persist_db:    Optional SQLAlchemy session for crash recovery.
    """

    def __init__(
        self,
        event_bus: EventBus,
        framework: str = "forge",
        run_id: str = "",
        target: str = "",
        persist_db: Any = None,
        backend: StateBackend | None = None,
        backend_kind: str = "",
        redis_url: str = "",
        tenant_id: str = "default",
        engagement_id: str = "",
        strict_event_scope: bool | None = None,
        canonical_truth_resolver: (
            Callable[[Mapping[str, Any]], Mapping[str, Any] | None] | None
        ) = None,
    ) -> None:
        self._bus = event_bus
        self.framework = framework
        self.run_id = run_id
        self.target = target
        self._db = persist_db
        self.tenant_id = _validated_state_tenant_id(tenant_id)
        self.engagement_id = engagement_id.strip() if isinstance(engagement_id, str) else ""
        self._strict_event_scope = (
            self.tenant_id != "default"
            if strict_event_scope is None
            else bool(strict_event_scope)
        )
        self._canonical_truth_resolver = canonical_truth_resolver
        if backend is not None:
            self._backend = backend
        elif backend_kind:
            self._backend = make_state_backend(
                backend_kind,
                db_session=persist_db,
                redis_url=redis_url,
                tenant_id=self.tenant_id,
            )
        elif persist_db:
            self._backend = SQLiteStateBackend(persist_db, tenant_id=self.tenant_id)
        else:
            self._backend = StateBackend()
        self._lock = threading.RLock()
        self._closed = False
        self._subscriptions: list[
            tuple[EventType, Callable[[Event], None]]
        ] = []

        # ── State containers ──
        self.findings:    list[FindingEntry] = []
        self.modules:     dict[str, ModuleStatus] = {}
        self.phases:      dict[int, PhaseStatus] = {}
        self.targets:     dict[str, TargetStatus] = {}
        self.credentials: list[CredentialEntry] = []
        self.sessions:    list[ShellSession] = []
        self.brain_verdicts: list[BrainVerdictEntry] = []
        self.chain_actions: list[ChainActionEntry] = []
        self.kill_chain   = KillChainState()
        self.metrics      = MetricsCollector()
        self.timeline:    list[dict[str, Any]] = []

        # Scan metadata
        self.scan_status: str = "initializing"
        self.scan_start:  float = 0.0
        self.scan_mode:   str = ""
        self.engagement:  str = self.engagement_id
        self.tester:      str = ""

        # Subscribe to all events
        self._subscribe()

        # Start persistence timer
        self._persist_timer: threading.Timer | None = None
        if self._backend.name != "memory":
            self._schedule_persist()

    def set_canonical_truth_resolver(
        self,
        resolver: Callable[[Mapping[str, Any]], Mapping[str, Any] | None],
    ) -> None:
        self._canonical_truth_resolver = resolver

    def enforce_strict_event_scope(self) -> None:
        """Require exact tenant/engagement/run context for future events."""
        with self._lock:
            self._strict_event_scope = True

    def _canonical_truth(
        self, value: Mapping[str, Any]
    ) -> Mapping[str, Any] | None:
        if self._canonical_truth_resolver is None:
            return None
        try:
            truth = self._canonical_truth_resolver(value)
        except Exception:
            return None
        return truth if isinstance(truth, Mapping) else None

    @staticmethod
    def _canonical_success(value: Mapping[str, Any]) -> bool:
        """Return whether persisted job/evidence truth authorizes completion."""
        truth = value
        evidence_refs = truth.get("evidence_refs") or ()
        lineage = truth.get("canonical_lineage") or ()
        signed_ref = str(truth.get("signed_outcome_ref") or "")
        return (
            bool(truth.get("canonical_action_id"))
            and bool(truth.get("canonical_job_id"))
            and bool(truth.get("canonical_attempt_id"))
            and str(truth.get("canonical_outcome") or "").lower() == "success"
            and signed_ref.startswith("run-truth:")
            and isinstance(evidence_refs, (list, tuple))
            and bool(evidence_refs)
            and all(
                isinstance(ref, str)
                and ref.startswith(("artifact:", "sha256:"))
                for ref in evidence_refs
            )
            and isinstance(lineage, (list, tuple))
            and bool(lineage)
            and all(isinstance(item, Mapping) for item in lineage)
        )

    def _canonical_truth_matches_event(
        self,
        value: Mapping[str, Any],
        truth: Mapping[str, Any] | None,
        *,
        module_id: str,
        target: str,
        observation_id: str = "",
        finding_id: str = "",
    ) -> bool:
        """Bind a successful projection to the event's full canonical identity."""

        if truth is None or not self._canonical_success(truth):
            return False

        def exact_aliases(
            names: tuple[str, ...], expected: str, *, required: bool
        ) -> bool:
            present = [value.get(name) for name in names if name in value]
            if any(not str(item or "").strip() for item in present):
                return False
            supplied = {str(item).strip() for item in present}
            if required and not supplied:
                return False
            return not supplied or supplied == {expected}

        identity_groups = (
            (("tenant_id",), str(truth.get("tenant_id") or ""), True),
            (("engagement_id",), str(truth.get("engagement_id") or ""), True),
            (("run_id",), str(truth.get("run_id") or ""), True),
            (
                ("canonical_plan_id", "plan_id"),
                str(truth.get("canonical_plan_id") or ""),
                bool(truth.get("canonical_plan_id")),
            ),
            (
                ("canonical_node_id", "node_id"),
                str(truth.get("canonical_node_id") or ""),
                bool(truth.get("canonical_node_id")),
            ),
            (
                ("canonical_action_id", "action_id"),
                str(truth.get("canonical_action_id") or ""),
                True,
            ),
            (
                ("canonical_job_id", "job_id"),
                str(truth.get("canonical_job_id") or ""),
                True,
            ),
            (
                ("canonical_attempt_id", "attempt_id"),
                str(truth.get("canonical_attempt_id") or ""),
                True,
            ),
        )
        if any(
            not expected or not exact_aliases(names, expected, required=required)
            for names, expected, required in identity_groups
        ):
            return False

        expected_capability = str(truth.get("canonical_capability_id") or "")
        expected_version = str(truth.get("canonical_capability_version") or "")
        expected_module = str(truth.get("canonical_module_id") or "")
        expected_runtime_version = str(
            truth.get("canonical_runtime_module_version") or ""
        )
        if (
            not module_id
            or module_id != expected_module
            or not exact_aliases(
                ("canonical_module_id", "module_id", "module"),
                expected_module,
                required=False,
            )
            or not exact_aliases(
                ("canonical_capability_id", "capability_id"),
                expected_capability,
                required=True,
            )
            or not exact_aliases(
                (
                    "canonical_capability_version",
                    "capability_version",
                    "canonical_module_version",
                    "module_version",
                ),
                expected_version,
                required=True,
            )
            or not exact_aliases(
                ("canonical_runtime_module_version", "runtime_module_version"),
                expected_runtime_version,
                required=True,
            )
        ):
            return False

        supplied_target = str(value.get("target") or "").strip()
        expected_target = str(truth.get("canonical_target") or "")
        if not supplied_target or supplied_target != str(target or "").strip():
            return False
        try:
            event_target = canonical_target(supplied_target)
        except (TypeError, ValueError):
            return False
        if not expected_target or event_target != expected_target:
            return False
        if not exact_aliases(
            ("canonical_target", "target_digest"), expected_target, required=False
        ):
            return False

        if not exact_aliases(
            ("canonical_outcome", "outcome"), "success", required=False
        ):
            return False
        signed_ref = str(truth.get("signed_outcome_ref") or "")
        if not exact_aliases(("signed_outcome_ref",), signed_ref, required=False):
            return False
        supplied_refs = value.get("evidence_refs")
        if supplied_refs is not None:
            if not isinstance(supplied_refs, (list, tuple)):
                return False
            if tuple(sorted(str(ref) for ref in supplied_refs)) != tuple(
                sorted(str(ref) for ref in truth.get("evidence_refs") or ())
            ):
                return False

        if observation_id and not exact_aliases(
            ("canonical_observation_id", "observation_id"),
            observation_id,
            required=True,
        ):
            return False
        if finding_id and not exact_aliases(
            ("canonical_finding_id", "finding_id", "id"),
            finding_id,
            required=True,
        ):
            return False

        expected_action = str(truth.get("canonical_action_id") or "")
        expected_job = str(truth.get("canonical_job_id") or "")
        expected_attempt = str(truth.get("canonical_attempt_id") or "")
        expected_plan = str(truth.get("canonical_plan_id") or "")
        expected_node = str(truth.get("canonical_node_id") or "")
        for raw in truth.get("canonical_lineage") or ():
            binding = dict(raw)
            if (
                str(binding.get("plan_id") or "") != expected_plan
                or str(binding.get("node_id") or "") != expected_node
                or str(binding.get("action_id") or "") != expected_action
                or str(binding.get("job_id") or "") != expected_job
                or str(binding.get("attempt_id") or "") != expected_attempt
                or str(binding.get("capability_id") or "") != expected_capability
                or str(binding.get("capability_version") or "") != expected_version
                or str(binding.get("module_id") or "") != expected_module
                or str(binding.get("target_digest") or "") != expected_target
                or (observation_id and str(binding.get("observation_id") or "") != observation_id)
                or (finding_id and str(binding.get("finding_id") or "") != finding_id)
                or str(binding.get("evidence_ref") or "")
                not in {str(ref) for ref in truth.get("evidence_refs") or ()}
            ):
                continue
            return True
        return False

    def _event_scope_allowed(self, event: Event) -> bool:
        """Check event identity before projecting it into dashboard state.

        DashboardServer enables strict scope even for its historical default
        tenant. Direct in-process fixtures may retain legacy omitted-context
        behavior only when strict scope is not requested and no engagement is
        active. Tenant-bound stores and every active engagement require exact
        event data bindings.
        """
        data = event.data
        event_tenant = data.get("tenant_id")
        strict_scope = self._strict_event_scope
        if strict_scope:
            if event_tenant != self.tenant_id:
                return False
        elif event_tenant is not None and event_tenant != self.tenant_id:
            return False

        expected_engagement = self.engagement_id or self.engagement
        event_engagement = data.get("engagement_id")
        if strict_scope and not expected_engagement:
            # A scoped tenant cannot accept an orphan projection. The only
            # event allowed to establish the first engagement is a fully
            # bound scan start; every other event must wait for that context.
            if event.event_type is not EventType.SCAN_START:
                return False
            if not isinstance(event_engagement, str) or not event_engagement.strip():
                return False
        if expected_engagement and event_engagement != expected_engagement:
            return False

        # EventBus stamps the top-level run_id; remote/canonical adapters may
        # also retain it in data. Require it whenever a tenant or engagement
        # binding makes this a production-scoped projection. Default-only
        # fixtures with no active engagement retain their legacy behavior.
        expected_run = self.run_id
        strict_run = strict_scope or bool(expected_engagement)
        if strict_run and expected_run:
            # Reject disagreement between the Event envelope and any copied
            # run binding in data; preferring one would permit cross-run data
            # to ride on an otherwise valid envelope.
            if event.run_id and event.run_id != expected_run:
                return False
            if data.get("run_id") is not None and data.get("run_id") != expected_run:
                return False
            if not event.run_id and data.get("run_id") is None:
                return False
        if strict_run and expected_engagement and not isinstance(event_engagement, str):
            return False
        return True

    def _subscribe(self) -> None:
        """Register handlers for all event types."""
        def guarded(handler: Callable[[Event], None]) -> Callable[[Event], None]:
            def receive(event: Event) -> None:
                # Hold the re-entrant state lock across admission and handler
                # execution so stop() fences an already-dispatched callback.
                with self._lock:
                    if self._closed or not self._event_scope_allowed(event):
                        return
                    handler(event)

            return receive

        def subscribe(
            event_type: EventType,
            handler: Callable[[Event], None],
        ) -> None:
            callback = guarded(handler)
            self._bus.subscribe(event_type, callback)
            self._subscriptions.append((event_type, callback))

        subscribe(EventType.SCAN_START, self._on_scan_start)
        subscribe(EventType.SCAN_COMPLETE, self._on_scan_complete)
        subscribe(EventType.SCAN_INTERRUPTED, self._on_scan_interrupted)
        subscribe(EventType.SCAN_ABORTED, self._on_scan_aborted)
        subscribe(EventType.PHASE_START, self._on_phase_start)
        subscribe(EventType.PHASE_COMPLETE, self._on_phase_complete)
        subscribe(EventType.MODULE_START, self._on_module_start)
        subscribe(EventType.MODULE_PROGRESS, self._on_module_progress)
        subscribe(EventType.MODULE_COMPLETE, self._on_module_complete)
        subscribe(EventType.MODULE_FAIL, self._on_module_fail)
        subscribe(EventType.MODULE_SKIP, self._on_module_skip)
        subscribe(EventType.FINDING_NEW, self._on_finding)
        subscribe(EventType.REQUEST_SENT, self._on_request)
        subscribe(EventType.REQUEST_ERROR, self._on_request_error)
        subscribe(EventType.WAF_BLOCK, self._on_waf_block)
        subscribe(EventType.RATE_LIMIT_HIT, self._on_rate_limit)
        subscribe(EventType.CREDENTIAL_FOUND, self._on_credential)
        subscribe(EventType.TARGET_DISCOVERED, self._on_target_discovered)
        subscribe(EventType.TARGET_PWNED, self._on_target_pwned)
        subscribe(EventType.SHELL_SESSION, self._on_shell_session)
        subscribe(EventType.BRAIN_VERDICT, self._on_brain_verdict)
        subscribe(EventType.CHAIN_ACTION_NEW, self._on_chain_action)

    # ── Event handlers ────────────────────────────────────────────────

    def _on_scan_start(self, event: Event) -> None:
        with self._lock:
            # Reset all live state so each scan starts with a clean dashboard.
            # Previous scan findings are only available via the HTML/SQLite reports.
            self.findings.clear()
            self.modules.clear()
            self.phases.clear()
            self.timeline.clear()
            self.credentials.clear()
            self.sessions.clear()
            self.brain_verdicts.clear()
            self.chain_actions.clear()
            self.kill_chain = KillChainState()
            self.metrics = MetricsCollector()

            self.scan_status = "advisory"
            self.scan_start = time.monotonic()
            self.scan_mode = event.data.get("mode", "")
            self.engagement = event.data.get(
                "engagement_id", event.data.get("engagement", self.engagement)
            )
            if not self.engagement_id and isinstance(self.engagement, str):
                self.engagement_id = self.engagement.strip()
            self.tester = event.data.get("tester", "")
            self.run_id = event.data.get("run_id", self.run_id)
            self.target = event.data.get("target", self.target)
            module_names = event.data.get("modules", [])
            if module_names:
                self.kill_chain.set_module_totals(module_names)
                self.metrics.set_total_modules(len(module_names))
            self._add_timeline(
                "scan_start_advisory",
                "Assessment start notification received",
                event.source,
            )

    def _on_scan_complete(self, event: Event) -> None:
        with self._lock:
            truth = self._canonical_truth(event.data)
            valid_truth = self._canonical_truth_matches_event(
                event.data,
                truth,
                module_id=str(
                    event.data.get("canonical_module_id")
                    or event.data.get("module_id")
                    or event.data.get("module")
                ),
                target=str(event.data.get("target") or ""),
            )
            all_modules_complete = bool(self.modules) and all(
                module.status == "complete" for module in self.modules.values()
            )
            if valid_truth and all_modules_complete:
                if self.scan_status == "completed":
                    return
                self.scan_status = "completed"
                self._add_timeline("scan_complete", "Assessment completed", event.source)
            elif self.scan_status != "completed":
                self.scan_status = "inconclusive"
                self._add_timeline(
                    "scan_complete_advisory",
                    "Assessment completion is advisory pending canonical evidence",
                    event.source,
                )

    def _on_scan_interrupted(self, event: Event) -> None:
        with self._lock:
            self.scan_status = "interrupted"
            self._add_timeline("scan_interrupted", "Assessment interrupted", event.source)

    def _on_scan_aborted(self, event: Event) -> None:
        with self._lock:
            durable_status = str(event.data.get("status") or "").strip().lower()
            projected_status = (
                "canceled" if durable_status == "canceled" else "aborted"
            )
            if self.scan_status == projected_status:
                return
            self.scan_status = projected_status
            self._add_timeline(
                "scan_aborted",
                "Assessment canceled"
                if self.scan_status == "canceled"
                else "Assessment aborted",
                event.source,
            )

    def _on_phase_start(self, event: Event) -> None:
        with self._lock:
            num = event.data.get("number", 0)
            name = event.data.get("name", f"Phase {num}")
            modules = event.data.get("modules", [])
            self.phases[num] = PhaseStatus(
                number=num, name=name, status="advisory", modules=modules,
            )
            self._add_timeline(
                "phase_start_advisory",
                f"Phase {num} notification: {name}",
                event.source,
            )

    def _on_phase_complete(self, event: Event) -> None:
        with self._lock:
            num = event.data.get("number", 0)
            if num in self.phases:
                truth = self._canonical_truth(event.data)
                valid_truth = self._canonical_truth_matches_event(
                    event.data,
                    truth,
                    module_id=str(
                        event.data.get("canonical_module_id")
                        or event.data.get("module_id")
                        or event.data.get("module")
                    ),
                    target=str(event.data.get("target") or ""),
                )
                phase_modules = tuple(self.phases[num].modules)
                phase_complete = bool(phase_modules) and all(
                    module_id in self.modules
                    and self.modules[module_id].status == "complete"
                    for module_id in phase_modules
                )
                if valid_truth and phase_complete:
                    if self.phases[num].status == "complete":
                        return
                    self.phases[num].status = "complete"
                elif self.phases[num].status != "complete":
                    self.phases[num].status = "advisory"
                self.phases[num].duration = event.data.get("duration", 0.0)

    def _on_module_start(self, event: Event) -> None:
        name = event.data.get("name", event.source)
        with self._lock:
            self.modules[name] = ModuleStatus(
                name=name, status="advisory",
                start_time=time.monotonic(),
                phase=event.data.get("phase", 0),
            )

    def _on_module_progress(self, event: Event) -> None:
        name = event.data.get("name", event.source)
        with self._lock:
            if name in self.modules:
                self.modules[name].progress_pct = min(
                    float(event.data.get("progress", 0.0)), 99.0
                )

    def _on_module_complete(self, event: Event) -> None:
        name = event.data.get("name", event.source)
        with self._lock:
            if name in self.modules:
                mod = self.modules[name]
                truth = self._canonical_truth(event.data)
                evidence_refs = (truth or {}).get("evidence_refs") or ()
                if not isinstance(evidence_refs, (list, tuple)):
                    evidence_refs = ()
                valid_truth = self._canonical_truth_matches_event(
                    event.data,
                    truth,
                    module_id=str(name),
                    target=str(event.data.get("target") or ""),
                )
                if not valid_truth and mod.status == "complete":
                    return
                counted = (
                    self.kill_chain.record_module_complete(
                        name,
                        canonical_job_id=str(
                            (truth or {}).get("canonical_job_id") or ""
                        ),
                        outcome=str((truth or {}).get("canonical_outcome") or ""),
                        evidence_refs=tuple(str(ref) for ref in evidence_refs),
                    )
                    if valid_truth
                    else False
                )
                if valid_truth and not counted and mod.status == "complete":
                    return
                mod.status = "complete" if valid_truth else "advisory"
                mod.progress_pct = (
                    100.0 if valid_truth else min(mod.progress_pct, 99.0)
                )
                mod.end_time = time.monotonic()
                mod.duration = mod.end_time - mod.start_time
                if counted:
                    mod.findings_count = len(
                        {
                            str(item.get("finding_id") or "")
                            for item in (truth or {}).get("canonical_lineage") or ()
                            if isinstance(item, Mapping)
                            and str(item.get("finding_id") or "")
                        }
                    )
                    self.metrics.record_module_complete(mod.duration)

    def _on_module_fail(self, event: Event) -> None:
        name = event.data.get("name", event.source)
        with self._lock:
            if name in self.modules:
                if self.modules[name].status == "complete":
                    return
                self.modules[name].status = "advisory"
                self.modules[name].error = (
                    "failure notification pending canonical job state"
                )
            else:
                self.modules[name] = ModuleStatus(
                    name=name,
                    status="advisory",
                    error="failure notification pending canonical job state",
                )

    def _on_module_skip(self, event: Event) -> None:
        name = event.data.get("name", event.source)
        with self._lock:
            if name in self.modules and self.modules[name].status == "complete":
                return
            self.modules[name] = ModuleStatus(
                name=name,
                status="advisory",
                error="skip notification pending canonical job state",
            )

    def _on_finding(self, event: Event) -> None:
        from common.confidence_policy import normalise_finding

        binding_fields = {
            key: event.data[key]
            for key in (
                "tenant_id",
                "engagement_id",
                "run_id",
                "canonical_plan_id",
                "canonical_node_id",
                "canonical_action_id",
                "canonical_job_id",
                "canonical_attempt_id",
                "canonical_capability_id",
                "canonical_capability_version",
                "canonical_module_id",
                "canonical_module_version",
                "canonical_runtime_module_version",
                "canonical_target",
                "canonical_observation_id",
                "canonical_finding_id",
                "action_id",
                "job_id",
                "attempt_id",
                "plan_id",
                "node_id",
                "capability_id",
                "capability_version",
                "module_id",
                "module_version",
                "runtime_module_version",
                "target_digest",
                "observation_id",
                "finding_id",
                "canonical_outcome",
                "outcome",
                "signed_outcome_ref",
                "evidence_refs",
            )
            if key in event.data
        }
        d = normalise_finding(dict(event.data))
        d.update(binding_fields)
        with self._lock:
            truth = self._canonical_truth(d)
            mod_name = str(d.get("module") or "")
            observation_id = str(d.get("observation_id") or "")
            finding_id = str(d.get("finding_id") or d.get("id") or "")
            if not (
                bool(observation_id)
                and bool(finding_id)
                and self._canonical_truth_matches_event(
                    d,
                    truth,
                    module_id=str(mod_name),
                    target=str(d.get("target") or ""),
                    observation_id=observation_id,
                    finding_id=finding_id,
                )
            ):
                return
            finding_bindings = [
                dict(item)
                for item in (truth or {}).get("canonical_lineage") or ()
                if isinstance(item, Mapping)
                and str(item.get("observation_id") or "") == observation_id
                and str(item.get("finding_id") or "") == finding_id
                and str(item.get("verification_state") or "")
                in {"candidate", "verified"}
            ]
            if not finding_bindings:
                return
            binding = finding_bindings[0]
            immutable_fields = (
                "finding_title",
                "finding_severity",
                "finding_description",
                "finding_created_at",
                "finding_status",
                "verification_state",
                "proof_type",
                "confidence",
                "maturity",
            )
            if any(
                str(item.get(field) or "") != str(binding.get(field) or "")
                for item in finding_bindings
                for field in immutable_fields
            ):
                return
            finding_evidence_refs = tuple(
                sorted(
                    {
                        str(item.get("evidence_ref") or "")
                        for item in finding_bindings
                        if str(item.get("evidence_ref") or "")
                    }
                )
            )
            if not finding_evidence_refs:
                return
            severity_value = str(binding.get("finding_severity") or "").lower()
            severity = (
                severity_value.capitalize()
                if severity_value
                in {"critical", "high", "medium", "low", "informational"}
                else "Informational"
            )
            target_display = str((truth or {}).get("canonical_target_display") or "")
            if not target_display:
                return
            entry = FindingEntry(
                id=finding_id,
                title=str(binding.get("finding_title") or "Canonical finding"),
                severity=severity,
                module=str((truth or {}).get("canonical_module_id") or ""),
                target=target_display,
                cvss_score=None,
                timestamp=str(binding.get("finding_created_at") or event.timestamp),
                url="",
                port=None,
                service="",
                description=str(binding.get("finding_description") or ""),
                mitre=[],
                evidence={
                    "state": "persisted",
                    "artifact_refs": list(finding_evidence_refs),
                },
                confidence=str(binding.get("confidence") or "UNVERIFIED"),
                status=str(binding.get("finding_status") or "open"),
                vpr_score=None,
                vpr_priority="",
                verification={
                    "source": "canonical_run_truth",
                    "signed_outcome_ref": str(
                        (truth or {}).get("signed_outcome_ref") or ""
                    ),
                },
                verification_state=str(
                    binding.get("verification_state") or "candidate"
                ),
                proof_type=str(binding.get("proof_type") or "passive"),
                maturity=str(binding.get("maturity") or "stable"),
            )
            event.data.clear()
            event.data.update(
                {
                    **binding_fields,
                    "id": entry.id,
                    "finding_id": entry.id,
                    "title": entry.title,
                    "severity": entry.severity,
                    "module": entry.module,
                    "target": entry.target,
                    "status": entry.status,
                    "verification_state": entry.verification_state,
                    "proof_type": entry.proof_type,
                    "maturity": entry.maturity,
                    "evidence_refs": finding_evidence_refs,
                }
            )
            if any(existing.id == entry.id for existing in self.findings):
                return
            self.findings.append(entry)
            counted = self.kill_chain.record_finding(
                mod_name,
                verification_state=entry.verification_state,
                observation_id=str(d.get("observation_id") or ""),
                evidence_refs=finding_evidence_refs,
            )
            # Update module finding count
            if counted and mod_name in self.modules:
                self.modules[mod_name].findings_count += 1
            # Update phase finding count
            if counted:
                for phase in self.phases.values():
                    if mod_name in phase.modules:
                        phase.findings += 1
                        break
            # Update target finding count
            target = entry.target
            if counted and target in self.targets:
                self.targets[target].findings += 1
            if counted:
                self.metrics.record_finding()
            # Timeline
            sev = entry.severity
            self._add_timeline(
                f"finding_{sev.lower()}",
                f"[{sev.upper()}] {entry.title}",
                mod_name,
            )

    def _on_request(self, event: Event) -> None:
        del event

    def _on_request_error(self, event: Event) -> None:
        del event

    def _on_waf_block(self, event: Event) -> None:
        del event

    def _on_rate_limit(self, event: Event) -> None:
        del event

    def _on_credential(self, event: Event) -> None:
        d = event.data
        reference = str(d.get("credential_reference") or "")
        if reference and not reference.startswith("cred:"):
            reference = ""
        entry = CredentialEntry(
            id=str(d.get("id") or str(uuid.uuid4())[:8]),
            cred_type=d.get("type", "REFERENCE"),
            account="",
            credential_reference=reference,
            credential_state=(
                "protected_reference" if reference else "purged_legacy"
            ),
            target="",
            discovered_by=d.get("module", event.source),
            timestamp=event.timestamp,
        )
        with self._lock:
            self.credentials.append(entry)
            self._add_timeline(
                "credential",
                f"Credential boundary record: {entry.credential_state}",
                event.source,
            )

    def _on_target_discovered(self, event: Event) -> None:
        del event

    def _on_target_pwned(self, event: Event) -> None:
        """Ignore raw compromise events until a typed canonical proof exists."""

        del event
        return

    def _on_shell_session(self, event: Event) -> None:
        """Ignore raw shell events until a typed canonical session proof exists."""

        del event
        return

    def _on_brain_verdict(self, event: Event) -> None:
        del event

    def _on_chain_action(self, event: Event) -> None:
        del event

    # ── Timeline ──────────────────────────────────────────────────────

    def _add_timeline(self, event_type: str, message: str, source: str) -> None:
        """Add an entry to the threat timeline."""
        self.timeline.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "message": message,
            "source": source,
        })
        # Cap timeline at 1000 entries
        if len(self.timeline) > 1000:
            self.timeline = self.timeline[-1000:]

    # ── Snapshots for dashboard rendering ─────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        """Full state snapshot for the web dashboard.

        Returns a JSON-serializable dict of all dashboard state.
        """
        with self._lock:
            metrics = self.metrics.snapshot()
            return {
                "framework":   self.framework,
                "tenant_id":   self.tenant_id,
                "engagement_id": self.engagement_id,
                "run_id":      self.run_id,
                "target":      self.target,
                "scan_status": self.scan_status,
                "scan_mode":   self.scan_mode,
                "engagement":  self.engagement,
                "tester":      self.tester,
                "findings":    [f.to_dict() for f in self.findings],
                "findings_count": len(self.findings),
                "modules":     {n: m.to_dict() for n, m in self.modules.items()},
                "phases":      {n: p.to_dict() for n, p in self.phases.items()},
                "targets":     {t: s.to_dict() for t, s in self.targets.items()},
                "credentials": [c.to_dict() for c in self.credentials],
                "sessions":    [s.to_dict() for s in self.sessions],
                "brain_verdicts": [v.to_dict() for v in self.brain_verdicts],
                "chain_actions": [a.to_dict() for a in self.chain_actions],
                "kill_chain":  self.kill_chain.to_dict(),
                "metrics":     metrics.to_dict(),
                "timeline":    self.timeline[-100:],
            }

    def findings_snapshot(
        self, severity: str | None = None, limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Filtered findings for the findings panel."""
        with self._lock:
            filtered = self.findings
            if severity:
                filtered = [f for f in filtered if f.severity == severity]
            return [f.to_dict() for f in filtered[-limit:]]

    def metrics_snapshot(self) -> MetricsSnapshot:
        """Current metrics for the metrics panel."""
        return self.metrics.snapshot()

    # ── Persistence ───────────────────────────────────────────────────

    def _schedule_persist(self) -> None:
        """Schedule periodic state persistence to SQLite."""
        with self._lock:
            if self._closed or self._backend.name == "memory":
                return
            timer = threading.Timer(5.0, self._persist_and_reschedule)
            timer.daemon = True
            self._persist_timer = timer
            timer.start()

    def _persist_and_reschedule(self) -> None:
        """Persist current state and schedule the next persistence."""
        with self._lock:
            if self._closed:
                return
        try:
            self._persist_state()
        except Exception as exc:
            log.debug("State persistence failed: %s", exc)
        with self._lock:
            reschedule = not self._closed and self.scan_status in {
                "running",
                "advisory",
            }
        if reschedule:
            self._schedule_persist()

    def _persist_state(self) -> None:
        """Write state snapshot to SQLite for crash recovery."""
        if self._backend.name == "memory":
            return
        try:
            self._backend.save(self.run_id, self.snapshot())
        except Exception as exc:
            log.debug("State persistence error: %s", exc)

    @classmethod
    def restore_from_db(
        cls,
        db_session: Any,
        run_id: str,
        event_bus: EventBus,
        *,
        tenant_id: str = "default",
    ) -> "StateStore" | None:
        """Restore state from SQLite for --attach mode.

        Args:
            db_session: SQLAlchemy session.
            run_id:     Scan run ID to restore.
            event_bus:  EventBus to subscribe to.

        Returns:
            Restored StateStore, or None if not found.
        """
        try:
            backend = SQLiteStateBackend(db_session, tenant_id=tenant_id)
            data = backend.load(run_id)
            if not data:
                return None
            if str(data.get("tenant_id") or "default") != tenant_id:
                return None
            store = cls(
                event_bus=event_bus,
                framework=data.get("framework", "forge"),
                run_id=run_id,
                target=data.get("target", ""),
                persist_db=db_session,
                backend=backend,
                tenant_id=tenant_id,
                engagement_id=str(
                    data.get("engagement_id") or data.get("engagement") or ""
                ),
            )
            # Restore findings through the same truth normalizer used for live events.
            from common.confidence_policy import normalise_finding
            for fd in data.get("findings", []):
                normalized = normalise_finding(dict(fd))
                store.findings.append(FindingEntry(**{
                    k: v for k, v in {**fd, **normalized}.items()
                    if k in FindingEntry.__dataclass_fields__
                }))
            # Restore timeline
            store.timeline = data.get("timeline", [])
            for verdict in data.get("brain_verdicts", []):
                store.brain_verdicts.append(BrainVerdictEntry(**{
                    k: v for k, v in verdict.items()
                    if k in BrainVerdictEntry.__dataclass_fields__
                }))
            for action in data.get("chain_actions", []):
                store.chain_actions.append(ChainActionEntry(**{
                    k: v for k, v in action.items()
                    if k in ChainActionEntry.__dataclass_fields__
                }))
            store.scan_status = data.get("scan_status", "unknown")
            log.info("Restored dashboard state for run %s (%d findings)",
                     run_id, len(store.findings))
            return store
        except Exception as exc:
            log.error("Failed to restore dashboard state: %s", exc)
            return None

    def stop(self) -> None:
        """Fence event/timer activity, then flush one final projection."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            timer = self._persist_timer
            self._persist_timer = None
            subscriptions = list(self._subscriptions)
            self._subscriptions.clear()
        if timer is not None:
            timer.cancel()
        for event_type, callback in subscriptions:
            self._bus.unsubscribe(event_type, callback)
        self._persist_state()


class TestStateStore:
    """Unit tests for state_store module."""

    def test_finding_event(self) -> None:
        bus = EventBus()
        bus.start()
        store = StateStore(bus, framework="webforge", target="https://test.com")

        bus.emit(Event(
            event_type=EventType.FINDING_NEW,
            data={
                "id": "f1", "title": "SQLi", "severity": "High",
                "module": "sqli_scanner", "target": "https://test.com",
                "cvss_score": 9.8,
            },
            source="sqli_scanner",
        ))

        import time as _time
        _time.sleep(0.3)
        bus.stop()

        assert store.findings == []

    def test_module_lifecycle(self) -> None:
        bus = EventBus()
        bus.start()
        store = StateStore(bus, target="10.0.0.1")

        bus.emit_simple(EventType.MODULE_START, source="port_scanner", name="port_scanner", phase=1)
        import time as _time
        _time.sleep(0.2)
        bus.emit_simple(EventType.MODULE_COMPLETE, source="port_scanner", name="port_scanner", findings_count=3)
        _time.sleep(0.2)
        bus.stop()

        assert "port_scanner" in store.modules
        assert store.modules["port_scanner"].status == "advisory"
        assert store.modules["port_scanner"].progress_pct < 100.0
        assert store.modules["port_scanner"].findings_count == 0

    def test_credential_event(self) -> None:
        bus = EventBus()
        bus.start()
        store = StateStore(bus, target="dc01.lab.local")

        bus.emit(Event(
            event_type=EventType.CREDENTIAL_FOUND,
            data={
                "type": "NTLM_HASH", "account": "admin",
                "secret": "aad3b435b51404eeaad3b435b51404ee",
                "target": "dc01.lab.local",
            },
            source="secretsdump",
        ))

        import time as _time
        _time.sleep(0.3)
        bus.stop()

        assert len(store.credentials) == 1
        assert store.credentials[0].cred_type == "NTLM_HASH"

    def test_full_snapshot(self) -> None:
        bus = EventBus()
        bus.start()
        store = StateStore(bus, framework="adforge", target="dc01.corp.local", run_id="run-1")

        bus.emit_simple(EventType.SCAN_START, source="adforge", mode="auth", modules=["user_enum", "kerberoast"])
        import time as _time
        _time.sleep(0.3)
        bus.stop()

        snap = store.snapshot()
        assert snap["framework"] == "adforge"
        assert snap["target"] == "dc01.corp.local"
        assert "kill_chain" in snap
        assert "metrics" in snap

    def test_target_lifecycle(self) -> None:
        bus = EventBus()
        bus.start()
        store = StateStore(bus, target="10.0.0.0/24")

        bus.emit_simple(EventType.TARGET_DISCOVERED, source="port_scanner", target="10.0.0.5", services=["ssh", "http"])
        bus.emit_simple(EventType.TARGET_PWNED, source="ssh_brute", target="10.0.0.5", access_level="root")

        import time as _time
        _time.sleep(0.3)
        bus.stop()

        assert store.targets == {}
