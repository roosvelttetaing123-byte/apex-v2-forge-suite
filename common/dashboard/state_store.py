"""In-memory state aggregator for the War Room dashboard.

StateStore is the single source of truth that dashboards render from.
It subscribes to EventBus events, aggregates them into structured state,
and provides thread-safe snapshots for the TUI and web dashboard.

Persists snapshots to SQLite every 5 seconds for crash recovery,
and can restore state from DB when attaching to a running session.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from common.dashboard.event_bus import Event, EventBus, EventType
from common.dashboard.kill_chain import KillChainState
from common.dashboard.metrics import MetricsCollector, MetricsSnapshot

log = logging.getLogger("forge.dashboard.state")


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "module": self.module, "target": self.target,
            "cvss_score": self.cvss_score, "timestamp": self.timestamp,
            "url": self.url, "port": self.port, "service": self.service,
            "description": self.description, "mitre": self.mitre,
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
    """A discovered credential."""
    id:            str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    cred_type:     str = ""    # PLAINTEXT, NTLM_HASH, KERB_TICKET, API_KEY, SSH_KEY, JWT
    account:       str = ""
    secret:        str = ""
    target:        str = ""
    discovered_by: str = ""
    timestamp:     str = ""

    def to_dict(self, mask: bool = True) -> dict[str, Any]:
        secret_display = self.secret
        if mask and len(self.secret) > 8:
            secret_display = self.secret[:4] + "…" + self.secret[-4:]
        elif mask and self.secret:
            secret_display = "●" * len(self.secret)
        return {
            "id": self.id, "cred_type": self.cred_type,
            "account": self.account, "secret": secret_display,
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
    ) -> None:
        self._bus = event_bus
        self.framework = framework
        self.run_id = run_id
        self.target = target
        self._db = persist_db
        self._lock = threading.RLock()

        # ── State containers ──
        self.findings:    list[FindingEntry] = []
        self.modules:     dict[str, ModuleStatus] = {}
        self.phases:      dict[int, PhaseStatus] = {}
        self.targets:     dict[str, TargetStatus] = {}
        self.credentials: list[CredentialEntry] = []
        self.sessions:    list[ShellSession] = []
        self.kill_chain   = KillChainState()
        self.metrics      = MetricsCollector()
        self.timeline:    list[dict[str, Any]] = []

        # Scan metadata
        self.scan_status: str = "initializing"
        self.scan_start:  float = 0.0
        self.scan_mode:   str = ""
        self.engagement:  str = ""
        self.tester:      str = ""

        # Subscribe to all events
        self._subscribe()

        # Start persistence timer
        self._persist_timer: threading.Timer | None = None
        if persist_db:
            self._schedule_persist()

    def _subscribe(self) -> None:
        """Register handlers for all event types."""
        self._bus.subscribe(EventType.SCAN_START, self._on_scan_start)
        self._bus.subscribe(EventType.SCAN_COMPLETE, self._on_scan_complete)
        self._bus.subscribe(EventType.SCAN_INTERRUPTED, self._on_scan_interrupted)
        self._bus.subscribe(EventType.PHASE_START, self._on_phase_start)
        self._bus.subscribe(EventType.PHASE_COMPLETE, self._on_phase_complete)
        self._bus.subscribe(EventType.MODULE_START, self._on_module_start)
        self._bus.subscribe(EventType.MODULE_PROGRESS, self._on_module_progress)
        self._bus.subscribe(EventType.MODULE_COMPLETE, self._on_module_complete)
        self._bus.subscribe(EventType.MODULE_FAIL, self._on_module_fail)
        self._bus.subscribe(EventType.MODULE_SKIP, self._on_module_skip)
        self._bus.subscribe(EventType.FINDING_NEW, self._on_finding)
        self._bus.subscribe(EventType.REQUEST_SENT, self._on_request)
        self._bus.subscribe(EventType.REQUEST_ERROR, self._on_request_error)
        self._bus.subscribe(EventType.WAF_BLOCK, self._on_waf_block)
        self._bus.subscribe(EventType.RATE_LIMIT_HIT, self._on_rate_limit)
        self._bus.subscribe(EventType.CREDENTIAL_FOUND, self._on_credential)
        self._bus.subscribe(EventType.TARGET_DISCOVERED, self._on_target_discovered)
        self._bus.subscribe(EventType.TARGET_PWNED, self._on_target_pwned)
        self._bus.subscribe(EventType.SHELL_SESSION, self._on_shell_session)

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
            self.kill_chain = KillChainState()
            self.metrics = MetricsCollector()

            self.scan_status = "running"
            self.scan_start = time.monotonic()
            self.scan_mode = event.data.get("mode", "")
            self.engagement = event.data.get("engagement", "")
            self.tester = event.data.get("tester", "")
            self.run_id = event.data.get("run_id", self.run_id)
            self.target = event.data.get("target", self.target)
            module_names = event.data.get("modules", [])
            if module_names:
                self.kill_chain.set_module_totals(module_names)
                self.metrics.set_total_modules(len(module_names))
            self._add_timeline("scan_start", "Assessment started", event.source)

    def _on_scan_complete(self, event: Event) -> None:
        with self._lock:
            self.scan_status = "completed"
            self._add_timeline("scan_complete", "Assessment completed", event.source)

    def _on_scan_interrupted(self, event: Event) -> None:
        with self._lock:
            self.scan_status = "interrupted"
            self._add_timeline("scan_interrupted", "Assessment interrupted", event.source)

    def _on_phase_start(self, event: Event) -> None:
        with self._lock:
            num = event.data.get("number", 0)
            name = event.data.get("name", f"Phase {num}")
            modules = event.data.get("modules", [])
            self.phases[num] = PhaseStatus(
                number=num, name=name, status="running", modules=modules,
            )
            self._add_timeline("phase_start", f"Phase {num}: {name}", event.source)

    def _on_phase_complete(self, event: Event) -> None:
        with self._lock:
            num = event.data.get("number", 0)
            if num in self.phases:
                self.phases[num].status = "complete"
                self.phases[num].duration = event.data.get("duration", 0.0)

    def _on_module_start(self, event: Event) -> None:
        name = event.data.get("name", event.source)
        with self._lock:
            self.modules[name] = ModuleStatus(
                name=name, status="running",
                start_time=time.monotonic(),
                phase=event.data.get("phase", 0),
            )
            self.kill_chain.record_module_start(name)
            self.metrics.record_module_start()

    def _on_module_progress(self, event: Event) -> None:
        name = event.data.get("name", event.source)
        with self._lock:
            if name in self.modules:
                self.modules[name].progress_pct = event.data.get("progress", 0.0)

    def _on_module_complete(self, event: Event) -> None:
        name = event.data.get("name", event.source)
        with self._lock:
            if name in self.modules:
                mod = self.modules[name]
                mod.status = "complete"
                mod.progress_pct = 100.0
                mod.end_time = time.monotonic()
                mod.duration = mod.end_time - mod.start_time
                mod.findings_count = event.data.get("findings_count", mod.findings_count)
                self.kill_chain.record_module_complete(name)
                self.metrics.record_module_complete(mod.duration)

    def _on_module_fail(self, event: Event) -> None:
        name = event.data.get("name", event.source)
        with self._lock:
            if name in self.modules:
                self.modules[name].status = "failed"
                self.modules[name].error = event.data.get("error", "unknown")
            else:
                self.modules[name] = ModuleStatus(
                    name=name, status="failed",
                    error=event.data.get("error", "unknown"),
                )
            self.metrics.record_module_fail()
            self._add_timeline(
                "module_fail", f"Module failed: {name} — {event.data.get('error', '')}",
                event.source,
            )

    def _on_module_skip(self, event: Event) -> None:
        name = event.data.get("name", event.source)
        with self._lock:
            self.modules[name] = ModuleStatus(
                name=name, status="skipped",
                error=event.data.get("reason", ""),
            )

    def _on_finding(self, event: Event) -> None:
        d = event.data
        entry = FindingEntry(
            id=d.get("id", str(uuid.uuid4())[:8]),
            title=d.get("title", "Untitled"),
            severity=d.get("severity", "Informational"),
            module=d.get("module", event.source),
            target=d.get("target", self.target),
            cvss_score=d.get("cvss_score"),
            timestamp=event.timestamp,
            url=d.get("url", ""),
            port=d.get("port"),
            service=d.get("service", ""),
            description=d.get("description", ""),
            mitre=d.get("mitre_attack", []),
            evidence=d.get("evidence", {}),
        )
        with self._lock:
            self.findings.append(entry)
            # Update module finding count
            mod_name = d.get("module", event.source)
            if mod_name in self.modules:
                self.modules[mod_name].findings_count += 1
            # Update phase finding count
            for phase in self.phases.values():
                if mod_name in phase.modules:
                    phase.findings += 1
                    break
            # Update target finding count
            target = d.get("target", self.target)
            if target in self.targets:
                self.targets[target].findings += 1
            # Update kill chain
            self.kill_chain.record_finding(mod_name)
            self.metrics.record_finding()
            # Timeline
            sev = d.get("severity", "Info")
            self._add_timeline(
                f"finding_{sev.lower()}",
                f"[{sev.upper()}] {d.get('title', 'Finding')}",
                mod_name,
            )

    def _on_request(self, event: Event) -> None:
        self.metrics.record_request(
            bytes_out=event.data.get("bytes_out", 0),
            bytes_in=event.data.get("bytes_in", 0),
        )

    def _on_request_error(self, event: Event) -> None:
        self.metrics.record_error()

    def _on_waf_block(self, event: Event) -> None:
        self.metrics.record_waf_block()

    def _on_rate_limit(self, event: Event) -> None:
        self.metrics.record_rate_limit()

    def _on_credential(self, event: Event) -> None:
        d = event.data
        entry = CredentialEntry(
            cred_type=d.get("type", "UNKNOWN"),
            account=d.get("account", ""),
            secret=d.get("secret", ""),
            target=d.get("target", ""),
            discovered_by=d.get("module", event.source),
            timestamp=event.timestamp,
        )
        with self._lock:
            self.credentials.append(entry)
            # Update target creds count
            target = d.get("target", "")
            if target in self.targets:
                self.targets[target].creds_count += 1
            self._add_timeline(
                "credential",
                f"Credential found: {d.get('type', '')} {d.get('account', '')}",
                event.source,
            )

    def _on_target_discovered(self, event: Event) -> None:
        target = event.data.get("target", "")
        with self._lock:
            if target and target not in self.targets:
                self.targets[target] = TargetStatus(
                    target=target,
                    services=event.data.get("services", []),
                )

    def _on_target_pwned(self, event: Event) -> None:
        target = event.data.get("target", "")
        with self._lock:
            if target in self.targets:
                self.targets[target].pwned = True
                self.targets[target].access_level = event.data.get("access_level", "user")
            self._add_timeline(
                "target_pwned",
                f"Target compromised: {target} ({event.data.get('access_level', '')})",
                event.source,
            )

    def _on_shell_session(self, event: Event) -> None:
        d = event.data
        with self._lock:
            session = ShellSession(
                session_id=len(self.sessions) + 1,
                target=d.get("target", ""),
                shell_type=d.get("shell_type", "CMD"),
                access_level=d.get("access_level", "user"),
                established=event.timestamp,
                module=event.source,
            )
            self.sessions.append(session)
            # Mark target as having shell
            target = d.get("target", "")
            if target in self.targets:
                self.targets[target].shell = True
                self.targets[target].pwned = True

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
        if not self._db:
            return
        self._persist_timer = threading.Timer(5.0, self._persist_and_reschedule)
        self._persist_timer.daemon = True
        self._persist_timer.start()

    def _persist_and_reschedule(self) -> None:
        """Persist current state and schedule the next persistence."""
        try:
            self._persist_state()
        except Exception as exc:
            log.debug("State persistence failed: %s", exc)
        if self.scan_status == "running":
            self._schedule_persist()

    def _persist_state(self) -> None:
        """Write state snapshot to SQLite for crash recovery."""
        if not self._db:
            return
        try:
            from common.db import DashboardStateModel
            snapshot_json = json.dumps(self.snapshot(), default=str)
            model = DashboardStateModel(
                id=self.run_id,
                run_id=self.run_id,
                state_json=snapshot_json,
                updated_at=datetime.now(timezone.utc),
            )
            self._db.merge(model)
            self._db.commit()
        except ImportError:
            pass  # DB models not yet available
        except Exception as exc:
            log.debug("State persistence error: %s", exc)

    @classmethod
    def restore_from_db(
        cls, db_session: Any, run_id: str, event_bus: EventBus,
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
            from common.db import DashboardStateModel
            model = db_session.query(DashboardStateModel).filter_by(
                run_id=run_id,
            ).first()
            if not model:
                return None
            data = json.loads(model.state_json)
            store = cls(
                event_bus=event_bus,
                framework=data.get("framework", "forge"),
                run_id=run_id,
                target=data.get("target", ""),
                persist_db=db_session,
            )
            # Restore findings
            for fd in data.get("findings", []):
                store.findings.append(FindingEntry(**{
                    k: v for k, v in fd.items()
                    if k in FindingEntry.__dataclass_fields__
                }))
            # Restore timeline
            store.timeline = data.get("timeline", [])
            store.scan_status = data.get("scan_status", "unknown")
            log.info("Restored dashboard state for run %s (%d findings)",
                     run_id, len(store.findings))
            return store
        except Exception as exc:
            log.error("Failed to restore dashboard state: %s", exc)
            return None

    def stop(self) -> None:
        """Stop persistence timer and flush final state."""
        if self._persist_timer:
            self._persist_timer.cancel()
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

        assert len(store.findings) == 1
        assert store.findings[0].title == "SQLi"
        assert store.findings[0].severity == "High"

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
        assert store.modules["port_scanner"].status == "complete"

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

        assert "10.0.0.5" in store.targets
        assert store.targets["10.0.0.5"].pwned is True
        assert store.targets["10.0.0.5"].access_level == "root"
