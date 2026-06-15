"""Abstract BaseModule — all forge modules inherit from this."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from common.dashboard.event_bus import EventBus

from common.config import BaseForgeConfig
from common.confirm_gate import confirm
from common.db import Session, save_finding
from common.evidence import Evidence
from common.finding import Finding, Severity
from common.scope import Scope, ScopeViolation


@dataclass
class ModuleResult:
    """Container for all findings produced by a module run."""
    module_name: str
    findings:    list[Finding] = field(default_factory=list)
    errors:      list[str]     = field(default_factory=list)
    duration_s:  float         = 0.0
    skipped:     bool          = False
    skip_reason: str           = ""


class BaseModule(ABC):
    """Abstract base class for all forge modules.

    Every module must implement run() and provide NAME, DESCRIPTION, PHASE.
    Subclasses inherit scope checking, rate limiting, logging, finding
    persistence, screenshot capture, and operator confirmation gate.
    """

    NAME:        str = "base_module"
    DESCRIPTION: str = "Base module"
    PHASE:       int = 0
    TAGS:        list[str] = []

    def __init__(
        self,
        config: BaseForgeConfig,
        scope: Scope,
        db_session: Session,
        results_dir: Path,
        run_id: str | None = None,
        event_bus: "EventBus | None" = None,
    ) -> None:
        """Initialize module with shared resources.

        Args:
            config:      Framework configuration.
            scope:       Scope enforcer instance.
            db_session:  Active SQLAlchemy session.
            results_dir: Directory for evidence output.
            run_id:      Scan run UUID for correlation.
            event_bus:   Optional dashboard event bus for real-time UI.
        """
        self.config      = config
        self.scope       = scope
        self.db          = db_session
        self.results_dir = results_dir
        self.run_id      = run_id or str(uuid.uuid4())
        self.findings:   list[Finding] = []
        self.errors:     list[str]     = []
        self.log         = logging.getLogger(f"forge.{self.NAME}")
        self._last_request_time: float = 0.0
        self._evidence_dir = results_dir / "evidence"
        self._screenshot_dir = self._evidence_dir / "screenshots"
        self._event_bus: "EventBus | None" = event_bus
        self._request_count: int = 0

    @abstractmethod
    async def run(self) -> ModuleResult:
        """Execute the module. Must be implemented by every module.

        Returns:
            ModuleResult containing all findings and metadata.
        """

    def check_scope(self, target: str) -> bool:
        """Validate target is in scope before any request.

        Returns:
            True if in scope. Logs and returns False if out of scope.
        """
        try:
            return self.scope.check(target)
        except ScopeViolation as exc:
            self.log.warning("Scope violation blocked: %s", exc)
            return False

    async def rate_limit(self, bytes_out: int = 0, bytes_in: int = 0) -> None:
        """Enforce rate limiting between requests and emit metrics."""
        if self.config.rate.requests_per_second <= 0:
            return
        min_interval = 1.0 / self.config.rate.requests_per_second
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.monotonic()
        self._request_count += 1
        self._emit_event("request_sent", bytes_out=bytes_out, bytes_in=bytes_in)

    def add_finding(self, finding: Finding) -> None:
        """Record a finding, persist to DB, emit to dashboard, and log it."""
        self.findings.append(finding)
        try:
            save_finding(self.db, finding.to_dict(), run_id=self.run_id)
        except Exception as exc:
            self.log.error("Failed to save finding to DB: %s", exc)
        self.log.info(
            "[FINDING] %s | %s | %s",
            finding.severity.value,
            finding.title,
            finding.target,
            extra={"forge_module": self.NAME, "target": finding.target},
        )
        # Emit to dashboard event bus
        self._emit_event(
            "finding_new",
            id=finding.id,
            title=finding.title,
            severity=finding.severity.value,
            module=self.NAME,
            target=finding.target,
            cvss_score=finding.cvss_v31_score,
            url=finding.url or "",
            port=finding.port,
            service=finding.service,
            description=finding.description,
            mitre_attack=finding.mitre_attack,
        )

    def new_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        reproduction_steps: list[str],
        remediation: str,
        references: list[str],
        evidence: Evidence | None = None,
        cvss_v31_vector: str | None = None,
        cvss_v40_vector: str | None = None,
        mitre_attack: list[str] | None = None,
        port: int | None = None,
        service: str | None = None,
        target: str | None = None,
        url: str | None = None,
    ) -> Finding:
        """Create a new finding, add it, and return it."""
        f = Finding(
            title=title,
            severity=severity,
            target=target or self.config.target,
            module=self.NAME,
            description=description,
            reproduction_steps=reproduction_steps,
            remediation=remediation,
            references=references,
            evidence=evidence or Evidence(),
            cvss_v31_vector=cvss_v31_vector,
            cvss_v40_vector=cvss_v40_vector,
            mitre_attack=mitre_attack or [],
            port=port,
            service=service,
        )
        self.add_finding(f)
        return f

    async def confirm_action(
        self,
        action: str,
        target: str,
        risk: str,
        on_confirm: Any = None,
        on_skip: Any = None,
    ) -> bool:
        """Require operator confirmation before executing a sensitive action."""
        return await confirm(
            module=self.NAME,
            action=action,
            target=target,
            risk=risk,
            on_confirm=on_confirm,
            on_skip=on_skip,
        )

    def capture_screenshot(
        self,
        url: str,
        finding_id: str,
        highlight_js: str | None = None,
        cookies: list[dict] | None = None,
    ) -> str | None:
        """Capture a screenshot for POC evidence.

        Returns path to PNG, or None if screenshot unavailable.
        """
        try:
            from common.screenshot import capture
            return capture(
                url=url,
                output_dir=self._screenshot_dir,
                highlight_js=highlight_js,
                cookies=cookies,
                finding_id=finding_id,
            )
        except Exception as exc:
            self.log.debug("Screenshot unavailable: %s", exc)
            return None

    def add_error(self, message: str) -> None:
        """Record a non-fatal module error for inclusion in the result."""
        self.errors.append(message)
        self.log.error("[ERROR] %s: %s", self.NAME, message)

    def _make_result(self, start_time: float, skipped: bool = False, skip_reason: str = "") -> ModuleResult:
        """Build a ModuleResult from accumulated findings and errors."""
        duration = time.monotonic() - start_time
        if skipped:
            self._emit_event("module_skip", name=self.NAME, reason=skip_reason)
        else:
            self._emit_event(
                "module_complete", name=self.NAME,
                findings_count=len(self.findings), duration=duration,
                error_count=len(self.errors),
            )
        return ModuleResult(
            module_name=self.NAME,
            findings=self.findings,
            errors=self.errors,
            duration_s=duration,
            skipped=skipped,
            skip_reason=skip_reason,
        )

    def _emit_event(self, event_type_str: str, **data: Any) -> None:
        """Emit a dashboard event if event_bus is connected."""
        if not self._event_bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            et = EventType(event_type_str)
            self._event_bus.emit(Event(
                event_type=et, data=data, source=self.NAME, run_id=self.run_id,
            ))
        except (ValueError, ImportError):
            pass  # Event type not recognized or dashboard not installed


class TestBaseModule:
    """Unit tests for base_module."""

    def test_module_requires_run(self) -> None:
        import inspect
        assert inspect.isabstract(BaseModule)

    def test_concrete_module(self, tmp_path: Path) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        class DummyModule(BaseModule):
            NAME = "dummy"
            DESCRIPTION = "Test module"
            PHASE = 1

            async def run(self) -> ModuleResult:
                start = time.monotonic()
                return self._make_result(start)

        cfg = BaseForgeConfig(target="10.0.0.1")
        scope = Scope(["10.0.0.0/24"])
        session = create_db(tmp_path / "test.db")
        mod = DummyModule(cfg, scope, session, tmp_path)
        result = asyncio.run(mod.run())
        assert result.module_name == "dummy"
        assert result.findings == []
        session.close()
