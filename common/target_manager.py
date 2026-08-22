"""Multi-target orchestration engine for bulk VAPT scanning.

Supports loading targets from files, deduplication, concurrent scanning,
per-target pause/resume/abort, and progress persistence.

Usage:
    python forge.py web --targets targets.txt --parallel 5
    python forge.py net --targets hosts.txt --mode internal --red-team
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, cast

from common.action_authorization import redact_authorization_value
from common.artifact_io import atomic_write_bytes, ensure_private_directory
from common.redaction import redacted_json_dumps
from common.scope import safe_target_display

log = logging.getLogger("forge.target_manager")


class TargetState(str, Enum):
    """Lifecycle state of a target in the scan queue."""
    QUEUED     = "queued"
    SCANNING   = "scanning"
    PAUSED     = "paused"
    COMPLETED  = "completed"
    FAILED     = "failed"
    NOT_AUTHORIZED = "not_authorized"
    ABORTED    = "aborted"
    SKIPPED    = "skipped"


@dataclass
class TargetEntry:
    """A single target in the scanning queue."""
    target:       str
    state:        TargetState = TargetState.QUEUED
    priority:     int = 5          # 1=highest, 10=lowest
    options:      dict[str, Any] = field(default_factory=dict)
    scan_id:      str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    start_time:   float = 0.0
    end_time:     float = 0.0
    duration:     float = 0.0
    findings:     int = 0
    errors:       list[str] = field(default_factory=list)
    retry_count:  int = 0
    max_retries:  int = 1

    def to_dict(self, *, safe_target: bool = False) -> dict[str, Any]:
        return {
            "target": safe_target_display(self.target) if safe_target else self.target,
            "state": self.state.value,
            "priority": self.priority, "scan_id": self.scan_id,
            "duration": round(self.duration, 1), "findings": self.findings,
            "errors": self.errors, "retry_count": self.retry_count,
        }


ScanFunction = Callable[[TargetEntry], Awaitable[dict[str, Any] | None]]


class TargetManager:
    """Orchestrates scanning across multiple targets.

    Features:
        - Load targets from file or programmatic addition
        - Deduplication — no double-scanning
        - Priority queue ordering
        - Concurrent scan control (max N parallel)
        - Per-target pause/resume/abort
        - Global pause/resume/abort
        - Progress persistence to JSON
        - Event bus integration for dashboard updates

    Args:
        max_parallel:   Maximum concurrent target scans.
        results_dir:    Base directory for scan results.
        event_bus:      Optional EventBus for dashboard integration.
        defer_results_setup: Wait for the scan callback to explicitly signal
            that its authorization boundary has passed before creating or
            updating shared progress artifacts.
    """

    def __init__(
        self,
        max_parallel: int = 3,
        results_dir: Path | None = None,
        event_bus: Any = None,
        defer_results_setup: bool = False,
        safe_target_persistence: bool = False,
    ) -> None:
        self.max_parallel = max_parallel
        self.results_dir = results_dir or Path("results")
        self.event_bus = event_bus
        # Authorization-aware callers can defer shared filesystem state until
        # their scan callback has consumed its exact action envelope.  The
        # default remains eager for legacy callers that do not provide that
        # boundary contract.
        self.defer_results_setup = defer_results_setup
        self.safe_target_persistence = safe_target_persistence
        self._targets: dict[str, TargetEntry] = {}
        self._queue: list[str] = []
        self._active: set[str] = set()
        self._global_paused = False
        self._global_aborted = False
        self._semaphore: asyncio.Semaphore | None = None
        self._lock = asyncio.Lock()
        self._scan_fn: ScanFunction | None = None
        self._progress_file: Path | None = None
        self._progress_enabled = not defer_results_setup

    def enable_progress_persistence(self) -> None:
        """Enable shared progress artifacts after an authorization boundary.

        Authorization-aware scan callbacks call this exactly after scope and
        action authorization succeeds (or for an intentional non-executing
        dry-run).  It is idempotent so concurrent target callbacks can safely
        signal readiness without racing a second directory creation.
        """
        if self._progress_enabled:
            return
        self._progress_enabled = True
        if self.results_dir:
            ensure_private_directory(self.results_dir)
            if self._progress_file is None:
                self._progress_file = self.results_dir / "target_progress.json"

    def load_targets_file(self, filepath: str | Path) -> int:
        """Load targets from a text file.

        Supports:
            - One target per line
            - Lines starting with # are comments
            - Empty lines are skipped
            - Inline options after target: `example.com --rate=5`

        Returns:
            Number of targets loaded.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Targets file not found: {filepath}")

        count = 0
        with open(filepath, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(maxsplit=1)
                target = parts[0]
                options = {}
                if len(parts) > 1:
                    # Parse inline options: --key=value or --flag
                    for token in parts[1].split():
                        if token.startswith("--"):
                            kv = token[2:].split("=", 1)
                            key = kv[0].replace("-", "_")
                            val = kv[1] if len(kv) > 1 else True
                            options[key] = val

                if self.add_target(target, options=options):
                    count += 1
                    log.debug("Loaded target %d: %s", count, safe_target_display(target))

        log.info("Loaded %d targets from %s", count, filepath)
        return count

    def add_target(
        self,
        target: str,
        priority: int = 5,
        options: dict[str, Any] | None = None,
    ) -> bool:
        """Add a target to the scan queue.

        Returns True if added, False if duplicate.
        """
        normalized = target.strip().rstrip("/").lower()
        if normalized in self._targets:
            log.debug("Duplicate target skipped: %s", safe_target_display(target))
            return False

        entry = TargetEntry(
            target=target.strip(),
            priority=priority,
            options=options or {},
        )
        self._targets[normalized] = entry
        self._queue.append(normalized)
        self._emit("target_queued", target=safe_target_display(target), priority=priority)
        return True

    def add_targets(self, targets: list[str]) -> int:
        """Add multiple targets. Returns count added."""
        return sum(1 for t in targets if self.add_target(t))

    async def run_all(
        self,
        scan_fn: ScanFunction,
    ) -> dict[str, Any]:
        """Execute scans for all queued targets.

        Args:
            scan_fn: Async function that takes a TargetEntry and runs the scan.
                     It should return a dict with 'findings' count and 'errors'.

        Returns:
            Summary dict with overall results.
        """
        self._scan_fn = scan_fn
        self._semaphore = asyncio.Semaphore(self.max_parallel)

        # Sort queue by priority
        self._queue.sort(key=lambda k: self._targets[k].priority)

        # Setup progress persistence
        if self.results_dir:
            if not self.defer_results_setup:
                ensure_private_directory(self.results_dir)
            self._progress_file = self.results_dir / "target_progress.json"

        start_time = time.monotonic()
        log.info("Starting multi-target scan: %d targets, %d parallel",
                 len(self._queue), self.max_parallel)

        # Launch all scans
        tasks = [
            asyncio.create_task(self._scan_target(key))
            for key in self._queue
        ]

        # Wait for all to complete
        await asyncio.gather(*tasks, return_exceptions=True)

        elapsed = time.monotonic() - start_time
        summary = self.summary()
        summary["total_duration"] = round(elapsed, 1)

        # Final progress save
        self._save_progress()

        log.info("Multi-target scan complete: %d targets in %.1fs",
                 len(self._targets), elapsed)
        return summary

    async def _scan_target(self, key: str) -> None:
        """Scan a single target with semaphore control."""
        entry = self._targets[key]

        # Wait for semaphore
        semaphore = cast(asyncio.Semaphore, self._semaphore)
        scan_fn = cast(ScanFunction, self._scan_fn)
        async with semaphore:
            # Check global abort
            if self._global_aborted:
                entry.state = TargetState.ABORTED
                return

            # Wait if globally paused
            while self._global_paused and not self._global_aborted:
                await asyncio.sleep(0.5)

            entry.state = TargetState.SCANNING
            entry.start_time = time.monotonic()
            self._active.add(key)
            self._emit("target_scanning", target=safe_target_display(entry.target))
            log.info("[TARGET] Scanning: %s", safe_target_display(entry.target))

            try:
                result = await scan_fn(entry)
                entry.findings = result.get("findings", 0) if result else 0
                raw_errors = result.get("errors", []) if result else []
                if raw_errors:
                    entry.errors.extend(
                        str(redact_authorization_value(str(error)))
                        for error in raw_errors
                    )
                status = str(
                    result.get(
                        "status",
                        "failed" if raw_errors else "completed",
                    )
                    if result
                    else "failed"
                )
                if raw_errors and status == "completed":
                    status = "failed"
                if status == "completed":
                    entry.state = TargetState.COMPLETED
                    self._emit(
                        "target_completed",
                        target=safe_target_display(entry.target),
                        findings=entry.findings,
                    )
                elif status == "aborted":
                    entry.state = TargetState.ABORTED
                    self._emit(
                        "target_failed",
                        target=safe_target_display(entry.target),
                        outcome="aborted",
                        error="scan aborted by operator",
                    )
                else:
                    entry.state = (
                        TargetState.NOT_AUTHORIZED
                        if status == "not_authorized"
                        else TargetState.FAILED
                    )
                    if not entry.errors:
                        entry.errors.append(f"scan ended with status: {status}")
                    self._emit(
                        "target_failed",
                        target=safe_target_display(entry.target),
                        outcome=status,
                        error=entry.errors[0],
                    )
            except asyncio.CancelledError:
                entry.state = TargetState.ABORTED
                log.info("[TARGET] Aborted: %s", safe_target_display(entry.target))
            except Exception as exc:
                safe_error = str(redact_authorization_value(str(exc)))
                entry.errors.append(safe_error)
                log.error(
                    "[TARGET] Failed: %s — %s",
                    safe_target_display(entry.target),
                    safe_error,
                )
                if entry.retry_count < entry.max_retries:
                    entry.retry_count += 1
                    entry.state = TargetState.QUEUED
                    log.info(
                        "[TARGET] Retrying %s (attempt %d)",
                        safe_target_display(entry.target),
                        entry.retry_count,
                    )
                    await self._scan_target(key)
                    return
                else:
                    entry.state = TargetState.FAILED
                    self._emit("target_failed", target=safe_target_display(entry.target),
                               error=safe_error)
            finally:
                entry.end_time = time.monotonic()
                entry.duration = entry.end_time - entry.start_time
                self._active.discard(key)
                self._save_progress()

    def pause_target(self, target: str) -> bool:
        """Pause scanning of a specific target."""
        key = target.strip().rstrip("/").lower()
        if key in self._targets and self._targets[key].state == TargetState.SCANNING:
            self._targets[key].state = TargetState.PAUSED
            self._emit("target_paused", target=target)
            return True
        return False

    def resume_target(self, target: str) -> bool:
        """Resume scanning of a specific target."""
        key = target.strip().rstrip("/").lower()
        if key in self._targets and self._targets[key].state == TargetState.PAUSED:
            self._targets[key].state = TargetState.SCANNING
            return True
        return False

    def pause_all(self) -> None:
        """Pause all scanning."""
        self._global_paused = True
        log.info("Global pause activated")

    def resume_all(self) -> None:
        """Resume all scanning."""
        self._global_paused = False
        log.info("Global pause released")

    def abort_all(self) -> None:
        """Abort all scanning."""
        self._global_aborted = True
        log.info("Global abort activated")

    def summary(self) -> dict[str, Any]:
        """Get summary of all target states."""
        counts = {s.value: 0 for s in TargetState}
        total_findings = 0
        for entry in self._targets.values():
            counts[entry.state.value] += 1
            total_findings += entry.findings

        return {
            "total_targets": len(self._targets),
            "states": counts,
            "total_findings": total_findings,
            "active": len(self._active),
            "targets": [
                entry.to_dict(safe_target=self.safe_target_persistence)
                for entry in self._targets.values()
            ],
        }

    def status(self) -> str:
        """Human-readable status string."""
        s = self.summary()
        return (
            f"Targets: {s['total_targets']} | "
            f"Active: {s['active']} | "
            f"Completed: {s['states']['completed']} | "
            f"Failed: {s['states']['failed']} | "
            f"Not authorized: {s['states']['not_authorized']} | "
            f"Findings: {s['total_findings']}"
        )

    def _save_progress(self) -> None:
        """Persist progress to JSON file."""
        if not self._progress_file or not self._progress_enabled:
            return
        try:
            progress = {
                "timestamp": time.time(),
                "summary": self.summary(),
            }
            payload = redacted_json_dumps(progress, indent=2, default=str).encode("utf-8")
            atomic_write_bytes(self._progress_file, payload, mode=0o600)
        except Exception as exc:
            log.debug("Progress save failed: %s", type(exc).__name__)

    def _emit(self, event_type: str, **data: Any) -> None:
        """Emit event to dashboard."""
        if not self.event_bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            et = EventType(event_type)
            protected = dict(data)
            if "target" in protected:
                protected["target"] = safe_target_display(str(protected["target"]))
            self.event_bus.emit(
                Event(event_type=et, data=protected, source="target_manager")
            )
        except (ValueError, ImportError):
            pass

    @classmethod
    def from_resume(cls, results_dir: Path, **kwargs: Any) -> "TargetManager":
        """Resume a previous multi-target scan from progress file."""
        progress_file = results_dir / "target_progress.json"
        if not progress_file.exists():
            raise FileNotFoundError(f"No progress file at {progress_file}")

        with open(progress_file) as f:
            data = json.load(f)

        mgr = cls(results_dir=results_dir, **kwargs)
        for t in data.get("summary", {}).get("targets", []):
            if t["state"] not in ("completed", "aborted"):
                mgr.add_target(t["target"])
                log.info("Resuming target: %s", t["target"])

        return mgr


class TestTargetManager:
    """Unit tests for target_manager."""

    def test_add_dedup(self) -> None:
        mgr = TargetManager()
        assert mgr.add_target("10.0.0.1") is True
        assert mgr.add_target("10.0.0.1") is False
        assert mgr.add_target("10.0.0.2") is True
        assert len(mgr._targets) == 2

    def test_load_file(self, tmp_path: Path) -> None:
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text(
            "# Comment\n"
            "https://example.com\n"
            "https://target2.com --rate=5\n"
            "\n"
            "10.0.0.1\n"
        )
        mgr = TargetManager()
        count = mgr.load_targets_file(targets_file)
        assert count == 3

    def test_summary(self) -> None:
        mgr = TargetManager()
        mgr.add_target("10.0.0.1")
        mgr.add_target("10.0.0.2")
        s = mgr.summary()
        assert s["total_targets"] == 2
        assert s["states"]["queued"] == 2

    def test_status(self) -> None:
        mgr = TargetManager()
        mgr.add_target("10.0.0.1")
        status = mgr.status()
        assert "Targets: 1" in status
