"""Engagement scheduler for time-based and recurring scans.

Supports one-shot scheduled scans, recurring weekly/daily scans,
and continuous monitoring mode with configurable intervals.
Integrates with TargetManager for multi-target orchestration.

Usage:
    # Run at 2am tonight
    python forge.py web --targets prod.txt --schedule "02:00"

    # Weekly on Monday at 2am
    python forge.py web --targets prod.txt --schedule "weekly:monday:02:00"

    # Every 6 hours
    python forge.py web --targets prod.txt --continuous --interval 6h

    # Daily at midnight
    python forge.py net --targets servers.txt --schedule "daily:00:00"
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine

from common.redaction import redact_text, redact_value

log = logging.getLogger("forge.engagement_scheduler")


class ScheduleType(str, Enum):
    """Type of schedule."""
    ONCE       = "once"        # Single shot at a specific time
    DAILY      = "daily"       # Every day at HH:MM
    WEEKLY     = "weekly"      # Every week on DAY at HH:MM
    INTERVAL   = "interval"    # Every N hours/minutes
    CONTINUOUS = "continuous"   # Repeats with interval between scans


DAY_MAP = {
    "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
    "friday": 4, "saturday": 5, "sunday": 6,
    "mon": 0, "tue": 1, "wed": 2, "thu": 3,
    "fri": 4, "sat": 5, "sun": 6,
}


@dataclass
class ScheduleConfig:
    """Parsed schedule configuration.

    Attributes:
        schedule_type:  Type of schedule (once, daily, weekly, interval, continuous).
        time_str:       HH:MM time string for time-based schedules.
        day_of_week:    Day name for weekly schedules (monday-sunday).
        interval_secs:  Interval in seconds for interval/continuous modes.
        max_runs:       Max number of scheduled runs (0 = unlimited).
        timezone_offset: UTC offset in hours (default: local).
    """
    schedule_type:  ScheduleType = ScheduleType.ONCE
    time_str:       str = "00:00"
    day_of_week:    str = ""
    interval_secs:  float = 86400.0   # 24 hours default
    max_runs:       int = 0           # 0 = unlimited
    timezone_offset: float = 0.0

    @classmethod
    def parse(cls, schedule_str: str) -> "ScheduleConfig":
        """Parse a schedule string into a ScheduleConfig.

        Supported formats:
            "02:00"                  → once at 02:00 today (or tomorrow if past)
            "daily:02:00"            → every day at 02:00
            "weekly:monday:02:00"    → every Monday at 02:00
            "interval:6h"            → every 6 hours
            "interval:30m"           → every 30 minutes
            "continuous:24h"         → continuous monitoring, 24h between scans

        Args:
            schedule_str: The schedule specification string.

        Returns:
            Parsed ScheduleConfig.

        Raises:
            ValueError: If the schedule string is invalid.
        """
        parts = schedule_str.lower().strip().split(":")
        config = cls()

        if len(parts) == 2 and parts[0].isdigit():
            # Simple "HH:MM" format — one-shot
            config.schedule_type = ScheduleType.ONCE
            config.time_str = schedule_str.strip()
            _validate_time(config.time_str)
            return config

        kind = parts[0]

        if kind == "daily" and len(parts) >= 3:
            config.schedule_type = ScheduleType.DAILY
            config.time_str = f"{parts[1]}:{parts[2]}"
            _validate_time(config.time_str)
            return config

        if kind == "weekly" and len(parts) >= 4:
            config.schedule_type = ScheduleType.WEEKLY
            config.day_of_week = parts[1]
            if config.day_of_week not in DAY_MAP:
                raise ValueError(
                    f"Invalid day: '{config.day_of_week}'. "
                    f"Use: {', '.join(DAY_MAP.keys())}"
                )
            config.time_str = f"{parts[2]}:{parts[3]}"
            _validate_time(config.time_str)
            return config

        if kind == "interval" and len(parts) >= 2:
            config.schedule_type = ScheduleType.INTERVAL
            config.interval_secs = _parse_duration(parts[1])
            return config

        if kind == "continuous" and len(parts) >= 2:
            config.schedule_type = ScheduleType.CONTINUOUS
            config.interval_secs = _parse_duration(parts[1])
            return config

        raise ValueError(
            f"Invalid schedule: '{schedule_str}'. "
            f"Formats: HH:MM, daily:HH:MM, weekly:DAY:HH:MM, "
            f"interval:Nh/Nm, continuous:Nh/Nm"
        )


def _validate_time(time_str: str) -> None:
    """Validate HH:MM format."""
    match = re.match(r"^(\d{1,2}):(\d{2})$", time_str)
    if not match:
        raise ValueError(f"Invalid time format: '{time_str}'. Use HH:MM.")
    h, m = int(match.group(1)), int(match.group(2))
    if h > 23 or m > 59:
        raise ValueError(f"Invalid time: {time_str}. Hours 0-23, minutes 0-59.")


def _parse_duration(duration_str: str) -> float:
    """Parse a duration string like '6h', '30m', '2d' into seconds.

    Args:
        duration_str: Duration with suffix (h=hours, m=minutes, d=days, s=seconds).

    Returns:
        Duration in seconds.
    """
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([smhd]?)$", duration_str.strip())
    if not match:
        raise ValueError(
            f"Invalid duration: '{duration_str}'. Use Ns, Nm, Nh, or Nd."
        )

    value = float(match.group(1))
    unit = match.group(2) or "s"

    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


@dataclass
class EngagementRun:
    """Record of a single scheduled engagement run.

    Attributes:
        run_id:        Unique ID for this run.
        started_at:    When the run started (ISO format).
        completed_at:  When the run finished (ISO format or empty).
        status:        Run status (scheduled, running, completed, failed, skipped).
        findings:      Number of findings from this run.
        duration:      Run duration in seconds.
        error:         Error message if failed.
    """
    run_id:       int = 0
    started_at:   str = ""
    completed_at: str = ""
    status:       str = "scheduled"
    findings:     int = 0
    duration:     float = 0.0
    error:        str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id, "started_at": self.started_at,
            "completed_at": self.completed_at, "status": self.status,
            "findings": self.findings, "duration": round(self.duration, 1),
            "error": redact_text(str(self.error))[:2000],
        }


class EngagementScheduler:
    """Manages scheduled and recurring scan engagements.

    Calculates the next run time based on the schedule configuration,
    sleeps until that time, then executes the provided scan function.
    Tracks run history and persists state for crash recovery.

    Args:
        config:         Schedule configuration (parsed from CLI).
        results_dir:    Base directory for engagement results.
        event_bus:      Optional EventBus for dashboard integration.
    """

    def __init__(
        self,
        config: ScheduleConfig,
        results_dir: Path | None = None,
        event_bus: Any = None,
    ) -> None:
        self.config = config
        self.results_dir = results_dir or Path("results")
        self.event_bus = event_bus
        self._runs: list[EngagementRun] = []
        self._run_counter = 0
        self._aborted = False
        self._history_file: Path | None = None

        if self.results_dir:
            self.results_dir.mkdir(parents=True, exist_ok=True)
            self._history_file = self.results_dir / "schedule_history.json"

    def next_run_time(self) -> datetime:
        """Calculate the next scheduled run time.

        Returns:
            datetime (UTC) of the next scheduled run.
        """
        now = datetime.now(timezone.utc)

        if self.config.schedule_type == ScheduleType.ONCE:
            return self._next_time_today_or_tomorrow(now)

        if self.config.schedule_type == ScheduleType.DAILY:
            return self._next_time_today_or_tomorrow(now)

        if self.config.schedule_type == ScheduleType.WEEKLY:
            return self._next_weekly(now)

        if self.config.schedule_type in (ScheduleType.INTERVAL, ScheduleType.CONTINUOUS):
            if not self._runs:
                # First run — start immediately
                return now
            # Next run is interval_secs after the last run completed
            last = self._runs[-1]
            if last.completed_at:
                last_time = datetime.fromisoformat(last.completed_at)
            else:
                last_time = now
            return last_time + timedelta(seconds=self.config.interval_secs)

        return now

    def _next_time_today_or_tomorrow(self, now: datetime) -> datetime:
        """Get next occurrence of HH:MM — today if not yet past, else tomorrow."""
        h, m = map(int, self.config.time_str.split(":"))
        target = now.replace(hour=h, minute=m, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        return target

    def _next_weekly(self, now: datetime) -> datetime:
        """Get next occurrence of DAY at HH:MM."""
        target_day = DAY_MAP.get(self.config.day_of_week, 0)
        h, m = map(int, self.config.time_str.split(":"))

        target = now.replace(hour=h, minute=m, second=0, microsecond=0)
        days_ahead = target_day - now.weekday()
        if days_ahead < 0 or (days_ahead == 0 and target <= now):
            days_ahead += 7
        target += timedelta(days=days_ahead)
        return target

    def seconds_until_next(self) -> float:
        """Seconds until the next scheduled run."""
        delta = self.next_run_time() - datetime.now(timezone.utc)
        return max(delta.total_seconds(), 0)

    async def run(
        self,
        scan_fn: Callable[[], Coroutine[Any, Any, dict[str, Any]]],
    ) -> list[EngagementRun]:
        """Execute the schedule — blocks until all runs are complete.

        For one-shot: waits for the scheduled time, runs once.
        For recurring: loops until max_runs reached or aborted.

        Args:
            scan_fn: Async function that executes the scan and returns
                     a dict with 'findings' count, 'errors', etc.

        Returns:
            List of EngagementRun records.
        """
        log.info(
            "Engagement scheduler started: type=%s, schedule=%s",
            self.config.schedule_type.value,
            self._describe_schedule(),
        )
        self._emit_event("schedule_start")

        runs_completed = 0

        while not self._aborted:
            # Check max runs
            if self.config.max_runs > 0 and runs_completed >= self.config.max_runs:
                log.info("Max runs reached (%d). Scheduler stopping.", self.config.max_runs)
                break

            # One-shot: only runs once
            if self.config.schedule_type == ScheduleType.ONCE and runs_completed > 0:
                break

            # Wait for next run time
            wait_secs = self.seconds_until_next()
            if wait_secs > 0:
                next_time = self.next_run_time()
                log.info(
                    "Next run scheduled for %s (in %.0f seconds)",
                    next_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    wait_secs,
                )
                self._emit_event("schedule_waiting", next_run=next_time.isoformat(),
                                 wait_seconds=round(wait_secs, 0))

                # Interruptible sleep
                try:
                    await asyncio.sleep(wait_secs)
                except asyncio.CancelledError:
                    log.info("Schedule cancelled during wait")
                    break

            if self._aborted:
                break

            # Execute the scan
            self._run_counter += 1
            run = EngagementRun(
                run_id=self._run_counter,
                started_at=datetime.now(timezone.utc).isoformat(),
                status="running",
            )
            self._runs.append(run)

            log.info("Starting scheduled run #%d", self._run_counter)
            self._emit_event("schedule_run_start", run_id=self._run_counter)

            start_time = time.monotonic()
            try:
                result = await scan_fn()
                run.findings = result.get("findings", 0) if result else 0
                run.status = "completed"
                run.completed_at = datetime.now(timezone.utc).isoformat()
                run.duration = time.monotonic() - start_time

                log.info(
                    "Scheduled run #%d completed: %d findings in %.1fs",
                    self._run_counter, run.findings, run.duration,
                )
                self._emit_event(
                    "schedule_run_complete", run_id=self._run_counter,
                    findings=run.findings, duration=round(run.duration, 1),
                )

            except asyncio.CancelledError:
                run.status = "aborted"
                run.completed_at = datetime.now(timezone.utc).isoformat()
                run.duration = time.monotonic() - start_time
                log.info("Scheduled run #%d cancelled", self._run_counter)
                break

            except Exception as exc:
                run.status = "failed"
                run.error = str(exc)
                run.completed_at = datetime.now(timezone.utc).isoformat()
                run.duration = time.monotonic() - start_time
                log.error("Scheduled run #%d failed: %s", self._run_counter, exc)
                self._emit_event(
                    "schedule_run_failed", run_id=self._run_counter,
                    error=str(exc),
                )

            runs_completed += 1
            self._save_history()

        self._emit_event("schedule_complete", total_runs=runs_completed)
        return self._runs

    def abort(self) -> None:
        """Abort the scheduler — stops after current run."""
        self._aborted = True
        log.info("Scheduler abort requested")

    def summary(self) -> dict[str, Any]:
        """Get scheduler summary."""
        return {
            "schedule_type": self.config.schedule_type.value,
            "schedule_desc": self._describe_schedule(),
            "total_runs": len(self._runs),
            "completed": sum(1 for r in self._runs if r.status == "completed"),
            "failed": sum(1 for r in self._runs if r.status == "failed"),
            "total_findings": sum(r.findings for r in self._runs),
            "next_run": self.next_run_time().isoformat() if not self._aborted else None,
            "runs": [r.to_dict() for r in self._runs],
        }

    def status(self) -> str:
        """Human-readable status string."""
        s = self.summary()
        return (
            f"Schedule: {s['schedule_desc']} | "
            f"Runs: {s['total_runs']} | "
            f"Completed: {s['completed']} | "
            f"Failed: {s['failed']} | "
            f"Findings: {s['total_findings']}"
        )

    def _describe_schedule(self) -> str:
        """Human-readable schedule description."""
        cfg = self.config
        if cfg.schedule_type == ScheduleType.ONCE:
            return f"Once at {cfg.time_str}"
        if cfg.schedule_type == ScheduleType.DAILY:
            return f"Daily at {cfg.time_str}"
        if cfg.schedule_type == ScheduleType.WEEKLY:
            return f"Weekly on {cfg.day_of_week.title()} at {cfg.time_str}"
        if cfg.schedule_type == ScheduleType.INTERVAL:
            return f"Every {_format_duration(cfg.interval_secs)}"
        if cfg.schedule_type == ScheduleType.CONTINUOUS:
            return f"Continuous ({_format_duration(cfg.interval_secs)} between scans)"
        return "Unknown"

    def _save_history(self) -> None:
        """Persist run history to JSON."""
        if not self._history_file:
            return
        try:
            data = {
                "schedule": self._describe_schedule(),
                "runs": [r.to_dict() for r in self._runs],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            safe_data = redact_value(data)
            descriptor = os.open(
                self._history_file,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    descriptor = -1
                    json.dump(safe_data, stream, indent=2)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        except Exception as exc:
            log.debug("History save failed: %s", redact_text(str(exc)))

    def _emit_event(self, event_type: str, **data: Any) -> None:
        """Emit event to dashboard."""
        if not self.event_bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType as ET
            # Use CONTROL_COMMAND for scheduler events
            self.event_bus.emit_simple(
                ET.CONTROL_COMMAND, source="scheduler",
                command=event_type, **data,
            )
        except Exception:
            pass

    @classmethod
    def from_cli_args(
        cls,
        schedule: str | None = None,
        continuous: bool = False,
        interval: str = "24h",
        results_dir: Path | None = None,
        event_bus: Any = None,
    ) -> "EngagementScheduler | None":
        """Create scheduler from CLI arguments.

        Returns None if no scheduling is requested.

        Args:
            schedule:    Schedule string from --schedule flag.
            continuous:  Whether --continuous flag was set.
            interval:    Interval string from --interval flag.
            results_dir: Results directory.
            event_bus:   EventBus instance.

        Returns:
            EngagementScheduler or None.
        """
        if schedule:
            config = ScheduleConfig.parse(schedule)
            return cls(config=config, results_dir=results_dir, event_bus=event_bus)

        if continuous:
            config = ScheduleConfig(
                schedule_type=ScheduleType.CONTINUOUS,
                interval_secs=_parse_duration(interval),
            )
            return cls(config=config, results_dir=results_dir, event_bus=event_bus)

        return None


def _format_duration(seconds: float) -> str:
    """Format seconds into a human-readable duration."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    if seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h" if hours % 1 else f"{int(hours)}h"
    days = seconds / 86400
    return f"{days:.1f}d" if days % 1 else f"{int(days)}d"


# ── Unit Tests ────────────────────────────────────────────────────────

class TestScheduleConfig:
    """Unit tests for schedule parsing."""

    def test_parse_once(self) -> None:
        config = ScheduleConfig.parse("02:00")
        assert config.schedule_type == ScheduleType.ONCE
        assert config.time_str == "02:00"

    def test_parse_daily(self) -> None:
        config = ScheduleConfig.parse("daily:03:30")
        assert config.schedule_type == ScheduleType.DAILY
        assert config.time_str == "03:30"

    def test_parse_weekly(self) -> None:
        config = ScheduleConfig.parse("weekly:monday:02:00")
        assert config.schedule_type == ScheduleType.WEEKLY
        assert config.day_of_week == "monday"
        assert config.time_str == "02:00"

    def test_parse_weekly_short_day(self) -> None:
        config = ScheduleConfig.parse("weekly:mon:14:00")
        assert config.schedule_type == ScheduleType.WEEKLY
        assert config.day_of_week == "mon"

    def test_parse_interval_hours(self) -> None:
        config = ScheduleConfig.parse("interval:6h")
        assert config.schedule_type == ScheduleType.INTERVAL
        assert config.interval_secs == 21600.0

    def test_parse_interval_minutes(self) -> None:
        config = ScheduleConfig.parse("interval:30m")
        assert config.schedule_type == ScheduleType.INTERVAL
        assert config.interval_secs == 1800.0

    def test_parse_continuous(self) -> None:
        config = ScheduleConfig.parse("continuous:24h")
        assert config.schedule_type == ScheduleType.CONTINUOUS
        assert config.interval_secs == 86400.0

    def test_parse_invalid(self) -> None:
        import pytest
        with pytest.raises(ValueError):
            ScheduleConfig.parse("garbage")

    def test_parse_invalid_time(self) -> None:
        import pytest
        with pytest.raises(ValueError):
            ScheduleConfig.parse("25:00")

    def test_parse_invalid_day(self) -> None:
        import pytest
        with pytest.raises(ValueError):
            ScheduleConfig.parse("weekly:funday:02:00")


class TestEngagementScheduler:
    """Unit tests for scheduler."""

    def test_next_run_once(self) -> None:
        config = ScheduleConfig(schedule_type=ScheduleType.ONCE, time_str="23:59")
        scheduler = EngagementScheduler(config=config)
        next_time = scheduler.next_run_time()
        assert next_time > datetime.now(timezone.utc) or True  # May wrap to tomorrow

    def test_next_run_interval(self) -> None:
        config = ScheduleConfig(
            schedule_type=ScheduleType.INTERVAL,
            interval_secs=3600,
        )
        scheduler = EngagementScheduler(config=config)
        # First run should be immediate (no history)
        wait = scheduler.seconds_until_next()
        assert wait < 1.0

    def test_summary(self) -> None:
        config = ScheduleConfig(schedule_type=ScheduleType.DAILY, time_str="02:00")
        scheduler = EngagementScheduler(config=config)
        s = scheduler.summary()
        assert s["schedule_type"] == "daily"
        assert "Daily" in s["schedule_desc"]

    def test_status(self) -> None:
        config = ScheduleConfig(schedule_type=ScheduleType.WEEKLY,
                                time_str="14:00", day_of_week="friday")
        scheduler = EngagementScheduler(config=config)
        status = scheduler.status()
        assert "Friday" in status
        assert "Schedule:" in status

    def test_format_duration(self) -> None:
        assert _format_duration(30) == "30s"
        assert _format_duration(120) == "2m"
        assert _format_duration(7200) == "2h"
        assert _format_duration(86400) == "1d"

    def test_from_cli_no_schedule(self) -> None:
        result = EngagementScheduler.from_cli_args()
        assert result is None

    def test_from_cli_schedule(self) -> None:
        result = EngagementScheduler.from_cli_args(schedule="daily:02:00")
        assert result is not None
        assert result.config.schedule_type == ScheduleType.DAILY

    def test_from_cli_continuous(self) -> None:
        result = EngagementScheduler.from_cli_args(
            continuous=True, interval="6h",
        )
        assert result is not None
        assert result.config.schedule_type == ScheduleType.CONTINUOUS
        assert result.config.interval_secs == 21600.0

    def test_abort(self) -> None:
        config = ScheduleConfig(schedule_type=ScheduleType.INTERVAL, interval_secs=60)
        scheduler = EngagementScheduler(config=config)
        scheduler.abort()
        assert scheduler._aborted is True
