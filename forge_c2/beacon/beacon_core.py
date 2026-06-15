"""Forge C2 — Beacon Core.

Manages beacon lifecycle: registration, check-in, tasking, results,
sleep/jitter control, kill dates, and metadata collection.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from forge_c2.beacon.beacon_crypto import BeaconCrypto, SessionKeys

log = logging.getLogger("forge.c2.beacon")


class BeaconState(str, Enum):
    """Lifecycle state of a beacon."""
    STAGING     = "staging"      # Waiting for initial check-in
    ACTIVE      = "active"       # Checking in regularly
    SLEEPING    = "sleeping"     # Extended sleep
    DEAD        = "dead"         # Missed too many check-ins
    KILLED      = "killed"       # Operator killed it


class BeaconArch(str, Enum):
    """Beacon architecture."""
    X64     = "x64"
    X86     = "x86"
    ARM64   = "arm64"


class BeaconOS(str, Enum):
    """Beacon operating system."""
    WINDOWS = "windows"
    LINUX   = "linux"
    MACOS   = "macos"


@dataclass
class BeaconTask:
    """A task queued for execution by a beacon."""
    task_id:      str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    command:      str = ""        # shell, download, upload, screenshot, etc.
    args:         dict[str, Any] = field(default_factory=dict)
    created_at:   float = field(default_factory=time.time)
    sent_at:      float = 0.0
    completed_at: float = 0.0
    status:       str = "queued"  # queued, sent, completed, failed
    result:       Any = None
    operator:     str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id, "command": self.command,
            "args": self.args, "status": self.status,
            "operator": self.operator,
        }


@dataclass
class BeaconMetadata:
    """System information collected on first check-in."""
    hostname:     str = ""
    username:     str = ""
    domain:       str = ""
    os_version:   str = ""
    os_arch:      BeaconArch = BeaconArch.X64
    os_type:      BeaconOS = BeaconOS.WINDOWS
    pid:          int = 0
    process_name: str = ""
    integrity:    str = ""        # Low, Medium, High, SYSTEM
    is_admin:     bool = False
    is_domain:    bool = False
    interfaces:   list[str] = field(default_factory=list)
    av_products:  list[str] = field(default_factory=list)
    internal_ip:  str = ""
    external_ip:  str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname, "username": self.username,
            "domain": self.domain, "os_version": self.os_version,
            "os_arch": self.os_arch.value, "os_type": self.os_type.value,
            "pid": self.pid, "process_name": self.process_name,
            "integrity": self.integrity, "is_admin": self.is_admin,
            "is_domain": self.is_domain, "interfaces": self.interfaces,
            "av_products": self.av_products,
            "internal_ip": self.internal_ip, "external_ip": self.external_ip,
        }


@dataclass
class Beacon:
    """A single C2 beacon instance.

    Tracks lifecycle, tasks, metadata, and cryptographic session.
    """
    beacon_id:      str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    state:          BeaconState = BeaconState.STAGING
    metadata:       BeaconMetadata = field(default_factory=BeaconMetadata)
    session:        SessionKeys | None = None

    # Timing
    registered_at:  float = field(default_factory=time.time)
    last_checkin:   float = 0.0
    sleep_seconds:  float = 60.0
    jitter_pct:     float = 20.0    # ±20% jitter
    kill_date:      float = 0.0     # 0 = no kill date

    # Task management
    task_queue:     list[BeaconTask] = field(default_factory=list)
    task_history:   list[BeaconTask] = field(default_factory=list)

    # Tracking
    checkin_count:  int = 0
    missed_checkins: int = 0
    max_missed:     int = 10
    transport:      str = "https"

    # Pivot
    parent_beacon:  str | None = None  # For chained beacons
    child_beacons:  list[str] = field(default_factory=list)

    def checkin(self) -> list[BeaconTask]:
        """Process a beacon check-in.

        Returns pending tasks to send to the beacon.
        """
        self.last_checkin = time.time()
        self.checkin_count += 1
        self.missed_checkins = 0

        if self.state == BeaconState.STAGING:
            self.state = BeaconState.ACTIVE
            log.info("Beacon %s activated (hostname=%s, user=%s)",
                     self.beacon_id, self.metadata.hostname, self.metadata.username)

        # Check kill date
        if self.kill_date > 0 and time.time() > self.kill_date:
            self.state = BeaconState.KILLED
            return [BeaconTask(command="exit", args={"reason": "kill_date"})]

        # Dequeue pending tasks
        pending = [t for t in self.task_queue if t.status == "queued"]
        for task in pending:
            task.status = "sent"
            task.sent_at = time.time()
        return pending

    def queue_task(self, command: str, operator: str = "", **args: Any) -> BeaconTask:
        """Queue a task for execution on next check-in."""
        task = BeaconTask(
            command=command, args=args, operator=operator,
        )
        self.task_queue.append(task)
        log.info("Task queued for beacon %s: %s (id=%s)",
                 self.beacon_id, command, task.task_id)
        return task

    def complete_task(self, task_id: str, result: Any, success: bool = True) -> None:
        """Mark a task as completed with results."""
        for task in self.task_queue:
            if task.task_id == task_id:
                task.status = "completed" if success else "failed"
                task.completed_at = time.time()
                task.result = result
                self.task_history.append(task)
                self.task_queue.remove(task)
                log.info("Task %s completed for beacon %s (success=%s)",
                         task_id, self.beacon_id, success)
                return
        log.warning("Task %s not found for beacon %s", task_id, self.beacon_id)

    def mark_missed(self) -> None:
        """Mark a missed check-in. Beacon goes dead after max_missed."""
        self.missed_checkins += 1
        if self.missed_checkins >= self.max_missed:
            self.state = BeaconState.DEAD
            log.warning("Beacon %s marked DEAD (%d missed check-ins)",
                        self.beacon_id, self.missed_checkins)

    def kill(self) -> BeaconTask:
        """Kill the beacon — sends exit task."""
        self.state = BeaconState.KILLED
        return self.queue_task("exit", args={"reason": "operator_kill"})

    def set_sleep(self, seconds: float, jitter_pct: float = 20.0) -> None:
        """Update sleep interval and jitter."""
        self.sleep_seconds = max(1.0, seconds)
        self.jitter_pct = max(0.0, min(90.0, jitter_pct))
        log.info("Beacon %s sleep updated: %.1fs / %.0f%% jitter",
                 self.beacon_id, self.sleep_seconds, self.jitter_pct)

    @property
    def is_alive(self) -> bool:
        return self.state in (BeaconState.ACTIVE, BeaconState.SLEEPING)

    @property
    def time_since_checkin(self) -> float:
        if self.last_checkin == 0:
            return time.time() - self.registered_at
        return time.time() - self.last_checkin

    @property
    def expected_checkin(self) -> float:
        """Expected seconds until next check-in."""
        if self.last_checkin == 0:
            return 0.0
        return max(0.0, self.sleep_seconds - self.time_since_checkin)

    def to_dict(self) -> dict[str, Any]:
        return {
            "beacon_id": self.beacon_id,
            "state": self.state.value,
            "metadata": self.metadata.to_dict(),
            "sleep_seconds": self.sleep_seconds,
            "jitter_pct": self.jitter_pct,
            "last_checkin": self.last_checkin,
            "checkin_count": self.checkin_count,
            "missed_checkins": self.missed_checkins,
            "transport": self.transport,
            "pending_tasks": len([t for t in self.task_queue if t.status == "queued"]),
            "completed_tasks": len(self.task_history),
            "time_since_checkin": round(self.time_since_checkin, 1),
            "is_alive": self.is_alive,
            "parent_beacon": self.parent_beacon,
            "child_beacons": self.child_beacons,
        }


class BeaconRegistry:
    """Registry of all active beacons.

    Manages beacon lifecycle, dead-beacon detection, and task routing.
    """

    def __init__(self, crypto: BeaconCrypto | None = None) -> None:
        self.crypto = crypto or BeaconCrypto()
        self._beacons: dict[str, Beacon] = {}

    def register(self, metadata: dict[str, Any] | None = None,
                 transport: str = "https") -> Beacon:
        """Register a new beacon."""
        beacon = Beacon(transport=transport)
        if metadata:
            beacon.metadata = BeaconMetadata(**{
                k: v for k, v in metadata.items()
                if k in BeaconMetadata.__dataclass_fields__
            })
        beacon.session = self.crypto.create_session(beacon.beacon_id)
        self._beacons[beacon.beacon_id] = beacon
        log.info("Beacon registered: %s (transport=%s)", beacon.beacon_id, transport)
        return beacon

    def get(self, beacon_id: str) -> Beacon | None:
        return self._beacons.get(beacon_id)

    def remove(self, beacon_id: str) -> None:
        if beacon_id in self._beacons:
            self.crypto.remove_session(beacon_id)
            del self._beacons[beacon_id]

    def active_beacons(self) -> list[Beacon]:
        return [b for b in self._beacons.values() if b.is_alive]

    def all_beacons(self) -> list[Beacon]:
        return list(self._beacons.values())

    def check_dead_beacons(self) -> list[str]:
        """Check for beacons that have missed too many check-ins.

        Returns list of beacon IDs that were marked dead.
        """
        newly_dead: list[str] = []
        for beacon in self._beacons.values():
            if beacon.is_alive and beacon.time_since_checkin > beacon.sleep_seconds * 3:
                beacon.mark_missed()
                if beacon.state == BeaconState.DEAD:
                    newly_dead.append(beacon.beacon_id)
        return newly_dead

    def summary(self) -> dict[str, Any]:
        counts = {s.value: 0 for s in BeaconState}
        for b in self._beacons.values():
            counts[b.state.value] += 1
        return {
            "total": len(self._beacons),
            "states": counts,
            "beacons": [b.to_dict() for b in self._beacons.values()],
        }


class TestBeaconCore:
    """Unit tests for beacon_core."""

    def test_register_and_checkin(self) -> None:
        registry = BeaconRegistry()
        beacon = registry.register(
            metadata={"hostname": "DESKTOP-ABC", "username": "admin"},
        )
        assert beacon.state == BeaconState.STAGING
        tasks = beacon.checkin()
        assert beacon.state == BeaconState.ACTIVE
        assert beacon.checkin_count == 1
        assert tasks == []

    def test_task_lifecycle(self) -> None:
        registry = BeaconRegistry()
        beacon = registry.register()
        beacon.checkin()  # Activate

        task = beacon.queue_task("shell", operator="tester", cmd="whoami")
        assert task.status == "queued"

        pending = beacon.checkin()
        assert len(pending) == 1
        assert pending[0].status == "sent"

        beacon.complete_task(task.task_id, result="SYSTEM", success=True)
        assert len(beacon.task_history) == 1

    def test_dead_detection(self) -> None:
        registry = BeaconRegistry()
        beacon = registry.register()
        beacon.checkin()
        beacon.sleep_seconds = 0.01  # Very short sleep
        beacon.max_missed = 2

        import time as _time
        _time.sleep(0.05)
        beacon.mark_missed()
        assert beacon.state == BeaconState.ACTIVE
        beacon.mark_missed()
        assert beacon.state == BeaconState.DEAD

    def test_kill(self) -> None:
        registry = BeaconRegistry()
        beacon = registry.register()
        beacon.checkin()
        task = beacon.kill()
        assert beacon.state == BeaconState.KILLED
        assert task.command == "exit"

    def test_summary(self) -> None:
        registry = BeaconRegistry()
        b1 = registry.register()
        b2 = registry.register()
        b1.checkin()
        s = registry.summary()
        assert s["total"] == 2
        assert s["states"]["active"] == 1
        assert s["states"]["staging"] == 1
