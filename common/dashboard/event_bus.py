"""Thread-safe event bus for real-time dashboard communication.

The EventBus sits between module execution and dashboard rendering.
Modules publish events (findings, status changes, metrics) and
dashboard components subscribe to event types they care about.

Supports both sync (threading) and async (asyncio) consumers.
"""
from __future__ import annotations

import asyncio
import json
import logging
import queue
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

log = logging.getLogger("forge.dashboard.events")


class EventType(str, Enum):
    """All event types the dashboard can consume."""

    # ── Scan lifecycle ────────────────────────────────────────────────
    SCAN_START          = "scan_start"
    SCAN_COMPLETE       = "scan_complete"
    SCAN_INTERRUPTED    = "scan_interrupted"
    SCAN_PAUSED         = "scan_paused"
    SCAN_RESUMED        = "scan_resumed"
    SCAN_ABORTED        = "scan_aborted"

    # ── Phase lifecycle ───────────────────────────────────────────────
    PHASE_START         = "phase_start"
    PHASE_COMPLETE      = "phase_complete"

    # ── Module lifecycle ──────────────────────────────────────────────
    MODULE_START        = "module_start"
    MODULE_PROGRESS     = "module_progress"
    MODULE_COMPLETE     = "module_complete"
    MODULE_FAIL         = "module_fail"
    MODULE_SKIP         = "module_skip"

    # ── Findings ──────────────────────────────────────────────────────
    FINDING_NEW         = "finding_new"
    FINDING_UPDATED     = "finding_updated"

    # ── Network / HTTP metrics ────────────────────────────────────────
    REQUEST_SENT        = "request_sent"
    REQUEST_ERROR       = "request_error"
    WAF_BLOCK           = "waf_block"
    RATE_LIMIT_HIT      = "rate_limit_hit"

    # ── Credentials ───────────────────────────────────────────────────
    CREDENTIAL_FOUND    = "credential_found"

    # ── Target status ─────────────────────────────────────────────────
    TARGET_DISCOVERED   = "target_discovered"
    TARGET_PWNED        = "target_pwned"
    TARGET_QUEUED       = "target_queued"
    TARGET_SCANNING     = "target_scanning"
    TARGET_PAUSED       = "target_paused"
    TARGET_COMPLETED    = "target_completed"
    TARGET_FAILED       = "target_failed"
    SHELL_SESSION       = "shell_session"

    # ── Operator actions ──────────────────────────────────────────────
    CONFIRM_PROMPTED    = "confirm_prompted"
    CONFIRM_ACCEPTED    = "confirm_accepted"
    CONFIRM_DECLINED    = "confirm_declined"

    # ── C2 Framework ─────────────────────────────────────────────────
    BEACON_CHECKIN      = "beacon_checkin"
    BEACON_NEW          = "beacon_new"
    BEACON_DEAD         = "beacon_dead"
    BEACON_TASK_SENT    = "beacon_task_sent"
    BEACON_TASK_RESULT  = "beacon_task_result"
    LISTENER_START      = "listener_start"
    LISTENER_STOP       = "listener_stop"
    C2_OPERATOR_JOIN    = "c2_operator_join"
    C2_OPERATOR_LEAVE   = "c2_operator_leave"

    # ── Post-Exploitation ─────────────────────────────────────────────
    LATERAL_MOVE        = "lateral_move"
    PERSISTENCE_SET     = "persistence_set"
    ROOTKIT_DEPLOYED    = "rootkit_deployed"
    DATA_STAGED         = "data_staged"
    DATA_EXFILTRATED    = "data_exfiltrated"

    # ── Intel Pipeline ────────────────────────────────────────────────
    INTEL_SYNC_START    = "intel_sync_start"
    INTEL_SYNC_COMPLETE = "intel_sync_complete"
    INTEL_CVE_NEW       = "intel_cve_new"

    # ── Payload Generation ────────────────────────────────────────────
    PAYLOAD_GENERATED   = "payload_generated"

    # ── Brain / AI ────────────────────────────────────────────────────
    BRAIN_VERDICT       = "brain_verdict"
    CHAIN_ACTION_NEW    = "chain_action_new"

    # ── Dashboard internal ────────────────────────────────────────────
    STATE_SNAPSHOT      = "state_snapshot"
    HEARTBEAT           = "heartbeat"
    CONTROL_COMMAND     = "control_command"


@dataclass
class Event:
    """A single event emitted by a module or the scan orchestrator.

    Attributes:
        event_type: Category of event (from EventType enum).
        data:       Payload dict — contents vary by event type.
        source:     Module or component that emitted the event.
        timestamp:  UTC ISO-8601 timestamp.
        event_id:   Unique identifier for dedup/replay.
        run_id:     Scan run UUID for correlation.
    """

    event_type: EventType
    data:       dict[str, Any] = field(default_factory=dict)
    source:     str            = ""
    timestamp:  str            = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_id:   str            = field(default_factory=lambda: str(uuid.uuid4())[:8])
    run_id:     str            = ""

    def to_json(self) -> str:
        """Serialize for WebSocket transmission."""
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return json.dumps(d, default=str)

    @classmethod
    def from_json(cls, raw: str) -> "Event":
        """Deserialize from WebSocket message."""
        d = json.loads(raw)
        d["event_type"] = EventType(d["event_type"])
        return cls(**d)


# Subscriber callback signature: receives the Event object
Subscriber = Callable[[Event], None]
AsyncSubscriber = Callable[[Event], Any]  # coroutine


class EventBus:
    """Thread-safe publish/subscribe event bus.

    Publishers call emit() from any thread (module execution threads).
    Subscribers register via subscribe() and get called on the bus's
    dispatch thread, or via async_subscribe() for asyncio consumers.

    Usage::

        bus = EventBus()
        bus.start()

        # Subscribe (sync)
        bus.subscribe(EventType.FINDING_NEW, my_callback)

        # Subscribe (async — for web dashboard WebSocket push)
        bus.async_subscribe(EventType.FINDING_NEW, my_async_callback)

        # Publish from a module
        bus.emit(Event(EventType.FINDING_NEW, data={...}, source="sqli_scanner"))

        # Shutdown
        bus.stop()
    """

    def __init__(self, run_id: str = "", history_size: int = 10_000) -> None:
        """Initialize the event bus.

        Args:
            run_id:       Scan run UUID stamped on all events.
            history_size: Max events kept in replay buffer.
        """
        self.run_id = run_id
        self._queue: queue.Queue[Event | None] = queue.Queue(maxsize=50_000)
        self._subscribers: dict[EventType, list[Subscriber]] = {}
        self._async_subscribers: dict[EventType, list[AsyncSubscriber]] = {}
        self._wildcard_subscribers: list[Subscriber] = []
        self._async_wildcard_subscribers: list[AsyncSubscriber] = []
        self._history: list[Event] = []
        self._history_size = history_size
        self._lock = threading.Lock()
        self._dispatch_thread: threading.Thread | None = None
        self._running = False
        self._event_count = 0
        self._loop: asyncio.AbstractEventLoop | None = None

    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Start the dispatch thread.

        Args:
            loop: asyncio event loop for scheduling async subscribers.
                  If None, async subscribers won't fire.
        """
        if self._running:
            return
        self._running = True
        self._loop = loop
        self._dispatch_thread = threading.Thread(
            target=self._dispatch_loop,
            name="EventBus-Dispatch",
            daemon=True,
        )
        self._dispatch_thread.start()
        log.debug("EventBus started (run_id=%s)", self.run_id)

    def stop(self) -> None:
        """Stop the dispatch thread gracefully."""
        if not self._running:
            return
        self._running = False
        self._queue.put(None)  # sentinel to unblock
        if self._dispatch_thread:
            self._dispatch_thread.join(timeout=5.0)
        log.debug("EventBus stopped (%d events processed)", self._event_count)

    def emit(self, event: Event) -> None:
        """Publish an event to the bus (thread-safe, non-blocking).

        Args:
            event: The Event to publish.
        """
        if not event.run_id:
            event.run_id = self.run_id
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            log.warning("EventBus queue full — dropping event: %s", event.event_type.value)

    def emit_simple(
        self,
        event_type: EventType,
        source: str = "",
        **data: Any,
    ) -> None:
        """Convenience method: emit an event with keyword data.

        Args:
            event_type: Type of event to emit.
            source:     Emitting module name.
            **data:     Keyword arguments become the event data dict.
        """
        self.emit(Event(
            event_type=event_type,
            data=data,
            source=source,
            run_id=self.run_id,
        ))

    def subscribe(self, event_type: EventType | None, callback: Subscriber) -> None:
        """Register a sync subscriber for a specific event type.

        Args:
            event_type: Type to subscribe to, or None for wildcard (all events).
            callback:   Function called with each matching Event.
        """
        with self._lock:
            if event_type is None:
                self._wildcard_subscribers.append(callback)
            else:
                self._subscribers.setdefault(event_type, []).append(callback)

    def async_subscribe(self, event_type: EventType | None, callback: AsyncSubscriber) -> None:
        """Register an async subscriber for a specific event type.

        Args:
            event_type: Type to subscribe to, or None for wildcard.
            callback:   Async function called with each matching Event.
        """
        with self._lock:
            if event_type is None:
                self._async_wildcard_subscribers.append(callback)
            else:
                self._async_subscribers.setdefault(event_type, []).append(callback)

    def unsubscribe(self, event_type: EventType | None, callback: Subscriber) -> None:
        """Remove a sync subscriber."""
        with self._lock:
            if event_type is None:
                if callback in self._wildcard_subscribers:
                    self._wildcard_subscribers.remove(callback)
            else:
                subs = self._subscribers.get(event_type, [])
                if callback in subs:
                    subs.remove(callback)

    def get_history(
        self,
        event_type: EventType | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Return recent events from the replay buffer.

        Args:
            event_type: Filter by type, or None for all.
            limit:      Max events to return.

        Returns:
            List of Events, newest first.
        """
        with self._lock:
            if event_type:
                filtered = [e for e in self._history if e.event_type == event_type]
            else:
                filtered = list(self._history)
            return filtered[-limit:]

    @property
    def event_count(self) -> int:
        """Total number of events processed since start."""
        return self._event_count

    @property
    def queue_size(self) -> int:
        """Current number of events waiting in the dispatch queue."""
        return self._queue.qsize()

    def _dispatch_loop(self) -> None:
        """Internal dispatch thread — routes events to subscribers."""
        while self._running:
            try:
                event = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if event is None:  # sentinel
                break

            self._event_count += 1

            # Store in history
            with self._lock:
                self._history.append(event)
                if len(self._history) > self._history_size:
                    self._history = self._history[-self._history_size:]

            # Dispatch to sync subscribers
            with self._lock:
                type_subs = list(self._subscribers.get(event.event_type, []))
                wildcard_subs = list(self._wildcard_subscribers)

            for cb in type_subs + wildcard_subs:
                try:
                    cb(event)
                except Exception as exc:
                    log.error(
                        "Subscriber error on %s: %s",
                        event.event_type.value, exc,
                    )

            # Dispatch to async subscribers
            if self._loop and not self._loop.is_closed():
                with self._lock:
                    async_type_subs = list(self._async_subscribers.get(event.event_type, []))
                    async_wildcard_subs = list(self._async_wildcard_subscribers)

                for cb in async_type_subs + async_wildcard_subs:
                    try:
                        self._loop.call_soon_threadsafe(
                            asyncio.ensure_future,
                            cb(event),
                        )
                    except RuntimeError:
                        # Loop closed between check and call
                        pass
                    except Exception as exc:
                        log.error(
                            "Async subscriber error on %s: %s",
                            event.event_type.value, exc,
                        )


class RemoteEventBus:
    """Forwards events to a remote dashboard process via HTTP POST.

    Drop-in replacement for EventBus when the scan runs in a separate
    process from the dashboard.  Uses only stdlib so no extra deps.

    Usage::

        bus = RemoteEventBus("http://localhost:1337", run_id="scan-001")
        bus.start()
        bus.emit(Event(EventType.FINDING_NEW, data={...}, source="sqli"))
        bus.stop()
    """

    def __init__(self, url: str, run_id: str = "") -> None:
        self.url = url.rstrip("/")
        self.run_id = run_id
        self._queue: queue.Queue[Event | None] = queue.Queue(maxsize=10_000)
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self, loop: Any = None) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._send_loop,
            name="RemoteEventBus-Send",
            daemon=True,
        )
        self._thread.start()
        log.debug("RemoteEventBus started → %s", self.url)

    def stop(self) -> None:
        self._running = False
        self._queue.put(None)
        if self._thread:
            self._thread.join(timeout=5.0)

    def emit(self, event: Event) -> None:
        if not event.run_id:
            event.run_id = self.run_id
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            log.warning("RemoteEventBus queue full — dropping %s", event.event_type.value)

    def emit_simple(
        self,
        event_type: EventType,
        source: str = "",
        **data: Any,
    ) -> None:
        self.emit(Event(
            event_type=event_type,
            data=data,
            source=source,
            run_id=self.run_id,
        ))

    # No-op stubs so code that calls subscribe/async_subscribe doesn't crash
    def subscribe(self, *_: Any, **__: Any) -> None:
        pass

    def async_subscribe(self, *_: Any, **__: Any) -> None:
        pass

    def _send_loop(self) -> None:
        import ssl
        import urllib.request
        endpoint = f"{self.url}/api/v1/events/emit"
        # Allow self-signed certs on local dashboard
        _ssl_ctx = ssl.create_default_context()
        _ssl_ctx.check_hostname = False
        _ssl_ctx.verify_mode = ssl.CERT_NONE
        while self._running:
            try:
                event = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if event is None:
                break
            try:
                payload = event.to_json().encode()
                req = urllib.request.Request(
                    endpoint,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=2, context=_ssl_ctx) as _:
                    pass
            except Exception as exc:
                log.debug("RemoteEventBus send failed: %s", exc)


class TestEventBus:
    """Unit tests for event_bus module."""

    def test_emit_and_subscribe(self) -> None:
        bus = EventBus(run_id="test-run")
        bus.start()
        received: list[Event] = []
        bus.subscribe(EventType.FINDING_NEW, lambda e: received.append(e))

        bus.emit(Event(
            event_type=EventType.FINDING_NEW,
            data={"title": "SQLi", "severity": "High"},
            source="sqli_scanner",
        ))

        time.sleep(0.2)
        bus.stop()
        assert len(received) == 1
        assert received[0].data["title"] == "SQLi"
        assert received[0].run_id == "test-run"

    def test_wildcard_subscriber(self) -> None:
        bus = EventBus()
        bus.start()
        received: list[Event] = []
        bus.subscribe(None, lambda e: received.append(e))

        bus.emit_simple(EventType.MODULE_START, source="test_mod", name="test")
        bus.emit_simple(EventType.FINDING_NEW, source="test_mod", title="XSS")

        time.sleep(0.2)
        bus.stop()
        assert len(received) == 2

    def test_history(self) -> None:
        bus = EventBus()
        bus.start()
        for i in range(5):
            bus.emit_simple(EventType.HEARTBEAT, source="test", count=i)
        time.sleep(0.3)
        bus.stop()
        history = bus.get_history(EventType.HEARTBEAT, limit=3)
        assert len(history) == 3

    def test_event_serialization(self) -> None:
        event = Event(
            event_type=EventType.FINDING_NEW,
            data={"title": "Test", "severity": "High"},
            source="test_module",
            run_id="run-123",
        )
        json_str = event.to_json()
        restored = Event.from_json(json_str)
        assert restored.event_type == EventType.FINDING_NEW
        assert restored.data["title"] == "Test"
        assert restored.run_id == "run-123"

    def test_queue_overflow_doesnt_crash(self) -> None:
        bus = EventBus()
        # Don't start — queue will fill up
        for _ in range(60_000):
            bus.emit_simple(EventType.HEARTBEAT, source="test")
        # Should not raise, just log warnings
        assert bus.queue_size <= 50_000
