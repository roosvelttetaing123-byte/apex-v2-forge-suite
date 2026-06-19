"""ForgeCollab — Out-of-Band Callback Server.

Burp Collaborator equivalent for blind vulnerability confirmation.
Runs DNS + HTTP + SMTP listeners and correlates callbacks to test tokens.

Critical for: blind SQLi, blind SSRF, blind XXE, blind XSS, blind CMDi,
Log4Shell, JNDI injection — any vuln that requires OOB proof.

Architecture:
    Each test payload embeds a unique token (UUID). When the vulnerable
    target makes an outbound request to our server, the callback is logged
    and correlated back to the originating test via token lookup.

    ┌─────────┐   payload w/ token   ┌─────────┐   OOB callback   ┌──────────────┐
    │  Module  │ ──────────────────→  │  Target  │ ──────────────→  │ ForgeCollab   │
    │ (scanner)│                      │  (vuln)  │                  │ (this server) │
    └─────────┘                      └─────────┘                  └──────┬───────┘
         │                                                               │
         │  poll /api/callbacks/{token}                                  │
         └───────────────────────────────────────────────────────────────┘

Modes:
    - Hosted: operator provides VPS IP + domain → ForgeCollab runs there
    - Local:  runs on local machine for internal network tests

Usage:
    python3 forge.py collab start --domain collab.example.com
    python3 forge.py collab start --local --port 8888

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("forge.collab")


# ══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════

class CallbackType(str, Enum):
    """Type of OOB callback received."""
    DNS       = "dns"
    HTTP      = "http"
    HTTPS     = "https"
    SMTP      = "smtp"
    LDAP      = "ldap"
    FTP       = "ftp"


class InteractionProtocol(str, Enum):
    """Protocol used in the interaction."""
    DNS   = "dns"
    HTTP  = "http"
    SMTP  = "smtp"


@dataclass
class Callback:
    """A single OOB callback received by the server.

    Attributes:
        token:        UUID token embedded in the test payload.
        callback_type: Protocol used (DNS/HTTP/SMTP).
        source_ip:    IP of the requesting host (the vulnerable target).
        source_port:  Port of the requesting host.
        timestamp:    When the callback was received (UTC ISO-8601).
        raw_data:     Protocol-specific raw data.
        details:      Parsed protocol-specific details.
        callback_id:  Unique ID for this specific callback event.
    """
    token:          str
    callback_type:  CallbackType
    source_ip:      str
    source_port:    int               = 0
    timestamp:      str               = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_data:       bytes             = field(default=b"", repr=False)
    details:        dict[str, Any]    = field(default_factory=dict)
    callback_id:    str               = field(default_factory=lambda: str(uuid.uuid4())[:12])

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON API response."""
        d = asdict(self)
        d["callback_type"] = self.callback_type.value
        d["raw_data"] = self.raw_data.hex() if self.raw_data else ""
        return d


@dataclass
class CollabToken:
    """A registered OOB test token.

    Created by a scanner module before injecting the payload.
    Modules poll for callbacks matching their token.

    Attributes:
        token:       UUID string embedded in the payload.
        module:      Module that created the token.
        vuln_type:   Type of vulnerability being tested.
        target:      Target URL/IP being tested.
        param:       Parameter being injected into.
        created_at:  When the token was registered.
        callbacks:   List of callbacks received for this token.
        notified:    Whether the module has been notified of a callback.
    """
    token:       str
    module:      str            = ""
    vuln_type:   str            = ""
    target:      str            = ""
    param:       str            = ""
    created_at:  str            = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    callbacks:   list[Callback] = field(default_factory=list)
    notified:    bool           = False


# ══════════════════════════════════════════════════════════════════════
# TOKEN REGISTRY
# ══════════════════════════════════════════════════════════════════════

class TokenRegistry:
    """Thread-safe registry of OOB test tokens and their callbacks.

    Central data store shared by all protocol listeners.
    Modules register tokens before injecting payloads, then poll
    or subscribe for callbacks.
    """

    def __init__(self, max_tokens: int = 50_000) -> None:
        self._tokens: dict[str, CollabToken] = {}
        self._lock = threading.Lock()
        self._max_tokens = max_tokens
        self._subscribers: list[Callable[[CollabToken, Callback], None]] = []
        self._async_subscribers: list[Callable[[CollabToken, Callback], Any]] = []
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Set the asyncio event loop for async subscriber dispatch."""
        self._loop = loop

    def register(
        self,
        module: str = "",
        vuln_type: str = "",
        target: str = "",
        param: str = "",
        token: str | None = None,
    ) -> str:
        """Register a new OOB test token.

        Args:
            module:    Name of the scanner module.
            vuln_type: Vulnerability type (sqli, ssrf, xxe, xss, cmdi, etc.).
            target:    Target URL/IP.
            param:     Parameter name being tested.
            token:     Optional pre-generated token. If None, a UUID is created.

        Returns:
            The token string to embed in payloads.
        """
        tok = token or str(uuid.uuid4()).replace("-", "")[:24]
        with self._lock:
            # Evict oldest tokens if at capacity
            if len(self._tokens) >= self._max_tokens:
                oldest = sorted(self._tokens.values(), key=lambda t: t.created_at)
                for old in oldest[:1000]:
                    del self._tokens[old.token]
                log.debug("Evicted 1000 oldest tokens (registry at capacity)")

            self._tokens[tok] = CollabToken(
                token=tok,
                module=module,
                vuln_type=vuln_type,
                target=target,
                param=param,
            )
        log.debug("Registered OOB token %s for %s/%s → %s", tok[:8], module, vuln_type, target)
        return tok

    def record_callback(self, callback: Callback) -> CollabToken | None:
        """Record an incoming callback against its token.

        Args:
            callback: The received Callback object.

        Returns:
            The matching CollabToken if found, None if token unknown.
        """
        with self._lock:
            collab_token = self._tokens.get(callback.token)
            if collab_token is None:
                # Unknown token — log but don't crash. Could be noise or
                # a delayed callback from a previous engagement.
                log.warning(
                    "OOB callback from %s for unknown token %s (%s)",
                    callback.source_ip, callback.token[:8], callback.callback_type.value,
                )
                return None

            collab_token.callbacks.append(callback)

        log.info(
            "[OOB] %s callback from %s for token %s (%s/%s → %s)",
            callback.callback_type.value.upper(),
            callback.source_ip,
            callback.token[:8],
            collab_token.module,
            collab_token.vuln_type,
            collab_token.target,
        )

        # Notify subscribers
        for sub in self._subscribers:
            try:
                sub(collab_token, callback)
            except Exception as exc:
                log.error("Callback subscriber error: %s", exc)

        # Notify async subscribers
        if self._loop and not self._loop.is_closed():
            for sub in self._async_subscribers:
                try:
                    self._loop.call_soon_threadsafe(
                        asyncio.ensure_future,
                        sub(collab_token, callback),
                    )
                except RuntimeError:
                    pass

        return collab_token

    def get_callbacks(self, token: str) -> list[Callback]:
        """Get all callbacks for a specific token.

        Args:
            token: The token string.

        Returns:
            List of Callback objects. Empty list if token not found.
        """
        with self._lock:
            ct = self._tokens.get(token)
            return list(ct.callbacks) if ct else []

    def has_callback(self, token: str) -> bool:
        """Check if any callbacks have been received for a token.

        Args:
            token: The token string.

        Returns:
            True if at least one callback exists.
        """
        with self._lock:
            ct = self._tokens.get(token)
            return bool(ct and ct.callbacks)

    def get_token_info(self, token: str) -> CollabToken | None:
        """Get the full CollabToken object."""
        with self._lock:
            return self._tokens.get(token)

    def subscribe(self, callback: Callable[[CollabToken, Callback], None]) -> None:
        """Register a sync subscriber for callback notifications."""
        self._subscribers.append(callback)

    def async_subscribe(self, callback: Callable[[CollabToken, Callback], Any]) -> None:
        """Register an async subscriber for callback notifications."""
        self._async_subscribers.append(callback)

    @property
    def stats(self) -> dict[str, int]:
        """Return registry statistics."""
        with self._lock:
            total = len(self._tokens)
            with_callbacks = sum(1 for t in self._tokens.values() if t.callbacks)
            total_callbacks = sum(len(t.callbacks) for t in self._tokens.values())
        return {
            "tokens_registered": total,
            "tokens_with_callbacks": with_callbacks,
            "total_callbacks": total_callbacks,
        }


# ══════════════════════════════════════════════════════════════════════
# DNS LISTENER
# ══════════════════════════════════════════════════════════════════════

class DNSListener:
    """Authoritative DNS server for OOB callback detection.

    Listens for DNS queries to *.{collab_domain}. Extracts the token
    from the subdomain (e.g., {token}.collab.example.com) and records
    the callback.

    The DNS response always returns a valid A record pointing to our
    own IP so the target's DNS resolution succeeds (important for
    chained attacks like SSRF → DNS → HTTP).
    """

    def __init__(
        self,
        registry: TokenRegistry,
        domain: str,
        listen_ip: str = "0.0.0.0",
        port: int = 53,
        response_ip: str = "127.0.0.1",
    ) -> None:
        self.registry = registry
        self.domain = domain.lower().rstrip(".")
        self.listen_ip = listen_ip
        self.port = port
        self.response_ip = response_ip
        self._sock: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the DNS listener in a background thread."""
        if self._running:
            return
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.listen_ip, self.port))
        except PermissionError:
            log.warning(
                "DNS listener requires root/admin for port %d. "
                "Try --dns-port 5353 or run as root.", self.port
            )
            self._running = False
            return
        except OSError as exc:
            log.warning("DNS bind failed on %s:%d — %s", self.listen_ip, self.port, exc)
            self._running = False
            return

        self._thread = threading.Thread(
            target=self._listen_loop,
            name="ForgeCollab-DNS",
            daemon=True,
        )
        self._thread.start()
        log.info("DNS listener started on %s:%d (domain: *.%s)", self.listen_ip, self.port, self.domain)

    def stop(self) -> None:
        """Stop the DNS listener."""
        self._running = False
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=3.0)
        log.info("DNS listener stopped")

    def _listen_loop(self) -> None:
        """Main DNS receive loop."""
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
                self._handle_query(data, addr)
            except OSError:
                if self._running:
                    log.debug("DNS socket error (shutting down?)")
                break
            except Exception as exc:
                log.error("DNS handler error: %s", exc)

    def _handle_query(self, data: bytes, addr: tuple[str, int]) -> None:
        """Parse DNS query, extract token, record callback, send response."""
        if len(data) < 12:
            return

        # Parse DNS header
        txn_id = data[:2]
        flags = struct.unpack("!H", data[2:4])[0]
        qdcount = struct.unpack("!H", data[4:6])[0]

        if qdcount == 0:
            return

        # Parse question section — extract queried domain name
        offset = 12
        labels: list[str] = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            label = data[offset:offset + length].decode("ascii", errors="ignore")
            labels.append(label)
            offset += length

        if offset + 4 > len(data):
            return

        qtype = struct.unpack("!H", data[offset:offset + 2])[0]
        qclass = struct.unpack("!H", data[offset + 2:offset + 4])[0]

        queried_name = ".".join(labels).lower()
        log.debug("DNS query from %s:%d for %s (type=%d)", addr[0], addr[1], queried_name, qtype)

        # Extract token from subdomain
        # Expected format: {token}.{collab_domain} or {token}.{sub}.{collab_domain}
        token = self._extract_token(queried_name)

        if token:
            callback = Callback(
                token=token,
                callback_type=CallbackType.DNS,
                source_ip=addr[0],
                source_port=addr[1],
                raw_data=data,
                details={
                    "queried_name": queried_name,
                    "query_type": qtype,
                    "labels": labels,
                },
            )
            self.registry.record_callback(callback)

        # Build DNS response — always respond with our IP so resolution works
        response = self._build_response(txn_id, data[12:offset + 4], queried_name, qtype)
        try:
            self._sock.sendto(response, addr)
        except Exception:
            pass

    def _extract_token(self, queried_name: str) -> str | None:
        """Extract the token from a DNS query name.

        Supports formats:
            {token}.collab.example.com
            {token}.{anything}.collab.example.com
            {hex_token}.collab.example.com
        """
        if not queried_name.endswith(self.domain):
            return None

        # Strip the collab domain suffix
        prefix = queried_name[:-(len(self.domain) + 1)]  # +1 for the dot
        if not prefix:
            return None

        # Token is the leftmost label
        token = prefix.split(".")[0]

        # Validate it looks like a token (alphanumeric, 8-36 chars)
        if len(token) < 8 or not token.replace("-", "").isalnum():
            return None

        return token

    def _build_response(
        self,
        txn_id: bytes,
        question: bytes,
        name: str,
        qtype: int,
    ) -> bytes:
        """Build a minimal DNS response with A record."""
        # Header: response, authoritative, no error
        flags = 0x8400  # QR=1, AA=1, RCODE=0
        header = txn_id + struct.pack("!HHHH", flags, 1, 1, 0, 0) if False else b""

        # Actually build it properly
        header = txn_id
        header += struct.pack("!H", flags)
        header += struct.pack("!HH", 1, 1)  # QDCOUNT=1, ANCOUNT=1
        header += struct.pack("!HH", 0, 0)  # NSCOUNT=0, ARCOUNT=0

        # Answer section — pointer to question name + A record
        answer = b"\xc0\x0c"                           # Name pointer to offset 12
        answer += struct.pack("!HH", 1, 1)             # TYPE=A, CLASS=IN
        answer += struct.pack("!I", 60)                 # TTL=60s
        answer += struct.pack("!H", 4)                  # RDLENGTH=4

        # Response IP
        ip_parts = self.response_ip.split(".")
        for part in ip_parts:
            answer += struct.pack("B", int(part))

        return header + question + answer


# ══════════════════════════════════════════════════════════════════════
# HTTP LISTENER
# ══════════════════════════════════════════════════════════════════════

class HTTPListener:
    """HTTP callback server for OOB detection.

    Catches all incoming HTTP requests, extracts the token from the
    URL path or subdomain, logs the full request (IP, URI, headers,
    body), and records the callback.

    Token extraction from URL:
        GET /{token}
        GET /callback/{token}
        GET /{token}/anything
        Host: {token}.collab.example.com (subdomain mode)

    Returns a 200 OK with minimal body so the target's request
    "succeeds" (important for SSRF chains).
    """

    def __init__(
        self,
        registry: TokenRegistry,
        domain: str,
        listen_ip: str = "0.0.0.0",
        port: int = 8888,
    ) -> None:
        self.registry = registry
        self.domain = domain.lower().rstrip(".")
        self.listen_ip = listen_ip
        self.port = port
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        """Start the HTTP listener."""
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.listen_ip,
            self.port,
        )
        log.info("HTTP listener started on %s:%d", self.listen_ip, self.port)

    async def stop(self) -> None:
        """Stop the HTTP listener."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        log.info("HTTP listener stopped")

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single HTTP connection."""
        peername = writer.get_extra_info("peername")
        source_ip = peername[0] if peername else "unknown"
        source_port = peername[1] if peername else 0

        try:
            # Read the full HTTP request (up to 64KB)
            raw_data = await asyncio.wait_for(reader.read(65536), timeout=10.0)
            if not raw_data:
                writer.close()
                return

            request_text = raw_data.decode("utf-8", errors="replace")
            lines = request_text.split("\r\n")

            # Parse request line
            request_line = lines[0] if lines else ""
            parts = request_line.split(" ")
            method = parts[0] if len(parts) >= 1 else "GET"
            path = parts[1] if len(parts) >= 2 else "/"

            # Parse headers
            headers: dict[str, str] = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == "":
                    body_start = i + 1
                    break
                if ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip().lower()] = val.strip()

            body = "\r\n".join(lines[body_start:]) if body_start > 0 else ""

            # Extract token from path or Host header
            token = self._extract_token(path, headers)

            if token:
                callback = Callback(
                    token=token,
                    callback_type=CallbackType.HTTP,
                    source_ip=source_ip,
                    source_port=source_port,
                    raw_data=raw_data,
                    details={
                        "method": method,
                        "path": path,
                        "headers": headers,
                        "body": body[:4096],  # cap body size
                        "user_agent": headers.get("user-agent", ""),
                        "host": headers.get("host", ""),
                    },
                )
                self.registry.record_callback(callback)
            else:
                log.debug("HTTP request from %s to %s — no token found", source_ip, path)

            # Send response — always 200 so SSRF chains work
            response_body = '{"status": "ok"}'
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(response_body)}\r\n"
                "Connection: close\r\n"
                "Server: Apache/2.4.41\r\n"  # Decoy server header
                "X-Powered-By: ASP.NET\r\n"  # Decoy — blend in
                "\r\n"
                f"{response_body}"
            )
            writer.write(response.encode())
            await writer.drain()

        except asyncio.TimeoutError:
            log.debug("HTTP connection timeout from %s", source_ip)
        except Exception as exc:
            log.debug("HTTP handler error from %s: %s", source_ip, exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _extract_token(self, path: str, headers: dict[str, str]) -> str | None:
        """Extract token from URL path or Host header subdomain.

        Checks path patterns first, then subdomain.
        """
        # Path-based extraction: /{token} or /callback/{token} or /c/{token}
        path_clean = path.split("?")[0].strip("/")
        segments = path_clean.split("/")

        for segment in segments:
            if len(segment) >= 8 and segment.replace("-", "").isalnum():
                # Check if this looks like a token (not a common path)
                if segment not in ("api", "callback", "c", "favicon.ico", "robots.txt"):
                    return segment

        # Subdomain-based: {token}.collab.example.com
        host = headers.get("host", "")
        if host and self.domain and host.lower().endswith(self.domain):
            prefix = host[:-(len(self.domain) + 1)]
            token_candidate = prefix.split(".")[0]
            if len(token_candidate) >= 8 and token_candidate.replace("-", "").isalnum():
                return token_candidate

        return None


# ══════════════════════════════════════════════════════════════════════
# SMTP LISTENER
# ══════════════════════════════════════════════════════════════════════

class SMTPListener:
    """SMTP callback server for email-based OOB detection.

    Catches email callbacks for SSRF-to-SMTP, email header injection,
    and similar attack chains.

    Token extraction from:
        RCPT TO: <{token}@collab.example.com>
        MAIL FROM: <{token}@collab.example.com>
        Email body containing the token
    """

    def __init__(
        self,
        registry: TokenRegistry,
        domain: str,
        listen_ip: str = "0.0.0.0",
        port: int = 25,
    ) -> None:
        self.registry = registry
        self.domain = domain.lower().rstrip(".")
        self.listen_ip = listen_ip
        self.port = port
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        """Start the SMTP listener."""
        try:
            self._server = await asyncio.start_server(
                self._handle_connection,
                self.listen_ip,
                self.port,
            )
            log.info("SMTP listener started on %s:%d", self.listen_ip, self.port)
        except PermissionError:
            log.warning(
                "SMTP listener requires root/admin for port %d. "
                "Try --smtp-port 2525 or run as root.", self.port
            )
        except OSError as exc:
            log.warning("SMTP bind failed on %s:%d — %s", self.listen_ip, self.port, exc)

    async def stop(self) -> None:
        """Stop the SMTP listener."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        log.info("SMTP listener stopped")

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single SMTP connection — minimal SMTP state machine."""
        peername = writer.get_extra_info("peername")
        source_ip = peername[0] if peername else "unknown"
        source_port = peername[1] if peername else 0

        tokens_found: list[str] = []
        all_data: list[str] = []

        try:
            # Send banner
            writer.write(b"220 mail.forge.local ESMTP ForgeCollab\r\n")
            await writer.drain()

            in_data = False
            data_lines: list[str] = []

            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                except asyncio.TimeoutError:
                    break

                if not line:
                    break

                text = line.decode("utf-8", errors="replace").strip()
                all_data.append(text)

                if in_data:
                    if text == ".":
                        in_data = False
                        writer.write(b"250 OK: Message accepted\r\n")
                        await writer.drain()
                        # Search body for tokens
                        body = "\n".join(data_lines)
                        for word in body.split():
                            cleaned = word.strip("<>@\"'")
                            if len(cleaned) >= 8 and cleaned.replace("-", "").isalnum():
                                tokens_found.append(cleaned)
                        data_lines = []
                    else:
                        data_lines.append(text)
                    continue

                cmd = text.upper()

                if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                    writer.write(b"250-mail.forge.local\r\n250 OK\r\n")
                elif cmd.startswith("MAIL FROM:"):
                    writer.write(b"250 OK\r\n")
                    # Extract token from sender
                    token = self._extract_email_token(text)
                    if token:
                        tokens_found.append(token)
                elif cmd.startswith("RCPT TO:"):
                    writer.write(b"250 OK\r\n")
                    # Extract token from recipient
                    token = self._extract_email_token(text)
                    if token:
                        tokens_found.append(token)
                elif cmd.startswith("DATA"):
                    writer.write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                    in_data = True
                elif cmd.startswith("QUIT"):
                    writer.write(b"221 Bye\r\n")
                    await writer.drain()
                    break
                elif cmd.startswith("RSET"):
                    writer.write(b"250 OK\r\n")
                else:
                    writer.write(b"250 OK\r\n")

                await writer.drain()

        except Exception as exc:
            log.debug("SMTP handler error from %s: %s", source_ip, exc)
        finally:
            # Record callbacks for all tokens found
            for token in set(tokens_found):
                callback = Callback(
                    token=token,
                    callback_type=CallbackType.SMTP,
                    source_ip=source_ip,
                    source_port=source_port,
                    raw_data="\n".join(all_data).encode("utf-8", errors="replace"),
                    details={
                        "conversation": all_data,
                        "tokens_in_email": list(set(tokens_found)),
                    },
                )
                self.registry.record_callback(callback)

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _extract_email_token(self, smtp_line: str) -> str | None:
        """Extract token from MAIL FROM: or RCPT TO: line.

        Expected: RCPT TO:<{token}@collab.example.com>
        """
        # Find email address
        start = smtp_line.find("<")
        end = smtp_line.find(">")
        if start == -1 or end == -1:
            # Try without angle brackets
            parts = smtp_line.split(":", 1)
            if len(parts) < 2:
                return None
            email = parts[1].strip().strip("<>")
        else:
            email = smtp_line[start + 1:end]

        if "@" not in email:
            return None

        local_part = email.split("@")[0]
        domain_part = email.split("@")[1].lower()

        # Must be addressed to our collab domain
        if not domain_part.endswith(self.domain):
            return None

        if len(local_part) >= 8 and local_part.replace("-", "").isalnum():
            return local_part

        return None


# ══════════════════════════════════════════════════════════════════════
# COLLAB API SERVER (REST endpoints for module polling)
# ══════════════════════════════════════════════════════════════════════

class CollabAPI:
    """REST API for scanner modules to interact with ForgeCollab.

    Endpoints:
        POST /api/token                   — Register a new OOB token
        GET  /api/callbacks/{token}       — Poll for callbacks
        GET  /api/callbacks/{token}/wait  — Long-poll (blocks until callback or timeout)
        GET  /api/stats                   — Server statistics
        GET  /api/health                  — Health check

    This is a lightweight HTTP server (no framework dependency) that
    runs alongside the callback listeners.
    """

    def __init__(
        self,
        registry: TokenRegistry,
        listen_ip: str = "127.0.0.1",
        port: int = 8889,
    ) -> None:
        self.registry = registry
        self.listen_ip = listen_ip
        self.port = port
        self._server: asyncio.AbstractServer | None = None
        # Pending long-poll futures keyed by token
        self._waiters: dict[str, list[asyncio.Future]] = {}

        # Subscribe to registry for long-poll wakeup
        registry.async_subscribe(self._on_callback)

    async def _on_callback(self, token: CollabToken, callback: Callback) -> None:
        """Wake up any long-poll waiters for this token."""
        waiters = self._waiters.pop(callback.token, [])
        for fut in waiters:
            if not fut.done():
                fut.set_result(callback)

    async def start(self) -> None:
        """Start the API server."""
        self._server = await asyncio.start_server(
            self._handle_request,
            self.listen_ip,
            self.port,
        )
        log.info("Collab API started on %s:%d", self.listen_ip, self.port)

    async def stop(self) -> None:
        """Stop the API server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Route incoming API requests."""
        try:
            raw = await asyncio.wait_for(reader.read(65536), timeout=10.0)
            if not raw:
                writer.close()
                return

            text = raw.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            request_line = lines[0]
            parts = request_line.split(" ")
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) >= 2 else "/"

            # Parse headers for content-length
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if line == "":
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # Find body
            body_idx = text.find("\r\n\r\n")
            body = text[body_idx + 4:] if body_idx != -1 else ""

            # Route
            response = await self._route(method, path, headers, body)
            writer.write(response.encode())
            await writer.drain()

        except Exception as exc:
            log.debug("API request error: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _route(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: str,
    ) -> str:
        """Route API request to handler."""
        path_clean = path.strip("/").split("?")[0]
        segments = path_clean.split("/")

        # POST /api/token
        if method == "POST" and path_clean == "api/token":
            return self._handle_register(body)

        # GET /api/callbacks/{token}
        if method == "GET" and len(segments) == 3 and segments[0] == "api" and segments[1] == "callbacks":
            token = segments[2]
            return self._handle_poll(token)

        # GET /api/callbacks/{token}/wait
        if method == "GET" and len(segments) == 4 and segments[3] == "wait":
            token = segments[2]
            return await self._handle_long_poll(token)

        # GET /api/stats
        if method == "GET" and path_clean == "api/stats":
            return self._json_response(self.registry.stats)

        # GET /api/health
        if method == "GET" and path_clean in ("api/health", "health"):
            return self._json_response({"status": "ok", "service": "forge_collab"})

        return self._json_response({"error": "not found"}, status=404)

    def _handle_register(self, body: str) -> str:
        """Handle POST /api/token — register a new OOB token."""
        try:
            data = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            data = {}

        token = self.registry.register(
            module=data.get("module", ""),
            vuln_type=data.get("vuln_type", ""),
            target=data.get("target", ""),
            param=data.get("param", ""),
        )
        return self._json_response({"token": token}, status=201)

    def _handle_poll(self, token: str) -> str:
        """Handle GET /api/callbacks/{token} — instant poll."""
        callbacks = self.registry.get_callbacks(token)
        return self._json_response({
            "token": token,
            "has_callback": len(callbacks) > 0,
            "count": len(callbacks),
            "callbacks": [c.to_dict() for c in callbacks],
        })

    async def _handle_long_poll(self, token: str, timeout: float = 30.0) -> str:
        """Handle GET /api/callbacks/{token}/wait — block until callback."""
        # Check if already has callbacks
        if self.registry.has_callback(token):
            return self._handle_poll(token)

        # Set up a future and wait
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._waiters.setdefault(token, []).append(fut)

        try:
            callback = await asyncio.wait_for(fut, timeout=timeout)
            return self._json_response({
                "token": token,
                "has_callback": True,
                "count": 1,
                "callbacks": [callback.to_dict()],
            })
        except asyncio.TimeoutError:
            return self._json_response({
                "token": token,
                "has_callback": False,
                "count": 0,
                "callbacks": [],
                "timeout": True,
            })

    def _json_response(self, data: dict, status: int = 200) -> str:
        """Build an HTTP response with JSON body."""
        body = json.dumps(data, indent=2)
        status_text = {200: "OK", 201: "Created", 404: "Not Found", 500: "Error"}.get(status, "OK")
        return (
            f"HTTP/1.1 {status} {status_text}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )


# ══════════════════════════════════════════════════════════════════════
# MAIN SERVER ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════

class ForgeCollabServer:
    """Main ForgeCollab server — orchestrates DNS + HTTP + SMTP + API.

    Usage::

        server = ForgeCollabServer(domain="collab.example.com")
        await server.start()
        # ... server runs ...
        await server.stop()

    Or with the EventBus::

        server = ForgeCollabServer(domain="collab.example.com", event_bus=bus)
        await server.start()
    """

    def __init__(
        self,
        domain: str = "",
        listen_ip: str = "0.0.0.0",
        http_port: int = 8888,
        dns_port: int = 53,
        smtp_port: int = 25,
        api_port: int = 8889,
        response_ip: str | None = None,
        event_bus: Any = None,
        local_mode: bool = False,
    ) -> None:
        """Initialize ForgeCollab.

        Args:
            domain:       Collab domain (e.g., collab.example.com).
            listen_ip:    IP to bind listeners on.
            http_port:    HTTP callback listener port.
            dns_port:     DNS listener port (requires root for 53).
            smtp_port:    SMTP listener port (requires root for 25).
            api_port:     REST API port for module interaction.
            response_ip:  IP to return in DNS responses (defaults to listen_ip).
            event_bus:    Optional EventBus for dashboard integration.
            local_mode:   If True, use local defaults (no DNS, higher ports).
        """
        self.domain = domain or os.environ.get("FORGE_COLLAB_DOMAIN", "collab.forge.local")
        self.listen_ip = listen_ip
        self.local_mode = local_mode

        if local_mode:
            dns_port = 0   # Skip DNS in local mode
            smtp_port = 0  # Skip SMTP in local mode

        self.registry = TokenRegistry()

        # Wire EventBus integration
        self._event_bus = event_bus
        if event_bus:
            self.registry.subscribe(self._on_callback_event)

        # Protocol listeners
        self._dns: DNSListener | None = None
        if dns_port > 0:
            self._dns = DNSListener(
                registry=self.registry,
                domain=self.domain,
                listen_ip=listen_ip,
                port=dns_port,
                response_ip=response_ip or listen_ip,
            )

        self._http = HTTPListener(
            registry=self.registry,
            domain=self.domain,
            listen_ip=listen_ip,
            port=http_port,
        )

        self._smtp: SMTPListener | None = None
        if smtp_port > 0:
            self._smtp = SMTPListener(
                registry=self.registry,
                domain=self.domain,
                listen_ip=listen_ip,
                port=smtp_port,
            )

        self._api = CollabAPI(
            registry=self.registry,
            listen_ip="127.0.0.1",  # API only on localhost
            port=api_port,
        )

    def _on_callback_event(self, token: CollabToken, callback: Callback) -> None:
        """Emit OOB callback event to dashboard EventBus."""
        if not self._event_bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            self._event_bus.emit(Event(
                event_type=EventType("oob_callback"),
                data={
                    "token": callback.token[:8],
                    "type": callback.callback_type.value,
                    "source_ip": callback.source_ip,
                    "module": token.module,
                    "vuln_type": token.vuln_type,
                    "target": token.target,
                },
                source="forge_collab",
            ))
        except (ValueError, ImportError):
            pass

    async def start(self) -> None:
        """Start all listeners."""
        loop = asyncio.get_running_loop()
        self.registry.set_loop(loop)

        log.info("ForgeCollab starting — domain: %s", self.domain)

        # Start DNS (runs in a thread)
        if self._dns:
            self._dns.start()

        # Start HTTP
        await self._http.start()

        # Start SMTP
        if self._smtp:
            await self._smtp.start()

        # Start API
        await self._api.start()

        log.info("ForgeCollab ready — all listeners active")
        log.info("  HTTP:  %s:%d", self.listen_ip, self._http.port)
        if self._dns:
            log.info("  DNS:   %s:%d", self.listen_ip, self._dns.port)
        if self._smtp:
            log.info("  SMTP:  %s:%d", self.listen_ip, self._smtp.port)
        log.info("  API:   127.0.0.1:%d", self._api.port)
        log.info("  Token format: {token}.%s", self.domain)

    async def stop(self) -> None:
        """Stop all listeners."""
        if self._dns:
            self._dns.stop()
        await self._http.stop()
        if self._smtp:
            await self._smtp.stop()
        await self._api.stop()
        log.info("ForgeCollab stopped — %s", json.dumps(self.registry.stats))

    async def run_forever(self) -> None:
        """Start and block until interrupted."""
        await self.start()
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()


# ══════════════════════════════════════════════════════════════════════
# MODULE-SIDE CLIENT
# ══════════════════════════════════════════════════════════════════════

class CollabClient:
    """Client for scanner modules to interact with ForgeCollab.

    Used within modules to:
    1. Generate OOB tokens
    2. Build payload URLs containing the token
    3. Poll for callbacks after injecting the payload

    Works in two modes:
    - Direct: When ForgeCollab server is in-process (shares TokenRegistry)
    - Remote: When ForgeCollab runs on a separate VPS (HTTP API calls)

    Usage in a scanner module::

        collab = CollabClient.from_config(config)
        if collab:
            token = collab.register("ssrf_scanner", "ssrf", target, "url_param")
            payload_url = collab.build_url(token)
            # ... inject payload_url into the target ...
            await asyncio.sleep(5)
            if collab.has_callback(token):
                confidence = "HIGH"  # OOB confirmed!
    """

    def __init__(
        self,
        registry: TokenRegistry | None = None,
        collab_domain: str = "",
        api_url: str = "",
    ) -> None:
        """Initialize the collab client.

        Args:
            registry:      Direct TokenRegistry (in-process mode).
            collab_domain: Domain for building payload URLs.
            api_url:       Remote API URL (e.g., http://127.0.0.1:8889).
        """
        self._registry = registry
        self.collab_domain = collab_domain or os.environ.get("FORGE_COLLAB_DOMAIN", "")
        self._api_url = api_url

    @classmethod
    def from_config(cls, config: Any = None, registry: TokenRegistry | None = None) -> "CollabClient | None":
        """Create a CollabClient from scan configuration.

        Returns None if no collab server is configured (graceful degradation).
        """
        domain = os.environ.get("FORGE_COLLAB_DOMAIN", "")
        if not domain and not registry:
            return None

        return cls(
            registry=registry,
            collab_domain=domain,
        )

    def register(
        self,
        module: str = "",
        vuln_type: str = "",
        target: str = "",
        param: str = "",
    ) -> str:
        """Register a new OOB token. Returns the token string."""
        if self._registry:
            return self._registry.register(module, vuln_type, target, param)

        # Remote mode — call API
        # For now, generate locally (remote API call would go here)
        return str(uuid.uuid4()).replace("-", "")[:24]

    def build_url(self, token: str, protocol: str = "http") -> str:
        """Build a callback URL containing the token.

        Args:
            token:    The OOB token.
            protocol: http or https.

        Returns:
            URL string, e.g., http://{token}.collab.example.com/
        """
        if self.collab_domain:
            return f"{protocol}://{token}.{self.collab_domain}/"
        return ""

    def build_dns_payload(self, token: str) -> str:
        """Build a DNS lookup payload.

        Returns:
            Domain string for nslookup/dig, e.g., {token}.collab.example.com
        """
        if self.collab_domain:
            return f"{token}.{self.collab_domain}"
        return ""

    def build_email(self, token: str) -> str:
        """Build an email address payload.

        Returns:
            Email address, e.g., {token}@collab.example.com
        """
        if self.collab_domain:
            return f"{token}@{self.collab_domain}"
        return ""

    def has_callback(self, token: str) -> bool:
        """Check if any callback has been received for this token."""
        if self._registry:
            return self._registry.has_callback(token)
        return False

    def get_callbacks(self, token: str) -> list[Callback]:
        """Get all callbacks for a token."""
        if self._registry:
            return self._registry.get_callbacks(token)
        return []

    async def wait_for_callback(self, token: str, timeout: float = 15.0) -> bool:
        """Async wait for a callback with polling.

        Args:
            token:   The OOB token to wait for.
            timeout: Max seconds to wait.

        Returns:
            True if callback received within timeout.
        """
        start = time.monotonic()
        interval = 0.5
        while time.monotonic() - start < timeout:
            if self.has_callback(token):
                return True
            await asyncio.sleep(interval)
            # Exponential backoff up to 2s
            interval = min(interval * 1.5, 2.0)
        return self.has_callback(token)


# ══════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

async def main() -> None:
    """Standalone CLI entry point for ForgeCollab."""
    import argparse

    parser = argparse.ArgumentParser(description="ForgeCollab — OOB Testing Infrastructure")
    parser.add_argument("--domain", default="", help="Collab domain (e.g., collab.example.com)")
    parser.add_argument("--listen", default="0.0.0.0", help="Bind address")
    parser.add_argument("--http-port", type=int, default=8888, help="HTTP listener port")
    parser.add_argument("--dns-port", type=int, default=53, help="DNS listener port (0 to disable)")
    parser.add_argument("--smtp-port", type=int, default=25, help="SMTP listener port (0 to disable)")
    parser.add_argument("--api-port", type=int, default=8889, help="API port")
    parser.add_argument("--response-ip", default=None, help="IP to return in DNS responses")
    parser.add_argument("--local", action="store_true", help="Local mode (no DNS/SMTP)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    server = ForgeCollabServer(
        domain=args.domain,
        listen_ip=args.listen,
        http_port=args.http_port,
        dns_port=args.dns_port,
        smtp_port=args.smtp_port,
        api_port=args.api_port,
        response_ip=args.response_ip,
        local_mode=args.local,
    )

    try:
        await server.run_forever()
    except KeyboardInterrupt:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
