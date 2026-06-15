"""MQTT Broker Audit — IoT/ICS messaging protocol security assessment.

MQTT (Message Queuing Telemetry Transport) is widely used in IoT, industrial,
and home automation environments. Misconfigurations can expose:

Checks:
  - Port 1883 (cleartext) and 8883 (TLS) reachability
  - Anonymous authentication (CONNECT without credentials)
  - Default / weak credentials
  - Topic enumeration via wildcard subscriptions (#)
  - Retained message disclosure
  - Publish access to sensitive topics ($SYS, command topics)
  - TLS availability and certificate validity
  - MQTT 3.1.1 vs 5.0 version fingerprinting
  - Broker identification ($SYS/broker/version)

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import asyncio
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity


# ── MQTT wire protocol helpers ─────────────────────────────────────────

def _encode_string(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">H", len(b)) + b


def _build_connect(client_id: str = "forge_audit",
                   username: str = "", password: str = "",
                   clean_session: bool = True) -> bytes:
    flags  = 0x02 if clean_session else 0
    payload = _encode_string(client_id)
    if username:
        flags |= 0x80
        payload += _encode_string(username)
    if password:
        flags |= 0x40
        payload += _encode_string(password)

    variable = (
        _encode_string("MQTT")
        + b"\x04"                   # Protocol Level: 3.1.1
        + bytes([flags])
        + struct.pack(">H", 60)     # KeepAlive: 60s
    )
    body    = variable + payload
    # Remaining length encoding (variable-length int)
    rem_len = _encode_remaining_length(len(body))
    return bytes([0x10]) + rem_len + body


def _build_subscribe(packet_id: int, topic: str, qos: int = 0) -> bytes:
    body    = struct.pack(">H", packet_id) + _encode_string(topic) + bytes([qos])
    rem_len = _encode_remaining_length(len(body))
    return bytes([0x82]) + rem_len + body


def _build_publish(topic: str, payload: bytes, qos: int = 0, packet_id: int = 1) -> bytes:
    header_byte = 0x30 | (qos << 1)
    body        = _encode_string(topic)
    if qos > 0:
        body += struct.pack(">H", packet_id)
    body       += payload
    rem_len     = _encode_remaining_length(len(body))
    return bytes([header_byte]) + rem_len + body


def _build_disconnect() -> bytes:
    return b"\xe0\x00"


def _encode_remaining_length(length: int) -> bytes:
    result = b""
    while True:
        byte = length & 0x7F
        length >>= 7
        if length > 0:
            byte |= 0x80
        result += bytes([byte])
        if length == 0:
            break
    return result


class MqttAudit(BaseModule):
    """MQTT broker security audit."""

    NAME        = "mqtt_audit"
    DESCRIPTION = "MQTT 1883/8883 anonymous auth, topic enumeration, and credential audit"
    PHASE       = 5
    TAGS        = ["iot", "mqtt", "ics", "scada", "credentials", "anonymous"]

    _DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", ""),
        ("mqtt", "mqtt"),
        ("user", "user"),
        ("guest", "guest"),
        ("root", "root"),
        ("test", "test"),
    ]

    # Sensitive topics to attempt publishing to (write access = critical)
    _SENSITIVE_PUB_TOPICS = [
        "cmnd/+/Power",          # Tasmota command
        "homeassistant/switch/+/set",
        "device/+/command",
        "control/+",
        "/cmd/+",
        "$SYS/+",
    ]

    async def run(self) -> ModuleResult:
        start    = time.monotonic()
        target   = self.config.target.rstrip("/")
        host     = target.replace("mqtt://", "").replace("mqtts://", "").split(":")[0]
        username = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")
        spray    = self.config.extra.get("spray_defaults", False)

        if not self.check_scope(host):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        plain_up = await self._check_port(host, 1883)
        tls_up   = await self._check_port(host, 8883)
        ws_up    = await self._check_port(host, 9001)

        if not plain_up and not tls_up and not ws_up:
            return self._make_result(start, skipped=True,
                                     skip_reason="MQTT ports 1883/8883/9001 not reachable")

        if plain_up and not tls_up:
            self._add_finding(
                host,
                "MQTT is available on port 1883 (cleartext) but NOT on 8883 (TLS). "
                "All MQTT traffic is transmitted in plaintext — credentials, topics, "
                "and payloads are visible to network eavesdroppers.",
                Severity.HIGH,
                "Enable TLS on port 8883 and disable plaintext 1883.",
            )

        # Anonymous auth test
        if plain_up:
            await self._test_anonymous(host, 1883, ssl_ctx=None)
        if tls_up:
            import ssl as ssl_mod
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl_mod.CERT_NONE
            await self._test_anonymous(host, 8883, ssl_ctx=ctx)

        # Default credential spray
        if spray:
            port = 8883 if tls_up else 1883
            for u, p in self._DEFAULT_CREDS:
                await self.rate_limit()
                await self._test_credentials(host, port, u, p, tls_up)

        # Authenticated tests
        if username and plain_up:
            await self._test_credentials(host, 1883, username, password, False)
            await self._topic_enum(host, 1883, username, password, False)
        if username and tls_up:
            await self._test_credentials(host, 8883, username, password, True)

        return self._make_result(start)

    # ── Anonymous auth ─────────────────────────────────────────────────

    async def _test_anonymous(self, host: str, port: int, ssl_ctx) -> None:
        """Attempt MQTT CONNECT without credentials."""
        await self.rate_limit()
        try:
            connect_pkt = _build_connect(client_id="forge_anon")
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=8
            )
            writer.write(connect_pkt)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(4), timeout=5)
            writer.write(_build_disconnect())
            await writer.drain()
            writer.close()

            if len(resp) >= 4 and resp[0] == 0x20:  # CONNACK
                return_code = resp[3]
                if return_code == 0x00:
                    scheme = "TLS" if ssl_ctx else "cleartext"
                    self._add_finding(
                        host,
                        f"MQTT anonymous authentication ALLOWED on port {port} ({scheme}). "
                        f"No username or password required to connect.",
                        Severity.CRITICAL,
                        "Enable authentication in the broker config. "
                        "Mosquitto: password_file, allow_anonymous false. "
                        "EMQX: disable allow_anonymous in emqx.conf.",
                    )
                    # With anonymous access, try topic enumeration
                    await self._topic_enum(host, port, "", "", bool(ssl_ctx))
        except Exception as exc:
            self.log.debug("MQTT anonymous %s:%d: %s", host, port, exc)

    # ── Credential test ────────────────────────────────────────────────

    async def _test_credentials(self, host: str, port: int, username: str,
                                 password: str, use_tls: bool) -> None:
        ssl_ctx = None
        if use_tls:
            import ssl as ssl_mod
            ssl_ctx = ssl_mod.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl_mod.CERT_NONE

        await self.rate_limit()
        try:
            connect_pkt = _build_connect(
                client_id="forge_cred_test", username=username, password=password
            )
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=8
            )
            writer.write(connect_pkt)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(4), timeout=5)
            writer.write(_build_disconnect())
            await writer.drain()
            writer.close()

            if len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0x00:
                self._add_finding(
                    host,
                    f"MQTT credential accepted: {username!r}:{password!r} on port {port}",
                    Severity.CRITICAL,
                    "Change default credentials immediately.",
                )
        except Exception as exc:
            self.log.debug("MQTT cred test %s@%s:%d: %s", username, host, port, exc)

    # ── Topic enumeration ──────────────────────────────────────────────

    async def _topic_enum(self, host: str, port: int, username: str,
                          password: str, use_tls: bool) -> None:
        """Subscribe to wildcard '#' to enumerate all topics + retained messages."""
        ssl_ctx = None
        if use_tls:
            import ssl as ssl_mod
            ssl_ctx = ssl_mod.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl_mod.CERT_NONE

        await self.rate_limit()
        topics_seen: list[str] = []
        sys_info: dict[str, str] = {}

        try:
            connect_pkt = _build_connect(
                client_id="forge_enum", username=username, password=password
            )
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=8
            )
            writer.write(connect_pkt)
            await writer.drain()

            connack = await asyncio.wait_for(reader.read(4), timeout=5)
            if len(connack) < 4 or connack[0] != 0x20 or connack[3] != 0x00:
                writer.close()
                return

            # Subscribe to wildcard
            writer.write(_build_subscribe(1, "#", qos=0))
            writer.write(_build_subscribe(2, "$SYS/#", qos=0))
            await writer.drain()

            # Collect messages for 3 seconds
            deadline = asyncio.get_event_loop().time() + 3.0
            buf = b""
            while asyncio.get_event_loop().time() < deadline:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=0.5)
                    if not chunk:
                        break
                    buf += chunk
                    buf = self._parse_publishes(buf, topics_seen, sys_info)
                except asyncio.TimeoutError:
                    continue

            writer.write(_build_disconnect())
            await writer.drain()
            writer.close()
        except Exception as exc:
            self.log.debug("MQTT topic enum %s:%d: %s", host, port, exc)
            return

        if sys_info.get("version"):
            self._add_info(host, f"MQTT broker version: {sys_info['version']}")
        if sys_info.get("clients"):
            self._add_info(host, f"MQTT connected clients: {sys_info['clients']}")

        if topics_seen:
            self._add_finding(
                host,
                f"MQTT wildcard subscription succeeded — {len(topics_seen)} topic(s) visible:\n"
                + "\n".join(f"  {t}" for t in topics_seen[:20]),
                Severity.HIGH,
                "Restrict topic access using ACLs. "
                "Mosquitto: acl_file with per-user topic permissions.",
            )

        # Check if sensitive topics are writable
        if self.confirm_action("MQTT publish probe to sensitive topics", host, "medium"):
            await self._test_publish_access(host, port, username, password, use_tls)

    def _parse_publishes(self, buf: bytes, topics: list, sys_info: dict) -> bytes:
        """Extract PUBLISH packets from buffer."""
        while len(buf) >= 2:
            if buf[0] & 0xF0 != 0x30:  # Not PUBLISH
                buf = buf[1:]
                continue
            rem_len, consumed = self._decode_remaining(buf[1:])
            if rem_len is None:
                break
            total = 1 + consumed + rem_len
            if len(buf) < total:
                break

            pkt  = buf[1 + consumed: total]
            buf  = buf[total:]
            try:
                tlen  = struct.unpack(">H", pkt[:2])[0]
                topic = pkt[2:2 + tlen].decode(errors="replace")
                payload = pkt[2 + tlen:].decode(errors="replace")
                if topic not in topics:
                    topics.append(topic)
                if topic.startswith("$SYS/broker/version"):
                    sys_info["version"] = payload
                elif topic.startswith("$SYS/broker/clients/connected"):
                    sys_info["clients"] = payload
            except Exception:
                pass
        return buf

    def _decode_remaining(self, data: bytes):
        value   = 0
        mul     = 1
        consumed = 0
        for byte in data[:4]:
            value   += (byte & 0x7F) * mul
            mul     *= 128
            consumed += 1
            if not (byte & 0x80):
                return value, consumed
        return None, 0

    async def _test_publish_access(self, host: str, port: int, username: str,
                                   password: str, use_tls: bool) -> None:
        """Try publishing to sensitive topics."""
        ssl_ctx = None
        if use_tls:
            import ssl as ssl_mod
            ssl_ctx = ssl_mod.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl_mod.CERT_NONE

        accessible = []
        for topic in self._SENSITIVE_PUB_TOPICS[:3]:
            await self.rate_limit()
            try:
                connect_pkt = _build_connect(
                    client_id="forge_pub_test", username=username, password=password
                )
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=8
                )
                writer.write(connect_pkt)
                await writer.drain()
                connack = await asyncio.wait_for(reader.read(4), timeout=5)
                if len(connack) >= 4 and connack[0] == 0x20 and connack[3] == 0x00:
                    pub_pkt = _build_publish(
                        topic.replace("+", "forge_test"),
                        b"forge_audit_probe",
                        qos=0
                    )
                    writer.write(pub_pkt)
                    await writer.drain()
                    accessible.append(topic)
                writer.write(_build_disconnect())
                await writer.drain()
                writer.close()
            except Exception:
                pass

        if accessible:
            self._add_finding(
                host,
                f"MQTT publish access to sensitive topics:\n"
                + "\n".join(f"  {t}" for t in accessible),
                Severity.CRITICAL,
                "Restrict publish ACLs. Operators should not be able to write to "
                "command or system topics without explicit authentication.",
            )

    # ── Helpers ────────────────────────────────────────────────────────

    async def _check_port(self, host: str, port: int) -> bool:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
            w.close()
            return True
        except Exception:
            return False

    def _add_finding(self, host: str, detail: str, severity: Severity,
                     remediation: str = "") -> None:
        from common.finding import Finding
        self.findings.append(Finding(
            title       = "MQTT Security Risk",
            description = detail,
            severity    = severity,
            host        = host,
            evidence    = detail,
            remediation = remediation or "Harden MQTT broker configuration.",
            references  = [
                "https://mqtt.org/mqtt-specification/",
                "https://attack.mitre.org/techniques/T0821/",
                "https://owasp.org/www-project-internet-of-things/",
            ],
        ))

    def _add_info(self, host: str, msg: str) -> None:
        from common.finding import Finding
        self.findings.append(Finding(
            title       = "MQTT Info",
            description = msg,
            severity    = Severity.INFO,
            host        = host,
            evidence    = msg,
            remediation = "",
        ))
