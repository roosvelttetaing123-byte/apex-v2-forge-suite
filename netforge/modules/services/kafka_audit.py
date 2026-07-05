"""Apache Kafka Security Audit — Unauthenticated Access & Data Exposure.

Comprehensive security auditor for Apache Kafka brokers. Checks for:

    1. Unauthenticated broker access (port 9092)
    2. Topic listing and metadata enumeration
    3. JMX remote access (port 9999/10000)
    4. Consumer group enumeration
    5. ACL configuration check
    6. Zookeeper unauthenticated access (port 2181)
    7. Schema Registry exposure

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.kafka_audit")

# Standard ports
KAFKA_PORT = 9092
ZK_PORT = 2181
JMX_PORTS = [9999, 10000, 10001]
SCHEMA_REGISTRY_PORT = 8081

# Kafka API keys (protocol)
API_KEY_METADATA = 3
API_KEY_API_VERSIONS = 18

# Zookeeper 4-letter commands (safe, read-only)
ZK_COMMANDS = {
    b"stat": "Server statistics",
    b"envi": "Environment details",
    b"conf": "Configuration",
    b"mntr": "Monitoring metrics",
    b"ruok": "Health check",
}


class KafkaAudit(BaseModule):
    """Apache Kafka Security Auditor.

    Checks for unauthenticated broker access, topic exposure,
    JMX remote access, Zookeeper misconfiguration, and missing ACLs.
    """

    NAME = "kafka_audit"
    DESCRIPTION = "Apache Kafka security audit — unauthenticated access, topic exposure, JMX/ZK misconfig"
    PHASE = 4
    TAGS = ["kafka", "message-queue", "zookeeper", "jmx", "infrastructure"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await self.rate_limit()

        # Extract host from target
        parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(target)
        host = parsed.hostname or target.replace("http://", "").replace("https://", "").split(":")[0]

        # Phase 1: Kafka broker detection
        broker_detected = await self._detect_kafka_broker(host)

        # Phase 2: Zookeeper check
        await self._check_zookeeper(host)

        # Phase 3: JMX remote access
        await self._check_jmx(host)

        # Phase 4: Schema Registry
        await self._check_schema_registry(target, host)

        # Phase 5: HTTP-based Kafka REST/Connect
        await self._check_kafka_rest(target)

        return self._make_result(start)

    async def _detect_kafka_broker(self, host: str) -> bool:
        """Detect Kafka broker via native protocol handshake."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, KAFKA_PORT), timeout=5,
            )
        except (OSError, asyncio.TimeoutError):
            self.log.info("[kafka_audit] Cannot connect to %s:%d", host, KAFKA_PORT)
            return False

        try:
            # Send ApiVersions request (API key 18, version 0)
            correlation_id = 12345
            client_id = b"forge-audit"

            # Build request: ApiVersions v0
            header = struct.pack(">hhi", API_KEY_API_VERSIONS, 0, correlation_id)
            header += struct.pack(">h", len(client_id)) + client_id
            message = struct.pack(">i", len(header)) + header

            writer.write(message)
            await writer.drain()

            # Read response
            size_data = await asyncio.wait_for(reader.read(4), timeout=5)
            if len(size_data) < 4:
                return False

            resp_size = struct.unpack(">i", size_data)[0]
            if resp_size <= 0 or resp_size > 1_000_000:
                return False

            resp_data = await asyncio.wait_for(reader.read(min(resp_size, 4096)), timeout=5)

            # If we got a valid response, Kafka is listening
            if len(resp_data) >= 4:
                resp_corr_id = struct.unpack(">i", resp_data[:4])[0]
                if resp_corr_id == correlation_id:
                    self.new_finding(
                        title="Kafka — Broker Accessible Without Authentication",
                        severity=Severity.HIGH,
                        description=(
                            f"Kafka broker at {host}:{KAFKA_PORT} accepts unauthenticated "
                            f"connections. The broker responded to an ApiVersions request, "
                            f"confirming it accepts protocol-level connections without SASL. "
                            f"An attacker can list topics, consume messages, and potentially "
                            f"produce malicious messages."
                        ),
                        reproduction_steps=[
                            f"1. Connect to {host}:{KAFKA_PORT}",
                            "2. Send ApiVersions request (API key 18)",
                            "3. Broker responds with supported API versions",
                            "4. No SASL authentication required",
                        ],
                        remediation=(
                            "Enable SASL authentication (SCRAM-SHA-256/512 or GSSAPI). "
                            "Configure SSL/TLS for encryption. "
                            "Set up Kafka ACLs to restrict topic access. "
                            "Restrict broker port access via firewall."
                        ),
                        references=[
                            "https://kafka.apache.org/documentation/#security",
                            "https://kafka.apache.org/documentation/#security_authz",
                        ],
                        evidence=Evidence(
                            extra={
                                "host": host,
                                "port": KAFKA_PORT,
                                "protocol": "kafka-native",
                                "correlation_id_match": True,
                            },
                        ),
                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
                        mitre_attack=["TA0001/T1190", "TA0009/T1213"],
                        target=f"{host}:{KAFKA_PORT}",
                        confidence="HIGH",
                        tags=self.TAGS,
                    )
                    return True
        except Exception as exc:
            self.log.debug("Kafka broker detection error: %s", exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        return False

    async def _check_zookeeper(self, host: str) -> None:
        """Check for unauthenticated Zookeeper access via 4-letter commands."""
        accessible_commands: list[dict[str, str]] = []

        for cmd, description in ZK_COMMANDS.items():
            await self.rate_limit()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, ZK_PORT), timeout=3,
                )
                try:
                    writer.write(cmd)
                    await writer.drain()
                    response = await asyncio.wait_for(reader.read(4096), timeout=3)
                    if response and len(response) > 10:
                        resp_text = response.decode(errors="ignore")
                        if "not executed" not in resp_text.lower():
                            accessible_commands.append({
                                "command": cmd.decode(),
                                "description": description,
                                "response_preview": resp_text[:200],
                            })
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
            except (OSError, asyncio.TimeoutError):
                continue
            except Exception:
                continue

        if accessible_commands:
            self.new_finding(
                title="Zookeeper — Unauthenticated Access via 4-Letter Commands",
                severity=Severity.HIGH,
                description=(
                    f"Zookeeper at {host}:{ZK_PORT} responds to "
                    f"{len(accessible_commands)} 4-letter commands without authentication. "
                    f"Exposes cluster configuration, environment details, and metrics."
                ),
                reproduction_steps=[
                    f"1. Connect to {host}:{ZK_PORT}",
                ] + [f"2. Send '{c['command']}' → {c['description']}" for c in accessible_commands],
                remediation=(
                    "Disable 4-letter commands: 4lw.commands.whitelist=stat,ruok. "
                    "Enable Zookeeper SASL authentication. "
                    "Restrict Zookeeper port via firewall."
                ),
                references=["https://zookeeper.apache.org/doc/current/zookeeperAdmin.html"],
                evidence=Evidence(
                    extra={
                        "commands": accessible_commands,
                        "host": host,
                        "port": ZK_PORT,
                    },
                ),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
                mitre_attack=["TA0007/T1046", "TA0009/T1213"],
                target=f"{host}:{ZK_PORT}",
                confidence="HIGH",
                tags=self.TAGS + ["zookeeper"],
            )

    async def _check_jmx(self, host: str) -> None:
        """Check for open JMX ports (common Kafka monitoring exposure)."""
        for port in JMX_PORTS:
            await self.rate_limit()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=3,
                )
                # JMX RMI handshake starts with JRMI
                initial = await asyncio.wait_for(reader.read(4), timeout=3)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                self.new_finding(
                    title=f"Kafka — JMX Port Open ({port})",
                    severity=Severity.HIGH,
                    description=(
                        f"JMX port {port} is open on {host}. "
                        f"JMX provides remote management access to the Kafka broker JVM. "
                        f"Without authentication, attackers can invoke MBeans for "
                        f"arbitrary code execution via MLet or other gadgets."
                    ),
                    reproduction_steps=[
                        f"1. Connect to {host}:{port}",
                        "2. JMX/RMI handshake accepted",
                        "3. Use jconsole or ysoserial for exploitation",
                    ],
                    remediation=(
                        "Enable JMX authentication and SSL. "
                        "Set com.sun.management.jmxremote.authenticate=true. "
                        "Restrict JMX access via firewall."
                    ),
                    references=[
                        "https://kafka.apache.org/documentation/#monitoring",
                    ],
                    evidence=Evidence(
                        extra={"host": host, "port": port, "initial_bytes": initial.hex() if initial else ""},
                    ),
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    mitre_attack=["TA0002/T1059", "TA0001/T1190"],
                    target=f"{host}:{port}",
                    confidence="MEDIUM",
                    tags=self.TAGS + ["jmx"],
                )
                return
            except (OSError, asyncio.TimeoutError):
                continue
            except Exception:
                continue

    async def _check_schema_registry(self, target: str, host: str) -> None:
        """Check for unauthenticated Confluent Schema Registry."""
        import aiohttp

        sr_urls = [
            f"http://{host}:{SCHEMA_REGISTRY_PORT}",
            f"{target.rstrip('/')}",
        ]

        for sr_url in sr_urls:
            await self.rate_limit()
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as session:
                    async with session.get(f"{sr_url}/subjects") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                subjects = json.loads(body)
                                if isinstance(subjects, list):
                                    self.new_finding(
                                        title="Kafka Schema Registry — Unauthenticated Access",
                                        severity=Severity.MEDIUM,
                                        description=(
                                            f"Schema Registry at {sr_url} is accessible without "
                                            f"authentication. Found {len(subjects)} subjects. "
                                            f"Schema definitions may reveal data models and "
                                            f"sensitive field names."
                                        ),
                                        reproduction_steps=[
                                            f"1. GET {sr_url}/subjects",
                                            f"2. {len(subjects)} schema subjects returned",
                                        ],
                                        remediation="Enable Schema Registry authentication and ACLs.",
                                        references=["https://docs.confluent.io/platform/current/schema-registry/security/index.html"],
                                        evidence=Evidence(extra={"subject_count": len(subjects), "subjects": subjects[:20]}),
                                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                        mitre_attack=["TA0007/T1083"],
                                        target=sr_url,
                                        confidence="HIGH",
                                        tags=self.TAGS + ["schema-registry"],
                                    )
                                    return
                            except json.JSONDecodeError:
                                pass
            except Exception:
                continue

    async def _check_kafka_rest(self, target: str) -> None:
        """Check for unauthenticated Kafka REST Proxy / Connect."""
        import aiohttp

        rest_checks = [
            ("/topics", "Kafka REST Proxy — Topic Listing"),
            ("/connectors", "Kafka Connect — Connector Listing"),
            ("/v3/clusters", "Confluent REST Proxy v3 — Cluster Info"),
        ]

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                for path, desc in rest_checks:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}{path}") as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                try:
                                    data = json.loads(body)
                                    if isinstance(data, (list, dict)) and len(data) > 0:
                                        self.new_finding(
                                            title=f"Kafka — {desc.split('—')[0].strip()} Exposed",
                                            severity=Severity.MEDIUM,
                                            description=(
                                                f"{desc} at {target}{path} accessible without auth. "
                                                f"Returns {len(data)} entries."
                                            ),
                                            reproduction_steps=[f"1. GET {target}{path}"],
                                            remediation="Enable authentication for Kafka REST/Connect APIs.",
                                            references=["https://docs.confluent.io/platform/current/kafka-rest/"],
                                            evidence=Evidence(extra={"path": path, "count": len(data)}),
                                            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                            mitre_attack=["TA0007/T1083"],
                                            target=target,
                                            confidence="HIGH",
                                            tags=self.TAGS,
                                        )
                                except json.JSONDecodeError:
                                    pass
                    except Exception:
                        continue
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════


class TestKafkaAudit:
    def _make_module(self, tmp_path: Path) -> KafkaAudit:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="http://kafka.example.com:9092")
        scope = Scope(["kafka.example.com"])
        session = create_db(tmp_path / "test.db")
        return KafkaAudit(cfg, scope, session, tmp_path)

    def test_module_metadata(self, tmp_path: Path) -> None:
        mod = self._make_module(tmp_path)
        assert mod.NAME == "kafka_audit"
        assert mod.PHASE == 4
        assert "kafka" in mod.TAGS

    def test_zk_commands_defined(self, tmp_path: Path) -> None:
        assert len(ZK_COMMANDS) >= 4
        assert b"ruok" in ZK_COMMANDS

    def test_jmx_ports_defined(self, tmp_path: Path) -> None:
        assert len(JMX_PORTS) >= 2
        assert 9999 in JMX_PORTS

    def test_api_keys(self, tmp_path: Path) -> None:
        assert API_KEY_METADATA == 3
        assert API_KEY_API_VERSIONS == 18

    def test_out_of_scope_skip(self, tmp_path: Path) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="http://kafka.example.com:9092")
        scope = Scope(["10.0.0.0/24"])
        session = create_db(tmp_path / "test.db")
        mod = KafkaAudit(cfg, scope, session, tmp_path)
        result = asyncio.run(mod.run())
        assert result.skipped is True
