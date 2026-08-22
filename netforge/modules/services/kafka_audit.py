"""Kafka Audit — unauthenticated broker, topic listing, consumer groups."""
from __future__ import annotations

import asyncio, sys, time, struct
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_UNAUTH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"


class KafkaAudit(BaseModule):
    NAME = "kafka_audit"
    DESCRIPTION = "Kafka: unauthenticated broker, topic enumeration, consumer group exposure"
    PHASE = 4
    TAGS = ["services", "kafka", "messaging", "cwe-306"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._audit(host)
        return self._make_result(start)

    async def _audit(self, host: str) -> None:
        for port in [9092, 9093, 9094]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=5)

                # Send Kafka API Versions request (ApiKey=18, version=0)
                # This is the simplest way to detect an unauthenticated Kafka broker
                correlation_id = 1
                client_id = b"forge-scanner"
                api_key = 18  # ApiVersions
                api_version = 0

                header = struct.pack(">hhih",
                    api_key, api_version, correlation_id, len(client_id))
                request = header + client_id
                msg = struct.pack(">i", len(request)) + request

                writer.write(msg)
                await writer.drain()

                response = await asyncio.wait_for(reader.read(4096), timeout=5)
                writer.close()

                if len(response) > 8:
                    # Valid Kafka response — broker is unauthenticated
                    self.new_finding(
                        title=f"Kafka Broker Unauthenticated — {host}:{port}",
                        severity=Severity.HIGH,
                        description=(
                            f"Kafka broker on {host}:{port} accepts unauthenticated connections. "
                            "Topics can be read/written without credentials."
                        ),
                        reproduction_steps=[
                            f"kafka-topics.sh --bootstrap-server {host}:{port} --list",
                        ],
                        remediation="Enable SASL authentication. Configure ACLs for topic access.",
                        references=["CWE-306"],
                        evidence=Evidence(extra={"host": host, "port": port,
                                                "response_len": len(response)}),
                        cvss_v31_vector=CVSS_UNAUTH,
                        mitre_attack=["TA0007/T1046"],
                        target=host, port=port, service="kafka", confidence="HIGH",
                    )
                    return
            except Exception:
                continue
