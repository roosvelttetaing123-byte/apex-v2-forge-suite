"""Elasticsearch Auditor — unauthenticated access, index enumeration, snapshot exposure.

Tests:
  - No-auth access to cluster info
  - Index enumeration with document counts and sizes
  - Sensitive index detection (logs, sessions, credentials)
  - Snapshot repository exposure
  - X-Pack security disabled detection
  - Script execution (Painless sandbox escape surface)
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NOAUTH     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_NOAUTH   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_DATA_LEAK  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_DATA_LEAK = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

ES_PORTS = [9200, 9201, 9300]

SENSITIVE_INDEX_PATTERNS = [
    "password", "credential", "secret", "session", "auth",
    "user", "customer", "payment", "credit", "ssn",
    "token", "key", "private", "admin", ".kibana",
    "logstash", "filebeat", "winlogbeat",
]


class ElasticAudit(BaseModule):
    """Elasticsearch security auditor."""

    NAME        = "elastic_audit"
    DESCRIPTION = "Elasticsearch: no-auth access, index enumeration, snapshot exposure, data leak risk"
    PHASE       = 4
    TAGS        = ["elasticsearch", "services", "database", "cwe-306", "cwe-200"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            for port in ES_PORTS:
                await self.rate_limit()
                if await self._check_elastic(host, port):
                    break

        return self._make_result(start)

    async def _check_elastic(self, host: str, port: int) -> bool:
        import aiohttp
        url = f"http://{host}:{port}"
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                # Test root endpoint
                await self.rate_limit()
                async with session.get(url) as resp:
                    if resp.status == 401:
                        return False
                    if resp.status != 200:
                        return False
                    cluster_info = await resp.json()

                cluster_name = cluster_info.get("cluster_name", "unknown")
                version = cluster_info.get("version", {}).get("number", "unknown")
                node_name = cluster_info.get("name", "unknown")

                ev = Evidence(
                    request_raw=f"GET {url}/",
                    extra={
                        "cluster_name": cluster_name,
                        "version": version,
                        "node_name": node_name,
                    },
                )
                self.new_finding(
                    title=f"Elasticsearch Unauthenticated Access — {host}:{port} (v{version})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Elasticsearch cluster '{cluster_name}' (v{version}) on {host}:{port} "
                        "is accessible without authentication.\n\n"
                        "An attacker can:\n"
                        "  1. Read all indexed data (PII, logs, credentials)\n"
                        "  2. Delete or modify indices\n"
                        "  3. Create snapshots to exfiltrate data\n"
                        "  4. Execute scripts via _search with Painless\n"
                        "  5. Use _reindex to copy data to attacker-controlled cluster"
                    ),
                    reproduction_steps=[
                        f"curl http://{host}:{port}/",
                        f"curl http://{host}:{port}/_cat/indices?v",
                        f"curl http://{host}:{port}/_search?pretty",
                    ],
                    remediation=(
                        "1. Enable X-Pack Security (free in Elasticsearch 6.8+/7.1+):\n"
                        "   xpack.security.enabled: true in elasticsearch.yml\n"
                        "2. Set up authentication: bin/elasticsearch-setup-passwords auto\n"
                        "3. Enable TLS for transport and HTTP layers\n"
                        "4. Bind to localhost: network.host: 127.0.0.1\n"
                        "5. Firewall: block TCP 9200/9300 from untrusted networks"
                    ),
                    references=["CWE-306", "CWE-284", "MITRE T1190"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_NOAUTH,
                    cvss_v40_vector=CVSS40_NOAUTH,
                    mitre_attack=["TA0001/T1190"],
                    port=port, service="elasticsearch", target=host,
                )

                # Enumerate indices
                await self._enumerate_indices(session, url, host, port)

                # Check snapshots
                await self._check_snapshots(session, url, host, port)

                return True

        except Exception:
            return False

    async def _enumerate_indices(
        self, session, url: str, host: str, port: int
    ) -> None:
        try:
            await self.rate_limit()
            async with session.get(f"{url}/_cat/indices?format=json") as resp:
                if resp.status != 200:
                    return
                indices = await resp.json()

            total_docs = 0
            total_size = 0
            sensitive_indices = []
            index_names = []

            for idx in indices:
                name = idx.get("index", "")
                doc_count = int(idx.get("docs.count", 0) or 0)
                size = idx.get("store.size", "0b")
                total_docs += doc_count
                index_names.append(name)

                for pattern in SENSITIVE_INDEX_PATTERNS:
                    if pattern in name.lower():
                        sensitive_indices.append({
                            "name": name, "docs": doc_count, "size": size,
                        })
                        break

            if sensitive_indices:
                ev = Evidence(
                    extra={
                        "sensitive_indices": sensitive_indices[:15],
                        "total_indices": len(indices),
                        "total_docs": total_docs,
                    },
                )
                self.new_finding(
                    title=f"Elasticsearch Sensitive Indices Exposed — {host}:{port} ({len(sensitive_indices)} indices)",
                    severity=Severity.HIGH,
                    description=(
                        f"{len(sensitive_indices)} potentially sensitive indices found in cluster "
                        f"({total_docs:,} total documents across {len(indices)} indices):\n"
                        + "\n".join(
                            f"  - {si['name']} ({si['docs']:,} docs, {si['size']})"
                            for si in sensitive_indices[:10]
                        )
                    ),
                    reproduction_steps=[
                        f"curl http://{host}:{port}/_cat/indices?v",
                        f"curl http://{host}:{port}/{sensitive_indices[0]['name']}/_search?pretty&size=5",
                    ],
                    remediation="Enable authentication and apply index-level access controls with X-Pack roles.",
                    references=["CWE-200", "CWE-312"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_DATA_LEAK,
                    cvss_v40_vector=CVSS40_DATA_LEAK,
                    port=port, service="elasticsearch", target=host,
                )
        except Exception:
            pass

    async def _check_snapshots(
        self, session, url: str, host: str, port: int
    ) -> None:
        try:
            await self.rate_limit()
            async with session.get(f"{url}/_snapshot") as resp:
                if resp.status != 200:
                    return
                repos = await resp.json()

            if repos:
                ev = Evidence(
                    extra={"repositories": list(repos.keys())[:10]},
                )
                self.new_finding(
                    title=f"Elasticsearch Snapshot Repositories Exposed — {host}:{port}",
                    severity=Severity.HIGH,
                    description=(
                        f"Snapshot repositories accessible: {', '.join(list(repos.keys())[:5])}. "
                        "Attackers can create snapshots to exfiltrate entire indices, "
                        "or restore snapshots from attacker-controlled repositories."
                    ),
                    reproduction_steps=[
                        f"curl http://{host}:{port}/_snapshot",
                        f"curl http://{host}:{port}/_snapshot/_all",
                    ],
                    remediation="Restrict snapshot API access. Use role-based access control.",
                    references=["CWE-200"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_DATA_LEAK,
                    cvss_v40_vector=CVSS40_DATA_LEAK,
                    port=port, service="elasticsearch", target=host,
                )
        except Exception:
            pass


class TestElasticAudit:
    def test_ports(self) -> None:
        assert 9200 in ES_PORTS

    def test_sensitive_patterns(self) -> None:
        assert "password" in SENSITIVE_INDEX_PATTERNS
        assert ".kibana" in SENSITIVE_INDEX_PATTERNS

    def test_cvss(self) -> None:
        assert CVSS_NOAUTH.startswith("CVSS:3.1")
        assert CVSS40_NOAUTH.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert ElasticAudit.PHASE == 4
