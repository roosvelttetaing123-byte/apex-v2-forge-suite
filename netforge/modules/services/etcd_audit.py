"""etcd Audit — unauthenticated access, key listing, cluster state."""
from __future__ import annotations

import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_UNAUTH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"


class EtcdAudit(BaseModule):
    NAME = "etcd_audit"
    DESCRIPTION = "etcd: unauthenticated access, key listing, cluster state, version"
    PHASE = 4
    TAGS = ["services", "etcd", "kubernetes", "cwe-306"]

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
        import aiohttp
        for port in [2379, 4001]:
            base = f"http://{host}:{port}"
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    # Version check
                    async with session.get(f"{base}/version", ssl=False) as resp:
                        if resp.status != 200:
                            continue
                        data = await resp.json()
                        version = data.get("etcdserver", "unknown")

                    # Key listing (v2 API)
                    async with session.get(f"{base}/v2/keys/?recursive=true",
                                          ssl=False) as keys_resp:
                        if keys_resp.status == 200:
                            keys_data = await keys_resp.json()
                            nodes = keys_data.get("node", {}).get("nodes", [])
                            key_names = [n.get("key", "") for n in nodes[:50]]

                            sensitive = [k for k in key_names if any(s in k.lower() for s in
                                       ["secret", "password", "token", "cert", "key", "config"])]

                            self.new_finding(
                                title=f"etcd Unauthenticated — {len(key_names)} Keys Exposed — {host}:{port}",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"etcd {version} on {host}:{port} allows unauthenticated access. "
                                    f"{len(key_names)} keys visible" +
                                    (f", {len(sensitive)} sensitive: {', '.join(sensitive[:5])}" if sensitive else "")
                                ),
                                reproduction_steps=[f"curl {base}/v2/keys/?recursive=true"],
                                remediation="Enable etcd authentication. Use client certificates. Restrict network access.",
                                references=["CWE-306"],
                                evidence=Evidence(extra={
                                    "host": host, "port": port, "version": version,
                                    "key_count": len(key_names), "sensitive": sensitive[:20],
                                }),
                                cvss_v31_vector=CVSS_UNAUTH,
                                mitre_attack=["TA0006/T1552"],
                                target=host, port=port, service="etcd", confidence="HIGH",
                            )
                            return

                    # Try v3 API (gRPC gateway)
                    async with session.post(f"{base}/v3/kv/range",
                                           json={"key": "AA==", "range_end": "//8="},
                                           ssl=False) as v3_resp:
                        if v3_resp.status == 200:
                            v3_data = await v3_resp.json()
                            count = v3_data.get("count", 0)
                            if count or v3_data.get("kvs"):
                                self.new_finding(
                                    title=f"etcd v3 API Unauthenticated — {host}:{port}",
                                    severity=Severity.CRITICAL,
                                    description=f"etcd {version} v3 API accessible without auth. {count} keys.",
                                    reproduction_steps=[f"curl -X POST {base}/v3/kv/range -d '{{\"key\":\"AA==\"}}'"],
                                    remediation="Enable auth: etcdctl auth enable",
                                    references=["CWE-306"],
                                    evidence=Evidence(extra={"host": host, "port": port, "count": count}),
                                    cvss_v31_vector=CVSS_UNAUTH,
                                    target=host, port=port, service="etcd", confidence="HIGH",
                                )
                    return
            except Exception:
                continue
