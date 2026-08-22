"""Consul Audit — ACL disabled, KV store exposure, service mesh misconfig."""
from __future__ import annotations

import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NO_ACL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"


class ConsulAudit(BaseModule):
    NAME = "consul_audit"
    DESCRIPTION = "Consul: ACL disabled, KV store exposure, service catalog, agent info"
    PHASE = 4
    TAGS = ["services", "consul", "hashicorp", "cwe-306"]

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
        for port in [8500, 8501]:
            scheme = "https" if port == 8501 else "http"
            base = f"{scheme}://{host}:{port}"
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    # Agent self info
                    async with session.get(f"{base}/v1/agent/self", ssl=False) as resp:
                        if resp.status != 200:
                            continue
                        data = await resp.json()
                        acl_enabled = data.get("Config", {}).get("ACL", {}).get("Enabled", False)

                        if not acl_enabled:
                            self.new_finding(
                                title=f"Consul ACL Disabled — Full Access — {host}:{port}",
                                severity=Severity.CRITICAL,
                                description="Consul ACLs are disabled. Full read/write access to KV store, services, and config.",
                                reproduction_steps=[f"curl {base}/v1/agent/self"],
                                remediation="Enable ACLs: consul acl bootstrap. Set default_policy=deny.",
                                references=["CWE-306"],
                                evidence=Evidence(extra={"host": host, "port": port, "acl": False}),
                                cvss_v31_vector=CVSS_NO_ACL,
                                target=host, port=port, service="http", confidence="HIGH",
                            )

                    # KV store enumeration
                    async with session.get(f"{base}/v1/kv/?keys", ssl=False) as kv_resp:
                        if kv_resp.status == 200:
                            keys = await kv_resp.json()
                            if isinstance(keys, list) and keys:
                                sensitive = [k for k in keys if any(s in k.lower() for s in
                                           ["password", "secret", "token", "key", "cred", "api"])]
                                if sensitive:
                                    self.new_finding(
                                        title=f"Consul KV Store — Sensitive Keys Exposed — {host}",
                                        severity=Severity.HIGH,
                                        description=f"Found {len(sensitive)} sensitive KV keys: {', '.join(sensitive[:5])}.",
                                        reproduction_steps=[f"curl {base}/v1/kv/?keys"],
                                        remediation="Enable ACLs. Restrict KV access.",
                                        references=["CWE-200"],
                                        evidence=Evidence(extra={"host": host, "sensitive_keys": sensitive[:20]}),
                                        target=host, port=port, service="http",
                                    )
                    return
            except Exception:
                continue
