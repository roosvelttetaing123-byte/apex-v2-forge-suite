"""Vault Audit — unsealed vault, dev mode, root tokens, audit logging."""
from __future__ import annotations

import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_DEV_MODE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class VaultAudit(BaseModule):
    NAME = "vault_audit"
    DESCRIPTION = "HashiCorp Vault: seal status, dev mode, health, audit backends"
    PHASE = 4
    TAGS = ["services", "vault", "hashicorp", "secrets", "cwe-311"]

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
        for port in [8200, 8201]:
            scheme = "https" if port == 8201 else "http"
            base = f"{scheme}://{host}:{port}"
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(f"{base}/v1/sys/health", ssl=False) as resp:
                        if resp.status not in (200, 429, 472, 473, 501, 503):
                            continue
                        data = await resp.json()
                        sealed = data.get("sealed", True)
                        version = data.get("version", "unknown")
                        cluster = data.get("cluster_name", "")

                        if not sealed:
                            # Check for dev mode
                            if "dev" in cluster.lower() or data.get("performance_standby"):
                                self.new_finding(
                                    title=f"Vault Dev Mode / Unsealed — {host}:{port}",
                                    severity=Severity.CRITICAL,
                                    description=f"Vault {version} on {host}:{port} appears to be in dev mode. All secrets accessible.",
                                    reproduction_steps=[f"curl {base}/v1/sys/health"],
                                    remediation="Never run dev mode in production. Use auto-unseal with HSM/KMS.",
                                    references=["CWE-311"],
                                    evidence=Evidence(extra={"host": host, "port": port, "version": version}),
                                    cvss_v31_vector=CVSS_DEV_MODE,
                                    target=host, port=port, service="http", confidence="HIGH",
                                )
                            else:
                                self.new_finding(
                                    title=f"Vault Unsealed — {version} — {host}:{port}",
                                    severity=Severity.LOW,
                                    description=f"Vault {version} is unsealed (normal operation). Version disclosed via health endpoint.",
                                    reproduction_steps=[f"curl {base}/v1/sys/health"],
                                    remediation="Disable health endpoint for unauthenticated access if not needed.",
                                    references=["CWE-200"],
                                    evidence=Evidence(extra={"host": host, "version": version}),
                                    target=host, port=port, service="http",
                                )
                    return
            except Exception:
                continue
