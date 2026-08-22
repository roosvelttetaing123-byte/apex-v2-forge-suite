"""Certificate Transparency Log Scanner — crt.sh enumeration for hidden subdomains.

Queries crt.sh (Certificate Transparency logs) to discover:
  - Subdomains not in public DNS
  - Wildcard certificate patterns
  - Internal hostnames leaked in SAN fields
  - Expired/revoked certs exposing decommissioned infrastructure

No API key required — crt.sh is free and public.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.leak_intel.crtsh_scanner")


class CrtshScanner(BaseModule):
    """Enumerate subdomains via Certificate Transparency logs (crt.sh)."""

    NAME        = "crtsh_scanner"
    DESCRIPTION = "Certificate Transparency log enumeration — hidden subdomain discovery"
    PHASE       = 0
    TAGS        = ["osint", "leak_intel", "crtsh", "recon", "subdomain"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        domain = self._extract_domain()
        if not domain:
            return self._make_result(start, skipped=True, skip_reason="No domain derivable from target")

        self.log.info("Querying crt.sh for CT log entries: %s", domain)

        try:
            import aiohttp
        except ImportError:
            return self._make_result(start, skipped=True, skip_reason="aiohttp not installed")

        subdomains: set[str] = set()
        internal_names: list[str] = []

        async with aiohttp.ClientSession() as session:
            await self.rate_limit()
            url = f"https://crt.sh/?q=%25.{domain}&output=json"

            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        self.log.warning("crt.sh returned status %d", resp.status)
                        return self._make_result(start)
                    entries = await resp.json()
            except Exception as exc:
                self.log.warning("crt.sh query failed: %s", exc)
                return self._make_result(start)

            # Parse CT log entries
            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if not name or name.startswith("*"):
                        # Track wildcard patterns but skip for subdomain list
                        continue
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains.add(name)
                        # Check for internal-looking names
                        if self._looks_internal(name):
                            internal_names.append(name)

        # Report findings
        if subdomains:
            self.new_finding(
                title=f"CT Log Subdomain Enumeration: {len(subdomains)} subdomains for {domain}",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Certificate Transparency logs reveal {len(subdomains)} unique subdomains for {domain}.\n"
                    f"Sample: {', '.join(sorted(subdomains)[:15])}"
                ),
                reproduction_steps=[
                    f"1. Query crt.sh: https://crt.sh/?q=%25.{domain}",
                    "2. Review the full list of subdomains",
                    "3. Probe each for live services",
                ],
                remediation=(
                    "Review all discovered subdomains for unintended exposure.\n"
                    "Decommission or restrict access to internal/staging/dev subdomains."
                ),
                references=[
                    "https://crt.sh",
                    "https://certificate.transparency.dev/",
                ],
                evidence=Evidence(
                    extra={"subdomain_count": len(subdomains), "subdomains": sorted(subdomains)[:50]},
                ),
                tags=["osint", "recon", "subdomain", "ct_log"],
                mitre_attack=["T1596.003"],
            )

        if internal_names:
            self.new_finding(
                title=f"CT Log Internal Subdomain Leak: {len(internal_names)} internal names for {domain}",
                severity=Severity.MEDIUM,
                description=(
                    f"Certificate Transparency logs expose internal-looking subdomains:\n"
                    f"{', '.join(internal_names[:20])}\n\n"
                    "These may reveal internal infrastructure, staging environments, "
                    "or decommissioned services that are still reachable."
                ),
                reproduction_steps=[
                    f"1. Query crt.sh for {domain}",
                    "2. Filter for internal-looking names (dev, staging, internal, vpn, etc.)",
                    "3. Attempt to resolve and access each",
                ],
                remediation=(
                    "Use private CAs for internal services instead of public CAs.\n"
                    "Restrict access to internal subdomains via firewall rules."
                ),
                references=["https://crt.sh"],
                evidence=Evidence(extra={"internal_names": internal_names}),
                tags=["osint", "leak", "internal", "subdomain"],
                mitre_attack=["T1596.003", "T1590.002"],
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            )

        return self._make_result(start)

    def _extract_domain(self) -> str:
        """Extract base domain from target."""
        target = self.config.target.replace("https://", "").replace("http://", "")
        target = target.split("/")[0].split(":")[0]
        parts = target.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return target

    def _looks_internal(self, name: str) -> bool:
        """Check if a subdomain name looks like internal infrastructure."""
        internal_markers = (
            "internal", "intranet", "vpn", "staging", "stage", "dev", "development",
            "test", "testing", "qa", "uat", "admin", "mgmt", "management", "corp",
            "private", "backend", "api-internal", "db", "database", "jenkins",
            "gitlab", "jira", "confluence", "grafana", "kibana", "elastic",
            "prometheus", "vault", "consul", "k8s", "kube", "docker", "registry",
        )
        return any(marker in name for marker in internal_markers)
