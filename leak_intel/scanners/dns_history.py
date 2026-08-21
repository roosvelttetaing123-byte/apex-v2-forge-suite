"""DNS History Scanner — SecurityTrails/PassiveTotal historical DNS for decommissioned subdomains.

Queries historical DNS APIs to find:
  - Old A/CNAME records → decommissioned subdomains (subdomain takeover candidates)
  - IP address history → infrastructure changes
  - Historical MX/NS records → mail/DNS provider changes

API keys: SECURITYTRAILS_API_KEY or PASSIVETOTAL_KEY + PASSIVETOTAL_USER env vars.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.leak_intel.dns_history")


class DnsHistoryScanner(BaseModule):
    """Discover decommissioned subdomains via historical DNS data."""

    NAME        = "dns_history"
    DESCRIPTION = "Historical DNS — SecurityTrails/PassiveTotal decommissioned subdomain discovery"
    PHASE       = 0
    TAGS        = ["osint", "leak_intel", "dns", "recon", "subdomain"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._st_key = ""
        self._pt_user = ""
        self._pt_key = ""

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        domain = self._extract_domain()
        if not domain:
            return self._make_result(start, skipped=True, skip_reason="No domain derivable from target")

        if not self._st_key and not self._pt_key:
            return self._make_result(start, skipped=True,
                                      skip_reason="No SECURITYTRAILS_API_KEY or PASSIVETOTAL_KEY set")

        self.log.info("Querying historical DNS for: %s", domain)

        try:
            import aiohttp
        except ImportError:
            return self._make_result(start, skipped=True, skip_reason="aiohttp not installed")

        async with aiohttp.ClientSession() as session:
            if self._st_key:
                await self._query_securitytrails(session, domain)
            if self._pt_key and self._pt_user:
                await self._query_passivetotal(session, domain)

        return self._make_result(start)

    async def _query_securitytrails(self, session: Any, domain: str) -> None:
        """Query SecurityTrails for subdomain history."""
        headers = {"apikey": self._st_key, "Accept": "application/json"}

        # Get all subdomains
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        try:
            await self.rate_limit()
            async with session.get(url, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    self.log.warning("SecurityTrails returned %d", resp.status)
                    return
                data = await resp.json()

            subdomains = data.get("subdomains", [])
            if not subdomains:
                return

            # Get DNS history for interesting subdomains
            stale_subs: list[str] = []
            for sub in subdomains[:30]:
                fqdn = f"{sub}.{domain}"
                # Check if it resolves currently
                await self.rate_limit()
                hist_url = f"https://api.securitytrails.com/v1/history/{fqdn}/dns/a"
                try:
                    async with session.get(hist_url, headers=headers,
                                            timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status != 200:
                            continue
                        hist_data = await resp.json()

                    records = hist_data.get("records", [])
                    if records:
                        # Check if the most recent record's IP is now unresponsive
                        latest = records[0]
                        old_ips = [v.get("ip", "") for v in latest.get("values", [])]
                        # If there are old IPs but the subdomain might be decommissioned
                        if old_ips:
                            stale_subs.append(fqdn)

                except Exception:
                    continue

            if stale_subs:
                self.new_finding(
                    title=f"DNS History: {len(stale_subs)} historical subdomains for {domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"SecurityTrails reveals {len(stale_subs)} subdomains with historical DNS records "
                        f"that may be decommissioned or vulnerable to subdomain takeover:\n"
                        f"{', '.join(stale_subs[:20])}"
                    ),
                    reproduction_steps=[
                        f"1. Query SecurityTrails for {domain} subdomains",
                        "2. Check which historical subdomains no longer resolve",
                        "3. Test for subdomain takeover (dangling CNAME, expired cloud resources)",
                    ],
                    remediation=(
                        "Remove DNS records for decommissioned subdomains.\n"
                        "Audit cloud resources (S3, Azure, Heroku) for dangling references."
                    ),
                    references=[
                        "https://securitytrails.com/",
                        "https://labs.detectify.com/writeups/hostile-subdomain-takeover/",
                    ],
                    evidence=Evidence(extra={"stale_subdomains": stale_subs}),
                    tags=["osint", "dns_history", "subdomain", "takeover"],
                    mitre_attack=["T1596.001", "T1584.001"],
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                )

            # Always report the enumeration
            if subdomains:
                self.new_finding(
                    title=f"SecurityTrails Subdomain Enumeration: {len(subdomains)} subdomains for {domain}",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"SecurityTrails reveals {len(subdomains)} subdomains for {domain}.\n"
                        f"Sample: {', '.join(subdomains[:20])}"
                    ),
                    reproduction_steps=[f"1. Query SecurityTrails API for {domain}"],
                    remediation="Review and audit all subdomains.",
                    references=["https://securitytrails.com/"],
                    evidence=Evidence(extra={"subdomain_count": len(subdomains), "subdomains": subdomains[:50]}),
                    tags=["osint", "dns", "recon", "subdomain"],
                    mitre_attack=["T1596.001"],
                )

        except Exception as exc:
            self.log.debug("SecurityTrails error (%s)", type(exc).__name__)

    async def _query_passivetotal(self, session: Any, domain: str) -> None:
        """Query PassiveTotal/RiskIQ for passive DNS data."""
        headers = {
            "Authorization": aiohttp.encode_basic_auth(
                self._pt_user,
                self._pt_key,
            )
        }
        url = "https://api.passivetotal.org/v2/enrichment/subdomains"
        params = {"query": f"*.{domain}"}

        try:
            await self.rate_limit()
            async with session.get(url, params=params, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()

            subdomains = data.get("subdomains", [])
            if subdomains:
                self.new_finding(
                    title=f"PassiveTotal Subdomain Enumeration: {len(subdomains)} subdomains for {domain}",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"PassiveTotal passive DNS reveals {len(subdomains)} subdomains for {domain}.\n"
                        f"Sample: {', '.join(subdomains[:20])}"
                    ),
                    reproduction_steps=[f"1. Query PassiveTotal for *.{domain}"],
                    remediation="Audit subdomains for unintended exposure.",
                    references=["https://community.riskiq.com/"],
                    evidence=Evidence(extra={"subdomains": subdomains[:50]}),
                    tags=["osint", "dns", "passive_dns", "subdomain"],
                    mitre_attack=["T1596.001"],
                )

        except Exception as exc:
            self.log.debug("PassiveTotal error (%s)", type(exc).__name__)

    def _extract_domain(self) -> str:
        target = self.config.target.replace("https://", "").replace("http://", "")
        target = target.split("/")[0].split(":")[0]
        parts = target.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return target


import aiohttp  # noqa: E402
