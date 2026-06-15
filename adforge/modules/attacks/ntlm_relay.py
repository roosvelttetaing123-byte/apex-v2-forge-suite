"""NTLM relay attack setup and target identification."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NTLM_RELAY = "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"
CVSS40_NTLM_RELAY = "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"
class NtlmRelay(BaseModule):
    """NTLM relay attack setup — identify relay targets and prerequisites."""

    NAME        = "ntlm_relay"
    DESCRIPTION = "Identify NTLM relay targets: SMB hosts without signing, WebDAV/ADCS endpoints"
    PHASE       = 5
    TAGS        = ["attacks", "ntlm-relay", "smb", "mitre-T1557.001"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        confirmed = self.confirm_action(
            module=self.NAME,
            action="Identify NTLM relay targets (no active relay — identification only)",
            target=target,
            risk="Scans for SMB signing status and WebDAV/ADCS endpoints.",
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        relay_targets = await self._find_relay_targets()
        webdav_hosts  = await self._find_webdav_hosts()
        adcs_endpoint = await self._find_adcs_endpoint()

        if relay_targets or webdav_hosts or adcs_endpoint:
            ev = Evidence(
                extra={
                    "relay_targets":   relay_targets,
                    "webdav_hosts":    webdav_hosts,
                    "adcs_endpoint":   adcs_endpoint,
                }
            )
            self.new_finding(
                title=f"NTLM Relay Attack Viable — {len(relay_targets)} Target(s) Without SMB Signing",
                severity=Severity.CRITICAL,
                description=(
                    f"{len(relay_targets)} host(s) do not require SMB signing — relay targets. "
                    + (f"\nWebDAV hosts (HTTP relay): {', '.join(webdav_hosts[:5])}" if webdav_hosts else "")
                    + (f"\nAD CS ESC8 endpoint: {adcs_endpoint}" if adcs_endpoint else "")
                    + "\n\nNTLM relay chain:\n"
                    "1. Capture NTLM auth (via LLMNR/NBT-NS poison, Responder)\n"
                    "2. Relay to target without SMB signing\n"
                    "3. Execute commands / create accounts / dump secrets"
                ),
                reproduction_steps=[
                    "# Setup relay (requires captured auth first):",
                    f"impacket-ntlmrelayx -tf relay_targets.txt -smb2support",
                    "# Trigger auth via Responder or PetitPotam/PrintSpooler",
                    f"sudo responder -I eth0 -wrf",
                ],
                remediation=(
                    "Enable SMB signing on ALL domain hosts (required, not just enabled). "
                    "Disable NTLM where possible; use Kerberos-only environments. "
                    "Enable Extended Protection for Authentication (EPA) on web endpoints."
                ),
                references=["CVE-2019-1040", "MITRE T1557.001", "impacket ntlmrelayx"],
                evidence=ev,
                cvss_v31_vector=CVSS_NTLM_RELAY,
                cvss_v40_vector=CVSS40_NTLM_RELAY,
                mitre_attack=["TA0006/T1557.001"],
                target=target,
                operator_confirmed=True,
            )

        return self._make_result(start)

    async def _find_relay_targets(self) -> list[str]:
        """Return SMB hosts where signing is disabled or not enforced."""
        relay_targets: list[str] = []
        open_ports = self.config.extra.get("open_ports", {})
        for host, ports in open_ports.items():
            if not any(p["port"] == 445 for p in ports):
                continue
            # smb_audit stores True when signing is *required*, False/absent when not.
            # Default True (safe) — only flag hosts explicitly marked as unsigned.
            signing_required = self.config.extra.get(f"smb_signing_{host}", True)
            if not signing_required:
                relay_targets.append(host)
        return relay_targets

    async def _find_webdav_hosts(self) -> list[str]:
        """Find hosts with WebDAV enabled (allows HTTP-based NTLM relay)."""
        webdav_hosts: list[str] = []
        live_hosts = self.config.extra.get("live_hosts", [])

        for host in live_hosts[:20]:
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.request(
                        "OPTIONS", f"http://{host}",
                        timeout=aiohttp.ClientTimeout(total=3),
                    ) as resp:
                        allow = resp.headers.get("Allow", "")
                        dav   = resp.headers.get("DAV", "")
                        if "PROPFIND" in allow or dav:
                            webdav_hosts.append(host)
            except Exception:
                pass

        return webdav_hosts

    async def _find_adcs_endpoint(self) -> str | None:
        """Find AD CS web enrollment endpoint (ESC8 candidate)."""
        dc_ip = self.config.extra.get("dc", self.config.target)
        for path in ["/certsrv/", "/certsrv/mscep/mscep.dll", "/certsrv/certfnsh.asp"]:
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        f"http://{dc_ip}{path}",
                        timeout=aiohttp.ClientTimeout(total=3),
                    ) as resp:
                        if resp.status in (200, 401):
                            return f"http://{dc_ip}{path}"
            except Exception:
                pass
        return None


class TestNtlmRelay:
    def test_cvss_vector(self) -> None:
        assert CVSS_NTLM_RELAY.startswith("CVSS:3.1")
